use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const PUBLIC_RELEASES_ENABLED: bool = false;
const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/codewiresh/codewire/releases/latest";
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/codewiresh/codewire/releases/download";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
}

pub async fn run_current() -> anyhow::Result<()> {
    if !PUBLIC_RELEASES_ENABLED {
        anyhow::bail!(
            "automatic updates are unavailable during the private preview; \
             update your authorized source checkout and run `make cli-install` from its root"
        );
    }

    run_public_update().await
}

async fn run_public_update() -> anyhow::Result<()> {
    let current = current_version();
    if current == "dev" {
        anyhow::bail!("cannot update a dev build - install a release build first");
    }

    println!("Checking for updates...");
    let client = http_client()?;
    let latest = fetch_latest_version(&client).await?;
    if !is_newer(current, &latest) {
        println!("Already up to date ({current}).");
        return Ok(());
    }

    println!("New version available: {current} -> {latest}");
    println!("Downloading {latest}...");
    self_update(&client, &latest).await?;
    println!("Updated to {latest}.");
    Ok(())
}

fn current_version() -> &'static str {
    match option_env!("CODEWIRE_VERSION") {
        Some(version) if !version.trim().is_empty() => version,
        _ => "dev",
    }
}

fn http_client() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("codewire-cli")
        .build()?)
}

async fn fetch_latest_version(client: &Client) -> anyhow::Result<String> {
    fetch_latest_version_from(client, GITHUB_LATEST_RELEASE_URL).await
}

async fn fetch_latest_version_from(client: &Client, url: &str) -> anyhow::Result<String> {
    let response = client
        .get(url)
        .header("accept", "application/vnd.github+json")
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("github API returned {}", response.status().as_u16());
    }

    let release = response.json::<GitHubRelease>().await?;
    let tag = release.tag_name.trim();
    if tag.is_empty() {
        anyhow::bail!("empty tag_name in response");
    }
    Ok(tag.to_string())
}

pub(crate) fn is_newer(current: &str, latest: &str) -> bool {
    let Some(current) = parse_semver(current) else {
        return false;
    };
    let Some(latest) = parse_semver(latest) else {
        return false;
    };
    latest > current
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let version = version.trim().strip_prefix('v').unwrap_or(version.trim());
    let version = version.split_once('-').map_or(version, |(base, _)| base);
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

async fn self_update(client: &Client, latest_version: &str) -> anyhow::Result<()> {
    let asset = asset_name(latest_version)
        .ok_or_else(|| anyhow::anyhow!("unsupported platform: {}", platform_name()))?;
    let sums_url = release_url(latest_version, "SHA256SUMS");
    let expected_hash = fetch_checksum(client, &sums_url, &asset).await?;

    let exe = current_executable()?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("resolve executable directory"))?;
    let tmp_path = create_temp_path(dir)?;

    let result = download_and_replace(
        client,
        latest_version,
        &asset,
        &expected_hash,
        &exe,
        &tmp_path,
    )
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn current_executable() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving executable")?;
    fs::canonicalize(&exe).context("resolving symlinks")
}

async fn download_and_replace(
    client: &Client,
    latest_version: &str,
    asset: &str,
    expected_hash: &str,
    exe: &Path,
    tmp_path: &Path,
) -> anyhow::Result<()> {
    let asset_url = release_url(latest_version, asset);
    let response = client.get(asset_url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("download returned HTTP {}", response.status().as_u16());
    }
    let bytes = response.bytes().await?;
    let got_hash = sha256_hex(&bytes);
    if got_hash != expected_hash {
        anyhow::bail!("checksum mismatch: expected {expected_hash}, got {got_hash}");
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
        .with_context(|| format!("creating temp file {}", tmp_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", tmp_path.display()))?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting permissions on {}", tmp_path.display()))?;
    }

    fs::rename(tmp_path, exe).with_context(|| format!("replacing {}", exe.display()))?;
    Ok(())
}

async fn fetch_checksum(
    client: &Client,
    sums_url: &str,
    asset_name: &str,
) -> anyhow::Result<String> {
    let response = client.get(sums_url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("SHA256SUMS returned HTTP {}", response.status().as_u16());
    }
    let body = response.text().await?;
    parse_checksum(&body, asset_name)
        .ok_or_else(|| anyhow::anyhow!("no checksum found for {asset_name}"))
}

fn parse_checksum(body: &str, asset_name: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let hash = fields.next()?;
        let name = fields.next()?;
        if fields.next().is_none() && name == asset_name {
            Some(hash.to_string())
        } else {
            None
        }
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn release_url(version: &str, filename: &str) -> String {
    format!(
        "{}/{}/{}",
        RELEASE_DOWNLOAD_BASE,
        version.trim(),
        filename.trim()
    )
}

fn asset_name(version: &str) -> Option<String> {
    asset_name_for(version, std::env::consts::OS, std::env::consts::ARCH)
}

fn asset_name_for(version: &str, os: &str, arch: &str) -> Option<String> {
    let suffix = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => return None,
    };
    Some(format!("cw-{}-{}", version.trim(), suffix))
}

fn platform_name() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn create_temp_path(dir: &Path) -> anyhow::Result<PathBuf> {
    for attempt in 0..100u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = dir.join(format!(
            ".cw-update-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    anyhow::bail!("creating temp file path in {}", dir.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_comparison_matches_go_behavior() {
        assert!(is_newer("v0.2.48", "v0.2.49"));
        assert!(is_newer("0.2.48", "0.3.0"));
        assert!(is_newer("0.2.52-2-gf2fe21a", "0.2.53"));
        assert!(!is_newer("0.2.49", "0.2.49"));
        assert!(!is_newer("0.2.50", "0.2.49"));
        assert!(!is_newer("dev", "v9.9.9"));
        assert!(!is_newer("0.2", "0.3.0"));
    }

    #[test]
    fn unversioned_build_defaults_to_dev() {
        assert_eq!(current_version(), "dev");
    }

    #[test]
    fn asset_names_match_go_release_assets() {
        assert_eq!(
            asset_name_for("v0.2.48", "linux", "x86_64").as_deref(),
            Some("cw-v0.2.48-x86_64-unknown-linux-musl")
        );
        assert_eq!(
            asset_name_for("v0.2.48", "linux", "aarch64").as_deref(),
            Some("cw-v0.2.48-aarch64-unknown-linux-gnu")
        );
        assert_eq!(
            asset_name_for("v0.2.48", "macos", "aarch64").as_deref(),
            Some("cw-v0.2.48-aarch64-apple-darwin")
        );
        assert!(asset_name_for("v0.2.48", "windows", "x86_64").is_none());
    }

    #[test]
    fn checksum_parser_accepts_sha256sums_spacing() {
        let body = "\
bad  cw-v0.2.48-aarch64-apple-darwin
abc123  cw-v0.2.48-x86_64-unknown-linux-musl
";
        assert_eq!(
            parse_checksum(body, "cw-v0.2.48-x86_64-unknown-linux-musl").as_deref(),
            Some("abc123")
        );
        assert_eq!(parse_checksum(body, "missing"), None);
    }

    #[test]
    fn sha256_hex_matches_known_digest() {
        assert_eq!(
            sha256_hex(b"codewire"),
            "a1a0a7f9cf490282be035abda3ef89d805f3fbe808358e599805d06a502b80f5"
        );
    }

    #[tokio::test]
    async fn private_preview_update_explains_source_install() {
        let error = run_current().await.unwrap_err().to_string();

        assert!(error.contains("private preview"));
        assert!(error.contains("make cli-install"));
    }
}
