//! Trust for the local HTTPS CA (#4316): adding it to, and removing it from,
//! the per-user stores browsers read. Only per-user stores, as cw-security
//! decided on 2026-11-13: the NSS databases of Chromium-family browsers on
//! Linux and of Firefox, trusted as a TLS server CA only (`C,,`). Never a
//! machine-wide store, and not yet the macOS login keychain (#4316). An entry
//! is found again by the CA's SHA-256 fingerprint, never by its name alone.
//!
//! Trusting the CA also removes any older Codewire CA from the same store, so
//! a rotation that stopped part way is finished by trusting again.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context as _;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// The name every entry this CA adds starts with.
const NICKNAME_PREFIX: &str = "Codewire local HTTPS CA";

/// The CA as read from its certificate file.
pub(super) struct LocalCaCertificate {
    pub(super) path: PathBuf,
    /// SHA-256 of the DER certificate, uppercase hex.
    pub(super) fingerprint: String,
}

impl LocalCaCertificate {
    pub(super) fn read(path: &Path) -> anyhow::Result<Self> {
        let pem = std::fs::read_to_string(path).with_context(|| {
            format!("reading the local HTTPS CA certificate {}", path.display())
        })?;
        let der =
            pem_der(&pem).context("the local HTTPS CA certificate is not one PEM certificate")?;
        Ok(Self {
            path: path.to_owned(),
            fingerprint: hex_upper(&Sha256::digest(&der)),
        })
    }

    /// The name this CA's entries carry: the prefix and the start of its
    /// fingerprint, so a rotated CA's entry never shares a name with the
    /// next one's.
    fn nickname(&self) -> String {
        format!("{NICKNAME_PREFIX} {}", &self.fingerprint[..16])
    }
}

/// The DER bytes of a single PEM certificate.
fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?;
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(base64)
        .ok()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// One per-user store a browser reads: an NSS database (`cert9.db`)
/// directory, changed with `certutil`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Store {
    directory: PathBuf,
    certutil: PathBuf,
}

impl std::fmt::Display for Store {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "the NSS database {}", self.directory.display())
    }
}

impl Store {
    fn certutil(&self) -> Command {
        crate::process::command(&self.certutil, &[])
    }

    fn database(&self) -> String {
        format!("sql:{}", self.directory.display())
    }

    fn exists(&self) -> bool {
        self.directory.join("cert9.db").is_file()
    }
}

/// NSS's tool, found on `PATH`.
const CERTUTIL: &str = "certutil";

/// The per-user stores on this machine: Firefox's profiles, and on Linux
/// the shared NSS database `~/.pki/nssdb` that Chromium-family browsers
/// read, included even when it doesn't exist yet, because trusting creates
/// it.
pub(super) fn stores() -> anyhow::Result<Vec<Store>> {
    let home = PathBuf::from(
        std::env::var_os("HOME")
            .context("HOME is not set, so the per-user stores can't be found")?,
    );
    let mut directories = Vec::new();
    if !cfg!(target_os = "macos") {
        directories.push(home.join(".pki/nssdb"));
    }
    let profile_roots: &[&str] = if cfg!(target_os = "macos") {
        &["Library/Application Support/Firefox/Profiles"]
    } else {
        &[
            ".mozilla/firefox",
            "snap/firefox/common/.mozilla/firefox",
            ".var/app/org.mozilla.firefox/.mozilla/firefox",
        ]
    };
    for root in profile_roots {
        let Ok(profiles) = std::fs::read_dir(home.join(root)) else {
            continue;
        };
        let mut found: Vec<PathBuf> = profiles
            .flatten()
            .map(|entry| entry.path())
            .filter(|profile| profile.join("cert9.db").is_file())
            .collect();
        found.sort();
        directories.extend(found);
    }
    Ok(directories
        .into_iter()
        .map(|directory| Store {
            directory,
            certutil: PathBuf::from(CERTUTIL),
        })
        .collect())
}

/// Whether `certutil`, NSS's tool, is installed; NSS stores need it.
pub(super) fn certutil_installed() -> bool {
    crate::process::command(CERTUTIL, &[])
        .arg("-H")
        .output()
        .is_ok()
}

/// What to install for `certutil`.
pub(super) const CERTUTIL_HINT: &str = "install NSS's certutil: the package is libnss3-tools on Debian and Ubuntu, nss-tools on Fedora, nss on Arch, and nss with Homebrew";

/// Whether `store` trusts exactly this CA.
pub(super) fn holds(ca: &LocalCaCertificate, store: &Store) -> anyhow::Result<bool> {
    Ok(entries(store)?
        .iter()
        .any(|entry| entry.fingerprint == ca.fingerprint))
}

/// Trust the CA in `store` for TLS servers only, then remove every other
/// Codewire CA from it: an older one is left only by a rotation that
/// stopped part way. Whether the CA was newly added.
pub(super) fn trust(ca: &LocalCaCertificate, store: &Store) -> anyhow::Result<bool> {
    let changed: anyhow::Result<bool> = (|| {
        ensure_database(store)?;
        let entries = entries(store)?;
        let added = !entries
            .iter()
            .any(|entry| entry.fingerprint == ca.fingerprint);
        if added {
            run(store
                .certutil()
                .args([
                    "-A",
                    "-d",
                    &store.database(),
                    "-n",
                    &ca.nickname(),
                    "-t",
                    "C,,",
                    "-i",
                ])
                .arg(&ca.path))?;
        }
        for entry in entries
            .iter()
            .filter(|entry| entry.fingerprint != ca.fingerprint)
        {
            delete(store, &entry.nickname)?;
        }
        Ok(added)
    })();
    changed.with_context(|| format!("trusting the local HTTPS CA in {store}"))
}

/// Remove exactly this CA's entries from `store`. Whether it held any.
pub(super) fn untrust(ca: &LocalCaCertificate, store: &Store) -> anyhow::Result<bool> {
    let removed: anyhow::Result<bool> = (|| {
        let matching: Vec<Entry> = entries(store)?
            .into_iter()
            .filter(|entry| entry.fingerprint == ca.fingerprint)
            .collect();
        for entry in &matching {
            delete(store, &entry.nickname)?;
        }
        Ok(!matching.is_empty())
    })();
    removed.with_context(|| format!("removing the local HTTPS CA from {store}"))
}

/// The second half of a rotation, once the supervisor has replaced the CA:
/// trust the new CA in every store that trusted the old one, which also
/// removes the old one there. A store is never left trusting no CA. On a
/// failure the stores already done trust the new CA, the rest still trust
/// the old one, and `cw local-https trust` finishes the rest. The stores
/// that were moved.
pub(super) fn move_trust(
    old: &LocalCaCertificate,
    new: &LocalCaCertificate,
    stores: &[Store],
) -> anyhow::Result<Vec<Store>> {
    let mut moved = Vec::new();
    for store in stores {
        if !holds(old, store)? {
            continue;
        }
        trust(new, store).context(
            "the new CA is in place but not yet trusted everywhere; `cw local-https trust` finishes it",
        )?;
        moved.push(store.clone());
    }
    Ok(moved)
}

/// One Codewire CA entry in an NSS database.
struct Entry {
    nickname: String,
    fingerprint: String,
}

/// The Codewire CA entries in `store`, each with its certificate's
/// fingerprint. None when the database doesn't exist.
fn entries(store: &Store) -> anyhow::Result<Vec<Entry>> {
    if !store.exists() {
        return Ok(Vec::new());
    }
    let listing = output(store.certutil().args(["-L", "-d", &store.database()]))?;
    let mut entries = Vec::new();
    for nickname in codewire_nicknames(&listing) {
        let pem =
            output(
                store
                    .certutil()
                    .args(["-L", "-d", &store.database(), "-n", &nickname, "-a"]),
            )?;
        if let Some(der) = pem_der(&pem) {
            entries.push(Entry {
                nickname,
                fingerprint: hex_upper(&Sha256::digest(&der)),
            });
        }
    }
    Ok(entries)
}

fn delete(store: &Store, nickname: &str) -> anyhow::Result<()> {
    run(store
        .certutil()
        .args(["-D", "-d", &store.database(), "-n", nickname]))
}

/// Create the NSS database when it doesn't exist, as browsers would.
fn ensure_database(store: &Store) -> anyhow::Result<()> {
    if store.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&store.directory)
        .with_context(|| format!("creating {}", store.directory.display()))?;
    run(store
        .certutil()
        .args(["-N", "-d", &store.database(), "--empty-password"]))
}

/// The nicknames in `certutil -L` output that this feature could have added.
/// Each row is the nickname, padded, then the trust flags.
fn codewire_nicknames(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter(|line| line.starts_with(NICKNAME_PREFIX))
        .filter_map(|line| {
            line.trim_end()
                .rsplit_once(char::is_whitespace)
                .map(|(name, _)| name.trim_end().to_owned())
        })
        .collect()
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    output(command).map(drop)
}

fn output(command: &mut Command) -> anyhow::Result<String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let result = command
        .output()
        .with_context(|| format!("running {program}"))?;
    anyhow::ensure!(
        result.status.success(),
        "the command {program} failed: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

#[cfg(test)]
mod tests;
