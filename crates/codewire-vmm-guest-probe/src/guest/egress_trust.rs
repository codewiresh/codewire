//! The workspace's trust in this boot's TLS front door (#3999).
//!
//! When the seed carries the front door's CA certificate, PID 1 publishes
//! two files in the container control directory, which the workspace sees
//! read-only at `/run/codewire-host`:
//!
//! - `egress-ca.pem`, the CA alone, which `NODE_EXTRA_CA_CERTS` names unless
//!   the image or project set it ([`TRUST_ENVIRONMENT`]). It adds to Node's
//!   own roots rather than replacing them, and covers Claude Code;
//! - `ca-certificates.crt`, the image's own system bundle followed by the CA,
//!   which `CODEX_CA_CERTIFICATE` names while the Codex client is selected
//!   ([`CODEX_TRUST_ENVIRONMENT`]). Codex ignores the Node variable, and the
//!   bundle serves whether Codex adds the file to its roots or replaces them
//!   with it (#5447). Git's `http.https://github.com/.sslCAInfo` names it
//!   too while the boot binds GitHub's hosts, which applies to
//!   `https://github.com/` URLs alone (the projection's, #4001). Nothing
//!   else names it: `SSL_CERT_FILE` and the like replace every tool's trust
//!   store, so a CA the user adds after boot would silently stop being
//!   trusted;
//! - `egress-ca.d/<hash>.0`, the CA alone under its OpenSSL subject-hash
//!   name, only while the boot binds GitHub's hosts, which is while its seed
//!   carries GitHub's placeholder (#4001). `SSL_CERT_DIR` then names the
//!   image's own certificate directory and this one
//!   ([`GITHUB_TRUST_ENVIRONMENT`]), so `gh` adds the CA to its roots and
//!   replaces nothing, and a root the user adds after boot is still trusted.
//!
//! Nothing is mounted over the image's own trust store and its layer is
//! never written, so `update-ca-certificates` in the workspace keeps working
//! and the sealed container configuration does not change with the CA. An
//! image without a system bundle gets the CA alone in the bundle.
//!
//! The image's bundle is read through the merged root with every path
//! component resolved inside it, so a symlink in the image can never make
//! PID 1 copy one of the guest's own files into the bundle.
//!
//! Without a CA in the seed nothing is published: the boot is exactly as
//! before interception existed. A restored boot publishes from its own seed
//! before the workspace thaws, and removes the files when it has no CA.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

use crate::EgressCaCertificate;

/// The image's system bundle, relative to its root.
const IMAGE_TRUST_BUNDLE_RELATIVE: &str = "etc/ssl/certs/ca-certificates.crt";
/// The published CA alone, in the control directory.
pub(super) const CONTAINER_EGRESS_CA_PATH: &str = "/run/codewire/container/egress-ca.pem";
/// The same file as the workspace sees it.
pub(crate) const WORKSPACE_EGRESS_CA_PATH: &str = "/run/codewire-host/egress-ca.pem";
/// The published bundle, in the control directory.
pub(super) const CONTAINER_TRUST_BUNDLE_PATH: &str = "/run/codewire/container/ca-certificates.crt";
/// The same bundle as the workspace sees it.
pub(crate) const WORKSPACE_TRUST_BUNDLE_PATH: &str = "/run/codewire-host/ca-certificates.crt";
/// The hashed directory holding the CA alone, in the control directory. The
/// workspace sees it as `/run/codewire-host/egress-ca.d`.
pub(super) const CONTAINER_EGRESS_CA_DIR: &str = "/run/codewire/container/egress-ca.d";
/// What a boot with a CA sets for the workspace, unless the image or the
/// project already sets the name: then that tool does not trust the front
/// door, and its intercepted connections fail their TLS handshake.
pub(crate) const TRUST_ENVIRONMENT: [(&str, &str); 1] =
    [("NODE_EXTRA_CA_CERTS", WORKSPACE_EGRESS_CA_PATH)];
/// What a boot with a CA also sets while the Codex client is selected, on
/// the same terms.
pub(crate) const CODEX_TRUST_ENVIRONMENT: [(&str, &str); 1] =
    [("CODEX_CA_CERTIFICATE", WORKSPACE_TRUST_BUNDLE_PATH)];
/// What a boot with a CA also sets while it binds GitHub's hosts, on the
/// same terms: the image's own certificate directory first, then the CA's.
/// Only this environment variable is kept when set; Git's setting is the
/// projection's, which a `GIT_SSL_CAINFO` the image or project sets
/// replaces (logged).
pub(crate) const GITHUB_TRUST_ENVIRONMENT: [(&str, &str); 1] = [(
    "SSL_CERT_DIR",
    "/etc/ssl/certs:/run/codewire-host/egress-ca.d",
)];
/// A system bundle is a few hundred KiB; anything far larger is not one.
const MAX_IMAGE_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
const PUBLISHED_MODE: u32 = 0o444;

const RESOLVE_IN_IMAGE: ResolveFlags = ResolveFlags::IN_ROOT
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

/// This boot's active plan with [`TRUST_ENVIRONMENT`] when it has a CA,
/// [`CODEX_TRUST_ENVIRONMENT`] too while `clients` holds Codex, and
/// [`GITHUB_TRUST_ENVIRONMENT`] while the boot binds GitHub's hosts.
pub(super) fn with_trust_environment(
    plan: crate::workspace_plan::WorkspacePlan,
    certificate: Option<&EgressCaCertificate>,
    clients: ManagedCredentialClients,
    github: bool,
) -> Result<crate::workspace_plan::WorkspacePlan> {
    if certificate.is_none() {
        return Ok(plan);
    }
    let codex: &[(&str, &str)] = if clients.contains(ManagedCredentialClient::Codex) {
        &CODEX_TRUST_ENVIRONMENT
    } else {
        &[]
    };
    let github_environment: &[(&str, &str)] = if github {
        &GITHUB_TRUST_ENVIRONMENT
    } else {
        &[]
    };
    let (plan, kept) = plan
        .with_environment_defaults(
            &[TRUST_ENVIRONMENT.as_slice(), codex, github_environment].concat(),
        )
        .context("point the workspace at the egress CA")?;
    for name in kept {
        eprintln!(
            "codewire guest: the image or project sets {name}, so it is kept and that tool does not trust the egress front door"
        );
    }
    // Git reads this variable after its configuration, so it replaces the
    // projection's `sslCAInfo` for GitHub too.
    if github
        && plan
            .environment
            .iter()
            .any(|entry| entry.starts_with("GIT_SSL_CAINFO="))
    {
        eprintln!(
            "codewire guest: the image or project sets GIT_SSL_CAINFO, so Git does not trust the egress front door"
        );
    }
    Ok(plan)
}

/// Publish this boot's trust files from its seed's certificate and the
/// image at `merged_root`, or remove them when the boot has no CA. Runs
/// before the workspace starts and, on a restore, before it thaws.
pub(super) fn publish(seed: &crate::Seed, merged_root: &Path) -> Result<()> {
    let certificate = seed.egress_ca();
    publish_ca_directory(
        Path::new(CONTAINER_EGRESS_CA_DIR),
        certificate.filter(|_| super::interception::binds_github(seed)),
    )?;
    let Some(certificate) = certificate else {
        for path in [CONTAINER_EGRESS_CA_PATH, CONTAINER_TRUST_BUNDLE_PATH] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).with_context(|| format!("remove {path}")),
            }
        }
        return Ok(());
    };
    let pem = certificate.to_pem();
    super::write_durable(
        Path::new(CONTAINER_EGRESS_CA_PATH),
        pem.as_bytes(),
        PUBLISHED_MODE,
    )
    .context("publish the egress CA")?;
    super::write_durable(
        Path::new(CONTAINER_TRUST_BUNDLE_PATH),
        &bundle(image_bundle(merged_root), &pem),
        PUBLISHED_MODE,
    )
    .context("publish the workspace trust bundle")
}

/// Replace `directory` with one holding `certificate` alone as
/// `<subject-hash>.0`, or remove it without one. The directory is PID 1's
/// own: it holds nothing else, and a symlink in its place is removed, never
/// followed.
fn publish_ca_directory(directory: &Path, certificate: Option<&EgressCaCertificate>) -> Result<()> {
    match std::fs::remove_dir_all(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove {}", directory.display())),
    }
    let Some(certificate) = certificate else {
        return Ok(());
    };
    let hash = certificate
        .subject_hash()
        .context("name the egress CA by its subject hash")?;
    super::create_dir(directory, 0o755)?;
    super::write_durable(
        &directory.join(format!("{hash}.0")),
        certificate.to_pem().as_bytes(),
        PUBLISHED_MODE,
    )
    .context("publish the hashed egress CA")
}

/// The comment-only CA file of a hosted Sandbox without interception: a
/// launch never names it, and Node loads it silently if a workload does.
const HOSTED_NO_CA: &[u8] = b"# This Sandbox's egress is not intercepted; it has no egress CA.\n";

/// Install a hosted daemon's trust from its first egress session (#6072),
/// before the daemon serves: `ca_path` holds the CA alone, and `bundle_path`
/// the image's own system bundle (this container's, read under `/`)
/// followed by the CA. Without a CA, `ca_path` holds a comment and
/// `bundle_path` is removed. An error means the daemon must not serve.
pub fn publish_hosted(
    certificate: Option<&EgressCaCertificate>,
    ca_path: &Path,
    bundle_path: &Path,
) -> Result<()> {
    for path in [ca_path, bundle_path] {
        let parent = path
            .parent()
            .with_context(|| format!("{} has no parent", path.display()))?;
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let Some(certificate) = certificate else {
        match std::fs::remove_file(bundle_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", bundle_path.display()));
            }
        }
        return super::write_durable(ca_path, HOSTED_NO_CA, PUBLISHED_MODE)
            .context("write the hosted egress trust");
    };
    let pem = certificate.to_pem();
    super::write_durable(
        bundle_path,
        &bundle(image_bundle(Path::new("/")), &pem),
        PUBLISHED_MODE,
    )
    .context("write the hosted trust bundle")?;
    super::write_durable(ca_path, pem.as_bytes(), PUBLISHED_MODE)
        .context("write the hosted egress CA")
}

/// The image's bundle, then the CA.
fn bundle(image: Option<Vec<u8>>, ca_pem: &str) -> Vec<u8> {
    let mut bundle = image.unwrap_or_default();
    if !bundle.is_empty() && !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(ca_pem.as_bytes());
    bundle
}

/// The image's system bundle, or `None` when it has none that can be used.
fn image_bundle(merged_root: &Path) -> Option<Vec<u8>> {
    match read_image_bundle(merged_root) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!(
                "codewire guest: the image's trust bundle is unusable ({error}); the workspace trusts only the egress CA"
            );
            None
        }
    }
}

fn read_image_bundle(merged_root: &Path) -> io::Result<Option<Vec<u8>>> {
    let root = File::open(merged_root)?;
    // A path descriptor first: nothing the image put there, such as a device
    // or a FIFO, is opened before it is known to be a regular file.
    let path = match openat2(
        &root,
        IMAGE_TRUST_BUNDLE_RELATIVE,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_IN_IMAGE,
    ) {
        Ok(path) => path,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let stat = rustix::fs::fstat(&path)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || u64::try_from(stat.st_size).map_or(true, |size| size > MAX_IMAGE_BUNDLE_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file of bounded size",
        ));
    }
    // Reopen that same file, already resolved inside the image, to read it.
    let file = File::open(format!("/proc/self/fd/{}", path.as_raw_fd()))?;
    let mut bundle = Vec::new();
    file.take(MAX_IMAGE_BUNDLE_BYTES).read_to_end(&mut bundle)?;
    Ok(Some(bundle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate() -> EgressCaCertificate {
        let ca =
            codewire_egress_front_door::EnvironmentCa::generate(["api.anthropic.com"]).unwrap();
        EgressCaCertificate::from_der(ca.certificate_der().to_vec()).unwrap()
    }

    fn image_with(bundle: Option<&[u8]>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        if let Some(bundle) = bundle {
            std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
            std::fs::write(root.path().join(IMAGE_TRUST_BUNDLE_RELATIVE), bundle).unwrap();
        }
        root
    }

    fn codex() -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(["codex"]).unwrap()
    }

    fn environment_of(plan: &crate::workspace_plan::WorkspacePlan, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        plan.environment
            .iter()
            .find_map(|entry| entry.strip_prefix(&prefix).map(str::to_owned))
    }

    #[test]
    fn a_boot_with_a_ca_points_node_at_it_and_nothing_else() {
        let plain = super::super::tests::test_workspace_plan();
        let plan = with_trust_environment(
            plain.clone(),
            Some(&certificate()),
            ManagedCredentialClients::default(),
            false,
        )
        .unwrap();
        assert_eq!(
            environment_of(&plan, "NODE_EXTRA_CA_CERTS").as_deref(),
            Some(WORKSPACE_EGRESS_CA_PATH)
        );
        for replaced_store in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "CODEX_CA_CERTIFICATE",
            "SSL_CERT_DIR",
        ] {
            assert_eq!(
                environment_of(&plan, replaced_store),
                None,
                "{replaced_store}"
            );
        }
        assert_eq!(plan.environment.len(), plain.environment.len() + 1);
    }

    #[test]
    fn a_boot_without_a_ca_keeps_the_plan_unchanged() {
        let plain = super::super::tests::test_workspace_plan();
        let plan = with_trust_environment(plain.clone(), None, codex(), true).unwrap();
        assert_eq!(plan.environment, plain.environment);
    }

    #[test]
    fn a_boot_with_a_ca_and_codex_points_codex_at_the_bundle() {
        let plain = super::super::tests::test_workspace_plan();
        let plan =
            with_trust_environment(plain.clone(), Some(&certificate()), codex(), false).unwrap();
        assert_eq!(
            environment_of(&plan, "CODEX_CA_CERTIFICATE").as_deref(),
            Some(WORKSPACE_TRUST_BUNDLE_PATH)
        );
        assert_eq!(
            environment_of(&plan, "NODE_EXTRA_CA_CERTS").as_deref(),
            Some(WORKSPACE_EGRESS_CA_PATH)
        );
        assert_eq!(plan.environment.len(), plain.environment.len() + 2);
    }

    /// While the boot binds GitHub's hosts, `SSL_CERT_DIR` names the image's
    /// own directory, then the CA's; an image or project value is kept.
    #[test]
    fn a_boot_binding_github_adds_the_ca_directory_after_the_images() {
        let plain = super::super::tests::test_workspace_plan();
        let plan = with_trust_environment(
            plain.clone(),
            Some(&certificate()),
            ManagedCredentialClients::default(),
            true,
        )
        .unwrap();
        assert_eq!(
            environment_of(&plan, "SSL_CERT_DIR").as_deref(),
            Some("/etc/ssl/certs:/run/codewire-host/egress-ca.d")
        );
        assert_eq!(environment_of(&plan, "SSL_CERT_FILE"), None);
        assert_eq!(plan.environment.len(), plain.environment.len() + 2);
        let mut image = plain;
        image
            .environment
            .push("SSL_CERT_DIR=/opt/corp-certs".to_owned());
        let plan = with_trust_environment(
            image,
            Some(&certificate()),
            ManagedCredentialClients::default(),
            true,
        )
        .unwrap();
        assert_eq!(
            environment_of(&plan, "SSL_CERT_DIR").as_deref(),
            Some("/opt/corp-certs")
        );
    }

    /// The directory holds the CA alone under its subject hash, replaced at
    /// each publish and removed without a CA; a symlink in its place is
    /// removed, never followed.
    #[test]
    fn the_ca_directory_holds_the_ca_alone_under_its_subject_hash() {
        use std::os::unix::fs::PermissionsExt as _;
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("egress-ca.d");
        let certificate = certificate();
        let name = format!("{}.0", certificate.subject_hash().unwrap());
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("stale.0"), b"earlier boot").unwrap();
        publish_ca_directory(&directory, Some(&certificate)).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from(&name)]);
        let file = directory.join(&name);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            certificate.to_pem()
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            PUBLISHED_MODE
        );

        publish_ca_directory(&directory, None).unwrap();
        assert!(std::fs::symlink_metadata(&directory).is_err());
        publish_ca_directory(&directory, None).unwrap();

        let outside = temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, &directory).unwrap();
        publish_ca_directory(&directory, Some(&certificate)).unwrap();
        assert!(std::fs::symlink_metadata(&directory).unwrap().is_dir());
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"outside");
    }

    #[test]
    fn the_workspace_paths_are_the_published_files_under_run_codewire_host() {
        let (_, github_ca_dir) = GITHUB_TRUST_ENVIRONMENT[0].1.split_once(':').unwrap();
        for (container, workspace) in [
            (CONTAINER_EGRESS_CA_PATH, WORKSPACE_EGRESS_CA_PATH),
            (CONTAINER_TRUST_BUNDLE_PATH, WORKSPACE_TRUST_BUNDLE_PATH),
            (CONTAINER_EGRESS_CA_DIR, github_ca_dir),
        ] {
            assert_eq!(
                Path::new(container).file_name(),
                Path::new(workspace).file_name()
            );
            assert!(workspace.starts_with("/run/codewire-host/"));
        }
    }

    #[test]
    fn an_image_value_is_kept() {
        let mut image = super::super::tests::test_workspace_plan();
        image
            .environment
            .push("NODE_EXTRA_CA_CERTS=/opt/corp.pem".to_owned());
        image
            .environment
            .push("CODEX_CA_CERTIFICATE=/opt/corp-bundle.pem".to_owned());
        let plan = with_trust_environment(image, Some(&certificate()), codex(), false).unwrap();
        assert_eq!(
            environment_of(&plan, "NODE_EXTRA_CA_CERTS").as_deref(),
            Some("/opt/corp.pem")
        );
        assert_eq!(
            environment_of(&plan, "CODEX_CA_CERTIFICATE").as_deref(),
            Some("/opt/corp-bundle.pem")
        );
    }

    #[test]
    fn the_bundle_is_the_image_roots_then_the_ca() {
        let pem = certificate().to_pem();
        let image = image_with(Some(
            b"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
        ));
        let bundle = bundle(image_bundle(image.path()), &pem);
        let text = String::from_utf8(bundle).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\nroot\n"));
        assert!(text.ends_with(&pem));
        assert_eq!(text.matches("BEGIN CERTIFICATE").count(), 2);
    }

    #[test]
    fn an_image_without_a_bundle_trusts_only_the_ca() {
        let pem = certificate().to_pem();
        let image = image_with(None);
        assert_eq!(image_bundle(image.path()), None);
        assert_eq!(bundle(image_bundle(image.path()), &pem), pem.as_bytes());
    }

    #[test]
    fn a_symlink_out_of_the_image_reads_inside_it_never_the_guest() {
        // An absolute link resolves against the image root, not PID 1's.
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"guest-only").unwrap();
        let image = image_with(None);
        std::fs::create_dir_all(image.path().join("etc/ssl/certs")).unwrap();
        std::os::unix::fs::symlink(&secret, image.path().join(IMAGE_TRUST_BUNDLE_RELATIVE))
            .unwrap();
        assert_eq!(read_image_bundle(image.path()).unwrap(), None);

        let relative = image_with(None);
        std::fs::create_dir_all(relative.path().join("etc/ssl/certs")).unwrap();
        std::os::unix::fs::symlink(
            "../../../../../../../../..".to_owned() + secret.to_str().unwrap(),
            relative.path().join(IMAGE_TRUST_BUNDLE_RELATIVE),
        )
        .unwrap();
        assert_eq!(read_image_bundle(relative.path()).unwrap(), None);
    }

    #[test]
    fn a_link_inside_the_image_is_followed() {
        let image = image_with(None);
        std::fs::create_dir_all(image.path().join("etc/ssl/certs")).unwrap();
        std::fs::write(image.path().join("etc/ssl/real.pem"), b"roots").unwrap();
        std::os::unix::fs::symlink(
            "/etc/ssl/real.pem",
            image.path().join(IMAGE_TRUST_BUNDLE_RELATIVE),
        )
        .unwrap();
        assert_eq!(
            read_image_bundle(image.path()).unwrap(),
            Some(b"roots".to_vec())
        );
    }

    #[test]
    fn a_fifo_in_place_of_the_bundle_is_never_opened_for_reading() {
        let image = image_with(None);
        std::fs::create_dir_all(image.path().join("etc/ssl/certs")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            image.path().join(IMAGE_TRUST_BUNDLE_RELATIVE),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        // Reading a FIFO with no writer would block; this returns at once.
        assert!(read_image_bundle(image.path()).is_err());
    }

    #[test]
    fn a_directory_in_place_of_the_bundle_is_unusable() {
        let image = image_with(None);
        std::fs::create_dir_all(image.path().join(IMAGE_TRUST_BUNDLE_RELATIVE)).unwrap();
        assert_eq!(image_bundle(image.path()), None);
    }
}
