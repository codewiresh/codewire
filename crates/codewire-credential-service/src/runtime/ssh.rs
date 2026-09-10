//! Trusted service-image composition of the existing selected-key agent owner.
//! No request can supply executable paths or select another runtime directory.

use std::path::Path;

use super::RuntimeError;
use super::{
    BrokerUpstreamTransport, PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};

pub(super) fn configure<A, U>(
    bridge: PlatformCredentialBridgeService<A, U>,
    runtime: &Path,
) -> Result<PlatformCredentialBridgeService<A, U>, RuntimeError>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    #[cfg(target_os = "linux")]
    {
        bridge
            .with_ssh_agent_owner(std::sync::Arc::new(owner(runtime)?))
            .map_err(|_| RuntimeError::Configuration("SSH agent owner"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bridge, runtime);
        Err(RuntimeError::Configuration("SSH agent requires Linux"))
    }
}

#[cfg(target_os = "linux")]
fn owner(
    runtime: &Path,
) -> Result<codewire_credential_broker::ssh_agent::SshAgentOwner, RuntimeError> {
    use codewire_credential_broker::ssh_agent::{SshAgentConfig, SshAgentOwner};

    let private = private_runtime(runtime)?;
    let config = SshAgentConfig::new(
        private,
        "/usr/bin/ssh-agent".into(),
        "/usr/bin/ssh-add".into(),
        "/usr/local/libexec/codewire/ssh-askpass".into(),
    )
    .map_err(|_| RuntimeError::Configuration("SSH agent tools"))?;
    Ok(SshAgentOwner::new(config))
}

#[cfg(target_os = "linux")]
fn private_runtime(runtime: &Path) -> Result<std::path::PathBuf, RuntimeError> {
    use std::os::unix::fs::DirBuilderExt;

    if std::fs::canonicalize(runtime)
        .map_err(|_| RuntimeError::Configuration("SSH agent runtime"))?
        .as_os_str()
        != runtime.as_os_str()
    {
        return Err(RuntimeError::Configuration("SSH agent runtime"));
    }
    let private = runtime.join("ssh-agent");
    // The admitted memory-volume mount may be root/group owned. Create only
    // our private child; never chmod, replace or recursively create an object.
    match std::fs::DirBuilder::new().mode(0o700).create(&private) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(RuntimeError::Configuration("SSH agent runtime")),
    }
    codewire_credential_broker::provider_enrollment::validate_private_tmpfs_runtime(&private)
        .map_err(|_| RuntimeError::Configuration("SSH agent runtime"))?;
    Ok(private)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    fn memory_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("codewire-service-ssh-")
            .tempdir_in("/dev/shm")
            .unwrap()
    }

    #[test]
    fn private_runtime_creates_and_reuses_only_its_owned_memory_child() {
        let root = memory_root();
        let private = private_runtime(root.path()).unwrap();
        assert_eq!(private, root.path().join("ssh-agent"));
        let before = std::fs::symlink_metadata(&private).unwrap();
        assert_eq!(before.permissions().mode() & 0o777, 0o700);
        assert_eq!(private_runtime(root.path()).unwrap(), private);
        let after = std::fs::symlink_metadata(&private).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    }

    #[test]
    fn private_runtime_preserves_conflicting_file_and_symlink() {
        let root = memory_root();
        let path = root.path().join("ssh-agent");
        std::fs::write(&path, b"synthetic occupied object").unwrap();
        assert!(private_runtime(root.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic occupied object");
        std::fs::remove_file(&path).unwrap();
        let target = memory_root();
        symlink(target.path(), &path).unwrap();
        assert!(private_runtime(root.path()).is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }

    #[test]
    fn private_runtime_does_not_repair_insecure_existing_permissions() {
        let root = memory_root();
        let private = private_runtime(root.path()).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(private_runtime(root.path()).is_err());
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    #[test]
    fn private_runtime_rejects_noncanonical_root_and_missing_parents() {
        let root = memory_root();
        assert!(private_runtime(&root.path().join("absent/parent")).is_err());
        assert!(!root.path().join("absent").exists());
        assert!(private_runtime(&root.path().join(".")).is_err());
    }

    /// Run by the service-image acceptance owner, not ordinary host unit tests.
    /// Proves the packaged loader/tool closure under the actual service UID and
    /// tmpfs layout. It neither enrolls a credential nor contacts a provider.
    #[tokio::test]
    #[ignore = "requires packaged service image, UID65532, read-only root and runtime tmpfs"]
    async fn packaged_agent_signs_and_drains() {
        use codewire_credential_broker::ssh_agent::sign_once;
        use codewire_gateway_proto::codewire::bridge::v1::CredentialSshSignRequest;
        use codewire_protected_store::ssh_material::{
            decode_protected_material, generate_ed25519, import_openssh,
        };

        assert_eq!(std::fs::metadata("/proc/self").unwrap().uid(), 65532);
        let runtime = Path::new("/run/codewire-credentials");
        let owner = owner(runtime).unwrap();
        // Reuse the protected-store's explicitly public synthetic encrypted
        // fixture. The second key exercises packaged askpass and its FIFO.
        let encrypted = import_openssh(
            zeroize::Zeroizing::new(include_bytes!(
                "../../../codewire-protected-store/src/ssh_material/fixtures/ed25519-aes256-ctr.openssh"
            ).to_vec()),
            Some(zeroize::Zeroizing::new(b"codewire-synthetic-passphrase-only".to_vec())),
        ).unwrap();
        let mut results = Vec::new();
        for prepared in [generate_ed25519().unwrap(), encrypted] {
            let (_, protected) = prepared.into_parts();
            let material = decode_protected_material(protected).unwrap();
            let request = CredentialSshSignRequest {
                public_key_blob: material.public_key().key_blob().to_vec(),
                data: b"synthetic service image acceptance".to_vec(),
                flags: 0,
            };
            results.push(
                sign_once(
                    &owner,
                    material,
                    request,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                    std::future::pending(),
                )
                .await,
            );
        }
        let drain = owner.shutdown().await;
        assert_eq!(
            std::fs::read_dir(runtime.join("ssh-agent"))
                .unwrap()
                .count(),
            0
        );
        drain.unwrap();
        for result in results {
            let signature = result.unwrap();
            assert_eq!(signature.len(), 4 + b"ssh-ed25519".len() + 4 + 64);
            assert_eq!(&signature[4..15], b"ssh-ed25519");
        }
    }
}
