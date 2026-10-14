//! Trusted host composition only. No environment/credential RPC controls tool
//! paths, helper contents or runtime staging, and no ambient agent is imported.
//!
//! Linux stages each signature's agent on the allowlisted XDG_RUNTIME_DIR
//! tmpfs. macOS has no per-user tmpfs; it stages in `signer` inside the
//! authority's short socket directory, where each agent's directory holds only its socket and
//! the passphrase FIFO (the key reaches ssh-add on stdin), and supplies the
//! Darwin child preparation and FIFO primitives the signer cannot implement.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use codewire_credential_broker::provider_enrollment::validate_private_directory;
#[cfg(target_os = "macos")]
use codewire_credential_broker::ssh_agent::DarwinProcessPrimitives;
use codewire_credential_broker::ssh_agent::{SshAgentConfig, SshAgentError, SshAgentOwner};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_local_credentials::{LocalSshSignError, LocalSshSignRequest, LocalSshSigner};
use codewire_protected_store::ssh_material::SshAgentMaterial;
use sha2::{Digest, Sha256};
use tokio::sync::{OnceCell, watch};
use tokio::time::Instant;

pub(super) struct LocalSshAgentAdapter {
    authority_root: PathBuf,
    /// The authority's short socket directory, where macOS stages each
    /// agent (#2745).
    #[cfg(target_os = "macos")]
    socket_dir: PathBuf,
    #[cfg(target_os = "linux")]
    runtime: Option<PathBuf>,
    owner: OnceCell<Arc<SshAgentOwner>>,
}

impl LocalSshAgentAdapter {
    pub(super) fn new(authority_root: PathBuf, socket_dir: PathBuf) -> Self {
        #[cfg(not(target_os = "macos"))]
        let _ = socket_dir;
        Self {
            authority_root,
            #[cfg(target_os = "macos")]
            socket_dir,
            // This is the already-allowlisted host runtime path, not provider
            // authentication or a workload-controlled environment override.
            #[cfg(target_os = "linux")]
            runtime: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            owner: OnceCell::new(),
        }
    }

    async fn owner(&self) -> Result<&Arc<SshAgentOwner>, LocalSshSignError> {
        self.owner
            .get_or_try_init(|| async {
                let root = self.authority_root.clone();
                #[cfg(target_os = "linux")]
                let runtime = self.runtime.clone().ok_or(LocalSshSignError::Unavailable)?;
                #[cfg(target_os = "macos")]
                let socket_dir = self.socket_dir.clone();
                // Retained by the authority's operation task through this join;
                // dropping its RPC waiter never abandons helper initialization.
                let config = tokio::task::spawn_blocking(move || {
                    let helper = install_public_askpass(&root)?;
                    #[cfg(target_os = "linux")]
                    let config = SshAgentConfig::new(
                        runtime,
                        "/usr/bin/ssh-agent".into(),
                        "/usr/bin/ssh-add".into(),
                        helper,
                    );
                    #[cfg(target_os = "macos")]
                    let config = SshAgentConfig::new(
                        darwin::signer_runtime(&socket_dir)?,
                        "/usr/bin/ssh-agent".into(),
                        "/usr/bin/ssh-add".into(),
                        helper,
                        DarwinProcessPrimitives {
                            prepare_child: darwin::prepare_openssh_child,
                            make_fifo: darwin::make_private_fifo,
                        },
                    );
                    config.map_err(map_error)
                })
                .await
                .map_err(|_| LocalSshSignError::Unavailable)??;
                Ok(Arc::new(SshAgentOwner::new(config)))
            })
            .await
    }

    pub(super) async fn shutdown(&self) -> Result<(), LocalSshSignError> {
        match self.owner.get() {
            Some(owner) => owner.shutdown().await.map_err(map_error),
            None => Ok(()),
        }
    }
}

#[tonic::async_trait]
impl LocalSshSigner for LocalSshAgentAdapter {
    async fn sign_once(
        &self,
        material: SshAgentMaterial,
        request: LocalSshSignRequest,
        deadline: Instant,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<Vec<u8>, LocalSshSignError> {
        if *cancellation.borrow() || deadline <= Instant::now() {
            return Err(LocalSshSignError::Expired);
        }
        let owner = self.owner().await?;
        codewire_credential_broker::ssh_agent::sign_once(
            owner,
            material,
            v1::CredentialSshSignRequest {
                public_key_blob: request.public_key_blob,
                data: request.data.to_vec(),
                flags: request.flags,
            },
            deadline,
            async move {
                loop {
                    if *cancellation.borrow() || cancellation.changed().await.is_err() {
                        break;
                    }
                }
            },
        )
        .await
        .map_err(map_error)
    }
}

fn map_error(error: SshAgentError) -> LocalSshSignError {
    match error {
        SshAgentError::Denied => LocalSshSignError::Denied,
        SshAgentError::Expired | SshAgentError::Cancelled => LocalSshSignError::Expired,
        SshAgentError::Cleanup => LocalSshSignError::Cleanup,
        _ => LocalSshSignError::Unavailable,
    }
}

fn install_public_askpass(root: &Path) -> Result<PathBuf, LocalSshSignError> {
    validate_private_directory(root).map_err(|_| LocalSshSignError::Unavailable)?;
    let script = codewire_credential_broker::ssh_agent::askpass_script();
    // Content-addressed public executable, not a credential generation/store.
    // Atomic no-clobber publication preserves any existing owner-created file;
    // SshAgentConfig then validates exact bytes, links, owners and permissions.
    let target = root.join(format!("ssh-askpass-{:x}", Sha256::digest(script)));
    let mut staged = tempfile::Builder::new()
        .prefix(".ssh-askpass-")
        .tempfile_in(root)
        .map_err(|_| LocalSshSignError::Unavailable)?;
    staged
        .write_all(script)
        .map_err(|_| LocalSshSignError::Unavailable)?;
    staged
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|_| LocalSshSignError::Unavailable)?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| LocalSshSignError::Unavailable)?;
    match staged.persist_noclobber(&target) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(LocalSshSignError::Unavailable),
    }
    Ok(target)
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};

    use codewire_credential_broker::provider_enrollment::validate_private_directory;
    use codewire_local_credentials::LocalSshSignError;

    /// The signer's private staging root inside the authority's short socket
    /// directory, so each agent socket fits Darwin's bound for any HOME.
    pub(super) fn signer_runtime(socket_dir: &Path) -> Result<PathBuf, LocalSshSignError> {
        let runtime = socket_dir.join("signer");
        match std::fs::DirBuilder::new().mode(0o700).create(&runtime) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(LocalSshSignError::Unavailable),
        }
        validate_private_directory(&runtime).map_err(|_| LocalSshSignError::Unavailable)?;
        Ok(runtime)
    }

    /// ssh-agent and ssh-add start holding only their standard descriptors.
    /// The authority is multi-threaded, and Darwin sets close-on-exec in a
    /// second call for some descriptors, so mark every inherited one first.
    pub(super) fn prepare_openssh_child(command: &mut tokio::process::Command) {
        // SAFETY: the hook runs between fork and exec and makes only
        // getdtablesize and fcntl calls.
        unsafe {
            command.pre_exec(|| {
                codewire_local_vmm::darwin::process::mark_inherited_descriptors_close_on_exec();
                Ok(())
            });
        }
    }

    /// One owner-only FIFO at exactly `path`; it fails if anything exists.
    pub(super) fn make_private_fifo(path: &Path) -> std::io::Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: the path is NUL-terminated and outlives the call.
        if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn askpass_is_public_immutable_and_atomically_reused_without_changing_existing_files() {
        let root = root();
        let helper = install_public_askpass(root.path()).unwrap();
        let before = std::fs::metadata(&helper).unwrap();
        assert_eq!(before.permissions().mode() & 0o777, 0o500);
        assert_eq!(before.nlink(), 1);
        assert_eq!(
            std::fs::read(&helper).unwrap(),
            codewire_credential_broker::ssh_agent::askpass_script()
        );
        assert_eq!(install_public_askpass(root.path()).unwrap(), helper);
        assert_eq!(std::fs::metadata(&helper).unwrap().ino(), before.ino());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conflicting_public_helper_is_preserved_and_configuration_rejects_it() {
        let root = root();
        let script = codewire_credential_broker::ssh_agent::askpass_script();
        let helper = root
            .path()
            .join(format!("ssh-askpass-{:x}", Sha256::digest(script)));
        std::fs::write(&helper, b"owner-created file").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(install_public_askpass(root.path()).unwrap(), helper);
        assert_eq!(std::fs::read(&helper).unwrap(), b"owner-created file");
        let runtime = tempfile::tempdir_in("/dev/shm").unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            SshAgentConfig::new(
                runtime.path().into(),
                "/usr/bin/ssh-agent".into(),
                "/usr/bin/ssh-add".into(),
                helper
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn unused_signer_touches_no_runtime_tools_or_helper_files() {
        let root = root();
        let adapter = LocalSshAgentAdapter {
            authority_root: root.path().into(),
            #[cfg(target_os = "linux")]
            runtime: None,
            owner: OnceCell::new(),
        };
        adapter.shutdown().await.unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_fifo_is_owner_only_and_never_replaces_an_existing_path() {
        use std::os::unix::fs::FileTypeExt as _;

        let root = root();
        let fifo = root.path().join("askpass.fifo");
        darwin::make_private_fifo(&fifo).unwrap();
        let metadata = std::fs::symlink_metadata(&fifo).unwrap();
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(darwin::make_private_fifo(&fifo).is_err());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_openssh_children_inherit_only_standard_descriptors() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

        let source = std::fs::File::open("/dev/null").unwrap();
        // F_DUPFD clears close-on-exec; 64 keeps the probe off any descriptor
        // a test runner thread might reuse meanwhile.
        // SAFETY: duplicates a descriptor this test owns.
        let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(raw >= 64);
        // SAFETY: `raw` is a fresh descriptor nothing else owns.
        let leaked = unsafe { OwnedFd::from_raw_fd(raw) };
        let probe = |prepare: bool| {
            let mut command = tokio::process::Command::new("/bin/test");
            command.args(["-e", &format!("/dev/fd/{}", leaked.as_raw_fd())]);
            if prepare {
                darwin::prepare_openssh_child(&mut command);
            }
            command
        };
        assert!(probe(false).status().await.unwrap().success());
        assert!(!probe(true).status().await.unwrap().success());
    }

    /// The composed macOS signer signs with Apple's tools through the
    /// credential root's `signer` staging, which is empty again afterwards.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn darwin_composed_signer_signs_once_and_leaves_no_staging() {
        use codewire_protected_store::ssh_material::{decode_protected_material, generate_ed25519};

        // A short root keeps the agent socket under Darwin's 104-byte bound.
        let root = tempfile::Builder::new()
            .prefix("cw-signer-")
            .tempdir_in("/private/tmp")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let authority_root = std::fs::canonicalize(root.path()).unwrap();
        let adapter = LocalSshAgentAdapter::new(authority_root.clone());
        let (_, protected) = generate_ed25519().unwrap().into_parts();
        let material = decode_protected_material(protected).unwrap();
        let blob = material.public_key().key_blob().to_vec();
        let (_cancel, cancellation) = watch::channel(false);
        let signature = adapter
            .sign_once(
                material,
                LocalSshSignRequest {
                    public_key_blob: blob,
                    data: zeroize::Zeroizing::new(b"synthetic macOS signer challenge".to_vec()),
                    flags: 0,
                },
                Instant::now() + std::time::Duration::from_secs(30),
                cancellation,
            )
            .await
            .unwrap();
        assert!(!signature.is_empty());
        adapter.shutdown().await.unwrap();
        let signer = authority_root.join("signer");
        assert_eq!(
            std::fs::symlink_metadata(&signer).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(std::fs::read_dir(signer).unwrap().count(), 0);
    }
}
