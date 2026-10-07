//! Trusted host composition only. No environment/credential RPC controls tool
//! paths, helper contents or runtime staging, and no ambient agent is imported.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use codewire_credential_broker::provider_enrollment::validate_private_directory;
use codewire_credential_broker::ssh_agent::{SshAgentConfig, SshAgentError, SshAgentOwner};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_local_credentials::{LocalSshSignError, LocalSshSignRequest, LocalSshSigner};
use codewire_protected_store::ssh_material::SshAgentMaterial;
use sha2::{Digest, Sha256};
use tokio::sync::{OnceCell, watch};
use tokio::time::Instant;

pub(super) struct LocalSshAgentAdapter {
    authority_root: PathBuf,
    runtime: Option<PathBuf>,
    owner: OnceCell<Arc<SshAgentOwner>>,
}

impl LocalSshAgentAdapter {
    pub(super) fn new(authority_root: PathBuf) -> Self {
        Self {
            authority_root,
            // This is the already-allowlisted host runtime path, not provider
            // authentication or a workload-controlled environment override.
            runtime: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            owner: OnceCell::new(),
        }
    }

    async fn owner(&self) -> Result<&Arc<SshAgentOwner>, LocalSshSignError> {
        self.owner
            .get_or_try_init(|| async {
                let root = self.authority_root.clone();
                let runtime = self.runtime.clone().ok_or(LocalSshSignError::Unavailable)?;
                // Retained by the authority's operation task through this join;
                // dropping its RPC waiter never abandons helper initialization.
                let config = tokio::task::spawn_blocking(move || {
                    let helper = install_public_askpass(&root)?;
                    SshAgentConfig::new(
                        runtime,
                        "/usr/bin/ssh-agent".into(),
                        "/usr/bin/ssh-add".into(),
                        helper,
                    )
                    .map_err(map_error)
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
            runtime: None,
            owner: OnceCell::new(),
        };
        adapter.shutdown().await.unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
