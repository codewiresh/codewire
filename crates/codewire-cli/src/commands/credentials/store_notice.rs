//! What `cw credentials --local` says about where a root keeps its
//! credentials (#5255, `docs/dev/SECRETS-AND-CREDENTIALS.md` "Linux file
//! store"): a file store is named as not encrypted by cw, and on Linux a root
//! that isn't the account's own is warned before it writes to the desktop
//! keyring.

use std::path::Path;

use codewire_local_credentials::FILE_STORE_DIRECTORY;
#[cfg(target_os = "linux")]
use codewire_local_credentials::LocalCredentialClient;
#[cfg(target_os = "linux")]
use codewire_protected_store::ProtectedStoreBackend;

#[cfg(target_os = "linux")]
use super::super::CredentialsCommand;
#[cfg(target_os = "linux")]
use super::super::credential_input::CredentialOperation;

/// Said after a local listing whose store is the file store.
pub(super) fn file_store_line(root: &Path) -> String {
    format!(
        "Store: files in {}, not encrypted by cw (protected by file permissions and your disk encryption)",
        root.join(FILE_STORE_DIRECTORY).display()
    )
}

/// Said before a local write that goes to the session keyring from a root
/// that isn't the account's own: a scratch `HOME` doesn't keep it out of the
/// keyring.
#[cfg(target_os = "linux")]
pub(super) fn keyring_warning(
    root: &Path,
    backend: ProtectedStoreBackend,
    account_home: &Path,
) -> Option<String> {
    (backend == ProtectedStoreBackend::SecretService
        && !crate::config::account::is_own_codewire_path(root, account_home, "credentials-v1"))
    .then(|| {
        format!(
            "Saving to your desktop keyring (Secret Service), not inside {}. Set local_credential_store = \"file\" to keep this root's credentials with it.",
            root.display()
        )
    })
}

/// Whether the operation stores new credential material.
#[cfg(target_os = "linux")]
pub(super) fn writes_material(operation: &CredentialOperation) -> bool {
    matches!(
        operation,
        CredentialOperation::GenerateIntoProfile(..)
            | CredentialOperation::Credential(
                CredentialsCommand::Connect(_)
                    | CredentialsCommand::Add(_)
                    | CredentialsCommand::Generate(_)
                    | CredentialsCommand::Rotate(_)
            )
    )
}

/// One stderr line before a scratch root writes to the desktop keyring
/// (#5255). A root, store or home that can't be read says nothing.
#[cfg(target_os = "linux")]
pub(super) fn warn_before_keyring_write(client: &LocalCredentialClient) {
    let Some(store) = client.info().protected_store else {
        return;
    };
    let (Ok(root), Ok(home)) = (
        super::super::local_credential_root(&crate::config::OsEnv),
        crate::config::account::home_directory(),
    ) else {
        return;
    };
    if let Some(warning) = keyring_warning(&root, store.backend, &home) {
        eprintln!("{warning}");
    }
}

#[cfg(test)]
mod tests;
