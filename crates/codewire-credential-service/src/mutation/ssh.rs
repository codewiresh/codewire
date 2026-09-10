//! Create-only SSH preparation under the existing mutation owner's lifetime.

use codewire_access::CredentialMetadata;
use codewire_protected_store::ssh_material::{
    MAX_OPENSSH_PRIVATE_KEY_BYTES, MAX_SSH_PASSPHRASE_BYTES, PreparedSshCredential,
    SshMaterialError, generate_ed25519, import_openssh,
};
use codewire_server_core::auth::CredentialMutationAuthority;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::{CredentialMutationOwner, Error, Scope, publication, unix_now, validate_name};

const SSH_PREPARATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// No Debug or Clone: even rejected imports keep their buffers zeroizing.
pub(super) enum Input {
    Generate,
    Import {
        private_key: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    },
}

impl Input {
    fn validate(&self) -> Result<(), Error> {
        if let Self::Import {
            private_key,
            passphrase,
        } = self
            && (private_key.is_empty()
                || private_key.len() > MAX_OPENSSH_PRIVATE_KEY_BYTES
                || passphrase.as_ref().is_some_and(|value| {
                    value.is_empty()
                        || value.len() > MAX_SSH_PASSPHRASE_BYTES
                        || value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
                }))
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn prepare(self) -> Result<PreparedSshCredential, SshMaterialError> {
        match self {
            Self::Generate => generate_ed25519(),
            Self::Import {
                private_key,
                passphrase,
            } => import_openssh(private_key, passphrase),
        }
    }
}

impl CredentialMutationOwner {
    pub(super) async fn add_ssh(
        &self,
        authority: CredentialMutationAuthority,
        name: String,
        expires_at_unix: Option<u64>,
        input: Input,
    ) -> Result<CredentialMetadata, Error> {
        validate_name(&name)?;
        validate_expiry(expires_at_unix, unix_now()?)?;
        input.validate()?;
        let scope = Scope::new(authority, self.stop.child_token(), SSH_PREPARATION_TIMEOUT)?;
        let deadline = scope.deadline;
        let cancelled = scope.cancel.clone();
        let _guard = cancelled.clone().drop_guard();
        let (sender, receiver) = oneshot::channel();
        {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            let permit = self.admit(*accepting)?;
            let shared = self.shared.clone();
            self.workers.spawn(async move {
                // This tracked driver is never aborted. It retains admission
                // until crypto has actually joined and publication has drained.
                let _permit = permit;
                let result = async {
                    scope.check()?;
                    let prepared =
                        prepare_retained(&scope.cancel, scope.deadline, move || input.prepare())
                            .await?;
                    scope.check()?;
                    publication::add_ssh(&shared, &scope, name, expires_at_unix, prepared).await
                }
                .await;
                let _ = sender.send(result);
            });
        }
        tokio::select! {
            biased;
            _ = cancelled.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::PublicationUnknown),
            result = receiver => result.map_err(|_| Error::PublicationUnknown)?,
        }
    }
}

fn validate_expiry(expiry: Option<u64>, now: u64) -> Result<(), Error> {
    if expiry.is_some_and(|value| value <= now || value > i64::MAX as u64) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

/// Cancellation revokes publication, not ownership of CPU work. In particular,
/// passing a bare JoinHandle to Scope::wait would detach the worker on timeout.
/// Cleanup may outlast the original deadline; it never renews authority.
async fn prepare_retained(
    cancel: &CancellationToken,
    deadline: Instant,
    operation: impl FnOnce() -> Result<PreparedSshCredential, SshMaterialError> + Send + 'static,
) -> Result<PreparedSshCredential, Error> {
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Error::Expired);
    }
    let mut worker = tokio::task::spawn_blocking(operation);
    let cancelled = tokio::select! {
        biased;
        _ = cancel.cancelled() => Error::Cancelled,
        _ = tokio::time::sleep_until(deadline) => Error::Expired,
        result = &mut worker => {
            // A ready join can win before the timer's rounded wakeup even
            // though the original deadline has passed. Joining proves cleanup
            // ownership, not authority to release the prepared material.
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            return result.map_err(|_| Error::Unavailable)?.map_err(material_error);
        },
    };
    // Consume every result, including a successful private key prepared after
    // cancellation. Its material is destroyed without wrapping or publication.
    drop(worker.await);
    Err(cancelled)
}

fn material_error(error: SshMaterialError) -> Error {
    match error {
        SshMaterialError::EntropyUnavailable => Error::Unavailable,
        _ => Error::InvalidInput,
    }
}

#[cfg(test)]
mod tests;
