//! Named lifecycle operations under the existing owned publication driver.

use super::*;

pub(super) enum Update {
    Rename {
        expected_name: String,
        name: String,
    },
    Rotate {
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
    },
}

impl CredentialMutationOwner {
    pub(super) async fn update(
        &self,
        authority: CredentialMutationAuthority,
        id: String,
        revision: u64,
        update: Update,
    ) -> Result<CredentialMetadata, Error> {
        let id = CredentialId::parse(id).map_err(|_| Error::InvalidInput)?;
        if revision == 0 || i64::try_from(revision).is_err() {
            return Err(Error::InvalidInput);
        }
        match &update {
            Update::Rename {
                expected_name,
                name,
            } => {
                validate_name(expected_name)?;
                validate_name(name)?;
            }
            Update::Rotate {
                material,
                expires_at_unix,
            } => {
                if material.expose_secret().len() > 1024
                    || expires_at_unix.is_some_and(|expiry| expiry > i64::MAX as u64)
                {
                    return Err(Error::InvalidInput);
                }
            }
        }
        let scope = Scope::new(authority, self.stop.child_token(), MUTATION_TIMEOUT)?;
        let deadline = scope.deadline;
        let cancelled = scope.cancel.clone();
        let _guard = cancelled.clone().drop_guard();
        let (sender, receiver) = oneshot::channel();
        {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            let permit = self.admit(*accepting)?;
            let shared = self.shared.clone();
            self.workers.spawn(async move {
                let _permit = permit;
                let result = match update {
                    Update::Rename {
                        expected_name,
                        name,
                    } => {
                        publication::rename(&shared, &scope, id, revision, expected_name, name)
                            .await
                    }
                    Update::Rotate {
                        material,
                        expires_at_unix,
                    } => {
                        publication::rotate_api_key(
                            &shared,
                            &scope,
                            id,
                            revision,
                            material,
                            expires_at_unix,
                        )
                        .await
                    }
                };
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
