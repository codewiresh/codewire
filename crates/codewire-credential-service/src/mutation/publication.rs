//! One caller-owned connection from authorization through publication.

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, ProviderId,
};
use codewire_credential_broker::codex_enrollment::{
    CodexPublicationOutcome, CompletedCodexEnrollment,
};
use codewire_platform_credentials::{CredentialRegistration, PreparedCredentialCreation};
use codewire_protected_store::ProtectedValue;
use sqlx::{Acquire, Postgres, Transaction};
use tokio::time::Instant;

use super::{
    Error, MUTATION_TIMEOUT, Scope, Shared, authority_error, enrollment_error, store_error,
};

pub(super) struct Publication<T> {
    pub outcome: CodexPublicationOutcome,
    pub result: Result<T, Error>,
}

enum Mutation {
    Create(Box<PreparedCredentialCreation>),
    Revoke { id: CredentialId, revision: u64 },
    Delete { id: CredentialId, revision: u64 },
}

pub(super) async fn enroll(
    shared: &Shared,
    scope: &Scope,
    completed: &mut CompletedCodexEnrollment,
    name: String,
) -> Publication<CredentialMetadata> {
    let prepared = async {
        scope.check()?;
        let imported = completed.take_import().map_err(enrollment_error)?;
        let (bundle, account_hint) = imported.into_parts();
        let mut bytes = bundle.into_bytes();
        let material = ProtectedValue::new(std::mem::take(&mut *bytes))
            .map_err(|_| Error::EnrollmentFailed)?;
        let registration = CredentialRegistration {
            provider: ProviderId::parse("openai").expect("built-in provider"),
            authentication_kind: CredentialAuthKind::OAuth,
            display_name: name,
            account_hint,
            expires_at_unix: None,
        };
        // All provider/envelope work precedes the identity/publication locks.
        scope
            .wait(
                completed.wait_for_publication(shared.store.prepare_creation(
                    &scope.owner,
                    registration,
                    &material,
                )),
            )
            .await?
            .map_err(enrollment_error)?
            .map_err(store_error)
    }
    .await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Publication {
                outcome: CodexPublicationOutcome::NotPublished,
                result: Err(error),
            };
        }
    };
    let result = publish(
        shared,
        scope,
        Some(completed),
        Mutation::Create(Box::new(prepared)),
    )
    .await;
    Publication {
        outcome: result.outcome,
        result: result
            .result
            .and_then(|metadata| metadata.ok_or(Error::PublicationUnknown)),
    }
}

pub(super) async fn lifecycle(
    shared: &Shared,
    scope: &Scope,
    id: CredentialId,
    revision: u64,
    delete: bool,
) -> Result<Option<CredentialMetadata>, Error> {
    let mutation = if delete {
        Mutation::Delete { id, revision }
    } else {
        Mutation::Revoke { id, revision }
    };
    publish(shared, scope, None, mutation).await.result
}

async fn publish(
    shared: &Shared,
    scope: &Scope,
    completed: Option<&CompletedCodexEnrollment>,
    mutation: Mutation,
) -> Publication<Option<CredentialMetadata>> {
    let deadline = scope.deadline.min(Instant::now() + MUTATION_TIMEOUT);
    let acquired = tokio::time::timeout_at(deadline, scope.wait(shared.pool.acquire())).await;
    let mut connection = match acquired {
        Ok(Ok(Ok(connection))) => connection,
        _ => {
            return Publication {
                outcome: CodexPublicationOutcome::NotPublished,
                result: Err(Error::Unavailable),
            };
        }
    };
    let mut commit_issued = false;
    let result = tokio::time::timeout_at(deadline, async {
        // Borrow from our connection, not pool.begin(): the driver retains the
        // exact connection after a cancelled query/COMMIT future is dropped.
        let mut tx = connection.begin().await.map_err(|_| Error::Unavailable)?;
        let applied = async {
            scope.check()?;
            scope
                .authority
                .lock_for_publication(&mut tx)
                .await
                .map_err(authority_error)?;
            apply(shared, scope, &mut tx, mutation).await
        }
        .await;
        let metadata = match applied {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };
        // There is no await between these final original-authority checks and
        // issuing COMMIT. A cancellation after issuance cannot uncommit it.
        let admitted = scope.check().and_then(|()| {
            if let Some(completed) = completed {
                completed.check_active().map_err(enrollment_error)?;
            }
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            Ok(())
        });
        if let Err(error) = admitted {
            let _ = tx.rollback().await;
            return Err(error);
        }
        commit_issued = true;
        tx.commit().await.map_err(|_| Error::PublicationUnknown)?;
        Ok(metadata)
    })
    .await;
    match result {
        Ok(Ok(metadata)) => Publication {
            outcome: CodexPublicationOutcome::Published,
            result: Ok(metadata),
        },
        result => {
            // SQLx 0.8.6 close_hard() flushes its buffered stream. Do not use
            // it here: a cancelled transaction may have queued COMMIT/ROLLBACK.
            // Detach and drop the raw connection/socket without returning it
            // to the pool or flushing more SQL. This relinquishes local
            // ownership, not an already-issued server COMMIT: PostgreSQL
            // disables statement_timeout before commit processing, and its
            // idle timeout does not apply to an active deferred trigger.
            // The server may still commit after this socket has been dropped.
            drop(connection.detach());
            if commit_issued {
                Publication {
                    outcome: CodexPublicationOutcome::Unknown,
                    result: Err(Error::PublicationUnknown),
                }
            } else {
                Publication {
                    outcome: CodexPublicationOutcome::NotPublished,
                    result: Err(match result {
                        Ok(Err(error)) => error,
                        _ => Error::Unavailable,
                    }),
                }
            }
        }
    }
}

async fn apply(
    shared: &Shared,
    scope: &Scope,
    tx: &mut Transaction<'_, Postgres>,
    mutation: Mutation,
) -> Result<Option<CredentialMetadata>, Error> {
    match mutation {
        Mutation::Create(prepared) => shared
            .store
            .create_prepared_in(tx, &scope.owner, *prepared)
            .await
            .map(|record| Some(record.metadata))
            .map_err(store_error),
        Mutation::Revoke { id, revision } => {
            let record = shared
                .store
                .record_for_update_in(tx, &scope.owner, &id)
                .await
                .map_err(store_error)?;
            if record.metadata.revocation_generation != revision {
                return Err(Error::StaleRevision);
            }
            shared
                .store
                .revoke_in(tx, &scope.owner, &id, record.version)
                .await
                .map(|record| Some(record.metadata))
                .map_err(store_error)
        }
        Mutation::Delete { id, revision } => {
            let record = shared
                .store
                .record_for_update_in(tx, &scope.owner, &id)
                .await
                .map_err(store_error)?;
            if record.metadata.revocation_generation != revision {
                return Err(Error::StaleRevision);
            }
            if record.metadata.status != CredentialStatus::Revoked {
                return Err(Error::MustBeRevoked);
            }
            shared
                .store
                .delete_revoked_in(tx, &scope.owner, &id, record.version)
                .await
                .map_err(store_error)?;
            Ok(None)
        }
    }
}
