//! One caller-owned connection from authorization through publication.

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, ProviderId,
};
use codewire_platform_credentials::{
    CredentialRegistration, PreparedCredentialCreation, PreparedCredentialReplacement,
};
use codewire_protected_store::ProtectedValue;
use sqlx::{Acquire, PgConnection, Postgres, Transaction};
use tokio::time::Instant;

use super::enrollment::{Completed, Outcome};
use super::{EnrollmentTarget, Error, Scope, Shared, authority_error, store_error};

pub(super) struct Publication<T> {
    pub outcome: Outcome,
    pub result: Result<T, Error>,
}

enum Mutation {
    Create(Box<PreparedCredentialCreation>),
    Replace(Box<PreparedCredentialReplacement>),
    Rename {
        id: CredentialId,
        revision: u64,
        expected_name: String,
        name: String,
    },
    Revoke {
        id: CredentialId,
        revision: u64,
    },
    Delete {
        id: CredentialId,
        revision: u64,
    },
}

pub(super) async fn enroll(
    shared: &Shared,
    scope: &Scope,
    completed: &mut Completed,
    target: EnrollmentTarget,
) -> Publication<CredentialMetadata> {
    let prepared = async {
        scope.check()?;
        let (material, account_hint) = completed.take_material()?;
        let target = match target {
            EnrollmentTarget::CreateGithubAccount => {
                if completed.provider() != "github" {
                    return Err(Error::EnrollmentFailed);
                }
                let name = account_hint.as_deref().ok_or(Error::EnrollmentFailed)?;
                super::validate_name(name)?;
                EnrollmentTarget::Create(name.to_owned())
            }
            target => target,
        };
        // All provider/envelope work precedes the identity/publication locks.
        match target {
            EnrollmentTarget::Create(name) => {
                let registration = CredentialRegistration {
                    provider: ProviderId::parse(completed.provider()).expect("built-in provider"),
                    authentication_kind: completed.authentication_kind(),
                    display_name: name,
                    account_hint,
                    expires_at_unix: None,
                };
                let prepared = scope
                    .wait(
                        shared
                            .store
                            .prepare_creation(&scope.owner, registration, &material),
                    )
                    .await?
                    .map_err(store_error)?;
                Ok(Mutation::Create(Box::new(prepared)))
            }
            EnrollmentTarget::Reconnect(expected) => {
                let prepared = scope
                    .wait(shared.store.prepare_replacement(
                        &scope.owner,
                        &expected,
                        &material,
                        account_hint,
                    ))
                    .await?
                    .map_err(store_error)?;
                Ok(Mutation::Replace(Box::new(prepared)))
            }
            EnrollmentTarget::CreateGithubAccount => unreachable!("resolved above"),
        }
    }
    .await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Publication {
                outcome: Outcome::NotPublished,
                result: Err(error),
            };
        }
    };
    let github_create = completed.provider() == "github" && matches!(prepared, Mutation::Create(_));
    let result = publish(shared, scope, prepared).await;
    Publication {
        outcome: result.outcome,
        result: result
            .result
            .and_then(|metadata| metadata.ok_or(Error::PublicationUnknown))
            .map_err(|error| match error {
                // The singleton index rejected a concurrent second connection.
                Error::AlreadyExists if github_create => Error::GitHubAlreadyConnected,
                error => error,
            }),
    }
}

pub(super) async fn add_api_key(
    shared: &Shared,
    scope: &Scope,
    registration: CredentialRegistration,
    material: ProtectedValue,
) -> Result<CredentialMetadata, Error> {
    let prepared = scope
        .wait(
            shared
                .store
                .prepare_creation(&scope.owner, registration, &material),
        )
        .await?
        .map_err(store_error)?;
    drop(material);
    publish(shared, scope, Mutation::Create(Box::new(prepared)))
        .await
        .result?
        .ok_or(Error::PublicationUnknown)
}

pub(super) async fn rename(
    shared: &Shared,
    scope: &Scope,
    id: CredentialId,
    revision: u64,
    expected_name: String,
    name: String,
) -> Result<CredentialMetadata, Error> {
    publish(
        shared,
        scope,
        Mutation::Rename {
            id,
            revision,
            expected_name,
            name,
        },
    )
    .await
    .result?
    .ok_or(Error::PublicationUnknown)
}

pub(super) async fn rotate_api_key(
    shared: &Shared,
    scope: &Scope,
    id: CredentialId,
    revision: u64,
    material: ProtectedValue,
    expires_at_unix: Option<u64>,
) -> Result<CredentialMetadata, Error> {
    let expected = scope
        .wait(shared.store.record(&scope.owner, &id))
        .await?
        .map_err(store_error)?;
    if expected.metadata.revocation_generation != revision {
        return Err(Error::StaleRevision);
    }
    if expected.metadata.authentication_kind != CredentialAuthKind::ApiKey {
        return Err(Error::InvalidInput);
    }
    super::validate_api_key(
        expected.metadata.provider.as_str(),
        &expected.metadata.display_name,
        material.expose_secret(),
        expires_at_unix,
    )?;
    let prepared = scope
        .wait(shared.store.prepare_api_key_replacement(
            &scope.owner,
            &expected,
            &material,
            expires_at_unix,
        ))
        .await?
        .map_err(store_error)?;
    drop(material);
    publish(shared, scope, Mutation::Replace(Box::new(prepared)))
        .await
        .result?
        .ok_or(Error::PublicationUnknown)
}

/// Create, or replace the exact named existing, Claude subscription token.
/// All protected-material work precedes the publication locks; replacement
/// is fenced on the observed generation again at publication.
pub(super) async fn add_claude_subscription_token(
    shared: &Shared,
    scope: &Scope,
    name: String,
    material: ProtectedValue,
    replacement: Option<(CredentialId, u64)>,
    expires_at_unix: u64,
) -> Result<CredentialMetadata, Error> {
    let mutation = match replacement {
        None => {
            let registration = CredentialRegistration {
                provider: ProviderId::parse("anthropic").expect("built-in provider"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: name,
                account_hint: None,
                expires_at_unix: Some(expires_at_unix),
            };
            let prepared = scope
                .wait(
                    shared
                        .store
                        .prepare_creation(&scope.owner, registration, &material),
                )
                .await?
                .map_err(store_error)?;
            Mutation::Create(Box::new(prepared))
        }
        Some((id, revision)) => {
            let expected = scope
                .wait(shared.store.record(&scope.owner, &id))
                .await?
                .map_err(store_error)?;
            if expected.metadata.display_name != name
                || expected.metadata.provider.as_str() != "anthropic"
                || expected.metadata.authentication_kind != CredentialAuthKind::OAuth
            {
                return Err(Error::InvalidInput);
            }
            if expected.metadata.revocation_generation != revision {
                return Err(Error::StaleRevision);
            }
            let prepared = scope
                .wait(shared.store.prepare_subscription_token_replacement(
                    &scope.owner,
                    &expected,
                    &material,
                    expires_at_unix,
                ))
                .await?
                .map_err(store_error)?;
            Mutation::Replace(Box::new(prepared))
        }
    };
    drop(material);
    publish(shared, scope, mutation)
        .await
        .result?
        .ok_or(Error::PublicationUnknown)
}

pub(super) async fn add_ssh(
    shared: &Shared,
    scope: &Scope,
    name: String,
    expires_at_unix: Option<u64>,
    prepared: codewire_protected_store::ssh_material::PreparedSshCredential,
) -> Result<CredentialMetadata, Error> {
    let prepared = scope
        .wait(
            shared
                .store
                .prepare_ssh_creation(&scope.owner, name, expires_at_unix, prepared),
        )
        .await?
        .map_err(store_error)?;
    publish(shared, scope, Mutation::Create(Box::new(prepared)))
        .await
        .result?
        .ok_or(Error::PublicationUnknown)
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
    publish(shared, scope, mutation).await.result
}

async fn publish(
    shared: &Shared,
    scope: &Scope,
    mutation: Mutation,
) -> Publication<Option<CredentialMetadata>> {
    let deadline = scope.deadline.min(Instant::now() + shared.mutation_timeout);
    let acquired = tokio::time::timeout_at(deadline, scope.wait(shared.pool.acquire())).await;
    let mut connection = match acquired {
        Ok(Ok(Ok(connection))) => connection,
        _ => {
            return Publication {
                outcome: Outcome::NotPublished,
                result: Err(Error::Unavailable),
            };
        }
    };
    let metadata;
    let transaction = {
        let prepared = tokio::time::timeout_at(
            deadline,
            prepare_publication(&mut connection, shared, scope, mutation, deadline),
        )
        .await;
        match prepared {
            Ok(Ok((transaction, committed_metadata))) => {
                metadata = committed_metadata;
                transaction
            }
            result => {
                let error = Err(match result {
                    Ok(Err(error)) => error,
                    _ => Error::Unavailable,
                });
                // SQLx 0.8.6 close_hard() flushes its buffered stream. Do not
                // use it here: a cancelled transaction may have queued
                // ROLLBACK before COMMIT was issued. Detach and drop the raw
                // connection/socket without returning it to the pool or
                // flushing more SQL.
                drop(result);
                drop(connection.detach());
                return Publication {
                    outcome: Outcome::NotPublished,
                    result: error,
                };
            }
        }
    };

    // COMMIT is irrevocable. Everything above remains bounded by the mutation
    // deadline, but dropping this future after issuing COMMIT cannot turn an
    // in-flight server result into a safe rollback. Keep the owned worker and
    // connection alive until PostgreSQL returns a terminal commit result.
    let result = transaction.commit().await;
    match result {
        Ok(()) => Publication {
            outcome: Outcome::Published,
            result: Ok(metadata),
        },
        Err(_) => {
            // SQLx 0.8.6 close_hard() flushes its buffered stream. Do not use
            // it here: a cancelled transaction may have queued COMMIT/ROLLBACK.
            // Detach and drop the raw connection/socket without returning it
            // to the pool or flushing more SQL. This relinquishes local
            // ownership, not an already-issued server COMMIT: PostgreSQL
            // disables statement_timeout before commit processing, and its
            // idle timeout does not apply to an active deferred trigger.
            // The server may still commit after this socket has been dropped.
            drop(connection.detach());
            Publication {
                outcome: Outcome::Unknown,
                result: Err(Error::PublicationUnknown),
            }
        }
    }
}

async fn prepare_publication<'connection>(
    connection: &'connection mut PgConnection,
    shared: &Shared,
    scope: &Scope,
    mutation: Mutation,
    deadline: Instant,
) -> Result<
    (
        Transaction<'connection, Postgres>,
        Option<CredentialMetadata>,
    ),
    Error,
> {
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
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(())
    });
    if let Err(error) = admitted {
        let _ = tx.rollback().await;
        return Err(error);
    }
    Ok((tx, metadata))
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
        Mutation::Replace(prepared) => shared
            .store
            .replace_prepared_in(tx, &scope.owner, *prepared)
            .await
            .map(|record| Some(record.metadata))
            .map_err(store_error),
        Mutation::Rename {
            id,
            revision,
            expected_name,
            name,
        } => shared
            .store
            .rename_in(tx, &scope.owner, &id, revision, &expected_name, name)
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
            let github = record.metadata.provider.as_str() == "github"
                && record.metadata.authentication_kind == CredentialAuthKind::OAuth;
            let version = if record.metadata.status == CredentialStatus::Revoked {
                record.version
            } else if github {
                // GitHub is one account-level connection with no user-visible
                // revoke step. Revoke and forget it in this same fenced
                // transaction; profiles are unchanged and include it again on reconnect.
                shared
                    .store
                    .revoke_in(tx, &scope.owner, &id, record.version)
                    .await
                    .map_err(store_error)?
                    .version
            } else {
                return Err(Error::MustBeRevoked);
            };
            shared
                .store
                .delete_revoked_in(tx, &scope.owner, &id, version)
                .await
                .map_err(store_error)?;
            Ok(None)
        }
    }
}
