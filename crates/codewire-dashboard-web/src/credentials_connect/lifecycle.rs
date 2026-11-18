//! Revoking and deleting a credential from the dashboard, each at the exact
//! revision the page showed.

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    Credential, CredentialAuthenticationKind, CredentialStatus, DeleteCredentialRequest,
    ProviderRevocationOutcome, RevokeCredentialRequest,
};
use connectrpc::ConnectError;

use super::{
    get_exact_credential, invalid_metadata, mutation_client, validate_exact_credential_ack,
};
use crate::state::AppState;

pub(crate) async fn revoke_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
) -> Result<(), ConnectError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    if current.revocation_generation != expected_generation || is_github_connection(&current) {
        // GitHub has no user-visible revoke step; Delete replaces it.
        return Err(ConnectError::aborted("credential metadata changed"));
    }
    let mut expected = current;
    expected.status = CredentialStatus::Revoked.into();
    expected.revocation_generation = expected_generation
        .checked_add(1)
        .filter(|generation| *generation <= i64::MAX as u64)
        .ok_or_else(invalid_metadata)?;
    let response = mutation_client(state, cookie)
        .revoke_credential(RevokeCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            ..Default::default()
        })
        .await?
        .into_owned();
    validate_exact_credential_ack(response.credential.into_option(), &expected)
}

/// What GitHub said when disconnecting asked it to revoke the connection's
/// access token (#4717 C6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitHubAnswer {
    Confirmed,
    NotConfirmed,
}

/// Why a delete or a GitHub disconnect stopped.
#[derive(Debug)]
pub(crate) enum DeleteError {
    /// Nothing changed: the read, the revision check or Codewire's revoke
    /// failed.
    Unchanged(ConnectError),
    /// The GitHub connection was revoked, but its record wasn't removed;
    /// Disconnect again removes the revoked revision (#4717 C6).
    RevokedNotRemoved,
}

impl From<ConnectError> for DeleteError {
    fn from(error: ConnectError) -> Self {
        Self::Unchanged(error)
    }
}

/// Deletes a revoked credential, or disconnects GitHub, the account's one
/// connection: an active one is revoked first, as the CLI's delete does, so
/// GitHub is asked to revoke its access token, then the revoked revision is
/// deleted. Returns what GitHub said, for a GitHub connection that was active.
pub(crate) async fn delete_credential(
    state: &AppState,
    cookie: HeaderValue,
    credential_id: String,
    expected_generation: u64,
) -> Result<Option<GitHubAnswer>, DeleteError> {
    let current = get_exact_credential(state, cookie.clone(), &credential_id).await?;
    let active = current.status != CredentialStatus::Revoked;
    if current.revocation_generation != expected_generation
        || active && !is_github_connection(&current)
    {
        return Err(ConnectError::aborted("credential metadata changed").into());
    }
    let (revision, answer) = if active {
        let (revision, answer) =
            revoke_github(state, cookie.clone(), current, expected_generation).await?;
        (revision, Some(answer))
    } else {
        (expected_generation, None)
    };
    let deleted = mutation_client(state, cookie)
        .delete_credential(DeleteCredentialRequest {
            credential_id,
            expected_revocation_generation: revision,
            ..Default::default()
        })
        .await;
    match deleted {
        Ok(_) => Ok(answer),
        // The revoke held, so the person is told GitHub is disconnected.
        // Disconnecting again can't meet InUse: no profile entry can name a
        // GitHub credential (`platform_access_profile_entries_slot_check`).
        Err(_) if answer.is_some() => Err(DeleteError::RevokedNotRemoved),
        Err(error) => Err(error.into()),
    }
}

/// Revokes the exact GitHub revision; Codewire's revoke failing stops the
/// disconnect before anything is deleted.
async fn revoke_github(
    state: &AppState,
    cookie: HeaderValue,
    current: Credential,
    expected_generation: u64,
) -> Result<(u64, GitHubAnswer), ConnectError> {
    let credential_id = current.id.clone();
    let mut expected = current;
    expected.status = CredentialStatus::Revoked.into();
    expected.revocation_generation = expected_generation
        .checked_add(1)
        .filter(|generation| *generation <= i64::MAX as u64)
        .ok_or_else(invalid_metadata)?;
    let response = mutation_client(state, cookie)
        .revoke_credential(RevokeCredentialRequest {
            credential_id,
            expected_revocation_generation: expected_generation,
            ..Default::default()
        })
        .await?
        .into_owned();
    let confirmed = response
        .provider_revocation
        .as_option()
        .is_some_and(|reported| reported.outcome == ProviderRevocationOutcome::Confirmed);
    let revision = expected.revocation_generation;
    validate_exact_credential_ack(response.credential.into_option(), &expected)?;
    let answer = if confirmed {
        GitHubAnswer::Confirmed
    } else {
        GitHubAnswer::NotConfirmed
    };
    Ok((revision, answer))
}

fn is_github_connection(credential: &Credential) -> bool {
    credential.provider == "github"
        && credential.authentication_kind == CredentialAuthenticationKind::Oauth
}
