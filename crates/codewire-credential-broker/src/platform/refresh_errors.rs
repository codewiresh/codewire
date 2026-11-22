//! How the platform store's refresh answers read to the broker, and its close
//! of a rate-limited attempt (#4975).

use super::*;
use crate::RateLimitClose;

pub(super) fn refresh_lease_error(error: BrokerLeaseError) -> BrokerRefreshError {
    match error {
        BrokerLeaseError::InvalidRequest => BrokerRefreshError::InvalidRequest,
        // A credential needing Reconnect is never refreshed again automatically.
        BrokerLeaseError::Denied
        | BrokerLeaseError::ReconnectRequired(_)
        | BrokerLeaseError::NotSelected => BrokerRefreshError::Denied,
        BrokerLeaseError::Unavailable => BrokerRefreshError::Unavailable,
        BrokerLeaseError::InvalidResponse => BrokerRefreshError::InvalidResponse,
    }
}

pub(super) fn refresh_store_error(error: PlatformCredentialError) -> BrokerRefreshError {
    match error {
        PlatformCredentialError::RefreshInProgress => BrokerRefreshError::InProgress,
        PlatformCredentialError::StaleVersion | PlatformCredentialError::StaleRefresh => {
            BrokerRefreshError::Stale
        }
        // Never a denial: the sign-in is kept while the provider's wait runs.
        PlatformCredentialError::RefreshRateLimited {
            retry_after_seconds,
        } => BrokerRefreshError::RateLimited {
            wait_seconds: retry_after_seconds,
        },
        other => refresh_lease_error(credential_error(other)),
    }
}

/// Close a started attempt as rate-limited. The store refuses one begun after
/// a wait, or no longer started, as stale: that attempt is then failed, so a
/// second rate limit is terminal, as the rule says. Any other refusal fails
/// it too, at once, rather than leaving it to lapse to the same end.
pub(super) async fn rate_limit(
    credentials: &PlatformCredentialStore,
    started: StartedOAuthRefresh,
    wait_seconds: u64,
) -> Result<RateLimitClose, BrokerRefreshError> {
    match credentials
        .rate_limit_oauth_refresh(&started, wait_seconds)
        .await
    {
        Ok(()) => Ok(RateLimitClose::Waiting),
        Err(_) => credentials
            .fail_oauth_refresh(started)
            .await
            .map(|()| RateLimitClose::Failed)
            .map_err(refresh_store_error),
    }
}

/// Reserves a refresh for this broker and names it: the store logs each
/// transition of the attempt, and this line ties the attempt to the broker
/// instance that began it (#5957, #4002). Ids only, never a value.
pub(super) async fn begin(
    credentials: &PlatformCredentialStore,
    owner: &Owner,
    (id, version, attempt_id): (&CredentialId, CredentialVersion, Uuid),
    broker_instance: Uuid,
) -> Result<PreparedOAuthRefresh, BrokerRefreshError> {
    let prepared = credentials
        .begin_oauth_refresh(owner, id, version, attempt_id)
        .await
        .map_err(refresh_store_error)?;
    tracing::info!(
        credential_id = id.as_str(),
        %attempt_id,
        holder = "broker",
        %broker_instance,
        "provider credential refresh begun"
    );
    Ok(prepared)
}
