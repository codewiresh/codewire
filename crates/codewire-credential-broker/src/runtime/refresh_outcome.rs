//! What a started refresh that did not publish answers: its failure is
//! recorded where it can be, so the epoch goes on (#5537, #5539).

use super::*;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A refresh whose provider answer could not be stored after its retries
    /// (#5537). With its started permit back, the attempt is recorded as
    /// failed: the credential needs Reconnect, only this request is refused,
    /// and the epoch goes on. The authority refuses that record when a result
    /// was stored after all, and without the permit nothing can be recorded:
    /// either way the request answers `AuthorityUnavailable`, ending the
    /// epoch so recovery decides from the journal.
    pub(super) async fn publication_failed(
        leases: &P,
        failure: CommitFailure<P::StartedRefresh>,
        provider: &'static str,
    ) -> Result<(), BrokerRequestError> {
        let CommitFailure { started, error } = failure;
        match started {
            Some(started) => {
                Self::fail_started_refresh(
                    leases,
                    started,
                    provider,
                    RefreshFailure::Publication(error),
                    BrokerRequestError::ReconnectRequired(WithheldReason::NeedsReconnect),
                )
                .await
            }
            None => {
                RefreshFailure::Publication(error).warn(provider);
                Err(publication_failure())
            }
        }
    }

    /// Record one terminal failure for an exact started attempt after logging
    /// its closed class. The caller never retries the previous refresh token.
    /// A rate-limited attempt is closed as waiting instead, where the
    /// placement records it (#4975); a refused close leaves it failed.
    pub(super) async fn fail_started_refresh(
        leases: &P,
        permit: P::StartedRefresh,
        provider: &'static str,
        failure: RefreshFailure,
        error: BrokerRequestError,
    ) -> Result<(), BrokerRequestError> {
        failure.warn(provider);
        if let RefreshFailure::RateLimited { wait_seconds } = failure {
            return match leases
                .rate_limit_credential_refresh(permit, wait_seconds)
                .await
            {
                Ok(RateLimitClose::Waiting) => {
                    Err(BrokerRequestError::RefreshRateLimited { wait_seconds })
                }
                Ok(RateLimitClose::Failed) => Err(error),
                Err(_) => {
                    tracing::warn!(
                        provider,
                        failure = failure.class(),
                        "provider credential refresh failure could not be recorded"
                    );
                    Err(BrokerRequestError::AuthorityUnavailable)
                }
            };
        }
        match leases.fail_credential_refresh(permit).await {
            Ok(()) => Err(error),
            Err(_) => {
                tracing::warn!(
                    provider,
                    failure = failure.class(),
                    "provider credential refresh failure could not be recorded"
                );
                Err(BrokerRequestError::AuthorityUnavailable)
            }
        }
    }
}
