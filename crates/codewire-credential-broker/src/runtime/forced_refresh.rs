//! When a provider's 401 may force a refresh of a stored sign-in (#3999).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;

use codewire_access::CredentialId;

use super::{BrokerRequestError, BrokerUpstreamBody, BrokerUpstreamError, BrokerUpstreamResponse};
use crate::BrokerCredentialLease;

/// The stored sign-in a request was sent with. A refresh forced by its 401
/// replaces exactly this generation, never a later one.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RefreshCredentialGeneration {
    pub(super) credential_id: CredentialId,
    pub(super) revocation_generation: u64,
    pub(super) material_generation: u64,
}

pub(super) fn refresh_generation(
    lease: &impl BrokerCredentialLease,
) -> RefreshCredentialGeneration {
    RefreshCredentialGeneration {
        credential_id: lease.credential_metadata().id.clone(),
        revocation_generation: lease.credential_metadata().revocation_generation,
        material_generation: lease.material_generation(),
    }
}

/// How long ago a sign-in must last have been refreshed before a provider
/// 401 may force another refresh of it.
///
/// A process in the environment shapes the request and so decides when a 401
/// happens. Every forced exchange rotates the refresh token, and one the
/// provider refuses, or whose outcome is uncertain (a 429, a 5xx, a timeout,
/// a network error), leaves the sign-in "Reconnect needed", as every refresh
/// does. This age is what bounds how often such a process can cause one.
///
/// The time compared is the one stored in the sign-in itself, which every
/// exchange rewrites. So the bound holds for one sign-in across every broker
/// that serves it and across their restarts, which a count kept in one
/// broker's memory would not. It also means a token that was refreshed
/// moments ago and is still rejected is not refreshed again: another
/// exchange would not fix that 401.
pub(super) const FORCED_REFRESH_MIN_AGE: Duration = Duration::from_secs(10 * 60);

/// Whether a 401 may force a refresh of a sign-in last refreshed at
/// `refreshed_at_unix`. One stamped in the future is not due.
pub(super) fn forced_refresh_due(refreshed_at_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(refreshed_at_unix) >= FORCED_REFRESH_MIN_AGE.as_secs()
}

/// When this broker last tried a forced rotation of each sign-in, in its own
/// memory (#5078). The stored time moves only when a rotation succeeds, so
/// without this a sign-in whose rotation cannot start (the authority refuses
/// or is away) would be tried again on every 401. One try per sign-in in
/// `FORCED_REFRESH_MIN_AGE`, per broker; the stored time remains the bound
/// that holds across brokers.
#[derive(Default)]
pub(super) struct ForcedAttempts(Mutex<HashMap<CredentialId, u64>>);

impl ForcedAttempts {
    /// Whether this broker may try a forced rotation of `credential` now,
    /// recording the try when it may. Entries past the age are dropped, so
    /// the map holds only sign-ins tried in the last ten minutes.
    pub(super) fn begin(&self, credential: &CredentialId, now_unix: u64) -> bool {
        let mut attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts.retain(|_, at| !forced_refresh_due(*at, now_unix));
        if attempts.contains_key(credential) {
            return false;
        }
        attempts.insert(credential.clone(), now_unix);
        true
    }
}

/// The most of a provider's 401 held in memory while the sign-in refreshes.
/// The API's rejection is a few hundred bytes of JSON. A larger one is
/// answered as it is, with no refresh.
pub(super) const HELD_REJECTION_MAX_BYTES: usize = 64 * 1024;

/// Reads the provider's 401 to its end, so no upstream connection is held
/// open while the sign-in refreshes: an exchange can take as long as its
/// timeout. Returns the reply, still to be answered as it came, and whether
/// all of it was read. One longer than `HELD_REJECTION_MAX_BYTES`, or one
/// that failed while it was read, was not: what was read goes back in front
/// of the rest.
pub(super) async fn hold_rejection(
    response: BrokerUpstreamResponse,
) -> (BrokerUpstreamResponse, bool) {
    let (status, headers, mut body) = response.into_parts();
    let mut held: Vec<Result<Bytes, BrokerUpstreamError>> = Vec::new();
    let mut held_bytes = 0_usize;
    let whole = loop {
        match body.next().await {
            None => break true,
            Some(Ok(chunk)) => {
                held_bytes = held_bytes.saturating_add(chunk.len());
                held.push(Ok(chunk));
                if held_bytes > HELD_REJECTION_MAX_BYTES {
                    break false;
                }
            }
            Some(Err(error)) => {
                held.push(Err(error));
                break false;
            }
        }
    };
    let held = futures::stream::iter(held);
    let body: BrokerUpstreamBody = if whole {
        Box::pin(held)
    } else {
        Box::pin(held.chain(body))
    };
    (BrokerUpstreamResponse::new(status, headers, body), whole)
}

/// Why a sign-in's request could not be prepared again after its forced
/// refresh, split by where it failed (#4974).
#[derive(Debug)]
pub(super) enum RetryFailure {
    /// The exchange itself failed: the provider refused it, its outcome is
    /// uncertain, or its result could not be stored. The 401 is then the
    /// provider's own answer about a credential still this environment's.
    Refresh(BrokerRequestError),
    /// The request no longer has this credential: the re-lease or its binding
    /// was refused, before or after the exchange, or the authority refused to
    /// begin a refresh of it. The provider never judged that, so its 401 says
    /// nothing about it.
    Request(BrokerRequestError),
}

/// Refuses to begin a refresh at a provider the transport cannot reach
/// (#5286). A refresh that fails in transport is recorded as an attempt of
/// unknown outcome, which is terminal for a sign-in, so one toward a host
/// with no address must never be begun: nothing was asked of the provider,
/// and the sign-in stays as it was.
pub(super) fn refresh_reachable(unserved: bool) -> Result<(), RetryFailure> {
    if unserved {
        return Err(BrokerRequestError::UpstreamFailed.into());
    }
    Ok(())
}

impl super::OAuthRefreshMaterial {
    /// The slot whose provider this refresh asks.
    pub(super) fn slot(&self) -> &'static str {
        match self {
            Self::Codex(_) => "codex",
            Self::Claude(_) => "anthropic",
            Self::Antigravity(_) => "antigravity",
        }
    }
}

impl From<BrokerRequestError> for RetryFailure {
    fn from(error: BrokerRequestError) -> Self {
        Self::Request(error)
    }
}

impl From<RetryFailure> for BrokerRequestError {
    fn from(failure: RetryFailure) -> Self {
        match failure {
            RetryFailure::Refresh(error) | RetryFailure::Request(error) => error,
        }
    }
}

/// What a sign-in's 401 is answered with when its forced refresh failed:
/// `Ok` answers the provider's held 401, when the exchange itself failed.
/// An unavailable authority still ends the epoch, and a request that no
/// longer has this credential gets its own error, as before #4972.
pub(super) fn after_failed_refresh(
    failure: RetryFailure,
    provider: &'static str,
) -> Result<(), BrokerRequestError> {
    match failure {
        RetryFailure::Refresh(BrokerRequestError::AuthorityUnavailable) => {
            Err(BrokerRequestError::AuthorityUnavailable)
        }
        RetryFailure::Refresh(error) => {
            tracing::info!(
                provider,
                %error,
                "a sign-in's 401 is returned after its forced refresh failed"
            );
            Ok(())
        }
        RetryFailure::Request(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const MIN_AGE: u64 = 600;

    #[test]
    fn the_age_is_ten_minutes() {
        assert_eq!(FORCED_REFRESH_MIN_AGE.as_secs(), MIN_AGE);
    }

    #[test]
    fn a_sign_in_younger_than_the_age_is_not_due() {
        assert!(!forced_refresh_due(NOW - (MIN_AGE - 1), NOW));
        assert!(!forced_refresh_due(NOW, NOW));
    }

    #[test]
    fn a_sign_in_of_exactly_the_age_is_due() {
        assert!(forced_refresh_due(NOW - MIN_AGE, NOW));
    }

    #[test]
    fn an_older_sign_in_is_due() {
        assert!(forced_refresh_due(NOW - MIN_AGE - 1, NOW));
        assert!(forced_refresh_due(0, NOW));
    }

    #[test]
    fn one_forced_attempt_per_sign_in_in_the_age() {
        let attempts = ForcedAttempts::default();
        let first = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let second = CredentialId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        assert!(attempts.begin(&first, NOW));
        assert!(!attempts.begin(&first, NOW));
        assert!(!attempts.begin(&first, NOW + MIN_AGE - 1));
        assert!(attempts.begin(&second, NOW), "another sign-in is its own");
        assert!(attempts.begin(&first, NOW + MIN_AGE));
        assert_eq!(
            attempts.0.lock().unwrap().len(),
            1,
            "old entries are dropped"
        );
    }

    #[test]
    fn a_sign_in_stamped_in_the_future_is_not_due() {
        assert!(!forced_refresh_due(NOW + 1, NOW));
        assert!(!forced_refresh_due(u64::MAX, NOW));
    }
}
