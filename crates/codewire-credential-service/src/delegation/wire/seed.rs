//! A local VM's seed placeholders on a platform profile (#4001;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Its seed placeholders"): before the
//! boot starts, the placeholder each of its delegation's leases will carry.
//! The selection is admitted exactly as `DelegateCredentials` admits it, and
//! the values are derived exactly as those leases derive theirs. No value is
//! ever logged; each call is counted by its outcome.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use codewire_access::{CapabilitySlot, EnvironmentId, ManagedCredentialClients, OwnerId};
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator,
};
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::auth::OAuthBearerAuthority;
use uuid::Uuid;

use super::{MAX_SELECTION_BYTES, Service, authority_error, selection};
use crate::delegation::OwnerLocalRuntimeAuthority;

/// The most slots one call names: every slot a profile can select fits.
const MAX_SLOTS: usize = 16;
/// Calls one user may make in [`RATE_WINDOW`] before the next is refused.
const RATE_LIMIT: usize = 30;
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Users tracked at once before the windows that have passed are swept.
const SWEEP_AT: usize = 4_096;

/// Why a call was refused. Each refused admission is the same `Denied`,
/// whatever check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    Denied,
    Unavailable,
    RateLimited,
}

impl Refusal {
    fn outcome(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::RateLimited => "rate_limited",
        }
    }

    pub(super) fn status(self) -> connectrpc::ConnectError {
        match self {
            Self::Denied => connectrpc::ConnectError::permission_denied(
                "credential placeholders denied for this selection",
            ),
            Self::Unavailable => {
                connectrpc::ConnectError::unavailable("credential placeholders unavailable")
            }
            Self::RateLimited => connectrpc::ConnectError::resource_exhausted(
                "too many credential placeholder requests; try again in a minute",
            ),
        }
    }
}

impl From<PlatformBridgeAuthenticationError> for Refusal {
    fn from(error: PlatformBridgeAuthenticationError) -> Self {
        match error {
            PlatformBridgeAuthenticationError::Unavailable => Self::Unavailable,
            _ => Self::Denied,
        }
    }
}

/// Each user's calls in the last [`RATE_WINDOW`], in this process.
#[derive(Default)]
pub(super) struct RateLimit(Mutex<HashMap<String, VecDeque<Instant>>>);

impl RateLimit {
    /// Count one call by `user` at `now`, or refuse it when the user has
    /// made [`RATE_LIMIT`] calls in the window before it. A refused call is
    /// not counted, so a caller that waits is served once the window moves.
    fn admit(&self, user: &str, now: Instant) -> bool {
        let mut users = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let live = |at: &Instant| now.saturating_duration_since(*at) < RATE_WINDOW;
        if users.len() >= SWEEP_AT {
            users.retain(|_, calls| calls.back().is_some_and(live));
        }
        let calls = users.entry(user.to_owned()).or_default();
        while calls.front().is_some_and(|at| !live(at)) {
            calls.pop_front();
        }
        if calls.len() >= RATE_LIMIT {
            return false;
        }
        calls.push_back(now);
        true
    }
}

impl<A, U> Service<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    /// One call's answer, counted by its outcome.
    pub(super) async fn seed_placeholders(
        &self,
        oauth: OAuthBearerAuthority,
        request: connectrpc::ServiceRequest<'_, proto::EnvironmentCredentialPlaceholdersRequest>,
    ) -> Result<proto::EnvironmentCredentialPlaceholdersResponse, Refusal> {
        let result = self.answer(oauth, request).await;
        match &result {
            Ok(response) => tracing::info!(
                event = "seed_placeholders",
                outcome = "answered",
                slots = response.placeholders.len(),
                "credential placeholders answered for a local VM's seed"
            ),
            Err(refusal) => tracing::warn!(
                event = "seed_placeholders",
                outcome = refusal.outcome(),
                "credential placeholders refused for a local VM's seed"
            ),
        }
        result
    }

    async fn answer(
        &self,
        oauth: OAuthBearerAuthority,
        request: connectrpc::ServiceRequest<'_, proto::EnvironmentCredentialPlaceholdersRequest>,
    ) -> Result<proto::EnvironmentCredentialPlaceholdersResponse, Refusal> {
        if !self.seed_rate.admit(oauth.user_id(), Instant::now()) {
            return Err(Refusal::RateLimited);
        }
        if request.bytes().len() > MAX_SELECTION_BYTES {
            return Err(Refusal::Denied);
        }
        let request = request.to_owned_message();
        let slots = requested_slots(&request.capability_slots)?;
        let open = request.selection.into_option().ok_or(Refusal::Denied)?;
        // The key is derived from the parsed UUID's canonical string, which
        // `selection` has already required the request to be in.
        let environment = Uuid::parse_str(&open.runtime.environment_id)
            .ok()
            .and_then(|id| EnvironmentId::parse(id.to_string()).ok())
            .ok_or(Refusal::Denied)?;
        let user = OwnerId::parse(oauth.user_id()).map_err(|_| Refusal::Denied)?;
        let selection = selection(open, oauth.user_id())?;
        let expiry = u64::try_from(oauth.expires_at().timestamp()).map_err(|_| Refusal::Denied)?;
        // Every check a delegation's admission of this boot makes, before any
        // key is read.
        let admitted = OwnerLocalRuntimeAuthority::new(
            self.pool.clone(),
            self.provider.clone(),
            PlatformAccessProfileStore::new(
                self.pool.clone(),
                codewire_access::builtin_provider_catalog(),
            ),
            oauth,
            selection,
            expiry,
        )
        .await
        .map_err(|error| Refusal::from(authority_error(error)))?;
        let placeholders = self
            .bridge
            .owner_local_seed_placeholders(&user, &environment, admitted.admitted_grants(), &slots)
            .await
            .map_err(|_| Refusal::Unavailable)?;
        Ok(proto::EnvironmentCredentialPlaceholdersResponse {
            placeholders: placeholders
                .into_iter()
                .map(
                    |(slot, placeholder)| proto::EnvironmentCredentialPlaceholder {
                        capability_slot: slot.as_str().to_owned(),
                        placeholder: placeholder.as_str().to_owned(),
                        ..Default::default()
                    },
                )
                .collect(),
            ..Default::default()
        })
    }
}

/// The requested slots: at most [`MAX_SLOTS`], each one a profile can
/// select, none twice.
fn requested_slots(slots: &[String]) -> Result<Vec<CapabilitySlot>, Refusal> {
    if slots.len() > MAX_SLOTS
        || ManagedCredentialClients::from_profile_slots(slots.iter().map(String::as_str)).is_err()
    {
        return Err(Refusal::Denied);
    }
    slots
        .iter()
        .map(|slot| CapabilitySlot::parse(slot.as_str()).map_err(|_| Refusal::Denied))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_gets_thirty_calls_a_minute_and_others_are_counted_apart() {
        let limit = RateLimit::default();
        let start = Instant::now();
        for _ in 0..RATE_LIMIT {
            assert!(limit.admit("alice", start));
        }
        assert!(!limit.admit("alice", start));
        assert!(!limit.admit("alice", start + RATE_WINDOW - Duration::from_millis(1)));
        assert!(limit.admit("bob", start));
        // Once the first calls leave the window, the user is served again.
        assert!(limit.admit("alice", start + RATE_WINDOW));
    }

    #[test]
    fn only_slots_a_profile_can_select_are_asked_for_at_most_once_each() {
        let slots = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(
            requested_slots(&slots(&["anthropic", "github"])).unwrap(),
            [CapabilitySlot::anthropic(), CapabilitySlot::github()]
        );
        assert!(requested_slots(&[]).unwrap().is_empty());
        for refused in [
            slots(&["anthropic", "anthropic"]),
            slots(&["not-a-slot"]),
            slots(&["git_ssh"]),
            vec!["anthropic".to_owned(); MAX_SLOTS + 1],
        ] {
            assert_eq!(
                requested_slots(&refused),
                Err(Refusal::Denied),
                "{refused:?}"
            );
        }
    }
}
