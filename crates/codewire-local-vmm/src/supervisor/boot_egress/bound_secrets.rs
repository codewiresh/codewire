//! A local VM boot's record of its bound secrets (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosts and the front door"): read
//! from exactly the local sources its projection selects, refused by name
//! when its hosts' union with its credentials' doesn't hold or the boot
//! can't intercept, and otherwise handed to its runner, which binds its
//! hosts and holds it for the boot's life.

use std::time::Duration;

use codewire_access::{FirstBindSecret, PlatformBootRecord};
use codewire_egress_policy::intercept::InterceptSet;
use codewire_local_credentials::AuthorityFeature;

use crate::control::v1;
use crate::runner::{BoundSecretsRefusal, bound_hosts};

use super::{Supervisor, SupervisorError};

/// The supervisor's bound on the authority's metadata read.
const RECORD_CALL_BOUND: Duration = Duration::from_secs(30);
/// The supervisor's bound on a platform boot's record question, past the
/// authority's own 10-second deadline for it, the seed placeholders'.
const PLATFORM_RECORD_CALL_BOUND: Duration = Duration::from_secs(15);

impl Supervisor {
    /// What the boot of `broker`'s selection records. A boot that selects no
    /// local source records an empty list; one whose authority predates the
    /// record records nothing (`None`), and that authority projects as it
    /// always has. A selection the authority can't read fails the boot.
    pub(super) async fn record_bound_secrets(
        &self,
        broker: &super::super::CredentialBrokerEnsureRequest,
    ) -> Result<Option<Vec<FirstBindSecret>>, SupervisorError> {
        let Some(projection) = &broker.projection else {
            return Ok(Some(Vec::new()));
        };
        let mut client = self.access_control_client().await?;
        if !AuthorityFeature::BootBoundSecrets.served_by(client.info().protocol_version) {
            return Ok(None);
        }
        tokio::time::timeout(
            RECORD_CALL_BOUND,
            client.record_boot_bound_secrets(projection),
        )
        .await
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?
        .map(Some)
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)
    }

    /// What a platform boot of `broker`'s selection records of its platform
    /// sources: the platform's sealed record, through the authority. A boot
    /// that isn't on the platform has none, and so does one whose authority
    /// or platform keeps none (older than the record, or with no seal key):
    /// its delegation then counts as recording nothing. A selection the
    /// platform can't read, or a seal key it can't reach, fails the boot.
    pub(super) async fn record_platform_bound_secrets(
        &self,
        broker: &super::super::CredentialBrokerEnsureRequest,
    ) -> Result<Option<PlatformBootRecord>, SupervisorError> {
        let Some(platform) = &broker.platform else {
            return Ok(None);
        };
        let mut client = self.access_control_client().await?;
        if !AuthorityFeature::PlatformBootBoundSecrets.served_by(client.info().protocol_version) {
            return Ok(None);
        }
        tokio::time::timeout(
            PLATFORM_RECORD_CALL_BOUND,
            client.platform_boot_bound_secrets(
                &broker.environment_id,
                broker.environment_generation,
                platform.clone(),
            ),
        )
        .await
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)
    }
}

/// Refuse a platform boot that records a local source's bound secret: its
/// front door relays every request to the platform, which holds no grant
/// for it, so it would never be swapped (docs/dev/SECRETS-AND-CREDENTIALS.md,
/// "A mixed boot").
pub(super) fn admit_mixed(
    local: &[FirstBindSecret],
    platform_boot: bool,
) -> Result<(), BoundSecretsRefusal> {
    match local.first() {
        Some(first) if platform_boot => Err(BoundSecretsRefusal::LocalOnPlatform {
            key: first.key.clone(),
        }),
        _ => Ok(()),
    }
}

/// Refuse a boot whose `record` can't be served: one that doesn't
/// intercept, by the first key it would bind, or one whose hosts' union with
/// `credentials`, the names its selected credentials bind, doesn't hold.
pub(super) fn admit(
    record: &[FirstBindSecret],
    interception: &v1::Interception,
    credentials: &InterceptSet,
) -> Result<(), BoundSecretsRefusal> {
    let Some(first) = record.first() else {
        return Ok(());
    };
    if interception.state != v1::InterceptionState::Intercepted as i32 {
        return Err(BoundSecretsRefusal::NotInterceptable {
            key: first.key.clone(),
            reason: why_not(interception),
        });
    }
    bound_hosts(record, credentials).map(drop)
}

/// The names a boot's selected credentials bind, which its bound secrets'
/// hosts may not repeat: every host the front door routes for `clients`.
pub(super) fn credential_intercepts(
    intercept: bool,
    clients: codewire_access::ManagedCredentialClients,
) -> InterceptSet {
    codewire_egress_front_door_bridge::RouteTable::for_clients(clients)
        .filter(|_| intercept)
        .and_then(|routes| routes.intercepts().ok())
        .unwrap_or_default()
}

/// Why a boot doesn't intercept, as its refusal says it.
fn why_not(interception: &v1::Interception) -> &'static str {
    use v1::InterceptionReason as Reason;
    if interception.state == v1::InterceptionState::Off as i32 {
        return "interception is switched off";
    }
    match Reason::try_from(interception.reason) {
        Ok(Reason::NoCredentials) => "it has no local credential broker",
        Ok(Reason::PlatformCredentials) => {
            "its credentials come from the platform, whose relay can't serve this front door"
        }
        Ok(Reason::CredentialServiceOutdated) => {
            "the running local credential service predates boot secrets"
        }
        _ => "it does not intercept",
    }
}

#[cfg(test)]
mod tests;
