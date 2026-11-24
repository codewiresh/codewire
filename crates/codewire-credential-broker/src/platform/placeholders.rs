//! A hosted epoch's credential placeholders (#4001): the one each lease
//! carries, and the set an intercepted epoch's Sandbox projects. Both are
//! derived the same way, through the epoch's one cache, kept by the inputs
//! each is derived from. A local VM on a platform profile gets its seed's
//! placeholders here too, derived as its delegation's leases derive theirs.

use codewire_access::{
    AvailableGrants, CapabilitySlot, CredentialPlaceholder, DerivedGrant, EnvironmentId, OwnerId,
    PlaceholderKey, ProjectedPlaceholders,
};
use codewire_platform_credentials::{PlatformCredentialError, PlatformCredentialStore};

use super::{PlatformBrokerLeaseProvider, PlatformRuntimeAuthority, RuntimeIdentity};
use crate::BrokerLeaseError;
use crate::timing::{self, PlaceholderUse};

/// One hosted epoch's derived placeholders, each by the inputs it is derived
/// from (#4001). A placeholder is not a secret: it is worthless outside its
/// environment. The key it is derived under is never kept: a lease that finds
/// none here reads and opens the key, derives, and drops it. So the key is
/// read once per epoch and credential, not on every request.
#[derive(Default)]
pub(crate) struct EpochPlaceholders(
    std::sync::Mutex<std::collections::HashMap<PlaceholderInputs, CredentialPlaceholder>>,
);

/// Exactly the derivation's inputs: environment, the binding's profile
/// revision, capability slot and credential. So a rebind within an epoch
/// derives again, and a new generation of the same binding does not.
type PlaceholderInputs = (String, u64, String, String);

/// Whose leases carry a placeholder when their epoch has a cache: a hosted
/// epoch's, and a delegation's that declared a front door (#4909). Only their
/// admission gives an epoch the cache.
pub(super) fn leases_carry_placeholders(identity: &RuntimeIdentity) -> bool {
    matches!(
        identity,
        RuntimeIdentity::Hosted { .. } | RuntimeIdentity::OwnerLocal { .. }
    )
}

pub(super) fn placeholder_inputs(grant: &DerivedGrant) -> PlaceholderInputs {
    (
        grant.environment_id.as_str().to_owned(),
        grant.profile.as_ref().map_or(0, |profile| profile.revision),
        grant.capability_slot.as_str().to_owned(),
        grant.credential_id.as_str().to_owned(),
    )
}

impl EpochPlaceholders {
    fn get(&self, inputs: &PlaceholderInputs) -> Option<CredentialPlaceholder> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(inputs)
            .cloned()
    }

    fn insert(&self, inputs: PlaceholderInputs, placeholder: CredentialPlaceholder) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(inputs, placeholder);
    }
}

impl<A: PlatformRuntimeAuthority> PlatformBrokerLeaseProvider<A> {
    /// The placeholder for `grant`'s credential in its environment generation:
    /// the one this epoch already derived, or one derived now under the
    /// environment's key (a hosted environment's own, or a local VM's from its
    /// owner's local root, #6191), which is read for this lease alone and
    /// dropped here.
    ///
    /// A key that cannot be read or created gives none, and the lease is
    /// marked failed: a placeholder never decides whether a lease is admitted,
    /// but the front door's swap refuses a request whose lease failed (#4001
    /// step C3). That failure is logged at warn with the environment and one
    /// closed reason, and labels the request's timing line.
    pub(super) async fn placeholder(
        &self,
        placeholders: &EpochPlaceholders,
        grant: &DerivedGrant,
    ) -> Option<CredentialPlaceholder> {
        match self.derived_placeholder(placeholders, grant).await {
            Ok(placeholder) => Some(placeholder),
            Err(reason) => {
                tracing::warn!(
                    environment_id = grant.environment_id.as_str(),
                    owner_local =
                        matches!(self.session.identity, RuntimeIdentity::OwnerLocal { .. }),
                    reason = reason.label(),
                    "lease carries no placeholder: its environment's key could not be read"
                );
                None
            }
        }
    }

    /// `grant`'s placeholder: the one this epoch already derived, or one
    /// derived now under the environment's key, which is read for this call
    /// alone and dropped here. The outcome labels the timing line; a failure
    /// is one closed reason.
    async fn derived_placeholder(
        &self,
        placeholders: &EpochPlaceholders,
        grant: &DerivedGrant,
    ) -> Result<CredentialPlaceholder, PlaceholderUse> {
        let inputs = placeholder_inputs(grant);
        if let Some(placeholder) = placeholders.get(&inputs) {
            timing::placeholder(PlaceholderUse::Reused);
            return Ok(placeholder);
        }
        let key = match &self.session.identity {
            RuntimeIdentity::Hosted { .. } => {
                self.credentials
                    .environment_placeholder_key(&grant.environment_id)
                    .await
            }
            // A local VM on a platform profile has no environments row: its
            // key comes from its owner's local root, by the admitted
            // session's user and environment, never a frame (#6191).
            RuntimeIdentity::OwnerLocal { .. } => {
                let context = &self.session.context;
                if grant.environment_id != context.environment_id {
                    timing::placeholder(PlaceholderUse::NotFound);
                    return Err(PlaceholderUse::NotFound);
                }
                self.credentials
                    .owner_local_placeholder_key(&context.user_id, &context.environment_id)
                    .await
            }
        };
        match key {
            Ok(key) => {
                let placeholder = lease_placeholder(&key, grant);
                placeholders.insert(inputs, placeholder.clone());
                timing::placeholder(PlaceholderUse::Derived);
                Ok(placeholder)
            }
            Err(error) => {
                let reason = placeholder_failure(&error);
                timing::placeholder(reason);
                Err(reason)
            }
        }
    }

    /// The placeholders an intercepted hosted epoch's Sandbox projects
    /// (#4001; docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception"):
    /// for each projected slot the binding grants ([`projected_grants`]), its
    /// credential's placeholder, derived and kept exactly as this epoch's
    /// leases derive theirs. A slot the binding doesn't grant has none, and
    /// the `github` slot has one only while GitHub's hosts are bound.
    /// Admission reads it once. A grant evaluation that fails, or a key that
    /// cannot be read or created, refuses the admission, so a Sandbox never
    /// gets part of a set. A service whose hosted placeholders are off, which
    /// its deployment must never pair with interception, projects none (the
    /// bridge logs that): the Sandbox then has no Anthropic bearer, never a
    /// real credential.
    pub(crate) async fn projected_placeholders(
        &self,
    ) -> Result<ProjectedPlaceholders, BrokerLeaseError> {
        let Some(placeholders) = &self.placeholders else {
            return Ok(ProjectedPlaceholders::default());
        };
        let session = self.session().await?;
        if !matches!(session.identity, RuntimeIdentity::Hosted { .. }) {
            return Err(BrokerLeaseError::Denied);
        }
        let available = self.available_grants(&session).await?;
        let github_bound = crate::network::binds_github(&available);
        let ProjectedGrants { anthropic, github } = projected_grants(&available, github_bound);
        let mut projected = ProjectedPlaceholders::default();
        if let Some(grant) = anthropic {
            projected =
                projected.with_anthropic(self.projected_placeholder(placeholders, grant).await?);
        }
        if let Some(grant) = github {
            projected =
                projected.with_github(self.projected_placeholder(placeholders, grant).await?);
        }
        Ok(projected)
    }

    /// One projected slot's placeholder; a key that cannot be read refuses
    /// the admission.
    async fn projected_placeholder(
        &self,
        placeholders: &EpochPlaceholders,
        grant: &DerivedGrant,
    ) -> Result<CredentialPlaceholder, BrokerLeaseError> {
        self.derived_placeholder(placeholders, grant)
            .await
            .map_err(|reason| {
                tracing::warn!(
                    environment_id = grant.environment_id.as_str(),
                    reason = reason.label(),
                    "an intercepted epoch was refused: its environment's placeholder key could not be read"
                );
                BrokerLeaseError::Unavailable
            })
    }
}

/// The grants whose placeholders an intercepted epoch's Sandbox projects.
#[derive(Debug, Default, PartialEq, Eq)]
struct ProjectedGrants<'a> {
    /// The `anthropic` slot's, which its API-key and subscription-token forms
    /// take as a variable.
    anthropic: Option<&'a DerivedGrant>,
    /// The `github` slot's, only while GitHub's hosts are bound: unbound,
    /// Git and `gh` keep their loopback route and take no placeholder.
    github: Option<&'a DerivedGrant>,
}

/// The projected slots' grants among `available`; `github_bound` says
/// whether GitHub's hosts are bound (`network::binds_github`).
fn projected_grants(available: &AvailableGrants, github_bound: bool) -> ProjectedGrants<'_> {
    let granted = |slot: CapabilitySlot| {
        available
            .grants
            .iter()
            .find(|grant| grant.capability_slot == slot)
    };
    ProjectedGrants {
        anthropic: granted(CapabilitySlot::anthropic()),
        github: github_bound
            .then(|| granted(CapabilitySlot::github()))
            .flatten(),
    }
}

/// `grant`'s placeholder under its environment's `key`: the same derivation,
/// from the same grant fields, as a local lease's. Like local, it takes the
/// selected binding's profile revision, not the environment generation, so a
/// new generation of the same binding keeps its placeholders (#4812).
pub(super) fn lease_placeholder(
    key: &PlaceholderKey,
    grant: &DerivedGrant,
) -> CredentialPlaceholder {
    CredentialPlaceholder::derive(
        key,
        &grant.environment_id,
        grant.profile.as_ref().map_or(0, |profile| profile.revision),
        &grant.capability_slot,
        &grant.credential_id,
    )
}

/// The seed placeholders of a local VM on a platform profile (#4001;
/// docs/dev/SECRETS-AND-CREDENTIALS.md, "Its seed placeholders"): for each of
/// `slots` that `grants` grants, in that order, exactly the placeholder a
/// lease of that grant carries in an owner-local delegation epoch of
/// `user`'s `environment`, derived under `user`'s local root as such a lease
/// derives it. A slot not granted is left out. The key is read only when a
/// slot is granted, and is dropped here; a key that cannot be read or
/// created fails the whole answer. `grants` must come from an admission of
/// `user`'s selection for `environment`, which the caller has made.
pub(super) async fn owner_local_seed_placeholders(
    credentials: &PlatformCredentialStore,
    user: &OwnerId,
    environment: &EnvironmentId,
    grants: &AvailableGrants,
    slots: &[CapabilitySlot],
) -> Result<Vec<(CapabilitySlot, CredentialPlaceholder)>, PlatformCredentialError> {
    let granted: Vec<&DerivedGrant> = slots
        .iter()
        .filter_map(|slot| {
            grants
                .grants
                .iter()
                .find(|grant| &grant.capability_slot == slot)
        })
        .collect();
    if granted.is_empty() {
        return Ok(Vec::new());
    }
    // As a lease's: never a grant of another environment.
    if granted
        .iter()
        .any(|grant| &grant.environment_id != environment)
    {
        return Err(PlatformCredentialError::NotFound);
    }
    let key = credentials
        .owner_local_placeholder_key(user, environment)
        .await?;
    Ok(granted
        .into_iter()
        .map(|grant| {
            (
                grant.capability_slot.clone(),
                lease_placeholder(&key, grant),
            )
        })
        .collect())
}

/// The one closed reason a placeholder key read failed for. The database and
/// the key-encryption provider both count as the provider: either way the key
/// was there to read and could not be.
fn placeholder_failure(error: &PlatformCredentialError) -> PlaceholderUse {
    match error {
        PlatformCredentialError::NotFound => PlaceholderUse::NotFound,
        PlatformCredentialError::CorruptRecord => PlaceholderUse::CorruptRecord,
        _ => PlaceholderUse::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use codewire_access::{
        BrokerOperationId, BrokerRouteId, CredentialId, EnvironmentId, GrantPermission,
    };

    use super::*;

    fn grant(slot: &str) -> DerivedGrant {
        DerivedGrant {
            environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
            environment_generation: 3,
            profile: None,
            capability_slot: CapabilitySlot::parse(slot).unwrap(),
            credential_id: CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            credential_revocation_generation: 7,
            expires_at_unix: None,
            permissions: BTreeSet::from([GrantPermission {
                operation: BrokerOperationId::parse("responses").unwrap(),
                route: BrokerRouteId::parse("route").unwrap(),
            }]),
        }
    }

    fn available(slots: &[&str]) -> AvailableGrants {
        AvailableGrants {
            grants: slots.iter().map(|slot| grant(slot)).collect(),
            reconnect_required: Default::default(),
            ungranted_github: codewire_access::UngrantedGitHub::None,
        }
    }

    fn slots(projected: &ProjectedGrants<'_>) -> Vec<&'static str> {
        [
            projected.anthropic.map(|_| "anthropic"),
            projected.github.map(|_| "github"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The set carries the `github` slot's placeholder only when the binding
    /// grants that slot and GitHub's hosts are bound; the `anthropic` slot's
    /// whenever it is granted. No other slot is ever projected (#4001).
    #[test]
    fn the_github_slot_is_projected_only_while_its_hosts_are_bound() {
        let both = available(&["codex", "anthropic", "github", "ssh"]);
        assert_eq!(
            slots(&projected_grants(&both, true)),
            ["anthropic", "github"]
        );
        assert_eq!(slots(&projected_grants(&both, false)), ["anthropic"]);
        let github = available(&["github"]);
        assert_eq!(slots(&projected_grants(&github, true)), ["github"]);
        assert!(slots(&projected_grants(&github, false)).is_empty());
        let neither = available(&["codex", "openai", "ssh"]);
        assert!(slots(&projected_grants(&neither, true)).is_empty());
        assert_eq!(
            projected_grants(&both, true).github,
            both.grants
                .iter()
                .find(|grant| grant.capability_slot == CapabilitySlot::github())
        );
    }
}
