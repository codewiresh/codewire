//! A hosted epoch's credential placeholders (#4001): the one each lease
//! carries, and the set an intercepted epoch's Sandbox projects. Both are
//! derived the same way, through the epoch's one cache, kept by the inputs
//! each is derived from.

use codewire_access::{
    CapabilitySlot, CredentialPlaceholder, DerivedGrant, PlaceholderKey, ProjectedPlaceholders,
};
use codewire_platform_credentials::PlatformCredentialError;

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
    /// environment's key, which is read for this lease alone and dropped here.
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
                    reason = reason.label(),
                    "hosted lease carries no placeholder: its environment's key could not be read"
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
        match self
            .credentials
            .environment_placeholder_key(&grant.environment_id)
            .await
        {
            Ok(key) => {
                let placeholder = hosted_placeholder(&key, grant);
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
    /// for each projected slot the binding grants, its credential's
    /// placeholder, derived and kept exactly as this epoch's leases derive
    /// theirs. A slot the binding doesn't grant has none. Admission reads it
    /// once. A grant evaluation that fails, or a key that cannot be read or
    /// created, refuses the admission, so a Sandbox never gets part of a
    /// set. A service whose hosted placeholders are off, which its deployment
    /// must never pair with interception, projects none (the bridge logs
    /// that): the Sandbox then has no Anthropic bearer, never a real
    /// credential.
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
        let mut projected = ProjectedPlaceholders::default();
        if let Some(grant) = available
            .grants
            .iter()
            .find(|grant| grant.capability_slot == CapabilitySlot::anthropic())
        {
            let placeholder = self
                .derived_placeholder(placeholders, grant)
                .await
                .map_err(|reason| {
                    tracing::warn!(
                        environment_id = grant.environment_id.as_str(),
                        reason = reason.label(),
                        "an intercepted epoch was refused: its environment's placeholder key could not be read"
                    );
                    BrokerLeaseError::Unavailable
                })?;
            projected = projected.with_anthropic(placeholder);
        }
        Ok(projected)
    }
}

/// `grant`'s placeholder under its environment's `key`: the same derivation,
/// from the same grant fields, as a local lease's. Like local, it takes the
/// selected binding's profile revision, not the environment generation, so a
/// new generation of the same binding keeps its placeholders (#4812).
pub(super) fn hosted_placeholder(
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
