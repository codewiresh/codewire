//! One hosted epoch's derived placeholders (#4001), kept by the inputs each
//! is derived from.

use codewire_access::{CredentialPlaceholder, DerivedGrant};

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
pub(super) type PlaceholderInputs = (String, u64, String, String);

pub(super) fn placeholder_inputs(grant: &DerivedGrant) -> PlaceholderInputs {
    (
        grant.environment_id.as_str().to_owned(),
        grant.profile.as_ref().map_or(0, |profile| profile.revision),
        grant.capability_slot.as_str().to_owned(),
        grant.credential_id.as_str().to_owned(),
    )
}

impl EpochPlaceholders {
    pub(super) fn get(&self, inputs: &PlaceholderInputs) -> Option<CredentialPlaceholder> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(inputs)
            .cloned()
    }

    pub(super) fn insert(&self, inputs: PlaceholderInputs, placeholder: CredentialPlaceholder) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(inputs, placeholder);
    }
}
