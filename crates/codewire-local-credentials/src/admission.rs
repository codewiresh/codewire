//! The parts of an environment credential admission that a lease and an
//! environment's placeholder share: the grant for one slot, and the
//! credential it selects once that credential is usable now.

use std::collections::BTreeSet;

use codewire_access::{
    CapabilitySlot, CredentialStatus, DerivedGrant, EnvironmentAccessBinding, EnvironmentId,
    GrantContext, GrantPermission, GrantPlacement, OwnerId, ProviderCatalog,
    derive_available_grants,
};
use codewire_protected_store::ProtectedStore;
use rusqlite::Connection;

use crate::{
    InternalCredentialRecord, LocalCredentialAuthority, LocalCredentialError, MaterialState,
    active_github_connection, load_environment_access_binding, load_internal_credential,
    load_profile_revision, load_ready_credential_metadata, unix_seconds,
};

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// One environment slot's admission, in a lease's order: the grant the
    /// environment's current binding derives for `slot`, `permission` in
    /// that grant when the caller has one (only a lease names an operation),
    /// and the credential the grant selects, usable now.
    pub(crate) fn admit_environment_slot_at(
        &self,
        connection: &Connection,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
        permission: Option<&GrantPermission>,
    ) -> Result<(DerivedGrant, InternalCredentialRecord), LocalCredentialError> {
        let grant = self.environment_slot_grant_at(
            connection,
            environment_id,
            environment_generation,
            slot,
        )?;
        if permission.is_some_and(|permission| !grant.permissions.contains(permission)) {
            return Err(LocalCredentialError::CredentialOperationLeaseDenied);
        }
        let record = load_granted_credential(connection, &grant)?;
        Ok((grant, record))
    }

    /// The grant the environment's current binding derives for `slot`. A slot
    /// whose credential is withheld (revoked, expired or needing reconnect)
    /// is refused as that credential is, and only that slot (#5545).
    fn environment_slot_grant_at(
        &self,
        connection: &Connection,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
    ) -> Result<DerivedGrant, LocalCredentialError> {
        let binding = load_environment_access_binding(connection, environment_id)?.binding;
        let mut available = derive_local_available_grants(
            connection,
            &binding,
            environment_generation,
            &self.owner_id,
            &self.catalog,
        )?;
        // The refusal a whole-selection derivation gave this slot before.
        if let Some(withheld) = available.reconnect_required.remove(slot) {
            return Err(LocalCredentialError::CredentialWithheld(withheld.reason));
        }
        available
            .grants
            .into_iter()
            .find(|grant| grant.capability_slot == *slot)
            .ok_or(LocalCredentialError::CredentialOperationLeaseDenied)
    }
}

/// The credential `grant` selects, once it is ready, unrevoked since the grant
/// was derived, active and unexpired.
fn load_granted_credential(
    connection: &Connection,
    grant: &DerivedGrant,
) -> Result<InternalCredentialRecord, LocalCredentialError> {
    let record =
        load_internal_credential(connection, &grant.credential_id, Some(MaterialState::Ready))?;
    if record.public.metadata.revocation_generation != grant.credential_revocation_generation {
        return Err(LocalCredentialError::CredentialOperationLeaseDenied);
    }
    if record.public.metadata.status != CredentialStatus::Active {
        return Err(LocalCredentialError::CredentialInactive);
    }
    if let Some(expires_at) = record.public.metadata.expires_at_unix
        && expires_at <= unix_seconds()?
    {
        return Err(LocalCredentialError::CredentialInactive);
    }
    Ok(record)
}

/// The grants an environment's binding derives now. A profile credential that
/// was revoked, expired or needs reconnecting withholds only its own
/// capability, as in a hosted Sandbox (#5545): a local VM is the user's own
/// machine, so one such credential never refuses the rest.
pub(crate) fn derive_local_environment_grants(
    connection: &Connection,
    binding: &EnvironmentAccessBinding,
    environment_generation: u64,
    owner_id: &OwnerId,
    catalog: &ProviderCatalog,
) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
    derive_local_available_grants(
        connection,
        binding,
        environment_generation,
        owner_id,
        catalog,
    )
    .map(|available| available.grants)
}

/// [`derive_local_environment_grants`] with the capabilities it withholds and
/// why.
fn derive_local_available_grants(
    connection: &Connection,
    binding: &EnvironmentAccessBinding,
    environment_generation: u64,
    owner_id: &OwnerId,
    catalog: &ProviderCatalog,
) -> Result<codewire_access::AvailableGrants, LocalCredentialError> {
    let profile =
        load_profile_revision(connection, &binding.profile_id, binding.profile_revision)?.profile;
    let credentials = load_ready_credential_metadata(connection)?;
    let context = GrantContext {
        environment_id: binding.environment_id.clone(),
        environment_generation,
        placement: GrantPlacement::Local,
        user_id: owner_id.clone(),
        organization_id: None,
        allow_personal_credentials: false,
        authorized_credentials: profile
            .entries
            .values()
            .cloned()
            .chain(if profile.includes_github() {
                active_github_connection(connection)?
            } else {
                None
            })
            .collect::<BTreeSet<_>>(),
    };
    derive_available_grants(
        &context,
        binding,
        &profile,
        &credentials,
        catalog,
        unix_seconds()?,
    )
    .map_err(Into::into)
}
