//! The parts of an environment credential admission that a lease and an
//! environment's placeholder share: the grant for one slot, and the
//! credential it selects once that credential is usable now.

use codewire_access::{
    CapabilitySlot, CredentialStatus, DerivedGrant, EnvironmentId, GrantPermission,
};
use codewire_protected_store::ProtectedStore;
use rusqlite::Connection;

use crate::{
    InternalCredentialRecord, LocalCredentialAuthority, LocalCredentialError, MaterialState,
    derive_local_environment_grants, load_environment_access_binding, load_internal_credential,
    unix_seconds,
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

    /// The grant the environment's current binding derives for `slot`.
    fn environment_slot_grant_at(
        &self,
        connection: &Connection,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
    ) -> Result<DerivedGrant, LocalCredentialError> {
        let binding = load_environment_access_binding(connection, environment_id)?.binding;
        derive_local_environment_grants(
            connection,
            &binding,
            environment_generation,
            &self.owner_id,
            &self.catalog,
        )?
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
