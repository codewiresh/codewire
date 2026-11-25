//! A slot's grant from one evaluation, and the checks a lease applies to it
//! and to the credential record it reads.

use super::*;

/// The slot's grant from one grant evaluation, with its deadline attenuated
/// to `session`'s identity expiry. A credential that needs Reconnect withholds
/// only its own slot: say so for exactly that slot; every other absence, or a
/// grant without `permission`, is a denial.
pub(super) fn select_grant(
    available: &AvailableGrants,
    session: &PlatformRuntimeSession,
    slot: &CapabilitySlot,
    permission: &GrantPermission,
) -> Result<DerivedGrant, BrokerLeaseError> {
    let Some(grant) = available
        .grants
        .iter()
        .find(|grant| &grant.capability_slot == slot)
    else {
        // Grant evaluation rejects the whole selection for anything but
        // lifecycle, so a slot with neither a grant nor a withheld credential
        // is one the profile doesn't fill.
        return Err(match available.reconnect_required.get(slot) {
            Some(withheld) => BrokerLeaseError::ReconnectRequired(withheld.reason),
            None if *slot == CapabilitySlot::github() => match available.ungranted_github {
                codewire_access::UngrantedGitHub::NotConnected => {
                    BrokerLeaseError::ReconnectRequired(WithheldReason::NeedsReconnect)
                }
                codewire_access::UngrantedGitHub::NotAuthorized => BrokerLeaseError::Denied,
                codewire_access::UngrantedGitHub::None => BrokerLeaseError::NotSelected,
            },
            None => BrokerLeaseError::NotSelected,
        });
    };
    if !grant.permissions.contains(permission) {
        return Err(BrokerLeaseError::Denied);
    }
    let mut grant = grant.clone();
    grant.expires_at_unix = Some(
        grant
            .expires_at_unix
            .unwrap_or(session.identity_expires_at_unix)
            .min(session.identity_expires_at_unix),
    );
    Ok(grant)
}

/// Why one evaluation of a checked lease failed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Checked {
    /// A refusal, which stands.
    Refused(BrokerLeaseError),
    /// The credential's record moved to another revocation generation, still
    /// active, while the lease read it.
    Moved,
}

impl Checked {
    /// `record`, read for `grant`'s credential and found not to match it:
    /// `Moved` when it is that same active platform credential of `owner` at
    /// another revocation generation, otherwise a denial.
    pub(super) fn moved(grant: &DerivedGrant, owner: &Owner, record: &CredentialRecord) -> Self {
        let metadata = &record.metadata;
        if metadata.id == grant.credential_id
            && metadata.placement == Placement::Platform
            && metadata.owner == *owner
            && metadata.status == CredentialStatus::Active
            && record.version.revocation_generation != grant.credential_revocation_generation
        {
            Self::Moved
        } else {
            Self::Refused(BrokerLeaseError::Denied)
        }
    }

    /// The answer of a lease that is not evaluated again.
    pub(super) fn refused(self) -> BrokerLeaseError {
        match self {
            Self::Refused(error) => error,
            Self::Moved => BrokerLeaseError::Denied,
        }
    }
}

impl From<BrokerLeaseError> for Checked {
    fn from(error: BrokerLeaseError) -> Self {
        Self::Refused(error)
    }
}

/// Whether `record` is the exact platform record `grant` was derived for,
/// owned by `owner`.
pub(super) fn record_matches(
    record: &CredentialRecord,
    grant: &DerivedGrant,
    owner: &Owner,
) -> bool {
    record.metadata.id == grant.credential_id
        && record.metadata.placement == Placement::Platform
        && record.metadata.owner == *owner
        && record.version.revocation_generation != 0
        && record.version.material_generation != 0
        && record.metadata.revocation_generation == grant.credential_revocation_generation
        && record.version.revocation_generation == grant.credential_revocation_generation
}

pub(super) fn same_grant_binding(a: &DerivedGrant, b: &DerivedGrant) -> bool {
    a.environment_id == b.environment_id
        && a.environment_generation == b.environment_generation
        && a.profile == b.profile
        && a.capability_slot == b.capability_slot
        && a.credential_id == b.credential_id
        && a.permissions == b.permissions
}

pub(super) fn ensure_live(
    metadata: &CredentialMetadata,
    grant: &DerivedGrant,
) -> Result<(), BrokerLeaseError> {
    let now = unix_now().map_err(runtime_error)?;
    if metadata.status != codewire_access::CredentialStatus::Active
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_none_or(|expiry| expiry <= now)
    {
        return Err(BrokerLeaseError::Denied);
    }
    Ok(())
}
