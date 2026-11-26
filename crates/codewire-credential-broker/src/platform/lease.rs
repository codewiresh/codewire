//! What one platform lease hands the broker: the record and grant it
//! admitted and the material it read. A hosted epoch's lease also notes,
//! when its value is swapped into a request, the use that request's sends
//! make (#6189).

use codewire_access::{CredentialMetadata, CredentialPlaceholder, DerivedGrant, GrantPermission};
use codewire_platform_credentials::CredentialRecord;
use codewire_protected_store::ProtectedValue;

use crate::BrokerCredentialLease;
use crate::credential_uses::{self, EpochUses};

/// Non-cloneable, non-serializable, zeroizing operation material.
pub struct PlatformCredentialLease {
    pub(super) record: CredentialRecord,
    pub(super) grant: DerivedGrant,
    pub(super) permission: GrantPermission,
    pub(super) material: ProtectedValue,
    pub(super) placeholder: Option<CredentialPlaceholder>,
    pub(super) placeholder_failed: bool,
    /// Where a hosted epoch's uses fold; `None` for any other lease.
    pub(super) uses: Option<EpochUses>,
}

impl BrokerCredentialLease for PlatformCredentialLease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        &self.record.metadata
    }
    fn grant(&self) -> &DerivedGrant {
        &self.grant
    }
    fn permission(&self) -> &GrantPermission {
        &self.permission
    }
    fn material_generation(&self) -> u64 {
        self.record.version.material_generation
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        if let Some(uses) = &self.uses {
            let metadata = &self.record.metadata;
            credential_uses::swapped(uses, metadata.id.as_str(), metadata.provider.as_str());
        }
        operation(self.material.expose_secret())
    }
    fn placeholder(&self) -> Option<&CredentialPlaceholder> {
        self.placeholder.as_ref()
    }
    fn placeholder_failed(&self) -> bool {
        self.placeholder_failed
    }
}
