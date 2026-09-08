use std::collections::BTreeSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::BrokerCredentialLease;
use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
    CredentialId, CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentId,
    GrantPermission, Owner, OwnerId, Placement, ProviderId,
};
use zeroize::Zeroizing;

pub(crate) const TOKEN: &[u8] = b"CW_SYNTHETIC_HTTP_token+/_~==";

pub(crate) struct Lease {
    pub metadata: CredentialMetadata,
    pub grant: DerivedGrant,
    pub permission: GrantPermission,
    pub material: Zeroizing<Vec<u8>>,
    pub reads: Arc<AtomicUsize>,
}

impl Lease {
    pub fn new(
        provider: &str,
        kind: CredentialAuthKind,
        slot: &str,
        operation: &str,
        route: &str,
    ) -> Self {
        let id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let permission = GrantPermission {
            operation: BrokerOperationId::parse(operation).unwrap(),
            route: BrokerRouteId::parse(route).unwrap(),
        };
        Self {
            metadata: CredentialMetadata {
                id: id.clone(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse(provider).unwrap(),
                authentication_kind: kind,
                display_name: "synthetic-only".into(),
                account_hint: None,
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: None,
                revocation_generation: 7,
            },
            grant: DerivedGrant {
                environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                environment_generation: 3,
                profile_id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                profile_revision: 4,
                capability_slot: CapabilitySlot::parse(slot).unwrap(),
                credential_id: id,
                credential_revocation_generation: 7,
                expires_at_unix: None,
                permissions: BTreeSet::from([permission.clone()]),
            },
            permission,
            material: Zeroizing::new(TOKEN.to_vec()),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl BrokerCredentialLease for Lease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        &self.metadata
    }
    fn grant(&self) -> &DerivedGrant {
        &self.grant
    }
    fn permission(&self) -> &GrantPermission {
        &self.permission
    }
    fn material_generation(&self) -> u64 {
        2
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        self.reads.fetch_add(1, Ordering::Relaxed);
        operation(&self.material)
    }
}
