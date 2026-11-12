//! The placeholder a lease carries (#3999): the local authority's, and none
//! from any other lease.

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot,
    CredentialAuthKind, EnvironmentAccessBinding, EnvironmentId, GrantPermission, ProviderCatalog,
    ProviderDefinition, ProviderId,
};
use codewire_local_credentials::{
    CredentialOperationLeaseRequest, LocalCredentialAuthority, NewCredential,
};
use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
use tempfile::TempDir;

use crate::BrokerCredentialLease;
use crate::http_test_support::Lease;

#[test]
fn a_test_fake_lease_carries_no_placeholder() {
    let lease = Lease::new(
        "openai",
        CredentialAuthKind::ApiKey,
        "openai",
        "responses",
        "openai-api",
    );
    assert!(BrokerCredentialLease::placeholder(&lease).is_none());
}

#[test]
fn a_local_lease_carries_its_authoritys_placeholder() {
    let permission = GrantPermission {
        operation: BrokerOperationId::parse("responses").unwrap(),
        route: BrokerRouteId::parse("openai-api").unwrap(),
    };
    let catalog = ProviderCatalog::from_definitions([ProviderDefinition {
        id: ProviderId::parse("openai").unwrap(),
        authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
        capabilities: BTreeMap::from([(
            CapabilitySlot::openai(),
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
                permissions: BTreeSet::from([permission.clone()]),
            },
        )]),
    }])
    .unwrap();
    let temp = TempDir::new().unwrap();
    let authority = LocalCredentialAuthority::open(
        &temp.path().join("authority"),
        EphemeralProtectedStore::default(),
        catalog,
    )
    .unwrap();
    let credential = authority
        .add_credential(
            NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
                display_name: "synthetic".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"synthetic-openai-material").unwrap(),
        )
        .unwrap();
    let profile = authority
        .create_profile(
            AccessProfileName::parse("synthetic").unwrap(),
            BTreeMap::from([(CapabilitySlot::openai(), credential.metadata.id.clone())]),
        )
        .unwrap();
    let environment_id = EnvironmentId::parse("environment-test").unwrap();
    let binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id,
        profile_revision: profile.profile.revision,
    };
    authority
        .create_environment_access_binding(binding.clone())
        .unwrap();
    // Deriving it without a lease loads the authority's placeholder key.
    let expected = authority
        .environment_credential_placeholder(
            &environment_id,
            3,
            &CapabilitySlot::openai(),
            &credential.metadata.id,
            Some(&binding),
        )
        .unwrap();
    let lease = authority
        .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
            environment_id: environment_id.clone(),
            environment_generation: 3,
            capability_slot: CapabilitySlot::openai(),
            operation: permission.operation,
            route: permission.route,
        })
        .unwrap();
    let placeholder = BrokerCredentialLease::placeholder(&lease).unwrap();
    assert!(placeholder.ct_eq(&expected));
}
