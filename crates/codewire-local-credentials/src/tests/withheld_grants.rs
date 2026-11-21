use super::*;

/// A local profile credential that was revoked withholds only its own
/// capability: the profile's other credential keeps its grant and its lease,
/// and the revoked one is refused as it always was (#5545).
#[test]
fn a_revoked_profile_credential_withholds_only_its_own_capability() {
    let responses = || GrantPermission {
        operation: BrokerOperationId::parse("responses").expect("operation ID"),
        route: BrokerRouteId::parse("openai-api").expect("route ID"),
    };
    let catalog = ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider("openai"),
        authentication_kinds: BTreeSet::from([
            CredentialAuthKind::OAuth,
            CredentialAuthKind::ApiKey,
        ]),
        capabilities: BTreeMap::from([
            (
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                    permissions: BTreeSet::from([responses()]),
                },
            ),
            (
                CapabilitySlot::openai(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
                    permissions: BTreeSet::from([responses()]),
                },
            ),
        ]),
    }])
    .expect("provider catalog");
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog)
        .expect("open authority");
    let sign_in = authority
        .add_credential(new_credential("sign-in"), material(b"sign-in-token"))
        .expect("add sign-in");
    let key = authority
        .add_credential(
            NewCredential {
                authentication_kind: CredentialAuthKind::ApiKey,
                ..new_credential("api-key")
            },
            material(b"api-key"),
        )
        .expect("add API key");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            BTreeMap::from([
                (CapabilitySlot::codex(), sign_in.metadata.id.clone()),
                (CapabilitySlot::openai(), key.metadata.id.clone()),
            ]),
        )
        .expect("create profile");
    let environment_id = environment("env-withheld");
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .expect("bind profile");
    authority
        .revoke_credential(&sign_in.metadata.id)
        .expect("revoke sign-in");

    let grants = authority
        .evaluate_environment_grants(&environment_id, 7)
        .expect("one revoked credential doesn't refuse the selection");
    assert_eq!(
        grants
            .iter()
            .map(|grant| grant.capability_slot.clone())
            .collect::<Vec<_>>(),
        vec![CapabilitySlot::openai()]
    );
    assert!(matches!(
        authority.lease_environment_credential_operation(&operation_lease_request(&environment_id)),
        Err(LocalCredentialError::CredentialWithheld(
            codewire_access::WithheldReason::Revoked
        ))
    ));
    let lease = authority
        .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
            capability_slot: CapabilitySlot::openai(),
            ..operation_lease_request(&environment_id)
        })
        .expect("the other capability still leases");
    assert_eq!(lease.with_material(<[u8]>::to_vec), b"api-key");
    // A binding to that profile is still accepted, as `cw update` makes one.
    authority
        .replace_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            profile.profile.revision,
            profile.profile.id.clone(),
            profile.profile.revision,
        )
        .expect("rebinding a profile with a revoked credential succeeds");
}
