//! A local store opens after its authority stops at any write step of a
//! refresh, for each sign-in it refreshes (#5177).

use super::*;

/// The sign-ins whose refresh runs through the local refresh journal.
#[derive(Clone, Copy, Debug)]
enum SignIn {
    Codex,
    Claude,
}

impl SignIn {
    fn credential(self) -> NewCredential {
        let (provider_id, authentication_kind) = match self {
            Self::Codex => ("openai", CredentialAuthKind::OAuth),
            Self::Claude => ("anthropic", CredentialAuthKind::ClaudeSignIn),
        };
        NewCredential {
            provider: provider(provider_id),
            authentication_kind,
            display_name: "work".to_owned(),
            account_hint: Some("work@example.test".to_owned()),
            expires_at_unix: Some(4_102_444_800),
        }
    }

    fn request(self, environment_id: &EnvironmentId) -> CredentialOperationLeaseRequest {
        let (capability_slot, operation, route) = match self {
            Self::Codex => (CapabilitySlot::codex(), "responses", "openai-api"),
            Self::Claude => (CapabilitySlot::anthropic(), "messages", "anthropic-api"),
        };
        CredentialOperationLeaseRequest {
            environment_id: environment_id.clone(),
            environment_generation: 7,
            capability_slot,
            operation: BrokerOperationId::parse(operation).expect("operation ID"),
            route: BrokerRouteId::parse(route).expect("route ID"),
        }
    }
}

/// The last write step of a refresh that completed before the authority
/// stopped, in the order a refresh makes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LastWrite {
    /// The journal row and its Reserved marker, one transaction.
    Reserve,
    /// The marker moved to Started: the provider may have rotated the token.
    Start,
    /// The broker stored the refreshed material as the next generation.
    Stage,
    /// The commit published the next generation; the old material remains.
    Publish,
    /// The old material was removed; its journal row remains.
    Retire,
}

const LAST_WRITES: [LastWrite; 5] = [
    LastWrite::Reserve,
    LastWrite::Start,
    LastWrite::Stage,
    LastWrite::Publish,
    LastWrite::Retire,
];

fn open(
    root: &std::path::Path,
    store: &TestProtectedStore,
) -> Result<LocalCredentialAuthority<TestProtectedStore>, LocalCredentialError> {
    LocalCredentialAuthority::open(
        root,
        store.clone(),
        codewire_access::builtin_provider_catalog(),
    )
}

/// Adds the sign-in, selects it for one environment and reserves its refresh.
/// Returns the credential and the refresh's channel, refresh and request IDs.
fn reserve_refresh(
    authority: &LocalCredentialAuthority<TestProtectedStore>,
    sign_in: SignIn,
    request: &CredentialOperationLeaseRequest,
) -> (CredentialId, (Uuid, Uuid, Uuid)) {
    let credential = authority
        .add_credential(sign_in.credential(), material(b"synthetic-old-sign-in"))
        .expect("add sign-in");
    let id = credential.metadata.id.clone();
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            BTreeMap::from([(request.capability_slot.clone(), id.clone())]),
        )
        .expect("create profile");
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: request.environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .expect("bind environment access");
    let grant = authority
        .admit_environment_credential_operation(request)
        .expect("admit the sign-in")
        .grant;
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (channel_id, refresh_id, request_id) = ids;
    assert!(matches!(
        authority.begin_environment_credential_refresh(
            channel_id, refresh_id, request_id, request, &grant, 1,
        ),
        Ok(CredentialRefreshAdmission::Reserved(_))
    ));
    (id, ids)
}

/// One case: the authority stops after `last`, and the store reopens.
fn stop_and_reopen(sign_in: SignIn, last: LastWrite) {
    let context = format!("{sign_in:?} stopped after {last:?}");
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let request = sign_in.request(&environment("env-refresh-crash"));
    let id = {
        let authority = open(&root, &store).expect("open authority");
        let (id, (channel_id, refresh_id, request_id)) =
            reserve_refresh(&authority, sign_in, &request);
        if last >= LastWrite::Start {
            authority
                .start_environment_credential_refresh(channel_id, refresh_id, request_id)
                .expect("durable start");
        }
        if last >= LastWrite::Stage {
            store
                .put(
                    &protected_entry_id(&id, 2).expect("next entry"),
                    &material(b"synthetic-new-sign-in"),
                )
                .expect("stage the refreshed sign-in");
        }
        if last >= LastWrite::Publish {
            // The removal of the old material fails before, or right
            // after, it takes effect; the commit still answers.
            store.set_delete_fault(if last == LastWrite::Publish {
                Fault::BeforeEffect
            } else {
                Fault::AfterEffect
            });
            authority
                .commit_environment_credential_refresh(channel_id, refresh_id, request_id)
                .unwrap_or_else(|error| panic!("{context}: commit: {error}"));
            store.clear_faults();
        }
        // Dropping the authority here is it stopping after `last`.
        id
    };

    let authority =
        open(&root, &store).unwrap_or_else(|error| panic!("{context}: reopen: {error}"));
    let connection = authority.connection().expect("credential database");
    assert!(
        load_credential_refresh_marker(&connection, &id)
            .expect("read marker")
            .is_none(),
        "{context}: the refresh marker is resolved"
    );
    assert!(
        load_protected_entry_journal(&connection, &id)
            .expect("read journal")
            .is_none(),
        "{context}: the journal is resolved"
    );
    drop(connection);
    assert_eq!(store.entry_count(), 1, "{context}: one material remains");
    let record = authority.get_credential(&id).expect("read credential");
    let lease = authority.lease_environment_credential_operation(&request);
    match last {
        LastWrite::Reserve => {
            // No provider request was allowed: the sign-in is as it was.
            assert_eq!(
                record.metadata.status,
                CredentialStatus::Active,
                "{context}"
            );
            assert_eq!(record.metadata.revocation_generation, 1, "{context}");
            let lease = lease.expect("lease the old sign-in");
            assert_eq!(lease.material_generation(), 1, "{context}");
            assert_eq!(
                lease.with_material(<[u8]>::to_vec),
                b"synthetic-old-sign-in"
            );
        }
        LastWrite::Start => {
            // Reconnect needed: the old refresh token is never sent again.
            assert_eq!(
                record.metadata.status,
                CredentialStatus::RefreshFailed,
                "{context}"
            );
            assert_eq!(record.metadata.revocation_generation, 2, "{context}");
            assert!(lease.is_err(), "{context}: a failed sign-in is not leased");
        }
        LastWrite::Stage | LastWrite::Publish | LastWrite::Retire => {
            assert_eq!(
                record.metadata.status,
                CredentialStatus::Active,
                "{context}"
            );
            assert_eq!(record.metadata.revocation_generation, 2, "{context}");
            let lease = lease.expect("lease the refreshed sign-in");
            assert_eq!(lease.material_generation(), 2, "{context}");
            assert_eq!(
                lease.with_material(<[u8]>::to_vec),
                b"synthetic-new-sign-in"
            );
        }
    }
}

#[test]
fn a_store_opens_after_a_crash_at_each_write_step_of_a_refresh() {
    // Every case runs, so a failure names each stop point that breaks.
    let failed: Vec<_> = [SignIn::Codex, SignIn::Claude]
        .into_iter()
        .flat_map(|sign_in| LAST_WRITES.map(|last| (sign_in, last)))
        .filter(|&(sign_in, last)| {
            std::panic::catch_unwind(|| stop_and_reopen(sign_in, last)).is_err()
        })
        .collect();
    assert!(failed.is_empty(), "failed cases: {failed:?}");
}

#[test]
fn a_failed_refresh_of_either_sign_in_reads_reconnect_needed() {
    for sign_in in [SignIn::Codex, SignIn::Claude] {
        let temp = TempDir::new().expect("temporary directory");
        let root = authority_root(&temp);
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let request = sign_in.request(&environment("env-refresh-failed"));
        let authority = open(&root, &store).expect("open authority");
        let (id, (channel_id, refresh_id, request_id)) =
            reserve_refresh(&authority, sign_in, &request);
        authority
            .start_environment_credential_refresh(channel_id, refresh_id, request_id)
            .expect("durable start");
        let failed = authority
            .fail_environment_credential_refresh(channel_id, refresh_id, request_id)
            .unwrap_or_else(|error| panic!("{sign_in:?}: fail: {error}"));
        assert_eq!(failed.metadata.status, CredentialStatus::RefreshFailed);
        assert_eq!(failed.metadata.revocation_generation, 2);
        drop(authority);

        let authority = open(&root, &store).unwrap_or_else(|error| panic!("{sign_in:?}: {error}"));
        assert_eq!(
            authority
                .get_credential(&id)
                .expect("read credential")
                .metadata
                .status,
            CredentialStatus::RefreshFailed
        );
    }
}
