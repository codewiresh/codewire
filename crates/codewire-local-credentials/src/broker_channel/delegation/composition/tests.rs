use super::*;
use crate::LocalLaunchSecretSelection;
use codewire_access::builtin_provider_catalog;
use codewire_daemon_proto::projection::{decode_local_inventories, encode_platform_inventories};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
};
use codewire_workload_secrets::{
    EnvironmentProjection, ProjectionContributor, ProjectionRecipient, seal_environment_projection,
    seal_environment_projection_fragment,
};
use std::sync::atomic::AtomicUsize;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
struct Store {
    inner: Arc<EphemeralProtectedStore>,
    reads: Arc<AtomicUsize>,
}
impl ProtectedStore for Store {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.inner.persistence()
    }
    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get(id)
    }
    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        self.inner.put(id, value)
    }
    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.inner.delete(id)
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    composer: Arc<ProjectionComposer<Store>>,
    context: ProjectionContext,
    store: Store,
}

fn fixture(mixed: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::default();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            store.clone(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    for (key, value) in [
        ("SHARED", b"local-user".as_slice()),
        ("LOCAL_ONLY", b"local-only"),
        ("OVERRIDDEN", b"must-not-read"),
    ] {
        authority
            .set_user_workload_secret(key, ProtectedValue::from_slice(value).unwrap())
            .unwrap();
    }
    store.reads.store(0, Ordering::Relaxed);
    let context = ProjectionContext {
        environment_id: *Uuid::new_v4().as_bytes(),
        operation_generation: 7,
        selection_sha256: [5; 32],
        deadline_unix_ms: now().unwrap() + 30_000,
    };
    let local = LocalEnvironmentProjectionBinding {
        selection: LocalLaunchSecretSelection {
            user: true,
            overridden_keys: ["OVERRIDDEN".into()].into(),
            reserved_keys: ["CODEX_HOME".into()].into(),
            ..Default::default()
        },
        selection_sha256: context.selection_sha256,
    };
    let platform = PlatformCredentialBinding {
        config_directory: temp.path().join("platform"),
        server_url: "https://platform.invalid".into(),
        selection_sha256: context.selection_sha256,
        selection: PlatformProjectionSelection {
            creator: "owner".into(),
            organization: "organization".into(),
            organization_selected: mixed,
            project_id: mixed.then(|| Uuid::new_v4().to_string()),
            user_selected: false,
            profile: Some((Uuid::new_v4().to_string(), 1)),
            ordinary_keys: local.selection.overridden_keys.clone(),
            reserved_keys: local.selection.reserved_keys.clone(),
        },
    };
    let lifetime = BrokerChannelRefreshLifetime::new(Arc::clone(&authority));
    let rpc = BrokerLeaseRpc {
        local_profile: None,
        authority,
        channel_id: lifetime.channel_id,
        refresh_lifetime: lifetime,
        environment_id: EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string())
            .unwrap(),
        environment_generation: context.operation_generation,
        audit: Arc::new(super::super::super::BrokerLeaseAuditLog::default()),
        ready: Mutex::new(None),
        projection: Some(local),
        projection_operations: Arc::new(Semaphore::new(1)),
        platform: Mutex::new(None),
        platform_mode: super::super::super::BrokerPlatformMode::Delegated,
        platform_admitted: Arc::new(AtomicBool::new(true)),
        platform_sources: Mutex::new(None),
    };
    let composer = ProjectionComposer::for_binding(&rpc, &platform)
        .unwrap()
        .unwrap();
    Fixture {
        _temp: temp,
        composer,
        context,
        store,
    }
}

fn request(f: &Fixture, recipient: &ProjectionRecipient) -> bridge::CredentialBridgeGuestMessage {
    bridge::CredentialBridgeGuestMessage {
        payload: Some(
            bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionRequest {
                    request_id: Uuid::new_v4().to_string(),
                    recipient_public_key: recipient.public_key().to_vec(),
                    selection_sha256: f.context.selection_sha256.to_vec(),
                    deadline_unix_ms: f.context.deadline_unix_ms,
                    local_inventories: Vec::new(),
                },
            ),
        ),
    }
}

fn projection_request(
    frame: &bridge::CredentialBridgeGuestMessage,
) -> &bridge::EnvironmentProjectionRequest {
    let Some(bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(request)) =
        &frame.payload
    else {
        panic!("projection request");
    };
    request
}

fn response(
    f: &Fixture,
    prepared: &bridge::CredentialBridgeGuestMessage,
) -> bridge::CredentialBridgeHostMessage {
    let request = projection_request(prepared);
    let recipient = request.recipient_public_key.as_slice().try_into().unwrap();
    let output = if f.composer.mixed {
        let platform: Vec<_> = f
            .composer
            .platform
            .source_identities()
            .into_iter()
            .map(|(source, source_identity)| ProjectionSourceInventory {
                contributor: ProjectionContributor::Platform,
                source,
                source_identity,
                keys: if source == codewire_workload_secrets::WorkloadSecretSource::Organization {
                    ["ORG_ONLY".into(), "SHARED".into()].into()
                } else {
                    ["PROJECT_ONLY".into(), "SHARED".into()].into()
                },
            })
            .collect();
        let mut inventories = decode_local_inventories(&request.local_inventories).unwrap();
        inventories.extend(platform.clone());
        inventories.sort_by_key(|inventory| inventory.source);
        let plan = ProjectionCompositionPlan::new(
            &f.context,
            *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
            recipient,
            &inventories,
            &f.composer.platform.ordinary_keys,
            &f.composer.platform.reserved_keys,
            now().unwrap(),
        )
        .unwrap();
        let values = EnvironmentProjection::from_entries(
            plan.winning_keys(ProjectionContributor::Platform)
                .iter()
                .map(|key| {
                    (
                        key.clone(),
                        Zeroizing::new(format!("platform-{key}").into_bytes()),
                    )
                }),
        )
        .unwrap();
        let sealed_platform_fragment = seal_environment_projection_fragment(
            values,
            &f.context,
            recipient,
            ProjectionContributor::Platform,
            &plan,
            now().unwrap(),
        )
        .unwrap();
        bridge::environment_projection_response::Result::Composition(
            bridge::EnvironmentProjectionComposition {
                sealed_platform_fragment,
                platform_inventories: encode_platform_inventories(&platform).unwrap(),
            },
        )
    } else {
        let empty = EnvironmentProjection::from_entries(Vec::<(String, Zeroizing<Vec<u8>>)>::new())
            .unwrap();
        bridge::environment_projection_response::Result::SealedProjection(
            seal_environment_projection(empty, &f.context, recipient, now().unwrap()).unwrap(),
        )
    };
    bridge::CredentialBridgeHostMessage {
        payload: Some(
            bridge::credential_bridge_host_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionResponse {
                    request_id: request.request_id.clone(),
                    result: Some(output),
                },
            ),
        ),
    }
}

fn response_mut(
    frame: &mut bridge::CredentialBridgeHostMessage,
) -> &mut bridge::EnvironmentProjectionResponse {
    let Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(response)) =
        &mut frame.payload
    else {
        panic!("projection response");
    };
    response
}

#[tokio::test]
async fn actual_owner_composition_reads_only_local_winners_and_launcher_opens_both() {
    let f = fixture(true);
    let recipient = ProjectionRecipient::new();
    let mut input = f
        .composer
        .input(Box::pin(stream::iter([Ok(request(&f, &recipient))])));
    let prepared = input.next().await.unwrap().unwrap();
    assert_eq!(f.store.reads.load(Ordering::Relaxed), 0);
    assert_eq!(projection_request(&prepared).local_inventories.len(), 1);
    let mut output = f
        .composer
        .output(Box::pin(stream::iter([Ok(response(&f, &prepared))])));
    let mut completed = output.next().await.unwrap().unwrap();
    let Some(bridge::environment_projection_response::Result::SealedProjection(bytes)) =
        response_mut(&mut completed).result.take()
    else {
        panic!("complete bundle only");
    };
    let values = recipient.open(&bytes, &f.context, now().unwrap()).unwrap();
    assert_eq!(
        values.entries().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            ("LOCAL_ONLY", "local-only"),
            ("SHARED", "local-user"),
            ("ORG_ONLY", "platform-ORG_ONLY"),
            ("PROJECT_ONLY", "platform-PROJECT_ONLY"),
        ])
    );
    assert_eq!(f.store.reads.load(Ordering::Relaxed), 2);
    assert!(f.composer.pending.lock().await.is_empty());
}

#[tokio::test]
async fn platform_profile_local_application_sources_never_forward_empty_remote_values() {
    let f = fixture(false);
    let recipient = ProjectionRecipient::new();
    let prepared = Arc::clone(&f.composer)
        .prepare(request(&f, &recipient))
        .await
        .unwrap();
    assert!(projection_request(&prepared).local_inventories.is_empty());
    let mut completed = Arc::clone(&f.composer)
        .complete(response(&f, &prepared))
        .await
        .unwrap();
    let Some(bridge::environment_projection_response::Result::SealedProjection(bytes)) =
        response_mut(&mut completed).result.take()
    else {
        panic!("complete bundle");
    };
    assert_eq!(
        recipient
            .open(&bytes, &f.context, now().unwrap())
            .unwrap()
            .entries()
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("LOCAL_ONLY", "local-only"), ("SHARED", "local-user")])
    );
}

#[tokio::test]
async fn mixed_mode_rejects_single_downgrade_wrong_or_missing_platform_scopes_before_reads() {
    for field in 0..5 {
        let f = fixture(true);
        let recipient = ProjectionRecipient::new();
        let prepared = Arc::clone(&f.composer)
            .prepare(request(&f, &recipient))
            .await
            .unwrap();
        let mut response = response(&f, &prepared);
        let output = response_mut(&mut response);
        if field == 0 {
            let empty =
                EnvironmentProjection::from_entries(Vec::<(String, Zeroizing<Vec<u8>>)>::new())
                    .unwrap();
            output.result = Some(
                bridge::environment_projection_response::Result::SealedProjection(
                    seal_environment_projection(
                        empty,
                        &f.context,
                        recipient.public_key(),
                        now().unwrap(),
                    )
                    .unwrap(),
                ),
            );
        } else {
            let Some(bridge::environment_projection_response::Result::Composition(composition)) =
                &mut output.result
            else {
                panic!("composition");
            };
            match field {
                1 => {
                    composition.platform_inventories.pop();
                }
                2 => composition.platform_inventories[0]
                    .source_identity
                    .push_str("-other-owner"),
                3 => composition.platform_inventories.reverse(),
                _ => composition.platform_inventories[0]
                    .keys
                    .push("SHARED".into()),
            }
        }
        assert!(
            Arc::clone(&f.composer).complete(response).await.is_err(),
            "field {field}"
        );
        assert_eq!(f.store.reads.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn guest_cannot_supply_inventory_or_change_the_immutable_selection() {
    for field in 0..3 {
        let f = fixture(true);
        let recipient = ProjectionRecipient::new();
        let mut request = request(&f, &recipient);
        let Some(bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(value)) =
            &mut request.payload
        else {
            unreachable!();
        };
        match field {
            0 => value
                .local_inventories
                .push(bridge::EnvironmentProjectionInventory::default()),
            1 => value.selection_sha256[0] ^= 1,
            _ => value.deadline_unix_ms = 1,
        }
        if field == 0 {
            assert!(!super::super::valid_remaining_frame(&request));
        }
        assert!(Arc::clone(&f.composer).prepare(request).await.is_err());
        assert_eq!(f.store.reads.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn changed_local_names_cancelled_request_and_closed_epoch_do_not_release_values() {
    for effect in 0..3 {
        let f = fixture(true);
        let recipient = ProjectionRecipient::new();
        let prepared = Arc::clone(&f.composer)
            .prepare(request(&f, &recipient))
            .await
            .unwrap();
        let remote = response(&f, &prepared);
        match effect {
            0 => {
                f.composer
                    .authority
                    .set_user_workload_secret(
                        "ADDED",
                        ProtectedValue::from_slice(b"new-name").unwrap(),
                    )
                    .unwrap();
            }
            1 => {
                Arc::clone(&f.composer)
                    .prepare(bridge::CredentialBridgeGuestMessage {
                        payload: Some(bridge::credential_bridge_guest_message::Payload::Cancel(
                            bridge::CredentialBridgeCancel {
                                request_id: projection_request(&prepared).request_id.clone(),
                            },
                        )),
                    })
                    .await
                    .unwrap();
            }
            _ => f.composer.lifetime.closed.store(true, Ordering::Release),
        }
        // The synthetic writer checks its new protected-entry collision. Count
        // projection reads separately from that deliberate source mutation.
        let before_projection = f.store.reads.load(Ordering::Relaxed);
        assert!(Arc::clone(&f.composer).complete(remote).await.is_err());
        assert_eq!(f.store.reads.load(Ordering::Relaxed), before_projection);
    }
}

#[tokio::test]
async fn pending_projection_rejects_duplicate_ids_and_unsolicited_responses() {
    let f = fixture(true);
    let recipient = ProjectionRecipient::new();
    let original = request(&f, &recipient);
    let prepared = Arc::clone(&f.composer)
        .prepare(original.clone())
        .await
        .unwrap();
    assert!(Arc::clone(&f.composer).prepare(original).await.is_err());
    let mut response = response(&f, &prepared);
    response_mut(&mut response).request_id = Uuid::new_v4().to_string();
    assert!(Arc::clone(&f.composer).complete(response).await.is_err());
    assert_eq!(f.store.reads.load(Ordering::Relaxed), 0);
}
