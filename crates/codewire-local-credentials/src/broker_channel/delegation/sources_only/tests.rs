use super::*;

mod owner_flow;
mod selection;

use codewire_access::builtin_provider_catalog;
use codewire_gateway_proto::projection::{decode_local_inventories, encode_platform_inventories};
use codewire_project::PlatformProjectionSelection;
use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
use codewire_workload_secrets::{
    EnvironmentProjection, ProjectionCompositionPlan, ProjectionContributor, ProjectionRecipient,
    ProjectionSourceInventory, WorkloadSecretSource, seal_environment_projection,
    seal_environment_projection_fragment,
};
use futures::future::BoxFuture;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{Notify, Semaphore, oneshot};
use zeroize::Zeroizing;

use crate::broker_channel::{
    BrokerLeaseAuditLog, BrokerLeaseChannelControl, BrokerPlatformMode,
    LocalCredentialBrokerLeaseClient, serve_broker_lease_channel_with_ready,
};
use crate::control::v1::local_credential_broker_lease_service_server::LocalCredentialBrokerLeaseService;
use crate::{
    LocalCredentialAuthority, LocalEnvironmentProjectionBinding, LocalLaunchSecretSelection,
    PlatformCredentialBinding, PlatformCredentialConnector,
};

#[derive(Clone, Copy)]
enum Mode {
    Seal,
    Deny,
    WrongId,
    WrongKind,
    Downgrade,
    Pending,
}

#[derive(Default)]
struct Observation {
    admissions: AtomicUsize,
    requests: AtomicUsize,
    dropped: AtomicBool,
    requested: Notify,
    selection: std::sync::Mutex<Option<(PlatformCredentialBinding, bridge::CredentialBridgeReady)>>,
}

struct OutputOwner(Arc<Observation>);

impl Drop for OutputOwner {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Release);
    }
}

struct SyntheticConnector {
    mode: Mode,
    observation: Arc<Observation>,
}

impl PlatformCredentialConnector for SyntheticConnector {
    fn connect(
        &self,
        binding: PlatformCredentialBinding,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<PlatformCredentialOutput, Status>> {
        assert!(binding.selection.profile.is_none());
        assert!(deadline > Instant::now());
        *self.observation.selection.lock().unwrap() = Some((binding.clone(), ready.clone()));
        self.observation.admissions.fetch_add(1, Ordering::Relaxed);
        let mode = self.mode;
        let owner = OutputOwner(Arc::clone(&self.observation));
        Box::pin(async move {
            let output = stream::try_unfold(
                (input, binding, ready, owner),
                move |(mut input, binding, ready, owner)| async move {
                    let Some(frame) = input.next().await else {
                        return Ok(None);
                    };
                    let Some(
                        bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(
                            request,
                        ),
                    ) = frame?.payload
                    else {
                        return Err(denied());
                    };
                    owner.0.requests.fetch_add(1, Ordering::Relaxed);
                    owner.0.requested.notify_one();
                    if matches!(mode, Mode::Pending) {
                        std::future::pending::<()>().await;
                    }
                    let frame = synthetic_response(&binding, &ready, request, mode);
                    Ok(Some((frame, (input, binding, ready, owner))))
                },
            );
            Ok(Box::pin(output) as PlatformCredentialOutput)
        })
    }
}

fn synthetic_response(
    binding: &PlatformCredentialBinding,
    ready: &bridge::CredentialBridgeReady,
    request: bridge::EnvironmentProjectionRequest,
    mode: Mode,
) -> bridge::CredentialBridgeHostMessage {
    if matches!(mode, Mode::WrongKind) {
        return bridge::CredentialBridgeHostMessage {
            payload: Some(
                bridge::credential_bridge_host_message::Payload::ResponseEnd(
                    bridge::CredentialBridgeResponseEnd {
                        request_id: request.request_id,
                    },
                ),
            ),
        };
    }
    let now = crate::unix_millis().unwrap();
    let context = ProjectionContext {
        environment_id: *Uuid::parse_str(&ready.environment_id).unwrap().as_bytes(),
        operation_generation: ready.environment_generation,
        selection_sha256: binding.selection_sha256,
        deadline_unix_ms: request.deadline_unix_ms,
    };
    let recipient = request.recipient_public_key.as_slice().try_into().unwrap();
    let values = EnvironmentProjection::from_entries([(
        "PLATFORM_ONLY".to_owned(),
        Zeroizing::new(b"synthetic-platform".to_vec()),
    )])
    .unwrap();
    let result = if matches!(mode, Mode::Deny) {
        bridge::environment_projection_response::Result::Failure(
            bridge::CredentialBridgeFailureReason::Denied as i32,
        )
    } else if request.local_inventories.is_empty() || matches!(mode, Mode::Downgrade) {
        bridge::environment_projection_response::Result::SealedProjection(
            seal_environment_projection(values, &context, recipient, now).unwrap(),
        )
    } else {
        let platform = vec![ProjectionSourceInventory {
            contributor: ProjectionContributor::Platform,
            source: WorkloadSecretSource::Organization,
            source_identity: binding.selection.source_identities()[0].1.clone(),
            keys: ["PLATFORM_ONLY".into()].into(),
        }];
        let mut inventories = decode_local_inventories(&request.local_inventories).unwrap();
        inventories.extend(platform.clone());
        inventories.sort_by_key(|inventory| inventory.source);
        let plan = ProjectionCompositionPlan::new(
            &context,
            *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
            recipient,
            &inventories,
            &binding.selection.ordinary_keys,
            &binding.selection.reserved_keys,
            now,
        )
        .unwrap();
        bridge::environment_projection_response::Result::Composition(
            bridge::EnvironmentProjectionComposition {
                sealed_platform_fragment: seal_environment_projection_fragment(
                    values,
                    &context,
                    recipient,
                    ProjectionContributor::Platform,
                    &plan,
                    now,
                )
                .unwrap(),
                platform_inventories: encode_platform_inventories(&platform).unwrap(),
            },
        )
    };
    bridge::CredentialBridgeHostMessage {
        payload: Some(
            bridge::credential_bridge_host_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionResponse {
                    request_id: if matches!(mode, Mode::WrongId) {
                        Uuid::new_v4().to_string()
                    } else {
                        request.request_id
                    },
                    result: Some(result),
                },
            ),
        ),
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    rpc: Arc<BrokerLeaseRpc<EphemeralProtectedStore>>,
    context: ProjectionContext,
    observation: Arc<Observation>,
    manager_ready: oneshot::Receiver<()>,
}

fn fixture(mode: Mode, mixed: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    authority
        .set_user_workload_secret(
            "LOCAL_ONLY",
            ProtectedValue::from_slice(b"synthetic-local").unwrap(),
        )
        .unwrap();
    let context = ProjectionContext {
        environment_id: *Uuid::new_v4().as_bytes(),
        operation_generation: 7,
        selection_sha256: [17; 32],
        deadline_unix_ms: crate::unix_millis().unwrap() + 30_000,
    };
    let binding = PlatformCredentialBinding {
        config_directory: temp.path().join("platform"),
        server_url: "https://platform.invalid".into(),
        selection_sha256: context.selection_sha256,
        selection: PlatformProjectionSelection {
            creator: "owner".into(),
            organization: "organization".into(),
            organization_selected: true,
            project_id: None,
            user_selected: false,
            profile: None,
            ordinary_keys: Default::default(),
            reserved_keys: ["CODEX_HOME".into()].into(),
        },
    };
    let projection = mixed.then(|| LocalEnvironmentProjectionBinding {
        selection: LocalLaunchSecretSelection {
            user: true,
            reserved_keys: binding.selection.reserved_keys.clone(),
            ..Default::default()
        },
        selection_sha256: context.selection_sha256,
    });
    let observation = Arc::new(Observation::default());
    let connector = Arc::new(SyntheticConnector {
        mode,
        observation: Arc::clone(&observation),
    });
    let lifetime = BrokerChannelRefreshLifetime::new(Arc::clone(&authority));
    let (ready, manager_ready) = oneshot::channel();
    let rpc = Arc::new(BrokerLeaseRpc {
        local_profile: None,
        authority,
        channel_id: lifetime.channel_id,
        refresh_lifetime: lifetime,
        environment_id: EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string())
            .unwrap(),
        environment_generation: context.operation_generation,
        audit: Arc::new(BrokerLeaseAuditLog::default()),
        ready: Mutex::new(Some(ready)),
        projection,
        projection_operations: Arc::new(Semaphore::new(1)),
        platform: Mutex::new(Some((binding, connector))),
        platform_mode: BrokerPlatformMode::SourcesOnly,
        platform_admitted: Arc::new(AtomicBool::new(false)),
        platform_sources: Mutex::new(None),
    });
    Fixture {
        _temp: temp,
        rpc,
        context,
        observation,
        manager_ready,
    }
}

fn ready(f: &Fixture) -> bridge::CredentialBridgeReady {
    bridge::CredentialBridgeReady {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: f.rpc.environment_id.to_string(),
        environment_generation: f.context.operation_generation,
    }
}

fn request(f: &Fixture, recipient: &ProjectionRecipient) -> v1::BrokerEnvironmentProjectionRequest {
    v1::BrokerEnvironmentProjectionRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        selection_sha256: f.context.selection_sha256.to_vec(),
        deadline_unix_ms: f.context.deadline_unix_ms,
    }
}

async fn admit(f: &Fixture) -> Result<Response<v1::BrokerReadyResponse>, Status> {
    f.rpc
        .report_broker_ready(Request::new(v1::BrokerReadyRequest {
            protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
            guest_ready: Some(ready(f)),
        }))
        .await
}

#[tokio::test]
async fn sources_only_ready_is_exact_once_only_and_keeps_local_provider_mode() {
    let mut f = fixture(Mode::Seal, false);
    assert!(f.rpc.require_local_mode().is_ok());
    let recipient = ProjectionRecipient::new();
    assert!(
        f.rpc
            .project_platform_sources(request(&f, &recipient))
            .await
            .is_err()
    );
    assert_eq!(f.observation.admissions.load(Ordering::Relaxed), 0);
    admit(&f).await.unwrap();
    assert_eq!(f.manager_ready.try_recv(), Ok(()));
    assert!(admit(&f).await.is_err());
    assert_eq!(f.observation.admissions.load(Ordering::Relaxed), 1);

    let f = fixture(Mode::Seal, false);
    let mut wrong = ready(&f);
    wrong.environment_generation += 1;
    assert!(
        f.rpc
            .report_broker_ready(Request::new(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
                guest_ready: Some(wrong),
            }))
            .await
            .is_err()
    );
    assert_eq!(f.observation.admissions.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn local_provider_sources_reuse_one_admission_and_launcher_opens_complete_values() {
    for mixed in [false, true] {
        let f = fixture(Mode::Seal, mixed);
        admit(&f).await.unwrap();
        for _ in 0..2 {
            let recipient = ProjectionRecipient::new();
            let response = f
                .rpc
                .project_environment(Request::new(request(&f, &recipient)))
                .await
                .unwrap()
                .into_inner();
            let opened = recipient
                .open(
                    &response.sealed_projection,
                    &f.context,
                    crate::unix_millis().unwrap(),
                )
                .unwrap();
            let values: std::collections::BTreeMap<_, _> = opened.entries().collect();
            assert_eq!(values.len(), if mixed { 2 } else { 1 });
            assert_eq!(values.get("PLATFORM_ONLY"), Some(&"synthetic-platform"));
            if mixed {
                assert_eq!(values.get("LOCAL_ONLY"), Some(&"synthetic-local"));
            }
        }
        assert_eq!(f.observation.admissions.load(Ordering::Relaxed), 1);
        assert_eq!(f.observation.requests.load(Ordering::Relaxed), 2);
        assert!(!f.rpc.refresh_lifetime.closed.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn source_response_mismatch_or_mixed_downgrade_drops_connection_and_epoch() {
    for (mode, mixed) in [
        (Mode::WrongId, false),
        (Mode::WrongKind, false),
        (Mode::Downgrade, true),
    ] {
        let f = fixture(mode, mixed);
        admit(&f).await.unwrap();
        let recipient = ProjectionRecipient::new();
        assert!(
            f.rpc
                .project_platform_sources(request(&f, &recipient))
                .await
                .is_err()
        );
        assert!(f.rpc.refresh_lifetime.closed.load(Ordering::Acquire));
        assert!(f.observation.dropped.load(Ordering::Acquire));
        assert!(f.rpc.platform_sources.lock().await.is_none());
    }
}

#[tokio::test]
async fn explicit_denial_is_complete_but_invalid_request_never_enters_source_connection() {
    let f = fixture(Mode::Deny, false);
    admit(&f).await.unwrap();
    let recipient = ProjectionRecipient::new();
    let mut invalid = request(&f, &recipient);
    invalid.selection_sha256[0] ^= 1;
    assert!(f.rpc.project_platform_sources(invalid).await.is_err());
    assert_eq!(f.observation.requests.load(Ordering::Relaxed), 0);
    for _ in 0..2 {
        assert_eq!(
            f.rpc
                .project_platform_sources(request(&f, &recipient))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    assert_eq!(f.observation.requests.load(Ordering::Relaxed), 2);
    assert!(!f.rpc.refresh_lifetime.closed.load(Ordering::Acquire));
}

#[tokio::test]
async fn cancelling_source_exchange_drops_both_directions_and_keeps_no_late_response() {
    let f = fixture(Mode::Pending, true);
    admit(&f).await.unwrap();
    let recipient = ProjectionRecipient::new();
    let request = request(&f, &recipient);
    let rpc = Arc::clone(&f.rpc);
    let task = tokio::spawn(async move { rpc.project_platform_sources(request).await });
    tokio::time::timeout(Duration::from_secs(2), f.observation.requested.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(f.observation.dropped.load(Ordering::Acquire));
    assert!(f.rpc.refresh_lifetime.closed.load(Ordering::Acquire));
    assert!(f.rpc.platform_sources.lock().await.is_none());
    f.rpc.refresh_lifetime.wait_for_operations().await;
}

#[tokio::test]
async fn inherited_source_rpc_uses_actual_ready_and_epoch_close_stops_server_with_peer_open() {
    let f = fixture(Mode::Seal, true);
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::spawn(serve_broker_lease_channel_with_ready(
        Arc::clone(&f.rpc.refresh_lifetime),
        server_stream,
        f.rpc.environment_id.clone(),
        f.context.operation_generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        f.rpc.projection.clone(),
        BrokerLeaseChannelControl {
            local_profile: None,
            ready: Some(ready_tx),
            shutdown: None,
            platform: f.rpc.platform.lock().await.take(),
            platform_delegated: false,
        },
    ));
    let mut client = LocalCredentialBrokerLeaseClient::connect(
        client_stream,
        crate::tests::TestProtectedStore::new(
            codewire_protected_store::ProtectedStorePersistence::ProcessLifetime,
        ),
        f.rpc.environment_id.clone(),
        f.context.operation_generation,
    )
    .await
    .unwrap();
    client.report_ready(ready(&f)).await.unwrap();
    ready_rx.await.unwrap();
    let recipient = ProjectionRecipient::new();
    let sealed = client
        .project_environment(
            Uuid::new_v4(),
            recipient.public_key(),
            f.context.selection_sha256,
            f.context.deadline_unix_ms,
        )
        .await
        .unwrap();
    assert_eq!(
        recipient
            .open(&sealed, &f.context, crate::unix_millis().unwrap())
            .unwrap()
            .entries()
            .len(),
        2
    );
    f.rpc.refresh_lifetime.close();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(f.observation.dropped.load(Ordering::Acquire));
    drop(client);
}
