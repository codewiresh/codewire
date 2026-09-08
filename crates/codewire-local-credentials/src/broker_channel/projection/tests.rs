use std::sync::atomic::AtomicUsize;
use std::sync::{Condvar, Mutex as StdMutex};

use codewire_access::builtin_provider_catalog;
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
};
use codewire_workload_secrets::ProjectionRecipient;

use super::*;

#[derive(Default)]
struct Gate {
    enabled: AtomicBool,
    started: tokio::sync::Notify,
    released: StdMutex<bool>,
    changed: Condvar,
}

struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.changed.notify_all();
    }
}

#[derive(Clone, Default)]
struct Store {
    inner: Arc<EphemeralProtectedStore>,
    reads: Arc<AtomicUsize>,
    gate: Option<Arc<Gate>>,
}
impl ProtectedStore for Store {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.inner.persistence()
    }
    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(gate) = &self.gate
            && gate.enabled.load(Ordering::Acquire)
        {
            gate.started.notify_one();
            let mut released = gate.released.lock().unwrap();
            while !*released {
                released = gate.changed.wait(released).unwrap();
            }
        }
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

fn fixture(
    store: Store,
) -> (
    tempfile::TempDir,
    Arc<LocalCredentialAuthority<Store>>,
    ProjectionContext,
) {
    let temp = tempfile::tempdir().unwrap();
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            store.clone(),
            builtin_provider_catalog(),
        )
        .unwrap(),
    );
    authority
        .set_user_workload_secret(
            "DATABASE_URL",
            ProtectedValue::from_slice(b"synthetic-db-url").unwrap(),
        )
        .unwrap();
    store.reads.store(0, Ordering::Relaxed);
    if let Some(gate) = store.gate.as_ref() {
        gate.enabled.store(true, Ordering::Release);
    }
    let context = ProjectionContext {
        environment_id: *Uuid::new_v4().as_bytes(),
        operation_generation: 7,
        selection_sha256: [2; 32],
        deadline_unix_ms: crate::unix_millis().unwrap() + 30_000,
    };
    (temp, authority, context)
}

fn binding(context: &ProjectionContext) -> LocalEnvironmentProjectionBinding {
    LocalEnvironmentProjectionBinding {
        selection: LocalLaunchSecretSelection {
            user: true,
            ..Default::default()
        },
        selection_sha256: context.selection_sha256,
    }
}

fn rpc(
    authority: Arc<LocalCredentialAuthority<Store>>,
    context: &ProjectionContext,
) -> BrokerLeaseRpc<Store> {
    let refresh_lifetime = BrokerChannelRefreshLifetime::new(Arc::clone(&authority));
    let channel_id = refresh_lifetime.channel_id;
    BrokerLeaseRpc {
        local_profile: None,
        refresh_lifetime,
        authority,
        channel_id,
        environment_id: EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string())
            .unwrap(),
        environment_generation: context.operation_generation,
        audit: Arc::new(BrokerLeaseAuditLog::default()),
        ready: Mutex::new(None),
        projection: Some(binding(context)),
        projection_operations: Arc::new(Semaphore::new(1)),
        platform: Mutex::new(None),
        platform_mode: BrokerPlatformMode::Local,
        platform_admitted: Arc::new(AtomicBool::new(false)),
        platform_sources: Mutex::new(None),
    }
}

fn request(
    context: &ProjectionContext,
    recipient: &ProjectionRecipient,
) -> v1::BrokerEnvironmentProjectionRequest {
    v1::BrokerEnvironmentProjectionRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: recipient.public_key().to_vec(),
        selection_sha256: context.selection_sha256.to_vec(),
        deadline_unix_ms: context.deadline_unix_ms,
    }
}

#[tokio::test]
async fn inherited_channel_seals_only_bound_application_values_and_observes_rotation() {
    let store = Store::default();
    let (_temp, authority, context) = fixture(store.clone());
    // Prove the encrypted RPC exceeds the old64KiB metadata transport limit.
    authority
        .set_user_workload_secret(
            "LARGE",
            ProtectedValue::from_slice(&vec![b'x'; 64 * 1024]).unwrap(),
        )
        .unwrap();
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let environment_id =
        EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string()).unwrap();
    let server = tokio::spawn(serve_broker_lease_channel_with_ready(
        BrokerChannelRefreshLifetime::new(Arc::clone(&authority)),
        server_stream,
        environment_id.clone(),
        context.operation_generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        Some(binding(&context)),
        BrokerLeaseChannelControl::default(),
    ));
    let client = LocalCredentialBrokerLeaseClient::connect(
        client_stream,
        store.clone(),
        environment_id,
        context.operation_generation,
    )
    .await
    .unwrap();
    for expected in ["synthetic-db-url", "synthetic-rotated-db-url"] {
        let recipient = ProjectionRecipient::new();
        let sealed = client
            .project_environment(
                Uuid::new_v4(),
                recipient.public_key(),
                context.selection_sha256,
                context.deadline_unix_ms,
            )
            .await
            .unwrap();
        assert!(sealed.len() > 64 * 1024);
        assert!(
            !sealed
                .windows(expected.len())
                .any(|window| window == expected.as_bytes())
        );
        let projection = recipient
            .open(&sealed, &context, crate::unix_millis().unwrap())
            .unwrap();
        assert!(
            projection
                .entries()
                .any(|(key, value)| key == "DATABASE_URL" && value == expected)
        );
        authority
            .set_user_workload_secret(
                "DATABASE_URL",
                ProtectedValue::from_slice(b"synthetic-rotated-db-url").unwrap(),
            )
            .unwrap();
    }
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn absent_binding_and_wrong_context_fail_before_material_reads() {
    let store = Store::default();
    let (_temp, authority, context) = fixture(store.clone());
    let mut service = rpc(authority, &context);
    let recipient = ProjectionRecipient::new();
    for kind in 0..7 {
        let mut input = request(&context, &recipient);
        match kind {
            0 => input.selection_sha256[0] ^= 1,
            1 => input.request_id = Uuid::nil().to_string(),
            2 => input.recipient_public_key.pop().map(|_| ()).unwrap(),
            3 => input.deadline_unix_ms = crate::unix_millis().unwrap(),
            4 => input.recipient_public_key = vec![0; 32],
            5 => {
                input.recipient_public_key = vec![255; 32];
                input.recipient_public_key[0] = 0xed;
                input.recipient_public_key[31] = 0x7f;
            }
            6 => service.projection = None,
            _ => unreachable!(),
        }
        assert_eq!(
            service
                .project_bound_environment(input)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    assert_eq!(store.reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn managed_shutdown_waits_for_blocking_projection_and_denies_late_delivery() {
    let gate = Arc::new(Gate::default());
    let release = ReleaseGate(Arc::clone(&gate));
    let store = Store {
        gate: Some(Arc::clone(&gate)),
        ..Default::default()
    };
    let (_temp, authority, context) = fixture(store.clone());
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let environment_id =
        EnvironmentId::parse(Uuid::from_bytes(context.environment_id).to_string()).unwrap();
    let (shutdown, stopped) = watch::channel(false);
    let mut server = tokio::spawn(serve_broker_lease_channel_with_ready(
        BrokerChannelRefreshLifetime::new(authority),
        server_stream,
        environment_id.clone(),
        context.operation_generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        Some(binding(&context)),
        BrokerLeaseChannelControl {
            local_profile: None,
            ready: None,
            shutdown: Some(stopped),
            platform: None,
            platform_delegated: false,
        },
    ));
    let client = LocalCredentialBrokerLeaseClient::connect(
        client_stream,
        store,
        environment_id,
        context.operation_generation,
    )
    .await
    .unwrap();
    let recipient = ProjectionRecipient::new();
    let request = tokio::spawn(async move {
        client
            .project_environment(
                Uuid::new_v4(),
                recipient.public_key(),
                context.selection_sha256,
                context.deadline_unix_ms,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.started.notified())
        .await
        .unwrap();
    shutdown.send(true).unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut server)
            .await
            .is_err()
    );
    drop(release);
    assert!(request.await.unwrap().is_err());
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn channel_revocation_during_blocking_read_denies_late_delivery() {
    let gate = Arc::new(Gate::default());
    let release = ReleaseGate(Arc::clone(&gate));
    let store = Store {
        gate: Some(Arc::clone(&gate)),
        ..Default::default()
    };
    let (_temp, authority, context) = fixture(store);
    let service = Arc::new(rpc(authority, &context));
    let recipient = ProjectionRecipient::new();
    let input = request(&context, &recipient);
    let task_service = Arc::clone(&service);
    let task = tokio::spawn(async move { task_service.project_bound_environment(input).await });
    gate.started.notified().await;
    service.refresh_lifetime.close();
    assert_eq!(
        service
            .refresh_lifetime
            .active_operations
            .load(Ordering::Acquire),
        1
    );
    drop(release);
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        service
            .refresh_lifetime
            .active_operations
            .load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn cancellation_does_not_reopen_blocking_projection_capacity() {
    let gate = Arc::new(Gate::default());
    let release = ReleaseGate(Arc::clone(&gate));
    let store = Store {
        gate: Some(Arc::clone(&gate)),
        ..Default::default()
    };
    let (_temp, authority, context) = fixture(store.clone());
    let service = Arc::new(rpc(authority, &context));
    let recipient = ProjectionRecipient::new();
    let input = request(&context, &recipient);
    let task_service = Arc::clone(&service);
    let task = tokio::spawn(async move { task_service.project_bound_environment(input).await });
    gate.started.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let denied = service
        .project_bound_environment(request(&context, &recipient))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::ResourceExhausted);
    assert_eq!(store.reads.load(Ordering::Relaxed), 1);
    drop(release);
    let _barrier = service.projection_operations.acquire().await.unwrap();
    assert_eq!(
        service
            .refresh_lifetime
            .active_operations
            .load(Ordering::Acquire),
        0
    );
}
