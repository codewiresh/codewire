use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessProfileName, CapabilityPolicy, CredentialAuthKind, EnvironmentAccessBinding,
    EnvironmentId, ProviderCatalog, ProviderDefinition, ProviderId,
};
use codewire_daemon_proto::codewire::bridge::v1 as daemon_v1;
use codewire_protected_store::ProtectedStorePersistence;
use codewire_protected_store::ssh_material::generate_ed25519;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Notify, Semaphore};

use super::*;
use crate::broker_channel::{
    BrokerLeaseAuditLog, BrokerLeaseChannelControl, LocalCredentialBrokerLeaseClient,
    LocalSshOperationRuntime, serve_broker_lease_channel_with_ready,
};
use crate::tests::TestProtectedStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Signature,
    Cleanup,
    Panic,
}

struct Signer {
    calls: AtomicUsize,
    started: Notify,
    release: Semaphore,
    block: AtomicBool,
    outcome: Mutex<Outcome>,
}

impl Signer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Semaphore::new(0),
            block: AtomicBool::new(false),
            outcome: Mutex::new(Outcome::Signature),
        })
    }
}

#[tonic::async_trait]
impl LocalSshSigner for Signer {
    async fn sign_once(
        &self,
        material: SshAgentMaterial,
        request: LocalSshSignRequest,
        deadline: Instant,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<Vec<u8>, LocalSshSignError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(material.public_key().key_blob(), request.public_key_blob);
        assert_eq!(request.data.as_slice(), b"synthetic signing payload");
        assert_eq!(request.flags, 0);
        self.started.notify_one();
        if self.block.load(Ordering::Acquire) {
            let cancelled = tokio::select! {
                biased;
                _ = async {
                    while !*cancellation.borrow() {
                        cancellation.changed().await.unwrap();
                    }
                } => true,
                _ = tokio::time::sleep_until(deadline) => true,
                permit = self.release.acquire() => {
                    permit.unwrap().forget();
                    false
                },
            };
            if cancelled {
                self.release.acquire().await.unwrap().forget();
            }
        }
        match *self.outcome.lock().await {
            Outcome::Signature => Ok(vec![9; 64]),
            Outcome::Cleanup => Err(LocalSshSignError::Cleanup),
            Outcome::Panic => panic!("synthetic signer panic"),
        }
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    authority: Arc<LocalCredentialAuthority<TestProtectedStore>>,
    store: TestProtectedStore,
    lifetime: Arc<BrokerChannelRefreshLifetime<TestProtectedStore>>,
    rpc: Arc<BrokerLeaseRpc<TestProtectedStore>>,
    environment_id: EnvironmentId,
    profile_id: codewire_access::AccessProfileId,
    public_key_blob: Vec<u8>,
}

fn catalog() -> ProviderCatalog {
    let permissions = BTreeSet::from([
        GrantPermission {
            operation: BrokerOperationId::parse("ssh-identities").unwrap(),
            route: BrokerRouteId::parse("ssh-agent").unwrap(),
        },
        GrantPermission {
            operation: BrokerOperationId::parse("ssh-sign").unwrap(),
            route: BrokerRouteId::parse("ssh-agent").unwrap(),
        },
    ]);
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: ProviderId::parse("ssh").unwrap(),
        authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
        capabilities: BTreeMap::from([(
            CapabilitySlot::parse("ssh").unwrap(),
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
                permissions,
            },
        )]),
    }])
    .unwrap()
}

fn fixture(signer: Arc<Signer>) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let store = TestProtectedStore::new(ProtectedStorePersistence::ProcessLifetime);
    let authority = Arc::new(
        LocalCredentialAuthority::open(&temp.path().join("authority"), store.clone(), catalog())
            .unwrap(),
    );
    let prepared = generate_ed25519().unwrap();
    let public_key_blob = prepared.public_key().key_blob().to_vec();
    let credential = authority
        .add_ssh_credential("synthetic-ssh".into(), None, prepared, || Ok(()))
        .unwrap();
    let profile = authority
        .create_profile(
            AccessProfileName::parse("ssh-work").unwrap(),
            BTreeMap::from([(
                CapabilitySlot::parse("ssh").unwrap(),
                credential.metadata.id,
            )]),
        )
        .unwrap();
    let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .unwrap();
    let lifetime = BrokerChannelRefreshLifetime::new_with_ssh_runtime(
        Arc::clone(&authority),
        LocalSshOperationRuntime::new(Some(signer)),
    );
    let rpc = Arc::new(BrokerLeaseRpc {
        local_profile: Some(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        }),
        authority: Arc::clone(&authority),
        channel_id: lifetime.channel_id,
        refresh_lifetime: Arc::clone(&lifetime),
        environment_id: environment_id.clone(),
        environment_generation: 7,
        audit: Arc::new(BrokerLeaseAuditLog::default()),
        ready: Mutex::new(None),
        projection: None,
        projection_operations: Arc::new(tokio::sync::Semaphore::new(1)),
        platform: Mutex::new(None),
        platform_mode: super::super::BrokerPlatformMode::Local,
        platform_admitted: Arc::new(AtomicBool::new(false)),
        platform_sources: Mutex::new(None),
    });
    Fixture {
        _temp: temp,
        authority,
        store,
        lifetime,
        rpc,
        environment_id,
        profile_id: profile.profile.id,
        public_key_blob,
    }
}

#[tokio::test]
async fn generated_tonic_client_forwards_typed_ssh_and_channel_drains() {
    let signer = Signer::new();
    let fixture = fixture(Arc::clone(&signer));
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let server = tokio::spawn(serve_broker_lease_channel_with_ready(
        Arc::clone(&fixture.lifetime),
        server_stream,
        fixture.environment_id.clone(),
        7,
        Arc::new(BrokerLeaseAuditLog::default()),
        None,
        BrokerLeaseChannelControl {
            local_profile: fixture.rpc.local_profile.clone(),
            ..Default::default()
        },
    ));
    let mut client = LocalCredentialBrokerLeaseClient::connect(
        client_stream,
        fixture.store.clone(),
        fixture.environment_id.clone(),
        7,
    )
    .await
    .unwrap();

    let identity = client
        .ssh_operation(
            request(
                Uuid::new_v4(),
                daemon_v1::credential_ssh_request::Operation::Identities(
                    daemon_v1::CredentialSshIdentitiesRequest {},
                ),
            )
            .request
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        identity.result,
        Some(daemon_v1::credential_ssh_response::Result::Identity(
            daemon_v1::CredentialSshIdentity {
                public_key_blob: fixture.public_key_blob.clone(),
            }
        ))
    );
    let signature = client
        .ssh_operation(
            sign(Uuid::new_v4(), fixture.public_key_blob.clone())
                .request
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        signature.result,
        Some(daemon_v1::credential_ssh_response::Result::Signature(
            daemon_v1::CredentialSshSignature {
                signature_blob: vec![9; 64],
            }
        ))
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);

    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        fixture
            .lifetime
            .ssh_operations
            .active
            .lock()
            .unwrap()
            .is_empty()
    );
}

fn deadline() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 29_000
}

fn request(
    id: Uuid,
    operation: daemon_v1::credential_ssh_request::Operation,
) -> v1::BrokerSshRequest {
    v1::BrokerSshRequest {
        protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
        request: Some(daemon_v1::CredentialSshRequest {
            request_id: id.to_string(),
            deadline_unix_ms: deadline(),
            operation: Some(operation),
        }),
    }
}

fn sign(id: Uuid, public_key_blob: Vec<u8>) -> v1::BrokerSshRequest {
    request(
        id,
        daemon_v1::credential_ssh_request::Operation::Sign(daemon_v1::CredentialSshSignRequest {
            public_key_blob,
            data: b"synthetic signing payload".to_vec(),
            flags: 0,
        }),
    )
}

#[tokio::test]
async fn identities_are_current_metadata_only_and_sign_is_exact_key_only() {
    let signer = Signer::new();
    let fixture = fixture(Arc::clone(&signer));
    let identity = fixture
        .rpc
        .run_ssh_operation(request(
            Uuid::new_v4(),
            daemon_v1::credential_ssh_request::Operation::Identities(
                daemon_v1::CredentialSshIdentitiesRequest {},
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        identity.result,
        Some(daemon_v1::credential_ssh_response::Result::Identity(
            daemon_v1::CredentialSshIdentity {
                public_key_blob: fixture.public_key_blob.clone(),
            }
        ))
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);

    let signed = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), fixture.public_key_blob.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        signed.result,
        Some(daemon_v1::credential_ssh_response::Result::Signature(
            daemon_v1::CredentialSshSignature {
                signature_blob: vec![9; 64],
            }
        ))
    );
    let denied = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), vec![7; 32]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        denied.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ))
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn abandoned_waiter_and_channel_close_retain_operation_until_signer_drain() {
    let signer = Signer::new();
    signer.block.store(true, Ordering::Release);
    let fixture = fixture(Arc::clone(&signer));
    let request = sign(Uuid::new_v4(), fixture.public_key_blob.clone());
    let rpc = Arc::clone(&fixture.rpc);
    let waiter = tokio::spawn(async move { rpc.run_ssh_operation(request).await });
    signer.started.notified().await;
    waiter.abort();
    let mut drain = tokio::spawn({
        let lifetime = Arc::clone(&fixture.lifetime);
        async move { lifetime.close_and_wait().await }
    });
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    signer.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(3), &mut drain)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn final_tuple_revalidation_discards_signature_after_binding_removal() {
    let signer = Signer::new();
    signer.block.store(true, Ordering::Release);
    let fixture = fixture(Arc::clone(&signer));
    let rpc = Arc::clone(&fixture.rpc);
    let public_key_blob = fixture.public_key_blob.clone();
    let operation = tokio::spawn(async move {
        rpc.run_ssh_operation(sign(Uuid::new_v4(), public_key_blob))
            .await
    });
    signer.started.notified().await;
    fixture
        .authority
        .delete_environment_access_binding(&fixture.environment_id, &fixture.profile_id, 1)
        .unwrap();
    signer.release.add_permits(1);
    let response = operation.await.unwrap().unwrap().into_inner();
    assert_eq!(
        response.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ))
    );
}

#[tokio::test]
async fn cleanup_failure_latches_global_ssh_admission_closed() {
    let signer = Signer::new();
    *signer.outcome.lock().await = Outcome::Cleanup;
    let fixture = fixture(Arc::clone(&signer));
    let first = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), fixture.public_key_blob.clone()))
        .await;
    assert_eq!(first.unwrap_err().code(), tonic::Code::Unavailable);
    let second = fixture
        .rpc
        .run_ssh_operation(request(
            Uuid::new_v4(),
            daemon_v1::credential_ssh_request::Operation::Identities(
                daemon_v1::CredentialSshIdentitiesRequest {},
            ),
        ))
        .await;
    assert_eq!(second.unwrap_err().code(), tonic::Code::Unavailable);
    assert!(fixture.lifetime.ssh_operations.cleanup_failed());
}

#[tokio::test]
async fn signer_panic_latches_cleanup_before_operation_capacity_is_released() {
    let signer = Signer::new();
    *signer.outcome.lock().await = Outcome::Panic;
    let fixture = fixture(Arc::clone(&signer));

    let first = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), fixture.public_key_blob.clone()))
        .await;
    assert_eq!(first.unwrap_err().code(), tonic::Code::Unavailable);
    assert!(fixture.lifetime.ssh_operations.cleanup_failed());
    let second = fixture
        .rpc
        .run_ssh_operation(request(
            Uuid::new_v4(),
            daemon_v1::credential_ssh_request::Operation::Identities(
                daemon_v1::CredentialSshIdentitiesRequest {},
            ),
        ))
        .await;
    assert_eq!(second.unwrap_err().code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn revoked_ssh_identity_is_denied_and_audited_without_starting_a_signer() {
    let signer = Signer::new();
    let fixture = fixture(Arc::clone(&signer));
    let credential = fixture.authority.list_credentials().unwrap().remove(0);
    fixture
        .authority
        .revoke_credential(&credential.metadata.id)
        .unwrap();
    let response = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), fixture.public_key_blob.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ))
    );
    let events = fixture.rpc.audit.recent(10).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, BrokerLeaseAuditDecision::Denied);
    assert!(events[0].credential_id.is_none());
    assert!(events[0].profile_id.is_none());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    fixture.lifetime.close_and_wait().await;
}

#[tokio::test]
async fn profile_replacement_cannot_retarget_an_existing_ssh_channel() {
    let signer = Signer::new();
    let fixture = fixture(Arc::clone(&signer));
    let pinned = fixture.rpc.local_profile.as_ref().unwrap();
    let profile = fixture
        .authority
        .get_profile_revision(&pinned.profile_id, pinned.profile_revision)
        .unwrap();
    let replacement = fixture
        .authority
        .create_profile(
            AccessProfileName::parse("replacement").unwrap(),
            profile.profile.entries,
        )
        .unwrap()
        .profile;
    fixture
        .authority
        .replace_environment_access_binding(
            &pinned.environment_id,
            &pinned.profile_id,
            pinned.profile_revision,
            replacement.id,
            replacement.revision,
        )
        .unwrap();
    for request in [
        request(
            Uuid::new_v4(),
            daemon_v1::credential_ssh_request::Operation::Identities(
                daemon_v1::CredentialSshIdentitiesRequest {},
            ),
        ),
        sign(Uuid::new_v4(), fixture.public_key_blob.clone()),
    ] {
        let response = fixture
            .rpc
            .run_ssh_operation(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response.result,
            Some(daemon_v1::credential_ssh_response::Result::Failure(
                daemon_v1::CredentialBridgeFailureReason::Denied as i32,
            ))
        );
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    fixture.lifetime.close_and_wait().await;
}

#[tokio::test]
async fn request_ids_and_global_eight_operation_budget_remain_reserved_until_drain() {
    let signer = Signer::new();
    signer.block.store(true, Ordering::Release);
    let fixture = fixture(Arc::clone(&signer));
    let duplicate_id = Uuid::new_v4();
    let mut operations = Vec::new();
    {
        let rpc = Arc::clone(&fixture.rpc);
        let public_key_blob = fixture.public_key_blob.clone();
        operations.push(tokio::spawn(async move {
            rpc.run_ssh_operation(sign(duplicate_id, public_key_blob))
                .await
        }));
        signer.started.notified().await;
    }
    let duplicate = fixture
        .rpc
        .run_ssh_operation(sign(duplicate_id, fixture.public_key_blob.clone()))
        .await;
    assert_eq!(duplicate.unwrap_err().code(), tonic::Code::InvalidArgument);
    for _ in 1..MAX_ACTIVE_SSH_OPERATIONS {
        let rpc = Arc::clone(&fixture.rpc);
        let public_key_blob = fixture.public_key_blob.clone();
        operations.push(tokio::spawn(async move {
            rpc.run_ssh_operation(sign(Uuid::new_v4(), public_key_blob))
                .await
        }));
        signer.started.notified().await;
    }
    let ninth = fixture
        .rpc
        .run_ssh_operation(sign(Uuid::new_v4(), fixture.public_key_blob.clone()))
        .await;
    assert_eq!(ninth.unwrap_err().code(), tonic::Code::Unavailable);

    fixture.lifetime.close();
    signer.release.add_permits(MAX_ACTIVE_SSH_OPERATIONS);
    for operation in operations {
        let response = operation.await.unwrap().unwrap().into_inner();
        assert_eq!(
            response.result,
            Some(daemon_v1::credential_ssh_response::Result::Failure(
                daemon_v1::CredentialBridgeFailureReason::Unavailable as i32,
            ))
        );
    }
    fixture.lifetime.wait_for_operations().await;
}
