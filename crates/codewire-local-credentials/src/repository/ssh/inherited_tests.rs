use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilityPolicy, CapabilitySlot,
    CredentialAuthKind, GrantPermission, ProviderCatalog, ProviderDefinition, ProviderId,
};
use codewire_gateway_proto::codewire::bridge::v1 as daemon_v1;
use codewire_protected_store::ProtectedStorePersistence;
use codewire_protected_store::ssh_material::{SshAgentMaterial, generate_ed25519};
use tokio::net::UnixStream;
use tokio::sync::{Notify, Semaphore, oneshot, watch};
use tokio::time::Instant;

use super::*;
use crate::broker_channel::LocalSshOperationRuntime;
use crate::repository::{RepositoryLeaseChannelError, serve_repository_lease_channel_with_ready};
use crate::tests::TestProtectedStore;
use crate::{LocalSshSignError, LocalSshSignRequest, LocalSshSigner};

const KNOWN_HOST: &str =
    "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";

mod platform;

struct Signer {
    calls: AtomicUsize,
    block: AtomicBool,
    deadline_elapsed: AtomicBool,
    started: Notify,
    cancelled: Notify,
    release: Semaphore,
}

impl Signer {
    fn new(block: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            block: AtomicBool::new(block),
            deadline_elapsed: AtomicBool::new(false),
            started: Notify::new(),
            cancelled: Notify::new(),
            release: Semaphore::new(0),
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
        assert_eq!(request.data.as_slice(), b"synthetic repository payload");
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
                _ = tokio::time::sleep_until(deadline) => {
                    self.deadline_elapsed.store(true, Ordering::Release);
                    false
                },
                permit = self.release.acquire() => {
                    permit.unwrap().forget();
                    false
                },
            };
            if cancelled {
                self.cancelled.notify_one();
                self.release.acquire().await.unwrap().forget();
            }
        }
        Ok(vec![9; 64])
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    authority: Arc<LocalCredentialAuthority<TestProtectedStore>>,
    credential_id: codewire_access::CredentialId,
    authorization: RepositoryCredentialLeaseRequest,
    public_key_blob: Vec<u8>,
    signer: Arc<Signer>,
}

impl Fixture {
    fn new(block_signer: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::new(ProtectedStorePersistence::ProcessLifetime);
        let signer = Signer::new(block_signer);
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temporary.path().join("authority"),
                store,
                ssh_catalog(),
            )
            .unwrap(),
        );
        let prepared = generate_ed25519().unwrap();
        let public_key_blob = prepared.public_key().key_blob().to_vec();
        let credential = authority
            .add_ssh_credential("repository-ssh".into(), None, prepared, || Ok(()))
            .unwrap();
        let credential_id = credential.metadata.id.clone();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("repository-ssh").unwrap(),
                BTreeMap::from([(CapabilitySlot::parse("ssh").unwrap(), credential_id.clone())]),
            )
            .unwrap();
        Self {
            _temporary: temporary,
            authority,
            credential_id,
            authorization: RepositoryCredentialLeaseRequest {
                request_id: Uuid::new_v4(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
                source: "git@example.com:org/app.git".into(),
                branch: "main".into(),
                revision: String::new(),
                known_hosts: vec![KNOWN_HOST.into()],
            },
            public_key_blob,
            signer,
        }
    }

    async fn connect(
        &self,
    ) -> (
        LocalCredentialRepositoryLeaseClient,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), RepositoryLeaseChannelError>>,
    ) {
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&self.authority),
            server_stream,
            self.authorization.clone(),
            LocalSshOperationRuntime::new(Some(self.signer.clone())),
            None,
            ready_tx,
            shutdown_rx,
        ));
        let mut client = LocalCredentialRepositoryLeaseClient::connect(
            client_stream,
            self.authorization.request_id,
        )
        .await
        .unwrap();
        client.report_ready().await.unwrap();
        ready_rx.await.unwrap();
        (client, shutdown_tx, server)
    }
}

fn ssh_catalog() -> ProviderCatalog {
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
    operation: daemon_v1::credential_ssh_request::Operation,
) -> daemon_v1::CredentialSshRequest {
    daemon_v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string(),
        deadline_unix_ms: deadline(),
        operation: Some(operation),
    }
}

fn identities() -> daemon_v1::CredentialSshRequest {
    request(daemon_v1::credential_ssh_request::Operation::Identities(
        daemon_v1::CredentialSshIdentitiesRequest {},
    ))
}

fn sign(public_key_blob: Vec<u8>) -> daemon_v1::CredentialSshRequest {
    request(daemon_v1::credential_ssh_request::Operation::Sign(
        daemon_v1::CredentialSshSignRequest {
            public_key_blob,
            data: b"synthetic repository payload".to_vec(),
            flags: 0,
        },
    ))
}

#[tokio::test]
async fn inherited_rpc_binds_preparation_identity_key_and_revocation() {
    let fixture = Fixture::new(false);
    let (mut client, shutdown, server) = fixture.connect().await;

    let wrong_preparation = client
        .inner
        .get_repository_ssh_checkout(v1::RepositorySshCheckoutRequest {
            protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
            preparation_request_id: Uuid::new_v4().to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(wrong_preparation.code(), tonic::Code::PermissionDenied);

    let checkout = client.ssh_checkout().await.unwrap();
    assert_eq!(
        checkout.preparation_request_id,
        fixture.authorization.request_id
    );
    assert_eq!(checkout.profile_id, fixture.authorization.profile_id);
    assert_eq!(
        checkout.profile_revision,
        fixture.authorization.profile_revision
    );
    assert_eq!(checkout.source, fixture.authorization.source);
    assert_eq!(checkout.known_hosts, fixture.authorization.known_hosts);

    let identity = client.ssh_operation(identities()).await.unwrap();
    assert_eq!(
        identity.result,
        Some(daemon_v1::credential_ssh_response::Result::Identity(
            daemon_v1::CredentialSshIdentity {
                public_key_blob: fixture.public_key_blob.clone(),
            },
        ))
    );
    assert_eq!(fixture.signer.calls.load(Ordering::SeqCst), 0);

    let wrong_key = client.ssh_operation(sign(vec![7; 32])).await.unwrap();
    assert_eq!(
        wrong_key.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ))
    );
    assert_eq!(fixture.signer.calls.load(Ordering::SeqCst), 0);

    let signature = client
        .ssh_operation(sign(fixture.public_key_blob.clone()))
        .await
        .unwrap();
    assert_eq!(
        signature.result,
        Some(daemon_v1::credential_ssh_response::Result::Signature(
            daemon_v1::CredentialSshSignature {
                signature_blob: vec![9; 64],
            },
        ))
    );
    assert_eq!(fixture.signer.calls.load(Ordering::SeqCst), 1);

    fixture
        .authority
        .revoke_credential(&fixture.credential_id)
        .unwrap();
    let revoked = client.ssh_operation(identities()).await.unwrap();
    assert_eq!(
        revoked.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ))
    );

    shutdown.send_replace(true);
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn inherited_channel_cancellation_waits_for_signer_drain() {
    let fixture = Fixture::new(true);
    let (mut client, shutdown, mut server) = fixture.connect().await;
    client.ssh_checkout().await.unwrap();
    let mut operations = client.inner.clone();
    let preparation_request_id = fixture.authorization.request_id.to_string();
    let request = sign(fixture.public_key_blob.clone());
    let operation = tokio::spawn(async move {
        operations
            .repository_ssh_operation(v1::RepositorySshOperationRequest {
                protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
                preparation_request_id,
                request: Some(request),
            })
            .await
    });
    fixture.signer.started.notified().await;

    shutdown.send_replace(true);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        fixture.signer.cancelled.notified(),
    )
    .await
    .expect("channel shutdown must cancel the signer before its original deadline");
    assert!(!fixture.signer.deadline_elapsed.load(Ordering::Acquire));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut server)
            .await
            .is_err()
    );

    fixture.signer.release.add_permits(1);
    let response = operation.await.unwrap().unwrap().into_inner();
    assert_eq!(
        response.result,
        Some(daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Unavailable as i32,
        ))
    );
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
