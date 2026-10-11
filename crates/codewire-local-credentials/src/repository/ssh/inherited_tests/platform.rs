use super::*;
use codewire_credential_bridge::{CredentialBridge, CredentialBridgeOutput};
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

struct PlatformFixture {
    local: Fixture,
    client: LocalCredentialRepositoryLeaseClient,
    shutdown: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), RepositoryLeaseChannelError>>,
    input: mpsc::Sender<Result<daemon_v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    stop_driver: oneshot::Sender<()>,
    driver: tokio::task::JoinHandle<()>,
}

impl PlatformFixture {
    async fn new() -> Self {
        let mut local = Fixture::new(false);
        // No matching local profile exists: every permitted operation must use
        // the already admitted platform bridge, never a local store fallback.
        local.authorization.profile_id =
            AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap();
        local.authorization.profile_revision = 19;
        let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(daemon_v1::credential_bridge_guest_message::Payload::Ready(
                _
            ))
        ));
        let (input, receiver) = mpsc::channel(4);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        let (stop_driver, stopped) = oneshot::channel();
        let driver = tokio::spawn(connection.run_until(async {
            let _ = stopped.await;
        }));
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let (ready, ready_rx) = oneshot::channel();
        let (shutdown, stopped) = watch::channel(false);
        let server = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&local.authority),
            server_stream,
            local.authorization.clone(),
            LocalSshOperationRuntime::new(Some(local.signer.clone())),
            Some(Arc::new(
                crate::repository::RepositoryPlatformCheckout::Ssh { bridge },
            )),
            ready,
            stopped,
            std::sync::Arc::new(std::sync::Mutex::new(None)),
        ));
        let mut client = LocalCredentialRepositoryLeaseClient::connect(
            client_stream,
            local.authorization.request_id,
        )
        .await
        .unwrap();
        client.report_ready().await.unwrap();
        ready_rx.await.unwrap();
        Self {
            local,
            client,
            shutdown,
            server,
            input,
            output,
            stop_driver,
            driver,
        }
    }

    async fn finish(self) {
        self.shutdown.send_replace(true);
        drop(self.client);
        tokio::time::timeout(std::time::Duration::from_secs(2), self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.stop_driver.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), self.driver)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.local.signer.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn platform_inherited_ssh_keeps_exact_public_intent_and_relays_only_typed_operations() {
    let mut fixture = PlatformFixture::new().await;
    assert_eq!(
        fixture
            .client
            .ssh_operation(identities())
            .await
            .unwrap_err(),
        RepositoryLeaseChannelError::Denied
    );
    assert_eq!(
        fixture.client.brokered_checkout().await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let wrong = fixture
        .client
        .inner
        .get_repository_ssh_checkout(v1::RepositorySshCheckoutRequest {
            protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
            preparation_request_id: Uuid::new_v4().to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), tonic::Code::PermissionDenied);
    let intent = fixture.client.ssh_checkout().await.unwrap();
    assert_eq!(intent.profile_id, fixture.local.authorization.profile_id);
    assert_eq!(intent.profile_revision, 19);
    assert_eq!(intent.source, fixture.local.authorization.source);
    assert_eq!(intent.known_hosts, [KNOWN_HOST]);
    assert_eq!(
        fixture.client.ssh_checkout().await.unwrap_err(),
        RepositoryLeaseChannelError::Denied
    );

    use daemon_v1::credential_ssh_response::Result as Outcome;
    for (request, outcome) in [
        (
            identities(),
            Outcome::Identity(daemon_v1::CredentialSshIdentity {
                public_key_blob: fixture.local.public_key_blob.clone(),
            }),
        ),
        (
            sign(fixture.local.public_key_blob.clone()),
            Outcome::Signature(daemon_v1::CredentialSshSignature {
                signature_blob: vec![9; 64],
            }),
        ),
        (
            identities(),
            Outcome::Failure(daemon_v1::CredentialBridgeFailureReason::Denied as i32),
        ),
    ] {
        let expected = request.clone();
        let response = daemon_v1::CredentialSshResponse {
            request_id: request.request_id.clone(),
            result: Some(outcome.clone()),
        };
        let (result, ()) = tokio::join!(fixture.client.ssh_operation(request), async {
            let frame = fixture.output.next().await.unwrap().unwrap();
            assert_eq!(
                frame.payload,
                Some(daemon_v1::credential_bridge_guest_message::Payload::Ssh(
                    expected
                ))
            );
            fixture
                .input
                .send(Ok(daemon_v1::CredentialBridgeHostMessage {
                    payload: Some(daemon_v1::credential_bridge_host_message::Payload::Ssh(
                        response,
                    )),
                }))
                .await
                .unwrap();
        });
        assert_eq!(result.unwrap().result, Some(outcome));
    }
    fixture.finish().await;
}

#[tokio::test]
async fn platform_inherited_ssh_cancellation_drains_private_channel_while_peer_stays_open() {
    let mut fixture = PlatformFixture::new().await;
    fixture.client.ssh_checkout().await.unwrap();
    let mut client = fixture.client.inner.clone();
    let preparation_request_id = fixture.local.authorization.request_id.to_string();
    let request = sign(fixture.local.public_key_blob.clone());
    let operation = tokio::spawn(async move {
        client
            .repository_ssh_operation(v1::RepositorySshOperationRequest {
                protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
                preparation_request_id,
                request: Some(request),
            })
            .await
    });
    assert!(matches!(
        fixture.output.next().await.unwrap().unwrap().payload,
        Some(daemon_v1::credential_bridge_guest_message::Payload::Ssh(_))
    ));
    // Keep platform input, bridge driver and private client open. Existing
    // channel cancellation must end the local RPC without a remote ACK.
    fixture.shutdown.send_replace(true);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), operation)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code(),
        tonic::Code::Cancelled
    );
    fixture.finish().await;
}
