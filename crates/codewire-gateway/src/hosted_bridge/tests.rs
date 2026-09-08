//! Generated-RPC transport proof with synthetic peers. These fixtures do not
//! claim Kubernetes authentication, provider success, or protected-store proof.
use super::*;
use codewire_gateway_proto::broker::v1::credential_broker_service_server::{
    CredentialBrokerService, CredentialBrokerServiceServer,
};
use codewire_gateway_proto::daemon::v1 as daemon_v1;
use codewire_gateway_proto::daemon::v1::daemon_service_server::{
    DaemonService, DaemonServiceServer,
};
use codewire_gateway_proto::{CREDENTIAL_BRIDGE_PROTOCOL_VERSION, DAEMON_AUTH_TOKEN_HEADER};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};
use tonic::{Request, Response};

const DAEMON_TOKEN: &str = "synthetic.daemon.capability";
const WORKSPACE_TOKEN: &str = "Bearer synthetic.workspace.one";

struct DaemonCall {
    input: Streaming<v1::CredentialBridgeHostMessage>,
    output: mpsc::Sender<Result<v1::CredentialBridgeGuestMessage, Status>>,
}
struct BrokerCall {
    input: Streaming<v1::CredentialBridgeGuestMessage>,
    output: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    ready: v1::CredentialBridgeReady,
    gateway: String,
    workspace: Vec<u8>,
    accept: oneshot::Sender<Result<(), Status>>,
}
#[derive(Clone)]
struct SyntheticDaemon {
    environment: Uuid,
    workspace_token: Arc<Mutex<String>>,
    calls: mpsc::Sender<DaemonCall>,
}
#[derive(Clone)]
struct SyntheticBroker {
    calls: mpsc::Sender<BrokerCall>,
}

macro_rules! daemon_service {
    ($( $method:ident($input:ty) -> $output:ty ),* $(,)?) => {
        #[tonic::async_trait]
        impl DaemonService for SyntheticDaemon {
            type ExecSessionStream = ReceiverStream<Result<daemon_v1::ExecMessage, Status>>;
            type PtySessionStream = ReceiverStream<Result<daemon_v1::PtyMessage, Status>>;
            type AttachSessionStream = ReceiverStream<Result<daemon_v1::SessionAttachMessage, Status>>;
            type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeGuestMessage, Status>>;
            async fn credential_bridge(&self, request: Request<Streaming<v1::CredentialBridgeHostMessage>>) -> Result<Response<Self::CredentialBridgeStream>, Status> {
                assert_eq!(request.metadata().get(DAEMON_AUTH_TOKEN_HEADER).unwrap(), DAEMON_TOKEN);
                let (output, receiver) = mpsc::channel(4);
                output.send(Ok(v1::CredentialBridgeGuestMessage { payload: Some(v1::credential_bridge_guest_message::Payload::Ready(v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION, environment_id: self.environment.to_string(), environment_generation: 7,
                })) })).await.unwrap();
                self.calls.send(DaemonCall { input: request.into_inner(), output }).await.map_err(|_| Status::cancelled("fixture closed"))?;
                let mut response = Response::new(ReceiverStream::new(receiver));
                let mut token = tonic::metadata::MetadataValue::from_bytes(self.workspace_token.lock().await.as_bytes());
                token.set_sensitive(true);
                response.metadata_mut().insert_bin(codewire_daemon::client::HOSTED_WORKSPACE_AUTHORIZATION, token);
                Ok(response)
            }
            $( async fn $method(&self, _request: Request<$input>) -> Result<Response<$output>, Status> { Err(Status::unimplemented("fixture unused RPC")) } )*
        }
    };
}
daemon_service! {
    poweroff_guest(daemon_v1::PoweroffGuestRequest) -> daemon_v1::PoweroffGuestResponse,
    get_capabilities(daemon_v1::GetCapabilitiesRequest) -> daemon_v1::GetCapabilitiesResponse,
    get_health(daemon_v1::GetHealthRequest) -> daemon_v1::GetHealthResponse,
    launch_session(daemon_v1::LaunchSessionRequest) -> daemon_v1::LaunchSessionResponse,
    list_sessions(daemon_v1::ListSessionsRequest) -> daemon_v1::ListSessionsResponse,
    get_session(daemon_v1::GetSessionRequest) -> daemon_v1::GetSessionResponse,
    stop_session(daemon_v1::StopSessionRequest) -> daemon_v1::StopSessionResponse,
    restart_session(daemon_v1::RestartSessionRequest) -> daemon_v1::RestartSessionResponse,
    read_session_output(daemon_v1::ReadSessionOutputRequest) -> daemon_v1::ReadSessionOutputResponse,
    attach_session(Streaming<daemon_v1::SessionAttachMessage>) -> Self::AttachSessionStream,
    exec_session(Streaming<daemon_v1::ExecMessage>) -> Self::ExecSessionStream,
    pty_session(Streaming<daemon_v1::PtyMessage>) -> Self::PtySessionStream,
    list(daemon_v1::ListRequest) -> daemon_v1::ListResponse,
    stat(daemon_v1::StatRequest) -> daemon_v1::StatResponse,
    open_file(daemon_v1::OpenFileRequest) -> daemon_v1::OperationStatus,
    read(daemon_v1::ReadRequest) -> daemon_v1::ReadResponse,
    write(daemon_v1::WriteRequest) -> daemon_v1::WriteResponse,
    mkdir(daemon_v1::MkdirRequest) -> daemon_v1::OperationStatus,
    remove(daemon_v1::RemoveRequest) -> daemon_v1::OperationStatus,
    rename(daemon_v1::RenameRequest) -> daemon_v1::OperationStatus,
    set_stat(daemon_v1::SetStatRequest) -> daemon_v1::OperationStatus,
    readlink(daemon_v1::ReadlinkRequest) -> daemon_v1::ReadlinkResponse,
}

#[tonic::async_trait]
impl CredentialBrokerService for SyntheticBroker {
    type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;
    async fn credential_bridge(
        &self,
        request: Request<Streaming<v1::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        let gateway = request
            .metadata()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let workspace = request
            .metadata()
            .get_bin(codewire_daemon::client::HOSTED_WORKSPACE_AUTHORIZATION)
            .unwrap()
            .to_bytes()
            .unwrap()
            .to_vec();
        let mut input = request.into_inner();
        let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) =
            input.message().await?.unwrap().payload
        else {
            panic!("Ready must be first");
        };
        let (output, receiver) = mpsc::channel(4);
        let (accept, accepted) = oneshot::channel();
        self.calls
            .send(BrokerCall {
                input,
                output,
                ready,
                gateway,
                workspace,
                accept,
            })
            .await
            .map_err(|_| Status::cancelled("fixture closed"))?;
        accepted
            .await
            .map_err(|_| Status::cancelled("fixture rejected"))??;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    config: HostedBridgeConfig,
    daemon: SessionClient,
    daemon_calls: mpsc::Receiver<DaemonCall>,
    broker_calls: mpsc::Receiver<BrokerCall>,
    workspace_token: Arc<Mutex<String>>,
    shutdown: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let gateway_token = temp.path().join("gateway-token");
        std::fs::write(&gateway_token, "synthetic.gateway.one").unwrap();
        let environment_id = Uuid::new_v4();
        let workspace_token = Arc::new(Mutex::new(WORKSPACE_TOKEN.into()));
        let (daemon_tx, daemon_calls) = mpsc::channel(2);
        let (broker_tx, broker_calls) = mpsc::channel(2);
        let daemon_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let daemon_endpoint = format!("http://{}", daemon_listener.local_addr().unwrap());
        let broker_endpoint = format!("http://{}", broker_listener.local_addr().unwrap());
        let shutdown = CancellationToken::new();
        let daemon_shutdown = shutdown.clone();
        let broker_shutdown = shutdown.clone();
        let synthetic_daemon = SyntheticDaemon {
            environment: environment_id,
            workspace_token: workspace_token.clone(),
            calls: daemon_tx,
        };
        let tasks = vec![
            tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(DaemonServiceServer::new(synthetic_daemon))
                    .serve_with_incoming_shutdown(
                        TcpListenerStream::new(daemon_listener),
                        daemon_shutdown.cancelled(),
                    )
                    .await
                    .unwrap();
            }),
            tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(CredentialBrokerServiceServer::new(SyntheticBroker {
                        calls: broker_tx,
                    }))
                    .serve_with_incoming_shutdown(
                        TcpListenerStream::new(broker_listener),
                        broker_shutdown.cancelled(),
                    )
                    .await
                    .unwrap();
            }),
        ];
        let daemon = SessionClient::connect(&daemon_endpoint, DAEMON_TOKEN)
            .await
            .unwrap();
        let channel = tonic::transport::Endpoint::from_shared(broker_endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            _temp: temp,
            config: HostedBridgeConfig {
                environment_id,
                generation: 7,
                gateway_token,
                broker: BrokerEndpoint::Preconfigured(channel),
            },
            daemon,
            daemon_calls,
            broker_calls,
            workspace_token,
            shutdown,
            tasks,
        }
    }
    fn epoch(
        &self,
    ) -> (
        CancellationToken,
        tokio::task::JoinHandle<Result<(), DrainFailure>>,
    ) {
        self.epoch_with_lifetime(EPOCH_MAX_LIFETIME)
    }

    fn epoch_with_lifetime(
        &self,
        lifetime: Duration,
    ) -> (
        CancellationToken,
        tokio::task::JoinHandle<Result<(), DrainFailure>>,
    ) {
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let config = self.config.clone();
        let daemon = self.daemon.clone();
        (
            cancellation,
            tokio::spawn(async move {
                run_epoch_with_lifetime(&config, &daemon, child, lifetime).await
            }),
        )
    }
    async fn stop(self) {
        self.shutdown.cancel();
        for task in self.tasks {
            bounded(task).await.unwrap();
        }
    }
}
async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("bounded synthetic transport")
}

#[tokio::test]
async fn broker_admission_precedes_open_and_typed_frames_are_preserved() {
    let mut fixture = Fixture::new().await;
    let (cancel, task) = fixture.epoch();
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let broker = bounded(fixture.broker_calls.recv()).await.unwrap();
    assert_eq!(
        broker.ready.environment_id,
        fixture.config.environment_id.to_string()
    );
    assert_eq!(broker.gateway, "Bearer synthetic.gateway.one");
    assert_eq!(broker.workspace, WORKSPACE_TOKEN.as_bytes());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), daemon.input.message())
            .await
            .is_err()
    );
    let BrokerCall {
        mut input,
        output,
        accept,
        ..
    } = broker;
    accept.send(Ok(())).unwrap();
    assert!(matches!(
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    let request = v1::EnvironmentProjectionRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: vec![7; 32],
        selection_sha256: vec![9; 32],
        deadline_unix_ms: 123456,
    };
    daemon
        .output
        .send(Ok(v1::CredentialBridgeGuestMessage {
            payload: Some(
                v1::credential_bridge_guest_message::Payload::EnvironmentProjection(
                    request.clone(),
                ),
            ),
        }))
        .await
        .unwrap();
    assert_eq!(
        bounded(input.message()).await.unwrap().unwrap().payload,
        Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(request.clone()))
    );
    let response = v1::EnvironmentProjectionResponse {
        request_id: request.request_id,
        result: Some(
            v1::environment_projection_response::Result::SealedProjection(
                b"opaque-synthetic-ciphertext".to_vec(),
            ),
        ),
    };
    output
        .send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(
                v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                    response.clone(),
                ),
            ),
        }))
        .await
        .unwrap();
    assert_eq!(
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_host_message::Payload::EnvironmentProjection(response))
    );
    for signing in [false, true] {
        let operation = if signing {
            v1::credential_ssh_request::Operation::Sign(v1::CredentialSshSignRequest {
                public_key_blob: vec![1; 32],
                data: vec![2; 64],
                flags: 0,
            })
        } else {
            v1::credential_ssh_request::Operation::Identities(v1::CredentialSshIdentitiesRequest {})
        };
        let request = v1::CredentialSshRequest {
            request_id: Uuid::new_v4().to_string(),
            deadline_unix_ms: u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                + 29_000,
            operation: Some(operation),
        };
        daemon
            .output
            .send(Ok(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(
                    request.clone(),
                )),
            }))
            .await
            .unwrap();
        assert_eq!(
            bounded(input.message()).await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ssh(
                request.clone()
            ))
        );
        let result = if signing {
            v1::credential_ssh_response::Result::Signature(v1::CredentialSshSignature {
                signature_blob: vec![3; 64],
            })
        } else {
            v1::credential_ssh_response::Result::Identity(v1::CredentialSshIdentity {
                public_key_blob: vec![1; 32],
            })
        };
        let response = v1::CredentialSshResponse {
            request_id: request.request_id,
            result: Some(result),
        };
        output
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                    response.clone(),
                )),
            }))
            .await
            .unwrap();
        assert_eq!(
            bounded(daemon.input.message())
                .await
                .unwrap()
                .unwrap()
                .payload,
            Some(v1::credential_bridge_host_message::Payload::Ssh(response))
        );
    }
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    assert!(bounded(input.message()).await.unwrap().is_none());
    assert!(bounded(daemon.input.message()).await.unwrap().is_none());
    drop((input, output, daemon));
    fixture.stop().await;
}

#[tokio::test]
async fn rejected_and_cancelled_admission_never_send_open_and_reconnect_rereads_tokens() {
    let mut fixture = Fixture::new().await;
    for accept_rejection in [true, false] {
        let (cancel, task) = fixture.epoch();
        let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
        let broker = bounded(fixture.broker_calls.recv()).await.unwrap();
        if accept_rejection {
            assert_eq!(broker.workspace, WORKSPACE_TOKEN.as_bytes());
            broker
                .accept
                .send(Err(Status::permission_denied("synthetic denied")))
                .unwrap();
        } else {
            assert_eq!(broker.gateway, "Bearer synthetic.gateway.two");
            assert_eq!(broker.workspace, b"Bearer synthetic.workspace.two");
            cancel.cancel();
            drop(broker.accept);
        }
        bounded(task).await.unwrap().unwrap();
        assert!(bounded(daemon.input.message()).await.unwrap().is_none());
        drop((daemon, broker.input, broker.output));
        std::fs::write(&fixture.config.gateway_token, "synthetic.gateway.two").unwrap();
        *fixture.workspace_token.lock().await = "Bearer synthetic.workspace.two".into();
    }
    fixture.stop().await;
}

#[tokio::test]
async fn cancelled_outgoing_stream_drops_queued_frames_and_acknowledges_drain() {
    let cancellation = CancellationToken::new();
    let (sender, receiver) = mpsc::channel(1);
    sender
        .send(v1::CredentialBridgeGuestMessage::default())
        .await
        .unwrap();
    let (closed, ack) = oneshot::channel();
    let mut output = RelayOutput {
        frames: ReceiverStream::new(receiver),
        cancelled: Box::pin(cancellation.clone().cancelled_owned()),
        closed: Some(closed),
    };
    cancellation.cancel();
    assert!(output.next().await.is_none());
    bounded(ack).await.unwrap();
}

#[tokio::test]
async fn epoch_expiry_drains_both_producers_and_only_fresh_requests_reach_replacement() {
    let mut fixture = Fixture::new().await;
    let (_cancel, task) = fixture.epoch_with_lifetime(Duration::from_secs(1));
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall {
        mut input,
        output,
        accept,
        ..
    } = bounded(fixture.broker_calls.recv()).await.unwrap();
    accept.send(Ok(())).unwrap();
    assert!(matches!(
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    let old = v1::EnvironmentProjectionRequest {
        request_id: Uuid::new_v4().to_string(),
        recipient_public_key: vec![7; 32],
        selection_sha256: vec![9; 32],
        deadline_unix_ms: 123456,
    };
    daemon
        .output
        .send(Ok(v1::CredentialBridgeGuestMessage {
            payload: Some(
                v1::credential_bridge_guest_message::Payload::EnvironmentProjection(old.clone()),
            ),
        }))
        .await
        .unwrap();
    assert_eq!(
        bounded(input.message()).await.unwrap().unwrap().payload,
        Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(old))
    );
    // Leave a request pending: expiry, not a response or explicit test cancel,
    // must retire both old outgoing producers before this owner completes.
    bounded(task).await.unwrap().unwrap();
    assert!(!matches!(bounded(input.message()).await, Ok(Some(_))));
    assert!(!matches!(
        bounded(daemon.input.message()).await,
        Ok(Some(_))
    ));
    drop((input, output, daemon));

    let (cancel, task) = fixture.epoch();
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall {
        mut input,
        output,
        accept,
        ..
    } = bounded(fixture.broker_calls.recv()).await.unwrap();
    accept.send(Ok(())).unwrap();
    assert!(matches!(
        bounded(daemon.input.message())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_host_message::Payload::Open(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), input.message())
            .await
            .is_err(),
        "old pending projection was replayed"
    );
    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    assert!(!matches!(bounded(input.message()).await, Ok(Some(_))));
    assert!(!matches!(
        bounded(daemon.input.message()).await,
        Ok(Some(_))
    ));
    drop((input, output, daemon));
    fixture.stop().await;
}
