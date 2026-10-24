//! Generated-RPC transport proof with synthetic peers. These fixtures do not
//! claim Kubernetes authentication, provider success, or protected-store proof.
mod budgets;
mod relay;
mod ssh_deadlines;

use super::*;
use crate::worker::credential_relay::budget::Limits;
use crate::worker::credential_relay::connection::DaemonTarget;
use codewire_daemon_proto::broker::v1::credential_broker_service_server::{
    CredentialBrokerService, CredentialBrokerServiceServer,
};
use codewire_daemon_proto::daemon::v1 as daemon_v1;
use codewire_daemon_proto::daemon::v1::daemon_service_server::{
    DaemonService, DaemonServiceServer,
};
use codewire_daemon_proto::{CREDENTIAL_BRIDGE_PROTOCOL_VERSION, DAEMON_AUTH_TOKEN_HEADER};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::{
    StreamExt,
    wrappers::{ReceiverStream, TcpListenerStream},
};
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
    relay: String,
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
    /// Response-header capability values; empty models an older broker.
    capabilities: Arc<std::sync::Mutex<Vec<&'static str>>>,
    /// Response-header expiry values; empty models an older broker.
    expires_at: Arc<std::sync::Mutex<Vec<String>>>,
}

macro_rules! daemon_service {
    ($( $method:ident($input:ty) -> $output:ty ),* $(,)?) => {
        #[tonic::async_trait]
        impl DaemonService for SyntheticDaemon {
            type ExecSessionStream = ReceiverStream<Result<daemon_v1::ExecMessage, Status>>;
            type PtySessionStream = ReceiverStream<Result<daemon_v1::PtyMessage, Status>>;
            type ForwardTcpStream = ReceiverStream<Result<daemon_v1::ForwardTcpMessage, Status>>;
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
    set_app_ports(daemon_v1::SetAppPortsRequest) -> daemon_v1::SetAppPortsResponse,
    get_capabilities(daemon_v1::GetCapabilitiesRequest) -> daemon_v1::GetCapabilitiesResponse,
    get_health(daemon_v1::GetHealthRequest) -> daemon_v1::GetHealthResponse,
    launch_session(daemon_v1::LaunchSessionRequest) -> daemon_v1::LaunchSessionResponse,
    list_sessions(daemon_v1::ListSessionsRequest) -> daemon_v1::ListSessionsResponse,
    get_session(daemon_v1::GetSessionRequest) -> daemon_v1::GetSessionResponse,
    stop_session(daemon_v1::StopSessionRequest) -> daemon_v1::StopSessionResponse,
    restart_session(daemon_v1::RestartSessionRequest) -> daemon_v1::RestartSessionResponse,
    send_session_input(daemon_v1::SendSessionInputRequest) -> daemon_v1::SendSessionInputResponse,
    read_session_output(daemon_v1::ReadSessionOutputRequest) -> daemon_v1::ReadSessionOutputResponse,
    attach_session(Streaming<daemon_v1::SessionAttachMessage>) -> Self::AttachSessionStream,
    exec_session(Streaming<daemon_v1::ExecMessage>) -> Self::ExecSessionStream,
    pty_session(Streaming<daemon_v1::PtyMessage>) -> Self::PtySessionStream,
    forward_tcp(Streaming<daemon_v1::ForwardTcpMessage>) -> Self::ForwardTcpStream,
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
        let relay = request
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
                relay,
                workspace,
                accept,
            })
            .await
            .map_err(|_| Status::cancelled("fixture closed"))?;
        accepted
            .await
            .map_err(|_| Status::cancelled("fixture rejected"))??;
        let mut response = Response::new(ReceiverStream::new(receiver));
        for capability in self.capabilities.lock().unwrap().iter() {
            response.metadata_mut().append(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                tonic::metadata::MetadataValue::from_static(capability),
            );
        }
        for value in self.expires_at.lock().unwrap().iter() {
            response.metadata_mut().append(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER,
                value.parse().unwrap(),
            );
        }
        Ok(response)
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    config: EpochConfig,
    daemon_calls: mpsc::Receiver<DaemonCall>,
    broker_calls: mpsc::Receiver<BrokerCall>,
    workspace_token: Arc<Mutex<String>>,
    broker_capabilities: Arc<std::sync::Mutex<Vec<&'static str>>>,
    broker_expires_at: Arc<std::sync::Mutex<Vec<String>>>,
    shutdown: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_limits(Limits::DEFAULT).await
    }

    async fn with_limits(limits: Limits) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let relay_token = temp.path().join("relay-token");
        std::fs::write(&relay_token, "synthetic.relay.one").unwrap();
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
        let broker_capabilities = Arc::new(std::sync::Mutex::new(Vec::new()));
        let broker_expires_at = Arc::new(std::sync::Mutex::new(Vec::new()));
        let synthetic_broker = SyntheticBroker {
            calls: broker_tx,
            capabilities: broker_capabilities.clone(),
            expires_at: broker_expires_at.clone(),
        };
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
                    .add_service(CredentialBrokerServiceServer::new(synthetic_broker))
                    .serve_with_incoming_shutdown(
                        TcpListenerStream::new(broker_listener),
                        broker_shutdown.cancelled(),
                    )
                    .await
                    .unwrap();
            }),
        ];
        let channel = tonic::transport::Endpoint::from_shared(broker_endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            _temp: temp,
            config: EpochConfig {
                environment_id,
                generation: 7,
                daemon: DaemonTarget {
                    endpoint: daemon_endpoint,
                    credential: Zeroizing::new(DAEMON_TOKEN.into()),
                },
                relay_token,
                broker: BrokerEndpoint::Preconfigured(channel),
                budget: EnvironmentBudget::new(limits),
            },
            daemon_calls,
            broker_calls,
            workspace_token,
            broker_capabilities,
            broker_expires_at,
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
        let (cancellation, _admitted, task) = self.start_epoch(None, lifetime);
        (cancellation, task)
    }

    /// A fresh epoch (`succeeds` None) or a successor of an epoch with that
    /// expiry. The receiver reports the daemon's Open.
    fn start_epoch(
        &self,
        succeeds: Option<u64>,
        lifetime: Duration,
    ) -> (
        CancellationToken,
        oneshot::Receiver<Admitted>,
        tokio::task::JoinHandle<Result<(), DrainFailure>>,
    ) {
        let cancellation = CancellationToken::new();
        let (admitted, receiver) = oneshot::channel();
        let start = EpochStart {
            cancellation: cancellation.clone(),
            admitted,
            succeeds,
        };
        let config = self.config.clone();
        (
            cancellation,
            receiver,
            tokio::spawn(async move { run_epoch_with_lifetime(&config, start, lifetime).await }),
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
    assert_eq!(broker.relay, "Bearer synthetic.relay.one");
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
        local_inventories: vec![v1::EnvironmentProjectionInventory {
            source: v1::EnvironmentProjectionSource::Project as i32,
            source_identity: "/projects/local-owner/local-project".into(),
            keys: vec!["LOCAL_ONLY".into()],
        }],
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
async fn broker_capabilities_reach_the_open_and_login_frames_relay_opaquely() {
    for current_broker in [false, true] {
        let mut fixture = Fixture::new().await;
        if current_broker {
            // A malformed and an unknown value are dropped, never forwarded.
            *fixture.broker_capabilities.lock().unwrap() = vec![
                "future-op",
                "Not-Canonical",
                "codex-login",
                "codex-login",
                "claude-login",
            ];
        }
        let (cancel, task) = fixture.epoch();
        let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
        let BrokerCall {
            mut input,
            output,
            accept,
            ..
        } = bounded(fixture.broker_calls.recv()).await.unwrap();
        accept.send(Ok(())).unwrap();
        let Some(v1::credential_bridge_host_message::Payload::Open(open)) =
            bounded(daemon.input.message())
                .await
                .unwrap()
                .unwrap()
                .payload
        else {
            panic!("Open must follow broker admission");
        };
        if !current_broker {
            // An older broker lists nothing, so the daemon never sends a
            // Codex login it would end the epoch on.
            assert!(open.capabilities.is_empty());
        } else {
            assert_eq!(open.capabilities, ["codex-login", "claude-login"]);
            let request = v1::CodexLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: vec![7; 32],
                deadline_unix_ms: 123456,
            };
            daemon
                .output
                .send(Ok(v1::CredentialBridgeGuestMessage {
                    payload: Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
                        request.clone(),
                    )),
                }))
                .await
                .unwrap();
            assert_eq!(
                bounded(input.message()).await.unwrap().unwrap().payload,
                Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
                    request.clone()
                ))
            );
            for result in [
                v1::codex_login_response::Result::SealedLogin(
                    b"opaque-synthetic-sealed-login".to_vec(),
                ),
                v1::codex_login_response::Result::Failure(
                    v1::CredentialBridgeFailureReason::Denied as i32,
                ),
            ] {
                let response = v1::CodexLoginResponse {
                    request_id: request.request_id.clone(),
                    result: Some(result),
                };
                output
                    .send(Ok(v1::CredentialBridgeHostMessage {
                        payload: Some(v1::credential_bridge_host_message::Payload::CodexLogin(
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
                    Some(v1::credential_bridge_host_message::Payload::CodexLogin(
                        response
                    ))
                );
            }
            let request = v1::ClaudeLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: vec![8; 32],
                deadline_unix_ms: 123456,
            };
            daemon
                .output
                .send(Ok(v1::CredentialBridgeGuestMessage {
                    payload: Some(v1::credential_bridge_guest_message::Payload::ClaudeLogin(
                        request.clone(),
                    )),
                }))
                .await
                .unwrap();
            assert_eq!(
                bounded(input.message()).await.unwrap().unwrap().payload,
                Some(v1::credential_bridge_guest_message::Payload::ClaudeLogin(
                    request.clone()
                ))
            );
            let response = v1::ClaudeLoginResponse {
                request_id: request.request_id.clone(),
                result: Some(v1::claude_login_response::Result::SealedLogin(
                    b"opaque-synthetic-sealed-claude-login".to_vec(),
                )),
            };
            output
                .send(Ok(v1::CredentialBridgeHostMessage {
                    payload: Some(v1::credential_bridge_host_message::Payload::ClaudeLogin(
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
                Some(v1::credential_bridge_host_message::Payload::ClaudeLogin(
                    response
                ))
            );
        }
        cancel.cancel();
        bounded(task).await.unwrap().unwrap();
        drop((input, output, daemon));
        fixture.stop().await;
    }
}

#[test]
fn only_bounded_canonical_capability_headers_are_copied() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    for value in [
        "codex-login",
        "Codex-Login",
        "future-op",
        "spaces are invalid",
    ] {
        if let Ok(value) = value.parse() {
            metadata.append(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                value,
            );
        }
    }
    assert_eq!(broker_capabilities(&metadata), ["codex-login", "future-op"]);
    for _ in 0..codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES * 2 {
        metadata.append(
            codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
            "padding".parse().unwrap(),
        );
    }
    assert_eq!(
        broker_capabilities(&metadata).len(),
        codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES
    );
    assert!(broker_capabilities(&tonic::metadata::MetadataMap::new()).is_empty());
}

/// Over the generated RPCs: nothing is dialed while the broker cannot admit
/// the environment, and the first epoch's Open reaches the daemon within a
/// second of the running signal, on its first attempt.
#[tokio::test]
async fn the_first_epoch_is_admitted_within_a_second_of_the_running_signal() {
    let mut fixture = Fixture::new().await;
    let (admissible, admission) = watch::channel(false);
    let shutdown = CancellationToken::new();
    let config = fixture.config.clone();
    let stop = shutdown.clone();
    let relay = tokio::spawn(async move { run(&config, admission, stop.cancelled()).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), fixture.daemon_calls.recv())
            .await
            .is_err()
    );
    let signalled = std::time::Instant::now();
    admissible.send_replace(true);
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall {
        input,
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
    let admitted_after = signalled.elapsed();
    assert!(
        admitted_after < Duration::from_secs(1),
        "admitted {admitted_after:?} after the signal"
    );
    assert!(fixture.daemon_calls.try_recv().is_err());
    shutdown.cancel();
    bounded(relay).await.unwrap().unwrap();
    drop((daemon, input, output));
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
            assert_eq!(broker.relay, "Bearer synthetic.relay.two");
            assert_eq!(broker.workspace, b"Bearer synthetic.workspace.two");
            cancel.cancel();
            drop(broker.accept);
        }
        bounded(task).await.unwrap().unwrap();
        assert!(bounded(daemon.input.message()).await.unwrap().is_none());
        drop((daemon, broker.input, broker.output));
        std::fs::write(&fixture.config.relay_token, "synthetic.relay.two").unwrap();
        *fixture.workspace_token.lock().await = "Bearer synthetic.workspace.two".into();
    }
    fixture.stop().await;
}

#[tokio::test]
async fn a_sealed_outgoing_queue_returns_every_frames_bytes_at_once() {
    let cancellation = CancellationToken::new();
    let budget = EnvironmentBudget::new(Limits::DEFAULT);
    let stream = budget.stream();
    let (sender, receiver) = mpsc::channel(4);
    for _ in 0..3 {
        sender
            .send(Queued {
                frame: v1::CredentialBridgeGuestMessage::default(),
                charge: Some(stream.charge(1024).await.unwrap()),
            })
            .await
            .unwrap();
    }
    let queue = OutgoingQueue::new(receiver);
    let mut output = RelayOutput {
        queue: queue.clone(),
        cancelled: Box::pin(cancellation.clone().cancelled_owned()),
    };
    // A yielded frame stays charged until tonic asks for the next one.
    assert!(output.next().await.is_some());
    assert_eq!(budget.available(), Limits::DEFAULT.environment - 3072);
    assert!(output.next().await.is_some());
    assert_eq!(budget.available(), Limits::DEFAULT.environment - 2048);
    // Sealing, as an ending epoch does whether or not tonic polls again,
    // drops the held and the queued frame and leaves nothing to yield.
    queue.seal();
    assert_eq!(budget.available(), Limits::DEFAULT.environment);
    assert!(output.next().await.is_none());
    assert!(sender.is_closed());

    // Cancellation alone seals a queue at its next poll.
    cancellation.cancel();
    let (sender, receiver) = mpsc::channel(1);
    sender
        .send(Queued {
            frame: v1::CredentialBridgeGuestMessage::default(),
            charge: Some(stream.charge(1024).await.unwrap()),
        })
        .await
        .unwrap();
    let mut output = RelayOutput {
        queue: OutgoingQueue::new(receiver),
        cancelled: Box::pin(cancellation.clone().cancelled_owned()),
    };
    assert!(output.next().await.is_none());
    assert_eq!(budget.available(), Limits::DEFAULT.environment);
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
        local_inventories: Vec::new(),
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

#[tokio::test]
async fn a_daemon_refusing_the_credential_ends_the_epoch_before_the_broker() {
    let (calls, _unused_calls) = mpsc::channel(1);
    let refusing = SyntheticDaemon {
        environment: Uuid::new_v4(),
        workspace_token: Arc::new(Mutex::new(WORKSPACE_TOKEN.into())),
        calls,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(DaemonServiceServer::with_interceptor(
                refusing,
                |_request: Request<()>| Err(Status::unauthenticated("credential refused")),
            ))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_shutdown.cancelled(),
            )
            .await
            .unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let relay_token = temp.path().join("relay-token");
    std::fs::write(&relay_token, "synthetic.relay.one").unwrap();
    // Nothing listens here: reaching the broker would fail the bound below.
    let broker = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
    let config = EpochConfig {
        environment_id: Uuid::new_v4(),
        generation: 7,
        daemon: DaemonTarget {
            endpoint,
            credential: Zeroizing::new("synthetic.stale.capability".into()),
        },
        relay_token,
        broker: BrokerEndpoint::Preconfigured(broker),
        budget: EnvironmentBudget::new(Limits::DEFAULT),
    };
    let (admitted, never_admitted) = oneshot::channel();
    bounded(run_epoch_with_lifetime(
        &config,
        EpochStart {
            cancellation: CancellationToken::new(),
            admitted,
            succeeds: None,
        },
        EPOCH_MAX_LIFETIME,
    ))
    .await
    .unwrap();
    assert!(never_admitted.await.is_err());
    shutdown.cancel();
    bounded(server).await.unwrap();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn broker_expiry_header_is_parsed_strictly() {
    use ExpiryRejected::{Malformed, OutOfRange};
    let now = Duration::from_secs(1_800_000_000) + Duration::from_millis(400);
    let secs = now.as_secs();
    for (value, expected) in [
        ((secs + 1).to_string(), Ok(secs + 1)),
        ((secs + 600).to_string(), Ok(secs + 600)),
        ((secs + 660).to_string(), Ok(secs + 660)),
        (format!("000{}", secs + 60), Ok(secs + 60)),
        (secs.to_string(), Err(OutOfRange)),
        ((secs - 1).to_string(), Err(OutOfRange)),
        ((secs + 661).to_string(), Err(OutOfRange)),
        ("0".to_owned(), Err(OutOfRange)),
        (String::new(), Err(Malformed)),
        (format!("+{}", secs + 60), Err(Malformed)),
        (format!(" {}", secs + 60), Err(Malformed)),
        (format!("{}.0", secs + 60), Err(Malformed)),
        (format!("{}s", secs + 60), Err(Malformed)),
        ("-1".to_owned(), Err(Malformed)),
        // 20 digits overflowing u64, and 21 digits.
        ("99999999999999999999".to_owned(), Err(Malformed)),
        (format!("{:0>21}", secs + 60), Err(Malformed)),
    ] {
        assert_eq!(parse_expiry(&value, now), expected, "{value:?}");
    }

    let mut metadata = tonic::metadata::MetadataMap::new();
    assert_eq!(broker_expiry(&metadata), Err(ExpiryRejected::Absent));
    let ahead = unix_now() + 120;
    metadata.insert(
        codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER,
        ahead.to_string().parse().unwrap(),
    );
    let expiry = broker_expiry(&metadata).unwrap();
    assert_eq!(expiry.unix, ahead);
    let remaining = expiry.at.saturating_duration_since(Instant::now());
    assert!(remaining > Duration::from_secs(118) && remaining <= Duration::from_secs(120));
    // Two values are ambiguous, never a choice.
    metadata.append(
        codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER,
        ahead.to_string().parse().unwrap(),
    );
    assert_eq!(broker_expiry(&metadata), Err(ExpiryRejected::Ambiguous));
    for (reason, expected) in [
        (ExpiryRejected::Absent, "absent"),
        (ExpiryRejected::Ambiguous, "ambiguous"),
        (ExpiryRejected::Malformed, "malformed"),
        (ExpiryRejected::OutOfRange, "out_of_range"),
        (ExpiryRejected::Clock, "clock"),
    ] {
        assert_eq!(reason.reason(), expected);
    }
}

#[test]
fn a_successor_must_expire_strictly_later_than_the_current_epoch() {
    let at = Instant::now();
    let expiry = |unix| Some(BrokerExpiry { unix, at });
    assert!(extends(expiry(1_001), 1_000));
    assert!(extends(expiry(1_040), 1_000));
    assert!(extends(expiry(1_600), 1_000));
    assert!(!extends(expiry(1_000), 1_000));
    assert!(!extends(expiry(999), 1_000));
    assert!(!extends(None, 1_000));
    assert!(!extends(expiry(u64::MAX), u64::MAX));
}

/// Admit one epoch with `succeeds` against a broker reporting `expires_at`.
/// Returns whether the daemon was sent an Open, and what was admitted.
async fn admit_successor(
    fixture: &mut Fixture,
    succeeds: Option<u64>,
    expires_at: Vec<String>,
) -> Option<Admitted> {
    *fixture.broker_expires_at.lock().unwrap() = expires_at;
    let (cancel, admitted, task) = fixture.start_epoch(succeeds, EPOCH_MAX_LIFETIME);
    let mut daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall {
        mut input,
        output,
        accept,
        ..
    } = bounded(fixture.broker_calls.recv()).await.unwrap();
    accept.send(Ok(())).unwrap();
    let opened = match bounded(daemon.input.message()).await.unwrap() {
        Some(frame) => {
            assert!(matches!(
                frame.payload,
                Some(v1::credential_bridge_host_message::Payload::Open(_))
            ));
            let admitted = bounded(admitted).await.unwrap();
            cancel.cancel();
            Some(admitted)
        }
        // Dropped while prepared: the request stream ends with no Open, and
        // the epoch drains by itself without being cancelled.
        None => {
            assert!(bounded(admitted).await.is_err());
            None
        }
    };
    bounded(task).await.unwrap().unwrap();
    assert!(!matches!(bounded(input.message()).await, Ok(Some(_))));
    drop((input, output, daemon));
    opened
}

#[tokio::test]
async fn a_successor_that_does_not_extend_the_expiry_never_sends_open() {
    let mut fixture = Fixture::new().await;
    let current = unix_now() + 100;
    // A fresh epoch reports the expiry it was admitted with.
    let admitted = admit_successor(&mut fixture, None, vec![current.to_string()])
        .await
        .unwrap();
    assert_eq!(admitted.expiry.map(|expiry| expiry.unix), Some(current));
    for refused in [
        // Neither token rotated yet: it would end with the current epoch.
        vec![current.to_string()],
        vec![(current - 1).to_string()],
        // An older broker, or a malformed or ambiguous header, cannot prove
        // that kubelet already rotated the successor's tokens.
        vec![],
        vec!["soon".to_owned()],
        vec![(current + 60).to_string(), (current + 60).to_string()],
    ] {
        assert!(
            admit_successor(&mut fixture, Some(current), refused.clone())
                .await
                .is_none(),
            "{refused:?}"
        );
    }
    // One token rotated and the other expires 40 seconds later: the successor
    // is admitted with overlap and serves until then (#2641).
    for later in [40, 1, 500] {
        let admitted = admit_successor(
            &mut fixture,
            Some(current),
            vec![(current + later).to_string()],
        )
        .await
        .unwrap();
        assert_eq!(
            admitted.expiry.map(|expiry| expiry.unix),
            Some(current + later)
        );
    }
    fixture.stop().await;
}

#[tokio::test]
async fn a_missing_or_malformed_expiry_admits_a_fresh_epoch_without_one() {
    let mut fixture = Fixture::new().await;
    for header in [
        vec![],
        vec!["12a".to_owned()],
        vec![(unix_now() + 900).to_string()],
    ] {
        let admitted = admit_successor(&mut fixture, None, header).await.unwrap();
        assert_eq!(admitted.expiry, None);
        assert!(Renewal::new(&admitted).is_none());
    }
    fixture.stop().await;
}

/// The log names the hop that refused an epoch, and tells a transport failure
/// tonic made locally from a status the peer answered.
#[test]
fn an_unadmitted_epoch_names_its_hop() {
    let connect = Status::from_error(Box::new(tonic::ConnectError(Box::new(
        std::io::Error::other("connection refused"),
    ))));
    assert_eq!(connect.code(), tonic::Code::Unavailable);
    let unreachable = Unadmitted::from_daemon(&SessionClientError::Status(connect));
    assert_eq!(
        (unreachable.hop(), unreachable.reason()),
        ("daemon", "daemon_unreachable")
    );
    let refused = Unadmitted::from_daemon(&SessionClientError::Status(
        Status::failed_precondition("credential bridge is unavailable"),
    ));
    assert_eq!(
        (refused, refused.hop(), refused.reason()),
        (
            Unadmitted::DaemonRefused(tonic::Code::FailedPrecondition),
            "daemon",
            "daemon_refused"
        )
    );
    let broker = Unadmitted::from_broker(&Status::permission_denied("denied"));
    assert_eq!(
        (broker.hop(), broker.reason()),
        ("broker", "broker_refused")
    );
    assert_eq!(Unadmitted::RelayToken.hop(), "relay");
}
