use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response};

use super::*;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::host::path as host_path;
use crate::supervisor_config::{NATIVE_SUPERVISOR_PROTOCOL_VERSION, NativeRuntimeConfig};

#[derive(Clone)]
enum WatchReply {
    Updates(Vec<Result<v1::Operation, Status>>),
    Failure(tonic::Code),
}

#[derive(Clone)]
struct ProtocolPeer {
    info: Result<v1::SupervisorInfo, tonic::Code>,
    calls: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<VecDeque<WatchReply>>>,
    /// Whether `get` finds the environment; false answers NotFound, as after
    /// a failed create's rollback.
    environment_present: bool,
}

impl ProtocolPeer {
    fn record(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }
}

// This is a synthetic protocol peer, not the native supervisor or a proof of
// server-side peer admission. Product owner-only listener code stays Linux-only.
#[tonic::async_trait]
impl LocalSupervisorService for ProtocolPeer {
    async fn get_supervisor_info(
        &self,
        _: Request<v1::GetSupervisorInfoRequest>,
    ) -> Result<Response<v1::SupervisorInfo>, Status> {
        self.record("info");
        self.info
            .clone()
            .map(Response::new)
            .map_err(|code| Status::new(code, "untrusted peer details"))
    }

    async fn list_environments(
        &self,
        _: Request<v1::ListEnvironmentsRequest>,
    ) -> Result<Response<v1::ListEnvironmentsResponse>, Status> {
        self.record("list");
        Ok(Response::new(v1::ListEnvironmentsResponse {
            environments: vec![environment()],
        }))
    }

    async fn get_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        assert_eq!(request.name, "dev");
        assert!(request.request_id.is_empty());
        assert!(request.environment_id.is_empty());
        self.record("get");
        if !self.environment_present {
            return Err(Status::not_found("local environment was not found"));
        }
        Ok(Response::new(environment()))
    }

    async fn stop_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let request = request.into_inner();
        assert_eq!(request.name, "dev");
        assert!(!Uuid::parse_str(&request.request_id).unwrap().is_nil());
        assert!(request.environment_id.is_empty());
        self.record("stop");
        Ok(Response::new(operation(v1::OperationPhase::Intent)))
    }

    type WatchOperationStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<v1::Operation, Status>>>;

    async fn watch_operation(
        &self,
        request: Request<v1::WatchOperationRequest>,
    ) -> Result<Response<Self::WatchOperationStream>, Status> {
        self.record(format!("watch:{}", request.into_inner().operation_id));
        match self.replies.lock().unwrap().pop_front().unwrap() {
            WatchReply::Updates(updates) => Ok(Response::new(tokio_stream::iter(updates))),
            WatchReply::Failure(code) => Err(Status::new(code, "untrusted stream details")),
        }
    }

    async fn create_environment(
        &self,
        request: Request<v1::CreateEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        assert_eq!(request.into_inner().name, "dev");
        self.record("create");
        Ok(Response::new(operation(v1::OperationPhase::Intent)))
    }

    async fn select_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn retire_supervisor(
        &self,
        _: Request<v1::RetireSupervisorRequest>,
    ) -> Result<Response<v1::RetireSupervisorResponse>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn list_orphans(
        &self,
        _: Request<v1::ListOrphansRequest>,
    ) -> Result<Response<v1::ListOrphansResponse>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn start_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn restart_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn refresh_environment_skills(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn resize_environment(
        &self,
        _: Request<v1::ResizeEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn update_host_ports(
        &self,
        _: Request<v1::UpdateHostPortsRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn update_environment_sources(
        &self,
        _: Request<v1::UpdateEnvironmentSourcesRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn delete_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn get_operation(
        &self,
        _: Request<v1::GetOperationRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn ensure_credential_broker(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::CredentialBrokerRuntime>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn get_daemon_access(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    type OpenEnvironmentSshStreamStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<v1::SshStreamFrame, Status>>>;

    async fn open_environment_ssh_stream(
        &self,
        _: Request<tonic::Streaming<v1::SshStreamFrame>>,
    ) -> Result<Response<Self::OpenEnvironmentSshStreamStream>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }

    async fn get_managed_runtime(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::ManagedRuntime>, Status> {
        Err(Status::unimplemented("unused synthetic method"))
    }
}

struct TestServer {
    _parent: tempfile::TempDir,
    config: NativeRuntimeConfig,
    socket: PathBuf,
    identity: host_path::SocketIdentity,
    calls: Arc<Mutex<Vec<String>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    fn start(
        info: impl FnOnce(&NativeRuntimeConfig) -> Result<v1::SupervisorInfo, tonic::Code>,
        replies: Vec<WatchReply>,
    ) -> Self {
        Self::start_with_environment(info, replies, true)
    }

    fn start_with_environment(
        info: impl FnOnce(&NativeRuntimeConfig) -> Result<v1::SupervisorInfo, tonic::Code>,
        replies: Vec<WatchReply>,
        environment_present: bool,
    ) -> Self {
        // Keep Unix paths short and canonical on both hosts. This creates only
        // an owned fixture; production input is never silently canonicalized.
        let parent = tempfile::Builder::new()
            .prefix("cw-sc-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(fs::canonicalize("/var/tmp").unwrap())
            .unwrap();
        let private = host_path::PrivateRoot::open(parent.path()).unwrap();
        private.create_dir(Path::new("runtime"), 0o700).unwrap();
        let config = NativeRuntimeConfig {
            root: parent.path().join("runtime"),
            artifact_root: parent.path().join("artifacts"),
            artifact_lock: parent.path().join("artifacts.lock"),
            mesh_data_dir: parent.path().join("mesh"),
            platform_config_dir: parent.path().join("platform"),
            credential_authority_root: parent.path().join("authority"),
            executable: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        };
        crate::socket_dir::prepare(&config.root).unwrap();
        let socket = config.supervisor_socket();
        let listener = UnixListener::bind(&socket).unwrap();
        let identity = host_path::set_socket_private(&socket).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peer = ProtocolPeer {
            info: info(&config),
            calls: calls.clone(),
            replies: Arc::new(Mutex::new(replies.into())),
            environment_present,
        };
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LocalSupervisorServiceServer::new(peer))
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = receiver.await;
                })
                .await
                .unwrap();
        });
        Self {
            _parent: parent,
            config,
            socket,
            identity,
            calls,
            shutdown: Some(shutdown),
            task,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    async fn finish(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), &mut self.task)
            .await
            .unwrap()
            .unwrap();
        self.identity.revalidate(&self.socket).unwrap();
        assert!(
            host_path::PrivateRoot::open(&self.config.socket_dir())
                .unwrap()
                .remove_private_socket(Path::new("supervisor.sock"))
                .unwrap()
        );
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Abort only the task created by this fixture, including panic paths.
        self.task.abort();
    }
}

fn valid_info(config: &NativeRuntimeConfig) -> Result<v1::SupervisorInfo, tonic::Code> {
    Ok(crate::supervisor_config::supervisor_info(config))
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("synthetic client operation exceeded its five-second deadline")
}

fn operation(phase: v1::OperationPhase) -> v1::Operation {
    v1::Operation {
        operation_id: "f30e0037-c1b1-46d0-8d8d-cd512049a002".to_owned(),
        phase: phase as i32,
        ..Default::default()
    }
}

fn environment() -> v1::Environment {
    v1::Environment {
        name: "dev".to_owned(),
        state: v1::EnvironmentState::Stopped as i32,
        ..Default::default()
    }
}

#[test]
fn operation_phases_outcomes_and_selectors_preserve_contract() {
    for phase in [
        v1::OperationPhase::Intent,
        v1::OperationPhase::EffectApplied,
    ] {
        assert!(!operation_terminal(&operation(phase)).unwrap());
        assert!(operation_outcome(operation(phase)).is_err());
    }
    for phase in [
        v1::OperationPhase::Completed,
        v1::OperationPhase::Failed,
        v1::OperationPhase::Interrupted,
    ] {
        assert!(operation_terminal(&operation(phase)).unwrap());
        assert_eq!(
            operation_outcome(operation(phase)).is_ok(),
            phase == v1::OperationPhase::Completed
        );
    }
    for phase in [0, -1, 99] {
        let mut invalid = operation(v1::OperationPhase::Intent);
        invalid.phase = phase;
        assert_eq!(
            operation_terminal(&invalid).unwrap_err().code(),
            tonic::Code::Internal
        );
    }
    let read = read_selector("dev");
    assert_eq!(read.name, "dev");
    assert!(read.request_id.is_empty() && read.environment_id.is_empty());
    let first = mutation_selector("dev");
    let second = mutation_selector("dev");
    assert_eq!(first.name, "dev");
    assert!(first.environment_id.is_empty());
    assert!(!Uuid::parse_str(&first.request_id).unwrap().is_nil());
    assert_ne!(first.request_id, second.request_id);
}

#[tokio::test]
async fn existing_endpoint_admits_compatibility_before_requests() {
    let server = TestServer::start(valid_info, vec![]);
    let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
        .await
        .unwrap();
    assert_eq!(bounded(client.list()).await.unwrap(), vec![environment()]);
    assert_eq!(server.calls(), ["info", "list"]);
    drop(client);
    server.finish().await;
}

#[tokio::test]
async fn exact_configuration_digest_is_admitted() {
    let server = TestServer::start(valid_info, vec![]);
    let mut client = bounded(NativeSupervisorClient::connect_admitted(
        &server.socket,
        Some(server.config.configuration_digest()),
    ))
    .await
    .unwrap();
    assert_eq!(bounded(client.list()).await.unwrap(), vec![environment()]);
    assert_eq!(server.calls(), ["info", "list"]);
    drop(client);
    server.finish().await;
}

#[tokio::test]
async fn compatibility_rejects_old_wrong_malformed_and_unavailable_peers() {
    for case in 0..5 {
        let server = TestServer::start(
            |config| {
                let mut info = valid_info(config).unwrap();
                match case {
                    0 => Err(tonic::Code::Unimplemented),
                    1 => {
                        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1;
                        Ok(info)
                    }
                    2 => {
                        info.configuration_sha256.pop();
                        Ok(info)
                    }
                    3 => Ok(info),
                    _ => Err(tonic::Code::PermissionDenied),
                }
            },
            vec![],
        );
        let error = match bounded(NativeSupervisorClient::connect_admitted(
            &server.socket,
            Some([0; 32]),
        ))
        .await
        {
            Ok(_) => panic!("incompatible peer admitted"),
            Err(error) => error,
        };
        match case {
            0 => assert!(matches!(
                error,
                SupervisorClientError::SupervisorProtocolUnavailable
            )),
            1 => assert!(matches!(
                error,
                SupervisorClientError::Configuration(
                    SupervisorConfigError::SupervisorProtocolMismatch { .. }
                )
            )),
            2 => assert!(matches!(
                error,
                SupervisorClientError::Configuration(SupervisorConfigError::InvalidSupervisorInfo)
            )),
            3 => assert!(matches!(
                error,
                SupervisorClientError::Configuration(
                    SupervisorConfigError::SupervisorConfigurationMismatch
                )
            )),
            _ => assert!(matches!(
                error,
                SupervisorClientError::SupervisorInfoUnavailable
            )),
        }
        assert!(!error.to_string().contains("untrusted"));
        assert_eq!(server.calls(), ["info"]);
        server.finish().await;
    }
}

#[tokio::test]
async fn mutation_waits_for_terminal_then_reads_environment() {
    let server = TestServer::start(
        valid_info,
        vec![WatchReply::Updates(vec![
            Ok(operation(v1::OperationPhase::EffectApplied)),
            Ok(operation(v1::OperationPhase::Completed)),
        ])],
    );
    let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
        .await
        .unwrap();
    assert_eq!(bounded(client.stop("dev")).await.unwrap(), environment());
    assert_eq!(
        server.calls(),
        [
            "info",
            "stop",
            "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002",
            "get"
        ]
    );
    drop(client);
    server.finish().await;
}

#[tokio::test]
async fn connect_only_stream_failure_has_no_restart_authority() {
    for reply in [
        WatchReply::Updates(vec![]),
        WatchReply::Failure(tonic::Code::Unavailable),
    ] {
        let server = TestServer::start(valid_info, vec![reply]);
        let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
            .await
            .unwrap();
        let initial = operation(v1::OperationPhase::Intent);
        let error = bounded(client.follow_operation(initial.clone(), &mut |_| {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(error.message().contains(&initial.operation_id));
        assert!(!error.message().contains("untrusted"));
        assert_eq!(
            server.calls(),
            ["info", "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002"]
        );
        server.identity.revalidate(&server.socket).unwrap();
        drop(client);
        server.finish().await;
    }
}

#[tokio::test]
async fn observe_sees_the_initial_and_each_non_terminal_update() {
    let mut started = operation(v1::OperationPhase::EffectApplied);
    started.stage = v1::OperationStage::StartVm as i32;
    let server = TestServer::start(
        valid_info,
        vec![WatchReply::Updates(vec![
            Ok(started.clone()),
            Ok(operation(v1::OperationPhase::Completed)),
        ])],
    );
    let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
        .await
        .unwrap();
    let initial = operation(v1::OperationPhase::Intent);
    let mut seen = Vec::new();
    let mut observe = |update: &v1::Operation| seen.push(update.clone());
    bounded(client.follow_operation(initial.clone(), &mut observe))
        .await
        .unwrap();
    assert_eq!(seen, [initial, started]);
    drop(client);
    server.finish().await;
}

#[tokio::test]
async fn a_failed_create_says_whether_its_rollback_removed_it() {
    for (present, expected) in [
        (
            false,
            " No environment was kept; the image layers it downloaded stay cached, so a retry resumes.",
        ),
        (
            true,
            " The failed environment could not be removed; run `cw --local rm dev`.",
        ),
    ] {
        let mut failed = operation(v1::OperationPhase::Failed);
        failed.error_code = "create_registry_platform".to_owned();
        let server = TestServer::start_with_environment(
            valid_info,
            vec![WatchReply::Updates(vec![Ok(failed)])],
            present,
        );
        let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
            .await
            .unwrap();
        let error = bounded(client.create(v1::CreateEnvironmentRequest {
            name: "dev".to_owned(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            error
                .message()
                .contains("failed: create_registry_platform (")
        );
        assert!(error.message().ends_with(expected), "{}", error.message());
        assert_eq!(
            server.calls(),
            [
                "info",
                "create",
                "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002",
                "get"
            ]
        );
        drop(client);
        server.finish().await;
    }
}

#[tokio::test]
async fn terminal_initial_result_does_not_open_a_watch() {
    let server = TestServer::start(valid_info, vec![]);
    let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
        .await
        .unwrap();
    let terminal = operation(v1::OperationPhase::Completed);
    assert_eq!(
        bounded(client.follow_operation(terminal.clone(), &mut |_| {}))
            .await
            .unwrap(),
        terminal
    );
    assert_eq!(server.calls(), ["info"]);
    drop(client);
    server.finish().await;
}

#[tokio::test]
async fn stream_failures_and_invalid_phases_do_not_become_success() {
    for (phase, expected_code) in [
        (
            v1::OperationPhase::Failed as i32,
            tonic::Code::FailedPrecondition,
        ),
        (
            v1::OperationPhase::Interrupted as i32,
            tonic::Code::FailedPrecondition,
        ),
        (99, tonic::Code::Internal),
    ] {
        let mut update = operation(v1::OperationPhase::Intent);
        update.phase = phase;
        update.error_code = "synthetic_failure".to_owned();
        let server = TestServer::start(valid_info, vec![WatchReply::Updates(vec![Ok(update)])]);
        let mut client = bounded(NativeSupervisorClient::connect(&server.socket))
            .await
            .unwrap();
        let initial = operation(v1::OperationPhase::Intent);
        let error = bounded(client.follow_operation(initial.clone(), &mut |_| {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
        assert!(error.message().contains(&initial.operation_id));
        assert_eq!(
            server.calls(),
            ["info", "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002"]
        );
        drop(client);
        server.finish().await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_reconnect_readmits_and_replaces_client_without_reissuing_mutation() {
    let server = TestServer::start(
        valid_info,
        vec![
            WatchReply::Updates(vec![]),
            WatchReply::Updates(vec![Ok(operation(v1::OperationPhase::Completed))]),
        ],
    );
    // This in-process protocol fixture uses the generic pinned API and opts
    // into watch reconnect. Production only enables this after fixed-role
    // configuration admission, exercised in linux::supervisor_peer tests.
    let mut client = bounded(NativeSupervisorClient::connect_admitted(
        &server.socket,
        Some(server.config.configuration_digest()),
    ))
    .await
    .unwrap();
    client.reconnect_enabled = true;
    let original_pin = client.peer_pin.clone();
    let started = tokio::time::Instant::now();
    assert_eq!(bounded(client.stop("dev")).await.unwrap(), environment());
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(
        server.calls(),
        [
            "info",
            "stop",
            "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002",
            "info",
            "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002",
            "get"
        ]
    );
    assert!(Arc::ptr_eq(&original_pin, &client.peer_pin));
    drop(client);
    server.finish().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_watch_reconnect_is_bounded_to_three_attempts() {
    let server = TestServer::start(
        valid_info,
        vec![WatchReply::Failure(tonic::Code::Unavailable); 4],
    );
    let mut client = bounded(NativeSupervisorClient::connect_admitted(
        &server.socket,
        Some(server.config.configuration_digest()),
    ))
    .await
    .unwrap();
    client.reconnect_enabled = true;
    let started = tokio::time::Instant::now();
    let error =
        bounded(client.follow_operation(operation(v1::OperationPhase::Intent), &mut |_| {}))
            .await
            .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(started.elapsed() >= Duration::from_millis(300));
    let calls = server.calls();
    assert_eq!(
        calls.iter().filter(|call| call.as_str() == "info").count(),
        4
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.as_str() == "watch:f30e0037-c1b1-46d0-8d8d-cd512049a002")
            .count(),
        4
    );
    assert_eq!(calls.len(), 8);
    drop(client);
    server.finish().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn watch_reconnect_refuses_replacement_and_preserves_original_operation_without_replay() {
    let mut server = TestServer::start(
        valid_info,
        vec![WatchReply::Failure(tonic::Code::Unavailable)],
    );
    let mut client = bounded(NativeSupervisorClient::connect_admitted(
        &server.socket,
        Some(server.config.configuration_digest()),
    ))
    .await
    .unwrap();
    client.reconnect_enabled = true;
    let original_calls = server.calls.clone();
    let initial = operation(v1::OperationPhase::Intent);
    let expected_id = initial.operation_id.clone();
    let follower = tokio::spawn(async move { client.follow_operation(initial, &mut |_| {}).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while original_calls.lock().unwrap().len() < 2 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    server.shutdown.take().unwrap().send(()).unwrap();
    bounded(&mut server.task).await.unwrap();
    host_path::PrivateRoot::open(&server.config.socket_dir())
        .unwrap()
        .remove_private_socket(Path::new("supervisor.sock"))
        .unwrap();
    let listener = UnixListener::bind(&server.socket).unwrap();
    server.identity = host_path::set_socket_private(&server.socket).unwrap();
    let replacement_calls = Arc::new(Mutex::new(Vec::new()));
    let peer = ProtocolPeer {
        info: valid_info(&server.config),
        calls: replacement_calls.clone(),
        replies: Arc::new(Mutex::new(VecDeque::new())),
        environment_present: true,
    };
    let (shutdown, receiver) = oneshot::channel();
    server.task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LocalSupervisorServiceServer::new(peer))
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = receiver.await;
            })
            .await
            .unwrap();
    });
    server.shutdown = Some(shutdown);
    let error = bounded(follower).await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(error.message().contains(&expected_id));
    assert_eq!(
        *original_calls.lock().unwrap(),
        ["info", &format!("watch:{expected_id}")]
    );
    assert!(replacement_calls.lock().unwrap().is_empty());
    server.identity.revalidate(&server.socket).unwrap();
    server.finish().await;
}

#[test]
fn direct_share_change_failures_name_the_moved_source() {
    for code in ["create_direct_share_changed", "start_direct_share_changed"] {
        let hint = operation_error_hint(code);
        assert!(
            hint.contains("direct-mount source directory"),
            "{code}: {hint}"
        );
        assert!(
            hint.contains("put the original directory back"),
            "{code}: {hint}"
        );
    }
    assert_eq!(operation_error_hint("start_failed"), "");
}
