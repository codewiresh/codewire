//! Real daemon RPC -> one-shot launcher -> workload conformance, synthetic only.
//! Run with an executable TMPDIR (the host's /tmp is mounted noexec). The daemon
//! is itself an env-cleared child so native inheritance cannot copy owner auth.
#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_daemon::client::SessionClient;
use codewire_daemon::{
    Config, CredentialBridgeConfig, CredentialBridgeTransport, DaemonAuthToken,
    LaunchProjectionConfig, NativeLaunchProjectionConfig, serve_grpc_with_incoming,
};
use codewire_daemon_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::daemon::v1::daemon_service_client::DaemonServiceClient;
use codewire_workload_secrets::launcher::{now_unix_ms, run_environment_launcher};
use codewire_workload_secrets::{
    EnvironmentProjection, ProjectionContext, seal_environment_projection,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::transport::{Channel, Endpoint};
use uuid::Uuid;

const TOKEN: &str = "synthetic-projection-conformance-token";
const DAEMON_ROOT: &str = "CW_SYNTHETIC_PROJECTION_DAEMON_ROOT";
const ENVIRONMENT_ID: &str = "CW_SYNTHETIC_PROJECTION_ENVIRONMENT_ID";
const LAUNCH_SOCKET: &str = "CW_SYNTHETIC_PROJECTION_LAUNCH_SOCKET";
const SELECTION: [u8; 32] = [9; 32];
const GENERATION: u64 = 7;
const BOUND: Duration = Duration::from_secs(15);
const FIRST: &str = "synthetic-projected-first";
const SECOND: &str = "synthetic-projected-second";
const REQUEST_ENV: [&str; 3] = [
    "PROJECTION_EXPLICIT=explicit-request-value",
    "PROJECTION_EMPTY=",
    "REQUEST_ONLY=request-input",
];
const PROBE: &str = concat!(
    "if [ -t 0 ] && [ -t 1 ]; then tty=yes; else tty=no; fi; ",
    "printf '\nCW_PROJECTION_RESULT|%s|%s:%s|%s|%s|%s|%s|%s\n' ",
    "\"$PROJECTION_EXPLICIT\" \"${PROJECTION_EMPTY+x}\" \"$PROJECTION_EMPTY\" ",
    "\"$PROJECTION_ROTATING\" \"$TERM\" \"$tty\" \"$IMAGE_ONLY\" \"$REQUEST_ONLY\"",
);
const TRANSIENT_PROBE: &str =
    "printf 'CW_TRANSIENT_RESULT|%s|%s\\n' \"$CW_DEV_PRECEDENCE\" \"$PROJECTION_ROTATING\"";

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(BOUND, future)
        .await
        .expect("synthetic projection conformance deadline")
}

fn authorized<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        DAEMON_AUTH_TOKEN_HEADER,
        TOKEN.parse().expect("synthetic token metadata"),
    );
    request
}

#[test]
fn projection_daemon_child() {
    let Some(root) = std::env::var_os(DAEMON_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let environment = Uuid::parse_str(&std::env::var(ENVIRONMENT_ID).unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let config = Config {
            listen_addr: endpoint.clone(),
            workspace_root: root.join("workspace"),
            home_root: root.join("home"),
            auth_token: DaemonAuthToken::new(TOKEN).unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: Some(CredentialBridgeConfig {
                transport: CredentialBridgeTransport::Local,
                environment_id: environment,
                environment_generation: GENERATION,
                ingress_socket: root.join("provider.sock"),
                ingress_uid: unsafe { libc::geteuid() },
                ingress_gid: unsafe { libc::getegid() },
            }),
            managed_credential_clients: Default::default(),
            launch_projection: Some(LaunchProjectionConfig {
                selection_sha256: SELECTION,
                native: Some(NativeLaunchProjectionConfig {
                    helper_path: root.join("launcher"),
                    process_directory: root.join("processes"),
                }),
            }),
        };
        println!("\nCW_PROJECTION_ENDPOINT={endpoint}");
        std::io::stdout().flush().unwrap();
        serve_grpc_with_incoming(config, TcpListenerStream::new(listener), async {
            // EOF on the parent's owned pipe is the fixture's shutdown signal.
            tokio::task::spawn_blocking(|| {
                let _ = std::io::stdin().read(&mut [0]);
            })
            .await
            .unwrap();
        })
        .await
        .unwrap();
    });
}

#[test]
fn projection_launcher_child() {
    let Some(socket) = std::env::var_os(LAUNCH_SOCKET) else {
        return;
    };
    let command: Vec<OsString> = (0..3)
        .map(|index| std::env::var_os(format!("CW_SYNTHETIC_LAUNCH_ARG_{index}")).unwrap())
        .collect();
    // The adapter forwards the actual RPC command, not a substitute merge or
    // fake workload. Only this production launcher opens the sealed projection.
    assert!(run_environment_launcher(Path::new(&socket), &command).is_err());
    std::process::exit(71);
}

fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn create_launcher_adapter(root: &Path) {
    let executable = std::env::current_exe().unwrap();
    let script = format!(
        "#!/bin/sh\nset -eu\n\
         [ \"$#\" = 7 ] && [ \"$1\" = __environment-launch ] && \
         [ \"$2\" = --projection-socket ] && [ \"$4\" = -- ] || exit 72\n\
         export {LAUNCH_SOCKET}=\"$3\"\nshift 4\n\
         export CW_SYNTHETIC_LAUNCH_ARG_0=\"$1\"\n\
         export CW_SYNTHETIC_LAUNCH_ARG_1=\"$2\"\n\
         export CW_SYNTHETIC_LAUNCH_ARG_2=\"$3\"\n\
         printf '%s\\n' \"$$\" > {}\n\
         exec {} --exact projection_launcher_child --nocapture\n",
        quote_shell(root.join("launcher.pid").to_str().unwrap()),
        quote_shell(executable.to_str().unwrap()),
    );
    let adapter = root.join("launcher");
    std::fs::write(&adapter, script).unwrap();
    std::fs::set_permissions(adapter, std::fs::Permissions::from_mode(0o700)).unwrap();
}

struct Harness {
    // Drop the kill-on-drop child before removing its owned scratch directory.
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: JoinHandle<Vec<u8>>,
    stderr: JoinHandle<Vec<u8>>,
    stop_projection: Option<oneshot::Sender<()>>,
    projection: Option<JoinHandle<ProjectionHistory>>,
    session_client: SessionClient,
    client: DaemonServiceClient<Channel>,
    root: tempfile::TempDir,
    endpoint: String,
    environment: Uuid,
}

#[derive(Default)]
struct ProjectionHistory {
    ids: BTreeSet<String>,
    recipients: BTreeSet<Vec<u8>>,
    count: usize,
    cancellations: BTreeSet<String>,
}

struct ProjectionGate {
    index: usize,
    requested: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with_gate(None).await
    }

    async fn start_with_gate(gate: Option<ProjectionGate>) -> Self {
        let root = tempfile::Builder::new()
            .prefix("cw-proj-")
            .tempdir()
            .unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o700)).unwrap();
        for directory in ["home", "workspace", "processes"] {
            let directory = canonical.join(directory);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        create_launcher_adapter(&canonical);
        let environment = Uuid::new_v4();
        Self::open(root, environment, ProjectionHistory::default(), gate).await
    }

    async fn open(
        root: tempfile::TempDir,
        environment: Uuid,
        history: ProjectionHistory,
        mut gate: Option<ProjectionGate>,
    ) -> Self {
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "projection_daemon_child", "--nocapture"])
            .env_clear()
            .env(DAEMON_ROOT, &canonical)
            .env(ENVIRONMENT_ID, environment.to_string())
            .env("HOME", canonical.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env("TERM", "image-term")
            .env("PROJECTION_EXPLICIT", "image-explicit")
            .env("PROJECTION_EMPTY", "image-not-empty")
            .env("PROJECTION_ROTATING", "image-rotating")
            .env("IMAGE_ONLY", "image-only")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let endpoint = bounded(async {
            loop {
                let mut line = String::new();
                assert!(output.read_line(&mut line).await.unwrap() > 0);
                if let Some(endpoint) = line.trim().strip_prefix("CW_PROJECTION_ENDPOINT=") {
                    break endpoint.to_owned();
                }
            }
        })
        .await;
        let stdout = tokio::spawn(async move {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        let mut errors = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new();
            errors.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        let client = bounded(DaemonServiceClient::connect(endpoint.clone()))
            .await
            .unwrap();
        let session_client = bounded(SessionClient::connect(endpoint.clone(), TOKEN))
            .await
            .unwrap();
        let mut connection =
            bounded(session_client.open_credential_bridge(environment, GENERATION))
                .await
                .unwrap();
        let ready = bounded(connection.receive()).await.unwrap().unwrap();
        let Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(ready)) = ready.payload
        else {
            panic!("synthetic bridge did not receive Ready");
        };
        assert_eq!(ready.environment_id, environment.to_string());
        assert_eq!(ready.environment_generation, GENERATION);
        let (stop_projection, mut stop) = oneshot::channel();
        let projection = tokio::spawn(async move {
            let ProjectionHistory {
                mut ids,
                mut recipients,
                mut count,
                mut cancellations,
            } = history;
            let mut gated_request_id = None;
            loop {
                let message = tokio::select! {
                    _ = &mut stop => break,
                    message = connection.receive() => message.unwrap().expect("projection bridge closed"),
                };
                let request = match message.payload {
                    Some(
                        bridge_v1::credential_bridge_guest_message::Payload::EnvironmentProjection(
                            request,
                        ),
                    ) => request,
                    Some(bridge_v1::credential_bridge_guest_message::Payload::Cancel(cancel)) => {
                        assert_eq!(Some(&cancel.request_id), gated_request_id.as_ref());
                        assert!(ids.contains(&cancel.request_id));
                        assert!(cancellations.insert(cancel.request_id));
                        continue;
                    }
                    _ => panic!("unexpected synthetic bridge operation"),
                };
                assert!(ids.insert(request.request_id.clone()));
                assert!(recipients.insert(request.recipient_public_key.clone()));
                assert_eq!(request.selection_sha256, SELECTION);
                if gate.as_ref().is_some_and(|gate| gate.index == count) {
                    let gate = gate.take().unwrap();
                    gated_request_id = Some(request.request_id.clone());
                    gate.requested.send(()).unwrap();
                    bounded(gate.release).await.unwrap();
                }
                let context = ProjectionContext {
                    environment_id: *environment.as_bytes(),
                    operation_generation: GENERATION,
                    selection_sha256: SELECTION,
                    deadline_unix_ms: request.deadline_unix_ms,
                };
                context.validate_at(now_unix_ms().unwrap()).unwrap();
                let rotating = match count {
                    0 => FIRST,
                    1 => SECOND,
                    _ => panic!("unexpected projection retry or extra launch"),
                };
                let values = EnvironmentProjection::from_entries([
                    (
                        "PROJECTION_EXPLICIT".into(),
                        b"projected-shadow".to_vec().into(),
                    ),
                    (
                        "PROJECTION_EMPTY".into(),
                        b"projected-not-empty".to_vec().into(),
                    ),
                    (
                        "PROJECTION_ROTATING".into(),
                        rotating.as_bytes().to_vec().into(),
                    ),
                    ("TERM".into(), b"projected-term".to_vec().into()),
                    (
                        "CW_DEV_PRECEDENCE".into(),
                        b"projected-shadow".to_vec().into(),
                    ),
                ])
                .unwrap();
                let sealed = seal_environment_projection(
                    values,
                    &context,
                    request.recipient_public_key.try_into().unwrap(),
                    now_unix_ms().unwrap(),
                )
                .unwrap();
                bounded(connection.response_sender().send_environment_projection(
                    bridge_v1::EnvironmentProjectionResponse {
                        request_id: request.request_id,
                        result: Some(
                            bridge_v1::environment_projection_response::Result::SealedProjection(
                                sealed,
                            ),
                        ),
                    },
                ))
                .await
                .unwrap();
                count += 1;
            }
            ProjectionHistory {
                ids,
                recipients,
                count,
                cancellations,
            }
        });
        Self {
            child,
            stdin,
            stdout,
            stderr,
            stop_projection: Some(stop_projection),
            projection: Some(projection),
            session_client,
            client,
            root,
            endpoint,
            environment,
        }
    }

    async fn exited(&mut self, id: &str) -> v1::SessionRecord {
        bounded(async {
            loop {
                let record = self
                    .client
                    .get_session(authorized(v1::GetSessionRequest {
                        session_id: id.into(),
                    }))
                    .await
                    .unwrap()
                    .into_inner()
                    .session
                    .unwrap();
                match v1::SessionLifecycleState::try_from(record.state).unwrap() {
                    v1::SessionLifecycleState::Exited => {
                        assert_eq!(record.exit_code, Some(0));
                        return record;
                    }
                    v1::SessionLifecycleState::Starting | v1::SessionLifecycleState::Running => {}
                    _ => panic!(
                        "synthetic projected launch did not exit normally: {}",
                        record.status_message
                    ),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }

    async fn output(&mut self, id: &str, offset: u64, pty: bool) -> String {
        let output = bounded(self.client.read_session_output(authorized(
            v1::ReadSessionOutputRequest {
                session_id: id.into(),
                offset,
                limit: 64 * 1024,
                allow_history_gap: false,
            },
        )))
        .await
        .unwrap()
        .into_inner();
        assert!(output.eof);
        let mut bytes = Vec::new();
        for chunk in output.chunks {
            assert_eq!(
                chunk.stream,
                if pty {
                    v1::SessionOutputStream::Pty
                } else {
                    v1::SessionOutputStream::Stdout
                } as i32
            );
            bytes.extend_from_slice(&chunk.data);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn assert_persisted_inputs(&self, id: &str, pty: bool, term: &str) {
        let path = self
            .root
            .path()
            .join("home/.codewire/daemon/sessions")
            .join(id)
            .join("session.json");
        let bytes = std::fs::read(path).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(metadata["env"], serde_json::json!(REQUEST_ENV));
        assert_eq!(metadata["term"], term);
        assert_eq!(metadata["pty"], pty);
        assert_eq!(
            metadata["command"],
            serde_json::json!(["/bin/sh", "-c", PROBE])
        );
        for absent in [
            FIRST,
            SECOND,
            "projected-shadow",
            "projected-not-empty",
            "projected-term",
            "image-rotating",
        ] {
            assert!(
                !bytes
                    .windows(absent.len())
                    .any(|part| part == absent.as_bytes())
            );
        }
    }

    async fn stop(self) {
        self.stop_with_cancellations(0).await;
    }

    async fn stop_with_cancellations(self, cancellations: usize) {
        self.stop_preserving_store(2, cancellations).await;
    }

    async fn stop_preserving_store(
        mut self,
        projections: usize,
        cancellations: usize,
    ) -> (tempfile::TempDir, Uuid, ProjectionHistory) {
        self.stop_projection.take().unwrap().send(()).unwrap();
        let history = bounded(self.projection.take().unwrap()).await.unwrap();
        assert_eq!(history.count, projections);
        assert_eq!(history.cancellations.len(), cancellations);
        let pid = self.child.id().expect("owned daemon PID before reaping");
        drop(self.stdin.take());
        let status = bounded(self.child.wait()).await.unwrap();
        assert_eq!(self.child.try_wait().unwrap(), Some(status));
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        let stdout = bounded(self.stdout).await.unwrap();
        let stderr = bounded(self.stderr).await.unwrap();
        assert!(
            status.success(),
            "synthetic daemon failed: {} {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert!(!self.root.path().join("provider.sock").exists());
        assert_eq!(
            std::fs::read_dir(self.root.path().join("processes"))
                .unwrap()
                .count(),
            0
        );
        (self.root, self.environment, history)
    }
}

async fn assert_transient_projection(client: &SessionClient, rotating: &str) {
    let mut stream = bounded(client.exec_transient(v1::ExecStartRequest {
        command: vec!["/bin/sh".into(), "-c".into(), TRANSIENT_PROBE.into()],
        working_dir: String::new(),
        env: vec!["CW_DEV_PRECEDENCE=ordinary-config".into()],
    }))
    .await
    .unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    while let Some(message) = bounded(stream.message()).await.unwrap() {
        assert!(exit.is_none(), "transient exec emitted a frame after Exit");
        match message.payload.unwrap() {
            v1::exec_message::Payload::Stdout(bytes) => stdout.extend_from_slice(&bytes),
            v1::exec_message::Payload::Stderr(bytes) => stderr.extend_from_slice(&bytes),
            v1::exec_message::Payload::Exit(status) => exit = Some(status.code),
            _ => panic!("transient exec emitted an unexpected frame"),
        }
    }
    assert_eq!(exit, Some(0));
    assert!(stderr.is_empty());
    let stdout = String::from_utf8(stdout).unwrap();
    let receipts: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("CW_TRANSIENT_RESULT|"))
        .collect();
    let expected = format!("CW_TRANSIENT_RESULT|ordinary-config|{rotating}");
    assert_eq!(receipts, [expected.as_str()]);
    assert!(!stdout.contains("CW_TRANSIENT_RESULT|projected-shadow|"));
}

#[tokio::test]
async fn transient_projection_preserves_override_and_terminal_exit_twice() {
    let harness = Harness::start().await;
    assert_transient_projection(&harness.session_client, FIRST).await;
    assert_transient_projection(&harness.session_client, SECOND).await;
    harness.stop().await;
}

async fn launch_and_restart(pty: bool) {
    launch_and_restart_with_harness(Harness::start().await, pty, true).await;
}

async fn launch_and_restart_with_harness(mut harness: Harness, pty: bool, reopen_daemon: bool) {
    let term = if pty { "requested-term" } else { "" };
    let launched = bounded(
        harness
            .client
            .launch_session(authorized(v1::LaunchSessionRequest {
                command: vec!["/bin/sh".into(), "-c".into(), PROBE.into()],
                working_dir: harness
                    .root
                    .path()
                    .join("workspace")
                    .to_str()
                    .unwrap()
                    .into(),
                env: REQUEST_ENV.iter().map(|entry| (*entry).into()).collect(),
                pty,
                term: term.into(),
                width: 80,
                height: 24,
            })),
    )
    .await
    .unwrap()
    .into_inner()
    .session
    .unwrap();
    let id = launched.session_id;
    let first = harness.exited(&id).await;
    let output = harness.output(&id, 0, pty).await;
    assert_probe(&output, FIRST, pty);
    harness.assert_persisted_inputs(&id, pty, term);

    if reopen_daemon {
        // Reap the old daemon, retain only its owned persisted store, and
        // reconnect a new bridge with the exact same admitted authority.
        // Carry recipient/request history so freshness spans both daemons.
        let (root, environment, history) = harness.stop_preserving_store(1, 0).await;
        harness = Harness::open(root, environment, history, None).await;
        let recovered = harness.exited(&id).await;
        assert_eq!(recovered.output_end_offset, first.output_end_offset);
        harness.assert_persisted_inputs(&id, pty, term);
    }

    let restarted = bounded(harness.client.restart_session(authorized(
        v1::RestartSessionRequest {
            session_id: id.clone(),
        },
    )))
    .await
    .unwrap()
    .into_inner()
    .session
    .unwrap();
    assert_eq!(restarted.session_id, id);
    let second = harness.exited(&id).await;
    assert!(second.output_end_offset > first.output_end_offset);
    let output = harness.output(&id, first.output_end_offset, pty).await;
    assert_probe(&output, SECOND, pty);
    assert!(!output.contains(FIRST));
    harness.assert_persisted_inputs(&id, pty, term);
    harness.stop().await;
}

fn assert_probe(output: &str, rotating: &str, pty: bool) {
    let term = if pty {
        "requested-term"
    } else {
        "projected-term"
    };
    let tty = if pty { "yes" } else { "no" };
    let expected = format!(
        "CW_PROJECTION_RESULT|explicit-request-value|x:|{rotating}|{term}|{tty}|image-only|request-input"
    );
    let rows: Vec<_> = output
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.starts_with("CW_PROJECTION_RESULT|"))
        .collect();
    assert_eq!(rows, [expected]);
    assert!(!output.contains("projected-shadow"));
    assert!(!output.contains("projected-not-empty"));
    assert!(!output.contains("image-rotating"));
}

#[tokio::test]
async fn managed_non_pty_restart_preserves_explicit_and_empty_values_with_fresh_projection() {
    launch_and_restart(false).await;
}

#[tokio::test]
async fn managed_pty_restart_preserves_explicit_and_empty_values_with_fresh_projection() {
    launch_and_restart(true).await;
}

async fn cancelled_launch_reaps_and_settles_without_a_late_launch(pty: bool) {
    let (requested, received) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    let mut harness = Harness::start_with_gate(Some(ProjectionGate {
        index: 0,
        requested,
        release: gate,
    }))
    .await;
    let request = v1::LaunchSessionRequest {
        command: vec!["/bin/sh".into(), "-c".into(), PROBE.into()],
        working_dir: harness
            .root
            .path()
            .join("workspace")
            .to_str()
            .unwrap()
            .into(),
        env: REQUEST_ENV.iter().map(|entry| (*entry).into()).collect(),
        pty,
        term: if pty {
            "requested-term".into()
        } else {
            String::new()
        },
        width: 80,
        height: 24,
    };
    // Match the former private unary deadline, not a sleep racing launch.
    // The real bridge gate proves the request reached its exact launcher.
    let channel = Endpoint::from_shared(harness.endpoint.clone())
        .unwrap()
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();
    let mut deadline_client = DaemonServiceClient::new(channel);
    let pending_request = request.clone();
    let mut pending = tokio::spawn(async move {
        deadline_client
            .launch_session(authorized(pending_request))
            .await
    });
    bounded(async {
        tokio::select! {
            ready = received => ready.unwrap(),
            result = &mut pending => panic!("launch settled before its projection gate: {result:?}"),
        }
    }).await;
    let sessions = harness
        .client
        .list_sessions(authorized(v1::ListSessionsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .sessions;
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].state,
        v1::SessionLifecycleState::Starting as i32
    );
    let id = sessions[0].session_id.clone();
    let pid: u32 = std::fs::read_to_string(harness.root.path().join("launcher.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(bounded(pending).await.unwrap().is_err());
    bounded(async {
        while Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let settled = tokio::time::timeout(BOUND, async {
        loop {
            let record = harness
                .client
                .get_session(authorized(v1::GetSessionRequest {
                    session_id: id.clone(),
                }))
                .await
                .unwrap()
                .into_inner()
                .session
                .unwrap();
            if record.state != v1::SessionLifecycleState::Starting as i32 {
                break record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled launch left a Starting record after its child was reaped");
    assert_eq!(settled.state, v1::SessionLifecycleState::Failed as i32);
    assert!(settled.started_at.is_none());
    assert!(settled.finished_at.is_some());
    assert!(settled.exit_code.is_none());
    assert_eq!(settled.output_end_offset, 0);
    release.send(()).unwrap();

    // A later explicit Launch is distinct; opening the old projection gate
    // must neither resurrect its session nor replay its command.
    let fresh = bounded(harness.client.launch_session(authorized(request)))
        .await
        .unwrap()
        .into_inner()
        .session
        .unwrap();
    assert_ne!(fresh.session_id, id);
    harness.exited(&fresh.session_id).await;
    assert_probe(
        &harness.output(&fresh.session_id, 0, pty).await,
        SECOND,
        pty,
    );
    assert!(harness.output(&id, 0, pty).await.is_empty());
    let old = harness
        .client
        .get_session(authorized(v1::GetSessionRequest { session_id: id }))
        .await
        .unwrap()
        .into_inner()
        .session
        .unwrap();
    assert_eq!(old.state, v1::SessionLifecycleState::Failed as i32);
    harness.stop_with_cancellations(1).await;
}

#[tokio::test]
async fn cancelled_pty_launch_reaps_and_settles_without_a_late_launch() {
    cancelled_launch_reaps_and_settles_without_a_late_launch(true).await;
}

#[tokio::test]
async fn cancelled_pipe_launch_reaps_and_settles_without_a_late_launch() {
    cancelled_launch_reaps_and_settles_without_a_late_launch(false).await;
}

async fn delayed_projection_fits_launch_budget(index: usize) {
    let (requested, received) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    let mut harness = Harness::start_with_gate(Some(ProjectionGate {
        index,
        requested,
        release: gate,
    }))
    .await;
    // Composed daemon proof of the Launch/Restart budget. The platform unit
    // test binds its operation-specific policy to the original projection TTL;
    // this real RPC/launcher/bridge path proves a projection beyond five
    // seconds succeeds without changing its authorization expiry.
    let channel = Endpoint::from_shared(harness.endpoint.clone())
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(40))
        .connect()
        .await
        .unwrap();
    harness.client = DaemonServiceClient::new(channel);
    let delay = tokio::spawn(async move {
        bounded(received).await.unwrap();
        tokio::time::sleep(Duration::from_secs(6)).await;
        release.send(()).unwrap();
    });
    launch_and_restart_with_harness(harness, true, false).await;
    delay.await.unwrap();
}

#[tokio::test]
async fn daemon_shutdown_reaps_a_launch_with_its_real_projection_still_pending() {
    let (requested, observed) = oneshot::channel();
    let (_release, gate) = oneshot::channel();
    let mut harness = Harness::start_with_gate(Some(ProjectionGate {
        index: 0,
        requested,
        release: gate,
    }))
    .await;
    let marker = harness.root.path().join("must-not-run-on-shutdown");
    let request = v1::LaunchSessionRequest {
        command: vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf late > {}", quote_shell(marker.to_str().unwrap())),
        ],
        ..Default::default()
    };
    let mut client = harness.client.clone();
    let pending = tokio::spawn(async move { client.launch_session(authorized(request)).await });
    bounded(observed).await.unwrap();
    let pid: u32 = std::fs::read_to_string(harness.root.path().join("launcher.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(Path::new(&format!("/proc/{pid}")).exists());
    // Keep the host connected and its exact response gated until after daemon
    // termination. Closing the owned fixture pipe must cancel launch itself,
    // not rely on a host disconnect or the thirty-second authorization expiry.
    drop(harness.stdin.take());
    let status = tokio::time::timeout(Duration::from_secs(15), harness.child.wait())
        .await
        .expect("shutdown settles without releasing projection")
        .unwrap();
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    assert!(!marker.exists());
    let result = bounded(pending).await.unwrap();
    if let Ok(response) = result {
        assert_eq!(
            response.into_inner().session.unwrap().state,
            v1::SessionLifecycleState::Failed as i32
        );
    }
    // The external observer is intentionally still gated; it never provided
    // projection success. Retire this fixture-owned task after product exit.
    let projection = harness.projection.take().unwrap();
    projection.abort();
    let _ = projection.await;
    let stdout = bounded(harness.stdout).await.unwrap();
    let stderr = bounded(harness.stderr).await.unwrap();
    assert!(
        status.success(),
        "daemon shutdown failed: {} {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(!harness.root.path().join("provider.sock").exists());
    assert_eq!(
        std::fs::read_dir(harness.root.path().join("processes"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn projected_launch_allows_projection_beyond_connect_timeout() {
    delayed_projection_fits_launch_budget(0).await;
}

#[tokio::test]
async fn projected_restart_allows_projection_beyond_connect_timeout() {
    delayed_projection_fits_launch_budget(1).await;
}
