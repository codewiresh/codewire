mod support;

use std::time::Duration;

use codewire_daemon::client::{SessionClient, SessionClientError};
use codewire_daemon::service::DaemonRuntimeState;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{
    DAEMON_CAPABILITIES, DAEMON_CAPABILITY_ATTACH, DAEMON_CAPABILITY_EXEC,
    DAEMON_CAPABILITY_SESSIONS, DAEMON_PROTOCOL_VERSION,
};
use tokio::sync::mpsc;
use tokio_stream::iter;
use tokio_stream::wrappers::ReceiverStream;

use support::{DaemonHarness, HarnessClient};

#[tokio::test]
async fn generated_session_client_authenticates_and_requires_ready_daemon() {
    let harness = DaemonHarness::spawn_with_auth_token("daemon-test-token").await;
    let client = SessionClient::from_channel(harness.channel().await, "daemon-test-token")
        .expect("construct generated session client from injected channel");
    client.require_ready().await.expect("ready daemon");
    let capabilities = client
        .get_capabilities(&[DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH])
        .await
        .expect("generated capabilities");
    assert_eq!(capabilities.state, v1::DaemonState::Ready as i32);
    assert!(
        capabilities
            .capabilities
            .iter()
            .any(|capability| capability == DAEMON_CAPABILITY_SESSIONS)
    );
    let health = client.get_health().await.expect("generated health");
    assert_eq!(health.state, v1::DaemonState::Ready as i32);

    let launched = client
        .launch(v1::LaunchSessionRequest {
            name: String::new(),
            parent_session_id: None,
            command: vec!["sh".into(), "-c".into(), "printf generated-client".into()],
            ..v1::LaunchSessionRequest::default()
        })
        .await
        .expect("launch through generated client");
    assert!(!launched.session_id.is_empty());
    assert_eq!(
        client
            .get(&launched.session_id)
            .await
            .expect("get through generated client")
            .session_id,
        launched.session_id
    );

    let invalid = SessionClient::connect(harness.endpoint(), "wrong-daemon-token")
        .await
        .expect("connect invalid client for server authentication check");
    let error = invalid
        .require_ready()
        .await
        .expect_err("invalid daemon token fails closed");
    assert!(
        matches!(&error, SessionClientError::Status(status) if status.code() == tonic::Code::Unauthenticated)
    );
    assert!(!error.to_string().contains("wrong-daemon-token"));

    assert!(matches!(
        SessionClient::connect(harness.endpoint(), "").await,
        Err(SessionClientError::InvalidCredential)
    ));
    let invalid_endpoint =
        match SessionClient::connect("not a local daemon endpoint", "test-token").await {
            Ok(_) => panic!("invalid endpoint unexpectedly connected"),
            Err(error) => error,
        };
    assert!(matches!(
        invalid_endpoint,
        SessionClientError::InvalidEndpoint
    ));
    assert!(
        !invalid_endpoint
            .to_string()
            .contains("not a local daemon endpoint")
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn generated_client_transient_exec_is_not_a_durable_session() {
    let harness = DaemonHarness::spawn_with_auth_token("daemon-test-token").await;
    let client = SessionClient::from_channel(harness.channel().await, "daemon-test-token")
        .expect("construct generated session client from injected channel");
    let marker = harness.workspace_root().join("transient-marker");
    let mut stream = client
        .exec_transient(v1::ExecStartRequest {
            command: vec![
                "sh".into(),
                "-c".into(),
                "printf transient-ok > transient-marker".into(),
            ],
            working_dir: harness.workspace_root().to_string_lossy().into_owned(),
            env: Vec::new(),
        })
        .await
        .expect("start transient exec");
    let mut exit = None;
    while let Some(message) = stream.message().await.expect("read transient exec") {
        if let Some(v1::exec_message::Payload::Exit(status)) = message.payload {
            exit = Some(status.code);
        }
    }
    assert_eq!(exit, Some(0));
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "transient-ok");
    assert!(
        client
            .list()
            .await
            .expect("list durable sessions")
            .is_empty()
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn injected_transport_rejects_unauthenticated_side_effects() {
    let harness = DaemonHarness::spawn_with_auth_token("daemon-test-token").await;
    let marker = harness.workspace_root().join("unauthorized-marker");
    let working_dir = harness.workspace_root().to_string_lossy().into_owned();
    let command = vec![
        "sh".into(),
        "-c".into(),
        "printf forbidden > unauthorized-marker".into(),
    ];
    let mut client = harness.unauthenticated_client().await;

    let error = client
        .launch_session(v1::LaunchSessionRequest {
            command: command.clone(),
            working_dir: working_dir.clone(),
            ..Default::default()
        })
        .await
        .expect_err("missing token rejects durable session launch");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    let error = client
        .exec_session(iter([v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                command: command.clone(),
                working_dir,
                ..Default::default()
            })),
        }]))
        .await
        .expect_err("missing token rejects streaming exec");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    let error = client
        .open_file(v1::OpenFileRequest {
            path: "unauthorized-marker".into(),
            options: Some(v1::FileOpenOptions {
                write: true,
                create: true,
                ..Default::default()
            }),
            perm: 0o600,
        })
        .await
        .expect_err("missing token rejects file creation");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    let wrong = SessionClient::from_channel(harness.channel().await, "wrong-daemon-token")
        .expect("construct wrong-token client");
    let error = wrong
        .launch(v1::LaunchSessionRequest {
            command,
            ..Default::default()
        })
        .await
        .expect_err("wrong token rejects durable session launch");
    assert!(
        matches!(&error, SessionClientError::Status(status) if status.code() == tonic::Code::Unauthenticated)
    );
    assert!(!error.to_string().contains("wrong-daemon-token"));

    tokio::task::yield_now().await;
    assert!(!marker.exists(), "unauthorized request created a file");
    harness.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn injected_transport_does_not_mount_http_diagnostics() {
    let harness = DaemonHarness::spawn().await;
    let mut grpc = harness.client().await;
    grpc.get_health(v1::GetHealthRequest {})
        .await
        .expect("injected gRPC endpoint is ready");

    let raw_client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .unix_socket(
            harness
                .unix_socket()
                .expect("Unix harness exposes its socket"),
        )
        .build()
        .expect("build Unix HTTP client");
    for path in ["/health", "/exec-check"] {
        let response = raw_client
            .get(format!("http://localhost{path}"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("raw HTTP/2 request reaches {path}: {error}"));
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| panic!("read {path} response: {error}"));
        assert!(
            !status.is_success() || !content_type.starts_with("application/json"),
            "injected transport mounted auxiliary route {path}"
        );
        assert!(!body.contains("\"status\":\"ok\""), "health route ran");
        assert!(!body.contains("\"exec_ok\""), "exec diagnostic ran");
        assert!(!body.contains("\"shell\""), "exec diagnostic ran");
    }
    drop(raw_client);
    drop(grpc);
    harness.shutdown().await;
}

#[tokio::test]
async fn hosted_tcp_transport_preserves_authenticated_typed_lifecycle_and_files() {
    let harness = DaemonHarness::spawn_hosted_tcp().await;
    let mut client = harness.client().await;
    let health = client
        .get_health(v1::GetHealthRequest {})
        .await
        .expect("hosted TCP daemon health")
        .into_inner();
    assert_eq!(health.state, v1::DaemonState::Ready as i32);

    let session_id = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(), "printf hosted-tcp".into()],
            ..Default::default()
        })
        .await
        .expect("hosted TCP launch")
        .into_inner()
        .session
        .expect("hosted TCP session")
        .session_id;
    let exited = wait_for_session_state(
        &mut client,
        &session_id,
        &[v1::SessionLifecycleState::Exited],
    )
    .await;
    assert_eq!(exited.exit_code, Some(0));
    assert_eq!(exited.output_end_offset, 10);

    client
        .open_file(v1::OpenFileRequest {
            path: "hosted-tcp.txt".into(),
            options: Some(v1::FileOpenOptions {
                write: true,
                create: true,
                truncate: true,
                ..Default::default()
            }),
            perm: 0o600,
        })
        .await
        .expect("hosted TCP file create");
    let write = client
        .write(v1::WriteRequest {
            path: "hosted-tcp.txt".into(),
            offset: 0,
            data: b"hosted".to_vec(),
        })
        .await
        .expect("hosted TCP file write")
        .into_inner();
    assert_eq!(write.bytes_written, 6);
    drop(client);
    harness.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn injected_exec_half_close_delivers_output_and_exit() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let (input, rx) = mpsc::channel(4);
    input
        .send(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                command: vec!["sh".into(), "-c".into(), "cat".into()],
                ..Default::default()
            })),
        })
        .await
        .expect("send exec start");
    input
        .send(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Stdin(b"half-close".to_vec())),
        })
        .await
        .expect("send exec input");
    input
        .send(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::CloseStdin(())),
        })
        .await
        .expect("half-close exec stdin");
    drop(input);

    let mut output = client
        .exec_session(ReceiverStream::new(rx))
        .await
        .expect("start half-close exec")
        .into_inner();
    let (stdout, exit) = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stdout = Vec::new();
        let mut exit = None;
        while let Some(message) = output.message().await.expect("exec output") {
            match message.payload {
                Some(v1::exec_message::Payload::Stdout(data)) => stdout.extend(data),
                Some(v1::exec_message::Payload::Exit(status)) => {
                    exit = Some(status.code);
                    break;
                }
                Some(v1::exec_message::Payload::Error(error)) => panic!("exec error: {error}"),
                _ => {}
            }
        }
        (stdout, exit)
    })
    .await
    .expect("half-closed exec completed");
    assert_eq!(stdout, b"half-close");
    assert_eq!(exit, Some(0));
    drop(client);
    harness.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn injected_slow_reader_and_active_stream_shutdown_are_bounded() {
    let harness = DaemonHarness::spawn().await;
    let pid_file = harness.workspace_root().join("blocked.pid");
    let working_dir = harness.workspace_root().to_string_lossy().into_owned();
    let mut client = harness.client().await;
    let (input, rx) = mpsc::channel(4);
    input
        .send(v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "echo $$ > blocked.pid; exec yes blocked".into(),
                ],
                working_dir,
                ..Default::default()
            })),
        })
        .await
        .expect("send blocked exec start");
    let mut output = client
        .exec_session(ReceiverStream::new(rx))
        .await
        .expect("start blocked exec")
        .into_inner();
    let pid = wait_for_pid(&pid_file).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::time::timeout(Duration::from_secs(6), harness.shutdown())
        .await
        .expect("active injected stream shutdown is bounded");
    wait_for_process_exit(pid).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match output.message().await {
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return,
            }
        }
    })
    .await
    .expect("forced transport close terminates the response stream");
    tokio::time::timeout(
        Duration::from_secs(2),
        client.get_health(v1::GetHealthRequest {}),
    )
    .await
    .expect("closed transport rejects new RPC promptly")
    .expect_err("closed transport rejects new RPC");
    drop(output);
    drop(input);
    drop(client);
}

#[cfg(unix)]
#[tokio::test]
async fn injected_pty_transport_loss_terminates_remote_process() {
    let harness = DaemonHarness::spawn().await;
    let pid_file = harness.workspace_root().join("pty.pid");
    let working_dir = harness.workspace_root().to_string_lossy().into_owned();
    let mut client = harness.client().await;
    let (input, rx) = mpsc::channel(4);
    input
        .send(v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Start(v1::PtyStartRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "echo $$ > pty.pid; exec sleep 300".into(),
                ],
                working_dir,
                term: "xterm-256color".into(),
                width: 80,
                height: 24,
                ..Default::default()
            })),
        })
        .await
        .expect("send PTY start");
    let output = client
        .pty_session(ReceiverStream::new(rx))
        .await
        .expect("start PTY")
        .into_inner();
    let pid = wait_for_pid(&pid_file).await;
    drop(input);
    drop(output);
    drop(client);
    wait_for_process_exit(pid).await;
    harness.shutdown().await;
}

#[tokio::test]
async fn capability_negotiation_reports_typed_actionable_states() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;

    struct Case {
        name: &'static str,
        protocol_version: u32,
        required_capabilities: Vec<String>,
        want_state: v1::DaemonState,
        want_message: &'static str,
    }

    let cases = [
        Case {
            name: "discovery",
            protocol_version: 0,
            required_capabilities: Vec::new(),
            want_state: v1::DaemonState::Ready,
            want_message: "daemon ready",
        },
        Case {
            name: "supported",
            protocol_version: DAEMON_PROTOCOL_VERSION,
            required_capabilities: vec![
                DAEMON_CAPABILITY_EXEC.into(),
                DAEMON_CAPABILITY_SESSIONS.into(),
                DAEMON_CAPABILITY_ATTACH.into(),
            ],
            want_state: v1::DaemonState::Ready,
            want_message: "daemon ready",
        },
        Case {
            name: "missing capability",
            protocol_version: DAEMON_PROTOCOL_VERSION,
            required_capabilities: vec!["attach.v2".into(), "signals.v1".into()],
            want_state: v1::DaemonState::Unsupported,
            want_message: "daemon does not support required capabilities: attach.v2, signals.v1",
        },
        Case {
            name: "newer protocol",
            protocol_version: DAEMON_PROTOCOL_VERSION + 1,
            required_capabilities: Vec::new(),
            want_state: v1::DaemonState::UpgradeRequired,
            want_message: "daemon protocol 1 does not support requested protocol 2; upgrade the environment daemon",
        },
    ];

    for case in cases {
        let response = client
            .get_capabilities(v1::GetCapabilitiesRequest {
                protocol_version: case.protocol_version,
                required_capabilities: case.required_capabilities,
            })
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", case.name))
            .into_inner();
        assert_eq!(response.state, case.want_state as i32, "{}", case.name);
        assert_eq!(response.message, case.want_message, "{}", case.name);
        assert_eq!(response.protocol_version, DAEMON_PROTOCOL_VERSION);
        assert_eq!(
            response.capabilities,
            DAEMON_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>()
        );
        assert!(!response.daemon_version.is_empty(), "{}", case.name);
    }
}

#[tokio::test]
async fn health_conformance_distinguishes_starting_ready_and_unhealthy() {
    let cases = [
        (
            v1::DaemonState::Starting,
            "daemon startup is still reconciling",
        ),
        (v1::DaemonState::Ready, "daemon ready"),
        (
            v1::DaemonState::Unhealthy,
            "workspace filesystem is unavailable",
        ),
    ];

    for (state, message) in cases {
        let diagnostics = vec![v1::HealthDiagnostic {
            name: "workspace".into(),
            healthy: state == v1::DaemonState::Ready,
            message: message.into(),
        }];
        let harness = DaemonHarness::spawn_with_runtime_state(DaemonRuntimeState::new(
            state,
            message,
            diagnostics.clone(),
        ))
        .await;
        let mut client = harness.client().await;
        let response = client
            .get_health(v1::GetHealthRequest {})
            .await
            .expect("typed daemon health")
            .into_inner();
        assert_eq!(response.state, state as i32);
        assert_eq!(response.message, message);
        assert_eq!(response.diagnostics, diagnostics);

        let capabilities = client
            .get_capabilities(v1::GetCapabilitiesRequest {
                protocol_version: DAEMON_PROTOCOL_VERSION,
                required_capabilities: Vec::new(),
            })
            .await
            .expect("typed daemon capabilities")
            .into_inner();
        assert_eq!(capabilities.state, state as i32);
        assert_eq!(capabilities.message, message);
    }
}

#[tokio::test]
async fn injected_transport_preserves_exec_and_file_contracts() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;

    let request = iter([
        v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                command: vec!["sh".into(), "-c".into(), "printf conformance".into()],
                ..Default::default()
            })),
        },
        v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::CloseStdin(())),
        },
    ]);
    let mut stream = client
        .exec_session(request)
        .await
        .expect("exec through real listener")
        .into_inner();
    let mut stdout = Vec::new();
    let mut exit = None;
    while let Some(message) = stream.message().await.expect("exec output") {
        match message.payload {
            Some(v1::exec_message::Payload::Stdout(data)) => stdout.extend(data),
            Some(v1::exec_message::Payload::Exit(status)) => {
                exit = Some(status.code);
                break;
            }
            Some(v1::exec_message::Payload::Error(error)) => panic!("exec error: {error}"),
            _ => {}
        }
    }
    assert_eq!(stdout, b"conformance");
    assert_eq!(exit, Some(0));

    client
        .open_file(v1::OpenFileRequest {
            path: "conformance.txt".into(),
            options: Some(v1::FileOpenOptions {
                write: true,
                create: true,
                truncate: true,
                ..Default::default()
            }),
            perm: 0o600,
        })
        .await
        .expect("create file");
    client
        .write(v1::WriteRequest {
            path: "conformance.txt".into(),
            offset: 0,
            data: b"daemon".to_vec(),
        })
        .await
        .expect("write file");
    let read = client
        .read(v1::ReadRequest {
            path: "conformance.txt".into(),
            offset: 0,
            length: 6,
        })
        .await
        .expect("read file")
        .into_inner();
    assert_eq!(read.data, b"daemon");
}

#[test]
fn session_vocabulary_keeps_stable_identity_offsets_and_detach_status() {
    let session = v1::SessionRecord {
        session_id: "session-01JTEST".into(),
        state: v1::SessionLifecycleState::Running as i32,
        command: vec!["sh".into()],
        output_end_offset: 9,
        ..Default::default()
    };
    assert_eq!(session.session_id, "session-01JTEST");
    assert_eq!(session.output_end_offset, 9);

    let chunk = v1::SessionOutputChunk {
        offset: 4,
        next_offset: 9,
        stream: v1::SessionOutputStream::Pty as i32,
        data: b"bytes".to_vec(),
    };
    assert_eq!(chunk.next_offset, chunk.offset + chunk.data.len() as u64);

    let detach = v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest {
                session_id: session.session_id.clone(),
            },
        )),
    };
    assert!(matches!(
        detach.payload,
        Some(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest { session_id }
        )) if session_id == "session-01JTEST"
    ));

    let status = v1::SessionStatus {
        session_id: session.session_id,
        state: v1::SessionLifecycleState::Running as i32,
        output_end_offset: chunk.next_offset,
        ..Default::default()
    };
    assert_eq!(status.output_end_offset, 9);
    assert_eq!(status.state, v1::SessionLifecycleState::Running as i32);
}

#[tokio::test]
async fn durable_session_lifecycle_persists_output_and_restarts() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let launched = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec![
                "sh".into(),
                "-c".into(),
                "printf first; printf second >&2; exit 7".into(),
            ],
            ..Default::default()
        })
        .await
        .expect("launch durable session")
        .into_inner()
        .session
        .expect("launched session");
    assert_eq!(launched.state, v1::SessionLifecycleState::Running as i32);
    assert!(launched.session_id.starts_with("session-"));

    let exited = wait_for_session_state(
        &mut client,
        &launched.session_id,
        &[v1::SessionLifecycleState::Exited],
    )
    .await;
    assert_eq!(exited.exit_code, Some(7));
    assert_eq!(exited.output_end_offset, 11);
    assert!(exited.finished_at.is_some());

    let sessions = client
        .list_sessions(v1::ListSessionsRequest {})
        .await
        .expect("list durable sessions")
        .into_inner()
        .sessions;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, launched.session_id);

    assert_persisted_output(&harness, &launched.session_id, 11, b"first", b"second").await;

    let restarted = client
        .restart_session(v1::RestartSessionRequest {
            session_id: launched.session_id.clone(),
            expected_launch_generation: None,
        })
        .await
        .expect("restart durable session")
        .into_inner()
        .session
        .expect("restarted session");
    assert_eq!(restarted.session_id, launched.session_id);
    assert_eq!(restarted.state, v1::SessionLifecycleState::Running as i32);
    assert_eq!(restarted.output_end_offset, 11);

    let exited_again = wait_for_session_state(
        &mut client,
        &launched.session_id,
        &[v1::SessionLifecycleState::Exited],
    )
    .await;
    assert_eq!(exited_again.exit_code, Some(7));
    assert_eq!(exited_again.output_end_offset, 22);
    assert_persisted_output(
        &harness,
        &launched.session_id,
        22,
        b"firstfirst",
        b"secondsecond",
    )
    .await;
}

#[tokio::test]
async fn durable_session_survives_client_detach_until_explicit_stop() {
    let harness = DaemonHarness::spawn().await;
    let session_id = {
        let mut client = harness.client().await;
        client
            .launch_session(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "printf ready; exec sleep 30".into(),
                ],
                ..Default::default()
            })
            .await
            .expect("launch detached session")
            .into_inner()
            .session
            .expect("detached session")
            .session_id
    };

    let mut reattached_client = harness.client().await;
    let running = wait_for_output(&mut reattached_client, &session_id, 5).await;
    assert_eq!(running.state, v1::SessionLifecycleState::Running as i32);
    let stopped = reattached_client
        .stop_session(v1::StopSessionRequest {
            session_id: session_id.clone(),
        })
        .await
        .expect("stop detached session")
        .into_inner()
        .session
        .expect("stopped session");
    assert_eq!(stopped.state, v1::SessionLifecycleState::Stopped as i32);
    assert_eq!(stopped.exit_code, None);
    assert_eq!(stopped.output_end_offset, 5);
    assert_persisted_output(&harness, &session_id, 5, b"ready", b"").await;
}

#[tokio::test]
async fn output_reads_split_binary_frames_without_gaps_or_duplicates() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let session_id = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(), "printf '\\000\\377abc\\n'".into()],
            ..Default::default()
        })
        .await
        .expect("launch binary output session")
        .into_inner()
        .session
        .expect("binary output session")
        .session_id;
    let exited = wait_for_session_state(
        &mut client,
        &session_id,
        &[v1::SessionLifecycleState::Exited],
    )
    .await;
    assert_eq!(exited.output_end_offset, 6);

    let mut offset = 0;
    let mut output = Vec::new();
    let mut chunks = Vec::new();
    loop {
        let response = client
            .read_session_output(v1::ReadSessionOutputRequest {
                session_id: session_id.clone(),
                offset,
                limit: 2,
                allow_history_gap: false,
            })
            .await
            .expect("read binary output")
            .into_inner();
        for chunk in response.chunks {
            assert_eq!(chunk.offset, offset);
            assert_eq!(chunk.next_offset, chunk.offset + chunk.data.len() as u64);
            assert_eq!(chunk.stream, v1::SessionOutputStream::Stdout as i32);
            offset = chunk.next_offset;
            output.extend_from_slice(&chunk.data);
            chunks.push(chunk);
        }
        assert_eq!(response.next_offset, offset);
        if response.eof {
            break;
        }
    }
    assert!(
        chunks.len() >= 3,
        "two-byte reads must split the output frame"
    );
    assert_eq!(offset, 6);
    assert_eq!(output, [0, 0xff, b'a', b'b', b'c', b'\n']);

    let resumed = client
        .read_session_output(v1::ReadSessionOutputRequest {
            session_id: session_id.clone(),
            offset: 2,
            limit: 3,
            allow_history_gap: false,
        })
        .await
        .expect("resume from an interior frame offset")
        .into_inner();
    assert_eq!(resumed.next_offset, 5);
    assert!(!resumed.eof);
    assert_eq!(
        resumed
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.data)
            .collect::<Vec<_>>(),
        b"abc"
    );

    let error = client
        .read_session_output(v1::ReadSessionOutputRequest {
            session_id,
            offset: 7,
            limit: 1,
            allow_history_gap: false,
        })
        .await
        .expect_err("offset beyond durable output is rejected");
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn attach_forwards_input_and_resumes_after_detach_or_transport_loss() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let session_id = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec![
                "sh".into(),
                "-c".into(),
                "IFS= read -r line; printf 'got:%s' \"$line\"; exec sleep 30".into(),
            ],
            ..Default::default()
        })
        .await
        .expect("launch input session")
        .into_inner()
        .session
        .expect("input session")
        .session_id;

    let (request_tx, request_rx) = mpsc::channel(8);
    request_tx
        .send(attach_message(&session_id, 0))
        .await
        .expect("send attach start");
    let mut attached = client
        .attach_session(ReceiverStream::new(request_rx))
        .await
        .expect("attach to durable session")
        .into_inner();
    let initial = next_attach_status(&mut attached).await;
    assert_eq!(initial.state, v1::SessionLifecycleState::Running as i32);

    request_tx
        .send(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Input(
                v1::SessionInput {
                    data: b"hello\n".to_vec(),
                },
            )),
        })
        .await
        .expect("send attached input");
    let first_output = collect_attach_output(&mut attached, 9).await;
    assert_eq!(first_output, b"got:hello");

    request_tx
        .send(detach_message(&session_id))
        .await
        .expect("send detach");
    let detached =
        next_attach_status_with_message(&mut attached, "client detached; session remains running")
            .await;
    assert_eq!(detached.message, "client detached; session remains running");
    assert!(
        attached
            .message()
            .await
            .expect("detached stream end")
            .is_none(),
        "detach closes only the client stream"
    );
    assert_eq!(
        get_session(&mut client, &session_id).await.state,
        v1::SessionLifecycleState::Running as i32
    );

    let (resume_tx, resume_rx) = mpsc::channel(4);
    resume_tx
        .send(attach_message(&session_id, 4))
        .await
        .expect("send resume start");
    let mut resumed = client
        .attach_session(ReceiverStream::new(resume_rx))
        .await
        .expect("resume attached output")
        .into_inner();
    assert_eq!(collect_attach_output(&mut resumed, 5).await, b"hello");
    drop(resumed);
    drop(resume_tx);
    assert_eq!(
        get_session(&mut client, &session_id).await.state,
        v1::SessionLifecycleState::Running as i32
    );

    client
        .stop_session(v1::StopSessionRequest { session_id })
        .await
        .expect("stop session after transport loss");
}

#[tokio::test]
async fn silent_attachment_emits_periodic_status_heartbeat() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let session_id = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(), "exec sleep 30".into()],
            ..Default::default()
        })
        .await
        .expect("launch silent session")
        .into_inner()
        .session
        .expect("silent session")
        .session_id;

    let (request_tx, request_rx) = mpsc::channel(4);
    request_tx
        .send(attach_message(&session_id, 0))
        .await
        .expect("send attach start");
    let mut attached = client
        .attach_session(ReceiverStream::new(request_rx))
        .await
        .expect("attach to silent session")
        .into_inner();
    let initial = next_attach_status(&mut attached).await;
    let heartbeat = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let message = attached
                .message()
                .await
                .expect("heartbeat response")
                .expect("heartbeat response message");
            if let Some(v1::session_attach_message::Payload::Status(status)) = message.payload
                && status == initial
            {
                return status;
            }
        }
    })
    .await
    .expect("silent attachment heartbeat arrived");

    assert_eq!(heartbeat.state, v1::SessionLifecycleState::Running as i32);
    client
        .stop_session(v1::StopSessionRequest { session_id })
        .await
        .expect("stop silent session");
}

#[tokio::test]
async fn retained_history_gap_precedes_replay_and_resuming_keeps_the_same_live_shell() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let output_bytes = 8 * 1024 * 1024 + 1024;
    let tail = "retained-tail";
    let session_id = client.launch_session(v1::LaunchSessionRequest {
        command: vec!["sh".into(), "-c".into(), format!(
            "head -c {output_bytes} /dev/zero; printf '{tail}'; read line; printf 'same-shell:%s' \"$line\"; read next"
        )],
        ..Default::default()
    }).await.unwrap().into_inner().session.unwrap().session_id;
    let record = wait_for_output(&mut client, &session_id, output_bytes + tail.len() as u64).await;
    assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);
    assert!(record.output_start_offset > 0);
    assert_eq!(record.output_end_offset, output_bytes + tail.len() as u64);

    let denied = client
        .read_session_output(v1::ReadSessionOutputRequest {
            session_id: session_id.clone(),
            offset: 0,
            limit: 1,
            allow_history_gap: false,
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::FailedPrecondition);
    assert!(
        denied
            .message()
            .contains(&record.output_start_offset.to_string())
    );
    let replay = client
        .read_session_output(v1::ReadSessionOutputRequest {
            session_id: session_id.clone(),
            offset: 0,
            limit: 1,
            allow_history_gap: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(replay.history_gap);
    assert_eq!(replay.retained_start_offset, record.output_start_offset);
    assert_eq!(replay.chunks[0].offset, record.output_start_offset);

    let (tx, rx) = mpsc::channel(4);
    tx.send(attach_message(&session_id, 0)).await.unwrap();
    let mut attached = client
        .attach_session(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(5), attached.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Some(v1::session_attach_message::Payload::HistoryGap(gap)) = first.payload else {
        panic!("gap must precede replay");
    };
    assert_eq!(gap.requested_offset, 0);
    assert_eq!(gap.retained_start_offset, record.output_start_offset);
    let next = attached.message().await.unwrap().unwrap();
    let Some(v1::session_attach_message::Payload::Output(chunk)) = next.payload else {
        panic!("replay follows gap");
    };
    assert_eq!(chunk.offset, record.output_start_offset);
    drop(attached);
    drop(tx);
    assert_eq!(
        get_session(&mut client, &session_id).await.state,
        v1::SessionLifecycleState::Running as i32
    );

    let (tx, rx) = mpsc::channel(4);
    tx.send(attach_message(&session_id, record.output_end_offset))
        .await
        .unwrap();
    let mut resumed = client
        .attach_session(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let initial = resumed.message().await.unwrap().unwrap();
    assert!(matches!(
        initial.payload,
        Some(v1::session_attach_message::Payload::Status(_))
    ));
    tx.send(v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Input(
            v1::SessionInput {
                data: b"okay\n".to_vec(),
            },
        )),
    })
    .await
    .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = resumed.message().await.unwrap().unwrap();
            match message.payload {
                Some(v1::session_attach_message::Payload::HistoryGap(_)) => {
                    panic!("retained cursor must not emit a gap")
                }
                Some(v1::session_attach_message::Payload::Output(chunk)) => break chunk,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(message.offset, record.output_end_offset);
    assert_eq!(message.data, b"same-shell:okay");
    client
        .stop_session(v1::StopSessionRequest { session_id })
        .await
        .unwrap();
}

#[tokio::test]
async fn pty_resize_is_applied_before_status_and_detach_preserves_session() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;
    let session_id = client
        .launch_session(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(), "exec sleep 30".into()],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        })
        .await
        .expect("launch durable PTY session")
        .into_inner()
        .session
        .expect("durable PTY session")
        .session_id;

    let (request_tx, request_rx) = mpsc::channel(8);
    request_tx
        .send(attach_message(&session_id, 0))
        .await
        .expect("send PTY attach");
    let mut attached = client
        .attach_session(ReceiverStream::new(request_rx))
        .await
        .expect("attach PTY")
        .into_inner();
    let initial = next_attach_status(&mut attached).await;
    assert_eq!(initial.message, "session running");

    request_tx
        .send(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Resize(
                v1::ResizeRequest {
                    width: 132,
                    height: 43,
                },
            )),
        })
        .await
        .expect("send PTY resize");
    let resized = next_attach_status(&mut attached).await;
    assert_eq!(resized.message, "session resized to 132x43");
    let record = get_session(&mut client, &session_id).await;
    assert!(record.pty);
    assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);

    request_tx
        .send(detach_message(&session_id))
        .await
        .expect("detach PTY client");
    let detached = next_attach_status(&mut attached).await;
    assert_eq!(detached.message, "client detached; session remains running");
    assert_eq!(
        get_session(&mut client, &session_id).await.state,
        v1::SessionLifecycleState::Running as i32
    );
    let stopped = client
        .stop_session(v1::StopSessionRequest {
            session_id: session_id.clone(),
        })
        .await
        .expect("stop detached PTY")
        .into_inner()
        .session
        .expect("stopped detached PTY");
    assert_eq!(stopped.state, v1::SessionLifecycleState::Stopped as i32);
    let restarted = client
        .restart_session(v1::RestartSessionRequest {
            session_id: session_id.clone(),
            expected_launch_generation: None,
        })
        .await
        .expect("restart durable PTY")
        .into_inner()
        .session
        .expect("restarted durable PTY");
    assert!(restarted.pty);
    assert_eq!(restarted.state, v1::SessionLifecycleState::Running as i32);
    client
        .stop_session(v1::StopSessionRequest { session_id })
        .await
        .expect("stop restarted PTY");
}

#[tokio::test]
async fn injected_transport_file_operations_enforce_offsets_and_workspace_boundaries() {
    let harness = DaemonHarness::spawn().await;
    let mut client = harness.client().await;

    client
        .mkdir(v1::MkdirRequest {
            path: "boundary".into(),
            perm: 0o700,
        })
        .await
        .expect("create boundary directory");
    client
        .open_file(v1::OpenFileRequest {
            path: "boundary/data.bin".into(),
            options: Some(v1::FileOpenOptions {
                write: true,
                create: true,
                exclusive: true,
                ..Default::default()
            }),
            perm: 0o600,
        })
        .await
        .expect("create boundary file");
    client
        .write(v1::WriteRequest {
            path: "boundary/data.bin".into(),
            offset: 0,
            data: vec![0, 0xff, 1, 2],
        })
        .await
        .expect("write binary file");
    let read = client
        .read(v1::ReadRequest {
            path: "boundary/data.bin".into(),
            offset: 1,
            length: 2,
        })
        .await
        .expect("read binary file boundary")
        .into_inner();
    assert_eq!(read.data, [0xff, 1]);

    for request in [
        v1::ReadRequest {
            path: "boundary/data.bin".into(),
            offset: -1,
            length: 1,
        },
        v1::ReadRequest {
            path: "boundary/data.bin".into(),
            offset: 0,
            length: -1,
        },
        v1::ReadRequest {
            path: "../../etc/passwd".into(),
            offset: 0,
            length: 1,
        },
    ] {
        let error = client
            .read(request)
            .await
            .expect_err("invalid file boundary rejected");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    client
        .rename(v1::RenameRequest {
            old_path: "boundary/data.bin".into(),
            new_path: "boundary/renamed.bin".into(),
        })
        .await
        .expect("rename boundary file");
    client
        .set_stat(v1::SetStatRequest {
            path: "boundary/renamed.bin".into(),
            size: Some(2),
            mode: Some(0o640),
            ..Default::default()
        })
        .await
        .expect("set boundary file stat");
    let stat = client
        .stat(v1::StatRequest {
            path: "boundary/renamed.bin".into(),
            follow: false,
        })
        .await
        .expect("stat boundary file")
        .into_inner()
        .entry
        .expect("boundary file metadata");
    assert_eq!(stat.size, 2);
    assert_eq!(stat.mode & 0o777, 0o640);
    client
        .remove(v1::RemoveRequest {
            path: "boundary/renamed.bin".into(),
            dir: false,
        })
        .await
        .expect("remove boundary file");
}

#[tokio::test]
async fn daemon_restart_marks_unrecoverable_live_session_interrupted() {
    let temp = tempfile::tempdir().expect("persistent daemon roots");
    let workspace_root = temp.path().join("workspace");
    let home_root = temp.path().join("home");
    let first = DaemonHarness::spawn_at(workspace_root.clone(), home_root.clone()).await;
    let mut first_client = first.client().await;
    let session_id = first_client
        .launch_session(v1::LaunchSessionRequest {
            command: vec![
                "sh".into(),
                "-c".into(),
                "printf booted; exec sleep 30".into(),
            ],
            ..Default::default()
        })
        .await
        .expect("launch session before daemon restart")
        .into_inner()
        .session
        .expect("session before daemon restart")
        .session_id;
    let running = wait_for_output(&mut first_client, &session_id, 6).await;
    assert_eq!(running.state, v1::SessionLifecycleState::Running as i32);

    let completed_id = first_client
        .launch_session(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(), "printf retained; exit 9".into()],
            ..Default::default()
        })
        .await
        .expect("launch completed session before daemon restart")
        .into_inner()
        .session
        .expect("completed session before daemon restart")
        .session_id;
    let completed = wait_for_session_state(
        &mut first_client,
        &completed_id,
        &[v1::SessionLifecycleState::Exited],
    )
    .await;
    assert_eq!(completed.exit_code, Some(9));
    assert_eq!(completed.output_end_offset, 8);

    drop(first_client);
    first.shutdown().await;

    let second = DaemonHarness::spawn_at(workspace_root, home_root).await;
    let mut second_client = second.client().await;
    let recovered = second_client
        .get_session(v1::GetSessionRequest {
            session_id: session_id.clone(),
        })
        .await
        .expect("recover session after daemon restart")
        .into_inner()
        .session
        .expect("recovered session");
    assert_eq!(
        recovered.state,
        v1::SessionLifecycleState::Interrupted as i32
    );
    assert_eq!(recovered.exit_code, None);
    assert_eq!(recovered.output_end_offset, 6);
    assert!(recovered.finished_at.is_some());
    assert_eq!(
        recovered.status_message,
        "session interrupted because the environment daemon restarted"
    );
    assert_persisted_output(&second, &session_id, 6, b"booted", b"").await;
    let recovered_output = second_client
        .read_session_output(v1::ReadSessionOutputRequest {
            session_id: session_id.clone(),
            offset: 0,
            limit: 0,
            allow_history_gap: false,
        })
        .await
        .expect("read indexed output after daemon restart")
        .into_inner();
    assert!(recovered_output.eof);
    assert_eq!(recovered_output.next_offset, 6);
    assert_eq!(
        recovered_output
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.data)
            .collect::<Vec<_>>(),
        b"booted"
    );

    let retained = second_client
        .get_session(v1::GetSessionRequest {
            session_id: completed_id.clone(),
        })
        .await
        .expect("recover completed session after daemon restart")
        .into_inner()
        .session
        .expect("retained completed session");
    assert_eq!(retained.state, v1::SessionLifecycleState::Exited as i32);
    assert_eq!(retained.exit_code, Some(9));
    assert_eq!(retained.output_end_offset, 8);
    assert!(retained.finished_at.is_some());
    assert_persisted_output(&second, &completed_id, 8, b"retained", b"").await;
}

async fn wait_for_session_state(
    client: &mut HarnessClient,
    session_id: &str,
    states: &[v1::SessionLifecycleState],
) -> v1::SessionRecord {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let session = get_session(client, session_id).await;
            let state = v1::SessionLifecycleState::try_from(session.state)
                .expect("known session lifecycle state");
            if states.contains(&state) {
                return session;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session reached expected state")
}

async fn wait_for_output(
    client: &mut HarnessClient,
    session_id: &str,
    minimum_offset: u64,
) -> v1::SessionRecord {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let session = get_session(client, session_id).await;
            if session.output_end_offset >= minimum_offset {
                return session;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session persisted expected output")
}

async fn get_session(client: &mut HarnessClient, session_id: &str) -> v1::SessionRecord {
    client
        .get_session(v1::GetSessionRequest {
            session_id: session_id.into(),
        })
        .await
        .expect("get durable session")
        .into_inner()
        .session
        .expect("durable session record")
}

fn attach_message(session_id: &str, output_offset: u64) -> v1::SessionAttachMessage {
    v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Attach(
            v1::AttachSessionRequest {
                session_id: session_id.into(),
                output_offset,
            },
        )),
    }
}

fn detach_message(session_id: &str) -> v1::SessionAttachMessage {
    v1::SessionAttachMessage {
        payload: Some(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest {
                session_id: session_id.into(),
            },
        )),
    }
}

#[cfg(unix)]
async fn wait_for_pid(path: &std::path::Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(raw) = std::fs::read_to_string(path)
                && let Ok(pid) = raw.trim().parse()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process pid was not written to {}", path.display()))
}

#[cfg(unix)]
async fn wait_for_process_exit(pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let running = tokio::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .expect("inspect remote process")
                .success();
            if !running {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("remote process {pid} survived transport loss"));
}

async fn next_attach_status(
    stream: &mut tonic::Streaming<v1::SessionAttachMessage>,
) -> v1::SessionStatus {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = stream
                .message()
                .await
                .expect("attach response")
                .expect("attach response message");
            if let Some(v1::session_attach_message::Payload::Status(status)) = message.payload {
                return status;
            }
        }
    })
    .await
    .expect("attach status arrived")
}

async fn next_attach_status_with_message(
    stream: &mut tonic::Streaming<v1::SessionAttachMessage>,
    expected: &str,
) -> v1::SessionStatus {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = next_attach_status(stream).await;
            if status.message == expected {
                return status;
            }
        }
    })
    .await
    .expect("attach status with expected message arrived")
}

async fn collect_attach_output(
    stream: &mut tonic::Streaming<v1::SessionAttachMessage>,
    length: usize,
) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut output = Vec::new();
        while output.len() < length {
            let message = stream
                .message()
                .await
                .expect("attach response")
                .expect("attach output message");
            if let Some(v1::session_attach_message::Payload::Output(chunk)) = message.payload {
                output.extend(chunk.data);
            }
        }
        output
    })
    .await
    .expect("attached output arrived")
}

async fn assert_persisted_output(
    harness: &DaemonHarness,
    session_id: &str,
    expected_end_offset: u64,
    expected_stdout: &[u8],
    expected_stderr: &[u8],
) {
    let frames = harness.persisted_output(session_id).await;
    let mut next_offset = 0;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for frame in frames {
        assert_eq!(frame.offset, next_offset);
        next_offset += frame.data.len() as u64;
        match frame.stream {
            v1::SessionOutputStream::Stdout => stdout.extend(frame.data),
            v1::SessionOutputStream::Stderr => stderr.extend(frame.data),
            stream => panic!("unexpected persisted output stream: {stream:?}"),
        }
    }
    assert_eq!(next_offset, expected_end_offset);
    assert_eq!(stdout, expected_stdout);
    assert_eq!(stderr, expected_stderr);
}
