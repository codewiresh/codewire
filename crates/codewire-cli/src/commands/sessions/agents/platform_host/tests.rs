use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REQUEST: &str = "6a162b2b-a758-4c8c-bccb-794502c82f09";
fn request() -> rpc::MutateEnvironmentAgentRequest {
    rpc::MutateEnvironmentAgentRequest {
        org_id: "org".into(),
        environment_id: "env".into(),
        request_id: REQUEST.into(),
        expected_scope: Some(rpc::EnvironmentAgentScope {
            incarnation: Some(
                codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation {
                    org_id: "org".into(),
                    environment_id: "env".into(),
                    pod_uid: "original-pod".into(),
                    binding_generation: u64::MAX,
                    ..Default::default()
                },
            )
            .into(),
            support_image_sha256: vec![7; 32],
            support_image_size: 123,
            ..Default::default()
        })
        .into(),
        operation: Some(rpc::mutate_environment_agent_request::Operation::Launch(
            Box::new(rpc::EnvironmentAgentLaunch {
                agent: rpc::EnvironmentAgentKind::Codex.into(),
                prompt: Some("PRIVATE_PROMPT_CANARY".into()),
                ..Default::default()
            }),
        )),
        ..Default::default()
    }
}

#[test]
fn saved_original_request_survives_reader_restart_without_prompt_values() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    let request = request();
    save_request_at(&directory, &request).unwrap();
    let path = directory.join(format!("{REQUEST}.json"));
    let raw = fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("PRIVATE_PROMPT_CANARY"));
    let saved: RequestReference = read_record(&path).unwrap();
    assert_eq!(saved.request_id, REQUEST);
    assert_eq!(saved.scope, *request.expected_scope.as_option().unwrap());
    assert_eq!(
        saved.request_sha256,
        format!("{:x}", sha2::Sha256::digest(request.encode_to_vec()))
    );
    assert_eq!(saved.session_id, format!("session-{REQUEST}"));
    save_request_at(&directory, &request).unwrap();
    assert_eq!(fs::read(&path).unwrap(), raw);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn changed_payload_scope_or_cleanup_lineage_cannot_replace_original_uuid() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    let mut original = request();
    original.operation = Some(rpc::mutate_environment_agent_request::Operation::Control(
        Box::new(rpc::EnvironmentAgentControl {
            action: rpc::EnvironmentAgentAction::Stop.into(),
            session_id: "session-original".into(),
            driver_id: REQUEST.into(),
            expected_launch_generation: 2,
            cleanup_of_request_id: Some("6d370dab-3d67-4d76-93c3-3bd31581fbe9".into()),
            ..Default::default()
        }),
    ));
    save_request_at(&directory, &original).unwrap();
    let path = directory.join(format!("{REQUEST}.json"));
    let raw = fs::read(&path).unwrap();
    for kind in 0..3 {
        let mut changed = original.clone();
        if kind == 0 {
            changed.environment_id = "replacement".into();
        }
        if let Some(rpc::mutate_environment_agent_request::Operation::Control(control)) =
            &mut changed.operation
        {
            if kind == 1 {
                control.expected_launch_generation = 3;
            }
            if kind == 2 {
                control.cleanup_of_request_id = Some(REQUEST.into());
            }
        }
        assert!(save_request_at(&directory, &changed).is_err());
        assert_eq!(fs::read(&path).unwrap(), raw);
    }
}

#[test]
fn contended_request_reference_and_oversized_payload_refuse_before_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("requests");
    private_directory(&directory).unwrap();
    let lock = StateLock::try_acquire(&directory.join(format!("{REQUEST}.lock")))
        .unwrap()
        .unwrap();
    assert!(save_request_at(&directory, &request()).is_err());
    assert!(!directory.join(format!("{REQUEST}.json")).exists());
    drop(lock);
    let mut large = request();
    if let Some(rpc::mutate_environment_agent_request::Operation::Launch(launch)) =
        &mut large.operation
    {
        launch.prompt = Some("x".repeat(256 * 1024));
    }
    assert!(save_request_at(&directory, &large).is_err());
    assert!(!directory.join(format!("{REQUEST}.json")).exists());
}

#[test]
fn a_stopped_conversation_names_how_to_continue_it_and_is_recognised_on_every_client() {
    // #2705: a conversation of an earlier Pod stopped with its environment;
    // a new message or a restart continues it, never a new conversation.
    assert_eq!(
        stopped_with_environment("env", "reviewer"),
        "managed conversation \"reviewer\" stopped with its environment; \
         `cw msg env reviewer TEXT` or `cw restart env reviewer` continues it here"
    );
    // The driver runs in the Sandbox, which is always Linux, so the client's
    // own OS never decides whether a listed session is a managed one.
    let driver = |second: &str| {
        vec![
            "/codewire/bin/cw".to_owned(),
            second.to_owned(),
            "--environment".to_owned(),
            "env".to_owned(),
            "--driver-id".to_owned(),
            REQUEST.to_owned(),
        ]
    };
    assert!(is_platform_driver(&driver("__platform-agent-driver")));
    assert!(!is_platform_driver(&driver("__agent-driver")));
    assert!(!is_platform_driver(&["sh".to_owned()]));
    assert!(!is_platform_driver(&[]));
}

#[test]
fn platform_refusals_are_definite_only_with_their_exact_reason() {
    // #2782: a refusal at admission names its reason; nothing else is
    // treated as definite, so a lost answer stays an uncertain outcome.
    use codewire_proto::google::rpc::ErrorInfo;
    use connectrpc::{ConnectError, ErrorDetail};
    let reasoned = |error: ConnectError, reason: &str| {
        codewire_client::ClientError::from(error.with_detail(ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &ErrorInfo {
                reason: reason.into(),
                domain: "codewire.sh".into(),
                ..Default::default()
            },
        )))
    };
    let blocked = reasoned(
        ConnectError::failed_precondition("message x is still in progress; try again shortly"),
        "PLATFORM_AGENT_REQUEST_REFUSED",
    );
    assert!(request_refused(&blocked));
    assert!(!resume_refused(&blocked));
    let resume = reasoned(
        ConnectError::failed_precondition("the previous Pod is still stopping"),
        "PLATFORM_AGENT_RESUME_REFUSED",
    );
    assert!(resume_refused(&resume));
    assert!(!request_refused(&resume));
    // The right reason under another code, a plain conflict, or no reason at
    // all stay uncertain.
    for error in [
        reasoned(
            ConnectError::unavailable("transport"),
            "PLATFORM_AGENT_REQUEST_REFUSED",
        ),
        codewire_client::ClientError::from(ConnectError::already_exists(
            "platform managed request requires observation or original-generation cleanup",
        )),
        codewire_client::ClientError::new(
            codewire_client::ErrorCode::FailedPrecondition,
            "no reason",
        ),
    ] {
        assert!(!request_refused(&error), "{error:?}");
        assert!(!resume_refused(&error), "{error:?}");
    }
}

const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
const MESSAGE: &str = "dff2f8e1-1788-454e-94a9-f4dc6d4b057e";
const INFO: &str = "/codewire.v1.EnvironmentAgentService/GetEnvironmentAgentInfo";
const LIST: &str = "/codewire.v1.EnvironmentAgentService/ListEnvironmentAgents";
const READ: &str = "/codewire.v1.EnvironmentAgentService/ReadEnvironmentAgent";
const SESSIONS: &str = "/codewire.v1.EnvironmentSessionService/ListSessions";
const EARLIER_POD: &str = "earlier-pod";
const CURRENT_POD: &str = "current-pod";

fn session_id() -> String {
    format!("session-{REQUEST}")
}

fn scope_in(pod: &str) -> rpc::EnvironmentAgentScope {
    rpc::EnvironmentAgentScope {
        incarnation: Some(
            codewire_client::cw_runtime::EnvironmentCwRuntimeIncarnation {
                org_id: "org".into(),
                environment_id: ENVIRONMENT.into(),
                pod_uid: pod.into(),
                binding_generation: 1,
                ..Default::default()
            },
        )
        .into(),
        support_image_sha256: vec![7; 32],
        support_image_size: 123,
        ..Default::default()
    }
}

fn pod_of(scope: &rpc::EnvironmentAgentScope) -> String {
    scope.incarnation.as_option().unwrap().pod_uid.clone()
}

/// A message sent at generation 1 in the environment's earlier Pod.
fn earlier_message() -> MessageLocation {
    MessageLocation {
        version: 1,
        org_id: "org".into(),
        environment_id: ENVIRONMENT.into(),
        scope: scope_in(EARLIER_POD),
        session_id: session_id(),
        driver_id: REQUEST.into(),
        launch_generation: 1,
        message_id: MESSAGE.into(),
    }
}

fn synthetic_client(server: &MockServer) -> codewire_client::CodewireClient {
    let platform = crate::config::ResolvedPlatformConfig::static_token(
        server.uri(),
        "synthetic-managed-wait-token",
        true,
        None,
    );
    codewire_client(&platform).unwrap()
}

fn proto(message: &impl buffa::Message) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/proto")
        .set_body_bytes(message.encode_to_vec())
}

fn refusal(status: u16, code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(serde_json::json!({"code": code, "message": message}))
}

/// The completed record of the message from before Stop/Start, at its own
/// generation, as the current Pod returns it for `request`.
fn completed_record(request: &rpc::ReadEnvironmentAgentRequest) -> ResponseTemplate {
    let record = serde_json::to_vec(&serde_json::json!({"record": {
        "version": 1, "id": MESSAGE, "driver_id": REQUEST, "target_session_id": session_id(),
        "action": "message", "text": "Return the synthetic reply before Stop/Start.",
        "reply_to": null, "expected_turn_id": null, "expected_active_message_id": null,
        "turn_id": "01a13b2c-1835-78d0-aa41-b04a38440f08", "state": "completed",
        "created_at": "2026-10-14T19:41:23Z", "updated_at": "2026-10-14T19:41:25Z",
        "accepted_at": "2026-10-14T19:41:24Z", "started_at": "2026-10-14T19:41:24Z",
        "finished_at": "2026-10-14T19:41:25Z", "native_acknowledged": true,
        "platform_launch_generation": 1, "result": "CWOPENAI broker [REDACTED]",
        "result_truncated": false, "error": null, "usage": null, "source": null,
        "notification": null}}))
    .unwrap();
    proto(&rpc::ReadEnvironmentAgentResponse {
        scope: request.expected_scope.clone(),
        session_id: request.session_id.clone(),
        driver_id: request.driver_id.clone(),
        launch_generation: request.expected_launch_generation,
        kind: request.kind,
        message_id: request.message_id.clone(),
        record_sha256: sha2::Sha256::digest(&record).to_vec(),
        record_json: record,
        ..Default::default()
    })
}

/// The environment now runs `CURRENT_POD`. Orchestration lists the
/// conversation there at `generation`, or not at all; the earlier Pod's
/// scope is refused, and a read in the current scope answers with `current`.
async fn platform(
    listed: Option<u64>,
    current: impl Fn(&rpc::ReadEnvironmentAgentRequest) -> ResponseTemplate + Send + Sync + 'static,
) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(INFO))
        .respond_with(proto(&rpc::GetEnvironmentAgentInfoResponse {
            scope: Some(scope_in(CURRENT_POD)).into(),
            ..Default::default()
        }))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(LIST))
        .respond_with(move |request: &wiremock::Request| {
            let request =
                rpc::ListEnvironmentAgentsRequest::decode_from_slice(&request.body).unwrap();
            assert_eq!(
                pod_of(request.expected_scope.as_option().unwrap()),
                CURRENT_POD
            );
            proto(&rpc::ListEnvironmentAgentsResponse {
                scope: request.expected_scope.clone(),
                sessions: listed
                    .map(|generation| codewire_client::EnvironmentSession {
                        session_id: session_id(),
                        launch_generation: generation,
                        ..Default::default()
                    })
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(READ))
        .respond_with(move |request: &wiremock::Request| {
            let request =
                rpc::ReadEnvironmentAgentRequest::decode_from_slice(&request.body).unwrap();
            if pod_of(request.expected_scope.as_option().unwrap()) == CURRENT_POD {
                current(&request)
            } else {
                refusal(400, "failed_precondition", "platform managed scope changed")
            }
        })
        .mount(&server)
        .await;
    server
}

/// Every message read, as (Pod, generation), in order.
async fn reads(server: &MockServer) -> Vec<(String, u64)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == READ)
        .map(|request| {
            let read = rpc::ReadEnvironmentAgentRequest::decode_from_slice(&request.body).unwrap();
            assert_eq!(
                (read.session_id.as_str(), read.message_id.as_str()),
                (session_id().as_str(), MESSAGE)
            );
            (
                pod_of(read.expected_scope.as_option().unwrap()),
                read.expected_launch_generation,
            )
        })
        .collect()
}

async fn wait_for(server: &MockServer) -> anyhow::Result<MessageRecord> {
    await_location(
        &earlier_message(),
        &synthetic_client(server),
        Duration::from_secs(5),
        |record| record.state.is_terminal(),
    )
    .await
}

#[tokio::test]
async fn a_message_from_before_stop_start_is_read_where_its_conversation_resumed() {
    // Orchestration lists the conversation in the current Pod at generation
    // 2: it resumed there, which holds the message at its own generation.
    let server = platform(Some(2), completed_record).await;
    let record = wait_for(&server).await.unwrap();
    assert_eq!(record.id, MESSAGE);
    assert_eq!(record.state, MessageState::Completed);
    assert_eq!(record.platform_launch_generation, Some(1));
    assert_eq!(
        reads(&server).await,
        [(EARLIER_POD.to_owned(), 1), (CURRENT_POD.to_owned(), 1)]
    );
}

#[tokio::test]
async fn a_conversation_not_resumed_says_it_stopped_and_how_to_continue_it() {
    // Not listed in the current Pod: nothing is read there, and neither
    // `wait` nor `find` tells anyone to start a new conversation.
    let server = platform(None, |_| panic!("the current scope must not be read")).await;
    let error = wait_for(&server).await.unwrap_err().to_string();
    assert_eq!(
        error,
        format!(
            "managed message {MESSAGE} was sent before its environment stopped; \
             managed conversation \"{session}\" stopped with its environment; \
             `cw msg {ENVIRONMENT} {session} TEXT` or `cw restart {ENVIRONMENT} {session}` \
             continues it here",
            session = session_id()
        )
    );
    assert_eq!(reads(&server).await, [(EARLIER_POD.to_owned(), 1)]);

    Mock::given(method("POST"))
        .and(path(SESSIONS))
        .respond_with(proto(&codewire_client::ListSessionsResponse {
            sessions: vec![codewire_client::EnvironmentSession {
                session_id: session_id(),
                name: "reviewer".into(),
                command: vec!["/codewire/bin/cw".into(), "__platform-agent-driver".into()],
                launch_generation: 1,
                ..Default::default()
            }],
            ..Default::default()
        }))
        .mount(&server)
        .await;
    let endpoint = Endpoint {
        org_id: "org".into(),
        environment_id: ENVIRONMENT.into(),
        client: synthetic_client(&server),
        scope: scope_in(CURRENT_POD),
    };
    let error = endpoint.find("reviewer").await.unwrap_err().to_string();
    assert_eq!(error, stopped_with_environment(ENVIRONMENT, "reviewer"));
    assert!(!error.contains("start a new"), "{error}");
}

#[tokio::test]
async fn a_failed_read_where_the_conversation_resumed_shows_its_own_error() {
    // The conversation resumed, but the read in the current scope fails for
    // another reason: that error is shown, read once, and no wording about
    // the Stop replaces it.
    let server = platform(Some(2), |_| {
        refusal(403, "permission_denied", "synthetic current-scope refusal")
    })
    .await;
    let error = wait_for(&server).await.unwrap_err().to_string();
    assert_eq!(error, "synthetic current-scope refusal");
    assert_eq!(
        reads(&server).await,
        [(EARLIER_POD.to_owned(), 1), (CURRENT_POD.to_owned(), 1)]
    );
}
