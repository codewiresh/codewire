use std::collections::BTreeSet;

use base64::Engine as _;
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    EnvironmentSession, EnvironmentSessionServiceClient, EnvironmentSessionState,
    GetSessionRequest, LaunchSessionRequest, ListSessionsRequest, RestartSessionRequest,
    StopSessionRequest,
};
use connectrpc::client::HttpClient;
use connectrpc::{CodecFormat, ErrorCode, Protocol};

use super::{Auth, Harness, PRIMARY_ORG, assert_rpc_bad_request, assert_rpc_error};

const BACKEND_ENV: &str = "env_exec_contract_backend";
const STOPPED_ENV: &str = "env_environment_contract_start_binary";
const STARTING_ENV: &str = "env_environment_contract_state_starting";
const VIEWER_ENV: &str = "env_port_contract_viewer";
const MISSING_ENV: &str = "env_exec_contract_missing";
const MISSING_ORG: &str = "org_exec_contract_missing";
const PRIVATE_ENV_NAME: &str = "CODEWIRE_SESSION_CONTRACT_PRIVATE_VALUE";
const PRIVATE_ENV_VALUE: &str = "synthetic-session-env-not-public-2099";

pub(super) async fn run(harness: &Harness) {
    assert_session_gates(harness).await;
    assert_launch_validation(harness).await;
    assert_session_lifecycle(harness).await;
}

fn client(
    harness: &Harness,
    auth: Auth,
    codec: CodecFormat,
    protocol: Protocol,
) -> EnvironmentSessionServiceClient<HttpClient> {
    // Native gRPC requires HTTP/2. The production HTTPS client negotiates h2
    // with ALPN; this cleartext contract harness must request h2c explicitly
    // so trailing status details are transported rather than degrading onto
    // an HTTP/1 connection. Connect cases retain the ordinary auto client.
    let transport = if protocol == Protocol::Grpc {
        HttpClient::plaintext_http2_only()
    } else {
        HttpClient::plaintext()
    };
    EnvironmentSessionServiceClient::new(
        transport,
        harness.client_config(auth, codec).with_protocol(protocol),
    )
}

async fn assert_session_gates(harness: &Harness) {
    for (protocol, codec) in [
        (Protocol::Connect, CodecFormat::Proto),
        (Protocol::Connect, CodecFormat::Json),
        (Protocol::Grpc, CodecFormat::Proto),
    ] {
        let inventory_client = client(harness, Auth::Admin, codec, protocol);
        for (auth, org_id, environment_id, code, message) in [
            (
                Auth::None,
                PRIMARY_ORG,
                BACKEND_ENV,
                ErrorCode::Unauthenticated,
                "unauthorized",
            ),
            (
                Auth::Admin,
                MISSING_ORG,
                BACKEND_ENV,
                ErrorCode::NotFound,
                "organization not found",
            ),
            (
                Auth::Admin,
                PRIMARY_ORG,
                MISSING_ENV,
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::User,
                PRIMARY_ORG,
                VIEWER_ENV,
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::Admin,
                PRIMARY_ORG,
                STOPPED_ENV,
                ErrorCode::FailedPrecondition,
                "environment must be running",
            ),
            // Coming back, as after its runtime is replaced (#4311): clients
            // wait out Unavailable and reattach.
            (
                Auth::Admin,
                PRIMARY_ORG,
                STARTING_ENV,
                ErrorCode::Unavailable,
                "environment is starting",
            ),
        ] {
            let before = session_inventory(harness, &inventory_client).await;
            let error = client(harness, auth, codec, protocol)
                .list_sessions(ListSessionsRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("EnvironmentSessionService gate must fail");
            assert_rpc_error(&error, code, message);
            let before_launch = session_inventory(harness, &inventory_client).await;
            assert_eq!(before_launch, before, "rejected List creates no session");

            let error = client(harness, auth, codec, protocol)
                .launch_session(LaunchSessionRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    command: vec!["/bin/sh".into(), "-c".into(), "exec sleep 60".into()],
                    ..Default::default()
                })
                .await
                .expect_err("well-formed LaunchSession must preserve the target gate");
            assert_rpc_error(&error, code, message);
            assert_eq!(
                session_inventory(harness, &inventory_client).await,
                before_launch,
                "rejected Launch creates no session"
            );
        }
    }
}

async fn assert_launch_validation(harness: &Harness) {
    for (protocol, codec) in [
        (Protocol::Connect, CodecFormat::Proto),
        (Protocol::Connect, CodecFormat::Json),
        (Protocol::Grpc, CodecFormat::Proto),
    ] {
        let client = client(harness, Auth::Admin, codec, protocol);
        let before = session_inventory(harness, &client).await;
        let error = client
            .launch_session(LaunchSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            })
            .await
            .expect_err("empty durable-session launch command must fail");
        assert_rpc_error(&error, ErrorCode::InvalidArgument, "validation failed");
        assert_rpc_bad_request(&error, &["command"]);
        // The private daemon defaults an empty command to a shell. A forwarded
        // invalid launch would therefore leave a session record, not merely a
        // second validation error. This proves no created session; exact RPC
        // dispatch counts belong to the injected core mutation fixture.
        assert_eq!(session_inventory(harness, &client).await, before);
    }
}

async fn assert_session_lifecycle(harness: &Harness) {
    for (protocol, codec) in [
        (Protocol::Connect, CodecFormat::Proto),
        (Protocol::Connect, CodecFormat::Json),
        (Protocol::Grpc, CodecFormat::Proto),
    ] {
        let client = client(harness, Auth::Admin, codec, protocol);
        let before = session_inventory(harness, &client).await;
        // Keep the process running through Get/List/Stop while bounding its
        // lifetime even if a later assertion aborts the fixture. No provider
        // credentials are involved: the env value is a synthetic DTO canary.
        let command = vec!["/bin/sh".into(), "-c".into(), "exec sleep 60".into()];
        let launched = client
            .launch_session(LaunchSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                command: command.clone(),
                env: [(PRIVATE_ENV_NAME.into(), PRIVATE_ENV_VALUE.into())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .await
            .expect("durable session LaunchSession round trip")
            .into_owned()
            .session
            .into_option()
            .expect("launch acknowledgement contains a session");
        assert_public_session(harness, &launched);
        assert_eq!(
            launched.state.as_known(),
            Some(EnvironmentSessionState::Running)
        );
        assert_eq!(launched.command, command);
        assert!(!launched.pty);
        assert!(launched.created_at.is_set());
        assert!(launched.started_at.is_set());
        assert!(launched.finished_at.is_unset());
        assert!(launched.exit_code.is_none());
        let session_id = launched.session_id.clone();
        assert!(!session_id.is_empty());
        let mut expected = before.clone();
        assert!(
            expected.insert(session_id.clone()),
            "launch assigns a new ID"
        );
        assert_eq!(session_inventory(harness, &client).await, expected);

        let fetched = client
            .get_session(GetSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                session_id: session_id.clone(),
                ..Default::default()
            })
            .await
            .expect("durable session GetSession round trip")
            .into_owned()
            .session
            .into_option()
            .expect("get acknowledgement contains a session");
        assert_public_session(harness, &fetched);
        assert_eq!(
            fetched, launched,
            "Get returns the authoritative launch record"
        );

        let stopped = stop_session(harness, &client, &session_id).await;
        assert_eq!(stopped.command, command);
        assert_eq!(stopped.created_at, launched.created_at);

        let restarted = client
            .restart_session(RestartSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                session_id: session_id.clone(),
                ..Default::default()
            })
            .await
            .expect("durable session RestartSession round trip")
            .into_owned()
            .session
            .into_option()
            .expect("restart acknowledgement contains a session");
        assert_public_session(harness, &restarted);
        assert_eq!(restarted.session_id, session_id, "restart retains identity");
        assert_eq!(
            restarted.state.as_known(),
            Some(EnvironmentSessionState::Running)
        );
        assert_eq!(restarted.command, command);
        assert_eq!(restarted.created_at, launched.created_at);
        assert!(restarted.started_at.is_set());
        assert!(restarted.finished_at.is_unset());
        assert!(restarted.exit_code.is_none());
        assert_eq!(session_inventory(harness, &client).await, expected);

        stop_session(harness, &client, &session_id).await;
        assert_eq!(session_inventory(harness, &client).await, expected);
        let final_record = client
            .get_session(GetSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                session_id,
                ..Default::default()
            })
            .await
            .expect("stopped durable session remains discoverable")
            .into_owned()
            .session
            .into_option()
            .expect("stopped session record");
        assert_public_session(harness, &final_record);
        assert_eq!(
            final_record.state.as_known(),
            Some(EnvironmentSessionState::Stopped)
        );
    }
}

async fn session_inventory(
    harness: &Harness,
    client: &EnvironmentSessionServiceClient<HttpClient>,
) -> BTreeSet<String> {
    let response = client
        .list_sessions(ListSessionsRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: BACKEND_ENV.into(),
            ..Default::default()
        })
        .await
        .expect("durable session ListSessions round trip")
        .into_owned();
    let mut ids = BTreeSet::new();
    for session in response.sessions {
        assert_public_session(harness, &session);
        assert!(!session.session_id.is_empty());
        assert!(
            ids.insert(session.session_id),
            "list contains no duplicate IDs"
        );
    }
    ids
}

async fn stop_session(
    harness: &Harness,
    client: &EnvironmentSessionServiceClient<HttpClient>,
    session_id: &str,
) -> EnvironmentSession {
    let stopped = match client
        .stop_session(StopSessionRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: BACKEND_ENV.into(),
            session_id: session_id.into(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response
            .into_owned()
            .session
            .into_option()
            .expect("stop acknowledgement contains a session"),
        // A daemon in its own PID namespace, as in production, answers a stop
        // inside its deadline. Where the runner cannot give it one, the
        // daemon scans this runner's whole process table, which can outlast
        // the 5 s stop deadline under load (#4237). The API's answer to an
        // unknown outcome is to refresh, so the test refreshes, under the
        // 30 s hang guard (docs/dev/AGENT-WORKFLOW.md).
        Err(error)
            if daemon_shares_the_runners_pids()
                && error.code == ErrorCode::FailedPrecondition
                && error
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains("outcome is unknown")) =>
        {
            stopped_within_hang_guard(client, session_id).await
        }
        Err(error) => panic!("durable session StopSession round trip: {error:?}"),
    };
    assert_public_session(harness, &stopped);
    assert_eq!(stopped.session_id, session_id);
    assert_eq!(
        stopped.state.as_known(),
        Some(EnvironmentSessionState::Stopped)
    );
    assert!(stopped.finished_at.is_set());
    stopped
}

/// Whether the CI script could not give the daemon its own PID namespace
/// (`ORCHESTRATION_DAEMON_PID_NAMESPACE`, set by
/// `scripts/ci/verify/run-integration-verification.sh`).
fn daemon_shares_the_runners_pids() -> bool {
    std::env::var("ORCHESTRATION_DAEMON_PID_NAMESPACE").as_deref() != Ok("own")
}

/// The session once its stop has finished, refreshed until then.
async fn stopped_within_hang_guard(
    client: &EnvironmentSessionServiceClient<HttpClient>,
    session_id: &str,
) -> EnvironmentSession {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let session = client
                .get_session(GetSessionRequest {
                    org_id: PRIMARY_ORG.into(),
                    environment_id: BACKEND_ENV.into(),
                    session_id: session_id.into(),
                    ..Default::default()
                })
                .await
                .expect("durable session GetSession round trip")
                .into_owned()
                .session
                .into_option()
                .expect("get acknowledgement contains a session");
            if session.state.as_known() != Some(EnvironmentSessionState::Running) {
                return session;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the stop finished within the 30 s hang guard")
}

fn assert_public_session(harness: &Harness, session: &EnvironmentSession) {
    let json = serde_json::to_value(session).expect("serialize public session record");
    let fields = json.as_object().expect("public session is an object");
    for field in fields.keys() {
        assert!(
            [
                "sessionId",
                "state",
                "command",
                "workingDir",
                "pty",
                "createdAt",
                "startedAt",
                "finishedAt",
                "exitCode",
                "outputEndOffset",
                "statusMessage",
                "launchGeneration",
            ]
            .contains(&field.as_str()),
            "unexpected public session field {field}"
        );
    }
    // The fixed public claims prefix detects a disclosed daemon bearer without
    // obtaining the signing secret or reconstructing a private credential.
    let daemon_claims = format!(r#"{{"environment_id":"{BACKEND_ENV}","scope":"daemon"}}"#);
    let daemon_token_prefix = format!(
        "{}.",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(daemon_claims)
    );
    // Check the actual decoded record in both encodings, including unknown
    // protobuf fields retained by the generated message. Environment values
    // and the synthetic caller credentials must not enter the public record.
    for bytes in [session.encode_to_vec(), json.to_string().into_bytes()] {
        for private in [
            PRIVATE_ENV_NAME,
            PRIVATE_ENV_VALUE,
            harness.admin_token.as_str(),
            harness.user_token.as_str(),
            harness.global_admin_token.as_str(),
            daemon_token_prefix.as_str(),
        ] {
            assert!(
                !private.is_empty()
                    && !bytes
                        .windows(private.len())
                        .any(|window| window == private.as_bytes()),
                "public session record contains private fixture material"
            );
        }
    }
}
