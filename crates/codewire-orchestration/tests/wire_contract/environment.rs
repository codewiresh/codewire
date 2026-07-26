use codewire_proto::codewire::v1::{
    AccessPermission, CancelEnvironmentDeletionRequest, CreateEnvironmentRequest,
    DeleteEnvironmentRequest, EnvironmentServiceClient, EnvironmentState,
    ExtendEnvironmentTtlRequest, GetEnvironmentDaemonStatusRequest, GetEnvironmentRequest,
    GetEnvironmentTrustReportRequest, GrantEnvironmentAccessRequest, ListEnvironmentAccessRequest,
    ListEnvironmentsRequest, ProtectEnvironmentRequest, RepairEnvironmentDaemonRequest,
    RevokeEnvironmentAccessRequest, StartEnvironmentRequest, StartOutcome, StopEnvironmentRequest,
    StreamEnvironmentDaemonLogsRequest, StreamEnvironmentDaemonLogsResponse, StreamLogsRequest,
    StreamLogsResponse, UnprotectEnvironmentRequest, WatchEnvironmentCreateRequest,
    WatchEnvironmentCreateResponse, stream_logs_response, watch_environment_create_response,
};
use connectrpc::{CodecFormat, ErrorCode};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, array, assert_bad_request, assert_connect_error,
    assert_error_info, assert_rpc_error, rpc_error_info_reason,
};

const SERVICE: &str = "codewire.v1.EnvironmentService";
const READ_ENV: &str = "env_environment_contract_read";
const LOG_ONE: &str = "log_environment_contract_01";
const LOG_TWO: &str = "log_environment_contract_02";

pub(super) async fn run(harness: &Harness) {
    assert_state_and_polling_wire_table(harness).await;
    assert_errors_pagination_and_prerequisites(harness).await;
    assert_unary_rpcs_both_codecs(harness).await;
    assert_daemon_proxy_gates_both_codecs(harness).await;
    assert_create_progress_both_codecs(harness).await;
    assert_logs_both_codecs(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn assert_state_and_polling_wire_table(harness: &Harness) {
    for (state, wire_state, desired, poll) in [
        (
            "pending",
            "ENVIRONMENT_STATE_PENDING",
            "DESIRED_STATE_STARTED",
            Some("5s"),
        ),
        (
            "pending_build",
            "ENVIRONMENT_STATE_PENDING_BUILD",
            "DESIRED_STATE_STOPPED",
            None,
        ),
        (
            "building",
            "ENVIRONMENT_STATE_BUILDING",
            "DESIRED_STATE_DESTROYED",
            None,
        ),
        (
            "build_failed",
            "ENVIRONMENT_STATE_BUILD_FAILED",
            "DESIRED_STATE_ARCHIVED",
            None,
        ),
        (
            "pulling_snapshot",
            "ENVIRONMENT_STATE_PULLING_SNAPSHOT",
            "DESIRED_STATE_RESIZED",
            None,
        ),
        (
            "creating",
            "ENVIRONMENT_STATE_CREATING",
            "DESIRED_STATE_STARTED",
            Some("3s"),
        ),
        (
            "starting",
            "ENVIRONMENT_STATE_STARTING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "running",
            "ENVIRONMENT_STATE_RUNNING",
            "DESIRED_STATE_STARTED",
            Some("2s"),
        ),
        (
            "stopping",
            "ENVIRONMENT_STATE_STOPPING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "stopped",
            "ENVIRONMENT_STATE_STOPPED",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "archiving",
            "ENVIRONMENT_STATE_ARCHIVING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "archived",
            "ENVIRONMENT_STATE_ARCHIVED",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "restoring",
            "ENVIRONMENT_STATE_RESTORING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "resizing",
            "ENVIRONMENT_STATE_RESIZING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "destroying",
            "ENVIRONMENT_STATE_DESTROYING",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "destroyed",
            "ENVIRONMENT_STATE_DESTROYED",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "error",
            "ENVIRONMENT_STATE_ERROR",
            "DESIRED_STATE_STARTED",
            None,
        ),
        (
            "unknown",
            "ENVIRONMENT_STATE_UNKNOWN",
            "DESIRED_STATE_STARTED",
            None,
        ),
    ] {
        let response = call(
            harness,
            "GetEnvironment",
            json!({"orgId": PRIMARY_ORG, "environmentId": format!("env_environment_contract_state_{state}")}),
            Auth::Admin,
        )
        .await;
        response.assert_status(StatusCode::OK, "GetEnvironment state table");
        let body = response.json();
        assert_eq!(body["environment"]["state"], wire_state, "state={state}");
        assert_eq!(
            body["environment"]["desiredState"], desired,
            "state={state}"
        );
        match poll {
            Some(interval) => assert_eq!(body["pollInterval"], interval, "state={state}"),
            None => assert!(body.get("pollInterval").is_none(), "state={state}: {body}"),
        }
    }
    let complete = call(
        harness,
        "GetEnvironment",
        json!({"orgId": PRIMARY_ORG, "environmentId": "env_environment_contract_state_running_complete"}),
        Auth::Admin,
    )
    .await;
    complete.assert_status(StatusCode::OK, "running setup-complete state");
    assert!(complete.json().get("pollInterval").is_none());
}

async fn assert_errors_pagination_and_prerequisites(harness: &Harness) {
    let ttl = call(
        harness,
        "ExtendEnvironmentTtl",
        json!({"orgId": PRIMARY_ORG, "environmentId": READ_ENV, "additionalSeconds": 59}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(&ttl, StatusCode::BAD_REQUEST, "invalid_argument", "");
    assert_bad_request(&body, &["additional_seconds"]);

    let denied = call(
        harness,
        "StopEnvironment",
        json!({"orgId": PRIMARY_ORG, "environmentId": "env_port_contract_viewer"}),
        Auth::User,
    )
    .await;
    let body = assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    assert_error_info(&denied, &body, "ACCESS_DENIED");

    let invalid_state = call(
        harness,
        "StopEnvironment",
        json!({"orgId": PRIMARY_ORG, "environmentId": "env_environment_contract_invalid_state"}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &invalid_state,
        StatusCode::BAD_REQUEST,
        "failed_precondition",
        "",
    );
    assert_error_info(&invalid_state, &body, "INVALID_STATE");

    let quota = call(
        harness,
        "CreateEnvironment",
        json!({"orgId": SECONDARY_ORG, "presetId": "preset_contract_official", "name": "environment-contract-quota-rejected"}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &quota,
        StatusCode::TOO_MANY_REQUESTS,
        "resource_exhausted",
        "",
    );
    assert_error_info(&quota, &body, "QUOTA_EXCEEDED");

    for (method, body) in [
        (
            "ListEnvironments",
            json!({"orgId": PRIMARY_ORG, "pageToken": "future-page"}),
        ),
        (
            "ListEnvironmentAccess",
            json!({"orgId": PRIMARY_ORG, "environmentId": "env_environment_contract_access_binary", "pageToken": "future-page"}),
        ),
    ] {
        let response = call(harness, method, body, Auth::Admin).await;
        assert_connect_error(&response, StatusCode::BAD_REQUEST, "invalid_argument", "");
    }

    for (org, environment) in [
        ("org_prereq_attacker", "env_prereq_foreign_creator"),
        ("org_prereq_attacker", "env_prereq_foreign_role"),
        (PRIMARY_ORG, "env_prereq_foreign_grant"),
    ] {
        let response = harness
            .rest(
                Method::GET,
                &format!("/api/v1/organizations/{org}/environments/{environment}/access"),
                None,
                Auth::User,
            )
            .await;
        response.assert_status(StatusCode::FORBIDDEN, "foreign environment access");
        let body = response.json();
        assert_eq!(body["code"], "access_denied");
        assert_eq!(
            body["detail"],
            "only environment owners can view access grants"
        );
    }
    harness
        .rest(
            Method::GET,
            &format!(
                "/api/v1/organizations/{SECONDARY_ORG}/environments/env_prereq_foreign_role/access"
            ),
            None,
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "actual organization environment access");

    let foreign_member = "orgm_apikey_contract_admin_2";
    let hidden = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/members/{foreign_member}/assignments"),
            None,
            Auth::User,
        )
        .await;
    hidden.assert_status(StatusCode::NOT_FOUND, "foreign member assignments");
    assert_eq!(hidden.json()["detail"], "member not found");
    let visible = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{SECONDARY_ORG}/members/{foreign_member}/assignments"),
            None,
            Auth::Admin,
        )
        .await;
    visible.assert_status(StatusCode::OK, "actual member assignments");
    assert_eq!(visible.json(), json!(["billing_admin"]));
}

async fn assert_unary_rpcs_both_codecs(harness: &Harness) {
    for (codec, suffix) in [(CodecFormat::Proto, "binary"), (CodecFormat::Json, "json")] {
        let client = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let listed = client
            .list_environments(ListEnvironmentsRequest {
                org_id: PRIMARY_ORG.into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .expect("ListEnvironments codec round trip")
            .into_owned();
        assert!(!listed.environments.is_empty());
        assert!(listed.next_page_token.is_empty());
        assert_eq!(listed.poll_interval.as_option().unwrap().seconds, 2);

        let got = client
            .get_environment(GetEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("GetEnvironment codec round trip")
            .into_owned();
        let environment = got.environment.as_option().expect("environment");
        assert_eq!(environment.id, READ_ENV);
        assert_eq!(environment.state, EnvironmentState::Running);
        assert_eq!(got.poll_interval.as_option().unwrap().seconds, 2);
        let rest = harness
            .rest(
                Method::GET,
                &format!("/api/v1/organizations/{PRIMARY_ORG}/environments/{READ_ENV}"),
                None,
                Auth::Admin,
            )
            .await;
        rest.assert_status(StatusCode::OK, "REST environment parity");
        let rest = rest.json();
        assert_eq!(rest["id"], environment.id);
        assert_eq!(rest["state"], "running");
        assert_eq!(rest["desired_state"], "started");

        let terminal_id = format!("env_environment_contract_start_{suffix}");
        let terminal = client
            .get_environment(GetEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: terminal_id.clone(),
                ..Default::default()
            })
            .await
            .expect("terminal GetEnvironment")
            .into_owned();
        assert_eq!(
            terminal.environment.as_option().unwrap().state,
            EnvironmentState::Stopped
        );
        assert!(terminal.poll_interval.as_option().is_none());

        let created = client
            .create_environment(CreateEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                preset_id: Some("preset_contract_official".into()),
                name: Some(format!("environment-contract-created-{suffix}")),
                ..Default::default()
            })
            .await
            .expect("CreateEnvironment")
            .into_owned();
        let created = created
            .environment
            .as_option()
            .expect("created environment");
        assert!(!created.id.is_empty());
        assert_eq!(created.org_id, PRIMARY_ORG);
        client
            .delete_environment(DeleteEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: created.id.clone(),
                ..Default::default()
            })
            .await
            .expect("DeleteEnvironment");

        let stopped = client
            .stop_environment(StopEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: format!("env_environment_contract_stop_{suffix}"),
                ..Default::default()
            })
            .await
            .expect("StopEnvironment")
            .into_owned();
        assert_eq!(stopped.status, "stop requested");

        let started = client
            .start_environment(StartEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: terminal_id,
                ..Default::default()
            })
            .await
            .expect("StartEnvironment")
            .into_owned();
        assert_eq!(started.status, "start requested");
        assert_eq!(started.outcome, StartOutcome::Started);
        let retried = client
            .start_environment(StartEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: format!("env_environment_contract_retry_{suffix}"),
                ..Default::default()
            })
            .await
            .expect("retry StartEnvironment")
            .into_owned();
        assert_eq!(retried.status, "retry requested");
        assert_eq!(retried.outcome, StartOutcome::Retried);

        let protect_id = format!("env_environment_contract_protect_{suffix}");
        let protected = client
            .protect_environment(ProtectEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: protect_id.clone(),
                ..Default::default()
            })
            .await
            .expect("ProtectEnvironment")
            .into_owned();
        assert_eq!(protected.status, "protected");
        let unprotected = client
            .unprotect_environment(UnprotectEnvironmentRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: protect_id,
                ..Default::default()
            })
            .await
            .expect("UnprotectEnvironment")
            .into_owned();
        assert_eq!(unprotected.status, "unprotected");

        let cancelled = client
            .cancel_environment_deletion(CancelEnvironmentDeletionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: format!("env_environment_contract_cancel_{suffix}"),
                ..Default::default()
            })
            .await
            .expect("CancelEnvironmentDeletion")
            .into_owned();
        assert_eq!(cancelled.status, "deletion_cancelled");
        let extended = client
            .extend_environment_ttl(ExtendEnvironmentTtlRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: format!("env_environment_contract_ttl_{suffix}"),
                additional_seconds: 60,
                ..Default::default()
            })
            .await
            .expect("ExtendEnvironmentTtl")
            .into_owned();
        assert_eq!(extended.status, "ttl_extended");

        let trust = client
            .get_environment_trust_report(GetEnvironmentTrustReportRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("GetEnvironmentTrustReport")
            .into_owned();
        let trust = trust.trust_report.as_option().expect("trust report");
        assert_eq!(trust.environment.as_option().unwrap().id, READ_ENV);
        assert!(!trust.summary.as_option().unwrap().trust_level.is_empty());

        let access_id = format!("env_environment_contract_access_{suffix}");
        let granted = client
            .grant_environment_access(GrantEnvironmentAccessRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: access_id.clone(),
                user_id: "usr_apikey_contract_user".into(),
                permission: AccessPermission::Viewer.into(),
                ..Default::default()
            })
            .await
            .expect("GrantEnvironmentAccess")
            .into_owned();
        let grant = granted.access_grant.as_option().expect("access grant");
        assert_eq!(grant.user_id, "usr_apikey_contract_user");
        assert!(grant.created_at.as_option().is_some());
        let access = client
            .list_environment_access(ListEnvironmentAccessRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: access_id.clone(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .expect("ListEnvironmentAccess")
            .into_owned();
        assert_eq!(access.access_grants.len(), 1);
        assert!(access.next_page_token.is_empty());
        client
            .revoke_environment_access(RevokeEnvironmentAccessRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: access_id,
                user_id: "usr_apikey_contract_user".into(),
                ..Default::default()
            })
            .await
            .expect("RevokeEnvironmentAccess");
    }
}

async fn assert_daemon_proxy_gates_both_codecs(harness: &Harness) {
    const VIEWER_ENV: &str = "env_port_contract_viewer";

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let unauthenticated = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::None, codec),
        )
        .get_environment_daemon_status(GetEnvironmentDaemonStatusRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: READ_ENV.into(),
            ..Default::default()
        })
        .await
        .expect_err("unauthenticated daemon status must fail");
        assert_rpc_error(&unauthenticated, ErrorCode::Unauthenticated, "unauthorized");

        let denied = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::User, codec),
        )
        .get_environment_daemon_status(GetEnvironmentDaemonStatusRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: VIEWER_ENV.into(),
            ..Default::default()
        })
        .await
        .expect_err("viewer daemon status must fail");
        assert_rpc_error(&denied, ErrorCode::PermissionDenied, "access denied");

        let client = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let unavailable = client
            .get_environment_daemon_status(GetEnvironmentDaemonStatusRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect_err("daemon status without a backend must fail");
        assert_rpc_error(
            &unavailable,
            ErrorCode::Unavailable,
            "sandbox backend not found",
        );

        let repair = client
            .repair_environment_daemon(RepairEnvironmentDaemonRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect_err("daemon repair without a backend must fail");
        assert_rpc_error(&repair, ErrorCode::Unavailable, "sandbox backend not found");

        let mut logs = client
            .stream_environment_daemon_logs(StreamEnvironmentDaemonLogsRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("open unavailable daemon log stream");
        let logs = logs
            .message::<StreamEnvironmentDaemonLogsResponse>()
            .await
            .expect_err("daemon logs without a backend must fail");
        assert_rpc_error(&logs, ErrorCode::Unavailable, "sandbox backend not found");
    }
}

async fn assert_create_progress_both_codecs(harness: &Harness) {
    for (codec, suffix) in [(CodecFormat::Proto, "binary"), (CodecFormat::Json, "json")] {
        let client = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let repo_url = format!("https://example.test/codewire/prepare-{suffix}");
        let mut stream = client
            .watch_environment_create(WatchEnvironmentCreateRequest {
                org_id: PRIMARY_ORG.into(),
                draft: Some(CreateEnvironmentRequest {
                    org_id: PRIMARY_ORG.into(),
                    repo_url: repo_url.clone(),
                    ..Default::default()
                })
                .into(),
                analyze: Some(false),
                ..Default::default()
            })
            .await
            .expect("open WatchEnvironmentCreate");
        assert_eq!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        let mut events = Vec::new();
        while let Some(message) = stream
            .message::<WatchEnvironmentCreateResponse>()
            .await
            .expect("WatchEnvironmentCreate message")
        {
            match &message.view().event {
                Some(watch_environment_create_response::EventView::Progress(progress)) => {
                    events.push(progress.phase.to_owned());
                }
                Some(watch_environment_create_response::EventView::Complete(complete)) => {
                    events.push("complete".into());
                    let draft = complete.draft.as_option().expect("complete draft");
                    assert_eq!(draft.org_id, PRIMARY_ORG);
                    assert_eq!(draft.repo_url, repo_url);
                }
                event => panic!("unexpected create progress event: {event:?}"),
            }
        }
        assert_eq!(events, ["repo_config", "resolving", "complete"]);

        let mut bad = client
            .watch_environment_create(WatchEnvironmentCreateRequest {
                org_id: PRIMARY_ORG.into(),
                draft: Some(CreateEnvironmentRequest {
                    org_id: PRIMARY_ORG.into(),
                    repo_url: "not-a-repository-url".into(),
                    ..Default::default()
                })
                .into(),
                analyze: Some(true),
                ..Default::default()
            })
            .await
            .expect("open invalid WatchEnvironmentCreate");
        let error = loop {
            match bad.message::<WatchEnvironmentCreateResponse>().await {
                Ok(Some(_)) => {}
                Ok(None) => panic!("invalid repository URL stream ended without an error"),
                Err(error) => break error,
            }
        };
        assert_rpc_error(&error, ErrorCode::InvalidArgument, "");
        assert_eq!(
            rpc_error_info_reason(&error).as_deref(),
            Some("INVALID_REPO_URL")
        );
    }
}

async fn assert_logs_both_codecs(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let mut stream = client
            .stream_logs(StreamLogsRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("open StreamLogs");
        assert_eq!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        let mut logs = Vec::new();
        while let Some(message) = stream
            .message::<StreamLogsResponse>()
            .await
            .expect("StreamLogs message")
        {
            match message.to_owned_message().event {
                Some(stream_logs_response::Event::Log(log)) => logs.push(*log),
                Some(stream_logs_response::Event::Heartbeat(_)) => {
                    panic!("bounded StreamLogs emitted a heartbeat")
                }
                None => panic!("bounded StreamLogs emitted an empty event"),
            }
        }
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].id, LOG_ONE);
        assert_eq!(logs[1].id, LOG_TWO);
        assert_eq!(
            logs[0].created_at.as_option(),
            logs[1].created_at.as_option()
        );

        let mut resumed = client
            .stream_logs(StreamLogsRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: READ_ENV.into(),
                after_log_id: LOG_ONE.into(),
                ..Default::default()
            })
            .await
            .expect("resume StreamLogs");
        let mut resumed_ids = Vec::new();
        while let Some(message) = resumed
            .message::<StreamLogsResponse>()
            .await
            .expect("resumed StreamLogs message")
        {
            if let Some(stream_logs_response::Event::Log(log)) = message.to_owned_message().event {
                resumed_ids.push(log.id.clone());
            }
        }
        assert_eq!(resumed_ids, [LOG_TWO]);

        let rest = harness
            .rest(
                Method::GET,
                &format!("/api/v1/organizations/{PRIMARY_ORG}/environments/{READ_ENV}/logs"),
                None,
                Auth::Admin,
            )
            .await;
        rest.assert_status(StatusCode::OK, "REST environment logs");
        let rest = rest.json();
        let rest = array(&rest, "REST environment logs");
        assert_eq!(rest.len(), logs.len());
        for (rest, connected) in rest.iter().zip(&logs) {
            assert_eq!(rest["id"], connected.id);
            assert_eq!(rest["environment_id"], connected.environment_id);
            assert_eq!(rest["phase"], connected.phase);
            assert_eq!(rest["status"], connected.status);
            assert_eq!(rest["message"], connected.message);
        }

        let user_client = EnvironmentServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::User, codec),
        );
        let mut hidden = user_client
            .stream_logs(StreamLogsRequest {
                org_id: SECONDARY_ORG.into(),
                environment_id: READ_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("open hidden StreamLogs");
        let error = hidden
            .message::<StreamLogsResponse>()
            .await
            .expect_err("nonmember StreamLogs must fail");
        assert_rpc_error(&error, ErrorCode::NotFound, "");
        assert_eq!(
            rpc_error_info_reason(&error).as_deref(),
            Some("ORG_NOT_FOUND")
        );
    }

    let hidden = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{SECONDARY_ORG}/environments/{READ_ENV}/logs"),
            None,
            Auth::User,
        )
        .await;
    hidden.assert_status(StatusCode::NOT_FOUND, "hidden REST logs");
    assert_eq!(
        String::from_utf8_lossy(&hidden.body),
        "{\"error\":\"organization not found\"}\n"
    );
}
