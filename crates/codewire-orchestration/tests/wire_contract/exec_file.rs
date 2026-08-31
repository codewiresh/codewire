use buffa_types::google::protobuf::Duration;
use codewire_proto::codewire::v1::{
    DownloadFileRequest, DownloadFileResponse, ExecRequest, ExecServiceClient, FileServiceClient,
    ListFilesRequest, StreamExecRequest, StreamExecResponse, UploadFileRequest,
    stream_exec_response, upload_file_request,
};
use connectrpc::client::HttpClient;
use connectrpc::{CodecFormat, ConnectError, ErrorCode};
use reqwest::StatusCode;
use serde_json::json;

use super::{
    Auth, Harness, KubeMode, PRIMARY_ORG, assert_bad_request, assert_connect_error,
    assert_error_info, assert_retry_info, assert_rpc_bad_request, assert_rpc_error, has_detail,
    rpc_has_retry_info,
};

const EXEC_SERVICE: &str = "codewire.v1.ExecService";
const BACKEND_ENV: &str = "env_exec_contract_backend";
const UNAVAILABLE_ENV: &str = "env_exec_contract_unavailable";
const STOPPED_ENV: &str = "env_environment_contract_start_binary";
const NO_BACKEND_ENV: &str = "env_environment_contract_read";
const VIEWER_ENV: &str = "env_port_contract_viewer";
const MISSING_ENV: &str = "env_exec_contract_missing";
const MISSING_ORG: &str = "org_exec_contract_missing";

pub(super) async fn run(harness: &Harness) {
    assert_exec_happy_paths(harness).await;
    assert_exec_gates(harness).await;
    assert_file_gates_and_protocol(harness).await;
    assert_canonical_exec_details(harness).await;
    assert_runtime_boundaries(harness).await;
}

fn exec_request(org_id: &str, environment_id: &str, command: &[&str]) -> ExecRequest {
    ExecRequest {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        command: command.iter().map(|value| (*value).into()).collect(),
        ..Default::default()
    }
}

fn stream_request(org_id: &str, environment_id: &str, command: &[&str]) -> StreamExecRequest {
    StreamExecRequest {
        org_id: org_id.into(),
        environment_id: environment_id.into(),
        command: command.iter().map(|value| (*value).into()).collect(),
        ..Default::default()
    }
}

fn exec_client(harness: &Harness, auth: Auth, codec: CodecFormat) -> ExecServiceClient<HttpClient> {
    ExecServiceClient::new(HttpClient::plaintext(), harness.client_config(auth, codec))
}

fn file_client(harness: &Harness, auth: Auth, codec: CodecFormat) -> FileServiceClient<HttpClient> {
    FileServiceClient::new(HttpClient::plaintext(), harness.client_config(auth, codec))
}

async fn stream_exec_error(
    client: &ExecServiceClient<HttpClient>,
    request: StreamExecRequest,
) -> ConnectError {
    match client.stream_exec(request).await {
        Err(error) => error,
        Ok(mut stream) => loop {
            match stream.message::<StreamExecResponse>().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("StreamExec completed successfully, expected an error"),
                Err(error) => break error,
            }
        },
    }
}

async fn download_error(
    client: &FileServiceClient<HttpClient>,
    request: DownloadFileRequest,
) -> ConnectError {
    match client.download_file(request).await {
        Err(error) => error,
        Ok(mut stream) => loop {
            match stream.message::<DownloadFileResponse>().await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("DownloadFile completed successfully, expected an error"),
                Err(error) => break error,
            }
        },
    }
}

async fn assert_exec_happy_paths(harness: &Harness) {
    assert_eq!(harness.kube_mode, KubeMode::Configured);
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = exec_client(harness, Auth::Admin, codec);
        let response = client
            .exec(exec_request(
                PRIMARY_ORG,
                BACKEND_ENV,
                &["codewire-contract-exec-happy"],
            ))
            .await
            .expect("Exec happy path")
            .into_owned();
        assert_eq!(response.exit_code, 17);
        assert_eq!(response.stdout, b"stdout-one\nstdout-two\n");
        assert_eq!(response.stderr, b"stderr-one\n");

        let mut stream = client
            .stream_exec(stream_request(
                PRIMARY_ORG,
                BACKEND_ENV,
                &["codewire-contract-exec-happy"],
            ))
            .await
            .expect("StreamExec happy path");
        assert_eq!(
            stream
                .headers()
                .get("x-accel-buffering")
                .and_then(|v| v.to_str().ok()),
            Some("no")
        );
        let mut events = Vec::new();
        while let Some(message) = stream
            .message::<StreamExecResponse>()
            .await
            .expect("StreamExec happy message")
        {
            events.push(message.to_owned_message().event.expect("exec event"));
        }
        assert!(!events.is_empty());
        assert!(matches!(
            events.last(),
            Some(stream_exec_response::Event::ExitCode(17))
        ));
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        for event in &events[..events.len() - 1] {
            match event {
                stream_exec_response::Event::Stdout(value) => stdout.extend(value),
                stream_exec_response::Event::Stderr(value) => stderr.extend(value),
                stream_exec_response::Event::ExitCode(code) => {
                    panic!("exit event {code} arrived before stream output completed")
                }
            }
        }
        assert_eq!(stdout, b"stdout-one\nstdout-two\n");
        assert_eq!(stderr, b"stderr-one\n");
    }
}

async fn assert_exec_gates(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        for (auth, request, code, message) in [
            (
                Auth::None,
                exec_request(PRIMARY_ORG, BACKEND_ENV, &["true"]),
                ErrorCode::Unauthenticated,
                "unauthorized",
            ),
            (
                Auth::Admin,
                exec_request(MISSING_ORG, BACKEND_ENV, &["true"]),
                ErrorCode::NotFound,
                "organization not found",
            ),
            (
                Auth::Admin,
                exec_request(PRIMARY_ORG, MISSING_ENV, &["true"]),
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::User,
                exec_request(PRIMARY_ORG, VIEWER_ENV, &["true"]),
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::Admin,
                exec_request(PRIMARY_ORG, STOPPED_ENV, &["true"]),
                ErrorCode::FailedPrecondition,
                "environment must be running",
            ),
            (
                Auth::Admin,
                exec_request(PRIMARY_ORG, NO_BACKEND_ENV, &["true"]),
                ErrorCode::Unavailable,
                "sandbox backend not found",
            ),
            (
                Auth::Admin,
                exec_request(PRIMARY_ORG, BACKEND_ENV, &[]),
                ErrorCode::InvalidArgument,
                "validation failed",
            ),
        ] {
            let client = exec_client(harness, auth, codec);
            let error = client.exec(request).await.expect_err("Exec gate must fail");
            assert_rpc_error(&error, code, message);
        }
        let client = exec_client(harness, Auth::Admin, codec);
        let mut negative_duration = exec_request(PRIMARY_ORG, BACKEND_ENV, &["true"]);
        negative_duration.timeout = Some(Duration {
            seconds: -1,
            ..Default::default()
        })
        .into();
        assert_rpc_error(
            &client
                .exec(negative_duration)
                .await
                .expect_err("negative Exec timeout must fail"),
            ErrorCode::InvalidArgument,
            "",
        );

        for (auth, request, code, message) in [
            (
                Auth::None,
                stream_request(PRIMARY_ORG, BACKEND_ENV, &["true"]),
                ErrorCode::Unauthenticated,
                "",
            ),
            (
                Auth::Admin,
                stream_request(MISSING_ORG, BACKEND_ENV, &["true"]),
                ErrorCode::NotFound,
                "organization not found",
            ),
            (
                Auth::Admin,
                stream_request(PRIMARY_ORG, MISSING_ENV, &["true"]),
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::User,
                stream_request(PRIMARY_ORG, VIEWER_ENV, &["true"]),
                ErrorCode::PermissionDenied,
                "access denied",
            ),
            (
                Auth::Admin,
                stream_request(PRIMARY_ORG, STOPPED_ENV, &["true"]),
                ErrorCode::FailedPrecondition,
                "environment must be running",
            ),
            (
                Auth::Admin,
                stream_request(PRIMARY_ORG, NO_BACKEND_ENV, &["true"]),
                ErrorCode::Unavailable,
                "sandbox backend not found",
            ),
            (
                Auth::Admin,
                stream_request(PRIMARY_ORG, BACKEND_ENV, &[]),
                ErrorCode::InvalidArgument,
                "validation failed",
            ),
        ] {
            let client = exec_client(harness, auth, codec);
            let error = stream_exec_error(&client, request).await;
            assert_rpc_error(&error, code, message);
        }
    }
}

async fn assert_file_gates_and_protocol(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
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
            (
                Auth::Admin,
                PRIMARY_ORG,
                NO_BACKEND_ENV,
                ErrorCode::Unavailable,
                "sandbox backend not found",
            ),
        ] {
            let client = file_client(harness, auth, codec);
            let error = client
                .list_files(ListFilesRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("ListFiles gate must fail");
            assert_rpc_error(&error, code, message);
        }

        let client = file_client(harness, Auth::Admin, codec);
        let page = client
            .list_files(ListFilesRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                page_token: "future".into(),
                ..Default::default()
            })
            .await
            .expect_err("unknown file page token must fail");
        assert_rpc_error(&page, ErrorCode::InvalidArgument, "validation failed");
        assert_rpc_bad_request(&page, &["page_token"]);

        let path = download_error(
            &client,
            DownloadFileRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            },
        )
        .await;
        assert_rpc_error(&path, ErrorCode::InvalidArgument, "validation failed");
        assert_rpc_bad_request(&path, &["path"]);

        let empty = client
            .upload_file(std::iter::empty::<UploadFileRequest>())
            .await
            .expect_err("empty UploadFile stream must fail");
        assert_rpc_error(&empty, ErrorCode::InvalidArgument, "validation failed");
        assert_rpc_bad_request(&empty, &["payload"]);

        let chunk_first = client
            .upload_file([UploadFileRequest {
                payload: Some(upload_file_request::Payload::Chunk(b"invalid".to_vec())),
                ..Default::default()
            }])
            .await
            .expect_err("chunk-first UploadFile must fail");
        assert_rpc_error(
            &chunk_first,
            ErrorCode::InvalidArgument,
            "validation failed",
        );
        assert_rpc_bad_request(&chunk_first, &["payload"]);

        let empty_header = client
            .upload_file([UploadFileRequest {
                payload: Some(upload_file_request::Payload::Header(Box::default())),
                ..Default::default()
            }])
            .await
            .expect_err("empty UploadFile header must fail");
        assert_rpc_error(
            &empty_header,
            ErrorCode::InvalidArgument,
            "validation failed",
        );
        assert_rpc_bad_request(
            &empty_header,
            &["header.org_id", "header.environment_id", "header.path"],
        );
    }
}

async fn assert_canonical_exec_details(harness: &Harness) {
    let denied = harness
        .connect_json(
            EXEC_SERVICE,
            "Exec",
            json!({"orgId": PRIMARY_ORG, "environmentId": VIEWER_ENV, "command": ["true"]}),
            Auth::User,
        )
        .await;
    let body = assert_connect_error(
        &denied,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "access denied",
    );
    assert_error_info(&denied, &body, "ACCESS_DENIED");

    let state = harness
        .connect_json(
            EXEC_SERVICE,
            "Exec",
            json!({"orgId": PRIMARY_ORG, "environmentId": STOPPED_ENV, "command": ["true"]}),
            Auth::Admin,
        )
        .await;
    let body = assert_connect_error(
        &state,
        StatusCode::BAD_REQUEST,
        "failed_precondition",
        "environment must be running",
    );
    assert_error_info(&state, &body, "INVALID_STATE");

    for (body, field) in [
        (
            json!({"orgId": PRIMARY_ORG, "environmentId": BACKEND_ENV}),
            "command",
        ),
        (
            json!({"orgId": PRIMARY_ORG, "environmentId": BACKEND_ENV, "command": ["true"], "timeout": "-1s"}),
            "timeout",
        ),
    ] {
        let response = harness
            .connect_json(EXEC_SERVICE, "Exec", body, Auth::Admin)
            .await;
        let error =
            assert_connect_error(&response, StatusCode::BAD_REQUEST, "invalid_argument", "");
        assert_bad_request(&error, &[field]);
    }

    let backend = harness
        .connect_json(
            EXEC_SERVICE,
            "Exec",
            json!({"orgId": PRIMARY_ORG, "environmentId": NO_BACKEND_ENV, "command": ["true"]}),
            Auth::Admin,
        )
        .await;
    let body = assert_connect_error(
        &backend,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "sandbox backend not found",
    );
    assert!(!has_detail(&body, "google.rpc.RetryInfo"));

    let timeout = harness
        .connect_json(
            EXEC_SERVICE,
            "Exec",
            json!({"orgId": PRIMARY_ORG, "environmentId": BACKEND_ENV, "command": ["codewire-contract-exec-timeout"], "timeout": "0.001s"}),
            Auth::Admin,
        )
        .await;
    let body = assert_connect_error(
        &timeout,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline_exceeded",
        "environment command timed out",
    );
    assert!(!has_detail(&body, "google.rpc.RetryInfo"));
}

pub(super) async fn assert_runtime_boundaries(harness: &Harness) {
    let exec = harness
        .connect_json(
            EXEC_SERVICE,
            "Exec",
            json!({"orgId": PRIMARY_ORG, "environmentId": UNAVAILABLE_ENV, "command": ["true"]}),
            Auth::Admin,
        )
        .await;
    let body = assert_connect_error(
        &exec,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        match harness.kube_mode {
            KubeMode::Configured => "environment daemon is unavailable",
            KubeMode::Unconfigured => "sandbox client not configured",
        },
    );
    assert_eq!(
        has_detail(&body, "google.rpc.RetryInfo"),
        harness.kube_mode == KubeMode::Configured
    );
    if harness.kube_mode == KubeMode::Configured {
        assert_retry_info(&body);
    }

    let exec_client = exec_client(harness, Auth::Admin, CodecFormat::Proto);
    let stream_error = stream_exec_error(
        &exec_client,
        stream_request(PRIMARY_ORG, UNAVAILABLE_ENV, &["true"]),
    )
    .await;
    assert_rpc_error(
        &stream_error,
        ErrorCode::Unavailable,
        match harness.kube_mode {
            KubeMode::Configured => "environment daemon is unavailable",
            KubeMode::Unconfigured => "sandbox client not configured",
        },
    );
    assert_eq!(
        rpc_has_retry_info(&stream_error),
        harness.kube_mode == KubeMode::Configured
    );

    let file_client = file_client(harness, Auth::Admin, CodecFormat::Proto);
    let file_error = file_client
        .list_files(ListFilesRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: UNAVAILABLE_ENV.into(),
            ..Default::default()
        })
        .await
        .expect_err("FileService runtime boundary must fail");
    assert_rpc_error(
        &file_error,
        ErrorCode::Unavailable,
        match harness.kube_mode {
            KubeMode::Configured => "environment daemon is unavailable",
            KubeMode::Unconfigured => "sandbox client not configured",
        },
    );
    assert_eq!(
        rpc_has_retry_info(&file_error),
        harness.kube_mode == KubeMode::Configured
    );
}
