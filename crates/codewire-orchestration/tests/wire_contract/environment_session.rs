use codewire_proto::codewire::v1::{
    EnvironmentSessionServiceClient, LaunchSessionRequest, ListSessionsRequest,
};
use connectrpc::client::HttpClient;
use connectrpc::{CodecFormat, ErrorCode, Protocol};

use super::{Auth, Harness, PRIMARY_ORG, assert_rpc_bad_request, assert_rpc_error};

const BACKEND_ENV: &str = "env_exec_contract_backend";
const STOPPED_ENV: &str = "env_environment_contract_start_binary";
const VIEWER_ENV: &str = "env_port_contract_viewer";
const MISSING_ENV: &str = "env_exec_contract_missing";
const MISSING_ORG: &str = "org_exec_contract_missing";

pub(super) async fn run(harness: &Harness) {
    assert_session_gates(harness).await;
    assert_launch_validation(harness).await;
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
        ] {
            let error = client(harness, auth, codec, protocol)
                .list_sessions(ListSessionsRequest {
                    org_id: org_id.into(),
                    environment_id: environment_id.into(),
                    ..Default::default()
                })
                .await
                .expect_err("EnvironmentSessionService gate must fail");
            assert_rpc_error(&error, code, message);
        }
    }
}

async fn assert_launch_validation(harness: &Harness) {
    for (protocol, codec) in [
        (Protocol::Connect, CodecFormat::Proto),
        (Protocol::Connect, CodecFormat::Json),
        (Protocol::Grpc, CodecFormat::Proto),
    ] {
        let error = client(harness, Auth::Admin, codec, protocol)
            .launch_session(LaunchSessionRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: BACKEND_ENV.into(),
                ..Default::default()
            })
            .await
            .expect_err("empty durable-session launch command must fail");
        assert_rpc_error(&error, ErrorCode::InvalidArgument, "validation failed");
        assert_rpc_bad_request(&error, &["command"]);
    }
}
