//! Client-facing Connect-RPC services served by orchestration.

use std::time::Duration;

use axum::http::StatusCode;
use codewire_server_core::AppError;
use codewire_server_core::connect::wire_error;
use codewire_server_core::connect_error::ConnectError as RenderedConnectError;
use connectrpc::RequestContext;

pub mod access_profiles;
pub mod account;
pub mod admin;
pub mod api_keys;
pub mod credentials;
pub mod environment;
pub mod environment_cw_runtime;
pub mod environment_session;
pub mod environment_setup;
pub mod exec;
pub mod file;
pub mod internal;
pub mod mesh_authorization;
pub mod organizations;
pub mod ports;
pub mod presets;
pub mod secrets;

/// Shared D12 renderer for sandbox-gated RPCs. ExecService and FileService
/// both call the same target gate, so state/access/upstream failures must keep
/// one canonical Connect meaning.
pub(crate) fn rendered_workspace_error(
    error: &AppError,
    request_id: Option<&str>,
) -> RenderedConnectError {
    if let AppError::BadRequest(detail) = error
        && detail.as_ref() == "environment must be running"
    {
        return RenderedConnectError::from_app_error(
            &AppError::Coded {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_state",
                detail: detail.clone(),
            },
            request_id,
        );
    }

    if let AppError::Coded {
        status,
        code,
        detail,
    } = error
        && *status == StatusCode::FORBIDDEN
        && code.is_empty()
        && detail.as_ref() == "access denied"
    {
        return RenderedConnectError::from_app_error(
            &AppError::Coded {
                status: *status,
                code: "access_denied",
                detail: detail.clone(),
            },
            request_id,
        );
    }

    let rendered = RenderedConnectError::from_app_error(error, request_id);
    if matches!(error, AppError::Upstream(_)) {
        rendered.with_retry_delay(Duration::from_secs(1))
    } else {
        rendered
    }
}

pub(crate) fn workspace_rpc_error(
    error: &AppError,
    ctx: &RequestContext,
) -> connectrpc::ConnectError {
    let request_id = ctx
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    wire_error(&rendered_workspace_error(error, request_id))
}
