//! Platform ownership for the shared public `FileService` daemon bridge.

use std::borrow::Cow;

use async_trait::async_trait;
use axum::http::StatusCode;
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::file::FileBackend;
use codewire_daemon_bridge::session::FieldViolation;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::{AppError, ValidationIssue};
use connectrpc::RequestContext;

use crate::api::ApiState;
use crate::api::environment_daemon::environment_daemon_bridge_client_core;
use crate::connect::rendered_workspace_error;

pub fn router(state: ApiState) -> connectrpc::Router {
    codewire_daemon_bridge::file::router(PlatformFileBackend { state })
}

#[derive(Clone)]
struct PlatformFileBackend {
    state: ApiState,
}

#[async_trait]
impl FileBackend for PlatformFileBackend {
    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        auth_user(ctx).map(|_| ())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        render(
            &AppError::Validation {
                errors: violations
                    .into_iter()
                    .map(|violation| ValidationIssue {
                        path: Cow::Borrowed(violation.path),
                        message: Cow::Borrowed(violation.message),
                    })
                    .collect(),
            },
            request_id,
        )
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        render(&file_client_error(error), request_id)
    }

    fn invalid_file_type(&self, request_id: Option<&str>) -> connectrpc::ConnectError {
        render(
            &AppError::Coded {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_path",
                detail: "path is not a regular file".into(),
            },
            request_id,
        )
    }

    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        environment_daemon_bridge_client_core(&self.state, &user, org_id, environment_id)
            .await
            .map_err(|error| render(&error, request_id(ctx)))
    }
}

fn file_client_error(error: DaemonClientError) -> AppError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => AppError::Coded {
                status: StatusCode::NOT_FOUND,
                code: "file_not_found",
                detail: "file not found".into(),
            },
            tonic::Code::InvalidArgument | tonic::Code::PermissionDenied => AppError::Coded {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_path",
                detail: "file path is invalid or denied".into(),
            },
            tonic::Code::AlreadyExists => AppError::Conflict("file already exists".into()),
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => AppError::Precondition(
                "environment daemon upgrade is required; run `cw daemon repair`".into(),
            ),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                AppError::Upstream("environment file transport was lost".into())
            }
            _ => AppError::InternalMsg("environment file request failed".into()),
        },
        DaemonClientError::NotReady { state, .. } => daemon_readiness_error(state),
        DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => AppError::Precondition(
            "environment daemon upgrade is required; run `cw daemon repair`".into(),
        ),
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            AppError::Upstream("environment file transport was lost".into())
        }
        DaemonClientError::InvalidFrame(_)
        | DaemonClientError::MissingResponse(_)
        | DaemonClientError::Remote(_) => {
            AppError::Upstream("environment daemon returned an invalid file response".into())
        }
        DaemonClientError::InvalidEndpoint | DaemonClientError::InvalidCredential => {
            AppError::InternalMsg("failed to authorize environment daemon".into())
        }
    }
}

fn daemon_readiness_error(state: codewire_daemon_proto::daemon::v1::DaemonState) -> AppError {
    use codewire_daemon_proto::daemon::v1::DaemonState;

    match state {
        // Transient: nothing has run, so clients wait it out (#4311).
        DaemonState::Starting => {
            AppError::ServiceUnavailable("environment daemon is still starting".into())
        }
        DaemonState::Unsupported | DaemonState::UpgradeRequired => AppError::Precondition(
            "environment daemon upgrade is required; run `cw daemon repair`".into(),
        ),
        DaemonState::Ready | DaemonState::Unhealthy | DaemonState::Unspecified => {
            AppError::Precondition("environment daemon is not ready; run `cw daemon status`".into())
        }
    }
}

fn render(error: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    wire_error(&rendered_workspace_error(error, request_id))
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectErrorDetail};

    #[test]
    fn missing_and_denied_paths_keep_stable_public_codes() {
        let missing = rendered_workspace_error(
            &file_client_error(DaemonClientError::Status(tonic::Status::not_found(
                "private detail",
            ))),
            Some("req-file"),
        );
        assert_eq!(missing.code, ConnectCode::NotFound);
        assert!(missing.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::ErrorInfo(info)
                if info.reason == "FILE_NOT_FOUND"
                    && info.metadata.get("request_id").map(String::as_str) == Some("req-file")
        )));

        let denied = rendered_workspace_error(
            &file_client_error(DaemonClientError::Status(tonic::Status::permission_denied(
                "private detail",
            ))),
            None,
        );
        assert_eq!(denied.code, ConnectCode::InvalidArgument);
        assert!(denied.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::ErrorInfo(info) if info.reason == "INVALID_PATH"
        )));
    }
}
