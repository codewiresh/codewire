//! Platform ownership for the shared public `ExecService` daemon bridge.

use std::borrow::Cow;

use async_trait::async_trait;
use axum::http::StatusCode;
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::exec::ExecBackend;
use codewire_daemon_bridge::session::FieldViolation;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::{AppError, ValidationIssue};
use connectrpc::RequestContext;

use crate::api::ApiState;
use crate::api::environment_daemon::environment_daemon_bridge_client_core;
use crate::connect::rendered_workspace_error;

pub fn router(state: ApiState) -> connectrpc::Router {
    codewire_daemon_bridge::exec::router(PlatformExecBackend { state })
}

#[derive(Clone)]
struct PlatformExecBackend {
    state: ApiState,
}

#[async_trait]
impl ExecBackend for PlatformExecBackend {
    fn server_restart(
        &self,
        restart: codewire_daemon_bridge::drain::Restart,
    ) -> Option<codewire_daemon_bridge::drain::RestartSignal> {
        Some(self.state.drain.signal(restart))
    }

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
        render(&exec_client_error(error), request_id)
    }

    fn timeout_error(&self, request_id: Option<&str>) -> connectrpc::ConnectError {
        render(
            &AppError::Coded {
                status: StatusCode::GATEWAY_TIMEOUT,
                code: "exec_timeout",
                detail: "environment command timed out".into(),
            },
            request_id,
        )
    }

    fn output_limit_error(&self, request_id: Option<&str>) -> connectrpc::ConnectError {
        render_output_limit(request_id)
    }

    fn invalid_daemon_frame(&self, request_id: Option<&str>) -> connectrpc::ConnectError {
        render(
            &AppError::Upstream("environment command ended without an exit status".into()),
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

fn exec_client_error(error: DaemonClientError) -> AppError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => AppError::Precondition(
                "environment daemon upgrade is required; run `cw daemon repair`".into(),
            ),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                AppError::Upstream("environment command transport was lost".into())
            }
            _ => AppError::InternalMsg("environment command failed".into()),
        },
        DaemonClientError::NotReady { state, .. } => daemon_readiness_error(state),
        DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => AppError::Precondition(
            "environment daemon upgrade is required; run `cw daemon repair`".into(),
        ),
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            AppError::Upstream("environment command transport was lost".into())
        }
        DaemonClientError::Remote(_) => {
            AppError::Precondition("environment command failed to start".into())
        }
        DaemonClientError::InvalidFrame(_) | DaemonClientError::MissingResponse(_) => {
            AppError::Upstream("environment daemon returned an invalid command stream".into())
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

fn render_output_limit(request_id: Option<&str>) -> connectrpc::ConnectError {
    render(
        &AppError::Coded {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "resource_limit_exceeded",
            detail: "environment command output is too large".into(),
        },
        request_id,
    )
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::ConnectCode;

    #[test]
    fn daemon_transport_failures_remain_retryable() {
        let rendered = rendered_workspace_error(
            &exec_client_error(DaemonClientError::RequestClosed),
            Some("request-1"),
        );
        assert_eq!(rendered.code, ConnectCode::Unavailable);
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            codewire_server_core::connect_error::ConnectErrorDetail::RetryInfo(_)
        )));
    }

    #[test]
    fn unary_output_limit_is_resource_exhausted() {
        let error = render_output_limit(Some("request-1"));
        assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
    }

    #[test]
    fn daemon_readiness_guidance_preserves_platform_semantics() {
        use codewire_daemon_proto::daemon::v1::DaemonState;

        let starting = daemon_readiness_error(DaemonState::Starting);
        assert!(matches!(
            &starting,
            AppError::ServiceUnavailable(message) if message == "environment daemon is still starting"
        ));
        assert_eq!(
            rendered_workspace_error(&starting, Some("request-1")).code,
            ConnectCode::Unavailable
        );
        assert!(matches!(
            daemon_readiness_error(DaemonState::UpgradeRequired),
            AppError::Precondition(message) if message.contains("daemon repair")
        ));
        assert!(matches!(
            daemon_readiness_error(DaemonState::Unhealthy),
            AppError::Precondition(message) if message.contains("daemon status")
        ));
    }
}
