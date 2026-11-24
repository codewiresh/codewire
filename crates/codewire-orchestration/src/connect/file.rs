//! Platform ownership for the shared public `FileService` daemon bridge.

use std::borrow::Cow;

use async_trait::async_trait;
use axum::http::StatusCode;
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::file::{FileBackend, written_files_message};
use codewire_daemon_bridge::session::FieldViolation;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::connect_error::{
    ConnectError as RenderedConnectError, ConnectErrorDetail, ERROR_INFO_DOMAIN, ErrorInfo,
};
use codewire_server_core::{AppError, ValidationIssue};
use connectrpc::RequestContext;

use crate::api::ApiState;
use crate::api::environment_daemon::environment_daemon_bridge_client_core;
use crate::connect::rendered_workspace_error;

pub fn router(state: ApiState) -> connectrpc::Router {
    codewire_daemon_bridge::file::router(PlatformFileBackend { state })
}

/// The `WriteFiles` body budget for the file mount, charged to the user the
/// auth layer admitted. The mount applies it inside authentication, so only an
/// admitted caller is charged (#5804).
pub fn admission(routes: axum::Router) -> axum::Router {
    codewire_daemon_bridge::file::write_files_admission(routes, authenticated_user)
}

/// The admitted user's stable id, which for an API key is its owner's; never
/// a credential.
fn authenticated_user(request: &axum::extract::Request) -> Option<String> {
    request
        .extensions()
        .get::<AuthUser>()
        .map(|user| user.user_id.clone())
}

#[derive(Clone)]
struct PlatformFileBackend {
    state: ApiState,
}

#[async_trait]
impl FileBackend for PlatformFileBackend {
    fn server_restart(
        &self,
        restart: codewire_daemon_bridge::drain::Restart,
    ) -> Option<codewire_daemon_bridge::drain::RestartSignal> {
        Some(self.state.drain.signal(restart))
    }

    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        auth_user(ctx).map(|_| ())
    }

    async fn admit_stream(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Option<codewire_daemon_bridge::drain::EndSignal>, connectrpc::ConnectError> {
        crate::connect::fenced_stream(&self.state, ctx, "file", org_id, environment_id)
            .await
            .map(Some)
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
                        path: violation.path,
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

    /// The daemon's error as [`Self::daemon_error`] renders it, its message
    /// and its `ErrorInfo` metadata entry `written` (a JSON array) naming the
    /// files already put in place.
    fn written_files_error(
        &self,
        error: DaemonClientError,
        written: &[String],
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        wire_error(&written_files_error(
            rendered_workspace_error(&file_client_error(error), request_id),
            written,
        ))
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

fn written_files_error(
    mut rendered: RenderedConnectError,
    written: &[String],
) -> RenderedConnectError {
    let list = serde_json::Value::from(written).to_string();
    let info = rendered.details.iter_mut().find_map(|detail| match detail {
        ConnectErrorDetail::ErrorInfo(info) => Some(info),
        _ => None,
    });
    match info {
        Some(info) => {
            info.metadata.insert("written".to_owned(), list);
        }
        None => rendered
            .details
            .push(ConnectErrorDetail::ErrorInfo(ErrorInfo {
                reason: String::new(),
                domain: ERROR_INFO_DOMAIN.to_owned(),
                metadata: [("written".to_owned(), list)].into(),
            })),
    }
    rendered.message = written_files_message(Some(&rendered.message), written);
    rendered
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
    use codewire_server_core::connect_error::ConnectCode;
    use tower::ServiceExt as _;

    /// The file mount's admission charges the user the auth layer admitted:
    /// one user's share full refuses that user's next `WriteFiles` call before
    /// its body is read, and not another user's.
    #[tokio::test]
    async fn the_write_files_admission_charges_the_authenticated_user() {
        const WRITE_FILES: &str =
            codewire_proto::codewire::v1::FILE_SERVICE_WRITE_FILES_SPEC.procedure;
        const MAX: usize = codewire_daemon_bridge::file::WRITE_FILES_MAX_MESSAGE_BYTES;
        let (reached, mut reached_rx) = tokio::sync::watch::channel(0_usize);
        let inner = axum::Router::new().route(
            WRITE_FILES,
            // Like the Connect dispatcher, the route keeps the request's
            // extensions, and its untaken charge, until it answers.
            axum::routing::post(move |request: axum::extract::Request| async move {
                reached.send_modify(|count| *count += 1);
                let (parts, body) = request.into_parts();
                let _read = axum::body::to_bytes(body, usize::MAX).await;
                drop(parts);
                StatusCode::OK
            }),
        );
        let router = admission(inner);
        let call = |user: &str, length: usize| {
            let mut request = axum::http::Request::post(WRITE_FILES)
                .header("content-type", "application/proto")
                .header("content-length", length)
                .body(axum::body::Body::from_stream(futures::stream::pending::<
                    Result<axum::body::Bytes, std::convert::Infallible>,
                >()))
                .expect("request");
            request.extensions_mut().insert(AuthUser {
                user_id: user.to_owned(),
                org_id: None,
                is_admin: false,
                via_api_key: true,
            });
            router.clone().oneshot(request)
        };
        let held = [
            tokio::spawn(call("user-a", MAX)),
            tokio::spawn(call("user-a", MAX)),
        ];
        let timeout = std::time::Duration::from_secs(10);
        tokio::time::timeout(timeout, reached_rx.wait_for(|count| *count >= 2))
            .await
            .expect("held calls did not reach the service")
            .expect("reached sender kept");

        let refused = tokio::time::timeout(timeout, call("user-a", 10))
            .await
            .expect("refused at once")
            .expect("infallible");
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(refused.into_body(), 64 * 1024)
            .await
            .expect("error body");
        assert!(
            body.starts_with(br#"{"code":"resource_exhausted""#),
            "{body:?}"
        );
        assert_eq!(*reached_rx.borrow(), 2);

        // Another user is admitted; its body never arrives, so it is left
        // running and dropped with the test.
        let other = tokio::spawn(call("user-b", 10));
        tokio::time::timeout(timeout, reached_rx.wait_for(|count| *count >= 3))
            .await
            .expect("another user was not admitted")
            .expect("reached sender kept");
        for call in held.into_iter().chain([other]) {
            call.abort();
        }
    }

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

    #[test]
    fn a_partial_write_names_the_files_written_in_its_error_info_and_message() {
        let written = [
            "/workspace/a.txt".to_owned(),
            "/workspace/\"b\".txt".to_owned(),
        ];
        let rendered = written_files_error(
            rendered_workspace_error(
                &file_client_error(DaemonClientError::Status(tonic::Status::permission_denied(
                    "private detail",
                ))),
                Some("req-write"),
            ),
            &written,
        );
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let infos = rendered
            .details
            .iter()
            .filter_map(|detail| match detail {
                ConnectErrorDetail::ErrorInfo(info) => Some(info),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].reason, "INVALID_PATH");
        assert_eq!(
            infos[0].metadata.get("request_id").map(String::as_str),
            Some("req-write")
        );
        let listed: Vec<String> =
            serde_json::from_str(&infos[0].metadata["written"]).expect("a JSON array");
        assert_eq!(listed, written);
        assert!(rendered.message.contains("/workspace/a.txt"));

        // An error with no ErrorInfo of its own gains one.
        let rendered = written_files_error(
            rendered_workspace_error(
                &file_client_error(DaemonClientError::Status(tonic::Status::internal(
                    "private detail",
                ))),
                None,
            ),
            &written[..1],
        );
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::ErrorInfo(info)
                if info.metadata.get("written").map(String::as_str)
                    == Some(r#"["/workspace/a.txt"]"#)
        )));
    }
}
