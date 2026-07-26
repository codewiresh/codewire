//! Connect-RPC adapter for durable environment command and PTY sessions.
//!
//! The public service owns product authentication and published wire shapes.
//! It delegates only after the control plane has authorized the environment
//! and derived the private daemon credential; that credential never crosses
//! this adapter boundary.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_gateway_proto::daemon::v1;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::auth_user;
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;

use crate::api::ApiState;
use crate::api::environment_daemon::{
    EnvironmentDaemonSessionAttachment, attach_environment_daemon_session_core,
    get_environment_daemon_session_core, launch_environment_daemon_session_core,
    list_environment_daemon_sessions_core, read_environment_daemon_session_output_core,
    restart_environment_daemon_session_core, stop_environment_daemon_session_core,
};
use crate::connect::{rendered_workspace_error, workspace_rpc_error};

/// Registers the public durable-session service. This has no REST sibling:
/// sessions use one generated RPC contract. The direct h2c leg speaks Connect;
/// the secure first-party public edge speaks native gRPC so request streaming
/// remains full duplex through Cloudflare and ingress-nginx.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EnvironmentSessionConnectService { state }))
}

struct EnvironmentSessionConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentSessionService for EnvironmentSessionConnectService {
    async fn launch_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::LaunchSessionRequest>,
    ) -> ServiceResult<proto::LaunchSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_launch(&request).map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let session = launch_environment_daemon_session_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            v1::LaunchSessionRequest {
                command: request.command,
                working_dir: request.working_dir,
                env: request
                    .env
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
                pty: request.pty,
                term: request.term,
                width: terminal_dimension(request.columns),
                height: terminal_dimension(request.rows),
            },
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::LaunchSessionResponse {
            session: Some(proto_session(session)).into(),
            ..Default::default()
        })
    }

    async fn list_sessions(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListSessionsRequest>,
    ) -> ServiceResult<proto::ListSessionsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(&request.org_id, &request.environment_id, None)
            .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let sessions = list_environment_daemon_sessions_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::ListSessionsResponse {
            sessions: sessions.into_iter().map(proto_session).collect(),
            ..Default::default()
        })
    }

    async fn get_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetSessionRequest>,
    ) -> ServiceResult<proto::GetSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(
            &request.org_id,
            &request.environment_id,
            Some(&request.session_id),
        )
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let session = get_environment_daemon_session_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.session_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::GetSessionResponse {
            session: Some(proto_session(session)).into(),
            ..Default::default()
        })
    }

    async fn stop_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopSessionRequest>,
    ) -> ServiceResult<proto::StopSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(
            &request.org_id,
            &request.environment_id,
            Some(&request.session_id),
        )
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let session = stop_environment_daemon_session_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.session_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::StopSessionResponse {
            session: Some(proto_session(session)).into(),
            ..Default::default()
        })
    }

    async fn restart_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RestartSessionRequest>,
    ) -> ServiceResult<proto::RestartSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(
            &request.org_id,
            &request.environment_id,
            Some(&request.session_id),
        )
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let session = restart_environment_daemon_session_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.session_id,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::RestartSessionResponse {
            session: Some(proto_session(session)).into(),
            ..Default::default()
        })
    }

    async fn read_session_output(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ReadSessionOutputRequest>,
    ) -> ServiceResult<proto::ReadSessionOutputResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(
            &request.org_id,
            &request.environment_id,
            Some(&request.session_id),
        )
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let output = read_environment_daemon_session_output_core(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.session_id,
            request.offset,
            request.limit,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::ReadSessionOutputResponse {
            chunks: output.chunks.into_iter().map(proto_output_chunk).collect(),
            next_offset: output.next_offset,
            eof: output.eof,
            ..Default::default()
        })
    }

    async fn attach_session(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::AttachSessionRequest>,
    ) -> ServiceResult<ServiceStream<proto::AttachSessionResponse>> {
        let user = auth_user(&ctx)?.clone();
        let first = match requests.next().await {
            Some(Ok(message)) => message.to_owned_message(),
            Some(Err(error)) => return Err(error),
            None => {
                return Err(workspace_rpc_error(
                    &protocol_error("/input", "open must be the first message"),
                    &ctx,
                ));
            }
        };
        let open = match first.input {
            Some(proto::attach_session_request::Input::Open(open)) => *open,
            _ => {
                return Err(workspace_rpc_error(
                    &protocol_error("/input", "open must be the first message"),
                    &ctx,
                ));
            }
        };
        validate_coordinates(&open.org_id, &open.environment_id, Some(&open.session_id))
            .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let session = attach_environment_daemon_session_core(
            &self.state,
            &user,
            &open.org_id,
            &open.environment_id,
            &open.session_id,
            open.output_offset,
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let request_id = ctx
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(bridge_attach_session(
            requests,
            session,
            open.session_id,
            request_id,
            tx,
        ));
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        connectrpc::Response::stream_ok(stream)
    }
}

async fn bridge_attach_session(
    mut requests: InboundStream<proto::AttachSessionRequest>,
    mut session: EnvironmentDaemonSessionAttachment,
    session_id: String,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::AttachSessionResponse, connectrpc::ConnectError>>,
) {
    let mut inbound_closed = false;
    loop {
        tokio::select! {
            request = requests.next(), if !inbound_closed => {
                let Some(request) = request else {
                    inbound_closed = true;
                    continue;
                };
                let request = match request {
                    Ok(request) => request.to_owned_message(),
                    Err(error) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                };
                let message = match attach_input(request, &session_id) {
                    Ok(message) => message,
                    Err(error) => {
                        let _ = tx.send(Err(render_session_error(&error, request_id.as_deref()))).await;
                        return;
                    }
                };
                if let Err(error) = session.send_input(message).await {
                    let _ = tx.send(Err(render_session_error(&error, request_id.as_deref()))).await;
                    return;
                }
            }
            output = session.next_output() => {
                let output = match output {
                    Ok(Some(output)) => output,
                    Ok(None) => return,
                    Err(error) => {
                        let _ = tx.send(Err(render_session_error(&error, request_id.as_deref()))).await;
                        return;
                    }
                };
                let response = match attach_output(output, &mut session, &session_id).await {
                    Ok(response) => response,
                    Err(error) => {
                        let _ = tx.send(Err(render_session_error(&error, request_id.as_deref()))).await;
                        return;
                    }
                };
                if tx.send(Ok(response)).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn attach_input(
    request: proto::AttachSessionRequest,
    session_id: &str,
) -> AppResult<v1::SessionAttachMessage> {
    let payload = match request.input {
        Some(proto::attach_session_request::Input::Stdin(data)) => {
            v1::session_attach_message::Payload::Input(v1::SessionInput { data })
        }
        Some(proto::attach_session_request::Input::Resize(resize)) => {
            v1::session_attach_message::Payload::Resize(v1::ResizeRequest {
                width: terminal_dimension(resize.columns),
                height: terminal_dimension(resize.rows),
            })
        }
        Some(proto::attach_session_request::Input::Detach(_)) => {
            v1::session_attach_message::Payload::Detach(v1::DetachSessionRequest {
                session_id: session_id.to_string(),
            })
        }
        Some(proto::attach_session_request::Input::Open(_)) => {
            return Err(protocol_error("/input/open", "may only be sent once"));
        }
        None => return Err(protocol_error("/input", "is required")),
    };
    Ok(v1::SessionAttachMessage {
        payload: Some(payload),
    })
}

async fn attach_output(
    output: v1::SessionAttachMessage,
    session: &mut EnvironmentDaemonSessionAttachment,
    session_id: &str,
) -> AppResult<proto::AttachSessionResponse> {
    let event = match output.payload {
        Some(v1::session_attach_message::Payload::Output(chunk)) => {
            proto::attach_session_response::Event::Output(Box::new(proto_output_chunk(chunk)))
        }
        Some(v1::session_attach_message::Payload::Status(_)) => {
            let record = session.session(session_id).await?;
            proto::attach_session_response::Event::Status(Box::new(proto::AttachSessionStatus {
                session: Some(proto_session(record)).into(),
                ..Default::default()
            }))
        }
        Some(v1::session_attach_message::Payload::Attach(_))
        | Some(v1::session_attach_message::Payload::Input(_))
        | Some(v1::session_attach_message::Payload::Resize(_))
        | Some(v1::session_attach_message::Payload::Detach(_))
        | None => {
            return Err(AppError::InternalMsg(
                "environment daemon emitted an invalid session frame".into(),
            ));
        }
    };
    Ok(proto::AttachSessionResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn validate_launch(request: &proto::LaunchSessionRequest) -> AppResult<()> {
    let mut errors = coordinate_errors(
        &request.org_id,
        &request.environment_id,
        None,
        "/org_id",
        "/environment_id",
        "/session_id",
    );
    if request.command.is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed("/command"),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    validation_result(errors)
}

fn validate_coordinates(
    org_id: &str,
    environment_id: &str,
    session_id: Option<&str>,
) -> AppResult<()> {
    validation_result(coordinate_errors(
        org_id,
        environment_id,
        session_id,
        "/org_id",
        "/environment_id",
        "/session_id",
    ))
}

fn coordinate_errors(
    org_id: &str,
    environment_id: &str,
    session_id: Option<&str>,
    org_path: &'static str,
    environment_path: &'static str,
    session_path: &'static str,
) -> Vec<ValidationIssue> {
    let mut errors = Vec::new();
    if org_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(org_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if environment_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(environment_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if session_id.is_some_and(|session_id| session_id.trim().is_empty()) {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(session_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    errors
}

fn validation_result(errors: Vec<ValidationIssue>) -> AppResult<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn protocol_error(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed(path),
            message: Cow::Borrowed(message),
        }],
    }
}

fn terminal_dimension(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn proto_session(record: v1::SessionRecord) -> proto::EnvironmentSession {
    proto::EnvironmentSession {
        session_id: record.session_id,
        state: proto_session_state(record.state).into(),
        command: record.command,
        working_dir: record.working_dir,
        pty: record.pty,
        created_at: record
            .created_at
            .map(|timestamp| Timestamp::from_unix(timestamp.seconds, timestamp.nanos))
            .into(),
        started_at: record
            .started_at
            .map(|timestamp| Timestamp::from_unix(timestamp.seconds, timestamp.nanos))
            .into(),
        finished_at: record
            .finished_at
            .map(|timestamp| Timestamp::from_unix(timestamp.seconds, timestamp.nanos))
            .into(),
        exit_code: record.exit_code,
        output_end_offset: record.output_end_offset,
        status_message: record.status_message,
        ..Default::default()
    }
}

fn proto_session_state(state: i32) -> proto::EnvironmentSessionState {
    use v1::SessionLifecycleState as Internal;
    match Internal::try_from(state).unwrap_or(Internal::Unspecified) {
        Internal::Unspecified => proto::EnvironmentSessionState::Unspecified,
        Internal::Starting => proto::EnvironmentSessionState::Starting,
        Internal::Running => proto::EnvironmentSessionState::Running,
        Internal::Stopping => proto::EnvironmentSessionState::Stopping,
        Internal::Stopped => proto::EnvironmentSessionState::Stopped,
        Internal::Exited => proto::EnvironmentSessionState::Exited,
        Internal::Failed => proto::EnvironmentSessionState::Failed,
        Internal::Interrupted => proto::EnvironmentSessionState::Interrupted,
    }
}

fn proto_output_chunk(chunk: v1::SessionOutputChunk) -> proto::EnvironmentSessionOutputChunk {
    proto::EnvironmentSessionOutputChunk {
        offset: chunk.offset,
        next_offset: chunk.next_offset,
        stream: proto_output_stream(chunk.stream).into(),
        data: chunk.data,
        ..Default::default()
    }
}

fn proto_output_stream(stream: i32) -> proto::EnvironmentSessionOutputStream {
    use v1::SessionOutputStream as Internal;
    match Internal::try_from(stream).unwrap_or(Internal::Unspecified) {
        Internal::Unspecified => proto::EnvironmentSessionOutputStream::Unspecified,
        Internal::Stdout => proto::EnvironmentSessionOutputStream::Stdout,
        Internal::Stderr => proto::EnvironmentSessionOutputStream::Stderr,
        Internal::Pty => proto::EnvironmentSessionOutputStream::Pty,
    }
}

fn render_session_error(error: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    codewire_server_core::connect::wire_error(&rendered_workspace_error(error, request_id))
}
