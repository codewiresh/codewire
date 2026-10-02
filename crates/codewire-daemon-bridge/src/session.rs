//! Shared public `EnvironmentSessionService` adapter.
//!
//! Backends authorize public coordinates and retain the private daemon
//! credential. This module owns only validation, public/private conversion,
//! bounded stream relay, and half-close behavior.

use std::sync::Arc;

use async_trait::async_trait;
use buffa_types::Timestamp;
use codewire_gateway_proto::daemon::v1;
use codewire_proto::codewire::v1 as proto;
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;

const STREAM_BUFFER: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldViolation {
    pub path: &'static str,
    pub message: &'static str,
}

#[async_trait]
pub trait EnvironmentSessionAttachment: Send + 'static {
    async fn send_input(
        &self,
        message: v1::SessionAttachMessage,
    ) -> Result<(), connectrpc::ConnectError>;

    async fn next_output(
        &mut self,
    ) -> Result<Option<v1::SessionAttachMessage>, connectrpc::ConnectError>;

    async fn session(
        &mut self,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError>;
}

#[async_trait]
pub trait EnvironmentSessionBackend: Clone + Send + Sync + 'static {
    type Attachment: EnvironmentSessionAttachment;

    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError>;

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn invalid_daemon_frame(&self, request_id: Option<&str>) -> connectrpc::ConnectError;

    async fn launch(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError>;

    async fn list(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<v1::SessionRecord>, connectrpc::ConnectError>;

    async fn get(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError>;

    async fn stop(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError>;

    async fn restart(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<v1::SessionRecord, connectrpc::ConnectError>;

    async fn send_input(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::SendSessionInputRequest,
    ) -> Result<(), connectrpc::ConnectError>;

    async fn read_output(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, connectrpc::ConnectError>;

    async fn attach(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
        output_offset: u64,
    ) -> Result<Self::Attachment, connectrpc::ConnectError>;
}

#[derive(Clone)]
pub struct EnvironmentSessionBridge<B> {
    backend: B,
}

impl<B> EnvironmentSessionBridge<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

pub fn router<B>(backend: B) -> connectrpc::Router
where
    B: EnvironmentSessionBackend,
{
    connectrpc::Router::new().add_service(Arc::new(EnvironmentSessionBridge::new(backend)))
}

#[allow(refining_impl_trait)]
impl<B> proto::EnvironmentSessionService for EnvironmentSessionBridge<B>
where
    B: EnvironmentSessionBackend,
{
    async fn launch_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::LaunchSessionRequest>,
    ) -> ServiceResult<proto::LaunchSessionResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.to_owned_message();
        let violations = launch_violations(&request);
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let session = self
            .backend
            .launch(
                &ctx,
                &request.org_id,
                &request.environment_id,
                v1::LaunchSessionRequest {
                    name: request.name,
                    parent_session_id: request.parent_session_id,
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
            .await?;
        connectrpc::Response::ok(proto::LaunchSessionResponse {
            session: Some(public_session(session)).into(),
            ..Default::default()
        })
    }

    async fn list_sessions(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListSessionsRequest>,
    ) -> ServiceResult<proto::ListSessionsResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.view();
        let violations = coordinate_violations(request.org_id, request.environment_id, None);
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let sessions = self
            .backend
            .list(&ctx, request.org_id, request.environment_id)
            .await?;
        connectrpc::Response::ok(proto::ListSessionsResponse {
            sessions: sessions.into_iter().map(public_session).collect(),
            ..Default::default()
        })
    }

    async fn get_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetSessionRequest>,
    ) -> ServiceResult<proto::GetSessionResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.view();
        let violations = coordinate_violations(
            request.org_id,
            request.environment_id,
            Some(request.session_id),
        );
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let session = self
            .backend
            .get(
                &ctx,
                request.org_id,
                request.environment_id,
                request.session_id,
            )
            .await?;
        connectrpc::Response::ok(proto::GetSessionResponse {
            session: Some(public_session(session)).into(),
            ..Default::default()
        })
    }

    async fn stop_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopSessionRequest>,
    ) -> ServiceResult<proto::StopSessionResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.view();
        let violations = coordinate_violations(
            request.org_id,
            request.environment_id,
            Some(request.session_id),
        );
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let session = self
            .backend
            .stop(
                &ctx,
                request.org_id,
                request.environment_id,
                request.session_id,
            )
            .await?;
        connectrpc::Response::ok(proto::StopSessionResponse {
            session: Some(public_session(session)).into(),
            ..Default::default()
        })
    }

    async fn restart_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RestartSessionRequest>,
    ) -> ServiceResult<proto::RestartSessionResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.view();
        let violations = coordinate_violations(
            request.org_id,
            request.environment_id,
            Some(request.session_id),
        );
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let session = self
            .backend
            .restart(
                &ctx,
                request.org_id,
                request.environment_id,
                request.session_id,
                request.expected_launch_generation,
            )
            .await?;
        connectrpc::Response::ok(proto::RestartSessionResponse {
            session: Some(public_session(session)).into(),
            ..Default::default()
        })
    }

    async fn send_session_input(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::SendSessionInputRequest>,
    ) -> ServiceResult<proto::SendSessionInputResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.to_owned_message();
        let mut violations = coordinate_violations(
            &request.org_id,
            &request.environment_id,
            Some(&request.session_id),
        );
        if request.data.is_empty()
            || request.data.len() > codewire_gateway_proto::SESSION_INPUT_MAX_BYTES
        {
            violations.push(violation("/data", "must contain 1..65536 bytes"));
        }
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        self.backend
            .send_input(
                &ctx,
                &request.org_id,
                &request.environment_id,
                v1::SendSessionInputRequest {
                    session_id: request.session_id,
                    data: request.data,
                },
            )
            .await?;
        connectrpc::Response::ok(proto::SendSessionInputResponse::default())
    }

    async fn read_session_output(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ReadSessionOutputRequest>,
    ) -> ServiceResult<proto::ReadSessionOutputResponse> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx);
        let request = request.view();
        let violations = coordinate_violations(
            request.org_id,
            request.environment_id,
            Some(request.session_id),
        );
        if !violations.is_empty() {
            return Err(self.backend.validation_error(violations, request_id));
        }
        let output = self
            .backend
            .read_output(
                &ctx,
                request.org_id,
                request.environment_id,
                v1::ReadSessionOutputRequest {
                    session_id: request.session_id.to_owned(),
                    offset: request.offset,
                    limit: request.limit,
                    allow_history_gap: request.allow_history_gap,
                },
            )
            .await?;
        connectrpc::Response::ok(proto::ReadSessionOutputResponse {
            chunks: output.chunks.into_iter().map(public_output_chunk).collect(),
            next_offset: output.next_offset,
            eof: output.eof,
            retained_start_offset: output.retained_start_offset,
            history_gap: output.history_gap,
            ..Default::default()
        })
    }

    async fn attach_session(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::AttachSessionRequest>,
    ) -> ServiceResult<ServiceStream<proto::AttachSessionResponse>> {
        self.backend.authorize(&ctx)?;
        let request_id = request_id(&ctx).map(str::to_owned);
        let first = match requests.next().await {
            Some(Ok(message)) => message.to_owned_message(),
            Some(Err(error)) => return Err(error),
            None => {
                return Err(self.backend.validation_error(
                    vec![violation("/input", "open must be the first message")],
                    request_id.as_deref(),
                ));
            }
        };
        let open = match first.input {
            Some(proto::attach_session_request::Input::Open(open)) => *open,
            _ => {
                return Err(self.backend.validation_error(
                    vec![violation("/input", "open must be the first message")],
                    request_id.as_deref(),
                ));
            }
        };
        let violations =
            coordinate_violations(&open.org_id, &open.environment_id, Some(&open.session_id));
        if !violations.is_empty() {
            return Err(self
                .backend
                .validation_error(violations, request_id.as_deref()));
        }
        let attachment = self
            .backend
            .attach(
                &ctx,
                &open.org_id,
                &open.environment_id,
                &open.session_id,
                open.output_offset,
            )
            .await?;
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        tokio::spawn(bridge_attachment(
            self.backend.clone(),
            requests,
            attachment,
            open.session_id,
            request_id,
            tx,
        ));
        connectrpc::Response::stream_ok(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        }))
    }
}

async fn bridge_attachment<B>(
    backend: B,
    mut requests: InboundStream<proto::AttachSessionRequest>,
    mut attachment: B::Attachment,
    session_id: String,
    request_id: Option<String>,
    tx: mpsc::Sender<Result<proto::AttachSessionResponse, connectrpc::ConnectError>>,
) where
    B: EnvironmentSessionBackend,
{
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
                let message = match private_attach_input(request, &session_id) {
                    Ok(message) => message,
                    Err(violations) => {
                        let error = backend.validation_error(violations, request_id.as_deref());
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                };
                if let Err(error) = attachment.send_input(message).await {
                    let _ = tx.send(Err(error)).await;
                    return;
                }
            }
            output = attachment.next_output() => {
                let output = match output {
                    Ok(Some(output)) => output,
                    Ok(None) => return,
                    Err(error) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                };
                let response = match public_attach_output(output, &mut attachment, &session_id).await {
                    Ok(response) => response,
                    Err(AttachOutputError::Backend(error)) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                    Err(AttachOutputError::InvalidFrame) => {
                        let error = backend.invalid_daemon_frame(request_id.as_deref());
                        let _ = tx.send(Err(error)).await;
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

fn private_attach_input(
    request: proto::AttachSessionRequest,
    session_id: &str,
) -> Result<v1::SessionAttachMessage, Vec<FieldViolation>> {
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
                session_id: session_id.to_owned(),
            })
        }
        Some(proto::attach_session_request::Input::Open(_)) => {
            return Err(vec![violation("/input/open", "may only be sent once")]);
        }
        None => return Err(vec![violation("/input", "is required")]),
    };
    Ok(v1::SessionAttachMessage {
        payload: Some(payload),
    })
}

async fn public_attach_output<A>(
    output: v1::SessionAttachMessage,
    attachment: &mut A,
    session_id: &str,
) -> Result<proto::AttachSessionResponse, AttachOutputError>
where
    A: EnvironmentSessionAttachment,
{
    let event = match output.payload {
        Some(v1::session_attach_message::Payload::HistoryGap(gap)) => {
            if gap.requested_offset >= gap.retained_start_offset {
                return Err(AttachOutputError::InvalidFrame);
            }
            proto::attach_session_response::Event::HistoryGap(Box::new(
                proto::EnvironmentSessionOutputGap {
                    requested_offset: gap.requested_offset,
                    retained_start_offset: gap.retained_start_offset,
                    ..Default::default()
                },
            ))
        }
        Some(v1::session_attach_message::Payload::Output(chunk)) => {
            proto::attach_session_response::Event::Output(Box::new(public_output_chunk(chunk)))
        }
        Some(v1::session_attach_message::Payload::Status(status)) => {
            if status.session_id != session_id {
                return Err(AttachOutputError::InvalidFrame);
            }
            let state = v1::SessionLifecycleState::try_from(status.state)
                .ok()
                .filter(|state| *state != v1::SessionLifecycleState::Unspecified)
                .ok_or(AttachOutputError::InvalidFrame)?;
            let mut record = attachment
                .session(session_id)
                .await
                .map_err(AttachOutputError::Backend)?;
            if record.session_id != session_id {
                return Err(AttachOutputError::InvalidFrame);
            }

            // The private attach stream orders each status against its output
            // cursor. A fresh GetSession may already be terminal for a fast
            // command while output queued after this earlier status still has
            // to cross the bridge. Keep static record fields from the lookup,
            // but preserve the streamed lifecycle snapshot so terminal status
            // remains the final public event.
            record.state = status.state;
            record.exit_code = status.exit_code;
            record.output_end_offset = status.output_end_offset;
            record.output_start_offset = status.output_start_offset;
            record.status_message = status.message;
            if state == v1::SessionLifecycleState::Starting {
                record.started_at = None;
            }
            if matches!(
                state,
                v1::SessionLifecycleState::Starting
                    | v1::SessionLifecycleState::Running
                    | v1::SessionLifecycleState::Stopping
            ) {
                record.finished_at = None;
            }
            proto::attach_session_response::Event::Status(Box::new(proto::AttachSessionStatus {
                session: Some(public_session(record)).into(),
                ..Default::default()
            }))
        }
        Some(v1::session_attach_message::Payload::Attach(_))
        | Some(v1::session_attach_message::Payload::Input(_))
        | Some(v1::session_attach_message::Payload::Resize(_))
        | Some(v1::session_attach_message::Payload::Detach(_))
        | None => return Err(AttachOutputError::InvalidFrame),
    };
    Ok(proto::AttachSessionResponse {
        event: Some(event),
        ..Default::default()
    })
}

#[derive(Debug)]
enum AttachOutputError {
    Backend(connectrpc::ConnectError),
    InvalidFrame,
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn launch_violations(request: &proto::LaunchSessionRequest) -> Vec<FieldViolation> {
    let mut violations = coordinate_violations(&request.org_id, &request.environment_id, None);
    if request.command.is_empty() {
        violations.push(violation("/command", "must not be empty"));
    }
    if !codewire_gateway_proto::valid_session_name(&request.name) {
        violations.push(violation(
            "/name",
            "must be a safe name of at most 64 ASCII bytes",
        ));
    }
    if request
        .parent_session_id
        .as_deref()
        .is_some_and(|id| !canonical_session_id(id))
    {
        violations.push(violation(
            "/parent_session_id",
            "must be a canonical same-environment session identity",
        ));
    }
    violations
}

fn canonical_session_id(id: &str) -> bool {
    id.strip_prefix("session-")
        .and_then(|raw| {
            uuid::Uuid::parse_str(raw)
                .ok()
                .map(|uuid| uuid.to_string() == raw)
        })
        .unwrap_or(false)
}

fn coordinate_violations(
    org_id: &str,
    environment_id: &str,
    session_id: Option<&str>,
) -> Vec<FieldViolation> {
    let mut violations = Vec::new();
    if org_id.trim().is_empty() {
        violations.push(violation("/org_id", "must not be empty"));
    }
    if environment_id.trim().is_empty() {
        violations.push(violation("/environment_id", "must not be empty"));
    }
    if session_id.is_some_and(|session_id| session_id.trim().is_empty()) {
        violations.push(violation("/session_id", "must not be empty"));
    }
    violations
}

const fn violation(path: &'static str, message: &'static str) -> FieldViolation {
    FieldViolation { path, message }
}

fn terminal_dimension(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

pub fn public_session(record: v1::SessionRecord) -> proto::EnvironmentSession {
    proto::EnvironmentSession {
        name: record.name,
        parent_session_id: record.parent_session_id,
        cleanup_unknown: record.cleanup_unknown,
        launch_generation: record.launch_generation,
        session_id: record.session_id,
        state: public_session_state(record.state).into(),
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
        output_start_offset: record.output_start_offset,
        status_message: record.status_message,
        ..Default::default()
    }
}

fn public_session_state(state: i32) -> proto::EnvironmentSessionState {
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

fn public_output_chunk(chunk: v1::SessionOutputChunk) -> proto::EnvironmentSessionOutputChunk {
    proto::EnvironmentSessionOutputChunk {
        offset: chunk.offset,
        next_offset: chunk.next_offset,
        stream: public_output_stream(chunk.stream).into(),
        data: chunk.data,
        ..Default::default()
    }
}

fn public_output_stream(stream: i32) -> proto::EnvironmentSessionOutputStream {
    use v1::SessionOutputStream as Internal;
    match Internal::try_from(stream).unwrap_or(Internal::Unspecified) {
        Internal::Unspecified => proto::EnvironmentSessionOutputStream::Unspecified,
        Internal::Stdout => proto::EnvironmentSessionOutputStream::Stdout,
        Internal::Stderr => proto::EnvironmentSessionOutputStream::Stderr,
        Internal::Pty => proto::EnvironmentSessionOutputStream::Pty,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use buffa::{HasMessageView as _, Message as _};
    use connectrpc::{ErrorCode, StreamMessage};
    use prost::Message as _;
    use tokio::sync::{Mutex, Notify};

    const MESSAGE_FIELDS: &[(&str, &[(i32, &str)])] = &[
        (
            "codewire.v1.EnvironmentSession",
            &[
                (1, "session_id"),
                (2, "state"),
                (3, "command"),
                (4, "working_dir"),
                (5, "pty"),
                (6, "created_at"),
                (7, "started_at"),
                (8, "finished_at"),
                (9, "exit_code"),
                (10, "output_end_offset"),
                (11, "status_message"),
                (12, "output_start_offset"),
                (13, "name"),
                (14, "parent_session_id"),
                (15, "cleanup_unknown"),
                (16, "launch_generation"),
            ],
        ),
        (
            "codewire.v1.EnvironmentSessionOutputChunk",
            &[
                (1, "offset"),
                (2, "next_offset"),
                (3, "stream"),
                (4, "data"),
            ],
        ),
        (
            "codewire.v1.LaunchSessionRequest",
            &[
                (1, "org_id"),
                (2, "environment_id"),
                (3, "command"),
                (4, "working_dir"),
                (5, "env"),
                (6, "pty"),
                (7, "term"),
                (8, "columns"),
                (9, "rows"),
                (10, "name"),
                (11, "parent_session_id"),
            ],
        ),
        ("codewire.v1.LaunchSessionResponse", &[(1, "session")]),
        (
            "codewire.v1.ListSessionsRequest",
            &[(1, "org_id"), (2, "environment_id")],
        ),
        ("codewire.v1.ListSessionsResponse", &[(1, "sessions")]),
        (
            "codewire.v1.GetSessionRequest",
            &[(1, "org_id"), (2, "environment_id"), (3, "session_id")],
        ),
        ("codewire.v1.GetSessionResponse", &[(1, "session")]),
        (
            "codewire.v1.StopSessionRequest",
            &[(1, "org_id"), (2, "environment_id"), (3, "session_id")],
        ),
        ("codewire.v1.StopSessionResponse", &[(1, "session")]),
        (
            "codewire.v1.RestartSessionRequest",
            &[
                (1, "org_id"),
                (2, "environment_id"),
                (3, "session_id"),
                (4, "expected_launch_generation"),
            ],
        ),
        ("codewire.v1.RestartSessionResponse", &[(1, "session")]),
        (
            "codewire.v1.SendSessionInputRequest",
            &[
                (1, "org_id"),
                (2, "environment_id"),
                (3, "session_id"),
                (4, "data"),
            ],
        ),
        ("codewire.v1.SendSessionInputResponse", &[]),
        (
            "codewire.v1.ReadSessionOutputRequest",
            &[
                (1, "org_id"),
                (2, "environment_id"),
                (3, "session_id"),
                (4, "offset"),
                (5, "limit"),
                (6, "allow_history_gap"),
            ],
        ),
        (
            "codewire.v1.ReadSessionOutputResponse",
            &[
                (1, "chunks"),
                (2, "next_offset"),
                (3, "eof"),
                (4, "retained_start_offset"),
                (5, "history_gap"),
            ],
        ),
        (
            "codewire.v1.AttachSessionOpen",
            &[
                (1, "org_id"),
                (2, "environment_id"),
                (3, "session_id"),
                (4, "output_offset"),
            ],
        ),
        (
            "codewire.v1.AttachSessionResize",
            &[(1, "columns"), (2, "rows")],
        ),
        (
            "codewire.v1.AttachSessionRequest",
            &[(1, "open"), (2, "stdin"), (3, "resize"), (4, "detach")],
        ),
        ("codewire.v1.AttachSessionStatus", &[(1, "session")]),
        (
            "codewire.v1.EnvironmentSessionOutputGap",
            &[(1, "requested_offset"), (2, "retained_start_offset")],
        ),
        (
            "codewire.v1.AttachSessionResponse",
            &[(1, "output"), (2, "status"), (3, "history_gap")],
        ),
    ];

    fn descriptor() -> prost_types::FileDescriptorSet {
        prost_types::FileDescriptorSet::decode(
            include_bytes!("../../codewire-proto/codewire_descriptor.bin").as_slice(),
        )
        .unwrap()
    }

    type RestartRequestLog = Arc<Mutex<Vec<(String, Option<u64>)>>>;

    #[derive(Clone)]
    struct TestBackend {
        authorization_error: Option<connectrpc::ConnectError>,
        validation_calls: Arc<AtomicUsize>,
        output_reads: Arc<Mutex<Vec<v1::ReadSessionOutputRequest>>>,
        unary_inputs: Arc<Mutex<Vec<v1::SendSessionInputRequest>>>,
        restart_requests: RestartRequestLog,
    }

    impl TestBackend {
        fn allowed() -> Self {
            Self {
                authorization_error: None,
                validation_calls: Arc::new(AtomicUsize::new(0)),
                output_reads: Arc::new(Mutex::new(Vec::new())),
                unary_inputs: Arc::new(Mutex::new(Vec::new())),
                restart_requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn rejected() -> Self {
            Self {
                authorization_error: Some(connectrpc::ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "authentication required",
                )),
                validation_calls: Arc::new(AtomicUsize::new(0)),
                output_reads: Arc::new(Mutex::new(Vec::new())),
                unary_inputs: Arc::new(Mutex::new(Vec::new())),
                restart_requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    struct RecordingAttachment {
        inputs: Arc<Mutex<Vec<v1::SessionAttachMessage>>>,
        half_closed: Arc<AtomicBool>,
        half_close_notify: Arc<Notify>,
        outputs: VecDeque<v1::SessionAttachMessage>,
        session_result: Result<v1::SessionRecord, connectrpc::ConnectError>,
    }

    #[async_trait]
    impl EnvironmentSessionAttachment for RecordingAttachment {
        async fn send_input(
            &self,
            message: v1::SessionAttachMessage,
        ) -> Result<(), connectrpc::ConnectError> {
            self.inputs.lock().await.push(message);
            Ok(())
        }

        async fn next_output(
            &mut self,
        ) -> Result<Option<v1::SessionAttachMessage>, connectrpc::ConnectError> {
            while !self.half_closed.load(Ordering::SeqCst) {
                let notified = self.half_close_notify.notified();
                if self.half_closed.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
            Ok(self.outputs.pop_front())
        }

        async fn session(
            &mut self,
            _session_id: &str,
        ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
            self.session_result.clone()
        }
    }

    #[async_trait]
    impl EnvironmentSessionBackend for TestBackend {
        type Attachment = RecordingAttachment;

        fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
            self.authorization_error.clone().map_or(Ok(()), Err)
        }

        fn validation_error(
            &self,
            _violations: Vec<FieldViolation>,
            _request_id: Option<&str>,
        ) -> connectrpc::ConnectError {
            self.validation_calls.fetch_add(1, Ordering::SeqCst);
            connectrpc::ConnectError::new(ErrorCode::InvalidArgument, "invalid request")
        }

        fn invalid_daemon_frame(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
            connectrpc::ConnectError::new(ErrorCode::Internal, "invalid daemon frame")
        }

        async fn launch(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            _request: v1::LaunchSessionRequest,
        ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
            unreachable!("authorization must reject before launch")
        }

        async fn list(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
        ) -> Result<Vec<v1::SessionRecord>, connectrpc::ConnectError> {
            unreachable!("not used by bridge unit tests")
        }

        async fn get(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            _session_id: &str,
        ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
            unreachable!("not used by bridge unit tests")
        }

        async fn stop(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            _session_id: &str,
        ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
            unreachable!("not used by bridge unit tests")
        }

        async fn restart(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            session_id: &str,
            expected_launch_generation: Option<u64>,
        ) -> Result<v1::SessionRecord, connectrpc::ConnectError> {
            self.restart_requests
                .lock()
                .await
                .push((session_id.into(), expected_launch_generation));
            Ok(v1::SessionRecord {
                session_id: session_id.into(),
                launch_generation: 47,
                ..Default::default()
            })
        }

        async fn send_input(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            request: v1::SendSessionInputRequest,
        ) -> Result<(), connectrpc::ConnectError> {
            self.unary_inputs.lock().await.push(request);
            Ok(())
        }

        async fn read_output(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            request: v1::ReadSessionOutputRequest,
        ) -> Result<v1::ReadSessionOutputResponse, connectrpc::ConnectError> {
            self.output_reads.lock().await.push(request);
            Ok(v1::ReadSessionOutputResponse::default())
        }

        async fn attach(
            &self,
            _ctx: &RequestContext,
            _org_id: &str,
            _environment_id: &str,
            _session_id: &str,
            _output_offset: u64,
        ) -> Result<Self::Attachment, connectrpc::ConnectError> {
            unreachable!("not used by bridge unit tests")
        }
    }

    #[tokio::test]
    async fn unary_input_validates_before_dispatch_and_preserves_exact_bytes() {
        let backend = TestBackend::allowed();
        let inputs = backend.unary_inputs.clone();
        let bridge = EnvironmentSessionBridge::new(backend);
        for data in [
            vec![],
            vec![0; codewire_gateway_proto::SESSION_INPUT_MAX_BYTES + 1],
            vec![0xff, 0, b'\n'],
        ] {
            let valid =
                !data.is_empty() && data.len() <= codewire_gateway_proto::SESSION_INPUT_MAX_BYTES;
            let message = proto::SendSessionInputRequest {
                org_id: "org".into(),
                environment_id: "env".into(),
                session_id: "session-00000000-0000-4000-8000-000000000001".into(),
                data: data.clone(),
                ..Default::default()
            };
            let body = bytes::Bytes::from(message.encode_to_vec());
            let view = proto::SendSessionInputRequest::decode_view(&body).unwrap();
            let result = proto::EnvironmentSessionService::send_session_input(
                &bridge,
                RequestContext::default(),
                ServiceRequest::from_parts(&view, &body),
            )
            .await;
            if valid {
                result.unwrap();
                assert_eq!(inputs.lock().await.last().unwrap().data, data);
            } else {
                assert_eq!(result.unwrap_err().code, ErrorCode::InvalidArgument);
                assert!(inputs.lock().await.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn unary_input_authorization_precedes_validation_and_dispatch() {
        let backend = TestBackend::rejected();
        let calls = backend.validation_calls.clone();
        let inputs = backend.unary_inputs.clone();
        let bridge = EnvironmentSessionBridge::new(backend);
        let message = proto::SendSessionInputRequest::default();
        let body = bytes::Bytes::from(message.encode_to_vec());
        let view = proto::SendSessionInputRequest::decode_view(&body).unwrap();
        let error = proto::EnvironmentSessionService::send_session_input(
            &bridge,
            RequestContext::default(),
            ServiceRequest::from_parts(&view, &body),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(inputs.lock().await.is_empty());
    }

    #[tokio::test]
    async fn guarded_restart_forwards_generation_and_maps_the_admitted_record() {
        let backend = TestBackend::allowed();
        let requests = backend.restart_requests.clone();
        let bridge = EnvironmentSessionBridge::new(backend);
        for expected in [Some(41), None] {
            let message = proto::RestartSessionRequest {
                org_id: "org".into(),
                environment_id: "environment".into(),
                session_id: "session".into(),
                expected_launch_generation: expected,
                ..Default::default()
            };
            let body = bytes::Bytes::from(message.encode_to_vec());
            let view = proto::RestartSessionRequest::decode_view(&body).unwrap();
            let response = proto::EnvironmentSessionService::restart_session(
                &bridge,
                RequestContext::default(),
                ServiceRequest::from_parts(&view, &body),
            )
            .await
            .unwrap();
            assert_eq!(
                response
                    .body
                    .session
                    .into_option()
                    .unwrap()
                    .launch_generation,
                47
            );
        }
        assert_eq!(
            *requests.lock().await,
            vec![("session".into(), Some(41)), ("session".into(), None)]
        );
    }

    #[tokio::test]
    async fn authorization_precedes_request_validation() {
        let backend = TestBackend::rejected();
        let validation_calls = backend.validation_calls.clone();
        let bridge = EnvironmentSessionBridge::new(backend);
        let message = proto::LaunchSessionRequest::default();
        let body = bytes::Bytes::from(message.encode_to_vec());
        let view = proto::LaunchSessionRequest::decode_view(&body).unwrap();
        let request = ServiceRequest::from_parts(&view, &body);

        let error = proto::EnvironmentSessionService::launch_session(
            &bridge,
            RequestContext::default(),
            request,
        )
        .await
        .expect_err("authorization must reject the request");

        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(validation_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn bidi_bridge_relays_inputs_then_drains_output_after_half_close() {
        let inputs = Arc::new(Mutex::new(Vec::new()));
        let half_closed = Arc::new(AtomicBool::new(false));
        let half_close_notify = Arc::new(Notify::new());
        let attachment = RecordingAttachment {
            inputs: inputs.clone(),
            half_closed: half_closed.clone(),
            half_close_notify: half_close_notify.clone(),
            outputs: VecDeque::from([
                v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::Output(
                        v1::SessionOutputChunk {
                            offset: 9,
                            next_offset: 12,
                            stream: v1::SessionOutputStream::Pty as i32,
                            data: b"out".to_vec(),
                        },
                    )),
                },
                v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::Status(
                        v1::SessionStatus {
                            session_id: "session-1".into(),
                            state: v1::SessionLifecycleState::Exited as i32,
                            exit_code: Some(0),
                            output_end_offset: 12,
                            output_start_offset: 0,
                            message: "session exited with status 0".into(),
                        },
                    )),
                },
            ]),
            session_result: Ok(v1::SessionRecord {
                session_id: "session-1".into(),
                state: v1::SessionLifecycleState::Exited as i32,
                output_end_offset: 12,
                ..Default::default()
            }),
        };
        let requests = VecDeque::from([
            proto::AttachSessionRequest {
                input: Some(proto::attach_session_request::Input::Stdin(
                    b"input".to_vec(),
                )),
                ..Default::default()
            },
            proto::AttachSessionRequest {
                input: Some(
                    proto::AttachSessionResize {
                        columns: 80,
                        rows: 24,
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            },
            proto::AttachSessionRequest {
                input: Some(buffa_types::google::protobuf::Empty::default().into()),
                ..Default::default()
            },
        ]);
        let inbound: InboundStream<proto::AttachSessionRequest> =
            Box::pin(futures::stream::unfold(
                (requests, half_closed, half_close_notify),
                |(mut requests, half_closed, half_close_notify)| async move {
                    if let Some(request) = requests.pop_front() {
                        return Some((
                            Ok(StreamMessage::from_message(&request)),
                            (requests, half_closed, half_close_notify),
                        ));
                    }
                    half_closed.store(true, Ordering::SeqCst);
                    half_close_notify.notify_waiters();
                    None
                },
            ));
        let (tx, mut rx) = mpsc::channel(STREAM_BUFFER);

        bridge_attachment(
            TestBackend::allowed(),
            inbound,
            attachment,
            "session-1".into(),
            None,
            tx,
        )
        .await;

        let inputs = inputs.lock().await;
        assert!(matches!(
            inputs[0].payload.as_ref(),
            Some(v1::session_attach_message::Payload::Input(input)) if input.data == b"input"
        ));
        assert!(matches!(
            inputs[1].payload.as_ref(),
            Some(v1::session_attach_message::Payload::Resize(resize))
                if resize.width == 80 && resize.height == 24
        ));
        assert!(matches!(
            inputs[2].payload.as_ref(),
            Some(v1::session_attach_message::Payload::Detach(detach))
                if detach.session_id == "session-1"
        ));
        drop(inputs);

        let mut responses = Vec::new();
        while let Some(response) = rx.recv().await {
            responses.push(response.expect("bridge response must succeed"));
        }
        assert_eq!(responses.len(), 2);
        assert!(matches!(
            responses[0].event.as_ref(),
            Some(proto::attach_session_response::Event::Output(output))
                if output.offset == 9
                    && output.next_offset == 12
                    && output.data == b"out"
        ));
        assert!(matches!(
            responses[1].event.as_ref(),
            Some(proto::attach_session_response::Event::Status(status))
                if status.session.as_option().is_some_and(|session| {
                    session.session_id == "session-1" && session.output_end_offset == 12
                })
        ));
    }

    #[tokio::test]
    async fn unary_bridge_preserves_explicit_history_gap_opt_in() {
        let backend = TestBackend::allowed();
        let reads = backend.output_reads.clone();
        let bridge = EnvironmentSessionBridge::new(backend);
        for allow_history_gap in [false, true] {
            let message = proto::ReadSessionOutputRequest {
                org_id: "org-1".into(),
                environment_id: "environment-1".into(),
                session_id: "session-1".into(),
                offset: 19,
                limit: 23,
                allow_history_gap,
                ..Default::default()
            };
            let body = bytes::Bytes::from(message.encode_to_vec());
            let view = proto::ReadSessionOutputRequest::decode_view(&body).unwrap();
            let request = ServiceRequest::from_parts(&view, &body);
            proto::EnvironmentSessionService::read_session_output(
                &bridge,
                RequestContext::default(),
                request,
            )
            .await
            .unwrap();
        }
        let reads = reads.lock().await;
        assert_eq!(reads.len(), 2);
        assert!(!reads[0].allow_history_gap);
        assert!(reads[1].allow_history_gap);
        assert!(
            reads
                .iter()
                .all(|request| request.offset == 19 && request.limit == 23)
        );
    }

    #[tokio::test]
    async fn queued_nonterminal_status_is_not_promoted_ahead_of_output() {
        let mut attachment = RecordingAttachment {
            inputs: Arc::new(Mutex::new(Vec::new())),
            half_closed: Arc::new(AtomicBool::new(true)),
            half_close_notify: Arc::new(Notify::new()),
            outputs: VecDeque::new(),
            session_result: Ok(v1::SessionRecord {
                session_id: "session-1".into(),
                state: v1::SessionLifecycleState::Exited as i32,
                exit_code: Some(0),
                output_end_offset: 12,
                status_message: "session exited with status 0".into(),
                finished_at: Some(prost_types::Timestamp::default()),
                ..Default::default()
            }),
        };
        let output = v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Status(
                v1::SessionStatus {
                    session_id: "session-1".into(),
                    state: v1::SessionLifecycleState::Running as i32,
                    exit_code: None,
                    output_end_offset: 0,
                    output_start_offset: 0,
                    message: "session running".into(),
                },
            )),
        };

        let response = public_attach_output(output, &mut attachment, "session-1")
            .await
            .expect("the streamed running snapshot must remain nonterminal");
        let Some(proto::attach_session_response::Event::Status(status)) = response.event else {
            panic!("bridge response must contain status");
        };
        let session = status.session.into_option().unwrap();
        assert_eq!(
            session.state.as_known(),
            Some(proto::EnvironmentSessionState::Running)
        );
        assert_eq!(session.exit_code, None);
        assert_eq!(session.output_end_offset, 0);
        assert_eq!(session.status_message, "session running");
        assert!(session.finished_at.as_option().is_none());
    }

    #[tokio::test]
    async fn retention_gap_is_forwarded_without_a_session_lookup_and_invalid_gaps_fail() {
        let mut attachment = RecordingAttachment {
            inputs: Arc::new(Mutex::new(Vec::new())),
            half_closed: Arc::new(AtomicBool::new(true)),
            half_close_notify: Arc::new(Notify::new()),
            outputs: VecDeque::new(),
            session_result: Err(connectrpc::ConnectError::new(
                ErrorCode::Unavailable,
                "unused lookup",
            )),
        };
        for (requested_offset, retained_start_offset, valid) in
            [(0, 4096, true), (4096, 4096, false), (4097, 4096, false)]
        {
            let result = public_attach_output(
                v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::HistoryGap(
                        v1::SessionOutputGap {
                            requested_offset,
                            retained_start_offset,
                        },
                    )),
                },
                &mut attachment,
                "session-1",
            )
            .await;
            if valid {
                let Some(proto::attach_session_response::Event::HistoryGap(gap)) =
                    result.expect("valid gap").event
                else {
                    panic!("expected gap");
                };
                assert_eq!(gap.requested_offset, requested_offset);
                assert_eq!(gap.retained_start_offset, retained_start_offset);
            } else {
                assert!(matches!(result, Err(AttachOutputError::InvalidFrame)));
            }
        }
    }

    #[tokio::test]
    async fn status_lookup_errors_are_not_reclassified_as_invalid_frames() {
        let mut attachment = RecordingAttachment {
            inputs: Arc::new(Mutex::new(Vec::new())),
            half_closed: Arc::new(AtomicBool::new(true)),
            half_close_notify: Arc::new(Notify::new()),
            outputs: VecDeque::new(),
            session_result: Err(connectrpc::ConnectError::new(
                ErrorCode::Unavailable,
                "daemon disconnected",
            )),
        };
        let output = v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Status(
                v1::SessionStatus {
                    session_id: "session-1".into(),
                    state: v1::SessionLifecycleState::Running as i32,
                    ..Default::default()
                },
            )),
        };

        match public_attach_output(output, &mut attachment, "session-1").await {
            Err(AttachOutputError::Backend(error)) => {
                assert_eq!(error.code, ErrorCode::Unavailable);
                assert_eq!(error.message.as_deref(), Some("daemon disconnected"));
            }
            _ => panic!("status lookup error must remain a backend error"),
        }
    }

    #[test]
    fn validation_collects_all_coordinate_and_command_failures() {
        let violations = launch_violations(&proto::LaunchSessionRequest::default());
        assert_eq!(
            violations,
            vec![
                violation("/org_id", "must not be empty"),
                violation("/environment_id", "must not be empty"),
                violation("/command", "must not be empty"),
            ]
        );
    }

    #[test]
    fn every_generated_session_route_is_owned_by_the_bridge() {
        let expected = [
            proto::ENVIRONMENT_SESSION_SERVICE_LAUNCH_SESSION_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_LIST_SESSIONS_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_GET_SESSION_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_STOP_SESSION_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_RESTART_SESSION_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_SEND_SESSION_INPUT_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_READ_SESSION_OUTPUT_SPEC,
            proto::ENVIRONMENT_SESSION_SERVICE_ATTACH_SESSION_SPEC,
        ]
        .into_iter()
        .map(|spec| spec.method().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
        let actual = descriptor()
            .file
            .iter()
            .filter(|file| file.package.as_deref() == Some("codewire.v1"))
            .flat_map(|file| &file.service)
            .find(|service| service.name.as_deref() == Some("EnvironmentSessionService"))
            .unwrap()
            .method
            .iter()
            .map(|method| method.name.as_deref().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(expected.len(), 8);
    }

    #[test]
    fn every_reachable_public_session_field_has_an_explicit_mapping() {
        let descriptor = descriptor();
        let messages = descriptor
            .file
            .iter()
            .flat_map(|file| {
                let package = file.package.as_deref().unwrap_or_default();
                file.message_type.iter().map(move |message| {
                    (
                        format!("{package}.{}", message.name.as_deref().unwrap()),
                        message,
                    )
                })
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (name, expected) in MESSAGE_FIELDS {
            let actual = messages
                .get(*name)
                .unwrap_or_else(|| panic!("missing descriptor message {name}"))
                .field
                .iter()
                .map(|field| (field.number.unwrap(), field.name.as_deref().unwrap()))
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                actual,
                expected.iter().copied().collect(),
                "field mapping drift for {name}"
            );
        }
    }

    #[test]
    fn private_records_convert_without_changing_byte_offsets() {
        let record = v1::SessionRecord {
            session_id: "session-1".into(),
            name: "label".into(),
            parent_session_id: Some("session-parent".into()),
            cleanup_unknown: true,
            launch_generation: 123,
            state: v1::SessionLifecycleState::Running as i32,
            command: vec!["sh".into()],
            working_dir: "/workspace".into(),
            pty: true,
            output_end_offset: 41,
            output_start_offset: 19,
            ..Default::default()
        };
        let public = public_session(record);
        assert_eq!(public.session_id, "session-1");
        assert_eq!(public.name, "label");
        assert_eq!(public.parent_session_id.as_deref(), Some("session-parent"));
        assert!(public.cleanup_unknown);
        assert_eq!(public.launch_generation, 123);
        assert_eq!(
            public.state.as_known(),
            Some(proto::EnvironmentSessionState::Running)
        );
        assert_eq!(public.output_end_offset, 41);
        assert_eq!(public.output_start_offset, 19);
    }
}
