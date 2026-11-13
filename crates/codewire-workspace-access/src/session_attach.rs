//! The `session@codewire.sh` SSH subsystem: attach to one of the
//! environment's durable sessions over its own SSH server (#3827), so
//! `cw shell` reaches it over the tailnet's direct path instead of through
//! the API.
//!
//! A client reaches this server only on the environment's tailnet, which the
//! coordinator admits (and keeps re-checking, #3828) only for principals with
//! operator access to the environment, or through orchestration's
//! operator-checked SSH proxy. That is the rule the API applies to
//! `AttachSession`. Sessions are environment-scoped, so such a principal may
//! attach to any of them, on both paths (owner, 2026-11-01, on #3827).
//!
//! The wire is `codewire_client::session_wire`: the public attach messages,
//! converted to and from the daemon's by the same functions the API relay
//! uses. Launch, list, stop and restart stay on the API, with its admission
//! checks; this subsystem only attaches.

use async_trait::async_trait;
use codewire_client::session_wire::{
    FrameDecoder, FrameError, TEMPORARY_FAILURE_EXIT, encode_frame,
};
use codewire_client::{AttachSessionRequest, attach_session_request};
use codewire_daemon::client::{SessionAttachment, SessionAttachmentInput, SessionClient};
use codewire_daemon_bridge::session::{
    AttachOutputError, EnvironmentSessionAttachment, FieldViolation, coordinate_violations,
    private_attach_input, private_attach_start, public_attach_output,
};
use codewire_daemon_proto::daemon::v1;
use connectrpc::ConnectError;
use russh::server::{Handle, Msg};
use russh::{Channel, ChannelId, ChannelMsg};

/// Serves one `session@codewire.sh` channel until it closes.
#[async_trait]
pub trait SessionAttachRunner: Send + Sync + 'static {
    async fn attach_session(&self, channel: Channel<Msg>, handle: Handle);
}

/// Attaches through the workspace daemon's own session client.
pub struct DaemonSessionAttachRunner {
    client: SessionClient,
    environment_id: String,
}

impl DaemonSessionAttachRunner {
    pub fn new(client: SessionClient, environment_id: impl Into<String>) -> Self {
        Self {
            client,
            environment_id: environment_id.into(),
        }
    }

    async fn relay(&self, channel: &mut Channel<Msg>, handle: &Handle) -> Result<(), RelayEnd> {
        let id = channel.id();
        let mut frames = FrameDecoder::default();
        let first = loop {
            if let Some(request) = frames
                .next_message::<AttachSessionRequest>()
                .map_err(frame_error)?
            {
                break request;
            }
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => frames.push(&data),
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => return Ok(()),
                Some(_) => {}
            }
        };
        let Some(attach_session_request::Input::Open(open)) = first.input else {
            return Err(RelayEnd::refused("open must be the first message"));
        };
        if let Some(violation) =
            coordinate_violations(&open.org_id, &open.environment_id, Some(&open.session_id))
                .first()
        {
            return Err(RelayEnd::refused(violation_message(violation)));
        }
        if open.environment_id != self.environment_id {
            return Err(RelayEnd::refused(format!(
                "this SSH server serves environment {}, not {}",
                self.environment_id, open.environment_id
            )));
        }
        let start = private_attach_start(&open);
        let session_id = open.session_id;
        let attachment = self
            .client
            .attach_from(start)
            .await
            .map_err(|error| match &error {
                codewire_daemon::client::SessionClientError::Status(status)
                    if status.code() == tonic::Code::NotFound =>
                {
                    RelayEnd::refused(format!("session {session_id} not found"))
                }
                _ => RelayEnd::temporary(format!("session {session_id} could not be attached")),
            })?;
        let mut attachment = DaemonAttachment {
            input: attachment.input_handle(),
            attachment,
            client: self.client.clone(),
        };
        // Like the API relay, input that ends leaves output flowing; the
        // channel closing detaches, and the session keeps running.
        let mut input_open = true;
        loop {
            while let Some(request) = frames
                .next_message::<AttachSessionRequest>()
                .map_err(frame_error)?
            {
                let message = private_attach_input(request, &session_id).map_err(|violations| {
                    RelayEnd::refused(
                        violations
                            .first()
                            .map(violation_message)
                            .unwrap_or_else(|| "invalid attach input".into()),
                    )
                })?;
                attachment
                    .send_input(message)
                    .await
                    .map_err(|_| RelayEnd::temporary("the session stopped accepting input"))?;
            }
            tokio::select! {
                message = channel.wait() => match message {
                    Some(ChannelMsg::Data { data }) if input_open => frames.push(&data),
                    Some(ChannelMsg::Eof) => input_open = false,
                    Some(ChannelMsg::Close) | None => return Ok(()),
                    Some(_) => {}
                },
                output = attachment.next_output() => {
                    let output = match output {
                        Ok(Some(output)) => output,
                        Ok(None) => return Ok(()),
                        Err(error) => return Err(RelayEnd::from_daemon(&error)),
                    };
                    let response = public_attach_output(output, &mut attachment, &session_id)
                        .await
                        .map_err(|error| match error {
                            // The daemon couldn't say what the session is.
                            AttachOutputError::Backend(error) => RelayEnd::from_daemon(&error),
                            AttachOutputError::InvalidFrame => {
                                RelayEnd::refused("the session attachment sent an invalid frame")
                            }
                        })?;
                    let frame = encode_frame(&response).map_err(frame_error)?;
                    if handle.data(id, frame).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[async_trait]
impl SessionAttachRunner for DaemonSessionAttachRunner {
    async fn attach_session(&self, mut channel: Channel<Msg>, handle: Handle) {
        let id = channel.id();
        let status = match self.relay(&mut channel, &handle).await {
            Ok(()) => 0,
            Err(RelayEnd { message, status }) => {
                tracing::info!(channel = ?id, %message, status, "session attach over SSH ended");
                let _ = handle
                    .extended_data(id, 1, format!("{message}\n").into_bytes())
                    .await;
                status
            }
        };
        end_channel(&handle, id, status).await;
    }
}

async fn end_channel(handle: &Handle, id: ChannelId, status: u32) {
    let _ = handle.exit_status_request(id, status).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// Why the relay ended an attachment: its stderr message and exit status.
/// A daemon that stopped answering, as while the sandbox restarts, ends it
/// with [`TEMPORARY_FAILURE_EXIT`], so the client tries again (#4342); a
/// refusal ends it with 1.
#[derive(Debug, PartialEq)]
struct RelayEnd {
    message: String,
    status: u32,
}

impl RelayEnd {
    fn refused(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: 1,
        }
    }

    fn temporary(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: TEMPORARY_FAILURE_EXIT,
        }
    }

    /// A failure the daemon gave: a session it doesn't have is final;
    /// anything else is the daemon not answering.
    fn from_daemon(error: &ConnectError) -> Self {
        let message = error.message.clone().unwrap_or_default();
        if error.code == connectrpc::ErrorCode::NotFound {
            Self::refused(message)
        } else {
            Self::temporary(message)
        }
    }
}

fn frame_error(error: FrameError) -> RelayEnd {
    RelayEnd::refused(error.to_string())
}

fn violation_message(violation: &FieldViolation) -> String {
    format!("{} {}", violation.path, violation.message)
}

/// The daemon attachment as the bridge's conversions expect it.
struct DaemonAttachment {
    attachment: SessionAttachment,
    input: SessionAttachmentInput,
    client: SessionClient,
}

#[async_trait]
impl EnvironmentSessionAttachment for DaemonAttachment {
    async fn send_input(&self, message: v1::SessionAttachMessage) -> Result<(), ConnectError> {
        let sent = match message.payload {
            Some(v1::session_attach_message::Payload::Input(input)) => {
                self.input.send_session_input(input).await
            }
            Some(v1::session_attach_message::Payload::Resize(resize)) => {
                self.input.resize(resize.width, resize.height).await
            }
            Some(v1::session_attach_message::Payload::Detach(_)) => self.input.detach().await,
            _ => return Err(ConnectError::invalid_argument("unsupported attach input")),
        };
        sent.map_err(|_| ConnectError::unavailable("the session stopped accepting input"))
    }

    async fn next_output(&mut self) -> Result<Option<v1::SessionAttachMessage>, ConnectError> {
        self.attachment
            .next_event()
            .await
            .map_err(|error| match error {
                codewire_daemon::client::SessionClientError::Status(status)
                    if status.code() == tonic::Code::NotFound =>
                {
                    ConnectError::not_found("session not found")
                }
                _ => ConnectError::unavailable("the session attachment ended unexpectedly"),
            })
    }

    async fn session(&mut self, session_id: &str) -> Result<v1::SessionRecord, ConnectError> {
        self.client
            .get(session_id)
            .await
            .map_err(|_| ConnectError::unavailable("the session record is unavailable"))
    }
}
