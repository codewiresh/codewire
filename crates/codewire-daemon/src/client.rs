//! Typed internal client for the environment daemon's durable-session API.
//!
//! This is intentionally separate from the public `codewire-client` facade:
//! local environments use the internal daemon protocol with their managed
//! endpoint and daemon token, while platform environments use Connect through
//! the public environment-session service.

use std::time::Duration;

pub use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITY_ATTACH, DAEMON_CAPABILITY_SESSIONS,
    DAEMON_PROTOCOL_VERSION,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};

#[derive(Debug, thiserror::Error)]
pub enum SessionClientError {
    #[error("daemon endpoint is invalid")]
    InvalidEndpoint,
    #[error("local environment daemon credential is invalid")]
    InvalidCredential,
    #[error("connect to local environment daemon failed")]
    Connect,
    #[error("local environment daemon RPC: {0}")]
    Status(#[from] tonic::Status),
    #[error("local environment daemon request stream is closed")]
    RequestClosed,
    #[error("local environment daemon returned no session record")]
    MissingSessionRecord,
    #[error("local environment daemon is not ready: {message}")]
    NotReady { message: String },
    #[error("local environment daemon does not support required capability {capability}")]
    MissingCapability { capability: &'static str },
}

#[derive(Clone)]
pub struct SessionClient {
    inner: v1::daemon_service_client::DaemonServiceClient<Channel>,
    auth_token: MetadataValue<tonic::metadata::Ascii>,
}

pub struct SessionAttachment {
    input: mpsc::Sender<v1::SessionAttachMessage>,
    output: Streaming<v1::SessionAttachMessage>,
    session_id: String,
}

#[derive(Clone)]
pub struct SessionAttachmentInput {
    input: mpsc::Sender<v1::SessionAttachMessage>,
    session_id: String,
}

impl SessionClient {
    /// Build a daemon client over a caller-provided transport channel.
    ///
    /// The channel may use TCP, a Unix socket, AF_VSOCK, or another tonic
    /// connector. Transport establishment and its host-side authorization are
    /// deliberately owned by the caller; daemon RPC authentication still uses
    /// the supplied token.
    pub fn from_channel(
        channel: Channel,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, SessionClientError> {
        let auth_token = Self::parse_auth_token(daemon_token)?;
        Ok(Self {
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel),
            auth_token,
        })
    }

    pub async fn connect(
        endpoint: impl AsRef<str>,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, SessionClientError> {
        let endpoint = endpoint.as_ref().trim();
        let daemon_token = daemon_token.as_ref().trim();
        if daemon_token.is_empty() {
            return Err(SessionClientError::InvalidCredential);
        }
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(|_| SessionClientError::InvalidEndpoint)?
            .connect_timeout(Duration::from_secs(3))
            .connect()
            .await
            .map_err(|_| SessionClientError::Connect)?;
        Self::from_channel(channel, daemon_token)
    }

    fn parse_auth_token(
        daemon_token: impl AsRef<str>,
    ) -> Result<MetadataValue<tonic::metadata::Ascii>, SessionClientError> {
        let daemon_token = daemon_token.as_ref().trim();
        if daemon_token.is_empty() {
            return Err(SessionClientError::InvalidCredential);
        }
        let mut auth_token = MetadataValue::try_from(daemon_token)
            .map_err(|_| SessionClientError::InvalidCredential)?;
        auth_token.set_sensitive(true);
        Ok(auth_token)
    }

    pub async fn require_ready(&self) -> Result<(), SessionClientError> {
        let response = self
            .get_capabilities(&[DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH])
            .await?;
        if response.state != v1::DaemonState::Ready as i32 {
            return Err(SessionClientError::NotReady {
                message: response.message,
            });
        }
        for capability in [DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH] {
            if !response
                .capabilities
                .iter()
                .any(|value| value == capability)
            {
                return Err(SessionClientError::MissingCapability { capability });
            }
        }
        Ok(())
    }

    pub async fn get_capabilities(
        &self,
        required_capabilities: &[&str],
    ) -> Result<v1::GetCapabilitiesResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .get_capabilities(
                self.authorized(v1::GetCapabilitiesRequest {
                    protocol_version: DAEMON_PROTOCOL_VERSION,
                    required_capabilities: required_capabilities
                        .iter()
                        .map(|capability| (*capability).to_string())
                        .collect(),
                }),
            )
            .await?
            .into_inner())
    }

    pub async fn get_health(&self) -> Result<v1::GetHealthResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .get_health(self.authorized(v1::GetHealthRequest {}))
            .await?
            .into_inner())
    }

    pub async fn launch(
        &self,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .launch_session(self.authorized(request))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn list(&self) -> Result<Vec<v1::SessionRecord>, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .list_sessions(self.authorized(v1::ListSessionsRequest {}))
            .await?
            .into_inner()
            .sessions)
    }

    pub async fn get(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .get_session(self.authorized(v1::GetSessionRequest {
                    session_id: session_id.to_string(),
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn stop(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .stop_session(self.authorized(v1::StopSessionRequest {
                    session_id: session_id.to_string(),
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn restart(&self, session_id: &str) -> Result<v1::SessionRecord, SessionClientError> {
        let mut client = self.inner.clone();
        Self::required_session(
            client
                .restart_session(self.authorized(v1::RestartSessionRequest {
                    session_id: session_id.to_string(),
                }))
                .await?
                .into_inner()
                .session,
        )
    }

    pub async fn read_output(
        &self,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, SessionClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .read_session_output(self.authorized(request))
            .await?
            .into_inner())
    }

    pub async fn attach(
        &self,
        session_id: impl Into<String>,
        output_offset: u64,
    ) -> Result<SessionAttachment, SessionClientError> {
        let session_id = session_id.into();
        let (input, rx) = mpsc::channel(32);
        input
            .send(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Attach(
                    v1::AttachSessionRequest {
                        session_id: session_id.clone(),
                        output_offset,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let mut client = self.inner.clone();
        let output = client
            .attach_session(self.authorized(ReceiverStream::new(rx)))
            .await?
            .into_inner();
        Ok(SessionAttachment {
            input,
            output,
            session_id,
        })
    }

    fn required_session(
        session: Option<v1::SessionRecord>,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        session.ok_or(SessionClientError::MissingSessionRecord)
    }

    fn authorized<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, self.auth_token.clone());
        request
    }
}

impl SessionAttachment {
    pub fn input_handle(&self) -> SessionAttachmentInput {
        SessionAttachmentInput {
            input: self.input.clone(),
            session_id: self.session_id.clone(),
        }
    }

    pub async fn next_event(
        &mut self,
    ) -> Result<Option<v1::SessionAttachMessage>, SessionClientError> {
        Ok(self.output.message().await?)
    }
}

impl SessionAttachmentInput {
    pub async fn send_input(&self, data: Vec<u8>) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Input(
            v1::SessionInput { data },
        ))
        .await
    }

    pub async fn resize(&self, width: i32, height: i32) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Resize(
            v1::ResizeRequest { width, height },
        ))
        .await
    }

    pub async fn detach(&self) -> Result<(), SessionClientError> {
        self.send(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest {
                session_id: self.session_id.clone(),
            },
        ))
        .await
    }

    async fn send(
        &self,
        payload: v1::session_attach_message::Payload,
    ) -> Result<(), SessionClientError> {
        self.input
            .send(v1::SessionAttachMessage {
                payload: Some(payload),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)
    }
}
