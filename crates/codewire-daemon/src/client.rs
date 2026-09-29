//! Typed internal client for the environment daemon's durable-session API.
//!
//! This is intentionally separate from the public `codewire-client` facade:
//! local environments use the internal daemon protocol with their managed
//! endpoint and daemon token, while platform environments use Connect through
//! the public environment-session service.

use std::sync::Arc;
use std::time::Duration;

use codewire_gateway_proto::codewire::bridge::v1 as bridge_v1;
pub use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::ssh::{self, SshOperation};
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITY_ATTACH,
    DAEMON_CAPABILITY_SESSIONS,
};
pub use codewire_gateway_proto::{DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const HOSTED_WORKSPACE_AUTHORIZATION: &str = "x-codewire-workspace-authorization-bin";

mod hosted;
pub use hosted::HostedCredentialBridgeDrain;

/// The admitted hosted daemon response, still inactive until the broker opens
/// it. Its request producer remains owned by the separately returned drain.
pub type HostedCredentialBridgePrepared = (
    PreparedHostedCredentialBridge,
    Streaming<bridge_v1::CredentialBridgeGuestMessage>,
);

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

/// Authenticated host side of one generation-bound credential bridge.
///
/// Both directions carry only guest request bytes and broker-redacted response
/// bytes. This API has no credential field; callers must redact all protected
/// material before constructing response headers or body frames.
pub struct CredentialBridgeConnection {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    output: Streaming<bridge_v1::CredentialBridgeGuestMessage>,
}

/// Cloneable response-only half of an authenticated credential bridge.
/// Callers must send only provider-filtered, already-redacted bytes.
#[derive(Clone)]
pub struct CredentialBridgeResponseSender {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    _hosted_lifetime: Option<Arc<hosted::HostedLifetime>>,
}

/// An inactive hosted stream. No Open has been sent and no live daemon epoch
/// replaced. Its fixed-purpose token is never exposed by Debug or a session RPC.
pub struct PreparedHostedCredentialBridge {
    input: mpsc::Sender<bridge_v1::CredentialBridgeHostMessage>,
    ready: bridge_v1::CredentialBridgeReady,
    workspace_authorization: Zeroizing<Vec<u8>>,
    hosted_lifetime: Arc<hosted::HostedLifetime>,
}

impl PreparedHostedCredentialBridge {
    pub fn ready(&self) -> &bridge_v1::CredentialBridgeReady {
        &self.ready
    }
    pub fn workspace_authorization(&self) -> &[u8] {
        &self.workspace_authorization
    }

    /// Call only after the isolated broker returned authenticated admission
    /// headers for this stream's real Ready and both exact Pod tokens.
    pub async fn activate(self) -> Result<CredentialBridgeResponseSender, SessionClientError> {
        self.input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                    bridge_v1::CredentialBridgeOpen {
                        protocol_version: self.ready.protocol_version,
                        environment_id: self.ready.environment_id.clone(),
                        environment_generation: self.ready.environment_generation,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        Ok(CredentialBridgeResponseSender {
            input: self.input,
            _hosted_lifetime: Some(self.hosted_lifetime),
        })
    }
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
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel)
                .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES),
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

    /// Request the trusted guest's fixed lifecycle action, without starting a
    /// workload or resolving application values. VM exit, not this RPC's ACK,
    /// is the runner's completion proof; poweroff may close the transport first.
    pub async fn poweroff_guest(&self) -> Result<(), SessionClientError> {
        self.inner
            .clone()
            .poweroff_guest(self.authorized(v1::PoweroffGuestRequest {}))
            .await?;
        Ok(())
    }

    pub async fn open_credential_bridge(
        &self,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<CredentialBridgeConnection, SessionClientError> {
        if environment_id.is_nil() || environment_generation == 0 {
            return Err(SessionClientError::InvalidCredential);
        }
        let (input, receiver) = mpsc::channel(32);
        input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(bridge_v1::credential_bridge_host_message::Payload::Open(
                    bridge_v1::CredentialBridgeOpen {
                        protocol_version:
                            codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: environment_id.to_string(),
                        environment_generation,
                    },
                )),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let mut client = self.inner.clone();
        let output = client
            .credential_bridge(self.authorized(ReceiverStream::new(receiver)))
            .await?
            .into_inner();
        Ok(CredentialBridgeConnection { input, output })
    }

    /// Prepare the existing private RPC without eagerly sending Open. Hosted
    /// daemons return token metadata and Ready before activation; local daemons
    /// do not support this ordering. The whole preparation has a finite bound.
    pub fn prepare_hosted_credential_bridge(
        &self,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<
        (
            HostedCredentialBridgeDrain,
            impl std::future::Future<
                Output = Result<HostedCredentialBridgePrepared, SessionClientError>,
            > + Send
            + 'static,
        ),
        SessionClientError,
    > {
        if environment_id.is_nil()
            || environment_generation == 0
            || environment_generation > i64::MAX as u64
        {
            return Err(SessionClientError::InvalidCredential);
        }
        let (input, body, hosted_lifetime, drain) = hosted::channel();
        let client_owner = self.clone();
        // The caller owns the drain BEFORE polling any network operation.
        // Dropping this future, a prepared result, or the last response sender
        // cancels the outgoing producer; callers still await its terminal ack.
        let preparation = async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let mut client = client_owner.inner.clone();
                let response = client
                    .credential_bridge(client_owner.authorized(body))
                    .await?;
                let mut values = response
                    .metadata()
                    .get_all_bin(HOSTED_WORKSPACE_AUTHORIZATION)
                    .iter();
                let workspace = match (values.next(), values.next()) {
                    (Some(value), None) => value
                        .to_bytes()
                        .map_err(|_| SessionClientError::InvalidCredential)?,
                    _ => return Err(SessionClientError::InvalidCredential),
                };
                let workspace_authorization = Zeroizing::new(workspace.to_vec());
                let token = workspace_authorization
                    .strip_prefix(b"Bearer ")
                    .ok_or(SessionClientError::InvalidCredential)?;
                if token.is_empty()
                    || token.len() > 16 * 1024
                    || !token.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                {
                    return Err(SessionClientError::InvalidCredential);
                }
                let mut output = response.into_inner();
                let ready = output
                    .message()
                    .await?
                    .ok_or(SessionClientError::RequestClosed)?;
                let Some(bridge_v1::credential_bridge_guest_message::Payload::Ready(ready)) =
                    ready.payload
                else {
                    return Err(SessionClientError::InvalidCredential);
                };
                if ready.protocol_version
                    != codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION
                    || ready.environment_id != environment_id.to_string()
                    || ready.environment_generation != environment_generation
                {
                    return Err(SessionClientError::InvalidCredential);
                }
                Ok((
                    PreparedHostedCredentialBridge {
                        input,
                        ready,
                        workspace_authorization,
                        hosted_lifetime,
                    },
                    output,
                ))
            })
            .await
            .map_err(|_| SessionClientError::Connect)?
        };
        Ok((drain, preparation))
    }

    pub async fn launch(
        &self,
        request: v1::LaunchSessionRequest,
    ) -> Result<v1::SessionRecord, SessionClientError> {
        if !request.name.is_empty() || request.parent_session_id.is_some() {
            self.require_capability(codewire_gateway_proto::DAEMON_CAPABILITY_SESSION_METADATA)
                .await?;
        }
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

    async fn require_capability(&self, capability: &'static str) -> Result<(), SessionClientError> {
        let capabilities = self.get_capabilities(&[capability]).await?;
        Self::validate_capability(capabilities, capability)
    }

    fn validate_capability(
        capabilities: v1::GetCapabilitiesResponse,
        capability: &'static str,
    ) -> Result<(), SessionClientError> {
        if !capabilities
            .capabilities
            .iter()
            .any(|value| value == capability)
        {
            return Err(SessionClientError::MissingCapability { capability });
        }
        if capabilities.state != v1::DaemonState::Ready as i32 {
            return Err(SessionClientError::NotReady {
                message: capabilities.message,
            });
        }
        Ok(())
    }

    /// Acknowledged raw input. An ambiguous timeout is never retried.
    pub async fn send_input(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), SessionClientError> {
        use codewire_gateway_proto::{
            DAEMON_CAPABILITY_SESSION_INPUT, SESSION_INPUT_MAX_BYTES, SESSION_INPUT_TIMEOUT,
        };
        if data.is_empty() || data.len() > SESSION_INPUT_MAX_BYTES {
            return Err(tonic::Status::invalid_argument(
                "session input must contain 1..65536 bytes",
            )
            .into());
        }
        tokio::time::timeout(SESSION_INPUT_TIMEOUT, async {
            self.require_capability(DAEMON_CAPABILITY_SESSION_INPUT).await?;
            let mut client = self.inner.clone();
            let mut request = self.authorized(v1::SendSessionInputRequest { session_id: session_id.into(), data });
            request.set_timeout(SESSION_INPUT_TIMEOUT);
            client.send_session_input(request).await?;
            Ok(())
        }).await.map_err(|_| SessionClientError::Status(tonic::Status::deadline_exceeded(
            "session input acknowledgement timed out; input may have been written; do not retry automatically")))?
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

    /// Start one non-durable exec and close its stdin explicitly.
    ///
    /// The caller must retain and drain (or otherwise keep alive) the returned
    /// stream until the command or its transport ends. This is intended for
    /// private lifecycle control which must not create a user-visible durable
    /// session record.
    pub async fn exec_transient(
        &self,
        request: v1::ExecStartRequest,
    ) -> Result<Streaming<v1::ExecMessage>, SessionClientError> {
        let messages = tokio_stream::iter([
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Start(request)),
            },
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::CloseStdin(())),
            },
        ]);
        let mut client = self.inner.clone();
        Ok(client
            .exec_session(self.authorized(messages))
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

impl CredentialBridgeConnection {
    pub fn response_sender(&self) -> CredentialBridgeResponseSender {
        CredentialBridgeResponseSender {
            input: self.input.clone(),
            _hosted_lifetime: None,
        }
    }

    pub async fn receive(
        &mut self,
    ) -> Result<Option<bridge_v1::CredentialBridgeGuestMessage>, SessionClientError> {
        let message = self
            .output
            .message()
            .await
            .map_err(SessionClientError::from)?;
        if let Some(message) = &message {
            validate_credential_bridge_guest_message(message)?;
        }
        Ok(message)
    }

    pub async fn send_response_start(
        &self,
        response: bridge_v1::CredentialBridgeResponseStart,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_start(response).await
    }

    pub async fn send_response_body(
        &self,
        response: bridge_v1::CredentialBridgeResponseBody,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_body(response).await
    }

    pub async fn send_response_end(
        &self,
        response: bridge_v1::CredentialBridgeResponseEnd,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_end(response).await
    }

    pub async fn send_response_failure(
        &self,
        response: bridge_v1::CredentialBridgeResponseFailure,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_response_failure(response).await
    }

    pub async fn send_ssh(
        &self,
        response: bridge_v1::CredentialSshResponse,
    ) -> Result<(), SessionClientError> {
        self.response_sender().send_ssh(response).await
    }
}

impl CredentialBridgeResponseSender {
    pub async fn send_environment_projection(
        &self,
        response: bridge_v1::EnvironmentProjectionResponse,
    ) -> Result<(), SessionClientError> {
        self.send(
            bridge_v1::credential_bridge_host_message::Payload::EnvironmentProjection(response),
        )
        .await
    }

    pub async fn send_response_start(
        &self,
        response: bridge_v1::CredentialBridgeResponseStart,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseStart(response))
            .await
    }

    pub async fn send_response_body(
        &self,
        response: bridge_v1::CredentialBridgeResponseBody,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseBody(response))
            .await
    }

    pub async fn send_response_end(
        &self,
        response: bridge_v1::CredentialBridgeResponseEnd,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseEnd(response))
            .await
    }

    pub async fn send_response_failure(
        &self,
        response: bridge_v1::CredentialBridgeResponseFailure,
    ) -> Result<(), SessionClientError> {
        self.send(bridge_v1::credential_bridge_host_message::Payload::ResponseFailure(response))
            .await
    }

    /// Forward a response already correlated and validated by the shared
    /// credential bridge. This transport repeats bounded shape validation;
    /// only the shared bridge owns the pending request's operation and may
    /// prove that a failure or success matches it.
    pub async fn send_ssh(
        &self,
        response: bridge_v1::CredentialSshResponse,
    ) -> Result<(), SessionClientError> {
        validate_ssh_response_shape(&response)?;
        self.send(bridge_v1::credential_bridge_host_message::Payload::Ssh(
            response,
        ))
        .await
    }

    async fn send(
        &self,
        payload: bridge_v1::credential_bridge_host_message::Payload,
    ) -> Result<(), SessionClientError> {
        self.input
            .send(bridge_v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .map_err(|_| SessionClientError::RequestClosed)
    }
}

fn validate_credential_bridge_guest_message(
    message: &bridge_v1::CredentialBridgeGuestMessage,
) -> Result<(), SessionClientError> {
    if let Some(bridge_v1::credential_bridge_guest_message::Payload::Ssh(request)) =
        &message.payload
    {
        ssh::validate_request(request).map_err(SessionClientError::Status)?;
    }
    Ok(())
}

fn validate_ssh_response_shape(
    response: &bridge_v1::CredentialSshResponse,
) -> Result<(), SessionClientError> {
    use bridge_v1::credential_ssh_response::Result;
    let operation = match response.result.as_ref() {
        Some(Result::Identity(_)) => SshOperation::Identities,
        Some(Result::Signature(_)) => SshOperation::Sign,
        // A closed failure is valid for either operation. Request correlation
        // remains in CredentialBridge::relay_ssh, not this shallow transport.
        Some(Result::Failure(_)) | None => SshOperation::Identities,
    };
    ssh::validate_response(response, operation).map_err(SessionClientError::Status)
}

#[cfg(test)]
#[path = "client/credential_bridge_tests.rs"]
mod credential_bridge_tests;

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

#[cfg(test)]
mod session_input_capability_tests {
    use super::*;
    #[test]
    fn old_daemon_rejects_new_input_and_metadata_capabilities_before_dispatch() {
        for capability in [
            codewire_gateway_proto::DAEMON_CAPABILITY_SESSION_INPUT,
            codewire_gateway_proto::DAEMON_CAPABILITY_SESSION_METADATA,
        ] {
            let old = v1::GetCapabilitiesResponse {
                state: v1::DaemonState::Ready as i32,
                capabilities: vec![
                    DAEMON_CAPABILITY_SESSIONS.into(),
                    DAEMON_CAPABILITY_ATTACH.into(),
                ],
                ..Default::default()
            };
            assert!(
                matches!(SessionClient::validate_capability(old, capability), Err(SessionClientError::MissingCapability { capability: actual }) if actual == capability)
            );
        }
    }
}
