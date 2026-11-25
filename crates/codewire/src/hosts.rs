//! Hosts (#3609): computers that provide VMs. [`HostClient`] is the signed-in
//! API behind `cw host` and `cw hosts`; [`HostAgentClient`] is the host's own
//! session, which carries no user credential and authenticates the host by
//! its key.
//!
//! Neither holds a host key. Enrollment takes a signature the caller made,
//! and the session asks the caller to sign each challenge, so the key never
//! leaves the code that read it from the protected store.

use std::sync::Arc;

pub use codewire_proto::codewire::v1::{
    AttachHostRequest, AttachHostResponse, EnrollHostRequest, GetHostRequest, GrantHostRequest,
    Host, HostAttached, HostCreate, HostEnvironmentObservation, HostEnvironmentState, HostLimits,
    HostOpenTunnel, HostOperation, HostOperationFailure, HostOperationResult, HostPlatform,
    HostStaleGeneration, HostState, HostTunnelKind, LeaveHostRequest, ListHostsRequest,
    RevokeHostGrantRequest, RevokeHostRequest, UpdateHostProvideRequest, attach_host_request,
    attach_host_response, grant_host_request, host_operation, host_operation_result,
    revoke_host_grant_request,
};
use codewire_proto::codewire::v1::{
    AttachHostResponseView, HostAgentServiceClient, HostServiceClient, OpenHostTunnelResponseView,
};
use codewire_proto::codewire::v1::{
    HostAttachOpen, HostAttachProof, HostHello, HostTunnelOpen, HostTunnelReady,
    OpenHostTunnelRequest, OpenHostTunnelResponse, open_host_tunnel_request,
    open_host_tunnel_response,
};
use connectrpc::client::{BidiStream, CallOptions};

use crate::{
    ClientConfig, ClientError, ErrorCode, ReqwestConnectTransport, TokenProvider,
    default_http_client,
};

/// The first line of the statement a computer signs to enroll.
pub const ENROLLMENT_STATEMENT_CONTEXT: &str = "codewire-host-enroll-v1";
/// The first line of the statement a host signs to attach.
pub const ATTACH_STATEMENT_CONTEXT: &str = "codewire-host-attach-v1";
/// The first line of the statement a host signs to open a tunnel.
pub const TUNNEL_STATEMENT_CONTEXT: &str = "codewire-host-tunnel-v1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes a computer signs to enroll `public_key` for `user_id` in
/// `org_id`. The server checks the same bytes.
pub fn enrollment_statement(org_id: &str, user_id: &str, public_key: &[u8]) -> Vec<u8> {
    format!(
        "{ENROLLMENT_STATEMENT_CONTEXT}\n{org_id}\n{user_id}\n{}\n",
        hex(public_key)
    )
    .into_bytes()
}

/// The bytes a host signs to answer the challenge `nonce`.
pub fn attach_statement(host_id: &str, nonce: &[u8]) -> Vec<u8> {
    format!("{ATTACH_STATEMENT_CONTEXT}\n{host_id}\n{}\n", hex(nonce)).into_bytes()
}

/// The bytes a host signs to open the tunnel `tunnel_id` it was asked for
/// with `nonce`.
pub fn tunnel_statement(host_id: &str, tunnel_id: &str, nonce: &[u8]) -> Vec<u8> {
    format!(
        "{TUNNEL_STATEMENT_CONTEXT}\n{host_id}\n{tunnel_id}\n{}\n",
        hex(nonce)
    )
    .into_bytes()
}

/// The signed-in hosts API.
#[derive(Clone)]
pub struct HostClient {
    hosts: HostServiceClient<ReqwestConnectTransport>,
    token_provider: Arc<dyn TokenProvider>,
}

macro_rules! unary {
    ($name:ident, $call:ident, $request:ty, $response:ty) => {
        pub async fn $name(&self, request: $request) -> Result<$response, ClientError> {
            let options = self.options().await?;
            self.hosts
                .$call(request, options)
                .await
                .map(|response| response.into_owned())
                .map_err(ClientError::from)
        }
    };
}

impl HostClient {
    pub fn new(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
    ) -> Result<Self, ClientError> {
        let http = default_http_client(&config)?;
        Ok(Self {
            hosts: HostServiceClient::new(
                ReqwestConnectTransport::new(http, Some(Arc::clone(&token_provider))),
                config.connect_config()?,
            ),
            token_provider,
        })
    }

    async fn options(&self) -> Result<CallOptions, ClientError> {
        CallOptions::default()
            .try_with_header(
                "authorization",
                self.token_provider.token().await?.authorization_header(),
            )
            .map_err(ClientError::from)
    }

    unary!(
        enroll_host,
        enroll_host_with_options,
        EnrollHostRequest,
        codewire_proto::codewire::v1::EnrollHostResponse
    );
    unary!(
        list_hosts,
        list_hosts_with_options,
        ListHostsRequest,
        codewire_proto::codewire::v1::ListHostsResponse
    );
    unary!(
        get_host,
        get_host_with_options,
        GetHostRequest,
        codewire_proto::codewire::v1::GetHostResponse
    );
    unary!(
        update_host_provide,
        update_host_provide_with_options,
        UpdateHostProvideRequest,
        codewire_proto::codewire::v1::UpdateHostProvideResponse
    );
    unary!(
        grant_host,
        grant_host_with_options,
        GrantHostRequest,
        codewire_proto::codewire::v1::GrantHostResponse
    );
    unary!(
        revoke_host_grant,
        revoke_host_grant_with_options,
        RevokeHostGrantRequest,
        codewire_proto::codewire::v1::RevokeHostGrantResponse
    );
    unary!(
        revoke_host,
        revoke_host_with_options,
        RevokeHostRequest,
        codewire_proto::codewire::v1::RevokeHostResponse
    );
    unary!(
        leave_host,
        leave_host_with_options,
        LeaveHostRequest,
        codewire_proto::codewire::v1::LeaveHostResponse
    );
}

/// The host's session stream.
pub type HostAgentStream =
    BidiStream<reqwest::Body, AttachHostRequest, AttachHostResponseView<'static>>;

/// Opens host sessions. It sends no user credential: the session
/// authenticates the host by the signatures the caller supplies.
#[derive(Clone)]
pub struct HostAgentClient {
    agent: HostAgentServiceClient<ReqwestConnectTransport>,
}

/// What the control plane sent an attached host.
#[derive(Debug)]
pub enum HostEvent {
    Pong,
    /// Sign this nonce with [`AttachedHost::prove`].
    Challenge(Vec<u8>),
    /// The host was revoked; the session is over for good.
    Revoked,
    /// Another session for this host attached, and this one is over.
    Superseded,
    /// Run this lifecycle operation and answer with
    /// [`AttachedHost::send_result`].
    Operation(Box<HostOperation>),
    /// Open this tunnel with [`HostAgentClient::open_tunnel`].
    OpenTunnel(Box<HostOpenTunnel>),
    /// The stream ended without an error.
    Ended,
}

/// An attached host session, after its key was proven.
pub struct AttachedHost {
    stream: HostAgentStream,
    host_id: String,
    pub attached: HostAttached,
}

fn input(input: attach_host_request::Input) -> AttachHostRequest {
    AttachHostRequest {
        input: Some(input),
        ..Default::default()
    }
}

fn unexpected(what: &str) -> ClientError {
    ClientError::new(
        ErrorCode::Internal,
        format!("the host session sent {what} out of order"),
    )
}

async fn next_output(
    stream: &mut HostAgentStream,
) -> Result<Option<attach_host_response::Output>, ClientError> {
    match stream
        .message::<AttachHostResponse>()
        .await
        .map_err(ClientError::from)?
    {
        Some(message) => Ok(message.to_owned_message().output),
        None => match stream.error() {
            Some(error) => Err(ClientError::from(error.clone())),
            None => Ok(None),
        },
    }
}

impl HostAgentClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let http = default_http_client(&config)?;
        Ok(Self {
            agent: HostAgentServiceClient::new(
                ReqwestConnectTransport::new(http, None),
                config.environment_session_connect_config()?,
            ),
        })
    }

    /// Opens a session for `host_id`, proves the key with `sign`, and says
    /// hello with the environments the host has. `sign` returns the Ed25519
    /// signature of the bytes it is given.
    pub async fn attach(
        &self,
        host_id: &str,
        platform: HostPlatform,
        capability_version: u32,
        inventory: Vec<HostEnvironmentObservation>,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Result<AttachedHost, ClientError> {
        let mut stream = self
            .agent
            .attach_host_with_options(CallOptions::default())
            .await
            .map_err(ClientError::from)?;
        stream
            .send(input(attach_host_request::Input::Open(Box::new(
                HostAttachOpen {
                    host_id: host_id.to_owned(),
                    ..Default::default()
                },
            ))))
            .await
            .map_err(ClientError::from)?;
        let Some(attach_host_response::Output::Challenge(challenge)) =
            next_output(&mut stream).await?
        else {
            return Err(unexpected("something other than a challenge"));
        };
        stream
            .send(proof(sign(&attach_statement(host_id, &challenge.nonce))))
            .await
            .map_err(ClientError::from)?;
        let attached = match next_output(&mut stream).await? {
            Some(attach_host_response::Output::Attached(attached)) => *attached,
            Some(attach_host_response::Output::Revoked(_)) => {
                return Err(ClientError::new(
                    ErrorCode::PermissionDenied,
                    "the host is revoked",
                ));
            }
            _ => return Err(unexpected("something other than attached")),
        };
        stream
            .send(input(attach_host_request::Input::Hello(Box::new(
                HostHello {
                    capability_version,
                    platform: platform.into(),
                    inventory,
                    ..Default::default()
                },
            ))))
            .await
            .map_err(ClientError::from)?;
        Ok(AttachedHost {
            stream,
            host_id: host_id.to_owned(),
            attached,
        })
    }
}

/// A tunnel's stream, as the host opened it.
pub type HostTunnelStream =
    BidiStream<reqwest::Body, OpenHostTunnelRequest, OpenHostTunnelResponseView<'static>>;

fn tunnel_input(input: open_host_tunnel_request::Input) -> OpenHostTunnelRequest {
    OpenHostTunnelRequest {
        input: Some(input),
        ..Default::default()
    }
}

impl HostAgentClient {
    /// Opens the tunnel the session asked for in `request`, proving the key
    /// with `sign`. The caller answers with [`HostTunnel::ready`] or
    /// [`HostTunnel::failed`].
    pub async fn open_tunnel(
        &self,
        host_id: &str,
        request: &HostOpenTunnel,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Result<HostTunnel, ClientError> {
        let mut stream = self
            .agent
            .open_host_tunnel_with_options(CallOptions::default())
            .await
            .map_err(ClientError::from)?;
        stream
            .send(tunnel_input(open_host_tunnel_request::Input::Open(
                Box::new(HostTunnelOpen {
                    host_id: host_id.to_owned(),
                    tunnel_id: request.tunnel_id.clone(),
                    signature: sign(&tunnel_statement(
                        host_id,
                        &request.tunnel_id,
                        &request.nonce,
                    )),
                    ..Default::default()
                }),
            )))
            .await
            .map_err(ClientError::from)?;
        Ok(HostTunnel { stream })
    }
}

/// A tunnel the host opened.
pub struct HostTunnel {
    stream: HostTunnelStream,
}

impl HostTunnel {
    /// The host reached the environment: bytes may flow. The caller keeps
    /// the capability in memory it wipes.
    pub async fn ready(&mut self, daemon_capability: &str) -> Result<(), ClientError> {
        self.stream
            .send(tunnel_input(open_host_tunnel_request::Input::Ready(
                Box::new(HostTunnelReady {
                    daemon_capability: daemon_capability.to_owned(),
                    ..Default::default()
                }),
            )))
            .await
            .map_err(ClientError::from)
    }

    /// The host could not reach the environment; the tunnel ends.
    pub async fn failed(&mut self, failure: HostOperationFailure) -> Result<(), ClientError> {
        self.stream
            .send(tunnel_input(open_host_tunnel_request::Input::Failed(
                Box::new(failure),
            )))
            .await
            .map_err(ClientError::from)
    }

    pub async fn send(&mut self, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.stream
            .send(tunnel_input(open_host_tunnel_request::Input::Data(bytes)))
            .await
            .map_err(ClientError::from)
    }

    /// Ends this side of the tunnel; bytes may still arrive.
    pub fn close_send(&mut self) {
        self.stream.close_send();
    }

    /// The next bytes from the control plane; `None` when it ended its side.
    pub async fn receive(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        loop {
            match self
                .stream
                .message::<OpenHostTunnelResponse>()
                .await
                .map_err(ClientError::from)?
            {
                Some(message) => {
                    if let Some(open_host_tunnel_response::Output::Data(bytes)) =
                        message.to_owned_message().output
                    {
                        return Ok(Some(bytes));
                    }
                }
                None => {
                    return match self.stream.error() {
                        Some(error) => Err(ClientError::from(error.clone())),
                        None => Ok(None),
                    };
                }
            }
        }
    }
}

fn proof(signature: Vec<u8>) -> AttachHostRequest {
    input(attach_host_request::Input::Proof(Box::new(
        HostAttachProof {
            signature,
            ..Default::default()
        },
    )))
}

impl AttachedHost {
    pub async fn ping(&mut self) -> Result<(), ClientError> {
        self.stream
            .send(input(attach_host_request::Input::Ping(Box::default())))
            .await
            .map_err(ClientError::from)
    }

    /// Reports how an operation ended.
    pub async fn send_result(&mut self, result: HostOperationResult) -> Result<(), ClientError> {
        self.stream
            .send(input(attach_host_request::Input::OperationResult(
                Box::new(result),
            )))
            .await
            .map_err(ClientError::from)
    }

    /// Reports an environment's state.
    pub async fn send_observed(
        &mut self,
        observation: HostEnvironmentObservation,
    ) -> Result<(), ClientError> {
        self.stream
            .send(input(attach_host_request::Input::EnvironmentObserved(
                Box::new(observation),
            )))
            .await
            .map_err(ClientError::from)
    }

    /// Answers a challenge with `sign`'s signature of its statement.
    pub async fn prove(
        &mut self,
        nonce: &[u8],
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Result<(), ClientError> {
        self.stream
            .send(proof(sign(&attach_statement(&self.host_id, nonce))))
            .await
            .map_err(ClientError::from)
    }

    /// The next thing the control plane sends. An error is how the session
    /// ended.
    pub async fn next_event(&mut self) -> Result<HostEvent, ClientError> {
        Ok(match next_output(&mut self.stream).await? {
            Some(attach_host_response::Output::Pong(_)) => HostEvent::Pong,
            Some(attach_host_response::Output::Challenge(challenge)) => {
                HostEvent::Challenge(challenge.nonce)
            }
            Some(attach_host_response::Output::Revoked(_)) => HostEvent::Revoked,
            Some(attach_host_response::Output::Superseded(_)) => HostEvent::Superseded,
            Some(attach_host_response::Output::Attached(_)) => {
                return Err(unexpected("attached again"));
            }
            Some(attach_host_response::Output::Operation(operation)) => {
                HostEvent::Operation(operation)
            }
            Some(attach_host_response::Output::OpenTunnel(request)) => {
                HostEvent::OpenTunnel(request)
            }
            // Answers to access calls (capability 3), which this host never
            // makes.
            Some(
                attach_host_response::Output::AccessGrant(_)
                | attach_host_response::Output::HostKeyRecorded(_)
                | attach_host_response::Output::PeerRelayAllocation(_)
                | attach_host_response::Output::AccessRefused(_),
            ) => return Err(unexpected("an access answer it never asked for")),
            None => HostEvent::Ended,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The statements are part of the protocol: these bytes are the ones the
    /// server's own tests pin.
    #[test]
    fn statements_match_the_servers_bytes() {
        assert_eq!(
            enrollment_statement("org-1", "user-1", &[0xab, 0x01]),
            b"codewire-host-enroll-v1\norg-1\nuser-1\nab01\n"
        );
        assert_eq!(
            attach_statement("host-1", &[0xab, 0x01]),
            b"codewire-host-attach-v1\nhost-1\nab01\n"
        );
        assert_eq!(
            tunnel_statement("host-1", "tunnel-1", &[0xab, 0x01]),
            b"codewire-host-tunnel-v1\nhost-1\ntunnel-1\nab01\n"
        );
    }
}
