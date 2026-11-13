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
    Host, HostAttached, HostLimits, HostPlatform, HostState, LeaveHostRequest, ListHostsRequest,
    RevokeHostGrantRequest, RevokeHostRequest, UpdateHostProvideRequest, attach_host_request,
    attach_host_response, grant_host_request, revoke_host_grant_request,
};
use codewire_proto::codewire::v1::{
    AttachHostResponseView, HostAgentServiceClient, HostServiceClient,
};
use codewire_proto::codewire::v1::{HostAttachOpen, HostAttachProof, HostHello};
use connectrpc::client::{BidiStream, CallOptions};

use crate::{
    ClientConfig, ClientError, ErrorCode, ReqwestConnectTransport, TokenProvider,
    default_http_client,
};

/// The first line of the statement a computer signs to enroll.
pub const ENROLLMENT_STATEMENT_CONTEXT: &str = "codewire-host-enroll-v1";
/// The first line of the statement a host signs to attach.
pub const ATTACH_STATEMENT_CONTEXT: &str = "codewire-host-attach-v1";

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
            hosts: HostServiceClient::new(ReqwestConnectTransport(http), config.connect_config()?),
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
                ReqwestConnectTransport(http),
                config.environment_session_connect_config()?,
            ),
        })
    }

    /// Opens a session for `host_id`, proves the key with `sign`, and says
    /// hello. `sign` returns the Ed25519 signature of the bytes it is given.
    pub async fn attach(
        &self,
        host_id: &str,
        platform: HostPlatform,
        capability_version: u32,
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
            // Sent only to a host of capability version 2 or later.
            Some(attach_host_response::Output::Operation(_)) => {
                return Err(unexpected("an operation"));
            }
            Some(attach_host_response::Output::OpenTunnel(_)) => {
                return Err(unexpected("a tunnel"));
            }
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
    }
}
