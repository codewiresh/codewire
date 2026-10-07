//! Bounded public transport adapter over the existing isolated broker owner.

use std::collections::BTreeSet;
use std::sync::Arc;

use buffa::Message as _;
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::platform::PlatformRuntimeError;
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};
use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_project::PlatformProjectionSelection;
use codewire_protected_store::secret_envelope::KekProvider;
use codewire_proto::codewire::v1::{self as proto, CredentialDelegationService};
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::{
    ConnectAuthLayer, ProtocolPolicy, connect_router_with_auth_protocol_and_limits,
    oauth_bearer_authority,
};
use codewire_workload_secrets::MAX_WORKLOAD_SECRETS;
use connectrpc::{InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt;
use prost::Message as _;
use sqlx::PgPool;
use tonic::Status;
use uuid::Uuid;

use super::{OwnerLocalRuntimeAuthority, OwnerLocalSelection};

mod lifetime;

// One small names-only selection, followed by exactly one existing bridge
// frame per envelope. Eight bytes covers the enclosing tag/length prefix;
// oversized input is rejected by the dispatcher before a message is allocated.
const MAX_SELECTION_BYTES: usize = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 8;

pub(crate) fn router<A, U>(
    pool: PgPool,
    provider: Arc<dyn KekProvider>,
    bridge: PlatformCredentialBridgeService<A, U>,
) -> axum::Router
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    let service = Arc::new(Service {
        pool: pool.clone(),
        provider,
        bridge,
    });
    connect_router_with_auth_protocol_and_limits(
        connectrpc::Router::new().add_service(service),
        ConnectAuthLayer::oauth_bearer_only(AuthState { pool }),
        ProtocolPolicy::ConnectAndGrpc,
        connectrpc::Limits::default().with_max_message_size(MAX_ENVELOPE_BYTES),
    )
    .layer(axum::middleware::from_fn(lifetime::bind))
}

struct Service<A, U> {
    pool: PgPool,
    provider: Arc<dyn KekProvider>,
    bridge: PlatformCredentialBridgeService<A, U>,
}

#[allow(refining_impl_trait)]
impl<A, U> CredentialDelegationService for Service<A, U>
where
    A: PlatformBridgeAuthenticator + 'static,
    U: BrokerUpstreamTransport + Clone + 'static,
{
    async fn delegate_credentials(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::DelegateCredentialsRequest>,
    ) -> ServiceResult<ServiceStream<proto::DelegateCredentialsResponse>> {
        let admission_guard = lifetime::admission_guard(&ctx).ok_or_else(|| {
            connectrpc::ConnectError::internal("credential delegation lifetime unavailable")
        })?;
        let oauth = oauth_bearer_authority(&ctx)?.clone();
        // Retain only the original opaque authority, never request headers.
        drop(ctx);
        let mut admitted = None;
        // The owner-local epoch's expiry needs no early successor here.
        let (output, _expires_at_unix) = self
            .bridge
            .serve_authenticated(async {
                // This future is first polled AFTER the existing shared stream
                // permit and admission deadline have been acquired.
                let first = requests
                    .next()
                    .await
                    .ok_or(PlatformBridgeAuthenticationError::Denied)?
                    .map_err(|_| PlatformBridgeAuthenticationError::Denied)?;
                if first.bytes().len() > MAX_SELECTION_BYTES {
                    return Err(PlatformBridgeAuthenticationError::Denied);
                }
                let first = first.to_owned_message();
                let Some(proto::delegate_credentials_request::Input::Open(open)) = first.input
                else {
                    return Err(PlatformBridgeAuthenticationError::Denied);
                };
                let selection = selection((*open).clone(), oauth.user_id())?;
                admitted = Some(open);
                let expiry = u64::try_from(oauth.expires_at().timestamp())
                    .map_err(|_| PlatformBridgeAuthenticationError::Denied)?;
                let authority = OwnerLocalRuntimeAuthority::new(
                    self.pool.clone(),
                    self.provider.clone(),
                    PlatformAccessProfileStore::new(
                        self.pool.clone(),
                        codewire_access::builtin_provider_catalog(),
                    ),
                    oauth,
                    selection,
                    expiry,
                )
                .await
                .map_err(authority_error)?;
                let input = requests.map(|item| {
                    let item = item.map_err(|_| {
                        Status::unavailable("credential delegation input unavailable")
                    })?;
                    if item.bytes().len() > MAX_ENVELOPE_BYTES {
                        return Err(Status::resource_exhausted(
                            "credential delegation frame exceeds limit",
                        ));
                    }
                    decode_frame(item.to_owned_message())
                });
                Ok((authority, input))
            })
            .await
            .map_err(wire_error)?;
        admission_guard.disarm();
        let admitted = admitted.ok_or_else(|| {
            connectrpc::ConnectError::internal("credential delegation admission unavailable")
        })?;
        let acknowledgment = proto::DelegateCredentialsResponse {
            output: Some(proto::delegate_credentials_response::Output::Admitted(
                admitted,
            )),
            ..Default::default()
        };
        // The generated response owns the SAME bounded receiver. Its drop
        // closes the broker output; no detached intermediate forwarding task.
        connectrpc::Response::stream_ok(
            futures::stream::once(async { Ok(acknowledgment) })
                .chain(output.map(|item| encode_frame(item.map_err(wire_error)?))),
        )
    }
}

fn selection(
    open: proto::CredentialDelegationOpen,
    user_id: &str,
) -> Result<OwnerLocalSelection, PlatformBridgeAuthenticationError> {
    use PlatformBridgeAuthenticationError::Denied;
    let runtime = open.runtime.into_option().ok_or(Denied)?;
    if runtime.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION {
        return Err(Denied);
    }
    let environment = Uuid::parse_str(&runtime.environment_id).map_err(|_| Denied)?;
    if environment.is_nil() || environment.to_string() != runtime.environment_id {
        return Err(Denied);
    }
    let names = |keys: Vec<String>| {
        if keys.len() > MAX_WORKLOAD_SECRETS {
            return Err(Denied);
        }
        let count = keys.len();
        let keys: BTreeSet<_> = keys.into_iter().collect();
        if keys.len() != count {
            return Err(Denied);
        }
        Ok(keys)
    };
    let platform = PlatformProjectionSelection {
        creator: user_id.to_owned(),
        organization: open.org_id,
        organization_selected: open.organization_secrets,
        project_id: open.project_id,
        user_selected: open.user_secrets,
        profile: open
            .profile
            .into_option()
            .map(|profile| (profile.profile_id, profile.profile_revision)),
        ordinary_keys: names(open.ordinary_environment_keys)?,
        reserved_keys: names(open.reserved_environment_keys)?,
    };
    let hash = open.selection_sha256.try_into().map_err(|_| Denied)?;
    OwnerLocalSelection::new(environment, runtime.environment_generation, platform, hash)
        .map_err(authority_error)
}

fn decode_frame(
    request: proto::DelegateCredentialsRequest,
) -> Result<bridge::CredentialBridgeGuestMessage, Status> {
    let Some(proto::delegate_credentials_request::Input::Frame(frame)) = request.input else {
        return Err(Status::permission_denied(
            "credential delegation requires a bridge frame",
        ));
    };
    if frame.payload.is_none()
        || frame.encoded_len() as usize > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
    {
        return Err(Status::permission_denied(
            "credential delegation frame is invalid",
        ));
    }
    // Two generated Rust codecs consume the SAME canonical proto. Bound before
    // encoding/allocation; never JSON-map or duplicate provider frame schemas.
    let bytes = frame.encode_to_vec();
    let frame = bridge::CredentialBridgeGuestMessage::decode(bytes.as_slice())
        .map_err(|_| Status::permission_denied("credential delegation frame is invalid"))?;
    if frame.payload.is_none() {
        return Err(Status::permission_denied(
            "credential delegation frame is invalid",
        ));
    }
    Ok(frame)
}

fn encode_frame(
    frame: bridge::CredentialBridgeHostMessage,
) -> Result<proto::DelegateCredentialsResponse, connectrpc::ConnectError> {
    if frame.encoded_len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        || frame.payload.is_none()
        || matches!(
            frame.payload,
            Some(bridge::credential_bridge_host_message::Payload::Open(_))
        )
    {
        return Err(connectrpc::ConnectError::internal(
            "credential delegation response is invalid",
        ));
    }
    let bytes = frame.encode_to_vec();
    let frame = <codewire_proto::codewire::bridge::v1::CredentialBridgeHostMessage as buffa::Message>::decode_from_slice(&bytes)
        .map_err(|_| connectrpc::ConnectError::internal("credential delegation response is invalid"))?;
    Ok(proto::DelegateCredentialsResponse {
        output: Some(proto::delegate_credentials_response::Output::Frame(
            Box::new(frame),
        )),
        ..Default::default()
    })
}

fn authority_error(error: PlatformRuntimeError) -> PlatformBridgeAuthenticationError {
    match error {
        PlatformRuntimeError::Denied => PlatformBridgeAuthenticationError::Denied,
        PlatformRuntimeError::Unavailable => PlatformBridgeAuthenticationError::Unavailable,
    }
}

fn wire_error(status: Status) -> connectrpc::ConnectError {
    // Never return arbitrary incoming status messages or upstream diagnostics.
    match status.code() {
        tonic::Code::Unauthenticated => {
            connectrpc::ConnectError::unauthenticated("credential delegation requires owner OAuth")
        }
        tonic::Code::PermissionDenied | tonic::Code::InvalidArgument => {
            connectrpc::ConnectError::permission_denied("credential delegation denied")
        }
        tonic::Code::ResourceExhausted => {
            connectrpc::ConnectError::resource_exhausted("credential delegation capacity reached")
        }
        tonic::Code::DeadlineExceeded => {
            connectrpc::ConnectError::deadline_exceeded("credential delegation admission expired")
        }
        _ => connectrpc::ConnectError::unavailable("credential delegation unavailable"),
    }
}

#[cfg(test)]
mod tests;
