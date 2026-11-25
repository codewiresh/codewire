//! Bounded public transport adapter over the existing isolated broker owner.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use buffa::Message as _;
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::platform::PlatformRuntimeError;
use codewire_credential_broker::platform::bridge::{
    FRONT_DOOR_CAPABILITIES, PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator,
    PlatformCredentialBridgeService,
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
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::{Stream, StreamExt};
use prost::Message as _;
use sqlx::PgPool;
use tokio::sync::mpsc;
use tonic::Status;
use uuid::Uuid;

use super::{OwnerLocalRuntimeAuthority, OwnerLocalSelection};

mod lifetime;
mod seed;

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
        seed_rate: seed::RateLimit::default(),
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
    /// Seed placeholder calls per user (#4001).
    seed_rate: seed::RateLimit,
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
        let (keepalives, answers) = Keepalives::new();
        let mut admitted = None;
        // The owner-local epoch's expiry needs no early successor here.
        // The owner whose local front door may join this epoch (#4909).
        let owner = oauth.user_id().to_owned();
        let (output, _expires_at_unix, front_door_epoch) = self
            .bridge
            .serve_authenticated_delegation(owner, async {
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
                let front_door = open.front_door;
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
                let keepalives = Arc::clone(&keepalives);
                let input = requests.filter_map(move |item| {
                    futures::future::ready(
                        (|| {
                            let item = item.map_err(|_| {
                                Status::unavailable("credential delegation input unavailable")
                            })?;
                            if item.bytes().len() > MAX_ENVELOPE_BYTES {
                                return Err(Status::resource_exhausted(
                                    "credential delegation frame exceeds limit",
                                ));
                            }
                            decode_input(item.to_owned_message(), &keepalives)
                        })()
                        .transpose(),
                    )
                });
                Ok((authority, input, front_door))
            })
            .await
            .map_err(wire_error)?;
        admission_guard.disarm();
        let admitted = admitted.ok_or_else(|| {
            connectrpc::ConnectError::internal("credential delegation admission unavailable")
        })?;
        // Keepalives are accepted from here on: the client sends one only
        // after it reads this acknowledgment.
        keepalives.admit();
        let acknowledgment = proto::DelegateCredentialsResponse {
            output: Some(proto::delegate_credentials_response::Output::Admitted(
                admitted,
            )),
            accepts_keepalive: true,
            front_door_epoch,
            ..Default::default()
        };
        // The generated response owns the SAME bounded receiver. Its drop
        // closes the broker output; no detached intermediate forwarding task.
        connectrpc::Response::stream_ok(futures::stream::once(async { Ok(acknowledgment) }).chain(
            with_keepalive_answers(
                output.map(|item| encode_frame(item.map_err(wire_error)?)),
                answers,
            ),
        ))
    }

    async fn front_door_delegation(
        &self,
        ctx: RequestContext,
        requests: InboundStream<proto::FrontDoorDelegationRequest>,
    ) -> ServiceResult<ServiceStream<proto::FrontDoorDelegationResponse>> {
        let owner = oauth_bearer_authority(&ctx)?.user_id().to_owned();
        let metadata = tonic::metadata::MetadataMap::from_headers(ctx.headers().clone());
        drop(ctx);
        let input = requests
            .map(|item| {
                let item = item
                    .map_err(|_| Status::unavailable("front-door delegation input unavailable"))?;
                if item.bytes().len() > MAX_ENVELOPE_BYTES {
                    return Err(Status::resource_exhausted(
                        "front-door delegation frame exceeds limit",
                    ));
                }
                decode_front_door_frame(item.to_owned_message())
            })
            .boxed();
        let output = self
            .bridge
            .join_delegated_front_door(owner, &metadata, input)
            .await
            .map_err(|status| {
                front_door_refused(&status);
                wire_error(status)
            })?;
        // Only now, with the epoch claimed and the bridge admitted, does the
        // caller learn it joined, and what the epoch serves.
        let admitted = proto::FrontDoorDelegationResponse {
            output: Some(proto::front_door_delegation_response::Output::Admitted(
                Box::new(proto::FrontDoorDelegationAdmitted {
                    capabilities: FRONT_DOOR_CAPABILITIES
                        .iter()
                        .map(|capability| (*capability).to_owned())
                        .collect(),
                    ..Default::default()
                }),
            )),
            ..Default::default()
        };
        connectrpc::Response::stream_ok(
            futures::stream::once(async { Ok(admitted) })
                .chain(output.map(|item| encode_front_door_frame(item.map_err(wire_error)?))),
        )
    }

    async fn environment_credential_placeholders(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::EnvironmentCredentialPlaceholdersRequest>,
    ) -> ServiceResult<proto::EnvironmentCredentialPlaceholdersResponse> {
        let oauth = oauth_bearer_authority(&ctx)?.clone();
        drop(ctx);
        let answer = self
            .seed_placeholders(oauth, request)
            .await
            .map_err(seed::Refusal::status)?;
        Ok(connectrpc::Response::new(answer).with_header("cache-control", "private, no-store"))
    }
}

fn selection(
    open: proto::CredentialDelegationOpen,
    user_id: &str,
) -> Result<OwnerLocalSelection, PlatformBridgeAuthenticationError> {
    use PlatformBridgeAuthenticationError::Denied;
    let runtime = open.runtime.into_option().ok_or(Denied)?;
    // Only orchestration's relay gives a hosted Sandbox placeholders
    // (#4001); a client never sets them.
    if runtime.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        || !runtime.placeholders.is_empty()
    {
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

/// Request keepalives of one stream. They are answered on the response, never
/// passed to the bridge, and accepted only after admission. One answer may be
/// pending: the client waits for it before sending another, so a second one is
/// a protocol fault that ends the stream.
struct Keepalives {
    admitted: AtomicBool,
    answers: mpsc::Sender<()>,
}

impl Keepalives {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (answers, receiver) = mpsc::channel(1);
        (
            Arc::new(Self {
                admitted: AtomicBool::new(false),
                answers,
            }),
            receiver,
        )
    }

    fn admit(&self) {
        self.admitted.store(true, Ordering::Release);
    }

    fn accept(&self) -> Result<(), Status> {
        if !self.admitted.load(Ordering::Acquire) {
            return Err(Status::permission_denied(
                "credential delegation keepalive before admission",
            ));
        }
        match self.answers.try_send(()) {
            // A closed receiver means the response has ended; the input ends too.
            Ok(()) | Err(mpsc::error::TrySendError::Closed(())) => Ok(()),
            Err(mpsc::error::TrySendError::Full(())) => Err(Status::resource_exhausted(
                "credential delegation keepalive already pending",
            )),
        }
    }
}

/// One request: a bridge frame for the broker, or a keepalive answered here
/// (`None`).
fn decode_input(
    request: proto::DelegateCredentialsRequest,
    keepalives: &Keepalives,
) -> Result<Option<bridge::CredentialBridgeGuestMessage>, Status> {
    if matches!(
        request.input,
        Some(proto::delegate_credentials_request::Input::Keepalive(_))
    ) {
        return keepalives.accept().map(|()| None);
    }
    decode_frame(request).map(Some)
}

fn keepalive_answer() -> proto::DelegateCredentialsResponse {
    proto::DelegateCredentialsResponse {
        output: Some(proto::delegate_credentials_response::Output::Keepalive(
            Box::default(),
        )),
        ..Default::default()
    }
}

/// The broker's responses with each keepalive answer merged in. It ends with
/// the broker's responses, whether or not the answer channel has closed.
fn with_keepalive_answers<S>(
    frames: S,
    answers: mpsc::Receiver<()>,
) -> impl Stream<Item = Result<proto::DelegateCredentialsResponse, connectrpc::ConnectError>>
where
    S: Stream<Item = Result<proto::DelegateCredentialsResponse, connectrpc::ConnectError>>
        + Send
        + Unpin,
{
    enum Next<T> {
        Frame(Option<T>),
        Answer(Option<()>),
    }
    futures::stream::unfold(
        (frames, Some(answers)),
        |(mut frames, mut answers)| async move {
            loop {
                let next = {
                    let answer = async {
                        match answers.as_mut() {
                            Some(answers) => answers.recv().await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        biased;
                        frame = frames.next() => Next::Frame(frame),
                        answer = answer => Next::Answer(answer),
                    }
                };
                match next {
                    Next::Frame(frame) => return frame.map(|frame| (frame, (frames, answers))),
                    Next::Answer(Some(())) => {
                        return Some((Ok(keepalive_answer()), (frames, answers)));
                    }
                    Next::Answer(None) => answers = None,
                }
            }
        },
    )
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
    // A front-door session's frames are unknown frames on a delegation.
    if frame
        .payload
        .as_ref()
        .is_none_or(|payload| payload.is_front_door())
    {
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
        || frame
            .payload
            .as_ref()
            .is_some_and(|payload| payload.is_front_door())
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

/// One front-door frame from the local authority, bounded and carried
/// unparsed: the broker's front-door entry decides what it serves.
fn decode_front_door_frame(
    request: proto::FrontDoorDelegationRequest,
) -> Result<bridge::CredentialBridgeGuestMessage, Status> {
    let invalid = || Status::permission_denied("front-door delegation frame is invalid");
    let frame = request.frame.into_option().ok_or_else(invalid)?;
    if frame.payload.is_none()
        || frame.encoded_len() as usize > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
    {
        return Err(invalid());
    }
    let bytes = frame.encode_to_vec();
    bridge::CredentialBridgeGuestMessage::decode(bytes.as_slice()).map_err(|_| invalid())
}

/// One front-door frame from the broker. Never an Open: the local relay
/// writes its session's one Open itself.
fn encode_front_door_frame(
    frame: bridge::CredentialBridgeHostMessage,
) -> Result<proto::FrontDoorDelegationResponse, connectrpc::ConnectError> {
    let invalid =
        || connectrpc::ConnectError::internal("front-door delegation response is invalid");
    if frame.encoded_len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        || frame.payload.is_none()
        || matches!(
            frame.payload,
            Some(bridge::credential_bridge_host_message::Payload::Open(_))
        )
    {
        return Err(invalid());
    }
    let bytes = frame.encode_to_vec();
    let frame = <codewire_proto::codewire::bridge::v1::CredentialBridgeHostMessage as buffa::Message>::decode_from_slice(&bytes)
        .map_err(|_| invalid())?;
    Ok(proto::FrontDoorDelegationResponse {
        output: Some(proto::front_door_delegation_response::Output::Frame(
            Box::new(frame),
        )),
        ..Default::default()
    })
}

/// Counts a refused front-door join by its code, never its handle: an
/// unknown, ended and other owner's handle are one refusal to the caller.
fn front_door_refused(status: &Status) {
    let reason = match status.code() {
        tonic::Code::PermissionDenied => "no_live_epoch",
        tonic::Code::AlreadyExists => "already_joined",
        tonic::Code::DeadlineExceeded => "admission_timed_out",
        _ => "unavailable",
    };
    tracing::warn!(
        event = "front_door_join_refused",
        reason,
        "front-door delegation join refused"
    );
}

fn authority_error(error: PlatformRuntimeError) -> PlatformBridgeAuthenticationError {
    match error {
        PlatformRuntimeError::Denied
        | PlatformRuntimeError::CreatorDeparted
        | PlatformRuntimeError::CreatorDisabled => PlatformBridgeAuthenticationError::Denied,
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
        // A second front-door join of a live epoch (#4909).
        tonic::Code::AlreadyExists => connectrpc::ConnectError::already_exists(
            "this credential delegation already serves a front door",
        ),
        tonic::Code::DeadlineExceeded => {
            connectrpc::ConnectError::deadline_exceeded("credential delegation admission expired")
        }
        _ => connectrpc::ConnectError::unavailable("credential delegation unavailable"),
    }
}

#[cfg(test)]
mod tests;
