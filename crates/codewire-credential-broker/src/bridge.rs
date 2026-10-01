use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use codewire_daemon::client::{
    CredentialBridgeConnection, CredentialBridgeResponseSender, SessionClientError,
};
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADERS, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use codewire_workload_secrets::MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES;
use futures::StreamExt as _;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestError, BrokerUpstreamTransport,
    OpenAiBroker,
};

mod relay;
mod ssh;

pub use relay::{
    CredentialBridgeRelayInput, CredentialBridgeRelayOutput, run_admitted_credential_bridge_relay,
};

/// Stable, value-blind failures for one authenticated broker bridge epoch.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerBridgeError {
    #[error("credential broker bridge identity is invalid")]
    InvalidIdentity,
    #[error("credential broker bridge protocol is invalid")]
    InvalidProtocol,
    #[error("credential broker bridge is unavailable")]
    Unavailable,
}

/// One transport whose first frame matched the protocol and exact environment
/// coordinates supplied by its already-authenticated caller. The Ready frame
/// is not identity proof; peer authentication belongs to the transport owner.
pub struct AdmittedCredentialBridge<B: CredentialBridgeTransport> {
    bridge: B,
    ready: v1::CredentialBridgeReady,
}

impl<B: CredentialBridgeTransport> AdmittedCredentialBridge<B> {
    /// The original Ready from this already-authenticated transport. It is
    /// public binding metadata, not an independent proof of peer identity.
    pub fn ready(&self) -> &v1::CredentialBridgeReady {
        &self.ready
    }
}

struct ActiveRequest {
    incarnation: u64,
    ssh_cancellation: Option<CancellationToken>,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.ssh_cancellation {
            cancellation.cancel();
        }
    }
}

#[async_trait]
pub(crate) trait BrokerRequestExecutor: Send + Sync {
    /// The authority owns any started worker until terminal drain, including
    /// when this waiter is dropped. Cancellation suppresses signatures; it
    /// must not abandon a key-bearing worker or release its capacity early.
    async fn execute_ssh(
        &self,
        _request: v1::CredentialSshRequest,
        _cancellation: CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerRequestError> {
        Err(BrokerRequestError::Denied)
    }

    async fn project_environment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        Err(BrokerRequestError::Denied)
    }

    async fn project_environment_fragment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, BrokerRequestError> {
        Err(BrokerRequestError::Denied)
    }

    async fn execute_request(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError>;

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        Ok(())
    }
}

#[async_trait]
impl<P, U> BrokerRequestExecutor for OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    async fn execute_ssh(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerRequestError> {
        OpenAiBroker::execute_ssh(self, request, cancellation).await
    }

    async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        OpenAiBroker::project_environment(self, request).await
    }

    async fn project_environment_fragment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, BrokerRequestError> {
        OpenAiBroker::project_environment_fragment(self, request).await
    }

    async fn execute_request(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.execute(request).await
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        OpenAiBroker::wait_for_active_operations(self).await
    }
}

/// Credential-free input and response transport for one authenticated epoch.
///
/// Implementations must authenticate the peer before admission, bound encoded
/// messages and buffering, and terminate on transport loss or expiry of their
/// authority. `receive` must be cancellation-safe because the managed loop
/// selects it alongside request completions. Shutdown should end this transport
/// and await the managed runner, not abort the runner and skip its refresh drain.
#[async_trait]
pub trait CredentialBridgeTransport: Send {
    type ResponseSink: CredentialBridgeResponseSink;

    fn response_sink(&self) -> Self::ResponseSink;

    /// Receive the next frame, or EOF when this epoch ends. Discard underlying
    /// error details; they must not retain credentials or transport diagnostics.
    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError>;
}

/// Cloneable, bounded output for already-filtered broker response frames.
///
/// The managed runner sends bounded HTTP, environment-projection and SSH
/// terminals, never Open. Implementations must reject Open, apply backpressure
/// without unbounded buffering, and report epoch loss rather than keep a
/// disconnected send alive.
#[async_trait]
pub trait CredentialBridgeResponseSink: Clone + Send + Sync + 'static {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError>;
}

#[async_trait]
impl CredentialBridgeTransport for CredentialBridgeConnection {
    type ResponseSink = CredentialBridgeResponseSender;

    fn response_sink(&self) -> Self::ResponseSink {
        CredentialBridgeConnection::response_sender(self)
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        CredentialBridgeConnection::receive(self)
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for CredentialBridgeResponseSender {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError> {
        let result: Result<(), SessionClientError> = match payload {
            v1::credential_bridge_host_message::Payload::Ssh(response) => {
                self.send_ssh(response).await
            }
            v1::credential_bridge_host_message::Payload::EnvironmentProjection(response) => {
                self.send_environment_projection(response).await
            }
            v1::credential_bridge_host_message::Payload::ResponseStart(response) => {
                self.send_response_start(response).await
            }
            v1::credential_bridge_host_message::Payload::ResponseBody(response) => {
                self.send_response_body(response).await
            }
            v1::credential_bridge_host_message::Payload::ResponseEnd(response) => {
                self.send_response_end(response).await
            }
            v1::credential_bridge_host_message::Payload::ResponseFailure(response) => {
                self.send_response_failure(response).await
            }
            v1::credential_bridge_host_message::Payload::Open(_) => {
                return Err(BrokerBridgeError::InvalidProtocol);
            }
        };
        result.map_err(|_| BrokerBridgeError::Unavailable)
    }
}

/// Run one exact generation-bound bridge until its peer disconnects or a
/// response task loses the authenticated stream. Concurrent operations are
/// bounded. Guest cancellation ends the caller-side HTTP request, while the
/// broker retains the request slot until any started credential refresh and
/// its filtered response stream finish. The caller must authenticate the peer
/// and supply its authoritative environment coordinates before calling this.
pub async fn run_credential_bridge<P, U, B>(
    broker: OpenAiBroker<P, U>,
    bridge: B,
    environment_id: Uuid,
    environment_generation: u64,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
{
    let bridge = admit_credential_bridge(bridge, environment_id, environment_generation).await?;
    run_admitted_credential_bridge(broker, bridge).await
}

/// Compare the first frame's coordinates with the caller-authenticated peer
/// before reporting readiness or leasing provider material. This function does
/// not authenticate the peer, resolve owners, or authorize request-supplied IDs.
pub async fn admit_credential_bridge<B: CredentialBridgeTransport>(
    bridge: B,
    environment_id: Uuid,
    environment_generation: u64,
) -> Result<AdmittedCredentialBridge<B>, BrokerBridgeError> {
    let (bridge, ready) = admit_bridge(bridge, environment_id, environment_generation).await?;
    Ok(AdmittedCredentialBridge { bridge, ready })
}

/// Run a bridge after [`admit_credential_bridge`] matched its coordinates to
/// the caller-authenticated endpoint. Concurrent operations remain bounded,
/// and a cancelled request remains counted until its broker operation finishes.
/// The owner must await this runner after transport termination so started
/// refresh operations drain; dropping this future is not graceful shutdown.
pub async fn run_admitted_credential_bridge<P, U, B>(
    broker: OpenAiBroker<P, U>,
    bridge: AdmittedCredentialBridge<B>,
) -> Result<(), BrokerBridgeError>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
    B: CredentialBridgeTransport,
{
    let broker = Arc::new(broker);
    run_managed_bridge(broker, bridge.bridge).await
}

#[cfg(test)]
async fn run_bridge<E, B>(
    broker: Arc<E>,
    bridge: B,
    environment_id: Uuid,
    environment_generation: u64,
) -> Result<(), BrokerBridgeError>
where
    E: BrokerRequestExecutor + 'static,
    B: CredentialBridgeTransport,
{
    let bridge = admit_credential_bridge(bridge, environment_id, environment_generation).await?;
    run_managed_bridge(broker, bridge.bridge).await
}

async fn run_managed_bridge<E, B>(broker: Arc<E>, bridge: B) -> Result<(), BrokerBridgeError>
where
    E: BrokerRequestExecutor + 'static,
    B: CredentialBridgeTransport,
{
    let result = run_admitted_bridge(Arc::clone(&broker), bridge).await;
    // Request futures may be aborted when the whole bridge epoch is lost. Once
    // a refresh permit has been returned, its complete provider exchange and
    // terminal action are tracked independently. Drain that work, then any
    // protected-store worker that cannot itself be cancelled, before allowing
    // the lease channel to close and reconcile its exact generation.
    broker
        .wait_for_active_operations()
        .await
        .map_err(|_| BrokerBridgeError::Unavailable)?;
    result
}

async fn admit_bridge<B>(
    mut bridge: B,
    environment_id: Uuid,
    environment_generation: u64,
) -> Result<(B, v1::CredentialBridgeReady), BrokerBridgeError>
where
    B: CredentialBridgeTransport,
{
    if environment_id.is_nil() || environment_generation == 0 {
        return Err(BrokerBridgeError::InvalidIdentity);
    }
    let ready = bridge
        .receive()
        .await
        .map_err(|_| BrokerBridgeError::Unavailable)?
        .ok_or(BrokerBridgeError::Unavailable)?;
    let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) = ready.payload else {
        return Err(BrokerBridgeError::InvalidProtocol);
    };
    if ready.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION {
        return Err(BrokerBridgeError::InvalidProtocol);
    }
    if ready.environment_id != environment_id.to_string()
        || ready.environment_generation != environment_generation
    {
        return Err(BrokerBridgeError::InvalidIdentity);
    }

    Ok((bridge, ready))
}

async fn run_admitted_bridge<E, B>(broker: Arc<E>, mut bridge: B) -> Result<(), BrokerBridgeError>
where
    E: BrokerRequestExecutor + 'static,
    B: CredentialBridgeTransport,
{
    let sender = bridge.response_sink();
    let mut tasks = JoinSet::<(String, u64, Result<(), ()>)>::new();
    let mut active = HashMap::<String, ActiveRequest>::new();
    let mut next_incarnation = 0_u64;
    loop {
        tokio::select! {
            completed = tasks.join_next(), if !tasks.is_empty() => {
                let Some(completed) = completed else {
                    continue;
                };
                match completed {
                    Ok((request_id, incarnation, Ok(()))) => {
                        remove_completed_request(&mut active, &request_id, incarnation);
                    }
                    Ok((request_id, incarnation, Err(()))) => {
                        remove_completed_request(&mut active, &request_id, incarnation);
                        tasks.shutdown().await;
                        return Err(BrokerBridgeError::Unavailable);
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(_) => {
                        tasks.shutdown().await;
                        return Err(BrokerBridgeError::Unavailable);
                    }
                }
            }
            message = bridge.receive() => {
                let message = match message {
                    Ok(Some(message)) => message,
                    Ok(None) | Err(_) => {
                        tasks.shutdown().await;
                        return Err(BrokerBridgeError::Unavailable);
                    }
                };
                match message.payload {
                    Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) => {
                        let request_id = request.request_id.clone();
                        if !codewire_gateway_proto::ssh::valid_request_id(&request_id)
                            || active.contains_key(&request_id)
                        {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::InvalidProtocol);
                        }
                        if active.len() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                            if ssh::send_failure(&sender, request_id, BrokerRequestError::AuthorityUnavailable).await.is_err() {
                                tasks.shutdown().await;
                                return Err(BrokerBridgeError::Unavailable);
                            }
                            continue;
                        }
                        let Some(incarnation) = next_incarnation.checked_add(1) else {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::Unavailable);
                        };
                        next_incarnation = incarnation;
                        let cancellation = CancellationToken::new();
                        let operation_cancel = cancellation.clone();
                        let broker = Arc::clone(&broker);
                        let sender = sender.clone();
                        let completed_id = request_id.clone();
                        tasks.spawn(async move {
                            let result = ssh::serve(&*broker, &sender, request, operation_cancel).await;
                            (completed_id, incarnation, result)
                        });
                        active.insert(request_id, ActiveRequest {
                            incarnation,
                            ssh_cancellation: Some(cancellation),
                        });
                    }
                    Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(request)) => {
                        let request_id = request.request_id.clone();
                        if !Uuid::parse_str(&request_id).is_ok_and(|id| !id.is_nil() && id.to_string() == request_id)
                            || active.contains_key(&request_id)
                        {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::InvalidProtocol);
                        }
                        if active.len() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                            if send_projection_response(&sender, request_id, Err(BrokerRequestError::AuthorityUnavailable)).await.is_err() {
                                tasks.shutdown().await;
                                return Err(BrokerBridgeError::Unavailable);
                            }
                            continue;
                        }
                        let Some(incarnation) = next_incarnation.checked_add(1) else {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::Unavailable);
                        };
                        next_incarnation = incarnation;
                        let broker = Arc::clone(&broker);
                        let sender = sender.clone();
                        let completed_id = request_id.clone();
                        tasks.spawn(async move {
                            let result = if request.local_inventories.is_empty() {
                                let response = broker.project_environment(request).await;
                                send_projection_response(&sender, completed_id.clone(), response).await
                            } else {
                                let response = broker.project_environment_fragment(request).await;
                                send_composition_response(&sender, completed_id.clone(), response).await
                            };
                            (completed_id, incarnation, result)
                        });
                        active.insert(request_id, ActiveRequest { incarnation, ssh_cancellation: None });
                    }
                    Some(v1::credential_bridge_guest_message::Payload::Request(request)) => {
                        let request_id = request.request_id.clone();
                        let canonical_request_id = Uuid::parse_str(&request_id).is_ok_and(|id| {
                            !id.is_nil() && id.to_string() == request_id
                        });
                        if !canonical_request_id || active.contains_key(&request_id) {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::InvalidProtocol);
                        }
                        if active.len() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                            if send_failure(
                                &sender,
                                request_id,
                                BrokerRequestError::AuthorityUnavailable,
                            )
                            .await
                            .is_err()
                            {
                                tasks.shutdown().await;
                                return Err(BrokerBridgeError::Unavailable);
                            }
                            continue;
                        }
                        let Some(incarnation) = next_incarnation.checked_add(1) else {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::Unavailable);
                        };
                        next_incarnation = incarnation;
                        let broker = Arc::clone(&broker);
                        let sender = sender.clone();
                        let completed_id = request_id.clone();
                        let response_id = request_id.clone();
                        let _request_task = tasks.spawn(async move {
                            let result = serve_request(&*broker, &sender, &response_id, request).await;
                            (completed_id, incarnation, result)
                        });
                        active.insert(request_id, ActiveRequest { incarnation, ssh_cancellation: None });
                    }
                    Some(v1::credential_bridge_guest_message::Payload::Cancel(cancel)) => {
                        if !Uuid::parse_str(&cancel.request_id).is_ok_and(|id| {
                            !id.is_nil() && id.to_string() == cancel.request_id
                        }) {
                            tasks.shutdown().await;
                            return Err(BrokerBridgeError::InvalidProtocol);
                        }
                        if let Some(cancellation) = active.get(&cancel.request_id)
                            .and_then(|request| request.ssh_cancellation.as_ref())
                        {
                            cancellation.cancel();
                        }
                        // The caller has already cancelled the guest-facing HTTP
                        // request and deliberately drains late host frames. Keep
                        // this operation and its bounded in-flight slot alive so
                        // cancellation cannot strand an OAuth refresh reservation
                        // or interrupt protected-store staging after rotation.
                    }
                    Some(v1::credential_bridge_guest_message::Payload::Ready(_)) | None => {
                        tasks.shutdown().await;
                        return Err(BrokerBridgeError::InvalidProtocol);
                    }
                }
            }
        }
    }
}

async fn send_projection_response<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    response: Result<Vec<u8>, BrokerRequestError>,
) -> Result<(), ()> {
    use v1::environment_projection_response::Result as ProjectionResult;
    let result = match response {
        Ok(sealed)
            if !sealed.is_empty() && sealed.len() <= MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES =>
        {
            ProjectionResult::SealedProjection(sealed)
        }
        Ok(_) => {
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::ResponseTooLarge as i32)
        }
        Err(BrokerRequestError::InvalidRequest | BrokerRequestError::Denied) => {
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32)
        }
        Err(_) => ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32),
    };
    sender
        .send(
            v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionResponse {
                    request_id,
                    result: Some(result),
                },
            ),
        )
        .await
        .map_err(|_| ())
}

async fn send_composition_response<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    response: Result<v1::EnvironmentProjectionComposition, BrokerRequestError>,
) -> Result<(), ()> {
    match response {
        Ok(response)
            if !response.sealed_platform_fragment.is_empty()
                && response.sealed_platform_fragment.len()
                    <= MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES
                && codewire_gateway_proto::projection::decode_platform_inventories(
                    &response.platform_inventories,
                )
                .is_ok() =>
        {
            sender
                .send(
                    v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                        v1::EnvironmentProjectionResponse {
                            request_id,
                            result: Some(v1::environment_projection_response::Result::Composition(
                                response,
                            )),
                        },
                    ),
                )
                .await
                .map_err(|_| ())
        }
        Ok(_) => {
            send_projection_response(sender, request_id, Err(BrokerRequestError::Denied)).await
        }
        Err(error) => send_projection_response(sender, request_id, Err(error)).await,
    }
}

fn remove_completed_request(
    active: &mut HashMap<String, ActiveRequest>,
    request_id: &str,
    incarnation: u64,
) {
    if active
        .get(request_id)
        .is_some_and(|active| active.incarnation == incarnation)
    {
        active.remove(request_id);
    }
}

async fn serve_request<E, S>(
    broker: &E,
    sender: &S,
    request_id: &str,
    request: v1::CredentialBridgeRequest,
) -> Result<(), ()>
where
    E: BrokerRequestExecutor,
    S: CredentialBridgeResponseSink,
{
    let response = match broker.execute_request(request).await {
        Ok(response) => response,
        Err(error) => return finish_with_failure(sender, request_id.to_owned(), error).await,
    };
    let (status, headers, mut body) = response.into_parts();
    let headers = match response_headers_to_proto(&headers) {
        Ok(headers) => headers,
        Err(error) => return send_failure(sender, request_id.to_owned(), error).await,
    };
    sender
        .send(v1::credential_bridge_host_message::Payload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request_id.to_owned(),
                status_code: u32::from(status.as_u16()),
                headers,
            },
        ))
        .await
        .map_err(|_| ())?;
    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                return finish_with_failure(sender, request_id.to_owned(), error).await;
            }
        };
        for chunk in chunk.chunks(CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES) {
            if chunk.is_empty() {
                continue;
            }
            sender
                .send(v1::credential_bridge_host_message::Payload::ResponseBody(
                    v1::CredentialBridgeResponseBody {
                        request_id: request_id.to_owned(),
                        data: chunk.to_vec(),
                    },
                ))
                .await
                .map_err(|_| ())?;
        }
    }
    sender
        .send(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: request_id.to_owned(),
            },
        ))
        .await
        .map_err(|_| ())
}

async fn finish_with_failure<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    error: BrokerRequestError,
) -> Result<(), ()> {
    send_failure(sender, request_id, error).await?;
    if request_failure_ends_epoch(error) {
        Err(())
    } else {
        Ok(())
    }
}

fn request_failure_ends_epoch(error: BrokerRequestError) -> bool {
    matches!(
        error,
        BrokerRequestError::AuthorityUnavailable | BrokerRequestError::UpstreamFailed
    )
}

fn response_headers_to_proto(
    headers: &http::HeaderMap,
) -> Result<Vec<v1::CredentialHttpHeader>, BrokerRequestError> {
    if headers.len() > CREDENTIAL_BRIDGE_MAX_HEADERS {
        return Err(BrokerRequestError::ResponseTooLarge);
    }
    let mut total = 0_usize;
    let mut result = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
            .ok_or(BrokerRequestError::ResponseTooLarge)?;
        if name.as_str().len() > CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
            || value.as_bytes().len() > CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
            || total > CREDENTIAL_BRIDGE_MAX_HEADER_BYTES
        {
            return Err(BrokerRequestError::ResponseTooLarge);
        }
        result.push(v1::CredentialHttpHeader {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        });
    }
    Ok(result)
}

async fn send_failure<S: CredentialBridgeResponseSink>(
    sender: &S,
    request_id: String,
    error: BrokerRequestError,
) -> Result<(), ()> {
    let reason = match error {
        // HTTP routes answer ReconnectRequired themselves; any other operation
        // keeps the existing closed Denied reason that every daemon decodes.
        BrokerRequestError::InvalidRequest
        | BrokerRequestError::Denied
        | BrokerRequestError::ReconnectRequired => v1::CredentialBridgeFailureReason::Denied,
        BrokerRequestError::AuthorityUnavailable => v1::CredentialBridgeFailureReason::Unavailable,
        BrokerRequestError::UpstreamFailed => v1::CredentialBridgeFailureReason::UpstreamFailed,
        BrokerRequestError::ResponseTooLarge => v1::CredentialBridgeFailureReason::ResponseTooLarge,
    };
    sender
        .send(
            v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id,
                    reason: reason as i32,
                },
            ),
        )
        .await
        .map_err(|_| ())
}

#[cfg(test)]
pub(crate) mod tests {
    mod projection;
    mod ssh;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use bytes::Bytes;
    use futures::stream;
    use http::{HeaderMap, HeaderValue, StatusCode};
    use tokio::sync::{Notify, mpsc};

    use super::*;

    struct FakeBridge {
        input: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
        output: mpsc::Sender<v1::credential_bridge_host_message::Payload>,
    }

    #[derive(Clone)]
    struct FakeSender {
        output: mpsc::Sender<v1::credential_bridge_host_message::Payload>,
    }

    #[async_trait]
    impl CredentialBridgeTransport for FakeBridge {
        type ResponseSink = FakeSender;

        fn response_sink(&self) -> Self::ResponseSink {
            FakeSender {
                output: self.output.clone(),
            }
        }

        async fn receive(
            &mut self,
        ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
            Ok(self.input.recv().await)
        }
    }

    #[async_trait]
    impl CredentialBridgeResponseSink for FakeSender {
        async fn send(
            &self,
            payload: v1::credential_bridge_host_message::Payload,
        ) -> Result<(), BrokerBridgeError> {
            if matches!(
                payload,
                v1::credential_bridge_host_message::Payload::Open(_)
            ) {
                return Err(BrokerBridgeError::InvalidProtocol);
            }
            self.output
                .send(payload)
                .await
                .map_err(|_| BrokerBridgeError::Unavailable)
        }
    }

    struct FakeExecutor {
        slow_started: Arc<AtomicBool>,
    }

    #[async_trait]
    impl BrokerRequestExecutor for FakeExecutor {
        async fn execute_request(
            &self,
            request: v1::CredentialBridgeRequest,
        ) -> Result<BrokerHttpResponse, BrokerRequestError> {
            if request.path == "/upstream-failure" {
                return Err(BrokerRequestError::UpstreamFailed);
            }
            if request.path == "/slow" {
                self.slow_started.store(true, Ordering::Release);
                std::future::pending().await
            }
            let mut headers = HeaderMap::new();
            if request.path == "/large-headers" {
                headers.insert(
                    "x-large",
                    HeaderValue::from_bytes(&vec![
                        b'x';
                        CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES + 1
                    ])
                    .unwrap(),
                );
            } else {
                headers.insert("content-type", HeaderValue::from_static("text/plain"));
            }
            Ok(BrokerHttpResponse::new(
                StatusCode::OK,
                headers,
                Box::pin(stream::iter([Ok(Bytes::from(vec![
                    b'x';
                    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES
                        + 1
                ]))])),
            ))
        }
    }

    struct CompletingExecutor {
        started: Arc<AtomicBool>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl BrokerRequestExecutor for CompletingExecutor {
        async fn execute_request(
            &self,
            _request: v1::CredentialBridgeRequest,
        ) -> Result<BrokerHttpResponse, BrokerRequestError> {
            self.started.store(true, Ordering::Release);
            self.release.notified().await;
            Ok(BrokerHttpResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Box::pin(stream::once(async {
                    Ok(Bytes::from_static(b"late-filtered-response"))
                })),
            ))
        }
    }

    fn ready(environment_id: Uuid, generation: u64) -> v1::CredentialBridgeGuestMessage {
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: environment_id.to_string(),
                    environment_generation: generation,
                },
            )),
        }
    }

    fn request(id: Uuid, path: &str) -> v1::CredentialBridgeGuestMessage {
        request_with_id(id.to_string(), path)
    }

    fn request_with_id(id: String, path: &str) -> v1::CredentialBridgeGuestMessage {
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "codex".into(),
                    route: "openai-api".into(),
                    request_id: id,
                    method: "POST".into(),
                    path: path.into(),
                    query: String::new(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            )),
        }
    }

    pub(crate) async fn run_channel_test_bridge<E>(
        broker: Arc<E>,
        input: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
        output: mpsc::Sender<v1::credential_bridge_host_message::Payload>,
        environment_id: Uuid,
        environment_generation: u64,
    ) -> Result<(), BrokerBridgeError>
    where
        E: BrokerRequestExecutor + 'static,
    {
        run_bridge(
            broker,
            FakeBridge { input, output },
            environment_id,
            environment_generation,
        )
        .await
    }

    #[tokio::test]
    async fn public_transport_admission_consumes_only_matching_ready_coordinates() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(2);
        let (output_tx, mut output_rx) = mpsc::channel(1);
        let next = request(Uuid::new_v4(), "/ok");
        input_tx.send(ready(environment_id, 7)).await.unwrap();
        input_tx.send(next.clone()).await.unwrap();

        // No daemon connection, default generic type or compatibility wrapper
        // is needed. These coordinates stand for the caller's prior identity
        // admission; the Ready frame merely agrees with them.
        let mut admitted = admit_credential_bridge(
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            7,
        )
        .await
        .unwrap();
        assert_eq!(admitted.bridge.receive().await.unwrap(), Some(next));
        assert!(matches!(
            output_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        // A request cannot replace the coordinate handshake on an otherwise
        // authenticated transport, and is never executed during admission.
        let (input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, mut output_rx) = mpsc::channel(1);
        input_tx.send(request(Uuid::new_v4(), "/ok")).await.unwrap();
        let result = admit_credential_bridge(
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            7,
        )
        .await;
        assert!(matches!(result, Err(BrokerBridgeError::InvalidProtocol)));
        assert!(output_rx.recv().await.is_none());
    }

    struct DrainExecutor {
        drain_calls: AtomicUsize,
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl BrokerRequestExecutor for DrainExecutor {
        async fn execute_request(
            &self,
            _request: v1::CredentialBridgeRequest,
        ) -> Result<BrokerHttpResponse, BrokerRequestError> {
            Ok(BrokerHttpResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Box::pin(stream::empty()),
            ))
        }

        async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
            self.drain_calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn generic_transport_input_and_response_loss_await_one_managed_drain() {
        for lose_response in [false, true] {
            let environment_id = Uuid::new_v4();
            let (input_tx, input_rx) = mpsc::channel(2);
            let (output_tx, output_rx) = mpsc::channel(1);
            input_tx.send(ready(environment_id, 8)).await.unwrap();
            let input_guard = if lose_response {
                input_tx.send(request(Uuid::new_v4(), "/ok")).await.unwrap();
                drop(output_rx);
                Some(input_tx)
            } else {
                drop(input_tx);
                None
            };
            let executor = Arc::new(DrainExecutor {
                drain_calls: AtomicUsize::new(0),
                entered: Notify::new(),
                release: Notify::new(),
            });
            let task = tokio::spawn(run_bridge(
                Arc::clone(&executor),
                FakeBridge {
                    input: input_rx,
                    output: output_tx,
                },
                environment_id,
                8,
            ));
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                executor.entered.notified(),
            )
            .await
            .unwrap();
            assert_eq!(executor.drain_calls.load(Ordering::SeqCst), 1);
            assert!(
                !task.is_finished(),
                "epoch returned before its operation drain"
            );
            executor.release.notify_one();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(BrokerBridgeError::Unavailable)
            );
            assert_eq!(executor.drain_calls.load(Ordering::SeqCst), 1);
            drop(input_guard);
        }
    }

    #[tokio::test]
    async fn bridge_validates_identity_and_streams_bounded_frames() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(8);
        let (output_tx, mut output_rx) = mpsc::channel(8);
        let executor = Arc::new(FakeExecutor {
            slow_started: Arc::new(AtomicBool::new(false)),
        });
        let task = tokio::spawn(run_bridge(
            executor,
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            9,
        ));
        let request_id = Uuid::new_v4();
        input_tx.send(ready(environment_id, 9)).await.unwrap();
        input_tx.send(request(request_id, "/ok")).await.unwrap();

        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseStart(
                _
            ))
        ));
        let first = output_rx.recv().await.unwrap();
        let second = output_rx.recv().await.unwrap();
        let end = output_rx.recv().await.unwrap();
        assert!(matches!(
            first,
            v1::credential_bridge_host_message::Payload::ResponseBody(ref body)
                if body.data.len() == CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES
        ));
        assert!(matches!(
            second,
            v1::credential_bridge_host_message::Payload::ResponseBody(ref body)
                if body.data.len() == 1
        ));
        assert!(matches!(
            end,
            v1::credential_bridge_host_message::Payload::ResponseEnd(_)
        ));
        drop(input_tx);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    #[tokio::test]
    async fn guest_cancel_keeps_the_exact_in_flight_slot_reserved() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 3);
        let (output_tx, mut output_rx) = mpsc::channel(8);
        let slow_started = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::clone(&slow_started),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            4,
        ));
        let request_ids = (0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT)
            .map(|_| Uuid::new_v4())
            .collect::<Vec<_>>();
        input_tx.send(ready(environment_id, 4)).await.unwrap();
        for request_id in &request_ids {
            input_tx.send(request(*request_id, "/slow")).await.unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !slow_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        input_tx
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
                    v1::CredentialBridgeCancel {
                        request_id: request_ids[0].to_string(),
                    },
                )),
            })
            .await
            .unwrap();
        let overflow_id = Uuid::new_v4();
        input_tx
            .send(request(overflow_id, "/upstream-failure"))
            .await
            .unwrap();
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id,
                    reason,
                }
            )) if request_id == overflow_id.to_string()
                && reason == v1::CredentialBridgeFailureReason::Unavailable as i32
        ));
        drop(input_tx);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    #[tokio::test]
    async fn guest_cancel_drains_late_frames_until_the_operation_finishes() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(3);
        // Capacity one proves the retained task can make progress only while
        // the peer continues draining each late frame.
        let (output_tx, mut output_rx) = mpsc::channel(1);
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(Notify::new());
        let task = tokio::spawn(run_bridge(
            Arc::new(CompletingExecutor {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            4,
        ));
        let request_id = Uuid::new_v4();
        input_tx.send(ready(environment_id, 4)).await.unwrap();
        input_tx.send(request(request_id, "/slow")).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        input_tx
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
                    v1::CredentialBridgeCancel {
                        request_id: request_id.to_string(),
                    },
                )),
            })
            .await
            .unwrap();
        release.notify_one();

        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseStart(
                v1::CredentialBridgeResponseStart { request_id: id, .. }
            )) if id == request_id.to_string()
        ));
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseBody(
                v1::CredentialBridgeResponseBody { request_id: id, data }
            )) if id == request_id.to_string() && data == b"late-filtered-response"
        ));
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseEnd(
                v1::CredentialBridgeResponseEnd { request_id: id }
            )) if id == request_id.to_string()
        ));
        drop(input_tx);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    #[tokio::test]
    async fn bridge_rejects_a_ready_frame_for_another_generation() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        input_tx.send(ready(environment_id, 2)).await.unwrap();
        let result = run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            3,
        )
        .await;
        assert_eq!(result, Err(BrokerBridgeError::InvalidIdentity));
    }

    #[tokio::test]
    async fn bridge_rejects_an_incompatible_ready_protocol_before_requests() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(1);
        let (output_tx, _output_rx) = mpsc::channel(1);
        let mut incompatible = ready(environment_id, 3);
        let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) =
            incompatible.payload.as_mut()
        else {
            unreachable!();
        };
        ready.protocol_version += 1;
        input_tx.send(incompatible).await.unwrap();
        let result = run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            3,
        )
        .await;
        assert_eq!(result, Err(BrokerBridgeError::InvalidProtocol));
    }

    #[tokio::test]
    async fn request_ids_must_be_non_nil_canonical_uuids() {
        let alternate = Uuid::new_v4().simple().to_string();
        for denied in [Uuid::nil().to_string(), alternate] {
            let environment_id = Uuid::new_v4();
            let (input_tx, input_rx) = mpsc::channel(2);
            let (output_tx, mut output_rx) = mpsc::channel(1);
            let executor = Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            });
            let task = tokio::spawn(run_bridge(
                Arc::clone(&executor),
                FakeBridge {
                    input: input_rx,
                    output: output_tx,
                },
                environment_id,
                3,
            ));
            input_tx.send(ready(environment_id, 3)).await.unwrap();
            input_tx
                .send(request_with_id(denied, "/slow"))
                .await
                .unwrap();
            assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::InvalidProtocol));
            assert!(output_rx.try_recv().is_err());
            assert!(!executor.slow_started.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn stale_completion_cannot_remove_a_reused_request_id() {
        let mut active = HashMap::from([(
            "request".to_owned(),
            ActiveRequest {
                incarnation: 2,
                ssh_cancellation: None,
            },
        )]);
        remove_completed_request(&mut active, "request", 1);
        assert_eq!(
            active.get("request").map(|entry| entry.incarnation),
            Some(2)
        );
        remove_completed_request(&mut active, "request", 2);
        assert!(!active.contains_key("request"));
    }

    #[tokio::test]
    async fn duplicate_request_id_ends_the_epoch_without_an_ambiguous_failure() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(3);
        let (output_tx, mut output_rx) = mpsc::channel(1);
        let slow_started = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::clone(&slow_started),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            3,
        ));
        let request_id = Uuid::new_v4();
        input_tx.send(ready(environment_id, 3)).await.unwrap();
        input_tx.send(request(request_id, "/slow")).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !slow_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        input_tx.send(request(request_id, "/slow")).await.unwrap();
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::InvalidProtocol));
        assert!(output_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn transport_failure_reports_once_and_ends_the_dns_epoch() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(2);
        let (output_tx, mut output_rx) = mpsc::channel(2);
        let task = tokio::spawn(run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            3,
        ));
        let request_id = Uuid::new_v4();
        input_tx.send(ready(environment_id, 3)).await.unwrap();
        input_tx
            .send(request(request_id, "/upstream-failure"))
            .await
            .unwrap();
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure { request_id: id, reason }
            )) if id == request_id.to_string()
                && reason == v1::CredentialBridgeFailureReason::UpstreamFailed as i32
        ));
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    #[tokio::test]
    async fn oversized_filtered_headers_return_a_bounded_failure_frame() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(4);
        let (output_tx, mut output_rx) = mpsc::channel(4);
        let task = tokio::spawn(run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            7,
        ));
        let request_id = Uuid::new_v4();
        input_tx.send(ready(environment_id, 7)).await.unwrap();
        input_tx
            .send(request(request_id, "/large-headers"))
            .await
            .unwrap();
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure { request_id: id, reason }
            )) if id == request_id.to_string()
                && reason == v1::CredentialBridgeFailureReason::ResponseTooLarge as i32
        ));
        drop(input_tx);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    #[tokio::test]
    async fn in_flight_ceiling_rejects_only_the_excess_request_as_unavailable() {
        let environment_id = Uuid::new_v4();
        let (input_tx, input_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 2);
        let (output_tx, mut output_rx) = mpsc::channel(2);
        let task = tokio::spawn(run_bridge(
            Arc::new(FakeExecutor {
                slow_started: Arc::new(AtomicBool::new(false)),
            }),
            FakeBridge {
                input: input_rx,
                output: output_tx,
            },
            environment_id,
            8,
        ));
        input_tx.send(ready(environment_id, 8)).await.unwrap();
        for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
            input_tx
                .send(request(Uuid::new_v4(), "/slow"))
                .await
                .unwrap();
        }
        let excess = Uuid::new_v4();
        input_tx.send(request(excess, "/slow")).await.unwrap();
        assert!(matches!(
            output_rx.recv().await,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure { request_id: id, reason }
            )) if id == excess.to_string()
                && reason == v1::CredentialBridgeFailureReason::Unavailable as i32
        ));
        drop(input_tx);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }
}
