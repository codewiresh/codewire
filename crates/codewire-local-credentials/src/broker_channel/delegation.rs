//! Material-free platform delegation over the existing inherited broker FD.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_access::EnvironmentId;
use codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use futures::{Stream, StreamExt as _, stream};
use hyper_util::rt::TokioIo;
use prost::Message as _;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status, Streaming};

use super::{
    BROKER_CHANNEL_REQUEST_TIMEOUT, BROKER_LEASE_PROTOCOL_VERSION, BrokerChannelRefreshLifetime,
    BrokerChannelRefreshOperation, BrokerLeaseChannelError, BrokerLeaseRpc,
    LocalCredentialBrokerLeaseServiceClient, map_client_status,
};
use crate::ProtectedStore;
use crate::control::v1;
use crate::platform::{PlatformCredentialInput, PlatformCredentialOutput};

const PLATFORM_DELEGATION_SETUP_TIMEOUT: Duration = Duration::from_secs(15);

mod composition;
pub(super) mod sources_only;

type CloseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Child-side client for platform delegation on its one inherited FD.
///
/// Unlike the local lease client, this type has no protected-store handle and
/// exposes no path-based connector. The exact environment generation is fixed
/// when the authority-created stream is consumed.
pub struct LocalCredentialDelegationClient {
    inner: LocalCredentialBrokerLeaseServiceClient<Channel>,
    environment_id: EnvironmentId,
    environment_generation: u64,
}

impl std::fmt::Debug for LocalCredentialDelegationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCredentialDelegationClient")
            .field("environment_id", &self.environment_id)
            .field("environment_generation", &self.environment_generation)
            .finish_non_exhaustive()
    }
}

impl LocalCredentialDelegationClient {
    pub async fn connect(
        inherited_stream: UnixStream,
        environment_id: EnvironmentId,
        environment_generation: u64,
    ) -> Result<Self, BrokerLeaseChannelError> {
        if environment_generation == 0 {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let stream = Arc::new(Mutex::new(Some(inherited_stream)));
        // Bound only establishment. A request-wide Endpoint timeout would
        // tear down this intentionally long-lived delegation after 40 seconds.
        let endpoint = Endpoint::from_static("http://codewire-platform-credential-delegation");
        let connect = endpoint.connect_with_connector(tower::service_fn(move |_| {
            let stream = Arc::clone(&stream);
            async move {
                stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "broker delegation channel already consumed",
                    )
                })
            }
        }));
        let channel = tokio::time::timeout(BROKER_CHANNEL_REQUEST_TIMEOUT, connect)
            .await
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        Ok(Self {
            inner: LocalCredentialBrokerLeaseServiceClient::new(channel)
                .max_decoding_message_size(super::MAX_BROKER_DELEGATION_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(super::MAX_BROKER_DELEGATION_RPC_MESSAGE_BYTES),
            environment_id,
            environment_generation,
        })
    }

    /// Present the already-authenticated guest Ready and return only after the
    /// owner authority has admitted the exact public delegation selection.
    pub async fn delegate_credentials<S>(
        &mut self,
        ready: bridge::CredentialBridgeReady,
        remaining: S,
    ) -> Result<LocalCredentialDelegationOutput, BrokerLeaseChannelError>
    where
        S: Stream<Item = bridge::CredentialBridgeGuestMessage> + Send + 'static,
    {
        self.validate_ready(&ready)?;
        let first = bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                ready.clone(),
            )),
        };
        let input = stream::once(async move { first }).chain(remaining);
        let mut output = self
            .inner
            .delegate_credentials(Request::new(input))
            .await
            .map_err(map_client_status)?
            .into_inner();
        let admitted = output
            .message()
            .await
            .map_err(map_client_status)?
            .ok_or(BrokerLeaseChannelError::InvalidResponse)?;
        validate_admission(admitted, &ready)?;
        Ok(LocalCredentialDelegationOutput {
            inner: output,
            ended: false,
        })
    }

    /// Report process readiness only after `delegate_credentials` consumed the
    /// exact private admission acknowledgement.
    pub async fn report_ready(&mut self) -> Result<(), BrokerLeaseChannelError> {
        self.inner
            .report_broker_ready(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
                guest_ready: None,
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }

    fn validate_ready(
        &self,
        ready: &bridge::CredentialBridgeReady,
    ) -> Result<(), BrokerLeaseChannelError> {
        if !ready_matches(&self.environment_id, self.environment_generation, ready) {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        Ok(())
    }
}

/// Admitted platform host frames. A second admission or missing frame is a
/// protocol failure and permanently ends this stream.
pub struct LocalCredentialDelegationOutput {
    inner: Streaming<v1::BrokerDelegationResponse>,
    ended: bool,
}

impl Stream for LocalCredentialDelegationOutput {
    type Item = Result<bridge::CredentialBridgeHostMessage, BrokerLeaseChannelError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(response))) => match response.output {
                Some(v1::broker_delegation_response::Output::Frame(frame))
                    if valid_host_frame(&frame) =>
                {
                    Poll::Ready(Some(Ok(frame)))
                }
                _ => {
                    self.ended = true;
                    Poll::Ready(Some(Err(BrokerLeaseChannelError::InvalidResponse)))
                }
            },
            Poll::Ready(Some(Err(_))) => {
                self.ended = true;
                Poll::Ready(Some(Err(BrokerLeaseChannelError::Unavailable)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(super) type BrokerDelegationOutput =
    Pin<Box<dyn Stream<Item = Result<v1::BrokerDelegationResponse, Status>> + Send + 'static>>;

impl<S: ProtectedStore + 'static> BrokerLeaseRpc<S> {
    pub(super) async fn delegate_platform_credentials(
        &self,
        request: Request<Streaming<bridge::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<BrokerDelegationOutput>, Status> {
        if self.platform_mode != super::BrokerPlatformMode::Delegated {
            return Err(Status::failed_precondition(
                "full platform credential delegation is unavailable",
            ));
        }
        let (binding, connector) = self.platform.lock().await.take().ok_or_else(|| {
            Status::failed_precondition("platform credential delegation is unavailable")
        })?;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        let mut input = request.into_inner();
        let first = tokio::select! {
            message = input.message() => message?,
            _ = self.refresh_lifetime.closed() => {
                return Err(Status::unavailable("credential broker lease channel is unavailable"));
            }
        }
        .ok_or_else(|| Status::permission_denied("platform delegation Ready is missing"))?;
        let Some(bridge::credential_bridge_guest_message::Payload::Ready(ready)) = first.payload
        else {
            return Err(Status::permission_denied(
                "platform delegation Ready must be first",
            ));
        };
        if !ready_matches(&self.environment_id, self.environment_generation, &ready) {
            return Err(Status::permission_denied(
                "platform delegation Ready does not match the broker generation",
            ));
        }
        let deadline = Instant::now() + PLATFORM_DELEGATION_SETUP_TIMEOUT;
        let composer = composition::ProjectionComposer::for_binding(self, &binding)?;
        let remaining: PlatformCredentialInput = Box::pin(RemainingPlatformInput {
            inner: input,
            close: close_future(Arc::clone(&self.refresh_lifetime)),
            ended: false,
        });
        let remaining = match &composer {
            Some(composer) => composer.input(remaining),
            None => remaining,
        };
        let setup = connector.connect(binding, ready.clone(), remaining, deadline);
        let output = tokio::select! {
            result = tokio::time::timeout_at(deadline, setup) => {
                result.map_err(|_| Status::deadline_exceeded("platform credential delegation setup expired"))??
            }
            _ = self.refresh_lifetime.closed() => {
                return Err(Status::unavailable("credential broker lease channel is unavailable"));
            }
        };
        let output = match composer {
            Some(composer) => composer.output(output),
            None => output,
        };
        if Instant::now() >= deadline {
            return Err(Status::deadline_exceeded(
                "platform credential delegation setup expired",
            ));
        }
        let state = DelegationOutputState {
            admitted: Some(ready),
            output,
            close: close_future(Arc::clone(&self.refresh_lifetime)),
            _operation: Some(operation),
            admission_observed: Arc::clone(&self.platform_admitted),
            ended: false,
        };
        let output = stream::unfold(state, |mut state| async move {
            if state.ended {
                return None;
            }
            if let Some(ready) = state.admitted.take() {
                tokio::select! {
                    biased;
                    _ = &mut state.close => return None,
                    _ = std::future::ready(()) => {}
                }
                state.admission_observed.store(true, Ordering::Release);
                return Some((
                    Ok(v1::BrokerDelegationResponse {
                        output: Some(v1::broker_delegation_response::Output::Admitted(ready)),
                    }),
                    state,
                ));
            }
            let next = tokio::select! {
                next = state.output.next() => next,
                _ = &mut state.close => None,
            };
            let next = match next {
                Some(Ok(frame)) if valid_host_frame(&frame) => Ok(v1::BrokerDelegationResponse {
                    output: Some(v1::broker_delegation_response::Output::Frame(frame)),
                }),
                Some(Ok(_)) => {
                    state.ended = true;
                    Err(Status::internal(
                        "platform credential delegation returned an invalid frame",
                    ))
                }
                Some(Err(status)) => {
                    state.ended = true;
                    Err(status)
                }
                None => return None,
            };
            Some((next, state))
        });
        Ok(Response::new(Box::pin(output)))
    }
}

struct RemainingPlatformInput {
    inner: Streaming<bridge::CredentialBridgeGuestMessage>,
    close: CloseFuture,
    ended: bool,
}

impl Stream for RemainingPlatformInput {
    type Item = Result<bridge::CredentialBridgeGuestMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if self.close.as_mut().poll(context).is_ready() {
            self.ended = true;
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(frame))) => match valid_remaining_frame(&frame) {
                false => {
                    self.ended = true;
                    Poll::Ready(Some(Err(Status::permission_denied(
                        "platform credential delegation frame is invalid",
                    ))))
                }
                true => Poll::Ready(Some(Ok(frame))),
            },
            Poll::Ready(Some(Err(status))) => {
                self.ended = true;
                Poll::Ready(Some(Err(status)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

struct DelegationOutputState<S: ProtectedStore> {
    admitted: Option<bridge::CredentialBridgeReady>,
    output: PlatformCredentialOutput,
    close: CloseFuture,
    _operation: Option<BrokerChannelRefreshOperation<S>>,
    admission_observed: Arc<AtomicBool>,
    ended: bool,
}

fn close_future<S: ProtectedStore + 'static>(
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
) -> CloseFuture {
    Box::pin(async move { lifetime.closed().await })
}

pub(super) fn ready_matches(
    environment_id: &EnvironmentId,
    environment_generation: u64,
    ready: &bridge::CredentialBridgeReady,
) -> bool {
    ready.protocol_version == CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        && ready.environment_id == environment_id.to_string()
        && ready.environment_generation == environment_generation
        && ready.encoded_len() <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
}

fn validate_admission(
    response: v1::BrokerDelegationResponse,
    expected: &bridge::CredentialBridgeReady,
) -> Result<(), BrokerLeaseChannelError> {
    match response.output {
        Some(v1::broker_delegation_response::Output::Admitted(actual)) if actual == *expected => {
            Ok(())
        }
        _ => Err(BrokerLeaseChannelError::InvalidResponse),
    }
}

/// Guest frames a platform delegation relays, and below the host frames it
/// relays back. The Codex login, the one listed direct delivery exception
/// (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions"),
/// crosses in both directions under the same rule: the guest's request
/// reaches the platform broker, which decides it for the delegation's
/// creator, and its answer (a login sealed to the guest daemon, DENIED or
/// UNAVAILABLE) comes back. Neither may end the delegation, or one login
/// request would end every provider, GitHub and projection with it.
fn valid_remaining_frame(frame: &bridge::CredentialBridgeGuestMessage) -> bool {
    frame.encoded_len() <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        && !matches!(&frame.payload,
            Some(bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(request))
                if !request.local_inventories.is_empty())
        && matches!(
            frame.payload,
            Some(bridge::credential_bridge_guest_message::Payload::Request(_))
                | Some(bridge::credential_bridge_guest_message::Payload::Cancel(_))
                | Some(bridge::credential_bridge_guest_message::Payload::EnvironmentProjection(_))
                | Some(bridge::credential_bridge_guest_message::Payload::Ssh(_))
                | Some(bridge::credential_bridge_guest_message::Payload::CodexLogin(_))
        )
}

fn valid_host_frame(frame: &bridge::CredentialBridgeHostMessage) -> bool {
    frame.encoded_len() <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        && !matches!(&frame.payload,
            Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(response))
                if matches!(response.result, Some(bridge::environment_projection_response::Result::Composition(_))))
        && matches!(
            frame.payload,
            Some(bridge::credential_bridge_host_message::Payload::ResponseStart(_))
                | Some(bridge::credential_bridge_host_message::Payload::ResponseBody(_))
                | Some(bridge::credential_bridge_host_message::Payload::ResponseEnd(_))
                | Some(bridge::credential_bridge_host_message::Payload::ResponseFailure(_))
                | Some(bridge::credential_bridge_host_message::Payload::EnvironmentProjection(_))
                | Some(bridge::credential_bridge_host_message::Payload::Ssh(_))
                | Some(bridge::credential_bridge_host_message::Payload::CodexLogin(
                    _
                ))
        )
}

#[cfg(test)]
mod tests;
