//! The boot's front-door session over this channel's delegation (#4909).
//!
//! The connector that admitted the channel's delegation hands back a joiner
//! that keeps the platform's epoch handle; the relay only ever sees this
//! channel. A front-door session joins that delegation and no other, one at
//! a time, and ends with the channel.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use codewire_daemon_proto::codewire::bridge::v1 as bridge;
use futures::Stream;
use prost::Message as _;
use tokio::time::Instant;
use tonic::{Request, Response, Status, Streaming};

use super::{
    BrokerLeaseRpc, CloseFuture, FrontDoorDelegationOutput, PLATFORM_DELEGATION_SETUP_TIMEOUT,
    close_future, ready_matches,
};
use crate::ProtectedStore;
use crate::platform::{PlatformCredentialInput, PlatformCredentialOutput, PlatformFrontDoorJoiner};

/// The channel's front-door joiner, once its delegation is admitted, and
/// whether a front-door session holds it.
#[derive(Default)]
pub(in crate::broker_channel) struct FrontDoorSlot {
    joiner: std::sync::Mutex<Option<Arc<dyn PlatformFrontDoorJoiner>>>,
    busy: Arc<AtomicBool>,
}

impl FrontDoorSlot {
    /// Keep the admitted delegation's joiner; a delegation is admitted once
    /// per channel.
    pub(super) fn offer(&self, joiner: Option<Arc<dyn PlatformFrontDoorJoiner>>) {
        if let Ok(mut slot) = self.joiner.lock() {
            *slot = joiner;
        }
    }
}

impl<S: ProtectedStore + 'static> BrokerLeaseRpc<S> {
    pub(in crate::broker_channel) async fn delegate_front_door_session(
        &self,
        request: Request<Streaming<bridge::CredentialBridgeGuestMessage>>,
    ) -> Result<Response<FrontDoorDelegationOutput>, Status> {
        if !self.platform_admitted.load(Ordering::Acquire) {
            return Err(Status::failed_precondition(
                "the platform delegation is not admitted",
            ));
        }
        let joiner = self
            .front_door
            .joiner
            .lock()
            .map_err(|_| Status::unavailable("credential broker lease channel is unavailable"))?
            .clone()
            .ok_or_else(|| {
                Status::failed_precondition("the platform delegation joins no front door")
            })?;
        if self
            .front_door
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Status::already_exists(
                "this delegation already serves a front-door session",
            ));
        }
        let busy = Busy(Arc::clone(&self.front_door.busy));
        let mut input = request.into_inner();
        let first = tokio::select! {
            message = input.message() => message?,
            _ = self.refresh_lifetime.closed() => {
                return Err(Status::unavailable("credential broker lease channel is unavailable"));
            }
        }
        .ok_or_else(|| Status::permission_denied("front-door Ready is missing"))?;
        let Some(bridge::credential_bridge_guest_message::Payload::Ready(ready)) = first.payload
        else {
            return Err(Status::permission_denied("front-door Ready must be first"));
        };
        if !ready_matches(&self.environment_id, self.environment_generation, &ready) {
            return Err(Status::permission_denied(
                "front-door Ready does not match the broker generation",
            ));
        }
        let deadline = Instant::now() + PLATFORM_DELEGATION_SETUP_TIMEOUT;
        let remaining: PlatformCredentialInput = Box::pin(FrontDoorInput {
            inner: input,
            close: close_future(Arc::clone(&self.refresh_lifetime)),
            ended: false,
        });
        let (capabilities, output) = tokio::select! {
            result = tokio::time::timeout_at(deadline, joiner.join(ready, remaining, deadline)) => {
                result.map_err(|_| Status::deadline_exceeded("front-door delegation setup expired"))??
            }
            _ = self.refresh_lifetime.closed() => {
                return Err(Status::unavailable("credential broker lease channel is unavailable"));
            }
        };
        let output: FrontDoorDelegationOutput = Box::pin(Joined {
            output,
            close: close_future(Arc::clone(&self.refresh_lifetime)),
            ended: false,
            _busy: busy,
        });
        let mut response = Response::new(output);
        for capability in &capabilities {
            let value = capability
                .parse()
                .map_err(|_| Status::unavailable("front-door delegation admission is invalid"))?;
            response.metadata_mut().append(
                codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER,
                value,
            );
        }
        Ok(response)
    }
}

/// The relay's frames after its Ready: bounded, and only the kinds the
/// front-door entry serves. A projection, SSH, a login or a second Ready ends
/// the session; the relay's router answers those itself before they reach
/// here.
struct FrontDoorInput {
    inner: Streaming<bridge::CredentialBridgeGuestMessage>,
    close: CloseFuture,
    ended: bool,
}

fn front_door_frame(frame: &bridge::CredentialBridgeGuestMessage) -> bool {
    use bridge::credential_bridge_guest_message::Payload;
    frame.encoded_len() <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        && !matches!(
            frame.payload,
            None | Some(
                Payload::Ready(_)
                    | Payload::EnvironmentProjection(_)
                    | Payload::Ssh(_)
                    | Payload::CodexLogin(_)
                    | Payload::ClaudeLogin(_)
            )
        )
}

impl Stream for FrontDoorInput {
    type Item = Result<bridge::CredentialBridgeGuestMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended || self.close.as_mut().poll(context).is_ready() {
            self.ended = true;
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(frame))) if front_door_frame(&frame) => {
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Ok(_))) => {
                self.ended = true;
                Poll::Ready(Some(Err(Status::permission_denied(
                    "front-door delegation frame is invalid",
                ))))
            }
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

/// Frees the channel's one front-door place when its session ends.
struct Busy(Arc<AtomicBool>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A joined session's output: it ends with the channel, and never passes a
/// host Open, which the relay writes itself.
struct Joined {
    output: PlatformCredentialOutput,
    close: CloseFuture,
    ended: bool,
    _busy: Busy,
}

impl Stream for Joined {
    type Item = Result<bridge::CredentialBridgeHostMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended || self.close.as_mut().poll(context).is_ready() {
            self.ended = true;
            return Poll::Ready(None);
        }
        match self.output.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(frame)))
                if matches!(
                    frame.payload,
                    Some(bridge::credential_bridge_host_message::Payload::Open(_)) | None
                ) =>
            {
                self.ended = true;
                Poll::Ready(Some(Err(Status::unavailable(
                    "front-door delegation response is invalid",
                ))))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }
}
