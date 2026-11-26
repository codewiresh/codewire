//! `EgressService.FrontDoorSession` (#4001): cw-egress's TLS front door joins
//! the credential relay epoch running for a Pod on its own node.
//!
//! The Pod is checked as every other method checks it, and the environment
//! comes from its live binding only. The session then joins that binding's
//! current epoch on this process, which opens the broker's `FrontDoorBridge`
//! with its own credentials and handle; none of them reach this module. The
//! relay is leader-gated, so a Pod whose epoch runs on another process, or
//! not yet, is answered UNAVAILABLE and cw-egress retries. Once attached, the
//! session follows its binding across epoch renewals (`session`).

use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_request::Frame as RequestFrame;
use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_response::Frame as ResponseFrame;
use codewire_proto::codewire::internal::v1::{FrontDoorSessionRequest, FrontDoorSessionResponse};
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Status};
use uuid::Uuid;

use super::{CallerUse, EgressServiceState, denied};
use crate::front_door::BindingKey;

mod session;
#[cfg(test)]
pub(super) use session::{NO_EPOCH, STALL};

/// One request or response message: a whole bridge frame, its four-byte
/// length and the field's own tag and length.
pub(super) const MAX_MESSAGE_BYTES: usize =
    codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 64;

impl EgressServiceState {
    pub(super) async fn front_door_session(
        &self,
        ctx: &RequestContext,
        mut requests: InboundStream<FrontDoorSessionRequest>,
    ) -> ServiceResult<ServiceStream<FrontDoorSessionResponse>> {
        let caller = self.caller(ctx, CallerUse::HeldStream).await?;
        let Some(front_doors) = &self.front_doors else {
            return Err(ConnectError::unimplemented(
                "hosted credential interception is off",
            ));
        };
        if self.draining.is_cancelled() {
            return Err(draining());
        }
        let first = requests
            .next()
            .await
            .ok_or_else(not_open)?
            .map_err(|_| not_open())?
            .to_owned_message();
        let Some(RequestFrame::Open(open)) = first.frame else {
            return Err(not_open());
        };
        let guest = self.named_guest(&open.pod_name, &open.pod_uid);
        self.guest_on_node(&guest, &caller.node).await?;
        let binding = self
            .bindings
            .live_binding(&guest.uid, &guest.namespace, &guest.name)
            .await
            .map_err(|_| ConnectError::unavailable("the binding store is unavailable"))?
            .ok_or_else(denied)?;
        let key = BindingKey {
            environment_id: Uuid::parse_str(&binding.environment_id).map_err(|_| denied())?,
            pod_uid: guest.uid.clone(),
            generation: u64::try_from(binding.operation_generation).map_err(|_| denied())?,
        };
        // A newer session for the Pod replaces an older one, which only the
        // Pod's own node can have opened (`guest_on_node` above). The drain
        // stops every session too.
        let stop = self.draining.child_token();
        let place = front_doors
            .take_session(&key.pod_uid, stop.clone(), REPLACE_WAIT)
            .await;
        let first = match session::join(front_doors, &key).await {
            Ok(first) => first,
            Err(status) => return no_session(front_doors, &key, &status),
        };
        let open = session::open_frame(&key, &first.1.capabilities).ok_or_else(no_epoch)?;
        let frames = requests
            .map(|request| {
                let request = request
                    .map_err(|_| Status::unavailable("front-door session input ended"))?
                    .to_owned_message();
                match request.frame {
                    Some(RequestFrame::Bridge(frame)) => Ok(frame),
                    _ => Err(Status::failed_precondition(
                        "a front-door session opens once",
                    )),
                }
            })
            .boxed();
        let (output, outgoing) = mpsc::channel(1);
        let session = session::Session {
            front_doors: Arc::clone(front_doors),
            key,
            output,
            stop: stop.clone(),
            draining: self.draining.clone(),
        };
        tokio::spawn(async move {
            // Held until the session has let go of its upstreams.
            let _place = place;
            session.run(first, frames).await;
        });
        let bridge = |frame| FrontDoorSessionResponse {
            frame: Some(ResponseFrame::Bridge(frame)),
            ..Default::default()
        };
        let attached = FrontDoorSessionResponse {
            frame: Some(ResponseFrame::Attached(Box::default())),
            ..Default::default()
        };
        // Held by the stream cw-egress reads: dropping it, on a disconnect or
        // the token's expiry, ends the session and its upstreams.
        let ends = stop.drop_guard();
        let frames = ReceiverStream::new(outgoing).map(move |frame| {
            let _ = &ends;
            frame.map(bridge).map_err(|status| answer(&status))
        });
        // Like a watch, a session ends when the token cw-egress opened it
        // with expires, and cw-egress opens it again with a fresh one.
        let stream = futures::stream::iter([Ok(attached), Ok(bridge(open))])
            .chain(frames)
            .take_until(tokio::time::sleep_until(caller.expires_at));
        connectrpc::Response::stream_ok(stream)
    }
}

/// With no epoch to join, the broker's named refusal of the binding's last,
/// if this process holds one, ends the session as the front door's refusal
/// (#6406): Attached, then that refusal in place of Open. cw-egress opens the
/// session again within 30 seconds, renewing it. Otherwise the relay's answer,
/// as before.
fn no_session(
    front_doors: &crate::front_door::FrontDoorEpochs,
    key: &BindingKey,
    status: &Status,
) -> ServiceResult<ServiceStream<FrontDoorSessionResponse>> {
    let frame = (status.code() == Code::Unavailable)
        .then(|| front_doors.refusal(key))
        .flatten()
        .and_then(|refusal| session::refused_frame(key, refusal))
        .ok_or_else(|| answer(status))?;
    let attached = FrontDoorSessionResponse {
        frame: Some(ResponseFrame::Attached(Box::default())),
        ..Default::default()
    };
    let refused = FrontDoorSessionResponse {
        frame: Some(ResponseFrame::Bridge(frame)),
        ..Default::default()
    };
    connectrpc::Response::stream_ok(futures::stream::iter([Ok(attached), Ok(refused)]))
}

/// How long a newer session waits for the older one it replaces to let go
/// of the epoch before joining it anyway.
const REPLACE_WAIT: Duration = Duration::from_secs(5);

fn not_open() -> ConnectError {
    ConnectError::failed_precondition("a front-door session starts with its open frame")
}

fn no_epoch() -> ConnectError {
    ConnectError::unavailable("no credential relay epoch is running for this Pod")
}

fn draining() -> ConnectError {
    ConnectError::unavailable("this orchestration replica is draining")
}

/// The relay's answer for cw-egress, by code only.
fn answer(status: &Status) -> ConnectError {
    match status.code() {
        Code::PermissionDenied => denied(),
        Code::AlreadyExists => {
            ConnectError::already_exists("this epoch already has a front-door session")
        }
        Code::FailedPrecondition => {
            ConnectError::failed_precondition("a front-door session opens once")
        }
        Code::InvalidArgument => ConnectError::invalid_argument("front-door frame is invalid"),
        _ => no_epoch(),
    }
}
