//! `EgressService.FrontDoorSession` (#4001): cw-egress's TLS front door joins
//! the credential relay epoch running for a Pod on its own node.
//!
//! The Pod is checked as every other method checks it, and the environment
//! comes from its live binding only. The session then joins that binding's
//! current epoch on this process, which opens the broker's `FrontDoorBridge`
//! with its own credentials and handle; none of them reach this module. The
//! relay is leader-gated, so a Pod whose epoch runs on another process, or
//! not yet, is answered UNAVAILABLE and cw-egress retries.

use std::time::Duration;

use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_request::Frame as RequestFrame;
use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_response::Frame as ResponseFrame;
use codewire_proto::codewire::internal::v1::{FrontDoorSessionRequest, FrontDoorSessionResponse};
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::oneshot;
use tonic::{Code, Status};
use uuid::Uuid;

use super::{EgressServiceState, denied};
use crate::front_door::{BindingKey, Join, Joined};

/// One request or response message: a whole bridge frame, its four-byte
/// length and the field's own tag and length.
pub(super) const MAX_MESSAGE_BYTES: usize =
    codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 64;

/// How long a session waits for its epoch to open the broker stream, which
/// is bounded itself by the broker's admission timeout.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);

impl EgressServiceState {
    pub(super) async fn front_door_session(
        &self,
        ctx: &RequestContext,
        mut requests: InboundStream<FrontDoorSessionRequest>,
    ) -> ServiceResult<ServiceStream<FrontDoorSessionResponse>> {
        let caller = self.caller(ctx).await?;
        let Some(front_doors) = &self.front_doors else {
            return Err(ConnectError::unimplemented(
                "hosted credential interception is off",
            ));
        };
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
        let epoch = front_doors.current(&key).ok_or_else(no_epoch)?;
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
        let (reply, joined) = oneshot::channel();
        epoch
            .send(Join { frames, reply })
            .await
            .map_err(|_| no_epoch())?;
        let joined = tokio::time::timeout(JOIN_TIMEOUT, joined)
            .await
            .map_err(|_| no_epoch())?
            .map_err(|_| no_epoch())?
            .map_err(|status| answer(&status))?;
        let attached = FrontDoorSessionResponse {
            frame: Some(ResponseFrame::Attached(Box::default())),
            ..Default::default()
        };
        let Joined { frames, session } = joined;
        let frames = frames.map(move |frame| {
            // Held by the stream cw-egress reads: dropping it, on a
            // disconnect or the token's expiry, ends the relay's session.
            let _ = &session;
            frame
                .map(|frame| FrontDoorSessionResponse {
                    frame: Some(ResponseFrame::Bridge(frame)),
                    ..Default::default()
                })
                .map_err(|status| answer(&status))
        });
        // Like a watch, a session ends when the token cw-egress opened it
        // with expires, and cw-egress opens it again with a fresh one.
        let stream = futures::stream::once(async { Ok(attached) })
            .chain(frames)
            .take_until(tokio::time::sleep_until(caller.expires_at));
        connectrpc::Response::stream_ok(stream)
    }
}

fn not_open() -> ConnectError {
    ConnectError::failed_precondition("a front-door session starts with its open frame")
}

fn no_epoch() -> ConnectError {
    ConnectError::unavailable("no credential relay epoch is running for this Pod")
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
