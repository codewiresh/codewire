//! `EgressService.FrontDoorSession` over orchestration's own client: the
//! [`SessionOpener`] the front-door session task uses.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_request::Frame as RequestFrame;
use codewire_proto::codewire::internal::v1::__buffa::oneof::front_door_session_response::Frame as ResponseFrame;
use codewire_proto::codewire::internal::v1::{
    FrontDoorSessionOpen, FrontDoorSessionRequest, FrontDoorSessionResponse,
};
use connectrpc::{ConnectError, ErrorCode};
use tokio::sync::mpsc;

use super::Orchestration;
use crate::front_door_session::{Attached, SessionEnd, SessionOpener};

/// Orchestration ends a session at the token's expiry, within the hour;
/// this only bounds a call nothing ended.
const SESSION_BACKSTOP: Duration = Duration::from_secs(2 * 60 * 60);
/// What the server's route takes: one bridge frame and its envelope.
const MAX_MESSAGE_BYTES: usize = CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 64;

impl SessionOpener for Orchestration {
    fn open<'a>(
        &'a self,
        pod_uid: &'a str,
        pod_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Attached, SessionEnd>> + Send + 'a>> {
        Box::pin(self.front_door_session(pod_uid, pod_name))
    }
}

impl Orchestration {
    /// Opens the Pod's session, reading the token again, and returns once
    /// orchestration has attached it.
    async fn front_door_session(
        &self,
        pod_uid: &str,
        pod_name: &str,
    ) -> Result<Attached, SessionEnd> {
        let options = self
            .options()
            .map_err(|_| SessionEnd::Unavailable)?
            .with_timeout(SESSION_BACKSTOP)
            .with_max_message_size(MAX_MESSAGE_BYTES);
        let stream = self
            .client()
            .map_err(|_| SessionEnd::Unavailable)?
            .front_door_session_with_options(options)
            .await
            .map_err(|error| end_of(&error))?;
        let (mut send, mut receive) = stream.into_split();
        let open = FrontDoorSessionRequest {
            frame: Some(RequestFrame::Open(Box::new(FrontDoorSessionOpen {
                pod_uid: pod_uid.to_owned(),
                pod_name: pod_name.to_owned(),
                ..Default::default()
            }))),
            ..Default::default()
        };
        send.send(open).await.map_err(|error| end_of(&error))?;
        match receive.message::<FrontDoorSessionResponse>().await {
            Ok(Some(first))
                if matches!(
                    first.to_owned_message().frame,
                    Some(ResponseFrame::Attached(_))
                ) => {}
            Ok(Some(_)) => return Err(SessionEnd::Refused),
            Ok(None) => return Err(SessionEnd::Clean),
            Err(error) => return Err(end_of(&error)),
        }

        let (to_orchestration, mut outgoing) = mpsc::channel::<Vec<u8>>(1);
        let (incoming, from_orchestration) = mpsc::channel(1);
        // Closing our side when the relay ends tells orchestration to end the
        // session, which ends the other pump.
        tokio::spawn(async move {
            while let Some(frame) = outgoing.recv().await {
                let bridge = FrontDoorSessionRequest {
                    frame: Some(RequestFrame::Bridge(frame)),
                    ..Default::default()
                };
                if send.send(bridge).await.is_err() {
                    break;
                }
            }
            send.close_send();
        });
        tokio::spawn(async move {
            loop {
                let next = match receive.message::<FrontDoorSessionResponse>().await {
                    Ok(Some(message)) => match message.to_owned_message().frame {
                        Some(ResponseFrame::Bridge(frame)) => Ok(frame),
                        _ => Err(SessionEnd::Refused),
                    },
                    Ok(None) => return,
                    Err(error) => Err(end_of(&error)),
                };
                let last = next.is_err();
                if incoming.send(next).await.is_err() || last {
                    return;
                }
            }
        });
        Ok(Attached {
            to_orchestration,
            from_orchestration,
        })
    }
}

/// How the client waits after `error`.
fn end_of(error: &ConnectError) -> SessionEnd {
    match error.code {
        ErrorCode::PermissionDenied
        | ErrorCode::Unauthenticated
        | ErrorCode::FailedPrecondition
        | ErrorCode::InvalidArgument => SessionEnd::Refused,
        ErrorCode::Unimplemented => SessionEnd::Unimplemented,
        _ => SessionEnd::Unavailable,
    }
}
