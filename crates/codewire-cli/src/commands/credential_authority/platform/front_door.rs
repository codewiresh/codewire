//! A delegation's front-door joiner (#4909): the authority's half of the
//! boot's front-door session. It keeps the epoch's handle, joins
//! `FrontDoorDelegation` with it as the delegation's own creator, and carries
//! the relay's frames unchanged. Nothing it returns holds the handle, so the
//! confined relay never sees it.

use buffa::Message as _;
use codewire_client::{
    CodewireClient, FrontDoorDelegationStream, FrontDoorEpoch, credential_bridge as public_bridge,
};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, codewire::bridge::v1 as bridge,
};
use codewire_local_credentials::{
    PlatformCredentialInput, PlatformCredentialOutput, PlatformFrontDoorJoiner,
};
use codewire_proto::codewire::v1::{
    FrontDoorDelegationRequest, FrontDoorDelegationResponse, front_door_delegation_response,
};
use futures::{StreamExt as _, future::BoxFuture, stream};
use prost::Message as _;
use tokio::time::Instant;
use tonic::Status;

use super::{client_error, denied, expired, live, send_timeout};

pub(super) struct NativeFrontDoorJoiner {
    pub(super) client: CodewireClient,
    pub(super) epoch: FrontDoorEpoch,
}

impl PlatformFrontDoorJoiner for NativeFrontDoorJoiner {
    fn join(
        &self,
        ready: bridge::CredentialBridgeReady,
        input: PlatformCredentialInput,
        deadline: Instant,
    ) -> BoxFuture<'static, Result<(Vec<String>, PlatformCredentialOutput), Status>> {
        let client = self.client.clone();
        let epoch = self.epoch.clone();
        Box::pin(async move {
            tokio::time::timeout_at(deadline, async move {
                live(deadline)?;
                let ready =
                    public_bridge::CredentialBridgeReady::decode_from_slice(&ready.encode_to_vec())
                        .map_err(|_| denied())?;
                let (upstream, capabilities) = client
                    .join_front_door_delegation(&epoch, ready)
                    .await
                    .map_err(client_error)?;
                live(deadline)?;
                Ok((capabilities, relay(upstream, input)))
            })
            .await
            .map_err(|_| expired())?
        })
    }
}

/// The relay's frames up and the broker's frames down, each bounded and
/// converted between the two generated codecs of one proto. A second
/// admission, or any answer that is not a frame, ends the session.
fn relay(
    upstream: FrontDoorDelegationStream,
    input: PlatformCredentialInput,
) -> PlatformCredentialOutput {
    Box::pin(stream::try_unfold(
        (upstream, input, false),
        |(mut upstream, mut input, mut input_ended)| async move {
            loop {
                tokio::select! {
                    frame = input.next(), if !input_ended => match frame {
                        Some(frame) => {
                            let request = encode(frame?)?;
                            tokio::time::timeout(send_timeout(), upstream.send(request))
                                .await
                                .map_err(|_| super::unavailable())?
                                .map_err(|error| client_error(error.into()))?;
                        }
                        None => {
                            upstream.close_send();
                            input_ended = true;
                        }
                    },
                    response = upstream.message::<FrontDoorDelegationResponse>() => {
                        let response: Option<_> = response.map_err(|error| client_error(error.into()))?;
                        let Some(response) = response else {
                            return Ok(None);
                        };
                        if response.bytes().len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 8 {
                            return Err(denied());
                        }
                        let frame = decode(response.to_owned_message())?;
                        return Ok(Some((frame, (upstream, input, input_ended))));
                    }
                }
            }
        },
    ))
}

fn encode(
    frame: bridge::CredentialBridgeGuestMessage,
) -> Result<FrontDoorDelegationRequest, Status> {
    if frame.payload.is_none() || frame.encoded_len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
        return Err(denied());
    }
    let public =
        public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&frame.encode_to_vec())
            .map_err(|_| denied())?;
    Ok(FrontDoorDelegationRequest {
        frame: Some(public).into(),
        ..Default::default()
    })
}

fn decode(
    response: FrontDoorDelegationResponse,
) -> Result<bridge::CredentialBridgeHostMessage, Status> {
    let Some(front_door_delegation_response::Output::Frame(frame)) = response.output else {
        return Err(denied());
    };
    if frame.payload.is_none()
        || matches!(
            frame.payload,
            Some(public_bridge::credential_bridge_host_message::Payload::Open(_))
        )
        || frame.encoded_len() as usize > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
    {
        return Err(denied());
    }
    bridge::CredentialBridgeHostMessage::decode(frame.encode_to_vec().as_slice())
        .map_err(|_| denied())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client mirrors the bridge's handle header, which it cannot see.
    #[test]
    fn the_clients_handle_header_is_the_bridges() {
        assert_eq!(
            codewire_client::FRONT_DOOR_EPOCH_HEADER,
            codewire_daemon_proto::CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER
        );
        assert_eq!(
            codewire_client::FRONT_DOOR_EPOCH_BYTES,
            codewire_daemon_proto::CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES
        );
    }

    /// Frames cross unchanged; an empty frame, a host Open or a second
    /// admission does not.
    #[test]
    fn front_door_frames_cross_unchanged_and_an_open_or_admission_does_not() {
        let guest = bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Cancel(
                bridge::CredentialBridgeCancel {
                    request_id: "cancel".into(),
                },
            )),
        };
        let encoded = encode(guest.clone()).unwrap();
        assert_eq!(
            encoded.frame.into_option().unwrap().encode_to_vec(),
            guest.encode_to_vec()
        );
        assert!(encode(bridge::CredentialBridgeGuestMessage::default()).is_err());

        let host = public_bridge::CredentialBridgeHostMessage {
            payload: Some(
                public_bridge::credential_bridge_host_message::Payload::ResponseEnd(Box::new(
                    public_bridge::CredentialBridgeResponseEnd {
                        request_id: "end".into(),
                        ..Default::default()
                    },
                )),
            ),
            ..Default::default()
        };
        let frame =
            |frame: public_bridge::CredentialBridgeHostMessage| FrontDoorDelegationResponse {
                output: Some(front_door_delegation_response::Output::Frame(Box::new(
                    frame,
                ))),
                ..Default::default()
            };
        assert_eq!(
            decode(frame(host.clone())).unwrap().encode_to_vec(),
            host.encode_to_vec()
        );
        let open = public_bridge::CredentialBridgeHostMessage {
            payload: Some(
                public_bridge::credential_bridge_host_message::Payload::Open(Box::default()),
            ),
            ..Default::default()
        };
        assert!(decode(frame(open)).is_err());
        assert!(
            decode(FrontDoorDelegationResponse {
                output: Some(front_door_delegation_response::Output::Admitted(
                    Box::default()
                )),
                ..Default::default()
            })
            .is_err()
        );
    }
}
