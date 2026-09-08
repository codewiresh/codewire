//! Transparent relay for an already-admitted native guest bridge.
//!
//! This adapter owns no operation ledger and interprets no provider request.
//! It only preserves the actual admitted Ready and applies backpressure while
//! carrying the canonical shared frames to and from an owner-selected relay.

use std::future::Future;
use std::pin::Pin;

use codewire_gateway_proto::codewire::bridge::v1;
use futures::{Stream, StreamExt as _, stream};
use prost::Message as _;

use super::{
    AdmittedCredentialBridge, BrokerBridgeError, CredentialBridgeResponseSink,
    CredentialBridgeTransport,
};

/// Remaining guest frames after the exact Ready was consumed and validated.
pub type CredentialBridgeRelayInput =
    Pin<Box<dyn Stream<Item = v1::CredentialBridgeGuestMessage> + Send>>;

/// Already-admitted host frames returned by the remote authority.
pub type CredentialBridgeRelayOutput =
    Pin<Box<dyn Stream<Item = Result<v1::CredentialBridgeHostMessage, BrokerBridgeError>> + Send>>;

/// Relay one admitted bridge without creating a second request ledger.
///
/// `connect` receives the actual guest Ready and a demand-driven stream of all
/// later guest frames. It must return only after its remote authority has
/// admitted that Ready. Dropping the returned stream must close both remote
/// directions. This runner then forwards only canonical host payloads through
/// the original guest connection and returns when either authority is lost.
pub async fn run_admitted_credential_bridge_relay<B, C, F>(
    admitted: AdmittedCredentialBridge<B>,
    connect: C,
) -> Result<(), BrokerBridgeError>
where
    B: CredentialBridgeTransport + 'static,
    C: FnOnce(v1::CredentialBridgeReady, CredentialBridgeRelayInput) -> F,
    F: Future<Output = Result<CredentialBridgeRelayOutput, BrokerBridgeError>>,
{
    let AdmittedCredentialBridge { bridge, ready } = admitted;
    let sender = bridge.response_sink();
    let input = stream::unfold(bridge, |mut bridge| async move {
        match bridge.receive().await {
            Ok(Some(frame)) if valid_guest_frame(&frame) => Some((frame, bridge)),
            Ok(None) | Err(_) => None,
            Ok(Some(_)) => None,
        }
    });
    let mut output = connect(ready, Box::pin(input)).await?;
    while let Some(frame) = output.next().await {
        let frame = frame?;
        if frame.encoded_len() > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
            return Err(BrokerBridgeError::InvalidProtocol);
        }
        let payload = match frame.payload {
            Some(v1::credential_bridge_host_message::Payload::Open(_)) | None => {
                return Err(BrokerBridgeError::InvalidProtocol);
            }
            Some(payload) => payload,
        };
        sender.send(payload).await?;
    }
    Err(BrokerBridgeError::Unavailable)
}

fn valid_guest_frame(frame: &v1::CredentialBridgeGuestMessage) -> bool {
    frame.encoded_len() <= codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        && matches!(
            frame.payload,
            Some(v1::credential_bridge_guest_message::Payload::Request(_))
                | Some(v1::credential_bridge_guest_message::Payload::Cancel(_))
                | Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(_))
                | Some(v1::credential_bridge_guest_message::Payload::Ssh(_))
        )
}

#[cfg(test)]
mod tests;
