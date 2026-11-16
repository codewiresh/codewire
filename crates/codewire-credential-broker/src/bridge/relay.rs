//! Transparent relay for an already-admitted native guest bridge.
//!
//! This adapter owns no operation ledger and interprets no provider request.
//! It only preserves the actual admitted Ready and applies backpressure while
//! carrying the canonical shared frames to and from an owner-selected relay.

use std::future::Future;
use std::pin::Pin;

use codewire_daemon_proto::codewire::bridge::v1;
use futures::{Stream, StreamExt as _, stream};
use prost::Message as _;

use super::{
    AdmittedCredentialBridge, BrokerBridgeError, CredentialBridgeResponseSink,
    CredentialBridgeTransport, response_headers_to_proto,
};
use crate::network_policy;

/// Remaining guest frames after the exact Ready was consumed and validated.
pub type CredentialBridgeRelayInput =
    Pin<Box<dyn Stream<Item = v1::CredentialBridgeGuestMessage> + Send>>;

/// Already-admitted host frames returned by the remote authority.
pub type CredentialBridgeRelayOutput =
    Pin<Box<dyn Stream<Item = Result<v1::CredentialBridgeHostMessage, BrokerBridgeError>> + Send>>;

/// What the environment's network policy says about GitHub's hosts, as the
/// relay's owner was told at launch (#4926). The remote authority has no
/// network policy in hand, so the relay applies this one rule itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayNetworkPolicy {
    /// A rule allows GitHub's hosts: every frame is relayed.
    AllowsGitHub,
    /// No rule does: a request on the GitHub slot is answered here with the
    /// fixed refusal and never reaches the remote authority.
    RefusesGitHub,
}

/// Relay one admitted bridge without creating a second request ledger.
///
/// `connect` receives the actual guest Ready and a demand-driven stream of all
/// later guest frames. It must return only after its remote authority has
/// admitted that Ready. Dropping the returned stream must close both remote
/// directions. This runner then forwards only canonical host payloads through
/// the original guest connection and returns when either authority is lost.
pub async fn run_admitted_credential_bridge_relay<B, C, F>(
    admitted: AdmittedCredentialBridge<B>,
    network_policy: RelayNetworkPolicy,
    connect: C,
) -> Result<(), BrokerBridgeError>
where
    B: CredentialBridgeTransport + 'static,
    C: FnOnce(v1::CredentialBridgeReady, CredentialBridgeRelayInput) -> F,
    F: Future<Output = Result<CredentialBridgeRelayOutput, BrokerBridgeError>>,
{
    let AdmittedCredentialBridge { bridge, ready } = admitted;
    let sender = bridge.response_sink();
    let refusals = bridge.response_sink();
    let input = stream::unfold(
        (bridge, refusals),
        move |(mut bridge, refusals)| async move {
            loop {
                match bridge.receive().await {
                    Ok(Some(frame)) if valid_guest_frame(&frame) => {
                        if network_policy == RelayNetworkPolicy::RefusesGitHub
                            && let Some(request) = github_request(&frame)
                        {
                            refuse_github(&refusals, request).await.ok()?;
                            continue;
                        }
                        return Some((frame, (bridge, refusals)));
                    }
                    Ok(None) | Err(_) => return None,
                    Ok(Some(_)) => return None,
                }
            }
        },
    );
    let mut output = connect(ready, Box::pin(input)).await?;
    while let Some(frame) = output.next().await {
        let frame = frame?;
        if frame.encoded_len() > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
            return Err(BrokerBridgeError::InvalidProtocol);
        }
        let payload = match frame.payload {
            // A front-door session's frames are unknown frames on the
            // guest connections this relay carries.
            Some(v1::credential_bridge_host_message::Payload::Open(_)) | None => {
                return Err(BrokerBridgeError::InvalidProtocol);
            }
            Some(payload) if payload.is_front_door() => {
                return Err(BrokerBridgeError::InvalidProtocol);
            }
            Some(payload) => payload,
        };
        sender.send(payload).await?;
    }
    Err(BrokerBridgeError::Unavailable)
}

/// The request in `frame`, when it is one on the GitHub slot.
fn github_request(
    frame: &v1::CredentialBridgeGuestMessage,
) -> Option<&v1::CredentialBridgeRequest> {
    match &frame.payload {
        Some(v1::credential_bridge_guest_message::Payload::Request(request))
            if request.capability_slot == network_policy::GITHUB_SLOT =>
        {
            Some(request)
        }
        _ => None,
    }
}

/// Answer one GitHub request with the fixed refusal, whole, on the guest's
/// own connection. The relay keeps no ledger: the three frames are the
/// request's entire life, and a later cancel for it relays to an authority
/// that never saw it and ignores it.
async fn refuse_github<S: CredentialBridgeResponseSink>(
    sender: &S,
    request: &v1::CredentialBridgeRequest,
) -> Result<(), BrokerBridgeError> {
    network_policy::log_refusal(&request.route);
    let (status, headers, body) = network_policy::github_refusal(&request.route);
    let headers =
        response_headers_to_proto(&headers).map_err(|_| BrokerBridgeError::InvalidProtocol)?;
    let request_id = &request.request_id;
    sender
        .send(v1::credential_bridge_host_message::Payload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request_id.clone(),
                status_code: u32::from(status.as_u16()),
                headers,
            },
        ))
        .await?;
    sender
        .send(v1::credential_bridge_host_message::Payload::ResponseBody(
            v1::CredentialBridgeResponseBody {
                request_id: request_id.clone(),
                data: body.to_vec(),
            },
        ))
        .await?;
    sender
        .send(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: request_id.clone(),
            },
        ))
        .await
}

fn valid_guest_frame(frame: &v1::CredentialBridgeGuestMessage) -> bool {
    frame.encoded_len() <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES
        && matches!(
            frame.payload,
            Some(v1::credential_bridge_guest_message::Payload::Request(_))
                | Some(v1::credential_bridge_guest_message::Payload::Cancel(_))
                | Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(_))
                | Some(v1::credential_bridge_guest_message::Payload::Ssh(_))
                // The local broker lists the Codex and Claude logins on the
                // epoch; the platform broker decides each for the
                // delegation's creator.
                | Some(v1::credential_bridge_guest_message::Payload::CodexLogin(_))
                | Some(v1::credential_bridge_guest_message::Payload::ClaudeLogin(_))
        )
}

#[cfg(test)]
mod tests;
