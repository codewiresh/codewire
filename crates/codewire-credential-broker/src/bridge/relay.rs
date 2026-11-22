//! Transparent relay for a native guest bridge, opened once its remote
//! authority has admitted it.
//!
//! This adapter owns no operation ledger and interprets no provider request.
//! It only checks the guest's Ready against its own and applies backpressure
//! while carrying the canonical shared frames to and from an owner-selected
//! relay.

use std::future::Future;
use std::pin::Pin;

use codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_daemon_proto::codewire::bridge::v1;
use futures::{Stream, StreamExt as _, stream};
use prost::Message as _;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::{
    BrokerBridgeError, CredentialBridgeResponseSink, CredentialBridgeTransport, admit_bridge,
    response_headers_to_proto,
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

/// Relay one guest bridge, opened only once its remote authority has admitted
/// it, without creating a second request ledger.
///
/// `connect` receives the Ready this relay builds from `environment_id` and
/// `environment_generation`, and a demand-driven stream of all later guest
/// frames. It must return only after its remote authority has admitted that
/// Ready, with the authority's frames and what to do once the guest's bridge
/// is open. Dropping the returned stream must close both remote directions.
///
/// Only then is `open` run: it sends the guest its Open, which activates the
/// guest's epoch. So an authority that refuses leaves the guest no lost
/// epoch, and its startup launch waits for the successor relay instead of
/// ending the boot (#5957). The guest's own Ready must be the one built here.
/// This runner then forwards only canonical host payloads through that guest
/// connection and returns when either authority is lost.
pub async fn run_credential_bridge_relay<B, O, C, F, R>(
    environment_id: Uuid,
    environment_generation: u64,
    network_policy: RelayNetworkPolicy,
    connect: C,
    open: O,
) -> Result<(), BrokerBridgeError>
where
    B: CredentialBridgeTransport + 'static,
    O: Future<Output = Result<B, BrokerBridgeError>>,
    C: FnOnce(v1::CredentialBridgeReady, CredentialBridgeRelayInput) -> F,
    F: Future<Output = Result<(CredentialBridgeRelayOutput, R), BrokerBridgeError>>,
    R: Future<Output = Result<(), BrokerBridgeError>>,
{
    if environment_id.is_nil() || environment_generation == 0 {
        return Err(BrokerBridgeError::InvalidIdentity);
    }
    let ready = v1::CredentialBridgeReady {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: environment_id.to_string(),
        environment_generation,
    };
    // The guest's frames follow once its bridge is open; until then the
    // authority's demand waits.
    let (opened_bridge, guest) = oneshot::channel::<B>();
    let input = stream::once(guest)
        .filter_map(|bridge| std::future::ready(bridge.ok()))
        .flat_map(move |bridge| guest_frames(bridge, network_policy));
    let (mut output, opened) = connect(ready.clone(), Box::pin(input)).await?;
    let (bridge, guest_ready) =
        admit_bridge(open.await?, environment_id, environment_generation).await?;
    if guest_ready != ready {
        return Err(BrokerBridgeError::InvalidIdentity);
    }
    let sender = bridge.response_sink();
    // An authority that dropped its input reads no guest frame.
    let _ = opened_bridge.send(bridge);
    opened.await?;
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

/// The guest's frames after its Ready, ending at the first frame the relay
/// doesn't carry. A GitHub request the network policy refuses is answered
/// here and never reaches the authority.
fn guest_frames<B: CredentialBridgeTransport + 'static>(
    bridge: B,
    network_policy: RelayNetworkPolicy,
) -> impl Stream<Item = v1::CredentialBridgeGuestMessage> + Send {
    let refusals = bridge.response_sink();
    stream::unfold(
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
    )
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
