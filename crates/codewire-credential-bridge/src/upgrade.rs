//! WebSocket upgrades on a front-door session (#3999): the guest side.
//!
//! A TLS front door hands an intercepted WebSocket opening request to
//! [`CredentialBridge::upgrade_intercepted`]. It goes to the host as a
//! `CredentialBridgeUpgrade`, only on an epoch whose host's Open lists
//! [`CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET`], and counts against the
//! requests in flight like any request. A host that refuses answers with an
//! ordinary response. One that accepts sends `UpgradeAccepted` and then, at
//! once, a `StreamCredit` of [`CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES`]: the
//! guest starts with no send credit, so a host that skipped it would stall
//! every client that speaks first. The handshake then leaves the requests in flight for the open
//! sockets, at most [`MAX_OPEN_SOCKETS`], and its bytes cross through
//! [`upgraded_stream::pump`], never read. The handshake carries no framing:
//! the host adds `Connection` and `Upgrade` itself.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::body::Body;
use axum::http::header::{CONNECTION, HOST, UPGRADE};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use bytes::Bytes;
use codewire_access::{Refusal, RefusalProvider, Unforwarded};
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT,
    CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES, CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use super::upgraded_stream::{
    self, StreamClose, StreamControl, StreamCredits, StreamFrame, StreamSink,
};
use super::{
    BridgeBodyStream, BridgeFailure, BridgeState, CredentialBridge, FIRST_RESPONSE_TIMEOUT,
    GuestOutput, HOST_SEND_TIMEOUT, PendingCancellation, PendingResponse, RESPONSE_BODY_BUFFER,
    ResponsePhase, ResponseStart, classify_http_request, guest_message, headers_from_proto,
    headers_to_proto, invalid_host_frame, refusal_response, require_live_epoch, take_registered,
    v1,
};

/// The WebSocket sockets one bridge holds open at once, apart from its
/// requests in flight.
pub const MAX_OPEN_SOCKETS: usize = 16;
/// The pipe between the front door's end of a socket and its pump.
const SOCKET_PIPE_BYTES: usize = 64 * 1024;
/// Sockets that ended recently. The host's frames for one may still be on
/// their way; they are dropped, not taken as a protocol error. A host sends
/// nothing for a socket after its close, so only frames already in flight
/// arrive late, within one window each: 32 later closes are far past that,
/// and a frame that late is a broken host.
const ENDED_SOCKETS_KEPT: usize = 2 * MAX_OPEN_SOCKETS;

/// The front door's end of an accepted upgrade: the provider's bytes, both
/// ways.
pub type UpgradedSocket = DuplexStream;

/// The answer to a WebSocket opening request.
pub enum UpgradeAnswer {
    /// The host's `101`, and the front door's end of the socket.
    Switched {
        response: Response<()>,
        socket: UpgradedSocket,
    },
    /// The response to send instead: the host's own refusal, or this
    /// bridge's.
    Refused(Response<Body>),
}

/// What an accepted handshake hands its waiter.
pub(super) struct Switched {
    headers: HeaderMap,
    socket: UpgradedSocket,
}

struct OpenSocket {
    epoch: u64,
    control: StreamControl,
}

/// The open sockets, and those that just ended.
#[derive(Default)]
pub(super) struct Sockets {
    open: BTreeMap<String, OpenSocket>,
    ended: VecDeque<String>,
}

impl Sockets {
    /// Remove the sockets `lost` selects, for their epoch's loss.
    pub(super) fn take(&mut self, lost: impl Fn(u64) -> bool) -> Vec<StreamControl> {
        let ids = self
            .open
            .iter()
            .filter(|(_, socket)| lost(socket.epoch))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| {
                let socket = self.open.remove(&id)?;
                self.remember_ended(id);
                Some(socket.control)
            })
            .collect()
    }

    fn remember_ended(&mut self, id: String) {
        if self.ended.len() == ENDED_SOCKETS_KEPT {
            self.ended.pop_front();
        }
        self.ended.push_back(id);
    }
}

/// Whether a host's Open lists WebSocket upgrades.
pub(super) fn listed(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET)
}

/// Sends one socket's frames on its epoch's output.
struct SocketSink {
    output: GuestOutput,
    request_id: String,
}

impl StreamSink for SocketSink {
    async fn send(&self, frame: StreamFrame) -> Result<(), ()> {
        use v1::credential_bridge_guest_message::Payload;

        let request_id = self.request_id.clone();
        let payload = match frame {
            StreamFrame::Data(data) => Payload::StreamData(v1::CredentialBridgeStreamData {
                request_id,
                data: data.to_vec(),
            }),
            StreamFrame::Credit(credit_bytes) => {
                Payload::StreamCredit(v1::CredentialBridgeStreamCredit {
                    request_id,
                    credit_bytes,
                })
            }
            StreamFrame::Close(kind) => Payload::StreamClose(v1::CredentialBridgeStreamClose {
                request_id,
                kind: close_kind(kind) as i32,
            }),
        };
        match tokio::time::timeout(
            HOST_SEND_TIMEOUT,
            self.output.send(Ok(guest_message(payload))),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            // The epoch's output is gone or stuck; the pump resets.
            _ => Err(()),
        }
    }
}

fn close_kind(kind: StreamClose) -> v1::CredentialBridgeStreamCloseKind {
    match kind {
        StreamClose::HalfClose => v1::CredentialBridgeStreamCloseKind::HalfClose,
        StreamClose::Reset => v1::CredentialBridgeStreamCloseKind::Reset,
    }
}

/// What came back for a handshake.
enum Answer {
    Switched(Switched),
    Started(Result<Result<ResponseStart, BridgeFailure>, oneshot::error::RecvError>),
}

impl CredentialBridge {
    /// A WebSocket opening request a TLS front door outside the environment
    /// intercepted for `host`. This bridge refuses it itself when the
    /// epoch's host does not carry WebSockets or a limit is reached.
    pub async fn upgrade_intercepted(&self, host: &str, request: Request<()>) -> UpgradeAnswer {
        let refused = |refusal, provider| {
            UpgradeAnswer::Refused(refusal_response(refusal, provider, Some(host)))
        };
        let frame = match upgrade_frame(host, &request) {
            Ok(frame) => frame,
            Err(refusal) => return refused(refusal, None),
        };
        let provider = RefusalProvider::for_slot(&frame.capability_slot);
        let request_id = frame.request_id.clone();
        let (start_tx, start_rx) = oneshot::channel();
        let (switched_tx, switched_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(RESPONSE_BODY_BUFFER);
        let completed = Arc::new(AtomicBool::new(false));
        let (epoch, output) = {
            let mut state = self.inner.lock().await;
            let admitted = match admit_handshake(&state) {
                Ok(admitted) => admitted,
                Err(refusal) => return refused(refusal, provider),
            };
            state.pending.insert(
                request_id.clone(),
                PendingResponse {
                    epoch: admitted.0,
                    phase: ResponsePhase::AwaitingStart,
                    received_bytes: 0,
                    response_limit: CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES,
                    credit: None,
                    switched: Some(switched_tx),
                    start: Some(start_tx),
                    body: body_tx,
                    completed: Arc::clone(&completed),
                },
            );
            admitted
        };
        let mut cancellation = PendingCancellation::new(self.clone(), request_id.clone(), epoch);
        let send = output.send(Ok(guest_message(
            v1::credential_bridge_guest_message::Payload::Upgrade(frame),
        )));
        if !matches!(
            tokio::time::timeout(HOST_SEND_TIMEOUT, send).await,
            Ok(Ok(()))
        ) {
            self.detach(epoch).await;
            cancellation.disarm();
            return refused(Refusal::CredentialUnavailable, provider);
        }
        let answer = tokio::time::timeout(FIRST_RESPONSE_TIMEOUT, async {
            let mut switched_rx = switched_rx;
            let mut start_rx = start_rx;
            // An accepted handshake leaves the pending table, dropping its
            // start sender, only after its socket was sent here.
            tokio::select! {
                biased;
                Ok(switched) = &mut switched_rx => Answer::Switched(switched),
                started = &mut start_rx => Answer::Started(started),
            }
        })
        .await;
        match answer {
            Ok(Answer::Switched(Switched { headers, socket })) => {
                cancellation.disarm();
                let mut response = Response::new(());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                *response.headers_mut() = headers;
                UpgradeAnswer::Switched { response, socket }
            }
            Ok(Answer::Started(Ok(Ok(start)))) => {
                let mut refused = Response::new(Body::from_stream(BridgeBodyStream {
                    inner: ReceiverStream::new(body_rx),
                    cancellation,
                    completed,
                    failure_emitted: false,
                    _upload: None,
                }));
                *refused.status_mut() = start.status;
                *refused.headers_mut() = start.headers;
                UpgradeAnswer::Refused(refused)
            }
            Ok(Answer::Started(Ok(Err(failure)))) => refused(failure.refusal(), provider),
            Ok(Answer::Started(Err(_))) | Err(_) => {
                self.cancel(&request_id, epoch).await;
                cancellation.disarm();
                refused(Refusal::CredentialUnavailable, provider)
            }
        }
    }

    /// A host frame for a WebSocket: its acceptance, or one of its stream
    /// frames.
    pub(super) async fn apply_socket_frame(
        &self,
        epoch: u64,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), Status> {
        use v1::credential_bridge_host_message::Payload;

        match payload {
            Payload::UpgradeAccepted(accepted) => self.accept_upgrade(epoch, accepted).await,
            Payload::StreamData(data) => {
                self.to_socket(epoch, &data.request_id, |socket| {
                    socket.deliver(Bytes::from(data.data))
                })
                .await
            }
            Payload::StreamCredit(credit) => {
                self.to_socket(epoch, &credit.request_id, |socket| {
                    socket.credit(credit.credit_bytes)
                })
                .await
            }
            Payload::StreamClose(close) => {
                let kind = match v1::CredentialBridgeStreamCloseKind::try_from(close.kind) {
                    Ok(v1::CredentialBridgeStreamCloseKind::HalfClose) => StreamClose::HalfClose,
                    Ok(v1::CredentialBridgeStreamCloseKind::Reset) => StreamClose::Reset,
                    _ => return Err(invalid_host_frame()),
                };
                self.to_socket(epoch, &close.request_id, |socket| socket.close(kind))
                    .await
            }
            _ => Err(invalid_host_frame()),
        }
    }

    /// The handshake `accepted` answers becomes an open socket, and its
    /// waiter gets the front door's end of it.
    async fn accept_upgrade(
        &self,
        epoch: u64,
        accepted: v1::CredentialBridgeUpgradeAccepted,
    ) -> Result<(), Status> {
        let headers = headers_from_proto(&accepted.headers)?;
        let request_id = accepted.request_id;
        let mut state = self.inner.lock().await;
        require_live_epoch(&state, epoch)?;
        let output = state
            .live_host(epoch)
            .map(|host| host.output.clone())
            .ok_or_else(invalid_host_frame)?;
        let mut pending = take_registered(&mut state.pending, &request_id, |pending| {
            pending.epoch == epoch
                && pending.switched.is_some()
                && pending.phase != ResponsePhase::Streaming
        })?;
        // Handshakes are admitted only while a socket is free.
        if state.sockets.open.len() >= MAX_OPEN_SOCKETS {
            return Err(invalid_host_frame());
        }
        let (socket, pumped) = tokio::io::duplex(SOCKET_PIPE_BYTES);
        let (control, running) = upgraded_stream::pump(
            pumped,
            SocketSink {
                output,
                request_id: request_id.clone(),
            },
            StreamCredits {
                send: 0,
                granted: CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
            },
        );
        state.sockets.open.insert(
            request_id.clone(),
            OpenSocket {
                epoch,
                control: control.clone(),
            },
        );
        drop(state);
        let bridge = self.clone();
        let ended_id = request_id.clone();
        drop(tokio::spawn(async move {
            running.await;
            bridge.socket_ended(ended_id, epoch).await;
        }));
        let switched = pending.switched.take().ok_or_else(invalid_host_frame)?;
        // A front door that left first has no waiter: dropping its end lets
        // the pump tell the host.
        let _unwanted = switched.send(Switched { headers, socket });
        Ok(())
    }

    /// Apply a stream frame to the socket it names. A frame for a socket that
    /// just ended raced that end and is dropped; one for a socket this bridge
    /// never opened is a protocol error, like any stray frame.
    async fn to_socket(
        &self,
        epoch: u64,
        request_id: &str,
        apply: impl FnOnce(&StreamControl) -> Result<(), upgraded_stream::StreamProtocolError>,
    ) -> Result<(), Status> {
        let state = self.inner.lock().await;
        require_live_epoch(&state, epoch)?;
        match state.sockets.open.get(request_id) {
            Some(socket) if socket.epoch == epoch => {
                apply(&socket.control).map_err(|_| invalid_host_frame())
            }
            None if state.sockets.ended.iter().any(|ended| ended == request_id) => Ok(()),
            _ => Err(invalid_host_frame()),
        }
    }

    async fn socket_ended(&self, request_id: String, epoch: u64) {
        let mut state = self.inner.lock().await;
        if state
            .sockets
            .open
            .get(&request_id)
            .is_some_and(|socket| socket.epoch == epoch)
        {
            state.sockets.open.remove(&request_id);
            state.sockets.remember_ended(request_id);
        }
    }
}

/// The active epoch and its output, when it can take one more handshake:
/// its host carries WebSockets, a request slot is free, and a socket would
/// be free once this one is accepted.
fn admit_handshake(state: &BridgeState) -> Result<(u64, GuestOutput), Refusal> {
    let active = state
        .active
        .as_ref()
        .ok_or(Refusal::CredentialUnavailable)?;
    if !active.websockets {
        return Err(Refusal::WebsocketNotServed);
    }
    if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        return Err(Refusal::Busy);
    }
    let handshakes = state
        .pending
        .values()
        .filter(|pending| pending.switched.is_some())
        .count();
    if state.sockets.open.len() + handshakes >= MAX_OPEN_SOCKETS {
        return Err(Refusal::Busy);
    }
    Ok((active.epoch, active.output.clone()))
}

/// The handshake frame for `request`: classified exactly as a request is,
/// with the upgrade's own headers aside, which the classifier refuses on
/// every other request, and without framing or `Host`.
fn upgrade_frame(
    host: &str,
    request: &Request<()>,
) -> Result<v1::CredentialBridgeUpgrade, Refusal> {
    let headers = request.headers();
    let websocket = headers
        .get(UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if request.method() != Method::GET || !websocket {
        return Err(Refusal::RequestNotForwarded(Unforwarded::Refused));
    }
    let mut plain = headers.clone();
    plain.remove(UPGRADE);
    plain.remove(CONNECTION);
    let websocket_headers = plain
        .keys()
        .filter(|name| name.as_str().starts_with("sec-websocket-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in websocket_headers {
        plain.remove(name);
    }
    let classified = classify_http_request(request.method(), request.uri(), &plain)?;
    let mut sent = headers.clone();
    sent.remove(HOST);
    Ok(v1::CredentialBridgeUpgrade {
        request_id: crate::request_id_of(request).to_string(),
        method: Method::GET.as_str().to_owned(),
        path: classified.path.to_owned(),
        query: classified.query.unwrap_or_default().to_owned(),
        headers: headers_to_proto(&sent)
            .map_err(|()| Refusal::RequestNotForwarded(Unforwarded::Malformed))?,
        capability_slot: classified.capability_slot.to_owned(),
        route: classified.route.to_owned(),
        intercepted_host: host.to_owned(),
        initial_credit_bytes: CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES,
        intercept_decision: Vec::new(),
    })
}

#[cfg(test)]
mod tests;
