//! An admitted epoch's front-door joins (#4001).
//!
//! The epoch keeps the relay token, the daemon's workspace authorization, the
//! broker channel and the broker's epoch handle. A joining session gets only a
//! `FrontDoorBridge` stream opened with them, and the Open the relay writes
//! from that stream's capabilities. Frames cross as bytes: a guest frame's
//! length is checked and its message goes to the broker through a codec that
//! only copies bytes, so nothing here decodes a front-door message.
//!
//! Each joined session has its own stream budget inside the environment's. A
//! cw-egress that takes no frame for the stall bound ends only its session;
//! a socket out of credit is not a stall, since the broker then sends nothing.

use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use prost::Message as _;
use prost::bytes::{Buf as _, BufMut as _};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::http::uri::PathAndQuery;
use tonic::metadata::MetadataMap;
use tonic::transport::Channel;
use tonic::{Status, Streaming};
use uuid::Uuid;

use super::budget::{Charge, EnvironmentBudget, Oversized, StreamBudget};
use crate::front_door::{self, BindingKey, FrontDoorEpochs, Join, Joined};

const FRONT_DOOR_BRIDGE: &str = "/broker.v1.CredentialBrokerService/FrontDoorBridge";
/// Guest frames queued toward the broker; their bytes are bounded separately.
const FRAME_BUFFER: usize = 32;

/// What one admitted epoch lends the sessions that join it.
pub(super) struct EpochJoins {
    pub(super) environment_id: Uuid,
    pub(super) generation: u64,
    pub(super) channel: Channel,
    /// The epoch's own credential metadata plus its handle. Never leaves here.
    pub(super) metadata: MetadataMap,
    pub(super) budget: EnvironmentBudget,
    pub(super) admission_timeout: Duration,
}

/// Make this epoch its binding's current one and open each session that asks,
/// one at a time, until the epoch ends. Returns when it is replaced and no
/// session can reach it any more.
pub(super) async fn serve(
    epochs: &Arc<FrontDoorEpochs>,
    key: BindingKey,
    epoch: EpochJoins,
    cancellation: &CancellationToken,
) {
    let (joins, mut requests) = mpsc::channel(1);
    let _registration = epochs.register(key, joins);
    loop {
        let join = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            join = requests.recv() => join,
        };
        let Some(Join { frames, reply }) = join else {
            return;
        };
        let joined = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            joined = epoch.open(frames, cancellation.child_token()) => joined,
        };
        // A session that gave up waiting has nothing to be told.
        let _ = reply.send(joined);
    }
}

impl EpochJoins {
    async fn open(
        &self,
        frames: BoxStream<'static, Result<Vec<u8>, Status>>,
        session: CancellationToken,
    ) -> Result<Joined, Status> {
        let (output, outgoing) = mpsc::channel(1);
        let (queued, queue) = mpsc::channel(FRAME_BUFFER);
        let ready = self.ready();
        tokio::spawn(forward_guest(
            frames,
            ready.clone(),
            queued,
            self.budget.stream(),
            self.budget.stall(),
            session.clone(),
            output.clone(),
        ));
        // The broker reads Ready before it answers, and the front door sends
        // its own only after the Open written from that answer, so the relay
        // opens the upstream with the binding's Ready itself.
        let body = futures::stream::once(async move { ready }).chain(held(queue, session.clone()));
        let mut request = tonic::Request::new(body);
        *request.metadata_mut() = self.metadata.clone();
        let mut broker = tonic::client::Grpc::new(self.channel.clone())
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        let response = tokio::time::timeout(self.admission_timeout, async {
            broker.ready().await.map_err(|_| unavailable())?;
            broker
                .streaming(request, PathAndQuery::from_static(FRONT_DOOR_BRIDGE), Raw)
                .await
        })
        .await
        .unwrap_or_else(|_| Err(unavailable()))
        .inspect_err(|_| session.cancel())
        .map_err(|status| refusal(&status))?;
        // The front door's Open lists exactly what the broker listed for
        // this stream, as the daemon's Open does for its epoch.
        let capabilities = super::epoch::broker_capabilities(response.metadata());
        let Some(open) = self.open_frame(capabilities) else {
            session.cancel();
            return Err(unavailable());
        };
        let ends = session.clone().drop_guard();
        tokio::spawn(forward_host(
            response.into_inner(),
            output,
            self.budget.stall(),
            session,
        ));
        Ok(Joined {
            frames: futures::stream::once(async { Ok(open) })
                .chain(ReceiverStream::new(outgoing))
                .boxed(),
            session: ends,
        })
    }
}

impl EpochJoins {
    /// The Ready of the binding this epoch authenticated, unframed. Unlike the
    /// daemon leg, which forwards the daemon's own Ready, the front-door leg
    /// writes it: its identity is the authenticated binding's, never one the
    /// front door claims, and the broker still checks it against the
    /// workspace authorization.
    fn ready(&self) -> Vec<u8> {
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: self.environment_id.to_string(),
                    environment_generation: self.generation,
                },
            )),
        }
        .encode_to_vec()
    }

    /// The framed Open for a stream whose broker serves front-door sessions.
    fn open_frame(&self, capabilities: Vec<String>) -> Option<Vec<u8>> {
        if !capabilities
            .iter()
            .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR)
        {
            return None;
        }
        let open = v1::CredentialBridgeHostMessage {
            payload: Some(v1::credential_bridge_host_message::Payload::Open(
                v1::CredentialBridgeOpen {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: self.environment_id.to_string(),
                    environment_generation: self.generation,
                    capabilities,
                },
            )),
        };
        front_door::framed(&open.encode_to_vec())
    }
}

/// The broker's refusal, as cw-egress may see it: its code for the refusals
/// the design names, never its message.
fn refusal(status: &Status) -> Status {
    match status.code() {
        tonic::Code::PermissionDenied => Status::permission_denied("front-door session denied"),
        tonic::Code::AlreadyExists => {
            Status::already_exists("this epoch already has a front-door session")
        }
        _ => unavailable(),
    }
}

fn unavailable() -> Status {
    Status::unavailable("no credential relay epoch can take this session")
}

/// cw-egress's frames to the broker: each frame's length checked and its
/// bytes charged before it is queued. A bad frame ends the session with one
/// error; a cw-egress that closes its side only closes the broker's.
///
/// The first frame must be the front door's Ready, byte for byte the one the
/// relay already sent for it, within `stall`. It is consumed, and no other
/// frame is forwarded before it.
async fn forward_guest(
    mut frames: BoxStream<'static, Result<Vec<u8>, Status>>,
    ready: Vec<u8>,
    queued: mpsc::Sender<(Vec<u8>, Charge)>,
    budget: StreamBudget,
    stall: Duration,
    session: CancellationToken,
    output: mpsc::Sender<Result<Vec<u8>, Status>>,
) {
    let first = tokio::select! {
        biased;
        () = session.cancelled() => return,
        first = tokio::time::timeout(stall, frames.next()) => first,
    };
    let readied = match first {
        Ok(Some(Ok(frame))) => front_door::frame_message(&frame) == Some(&ready[..]),
        Ok(None) => return,
        Ok(Some(Err(_))) | Err(_) => false,
    };
    if !readied {
        // The session ends either way; the error is only its reason.
        let _ = output.try_send(Err(Status::invalid_argument(
            "a front-door session starts with its binding's Ready",
        )));
        session.cancel();
        return;
    }
    loop {
        let frame = tokio::select! {
            biased;
            () = session.cancelled() => return,
            frame = frames.next() => frame,
        };
        let frame = match frame {
            Some(Ok(frame)) => frame,
            None => return,
            Some(Err(status)) => {
                // The session ends either way; the error is only its reason.
                let _ = output.try_send(Err(status));
                session.cancel();
                return;
            }
        };
        let Some(message) = front_door::frame_message(&frame) else {
            // The session ends either way; the error is only its reason.
            let _ = output.try_send(Err(Status::invalid_argument("front-door frame is invalid")));
            session.cancel();
            return;
        };
        let message = message.to_vec();
        let queue = async {
            let charge = budget.charge(message.len()).await.map_err(|Oversized| ())?;
            queued.send((message, charge)).await.map_err(|_| ())
        };
        let outcome = tokio::select! {
            biased;
            () = session.cancelled() => return,
            outcome = tokio::time::timeout(stall, queue) => outcome,
        };
        if !matches!(outcome, Ok(Ok(()))) {
            session.cancel();
            return;
        }
    }
}

/// The queued guest frames for tonic. Each frame's bytes stay charged until
/// tonic asks for the next one.
fn held(
    queue: mpsc::Receiver<(Vec<u8>, Charge)>,
    session: CancellationToken,
) -> impl futures::Stream<Item = Vec<u8>> + Send + 'static {
    futures::stream::unfold(
        (queue, None::<Charge>, session),
        |(mut queue, held, session)| async move {
            drop(held);
            let next = tokio::select! {
                biased;
                () = session.cancelled() => None,
                next = queue.recv() => next,
            };
            next.map(|(frame, charge)| (frame, (queue, Some(charge), session)))
        },
    )
}

/// The broker's frames to cw-egress, framed. One is held at a time; a
/// cw-egress that takes none for `stall` ends this session alone.
async fn forward_host(
    mut responses: Streaming<Vec<u8>>,
    output: mpsc::Sender<Result<Vec<u8>, Status>>,
    stall: Duration,
    session: CancellationToken,
) {
    loop {
        let message = tokio::select! {
            biased;
            () = session.cancelled() => break,
            message = responses.message() => message,
        };
        let Ok(Some(message)) = message else {
            break;
        };
        let Some(frame) = front_door::framed(&message) else {
            break;
        };
        match tokio::time::timeout(stall, output.send(Ok(frame))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => break,
            Err(_) => {
                tracing::info!(
                    event = "credential_relay_front_door_stalled",
                    "credential relay ended a front-door session that took no frame"
                );
                break;
            }
        }
    }
    session.cancel();
}

/// Copies message bytes, never decoding them.
#[derive(Clone, Copy, Default)]
struct Raw;

impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Raw;
    type Decoder = Raw;

    fn encoder(&mut self) -> Self::Encoder {
        Raw
    }

    fn decoder(&mut self) -> Self::Decoder {
        Raw
    }
}

impl Encoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Vec<u8>, buffer: &mut EncodeBuf<'_>) -> Result<(), Status> {
        buffer.put_slice(&item);
        Ok(())
    }
}

impl Decoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, buffer: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        let mut message = vec![0; buffer.remaining()];
        buffer.copy_to_slice(&mut message);
        Ok(Some(message))
    }
}
