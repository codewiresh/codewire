//! An admitted epoch's front-door joins (#4001).
//!
//! The epoch keeps the relay token, the daemon's workspace authorization, the
//! broker channel and the broker's epoch handle. A joining session gets only
//! an upstream: a `FrontDoorBridge` stream opened with them and with the
//! binding's Ready, which the broker reads before it answers. Messages cross
//! as bytes through a codec that only copies them, so nothing here decodes a
//! front-door message. The session that joins writes the front door's Open,
//! checks its Ready and routes its requests between upstreams.
//!
//! Each upstream's frames toward the broker hold their own stream budget
//! inside the environment's, and a broker that takes none for the stall bound
//! ends that upstream.

use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES,
};
use futures::StreamExt as _;
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
/// Messages queued each way on one upstream; their bytes are bounded
/// separately toward the broker.
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

/// Make this epoch its binding's current one and open an upstream for each
/// session that asks, one at a time, until the epoch ends. Returns when it is
/// replaced and no session can reach it any more.
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
        let Some(Join { reply }) = join else {
            return;
        };
        let joined = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            joined = epoch.open(cancellation.child_token()) => joined,
        };
        // A session that gave up waiting has nothing to be told.
        let _ = reply.send(joined);
    }
}

impl EpochJoins {
    async fn open(&self, session: CancellationToken) -> Result<Joined, Status> {
        let (guest, guests) = mpsc::channel(FRAME_BUFFER);
        let (queued, queue) = mpsc::channel(FRAME_BUFFER);
        tokio::spawn(forward_guest(
            guests,
            queued,
            self.budget.stream(),
            self.budget.stall(),
            session.clone(),
        ));
        // Unlike the daemon leg, which forwards the daemon's own Ready, the
        // front-door leg writes it: the broker reads Ready before it answers,
        // its identity is the authenticated binding's, never one the front
        // door claims, and the broker still checks it against the workspace
        // authorization.
        let ready = front_door::binding_ready(self.environment_id, self.generation);
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
        let capabilities = super::epoch::broker_capabilities(response.metadata());
        if !capabilities
            .iter()
            .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR)
        {
            session.cancel();
            return Err(unavailable());
        }
        let (output, outgoing) = mpsc::channel(FRAME_BUFFER);
        let ends = session.clone().drop_guard();
        tokio::spawn(forward_host(response.into_inner(), output, session));
        Ok(Joined {
            capabilities,
            guest,
            host: ReceiverStream::new(outgoing).boxed(),
            session: ends,
        })
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

/// The session's messages to the broker, each charged before it is queued.
/// A broker that takes none for `stall`, or a message larger than a budget,
/// ends this upstream.
async fn forward_guest(
    mut guests: mpsc::Receiver<Vec<u8>>,
    queued: mpsc::Sender<(Vec<u8>, Charge)>,
    budget: StreamBudget,
    stall: Duration,
    session: CancellationToken,
) {
    loop {
        let message = tokio::select! {
            biased;
            () = session.cancelled() => return,
            message = guests.recv() => message,
        };
        let Some(message) = message else {
            return;
        };
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

/// The queued guest messages for tonic. Each message's bytes stay charged
/// until tonic asks for the next one.
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

/// The broker's messages to the session, until either ends.
async fn forward_host(
    mut responses: Streaming<Vec<u8>>,
    output: mpsc::Sender<Result<Vec<u8>, Status>>,
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
        if output.send(Ok(message)).await.is_err() {
            break;
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
