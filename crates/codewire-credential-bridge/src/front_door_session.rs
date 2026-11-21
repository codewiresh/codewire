//! A front-door session over one byte stream the supervisor made (#3999).
//!
//! The TLS front door runs outside the environment and speaks the guest side
//! of the bridge; the credential broker speaks the host side. They share one
//! Unix stream and nothing else, so there is no gRPC here: each message is a
//! four-byte big-endian length and its protobuf encoding, at most
//! [`CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES`]. The host writes Open first,
//! listing [`CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR`]; the guest answers
//! Ready and then serves exactly as over the daemon's RPC.
//!
//! Which entry a session has is decided by the broker from the socket it was
//! handed, never from anything on this stream (`BridgeEntry`).

use std::time::Duration;

use bytes::{Buf as _, BufMut as _, BytesMut};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET, CREDENTIAL_BRIDGE_MAX_CAPABILITIES,
    CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
    valid_credential_bridge_capability,
};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tonic::Status;

use uuid::Uuid;

use crate::{BridgeIdentity, CredentialBridge, EpochReplacement};

/// The host's first byte on the session socket, before its Open: the role
/// tag the front-door process checks before serving anything, so the socket
/// cannot be mistaken for the egress broker's hand-off (#3999). The front
/// door's process reads it; [`serve_front_door_session`] starts after it.
pub const FRONT_DOOR_SESSION_ROLE_TAG: u8 = b'C';
/// How long the guest waits for the host's Open.
pub const FRONT_DOOR_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Host messages queued for the writer: backpressure, never unbounded.
const HOST_SEND_BUFFER: usize = 32;
const LENGTH_BYTES: usize = 4;

/// Why a front-door session ended or never started. Carries no peer input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrontDoorSessionError {
    #[error("front-door session transport failed")]
    Transport,
    #[error("front-door session frame is invalid")]
    InvalidFrame,
    #[error("front-door session open is missing or invalid")]
    InvalidOpen,
    #[error("front-door session was refused by the bridge")]
    Refused,
}

/// Serve the guest side of one front-door session on `stream` until either
/// end closes it. The first frame must be an Open for `bridge`'s identity
/// that lists [`CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR`].
pub async fn serve_front_door_session<S>(
    bridge: &CredentialBridge,
    stream: S,
) -> Result<(), FrontDoorSessionError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = FrameReader::new(reader);
    let open = tokio::time::timeout(FRONT_DOOR_OPEN_TIMEOUT, reader.next())
        .await
        .map_err(|_| FrontDoorSessionError::InvalidOpen)??
        .ok_or(FrontDoorSessionError::InvalidOpen)?;
    let capabilities = admit_open(open, bridge.identity())?;
    let (prepared, mut output) = bridge
        .prepare_connection()
        .map_err(|_| FrontDoorSessionError::Refused)?;
    let input = futures::stream::unfold(reader, |mut reader| async move {
        match reader.next::<v1::CredentialBridgeHostMessage>().await {
            Ok(Some(message)) => Some((Ok(message), reader)),
            Ok(None) => None,
            Err(_) => Some((
                Err(Status::unavailable("front-door session transport failed")),
                reader,
            )),
        }
    });
    // A broker's successor opens its own session before the predecessor
    // ends: the new session takes all new work, and the old one relays only
    // the requests already sent on it, as for the daemon's loopback session.
    let connection = prepared
        .activate_with_replacement(input, &capabilities, EpochReplacement::Drain)
        .await
        .map_err(|_| FrontDoorSessionError::Refused)?;
    let pump = async {
        while let Some(frame) = output.next().await {
            let frame = frame.map_err(|_| FrontDoorSessionError::Transport)?;
            write_frame(&mut writer, &frame).await?;
        }
        Ok(())
    };
    tokio::select! {
        () = connection.run() => Ok(()),
        result = pump => result,
    }
}

/// The capabilities of a valid front-door Open for `identity`.
fn admit_open(
    message: v1::CredentialBridgeHostMessage,
    identity: BridgeIdentity,
) -> Result<Vec<String>, FrontDoorSessionError> {
    let Some(v1::credential_bridge_host_message::Payload::Open(open)) = message.payload else {
        return Err(FrontDoorSessionError::InvalidOpen);
    };
    let admitted = open.protocol_version == CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        && open.environment_id == identity.environment_id.to_string()
        && open.environment_generation == identity.environment_generation
        && open.capabilities.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITIES
        && open
            .capabilities
            .iter()
            .all(|capability| valid_credential_bridge_capability(capability))
        && open
            .capabilities
            .iter()
            .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR);
    if !admitted {
        return Err(FrontDoorSessionError::InvalidOpen);
    }
    Ok(open.capabilities)
}

/// The Ready of a binding, unframed: what a relay opens every upstream with,
/// and what the front door's own first frame must equal byte for byte.
pub fn binding_ready(environment_id: Uuid, generation: u64) -> Vec<u8> {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
            v1::CredentialBridgeReady {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment_id.to_string(),
                environment_generation: generation,
            },
        )),
    }
    .encode_to_vec()
}

/// What a front-door session's Open lists for an executor that does, or does
/// not, serve WebSocket upgrades: the front door itself and streamed request
/// bodies, since intercepted uploads are the large ones, and `websocket.v1`
/// only when upgrades are served. Listing it otherwise would let a guest send
/// Upgrade frames that end the session (#4973).
pub fn front_door_capabilities(serves_upgrades: bool) -> Vec<&'static str> {
    let mut capabilities = vec![
        CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
        CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    ];
    if serves_upgrades {
        capabilities.push(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET);
    }
    capabilities
}

/// The host side of one front-door session, after its Open was written.
pub struct FrontDoorHostSession {
    reader: FrameReader<tokio::io::ReadHalf<Box<dyn SessionStream>>>,
    sender: FrontDoorHostSender,
    writer: tokio::task::JoinHandle<()>,
}

/// A byte stream a front-door session runs on.
pub trait SessionStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> SessionStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Sends host messages on a [`FrontDoorHostSession`], in order. Each message
/// is queued whole, so a send dropped before it completes writes nothing.
#[derive(Clone)]
pub struct FrontDoorHostSender(mpsc::Sender<v1::CredentialBridgeHostMessage>);

impl FrontDoorHostSession {
    /// Write the Open for `identity`, listing `capabilities`: what the
    /// executor serving this session serves, from [`front_door_capabilities`]
    /// (#4973). A list without [`CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR`], or
    /// over [`CREDENTIAL_BRIDGE_MAX_CAPABILITIES`], or with a malformed name,
    /// opens nothing. Ready is not read here: the caller admits it as it
    /// admits any bridge's first frame.
    pub async fn open<S: SessionStream>(
        stream: S,
        identity: BridgeIdentity,
        capabilities: &[&str],
    ) -> Result<Self, FrontDoorSessionError> {
        let listed = capabilities.len() <= CREDENTIAL_BRIDGE_MAX_CAPABILITIES
            && capabilities
                .iter()
                .all(|capability| valid_credential_bridge_capability(capability))
            && capabilities.contains(&CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR);
        if !listed {
            return Err(FrontDoorSessionError::InvalidOpen);
        }
        let stream: Box<dyn SessionStream> = Box::new(stream);
        let (reader, mut writer) = tokio::io::split(stream);
        let open = v1::CredentialBridgeHostMessage {
            payload: Some(v1::credential_bridge_host_message::Payload::Open(
                v1::CredentialBridgeOpen {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: identity.environment_id.to_string(),
                    environment_generation: identity.environment_generation,
                    capabilities: capabilities
                        .iter()
                        .map(|&capability| capability.to_owned())
                        .collect(),
                    placeholders: Vec::new(),
                },
            )),
        };
        write_frame(&mut writer, &open).await?;
        let (sender, mut queued) = mpsc::channel(HOST_SEND_BUFFER);
        let writer = tokio::spawn(async move {
            while let Some(message) = queued.recv().await {
                if write_frame(&mut writer, &message).await.is_err() {
                    // Dropping the queue fails every later send.
                    return;
                }
            }
        });
        Ok(Self {
            reader: FrameReader::new(reader),
            sender: FrontDoorHostSender(sender),
            writer,
        })
    }

    pub fn sender(&self) -> FrontDoorHostSender {
        self.sender.clone()
    }

    /// Write every message already queued, then end the session. It returns
    /// once every [`FrontDoorHostSender`] of this session is dropped and the
    /// queue is written, so drop the callers' senders first. Dropping the
    /// session instead discards what is queued.
    pub async fn finish(mut self) {
        let writer = std::mem::replace(&mut self.writer, tokio::spawn(async {}));
        drop(self);
        let _ = writer.await;
    }

    /// The next guest message, or `None` when the guest closed the stream.
    /// Cancellation-safe: bytes already read stay buffered.
    pub async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, FrontDoorSessionError> {
        self.reader.next().await
    }

    /// [`Self::receive`], undecoded: the guest message's exact bytes, for a
    /// relay that routes and compares them as sent.
    pub async fn receive_frame(&mut self) -> Result<Option<BytesMut>, FrontDoorSessionError> {
        self.reader.next_frame().await
    }
}

impl Drop for FrontDoorHostSession {
    fn drop(&mut self) {
        self.writer.abort();
    }
}

impl FrontDoorHostSender {
    /// Queue one message. Open is refused: only [`FrontDoorHostSession::open`]
    /// writes it, first.
    pub async fn send(
        &self,
        message: v1::CredentialBridgeHostMessage,
    ) -> Result<(), FrontDoorSessionError> {
        if matches!(
            message.payload,
            None | Some(v1::credential_bridge_host_message::Payload::Open(_))
        ) {
            return Err(FrontDoorSessionError::InvalidFrame);
        }
        self.0
            .send(message)
            .await
            .map_err(|_| FrontDoorSessionError::Transport)
    }
}

/// Reads length-prefixed messages, keeping a partial one buffered across
/// cancelled reads.
struct FrameReader<R> {
    inner: R,
    buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
        }
    }

    async fn next<M: Message + Default>(&mut self) -> Result<Option<M>, FrontDoorSessionError> {
        match self.next_frame().await? {
            Some(frame) => M::decode(frame)
                .map(Some)
                .map_err(|_| FrontDoorSessionError::InvalidFrame),
            None => Ok(None),
        }
    }

    /// The next frame's encoded message, undecoded.
    async fn next_frame(&mut self) -> Result<Option<BytesMut>, FrontDoorSessionError> {
        loop {
            if let Some(length) = self.complete_frame()? {
                self.buffer.advance(LENGTH_BYTES);
                return Ok(Some(self.buffer.split_to(length)));
            }
            let read = self
                .inner
                .read_buf(&mut self.buffer)
                .await
                .map_err(|_| FrontDoorSessionError::Transport)?;
            if read == 0 {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(FrontDoorSessionError::InvalidFrame)
                };
            }
        }
    }

    /// The length of the buffered frame when all of it is buffered. A length
    /// over the bound is refused before its bytes are read.
    fn complete_frame(&mut self) -> Result<Option<usize>, FrontDoorSessionError> {
        let Some(prefix) = self.buffer.first_chunk::<LENGTH_BYTES>() else {
            return Ok(None);
        };
        let length = usize::try_from(u32::from_be_bytes(*prefix))
            .map_err(|_| FrontDoorSessionError::InvalidFrame)?;
        if length > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
            return Err(FrontDoorSessionError::InvalidFrame);
        }
        let total = LENGTH_BYTES + length;
        if self.buffer.len() >= total {
            return Ok(Some(length));
        }
        self.buffer.reserve(total - self.buffer.len());
        Ok(None)
    }
}

async fn write_frame<W, M>(writer: &mut W, message: &M) -> Result<(), FrontDoorSessionError>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let length = message.encoded_len();
    if length > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
        return Err(FrontDoorSessionError::InvalidFrame);
    }
    let prefix = u32::try_from(length).map_err(|_| FrontDoorSessionError::InvalidFrame)?;
    let mut frame = BytesMut::with_capacity(LENGTH_BYTES + length);
    frame.put_u32(prefix);
    message
        .encode(&mut frame)
        .map_err(|_| FrontDoorSessionError::InvalidFrame)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|_| FrontDoorSessionError::Transport)?;
    writer
        .flush()
        .await
        .map_err(|_| FrontDoorSessionError::Transport)
}

#[cfg(test)]
mod tests;
