//! DERP relay client.
//!
//! Port of the subset of `tailscale.com/derp`'s `Client` +
//! `derphttp.Client` that Codewire needs to interop with the Codewire
//! `codewire-derp` server binary. Async over tokio.
//!
//! Connection flow (from `derp.go`'s "Protocol flow" comment):
//!
//! 1. TCP + (optional) TLS connect.
//! 2. HTTP `GET /derp` with `Upgrade: DERP` / `Connection: Upgrade`;
//!    expect `101 Switching Protocols`, then speak DERP on the same conn.
//! 3. Server sends `ServerKey` (magic + its pubkey).
//! 4. Client sends `ClientInfo` (our pubkey + sealed JSON).
//! 5. Server sends `ServerInfo` (sealed JSON) — read lazily on first recv.
//!
//! Steady state: `Send(dst, pkt)` → server → `RecvPacket(src, pkt)` on the
//! peer. We also answer `Ping` with `Pong` and surface keepalives.
//!
//! Every [`Client`] method is cancellation-safe: transports race `recv`
//! against outgoing packets in a `select!`, and a frame half-read or
//! half-written when that future is dropped stays buffered in the client,
//! so the stream never loses its framing.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::frame::{self, FrameType, FRAME_HEADER_LEN, MAGIC, MAX_PACKET_SIZE, PROTOCOL_VERSION};
use super::key::{NodePrivate, NodePublic, KEY_LEN};
use super::Error;
use rand_core::{CryptoRng, RngCore};

/// Boxable async DERP stream type used by reconnecting transports that need
/// to erase the concrete plain/TLS stream type after the handshake.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedStream = Box<dyn AsyncReadWrite>;

/// `ClientInfo` JSON sent in the `ClientInfo` frame. Field names/casing
/// match Go's `derp.ClientInfo` (Go's `json` tags + default capitalized
/// names). The DERP server only requires `version`; the rest are optional.
#[derive(Serialize)]
struct ClientInfo {
    #[serde(rename = "version")]
    version: i32,
    #[serde(rename = "CanAckPings")]
    can_ack_pings: bool,
}

/// `ServerInfo` JSON, mirroring `derp.ServerInfo`. All fields optional.
#[derive(Deserialize, Default, Debug)]
struct ServerInfo {
    #[serde(default, rename = "TokenBucketBytesPerSecond")]
    _token_bucket_bytes_per_second: i64,
    #[serde(default, rename = "TokenBucketBytesBurst")]
    _token_bucket_bytes_burst: i64,
}

/// A message received from the DERP server. Maps onto `derp.ReceivedMessage`.
#[derive(Debug)]
pub enum ReceivedMessage {
    /// A relayed packet from `source`.
    Packet { source: NodePublic, data: Vec<u8> },
    /// Server told us a peer is gone.
    PeerGone { peer: NodePublic, reason: u8 },
    /// Server's startup info frame.
    ServerInfo,
    /// A no-op keepalive.
    KeepAlive,
    /// A ping we should (and do) answer with a pong.
    Ping([u8; 8]),
    /// A pong reply.
    Pong([u8; 8]),
    /// Connection-health text from the server (empty = healthy).
    Health(String),
    /// A frame type we don't model; raw type byte + payload.
    Other { frame_type: u8, data: Vec<u8> },
}

/// A DERP client over a generic byte stream `S`.
///
/// `S` is typically a `tokio_rustls::client::TlsStream<TcpStream>` (real
/// server) but is generic so tests can drive it over an in-memory duplex
/// pipe or a plain `TcpStream`.
pub struct Client<S> {
    conn: S,
    private: NodePrivate,
    server_key: NodePublic,
    public: NodePublic,
    /// Bytes read from `conn` that do not yet form a whole frame.
    read_buf: Vec<u8>,
    /// Encoded frames not yet fully written to `conn`.
    write_buf: Vec<u8>,
}

/// How much `recv` asks the stream for at once.
const READ_CHUNK: usize = 16 << 10;

/// Largest frame accepted: Go's 1<<20 receive cap plus key overhead.
const MAX_FRAME_LEN: usize = (1 << 20) + 64;

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform the DERP handshake over an already-established stream that
    /// is positioned right at the start of the DERP protocol (i.e. the
    /// HTTP upgrade, if any, has already completed).
    ///
    /// Reads `ServerKey`, then writes `ClientInfo`. `ServerInfo` is read
    /// on demand by [`Self::recv`].
    pub async fn handshake<R: RngCore + CryptoRng>(
        mut conn: S,
        private: NodePrivate,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let server_key = read_server_key(&mut conn).await?;
        let public = private.public();

        // Build + seal ClientInfo, then frame it.
        let info = ClientInfo {
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
        };
        let json = serde_json::to_vec(&info).map_err(|_| Error::Protocol("clientinfo json"))?;
        let sealed = private.seal_to(&server_key, &json, rng)?;

        let mut payload = Vec::with_capacity(KEY_LEN + sealed.len());
        payload.extend_from_slice(public.as_bytes());
        payload.extend_from_slice(&sealed);
        write_frame(&mut conn, FrameType::ClientInfo, &payload).await?;

        Ok(Self {
            conn,
            private,
            server_key,
            public,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        })
    }

    /// Our own public key (DERP routing address).
    pub fn public_key(&self) -> &NodePublic {
        &self.public
    }

    /// The server's public key, learned during the handshake.
    pub fn server_public_key(&self) -> &NodePublic {
        &self.server_key
    }

    /// Erase the concrete stream type while preserving DERP session state.
    pub fn boxed(self) -> Client<BoxedStream>
    where
        S: Send + 'static,
    {
        Client {
            conn: Box::new(self.conn),
            private: self.private,
            server_key: self.server_key,
            public: self.public,
            read_buf: self.read_buf,
            write_buf: self.write_buf,
        }
    }

    /// Send `pkt` to the peer identified by `dst` (a `SendPacket` frame).
    pub async fn send(&mut self, dst: &NodePublic, pkt: &[u8]) -> Result<(), Error> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(Error::Protocol("packet too big"));
        }
        let mut payload = Vec::with_capacity(KEY_LEN + pkt.len());
        payload.extend_from_slice(dst.as_bytes());
        payload.extend_from_slice(pkt);
        self.queue_frame(FrameType::SendPacket, &payload);
        self.flush_writes().await
    }

    /// Send a ping; the server (or peer, for mesh) echoes it in a pong.
    pub async fn send_ping(&mut self, data: [u8; 8]) -> Result<(), Error> {
        self.queue_frame(FrameType::Ping, &data);
        self.flush_writes().await
    }

    /// Tell the server whether this is the client's preferred (home) node.
    pub async fn note_preferred(&mut self, preferred: bool) -> Result<(), Error> {
        self.queue_frame(FrameType::NotePreferred, &[u8::from(preferred)]);
        self.flush_writes().await
    }

    fn queue_frame(&mut self, t: FrameType, payload: &[u8]) {
        frame::encode_header(t, payload.len() as u32, &mut self.write_buf);
        self.write_buf.extend_from_slice(payload);
    }

    /// Write every queued frame byte. Progress is kept in `write_buf`, so a
    /// dropped call leaves the rest for the next one.
    async fn flush_writes(&mut self) -> Result<(), Error> {
        while !self.write_buf.is_empty() {
            let written = self.conn.write(&self.write_buf).await?;
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            self.write_buf.drain(..written);
        }
        self.conn.flush().await?;
        Ok(())
    }

    /// Read one whole frame. Partial bytes are kept in `read_buf`, so a
    /// dropped call loses nothing.
    async fn read_frame(&mut self) -> Result<(FrameType, Vec<u8>), Error> {
        loop {
            if let Some(frame) = take_frame(&mut self.read_buf)? {
                return Ok(frame);
            }
            self.read_buf.reserve(READ_CHUNK);
            if self.conn.read_buf(&mut self.read_buf).await? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
        }
    }

    /// Receive one message from the server. Automatically replies to
    /// `Ping` with `Pong` (matching what magicsock does), decrypts and
    /// discards `ServerInfo`, and surfaces everything else typed.
    pub async fn recv(&mut self) -> Result<ReceivedMessage, Error> {
        // One frame in, one typed message out. We surface keepalives,
        // pings (and auto-pong them), peer-gone, etc. to the caller rather
        // than swallowing them, so the consumer's recv loop stays in
        // control — mirroring `derp.Client.Recv`, which also returns one
        // message per call.
        // Finish a pong an earlier, dropped call queued.
        self.flush_writes().await?;
        let (t, payload) = self.read_frame().await?;
        match t {
            FrameType::ServerInfo => {
                // Decrypt to validate the box, but the contents (rate
                // limits) are advisory and currently unused.
                let _info: ServerInfo = {
                    let clear = self.private.open_from(&self.server_key, &payload)?;
                    serde_json::from_slice(&clear).unwrap_or_default()
                };
                Ok(ReceivedMessage::ServerInfo)
            }
            FrameType::RecvPacket => {
                if payload.len() < KEY_LEN {
                    return Err(Error::Protocol("short recv packet"));
                }
                let source = NodePublic::from_slice(&payload[..KEY_LEN])?;
                let data = payload[KEY_LEN..].to_vec();
                Ok(ReceivedMessage::Packet { source, data })
            }
            FrameType::PeerGone => {
                if payload.len() < KEY_LEN {
                    return Err(Error::Protocol("short peer gone"));
                }
                let peer = NodePublic::from_slice(&payload[..KEY_LEN])?;
                let reason = payload.get(KEY_LEN).copied().unwrap_or(0);
                Ok(ReceivedMessage::PeerGone { peer, reason })
            }
            FrameType::PeerPresent => {
                // Mesh-only; surface the raw frame but don't fail.
                Ok(ReceivedMessage::Other {
                    frame_type: t.to_u8(),
                    data: payload,
                })
            }
            FrameType::KeepAlive => Ok(ReceivedMessage::KeepAlive),
            FrameType::Ping => {
                if payload.len() < 8 {
                    return Err(Error::Protocol("short ping"));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[..8]);
                // Echo the pong, like the Go client.
                self.queue_frame(FrameType::Pong, &data);
                self.flush_writes().await?;
                Ok(ReceivedMessage::Ping(data))
            }
            FrameType::Pong => {
                if payload.len() < 8 {
                    return Err(Error::Protocol("short pong"));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[..8]);
                Ok(ReceivedMessage::Pong(data))
            }
            FrameType::Health => Ok(ReceivedMessage::Health(
                String::from_utf8_lossy(&payload).into_owned(),
            )),
            other => Ok(ReceivedMessage::Other {
                frame_type: other.to_u8(),
                data: payload,
            }),
        }
    }
}

/// Read the `ServerKey` greeting: a `ServerKey` frame whose payload is
/// `MAGIC (8) || server_pub (32)`, possibly with trailing future bytes.
async fn read_server_key<S>(conn: &mut S) -> Result<NodePublic, Error>
where
    S: AsyncRead + Unpin,
{
    let (t, payload) = read_frame(conn).await?;
    if t != FrameType::ServerKey {
        return Err(Error::Protocol("expected server key frame"));
    }
    if payload.len() < MAGIC.len() + KEY_LEN {
        return Err(Error::Protocol("short server key frame"));
    }
    if &payload[..MAGIC.len()] != MAGIC {
        return Err(Error::Protocol("bad DERP magic"));
    }
    NodePublic::from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN])
}

/// Write a single framed message and flush.
async fn write_frame<S>(conn: &mut S, t: FrameType, payload: &[u8]) -> Result<(), Error>
where
    S: AsyncWrite + Unpin,
{
    let buf = frame::encode_frame(t, payload);
    conn.write_all(&buf).await?;
    conn.flush().await?;
    Ok(())
}

/// Read a single frame (header + payload).
async fn read_frame<S>(conn: &mut S) -> Result<(FrameType, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    conn.read_exact(&mut hdr).await?;
    let (t, len) = frame::decode_header(&hdr)?;
    if len as usize > MAX_FRAME_LEN {
        return Err(Error::Protocol("frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    conn.read_exact(&mut payload).await?;
    Ok((t, payload))
}

/// Remove and return the first whole frame in `buf`, if there is one.
fn take_frame(buf: &mut Vec<u8>) -> Result<Option<(FrameType, Vec<u8>)>, Error> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    let (t, len) = frame::decode_header(&buf[..FRAME_HEADER_LEN])?;
    let len = len as usize;
    if len > MAX_FRAME_LEN {
        return Err(Error::Protocol("frame too large"));
    }
    let end = FRAME_HEADER_LEN + len;
    if buf.len() < end {
        return Ok(None);
    }
    let payload = buf[FRAME_HEADER_LEN..end].to_vec();
    buf.drain(..end);
    Ok(Some((t, payload)))
}
