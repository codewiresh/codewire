//! Rust DERP relay core.
//!
//! This is the first #22/#58 server-side slice: it accepts already-upgraded
//! DERP streams, performs the same key-authenticated handshake as the Go DERP
//! server, and relays packets between connected clients by DERP node key.
//! The HTTP upgrade listeners are included here so Rust clients and the
//! candidate binary can exercise the same `/derp` entrypoint as the Go server.
//! The STUN listener covers the STUN-only edge mode used by the current Go
//! binary. Mesh forwarding covers the multi-replica DERP deployment shape.

mod runner;
pub use runner::run_from_env;

use std::collections::{HashMap, VecDeque};
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_tailnet::derp::frame::{self, FRAME_HEADER_LEN, FrameType, MAGIC, MAX_PACKET_SIZE};
use codewire_tailnet::derp::key::KEY_LEN;
use codewire_tailnet::derp::{NodePrivate, NodePublic};
use futures_util::{Sink, Stream};
use rcgen::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::PrivateKeyDer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Derp(#[from] codewire_tailnet::derp::Error),
    #[error("derp protocol: {0}")]
    Protocol(&'static str),
    #[error("http: {0}")]
    Http(&'static str),
    #[error("tls: {0}")]
    Tls(String),
    #[error("stun: {0}")]
    Stun(&'static str),
    #[error("mesh: {0}")]
    Mesh(&'static str),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("writer task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("limit: {0}")]
    Limit(&'static str),
}

type Result<T> = std::result::Result<T, Error>;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_HEADER_LEN: usize = 20;
const STUN_TRANSACTION_ID_LEN: usize = 12;
const MAX_STUN_PACKET: usize = 1500;
const STUN_FINGERPRINT_XOR: u32 = 0x5354_554e;
const MESH_KEY_LEN: usize = 32;
const PEER_PRESENT_FRAME_LEN: usize = KEY_LEN + 16 + 2 + 1;
const PEER_GONE_REASON_DISCONNECTED: u8 = 0x00;
const PEER_PRESENT_IS_REGULAR: u8 = 1 << 0;

// DERP handshakes are unauthenticated by design, so the relay bounds what an
// anonymous client can hold (#2505 M2).

/// Each step before relaying (TLS handshake, HTTP request head, DERP
/// handshake) must finish within this budget, so a client that stalls or
/// trickles bytes cannot keep its connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections one relay serves at once across its listeners. A connection
/// holds its slot from TCP accept until it closes, and one past the cap is
/// closed at once. Every registered peer belongs to a live connection, so
/// this also bounds the peer table.
const MAX_CONNECTIONS: usize = 10_000;
/// Largest HTTP request head the relay reads before the upgrade.
const MAX_HTTP_HEAD_BYTES: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshKey([u8; MESH_KEY_LEN]);

impl MeshKey {
    pub fn parse(raw: &str) -> std::result::Result<Self, Error> {
        let raw = raw.trim();
        if raw.len() != MESH_KEY_LEN * 2 {
            return Err(Error::Mesh("mesh key must be 64 hex characters"));
        }
        let mut out = [0u8; MESH_KEY_LEN];
        for (i, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
            out[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
        }
        Ok(Self(out))
    }

    fn as_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(MESH_KEY_LEN * 2);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn constant_time_eq(self, other: Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Mesh("mesh key must be hex")),
    }
}

#[derive(Clone)]
pub struct Relay {
    private: NodePrivate,
    public: NodePublic,
    mesh_key: Option<MeshKey>,
    inner: Arc<RelayInner>,
    connections: Arc<Semaphore>,
}

#[derive(Default)]
struct RelayInner {
    peers: Mutex<HashMap<NodePublic, mpsc::Sender<OutboundFrame>>>,
    forwarders: Mutex<HashMap<NodePublic, MeshForwarder>>,
    watchers: Mutex<HashMap<usize, mpsc::Sender<OutboundFrame>>>,
    next_id: AtomicUsize,
}

#[derive(Debug)]
struct OutboundFrame {
    typ: FrameType,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct MeshForwarder {
    id: usize,
    tx: mpsc::Sender<OutboundFrame>,
}

#[derive(Deserialize, Serialize)]
struct ClientInfo {
    #[serde(rename = "version")]
    version: i32,
    #[serde(default, rename = "CanAckPings")]
    _can_ack_pings: bool,
    #[serde(default, rename = "meshKey", alias = "MeshKey")]
    mesh_key: Option<String>,
}

struct Handshake {
    peer: NodePublic,
    is_mesh: bool,
    server_info: Vec<u8>,
}

impl Relay {
    pub fn new(private: NodePrivate) -> Self {
        let public = private.public();
        Self {
            private,
            public,
            mesh_key: None,
            inner: Arc::new(RelayInner::default()),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub fn new_with_mesh_key(private: NodePrivate, mesh_key: MeshKey) -> Self {
        let public = private.public();
        Self {
            private,
            public,
            mesh_key: Some(mesh_key),
            inner: Arc::new(RelayInner::default()),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub fn public_key(&self) -> &NodePublic {
        &self.public
    }

    /// A connection slot, or `None` when the relay already serves
    /// [`MAX_CONNECTIONS`]. The connection keeps the slot until it drops.
    fn admit(&self, peer_addr: SocketAddr) -> Option<OwnedSemaphorePermit> {
        let slot = self.connections.clone().try_acquire_owned().ok();
        if slot.is_none() {
            tracing::warn!(%peer_addr, "derp connection refused: relay at capacity");
        }
        slot
    }

    pub async fn accept<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake(&mut stream))
            .await
            .map_err(|_| Error::Limit("derp handshake timed out"))??;
        let peer = handshake.peer;
        let registered = !handshake.is_mesh;
        let (tx, rx) = mpsc::channel(64);
        // Clients may send as soon as they read ServerInfo, so regular peers
        // must be routable before that frame is visible on the wire.
        if registered {
            self.inner.register(peer.clone(), tx.clone()).await;
        }
        if let Err(err) =
            write_frame(&mut stream, FrameType::ServerInfo, &handshake.server_info).await
        {
            if registered {
                self.inner.unregister(&peer).await;
            }
            return Err(err);
        }

        let (reader, writer) = tokio::io::split(stream);
        let writer_task = tokio::spawn(write_loop(writer, rx));
        let read_result = self
            .read_loop(reader, peer.clone(), tx, handshake.is_mesh)
            .await;

        if registered {
            self.inner.unregister(&peer).await;
        }
        writer_task.await??;
        read_result
    }

    async fn handshake<S>(&self, stream: &mut S) -> Result<Handshake>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut server_key = Vec::with_capacity(MAGIC.len() + KEY_LEN);
        server_key.extend_from_slice(MAGIC);
        server_key.extend_from_slice(self.public.as_bytes());
        write_frame(stream, FrameType::ServerKey, &server_key).await?;

        let (typ, body) = read_frame(stream).await?;
        if typ != FrameType::ClientInfo {
            return Err(Error::Protocol("expected client info"));
        }
        if body.len() < KEY_LEN {
            return Err(Error::Protocol("short client info"));
        }

        let peer = NodePublic::from_slice(&body[..KEY_LEN])?;
        let clear = self.private.open_from(&peer, &body[KEY_LEN..])?;
        let info: ClientInfo = serde_json::from_slice(&clear)?;
        if info.version < frame::PROTOCOL_VERSION {
            return Err(Error::Protocol("unsupported protocol version"));
        }
        let is_mesh = match (info.mesh_key.as_deref(), self.mesh_key) {
            (Some(raw), Some(expected)) => MeshKey::parse(raw)?.constant_time_eq(expected),
            _ => false,
        };

        let server_info = self.private.seal_to(
            &peer,
            br#"{"TokenBucketBytesPerSecond":0,"TokenBucketBytesBurst":0}"#,
            &mut rand::rngs::OsRng,
        )?;

        Ok(Handshake {
            peer,
            is_mesh,
            server_info,
        })
    }

    pub async fn connect_mesh_io<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mesh_key = self
            .mesh_key
            .ok_or(Error::Mesh("mesh key not configured"))?;
        let server_key = read_server_key(&mut stream).await?;
        let info = ClientInfo {
            version: frame::PROTOCOL_VERSION,
            _can_ack_pings: true,
            mesh_key: Some(mesh_key.as_hex()),
        };
        let json = serde_json::to_vec(&info)?;
        let sealed = self
            .private
            .seal_to(&server_key, &json, &mut rand::rngs::OsRng)?;
        let mut payload = Vec::with_capacity(KEY_LEN + sealed.len());
        payload.extend_from_slice(self.public.as_bytes());
        payload.extend_from_slice(&sealed);
        write_frame(&mut stream, FrameType::ClientInfo, &payload).await?;

        let (tx, rx) = mpsc::channel(64);
        write_frame(&mut stream, FrameType::WatchConns, &[]).await?;

        let forwarder_id = self.inner.next_id();
        let (reader, writer) = tokio::io::split(stream);
        let writer_task = tokio::spawn(write_loop(writer, rx));
        let read_result = self
            .mesh_read_loop(reader, forwarder_id, tx.clone(), server_key)
            .await;
        self.inner.unregister_forwarder_id(forwarder_id).await;
        drop(tx);
        writer_task.await??;
        read_result
    }

    async fn mesh_read_loop<R>(
        &self,
        mut reader: R,
        forwarder_id: usize,
        tx: mpsc::Sender<OutboundFrame>,
        server_key: NodePublic,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            let frame = match read_frame(&mut reader).await {
                Ok(frame) => frame,
                Err(Error::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };

            match frame {
                (FrameType::ServerInfo, body) => {
                    let _clear = self.private.open_from(&server_key, &body)?;
                }
                (FrameType::PeerPresent, body) => {
                    let peer = parse_peer_present(&body)?;
                    if peer != self.public {
                        self.inner
                            .register_forwarder(
                                peer,
                                MeshForwarder {
                                    id: forwarder_id,
                                    tx: tx.clone(),
                                },
                            )
                            .await;
                    }
                }
                (FrameType::PeerGone, body) => {
                    let (peer, _) = parse_peer_gone(&body)?;
                    self.inner.unregister_forwarder(&peer, forwarder_id).await;
                }
                (FrameType::Ping, body) => {
                    if body.len() < 8 {
                        return Err(Error::Protocol("short ping"));
                    }
                    let mut pong = [0u8; 8];
                    pong.copy_from_slice(&body[..8]);
                    let _ = tx
                        .send(OutboundFrame {
                            typ: FrameType::Pong,
                            payload: pong.to_vec(),
                        })
                        .await;
                }
                (FrameType::KeepAlive, _) | (FrameType::Pong, _) | (FrameType::Health, _) => {}
                _ => {}
            }
        }
    }

    async fn read_loop<R>(
        &self,
        mut reader: R,
        peer: NodePublic,
        own_tx: mpsc::Sender<OutboundFrame>,
        is_mesh: bool,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut watcher_id = None;
        let result = loop {
            let frame = match read_frame(&mut reader).await {
                Ok(frame) => frame,
                Err(Error::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => break Ok(()),
                Err(err) => break Err(err),
            };

            match frame {
                (FrameType::SendPacket, body) => {
                    let (dst, pkt) = parse_send_packet(&body)?;
                    self.inner.route_packet(&peer, dst, pkt).await?;
                }
                (FrameType::ForwardPacket, body) if is_mesh => {
                    let (src, dst, pkt) = parse_forward_packet(&body)?;
                    self.inner.route_forwarded_packet(&src, dst, pkt).await?;
                }
                (FrameType::ForwardPacket, _) => {
                    break Err(Error::Protocol("insufficient permissions"));
                }
                (FrameType::WatchConns, body) if is_mesh => {
                    if !body.is_empty() {
                        break Err(Error::Protocol("watch conns body must be empty"));
                    }
                    if peer != self.public && watcher_id.is_none() {
                        watcher_id = Some(self.inner.register_watcher(own_tx.clone()).await);
                    }
                }
                (FrameType::WatchConns, _) => {
                    break Err(Error::Protocol("insufficient permissions"));
                }
                (FrameType::ClosePeer, body) if is_mesh => {
                    let target = parse_close_peer(&body)?;
                    self.inner.unregister(&target).await;
                }
                (FrameType::ClosePeer, _) => {
                    break Err(Error::Protocol("insufficient permissions"));
                }
                (FrameType::Ping, body) => {
                    if body.len() < 8 {
                        break Err(Error::Protocol("short ping"));
                    }
                    let mut pong = [0u8; 8];
                    pong.copy_from_slice(&body[..8]);
                    let _ = own_tx
                        .send(OutboundFrame {
                            typ: FrameType::Pong,
                            payload: pong.to_vec(),
                        })
                        .await;
                }
                (FrameType::NotePreferred, _)
                | (FrameType::KeepAlive, _)
                | (FrameType::Pong, _) => {}
                (FrameType::ClientInfo, _) => break Err(Error::Protocol("duplicate client info")),
                _ => {}
            }
        };
        if let Some(id) = watcher_id {
            self.inner.unregister_watcher(id).await;
        }
        result
    }
}

pub async fn serve_plain(listener: TcpListener, relay: Relay) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Some(slot) = relay.admit(peer_addr) else {
            continue;
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(err) = accept_http_io(relay, stream, peer_addr).await {
                log_connection_error(&err, peer_addr, "derp connection failed");
            }
        });
    }
}

pub async fn serve_tls(listener: TcpListener, relay: Relay, config: ServerConfig) -> Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Some(slot) = relay.admit(peer_addr) else {
            continue;
        };
        let relay = relay.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let result = async {
                let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                    .await
                    .map_err(|_| Error::Limit("tls handshake timed out"))?
                    .map_err(|err| Error::Tls(err.to_string()))?;
                accept_http_io(relay, stream, peer_addr).await
            }
            .await;
            if let Err(err) = result {
                log_connection_error(&err, peer_addr, "derp tls connection failed");
            }
        });
    }
}

/// A client that runs out its handshake budget is routine under load or
/// attack, so it logs at debug; every other failure stays a warning.
fn log_connection_error(err: &Error, peer_addr: SocketAddr, message: &'static str) {
    match err {
        Error::Limit(reason) => tracing::debug!(%peer_addr, reason, "derp connection closed"),
        _ => tracing::warn!(error = ?err, %peer_addr, "{message}"),
    }
}

pub async fn serve_mesh_discovery(
    relay: Relay,
    hostname: String,
    port: u16,
    self_ip: Option<IpAddr>,
) -> Result<()> {
    let mut peers: HashMap<IpAddr, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        interval.tick().await;
        let addrs: Vec<SocketAddr> = match lookup_host((hostname.as_str(), port)).await {
            Ok(addrs) => addrs.collect(),
            Err(err) => {
                tracing::warn!(error = ?err, %hostname, "derp mesh dns lookup failed");
                continue;
            }
        };
        let mut seen = HashMap::new();
        for addr in addrs {
            if Some(addr.ip()) == self_ip {
                continue;
            }
            seen.insert(addr.ip(), addr);
        }

        peers.retain(|ip, task| {
            let keep = seen.contains_key(ip) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });

        for (ip, addr) in seen {
            if peers.contains_key(&ip) {
                continue;
            }
            tracing::info!(%addr, "derp mesh peer discovered");
            let relay = relay.clone();
            let host = hostname.clone();
            peers.insert(
                ip,
                tokio::spawn(async move {
                    run_mesh_peer_loop(relay, addr, host).await;
                }),
            );
        }
    }
}

async fn run_mesh_peer_loop(relay: Relay, addr: SocketAddr, host: String) {
    loop {
        match connect_mesh_plain(relay.clone(), addr, &host).await {
            Ok(()) => {
                tracing::info!(%addr, "derp mesh peer disconnected");
            }
            Err(err) => {
                tracing::warn!(error = ?err, %addr, "derp mesh peer connection failed");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn connect_mesh_plain(relay: Relay, addr: SocketAddr, host: &str) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    write_http_upgrade(&mut stream, host).await?;
    relay.connect_mesh_io(stream).await
}

pub fn self_signed_tls_config(hosts: &[String]) -> Result<ServerConfig> {
    let subject_alt_names = normalized_tls_hosts(hosts);
    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|err| Error::Tls(err.to_string()))?;
    let certs = vec![cert.der().clone()];
    let key = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|err| Error::Tls(err.to_string()))?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| Error::Tls(err.to_string()))
}

fn normalized_tls_hosts(hosts: &[String]) -> Vec<String> {
    let hosts: Vec<_> = hosts
        .iter()
        .map(|host| host.trim())
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if hosts.is_empty() {
        vec!["127.0.0.1".to_string(), "localhost".to_string()]
    } else {
        hosts
    }
}

pub async fn serve_stun(socket: UdpSocket) -> Result<()> {
    let mut buf = [0u8; MAX_STUN_PACKET];
    loop {
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;
        match stun_binding_response(&buf[..n], peer_addr) {
            Ok(Some(response)) => {
                if let Err(err) = socket.send_to(&response, peer_addr).await {
                    tracing::warn!(error = ?err, %peer_addr, "stun response failed");
                }
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(error = ?err, %peer_addr, "ignoring invalid stun packet");
            }
        }
    }
}

fn stun_binding_response(packet: &[u8], peer_addr: SocketAddr) -> Result<Option<Vec<u8>>> {
    if packet.len() < STUN_HEADER_LEN {
        return Err(Error::Stun("packet too short"));
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != STUN_BINDING_REQUEST {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if STUN_HEADER_LEN + message_len > packet.len() {
        return Err(Error::Stun("declared length exceeds packet"));
    }
    if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != STUN_MAGIC_COOKIE {
        return Err(Error::Stun("bad magic cookie"));
    }

    let mut tx_id = [0u8; STUN_TRANSACTION_ID_LEN];
    tx_id.copy_from_slice(&packet[8..STUN_HEADER_LEN]);
    Ok(Some(stun_binding_success_response(tx_id, peer_addr)))
}

fn stun_binding_success_response(
    tx_id: [u8; STUN_TRANSACTION_ID_LEN],
    peer_addr: SocketAddr,
) -> Vec<u8> {
    let mapped_attr = stun_xor_mapped_address_attr(tx_id, peer_addr);
    let message_len = mapped_attr.len() + 8;
    let mut out = Vec::with_capacity(STUN_HEADER_LEN + message_len);
    out.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&(message_len as u16).to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&tx_id);
    out.extend_from_slice(&mapped_attr);

    let fingerprint = stun_fingerprint(&out);
    out.extend_from_slice(&STUN_ATTR_FINGERPRINT.to_be_bytes());
    out.extend_from_slice(&(4u16).to_be_bytes());
    out.extend_from_slice(&fingerprint.to_be_bytes());
    out
}

fn stun_xor_mapped_address_attr(
    tx_id: [u8; STUN_TRANSACTION_ID_LEN],
    peer_addr: SocketAddr,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    match peer_addr {
        SocketAddr::V4(addr) => {
            out.extend_from_slice(&(8u16).to_be_bytes());
            out.push(0);
            out.push(0x01);
            out.extend_from_slice(
                &(addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
            );
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = addr.ip().octets();
            out.extend(ip.iter().zip(cookie).map(|(a, b)| a ^ b));
        }
        SocketAddr::V6(addr) => {
            out.extend_from_slice(&(20u16).to_be_bytes());
            out.push(0);
            out.push(0x02);
            out.extend_from_slice(
                &(addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
            );
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&tx_id);
            let ip = addr.ip().octets();
            out.extend(ip.iter().zip(mask).map(|(a, b)| a ^ b));
        }
    }
    out
}

fn stun_fingerprint(packet_without_fingerprint: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(packet_without_fingerprint);
    hasher.finalize() ^ STUN_FINGERPRINT_XOR
}

async fn accept_http_io<S>(relay: Relay, mut stream: S, peer_addr: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = read_http_head(&mut stream).await?;
    if head.method != "GET" {
        write_http_response(&mut stream, 405, "Method Not Allowed").await?;
        return Ok(());
    }

    match head.path.as_str() {
        "/healthz" | "/derp/latency-check" => {
            write_http_response(&mut stream, 200, "OK").await?;
            Ok(())
        }
        "/derp" if head.is_websocket_derp() => {
            let key = head
                .header("sec-websocket-key")
                .ok_or(Error::Http("missing websocket key"))?;
            let accept = derive_accept_key(key.as_bytes());
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Connection: Upgrade\r\n\
                 Upgrade: websocket\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Protocol: derp\r\n\
                 \r\n"
            );
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            tracing::debug!(%peer_addr, "accepted derp websocket upgrade");
            let ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
            relay.accept(WebSocketIo::new(ws)).await
        }
        "/derp" if head.is_derp_upgrade() => {
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: DERP\r\n\
                      \r\n",
                )
                .await?;
            stream.flush().await?;
            tracing::debug!(%peer_addr, "accepted derp http upgrade");
            relay.accept(stream).await
        }
        "/derp" => {
            write_http_response(&mut stream, 426, "Upgrade Required").await?;
            Ok(())
        }
        _ => {
            write_http_response(&mut stream, 404, "Not Found").await?;
            Ok(())
        }
    }
}

async fn write_http_upgrade<S>(stream: &mut S, host: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET /derp HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: DERP\r\n\
         Connection: Upgrade\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8192 {
            return Err(Error::Http("response header too large"));
        }
    }
    let head = std::str::from_utf8(&head).map_err(|_| Error::Http("invalid response head"))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(Error::Http("unexpected mesh upgrade status"));
    }
    Ok(())
}

#[derive(Debug)]
struct HttpHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl HttpHead {
    fn is_derp_upgrade(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("derp"))
            && self.header("connection").is_some_and(header_has_upgrade)
    }

    fn is_websocket_derp(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
            && self.header("connection").is_some_and(header_has_upgrade)
            && self
                .header("sec-websocket-version")
                .is_none_or(|value| value == "13")
            && self
                .header("sec-websocket-protocol")
                .is_some_and(|value| header_has_token(value, "derp"))
            && self
                .header("sec-websocket-key")
                .is_some_and(|value| !value.trim().is_empty())
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

async fn read_http_head<S>(stream: &mut S) -> Result<HttpHead>
where
    S: AsyncRead + Unpin,
{
    // Byte by byte, so nothing after the head is consumed before the
    // upgrade; the deadline stops a client that trickles it.
    let head = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut head = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                return Ok(head);
            }
            if head.len() > MAX_HTTP_HEAD_BYTES {
                return Err(Error::Http("request header too large"));
            }
        }
    })
    .await
    .map_err(|_| Error::Limit("request head timed out"))??;

    let head = std::str::from_utf8(&head).map_err(|_| Error::Http("invalid request head"))?;
    parse_http_head(head)
}

fn parse_http_head(head: &str) -> Result<HttpHead> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(Error::Http("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or(Error::Http("missing request method"))?;
    let path = request_parts
        .next()
        .ok_or(Error::Http("missing request path"))?;
    let version = request_parts
        .next()
        .ok_or(Error::Http("missing request version"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(Error::Http("unsupported http version"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(Error::Http("malformed header"));
        };
        headers.push((key.trim().to_string(), value.trim().to_string()));
    }

    Ok(HttpHead {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn header_has_upgrade(value: &str) -> bool {
    header_has_token(value, "upgrade")
}

fn header_has_token(value: &str, wanted: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(wanted))
}

async fn write_http_response<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = reason.as_bytes();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

struct WebSocketIo<S> {
    ws: WebSocketStream<S>,
    read_buf: VecDeque<u8>,
}

impl<S> WebSocketIo<S> {
    fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: VecDeque::new(),
        }
    }
}

impl<S> AsyncRead for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            while buf.remaining() > 0 {
                let Some(byte) = self.read_buf.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            if !buf.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }

            match futures_util::ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    self.read_buf.extend(data);
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(_)) => {
                    return Poll::Ready(Err(IoError::new(
                        ErrorKind::InvalidData,
                        "non-binary websocket message",
                    )));
                }
                Some(Err(err)) => {
                    return Poll::Ready(Err(IoError::other(format!("websocket: {err}"))));
                }
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        futures_util::ready!(Pin::new(&mut self.ws).poll_ready(cx))
            .map_err(|err| IoError::other(format!("websocket: {err}")))?;
        Pin::new(&mut self.ws)
            .start_send(Message::binary(buf.to_vec()))
            .map_err(|err| IoError::other(format!("websocket: {err}")))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        futures_util::ready!(Pin::new(&mut self.ws).poll_flush(cx))
            .map_err(|err| IoError::other(format!("websocket: {err}")))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        futures_util::ready!(Pin::new(&mut self.ws).poll_close(cx))
            .map_err(|err| IoError::other(format!("websocket: {err}")))?;
        Poll::Ready(Ok(()))
    }
}

impl RelayInner {
    fn next_id(&self) -> usize {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn register(&self, peer: NodePublic, tx: mpsc::Sender<OutboundFrame>) {
        self.peers.lock().await.insert(peer.clone(), tx);
        self.broadcast_peer_present(peer).await;
    }

    async fn unregister(&self, peer: &NodePublic) {
        let removed = self.peers.lock().await.remove(peer).is_some();
        if removed {
            self.broadcast_peer_gone(peer.clone()).await;
        }
    }

    async fn register_forwarder(&self, peer: NodePublic, forwarder: MeshForwarder) {
        self.forwarders.lock().await.insert(peer, forwarder);
    }

    async fn unregister_forwarder(&self, peer: &NodePublic, forwarder_id: usize) {
        let mut forwarders = self.forwarders.lock().await;
        if forwarders
            .get(peer)
            .is_some_and(|forwarder| forwarder.id == forwarder_id)
        {
            forwarders.remove(peer);
        }
    }

    async fn unregister_forwarder_id(&self, forwarder_id: usize) {
        self.forwarders
            .lock()
            .await
            .retain(|_, forwarder| forwarder.id != forwarder_id);
    }

    async fn register_watcher(&self, tx: mpsc::Sender<OutboundFrame>) -> usize {
        let id = self.next_id();
        self.watchers.lock().await.insert(id, tx.clone());
        let peers: Vec<_> = self.peers.lock().await.keys().cloned().collect();
        for peer in peers {
            let _ = tx
                .send(OutboundFrame {
                    typ: FrameType::PeerPresent,
                    payload: peer_present_payload(&peer),
                })
                .await;
        }
        id
    }

    async fn unregister_watcher(&self, id: usize) {
        self.watchers.lock().await.remove(&id);
    }

    async fn broadcast_peer_present(&self, peer: NodePublic) {
        self.broadcast_to_watchers(FrameType::PeerPresent, peer_present_payload(&peer))
            .await;
    }

    async fn broadcast_peer_gone(&self, peer: NodePublic) {
        self.broadcast_to_watchers(
            FrameType::PeerGone,
            peer_gone_payload(&peer, PEER_GONE_REASON_DISCONNECTED),
        )
        .await;
    }

    async fn broadcast_to_watchers(&self, typ: FrameType, payload: Vec<u8>) {
        let watchers: Vec<_> = self
            .watchers
            .lock()
            .await
            .iter()
            .map(|(id, tx)| (*id, tx.clone()))
            .collect();
        let mut stale = Vec::new();
        for (id, tx) in watchers {
            if tx
                .send(OutboundFrame {
                    typ,
                    payload: payload.clone(),
                })
                .await
                .is_err()
            {
                stale.push(id);
            }
        }
        if !stale.is_empty() {
            self.watchers
                .lock()
                .await
                .retain(|id, _| !stale.contains(id));
        }
    }

    async fn route_packet(&self, src: &NodePublic, dst: NodePublic, pkt: &[u8]) -> Result<()> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(Error::Protocol("packet too big"));
        }

        let tx = { self.peers.lock().await.get(&dst).cloned() };
        if let Some(tx) = tx {
            let mut payload = Vec::with_capacity(KEY_LEN + pkt.len());
            payload.extend_from_slice(src.as_bytes());
            payload.extend_from_slice(pkt);
            let _ = tx
                .send(OutboundFrame {
                    typ: FrameType::RecvPacket,
                    payload,
                })
                .await;
        } else {
            let forwarder = { self.forwarders.lock().await.get(&dst).cloned() };
            if let Some(forwarder) = forwarder {
                let _ = forwarder
                    .tx
                    .send(OutboundFrame {
                        typ: FrameType::ForwardPacket,
                        payload: forward_packet_payload(src, &dst, pkt),
                    })
                    .await;
            }
        }
        Ok(())
    }

    async fn route_forwarded_packet(
        &self,
        src: &NodePublic,
        dst: NodePublic,
        pkt: &[u8],
    ) -> Result<()> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(Error::Protocol("packet too big"));
        }
        let tx = { self.peers.lock().await.get(&dst).cloned() };
        if let Some(tx) = tx {
            let mut payload = Vec::with_capacity(KEY_LEN + pkt.len());
            payload.extend_from_slice(src.as_bytes());
            payload.extend_from_slice(pkt);
            let _ = tx
                .send(OutboundFrame {
                    typ: FrameType::RecvPacket,
                    payload,
                })
                .await;
        }
        Ok(())
    }
}

fn parse_send_packet(body: &[u8]) -> Result<(NodePublic, &[u8])> {
    if body.len() < KEY_LEN {
        return Err(Error::Protocol("short send packet"));
    }
    let dst = NodePublic::from_slice(&body[..KEY_LEN])?;
    let pkt = &body[KEY_LEN..];
    if pkt.len() > MAX_PACKET_SIZE {
        return Err(Error::Protocol("packet too big"));
    }
    Ok((dst, pkt))
}

fn parse_forward_packet(body: &[u8]) -> Result<(NodePublic, NodePublic, &[u8])> {
    if body.len() < KEY_LEN * 2 {
        return Err(Error::Protocol("short forward packet"));
    }
    let src = NodePublic::from_slice(&body[..KEY_LEN])?;
    let dst = NodePublic::from_slice(&body[KEY_LEN..KEY_LEN * 2])?;
    let pkt = &body[KEY_LEN * 2..];
    if pkt.len() > MAX_PACKET_SIZE {
        return Err(Error::Protocol("packet too big"));
    }
    Ok((src, dst, pkt))
}

fn forward_packet_payload(src: &NodePublic, dst: &NodePublic, pkt: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KEY_LEN * 2 + pkt.len());
    payload.extend_from_slice(src.as_bytes());
    payload.extend_from_slice(dst.as_bytes());
    payload.extend_from_slice(pkt);
    payload
}

fn parse_close_peer(body: &[u8]) -> Result<NodePublic> {
    if body.len() != KEY_LEN {
        return Err(Error::Protocol("close peer wrong size"));
    }
    NodePublic::from_slice(body).map_err(Error::from)
}

fn parse_peer_present(body: &[u8]) -> Result<NodePublic> {
    if body.len() < KEY_LEN {
        return Err(Error::Protocol("short peer present"));
    }
    NodePublic::from_slice(&body[..KEY_LEN]).map_err(Error::from)
}

fn parse_peer_gone(body: &[u8]) -> Result<(NodePublic, u8)> {
    if body.len() < KEY_LEN {
        return Err(Error::Protocol("short peer gone"));
    }
    let peer = NodePublic::from_slice(&body[..KEY_LEN])?;
    let reason = body
        .get(KEY_LEN)
        .copied()
        .unwrap_or(PEER_GONE_REASON_DISCONNECTED);
    Ok((peer, reason))
}

fn peer_present_payload(peer: &NodePublic) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PEER_PRESENT_FRAME_LEN);
    payload.extend_from_slice(peer.as_bytes());
    payload.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.push(PEER_PRESENT_IS_REGULAR);
    payload
}

fn peer_gone_payload(peer: &NodePublic, reason: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KEY_LEN + 1);
    payload.extend_from_slice(peer.as_bytes());
    payload.push(reason);
    payload
}

async fn read_server_key<S>(stream: &mut S) -> Result<NodePublic>
where
    S: AsyncRead + Unpin,
{
    let (typ, payload) = read_frame(stream).await?;
    if typ != FrameType::ServerKey {
        return Err(Error::Protocol("expected server key"));
    }
    if payload.len() < MAGIC.len() + KEY_LEN {
        return Err(Error::Protocol("short server key"));
    }
    if &payload[..MAGIC.len()] != MAGIC {
        return Err(Error::Protocol("bad DERP magic"));
    }
    NodePublic::from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN]).map_err(Error::from)
}

async fn write_loop<W>(
    mut writer: tokio::io::WriteHalf<W>,
    mut rx: mpsc::Receiver<OutboundFrame>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = rx.recv().await {
        write_frame(&mut writer, frame.typ, &frame.payload).await?;
    }
    Ok(())
}

async fn write_frame<W>(writer: &mut W, typ: FrameType, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let buf = frame::encode_frame(typ, payload);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<(FrameType, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut hdr).await?;
    let (typ, len) = frame::decode_header(&hdr)?;
    if len as usize > (1 << 20) + 64 {
        return Err(Error::Protocol("frame too large"));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok((typ, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_tailnet::derp::{Client, ReceivedMessage};
    use rand::rngs::OsRng;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    #[tokio::test]
    async fn plain_http_listener_relays_packet_between_two_clients() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, server_task) = spawn_plain_relay(relay.clone()).await;

        let a_priv = NodePrivate::generate(&mut OsRng);
        let b_priv = NodePrivate::generate(&mut OsRng);
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = codewire_tailnet::derp::connect_plain(
            &addr.to_string(),
            "127.0.0.1",
            a_priv,
            &mut OsRng,
        )
        .await
        .expect("A connect");
        let mut b = codewire_tailnet::derp::connect_plain(
            &addr.to_string(),
            "127.0.0.1",
            b_priv,
            &mut OsRng,
        )
        .await
        .expect("B connect");

        assert_eq!(
            a.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );
        assert_eq!(
            b.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );
        drain_server_info(&mut a).await;
        drain_server_info(&mut b).await;

        a.send(&b_pub, b"over http upgrade").await.expect("send");
        let (source, data) = next_packet(&mut b).await;
        assert_eq!(source.as_bytes(), a_pub.as_bytes());
        assert_eq!(data, b"over http upgrade");

        drop(a);
        drop(b);
        server_task.abort();
    }

    #[tokio::test]
    async fn websocket_listener_relays_packet_between_two_clients() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, server_task) = spawn_plain_relay(relay.clone()).await;

        let a_priv = NodePrivate::generate(&mut OsRng);
        let b_priv = NodePrivate::generate(&mut OsRng);
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = connect_websocket_derp(addr, a_priv).await;
        let mut b = connect_websocket_derp(addr, b_priv).await;

        assert_eq!(
            a.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );
        assert_eq!(
            b.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );
        drain_server_info(&mut a).await;
        drain_server_info(&mut b).await;

        a.send(&b_pub, b"over websocket upgrade")
            .await
            .expect("send");
        let (source, data) = next_packet(&mut b).await;
        assert_eq!(source.as_bytes(), a_pub.as_bytes());
        assert_eq!(data, b"over websocket upgrade");

        drop(a);
        drop(b);
        server_task.abort();
    }

    #[tokio::test]
    async fn tls_http_listener_relays_packet_between_two_clients() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let tls_config = self_signed_tls_config(&["localhost".to_string()]).expect("tls config");
        let (addr, server_task) = spawn_tls_relay(relay.clone(), tls_config).await;

        let a_priv = NodePrivate::generate(&mut OsRng);
        let b_priv = NodePrivate::generate(&mut OsRng);
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = codewire_tailnet::derp::connect_tls(
            &addr.to_string(),
            "localhost",
            codewire_tailnet::derp::insecure_tls_config_for_tests(),
            a_priv,
            &mut OsRng,
        )
        .await
        .expect("A connect");
        let mut b = codewire_tailnet::derp::connect_tls(
            &addr.to_string(),
            "localhost",
            codewire_tailnet::derp::insecure_tls_config_for_tests(),
            b_priv,
            &mut OsRng,
        )
        .await
        .expect("B connect");

        drain_server_info(&mut a).await;
        drain_server_info(&mut b).await;

        a.send(&b_pub, b"over tls upgrade").await.expect("send");
        let (source, data) = next_packet(&mut b).await;
        assert_eq!(source.as_bytes(), a_pub.as_bytes());
        assert_eq!(data, b"over tls upgrade");

        drop(a);
        drop(b);
        server_task.abort();
    }

    #[tokio::test]
    async fn health_and_latency_endpoints_return_ok() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, server_task) = spawn_plain_relay(relay).await;

        let health = http_get(addr, "/healthz").await;
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.ends_with("OK"));

        let latency = http_get(addr, "/derp/latency-check").await;
        assert!(latency.starts_with("HTTP/1.1 200 OK"));
        assert!(latency.ends_with("OK"));

        server_task.abort();
    }

    #[tokio::test]
    async fn derp_path_requires_upgrade_headers() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, server_task) = spawn_plain_relay(relay).await;

        let response = http_get(addr, "/derp").await;
        assert!(response.starts_with("HTTP/1.1 426 Upgrade Required"));

        server_task.abort();
    }

    #[tokio::test]
    async fn stun_listener_returns_client_mapped_addr() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind stun");
        let server_addr = server.local_addr().expect("stun addr");
        let server_task = tokio::spawn(serve_stun(server));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let client_addr = client.local_addr().expect("client addr");
        let mapped = codewire_tailnet::stun::discover_mapped_addr(
            &client,
            server_addr,
            Duration::from_secs(1),
        )
        .await
        .expect("discover mapped addr");

        assert_eq!(mapped, client_addr);
        server_task.abort();
    }

    #[tokio::test]
    async fn relays_packet_between_two_clients() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
        let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);

        let a_relay = relay.clone();
        let b_relay = relay.clone();
        let a_task = tokio::spawn(async move { a_relay.accept(a_server_io).await });
        let b_task = tokio::spawn(async move { b_relay.accept(b_server_io).await });

        let a_priv = NodePrivate::generate(&mut OsRng);
        let b_priv = NodePrivate::generate(&mut OsRng);
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = Client::handshake(a_client_io, a_priv, &mut OsRng)
            .await
            .expect("A handshake");
        let mut b = Client::handshake(b_client_io, b_priv, &mut OsRng)
            .await
            .expect("B handshake");

        assert_eq!(
            a.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );
        assert_eq!(
            b.server_public_key().as_bytes(),
            relay.public_key().as_bytes()
        );

        drain_server_info(&mut a).await;
        drain_server_info(&mut b).await;

        let payload = b"hello through rust derp relay";
        a.send(&b_pub, payload).await.expect("send packet");

        let (source, data) = next_packet(&mut b).await;
        assert_eq!(source.as_bytes(), a_pub.as_bytes());
        assert_eq!(data, payload);

        drop(a);
        drop(b);
        a_task.await.expect("A relay task").expect("A relay result");
        b_task.await.expect("B relay task").expect("B relay result");
    }

    #[tokio::test]
    async fn replies_to_client_ping_with_pong() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let relay_task = {
            let relay = relay.clone();
            tokio::spawn(async move { relay.accept(server_io).await })
        };

        let mut client =
            Client::handshake(client_io, NodePrivate::generate(&mut OsRng), &mut OsRng)
                .await
                .expect("handshake");
        drain_server_info(&mut client).await;

        let ping = *b"12345678";
        client.send_ping(ping).await.expect("send ping");

        match client.recv().await.expect("recv pong") {
            ReceivedMessage::Pong(got) => assert_eq!(got, ping),
            other => panic!("expected pong, got {other:?}"),
        }

        drop(client);
        relay_task.await.expect("relay task").expect("relay result");
    }

    #[tokio::test]
    async fn mesh_forwards_packet_to_peer_on_remote_relay() {
        let mesh_key =
            MeshKey::parse("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .expect("mesh key");
        let relay_a = Relay::new_with_mesh_key(NodePrivate::generate(&mut OsRng), mesh_key);
        let relay_b = Relay::new_with_mesh_key(NodePrivate::generate(&mut OsRng), mesh_key);

        let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
        let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
        let a_relay_task = {
            let relay = relay_a.clone();
            tokio::spawn(async move { relay.accept(a_server_io).await })
        };
        let b_relay_task = {
            let relay = relay_b.clone();
            tokio::spawn(async move { relay.accept(b_server_io).await })
        };

        let a_priv = NodePrivate::generate(&mut OsRng);
        let b_priv = NodePrivate::generate(&mut OsRng);
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();
        let mut a = Client::handshake(a_client_io, a_priv, &mut OsRng)
            .await
            .expect("A handshake");
        let mut b = Client::handshake(b_client_io, b_priv, &mut OsRng)
            .await
            .expect("B handshake");
        drain_server_info(&mut a).await;
        drain_server_info(&mut b).await;

        let (mesh_client_io, mesh_server_io) = tokio::io::duplex(64 * 1024);
        let mesh_server_task = {
            let relay = relay_b.clone();
            tokio::spawn(async move { relay.accept(mesh_server_io).await })
        };
        let mesh_client_task = {
            let relay = relay_a.clone();
            tokio::spawn(async move { relay.connect_mesh_io(mesh_client_io).await })
        };
        wait_for_forwarder(&relay_a, &b_pub).await;

        a.send(&b_pub, b"over mesh").await.expect("send");
        let (source, data) = next_packet(&mut b).await;
        assert_eq!(source.as_bytes(), a_pub.as_bytes());
        assert_eq!(data, b"over mesh");

        drop(a);
        drop(b);
        a_relay_task
            .await
            .expect("A relay task")
            .expect("A relay result");
        b_relay_task
            .await
            .expect("B relay task")
            .expect("B relay result");
        mesh_client_task.abort();
        mesh_server_task.abort();
    }

    async fn spawn_plain_relay(relay: Relay) -> (SocketAddr, tokio::task::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let task = tokio::spawn(serve_plain(listener, relay));
        (addr, task)
    }

    async fn spawn_tls_relay(
        relay: Relay,
        tls_config: ServerConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let task = tokio::spawn(serve_tls(listener, relay, tls_config));
        (addr, task)
    }

    async fn connect_websocket_derp(
        addr: SocketAddr,
        private: NodePrivate,
    ) -> Client<WebSocketIo<tokio_tungstenite::MaybeTlsStream<TcpStream>>> {
        let mut request = format!("ws://{addr}/derp")
            .into_client_request()
            .expect("websocket request");
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("derp"));
        let (ws, response) = connect_async(request).await.expect("websocket connect");
        assert_eq!(response.status().as_u16(), 101);
        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|value| value.to_str().ok()),
            Some("derp")
        );
        Client::handshake(WebSocketIo::new(ws), private, &mut OsRng)
            .await
            .expect("derp websocket handshake")
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        response
    }

    async fn drain_server_info<S>(client: &mut Client<S>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match client.recv().await.expect("recv server info") {
            ReceivedMessage::ServerInfo => {}
            other => panic!("expected server info, got {other:?}"),
        }
    }

    async fn next_packet<S>(client: &mut Client<S>) -> (NodePublic, Vec<u8>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            match client.recv().await.expect("recv packet") {
                ReceivedMessage::Packet { source, data } => return (source, data),
                ReceivedMessage::KeepAlive | ReceivedMessage::ServerInfo => continue,
                other => panic!("expected packet, got {other:?}"),
            }
        }
    }

    async fn wait_for_forwarder(relay: &Relay, peer: &NodePublic) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if relay.inner.forwarders.lock().await.contains_key(peer) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("mesh forwarder registered");
    }

    /// Read everything the relay sends until it closes the connection. A
    /// reset counts as a close: the relay may drop a socket with unread
    /// input.
    async fn read_until_closed(sock: &mut TcpStream) -> Vec<u8> {
        let mut received = Vec::new();
        let mut buf = [0u8; 512];
        tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(5), async {
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await
        .expect("relay must close the connection");
        received
    }

    /// #2505 M2: a client that never finishes its request head loses the
    /// connection at the handshake deadline. Takes the deadline in real time.
    #[tokio::test]
    async fn stalled_request_head_is_closed_at_the_deadline() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, _task) = spawn_plain_relay(relay.clone()).await;

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"GET /derp HTTP/1.1\r\nHost: x\r\n")
            .await
            .expect("partial head");
        let started = tokio::time::Instant::now();
        assert!(read_until_closed(&mut sock).await.is_empty());
        assert!(started.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_secs(1));
        wait_for_free_slots(&relay).await;
    }

    /// #2505 M2: a request head over the size bound is refused at once.
    #[tokio::test]
    async fn oversized_request_head_is_refused() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, _task) = spawn_plain_relay(relay).await;

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let filler = "X-Pad: aaaa\r\n".repeat(MAX_HTTP_HEAD_BYTES / 8);
        sock.write_all(format!("GET /derp HTTP/1.1\r\nHost: x\r\n{filler}").as_bytes())
            .await
            .expect("oversized head");
        let started = tokio::time::Instant::now();
        assert!(read_until_closed(&mut sock).await.is_empty());
        assert!(started.elapsed() < HANDSHAKE_TIMEOUT);
    }

    /// #2505 M2: past the connection cap the relay closes new connections
    /// without serving them, and serves again once a slot frees. A served
    /// connection returns its slot when it closes.
    #[tokio::test]
    async fn connections_past_the_cap_are_closed_until_a_slot_frees() {
        let relay = Relay::new(NodePrivate::generate(&mut OsRng));
        let (addr, _task) = spawn_plain_relay(relay.clone()).await;
        let request = b"GET /derp HTTP/1.1\r\nHost: x\r\n\r\n";

        let every_slot = relay
            .connections
            .clone()
            .try_acquire_many_owned(MAX_CONNECTIONS as u32)
            .expect("take every slot");
        let mut refused = TcpStream::connect(addr).await.expect("connect");
        assert!(read_until_closed(&mut refused).await.is_empty());

        drop(every_slot);
        let mut served = TcpStream::connect(addr).await.expect("connect");
        served.write_all(request).await.expect("request");
        let response = read_until_closed(&mut served).await;
        assert!(
            response.starts_with(b"HTTP/1.1 426 "),
            "{}",
            String::from_utf8_lossy(&response)
        );
        wait_for_free_slots(&relay).await;
    }

    async fn wait_for_free_slots(relay: &Relay) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while relay.connections.available_permits() != MAX_CONNECTIONS {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a closed connection returns its slot");
    }
}
