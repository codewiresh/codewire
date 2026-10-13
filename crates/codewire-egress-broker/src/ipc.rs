//! Authenticated capability IPC between one confined packet worker and its
//! separate per-environment egress broker.
//!
//! The transport is a fixed set of already-created connected AF_UNIX streams,
//! one session each (#2638): one admits TCP flows, a pool resolves DNS and a
//! pool connects TCP, so a slow upstream lookup or connect delays only its own
//! session. Each session has its own key derived from the bootstrap key, and
//! the broker refuses a request outside its session's class. Every frame is
//! HMAC-authenticated and bound to one environment, boot generation, policy
//! digest, direction, and strictly increasing per-session request sequence.
//! The broker may transfer only one already-connected TCP descriptor after an
//! authenticated successful connect response; the client validates its socket
//! type and exact peer before accepting it.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Duration;

use codewire_egress_policy::{PolicyDigest, RouteClass};
use hmac::{Hmac, Mac as _};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
};
use sha2::Sha256;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, Interest};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    BrokerAdapterFailure, BrokerClock, BrokerDnsResponse, BrokerError, DnsRecordFamily,
    DnsResolver, PolicyEgressBroker, TcpConnector,
};

type HmacSha256 = Hmac<Sha256>;

pub const BROKER_IPC_KEY_LEN: usize = 32;
pub const BROKER_IPC_MAX_DNS_ADDRESSES: usize = 16;
const FRAME_MAGIC: &[u8; 8] = b"CWEBIPC1";
const FRAME_VERSION: u8 = 1;
const FRAME_KIND_REQUEST: u8 = 1;
const FRAME_KIND_RESPONSE: u8 = 2;
const FRAME_HEADER_LEN: usize = 76;
const FRAME_TAG_LEN: usize = 32;
const FRAME_MAX_PAYLOAD_LEN: usize = 512;
const FRAME_MAX_LEN: usize = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD_LEN + FRAME_TAG_LEN;
const FRAME_DOMAIN: &[u8] = b"codewire.egress-broker-ipc/v1\0";
const DESCRIPTOR_MARKER: u8 = b'F';
// Queue admission cannot consume the adapter's transaction budget. The latter
// includes the production DNS/TCP deadline plus IPC and descriptor delivery,
// with a margin: a transaction that outlives it fails its session, which ends
// the broker.
const BROKER_IPC_QUEUE_TIMEOUT: Duration = Duration::from_secs(2);
const BROKER_IPC_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(8);

/// Sessions that resolve DNS, so at most this many upstream lookups run at
/// once. A guest name lookup is an A and an AAAA query sent together, so four
/// names resolve at once, and three lookups hung for the resolver's 3 s
/// timeout still leave room for others.
pub const BROKER_IPC_DNS_SESSIONS: usize = 8;
/// Sessions that connect TCP, so at most this many upstream connects run at
/// once. A connect holds its session for one handshake (up to the connector's
/// 5 s timeout); 16 covers a package manager's parallel downloads.
pub const BROKER_IPC_CONNECT_SESSIONS: usize = 16;
/// Every session between one worker and its broker: admission first, then the
/// DNS sessions, then the connect sessions.
pub const BROKER_IPC_SESSIONS: usize = 1 + BROKER_IPC_DNS_SESSIONS + BROKER_IPC_CONNECT_SESSIONS;
const SESSION_KEY_DOMAIN: &[u8] = b"codewire.egress-broker-ipc/session-key/v1\0";

/// What one session may carry. Admission is a local policy check that never
/// waits on anything upstream, so it has a session of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerIpcSessionClass {
    Admission,
    Dns,
    Connect,
}

impl BrokerIpcSessionClass {
    /// The class of the session at `index` in [`BROKER_IPC_SESSIONS`] order.
    pub fn of(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Admission),
            index if index <= BROKER_IPC_DNS_SESSIONS => Some(Self::Dns),
            index if index < BROKER_IPC_SESSIONS => Some(Self::Connect),
            _ => None,
        }
    }

    fn carries(self, request: &BrokerRequest) -> bool {
        matches!(
            (self, request),
            (Self::Admission, BrokerRequest::AuthorizeTcp(_))
                | (Self::Dns, BrokerRequest::ResolveDns { .. })
                | (Self::Connect, BrokerRequest::ConnectTcp(_))
        )
    }
}

const OP_RESOLVE_DNS: u8 = 1;
const OP_AUTHORIZE_TCP: u8 = 2;
const OP_CONNECT_TCP: u8 = 3;

const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;
const STATUS_NO_DATA: u8 = 2;
const STATUS_NAME_ERROR: u8 = 3;
const STATUS_UNAVAILABLE: u8 = 4;
const STATUS_MALFORMED: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerIpcBinding {
    environment_id: Uuid,
    generation: u64,
    policy_digest: PolicyDigest,
}

impl BrokerIpcBinding {
    pub fn new(
        environment_id: Uuid,
        generation: u64,
        policy_digest: PolicyDigest,
    ) -> Result<Self, BrokerIpcError> {
        if environment_id.is_nil() || generation == 0 {
            return Err(BrokerIpcError::InvalidBinding);
        }
        Ok(Self {
            environment_id,
            generation,
            policy_digest,
        })
    }

    pub fn environment_id(self) -> Uuid {
        self.environment_id
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn policy_digest(self) -> PolicyDigest {
        self.policy_digest
    }
}

pub struct BrokerIpcKey(Zeroizing<[u8; BROKER_IPC_KEY_LEN]>);

impl BrokerIpcKey {
    pub fn from_bytes(bytes: [u8; BROKER_IPC_KEY_LEN]) -> Result<Self, BrokerIpcError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(BrokerIpcError::InvalidKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn with_bytes<T>(&self, apply: impl FnOnce(&[u8; BROKER_IPC_KEY_LEN]) -> T) -> T {
        apply(&self.0)
    }

    /// The key of the session at `index`: HMAC-SHA256 of the session-key
    /// domain and the index. Frames are authenticated only with session keys,
    /// so a frame from one session fails authentication on any other.
    fn for_session(&self, index: usize) -> Result<Self, BrokerIpcError> {
        let index = u8::try_from(index).map_err(|_| BrokerIpcError::SessionCount)?;
        self.with_bytes(|bytes| {
            let mut mac =
                HmacSha256::new_from_slice(bytes).map_err(|_| BrokerIpcError::InvalidKey)?;
            mac.update(SESSION_KEY_DOMAIN);
            mac.update(&[index]);
            let mut output: [u8; BROKER_IPC_KEY_LEN] = mac.finalize().into_bytes().into();
            let derived = Zeroizing::new(output);
            output.zeroize();
            if derived.iter().all(|byte| *byte == 0) {
                return Err(BrokerIpcError::InvalidKey);
            }
            Ok(Self(derived))
        })
    }
}

impl fmt::Debug for BrokerIpcKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrokerIpcKey([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerIpcDnsResponse {
    Addresses {
        addresses: Vec<IpAddr>,
        ttl_seconds: u32,
    },
    NoData,
    NameError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrokerIpcError {
    #[error("broker IPC binding is invalid")]
    InvalidBinding,
    #[error("broker IPC key is invalid")]
    InvalidKey,
    #[error("broker IPC session is closed")]
    SessionClosed,
    #[error("broker IPC session is busy")]
    SessionBusy,
    #[error("broker IPC session count is wrong")]
    SessionCount,
    #[error("broker IPC request is outside its session's class")]
    SessionClassMismatch,
    #[error("broker IPC frame I/O failed")]
    FrameIo,
    #[error("broker IPC frame is malformed")]
    MalformedFrame,
    #[error("broker IPC frame is oversized")]
    OversizedFrame,
    #[error("broker IPC authentication failed")]
    Authentication,
    #[error("broker IPC frame binding is wrong")]
    BindingMismatch,
    #[error("broker IPC sequence is replayed or out of order")]
    SequenceMismatch,
    #[error("broker IPC sequence is exhausted")]
    SequenceExhausted,
    #[error("broker IPC request was denied")]
    Denied,
    #[error("broker IPC remote adapter is unavailable")]
    RemoteUnavailable,
    #[error("broker IPC remote rejected malformed input")]
    RemoteMalformed,
    #[error("broker IPC connected descriptor is missing")]
    DescriptorMissing,
    #[error("broker IPC connected descriptor is invalid")]
    DescriptorInvalid,
}

struct ClientState {
    stream: UnixStream,
    binding: BrokerIpcBinding,
    key: BrokerIpcKey,
    next_sequence: u64,
    failed: bool,
}

/// Sessions of one class. A request checks out an idle session and gives it
/// back when it is done; a session that failed is never given back.
struct SessionPool {
    idle: StdMutex<VecDeque<ClientState>>,
    available: Semaphore,
    live: AtomicUsize,
}

impl SessionPool {
    fn new(sessions: Vec<ClientState>) -> Self {
        Self {
            available: Semaphore::new(sessions.len()),
            live: AtomicUsize::new(sessions.len()),
            idle: StdMutex::new(sessions.into()),
        }
    }

    fn len(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Take the longest-idle session, waiting at most the queue timeout for one.
    async fn checkout(&self) -> Result<CheckedOut<'_>, BrokerIpcError> {
        let permit = match timeout(BROKER_IPC_QUEUE_TIMEOUT, self.available.acquire()).await {
            Err(_) => return Err(BrokerIpcError::SessionBusy),
            // Closed once every session of the class has failed.
            Ok(Err(_)) => return Err(BrokerIpcError::SessionClosed),
            Ok(Ok(permit)) => permit,
        };
        // One permit per idle session, so the queue cannot be empty here.
        let state = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .ok_or(BrokerIpcError::SessionClosed)?;
        Ok(CheckedOut {
            pool: self,
            state: Some(state),
            permit: Some(permit),
        })
    }
}

/// A checked-out session. Dropping it, including when its request is
/// cancelled, returns it only if it can carry another request.
struct CheckedOut<'a> {
    pool: &'a SessionPool,
    state: Option<ClientState>,
    permit: Option<SemaphorePermit<'a>>,
}

impl std::ops::Deref for CheckedOut<'_> {
    type Target = ClientState;

    fn deref(&self) -> &ClientState {
        self.state
            .as_ref()
            .expect("a checked-out session holds its state")
    }
}

impl std::ops::DerefMut for CheckedOut<'_> {
    fn deref_mut(&mut self) -> &mut ClientState {
        self.state
            .as_mut()
            .expect("a checked-out session holds its state")
    }
}

impl Drop for CheckedOut<'_> {
    fn drop(&mut self) {
        let (Some(state), Some(permit)) = (self.state.take(), self.permit.take()) else {
            return;
        };
        if state.failed {
            permit.forget();
            if self.pool.live.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.pool.available.close();
            }
        } else {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(state);
            drop(permit);
        }
    }
}

/// The worker's end of every session to its broker.
pub struct BrokerIpcClient {
    admission: SessionPool,
    dns: SessionPool,
    connect: SessionPool,
}

impl BrokerIpcClient {
    /// One client over [`BROKER_IPC_SESSIONS`] connected streams, in session
    /// order. Each session uses its own key derived from `key`.
    pub fn new(
        streams: Vec<UnixStream>,
        binding: BrokerIpcBinding,
        key: BrokerIpcKey,
    ) -> Result<Self, BrokerIpcError> {
        if streams.len() != BROKER_IPC_SESSIONS {
            return Err(BrokerIpcError::SessionCount);
        }
        let (mut admission, mut dns, mut connect) = (Vec::new(), Vec::new(), Vec::new());
        for (index, stream) in streams.into_iter().enumerate() {
            let state = ClientState {
                stream,
                binding,
                key: key.for_session(index)?,
                next_sequence: 1,
                failed: false,
            };
            match BrokerIpcSessionClass::of(index).ok_or(BrokerIpcError::SessionCount)? {
                BrokerIpcSessionClass::Admission => admission.push(state),
                BrokerIpcSessionClass::Dns => dns.push(state),
                BrokerIpcSessionClass::Connect => connect.push(state),
            }
        }
        Ok(Self {
            admission: SessionPool::new(admission),
            dns: SessionPool::new(dns),
            connect: SessionPool::new(connect),
        })
    }

    /// Prove every session's key and binding with a request the policy
    /// refuses before any upstream effect: a protected loopback destination,
    /// and for DNS the protected name `localhost`.
    pub async fn verify_sessions(&self) -> Result<(), BrokerIpcError> {
        let protected = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        // Checkouts rotate through the idle queue, so each session is used once.
        for _ in 0..self.admission.len() {
            expect_denied(self.authorize_tcp(protected).await)?;
        }
        for _ in 0..self.dns.len() {
            expect_denied(
                self.resolve_dns("localhost", DnsRecordFamily::Ipv4)
                    .await
                    .map(drop),
            )?;
        }
        for _ in 0..self.connect.len() {
            expect_denied(self.connect_tcp(protected).await.map(drop))?;
        }
        Ok(())
    }

    pub async fn resolve_dns(
        &self,
        name: &str,
        family: DnsRecordFamily,
    ) -> Result<BrokerIpcDnsResponse, BrokerIpcError> {
        let request = encode_dns_request(name, family)?;
        let mut state = self.dns.checkout().await?;
        let deadline = Instant::now() + BROKER_IPC_TRANSACTION_TIMEOUT;
        let response = state.request(&request, deadline).await?;
        match decode_dns_response(&response, family) {
            Ok(response) => Ok(response),
            Err(error) if error.is_valid_remote_result() => Err(error),
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }

    pub async fn authorize_tcp(&self, destination: SocketAddr) -> Result<(), BrokerIpcError> {
        let request = encode_tcp_request(OP_AUTHORIZE_TCP, destination)?;
        let mut state = self.admission.checkout().await?;
        let deadline = Instant::now() + BROKER_IPC_TRANSACTION_TIMEOUT;
        let response = state.request(&request, deadline).await?;
        match decode_empty_response(&response, OP_AUTHORIZE_TCP) {
            Ok(()) => Ok(()),
            Err(error) if error.is_valid_remote_result() => Err(error),
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }

    pub async fn connect_tcp(&self, destination: SocketAddr) -> Result<OwnedFd, BrokerIpcError> {
        let request = encode_tcp_request(OP_CONNECT_TCP, destination)?;
        let mut state = self.connect.checkout().await?;
        let deadline = Instant::now() + BROKER_IPC_TRANSACTION_TIMEOUT;
        let response = state.request(&request, deadline).await?;
        match decode_empty_response(&response, OP_CONNECT_TCP) {
            Ok(()) => {}
            Err(error) if error.is_valid_remote_result() => return Err(error),
            Err(error) => {
                state.failed = true;
                return Err(error);
            }
        }
        // The descriptor is part of this operation, not the next frame. A
        // cancelled receive must never leave it for a subsequent request.
        state.failed = true;
        let descriptor = timeout_at(deadline, receive_descriptor(&state.stream))
            .await
            .unwrap_or(Err(BrokerIpcError::FrameIo))?;
        // The marker and its one descriptor are read: the session is in step
        // again, whatever the connection itself turns out to be.
        state.failed = false;
        match admit_connected_descriptor(descriptor, destination) {
            Ok(descriptor) => Ok(descriptor),
            // The connection closed or reset after the broker's handshake:
            // this request fails, the session carries on (#2638).
            Err(BrokerIpcError::RemoteUnavailable) => Err(BrokerIpcError::RemoteUnavailable),
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }
}

impl ClientState {
    async fn request(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, BrokerIpcError> {
        if self.failed {
            return Err(BrokerIpcError::SessionClosed);
        }
        let sequence = self.next_sequence;
        let frame = encode_frame(
            FRAME_KIND_REQUEST,
            sequence,
            self.binding,
            &self.key,
            payload,
        )?;
        // Once I/O starts, cancellation can leave a partial request or an
        // unread response. Poison the session before the first await; only a
        // complete authenticated response can make it reusable again.
        self.failed = true;
        let response = timeout_at(deadline, async {
            write_client_bytes(&self.stream, &frame)
                .await
                .map_err(|_| BrokerIpcError::FrameIo)?;
            read_client_frame(
                &mut self.stream,
                FRAME_KIND_RESPONSE,
                sequence,
                self.binding,
                &self.key,
            )
            .await
        })
        .await
        .map_err(|_| BrokerIpcError::FrameIo)??;
        self.next_sequence = match sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.failed = true;
                return Err(BrokerIpcError::SequenceExhausted);
            }
        };
        self.failed = false;
        Ok(response)
    }
}

/// The confined packet worker deliberately denies `sendto`/`recvfrom` even
/// though Tokio may use them to implement ordinary Unix-stream I/O. Drive the
/// already-connected broker capability with readiness plus `read`/`write` so
/// the client needs no socket creation, addressing, or datagram authority.
async fn write_client_bytes(stream: &UnixStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            rustix::io::write(stream, bytes).map_err(errno_to_io_error)
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn read_client_exact(stream: &UnixStream, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            rustix::io::read(stream, &mut *bytes).map_err(errno_to_io_error)
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn read_client_frame(
    stream: &mut UnixStream,
    expected_kind: u8,
    expected_sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
) -> Result<Vec<u8>, BrokerIpcError> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    read_client_exact(stream, &mut header)
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?;
    let payload_len = usize::from(u16::from_be_bytes([header[10], header[11]]));
    if payload_len > FRAME_MAX_PAYLOAD_LEN {
        return Err(BrokerIpcError::OversizedFrame);
    }
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_TAG_LEN))
        .ok_or(BrokerIpcError::OversizedFrame)?;
    if frame_len > FRAME_MAX_LEN {
        return Err(BrokerIpcError::OversizedFrame);
    }
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&header);
    frame.resize(frame_len, 0);
    read_client_exact(stream, &mut frame[FRAME_HEADER_LEN..])
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?;
    decode_frame(&frame, expected_kind, expected_sequence, binding, key)
}

fn expect_denied(result: Result<(), BrokerIpcError>) -> Result<(), BrokerIpcError> {
    match result {
        Err(BrokerIpcError::Denied) => Ok(()),
        Ok(()) => Err(BrokerIpcError::BindingMismatch),
        Err(error) => Err(error),
    }
}

impl BrokerIpcError {
    fn is_valid_remote_result(&self) -> bool {
        matches!(
            self,
            Self::Denied | Self::RemoteUnavailable | Self::RemoteMalformed
        )
    }
}

/// Serve every session of one worker until the first one fails, which ends
/// them all. `streams` are the broker's ends in [`BROKER_IPC_SESSIONS`] order.
pub async fn serve_broker_ipc<R, C, K>(
    streams: Vec<UnixStream>,
    binding: BrokerIpcBinding,
    key: BrokerIpcKey,
    broker: Arc<PolicyEgressBroker<R, C, K>>,
) -> Result<(), BrokerIpcError>
where
    R: DnsResolver,
    C: TcpConnector,
    C::Stream: AsFd,
    K: BrokerClock,
{
    if broker.policy_digest().await != binding.policy_digest()
        || broker.route_class() != RouteClass::General
    {
        return Err(BrokerIpcError::BindingMismatch);
    }
    if streams.len() != BROKER_IPC_SESSIONS {
        return Err(BrokerIpcError::SessionCount);
    }
    let mut sessions = JoinSet::new();
    for (index, stream) in streams.into_iter().enumerate() {
        let class = BrokerIpcSessionClass::of(index).ok_or(BrokerIpcError::SessionCount)?;
        sessions.spawn(serve_session(
            stream,
            binding,
            key.for_session(index)?,
            class,
            Arc::clone(&broker),
        ));
    }
    // A session ends only on an error; dropping the set aborts the others.
    match sessions.join_next().await {
        Some(Ok(Err(error))) => Err(error),
        Some(Ok(Ok(()))) | Some(Err(_)) | None => Err(BrokerIpcError::SessionClosed),
    }
}

async fn serve_session<R, C, K>(
    mut stream: UnixStream,
    binding: BrokerIpcBinding,
    key: BrokerIpcKey,
    class: BrokerIpcSessionClass,
    broker: Arc<PolicyEgressBroker<R, C, K>>,
) -> Result<(), BrokerIpcError>
where
    R: DnsResolver,
    C: TcpConnector,
    C::Stream: AsFd,
    K: BrokerClock,
{
    let mut sequence = 1_u64;
    loop {
        let payload = read_frame(&mut stream, FRAME_KIND_REQUEST, sequence, binding, &key).await?;
        let request = decode_request(&payload)?;
        if !class.carries(&request) {
            return Err(BrokerIpcError::SessionClassMismatch);
        }
        // `connect_tcp` evaluates policy again for the exact destination
        // under the broker's state lock: an earlier admission on the
        // admission session grants nothing here.
        match request {
            BrokerRequest::ResolveDns { name, family } => {
                let response = broker.resolve_dns(&name, family).await;
                let payload = encode_dns_broker_response(family, response)?;
                write_frame(
                    &mut stream,
                    FRAME_KIND_RESPONSE,
                    sequence,
                    binding,
                    &key,
                    &payload,
                )
                .await?;
            }
            BrokerRequest::AuthorizeTcp(destination) => {
                let response = broker.authorize_tcp(destination).await;
                let payload = encode_empty_broker_response(OP_AUTHORIZE_TCP, response.map(drop));
                write_frame(
                    &mut stream,
                    FRAME_KIND_RESPONSE,
                    sequence,
                    binding,
                    &key,
                    &payload,
                )
                .await?;
            }
            BrokerRequest::ConnectTcp(destination) => match broker.connect_tcp(destination).await {
                Ok(connection) => {
                    let (connected, _) = connection.into_parts();
                    let payload = [OP_CONNECT_TCP, STATUS_OK];
                    write_frame(
                        &mut stream,
                        FRAME_KIND_RESPONSE,
                        sequence,
                        binding,
                        &key,
                        &payload,
                    )
                    .await?;
                    send_connected_descriptor(&stream, connected.as_fd()).await?;
                }
                Err(error) => {
                    let payload = [OP_CONNECT_TCP, status_for_broker_error(&error)];
                    write_frame(
                        &mut stream,
                        FRAME_KIND_RESPONSE,
                        sequence,
                        binding,
                        &key,
                        &payload,
                    )
                    .await?;
                }
            },
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(BrokerIpcError::SequenceExhausted)?;
    }
}

enum BrokerRequest {
    ResolveDns {
        name: String,
        family: DnsRecordFamily,
    },
    AuthorizeTcp(SocketAddr),
    ConnectTcp(SocketAddr),
}

fn encode_dns_request(name: &str, family: DnsRecordFamily) -> Result<Vec<u8>, BrokerIpcError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let name_len = u16::try_from(name.len()).map_err(|_| BrokerIpcError::MalformedFrame)?;
    let mut payload = Vec::with_capacity(4 + name.len());
    payload.push(OP_RESOLVE_DNS);
    payload.push(encode_family(family));
    payload.extend_from_slice(&name_len.to_be_bytes());
    payload.extend_from_slice(name.as_bytes());
    Ok(payload)
}

fn encode_tcp_request(operation: u8, destination: SocketAddr) -> Result<Vec<u8>, BrokerIpcError> {
    if !matches!(operation, OP_AUTHORIZE_TCP | OP_CONNECT_TCP) || destination.port() == 0 {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let mut payload = Vec::with_capacity(20);
    payload.push(operation);
    encode_address(destination.ip(), &mut payload);
    payload.extend_from_slice(&destination.port().to_be_bytes());
    Ok(payload)
}

fn decode_request(payload: &[u8]) -> Result<BrokerRequest, BrokerIpcError> {
    let mut decoder = Decoder::new(payload);
    let operation = decoder.byte()?;
    match operation {
        OP_RESOLVE_DNS => {
            let family = decode_family(decoder.byte()?)?;
            let name_len = usize::from(decoder.u16()?);
            if name_len == 0 || name_len > 253 {
                return Err(BrokerIpcError::MalformedFrame);
            }
            let name = std::str::from_utf8(decoder.take(name_len)?)
                .map_err(|_| BrokerIpcError::MalformedFrame)?
                .to_string();
            decoder.finish()?;
            Ok(BrokerRequest::ResolveDns { name, family })
        }
        OP_AUTHORIZE_TCP | OP_CONNECT_TCP => {
            let address = decode_address(&mut decoder)?;
            let port = decoder.u16()?;
            if port == 0 {
                return Err(BrokerIpcError::MalformedFrame);
            }
            decoder.finish()?;
            let destination = SocketAddr::new(address, port);
            if operation == OP_AUTHORIZE_TCP {
                Ok(BrokerRequest::AuthorizeTcp(destination))
            } else {
                Ok(BrokerRequest::ConnectTcp(destination))
            }
        }
        _ => Err(BrokerIpcError::MalformedFrame),
    }
}

fn encode_dns_broker_response(
    family: DnsRecordFamily,
    response: Result<BrokerDnsResponse, BrokerError>,
) -> Result<Vec<u8>, BrokerIpcError> {
    match response {
        Ok(BrokerDnsResponse::Positive(response)) => {
            let addresses = response.addresses();
            if addresses.is_empty()
                || addresses.len() > BROKER_IPC_MAX_DNS_ADDRESSES
                || addresses
                    .iter()
                    .any(|address| !family_accepts(family, *address))
            {
                return Err(BrokerIpcError::MalformedFrame);
            }
            let mut payload = Vec::with_capacity(7 + addresses.len() * 16);
            payload.extend_from_slice(&[OP_RESOLVE_DNS, STATUS_OK]);
            payload.extend_from_slice(&response.ttl_seconds().to_be_bytes());
            payload.push(addresses.len() as u8);
            for address in addresses {
                encode_family_address(family, *address, &mut payload)?;
            }
            Ok(payload)
        }
        Ok(BrokerDnsResponse::NoData(_)) => Ok(vec![OP_RESOLVE_DNS, STATUS_NO_DATA]),
        Ok(BrokerDnsResponse::NameError(_)) => Ok(vec![OP_RESOLVE_DNS, STATUS_NAME_ERROR]),
        Err(error) => Ok(vec![OP_RESOLVE_DNS, status_for_broker_error(&error)]),
    }
}

fn encode_empty_broker_response(operation: u8, response: Result<(), BrokerError>) -> [u8; 2] {
    [
        operation,
        response
            .as_ref()
            .map_or_else(status_for_broker_error, |()| STATUS_OK),
    ]
}

fn status_for_broker_error(error: &BrokerError) -> u8 {
    match error {
        BrokerError::Denied(_) => STATUS_DENIED,
        BrokerError::Resolver(
            BrokerAdapterFailure::Unavailable | BrokerAdapterFailure::Timeout,
        )
        | BrokerError::Connector(
            BrokerAdapterFailure::Unavailable | BrokerAdapterFailure::Timeout,
        ) => STATUS_UNAVAILABLE,
        BrokerError::Policy(_)
        | BrokerError::Resolver(BrokerAdapterFailure::Malformed)
        | BrokerError::Connector(BrokerAdapterFailure::Malformed)
        | BrokerError::MalformedDnsAnswer => STATUS_MALFORMED,
    }
}

fn decode_dns_response(
    payload: &[u8],
    family: DnsRecordFamily,
) -> Result<BrokerIpcDnsResponse, BrokerIpcError> {
    let mut decoder = Decoder::new(payload);
    if decoder.byte()? != OP_RESOLVE_DNS {
        return Err(BrokerIpcError::MalformedFrame);
    }
    match decoder.byte()? {
        STATUS_OK => {
            let ttl_seconds = decoder.u32()?;
            if ttl_seconds == 0 {
                return Err(BrokerIpcError::MalformedFrame);
            }
            let count = usize::from(decoder.byte()?);
            if !(1..=BROKER_IPC_MAX_DNS_ADDRESSES).contains(&count) {
                return Err(BrokerIpcError::MalformedFrame);
            }
            let mut addresses = Vec::with_capacity(count);
            for _ in 0..count {
                addresses.push(decode_family_address(family, &mut decoder)?);
            }
            decoder.finish()?;
            Ok(BrokerIpcDnsResponse::Addresses {
                addresses,
                ttl_seconds,
            })
        }
        STATUS_NO_DATA => {
            decoder.finish()?;
            Ok(BrokerIpcDnsResponse::NoData)
        }
        STATUS_NAME_ERROR => {
            decoder.finish()?;
            Ok(BrokerIpcDnsResponse::NameError)
        }
        status => {
            decoder.finish()?;
            Err(decode_remote_error(status)?)
        }
    }
}

fn decode_empty_response(payload: &[u8], expected_operation: u8) -> Result<(), BrokerIpcError> {
    let mut decoder = Decoder::new(payload);
    if decoder.byte()? != expected_operation {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let status = decoder.byte()?;
    decoder.finish()?;
    if status == STATUS_OK {
        Ok(())
    } else {
        Err(decode_remote_error(status)?)
    }
}

fn decode_remote_error(status: u8) -> Result<BrokerIpcError, BrokerIpcError> {
    Ok(match status {
        STATUS_DENIED => BrokerIpcError::Denied,
        STATUS_UNAVAILABLE => BrokerIpcError::RemoteUnavailable,
        STATUS_MALFORMED => BrokerIpcError::RemoteMalformed,
        _ => return Err(BrokerIpcError::MalformedFrame),
    })
}

fn encode_address(address: IpAddr, payload: &mut Vec<u8>) {
    match address {
        IpAddr::V4(address) => {
            payload.push(4);
            payload.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            payload.push(6);
            payload.extend_from_slice(&address.octets());
        }
    }
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<IpAddr, BrokerIpcError> {
    match decoder.byte()? {
        4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(decoder.take(4)?).map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))),
        6 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(decoder.take(16)?).map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))),
        _ => Err(BrokerIpcError::MalformedFrame),
    }
}

fn encode_family(family: DnsRecordFamily) -> u8 {
    match family {
        DnsRecordFamily::Ipv4 => 4,
        DnsRecordFamily::Ipv6 => 6,
    }
}

fn decode_family(value: u8) -> Result<DnsRecordFamily, BrokerIpcError> {
    match value {
        4 => Ok(DnsRecordFamily::Ipv4),
        6 => Ok(DnsRecordFamily::Ipv6),
        _ => Err(BrokerIpcError::MalformedFrame),
    }
}

fn family_accepts(family: DnsRecordFamily, address: IpAddr) -> bool {
    matches!(
        (family, address),
        (DnsRecordFamily::Ipv4, IpAddr::V4(_)) | (DnsRecordFamily::Ipv6, IpAddr::V6(_))
    )
}

fn encode_family_address(
    family: DnsRecordFamily,
    address: IpAddr,
    payload: &mut Vec<u8>,
) -> Result<(), BrokerIpcError> {
    match (family, address) {
        (DnsRecordFamily::Ipv4, IpAddr::V4(address)) => {
            payload.extend_from_slice(&address.octets());
            Ok(())
        }
        (DnsRecordFamily::Ipv6, IpAddr::V6(address)) => {
            payload.extend_from_slice(&address.octets());
            Ok(())
        }
        _ => Err(BrokerIpcError::MalformedFrame),
    }
}

fn decode_family_address(
    family: DnsRecordFamily,
    decoder: &mut Decoder<'_>,
) -> Result<IpAddr, BrokerIpcError> {
    match family {
        DnsRecordFamily::Ipv4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(decoder.take(4)?).map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))),
        DnsRecordFamily::Ipv6 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(decoder.take(16)?).map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))),
    }
}

async fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
    payload: &[u8],
) -> Result<(), BrokerIpcError> {
    let frame = encode_frame(kind, sequence, binding, key, payload)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?;
    stream.flush().await.map_err(|_| BrokerIpcError::FrameIo)
}

async fn read_frame(
    stream: &mut UnixStream,
    expected_kind: u8,
    expected_sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
) -> Result<Vec<u8>, BrokerIpcError> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?;
    let payload_len = usize::from(u16::from_be_bytes([header[10], header[11]]));
    if payload_len > FRAME_MAX_PAYLOAD_LEN {
        return Err(BrokerIpcError::OversizedFrame);
    }
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_TAG_LEN))
        .ok_or(BrokerIpcError::OversizedFrame)?;
    if frame_len > FRAME_MAX_LEN {
        return Err(BrokerIpcError::OversizedFrame);
    }
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&header);
    frame.resize(frame_len, 0);
    stream
        .read_exact(&mut frame[FRAME_HEADER_LEN..])
        .await
        .map_err(|_| BrokerIpcError::FrameIo)?;
    decode_frame(&frame, expected_kind, expected_sequence, binding, key)
}

fn encode_frame(
    kind: u8,
    sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
    payload: &[u8],
) -> Result<Vec<u8>, BrokerIpcError> {
    if !matches!(kind, FRAME_KIND_REQUEST | FRAME_KIND_RESPONSE) {
        return Err(BrokerIpcError::MalformedFrame);
    }
    if sequence == 0 {
        return Err(BrokerIpcError::SequenceMismatch);
    }
    if payload.len() > FRAME_MAX_PAYLOAD_LEN {
        return Err(BrokerIpcError::OversizedFrame);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| BrokerIpcError::OversizedFrame)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + FRAME_TAG_LEN);
    frame.extend_from_slice(FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.push(kind);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(binding.environment_id().as_bytes());
    frame.extend_from_slice(&binding.generation().to_be_bytes());
    frame.extend_from_slice(binding.policy_digest().as_bytes());
    debug_assert_eq!(frame.len(), FRAME_HEADER_LEN);
    frame.extend_from_slice(payload);
    let tag = frame_tag(key, &frame)?;
    frame.extend_from_slice(&tag);
    Ok(frame)
}

fn decode_frame(
    frame: &[u8],
    expected_kind: u8,
    expected_sequence: u64,
    binding: BrokerIpcBinding,
    key: &BrokerIpcKey,
) -> Result<Vec<u8>, BrokerIpcError> {
    if frame.len() < FRAME_HEADER_LEN + FRAME_TAG_LEN || frame.len() > FRAME_MAX_LEN {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let tag_start = frame.len() - FRAME_TAG_LEN;
    verify_frame_tag(key, &frame[..tag_start], &frame[tag_start..])?;
    if &frame[..8] != FRAME_MAGIC || frame[8] != FRAME_VERSION || frame[9] != expected_kind {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let payload_len = usize::from(u16::from_be_bytes([frame[10], frame[11]]));
    if payload_len > FRAME_MAX_PAYLOAD_LEN
        || FRAME_HEADER_LEN + payload_len + FRAME_TAG_LEN != frame.len()
    {
        return Err(BrokerIpcError::MalformedFrame);
    }
    let sequence = u64::from_be_bytes(
        frame[12..20]
            .try_into()
            .map_err(|_| BrokerIpcError::MalformedFrame)?,
    );
    if sequence != expected_sequence {
        return Err(BrokerIpcError::SequenceMismatch);
    }
    if frame[20..36] != *binding.environment_id().as_bytes()
        || frame[36..44] != binding.generation().to_be_bytes()
        || frame[44..76] != *binding.policy_digest().as_bytes()
    {
        return Err(BrokerIpcError::BindingMismatch);
    }
    Ok(frame[FRAME_HEADER_LEN..tag_start].to_vec())
}

fn frame_tag(key: &BrokerIpcKey, authenticated: &[u8]) -> Result<[u8; 32], BrokerIpcError> {
    key.with_bytes(|bytes| {
        let mut mac = HmacSha256::new_from_slice(bytes).map_err(|_| BrokerIpcError::InvalidKey)?;
        mac.update(FRAME_DOMAIN);
        mac.update(authenticated);
        Ok(mac.finalize().into_bytes().into())
    })
}

fn verify_frame_tag(
    key: &BrokerIpcKey,
    authenticated: &[u8],
    tag: &[u8],
) -> Result<(), BrokerIpcError> {
    key.with_bytes(|bytes| {
        let mut mac = HmacSha256::new_from_slice(bytes).map_err(|_| BrokerIpcError::InvalidKey)?;
        mac.update(FRAME_DOMAIN);
        mac.update(authenticated);
        mac.verify_slice(tag)
            .map_err(|_| BrokerIpcError::Authentication)
    })
}

async fn send_connected_descriptor(
    stream: &UnixStream,
    descriptor: BorrowedFd<'_>,
) -> Result<(), BrokerIpcError> {
    loop {
        stream
            .writable()
            .await
            .map_err(|_| BrokerIpcError::FrameIo)?;
        let marker = [DESCRIPTOR_MARKER];
        let vectors = [IoSlice::new(&marker)];
        let descriptors = [descriptor];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(BrokerIpcError::DescriptorInvalid);
        }
        match stream.try_io(Interest::WRITABLE, || {
            sendmsg(stream, &vectors, &mut ancillary, SendFlags::empty()).map_err(errno_to_io_error)
        }) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(BrokerIpcError::FrameIo),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(BrokerIpcError::FrameIo),
        }
    }
}

/// Read the descriptor marker and exactly one untruncated descriptor.
async fn receive_descriptor(stream: &UnixStream) -> Result<OwnedFd, BrokerIpcError> {
    let mut marker = [0_u8; 1];
    let descriptors = loop {
        stream
            .readable()
            .await
            .map_err(|_| BrokerIpcError::DescriptorMissing)?;
        let mut vectors = [IoSliceMut::new(&mut marker)];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        match stream.try_io(Interest::READABLE, || {
            recvmsg(stream, &mut vectors, &mut ancillary, RecvFlags::empty())
                .map_err(errno_to_io_error)
        }) {
            Ok(message) => {
                if message.bytes != 1
                    || marker[0] != DESCRIPTOR_MARKER
                    || message
                        .flags
                        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                {
                    return Err(BrokerIpcError::DescriptorMissing);
                }
                let mut descriptors = Vec::new();
                let mut invalid_ancillary = false;
                for message in ancillary.drain() {
                    match message {
                        RecvAncillaryMessage::ScmRights(received) => descriptors.extend(received),
                        _ => invalid_ancillary = true,
                    }
                }
                if invalid_ancillary {
                    return Err(BrokerIpcError::DescriptorInvalid);
                }
                break descriptors;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(BrokerIpcError::DescriptorMissing),
        }
    };
    if descriptors.len() != 1 {
        return Err(BrokerIpcError::DescriptorInvalid);
    }
    descriptors
        .into_iter()
        .next()
        .ok_or(BrokerIpcError::DescriptorMissing)
}

/// Accept a received descriptor only as a TCP stream connected to exactly
/// `expected_peer`. A connection the peer already closed or reset is
/// `RemoteUnavailable`, an ordinary failed connect; any other socket, or a
/// different peer, is `DescriptorInvalid`.
fn admit_connected_descriptor(
    descriptor: OwnedFd,
    expected_peer: SocketAddr,
) -> Result<OwnedFd, BrokerIpcError> {
    fcntl_setfd(&descriptor, FdFlags::CLOEXEC).map_err(|_| BrokerIpcError::DescriptorInvalid)?;
    if rustix::net::sockopt::socket_type(&descriptor)
        .map_err(|_| BrokerIpcError::DescriptorInvalid)?
        != SocketType::STREAM
    {
        return Err(BrokerIpcError::DescriptorInvalid);
    }
    let connected = StdTcpStream::from(descriptor);
    let gone = |error: io::Error| match error.raw_os_error() {
        Some(libc_errno)
            if [
                rustix::io::Errno::NOTCONN,
                rustix::io::Errno::CONNRESET,
                rustix::io::Errno::INVAL,
            ]
            .iter()
            .any(|errno| errno.raw_os_error() == libc_errno) =>
        {
            BrokerIpcError::RemoteUnavailable
        }
        _ => BrokerIpcError::DescriptorInvalid,
    };
    connected.nodelay().map_err(gone)?;
    connected.set_nonblocking(true).map_err(gone)?;
    if connected.peer_addr().map_err(gone)? != expected_peer {
        return Err(BrokerIpcError::DescriptorInvalid);
    }
    Ok(OwnedFd::from(connected))
}

fn errno_to_io_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn byte(&mut self) -> Result<u8, BrokerIpcError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BrokerIpcError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, BrokerIpcError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| BrokerIpcError::MalformedFrame)?,
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BrokerIpcError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(BrokerIpcError::MalformedFrame)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(BrokerIpcError::MalformedFrame)?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), BrokerIpcError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(BrokerIpcError::MalformedFrame)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use codewire_egress_policy::lease::{DnsAddress, DnsResolution, LeaseInstant};
    use codewire_egress_policy::{CompiledPolicy, PolicyDocument};
    use tokio::sync::Notify;

    use super::*;
    use crate::{DnsResolverOutcome, SystemBrokerClock};

    #[test]
    fn transaction_deadline_exceeds_production_adapter_deadlines() {
        use crate::adapters::{SYSTEM_DNS_QUERY_TIMEOUT, SYSTEM_TCP_CONNECT_TIMEOUT};
        let margin = Duration::from_secs(3);
        assert!(BROKER_IPC_TRANSACTION_TIMEOUT >= SYSTEM_DNS_QUERY_TIMEOUT + margin);
        assert!(BROKER_IPC_TRANSACTION_TIMEOUT >= SYSTEM_TCP_CONNECT_TIMEOUT + margin);
    }

    const KEY_BYTES: [u8; BROKER_IPC_KEY_LEN] = [0x5a; BROKER_IPC_KEY_LEN];
    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    const FIRST_DNS: usize = 1;
    const FIRST_CONNECT: usize = 1 + BROKER_IPC_DNS_SESSIONS;

    fn key() -> BrokerIpcKey {
        BrokerIpcKey::from_bytes(KEY_BYTES).unwrap()
    }

    fn session_key(index: usize) -> BrokerIpcKey {
        key().for_session(index).unwrap()
    }

    /// Connected session streams in session order: the client's ends and the
    /// broker's.
    fn session_pairs() -> (Vec<UnixStream>, Vec<UnixStream>) {
        raise_open_file_limit();
        (0..BROKER_IPC_SESSIONS)
            .map(|_| UnixStream::pair().unwrap())
            .unzip()
    }

    /// Each pool test holds two descriptors per session and the tests run in
    /// parallel, past the 256 open files macOS starts a process with.
    fn raise_open_file_limit() {
        static RAISED: std::sync::Once = std::sync::Once::new();
        RAISED.call_once(|| {
            use rustix::process::{Resource, getrlimit, setrlimit};
            let mut limit = getrlimit(Resource::Nofile);
            let wanted = limit.maximum.map_or(4096, |maximum| maximum.min(4096));
            if limit.current.is_some_and(|current| current < wanted) {
                limit.current = Some(wanted);
                setrlimit(Resource::Nofile, limit).unwrap();
            }
        });
    }

    fn client(streams: Vec<UnixStream>, binding: BrokerIpcBinding) -> BrokerIpcClient {
        BrokerIpcClient::new(streams, binding, key()).unwrap()
    }

    fn binding(policy: &CompiledPolicy) -> BrokerIpcBinding {
        BrokerIpcBinding::new(Uuid::from_u128(0x1234), 7, policy.digest()).unwrap()
    }

    fn named_policy() -> CompiledPolicy {
        PolicyDocument::parse_yaml(
            br#"
version: 1
default: deny
rules:
  - id: named-dns
    action: allow
    protocols: [dns]
    ports: [53]
    destinations: [allowed.example.com]
    route_classes: [general]
  - id: named-tcp
    action: allow
    protocols: [tcp]
    ports: [443]
    destinations: [allowed.example.com]
    route_classes: [general]
"#,
        )
        .unwrap()
    }

    fn positive(address: IpAddr, ttl_seconds: u32) -> DnsResolverOutcome {
        DnsResolverOutcome::Positive(
            DnsResolution::new(vec![], vec![DnsAddress::new(address, ttl_seconds).unwrap()])
                .unwrap(),
        )
    }

    #[derive(Default)]
    struct FakeClock(AtomicU64);

    impl BrokerClock for FakeClock {
        fn now(&self) -> LeaseInstant {
            LeaseInstant::from_millis(self.0.load(Ordering::Relaxed))
        }
    }

    struct FakeResolver {
        outcomes: StdMutex<VecDeque<Result<DnsResolverOutcome, BrokerAdapterFailure>>>,
        requests: StdMutex<Vec<String>>,
    }

    impl FakeResolver {
        fn new(outcomes: impl IntoIterator<Item = DnsResolverOutcome>) -> Self {
            Self {
                outcomes: StdMutex::new(outcomes.into_iter().map(Ok).collect()),
                requests: StdMutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DnsResolver for FakeResolver {
        async fn resolve(
            &self,
            request: crate::DnsResolverRequest,
        ) -> Result<DnsResolverOutcome, BrokerAdapterFailure> {
            self.requests
                .lock()
                .unwrap()
                .push(request.name().to_string());
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(BrokerAdapterFailure::Unavailable))
        }
    }

    #[derive(Default)]
    struct BlockingResolver {
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl DnsResolver for BlockingResolver {
        async fn resolve(
            &self,
            _request: crate::DnsResolverRequest,
        ) -> Result<DnsResolverOutcome, BrokerAdapterFailure> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(positive(PUBLIC_V4, 60))
        }
    }

    #[derive(Default)]
    struct NoConnector {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl TcpConnector for NoConnector {
        type Stream = StdTcpStream;

        async fn connect(
            &self,
            _destination: SocketAddr,
        ) -> Result<Self::Stream, BrokerAdapterFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(BrokerAdapterFailure::Unavailable)
        }
    }

    #[test]
    fn frames_are_authenticated_bound_and_strictly_sequenced() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let payload = encode_dns_request("allowed.example.com", DnsRecordFamily::Ipv4).unwrap();
        let frame = encode_frame(FRAME_KIND_REQUEST, 4, binding, &key(), &payload).unwrap();
        assert_eq!(
            decode_frame(&frame, FRAME_KIND_REQUEST, 4, binding, &key()).unwrap(),
            payload
        );

        let mut tampered = frame.clone();
        tampered[FRAME_HEADER_LEN] ^= 1;
        assert_eq!(
            decode_frame(&tampered, FRAME_KIND_REQUEST, 4, binding, &key()),
            Err(BrokerIpcError::Authentication)
        );
        assert_eq!(
            decode_frame(&frame, FRAME_KIND_REQUEST, 5, binding, &key()),
            Err(BrokerIpcError::SequenceMismatch)
        );
        let wrong_binding =
            BrokerIpcBinding::new(Uuid::from_u128(0x5678), 7, policy.digest()).unwrap();
        assert_eq!(
            decode_frame(&frame, FRAME_KIND_REQUEST, 4, wrong_binding, &key()),
            Err(BrokerIpcError::BindingMismatch)
        );
        assert_eq!(
            encode_frame(
                FRAME_KIND_REQUEST,
                1,
                binding,
                &key(),
                &vec![0_u8; FRAME_MAX_PAYLOAD_LEN + 1],
            ),
            Err(BrokerIpcError::OversizedFrame)
        );
    }

    #[test]
    fn invalid_keys_bindings_and_payload_shapes_fail_closed() {
        assert_eq!(
            BrokerIpcKey::from_bytes([0_u8; BROKER_IPC_KEY_LEN]).unwrap_err(),
            BrokerIpcError::InvalidKey
        );
        let policy = CompiledPolicy::developer_baseline();
        assert_eq!(
            BrokerIpcBinding::new(Uuid::nil(), 1, policy.digest()),
            Err(BrokerIpcError::InvalidBinding)
        );
        assert_eq!(
            BrokerIpcBinding::new(Uuid::from_u128(1), 0, policy.digest()),
            Err(BrokerIpcError::InvalidBinding)
        );
        assert_eq!(format!("{:?}", key()), "BrokerIpcKey([redacted])");
        assert_eq!(
            encode_dns_request(&"a".repeat(254), DnsRecordFamily::Ipv4),
            Err(BrokerIpcError::MalformedFrame)
        );
        assert_eq!(
            encode_tcp_request(OP_CONNECT_TCP, SocketAddr::new(PUBLIC_V4, 0),),
            Err(BrokerIpcError::MalformedFrame)
        );
        assert_eq!(
            decode_dns_response(
                &[OP_RESOLVE_DNS, STATUS_OK, 0, 0, 0, 1, 0],
                DnsRecordFamily::Ipv4
            ),
            Err(BrokerIpcError::MalformedFrame)
        );
    }

    #[tokio::test]
    async fn ipc_denies_before_resolution_then_preserves_a_live_session() {
        let policy = named_policy();
        let binding = binding(&policy);
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
        let connector = Arc::new(NoConnector::default());
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::clone(&resolver),
            connector,
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);

        assert_eq!(
            client
                .resolve_dns("denied.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerIpcError::Denied)
        );
        assert!(resolver.requests().is_empty());

        assert_eq!(
            client
                .resolve_dns("Allowed.Example.COM.", DnsRecordFamily::Ipv4)
                .await
                .unwrap(),
            BrokerIpcDnsResponse::Addresses {
                addresses: vec![PUBLIC_V4],
                ttl_seconds: 60,
            }
        );
        assert_eq!(resolver.requests(), ["allowed.example.com"]);
        assert!(
            client
                .authorize_tcp(SocketAddr::new(PUBLIC_V4, 443))
                .await
                .is_ok()
        );
        assert_eq!(
            client.authorize_tcp(SocketAddr::new(PUBLIC_V4, 80)).await,
            Err(BrokerIpcError::Denied)
        );

        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not close")
                .unwrap(),
            Err(BrokerIpcError::FrameIo)
        );
    }

    /// A request cancelled mid-flight leaves its session out of step, so the
    /// session is retired, and the broker, finding it closed, ends every
    /// session: the environment fails closed rather than lose a session
    /// silently.
    #[tokio::test]
    async fn cancelling_an_in_flight_request_retires_its_session_and_ends_the_broker() {
        let policy = named_policy();
        let binding = binding(&policy);
        let resolver = Arc::new(BlockingResolver::default());
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::new(NoConnector::default()),
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);

        {
            let request = client.resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4);
            tokio::pin!(request);
            tokio::select! {
                () = resolver.entered.notified() => {}
                result = &mut request => {
                    panic!("DNS request completed before cancellation: {result:?}")
                }
            }
        }
        // The cancelled session may hold an unread response, so it is never
        // reused.
        assert_eq!(client.dns.len(), BROKER_IPC_DNS_SESSIONS - 1);
        resolver.release.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("the broker kept serving without the retired session")
                .unwrap(),
            Err(BrokerIpcError::FrameIo)
        );
        assert!(
            client
                .resolve_dns("denied.example.com", DnsRecordFamily::Ipv4)
                .await
                .is_err()
        );
    }

    /// Every session of a class checked out, as if each were in flight.
    async fn hold_all(pool: &SessionPool) -> Vec<CheckedOut<'_>> {
        let mut held = Vec::new();
        for _ in 0..pool.len() {
            held.push(pool.checkout().await.unwrap());
        }
        held
    }

    #[tokio::test]
    async fn cancelling_a_request_waiting_for_a_session_keeps_the_pool_whole() {
        let policy = named_policy();
        let binding = binding(&policy);
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::new(NoConnector::default()),
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);

        let held = hold_all(&client.dns).await;
        {
            let waiting = client.resolve_dns("denied.example.com", DnsRecordFamily::Ipv4);
            tokio::pin!(waiting);
            tokio::select! {
                biased;
                result = &mut waiting => {
                    panic!("a request without a session completed: {result:?}")
                }
                () = tokio::task::yield_now() => {}
            }
        }
        drop(held);
        assert_eq!(client.dns.len(), BROKER_IPC_DNS_SESSIONS);
        for _ in 0..BROKER_IPC_DNS_SESSIONS {
            assert_eq!(
                client
                    .resolve_dns("denied.example.com", DnsRecordFamily::Ipv4)
                    .await,
                Err(BrokerIpcError::Denied)
            );
        }

        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not close")
                .unwrap(),
            Err(BrokerIpcError::FrameIo)
        );
    }

    #[tokio::test]
    async fn a_request_waits_at_most_the_queue_timeout_for_a_session() {
        let policy = named_policy();
        let binding = binding(&policy);
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::new(NoConnector::default()),
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);

        let held = hold_all(&client.dns).await;
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let busy = client
            .resolve_dns("denied.example.com", DnsRecordFamily::Ipv4)
            .await;
        let waited = started.elapsed();
        assert!(waited >= BROKER_IPC_QUEUE_TIMEOUT && waited < BROKER_IPC_TRANSACTION_TIMEOUT);
        tokio::time::resume();
        assert_eq!(busy, Err(BrokerIpcError::SessionBusy));
        // Waiting for a DNS session never holds up admission.
        assert_eq!(
            client
                .authorize_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443))
                .await,
            Err(BrokerIpcError::Denied)
        );
        drop(held);
        assert_eq!(client.dns.len(), BROKER_IPC_DNS_SESSIONS);

        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not close")
                .unwrap(),
            Err(BrokerIpcError::FrameIo)
        );
    }

    #[tokio::test]
    async fn stalled_response_timeout_retires_the_session() {
        let policy = named_policy();
        let binding = binding(&policy);
        let request_observed = Arc::new(Notify::new());
        let close_server = Arc::new(Notify::new());
        let (client_streams, mut server_streams) = session_pairs();
        let mut server_stream = server_streams.remove(FIRST_DNS);
        let server = tokio::spawn({
            let request_observed = Arc::clone(&request_observed);
            let close_server = Arc::clone(&close_server);
            async move {
                let request = read_frame(
                    &mut server_stream,
                    FRAME_KIND_REQUEST,
                    1,
                    binding,
                    &session_key(FIRST_DNS),
                )
                .await
                .unwrap();
                assert!(matches!(
                    decode_request(&request).unwrap(),
                    BrokerRequest::ResolveDns { name, family }
                        if name == "allowed.example.com" && family == DnsRecordFamily::Ipv4
                ));
                request_observed.notify_one();
                close_server.notified().await;
            }
        });
        let client = client(client_streams, binding);

        let stalled = client.resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4);
        tokio::pin!(stalled);
        tokio::select! {
            () = request_observed.notified() => {}
            result = &mut stalled => {
                panic!("DNS request completed before the server stalled: {result:?}")
            }
        }
        tokio::time::pause();
        let stalled_result = stalled.await;
        tokio::time::resume();
        assert_eq!(stalled_result, Err(BrokerIpcError::FrameIo));
        assert_eq!(client.dns.len(), BROKER_IPC_DNS_SESSIONS - 1);
        drop(server_streams);

        close_server.notify_one();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn server_rejects_a_policy_digest_mismatch_before_reading() {
        let policy = named_policy();
        let wrong_binding = binding(&CompiledPolicy::developer_baseline());
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::new(NoConnector::default()),
            Arc::new(SystemBrokerClock::new()),
        ));
        let (_client, server) = session_pairs();
        assert_eq!(
            serve_broker_ipc(server, wrong_binding, key(), broker).await,
            Err(BrokerIpcError::BindingMismatch)
        );
    }

    #[tokio::test]
    async fn connected_tcp_descriptor_is_transferred_and_exact_peer_validated() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let destination = listener.local_addr().unwrap();
        let connected = StdTcpStream::connect(destination).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        let (client_streams, mut server_streams) = session_pairs();
        let mut server_stream = server_streams.remove(FIRST_CONNECT);
        let server = tokio::spawn(async move {
            let request = read_frame(
                &mut server_stream,
                FRAME_KIND_REQUEST,
                1,
                binding,
                &session_key(FIRST_CONNECT),
            )
            .await
            .unwrap();
            assert!(matches!(
                decode_request(&request).unwrap(),
                BrokerRequest::ConnectTcp(actual) if actual == destination
            ));
            write_frame(
                &mut server_stream,
                FRAME_KIND_RESPONSE,
                1,
                binding,
                &session_key(FIRST_CONNECT),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, connected.as_fd())
                .await
                .unwrap();
        });
        let client = client(client_streams, binding);
        let descriptor = client.connect_tcp(destination).await.unwrap();
        drop(server_streams);
        assert!(
            rustix::io::fcntl_getfd(&descriptor)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        assert!(descriptor.as_raw_fd() >= 0);
        let mut received = StdTcpStream::from(descriptor);
        received.set_nonblocking(false).unwrap();
        received.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        accepted.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_connect_after_response_before_descriptor_fails_client_session_closed() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let requested = SocketAddr::new(PUBLIC_V4, 443);
        let response_sent = Arc::new(Notify::new());
        let close_server = Arc::new(Notify::new());
        let (client_streams, mut server_streams) = session_pairs();
        let mut server_stream = server_streams.remove(FIRST_CONNECT);
        let server = tokio::spawn({
            let response_sent = Arc::clone(&response_sent);
            let close_server = Arc::clone(&close_server);
            async move {
                let request = read_frame(
                    &mut server_stream,
                    FRAME_KIND_REQUEST,
                    1,
                    binding,
                    &session_key(FIRST_CONNECT),
                )
                .await
                .unwrap();
                assert!(matches!(
                    decode_request(&request).unwrap(),
                    BrokerRequest::ConnectTcp(actual) if actual == requested
                ));
                write_frame(
                    &mut server_stream,
                    FRAME_KIND_RESPONSE,
                    1,
                    binding,
                    &session_key(FIRST_CONNECT),
                    &[OP_CONNECT_TCP, STATUS_OK],
                )
                .await
                .unwrap();
                response_sent.notify_one();
                close_server.notified().await;
            }
        });
        let client = client(client_streams, binding);

        {
            let connect = client.connect_tcp(requested);
            tokio::pin!(connect);
            tokio::select! {
                () = response_sent.notified() => {}
                result = &mut connect => {
                    panic!("connect completed before descriptor receipt: {result:?}")
                }
            }
            tokio::select! {
                biased;
                result = &mut connect => {
                    panic!("connect completed without a descriptor: {result:?}")
                }
                () = tokio::task::yield_now() => {}
            }
        }
        // The session may hold the descriptor, so it is never reused.
        assert_eq!(client.connect.len(), BROKER_IPC_CONNECT_SESSIONS - 1);

        close_server.notify_one();
        server.await.unwrap();
        drop(server_streams);
    }

    #[tokio::test]
    async fn mismatched_connected_peer_poison_closes_the_client_session() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let requested = SocketAddr::new(PUBLIC_V4, 443);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let connected = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let (client_streams, mut server_streams) = session_pairs();
        let mut server_stream = server_streams.remove(FIRST_CONNECT);
        let server = tokio::spawn(async move {
            let _ = read_frame(
                &mut server_stream,
                FRAME_KIND_REQUEST,
                1,
                binding,
                &session_key(FIRST_CONNECT),
            )
            .await
            .unwrap();
            write_frame(
                &mut server_stream,
                FRAME_KIND_RESPONSE,
                1,
                binding,
                &session_key(FIRST_CONNECT),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, connected.as_fd())
                .await
                .unwrap();
        });
        let client = client(client_streams, binding);
        assert!(matches!(
            client.connect_tcp(requested).await,
            Err(BrokerIpcError::DescriptorInvalid)
        ));
        assert_eq!(client.connect.len(), BROKER_IPC_CONNECT_SESSIONS - 1);
        server.await.unwrap();
        drop(server_streams);
    }

    #[tokio::test]
    async fn non_tcp_stream_descriptor_is_rejected() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let requested = SocketAddr::new(PUBLIC_V4, 443);
        let (foreign, _foreign_peer) = StdUnixStream::pair().unwrap();
        let (client_streams, mut server_streams) = session_pairs();
        let mut server_stream = server_streams.remove(FIRST_CONNECT);
        let server = tokio::spawn(async move {
            let _ = read_frame(
                &mut server_stream,
                FRAME_KIND_REQUEST,
                1,
                binding,
                &session_key(FIRST_CONNECT),
            )
            .await
            .unwrap();
            write_frame(
                &mut server_stream,
                FRAME_KIND_RESPONSE,
                1,
                binding,
                &session_key(FIRST_CONNECT),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, foreign.as_fd())
                .await
                .unwrap();
        });
        let client = client(client_streams, binding);
        assert!(matches!(
            client.connect_tcp(requested).await,
            Err(BrokerIpcError::DescriptorInvalid)
        ));
        server.await.unwrap();
        drop(server_streams);
    }

    /// An authenticated frame replayed on its own session, of any class, is
    /// out of sequence and ends the broker.
    #[tokio::test]
    async fn authenticated_replay_terminates_the_server_session() {
        let destination = SocketAddr::new(PUBLIC_V4, 443);
        let requests = [
            (
                0,
                encode_tcp_request(OP_AUTHORIZE_TCP, destination).unwrap(),
            ),
            (
                FIRST_DNS,
                encode_dns_request("example.com", DnsRecordFamily::Ipv4).unwrap(),
            ),
            (
                FIRST_CONNECT,
                encode_tcp_request(OP_CONNECT_TCP, destination).unwrap(),
            ),
        ];
        for (index, payload) in requests {
            let (binding, broker) = developer_broker(Arc::default());
            let (mut clients, server_streams) = session_pairs();
            let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
            let client = &mut clients[index];
            let replay = encode_frame(
                FRAME_KIND_REQUEST,
                1,
                binding,
                &session_key(index),
                &payload,
            )
            .unwrap();
            client.write_all(&replay).await.unwrap();
            read_frame(client, FRAME_KIND_RESPONSE, 1, binding, &session_key(index))
                .await
                .unwrap();
            client.write_all(&replay).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server)
                    .await
                    .expect("server did not reject replay")
                    .unwrap(),
                Err(BrokerIpcError::SequenceMismatch),
                "session {index}"
            );
        }
    }

    #[test]
    fn session_keys_are_distinct_and_never_the_bootstrap_key() {
        let keys: Vec<[u8; BROKER_IPC_KEY_LEN]> = (0..BROKER_IPC_SESSIONS)
            .map(|index| session_key(index).with_bytes(|bytes| *bytes))
            .collect();
        for (index, derived) in keys.iter().enumerate() {
            assert_ne!(*derived, KEY_BYTES);
            assert!(keys[index + 1..].iter().all(|other| other != derived));
        }
        // The same derivation on both sides.
        assert_eq!(keys[3], session_key(3).with_bytes(|bytes| *bytes));
        assert_eq!(
            key().for_session(256).unwrap_err(),
            BrokerIpcError::SessionCount
        );
        assert_eq!(
            BrokerIpcSessionClass::of(0),
            Some(BrokerIpcSessionClass::Admission)
        );
        assert_eq!(
            BrokerIpcSessionClass::of(FIRST_DNS),
            Some(BrokerIpcSessionClass::Dns)
        );
        assert_eq!(
            BrokerIpcSessionClass::of(FIRST_CONNECT - 1),
            Some(BrokerIpcSessionClass::Dns)
        );
        assert_eq!(
            BrokerIpcSessionClass::of(FIRST_CONNECT),
            Some(BrokerIpcSessionClass::Connect)
        );
        assert_eq!(
            BrokerIpcSessionClass::of(BROKER_IPC_SESSIONS - 1),
            Some(BrokerIpcSessionClass::Connect)
        );
        assert_eq!(BrokerIpcSessionClass::of(BROKER_IPC_SESSIONS), None);
    }

    /// The broker for the protected-destination and cross-session tests.
    fn developer_broker(
        connector: Arc<NoConnector>,
    ) -> (
        BrokerIpcBinding,
        Arc<PolicyEgressBroker<FakeResolver, NoConnector, FakeClock>>,
    ) {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            connector,
            Arc::new(FakeClock::default()),
        ));
        (binding, broker)
    }

    #[tokio::test]
    async fn a_frame_from_one_session_fails_authentication_on_another() {
        let payload = encode_dns_request("example.com", DnsRecordFamily::Ipv4).unwrap();
        let (binding, _) = developer_broker(Arc::default());
        for foreign in [session_key(0), session_key(FIRST_DNS + 1), key()] {
            let (_, broker) = developer_broker(Arc::default());
            let (mut clients, server_streams) = session_pairs();
            let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
            let frame = encode_frame(FRAME_KIND_REQUEST, 1, binding, &foreign, &payload).unwrap();
            clients[FIRST_DNS].write_all(&frame).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server)
                    .await
                    .expect("server accepted a foreign frame")
                    .unwrap(),
                Err(BrokerIpcError::Authentication)
            );
        }
    }

    #[tokio::test]
    async fn a_request_outside_its_session_class_ends_every_session() {
        let connector = Arc::new(NoConnector::default());
        let (binding, broker) = developer_broker(Arc::clone(&connector));
        let destination = SocketAddr::new(PUBLIC_V4, 443);
        let wrong_class = [
            (0, encode_tcp_request(OP_CONNECT_TCP, destination).unwrap()),
            (
                0,
                encode_dns_request("example.com", DnsRecordFamily::Ipv4).unwrap(),
            ),
            (
                FIRST_DNS,
                encode_tcp_request(OP_CONNECT_TCP, destination).unwrap(),
            ),
            (
                FIRST_DNS,
                encode_tcp_request(OP_AUTHORIZE_TCP, destination).unwrap(),
            ),
            (
                FIRST_CONNECT,
                encode_tcp_request(OP_AUTHORIZE_TCP, destination).unwrap(),
            ),
            (
                FIRST_CONNECT,
                encode_dns_request("example.com", DnsRecordFamily::Ipv4).unwrap(),
            ),
        ];
        for (index, payload) in wrong_class {
            let (mut clients, server_streams) = session_pairs();
            let server = tokio::spawn(serve_broker_ipc(
                server_streams,
                binding,
                key(),
                Arc::clone(&broker),
            ));
            let frame = encode_frame(
                FRAME_KIND_REQUEST,
                1,
                binding,
                &session_key(index),
                &payload,
            )
            .unwrap();
            clients[index].write_all(&frame).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server)
                    .await
                    .expect("server served a request outside its class")
                    .unwrap(),
                Err(BrokerIpcError::SessionClassMismatch)
            );
        }
        assert_eq!(connector.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn every_session_is_verified_without_an_upstream_effect() {
        let connector = Arc::new(NoConnector::default());
        let (binding, broker) = developer_broker(Arc::clone(&connector));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);
        client.verify_sessions().await.unwrap();
        assert_eq!(connector.calls.load(Ordering::Relaxed), 0);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not close");

        // A worker holding the wrong key fails verification.
        let (_, broker) = developer_broker(Arc::default());
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let wrong = BrokerIpcClient::new(
            client_streams,
            binding,
            BrokerIpcKey::from_bytes([0x33; BROKER_IPC_KEY_LEN]).unwrap(),
        )
        .unwrap();
        assert!(wrong.verify_sessions().await.is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not refuse the wrong key")
                .unwrap(),
            Err(BrokerIpcError::Authentication)
        );
    }

    /// A connect on a connect session never relies on an admission granted
    /// on the admission session: it is refused once the lease expires or the
    /// address becomes local to the host.
    #[tokio::test]
    async fn a_connect_evaluates_policy_again_after_admission_on_another_session() {
        let policy = named_policy();
        let binding = binding(&policy);
        let clock = Arc::new(FakeClock::default());
        let connector = Arc::new(NoConnector::default());
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([
                positive(PUBLIC_V4, 60),
                positive(PUBLIC_V4, 60),
            ])),
            Arc::clone(&connector),
            Arc::clone(&clock),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(
            server_streams,
            binding,
            key(),
            Arc::clone(&broker),
        ));
        let client = client(client_streams, binding);
        let destination = SocketAddr::new(PUBLIC_V4, 443);

        client
            .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        client.authorize_tcp(destination).await.unwrap();
        clock.0.store(61_000, Ordering::Relaxed);
        assert_eq!(
            client.connect_tcp(destination).await.unwrap_err(),
            BrokerIpcError::Denied
        );

        client
            .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        client.authorize_tcp(destination).await.unwrap();
        broker
            .set_host_addresses(
                codewire_egress_policy::host_addresses::HostAddressSet::new([], [PUBLIC_V4])
                    .unwrap(),
            )
            .await;
        assert_eq!(
            client.connect_tcp(destination).await.unwrap_err(),
            BrokerIpcError::Denied
        );
        assert_eq!(connector.calls.load(Ordering::Relaxed), 0);
        // A refusal is an answer, not a session failure.
        assert_eq!(client.connect.len(), BROKER_IPC_CONNECT_SESSIONS);

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not close");
    }

    /// Connects that never complete, as to a host that drops SYNs.
    #[derive(Default)]
    struct StalledConnector {
        entered: AtomicUsize,
        release: Notify,
    }

    #[async_trait]
    impl TcpConnector for StalledConnector {
        type Stream = StdTcpStream;

        async fn connect(
            &self,
            _destination: SocketAddr,
        ) -> Result<Self::Stream, BrokerAdapterFailure> {
            self.entered.fetch_add(1, Ordering::AcqRel);
            self.release.notified().await;
            Err(BrokerAdapterFailure::Timeout)
        }
    }

    /// #2638: with every connect session stalled upstream, DNS and admission
    /// still answer at once, and one more connect waits at most the queue
    /// timeout.
    #[tokio::test]
    async fn stalled_connects_leave_dns_and_admission_working() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let connector = Arc::new(StalledConnector::default());
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = Arc::new(client(client_streams, binding));
        let destination = SocketAddr::new(PUBLIC_V4, 443);

        let mut stalled = JoinSet::new();
        for _ in 0..BROKER_IPC_CONNECT_SESSIONS {
            let client = Arc::clone(&client);
            stalled.spawn(async move { client.connect_tcp(destination).await.map(drop) });
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while connector.entered.load(Ordering::Acquire) < BROKER_IPC_CONNECT_SESSIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every connect session reached the connector");

        let prompt = Duration::from_millis(500);
        let resolved = tokio::time::timeout(
            prompt,
            client.resolve_dns("example.com", DnsRecordFamily::Ipv4),
        )
        .await
        .expect("DNS waited on a stalled connect");
        assert_eq!(
            resolved.unwrap(),
            BrokerIpcDnsResponse::Addresses {
                addresses: vec![PUBLIC_V4],
                ttl_seconds: 60,
            }
        );
        tokio::time::timeout(prompt, client.authorize_tcp(destination))
            .await
            .expect("admission waited on a stalled connect")
            .unwrap();

        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let queued = client.connect_tcp(destination).await;
        let waited = started.elapsed();
        assert!(waited >= BROKER_IPC_QUEUE_TIMEOUT && waited < BROKER_IPC_TRANSACTION_TIMEOUT);
        tokio::time::resume();
        assert_eq!(queued.unwrap_err(), BrokerIpcError::SessionBusy);

        connector.release.notify_waiters();
        while let Some(result) = stalled.join_next().await {
            assert_eq!(result.unwrap(), Err(BrokerIpcError::RemoteUnavailable));
        }
        assert_eq!(client.connect.len(), BROKER_IPC_CONNECT_SESSIONS);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not close");
    }

    /// Connects to a local listener that resets each connection as soon as
    /// it is accepted, as a server that closes right after the handshake.
    struct ResettingConnector {
        listener: TcpListener,
    }

    #[async_trait]
    impl TcpConnector for ResettingConnector {
        type Stream = StdTcpStream;

        async fn connect(
            &self,
            _destination: SocketAddr,
        ) -> Result<Self::Stream, BrokerAdapterFailure> {
            let connected = StdTcpStream::connect(self.listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = self.listener.accept().unwrap();
            rustix::net::sockopt::set_socket_linger(&accepted, Some(Duration::ZERO)).unwrap();
            drop(accepted);
            // Wait until the reset has arrived.
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while connected.peer_addr().is_ok() {
                assert!(std::time::Instant::now() < deadline, "no reset arrived");
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(connected)
        }
    }

    /// #2638 review: a connection the server resets right after the
    /// handshake fails only its own request. Its session, and every other,
    /// carries on, and the broker keeps serving.
    #[tokio::test]
    async fn a_connection_reset_after_the_handshake_fails_only_its_request() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::new(ResettingConnector {
                listener: TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            }),
            Arc::new(FakeClock::default()),
        ));
        let (client_streams, server_streams) = session_pairs();
        let mut server = tokio::spawn(serve_broker_ipc(server_streams, binding, key(), broker));
        let client = client(client_streams, binding);
        let destination = SocketAddr::new(PUBLIC_V4, 443);

        // Every connect session in turn, then the first again.
        for _ in 0..=BROKER_IPC_CONNECT_SESSIONS {
            assert_eq!(
                client.connect_tcp(destination).await.unwrap_err(),
                BrokerIpcError::RemoteUnavailable
            );
        }
        assert_eq!(client.connect.len(), BROKER_IPC_CONNECT_SESSIONS);
        client.authorize_tcp(destination).await.unwrap();
        assert_eq!(
            client.resolve_dns("localhost", DnsRecordFamily::Ipv4).await,
            Err(BrokerIpcError::Denied)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err(),
            "the broker ended"
        );

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not close");
    }
}
