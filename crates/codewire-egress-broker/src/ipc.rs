//! Authenticated capability IPC between one confined packet worker and its
//! separate per-environment egress broker.
//!
//! The transport is an already-created connected AF_UNIX stream. Every frame
//! is HMAC-authenticated and bound to one environment, boot generation, policy
//! digest, direction, and strictly increasing request sequence. The broker may
//! transfer only one already-connected TCP descriptor after an authenticated
//! successful connect response; the client validates its socket type and exact
//! peer before accepting it.

use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

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
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

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

pub struct BrokerIpcClient {
    state: Mutex<ClientState>,
}

impl BrokerIpcClient {
    pub fn new(stream: UnixStream, binding: BrokerIpcBinding, key: BrokerIpcKey) -> Self {
        Self {
            state: Mutex::new(ClientState {
                stream,
                binding,
                key,
                next_sequence: 1,
                failed: false,
            }),
        }
    }

    pub async fn resolve_dns(
        &self,
        name: &str,
        family: DnsRecordFamily,
    ) -> Result<BrokerIpcDnsResponse, BrokerIpcError> {
        let request = encode_dns_request(name, family)?;
        let mut state = self.state.lock().await;
        let response = state.request(&request).await?;
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
        let mut state = self.state.lock().await;
        let response = state.request(&request).await?;
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
        let mut state = self.state.lock().await;
        let response = state.request(&request).await?;
        match decode_empty_response(&response, OP_CONNECT_TCP) {
            Ok(()) => {}
            Err(error) if error.is_valid_remote_result() => return Err(error),
            Err(error) => {
                state.failed = true;
                return Err(error);
            }
        }
        match receive_connected_descriptor(&state.stream, destination).await {
            Ok(descriptor) => Ok(descriptor),
            Err(error) => {
                state.failed = true;
                Err(error)
            }
        }
    }
}

impl ClientState {
    async fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>, BrokerIpcError> {
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
        if self.stream.write_all(&frame).await.is_err() || self.stream.flush().await.is_err() {
            self.failed = true;
            return Err(BrokerIpcError::FrameIo);
        }
        let response = match read_frame(
            &mut self.stream,
            FRAME_KIND_RESPONSE,
            sequence,
            self.binding,
            &self.key,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.next_sequence = match sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.failed = true;
                return Err(BrokerIpcError::SequenceExhausted);
            }
        };
        Ok(response)
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

pub async fn serve_broker_ipc<R, C, K>(
    mut stream: UnixStream,
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
    let mut sequence = 1_u64;
    loop {
        let payload = read_frame(&mut stream, FRAME_KIND_REQUEST, sequence, binding, &key).await?;
        let request = decode_request(&payload)?;
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

async fn receive_connected_descriptor(
    stream: &UnixStream,
    expected_peer: SocketAddr,
) -> Result<OwnedFd, BrokerIpcError> {
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
    let descriptor = descriptors
        .into_iter()
        .next()
        .ok_or(BrokerIpcError::DescriptorMissing)?;
    fcntl_setfd(&descriptor, FdFlags::CLOEXEC).map_err(|_| BrokerIpcError::DescriptorInvalid)?;
    if rustix::net::sockopt::socket_type(&descriptor)
        .map_err(|_| BrokerIpcError::DescriptorInvalid)?
        != SocketType::STREAM
    {
        return Err(BrokerIpcError::DescriptorInvalid);
    }
    let connected = StdTcpStream::from(descriptor);
    connected
        .nodelay()
        .map_err(|_| BrokerIpcError::DescriptorInvalid)?;
    connected
        .set_nonblocking(true)
        .map_err(|_| BrokerIpcError::DescriptorInvalid)?;
    if connected
        .peer_addr()
        .map_err(|_| BrokerIpcError::DescriptorInvalid)?
        != expected_peer
    {
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

    use super::*;
    use crate::{DnsResolverOutcome, SystemBrokerClock};

    const KEY_BYTES: [u8; BROKER_IPC_KEY_LEN] = [0x5a; BROKER_IPC_KEY_LEN];
    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    fn key() -> BrokerIpcKey {
        BrokerIpcKey::from_bytes(KEY_BYTES).unwrap()
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
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_ipc(server_stream, binding, key(), broker));
        let client = BrokerIpcClient::new(client_stream, binding, key());

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
        let (_client, server) = UnixStream::pair().unwrap();
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
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let request = read_frame(&mut server_stream, FRAME_KIND_REQUEST, 1, binding, &key())
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
                &key(),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, connected.as_fd())
                .await
                .unwrap();
        });
        let client = BrokerIpcClient::new(client_stream, binding, key());
        let descriptor = client.connect_tcp(destination).await.unwrap();
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
    async fn mismatched_connected_peer_poison_closes_the_client_session() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let requested = SocketAddr::new(PUBLIC_V4, 443);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let connected = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let _ = read_frame(&mut server_stream, FRAME_KIND_REQUEST, 1, binding, &key())
                .await
                .unwrap();
            write_frame(
                &mut server_stream,
                FRAME_KIND_RESPONSE,
                1,
                binding,
                &key(),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, connected.as_fd())
                .await
                .unwrap();
        });
        let client = BrokerIpcClient::new(client_stream, binding, key());
        assert!(matches!(
            client.connect_tcp(requested).await,
            Err(BrokerIpcError::DescriptorInvalid)
        ));
        assert_eq!(
            client.authorize_tcp(requested).await,
            Err(BrokerIpcError::SessionClosed)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn non_tcp_stream_descriptor_is_rejected() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let requested = SocketAddr::new(PUBLIC_V4, 443);
        let (foreign, _foreign_peer) = StdUnixStream::pair().unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let _ = read_frame(&mut server_stream, FRAME_KIND_REQUEST, 1, binding, &key())
                .await
                .unwrap();
            write_frame(
                &mut server_stream,
                FRAME_KIND_RESPONSE,
                1,
                binding,
                &key(),
                &[OP_CONNECT_TCP, STATUS_OK],
            )
            .await
            .unwrap();
            send_connected_descriptor(&server_stream, foreign.as_fd())
                .await
                .unwrap();
        });
        let client = BrokerIpcClient::new(client_stream, binding, key());
        assert!(matches!(
            client.connect_tcp(requested).await,
            Err(BrokerIpcError::DescriptorInvalid)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_replay_terminates_the_server_session() {
        let policy = CompiledPolicy::developer_baseline();
        let binding = binding(&policy);
        let broker = Arc::new(PolicyEgressBroker::new(
            policy,
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::new(NoConnector::default()),
            Arc::new(FakeClock::default()),
        ));
        let (mut client, server_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_ipc(server_stream, binding, key(), broker));
        let payload =
            encode_tcp_request(OP_AUTHORIZE_TCP, SocketAddr::new(PUBLIC_V4, 443)).unwrap();
        let replay = encode_frame(FRAME_KIND_REQUEST, 1, binding, &key(), &payload).unwrap();
        client.write_all(&replay).await.unwrap();
        let response = read_frame(&mut client, FRAME_KIND_RESPONSE, 1, binding, &key())
            .await
            .unwrap();
        assert_eq!(response, [OP_AUTHORIZE_TCP, STATUS_OK]);
        client.write_all(&replay).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not reject replay")
                .unwrap(),
            Err(BrokerIpcError::SequenceMismatch)
        );
    }
}
