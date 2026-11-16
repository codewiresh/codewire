use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::PacketBound;

pub const GUEST_NETWORK_VSOCK_PORT: u32 = 7_775;
/// The session protocol this crate speaks. A local VM's guest init carries
/// it in its runtime ABI marker, so a host never boots or restores a guest
/// that speaks another.
pub const NETWORK_PROTOCOL_VERSION: u16 = 2;
/// Guest PID 1 keeps the fail-closed network agent alive long enough for the
/// host to admit both isolated product processes and authenticate the session.
pub const NETWORK_HOST_READY_TIMEOUT_SECONDS: u64 = 60;
pub const NETWORK_HOST_HELLO_LEN: usize = 98;
pub const NETWORK_GUEST_ACK_LEN: usize = 74;
pub const NETWORK_HOST_READY_LEN: usize = 72;
pub const NETWORK_FRAME_HEADER_LEN: usize = 20;
pub const NETWORK_KEY_LEN: usize = 32;

const TAG_LEN: usize = NETWORK_KEY_LEN;
const NONCE_LEN: usize = 32;
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;
// Version 2 carries the session's packet bound in the hello and its echo in
// the acknowledgement (#4000).
const HOST_HELLO_MAGIC: &[u8; 8] = b"CWNETH2\0";
const GUEST_ACK_MAGIC: &[u8; 8] = b"CWNETA2\0";
const HOST_READY_MAGIC: &[u8; 8] = b"CWNETR1\0";
// Version 2 frames say in header byte 18 whether they carry a packet or a
// control message (#4000).
const FRAME_MAGIC: &[u8; 8] = b"CWNETF2\0";
const FRAME_KIND_PACKET: u8 = 0;
const FRAME_KIND_CONTROL: u8 = 1;
// A control frame's first byte names its message; each travels one way.
const CONTROL_SELF_CHECK: u8 = 1;
const CONTROL_EGRESS_TRUST: u8 = 2;
const SELF_CHECK_PASSED: u8 = 0;
const SELF_CHECK_FAILED: u8 = 1;
/// The most certificate bytes an egress trust frame carries. The receiver
/// parses them as a CA certificate under its own, smaller bound.
pub const MAX_EGRESS_TRUST_BYTES: usize = 4_096;
const KEY_DOMAIN: &[u8] = b"codewire-network-key-v1\0";
const HOST_HELLO_DOMAIN: &[u8] = b"codewire-network-host-hello-v2\0";
const GUEST_ACK_DOMAIN: &[u8] = b"codewire-network-guest-ack-v2\0";
const HOST_READY_DOMAIN: &[u8] = b"codewire-network-host-ready-v1\0";
const SESSION_DOMAIN: &[u8] = b"codewire-network-session-v1\0";
const FRAME_DOMAIN: &[u8] = b"codewire-network-frame-v2\0";

type HmacSha256 = Hmac<Sha256>;

/// A generation-bound key derived from the one-boot guest daemon token.
///
/// The network worker receives only this derived key, never the daemon token.
/// This type is deliberately non-cloneable and has no `Debug` implementation.
pub struct NetworkKey([u8; TAG_LEN]);

impl NetworkKey {
    pub fn derive(token: &str, vm_id: Uuid, generation: u64) -> Result<Self, NetworkError> {
        validate_identity(vm_id, generation)?;
        validate_token(token)?;
        let mut mac =
            HmacSha256::new_from_slice(token.as_bytes()).map_err(|_| NetworkError::InvalidKey)?;
        mac.update(KEY_DOMAIN);
        mac.update(vm_id.as_bytes());
        mac.update(&generation.to_le_bytes());
        Ok(Self(mac.finalize().into_bytes().into()))
    }

    /// Reconstitute a key delivered over a private inherited bootstrap
    /// descriptor. The daemon token is never exposed to the host worker.
    pub fn from_derived_bytes(bytes: [u8; NETWORK_KEY_LEN]) -> Result<Self, NetworkError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(NetworkError::InvalidKey);
        }
        Ok(Self(bytes))
    }

    /// Expose the derived key only to an in-process operation such as writing
    /// the worker's inherited, private bootstrap channel.
    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8; TAG_LEN]) -> T) -> T {
        operation(&self.0)
    }
}

impl Drop for NetworkKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkHostHello {
    pub vm_id: Uuid,
    pub generation: u64,
    pub nonce: [u8; NONCE_LEN],
    /// The bound the host fixed for this session's packets.
    pub packet_bound: PacketBound,
}

impl NetworkHostHello {
    pub fn new(
        vm_id: Uuid,
        generation: u64,
        nonce: [u8; NONCE_LEN],
        packet_bound: PacketBound,
    ) -> Result<Self, NetworkError> {
        validate_identity(vm_id, generation)?;
        validate_nonce(&nonce)?;
        Ok(Self {
            vm_id,
            generation,
            nonce,
            packet_bound,
        })
    }

    pub fn encode(&self, key: &NetworkKey) -> [u8; NETWORK_HOST_HELLO_LEN] {
        let mut bytes = [0_u8; NETWORK_HOST_HELLO_LEN];
        bytes[..8].copy_from_slice(HOST_HELLO_MAGIC);
        bytes[8..24].copy_from_slice(self.vm_id.as_bytes());
        bytes[24..32].copy_from_slice(&self.generation.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.nonce);
        bytes[64..66].copy_from_slice(&self.packet_bound.to_le_bytes());
        let tag = authentication_tag(key, HOST_HELLO_DOMAIN, &[&bytes[..66]]);
        bytes[66..].copy_from_slice(&tag);
        bytes
    }

    pub fn decode(
        bytes: &[u8],
        key: &NetworkKey,
        expected_vm_id: Uuid,
        expected_generation: u64,
    ) -> Result<Self, NetworkError> {
        validate_identity(expected_vm_id, expected_generation)?;
        if bytes.len() != NETWORK_HOST_HELLO_LEN {
            return Err(NetworkError::InvalidLength);
        }
        if &bytes[..8] != HOST_HELLO_MAGIC {
            return Err(NetworkError::InvalidMagic);
        }
        verify_authentication_tag(key, HOST_HELLO_DOMAIN, &[&bytes[..66]], &bytes[66..])?;
        let vm_id = Uuid::from_slice(&bytes[8..24]).map_err(|_| NetworkError::InvalidIdentity)?;
        let generation = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .expect("fixed network hello generation"),
        );
        let nonce = bytes[32..64].try_into().expect("fixed network hello nonce");
        let packet_bound = PacketBound::from_le_bytes(
            bytes[64..66]
                .try_into()
                .expect("fixed network hello packet bound"),
        )?;
        if vm_id != expected_vm_id || generation != expected_generation {
            return Err(NetworkError::InvalidIdentity);
        }
        Self::new(vm_id, generation, nonce, packet_bound)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkGuestAck {
    pub nonce: [u8; NONCE_LEN],
    /// The bound the guest accepted: the host's, echoed back.
    pub packet_bound: PacketBound,
}

impl NetworkGuestAck {
    pub fn new(nonce: [u8; NONCE_LEN], packet_bound: PacketBound) -> Result<Self, NetworkError> {
        validate_nonce(&nonce)?;
        Ok(Self {
            nonce,
            packet_bound,
        })
    }

    pub fn encode(&self, key: &NetworkKey) -> [u8; NETWORK_GUEST_ACK_LEN] {
        let mut bytes = [0_u8; NETWORK_GUEST_ACK_LEN];
        bytes[..8].copy_from_slice(GUEST_ACK_MAGIC);
        bytes[8..40].copy_from_slice(&self.nonce);
        bytes[40..42].copy_from_slice(&self.packet_bound.to_le_bytes());
        let tag = authentication_tag(key, GUEST_ACK_DOMAIN, &[&bytes[..42]]);
        bytes[42..].copy_from_slice(&tag);
        bytes
    }

    /// Authenticate an acknowledgement of the hello that sent
    /// `expected_nonce` and `expected_bound`. A guest that accepted any other
    /// bound fails the handshake.
    pub fn decode(
        bytes: &[u8],
        key: &NetworkKey,
        expected_nonce: &[u8; NONCE_LEN],
        expected_bound: PacketBound,
    ) -> Result<Self, NetworkError> {
        validate_nonce(expected_nonce)?;
        if bytes.len() != NETWORK_GUEST_ACK_LEN {
            return Err(NetworkError::InvalidLength);
        }
        if &bytes[..8] != GUEST_ACK_MAGIC {
            return Err(NetworkError::InvalidMagic);
        }
        verify_authentication_tag(key, GUEST_ACK_DOMAIN, &[&bytes[..42]], &bytes[42..])?;
        let nonce = bytes[8..40]
            .try_into()
            .expect("fixed network acknowledgement nonce");
        if &nonce != expected_nonce {
            return Err(NetworkError::InvalidIdentity);
        }
        let packet_bound = PacketBound::from_le_bytes(
            bytes[40..42]
                .try_into()
                .expect("fixed network acknowledgement packet bound"),
        )?;
        if packet_bound != expected_bound {
            return Err(NetworkError::InvalidPacketBound);
        }
        Self::new(nonce, packet_bound)
    }
}

/// Host proof that the authenticated worker has installed its fail-closed
/// packet engine. Guest PID 1 does not launch the workspace before this
/// message arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkHostReady {
    pub nonce: [u8; NONCE_LEN],
}

impl NetworkHostReady {
    pub fn new(nonce: [u8; NONCE_LEN]) -> Result<Self, NetworkError> {
        validate_nonce(&nonce)?;
        Ok(Self { nonce })
    }

    pub fn encode(&self, key: &NetworkKey) -> [u8; NETWORK_HOST_READY_LEN] {
        let mut bytes = [0_u8; NETWORK_HOST_READY_LEN];
        bytes[..8].copy_from_slice(HOST_READY_MAGIC);
        bytes[8..40].copy_from_slice(&self.nonce);
        let tag = authentication_tag(key, HOST_READY_DOMAIN, &[&bytes[..40]]);
        bytes[40..].copy_from_slice(&tag);
        bytes
    }

    pub fn decode(
        bytes: &[u8],
        key: &NetworkKey,
        expected_nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, NetworkError> {
        validate_nonce(expected_nonce)?;
        if bytes.len() != NETWORK_HOST_READY_LEN {
            return Err(NetworkError::InvalidLength);
        }
        if &bytes[..8] != HOST_READY_MAGIC {
            return Err(NetworkError::InvalidMagic);
        }
        verify_authentication_tag(key, HOST_READY_DOMAIN, &[&bytes[..40]], &bytes[40..])?;
        let nonce = bytes[8..40]
            .try_into()
            .expect("fixed network host-ready nonce");
        if &nonce != expected_nonce {
            return Err(NetworkError::InvalidIdentity);
        }
        Self::new(nonce)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkDirection {
    GuestToHost = 1,
    HostToGuest = 2,
}

/// The guest's egress self-check, which a hosted guest sends once as its
/// first frame after the host's ready (#4000 P6): both bypass probes must
/// fail, or the sandbox is not enforcing its lockdown. A pass admits nothing
/// by itself; it only reports what the guest saw. That it comes first and
/// only once is for the hosted host's reader to enforce, because a local VM's
/// guest never sends one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfCheck {
    Passed,
    Failed(SelfCheckFailure),
}

/// Which bypass probe succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfCheckFailure {
    /// A direct TCP dial over the Pod's own interface connected.
    DirectDial,
    /// A DNS query straight to the cluster's resolver was answered.
    Dns,
}

impl SelfCheck {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Passed => vec![CONTROL_SELF_CHECK, SELF_CHECK_PASSED],
            Self::Failed(SelfCheckFailure::DirectDial) => {
                vec![CONTROL_SELF_CHECK, SELF_CHECK_FAILED, 1]
            }
            Self::Failed(SelfCheckFailure::Dns) => vec![CONTROL_SELF_CHECK, SELF_CHECK_FAILED, 2],
        }
    }

    fn decode(body: &[u8]) -> Result<Self, NetworkError> {
        match body {
            [SELF_CHECK_PASSED] => Ok(Self::Passed),
            [SELF_CHECK_FAILED, 1] => Ok(Self::Failed(SelfCheckFailure::DirectDial)),
            [SELF_CHECK_FAILED, 2] => Ok(Self::Failed(SelfCheckFailure::Dns)),
            _ => Err(NetworkError::InvalidControl),
        }
    }
}

/// Whether the guest's agents trust an egress CA this session (#3999,
/// #4001). The host sends it as its first frame of every session, so the
/// guest knows before its workload's first TLS connection; a local VM's host
/// always sends [`Self::None`], because a local VM's CA rides in its seed.
#[derive(Clone, PartialEq, Eq)]
pub enum EgressTrust {
    None,
    /// The CA certificate's DER, as yet unparsed.
    Ca(Vec<u8>),
}

impl EgressTrust {
    fn encode(&self) -> Result<Vec<u8>, NetworkError> {
        let der = match self {
            Self::None => &[][..],
            Self::Ca(der) if !der.is_empty() && der.len() <= MAX_EGRESS_TRUST_BYTES => der,
            Self::Ca(_) => return Err(NetworkError::InvalidControl),
        };
        Ok([&[CONTROL_EGRESS_TRUST][..], der].concat())
    }

    fn decode(body: &[u8]) -> Result<Self, NetworkError> {
        match body {
            [] => Ok(Self::None),
            der if der.len() <= MAX_EGRESS_TRUST_BYTES => Ok(Self::Ca(der.to_vec())),
            _ => Err(NetworkError::InvalidControl),
        }
    }
}

impl std::fmt::Debug for EgressTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => formatter.write_str("EgressTrust::None"),
            Self::Ca(der) => write!(formatter, "EgressTrust::Ca({} bytes)", der.len()),
        }
    }
}

/// One authenticated frame's content.
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkFrame {
    Packet(Vec<u8>),
    SelfCheck(SelfCheck),
    EgressTrust(EgressTrust),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRole {
    Guest,
    Host,
}

/// Stateful authenticated raw-packet codec for one connected worker session.
///
/// The stream is ordered, and each direction must begin at sequence one and
/// increase exactly once per accepted frame. The session key is zeroized on
/// drop and this type is deliberately neither `Clone` nor `Debug`.
pub struct NetworkSession {
    key: [u8; TAG_LEN],
    outbound: NetworkDirection,
    inbound: NetworkDirection,
    next_outbound_sequence: u64,
    next_inbound_sequence: u64,
    packet_bound: PacketBound,
}

impl NetworkSession {
    pub fn new(
        key: &NetworkKey,
        nonce: &[u8; NONCE_LEN],
        role: NetworkRole,
        packet_bound: PacketBound,
    ) -> Result<Self, NetworkError> {
        validate_nonce(nonce)?;
        let session_key = authentication_tag(key, SESSION_DOMAIN, &[nonce]);
        let (outbound, inbound) = match role {
            NetworkRole::Guest => (NetworkDirection::GuestToHost, NetworkDirection::HostToGuest),
            NetworkRole::Host => (NetworkDirection::HostToGuest, NetworkDirection::GuestToHost),
        };
        Ok(Self {
            key: session_key,
            outbound,
            inbound,
            next_outbound_sequence: 1,
            next_inbound_sequence: 1,
            packet_bound,
        })
    }

    /// The bound both sides agreed for this session's packets.
    pub fn packet_bound(&self) -> PacketBound {
        self.packet_bound
    }

    /// The complete frame length one header declares, within this
    /// session's bound; see [`encoded_network_frame_len`].
    pub fn encoded_frame_len(&self, header: &[u8]) -> Result<usize, NetworkError> {
        encoded_network_frame_len(header, self.packet_bound)
    }

    pub fn encode_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if self.awaits_egress_trust(self.outbound, self.next_outbound_sequence) {
            return Err(NetworkError::InvalidControl);
        }
        self.encode_frame(FRAME_KIND_PACKET, packet)
    }

    /// The self-check result as a control frame, under the same MAC and
    /// sequence as the packets. Only the guest sends one.
    pub fn encode_self_check(&mut self, result: SelfCheck) -> Result<Vec<u8>, NetworkError> {
        if self.outbound != NetworkDirection::GuestToHost {
            return Err(NetworkError::InvalidControl);
        }
        self.encode_frame(FRAME_KIND_CONTROL, &result.encode())
    }

    /// The host's first frame: whether the guest trusts an egress CA. It is
    /// the host's frame 1 and no other.
    pub fn encode_egress_trust(&mut self, trust: &EgressTrust) -> Result<Vec<u8>, NetworkError> {
        if !self.awaits_egress_trust(self.outbound, self.next_outbound_sequence) {
            return Err(NetworkError::InvalidControl);
        }
        self.encode_frame(FRAME_KIND_CONTROL, &trust.encode()?)
    }

    /// The host's frame 1 is its egress trust, so neither side may put a
    /// packet there.
    fn awaits_egress_trust(&self, direction: NetworkDirection, sequence: u64) -> bool {
        direction == NetworkDirection::HostToGuest && sequence == 1
    }

    /// Every frame, of either kind, fits the session's bound: the peer's
    /// reader refuses a longer one before reading its body.
    fn encode_frame(&mut self, kind: u8, packet: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if packet.is_empty() || packet.len() > self.packet_bound.bytes() {
            return Err(NetworkError::InvalidPacketLength);
        }
        let packet_len =
            u16::try_from(packet.len()).map_err(|_| NetworkError::InvalidPacketLength)?;
        let sequence = self.next_outbound_sequence;
        let mut frame = vec![0_u8; NETWORK_FRAME_HEADER_LEN + packet.len() + TAG_LEN];
        frame[..8].copy_from_slice(FRAME_MAGIC);
        frame[8..16].copy_from_slice(&sequence.to_le_bytes());
        frame[16..18].copy_from_slice(&packet_len.to_le_bytes());
        frame[18] = kind;
        frame[NETWORK_FRAME_HEADER_LEN..NETWORK_FRAME_HEADER_LEN + packet.len()]
            .copy_from_slice(packet);
        let tag = frame_tag(
            &self.key,
            self.outbound,
            &frame[..NETWORK_FRAME_HEADER_LEN],
            packet,
        )?;
        frame[NETWORK_FRAME_HEADER_LEN + packet.len()..].copy_from_slice(&tag);
        self.next_outbound_sequence = sequence
            .checked_add(1)
            .ok_or(NetworkError::SequenceExhausted)?;
        Ok(frame)
    }

    /// Authenticate one packet frame. A control frame, which only a hosted
    /// host reads ([`Self::decode_frame`]), is a protocol error here.
    pub fn decode_packet(&mut self, frame: &[u8]) -> Result<Vec<u8>, NetworkError> {
        match self.decode_frame(frame)? {
            NetworkFrame::Packet(packet) => Ok(packet),
            NetworkFrame::SelfCheck(_) | NetworkFrame::EgressTrust(_) => {
                Err(NetworkError::InvalidControl)
            }
        }
    }

    /// Authenticate one frame of either kind.
    pub fn decode_frame(&mut self, frame: &[u8]) -> Result<NetworkFrame, NetworkError> {
        if frame.len() < NETWORK_FRAME_HEADER_LEN + TAG_LEN {
            return Err(NetworkError::InvalidLength);
        }
        let encoded_len = self.encoded_frame_len(&frame[..NETWORK_FRAME_HEADER_LEN])?;
        if frame.len() != encoded_len {
            return Err(NetworkError::InvalidLength);
        }
        let sequence = u64::from_le_bytes(
            frame[8..16]
                .try_into()
                .expect("fixed network frame sequence"),
        );
        if sequence != self.next_inbound_sequence {
            return Err(NetworkError::InvalidSequence);
        }
        let first_host_frame = self.awaits_egress_trust(self.inbound, sequence);
        let packet_end = frame.len() - TAG_LEN;
        let packet = &frame[NETWORK_FRAME_HEADER_LEN..packet_end];
        verify_frame_tag(
            &self.key,
            self.inbound,
            &frame[..NETWORK_FRAME_HEADER_LEN],
            packet,
            &frame[packet_end..],
        )?;
        self.next_inbound_sequence = sequence
            .checked_add(1)
            .ok_or(NetworkError::SequenceExhausted)?;
        let content = match (frame[18], packet.split_first()) {
            (FRAME_KIND_PACKET, _) => NetworkFrame::Packet(packet.to_vec()),
            (FRAME_KIND_CONTROL, Some((&CONTROL_SELF_CHECK, body)))
                if self.inbound == NetworkDirection::GuestToHost =>
            {
                NetworkFrame::SelfCheck(SelfCheck::decode(body)?)
            }
            (FRAME_KIND_CONTROL, Some((&CONTROL_EGRESS_TRUST, body))) if first_host_frame => {
                NetworkFrame::EgressTrust(EgressTrust::decode(body)?)
            }
            (FRAME_KIND_CONTROL, _) => return Err(NetworkError::InvalidControl),
            _ => return Err(NetworkError::InvalidFraming),
        };
        // The host's frame 1 is its egress trust and nothing else.
        if first_host_frame != matches!(content, NetworkFrame::EgressTrust(_)) {
            return Err(NetworkError::InvalidControl);
        }
        Ok(content)
    }
}

impl Drop for NetworkSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Return the complete authenticated frame length declared by one fixed
/// header. Callers may use this only to bound a stream read; authentication is
/// performed by `NetworkSession::decode_packet` after the complete frame is
/// present.
pub fn encoded_network_frame_len(
    header: &[u8],
    packet_bound: PacketBound,
) -> Result<usize, NetworkError> {
    if header.len() != NETWORK_FRAME_HEADER_LEN {
        return Err(NetworkError::InvalidLength);
    }
    if &header[..8] != FRAME_MAGIC {
        return Err(NetworkError::InvalidMagic);
    }
    if !matches!(header[18], FRAME_KIND_PACKET | FRAME_KIND_CONTROL) || header[19] != 0 {
        return Err(NetworkError::InvalidFraming);
    }
    let packet_len = usize::from(u16::from_le_bytes(
        header[16..18]
            .try_into()
            .expect("fixed network frame packet length"),
    ));
    if packet_len == 0 || packet_len > packet_bound.bytes() {
        return Err(NetworkError::InvalidPacketLength);
    }
    NETWORK_FRAME_HEADER_LEN
        .checked_add(packet_len)
        .and_then(|value| value.checked_add(TAG_LEN))
        .ok_or(NetworkError::InvalidLength)
}

fn validate_identity(vm_id: Uuid, generation: u64) -> Result<(), NetworkError> {
    if vm_id.is_nil() || generation == 0 {
        return Err(NetworkError::InvalidIdentity);
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8; NONCE_LEN]) -> Result<(), NetworkError> {
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(NetworkError::InvalidNonce);
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), NetworkError> {
    if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(NetworkError::InvalidKey);
    }
    Ok(())
}

fn authentication_tag(key: &NetworkKey, domain: &[u8], parts: &[&[u8]]) -> [u8; TAG_LEN] {
    key.with_bytes(|key| hmac_tag(key, domain, parts).expect("SHA-256 accepts every key length"))
}

fn verify_authentication_tag(
    key: &NetworkKey,
    domain: &[u8],
    parts: &[&[u8]],
    tag: &[u8],
) -> Result<(), NetworkError> {
    key.with_bytes(|key| verify_hmac_tag(key, domain, parts, tag))
}

fn frame_tag(
    key: &[u8; TAG_LEN],
    direction: NetworkDirection,
    header: &[u8],
    packet: &[u8],
) -> Result<[u8; TAG_LEN], NetworkError> {
    hmac_tag(key, FRAME_DOMAIN, &[&[direction as u8], header, packet])
}

fn verify_frame_tag(
    key: &[u8; TAG_LEN],
    direction: NetworkDirection,
    header: &[u8],
    packet: &[u8],
    tag: &[u8],
) -> Result<(), NetworkError> {
    verify_hmac_tag(
        key,
        FRAME_DOMAIN,
        &[&[direction as u8], header, packet],
        tag,
    )
}

fn hmac_tag(key: &[u8], domain: &[u8], parts: &[&[u8]]) -> Result<[u8; TAG_LEN], NetworkError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| NetworkError::InvalidKey)?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn verify_hmac_tag(
    key: &[u8],
    domain: &[u8],
    parts: &[&[u8]],
    tag: &[u8],
) -> Result<(), NetworkError> {
    if tag.len() != TAG_LEN {
        return Err(NetworkError::AuthenticationFailed);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| NetworkError::InvalidKey)?;
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(tag)
        .map_err(|_| NetworkError::AuthenticationFailed)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("guest network message length is invalid")]
    InvalidLength,
    #[error("guest network message magic is invalid")]
    InvalidMagic,
    #[error("guest network message framing is invalid")]
    InvalidFraming,
    #[error("guest network identity is invalid")]
    InvalidIdentity,
    #[error("guest network nonce is invalid")]
    InvalidNonce,
    #[error("guest network derived key input is invalid")]
    InvalidKey,
    #[error("guest network authentication failed")]
    AuthenticationFailed,
    #[error("guest network packet length is invalid")]
    InvalidPacketLength,
    #[error("guest network frame sequence is invalid")]
    InvalidSequence,
    #[error("guest network frame sequence is exhausted")]
    SequenceExhausted,
    #[error("guest network packet bound is invalid or was not accepted")]
    InvalidPacketBound,
    #[error("guest network control message is invalid")]
    InvalidControl,
}

#[cfg(test)]
mod tests;
