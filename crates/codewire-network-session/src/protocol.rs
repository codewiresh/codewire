use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const GUEST_NETWORK_VSOCK_PORT: u32 = 7_775;
/// Guest PID 1 keeps the fail-closed network agent alive long enough for the
/// host to admit both isolated product processes and authenticate the session.
pub const NETWORK_HOST_READY_TIMEOUT_SECONDS: u64 = 60;
pub const NETWORK_HOST_HELLO_LEN: usize = 96;
pub const NETWORK_GUEST_ACK_LEN: usize = 72;
pub const NETWORK_HOST_READY_LEN: usize = 72;
pub const NETWORK_FRAME_HEADER_LEN: usize = 20;
pub const NETWORK_MAX_PACKET_BYTES: usize = 2_048;
pub const NETWORK_KEY_LEN: usize = 32;

const TAG_LEN: usize = NETWORK_KEY_LEN;
const NONCE_LEN: usize = 32;
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;
const HOST_HELLO_MAGIC: &[u8; 8] = b"CWNETH1\0";
const GUEST_ACK_MAGIC: &[u8; 8] = b"CWNETA1\0";
const HOST_READY_MAGIC: &[u8; 8] = b"CWNETR1\0";
const FRAME_MAGIC: &[u8; 8] = b"CWNETF1\0";
const KEY_DOMAIN: &[u8] = b"codewire-network-key-v1\0";
const HOST_HELLO_DOMAIN: &[u8] = b"codewire-network-host-hello-v1\0";
const GUEST_ACK_DOMAIN: &[u8] = b"codewire-network-guest-ack-v1\0";
const HOST_READY_DOMAIN: &[u8] = b"codewire-network-host-ready-v1\0";
const SESSION_DOMAIN: &[u8] = b"codewire-network-session-v1\0";
const FRAME_DOMAIN: &[u8] = b"codewire-network-frame-v1\0";

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
}

impl NetworkHostHello {
    pub fn new(vm_id: Uuid, generation: u64, nonce: [u8; NONCE_LEN]) -> Result<Self, NetworkError> {
        validate_identity(vm_id, generation)?;
        validate_nonce(&nonce)?;
        Ok(Self {
            vm_id,
            generation,
            nonce,
        })
    }

    pub fn encode(&self, key: &NetworkKey) -> [u8; NETWORK_HOST_HELLO_LEN] {
        let mut bytes = [0_u8; NETWORK_HOST_HELLO_LEN];
        bytes[..8].copy_from_slice(HOST_HELLO_MAGIC);
        bytes[8..24].copy_from_slice(self.vm_id.as_bytes());
        bytes[24..32].copy_from_slice(&self.generation.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.nonce);
        let tag = authentication_tag(key, HOST_HELLO_DOMAIN, &[&bytes[..64]]);
        bytes[64..].copy_from_slice(&tag);
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
        verify_authentication_tag(key, HOST_HELLO_DOMAIN, &[&bytes[..64]], &bytes[64..])?;
        let vm_id = Uuid::from_slice(&bytes[8..24]).map_err(|_| NetworkError::InvalidIdentity)?;
        let generation = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .expect("fixed network hello generation"),
        );
        let nonce = bytes[32..64].try_into().expect("fixed network hello nonce");
        if vm_id != expected_vm_id || generation != expected_generation {
            return Err(NetworkError::InvalidIdentity);
        }
        Self::new(vm_id, generation, nonce)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkGuestAck {
    pub nonce: [u8; NONCE_LEN],
}

impl NetworkGuestAck {
    pub fn new(nonce: [u8; NONCE_LEN]) -> Result<Self, NetworkError> {
        validate_nonce(&nonce)?;
        Ok(Self { nonce })
    }

    pub fn encode(&self, key: &NetworkKey) -> [u8; NETWORK_GUEST_ACK_LEN] {
        let mut bytes = [0_u8; NETWORK_GUEST_ACK_LEN];
        bytes[..8].copy_from_slice(GUEST_ACK_MAGIC);
        bytes[8..40].copy_from_slice(&self.nonce);
        let tag = authentication_tag(key, GUEST_ACK_DOMAIN, &[&bytes[..40]]);
        bytes[40..].copy_from_slice(&tag);
        bytes
    }

    pub fn decode(
        bytes: &[u8],
        key: &NetworkKey,
        expected_nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, NetworkError> {
        validate_nonce(expected_nonce)?;
        if bytes.len() != NETWORK_GUEST_ACK_LEN {
            return Err(NetworkError::InvalidLength);
        }
        if &bytes[..8] != GUEST_ACK_MAGIC {
            return Err(NetworkError::InvalidMagic);
        }
        verify_authentication_tag(key, GUEST_ACK_DOMAIN, &[&bytes[..40]], &bytes[40..])?;
        let nonce = bytes[8..40]
            .try_into()
            .expect("fixed network acknowledgement nonce");
        if &nonce != expected_nonce {
            return Err(NetworkError::InvalidIdentity);
        }
        Self::new(nonce)
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
}

impl NetworkSession {
    pub fn new(
        key: &NetworkKey,
        nonce: &[u8; NONCE_LEN],
        role: NetworkRole,
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
        })
    }

    pub fn encode_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if packet.is_empty() || packet.len() > NETWORK_MAX_PACKET_BYTES {
            return Err(NetworkError::InvalidPacketLength);
        }
        let packet_len =
            u16::try_from(packet.len()).map_err(|_| NetworkError::InvalidPacketLength)?;
        let sequence = self.next_outbound_sequence;
        let mut frame = vec![0_u8; NETWORK_FRAME_HEADER_LEN + packet.len() + TAG_LEN];
        frame[..8].copy_from_slice(FRAME_MAGIC);
        frame[8..16].copy_from_slice(&sequence.to_le_bytes());
        frame[16..18].copy_from_slice(&packet_len.to_le_bytes());
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

    pub fn decode_packet(&mut self, frame: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if frame.len() < NETWORK_FRAME_HEADER_LEN + TAG_LEN {
            return Err(NetworkError::InvalidLength);
        }
        let encoded_len = encoded_network_frame_len(&frame[..NETWORK_FRAME_HEADER_LEN])?;
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
        Ok(packet.to_vec())
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
pub fn encoded_network_frame_len(header: &[u8]) -> Result<usize, NetworkError> {
    if header.len() != NETWORK_FRAME_HEADER_LEN {
        return Err(NetworkError::InvalidLength);
    }
    if &header[..8] != FRAME_MAGIC {
        return Err(NetworkError::InvalidMagic);
    }
    if header[18..20] != [0, 0] {
        return Err(NetworkError::InvalidFraming);
    }
    let packet_len = usize::from(u16::from_le_bytes(
        header[16..18]
            .try_into()
            .expect("fixed network frame packet length"),
    ));
    if packet_len == 0 || packet_len > NETWORK_MAX_PACKET_BYTES {
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
}

#[cfg(test)]
mod tests;
