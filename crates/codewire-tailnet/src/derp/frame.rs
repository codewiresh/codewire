//! DERP wire framing.
//!
//! Every DERP message is `frameType[1] || length[4 BE] || payload[length]`.
//! This is `tailscale.com/derp`'s `WriteFrameHeader` / `ReadFrameHeader`.
//! Frame type numbers and the magic preamble are copied verbatim from
//! `derp.go` (tailscale.com v1.96.1) so the bytes match exactly.
//!
//! We model the frame *types* as an enum and provide header
//! encode/decode plus per-frame payload builders. Payloads that carry
//! keys/packets are deliberately thin (length-prefixed byte blobs) so a
//! consumer can slice without copying; the higher-level [`super::client`]
//! turns them into typed messages.

use super::Error;

/// DERP magic preamble sent in the `ServerKey` frame: `"DERP🔑"`,
/// the 8 bytes `0x44 45 52 50 f0 9f 94 91`.
pub const MAGIC: &[u8] = b"DERP\xf0\x9f\x94\x91";

/// Length of a frame header: 1-byte type + 4-byte big-endian length.
pub const FRAME_HEADER_LEN: usize = 1 + 4;

/// The DERP protocol version we advertise in `ClientInfo`.
///
/// v2: received packets carry the source key at the front of
/// `RecvPacket` (see `derp.go` `ProtocolVersion`).
pub const PROTOCOL_VERSION: i32 = 2;

/// Max packet relayed over DERP (64 KiB), from `derp.MaxPacketSize`.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// One-byte frame type. Values are the wire numbers from `derp.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    ServerKey = 0x01,
    ClientInfo = 0x02,
    ServerInfo = 0x03,
    SendPacket = 0x04,
    RecvPacket = 0x05,
    KeepAlive = 0x06,
    NotePreferred = 0x07,
    PeerGone = 0x08,
    PeerPresent = 0x09,
    ForwardPacket = 0x0a,
    WatchConns = 0x10,
    ClosePeer = 0x11,
    Ping = 0x12,
    Pong = 0x13,
    Health = 0x14,
    Restarting = 0x15,
    /// Any frame type we don't model explicitly. We keep the raw byte so
    /// the reader can skip the payload and a consumer can still inspect it.
    Unknown(u8),
}

impl FrameType {
    pub fn from_u8(b: u8) -> FrameType {
        match b {
            0x01 => FrameType::ServerKey,
            0x02 => FrameType::ClientInfo,
            0x03 => FrameType::ServerInfo,
            0x04 => FrameType::SendPacket,
            0x05 => FrameType::RecvPacket,
            0x06 => FrameType::KeepAlive,
            0x07 => FrameType::NotePreferred,
            0x08 => FrameType::PeerGone,
            0x09 => FrameType::PeerPresent,
            0x0a => FrameType::ForwardPacket,
            0x10 => FrameType::WatchConns,
            0x11 => FrameType::ClosePeer,
            0x12 => FrameType::Ping,
            0x13 => FrameType::Pong,
            0x14 => FrameType::Health,
            0x15 => FrameType::Restarting,
            other => FrameType::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            FrameType::ServerKey => 0x01,
            FrameType::ClientInfo => 0x02,
            FrameType::ServerInfo => 0x03,
            FrameType::SendPacket => 0x04,
            FrameType::RecvPacket => 0x05,
            FrameType::KeepAlive => 0x06,
            FrameType::NotePreferred => 0x07,
            FrameType::PeerGone => 0x08,
            FrameType::PeerPresent => 0x09,
            FrameType::ForwardPacket => 0x0a,
            FrameType::WatchConns => 0x10,
            FrameType::ClosePeer => 0x11,
            FrameType::Ping => 0x12,
            FrameType::Pong => 0x13,
            FrameType::Health => 0x14,
            FrameType::Restarting => 0x15,
            FrameType::Unknown(b) => b,
        }
    }
}

/// Encode a 5-byte frame header (type + big-endian length) into `out`.
pub fn encode_header(t: FrameType, len: u32, out: &mut Vec<u8>) {
    out.push(t.to_u8());
    out.extend_from_slice(&len.to_be_bytes());
}

/// Encode a full frame (header + payload) into a freshly allocated buffer.
pub fn encode_frame(t: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    encode_header(t, payload.len() as u32, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Decode a frame header from the first 5 bytes of `buf`.
pub fn decode_header(buf: &[u8]) -> Result<(FrameType, u32), Error> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(Error::Protocol("short frame header"));
    }
    let t = FrameType::from_u8(buf[0]);
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Ok((t, len))
}
