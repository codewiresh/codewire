//! The supervisor's control socket with a Pod's front door, `CWHF1`: one
//! connected Unix stream at [`FRONT_DOOR_CONTROL_FD`], framed as the hand-off
//! is (`codewire_egress_front_door_bridge::control`). In order:
//!
//! 1. supervisor: [`encode_bindings`], the environment, its generation and
//!    the exact hosts;
//! 2. front door: [`PREPARED`]. It waits, not yet confined, so the supervisor
//!    can compare its executable with its own image;
//! 3. supervisor: [`CONFINE`];
//! 4. front door, confined and holding its new key: [`READY`] followed by the
//!    key's SubjectPublicKeyInfo in DER, which the supervisor takes only as
//!    a P-256 key ([`is_p256_spki`]). Nothing else ever leaves it;
//! 5. supervisor, once the Pod's broker is enforcing: [`HANDOFF`] with
//!    exactly one descriptor, the front door's end of the broker's hand-off
//!    socket. The front door reads the broker's role tag on it, says
//!    [`SERVING`] and serves;
//! 6. supervisor, at any time after: [`encode_leaves`], DER certificates the
//!    front door installs all or nothing. It answers [`INSTALLED`], or
//!    [`refused_message`] with a fixed code and keeps the leaves it had.
//!
//! A failure before serving is [`failed_message`] with a fixed stage. Any
//! other frame, or the socket closing, ends the front door.
//!
//! A second socket, at [`FRONT_DOOR_SESSIONS_FD`], carries only credential
//! sessions, so their answers never meet a leaves install's. Once serving,
//! the supervisor sends [`CREDENTIALS`] with exactly one descriptor, its end
//! of a socket pair whose other end the supervisor has already tagged
//! [`FRONT_DOOR_SESSION_ROLE_TAG`](codewire_egress_front_door_bridge::FRONT_DOOR_SESSION_ROLE_TAG).
//! The front door answers [`SESSION_SERVING`], or [`session_dropped_message`]
//! with a fixed code. Any other frame, or this socket closing, ends it too.

use std::os::fd::RawFd;

use codewire_egress_front_door_bridge::INTERCEPT_PORT;
use codewire_egress_policy::intercept::InterceptSet;
use codewire_egress_worker::broker_control::{
    ControlFrame, encode_intercept_frame, read_control_frame,
};
use uuid::Uuid;

/// The control socket's descriptor in the front-door process.
pub const FRONT_DOOR_CONTROL_FD: RawFd = 4;
/// The sessions socket's descriptor in the front-door process.
pub const FRONT_DOOR_SESSIONS_FD: RawFd = 5;
/// The largest frame either side sends: the framing's own bound.
pub const MAX_CONTROL_MESSAGE: usize = codewire_egress_policy::handoff::FRAME_MAX_LEN;

pub const BINDINGS: &[u8] = b"CWHF1 bindings\n";
pub const PREPARED: &[u8] = b"CWHF1 prepared\n";
pub const CONFINE: &[u8] = b"CWHF1 confine\n";
pub const READY: &[u8] = b"CWHF1 ready\n";
pub const HANDOFF: &[u8] = b"CWHF1 handoff\n";
pub const SERVING: &[u8] = b"CWHF1 serving\n";
pub const LEAVES: &[u8] = b"CWHF1 leaves\n";
pub const INSTALLED: &[u8] = b"CWHF1 installed\n";
const REFUSED_PREFIX: &[u8] = b"CWHF1 refused ";
pub const CREDENTIALS: &[u8] = b"CWHF1 credentials\n";
pub const SESSION_SERVING: &[u8] = b"CWHF1 session serving\n";
const SESSION_DROPPED_PREFIX: &[u8] = b"CWHF1 session dropped ";
const FAILED_PREFIX: &[u8] = b"CWHF1 failed ";

/// The most leaves one frame carries: what one install takes.
pub const MAX_LEAVES: usize = 32;

/// What a front door serves, as the supervisor sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bindings {
    pub environment_id: Uuid,
    pub generation: u64,
    pub intercepts: InterceptSet,
}

/// [`BINDINGS`], the environment id as 36 characters, the generation in
/// eight big-endian bytes, then the broker's own interception frame.
pub fn encode_bindings(bindings: &Bindings) -> std::io::Result<Vec<u8>> {
    let mut frame = BINDINGS.to_vec();
    frame.extend_from_slice(bindings.environment_id.hyphenated().to_string().as_bytes());
    frame.extend_from_slice(&bindings.generation.to_be_bytes());
    frame.extend_from_slice(&encode_intercept_frame(&bindings.intercepts)?);
    Ok(frame)
}

/// The bindings `frame` carries: a canonical environment, and at least one
/// binding, each on 443. Anything else, trailing bytes included, is none.
pub async fn decode_bindings(frame: &[u8]) -> Option<Bindings> {
    let rest = frame.strip_prefix(BINDINGS)?;
    let (environment_id, rest) = rest.split_at_checked(36)?;
    let (generation, mut rest) = rest.split_at_checked(8)?;
    let environment_id = std::str::from_utf8(environment_id).ok()?;
    let environment_id = Uuid::parse_str(environment_id)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == environment_id)?;
    let generation = u64::from_be_bytes(generation.try_into().ok()?);
    let Ok(ControlFrame::ReplaceIntercepts(intercepts)) = read_control_frame(&mut rest).await
    else {
        return None;
    };
    let served = intercepts
        .bindings()
        .iter()
        .all(|binding| binding.port() == INTERCEPT_PORT);
    (rest.is_empty() && !intercepts.is_empty() && served).then_some(Bindings {
        environment_id,
        generation,
        intercepts,
    })
}

/// [`READY`] and the key's SubjectPublicKeyInfo.
pub fn ready_message(spki: &[u8]) -> Vec<u8> {
    [READY, spki].concat()
}

/// Every P-256 public key's DER SubjectPublicKeyInfo up to its point:
/// id-ecPublicKey, prime256v1, and a 66-byte BIT STRING.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// An uncompressed P-256 point: its tag and two 32-byte coordinates.
const P256_POINT_LEN: usize = 65;

/// Whether `spki` is a P-256 public key's DER SubjectPublicKeyInfo with an
/// uncompressed point, the only key the signer issues leaves for. The
/// supervisor relays nothing else, so a wrong key fails at the node and not
/// at orchestration (#4001).
pub fn is_p256_spki(spki: &[u8]) -> bool {
    spki.len() == P256_SPKI_PREFIX.len() + P256_POINT_LEN
        && spki.starts_with(&P256_SPKI_PREFIX)
        && spki[P256_SPKI_PREFIX.len()] == 0x04
}

/// [`LEAVES`], the count in one byte, then each certificate's length in two
/// big-endian bytes and its DER. None past [`MAX_LEAVES`] or the frame's
/// bound.
pub fn encode_leaves<C: AsRef<[u8]>>(leaves: &[C]) -> Option<Vec<u8>> {
    if leaves.len() > MAX_LEAVES {
        return None;
    }
    let mut frame = LEAVES.to_vec();
    frame.push(u8::try_from(leaves.len()).ok()?);
    for leaf in leaves {
        let leaf = leaf.as_ref();
        frame.extend_from_slice(&u16::try_from(leaf.len()).ok()?.to_be_bytes());
        frame.extend_from_slice(leaf);
    }
    (frame.len() <= MAX_CONTROL_MESSAGE).then_some(frame)
}

/// The certificates a leaves frame carries, each borrowed from it; none for
/// anything that is not exactly one.
pub fn decode_leaves(frame: &[u8]) -> Option<Vec<&[u8]>> {
    let (&count, mut rest) = frame.strip_prefix(LEAVES)?.split_first()?;
    let count = usize::from(count);
    if count > MAX_LEAVES {
        return None;
    }
    let mut leaves = Vec::with_capacity(count);
    for _ in 0..count {
        let (length, after) = rest.split_at_checked(2)?;
        let length = usize::from(u16::from_be_bytes(length.try_into().ok()?));
        let (leaf, after) = after.split_at_checked(length)?;
        leaves.push(leaf);
        rest = after;
    }
    rest.is_empty().then_some(leaves)
}

/// Why a front door kept its previous leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafRefusal {
    /// A leaf it cannot read, for another key, or naming no DNS host.
    Invalid,
    Expired,
}

impl LeafRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_leaf",
            Self::Expired => "expired",
        }
    }
}

pub fn refused_message(why: LeafRefusal) -> Vec<u8> {
    [REFUSED_PREFIX, why.code().as_bytes(), b"\n"].concat()
}

pub fn decode_refused(message: &[u8]) -> Option<LeafRefusal> {
    let code = message.strip_prefix(REFUSED_PREFIX)?.strip_suffix(b"\n")?;
    [LeafRefusal::Invalid, LeafRefusal::Expired]
        .into_iter()
        .find(|why| why.code().as_bytes() == code)
}

/// Why a front door dropped a credential session's socket, and closed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRefusal {
    /// Not a connected Unix stream socket.
    Kind,
    /// No session role tag within its time, or another byte.
    Tag,
    /// The last session handed over isn't served yet.
    Busy,
}

impl SessionRefusal {
    const ALL: [Self; 3] = [Self::Kind, Self::Tag, Self::Busy];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Tag => "tag",
            Self::Busy => "busy",
        }
    }
}

pub fn session_dropped_message(why: SessionRefusal) -> Vec<u8> {
    [SESSION_DROPPED_PREFIX, why.code().as_bytes(), b"\n"].concat()
}

pub fn decode_session_dropped(message: &[u8]) -> Option<SessionRefusal> {
    let code = message
        .strip_prefix(SESSION_DROPPED_PREFIX)?
        .strip_suffix(b"\n")?;
    SessionRefusal::ALL
        .into_iter()
        .find(|why| why.code().as_bytes() == code)
}

/// Where a front door's start failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontDoorStage {
    Control,
    Bindings,
    /// No confinement admission came, or something else did.
    Admission,
    Confinement,
    Start,
    Handoff,
    /// The sessions socket is missing or not a connected Unix stream.
    Sessions,
}

impl FrontDoorStage {
    const ALL: [Self; 7] = [
        Self::Control,
        Self::Bindings,
        Self::Admission,
        Self::Confinement,
        Self::Start,
        Self::Handoff,
        Self::Sessions,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Bindings => "bindings",
            Self::Admission => "admission",
            Self::Confinement => "confinement",
            Self::Start => "start",
            Self::Handoff => "handoff",
            Self::Sessions => "sessions",
        }
    }
}

pub fn failed_message(stage: FrontDoorStage) -> Vec<u8> {
    [FAILED_PREFIX, stage.code().as_bytes(), b"\n"].concat()
}

pub fn decode_failed(message: &[u8]) -> Option<FrontDoorStage> {
    let code = message.strip_prefix(FAILED_PREFIX)?.strip_suffix(b"\n")?;
    FrontDoorStage::ALL
        .into_iter()
        .find(|stage| stage.code().as_bytes() == code)
}

#[cfg(test)]
mod tests {
    use codewire_egress_policy::intercept::InterceptBinding;

    use super::*;

    fn bindings() -> Bindings {
        Bindings {
            environment_id: Uuid::from_u128(0x6f1c_2a0e_8b4d_4e2a_9c3f_1d2e_3f4a_5b6c),
            generation: 9,
            intercepts: InterceptSet::new([
                InterceptBinding::new("api.openai.com", 443).unwrap(),
                InterceptBinding::new("chatgpt.com", 443).unwrap(),
            ])
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn bindings_are_read_exactly_as_they_were_sent() {
        let sent = bindings();
        let frame = encode_bindings(&sent).unwrap();
        assert_eq!(decode_bindings(&frame).await, Some(sent.clone()));

        let mut trailing = frame.clone();
        trailing.push(0);
        let mut upper = frame.clone();
        upper[BINDINGS.len()..BINDINGS.len() + 36].make_ascii_uppercase();
        let empty = encode_bindings(&Bindings {
            intercepts: InterceptSet::default(),
            ..sent
        })
        .unwrap();
        for refused in [
            &trailing[..],
            &frame[..frame.len() - 1],
            &upper,
            &empty,
            &frame[1..],
        ] {
            assert_eq!(decode_bindings(refused).await, None);
        }
    }

    #[test]
    fn leaves_are_bounded_and_read_whole() {
        let leaves = [vec![1_u8; 3], vec![], vec![2; 700]];
        let frame = encode_leaves(&leaves).unwrap();
        assert_eq!(
            decode_leaves(&frame).unwrap(),
            leaves.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        assert_eq!(decode_leaves(&frame[..frame.len() - 1]), None);
        assert_eq!(decode_leaves(&[&frame[..], &[0]].concat()), None);
        assert!(encode_leaves(&vec![vec![0_u8]; MAX_LEAVES + 1]).is_none());
        assert!(encode_leaves(&[vec![0_u8; MAX_CONTROL_MESSAGE]]).is_none());
        let mut too_many = LEAVES.to_vec();
        too_many.push(u8::try_from(MAX_LEAVES + 1).unwrap());
        too_many.extend(std::iter::repeat_n(0, 2 * (MAX_LEAVES + 1)));
        assert_eq!(decode_leaves(&too_many), None);
    }

    #[test]
    fn only_an_uncompressed_p256_key_is_taken_as_the_front_doors() {
        let key = codewire_egress_front_door::SignedLeaves::generate().unwrap();
        assert!(is_p256_spki(key.public_key_spki()));
        let spki = key.public_key_spki().to_vec();

        let other = |algorithm| rcgen::KeyPair::generate_for(algorithm).unwrap();
        let p384 = other(&rcgen::PKCS_ECDSA_P384_SHA384).public_key_der();
        let ed25519 = other(&rcgen::PKCS_ED25519).public_key_der();
        let mut compressed = spki.clone();
        compressed[P256_SPKI_PREFIX.len()] = 0x02;
        let mut other_curve = spki.clone();
        other_curve[22] = 0x08;
        for refused in [
            &p384[..],
            &ed25519,
            &compressed,
            &other_curve,
            &spki[..spki.len() - 1],
            &[&spki[..], &[0]].concat(),
            &spki[P256_SPKI_PREFIX.len()..],
            b"",
        ] {
            assert!(!is_p256_spki(refused), "{refused:02x?}");
        }
    }

    #[test]
    fn refusals_and_failures_are_fixed_codes() {
        for why in [LeafRefusal::Invalid, LeafRefusal::Expired] {
            assert_eq!(decode_refused(&refused_message(why)), Some(why));
        }
        for stage in FrontDoorStage::ALL {
            assert_eq!(decode_failed(&failed_message(stage)), Some(stage));
        }
        for why in SessionRefusal::ALL {
            assert_eq!(
                decode_session_dropped(&session_dropped_message(why)),
                Some(why)
            );
        }
        assert_eq!(decode_refused(b"CWHF1 refused other\n"), None);
        assert_eq!(decode_failed(b"CWHF1 failed control"), None);
        assert_eq!(decode_session_dropped(b"CWHF1 session dropped kind"), None);
    }
}
