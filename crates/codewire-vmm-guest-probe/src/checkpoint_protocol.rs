//! The VM checkpoint hook protocol between a local VM's runner and its guest
//! PID 1 (#3046 R4).
//!
//! The runner freezes the guest workload before it pauses the VM to take a VM
//! checkpoint, and thaws it afterwards. A VM restored from a checkpoint
//! resumes with that workload still frozen; before it thaws, the runner sends
//! `Resume`, and the guest reseeds its RNG with host entropy and moves every
//! boot-scoped secret to the restored boot's identity.
//!
//! Each connection is one exchange. The guest sends a fresh challenge, the
//! host sends one request MACed over it, and the guest answers with one reply
//! MACed over it too. The MAC key is derived from a boot's daemon token,
//! environment id and generation, as the network key is: `Freeze` and `Thaw`
//! use the guest's current identity, and `Resume` the identity of the seed
//! the runner wrote for the restored boot, which the guest rereads from its
//! seed disk.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

/// The guest's checkpoint hook listens here, for the host CID only.
pub const GUEST_CHECKPOINT_VSOCK_PORT: u32 = 7_779;
/// The hook protocol this guest speaks; the sealed init carries it in
/// [`crate::GUEST_CHECKPOINT_ABI_MARKER`].
pub const GUEST_CHECKPOINT_ABI: u32 = 1;
pub const CHECKPOINT_CHALLENGE_LEN: usize = 32;
pub const CHECKPOINT_HELLO_LEN: usize = 48;
pub const CHECKPOINT_REQUEST_LEN: usize = 192;
pub const CHECKPOINT_REPLY_LEN: usize = 128;
pub const CHECKPOINT_HOST_ENTROPY_LEN: usize = 64;

const HELLO_MAGIC: &[u8; 8] = b"CWCKH1\0\0";
const REQUEST_MAGIC: &[u8; 8] = b"CWCKQ1\0\0";
const REPLY_MAGIC: &[u8; 8] = b"CWCKR1\0\0";
const KEY_DOMAIN: &[u8] = b"codewire-checkpoint-v1\0";
const REQUEST_DOMAIN: &[u8] = b"codewire-checkpoint-request-v1\0";
const REPLY_DOMAIN: &[u8] = b"codewire-checkpoint-reply-v1\0";
const REQUEST_AUTHENTICATED_LEN: usize = 160;
const REPLY_AUTHENTICATED_LEN: usize = 96;
const TAG_LEN: usize = 32;
const _: () = assert!(
    CHECKPOINT_REQUEST_LEN == REQUEST_AUTHENTICATED_LEN + TAG_LEN
        && CHECKPOINT_REPLY_LEN == REPLY_AUTHENTICATED_LEN + TAG_LEN
);
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;

type HmacSha256 = Hmac<Sha256>;

/// One boot's hook key: `HMAC-SHA256(token, domain ‖ vm_id ‖ generation)`.
#[derive(Clone)]
pub struct CheckpointKey([u8; 32]);

impl CheckpointKey {
    pub fn derive(token: &str, vm_id: Uuid, generation: u64) -> Result<Self, CheckpointError> {
        if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CheckpointError::InvalidToken);
        }
        if vm_id.is_nil() || generation == 0 {
            return Err(CheckpointError::InvalidIdentity);
        }
        let mut mac = HmacSha256::new_from_slice(token.as_bytes())
            .map_err(|_| CheckpointError::InvalidToken)?;
        mac.update(KEY_DOMAIN);
        mac.update(vm_id.as_bytes());
        mac.update(&generation.to_le_bytes());
        Ok(Self(mac.finalize().into_bytes().into()))
    }

    fn mac(&self, domain: &[u8], challenge: &[u8; CHECKPOINT_CHALLENGE_LEN]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(domain);
        mac.update(challenge);
        mac
    }
}

impl Drop for CheckpointKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The guest's first message on a connection: a fresh challenge and the hook
/// protocol it speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointHello {
    pub challenge: [u8; CHECKPOINT_CHALLENGE_LEN],
    pub abi: u32,
}

impl CheckpointHello {
    pub fn encode(self) -> [u8; CHECKPOINT_HELLO_LEN] {
        let mut bytes = [0_u8; CHECKPOINT_HELLO_LEN];
        bytes[..8].copy_from_slice(HELLO_MAGIC);
        bytes[8..40].copy_from_slice(&self.challenge);
        bytes[40..44].copy_from_slice(&self.abi.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() != CHECKPOINT_HELLO_LEN {
            return Err(CheckpointError::InvalidLength);
        }
        if &bytes[..8] != HELLO_MAGIC {
            return Err(CheckpointError::InvalidMagic);
        }
        if bytes[44..].iter().any(|byte| *byte != 0) {
            return Err(CheckpointError::InvalidFraming);
        }
        let challenge: [u8; CHECKPOINT_CHALLENGE_LEN] =
            bytes[8..40].try_into().expect("fixed hello challenge");
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(CheckpointError::InvalidFraming);
        }
        Ok(Self {
            challenge,
            abi: u32::from_le_bytes(bytes[40..44].try_into().expect("fixed hello abi")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CheckpointAction {
    /// Freeze the workload cgroup: the VM is about to pause for a checkpoint.
    Freeze = 1,
    /// Thaw the workload cgroup.
    Thaw = 2,
    /// The VM was restored from a checkpoint: reseed the RNG and move to the
    /// identity in the seed, leaving the workload frozen.
    Resume = 3,
}

impl TryFrom<u16> for CheckpointAction {
    type Error = CheckpointError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Freeze),
            2 => Ok(Self::Thaw),
            3 => Ok(Self::Resume),
            _ => Err(CheckpointError::InvalidAction),
        }
    }
}

/// One host request. `vm_id` and `generation` name the identity whose key
/// MACs it: the guest's current one for `Freeze` and `Thaw`, the restored
/// boot's for `Resume`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRequest {
    pub action: CheckpointAction,
    pub operation_id: Uuid,
    pub vm_id: Uuid,
    pub generation: u64,
    /// Host entropy for `Resume`; zero otherwise.
    pub host_entropy: [u8; CHECKPOINT_HOST_ENTROPY_LEN],
    /// The host's wall clock in nanoseconds since the epoch, for `Resume`.
    pub host_time_ns: u64,
}

impl CheckpointRequest {
    pub fn encode(
        &self,
        key: &CheckpointKey,
        challenge: &[u8; CHECKPOINT_CHALLENGE_LEN],
    ) -> Result<[u8; CHECKPOINT_REQUEST_LEN], CheckpointError> {
        self.validate()?;
        let mut bytes = [0_u8; CHECKPOINT_REQUEST_LEN];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&(self.action as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&GUEST_CHECKPOINT_ABI.to_le_bytes());
        bytes[16..32].copy_from_slice(self.operation_id.as_bytes());
        bytes[32..48].copy_from_slice(self.vm_id.as_bytes());
        bytes[48..56].copy_from_slice(&self.generation.to_le_bytes());
        bytes[56..120].copy_from_slice(&self.host_entropy);
        bytes[120..128].copy_from_slice(&self.host_time_ns.to_le_bytes());
        let mut mac = key.mac(REQUEST_DOMAIN, challenge);
        mac.update(&bytes[..REQUEST_AUTHENTICATED_LEN]);
        bytes[REQUEST_AUTHENTICATED_LEN..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }

    /// The request's identity, read before its MAC can be checked: the
    /// guest needs it to choose the key. Nothing else in it is trusted yet.
    pub fn peek_identity(bytes: &[u8]) -> Result<(CheckpointAction, Uuid, u64), CheckpointError> {
        if bytes.len() != CHECKPOINT_REQUEST_LEN {
            return Err(CheckpointError::InvalidLength);
        }
        if &bytes[..8] != REQUEST_MAGIC {
            return Err(CheckpointError::InvalidMagic);
        }
        let action = CheckpointAction::try_from(u16::from_le_bytes(
            bytes[8..10].try_into().expect("fixed request action"),
        ))?;
        let vm_id = Uuid::from_slice(&bytes[32..48]).expect("fixed request vm id");
        let generation = u64::from_le_bytes(bytes[48..56].try_into().expect("fixed generation"));
        Ok((action, vm_id, generation))
    }

    pub fn decode(
        bytes: &[u8],
        key: &CheckpointKey,
        challenge: &[u8; CHECKPOINT_CHALLENGE_LEN],
    ) -> Result<Self, CheckpointError> {
        let (action, vm_id, generation) = Self::peek_identity(bytes)?;
        let mut mac = key.mac(REQUEST_DOMAIN, challenge);
        mac.update(&bytes[..REQUEST_AUTHENTICATED_LEN]);
        mac.verify_slice(&bytes[REQUEST_AUTHENTICATED_LEN..])
            .map_err(|_| CheckpointError::AuthenticationFailed)?;
        if bytes[10..12].iter().any(|byte| *byte != 0)
            || bytes[128..REQUEST_AUTHENTICATED_LEN]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(CheckpointError::InvalidFraming);
        }
        if u32::from_le_bytes(bytes[12..16].try_into().expect("fixed request abi"))
            != GUEST_CHECKPOINT_ABI
        {
            return Err(CheckpointError::UnsupportedAbi);
        }
        let request = Self {
            action,
            operation_id: Uuid::from_slice(&bytes[16..32]).expect("fixed operation id"),
            vm_id,
            generation,
            host_entropy: bytes[56..120].try_into().expect("fixed host entropy"),
            host_time_ns: u64::from_le_bytes(bytes[120..128].try_into().expect("fixed time")),
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), CheckpointError> {
        if self.operation_id.is_nil() || self.vm_id.is_nil() || self.generation == 0 {
            return Err(CheckpointError::InvalidIdentity);
        }
        let resume = self.action == CheckpointAction::Resume;
        let entropy = self.host_entropy.iter().any(|byte| *byte != 0);
        if resume != entropy || resume != (self.host_time_ns != 0) {
            return Err(CheckpointError::InvalidFraming);
        }
        Ok(())
    }
}

/// How the guest answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CheckpointStatus {
    Done = 0,
    /// The request was well formed but not allowed, such as a `Resume` to an
    /// identity that is not a fork or a newer generation. Nothing changed.
    Refused = 1,
    /// The guest could not do it, such as a freeze that timed out. A failed
    /// `Freeze` has thawed again.
    Failed = 2,
}

impl TryFrom<u16> for CheckpointStatus {
    type Error = CheckpointError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Done),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Failed),
            _ => Err(CheckpointError::InvalidFraming),
        }
    }
}

/// What the guest reports after `Resume`: each is a flag in the reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResumeReport {
    /// Host entropy was mixed in and the kernel CRNG reseeded.
    pub reseeded: bool,
    /// The guest kernel has a VM generation ID driver, which reseeds the CRNG
    /// when the VMM restores the VM, before any vCPU runs.
    pub vmgenid_driver: bool,
    /// The restore is a fork, and Codewire-written sign-ins were removed.
    pub removed_logins: bool,
}

/// The guest's answer, for the request's action and identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointReply {
    pub action: CheckpointAction,
    pub status: CheckpointStatus,
    pub operation_id: Uuid,
    pub vm_id: Uuid,
    pub generation: u64,
    /// The guest-side duration: the freeze for `Freeze`, the whole hook for
    /// `Resume`.
    pub elapsed_us: u64,
    /// For `Resume`: how far the guest's wall clock was from the host's
    /// before any step, in milliseconds (guest minus host).
    pub clock_skew_ms: i64,
    pub resume: ResumeReport,
}

const FLAG_RESEEDED: u32 = 1;
const FLAG_VMGENID_DRIVER: u32 = 2;
const FLAG_REMOVED_LOGINS: u32 = 4;

impl CheckpointReply {
    pub fn encode(
        &self,
        key: &CheckpointKey,
        challenge: &[u8; CHECKPOINT_CHALLENGE_LEN],
    ) -> [u8; CHECKPOINT_REPLY_LEN] {
        let mut bytes = [0_u8; CHECKPOINT_REPLY_LEN];
        bytes[..8].copy_from_slice(REPLY_MAGIC);
        bytes[8..10].copy_from_slice(&(self.action as u16).to_le_bytes());
        bytes[10..12].copy_from_slice(&(self.status as u16).to_le_bytes());
        let flags = (u32::from(self.resume.reseeded) * FLAG_RESEEDED)
            | (u32::from(self.resume.vmgenid_driver) * FLAG_VMGENID_DRIVER)
            | (u32::from(self.resume.removed_logins) * FLAG_REMOVED_LOGINS);
        bytes[12..16].copy_from_slice(&flags.to_le_bytes());
        bytes[16..32].copy_from_slice(self.operation_id.as_bytes());
        bytes[32..48].copy_from_slice(self.vm_id.as_bytes());
        bytes[48..56].copy_from_slice(&self.generation.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.elapsed_us.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.clock_skew_ms.to_le_bytes());
        let mut mac = key.mac(REPLY_DOMAIN, challenge);
        mac.update(&bytes[..REPLY_AUTHENTICATED_LEN]);
        bytes[REPLY_AUTHENTICATED_LEN..].copy_from_slice(&mac.finalize().into_bytes());
        bytes
    }

    /// Decodes a reply and checks it answers `request`.
    pub fn decode(
        bytes: &[u8],
        key: &CheckpointKey,
        challenge: &[u8; CHECKPOINT_CHALLENGE_LEN],
        request: &CheckpointRequest,
    ) -> Result<Self, CheckpointError> {
        if bytes.len() != CHECKPOINT_REPLY_LEN {
            return Err(CheckpointError::InvalidLength);
        }
        if &bytes[..8] != REPLY_MAGIC {
            return Err(CheckpointError::InvalidMagic);
        }
        let mut mac = key.mac(REPLY_DOMAIN, challenge);
        mac.update(&bytes[..REPLY_AUTHENTICATED_LEN]);
        mac.verify_slice(&bytes[REPLY_AUTHENTICATED_LEN..])
            .map_err(|_| CheckpointError::AuthenticationFailed)?;
        let flags = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed flags"));
        if flags & !(FLAG_RESEEDED | FLAG_VMGENID_DRIVER | FLAG_REMOVED_LOGINS) != 0
            || bytes[72..REPLY_AUTHENTICATED_LEN]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(CheckpointError::InvalidFraming);
        }
        let reply = Self {
            action: CheckpointAction::try_from(u16::from_le_bytes(
                bytes[8..10].try_into().expect("fixed action"),
            ))?,
            status: CheckpointStatus::try_from(u16::from_le_bytes(
                bytes[10..12].try_into().expect("fixed status"),
            ))?,
            operation_id: Uuid::from_slice(&bytes[16..32]).expect("fixed operation id"),
            vm_id: Uuid::from_slice(&bytes[32..48]).expect("fixed vm id"),
            generation: u64::from_le_bytes(bytes[48..56].try_into().expect("fixed generation")),
            elapsed_us: u64::from_le_bytes(bytes[56..64].try_into().expect("fixed elapsed")),
            clock_skew_ms: i64::from_le_bytes(bytes[64..72].try_into().expect("fixed skew")),
            resume: ResumeReport {
                reseeded: flags & FLAG_RESEEDED != 0,
                vmgenid_driver: flags & FLAG_VMGENID_DRIVER != 0,
                removed_logins: flags & FLAG_REMOVED_LOGINS != 0,
            },
        };
        if reply.action != request.action
            || reply.operation_id != request.operation_id
            || reply.vm_id != request.vm_id
            || reply.generation != request.generation
        {
            return Err(CheckpointError::InvalidIdentity);
        }
        Ok(reply)
    }
}

/// Whether a guest now running as `(current_vm_id, current_generation)` may
/// move to `(vm_id, generation)` on `Resume`: a fork moves to another
/// environment, and an in-place restore to a strictly newer generation.
pub fn resume_transition_allowed(
    current_vm_id: Uuid,
    current_generation: u64,
    vm_id: Uuid,
    generation: u64,
) -> bool {
    !vm_id.is_nil()
        && generation != 0
        && (vm_id != current_vm_id || generation > current_generation)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint hook message length is invalid")]
    InvalidLength,
    #[error("checkpoint hook message magic is invalid")]
    InvalidMagic,
    #[error("checkpoint hook message framing is invalid")]
    InvalidFraming,
    #[error("checkpoint hook action is unknown")]
    InvalidAction,
    #[error("checkpoint hook identity is invalid")]
    InvalidIdentity,
    #[error("checkpoint hook token is invalid")]
    InvalidToken,
    #[error("checkpoint hook message failed authentication")]
    AuthenticationFailed,
    #[error("checkpoint hook protocol version is not supported")]
    UnsupportedAbi,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "synthetic-checkpoint-token-0123456789abcdef";

    fn key(vm_id: Uuid, generation: u64) -> CheckpointKey {
        CheckpointKey::derive(TOKEN, vm_id, generation).unwrap()
    }

    fn resume(vm_id: Uuid, generation: u64) -> CheckpointRequest {
        CheckpointRequest {
            action: CheckpointAction::Resume,
            operation_id: Uuid::new_v4(),
            vm_id,
            generation,
            host_entropy: [7; CHECKPOINT_HOST_ENTROPY_LEN],
            host_time_ns: 1_800_000_000_000_000_000,
        }
    }

    #[test]
    fn hello_round_trips_and_refuses_an_empty_challenge() {
        let hello = CheckpointHello {
            challenge: [3; CHECKPOINT_CHALLENGE_LEN],
            abi: GUEST_CHECKPOINT_ABI,
        };
        assert_eq!(CheckpointHello::decode(&hello.encode()).unwrap(), hello);
        let empty = CheckpointHello {
            challenge: [0; CHECKPOINT_CHALLENGE_LEN],
            abi: 1,
        };
        assert_eq!(
            CheckpointHello::decode(&empty.encode()),
            Err(CheckpointError::InvalidFraming)
        );
    }

    #[test]
    fn request_and_reply_round_trip_under_one_key_and_challenge() {
        let vm_id = Uuid::new_v4();
        let key = key(vm_id, 4);
        let challenge = [9; CHECKPOINT_CHALLENGE_LEN];
        let request = resume(vm_id, 4);
        let bytes = request.encode(&key, &challenge).unwrap();
        assert_eq!(
            CheckpointRequest::peek_identity(&bytes).unwrap(),
            (CheckpointAction::Resume, vm_id, 4)
        );
        assert_eq!(
            CheckpointRequest::decode(&bytes, &key, &challenge).unwrap(),
            request
        );
        let reply = CheckpointReply {
            action: request.action,
            status: CheckpointStatus::Done,
            operation_id: request.operation_id,
            vm_id,
            generation: 4,
            elapsed_us: 1234,
            clock_skew_ms: -40,
            resume: ResumeReport {
                reseeded: true,
                vmgenid_driver: true,
                removed_logins: false,
            },
        };
        let encoded = reply.encode(&key, &challenge);
        assert_eq!(
            CheckpointReply::decode(&encoded, &key, &challenge, &request).unwrap(),
            reply
        );
    }

    #[test]
    fn every_message_is_bound_to_its_key_challenge_and_bytes() {
        let vm_id = Uuid::new_v4();
        let challenge = [9; CHECKPOINT_CHALLENGE_LEN];
        let request = resume(vm_id, 4);
        let bytes = request.encode(&key(vm_id, 4), &challenge).unwrap();
        for (key, challenge) in [
            (key(vm_id, 5), challenge),
            (key(Uuid::new_v4(), 4), challenge),
            (
                CheckpointKey::derive("another-synthetic-token-0123456789abcdef", vm_id, 4)
                    .unwrap(),
                challenge,
            ),
            (key(vm_id, 4), [8; CHECKPOINT_CHALLENGE_LEN]),
        ] {
            assert_eq!(
                CheckpointRequest::decode(&bytes, &key, &challenge),
                Err(CheckpointError::AuthenticationFailed)
            );
        }
        for index in [9, 20, 40, 50, 60, 125, 150, 170] {
            let mut tampered = bytes;
            tampered[index] ^= 1;
            assert!(CheckpointRequest::decode(&tampered, &key(vm_id, 4), &challenge).is_err());
        }
    }

    #[test]
    fn a_reply_must_answer_its_own_request() {
        let vm_id = Uuid::new_v4();
        let key = key(vm_id, 2);
        let challenge = [5; CHECKPOINT_CHALLENGE_LEN];
        let request = CheckpointRequest {
            action: CheckpointAction::Freeze,
            operation_id: Uuid::new_v4(),
            vm_id,
            generation: 2,
            host_entropy: [0; CHECKPOINT_HOST_ENTROPY_LEN],
            host_time_ns: 0,
        };
        let other = CheckpointRequest {
            operation_id: Uuid::new_v4(),
            ..request.clone()
        };
        let reply = CheckpointReply {
            action: CheckpointAction::Freeze,
            status: CheckpointStatus::Done,
            operation_id: request.operation_id,
            vm_id,
            generation: 2,
            elapsed_us: 0,
            clock_skew_ms: 0,
            resume: ResumeReport::default(),
        }
        .encode(&key, &challenge);
        CheckpointReply::decode(&reply, &key, &challenge, &request).unwrap();
        assert_eq!(
            CheckpointReply::decode(&reply, &key, &challenge, &other),
            Err(CheckpointError::InvalidIdentity)
        );
    }

    #[test]
    fn only_resume_carries_entropy_and_time() {
        let vm_id = Uuid::new_v4();
        let key = key(vm_id, 1);
        let challenge = [1; CHECKPOINT_CHALLENGE_LEN];
        let mut freeze = resume(vm_id, 1);
        freeze.action = CheckpointAction::Freeze;
        assert_eq!(
            freeze.encode(&key, &challenge),
            Err(CheckpointError::InvalidFraming)
        );
        let mut empty = resume(vm_id, 1);
        empty.host_entropy = [0; CHECKPOINT_HOST_ENTROPY_LEN];
        assert_eq!(
            empty.encode(&key, &challenge),
            Err(CheckpointError::InvalidFraming)
        );
    }

    #[test]
    fn resume_moves_only_to_a_fork_or_a_newer_generation() {
        let source = Uuid::new_v4();
        assert!(resume_transition_allowed(source, 3, Uuid::new_v4(), 1));
        assert!(resume_transition_allowed(source, 3, source, 4));
        assert!(!resume_transition_allowed(source, 3, source, 3));
        assert!(!resume_transition_allowed(source, 3, source, 2));
        assert!(!resume_transition_allowed(source, 3, Uuid::nil(), 9));
    }

    #[test]
    fn keys_refuse_weak_tokens_and_empty_identities() {
        assert_eq!(
            CheckpointKey::derive("short", Uuid::new_v4(), 1).err(),
            Some(CheckpointError::InvalidToken)
        );
        assert_eq!(
            CheckpointKey::derive(TOKEN, Uuid::nil(), 1).err(),
            Some(CheckpointError::InvalidIdentity)
        );
        assert_eq!(
            CheckpointKey::derive(TOKEN, Uuid::new_v4(), 0).err(),
            Some(CheckpointError::InvalidIdentity)
        );
    }
}
