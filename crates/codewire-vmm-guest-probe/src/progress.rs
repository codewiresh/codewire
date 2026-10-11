use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

pub const GUEST_PROGRESS_VSOCK_PORT: u32 = 7_776;
pub const PROGRESS_CHALLENGE_LEN: usize = 32;
pub const PROGRESS_REQUEST_LEN: usize = 64;
pub const PROGRESS_FRAME_LEN: usize = 96;

const REQUEST_MAGIC: &[u8; 8] = b"CWPRQ1\0\0";
const FRAME_MAGIC: &[u8; 8] = b"CWPRG1\0\0";
const FRAME_AUTHENTICATED_LEN: usize = 64;
const FRAME_TAG_LEN: usize = 32;
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 512;
const FLAG_TERMINAL: u16 = 1;
const FLAG_FAILURE: u16 = 2;
const FRAME_DOMAIN: &[u8] = b"codewire-guest-progress-frame-v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum GuestBootStage {
    StateMounted = 1,
    CgroupsReady = 2,
    DisksAdmitted = 3,
    RootMounted = 4,
    SetupHeaderReady = 5,
    SetupContentReady = 6,
    RootLayersReady = 7,
    WorkspacePlanReady = 8,
    OwnershipReady = 9,
    ContainerControlReady = 10,
    RootGenerationReady = 11,
    PersistentLayoutReady = 12,
    RuncLaunching = 13,
    RuncRunning = 14,
    WorkspaceRunning = 15,
    DaemonStarted = 16,
    SetupFailed = 17,
    WorkspaceFailed = 18,
    /// Docker is enabled but the workspace image has no Docker tooling.
    DockerToolingMissing = 19,
}

impl GuestBootStage {
    pub fn from_persisted(value: &str) -> Option<Self> {
        match value {
            "state-mounted" => Some(Self::StateMounted),
            "cgroups-ready" => Some(Self::CgroupsReady),
            "disks-admitted" => Some(Self::DisksAdmitted),
            "root-mounted" => Some(Self::RootMounted),
            "setup-header-ready" => Some(Self::SetupHeaderReady),
            "setup-content-ready" => Some(Self::SetupContentReady),
            "root-layers-ready" => Some(Self::RootLayersReady),
            "workspace-plan-ready" => Some(Self::WorkspacePlanReady),
            "ownership-ready" => Some(Self::OwnershipReady),
            "container-control-ready" => Some(Self::ContainerControlReady),
            "root-generation-ready" => Some(Self::RootGenerationReady),
            "persistent-layout-ready" => Some(Self::PersistentLayoutReady),
            "runc-launching" => Some(Self::RuncLaunching),
            "runc-running" => Some(Self::RuncRunning),
            "workspace-running" => Some(Self::WorkspaceRunning),
            "daemon-started" => Some(Self::DaemonStarted),
            "workspace-docker-tooling-missing" => Some(Self::DockerToolingMissing),
            value if value.starts_with("setup-") => Some(Self::SetupFailed),
            value if value.starts_with("workspace-") || value == "workspace-container-exited" => {
                Some(Self::WorkspaceFailed)
            }
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::DaemonStarted
                | Self::SetupFailed
                | Self::WorkspaceFailed
                | Self::DockerToolingMissing
        )
    }

    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::SetupFailed | Self::WorkspaceFailed | Self::DockerToolingMissing
        )
    }

    fn flags(self) -> u16 {
        (u16::from(self.is_terminal()) * FLAG_TERMINAL)
            | (u16::from(self.is_failure()) * FLAG_FAILURE)
    }
}

impl TryFrom<u16> for GuestBootStage {
    type Error = ProgressError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::StateMounted),
            2 => Ok(Self::CgroupsReady),
            3 => Ok(Self::DisksAdmitted),
            4 => Ok(Self::RootMounted),
            5 => Ok(Self::SetupHeaderReady),
            6 => Ok(Self::SetupContentReady),
            7 => Ok(Self::RootLayersReady),
            8 => Ok(Self::WorkspacePlanReady),
            9 => Ok(Self::OwnershipReady),
            10 => Ok(Self::ContainerControlReady),
            11 => Ok(Self::RootGenerationReady),
            12 => Ok(Self::PersistentLayoutReady),
            13 => Ok(Self::RuncLaunching),
            14 => Ok(Self::RuncRunning),
            15 => Ok(Self::WorkspaceRunning),
            16 => Ok(Self::DaemonStarted),
            17 => Ok(Self::SetupFailed),
            18 => Ok(Self::WorkspaceFailed),
            19 => Ok(Self::DockerToolingMissing),
            _ => Err(ProgressError::InvalidStage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressRequest {
    pub vm_id: Uuid,
    pub generation: u64,
    pub challenge: [u8; PROGRESS_CHALLENGE_LEN],
}

impl ProgressRequest {
    pub fn encode(self) -> [u8; PROGRESS_REQUEST_LEN] {
        let mut bytes = [0_u8; PROGRESS_REQUEST_LEN];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..24].copy_from_slice(self.vm_id.as_bytes());
        bytes[24..32].copy_from_slice(&self.generation.to_le_bytes());
        bytes[32..].copy_from_slice(&self.challenge);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProgressError> {
        if bytes.len() != PROGRESS_REQUEST_LEN {
            return Err(ProgressError::InvalidLength);
        }
        if &bytes[..8] != REQUEST_MAGIC {
            return Err(ProgressError::InvalidMagic);
        }
        let vm_id = Uuid::from_slice(&bytes[8..24]).map_err(|_| ProgressError::InvalidIdentity)?;
        let generation = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .expect("fixed progress request generation"),
        );
        let challenge: [u8; PROGRESS_CHALLENGE_LEN] = bytes[32..]
            .try_into()
            .expect("fixed progress request challenge");
        if vm_id.is_nil() || generation == 0 || challenge.iter().all(|byte| *byte == 0) {
            return Err(ProgressError::InvalidIdentity);
        }
        Ok(Self {
            vm_id,
            generation,
            challenge,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressFrame {
    pub vm_id: Uuid,
    pub generation: u64,
    pub sequence: u64,
    pub stage: GuestBootStage,
}

impl ProgressFrame {
    pub fn encode(
        self,
        challenge: &[u8; PROGRESS_CHALLENGE_LEN],
        token: &str,
    ) -> Result<[u8; PROGRESS_FRAME_LEN], ProgressError> {
        validate_token(token)?;
        if self.vm_id.is_nil() || self.generation == 0 || self.sequence == 0 {
            return Err(ProgressError::InvalidIdentity);
        }
        let mut bytes = [0_u8; PROGRESS_FRAME_LEN];
        bytes[..8].copy_from_slice(FRAME_MAGIC);
        bytes[8..24].copy_from_slice(self.vm_id.as_bytes());
        bytes[24..32].copy_from_slice(&self.generation.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[40..42].copy_from_slice(&(self.stage as u16).to_le_bytes());
        bytes[42..44].copy_from_slice(&self.stage.flags().to_le_bytes());
        let tag = frame_tag(token, challenge, &bytes[..FRAME_AUTHENTICATED_LEN])?;
        bytes[FRAME_AUTHENTICATED_LEN..].copy_from_slice(&tag);
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        challenge: &[u8; PROGRESS_CHALLENGE_LEN],
        token: &str,
        expected_vm_id: Uuid,
        expected_generation: u64,
    ) -> Result<Self, ProgressError> {
        validate_token(token)?;
        if bytes.len() != PROGRESS_FRAME_LEN {
            return Err(ProgressError::InvalidLength);
        }
        if &bytes[..8] != FRAME_MAGIC {
            return Err(ProgressError::InvalidMagic);
        }
        let mut mac = frame_mac(token, challenge)?;
        mac.update(&bytes[..FRAME_AUTHENTICATED_LEN]);
        mac.verify_slice(&bytes[FRAME_AUTHENTICATED_LEN..])
            .map_err(|_| ProgressError::AuthenticationFailed)?;
        if bytes[44..FRAME_AUTHENTICATED_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ProgressError::InvalidFraming);
        }
        let vm_id = Uuid::from_slice(&bytes[8..24]).map_err(|_| ProgressError::InvalidIdentity)?;
        let generation = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .expect("fixed progress frame generation"),
        );
        let sequence = u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .expect("fixed progress frame sequence"),
        );
        let stage = GuestBootStage::try_from(u16::from_le_bytes(
            bytes[40..42]
                .try_into()
                .expect("fixed progress frame stage"),
        ))?;
        let flags = u16::from_le_bytes(
            bytes[42..44]
                .try_into()
                .expect("fixed progress frame flags"),
        );
        if vm_id != expected_vm_id
            || generation != expected_generation
            || sequence == 0
            || flags != stage.flags()
        {
            return Err(ProgressError::InvalidIdentity);
        }
        Ok(Self {
            vm_id,
            generation,
            sequence,
            stage,
        })
    }
}

fn validate_token(token: &str) -> Result<(), ProgressError> {
    if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProgressError::InvalidToken);
    }
    Ok(())
}

fn frame_mac(
    token: &str,
    challenge: &[u8; PROGRESS_CHALLENGE_LEN],
) -> Result<HmacSha256, ProgressError> {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).map_err(|_| ProgressError::InvalidToken)?;
    mac.update(FRAME_DOMAIN);
    mac.update(challenge);
    Ok(mac)
}

fn frame_tag(
    token: &str,
    challenge: &[u8; PROGRESS_CHALLENGE_LEN],
    frame: &[u8],
) -> Result<[u8; FRAME_TAG_LEN], ProgressError> {
    let mut mac = frame_mac(token, challenge)?;
    mac.update(frame);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProgressError {
    #[error("guest progress message length is invalid")]
    InvalidLength,
    #[error("guest progress message magic is invalid")]
    InvalidMagic,
    #[error("guest progress message framing is invalid")]
    InvalidFraming,
    #[error("guest progress identity is invalid")]
    InvalidIdentity,
    #[error("guest progress stage is invalid")]
    InvalidStage,
    #[error("guest progress token is invalid")]
    InvalidToken,
    #[error("guest progress authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "guest-progress-test-token-0123456789abcdef";

    fn request() -> ProgressRequest {
        ProgressRequest {
            vm_id: Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap(),
            generation: 7,
            challenge: [0x5a; PROGRESS_CHALLENGE_LEN],
        }
    }

    #[test]
    fn request_and_authenticated_frame_round_trip_exactly() {
        let request = request();
        assert_eq!(ProgressRequest::decode(&request.encode()).unwrap(), request);
        let frame = ProgressFrame {
            vm_id: request.vm_id,
            generation: request.generation,
            sequence: 4,
            stage: GuestBootStage::WorkspaceRunning,
        };
        let encoded = frame.encode(&request.challenge, TOKEN).unwrap();
        assert_eq!(
            ProgressFrame::decode(
                &encoded,
                &request.challenge,
                TOKEN,
                request.vm_id,
                request.generation,
            )
            .unwrap(),
            frame
        );
    }

    #[test]
    fn frame_rejects_wrong_secret_challenge_generation_and_framing() {
        let request = request();
        let frame = ProgressFrame {
            vm_id: request.vm_id,
            generation: request.generation,
            sequence: 1,
            stage: GuestBootStage::RootMounted,
        };
        let encoded = frame.encode(&request.challenge, TOKEN).unwrap();
        for (token, challenge, generation) in [
            (
                "wrong-progress-test-token-0123456789abcdef",
                request.challenge,
                request.generation,
            ),
            (TOKEN, [0xa5; PROGRESS_CHALLENGE_LEN], request.generation),
            (TOKEN, request.challenge, request.generation + 1),
        ] {
            assert!(
                ProgressFrame::decode(&encoded, &challenge, token, request.vm_id, generation,)
                    .is_err()
            );
        }
        let mut corrupt = encoded;
        corrupt[50] = 1;
        assert!(
            ProgressFrame::decode(
                &corrupt,
                &request.challenge,
                TOKEN,
                request.vm_id,
                request.generation,
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_stages_collapse_failures_to_a_small_allowlist() {
        assert_eq!(
            GuestBootStage::from_persisted("setup-tar-absolute-path"),
            Some(GuestBootStage::SetupFailed)
        );
        assert_eq!(
            GuestBootStage::from_persisted("workspace-readiness-timeout"),
            Some(GuestBootStage::WorkspaceFailed)
        );
        assert_eq!(GuestBootStage::from_persisted("arbitrary-guest-text"), None);
    }

    #[test]
    fn missing_docker_tooling_is_its_own_terminal_failure() {
        let stage = GuestBootStage::from_persisted("workspace-docker-tooling-missing");
        assert_eq!(stage, Some(GuestBootStage::DockerToolingMissing));
        let stage = stage.unwrap();
        assert!(stage.is_failure() && stage.is_terminal());
        assert_eq!(GuestBootStage::try_from(19).unwrap(), stage);
        assert!(GuestBootStage::try_from(20).is_err());
        assert_eq!(
            GuestBootStage::from_persisted("workspace-docker-root-failed"),
            Some(GuestBootStage::WorkspaceFailed)
        );
    }
}
