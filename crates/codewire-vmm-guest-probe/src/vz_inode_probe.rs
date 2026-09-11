use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const VZ_INODE_PROBE_VSOCK_PORT: u32 = 7_775;
pub const VZ_INODE_PROBE_CHALLENGE_LEN: usize = 32;
pub const VZ_INODE_PROBE_FRAME_LEN: usize = 88;
pub const VZ_INODE_PROBE_SEED_LEN: usize = 4_096;

const FRAME_MAGIC: &[u8; 8] = b"CWVINOD1";
const STAGE_FRAME_MAGIC: &[u8; 8] = b"CWVSTG1\0";
const FRAME_BODY_LEN: usize = 56;
const DOMAIN: &[u8] = b"codewire-vz-exact-inode-probe-v1\0";

type HmacSha256 = Hmac<Sha256>;

/// Non-success progress emitted only by the synthetic exact-inode fixture.
///
/// These records deliberately carry no authentication and can never satisfy
/// readiness. They make a failed entitlement-gated hardware attempt locally
/// diagnosable before the guest has read the seed needed for the final HMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VzInodeProbeStage {
    Started = 1,
    FilesystemsMounted = 2,
    SeedRead = 3,
    DataIdentified = 4,
}

pub fn encode_vz_inode_probe_stage_frame(
    stage: VzInodeProbeStage,
) -> [u8; VZ_INODE_PROBE_FRAME_LEN] {
    let mut frame = [0_u8; VZ_INODE_PROBE_FRAME_LEN];
    frame[..8].copy_from_slice(STAGE_FRAME_MAGIC);
    frame[8] = stage as u8;
    frame
}

pub fn decode_vz_inode_probe_stage_frame(
    frame: &[u8],
) -> Result<VzInodeProbeStage, VzInodeProbeError> {
    if frame.len() != VZ_INODE_PROBE_FRAME_LEN
        || &frame[..8] != STAGE_FRAME_MAGIC
        || frame[9..].iter().any(|byte| *byte != 0)
    {
        return Err(VzInodeProbeError::InvalidFrame);
    }
    match frame[8] {
        1 => Ok(VzInodeProbeStage::Started),
        2 => Ok(VzInodeProbeStage::FilesystemsMounted),
        3 => Ok(VzInodeProbeStage::SeedRead),
        4 => Ok(VzInodeProbeStage::DataIdentified),
        _ => Err(VzInodeProbeError::InvalidFrame),
    }
}

pub fn encode_vz_inode_probe_frame(
    seed: &[u8],
    filesystem_uuid: [u8; 16],
    challenge: [u8; VZ_INODE_PROBE_CHALLENGE_LEN],
) -> Result<[u8; VZ_INODE_PROBE_FRAME_LEN], VzInodeProbeError> {
    validate_inputs(seed, filesystem_uuid, challenge)?;
    let mut frame = [0_u8; VZ_INODE_PROBE_FRAME_LEN];
    frame[..8].copy_from_slice(FRAME_MAGIC);
    frame[8..40].copy_from_slice(&Sha256::digest(seed));
    frame[40..56].copy_from_slice(&filesystem_uuid);
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts every key length");
    mac.update(DOMAIN);
    mac.update(&challenge);
    mac.update(&frame[..FRAME_BODY_LEN]);
    frame[FRAME_BODY_LEN..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(frame)
}

pub fn verify_vz_inode_probe_frame(
    frame: &[u8],
    seed: &[u8],
    filesystem_uuid: [u8; 16],
    challenge: [u8; VZ_INODE_PROBE_CHALLENGE_LEN],
) -> Result<(), VzInodeProbeError> {
    validate_inputs(seed, filesystem_uuid, challenge)?;
    if frame.len() != VZ_INODE_PROBE_FRAME_LEN {
        return Err(VzInodeProbeError::InvalidFrame);
    }
    let expected = encode_vz_inode_probe_frame(seed, filesystem_uuid, challenge)?;
    if frame[..FRAME_BODY_LEN] != expected[..FRAME_BODY_LEN] {
        return Err(VzInodeProbeError::InvalidFrame);
    }
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts every key length");
    mac.update(DOMAIN);
    mac.update(&challenge);
    mac.update(&frame[..FRAME_BODY_LEN]);
    mac.verify_slice(&frame[FRAME_BODY_LEN..])
        .map_err(|_| VzInodeProbeError::AuthenticationFailed)
}

fn validate_inputs(
    seed: &[u8],
    filesystem_uuid: [u8; 16],
    challenge: [u8; VZ_INODE_PROBE_CHALLENGE_LEN],
) -> Result<(), VzInodeProbeError> {
    if seed.len() != VZ_INODE_PROBE_SEED_LEN
        || seed.iter().all(|byte| *byte == 0)
        || filesystem_uuid.iter().all(|byte| *byte == 0)
        || challenge.iter().all(|byte| *byte == 0)
    {
        return Err(VzInodeProbeError::InvalidInput);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VzInodeProbeError {
    #[error("VZ inode probe input is invalid")]
    InvalidInput,
    #[error("VZ inode probe frame is invalid")]
    InvalidFrame,
    #[error("VZ inode probe frame authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_binds_seed_uuid_and_fresh_challenge() {
        let seed = [0x31; VZ_INODE_PROBE_SEED_LEN];
        let uuid = [0x42; 16];
        let challenge = [0x53; VZ_INODE_PROBE_CHALLENGE_LEN];
        let frame = encode_vz_inode_probe_frame(&seed, uuid, challenge).unwrap();
        assert_eq!(
            frame
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            concat!(
                "435756494e4f44314fdd600892f7d61608383a6f94b6b68a8630b65c0976dea3f",
                "5e410d4c4ff0bbd42424242424242424242424242424242fe9873626ac6bde0aed0",
                "c4ffa3f5f35f6a48fb1fa669bde365e28a7fb0d29b6a"
            )
        );
        verify_vz_inode_probe_frame(&frame, &seed, uuid, challenge).unwrap();

        let mut wrong_seed = seed;
        wrong_seed[0] ^= 1;
        assert_eq!(
            verify_vz_inode_probe_frame(&frame, &wrong_seed, uuid, challenge),
            Err(VzInodeProbeError::InvalidFrame)
        );
        let mut wrong_uuid = uuid;
        wrong_uuid[0] ^= 1;
        assert_eq!(
            verify_vz_inode_probe_frame(&frame, &seed, wrong_uuid, challenge),
            Err(VzInodeProbeError::InvalidFrame)
        );
        let mut wrong_challenge = challenge;
        wrong_challenge[0] ^= 1;
        assert_eq!(
            verify_vz_inode_probe_frame(&frame, &seed, uuid, wrong_challenge),
            Err(VzInodeProbeError::AuthenticationFailed)
        );
    }

    #[test]
    fn diagnostic_stages_are_fixed_distinct_non_success_frames() {
        for (stage, code) in [
            (VzInodeProbeStage::Started, 1),
            (VzInodeProbeStage::FilesystemsMounted, 2),
            (VzInodeProbeStage::SeedRead, 3),
            (VzInodeProbeStage::DataIdentified, 4),
        ] {
            let frame = encode_vz_inode_probe_stage_frame(stage);
            assert_eq!(frame.len(), VZ_INODE_PROBE_FRAME_LEN);
            assert_eq!(&frame[..8], STAGE_FRAME_MAGIC);
            assert_eq!(frame[8], code);
            assert!(frame[9..].iter().all(|byte| *byte == 0));
            assert_ne!(&frame[..8], FRAME_MAGIC);
            assert_eq!(decode_vz_inode_probe_stage_frame(&frame), Ok(stage));
        }

        let valid = encode_vz_inode_probe_stage_frame(VzInodeProbeStage::Started);
        assert_eq!(
            decode_vz_inode_probe_stage_frame(&valid[..87]),
            Err(VzInodeProbeError::InvalidFrame)
        );
        for offset in [0, 8, 20] {
            let mut malformed = valid;
            malformed[offset] ^= if offset == 8 { 0xff } else { 1 };
            assert_eq!(
                decode_vz_inode_probe_stage_frame(&malformed),
                Err(VzInodeProbeError::InvalidFrame)
            );
        }
    }

    #[test]
    fn zero_or_malformed_inputs_fail_closed() {
        let seed = [0x31; VZ_INODE_PROBE_SEED_LEN];
        let uuid = [0x42; 16];
        let challenge = [0x53; VZ_INODE_PROBE_CHALLENGE_LEN];
        assert_eq!(
            encode_vz_inode_probe_frame(&[], uuid, challenge),
            Err(VzInodeProbeError::InvalidInput)
        );
        assert_eq!(
            encode_vz_inode_probe_frame(&[0; VZ_INODE_PROBE_SEED_LEN], uuid, challenge),
            Err(VzInodeProbeError::InvalidInput)
        );
        assert_eq!(
            encode_vz_inode_probe_frame(&seed, [0; 16], challenge),
            Err(VzInodeProbeError::InvalidInput)
        );
        assert_eq!(
            encode_vz_inode_probe_frame(&seed, uuid, [0; VZ_INODE_PROBE_CHALLENGE_LEN]),
            Err(VzInodeProbeError::InvalidInput)
        );
        assert_eq!(
            verify_vz_inode_probe_frame(&[0; 87], &seed, uuid, challenge),
            Err(VzInodeProbeError::InvalidFrame)
        );
    }
}
