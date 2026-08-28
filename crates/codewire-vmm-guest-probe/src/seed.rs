use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const SEED_LEN: usize = 4096;
pub const SEED_DISK_SERIAL: &str = "CWSEED1";
pub const STATE_DISK_SERIAL: &str = "CWSTATE1";

const MAGIC: &[u8; 8] = b"CWSEED1\0";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 48;
const CHECKSUM_LEN: usize = 32;
const CHECKSUM_OFFSET: usize = SEED_LEN - CHECKSUM_LEN;
const TOKEN_MAX_LEN: usize = 512;
const TOKEN_MIN_LEN: usize = 32;

const VERSION_OFFSET: usize = 8;
const HEADER_LEN_OFFSET: usize = 10;
const TOTAL_LEN_OFFSET: usize = 12;
const VM_ID_OFFSET: usize = 16;
const GENERATION_OFFSET: usize = 32;
const PORT_OFFSET: usize = 40;
const TOKEN_LEN_OFFSET: usize = 44;
const RESERVED_OFFSET: usize = 46;
const TOKEN_OFFSET: usize = HEADER_LEN;

#[derive(Clone, PartialEq, Eq)]
pub struct Seed {
    vm_id: Uuid,
    generation: u64,
    daemon_vsock_port: u32,
    auth_token: String,
}

impl Seed {
    pub fn new(
        vm_id: Uuid,
        generation: u64,
        daemon_vsock_port: u32,
        auth_token: impl Into<String>,
    ) -> Result<Self, SeedError> {
        let seed = Self {
            vm_id,
            generation,
            daemon_vsock_port,
            auth_token: auth_token.into(),
        };
        seed.validate()?;
        Ok(seed)
    }

    pub fn vm_id(&self) -> Uuid {
        self.vm_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn daemon_vsock_port(&self) -> u32 {
        self.daemon_vsock_port
    }

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }

    pub fn encode(&self) -> [u8; SEED_LEN] {
        // Construction and decoding are the only ways to obtain a Seed, so
        // these invariants have already been checked.
        debug_assert!(self.validate().is_ok());

        let mut bytes = [0_u8; SEED_LEN];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        put_u16(&mut bytes, VERSION_OFFSET, FORMAT_VERSION);
        put_u16(&mut bytes, HEADER_LEN_OFFSET, HEADER_LEN as u16);
        put_u32(&mut bytes, TOTAL_LEN_OFFSET, SEED_LEN as u32);
        bytes[VM_ID_OFFSET..VM_ID_OFFSET + 16].copy_from_slice(self.vm_id.as_bytes());
        put_u64(&mut bytes, GENERATION_OFFSET, self.generation);
        put_u32(&mut bytes, PORT_OFFSET, self.daemon_vsock_port);
        put_u16(&mut bytes, TOKEN_LEN_OFFSET, self.auth_token.len() as u16);
        bytes[TOKEN_OFFSET..TOKEN_OFFSET + self.auth_token.len()]
            .copy_from_slice(self.auth_token.as_bytes());

        let checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SeedError> {
        if bytes.len() != SEED_LEN {
            return Err(SeedError::WrongLength {
                actual: bytes.len(),
            });
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(SeedError::BadMagic);
        }
        if get_u16(bytes, VERSION_OFFSET) != FORMAT_VERSION {
            return Err(SeedError::UnsupportedVersion);
        }
        if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN
            || get_u32(bytes, TOTAL_LEN_OFFSET) as usize != SEED_LEN
        {
            return Err(SeedError::InvalidFraming);
        }
        if bytes[RESERVED_OFFSET..HEADER_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroReserved);
        }

        let expected_checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        if expected_checksum[..] != bytes[CHECKSUM_OFFSET..] {
            return Err(SeedError::ChecksumMismatch);
        }

        let token_len = usize::from(get_u16(bytes, TOKEN_LEN_OFFSET));
        let token_end = TOKEN_OFFSET
            .checked_add(token_len)
            .filter(|end| *end <= CHECKSUM_OFFSET)
            .ok_or(SeedError::InvalidTokenLength { actual: token_len })?;
        if bytes[token_end..CHECKSUM_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroPadding);
        }

        let token = std::str::from_utf8(&bytes[TOKEN_OFFSET..token_end])
            .map_err(|_| SeedError::InvalidTokenCharacters)?;
        let vm_id = Uuid::from_slice(&bytes[VM_ID_OFFSET..VM_ID_OFFSET + 16])
            .map_err(|_| SeedError::InvalidVmId)?;
        Self::new(
            vm_id,
            get_u64(bytes, GENERATION_OFFSET),
            get_u32(bytes, PORT_OFFSET),
            token,
        )
    }

    fn validate(&self) -> Result<(), SeedError> {
        if self.vm_id.is_nil() {
            return Err(SeedError::InvalidVmId);
        }
        if self.generation == 0 {
            return Err(SeedError::InvalidGeneration);
        }
        if self.daemon_vsock_port == 0 || self.daemon_vsock_port == u32::MAX {
            return Err(SeedError::InvalidVsockPort);
        }

        let token = self.auth_token.as_bytes();
        if !(TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len()) {
            return Err(SeedError::InvalidTokenLength {
                actual: token.len(),
            });
        }
        if !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SeedError::InvalidTokenCharacters);
        }
        Ok(())
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Seed")
            .field("vm_id", &self.vm_id)
            .field("generation", &self.generation)
            .field("daemon_vsock_port", &self.daemon_vsock_port)
            .field("auth_token", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.auth_token.zeroize();
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeedError {
    #[error("seed must be exactly {SEED_LEN} bytes (got {actual})")]
    WrongLength { actual: usize },
    #[error("seed magic is invalid")]
    BadMagic,
    #[error("seed format version is unsupported")]
    UnsupportedVersion,
    #[error("seed framing fields are invalid")]
    InvalidFraming,
    #[error("seed reserved bytes must be zero")]
    NonZeroReserved,
    #[error("seed checksum is invalid")]
    ChecksumMismatch,
    #[error("seed padding must be zero")]
    NonZeroPadding,
    #[error("seed VM identity is invalid")]
    InvalidVmId,
    #[error("seed generation must be nonzero")]
    InvalidGeneration,
    #[error("seed vsock port is invalid")]
    InvalidVsockPort,
    #[error("seed daemon token length is invalid (got {actual})")]
    InvalidTokenLength { actual: usize },
    #[error("seed daemon token contains invalid characters")]
    InvalidTokenCharacters,
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed seed field"),
    )
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed seed field"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed seed field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    fn sample_seed() -> Seed {
        Seed::new(
            Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
            7,
            17777,
            TOKEN,
        )
        .unwrap()
    }

    #[test]
    fn seed_round_trip_is_exact_and_stable() {
        let seed = sample_seed();
        let encoded = seed.encode();

        assert_eq!(encoded.len(), SEED_LEN);
        assert_eq!(&encoded[..8], MAGIC);
        assert_eq!(
            format!("{:x}", Sha256::digest(encoded)),
            "8dffc25fb4bc751d7cb62c40da5ad8a4e6d3484f570fee69cfec8e8bc1629736"
        );
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.encode(), encoded);
    }

    #[test]
    fn seed_rejects_corruption_even_in_padding() {
        let mut encoded = sample_seed().encode();
        encoded[2000] ^= 1;
        assert_eq!(Seed::decode(&encoded), Err(SeedError::ChecksumMismatch));

        let mut encoded = sample_seed().encode();
        encoded[2000] = 1;
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroPadding));
    }

    #[test]
    fn seed_rejects_bad_framing_and_token_data() {
        let mut encoded = sample_seed().encode();
        encoded[RESERVED_OFFSET] = 1;
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));

        let mut encoded = sample_seed().encode();
        encoded[TOKEN_OFFSET] = b' ';
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(
            Seed::decode(&encoded),
            Err(SeedError::InvalidTokenCharacters)
        );
    }

    #[test]
    fn debug_never_exposes_the_token() {
        let rendered = format!("{:?}", sample_seed());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(TOKEN));

        let mut corrupt = sample_seed().encode();
        corrupt[TOKEN_OFFSET] = b'!';
        let error = Seed::decode(&corrupt).unwrap_err().to_string();
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("012345"));
    }

    #[test]
    fn constructor_rejects_ambiguous_values() {
        let id = Uuid::new_v4();
        assert_eq!(
            Seed::new(id, 0, 17777, TOKEN),
            Err(SeedError::InvalidGeneration)
        );
        assert_eq!(Seed::new(id, 1, 0, TOKEN), Err(SeedError::InvalidVsockPort));
        assert_eq!(
            Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN)),
            Ok(Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN)).unwrap())
        );
        assert_eq!(
            Seed::new(id, 1, 17777, "x".repeat(TOKEN_MIN_LEN - 1)),
            Err(SeedError::InvalidTokenLength {
                actual: TOKEN_MIN_LEN - 1
            })
        );
    }
}
