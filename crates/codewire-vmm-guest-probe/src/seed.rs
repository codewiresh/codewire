use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    GUEST_PROGRESS_VSOCK_PORT, MAX_SETUP_PACK_BYTES, SETUP_ALIGNMENT, SETUP_HEADER_LEN, Sha256Value,
};

pub const SEED_LEN: usize = 4096;
pub const SEED_DISK_SERIAL: &str = "CWSEED1";
pub const STATE_DISK_SERIAL: &str = "CWSTATE1";
pub const ROOT_DISK_SERIAL: &str = "CWROOT1";
pub const DOCKER_DISK_SERIAL: &str = "CWDOCKER1";

const MAGIC: &[u8; 8] = b"CWSEED1\0";
const FORMAT_VERSION_V1: u16 = 1;
const FORMAT_VERSION_V2: u16 = 2;
const FORMAT_VERSION_V3: u16 = 3;
const FORMAT_VERSION_V4: u16 = 4;
const FORMAT_VERSION_V5: u16 = 5;
const HEADER_LEN_V1: usize = 48;
const HEADER_LEN_V2: usize = 128;
const HEADER_LEN_V3: usize = 160;
const HEADER_LEN_V4: usize = 192;
const HEADER_LEN_V5: usize = HEADER_LEN_V4;
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
const FLAGS_OFFSET: usize = 46;
const SETUP_TOTAL_LEN_OFFSET: usize = 48;
const SETUP_ROOT_GENERATION_OFFSET: usize = 56;
const SETUP_HEADER_SHA256_OFFSET: usize = 88;
const V2_RESERVED_OFFSET: usize = 120;
const DIRECT_SHARES_SHA256_OFFSET: usize = 120;
const V3_RESERVED_OFFSET: usize = 152;
const SKILL_SNAPSHOT_SHA256_OFFSET: usize = 152;
const V4_RESERVED_OFFSET: usize = 184;
const TOKEN_OFFSET_V1: usize = HEADER_LEN_V1;
const TOKEN_OFFSET_V2: usize = HEADER_LEN_V2;
const TOKEN_OFFSET_V3: usize = HEADER_LEN_V3;
const TOKEN_OFFSET_V4: usize = HEADER_LEN_V4;
const TOKEN_OFFSET_V5: usize = HEADER_LEN_V5;
const SETUP_PRESENT_FLAG: u16 = 1;
const DIRECT_SHARES_PRESENT_FLAG: u16 = 1 << 1;
const SKILL_SNAPSHOT_PRESENT_FLAG: u16 = 1 << 2;
const DOCKER_DATA_DISK_PRESENT_FLAG: u16 = 1 << 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupBinding {
    total_bytes: u64,
    root_generation: Sha256Value,
    header_sha256: Sha256Value,
}

impl SetupBinding {
    pub fn new(
        total_bytes: u64,
        root_generation: Sha256Value,
        header_sha256: Sha256Value,
    ) -> Result<Self, SeedError> {
        let binding = Self {
            total_bytes,
            root_generation,
            header_sha256,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    pub fn root_generation(self) -> Sha256Value {
        self.root_generation
    }

    pub fn header_sha256(self) -> Sha256Value {
        self.header_sha256
    }

    fn validate(self) -> Result<(), SeedError> {
        if !(SETUP_HEADER_LEN as u64..=MAX_SETUP_PACK_BYTES).contains(&self.total_bytes)
            || !self.total_bytes.is_multiple_of(SETUP_ALIGNMENT)
        {
            return Err(SeedError::InvalidSetupBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Seed {
    vm_id: Uuid,
    generation: u64,
    daemon_vsock_port: u32,
    auth_token: String,
    setup: Option<SetupBinding>,
    direct_shares_sha256: Option<Sha256Value>,
    skill_snapshot_sha256: Option<Sha256Value>,
    docker_data_disk: bool,
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
            setup: None,
            direct_shares_sha256: None,
            skill_snapshot_sha256: None,
            docker_data_disk: false,
        };
        seed.validate()?;
        Ok(seed)
    }

    pub fn new_with_setup(
        vm_id: Uuid,
        generation: u64,
        daemon_vsock_port: u32,
        auth_token: impl Into<String>,
        setup: SetupBinding,
    ) -> Result<Self, SeedError> {
        let seed = Self {
            vm_id,
            generation,
            daemon_vsock_port,
            auth_token: auth_token.into(),
            setup: Some(setup),
            direct_shares_sha256: None,
            skill_snapshot_sha256: None,
            docker_data_disk: false,
        };
        seed.validate()?;
        Ok(seed)
    }

    pub fn new_with_bindings(
        vm_id: Uuid,
        generation: u64,
        daemon_vsock_port: u32,
        auth_token: impl Into<String>,
        setup: Option<SetupBinding>,
        direct_shares_sha256: Option<Sha256Value>,
    ) -> Result<Self, SeedError> {
        let seed = Self {
            vm_id,
            generation,
            daemon_vsock_port,
            auth_token: auth_token.into(),
            setup,
            direct_shares_sha256,
            skill_snapshot_sha256: None,
            docker_data_disk: false,
        };
        seed.validate()?;
        Ok(seed)
    }

    pub fn new_with_all_bindings(
        vm_id: Uuid,
        generation: u64,
        daemon_vsock_port: u32,
        auth_token: impl Into<String>,
        setup: Option<SetupBinding>,
        direct_shares_sha256: Option<Sha256Value>,
        skill_snapshot_sha256: Option<Sha256Value>,
    ) -> Result<Self, SeedError> {
        let seed = Self {
            vm_id,
            generation,
            daemon_vsock_port,
            auth_token: auth_token.into(),
            setup,
            direct_shares_sha256,
            skill_snapshot_sha256,
            docker_data_disk: false,
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

    pub fn setup(&self) -> Option<SetupBinding> {
        self.setup
    }

    pub fn direct_shares_sha256(&self) -> Option<Sha256Value> {
        self.direct_shares_sha256
    }

    pub fn skill_snapshot_sha256(&self) -> Option<Sha256Value> {
        self.skill_snapshot_sha256
    }

    pub fn with_docker_data_disk(mut self) -> Self {
        self.docker_data_disk = true;
        self
    }

    pub fn docker_data_disk(&self) -> bool {
        self.docker_data_disk
    }

    pub fn encode(&self) -> [u8; SEED_LEN] {
        // Construction and decoding are the only ways to obtain a Seed, so
        // these invariants have already been checked.
        debug_assert!(self.validate().is_ok());

        let mut bytes = [0_u8; SEED_LEN];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        let (version, header_len, token_offset) = if self.docker_data_disk {
            (FORMAT_VERSION_V5, HEADER_LEN_V5, TOKEN_OFFSET_V5)
        } else {
            match (
                self.setup,
                self.direct_shares_sha256,
                self.skill_snapshot_sha256,
            ) {
                (_, _, Some(_)) => (FORMAT_VERSION_V4, HEADER_LEN_V4, TOKEN_OFFSET_V4),
                (_, Some(_), None) => (FORMAT_VERSION_V3, HEADER_LEN_V3, TOKEN_OFFSET_V3),
                (Some(_), None, None) => (FORMAT_VERSION_V2, HEADER_LEN_V2, TOKEN_OFFSET_V2),
                (None, None, None) => (FORMAT_VERSION_V1, HEADER_LEN_V1, TOKEN_OFFSET_V1),
            }
        };
        put_u16(&mut bytes, VERSION_OFFSET, version);
        put_u16(&mut bytes, HEADER_LEN_OFFSET, header_len as u16);
        put_u32(&mut bytes, TOTAL_LEN_OFFSET, SEED_LEN as u32);
        bytes[VM_ID_OFFSET..VM_ID_OFFSET + 16].copy_from_slice(self.vm_id.as_bytes());
        put_u64(&mut bytes, GENERATION_OFFSET, self.generation);
        put_u32(&mut bytes, PORT_OFFSET, self.daemon_vsock_port);
        put_u16(&mut bytes, TOKEN_LEN_OFFSET, self.auth_token.len() as u16);
        let mut flags = 0;
        if let Some(setup) = self.setup {
            flags |= SETUP_PRESENT_FLAG;
            put_u64(&mut bytes, SETUP_TOTAL_LEN_OFFSET, setup.total_bytes);
            bytes[SETUP_ROOT_GENERATION_OFFSET..SETUP_ROOT_GENERATION_OFFSET + 32]
                .copy_from_slice(&setup.root_generation.as_bytes());
            bytes[SETUP_HEADER_SHA256_OFFSET..SETUP_HEADER_SHA256_OFFSET + 32]
                .copy_from_slice(&setup.header_sha256.as_bytes());
        }
        if let Some(direct_shares_sha256) = self.direct_shares_sha256 {
            flags |= DIRECT_SHARES_PRESENT_FLAG;
            bytes[DIRECT_SHARES_SHA256_OFFSET..DIRECT_SHARES_SHA256_OFFSET + 32]
                .copy_from_slice(&direct_shares_sha256.as_bytes());
        }
        if let Some(skill_snapshot_sha256) = self.skill_snapshot_sha256 {
            flags |= SKILL_SNAPSHOT_PRESENT_FLAG;
            bytes[SKILL_SNAPSHOT_SHA256_OFFSET..SKILL_SNAPSHOT_SHA256_OFFSET + 32]
                .copy_from_slice(&skill_snapshot_sha256.as_bytes());
        }
        if self.docker_data_disk {
            flags |= DOCKER_DATA_DISK_PRESENT_FLAG;
        }
        put_u16(&mut bytes, FLAGS_OFFSET, flags);
        bytes[token_offset..token_offset + self.auth_token.len()]
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
        if get_u32(bytes, TOTAL_LEN_OFFSET) as usize != SEED_LEN {
            return Err(SeedError::InvalidFraming);
        }

        let expected_checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        if expected_checksum[..] != bytes[CHECKSUM_OFFSET..] {
            return Err(SeedError::ChecksumMismatch);
        }

        let decoded_fields = match get_u16(bytes, VERSION_OFFSET) {
            FORMAT_VERSION_V1 => {
                if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN_V1 {
                    return Err(SeedError::InvalidFraming);
                }
                if get_u16(bytes, FLAGS_OFFSET) != 0 {
                    return Err(SeedError::NonZeroReserved);
                }
                (TOKEN_OFFSET_V1, None, None, None, false)
            }
            FORMAT_VERSION_V2 => {
                if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN_V2 {
                    return Err(SeedError::InvalidFraming);
                }
                if get_u16(bytes, FLAGS_OFFSET) != SETUP_PRESENT_FLAG
                    || bytes[V2_RESERVED_OFFSET..HEADER_LEN_V2]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(SeedError::NonZeroReserved);
                }
                let root_generation = Sha256Value::from_bytes(
                    bytes[SETUP_ROOT_GENERATION_OFFSET..SETUP_ROOT_GENERATION_OFFSET + 32]
                        .try_into()
                        .expect("fixed seed setup digest"),
                );
                let header_sha256 = Sha256Value::from_bytes(
                    bytes[SETUP_HEADER_SHA256_OFFSET..SETUP_HEADER_SHA256_OFFSET + 32]
                        .try_into()
                        .expect("fixed seed setup digest"),
                );
                let setup = SetupBinding::new(
                    get_u64(bytes, SETUP_TOTAL_LEN_OFFSET),
                    root_generation,
                    header_sha256,
                )?;
                (TOKEN_OFFSET_V2, Some(setup), None, None, false)
            }
            FORMAT_VERSION_V3 => {
                if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN_V3 {
                    return Err(SeedError::InvalidFraming);
                }
                let flags = get_u16(bytes, FLAGS_OFFSET);
                if flags & DIRECT_SHARES_PRESENT_FLAG == 0
                    || flags & !(SETUP_PRESENT_FLAG | DIRECT_SHARES_PRESENT_FLAG) != 0
                    || bytes[V3_RESERVED_OFFSET..HEADER_LEN_V3]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(SeedError::NonZeroReserved);
                }
                let setup = if flags & SETUP_PRESENT_FLAG != 0 {
                    Some(SetupBinding::new(
                        get_u64(bytes, SETUP_TOTAL_LEN_OFFSET),
                        Sha256Value::from_bytes(
                            bytes[SETUP_ROOT_GENERATION_OFFSET..SETUP_ROOT_GENERATION_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                        Sha256Value::from_bytes(
                            bytes[SETUP_HEADER_SHA256_OFFSET..SETUP_HEADER_SHA256_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                    )?)
                } else {
                    if bytes[SETUP_TOTAL_LEN_OFFSET..DIRECT_SHARES_SHA256_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                let direct_shares_sha256 = Sha256Value::from_bytes(
                    bytes[DIRECT_SHARES_SHA256_OFFSET..DIRECT_SHARES_SHA256_OFFSET + 32]
                        .try_into()
                        .expect("fixed seed direct-share digest"),
                );
                (
                    TOKEN_OFFSET_V3,
                    setup,
                    Some(direct_shares_sha256),
                    None,
                    false,
                )
            }
            FORMAT_VERSION_V4 => {
                if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN_V4 {
                    return Err(SeedError::InvalidFraming);
                }
                let flags = get_u16(bytes, FLAGS_OFFSET);
                if flags & SKILL_SNAPSHOT_PRESENT_FLAG == 0
                    || flags
                        & !(SETUP_PRESENT_FLAG
                            | DIRECT_SHARES_PRESENT_FLAG
                            | SKILL_SNAPSHOT_PRESENT_FLAG)
                        != 0
                    || bytes[V4_RESERVED_OFFSET..HEADER_LEN_V4]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(SeedError::NonZeroReserved);
                }
                let setup = if flags & SETUP_PRESENT_FLAG != 0 {
                    Some(SetupBinding::new(
                        get_u64(bytes, SETUP_TOTAL_LEN_OFFSET),
                        Sha256Value::from_bytes(
                            bytes[SETUP_ROOT_GENERATION_OFFSET..SETUP_ROOT_GENERATION_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                        Sha256Value::from_bytes(
                            bytes[SETUP_HEADER_SHA256_OFFSET..SETUP_HEADER_SHA256_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                    )?)
                } else {
                    if bytes[SETUP_TOTAL_LEN_OFFSET..DIRECT_SHARES_SHA256_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                let direct_shares_sha256 = if flags & DIRECT_SHARES_PRESENT_FLAG != 0 {
                    Some(Sha256Value::from_bytes(
                        bytes[DIRECT_SHARES_SHA256_OFFSET..DIRECT_SHARES_SHA256_OFFSET + 32]
                            .try_into()
                            .expect("fixed seed direct-share digest"),
                    ))
                } else {
                    if bytes[DIRECT_SHARES_SHA256_OFFSET..SKILL_SNAPSHOT_SHA256_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                let skill_snapshot_sha256 = Sha256Value::from_bytes(
                    bytes[SKILL_SNAPSHOT_SHA256_OFFSET..SKILL_SNAPSHOT_SHA256_OFFSET + 32]
                        .try_into()
                        .expect("fixed seed skill-snapshot digest"),
                );
                (
                    TOKEN_OFFSET_V4,
                    setup,
                    direct_shares_sha256,
                    Some(skill_snapshot_sha256),
                    false,
                )
            }
            FORMAT_VERSION_V5 => {
                if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN_V5 {
                    return Err(SeedError::InvalidFraming);
                }
                let flags = get_u16(bytes, FLAGS_OFFSET);
                if flags & DOCKER_DATA_DISK_PRESENT_FLAG == 0
                    || flags
                        & !(SETUP_PRESENT_FLAG
                            | DIRECT_SHARES_PRESENT_FLAG
                            | SKILL_SNAPSHOT_PRESENT_FLAG
                            | DOCKER_DATA_DISK_PRESENT_FLAG)
                        != 0
                    || bytes[V4_RESERVED_OFFSET..HEADER_LEN_V5]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(SeedError::NonZeroReserved);
                }
                let setup = if flags & SETUP_PRESENT_FLAG != 0 {
                    Some(SetupBinding::new(
                        get_u64(bytes, SETUP_TOTAL_LEN_OFFSET),
                        Sha256Value::from_bytes(
                            bytes[SETUP_ROOT_GENERATION_OFFSET..SETUP_ROOT_GENERATION_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                        Sha256Value::from_bytes(
                            bytes[SETUP_HEADER_SHA256_OFFSET..SETUP_HEADER_SHA256_OFFSET + 32]
                                .try_into()
                                .expect("fixed seed setup digest"),
                        ),
                    )?)
                } else {
                    if bytes[SETUP_TOTAL_LEN_OFFSET..DIRECT_SHARES_SHA256_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                let direct_shares_sha256 = if flags & DIRECT_SHARES_PRESENT_FLAG != 0 {
                    Some(Sha256Value::from_bytes(
                        bytes[DIRECT_SHARES_SHA256_OFFSET..SKILL_SNAPSHOT_SHA256_OFFSET]
                            .try_into()
                            .expect("fixed seed direct-share digest"),
                    ))
                } else {
                    if bytes[DIRECT_SHARES_SHA256_OFFSET..SKILL_SNAPSHOT_SHA256_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                let skill_snapshot_sha256 = if flags & SKILL_SNAPSHOT_PRESENT_FLAG != 0 {
                    Some(Sha256Value::from_bytes(
                        bytes[SKILL_SNAPSHOT_SHA256_OFFSET..V4_RESERVED_OFFSET]
                            .try_into()
                            .expect("fixed seed skill-snapshot digest"),
                    ))
                } else {
                    if bytes[SKILL_SNAPSHOT_SHA256_OFFSET..V4_RESERVED_OFFSET]
                        .iter()
                        .any(|byte| *byte != 0)
                    {
                        return Err(SeedError::NonZeroReserved);
                    }
                    None
                };
                (
                    TOKEN_OFFSET_V5,
                    setup,
                    direct_shares_sha256,
                    skill_snapshot_sha256,
                    true,
                )
            }
            _ => return Err(SeedError::UnsupportedVersion),
        };
        let (token_offset, setup, direct_shares_sha256, skill_snapshot_sha256, docker_data_disk) =
            decoded_fields;

        let token_len = usize::from(get_u16(bytes, TOKEN_LEN_OFFSET));
        let token_end = token_offset
            .checked_add(token_len)
            .filter(|end| *end <= CHECKSUM_OFFSET)
            .ok_or(SeedError::InvalidTokenLength { actual: token_len })?;
        if bytes[token_end..CHECKSUM_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroPadding);
        }

        let token = std::str::from_utf8(&bytes[token_offset..token_end])
            .map_err(|_| SeedError::InvalidTokenCharacters)?;
        let vm_id = Uuid::from_slice(&bytes[VM_ID_OFFSET..VM_ID_OFFSET + 16])
            .map_err(|_| SeedError::InvalidVmId)?;
        let seed = Self::new_with_all_bindings(
            vm_id,
            get_u64(bytes, GENERATION_OFFSET),
            get_u32(bytes, PORT_OFFSET),
            token,
            setup,
            direct_shares_sha256,
            skill_snapshot_sha256,
        )?;
        let seed = if docker_data_disk {
            seed.with_docker_data_disk()
        } else {
            seed
        };
        Ok(seed)
    }

    fn validate(&self) -> Result<(), SeedError> {
        if self.vm_id.is_nil() {
            return Err(SeedError::InvalidVmId);
        }
        if self.generation == 0 {
            return Err(SeedError::InvalidGeneration);
        }
        if self.daemon_vsock_port == 0
            || self.daemon_vsock_port == u32::MAX
            || self.daemon_vsock_port == GUEST_PROGRESS_VSOCK_PORT
        {
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
        if let Some(setup) = self.setup {
            setup.validate()?;
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
            .field("setup", &self.setup)
            .field("direct_shares_sha256", &self.direct_shares_sha256)
            .field("skill_snapshot_sha256", &self.skill_snapshot_sha256)
            .field("docker_data_disk", &self.docker_data_disk)
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
    #[error("seed setup binding is invalid")]
    InvalidSetupBinding,
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
        encoded[FLAGS_OFFSET] = 1;
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));

        let mut encoded = sample_seed().encode();
        encoded[TOKEN_OFFSET_V1] = b' ';
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
        corrupt[TOKEN_OFFSET_V1] = b'!';
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

    #[test]
    fn seed_v2_binds_one_boot_setup_without_changing_v1() {
        let setup = SetupBinding::new(
            SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
            Sha256Value::calculate(b"root-generation"),
            Sha256Value::calculate(b"setup-header"),
        )
        .unwrap();
        let seed = Seed::new_with_setup(
            Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
            7,
            17777,
            TOKEN,
            setup,
        )
        .unwrap();
        let encoded = seed.encode();
        assert_eq!(
            format!("{:x}", Sha256::digest(encoded)),
            "93276f73b575a81fbbda6e7ea504173bfb2185668eaa7e5d375c765c22f22d40"
        );
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION_V2);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN_V2 as u16);
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.setup(), Some(setup));
        assert_eq!(sample_seed().setup(), None);

        let mut corrupt = encoded;
        corrupt[V2_RESERVED_OFFSET] = 1;
        let checksum = Sha256::digest(&corrupt[..CHECKSUM_OFFSET]);
        corrupt[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&corrupt), Err(SeedError::NonZeroReserved));
    }

    #[test]
    fn seed_v3_binds_direct_share_plan_with_or_without_setup() {
        let direct_shares = Sha256Value::calculate(b"direct-share-plan");
        for setup in [
            None,
            Some(
                SetupBinding::new(
                    SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
                    Sha256Value::calculate(b"root-generation"),
                    Sha256Value::calculate(b"setup-header"),
                )
                .unwrap(),
            ),
        ] {
            let seed = Seed::new_with_bindings(
                Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
                7,
                17777,
                TOKEN,
                setup,
                Some(direct_shares),
            )
            .unwrap();
            let encoded = seed.encode();
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION_V3);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN_V3 as u16);
            assert_eq!(Seed::decode(&encoded).unwrap(), seed);
            assert_eq!(seed.setup(), setup);
            assert_eq!(seed.direct_shares_sha256(), Some(direct_shares));
        }
    }

    #[test]
    fn seed_v4_binds_skill_snapshot_with_optional_existing_bindings() {
        let setup = SetupBinding::new(
            SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
            Sha256Value::calculate(b"root-generation"),
            Sha256Value::calculate(b"setup-header"),
        )
        .unwrap();
        let direct_shares = Sha256Value::calculate(b"direct-share-plan");
        let skill_snapshot = Sha256Value::calculate(b"skill-snapshot-plan");
        for (setup, direct_shares) in [
            (None, None),
            (Some(setup), None),
            (None, Some(direct_shares)),
            (Some(setup), Some(direct_shares)),
        ] {
            let seed = Seed::new_with_all_bindings(
                Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
                7,
                17777,
                TOKEN,
                setup,
                direct_shares,
                Some(skill_snapshot),
            )
            .unwrap();
            let encoded = seed.encode();
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION_V4);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN_V4 as u16);
            assert_eq!(Seed::decode(&encoded).unwrap(), seed);
            assert_eq!(seed.setup(), setup);
            assert_eq!(seed.direct_shares_sha256(), direct_shares);
            assert_eq!(seed.skill_snapshot_sha256(), Some(skill_snapshot));
        }
    }

    #[test]
    fn seed_v5_binds_docker_disk_presence_with_every_optional_binding_shape() {
        let setup = SetupBinding::new(
            SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
            Sha256Value::calculate(b"root-generation"),
            Sha256Value::calculate(b"setup-header"),
        )
        .unwrap();
        let direct_shares = Sha256Value::calculate(b"direct-share-plan");
        let skill_snapshot = Sha256Value::calculate(b"skill-snapshot-plan");
        for (setup, direct_shares, skill_snapshot) in [
            (None, None, None),
            (Some(setup), None, None),
            (None, Some(direct_shares), None),
            (None, None, Some(skill_snapshot)),
            (Some(setup), Some(direct_shares), Some(skill_snapshot)),
        ] {
            let seed = Seed::new_with_all_bindings(
                Uuid::parse_str("8c3d9e72-e77f-4e75-9396-43a292614fa7").unwrap(),
                7,
                17777,
                TOKEN,
                setup,
                direct_shares,
                skill_snapshot,
            )
            .unwrap()
            .with_docker_data_disk();
            let encoded = seed.encode();
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION_V5);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN_V5 as u16);
            assert_ne!(
                get_u16(&encoded, FLAGS_OFFSET) & DOCKER_DATA_DISK_PRESENT_FLAG,
                0
            );
            assert_eq!(Seed::decode(&encoded).unwrap(), seed);
            assert!(seed.docker_data_disk());
            assert_eq!(seed.setup(), setup);
            assert_eq!(seed.direct_shares_sha256(), direct_shares);
            assert_eq!(seed.skill_snapshot_sha256(), skill_snapshot);
        }
    }

    #[test]
    fn seed_v5_requires_the_docker_flag_and_rejects_unknown_flags() {
        let seed = sample_seed().with_docker_data_disk();
        let mut encoded = seed.encode();
        put_u16(&mut encoded, FLAGS_OFFSET, 0);
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));

        let mut encoded = seed.encode();
        put_u16(
            &mut encoded,
            FLAGS_OFFSET,
            DOCKER_DATA_DISK_PRESENT_FLAG | (1 << 15),
        );
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
    }

    #[test]
    fn checksum_valid_retired_v6_seed_is_rejected() {
        // V6 was the unshipped one-boot workload-secret format. Construct its
        // historical framing locally so compatibility stays explicitly
        // fail-closed without restoring a production material decoder.
        const RETIRED_V6: u16 = 6;
        const RETIRED_HEADER_LEN: usize = 240;
        const RETIRED_SECRET_TOTAL_LEN_OFFSET: usize = 184;
        const RETIRED_SECRET_SHA256_OFFSET: usize = 192;
        const RETIRED_SECRET_ENTRY_COUNT_OFFSET: usize = 224;
        const RETIRED_SECRET_PRESENT_FLAG: u16 = 1 << 4;

        let mut encoded = sample_seed().with_docker_data_disk().encode();
        encoded[V4_RESERVED_OFFSET..RETIRED_HEADER_LEN + TOKEN.len()].fill(0);
        put_u16(&mut encoded, VERSION_OFFSET, RETIRED_V6);
        put_u16(&mut encoded, HEADER_LEN_OFFSET, RETIRED_HEADER_LEN as u16);
        put_u16(
            &mut encoded,
            FLAGS_OFFSET,
            DOCKER_DATA_DISK_PRESENT_FLAG | RETIRED_SECRET_PRESENT_FLAG,
        );
        put_u64(&mut encoded, RETIRED_SECRET_TOTAL_LEN_OFFSET, 4096);
        encoded[RETIRED_SECRET_SHA256_OFFSET..RETIRED_SECRET_SHA256_OFFSET + 32].fill(0x5a);
        put_u32(&mut encoded, RETIRED_SECRET_ENTRY_COUNT_OFFSET, 1);
        encoded[RETIRED_HEADER_LEN..RETIRED_HEADER_LEN + TOKEN.len()]
            .copy_from_slice(TOKEN.as_bytes());
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);

        assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
    }
}
