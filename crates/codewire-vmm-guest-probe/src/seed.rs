use std::fmt;

use codewire_access::ManagedCredentialClients;
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
// One current format. Retired versions, including the unshipped material-
// bearing v6, are never decoded or selected by a constructor.
const FORMAT_VERSION: u16 = 8;
const HEADER_LEN: usize = 256;
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
const DIRECT_SHARES_SHA256_OFFSET: usize = 120;
const SKILL_SNAPSHOT_SHA256_OFFSET: usize = 152;
const ENVIRONMENT_PROJECTION_SHA256_OFFSET: usize = 184;
const MANAGED_CREDENTIAL_CLIENTS_OFFSET: usize = 216;
const RESERVED_OFFSET: usize = 248;
const TOKEN_OFFSET: usize = HEADER_LEN;
const SETUP_PRESENT_FLAG: u16 = 1;
const DIRECT_SHARES_PRESENT_FLAG: u16 = 1 << 1;
const SKILL_SNAPSHOT_PRESENT_FLAG: u16 = 1 << 2;
const DOCKER_DATA_DISK_PRESENT_FLAG: u16 = 1 << 3;
const ENVIRONMENT_PROJECTION_PRESENT_FLAG: u16 = 1 << 4;

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
    environment_projection_sha256: Option<Sha256Value>,
    managed_credential_clients: ManagedCredentialClients,
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
            environment_projection_sha256: None,
            managed_credential_clients: ManagedCredentialClients::default(),
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
            environment_projection_sha256: None,
            managed_credential_clients: ManagedCredentialClients::default(),
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
            environment_projection_sha256: None,
            managed_credential_clients: ManagedCredentialClients::default(),
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
            environment_projection_sha256: None,
            managed_credential_clients: ManagedCredentialClients::default(),
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

    /// Bind the already-selected environment operation's projection metadata
    /// for this boot. This contains no application values or source IDs and
    /// does not authorize projection delivery by itself.
    pub fn with_environment_projection_sha256(mut self, hash: Sha256Value) -> Self {
        self.environment_projection_sha256 = Some(hash);
        self
    }

    pub fn environment_projection_sha256(&self) -> Option<Sha256Value> {
        self.environment_projection_sha256
    }

    /// Material-free client setup for this boot, not a provider access grant.
    pub fn with_managed_credential_clients(mut self, clients: ManagedCredentialClients) -> Self {
        self.managed_credential_clients = clients;
        self
    }

    pub fn managed_credential_clients(&self) -> ManagedCredentialClients {
        self.managed_credential_clients
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
        if let Some(hash) = self.environment_projection_sha256 {
            flags |= ENVIRONMENT_PROJECTION_PRESENT_FLAG;
            bytes[ENVIRONMENT_PROJECTION_SHA256_OFFSET..ENVIRONMENT_PROJECTION_SHA256_OFFSET + 32]
                .copy_from_slice(&hash.as_bytes());
        }
        put_u16(&mut bytes, FLAGS_OFFSET, flags);
        let clients = self.managed_credential_clients.encode().as_bytes();
        bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..MANAGED_CREDENTIAL_CLIENTS_OFFSET + clients.len()]
            .copy_from_slice(clients);
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
        if get_u32(bytes, TOTAL_LEN_OFFSET) as usize != SEED_LEN {
            return Err(SeedError::InvalidFraming);
        }

        let expected_checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        if expected_checksum[..] != bytes[CHECKSUM_OFFSET..] {
            return Err(SeedError::ChecksumMismatch);
        }

        if get_u16(bytes, VERSION_OFFSET) != FORMAT_VERSION {
            return Err(SeedError::UnsupportedVersion);
        }
        if usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN {
            return Err(SeedError::InvalidFraming);
        }
        let flags = get_u16(bytes, FLAGS_OFFSET);
        if flags
            & !(SETUP_PRESENT_FLAG
                | DIRECT_SHARES_PRESENT_FLAG
                | SKILL_SNAPSHOT_PRESENT_FLAG
                | DOCKER_DATA_DISK_PRESENT_FLAG
                | ENVIRONMENT_PROJECTION_PRESENT_FLAG)
            != 0
            || bytes[RESERVED_OFFSET..HEADER_LEN]
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
        let direct_shares_sha256 = decode_optional_hash(
            bytes,
            flags,
            DIRECT_SHARES_PRESENT_FLAG,
            DIRECT_SHARES_SHA256_OFFSET,
        )?;
        let skill_snapshot_sha256 = decode_optional_hash(
            bytes,
            flags,
            SKILL_SNAPSHOT_PRESENT_FLAG,
            SKILL_SNAPSHOT_SHA256_OFFSET,
        )?;
        let environment_projection_sha256 = decode_optional_hash(
            bytes,
            flags,
            ENVIRONMENT_PROJECTION_PRESENT_FLAG,
            ENVIRONMENT_PROJECTION_SHA256_OFFSET,
        )?;
        let docker_data_disk = flags & DOCKER_DATA_DISK_PRESENT_FLAG != 0;
        let client_bytes = &bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..RESERVED_OFFSET];
        let client_len = client_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(SeedError::InvalidManagedCredentialClients)?;
        if client_bytes[client_len..].iter().any(|byte| *byte != 0) {
            return Err(SeedError::InvalidManagedCredentialClients);
        }
        let clients = std::str::from_utf8(&client_bytes[..client_len])
            .map_err(|_| SeedError::InvalidManagedCredentialClients)?;
        let clients = ManagedCredentialClients::decode(clients)
            .map_err(|_| SeedError::InvalidManagedCredentialClients)?;

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
        let seed = if let Some(hash) = environment_projection_sha256 {
            seed.with_environment_projection_sha256(hash)
        } else {
            seed
        };
        Ok(seed.with_managed_credential_clients(clients))
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
            .field(
                "managed_credential_clients",
                &self.managed_credential_clients,
            )
            .field(
                "environment_projection_sha256",
                &self.environment_projection_sha256,
            )
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
    #[error("seed managed credential client selection is invalid")]
    InvalidManagedCredentialClients,
}

fn decode_optional_hash(
    bytes: &[u8],
    flags: u16,
    present_flag: u16,
    offset: usize,
) -> Result<Option<Sha256Value>, SeedError> {
    let hash = &bytes[offset..offset + 32];
    if flags & present_flag != 0 {
        Ok(Some(Sha256Value::from_bytes(
            hash.try_into().expect("fixed seed metadata digest"),
        )))
    } else if hash.iter().any(|byte| *byte != 0) {
        Err(SeedError::NonZeroReserved)
    } else {
        Ok(None)
    }
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
            "80227b8d57794734ca9f230300f55291375eb4a42cf5e46d16f88dea3b86525a"
        );
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.encode(), encoded);
    }

    #[test]
    fn managed_clients_are_exact_boot_metadata_not_new_authority_or_identity() {
        let base = sample_seed();
        for clients in [
            "v1:none",
            "v1:codex",
            "v1:openai",
            "v1:codex,openai",
            "v1:anthropic",
            "v1:codex,anthropic",
            "v1:openai,anthropic",
            "v1:codex,openai,anthropic",
            "v1:ssh",
            "v1:codex,ssh",
            "v1:openai,ssh",
            "v1:codex,openai,ssh",
            "v1:anthropic,ssh",
            "v1:codex,anthropic,ssh",
            "v1:openai,anthropic,ssh",
            "v1:codex,openai,anthropic,ssh",
        ] {
            let clients = ManagedCredentialClients::decode(clients).unwrap();
            let seed = base.clone().with_managed_credential_clients(clients);
            assert_eq!(seed.vm_id(), base.vm_id());
            assert_eq!(seed.generation(), base.generation());
            assert_eq!(seed.auth_token(), base.auth_token());
            assert_eq!(seed.environment_projection_sha256(), None);
            let decoded = Seed::decode(&seed.encode()).unwrap();
            assert_eq!(decoded.managed_credential_clients(), clients);
            assert_eq!(decoded, seed);
        }
        for invalid in ["", "codex", "v1:openai,codex", "v1:github", "v1:ssh,codex"] {
            let mut bytes = base.encode();
            bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..RESERVED_OFFSET].fill(0);
            bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET
                ..MANAGED_CREDENTIAL_CLIENTS_OFFSET + invalid.len()]
                .copy_from_slice(invalid.as_bytes());
            refresh_checksum(&mut bytes);
            assert_eq!(
                Seed::decode(&bytes),
                Err(SeedError::InvalidManagedCredentialClients)
            );
        }
        let mut bytes = base.encode();
        bytes[RESERVED_OFFSET - 1] = 1;
        refresh_checksum(&mut bytes);
        assert_eq!(
            Seed::decode(&bytes),
            Err(SeedError::InvalidManagedCredentialClients)
        );
        let maximum =
            ManagedCredentialClients::from_profile_slots(["codex", "openai", "anthropic", "ssh"])
                .unwrap()
                .encode();
        assert_eq!(maximum.len(), 29);
        let encoded = base
            .clone()
            .with_managed_credential_clients(ManagedCredentialClients::decode(maximum).unwrap())
            .encode();
        assert_eq!(encoded[MANAGED_CREDENTIAL_CLIENTS_OFFSET + 29], 0);
        assert!(
            encoded[MANAGED_CREDENTIAL_CLIENTS_OFFSET + 30..RESERVED_OFFSET]
                .iter()
                .all(|byte| *byte == 0)
        );
        let mut retired = base.encode();
        put_u16(&mut retired, VERSION_OFFSET, 7);
        refresh_checksum(&mut retired);
        assert_eq!(Seed::decode(&retired), Err(SeedError::UnsupportedVersion));
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
        put_u16(&mut encoded, FLAGS_OFFSET, 1 << 15);
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

    #[test]
    fn current_seed_binds_one_boot_setup_with_source_compatible_constructor() {
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
            "e8e0f945cae4404b931a8333fb2955f54343bbfe555de8ffe7c7ee62586303ee"
        );
        assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
        assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
        assert_eq!(Seed::decode(&encoded).unwrap(), seed);
        assert_eq!(seed.setup(), Some(setup));
        assert_eq!(sample_seed().setup(), None);

        let mut corrupt = encoded;
        corrupt[RESERVED_OFFSET] = 1;
        let checksum = Sha256::digest(&corrupt[..CHECKSUM_OFFSET]);
        corrupt[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&corrupt), Err(SeedError::NonZeroReserved));
    }

    #[test]
    fn current_seed_binds_direct_share_plan_with_or_without_setup() {
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
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
            assert_eq!(Seed::decode(&encoded).unwrap(), seed);
            assert_eq!(seed.setup(), setup);
            assert_eq!(seed.direct_shares_sha256(), Some(direct_shares));
        }
    }

    #[test]
    fn current_seed_binds_skill_snapshot_with_optional_existing_bindings() {
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
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
            assert_eq!(Seed::decode(&encoded).unwrap(), seed);
            assert_eq!(seed.setup(), setup);
            assert_eq!(seed.direct_shares_sha256(), direct_shares);
            assert_eq!(seed.skill_snapshot_sha256(), Some(skill_snapshot));
        }
    }

    #[test]
    fn current_seed_binds_docker_disk_presence_with_optional_bindings() {
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
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), FORMAT_VERSION);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), HEADER_LEN as u16);
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
    fn current_seed_docker_flag_is_explicit_and_unknown_flags_are_rejected() {
        let seed = sample_seed().with_docker_data_disk();
        let mut encoded = seed.encode();
        put_u16(&mut encoded, FLAGS_OFFSET, 0);
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(Seed::decode(&encoded).unwrap(), sample_seed());

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
        encoded[RETIRED_SECRET_TOTAL_LEN_OFFSET..RETIRED_HEADER_LEN + TOKEN.len()].fill(0);
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

    #[test]
    fn every_optional_binding_combination_uses_only_current_format() {
        let setup = SetupBinding::new(
            SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT,
            Sha256Value::calculate(b"root-generation"),
            Sha256Value::calculate(b"setup-header"),
        )
        .unwrap();
        let direct = Sha256Value::calculate(b"direct-share-plan");
        let skill = Sha256Value::calculate(b"skill-snapshot-plan");
        let projection = Sha256Value::calculate(b"canonical-project-selection");
        for flags in 0_u16..32 {
            let selected_setup = (flags & SETUP_PRESENT_FLAG != 0).then_some(setup);
            let selected_direct = (flags & DIRECT_SHARES_PRESENT_FLAG != 0).then_some(direct);
            let selected_skill = (flags & SKILL_SNAPSHOT_PRESENT_FLAG != 0).then_some(skill);
            let mut seed = Seed::new_with_all_bindings(
                sample_seed().vm_id(),
                7,
                17777,
                TOKEN,
                selected_setup,
                selected_direct,
                selected_skill,
            )
            .unwrap();
            if flags & DOCKER_DATA_DISK_PRESENT_FLAG != 0 {
                seed = seed.with_docker_data_disk();
            }
            if flags & ENVIRONMENT_PROJECTION_PRESENT_FLAG != 0 {
                seed = seed.with_environment_projection_sha256(projection);
            }
            let encoded = seed.encode();
            assert_eq!(get_u16(&encoded, VERSION_OFFSET), 8);
            assert_eq!(get_u16(&encoded, HEADER_LEN_OFFSET), 256);
            assert_eq!(get_u16(&encoded, FLAGS_OFFSET), flags);
            assert_eq!(
                &encoded[TOKEN_OFFSET..TOKEN_OFFSET + TOKEN.len()],
                TOKEN.as_bytes()
            );
            let decoded = Seed::decode(&encoded).unwrap();
            assert_eq!(decoded, seed);
            assert_eq!(decoded.encode(), encoded);
            assert_eq!(decoded.setup(), selected_setup);
            assert_eq!(decoded.direct_shares_sha256(), selected_direct);
            assert_eq!(decoded.skill_snapshot_sha256(), selected_skill);
            assert_eq!(
                decoded.docker_data_disk(),
                flags & DOCKER_DATA_DISK_PRESENT_FLAG != 0
            );
            assert_eq!(
                decoded.environment_projection_sha256(),
                (flags & ENVIRONMENT_PROJECTION_PRESENT_FLAG != 0).then_some(projection)
            );
        }
    }

    #[test]
    fn projection_binding_is_optional_checksum_bound_and_does_not_change_operation_identity() {
        let base = sample_seed();
        assert_eq!(base.environment_projection_sha256(), None);
        let hash = Sha256Value::calculate(b"canonical-project-selection");
        let seed = base.clone().with_environment_projection_sha256(hash);
        assert_eq!(seed.vm_id(), base.vm_id());
        assert_eq!(seed.generation(), base.generation());
        assert_eq!(seed.auth_token(), base.auth_token());
        let mut encoded = seed.encode();
        assert_eq!(&encoded[184..216], &hash.as_bytes());
        assert_eq!(&encoded[216..223], b"v1:none");
        assert!(encoded[223..256].iter().all(|byte| *byte == 0));
        encoded[184] ^= 1;
        assert_eq!(Seed::decode(&encoded), Err(SeedError::ChecksumMismatch));

        let mut encoded = seed.encode();
        put_u16(&mut encoded, FLAGS_OFFSET, 0);
        refresh_checksum(&mut encoded);
        assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
    }

    #[test]
    fn absent_binding_storage_and_reserved_bytes_cannot_hide_data() {
        for offset in [48, 56, 88, 120, 152, 184, 215, 248, 255] {
            let mut encoded = sample_seed().encode();
            encoded[offset] = 1;
            refresh_checksum(&mut encoded);
            assert_eq!(Seed::decode(&encoded), Err(SeedError::NonZeroReserved));
        }
        for header in [0, 48, 192, 223, 224, 225, 240, 255, 257, u16::MAX] {
            let mut encoded = sample_seed().encode();
            put_u16(&mut encoded, HEADER_LEN_OFFSET, header);
            refresh_checksum(&mut encoded);
            assert_eq!(Seed::decode(&encoded), Err(SeedError::InvalidFraming));
        }
    }

    #[test]
    fn checksum_valid_retired_versions_one_through_five_are_rejected() {
        // Historical byte shapes are test-only fixtures, not decoder branches.
        for (version, header, flags) in [
            (1, 48, 0),
            (2, 128, 1),
            (3, 160, 2),
            (4, 192, 4),
            (5, 192, 8),
        ] {
            let mut encoded = [0; SEED_LEN];
            encoded[..48].copy_from_slice(&sample_seed().encode()[..48]);
            put_u16(&mut encoded, VERSION_OFFSET, version);
            put_u16(&mut encoded, HEADER_LEN_OFFSET, header);
            put_u16(&mut encoded, FLAGS_OFFSET, flags);
            match version {
                2 => {
                    put_u64(&mut encoded, 48, SETUP_HEADER_LEN as u64 + SETUP_ALIGNMENT);
                    encoded[56..88].fill(0x11);
                    encoded[88..120].fill(0x22);
                }
                3 => encoded[120..152].fill(0x33),
                4 => encoded[152..184].fill(0x44),
                _ => {}
            }
            let offset = usize::from(header);
            encoded[offset..offset + TOKEN.len()].copy_from_slice(TOKEN.as_bytes());
            refresh_checksum(&mut encoded);
            assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
        }
        for version in [0, FORMAT_VERSION + 1, u16::MAX] {
            let mut encoded = sample_seed().encode();
            put_u16(&mut encoded, VERSION_OFFSET, version);
            refresh_checksum(&mut encoded);
            assert_eq!(Seed::decode(&encoded), Err(SeedError::UnsupportedVersion));
        }
    }

    fn refresh_checksum(encoded: &mut [u8; SEED_LEN]) {
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    }
}
