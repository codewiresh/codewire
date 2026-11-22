use std::fmt;

use codewire_access::ManagedCredentialClients;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::egress_ca::{EgressCaCertificate, EgressCaError, MAX_EGRESS_CA_DER_BYTES};

mod placeholders;
use crate::{
    GUEST_PROGRESS_VSOCK_PORT, MAX_SETUP_PACK_BYTES, SETUP_ALIGNMENT, SETUP_HEADER_LEN, Sha256Value,
};
use placeholders::PLACEHOLDER_REGION_LEN;
pub use placeholders::{PlaceholderSlot, SeedPlaceholders};

pub const SEED_LEN: usize = 4096;
pub const SEED_DISK_SERIAL: &str = "CWSEED1";
pub const STATE_DISK_SERIAL: &str = "CWSTATE1";
pub const ROOT_DISK_SERIAL: &str = "CWROOT1";
pub const DOCKER_DISK_SERIAL: &str = "CWDOCKER1";

const MAGIC: &[u8; 8] = b"CWSEED1\0";
// One current format. Retired versions, including the unshipped material-
// bearing v6, are never decoded or selected by a constructor.
const FORMAT_VERSION: u16 = 11;
// Referenced by the guest entrypoint and inspected in the admitted init ELF.
// A retained boot without this capability is never sent the current seed,
// and neither is one that speaks another network session protocol: a VM
// checkpoint taken under it would restore without a network (#4000).
pub const GUEST_RUNTIME_ABI_MARKER: &[u8] = b"\0CWGUESTABI\0seed=11;cw_catalog=1;net=2\0";
const HEADER_LEN: usize = 320;
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
const MANAGED_CREDENTIAL_CLIENTS_END: usize = 248;
const CW_RUNTIME_CATALOG_SHA256_OFFSET: usize = 248;
const EGRESS_CA_LEN_OFFSET: usize = 280;
const RESERVED_OFFSET: usize = 282;
const RESERVED_END: usize = 288;
const CW_RUNTIME_MOVED_FROM_SHA256_OFFSET: usize = 288;
const TOKEN_OFFSET: usize = HEADER_LEN;
/// The credential placeholders, then the egress CA's DER, start after the
/// longest token, so their places never depend on the token's length.
const PLACEHOLDERS_OFFSET: usize = TOKEN_OFFSET + TOKEN_MAX_LEN;
const EGRESS_CA_OFFSET: usize = PLACEHOLDERS_OFFSET + PLACEHOLDER_REGION_LEN;
const _: () = assert!(EGRESS_CA_OFFSET + MAX_EGRESS_CA_DER_BYTES == CHECKSUM_OFFSET);
const SETUP_PRESENT_FLAG: u16 = 1;
const DIRECT_SHARES_PRESENT_FLAG: u16 = 1 << 1;
const SKILL_SNAPSHOT_PRESENT_FLAG: u16 = 1 << 2;
const DOCKER_DATA_DISK_PRESENT_FLAG: u16 = 1 << 3;
const ENVIRONMENT_PROJECTION_PRESENT_FLAG: u16 = 1 << 4;
const CW_RUNTIME_CATALOG_PRESENT_FLAG: u16 = 1 << 5;
const EGRESS_CA_PRESENT_FLAG: u16 = 1 << 6;
/// Valid only with [`EGRESS_CA_PRESENT_FLAG`].
const PLACEHOLDERS_PRESENT_FLAG: u16 = 1 << 7;
const CW_RUNTIME_MOVED_FROM_PRESENT_FLAG: u16 = 1 << 8;
/// The builder guest of an image disk (#4646): it unpacks the setup pack's
/// layers onto its staging disk and powers off. Exclusive of every other
/// flag and optional field but the setup binding.
const IMAGE_BUILD_FLAG: u16 = 1 << 9;
/// The VM's overlay takes its lower from the shared image disk (#4646).
const IMAGE_DISK_FLAG: u16 = 1 << 10;

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
    cw_runtime_catalog_sha256: Option<Sha256Value>,
    cw_runtime_moved_from_sha256: Option<Sha256Value>,
    egress_ca: Option<EgressCaCertificate>,
    placeholders: SeedPlaceholders,
    image_build: bool,
    image_disk: bool,
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
            cw_runtime_catalog_sha256: None,
            cw_runtime_moved_from_sha256: None,
            egress_ca: None,
            placeholders: SeedPlaceholders::default(),
            image_build: false,
            image_disk: false,
        };
        seed.validate()?;
        Ok(seed)
    }

    /// The seed of an image disk's builder guest (#4646): a fresh VM id and
    /// key for this one build, the setup pack whose header carries the build
    /// id, and nothing else. No other constructor sets build mode.
    pub fn for_image_build(
        build_vm_id: Uuid,
        daemon_vsock_port: u32,
        auth_token: impl Into<String>,
        setup: SetupBinding,
    ) -> Result<Self, SeedError> {
        let mut seed = Self::new_with_setup(build_vm_id, 1, daemon_vsock_port, auth_token, setup)?;
        seed.image_build = true;
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
            cw_runtime_catalog_sha256: None,
            cw_runtime_moved_from_sha256: None,
            egress_ca: None,
            placeholders: SeedPlaceholders::default(),
            image_build: false,
            image_disk: false,
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
            cw_runtime_catalog_sha256: None,
            cw_runtime_moved_from_sha256: None,
            egress_ca: None,
            placeholders: SeedPlaceholders::default(),
            image_build: false,
            image_disk: false,
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
            cw_runtime_catalog_sha256: None,
            cw_runtime_moved_from_sha256: None,
            egress_ca: None,
            placeholders: SeedPlaceholders::default(),
            image_build: false,
            image_disk: false,
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

    /// Bind an independent read-only cw catalog, never workspace storage.
    pub fn with_cw_runtime_catalog_sha256(mut self, hash: Sha256Value) -> Self {
        self.cw_runtime_catalog_sha256 = Some(hash);
        self
    }

    pub fn cw_runtime_catalog_sha256(&self) -> Option<Sha256Value> {
        self.cw_runtime_catalog_sha256
    }

    /// Name the catalog this boot moves the environment from, the one boot
    /// whose guest may rebuild a runtime cache bound to it (#4980). Only
    /// with a bound catalog other than this one.
    pub fn with_cw_runtime_moved_from_sha256(
        mut self,
        hash: Sha256Value,
    ) -> Result<Self, SeedError> {
        if self
            .cw_runtime_catalog_sha256
            .is_none_or(|catalog| catalog == hash)
        {
            return Err(SeedError::InvalidRuntimeMove);
        }
        self.cw_runtime_moved_from_sha256 = Some(hash);
        Ok(self)
    }

    pub fn cw_runtime_moved_from_sha256(&self) -> Option<Sha256Value> {
        self.cw_runtime_moved_from_sha256
    }

    /// Trust the TLS front door's CA for this boot (#3999). Public trust
    /// material only: the key never leaves the front door.
    pub fn with_egress_ca(mut self, certificate: EgressCaCertificate) -> Self {
        self.egress_ca = Some(certificate);
        self
    }

    pub fn egress_ca(&self) -> Option<&EgressCaCertificate> {
        self.egress_ca.as_ref()
    }

    /// Give this boot's agents placeholders in place of their credentials
    /// (#3999). Only a boot that trusts the egress CA may carry them.
    pub fn with_credential_placeholders(
        mut self,
        placeholders: SeedPlaceholders,
    ) -> Result<Self, SeedError> {
        if self.egress_ca.is_none() && !placeholders.is_empty() {
            return Err(SeedError::InvalidPlaceholders);
        }
        self.placeholders = placeholders;
        Ok(self)
    }

    pub fn credential_placeholders(&self) -> &SeedPlaceholders {
        &self.placeholders
    }

    pub fn image_build(&self) -> bool {
        self.image_build
    }

    /// Attach the shared image disk; the overlay's lower is on it.
    pub fn with_image_disk(mut self) -> Self {
        self.image_disk = true;
        self
    }

    pub fn image_disk(&self) -> bool {
        self.image_disk
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
        if let Some(hash) = self.cw_runtime_catalog_sha256 {
            flags |= CW_RUNTIME_CATALOG_PRESENT_FLAG;
            bytes[CW_RUNTIME_CATALOG_SHA256_OFFSET..CW_RUNTIME_CATALOG_SHA256_OFFSET + 32]
                .copy_from_slice(&hash.as_bytes());
        }
        if let Some(hash) = self.cw_runtime_moved_from_sha256 {
            flags |= CW_RUNTIME_MOVED_FROM_PRESENT_FLAG;
            bytes[CW_RUNTIME_MOVED_FROM_SHA256_OFFSET..CW_RUNTIME_MOVED_FROM_SHA256_OFFSET + 32]
                .copy_from_slice(&hash.as_bytes());
        }
        if let Some(certificate) = &self.egress_ca {
            flags |= EGRESS_CA_PRESENT_FLAG;
            let der = certificate.der();
            let len = u16::try_from(der.len())
                .expect("an EgressCaCertificate is at most MAX_EGRESS_CA_DER_BYTES");
            put_u16(&mut bytes, EGRESS_CA_LEN_OFFSET, len);
            bytes[EGRESS_CA_OFFSET..EGRESS_CA_OFFSET + der.len()].copy_from_slice(der);
        }
        if !self.placeholders.is_empty() {
            flags |= PLACEHOLDERS_PRESENT_FLAG;
            self.placeholders
                .encode_into(&mut bytes[PLACEHOLDERS_OFFSET..EGRESS_CA_OFFSET]);
        }
        if self.image_build {
            flags |= IMAGE_BUILD_FLAG;
        }
        if self.image_disk {
            flags |= IMAGE_DISK_FLAG;
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
                | ENVIRONMENT_PROJECTION_PRESENT_FLAG
                | CW_RUNTIME_CATALOG_PRESENT_FLAG
                | EGRESS_CA_PRESENT_FLAG
                | PLACEHOLDERS_PRESENT_FLAG
                | CW_RUNTIME_MOVED_FROM_PRESENT_FLAG
                | IMAGE_BUILD_FLAG
                | IMAGE_DISK_FLAG)
            != 0
            || bytes[RESERVED_OFFSET..RESERVED_END]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroReserved);
        }
        let setup = decode_setup(bytes, flags)?;
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
        let cw_runtime_catalog_sha256 = decode_optional_hash(
            bytes,
            flags,
            CW_RUNTIME_CATALOG_PRESENT_FLAG,
            CW_RUNTIME_CATALOG_SHA256_OFFSET,
        )?;
        let cw_runtime_moved_from_sha256 = decode_optional_hash(
            bytes,
            flags,
            CW_RUNTIME_MOVED_FROM_PRESENT_FLAG,
            CW_RUNTIME_MOVED_FROM_SHA256_OFFSET,
        )?;
        let clients = decode_managed_credential_clients(bytes)?;

        let token_len = usize::from(get_u16(bytes, TOKEN_LEN_OFFSET));
        let token_end = TOKEN_OFFSET
            .checked_add(token_len)
            .filter(|end| *end <= PLACEHOLDERS_OFFSET)
            .ok_or(SeedError::InvalidTokenLength { actual: token_len })?;
        let (egress_ca, placeholders) = decode_egress_trust(bytes, flags, token_end)?;

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
        let seed = if let Some(hash) = cw_runtime_catalog_sha256 {
            seed.with_cw_runtime_catalog_sha256(hash)
        } else {
            seed
        };
        let seed = if let Some(hash) = cw_runtime_moved_from_sha256 {
            seed.with_cw_runtime_moved_from_sha256(hash)?
        } else {
            seed
        };
        let seed = if let Some(certificate) = egress_ca {
            seed.with_egress_ca(certificate)
                .with_credential_placeholders(placeholders)?
        } else {
            seed
        };
        let mut seed = seed.with_managed_credential_clients(clients);
        seed.image_build = flags & IMAGE_BUILD_FLAG != 0;
        seed.image_disk = flags & IMAGE_DISK_FLAG != 0;
        seed.validate()?;
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
        // Build mode fails closed: a builder carries its setup pack and
        // nothing an environment could use (condition 2 on #4646).
        if self.image_build
            && (self.setup.is_none()
                || self.image_disk
                || self.direct_shares_sha256.is_some()
                || self.skill_snapshot_sha256.is_some()
                || self.docker_data_disk
                || self.environment_projection_sha256.is_some()
                || self.managed_credential_clients != ManagedCredentialClients::default()
                || self.cw_runtime_catalog_sha256.is_some()
                || self.cw_runtime_moved_from_sha256.is_some()
                || self.egress_ca.is_some()
                || !self.placeholders.is_empty())
        {
            return Err(SeedError::InvalidImageBuild);
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
            .field("cw_runtime_catalog_sha256", &self.cw_runtime_catalog_sha256)
            .field("image_build", &self.image_build)
            .field("image_disk", &self.image_disk)
            .field(
                "cw_runtime_moved_from_sha256",
                &self.cw_runtime_moved_from_sha256,
            )
            .field("egress_ca", &self.egress_ca)
            .field("credential_placeholders", &self.placeholders)
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
    #[error("seed egress CA certificate is invalid: {0}")]
    InvalidEgressCa(EgressCaError),
    #[error("seed credential placeholders are invalid")]
    InvalidPlaceholders,
    #[error("seed runtime move must name a catalog other than the bound one")]
    InvalidRuntimeMove,
    #[error("an image disk builder's seed carries only its setup pack")]
    InvalidImageBuild,
}

/// The egress trust a seed carries (#3999): the CA certificate and, only
/// beside it, the credential placeholders. Every byte between the token's end
/// and the checksum that neither uses is zero.
fn decode_egress_trust(
    bytes: &[u8],
    flags: u16,
    token_end: usize,
) -> Result<(Option<EgressCaCertificate>, SeedPlaceholders), SeedError> {
    let egress_ca_len = usize::from(get_u16(bytes, EGRESS_CA_LEN_OFFSET));
    let egress_ca_end = EGRESS_CA_OFFSET + egress_ca_len;
    if flags & EGRESS_CA_PRESENT_FLAG == 0 && egress_ca_len != 0 {
        return Err(SeedError::NonZeroReserved);
    }
    if egress_ca_end > CHECKSUM_OFFSET {
        return Err(SeedError::InvalidEgressCa(EgressCaError::TooLarge {
            actual: egress_ca_len,
        }));
    }
    let placeholders = if flags & PLACEHOLDERS_PRESENT_FLAG != 0 {
        if flags & EGRESS_CA_PRESENT_FLAG == 0 {
            return Err(SeedError::InvalidPlaceholders);
        }
        let placeholders = SeedPlaceholders::decode(&bytes[PLACEHOLDERS_OFFSET..EGRESS_CA_OFFSET])?;
        if placeholders.is_empty() {
            return Err(SeedError::InvalidPlaceholders);
        }
        placeholders
    } else {
        if bytes[PLACEHOLDERS_OFFSET..EGRESS_CA_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroReserved);
        }
        SeedPlaceholders::default()
    };
    if bytes[token_end..PLACEHOLDERS_OFFSET]
        .iter()
        .chain(&bytes[egress_ca_end..CHECKSUM_OFFSET])
        .any(|byte| *byte != 0)
    {
        return Err(SeedError::NonZeroPadding);
    }
    let egress_ca = if flags & EGRESS_CA_PRESENT_FLAG != 0 {
        Some(
            EgressCaCertificate::from_der(bytes[EGRESS_CA_OFFSET..egress_ca_end].to_vec())
                .map_err(SeedError::InvalidEgressCa)?,
        )
    } else {
        None
    };
    Ok((egress_ca, placeholders))
}

/// The one-boot setup binding, present only with its flag; without it the
/// binding's bytes are zero.
fn decode_setup(bytes: &[u8], flags: u16) -> Result<Option<SetupBinding>, SeedError> {
    if flags & SETUP_PRESENT_FLAG == 0 {
        if bytes[SETUP_TOTAL_LEN_OFFSET..DIRECT_SHARES_SHA256_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SeedError::NonZeroReserved);
        }
        return Ok(None);
    }
    Ok(Some(SetupBinding::new(
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
    )?))
}

/// The managed credential clients: NUL-terminated text, zero after it.
fn decode_managed_credential_clients(bytes: &[u8]) -> Result<ManagedCredentialClients, SeedError> {
    let client_bytes = &bytes[MANAGED_CREDENTIAL_CLIENTS_OFFSET..MANAGED_CREDENTIAL_CLIENTS_END];
    let client_len = client_bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(SeedError::InvalidManagedCredentialClients)?;
    if client_bytes[client_len..].iter().any(|byte| *byte != 0) {
        return Err(SeedError::InvalidManagedCredentialClients);
    }
    let clients = std::str::from_utf8(&client_bytes[..client_len])
        .map_err(|_| SeedError::InvalidManagedCredentialClients)?;
    ManagedCredentialClients::decode(clients)
        .map_err(|_| SeedError::InvalidManagedCredentialClients)
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
mod tests;
