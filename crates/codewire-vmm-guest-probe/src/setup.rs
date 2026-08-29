use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SETUP_DISK_SERIAL: &str = "CWSETUP1";
pub const SETUP_HEADER_LEN: usize = 64 * 1024;
pub const SETUP_ALIGNMENT: u64 = 4096;
pub const MAX_SETUP_LAYERS: usize = 128;
pub const MAX_SETUP_PROJECT_BYTES: u64 = 256 * 1024;
pub const MAX_SETUP_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_SETUP_LAYER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_SETUP_TOTAL_LAYER_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_SETUP_PACK_BYTES: u64 = 65 * 1024 * 1024 * 1024;
pub const GUEST_ABI_VERSION: u32 = 1;
pub const ROOT_FORMAT_VERSION: u32 = 1;

const ROOT_GENERATION_DOMAIN: &[u8] = b"codewire-oci-root-generation-v1\0";

const MAGIC: &[u8; 8] = b"CWSETUP1";
const FORMAT_VERSION: u16 = 1;
const FIXED_HEADER_END: usize = 224;
const LAYER_ENTRY_LEN: usize = 96;
const CHECKSUM_LEN: usize = 32;
const CHECKSUM_OFFSET: usize = SETUP_HEADER_LEN - CHECKSUM_LEN;

const VERSION_OFFSET: usize = 8;
const HEADER_LEN_OFFSET: usize = 12;
const TOTAL_LEN_OFFSET: usize = 16;
const GUEST_ABI_OFFSET: usize = 24;
const ROOT_FORMAT_OFFSET: usize = 28;
const ARCHITECTURE_OFFSET: usize = 32;
const LAYER_COUNT_OFFSET: usize = 40;
const ROOT_GENERATION_OFFSET: usize = 64;
const MANIFEST_DIGEST_OFFSET: usize = 96;
const PROJECT_OBJECT_OFFSET: usize = 128;
const CONFIG_OBJECT_OFFSET: usize = 176;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Value([u8; 32]);

impl Sha256Value {
    pub fn parse_digest(value: &str) -> Result<Self, SetupError> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or(SetupError::InvalidSha256)?;
        Self::parse_hex(hex)
    }

    pub fn parse_hex(value: &str) -> Result<Self, SetupError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SetupError::InvalidSha256);
        }
        let mut digest = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(digest))
    }

    pub fn calculate(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for Sha256Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Value({self})")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetupArchitecture {
    Amd64 = 1,
    Arm64 = 2,
}

impl TryFrom<u8> for SetupArchitecture {
    type Error = SetupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Amd64),
            2 => Ok(Self::Arm64),
            _ => Err(SetupError::UnsupportedArchitecture),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LayerEncoding {
    Tar = 1,
    Gzip = 2,
    Zstd = 3,
}

impl TryFrom<u8> for LayerEncoding {
    type Error = SetupError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tar),
            2 => Ok(Self::Gzip),
            3 => Ok(Self::Zstd),
            _ => Err(SetupError::UnsupportedLayerEncoding),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupBlob {
    pub size: u64,
    pub sha256: Sha256Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupObject {
    pub offset: u64,
    pub size: u64,
    pub sha256: Sha256Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupLayerBlob {
    pub blob: SetupBlob,
    pub diff_id: Sha256Value,
    pub encoding: LayerEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupLayer {
    pub object: SetupObject,
    pub diff_id: Sha256Value,
    pub encoding: LayerEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupHeader {
    pub total_bytes: u64,
    pub guest_abi_version: u32,
    pub root_format_version: u32,
    pub architecture: SetupArchitecture,
    pub root_generation: Sha256Value,
    pub manifest_sha256: Sha256Value,
    pub project: SetupObject,
    pub config: SetupObject,
    pub layers: Vec<SetupLayer>,
}

impl SetupHeader {
    pub fn layout(
        root_generation: Sha256Value,
        manifest_sha256: Sha256Value,
        architecture: SetupArchitecture,
        project: SetupBlob,
        config: SetupBlob,
        layers: Vec<SetupLayerBlob>,
    ) -> Result<Self, SetupError> {
        if layers.len() > MAX_SETUP_LAYERS {
            return Err(SetupError::TooManyLayers);
        }
        validate_blob(project, 1, MAX_SETUP_PROJECT_BYTES)?;
        validate_blob(config, 1, MAX_SETUP_CONFIG_BYTES)?;

        let mut total_layer_bytes = 0_u64;
        let mut cursor = SETUP_HEADER_LEN as u64;
        let project = place_blob(&mut cursor, project)?;
        let config = place_blob(&mut cursor, config)?;
        let mut placed_layers = Vec::with_capacity(layers.len());
        for layer in layers {
            validate_blob(layer.blob, 1, MAX_SETUP_LAYER_BYTES)?;
            total_layer_bytes = total_layer_bytes
                .checked_add(layer.blob.size)
                .ok_or(SetupError::PackTooLarge)?;
            if total_layer_bytes > MAX_SETUP_TOTAL_LAYER_BYTES {
                return Err(SetupError::PackTooLarge);
            }
            placed_layers.push(SetupLayer {
                object: place_blob(&mut cursor, layer.blob)?,
                diff_id: layer.diff_id,
                encoding: layer.encoding,
            });
        }
        if cursor > MAX_SETUP_PACK_BYTES {
            return Err(SetupError::PackTooLarge);
        }
        let header = Self {
            total_bytes: cursor,
            guest_abi_version: GUEST_ABI_VERSION,
            root_format_version: ROOT_FORMAT_VERSION,
            architecture,
            root_generation,
            manifest_sha256,
            project,
            config,
            layers: placed_layers,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn encode(&self) -> Result<Vec<u8>, SetupError> {
        self.validate()?;
        let mut bytes = vec![0_u8; SETUP_HEADER_LEN];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        put_u16(&mut bytes, VERSION_OFFSET, FORMAT_VERSION);
        put_u32(&mut bytes, HEADER_LEN_OFFSET, SETUP_HEADER_LEN as u32);
        put_u64(&mut bytes, TOTAL_LEN_OFFSET, self.total_bytes);
        put_u32(&mut bytes, GUEST_ABI_OFFSET, self.guest_abi_version);
        put_u32(&mut bytes, ROOT_FORMAT_OFFSET, self.root_format_version);
        bytes[ARCHITECTURE_OFFSET] = self.architecture as u8;
        put_u32(&mut bytes, LAYER_COUNT_OFFSET, self.layers.len() as u32);
        put_digest(&mut bytes, ROOT_GENERATION_OFFSET, self.root_generation);
        put_digest(&mut bytes, MANIFEST_DIGEST_OFFSET, self.manifest_sha256);
        put_object(&mut bytes, PROJECT_OBJECT_OFFSET, self.project);
        put_object(&mut bytes, CONFIG_OBJECT_OFFSET, self.config);
        for (index, layer) in self.layers.iter().enumerate() {
            let offset = FIXED_HEADER_END + index * LAYER_ENTRY_LEN;
            bytes[offset] = layer.encoding as u8;
            put_u64(&mut bytes, offset + 8, layer.object.offset);
            put_u64(&mut bytes, offset + 16, layer.object.size);
            put_digest(&mut bytes, offset + 24, layer.object.sha256);
            put_digest(&mut bytes, offset + 56, layer.diff_id);
        }
        let checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SetupError> {
        if bytes.len() != SETUP_HEADER_LEN {
            return Err(SetupError::WrongHeaderLength(bytes.len()));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(SetupError::BadMagic);
        }
        if get_u16(bytes, VERSION_OFFSET) != FORMAT_VERSION {
            return Err(SetupError::UnsupportedVersion);
        }
        if get_u32(bytes, HEADER_LEN_OFFSET) as usize != SETUP_HEADER_LEN {
            return Err(SetupError::InvalidFraming);
        }
        let expected_checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        if expected_checksum[..] != bytes[CHECKSUM_OFFSET..] {
            return Err(SetupError::ChecksumMismatch);
        }
        if bytes[10..12].iter().any(|byte| *byte != 0)
            || bytes[33..40].iter().any(|byte| *byte != 0)
            || bytes[44..64].iter().any(|byte| *byte != 0)
        {
            return Err(SetupError::NonZeroReserved);
        }
        let count = usize::try_from(get_u32(bytes, LAYER_COUNT_OFFSET))
            .map_err(|_| SetupError::TooManyLayers)?;
        if count > MAX_SETUP_LAYERS {
            return Err(SetupError::TooManyLayers);
        }
        let mut layers = Vec::with_capacity(count);
        for index in 0..count {
            let offset = FIXED_HEADER_END + index * LAYER_ENTRY_LEN;
            if bytes[offset + 1..offset + 8]
                .iter()
                .chain(bytes[offset + 88..offset + LAYER_ENTRY_LEN].iter())
                .any(|byte| *byte != 0)
            {
                return Err(SetupError::NonZeroReserved);
            }
            layers.push(SetupLayer {
                encoding: LayerEncoding::try_from(bytes[offset])?,
                object: SetupObject {
                    offset: get_u64(bytes, offset + 8),
                    size: get_u64(bytes, offset + 16),
                    sha256: get_digest(bytes, offset + 24),
                },
                diff_id: get_digest(bytes, offset + 56),
            });
        }
        let used_end = FIXED_HEADER_END + count * LAYER_ENTRY_LEN;
        if bytes[used_end..CHECKSUM_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SetupError::NonZeroReserved);
        }
        let header = Self {
            total_bytes: get_u64(bytes, TOTAL_LEN_OFFSET),
            guest_abi_version: get_u32(bytes, GUEST_ABI_OFFSET),
            root_format_version: get_u32(bytes, ROOT_FORMAT_OFFSET),
            architecture: SetupArchitecture::try_from(bytes[ARCHITECTURE_OFFSET])?,
            root_generation: get_digest(bytes, ROOT_GENERATION_OFFSET),
            manifest_sha256: get_digest(bytes, MANIFEST_DIGEST_OFFSET),
            project: get_object(bytes, PROJECT_OBJECT_OFFSET),
            config: get_object(bytes, CONFIG_OBJECT_OFFSET),
            layers,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn encoded_sha256(&self) -> Result<Sha256Value, SetupError> {
        Ok(Sha256Value::calculate(&self.encode()?))
    }

    fn validate(&self) -> Result<(), SetupError> {
        if self.guest_abi_version != GUEST_ABI_VERSION
            || self.root_format_version != ROOT_FORMAT_VERSION
        {
            return Err(SetupError::UnsupportedRuntimeFormat);
        }
        if self.layers.len() > MAX_SETUP_LAYERS {
            return Err(SetupError::TooManyLayers);
        }
        validate_object(self.project, 1, MAX_SETUP_PROJECT_BYTES)?;
        validate_object(self.config, 1, MAX_SETUP_CONFIG_BYTES)?;
        if self.root_generation
            != oci_root_generation(self.project.sha256, self.manifest_sha256, self.architecture)
        {
            return Err(SetupError::RootGenerationMismatch);
        }
        let mut cursor = SETUP_HEADER_LEN as u64;
        validate_canonical_object(&mut cursor, self.project)?;
        validate_canonical_object(&mut cursor, self.config)?;
        let mut total_layer_bytes = 0_u64;
        for layer in &self.layers {
            validate_object(layer.object, 1, MAX_SETUP_LAYER_BYTES)?;
            total_layer_bytes = total_layer_bytes
                .checked_add(layer.object.size)
                .ok_or(SetupError::PackTooLarge)?;
            if total_layer_bytes > MAX_SETUP_TOTAL_LAYER_BYTES {
                return Err(SetupError::PackTooLarge);
            }
            validate_canonical_object(&mut cursor, layer.object)?;
        }
        if cursor != self.total_bytes
            || self.total_bytes > MAX_SETUP_PACK_BYTES
            || !self.total_bytes.is_multiple_of(SETUP_ALIGNMENT)
        {
            return Err(SetupError::InvalidLayout);
        }
        Ok(())
    }
}

pub fn oci_root_generation(
    project_sha256: Sha256Value,
    manifest_sha256: Sha256Value,
    architecture: SetupArchitecture,
) -> Sha256Value {
    let mut digest = Sha256::new();
    digest.update(ROOT_GENERATION_DOMAIN);
    digest.update(GUEST_ABI_VERSION.to_le_bytes());
    digest.update(ROOT_FORMAT_VERSION.to_le_bytes());
    digest.update([architecture as u8]);
    digest.update(project_sha256.as_bytes());
    digest.update(manifest_sha256.as_bytes());
    Sha256Value::from_bytes(digest.finalize().into())
}

fn place_blob(cursor: &mut u64, blob: SetupBlob) -> Result<SetupObject, SetupError> {
    let object = SetupObject {
        offset: *cursor,
        size: blob.size,
        sha256: blob.sha256,
    };
    *cursor = align(
        cursor
            .checked_add(blob.size)
            .ok_or(SetupError::PackTooLarge)?,
    )?;
    Ok(object)
}

fn validate_blob(blob: SetupBlob, minimum: u64, maximum: u64) -> Result<(), SetupError> {
    if !(minimum..=maximum).contains(&blob.size) {
        return Err(SetupError::InvalidObjectSize);
    }
    Ok(())
}

fn validate_object(object: SetupObject, minimum: u64, maximum: u64) -> Result<(), SetupError> {
    validate_blob(
        SetupBlob {
            size: object.size,
            sha256: object.sha256,
        },
        minimum,
        maximum,
    )?;
    if object.offset < SETUP_HEADER_LEN as u64 || !object.offset.is_multiple_of(SETUP_ALIGNMENT) {
        return Err(SetupError::InvalidLayout);
    }
    Ok(())
}

fn validate_canonical_object(cursor: &mut u64, object: SetupObject) -> Result<(), SetupError> {
    if object.offset != *cursor {
        return Err(SetupError::InvalidLayout);
    }
    *cursor = align(
        cursor
            .checked_add(object.size)
            .ok_or(SetupError::PackTooLarge)?,
    )?;
    Ok(())
}

fn align(value: u64) -> Result<u64, SetupError> {
    value
        .checked_add(SETUP_ALIGNMENT - 1)
        .map(|value| value / SETUP_ALIGNMENT * SETUP_ALIGNMENT)
        .ok_or(SetupError::PackTooLarge)
}

fn hex_nibble(value: u8) -> Result<u8, SetupError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(SetupError::InvalidSha256),
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
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed field"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}

fn put_digest(bytes: &mut [u8], offset: usize, digest: Sha256Value) {
    bytes[offset..offset + 32].copy_from_slice(&digest.0);
}

fn get_digest(bytes: &[u8], offset: usize) -> Sha256Value {
    Sha256Value(
        bytes[offset..offset + 32]
            .try_into()
            .expect("fixed digest field"),
    )
}

fn put_object(bytes: &mut [u8], offset: usize, object: SetupObject) {
    put_u64(bytes, offset, object.offset);
    put_u64(bytes, offset + 8, object.size);
    put_digest(bytes, offset + 16, object.sha256);
}

fn get_object(bytes: &[u8], offset: usize) -> SetupObject {
    SetupObject {
        offset: get_u64(bytes, offset),
        size: get_u64(bytes, offset + 8),
        sha256: get_digest(bytes, offset + 16),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("setup SHA-256 identity must be lowercase hexadecimal")]
    InvalidSha256,
    #[error("setup header must be exactly {SETUP_HEADER_LEN} bytes (got {0})")]
    WrongHeaderLength(usize),
    #[error("setup header magic is invalid")]
    BadMagic,
    #[error("setup header version is unsupported")]
    UnsupportedVersion,
    #[error("setup header framing is invalid")]
    InvalidFraming,
    #[error("setup header checksum is invalid")]
    ChecksumMismatch,
    #[error("setup header reserved bytes must be zero")]
    NonZeroReserved,
    #[error("setup runtime ABI or root format is unsupported")]
    UnsupportedRuntimeFormat,
    #[error("setup architecture is unsupported")]
    UnsupportedArchitecture,
    #[error("setup layer encoding is unsupported")]
    UnsupportedLayerEncoding,
    #[error("setup header has too many layers")]
    TooManyLayers,
    #[error("setup object size is invalid")]
    InvalidObjectSize,
    #[error("setup object layout is not canonical")]
    InvalidLayout,
    #[error("setup root generation is not bound to its immutable inputs")]
    RootGenerationMismatch,
    #[error("setup pack exceeds its size bound")]
    PackTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &[u8]) -> Sha256Value {
        Sha256Value::calculate(label)
    }

    fn header() -> SetupHeader {
        let project = digest(b"project");
        let manifest = digest(b"manifest");
        let architecture = SetupArchitecture::Amd64;
        SetupHeader::layout(
            oci_root_generation(project, manifest, architecture),
            manifest,
            architecture,
            SetupBlob {
                size: 123,
                sha256: project,
            },
            SetupBlob {
                size: 456,
                sha256: digest(b"config"),
            },
            vec![
                SetupLayerBlob {
                    blob: SetupBlob {
                        size: 789,
                        sha256: digest(b"layer-one"),
                    },
                    diff_id: digest(b"diff-one"),
                    encoding: LayerEncoding::Gzip,
                },
                SetupLayerBlob {
                    blob: SetupBlob {
                        size: 1000,
                        sha256: digest(b"layer-two"),
                    },
                    diff_id: digest(b"diff-two"),
                    encoding: LayerEncoding::Tar,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn setup_header_round_trip_is_exact_canonical_and_stable() {
        let header = header();
        let encoded = header.encode().unwrap();
        assert_eq!(encoded.len(), SETUP_HEADER_LEN);
        assert_eq!(&encoded[..8], MAGIC);
        assert_eq!(SetupHeader::decode(&encoded).unwrap(), header);
        assert_eq!(header.project.offset, SETUP_HEADER_LEN as u64);
        assert_eq!(header.project.offset % SETUP_ALIGNMENT, 0);
        assert_eq!(header.config.offset % SETUP_ALIGNMENT, 0);
        assert_eq!(header.layers[0].object.offset % SETUP_ALIGNMENT, 0);
        assert_eq!(header.total_bytes % SETUP_ALIGNMENT, 0);
        assert_eq!(header.encoded_sha256().unwrap(), digest(&encoded));
        assert_eq!(
            header.encoded_sha256().unwrap().to_string(),
            "1ef6b47480fa328a0927e064d7974fe833f62e59ce250c34bffc088e7b7308b9"
        );
    }

    #[test]
    fn setup_header_rejects_corruption_reserved_bytes_and_noncanonical_layout() {
        let mut encoded = header().encode().unwrap();
        encoded[1000] ^= 1;
        assert_eq!(
            SetupHeader::decode(&encoded),
            Err(SetupError::ChecksumMismatch)
        );

        let mut encoded = header().encode().unwrap();
        encoded[1000] = 1;
        let checksum = Sha256::digest(&encoded[..CHECKSUM_OFFSET]);
        encoded[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert_eq!(
            SetupHeader::decode(&encoded),
            Err(SetupError::NonZeroReserved)
        );

        let mut invalid = header();
        invalid.layers[0].object.offset += SETUP_ALIGNMENT;
        assert_eq!(invalid.encode(), Err(SetupError::InvalidLayout));
    }

    #[test]
    fn setup_header_rejects_unbounded_or_ambiguous_input() {
        let too_many = vec![
            SetupLayerBlob {
                blob: SetupBlob {
                    size: 1,
                    sha256: digest(b"layer"),
                },
                diff_id: digest(b"diff"),
                encoding: LayerEncoding::Gzip,
            };
            MAX_SETUP_LAYERS + 1
        ];
        assert_eq!(
            SetupHeader::layout(
                digest(b"root"),
                digest(b"manifest"),
                SetupArchitecture::Arm64,
                SetupBlob {
                    size: 1,
                    sha256: digest(b"project"),
                },
                SetupBlob {
                    size: 1,
                    sha256: digest(b"config"),
                },
                too_many,
            ),
            Err(SetupError::TooManyLayers)
        );
        assert_eq!(
            Sha256Value::parse_hex(&"A".repeat(64)),
            Err(SetupError::InvalidSha256)
        );
        assert_eq!(
            Sha256Value::parse_digest(&format!("sha512:{}", "a".repeat(64))),
            Err(SetupError::InvalidSha256)
        );
    }
}
