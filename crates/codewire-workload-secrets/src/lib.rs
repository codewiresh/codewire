#![forbid(unsafe_code)]

//! Bounded, deterministic codec for one-boot workload-secret delivery.
//!
//! The encoded bytes are intended only for an owner-private tmpfs staging
//! file which is attached to one VM boot and removed after guest readiness.
//! Debug and error values never render secret material.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const WORKLOAD_SECRET_DISK_SERIAL: &str = "CWSECRET1";
pub const WORKLOAD_SECRET_ALIGNMENT: u64 = 4096;
pub const MAX_WORKLOAD_SECRETS: usize = 256;
pub const MAX_WORKLOAD_SECRET_KEY_BYTES: usize = 256;
pub const MAX_WORKLOAD_SECRET_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_WORKLOAD_SECRET_DISK_BYTES: u64 = 16 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"CWSECR1\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 64;
const VERSION_OFFSET: usize = 8;
const HEADER_LEN_OFFSET: usize = 10;
const PAYLOAD_LEN_OFFSET: usize = 12;
const ENTRY_COUNT_OFFSET: usize = 20;
const RESERVED_OFFSET: usize = 24;
pub const WORKLOAD_SECRET_RUNTIME_NAMESPACE: &str = "codewire/workload-secrets-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadSecretSource {
    Organization,
    Project,
    User,
    ExplicitEnvironment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedWorkloadSecretMetadata {
    pub key: String,
    pub source: WorkloadSecretSource,
    pub overridden_sources: Vec<WorkloadSecretSource>,
}

/// Resolves key-only source metadata supplied from lowest to highest precedence.
pub fn resolve_workload_secret_metadata<'a>(
    source_keys: impl IntoIterator<Item = (WorkloadSecretSource, &'a str)>,
) -> Result<Vec<ResolvedWorkloadSecretMetadata>, WorkloadSecretCodecError> {
    let mut sources = BTreeMap::<String, Vec<WorkloadSecretSource>>::new();
    let mut previous_source = None;
    for (source, key) in source_keys {
        if previous_source.is_some_and(|previous| source < previous) {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        previous_source = Some(source);
        validate_workload_secret_metadata_key(key)?;
        let entry = sources.entry(key.to_owned()).or_default();
        if entry.last() == Some(&source) {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        entry.push(source);
        if sources.len() > MAX_WORKLOAD_SECRETS {
            return Err(WorkloadSecretCodecError::InvalidEntryCount);
        }
    }
    sources
        .into_iter()
        .map(|(key, mut ordered)| {
            let source = ordered
                .pop()
                .ok_or(WorkloadSecretCodecError::InvalidEntryCount)?;
            Ok(ResolvedWorkloadSecretMetadata {
                key,
                source,
                overridden_sources: ordered,
            })
        })
        .collect()
}

pub fn workload_secret_delivery_relative_path(
    environment_id: Uuid,
    generation: u64,
) -> Result<std::path::PathBuf, WorkloadSecretCodecError> {
    if environment_id.is_nil() || generation == 0 {
        return Err(WorkloadSecretCodecError::InvalidBinding);
    }
    Ok(std::path::Path::new(WORKLOAD_SECRET_RUNTIME_NAMESPACE)
        .join(environment_id.to_string())
        .join(format!("{generation}.raw")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WorkloadSecretBinding {
    total_bytes: u64,
    sha256: [u8; 32],
    entry_count: u32,
}

impl WorkloadSecretBinding {
    pub fn new(
        total_bytes: u64,
        sha256: [u8; 32],
        entry_count: u32,
    ) -> Result<Self, WorkloadSecretCodecError> {
        let binding = Self {
            total_bytes,
            sha256,
            entry_count,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    pub fn sha256(self) -> [u8; 32] {
        self.sha256
    }

    pub fn entry_count(self) -> u32 {
        self.entry_count
    }

    fn validate(self) -> Result<(), WorkloadSecretCodecError> {
        if self.total_bytes < WORKLOAD_SECRET_ALIGNMENT
            || self.total_bytes > MAX_WORKLOAD_SECRET_DISK_BYTES
            || !self.total_bytes.is_multiple_of(WORKLOAD_SECRET_ALIGNMENT)
            || self.entry_count == 0
            || usize::try_from(self.entry_count).unwrap_or(usize::MAX) > MAX_WORKLOAD_SECRETS
        {
            return Err(WorkloadSecretCodecError::InvalidBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for WorkloadSecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadSecretBinding")
            .field("total_bytes", &self.total_bytes)
            .field("sha256", &hex_digest(self.sha256))
            .field("entry_count", &self.entry_count)
            .finish()
    }
}

pub struct EncodedWorkloadSecrets {
    bytes: Zeroizing<Vec<u8>>,
    binding: WorkloadSecretBinding,
}

impl EncodedWorkloadSecrets {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn binding(&self) -> WorkloadSecretBinding {
        self.binding
    }
}

impl fmt::Debug for EncodedWorkloadSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedWorkloadSecrets")
            .field("binding", &self.binding)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub struct DecodedWorkloadSecrets {
    entries: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

impl DecodedWorkloadSecrets {
    pub fn entries(&self) -> &BTreeMap<String, Zeroizing<Vec<u8>>> {
        &self.entries
    }
}

impl fmt::Debug for DecodedWorkloadSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedWorkloadSecrets")
            .field("keys", &self.entries.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

pub fn encode_workload_secrets<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<EncodedWorkloadSecrets, WorkloadSecretCodecError> {
    let entries = entries.into_iter().collect::<Vec<_>>();
    if entries.is_empty() || entries.len() > MAX_WORKLOAD_SECRETS {
        return Err(WorkloadSecretCodecError::InvalidEntryCount);
    }
    let mut previous = None;
    let mut payload_len = 0_usize;
    for (key, value) in &entries {
        validate_workload_secret_key(key)?;
        validate_workload_secret_value(value)?;
        if previous.is_some_and(|previous| previous >= *key) {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        previous = Some(*key);
        payload_len = payload_len
            .checked_add(8)
            .and_then(|length| length.checked_add(key.len()))
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(WorkloadSecretCodecError::TooLarge)?;
    }
    let unaligned = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WorkloadSecretCodecError::TooLarge)?;
    let aligned = align_up(unaligned)?;
    if u64::try_from(aligned).map_err(|_| WorkloadSecretCodecError::TooLarge)?
        > MAX_WORKLOAD_SECRET_DISK_BYTES
    {
        return Err(WorkloadSecretCodecError::TooLarge);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; aligned]);
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    put_u16(&mut bytes, VERSION_OFFSET, VERSION);
    put_u16(&mut bytes, HEADER_LEN_OFFSET, HEADER_LEN as u16);
    put_u64(
        &mut bytes,
        PAYLOAD_LEN_OFFSET,
        u64::try_from(payload_len).map_err(|_| WorkloadSecretCodecError::TooLarge)?,
    );
    put_u32(
        &mut bytes,
        ENTRY_COUNT_OFFSET,
        u32::try_from(entries.len()).map_err(|_| WorkloadSecretCodecError::TooLarge)?,
    );
    let mut offset = HEADER_LEN;
    for (key, value) in entries {
        put_u16(
            &mut bytes,
            offset,
            u16::try_from(key.len()).map_err(|_| WorkloadSecretCodecError::InvalidKey)?,
        );
        put_u16(&mut bytes, offset + 2, 0);
        put_u32(
            &mut bytes,
            offset + 4,
            u32::try_from(value.len()).map_err(|_| WorkloadSecretCodecError::InvalidValue)?,
        );
        offset += 8;
        bytes[offset..offset + key.len()].copy_from_slice(key.as_bytes());
        offset += key.len();
        bytes[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();
    }
    let sha256: [u8; 32] = Sha256::digest(&*bytes).into();
    let binding = WorkloadSecretBinding::new(
        u64::try_from(bytes.len()).map_err(|_| WorkloadSecretCodecError::TooLarge)?,
        sha256,
        get_u32(&bytes, ENTRY_COUNT_OFFSET),
    )?;
    Ok(EncodedWorkloadSecrets { bytes, binding })
}

pub fn decode_workload_secrets(
    bytes: &[u8],
    binding: WorkloadSecretBinding,
) -> Result<DecodedWorkloadSecrets, WorkloadSecretCodecError> {
    binding.validate()?;
    if u64::try_from(bytes.len()).ok() != Some(binding.total_bytes)
        || !bytes
            .len()
            .is_multiple_of(WORKLOAD_SECRET_ALIGNMENT as usize)
        || <[u8; 32]>::from(Sha256::digest(bytes)) != binding.sha256
        || bytes.len() < HEADER_LEN
        || &bytes[..MAGIC.len()] != MAGIC
        || get_u16(bytes, VERSION_OFFSET) != VERSION
        || usize::from(get_u16(bytes, HEADER_LEN_OFFSET)) != HEADER_LEN
        || get_u32(bytes, ENTRY_COUNT_OFFSET) != binding.entry_count
        || bytes[RESERVED_OFFSET..HEADER_LEN]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(WorkloadSecretCodecError::InvalidBinding);
    }
    let payload_len = usize::try_from(get_u64(bytes, PAYLOAD_LEN_OFFSET))
        .map_err(|_| WorkloadSecretCodecError::InvalidFraming)?;
    let payload_end = HEADER_LEN
        .checked_add(payload_len)
        .filter(|end| *end <= bytes.len())
        .ok_or(WorkloadSecretCodecError::InvalidFraming)?;
    if bytes[payload_end..].iter().any(|byte| *byte != 0) {
        return Err(WorkloadSecretCodecError::NonZeroPadding);
    }
    let mut entries = BTreeMap::new();
    let mut offset = HEADER_LEN;
    let mut previous_key: Option<String> = None;
    for _ in 0..binding.entry_count {
        if offset.checked_add(8).is_none_or(|end| end > payload_end) {
            return Err(WorkloadSecretCodecError::InvalidFraming);
        }
        let key_len = usize::from(get_u16(bytes, offset));
        if get_u16(bytes, offset + 2) != 0 {
            return Err(WorkloadSecretCodecError::InvalidFraming);
        }
        let value_len = usize::try_from(get_u32(bytes, offset + 4))
            .map_err(|_| WorkloadSecretCodecError::InvalidFraming)?;
        offset += 8;
        let key_end = offset
            .checked_add(key_len)
            .filter(|end| *end <= payload_end)
            .ok_or(WorkloadSecretCodecError::InvalidFraming)?;
        let key = std::str::from_utf8(&bytes[offset..key_end])
            .map_err(|_| WorkloadSecretCodecError::InvalidKey)?
            .to_owned();
        validate_workload_secret_key(&key)?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
        previous_key = Some(key.clone());
        offset = key_end;
        let value_end = offset
            .checked_add(value_len)
            .filter(|end| *end <= payload_end)
            .ok_or(WorkloadSecretCodecError::InvalidFraming)?;
        let value = Zeroizing::new(bytes[offset..value_end].to_vec());
        validate_workload_secret_value(&value)?;
        offset = value_end;
        if entries.insert(key, value).is_some() {
            return Err(WorkloadSecretCodecError::NonCanonicalOrdering);
        }
    }
    if offset != payload_end
        || entries.len() != usize::try_from(binding.entry_count).unwrap_or(usize::MAX)
    {
        return Err(WorkloadSecretCodecError::InvalidFraming);
    }
    Ok(DecodedWorkloadSecrets { entries })
}

/// Validates one canonical environment-style workload-secret key.
pub fn validate_workload_secret_key(key: &str) -> Result<(), WorkloadSecretCodecError> {
    let mut bytes = key.bytes();
    if key.is_empty()
        || key.len() > MAX_WORKLOAD_SECRET_KEY_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(WorkloadSecretCodecError::InvalidKey);
    }
    Ok(())
}

/// Validates key-only resolution metadata across legacy platform and local
/// sources. Platform storage historically permits an ASCII digit first;
/// local delivery retains the stricter [`validate_workload_secret_key`]
/// grammar before values can be encoded.
pub fn validate_workload_secret_metadata_key(key: &str) -> Result<(), WorkloadSecretCodecError> {
    if key.is_empty()
        || key.len() > MAX_WORKLOAD_SECRET_KEY_BYTES
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(WorkloadSecretCodecError::InvalidKey);
    }
    Ok(())
}

/// Validates one workload-secret value without rendering or retaining it.
pub fn validate_workload_secret_value(value: &[u8]) -> Result<(), WorkloadSecretCodecError> {
    if value.is_empty()
        || value.len() > MAX_WORKLOAD_SECRET_VALUE_BYTES
        || value.contains(&0)
        || std::str::from_utf8(value).is_err()
    {
        return Err(WorkloadSecretCodecError::InvalidValue);
    }
    Ok(())
}

fn align_up(value: usize) -> Result<usize, WorkloadSecretCodecError> {
    let alignment = WORKLOAD_SECRET_ALIGNMENT as usize;
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(WorkloadSecretCodecError::TooLarge)
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
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("bounded field"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded field"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("bounded field"))
}

fn hex_digest(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WorkloadSecretCodecError {
    #[error("workload-secret binding is invalid")]
    InvalidBinding,
    #[error("workload-secret entry count is invalid")]
    InvalidEntryCount,
    #[error("workload-secret key is invalid")]
    InvalidKey,
    #[error("workload-secret value is invalid")]
    InvalidValue,
    #[error("workload-secret entries are not canonically ordered")]
    NonCanonicalOrdering,
    #[error("workload-secret delivery is too large")]
    TooLarge,
    #[error("workload-secret delivery framing is invalid")]
    InvalidFraming,
    #[error("workload-secret delivery padding is nonzero")]
    NonZeroPadding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_deterministic_and_debug_is_redacted() {
        let entries = BTreeMap::from([
            ("FIRST".to_owned(), b"synthetic-one".to_vec()),
            ("SECOND".to_owned(), b"synthetic-two".to_vec()),
        ]);
        let encoded = encode_workload_secrets(
            entries
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_slice())),
        )
        .unwrap();
        let decoded = decode_workload_secrets(encoded.bytes(), encoded.binding()).unwrap();
        assert_eq!(decoded.entries()["FIRST"].as_slice(), b"synthetic-one");
        assert!(!format!("{encoded:?} {decoded:?}").contains("synthetic"));
        let repeated = encode_workload_secrets(
            entries
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_slice())),
        )
        .unwrap();
        assert_eq!(encoded.bytes(), repeated.bytes());
    }

    #[test]
    fn corruption_ordering_and_oversize_fail_closed() {
        assert_eq!(
            encode_workload_secrets([("B", &b"two"[..]), ("A", &b"one"[..])]).unwrap_err(),
            WorkloadSecretCodecError::NonCanonicalOrdering
        );
        assert_eq!(
            encode_workload_secrets([("BAD-KEY", &b"one"[..])]).unwrap_err(),
            WorkloadSecretCodecError::InvalidKey
        );
        let encoded = encode_workload_secrets([("A", &b"one"[..])]).unwrap();
        let mut corrupt = encoded.bytes().to_vec();
        corrupt[HEADER_LEN] ^= 1;
        assert!(decode_workload_secrets(&corrupt, encoded.binding()).is_err());
    }

    #[test]
    fn shared_value_validation_is_bounded_and_content_preserving() {
        assert!(validate_workload_secret_value(b" leading and trailing \n").is_ok());
        assert!(validate_workload_secret_value(b"").is_err());
        assert!(validate_workload_secret_value(b"contains\0nul").is_err());
        assert!(validate_workload_secret_value(&[0xff]).is_err());
        assert!(
            validate_workload_secret_value(&vec![b'x'; MAX_WORKLOAD_SECRET_VALUE_BYTES]).is_ok()
        );
        assert!(
            validate_workload_secret_value(&vec![b'x'; MAX_WORKLOAD_SECRET_VALUE_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn metadata_resolution_is_sorted_bounded_and_uses_last_source_as_winner() {
        let inputs = [
            (WorkloadSecretSource::Organization, "SHARED"),
            (WorkloadSecretSource::Project, "PROJECT_ONLY"),
            (WorkloadSecretSource::Project, "SHARED"),
            (WorkloadSecretSource::User, "SHARED"),
            (WorkloadSecretSource::ExplicitEnvironment, "EXPLICIT"),
            (WorkloadSecretSource::ExplicitEnvironment, "SHARED"),
        ];
        assert_eq!(
            resolve_workload_secret_metadata(inputs).unwrap(),
            vec![
                ResolvedWorkloadSecretMetadata {
                    key: "EXPLICIT".into(),
                    source: WorkloadSecretSource::ExplicitEnvironment,
                    overridden_sources: vec![],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "PROJECT_ONLY".into(),
                    source: WorkloadSecretSource::Project,
                    overridden_sources: vec![],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "SHARED".into(),
                    source: WorkloadSecretSource::ExplicitEnvironment,
                    overridden_sources: vec![
                        WorkloadSecretSource::Organization,
                        WorkloadSecretSource::Project,
                        WorkloadSecretSource::User,
                    ],
                },
            ]
        );
        assert!(
            resolve_workload_secret_metadata([
                (WorkloadSecretSource::User, "SHARED"),
                (WorkloadSecretSource::Project, "SHARED"),
            ])
            .is_err()
        );
        assert!(
            resolve_workload_secret_metadata([
                (WorkloadSecretSource::User, "SHARED"),
                (WorkloadSecretSource::User, "SHARED"),
            ])
            .is_err()
        );
        assert_eq!(
            resolve_workload_secret_metadata([(
                WorkloadSecretSource::Organization,
                "1LEGACY_PLATFORM_KEY",
            )])
            .unwrap()[0]
                .key,
            "1LEGACY_PLATFORM_KEY"
        );
        assert!(
            resolve_workload_secret_metadata([(WorkloadSecretSource::Organization, "unsafe/key",)])
                .is_err()
        );
    }
}
