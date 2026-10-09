//! Schema-2 `cw` payload identity, release targets and executable admission.
//!
//! [`CwPayloadIdentity`] keeps the exact field names and protocol/record
//! semantics of the `cw-runtime.json` document carried by the cw OCI image
//! layer and native runtime pack. This crate widens only the target set to the
//! four published release targets. Native runtime admission remains stricter:
//! it accepts only static `x86_64-unknown-linux-musl` payloads built with its
//! pinned toolchain.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const PAYLOAD_SCHEMA_VERSION: u32 = 2;
/// Helper/control protocol understood by this build.
pub const PROTOCOL_VERSION: u32 = 1;
/// Managed record format understood by this build.
pub const RECORD_VERSION: u32 = 1;
pub const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
/// Smallest executable whose object header can be admitted.
pub const MIN_EXECUTABLE_BYTES: u64 = 64;
pub const MAX_IDENTITY_BYTES: usize = 16 * 1024;
/// Executable header bytes inspected by [`Platform::validate_executable_header`].
pub const EXECUTABLE_HEADER_BYTES: usize = 64;

const MAX_PACKAGE_VERSION: usize = 64;
const MAX_RUSTC: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("cw identity is empty or exceeds its {MAX_IDENTITY_BYTES}-byte bound")]
    Bounds,
    #[error("cw identity is not a valid JSON identity document")]
    Malformed,
    #[error("unsupported cw identity: {0}")]
    Unsupported(&'static str),
    #[error("cw release target {0:?} is not supported")]
    UnsupportedTarget(String),
    #[error("cw executable is not a {0} executable")]
    ExecutableFormat(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Linux,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// Operating system and architecture that can execute a `cw` binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
}

impl Platform {
    pub const ALL: [Self; 4] = [
        Self::new(Os::Linux, Arch::X86_64),
        Self::new(Os::Linux, Arch::Aarch64),
        Self::new(Os::Macos, Arch::X86_64),
        Self::new(Os::Macos, Arch::Aarch64),
    ];

    pub const fn new(os: Os, arch: Arch) -> Self {
        Self { os, arch }
    }

    /// The platform this build runs on, when releases support it.
    pub fn host() -> Option<Self> {
        let os = if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            return None;
        };
        let arch = if cfg!(target_arch = "x86_64") {
            Arch::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            return None;
        };
        Some(Self::new(os, arch))
    }

    pub fn as_str(self) -> &'static str {
        match (self.os, self.arch) {
            (Os::Linux, Arch::X86_64) => "linux-x86_64",
            (Os::Linux, Arch::Aarch64) => "linux-aarch64",
            (Os::Macos, Arch::X86_64) => "macos-x86_64",
            (Os::Macos, Arch::Aarch64) => "macos-aarch64",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|platform| platform.as_str() == value)
    }

    /// The single published release target for this platform.
    pub fn release_target(self) -> ReleaseTarget {
        match (self.os, self.arch) {
            (Os::Linux, Arch::X86_64) => ReleaseTarget::X86_64UnknownLinuxMusl,
            (Os::Linux, Arch::Aarch64) => ReleaseTarget::Aarch64UnknownLinuxGnu,
            (Os::Macos, Arch::X86_64) => ReleaseTarget::X86_64AppleDarwin,
            (Os::Macos, Arch::Aarch64) => ReleaseTarget::Aarch64AppleDarwin,
        }
    }

    /// Admit only a single-architecture 64-bit executable for this platform.
    /// The bytes are inspected, never executed.
    pub fn validate_executable_header(self, header: &[u8]) -> Result<(), IdentityError> {
        match self.os {
            Os::Linux => {
                let machine = match self.arch {
                    Arch::X86_64 => 62_u16,
                    Arch::Aarch64 => 183,
                };
                let valid = header.len() >= EXECUTABLE_HEADER_BYTES
                    && header[..4] == *b"\x7fELF"
                    && header[4] == 2
                    && header[5] == 1
                    && header[6] == 1
                    && matches!(header[7], 0 | 3)
                    && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
                    && u16::from_le_bytes([header[18], header[19]]) == machine;
                if valid {
                    Ok(())
                } else {
                    Err(IdentityError::ExecutableFormat(self.as_str()))
                }
            }
            Os::Macos => {
                let cpu_type = match self.arch {
                    Arch::X86_64 => 0x0100_0007_u32,
                    Arch::Aarch64 => 0x0100_000c,
                };
                let word = |offset: usize| {
                    u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap())
                };
                let valid = header.len() >= EXECUTABLE_HEADER_BYTES
                    && word(0) == 0xfeed_facf
                    && word(4) == cpu_type
                    && word(12) == 2;
                if valid {
                    Ok(())
                } else {
                    Err(IdentityError::ExecutableFormat(self.as_str()))
                }
            }
        }
    }
}

/// The four targets for which `cw` release assets are published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReleaseTarget {
    X86_64UnknownLinuxMusl,
    Aarch64UnknownLinuxGnu,
    X86_64AppleDarwin,
    Aarch64AppleDarwin,
}

impl ReleaseTarget {
    pub const ALL: [Self; 4] = [
        Self::X86_64UnknownLinuxMusl,
        Self::Aarch64UnknownLinuxGnu,
        Self::X86_64AppleDarwin,
        Self::Aarch64AppleDarwin,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64UnknownLinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64UnknownLinuxGnu => "aarch64-unknown-linux-gnu",
            Self::X86_64AppleDarwin => "x86_64-apple-darwin",
            Self::Aarch64AppleDarwin => "aarch64-apple-darwin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|target| target.as_str() == value)
    }

    pub fn platform(self) -> Platform {
        match self {
            Self::X86_64UnknownLinuxMusl => Platform::new(Os::Linux, Arch::X86_64),
            Self::Aarch64UnknownLinuxGnu => Platform::new(Os::Linux, Arch::Aarch64),
            Self::X86_64AppleDarwin => Platform::new(Os::Macos, Arch::X86_64),
            Self::Aarch64AppleDarwin => Platform::new(Os::Macos, Arch::Aarch64),
        }
    }
}

/// Public identity of one release executable: the `cw-runtime.json` schema-2
/// document. Field names and meanings are a shared contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwPayloadIdentity {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub record_version: u32,
    pub package_version: String,
    pub target: String,
    pub source_revision: String,
    pub source_tree_sha256: String,
    pub rustc: String,
    pub sha256: String,
    pub size: u64,
}

impl CwPayloadIdentity {
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
            return Err(IdentityError::Bounds);
        }
        let identity: Self = serde_json::from_slice(bytes).map_err(|_| IdentityError::Malformed)?;
        identity.validate()?;
        Ok(identity)
    }

    /// Validate every field and return the declared release target. Unknown
    /// schema, protocol or record versions are refused rather than guessed.
    pub fn validate(&self) -> Result<ReleaseTarget, IdentityError> {
        if self.schema_version != PAYLOAD_SCHEMA_VERSION {
            return Err(IdentityError::Unsupported("schema_version"));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(IdentityError::Unsupported("protocol_version"));
        }
        if self.record_version != RECORD_VERSION {
            return Err(IdentityError::Unsupported("record_version"));
        }
        if !valid_package_version(&self.package_version) {
            return Err(IdentityError::Unsupported("package_version"));
        }
        let target = ReleaseTarget::parse(&self.target)
            .ok_or_else(|| IdentityError::UnsupportedTarget(self.target.clone()))?;
        if !is_lower_hex(&self.source_revision, 40) {
            return Err(IdentityError::Unsupported("source_revision"));
        }
        if !is_sha256_hex(&self.source_tree_sha256) {
            return Err(IdentityError::Unsupported("source_tree_sha256"));
        }
        if !self.rustc.starts_with("rustc ")
            || self.rustc.len() > MAX_RUSTC
            || !self.rustc.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(IdentityError::Unsupported("rustc"));
        }
        if !is_sha256_hex(&self.sha256) {
            return Err(IdentityError::Unsupported("sha256"));
        }
        if !(MIN_EXECUTABLE_BYTES..=MAX_EXECUTABLE_BYTES).contains(&self.size) {
            return Err(IdentityError::Unsupported("size"));
        }
        Ok(target)
    }

    /// Canonical bytes: sorted keys, compact separators and one trailing
    /// newline, matching the image producer's encoding.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        self.validate()?;
        canonical_json(self)
    }
}

pub fn valid_package_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PACKAGE_VERSION
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

pub fn is_sha256_hex(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Serialize ASCII-only JSON with recursively sorted object keys, compact
/// separators and a trailing newline. Non-ASCII strings are refused so the
/// bytes match encoders that escape them.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    let value = serde_json::to_value(value).map_err(|_| IdentityError::Malformed)?;
    let mut bytes =
        serde_json::to_vec(&Canonical::from(value)?).map_err(|_| IdentityError::Malformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

enum Canonical {
    Leaf(serde_json::Value),
    Array(Vec<Canonical>),
    Object(BTreeMap<String, Canonical>),
}

impl Canonical {
    fn from(value: serde_json::Value) -> Result<Self, IdentityError> {
        Ok(match value {
            serde_json::Value::String(text) if !text.is_ascii() => {
                return Err(IdentityError::Malformed);
            }
            serde_json::Value::Array(items) => Self::Array(
                items
                    .into_iter()
                    .map(Self::from)
                    .collect::<Result<_, _>>()?,
            ),
            serde_json::Value::Object(entries) => Self::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| {
                        if key.is_ascii() {
                            Ok((key, Self::from(value)?))
                        } else {
                            Err(IdentityError::Malformed)
                        }
                    })
                    .collect::<Result<_, _>>()?,
            ),
            leaf => Self::Leaf(leaf),
        })
    }
}

impl Serialize for Canonical {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Leaf(value) => value.serialize(serializer),
            Self::Array(items) => items.serialize(serializer),
            Self::Object(entries) => entries.serialize(serializer),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn identity(target: &str) -> CwPayloadIdentity {
        CwPayloadIdentity {
            schema_version: 2,
            protocol_version: 1,
            record_version: 1,
            package_version: "0.1.0".into(),
            target: target.into(),
            source_revision: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            rustc: "rustc 1.93.0 (synthetic 2026-01-01)".into(),
            sha256: "c".repeat(64),
            size: 4096,
        }
    }

    #[test]
    fn every_release_target_is_admitted_and_maps_to_one_platform() {
        for target in ReleaseTarget::ALL {
            let value = identity(target.as_str());
            assert_eq!(value.validate(), Ok(target));
            assert_eq!(target.platform().release_target(), target);
            assert_eq!(
                Platform::parse(target.platform().as_str()),
                Some(target.platform())
            );
        }
        for unsupported in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", ""] {
            assert_eq!(
                identity(unsupported).validate(),
                Err(IdentityError::UnsupportedTarget(unsupported.into()))
            );
        }
    }

    #[test]
    fn canonical_encoding_sorts_keys_and_round_trips() {
        let value = identity("x86_64-unknown-linux-musl");
        let bytes = value.encode().unwrap();
        let expected = format!(
            concat!(
                "{{\"package_version\":\"0.1.0\",\"protocol_version\":1,\"record_version\":1,",
                "\"rustc\":\"rustc 1.93.0 (synthetic 2026-01-01)\",\"schema_version\":2,",
                "\"sha256\":\"{}\",\"size\":4096,\"source_revision\":\"{}\",",
                "\"source_tree_sha256\":\"{}\",\"target\":\"x86_64-unknown-linux-musl\"}}\n"
            ),
            "c".repeat(64),
            "a".repeat(40),
            "b".repeat(64)
        );
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), expected);
        assert_eq!(CwPayloadIdentity::decode(&bytes).unwrap(), value);
    }

    #[test]
    fn decode_refuses_unknown_duplicate_oversized_and_unsupported_fields() {
        let bytes = identity("aarch64-apple-darwin").encode().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let unknown = text.replacen('{', "{\"extra\":1,", 1);
        assert_eq!(
            CwPayloadIdentity::decode(unknown.as_bytes()),
            Err(IdentityError::Malformed)
        );
        let duplicate = text.replacen('{', "{\"size\":1,", 1);
        assert_eq!(
            CwPayloadIdentity::decode(duplicate.as_bytes()),
            Err(IdentityError::Malformed)
        );
        assert_eq!(
            CwPayloadIdentity::decode(&vec![b' '; MAX_IDENTITY_BYTES + 1]),
            Err(IdentityError::Bounds)
        );
        for (field, mutate) in [
            (
                "schema_version",
                Box::new(|v: &mut CwPayloadIdentity| v.schema_version = 3)
                    as Box<dyn Fn(&mut CwPayloadIdentity)>,
            ),
            ("protocol_version", Box::new(|v| v.protocol_version = 2)),
            ("record_version", Box::new(|v| v.record_version = 0)),
            (
                "package_version",
                Box::new(|v| v.package_version = "1.0 beta".into()),
            ),
            (
                "source_revision",
                Box::new(|v| v.source_revision = "A".repeat(40)),
            ),
            (
                "source_tree_sha256",
                Box::new(|v| v.source_tree_sha256 = "b".repeat(63)),
            ),
            ("rustc", Box::new(|v| v.rustc = "cargo 1.93.0".into())),
            ("sha256", Box::new(|v| v.sha256 = "g".repeat(64))),
            ("size", Box::new(|v| v.size = MAX_EXECUTABLE_BYTES + 1)),
        ] {
            let mut value = identity("aarch64-unknown-linux-gnu");
            mutate(&mut value);
            assert_eq!(
                value.validate(),
                Err(IdentityError::Unsupported(field)),
                "{field}"
            );
        }
    }

    #[test]
    fn executable_headers_are_admitted_only_for_their_platform() {
        let mut elf = vec![0_u8; EXECUTABLE_HEADER_BYTES];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 3;
        elf[18] = 62;
        let linux_x86 = Platform::new(Os::Linux, Arch::X86_64);
        let linux_arm = Platform::new(Os::Linux, Arch::Aarch64);
        assert_eq!(linux_x86.validate_executable_header(&elf), Ok(()));
        assert!(linux_arm.validate_executable_header(&elf).is_err());
        elf[18] = 183;
        assert_eq!(linux_arm.validate_executable_header(&elf), Ok(()));
        elf[4] = 1;
        assert!(linux_arm.validate_executable_header(&elf).is_err());

        let mut macho = vec![0_u8; EXECUTABLE_HEADER_BYTES];
        macho[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        macho[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        macho[12..16].copy_from_slice(&2_u32.to_le_bytes());
        let mac_arm = Platform::new(Os::Macos, Arch::Aarch64);
        let mac_x86 = Platform::new(Os::Macos, Arch::X86_64);
        assert_eq!(mac_arm.validate_executable_header(&macho), Ok(()));
        assert!(mac_x86.validate_executable_header(&macho).is_err());
        assert!(linux_x86.validate_executable_header(&macho).is_err());
        // Universal binaries and short headers are refused.
        let mut fat = macho.clone();
        fat[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
        assert!(mac_arm.validate_executable_header(&fat).is_err());
        assert!(mac_arm.validate_executable_header(&macho[..32]).is_err());
    }

    #[test]
    fn canonical_json_refuses_non_ascii_text() {
        let mut value = identity("x86_64-apple-darwin");
        value.rustc = "rustc 1.93.0 (é)".into();
        assert!(canonical_json(&value).is_err());
    }
}
