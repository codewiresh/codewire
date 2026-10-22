//! Closed public release documents. These functions perform no I/O and grant
//! no trust: the caller must verify the exact bytes with the compiled key.

use std::cmp::Ordering;

use crate::sha256::Sha256;
use serde::{Deserialize, Serialize};

use crate::identity::{
    CwPayloadIdentity, MAX_EXECUTABLE_BYTES, Platform, ReleaseTarget, canonical_json, is_sha256_hex,
};

pub const MAX_JSON_BYTES: usize = 64 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub(crate) const MAX_OBJECT_BYTES: u64 = MAX_EXECUTABLE_BYTES + 8 * 1024 * 1024;
const RELEASE_SCHEMA: &str = "codewire.cw.release/v1";
const CHANNEL_SCHEMA: &str = "codewire.cw.channel/v1";
const TARGET_ORDER: [&str; 4] = [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("release document is empty or exceeds its bound")]
    Bounds,
    #[error("release document is malformed, noncanonical or has unexpected fields")]
    Malformed,
    #[error("release document contradicts its {0}")]
    Invalid(&'static str),
    #[error("release object bytes differ from their signed digest or size")]
    ObjectMismatch,
    #[error(
        "stable channel would downgrade the verified installed version; use an explicit --version or rollback for an intentional downgrade"
    )]
    Downgrade,
    #[error("stable channel offers different bytes for the verified installed version")]
    Equivocation,
    #[error(
        "stable channel requires valid SemVer for both the release and verified installed version; select --version explicitly"
    )]
    VersionOrder,
}

type Result<T> = std::result::Result<T, ReleaseError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub key: String,
    pub sha256: String,
    pub size: u64,
}

impl ObjectRef {
    pub(crate) fn validate(&self, expected: &str, cap: u64) -> Result<()> {
        if self.key != expected || !is_sha256_hex(&self.sha256) || !(1..=cap).contains(&self.size) {
            return Err(ReleaseError::Invalid("object reference"));
        }
        Ok(())
    }

    fn validate_blob(&self) -> Result<()> {
        self.validate(
            &format!("cw/v1/blobs/sha256/{}", self.sha256),
            MAX_OBJECT_BYTES,
        )
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size || format!("{:x}", Sha256::digest(bytes)) != self.sha256
        {
            return Err(ReleaseError::ObjectMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checksums {
    pub file: ObjectRef,
    pub signature: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciReference {
    pub index_sha256: String,
    pub manifest_sha256: String,
    pub archive: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    pub target: String,
    pub asset_name: String,
    pub identity: CwPayloadIdentity,
    pub executable: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_pack: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_lock: Option<ObjectRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema: String,
    pub release_tag: String,
    pub package_version: String,
    pub tag_object_sha: String,
    pub source_revision: String,
    pub source_tree_sha256: String,
    pub rustc: String,
    pub signing_fingerprint: String,
    pub checksums: Checksums,
    pub targets: Vec<TargetEntry>,
}

impl ReleaseManifest {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != RELEASE_SCHEMA
            || !valid_release_tag(&self.release_tag)
            || self.package_version != self.release_tag
            || !lower_hex(&self.tag_object_sha, 40)
            || !lower_hex(&self.source_revision, 40)
            || !is_sha256_hex(&self.source_tree_sha256)
            || !valid_fingerprint(&self.signing_fingerprint)
        {
            return Err(ReleaseError::Invalid("release identity"));
        }
        self.checksums.file.validate(
            &release_key(&self.release_tag, "SHA256SUMS"),
            MAX_JSON_BYTES as u64,
        )?;
        self.checksums.signature.validate(
            &release_key(&self.release_tag, "SHA256SUMS.asc"),
            MAX_SIGNATURE_BYTES as u64,
        )?;
        if self.targets.len() != TARGET_ORDER.len() {
            return Err(ReleaseError::Invalid("four ordered targets"));
        }
        for (entry, expected) in self.targets.iter().zip(TARGET_ORDER) {
            let target = entry
                .identity
                .validate()
                .map_err(|_| ReleaseError::Invalid("payload identity"))?;
            if entry.target != expected
                || target.as_str() != expected
                || entry.asset_name != format!("cw-{}-{expected}", self.release_tag)
                || entry.identity.package_version != self.package_version
                || entry.identity.source_revision != self.source_revision
                || entry.identity.source_tree_sha256 != self.source_tree_sha256
                || entry.identity.rustc != self.rustc
                || entry.executable.sha256 != entry.identity.sha256
                || entry.executable.size != entry.identity.size
            {
                return Err(ReleaseError::Invalid("target identity"));
            }
            entry.executable.validate_blob()?;
            if target == ReleaseTarget::X86_64UnknownLinuxMusl {
                let (Some(oci), Some(pack), Some(lock)) =
                    (&entry.oci, &entry.runtime_pack, &entry.runtime_lock)
                else {
                    return Err(ReleaseError::Invalid("runtime transports"));
                };
                if !is_sha256_hex(&oci.index_sha256)
                    || !is_sha256_hex(&oci.manifest_sha256)
                    || oci.index_sha256 == oci.archive.sha256
                {
                    return Err(ReleaseError::Invalid("OCI identity"));
                }
                oci.archive.validate_blob()?;
                pack.validate_blob()?;
                lock.validate_blob()?;
            } else if entry.oci.is_some()
                || entry.runtime_pack.is_some()
                || entry.runtime_lock.is_some()
            {
                return Err(ReleaseError::Invalid("unexpected runtime transport"));
            }
        }
        Ok(())
    }

    pub fn target(&self, platform: Platform) -> &TargetEntry {
        self.targets
            .iter()
            .find(|entry| entry.target == platform.release_target().as_str())
            .expect("a validated manifest holds all four targets")
    }

    /// Compare the signed sums with the exact four declared raw assets.
    pub fn verify_checksums(&self, bytes: &[u8]) -> Result<()> {
        self.checksums.file.verify_bytes(bytes)?;
        let mut entries: Vec<_> = self.targets.iter().collect();
        entries.sort_by(|a, b| a.asset_name.cmp(&b.asset_name));
        let expected: String = entries
            .iter()
            .map(|entry| format!("{}  {}\n", entry.identity.sha256, entry.asset_name))
            .collect();
        if bytes != expected.as_bytes() {
            return Err(ReleaseError::Invalid("four checksums"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelPointer {
    pub channel: String,
    pub release_tag: String,
    pub release: ObjectRef,
    pub release_signature: ObjectRef,
}

impl ChannelPointer {
    fn validate(&self) -> Result<()> {
        if self.channel != "stable" || !valid_release_tag(&self.release_tag) {
            return Err(ReleaseError::Invalid("channel pointer"));
        }
        self.release.validate(
            &release_key(&self.release_tag, "release.json"),
            MAX_JSON_BYTES as u64,
        )?;
        self.release_signature.validate(
            &release_key(&self.release_tag, "release.json.asc"),
            MAX_SIGNATURE_BYTES as u64,
        )
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self).map_err(|_| ReleaseError::Malformed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelEnvelope {
    pub schema: String,
    pub pointer: ChannelPointer,
    pub signature: String,
}

impl ChannelEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode_canonical(bytes)?;
        if value.schema != CHANNEL_SCHEMA {
            return Err(ReleaseError::Invalid("channel schema"));
        }
        value.pointer.validate()?;
        validate_signature(value.signature.as_bytes())?;
        Ok(value)
    }
}

pub fn validate_signature(bytes: &[u8]) -> Result<()> {
    const START: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
    const END: &[u8] = b"-----END PGP SIGNATURE-----";
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(ReleaseError::Bounds);
    }
    if !bytes.is_ascii()
        || bytes.contains(&0)
        || !bytes.starts_with(START)
        || !bytes.ends_with(b"-----END PGP SIGNATURE-----\n")
        || bytes
            .windows(START.len())
            .filter(|value| *value == START)
            .count()
            != 1
        || bytes
            .windows(END.len())
            .filter(|value| *value == END)
            .count()
            != 1
    {
        return Err(ReleaseError::Invalid("armored signature"));
    }
    Ok(())
}

pub(crate) fn decode_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
        return Err(ReleaseError::Bounds);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| ReleaseError::Malformed)?;
    if canonical_json(&value).map_err(|_| ReleaseError::Malformed)? != bytes {
        return Err(ReleaseError::Malformed);
    }
    Ok(value)
}

pub fn release_key(version: &str, name: &str) -> String {
    format!("cw/v1/releases/{version}/{name}")
}

pub fn valid_release_tag(value: &str) -> bool {
    let Some(value) = value.strip_prefix('v') else {
        return false;
    };
    if value.is_empty() || value.len() >= 64 {
        return false;
    }
    let (core, pre) = value
        .split_once('-')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let parts: Vec<_> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        })
}

pub fn valid_fingerprint(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

pub(crate) fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stable is advisory on first contact: this schema has no signed freshness
/// counter or expiry. Once installed bytes are verified, refuse regressions
/// and equal-precedence versions with different digests. The caller must also
/// use the observed Store generation when committing selection.
pub fn guard_stable(installed: Option<(&str, &str)>, incoming: &CwPayloadIdentity) -> Result<()> {
    let offered = Semver::parse(&incoming.package_version).ok_or(ReleaseError::VersionOrder)?;
    let Some((version, digest)) = installed else {
        return Ok(());
    };
    let current = Semver::parse(version).ok_or(ReleaseError::VersionOrder)?;
    match offered.compare(&current) {
        Ordering::Less => Err(ReleaseError::Downgrade),
        Ordering::Equal if incoming.sha256 != digest => Err(ReleaseError::Equivocation),
        _ => Ok(()),
    }
}

/// The precedence of release version `a` against `b`, or None when either is
/// not a release version.
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    Some(Semver::parse(a)?.compare(&Semver::parse(b)?))
}

struct Semver<'a> {
    core: [&'a str; 3],
    prerelease: Option<Vec<&'a str>>,
}

impl<'a> Semver<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        if value.is_empty() || value.len() > 64 {
            return None;
        }
        let value = value.strip_prefix('v').unwrap_or(value);
        let (value, build) = value
            .split_once('+')
            .map_or((value, None), |(a, b)| (a, Some(b)));
        if build.is_some_and(|v| !identifiers(v, false)) {
            return None;
        }
        let (core, pre) = value
            .split_once('-')
            .map_or((value, None), |(a, b)| (a, Some(b)));
        let core: [_; 3] = core.split('.').collect::<Vec<_>>().try_into().ok()?;
        if !core.iter().all(|v| numeric(v)) || pre.is_some_and(|v| !identifiers(v, true)) {
            return None;
        }
        Some(Self {
            core,
            prerelease: pre.map(|v| v.split('.').collect()),
        })
    }

    fn compare(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(other.core) {
            let cmp = compare_numeric(a, b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => {
                for (a, b) in a.iter().zip(b) {
                    let an = a.bytes().all(|v| v.is_ascii_digit());
                    let bn = b.bytes().all(|v| v.is_ascii_digit());
                    let cmp = match (an, bn) {
                        (true, true) => compare_numeric(a, b),
                        (true, false) => Ordering::Less,
                        (false, true) => Ordering::Greater,
                        (false, false) => a.cmp(b),
                    };
                    if cmp != Ordering::Equal {
                        return cmp;
                    }
                }
                a.len().cmp(&b.len())
            }
        }
    }
}

fn numeric(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|v| v.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn identifiers(value: &str, prerelease: bool) -> bool {
    value.split('.').all(|v| {
        !v.is_empty()
            && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (!prerelease || !v.bytes().all(|b| b.is_ascii_digit()) || numeric(v))
    })
}

fn compare_numeric(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests;
