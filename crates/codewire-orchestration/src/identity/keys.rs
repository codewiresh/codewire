//! The signing key's versions, as OpenBao lists them, and the rules that
//! follow from their creation times alone:
//!
//! - every listed version is published in the JWKS;
//! - a version signs once it has been published for 24 hours: the signer
//!   uses the newest version created at least that long ago;
//! - a version leaves the JWKS 24 hours after a newer one starts signing,
//!   when the rotation job raises the key's minimum versions to the signer;
//! - the rotation job adds a version when the signing one is 30 days old.
//!
//! OpenBao lists only versions at or above `min_decryption_version`, so the
//! listing is the published set. Every decision reads it again; no clock or
//! cache of this process decides which version signs.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// How long a version is published before it signs, and how long it stays
/// published after it stops.
pub(crate) const PUBLICATION_OVERLAP: Duration = Duration::hours(24);
/// How long a version signs before the rotation job adds the next one.
pub(crate) const SIGNING_PERIOD: Duration = Duration::days(30);

const KEY_TYPE: &str = "ecdsa-p256";
/// DER of a P-256 `SubjectPublicKeyInfo` up to its uncompressed point: the
/// id-ecPublicKey and prime256v1 OIDs, then a 66-byte BIT STRING.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const P256_COORDINATE_BYTES: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeySetError {
    #[error("the key is not {KEY_TYPE}")]
    WrongType,
    #[error("the key lists no versions")]
    Empty,
    #[error("key version {0:?} is malformed")]
    MalformedVersion(String),
}

/// The `data` of OpenBao's `GET <transit mount>/keys/<name>`.
#[derive(Debug, Deserialize)]
pub(crate) struct KeyRead {
    #[serde(rename = "type")]
    key_type: String,
    keys: BTreeMap<String, KeyReadVersion>,
    latest_version: u32,
    min_decryption_version: u32,
    min_encryption_version: u32,
    exportable: bool,
    allow_plaintext_backup: bool,
    deletion_allowed: bool,
    #[serde(default)]
    auto_rotate_period: u64,
}

#[derive(Debug, Deserialize)]
struct KeyReadVersion {
    creation_time: String,
    public_key: String,
}

/// One published version: its number, when OpenBao created it, and its
/// public point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyVersion {
    pub(crate) version: u32,
    pub(crate) created_at: DateTime<Utc>,
    x: [u8; P256_COORDINATE_BYTES],
    y: [u8; P256_COORDINATE_BYTES],
}

/// The pinned configuration (design §6) and whether OpenBao still reports
/// it. A difference is drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCustody {
    pub(crate) exportable: bool,
    pub(crate) allow_plaintext_backup: bool,
    pub(crate) deletion_allowed: bool,
    pub(crate) auto_rotate_period: u64,
}

impl KeyCustody {
    pub(crate) fn is_pinned(&self) -> bool {
        !self.exportable
            && !self.allow_plaintext_backup
            && !self.deletion_allowed
            && self.auto_rotate_period == 0
    }
}

/// A non-empty, ordered set of published versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    versions: BTreeMap<u32, KeyVersion>,
    latest_version: u32,
    min_decryption_version: u32,
    min_encryption_version: u32,
    pub(crate) custody: KeyCustody,
}

/// What the rotation job does on one run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RotationPlan {
    /// Raise both minimum versions to this one, retiring every older version.
    pub(crate) retire_below: Option<u32>,
    /// Add a new version.
    pub(crate) rotate: bool,
}

#[derive(Serialize)]
pub(crate) struct Jwks {
    keys: Vec<Jwk>,
}

/// An ES256 public key. Field order is fixed so the served bytes are too.
#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    kid: String,
    x: String,
    y: String,
}

impl KeySet {
    pub(crate) fn from_read(read: KeyRead) -> Result<Self, KeySetError> {
        if read.key_type != KEY_TYPE {
            return Err(KeySetError::WrongType);
        }
        let versions = read
            .keys
            .into_iter()
            .map(|(number, version)| {
                let parsed = parse_version(&number, &version)
                    .ok_or(KeySetError::MalformedVersion(number))?;
                Ok((parsed.version, parsed))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if versions.is_empty() {
            return Err(KeySetError::Empty);
        }
        Ok(Self {
            versions,
            latest_version: read.latest_version,
            min_decryption_version: read.min_decryption_version,
            min_encryption_version: read.min_encryption_version,
            custody: KeyCustody {
                exportable: read.exportable,
                allow_plaintext_backup: read.allow_plaintext_backup,
                deletion_allowed: read.deletion_allowed,
                auto_rotate_period: read.auto_rotate_period,
            },
        })
    }

    /// Every published version, as a JWKS.
    pub(crate) fn jwks(&self) -> Jwks {
        Jwks {
            keys: self
                .versions
                .values()
                .map(|version| Jwk {
                    kty: "EC",
                    crv: "P-256",
                    alg: "ES256",
                    key_use: "sig",
                    kid: key_id(version.version),
                    x: URL_SAFE_NO_PAD.encode(version.x),
                    y: URL_SAFE_NO_PAD.encode(version.y),
                })
                .collect(),
        }
    }

    /// The version that signs at `now`: the newest one published for at
    /// least [`PUBLICATION_OVERLAP`]. A new key has none until its first
    /// version is 24 hours old, and signs nothing until then, so every
    /// verifier has had the version before it sees a token signed with it.
    pub(crate) fn signing_version(
        &self,
        now: DateTime<Utc>,
    ) -> Result<&KeyVersion, NotYetPublished> {
        self.versions
            .values()
            .rev()
            .find(|version| version.created_at + PUBLICATION_OVERLAP <= now)
            .ok_or(NotYetPublished)
    }

    pub(crate) fn rotation_plan(&self, now: DateTime<Utc>) -> RotationPlan {
        // A new key's first version has nothing to retire and is not due.
        let Ok(signing) = self.signing_version(now) else {
            return RotationPlan::default();
        };
        // The previous version stopped signing when this one turned 24 hours
        // old; it stays published 24 hours more.
        let previous_retired =
            signing.created_at + PUBLICATION_OVERLAP + PUBLICATION_OVERLAP <= now;
        let below_signing = self.min_decryption_version < signing.version
            || self.min_encryption_version < signing.version;
        RotationPlan {
            retire_below: (previous_retired && below_signing).then_some(signing.version),
            rotate: self.latest_version == signing.version
                && signing.created_at + SIGNING_PERIOD <= now,
        }
    }
}

/// The one key version a sign request may name. Only
/// [`KeySet::signing_key`] makes one, so a request can never name a version
/// that isn't the signing one, and never names none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigningKey {
    version: u32,
}

impl SigningKey {
    pub(crate) fn version(self) -> u32 {
        self.version
    }

    pub(crate) fn kid(self) -> String {
        key_id(self.version)
    }
}

/// Why the key may not sign now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SigningRefusal {
    #[error(transparent)]
    NotYetPublished(#[from] NotYetPublished),
    /// Its custody differs from the pins; nothing signs with a key that may
    /// have been exported or backed up.
    #[error("the sandbox identity key's configuration has drifted from its pinned custody")]
    Drift,
}

impl KeySet {
    /// The version that signs at `now`, from [`Self::signing_version`] and
    /// never a younger one, on a key whose custody is still pinned.
    pub(crate) fn signing_key(&self, now: DateTime<Utc>) -> Result<SigningKey, SigningRefusal> {
        if !self.custody.is_pinned() {
            return Err(SigningRefusal::Drift);
        }
        let version = self.signing_version(now)?;
        Ok(SigningKey {
            version: version.version,
        })
    }
}

/// No version of the key has been published for [`PUBLICATION_OVERLAP`] yet,
/// so nothing may sign. The message is fixed: it names no version or time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no sandbox identity key version has been published for 24 hours yet")]
pub(crate) struct NotYetPublished;

/// The `kid` of a version. It names the key, never a location.
pub(crate) fn key_id(version: u32) -> String {
    format!("sandbox-identity-{version}")
}

fn parse_version(number: &str, version: &KeyReadVersion) -> Option<KeyVersion> {
    if !number.bytes().all(|byte| byte.is_ascii_digit()) || number.starts_with('0') {
        return None;
    }
    let created_at = DateTime::parse_from_rfc3339(&version.creation_time)
        .ok()?
        .with_timezone(&Utc);
    let (x, y) = p256_point_from_pem(&version.public_key)?;
    Some(KeyVersion {
        version: number.parse().ok()?,
        created_at,
        x,
        y,
    })
}

/// The affine coordinates of a PEM `PUBLIC KEY` that is exactly a P-256
/// SubjectPublicKeyInfo with an uncompressed point.
fn p256_point_from_pem(
    pem: &str,
) -> Option<([u8; P256_COORDINATE_BYTES], [u8; P256_COORDINATE_BYTES])> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")?
        .strip_suffix("-----END PUBLIC KEY-----")?;
    let base64: String = body.split_whitespace().collect();
    let der = STANDARD.decode(base64).ok()?;
    let point = der.strip_prefix(P256_SPKI_PREFIX.as_slice())?;
    let coordinates = point.strip_prefix(&[0x04])?;
    if coordinates.len() != 2 * P256_COORDINATE_BYTES {
        return None;
    }
    let (x, y) = coordinates.split_at(P256_COORDINATE_BYTES);
    Some((x.try_into().ok()?, y.try_into().ok()?))
}

#[cfg(test)]
pub(crate) mod tests;
