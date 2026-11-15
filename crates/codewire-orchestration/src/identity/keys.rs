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
    /// least [`PUBLICATION_OVERLAP`], or the oldest listed when none has been
    /// yet (a new key's first version).
    pub(crate) fn signing_version(&self, now: DateTime<Utc>) -> &KeyVersion {
        let oldest = self.versions.values().next();
        self.versions
            .values()
            .rev()
            .find(|version| version.created_at + PUBLICATION_OVERLAP <= now)
            .or(oldest)
            .expect("KeySet::from_read admits only a non-empty set")
    }

    pub(crate) fn rotation_plan(&self, now: DateTime<Utc>) -> RotationPlan {
        let signing = self.signing_version(now);
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
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    /// Two P-256 public keys OpenBao 2.5.4 generated for an `ecdsa-p256`
    /// transit key.
    pub(crate) const PEM_1: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg4tPUaiDWhxczk51f4VKfnJTczec\nN+6mSYSviVNo8CWuBC883s6UqB6z4m2exA0lTYzvXqdZB1pxh4RuJRueaA==\n-----END PUBLIC KEY-----\n";
    pub(crate) const PEM_2: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc9L0JHUYUrZZcLCOSJHlSmeiS/3d\nAMiCr7NbEKXP1+07TwFgfOAqHhvN+is1wSCKvFI2fwI2uEPxBtelm/JqRw==\n-----END PUBLIC KEY-----\n";

    pub(crate) fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A key read as OpenBao returns it, with the given (version, creation
    /// time) pairs listed and the given minimums.
    pub(crate) fn key_read(
        versions: &[(u32, &str)],
        min_decryption: u32,
        min_encryption: u32,
    ) -> serde_json::Value {
        let keys: serde_json::Map<_, _> = versions
            .iter()
            .map(|(version, created)| {
                let pem = if version % 2 == 1 { PEM_1 } else { PEM_2 };
                (
                    version.to_string(),
                    json!({"certificate_chain": "", "creation_time": created, "name": "P-256", "public_key": pem}),
                )
            })
            .collect();
        json!({
            "allow_plaintext_backup": false, "auto_rotate_period": 0, "deletion_allowed": false,
            "derived": false, "exportable": false, "imported_key": false, "keys": keys,
            "latest_version": versions.iter().map(|(v, _)| *v).max().unwrap_or(0),
            "min_available_version": 0, "min_decryption_version": min_decryption,
            "min_encryption_version": min_encryption, "name": "sandbox-identity",
            "soft_deleted": false, "supports_decryption": false, "supports_derivation": false,
            "supports_encryption": false, "supports_signing": true, "type": "ecdsa-p256"
        })
    }

    pub(crate) fn key_set(value: serde_json::Value) -> Result<KeySet, KeySetError> {
        KeySet::from_read(serde_json::from_value(value).unwrap())
    }

    // The expected coordinates were read from the PEMs with `openssl ec
    // -pubin -text`, not from this code.
    #[test]
    fn every_listed_version_is_an_es256_signing_jwk() {
        let set = key_set(key_read(
            &[
                (1, "2026-11-01T00:00:00Z"),
                (2, "2026-11-02T00:00:00.123456789+01:00"),
            ],
            1,
            0,
        ))
        .unwrap();
        let jwks = serde_json::to_value(set.jwks()).unwrap();
        assert_eq!(
            jwks,
            json!({"keys": [
                {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "sandbox-identity-1",
                 "x": "g4tPUaiDWhxczk51f4VKfnJTczecN-6mSYSviVNo8CU",
                 "y": "rgQvPN7OlKges-JtnsQNJU2M716nWQdacYeEbiUbnmg"},
                {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "sandbox-identity-2",
                 "x": "c9L0JHUYUrZZcLCOSJHlSmeiS_3dAMiCr7NbEKXP1-0",
                 "y": "O08BYHzgKh4bzforNcEgirxSNn8CNrhD8QbXpZvyakc"}
            ]})
        );
    }

    #[test]
    fn a_key_that_is_not_p256_or_lists_nothing_is_never_published() {
        let mut wrong_type = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
        wrong_type["type"] = json!("ed25519");
        assert_eq!(key_set(wrong_type), Err(KeySetError::WrongType));
        assert_eq!(key_set(key_read(&[], 1, 0)), Err(KeySetError::Empty));

        for (number, pem) in [
            ("01", PEM_1),
            ("x", PEM_1),
            (
                "1",
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            ),
            // A P-384 key in the same armour.
            (
                "1",
                "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n-----END PUBLIC KEY-----",
            ),
        ] {
            let mut read = key_read(&[], 1, 0);
            read["keys"] =
                json!({number: {"creation_time": "2026-11-01T00:00:00Z", "public_key": pem}});
            assert!(
                matches!(key_set(read), Err(KeySetError::MalformedVersion(_))),
                "version {number:?} is refused"
            );
        }
    }

    #[test]
    fn a_version_signs_after_24_hours_published_and_leaves_24_hours_after_it_stops() {
        // v2 is created at t0 while v1 signs.
        let t0 = "2026-12-01T00:00:00Z";
        let set = key_set(key_read(&[(1, "2026-11-01T00:00:00Z"), (2, t0)], 1, 1)).unwrap();

        let before = at("2026-12-01T23:59:59Z");
        assert_eq!(set.signing_version(before).version, 1);
        assert_eq!(set.rotation_plan(before), RotationPlan::default());

        let switched = at("2026-12-02T00:00:00Z");
        assert_eq!(set.signing_version(switched).version, 2);
        // v1's last tokens are still live: it stays published.
        assert_eq!(
            set.rotation_plan(at("2026-12-02T23:59:59Z")),
            RotationPlan::default()
        );

        assert_eq!(
            set.rotation_plan(at("2026-12-03T00:00:00Z")),
            RotationPlan {
                retire_below: Some(2),
                rotate: false
            }
        );
    }

    #[test]
    fn a_stalled_rotation_job_leaves_signing_and_verifying_intact() {
        // The job last ran when v2 was created and has not run for three days:
        // v1 is still listed, v2 signs, and both stay in the JWKS.
        let set = key_set(key_read(
            &[(1, "2026-11-01T00:00:00Z"), (2, "2026-12-01T00:00:00Z")],
            1,
            1,
        ))
        .unwrap();
        let later = at("2026-12-04T00:00:00Z");
        assert_eq!(set.signing_version(later).version, 2);
        assert_eq!(set.jwks().keys.len(), 2);
        assert_eq!(set.rotation_plan(later).retire_below, Some(2));
    }

    #[test]
    fn the_job_rotates_once_the_signing_version_is_30_days_old() {
        let set = key_set(key_read(&[(3, "2026-11-01T00:00:00Z")], 3, 3)).unwrap();
        assert!(!set.rotation_plan(at("2026-11-30T23:59:59Z")).rotate);
        assert_eq!(
            set.rotation_plan(at("2026-12-01T00:00:00Z")),
            RotationPlan {
                retire_below: None,
                rotate: true
            }
        );
        // A pending version is already published: no second rotation.
        let pending = key_set(key_read(
            &[(3, "2026-11-01T00:00:00Z"), (4, "2026-12-01T00:00:00Z")],
            3,
            3,
        ))
        .unwrap();
        assert!(!pending.rotation_plan(at("2026-12-01T12:00:00Z")).rotate);
    }

    #[test]
    fn a_new_keys_first_version_signs_at_once() {
        let set = key_set(key_read(&[(1, "2026-11-14T12:00:00Z")], 1, 0)).unwrap();
        let now = at("2026-11-14T12:00:01Z");
        assert_eq!(set.signing_version(now).version, 1);
        assert_eq!(set.rotation_plan(now), RotationPlan::default());
    }

    #[test]
    fn custody_is_pinned_only_when_every_setting_matches() {
        let set = key_set(key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0)).unwrap();
        assert!(set.custody.is_pinned());
        for field in ["exportable", "allow_plaintext_backup", "deletion_allowed"] {
            let mut read = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
            read[field] = json!(true);
            assert!(!key_set(read).unwrap().custody.is_pinned(), "{field}");
        }
        let mut read = key_read(&[(1, "2026-11-01T00:00:00Z")], 1, 0);
        read["auto_rotate_period"] = json!(3600);
        assert!(!key_set(read).unwrap().custody.is_pinned());
    }
}
