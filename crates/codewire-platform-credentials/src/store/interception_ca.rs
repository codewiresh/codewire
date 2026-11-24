//! One hosted Pod's interception CA (#4001 step N1, #5030): its key, sealed
//! in `platform_interception_cas`, and the one primitive that signs with it
//! (docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception CA").
//!
//! The key is generated here and sealed under a DEK in the `platform` scope
//! for the Pod UID, with associated data naming the Pod UID. It is opened only
//! into an [`InterceptionCa`], for an attached row whose environment the
//! caller names, and wiped when that is dropped. Nothing here caches it, logs
//! it or returns it; the errors carry no input.

use std::time::Duration;

use codewire_egress_policy::check::CheckDestination;
use codewire_protected_store::secret_envelope::{
    DekContext, SECRET_FORMAT_V1, SecretCoordinates, decrypt_secret, encrypt_secret,
};
use rand::RngCore as _;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType, SerialNumber, SignatureAlgorithm,
};
use sqlx::FromRow as _;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    MaterialRow, PlatformCredentialStore, database_error, provider_call, validate_wrapper,
};
use crate::PlatformCredentialError as Error;

/// How long a CA is valid after it is generated (cw-security, #4001). The
/// guest keeps its first trust, so a CA is never replaced while its Pod lives.
pub const CA_VALIDITY: Duration = Duration::from_secs(400 * 24 * 60 * 60);
/// The longest a leaf may live, and never past its CA.
pub const MAX_LEAF_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// The most names one leaf carries.
pub const MAX_LEAF_HOSTS: usize = 32;
/// How far a certificate's start is moved back, for guest clocks slightly
/// behind this one.
const BACKDATE: Duration = Duration::from_secs(5 * 60);
const CA_COMMON_NAME: &str = "Codewire hosted egress CA";
/// The envelope's key coordinate; the path names the Pod UID.
const KEY: &str = "interception-ca/v1";

fn path(pod_uid: &str) -> String {
    format!("/platform-interception-cas/v1/{pod_uid}")
}

/// Why a leaf was not signed. Carries no input, so it may be logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LeafRefusal {
    #[error("a leaf names 1 to 32 distinct canonical DNS names of at least two labels")]
    InvalidHosts,
    #[error("a wildcard is signed only for an interceptable suffix")]
    WildcardNotInterceptable,
    #[error("a leaf lives more than nothing and at most an hour")]
    InvalidLifetime,
    #[error("a leaf's key is an ECDSA P-256 SubjectPublicKeyInfo")]
    InvalidPublicKey,
    #[error("the interception CA has expired")]
    Expired,
    #[error("leaf signing failed")]
    Sign,
}

/// One Pod's opened CA: signs leaves and is wiped on drop. It is made only by
/// [`PlatformCredentialStore::open_interception_ca`], for an attached row.
pub struct InterceptionCa {
    key: SecretKey,
    certificate_der: Vec<u8>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

/// A key pair whose PKCS#8 encoding is wiped on drop. The ring key schedule
/// rcgen also holds has no wipe of its own.
struct SecretKey(KeyPair);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for InterceptionCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InterceptionCa")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl InterceptionCa {
    /// A CA in memory, valid from now for `validity`, made exactly as the
    /// store makes one, for tests that sign real leaves without a database.
    #[cfg(any(test, feature = "interception-ca-test-support"))]
    pub fn generate_for_test(validity: Duration) -> Self {
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .expect("now is a valid timestamp");
        let (not_before, not_after) = (now - BACKDATE, now + validity);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 key");
        let certificate = ca_params(not_before, not_after)
            .self_signed(&key)
            .expect("CA certificate");
        Self {
            key: SecretKey(key),
            certificate_der: certificate.der().to_vec(),
            not_before,
            not_after,
        }
    }

    /// The CA certificate, DER, for the guest's trust.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// When the CA stops being valid; no leaf outlives it.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// A leaf for `public_key` (a DER SubjectPublicKeyInfo, ECDSA P-256),
    /// naming exactly `hosts`, valid from now for `lifetime` or until the CA
    /// ends. It is serverAuth only and never a CA. Which hosts, and for how
    /// long within the bound, is the caller's to decide from its own binding
    /// record (N2); this refuses anything outside the profile.
    pub fn sign_leaf(
        &self,
        public_key: &[u8],
        hosts: &[&str],
        lifetime: Duration,
    ) -> Result<Vec<u8>, LeafRefusal> {
        if lifetime.is_zero() || lifetime > MAX_LEAF_LIFETIME {
            return Err(LeafRefusal::InvalidLifetime);
        }
        let public_key = P256PublicKey::from_spki(public_key)?;
        let names = leaf_names(hosts)?;
        let now = OffsetDateTime::now_utc();
        if now >= self.not_after {
            return Err(LeafRefusal::Expired);
        }
        let mut params = CertificateParams::default();
        // rcgen writes the SAN extension non-critical, which RFC 5280 allows
        // only beside a non-empty subject, so the subject names the first host.
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, names[0]);
        params.subject_alt_names = names
            .iter()
            .map(|name| {
                (*name)
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|_| LeafRefusal::InvalidHosts)
            })
            .collect::<Result<_, _>>()?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial().map_err(|_| LeafRefusal::Sign)?);
        params.not_before = (now - BACKDATE).max(self.not_before);
        params.not_after = (now + lifetime).min(self.not_after);
        let issuer = self.issuer().map_err(|_| LeafRefusal::Sign)?;
        let leaf = params
            .signed_by(&public_key, &issuer, &self.key.0)
            .map_err(|_| LeafRefusal::Sign)?;
        Ok(leaf.der().to_vec())
    }

    /// The issuer rcgen signs under: the stored CA's own parameters, with its
    /// key. Its subject and key identifier are the stored certificate's.
    fn issuer(&self) -> Result<Certificate, rcgen::Error> {
        ca_params(self.not_before, self.not_after).self_signed(&self.key.0)
    }
}

/// The CA's parameters: a CA for one path step, signing certificates only,
/// with a critical name constraint excluding every IP address and permitting
/// no DNS subtree. The signer's binding record is the host limit, and a DNS
/// constraint would freeze today's hosts into the Pod's life (cw-security,
/// #4001).
fn ca_params(not_before: OffsetDateTime, not_after: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: Vec::new(),
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    params.not_before = not_before;
    params.not_after = not_after;
    params
}

/// A positive 128-bit serial, so no two leaves of one CA share one.
fn random_serial() -> Result<SerialNumber, rand::Error> {
    let mut serial = [0_u8; 16];
    rand::rngs::OsRng.try_fill_bytes(&mut serial)?;
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    Ok(SerialNumber::from_slice(&serial))
}

/// The names a leaf may carry: exact canonical DNS names of at least two
/// labels, and a `*.<suffix>` only for an interceptable suffix, which a TLS
/// client matches one label deep.
fn leaf_names<'a>(hosts: &[&'a str]) -> Result<Vec<&'a str>, LeafRefusal> {
    if hosts.is_empty() || hosts.len() > MAX_LEAF_HOSTS {
        return Err(LeafRefusal::InvalidHosts);
    }
    let mut names: Vec<&str> = Vec::with_capacity(hosts.len());
    for &host in hosts {
        let exact = match host.strip_prefix("*.") {
            Some(suffix) => {
                if !canonical(suffix) {
                    return Err(LeafRefusal::InvalidHosts);
                }
                if !interceptable_suffix(suffix) {
                    return Err(LeafRefusal::WildcardNotInterceptable);
                }
                true
            }
            None => canonical(host),
        };
        if !exact || names.contains(&host) {
            return Err(LeafRefusal::InvalidHosts);
        }
        names.push(host);
    }
    Ok(names)
}

/// The egress policy's canonical name, taken as it is: a name that needed
/// lowercasing or a trailing dot removed is not exact, and an IP address is
/// not a name.
fn canonical(host: &str) -> bool {
    matches!(
        CheckDestination::parse(host),
        Ok(CheckDestination::Name(name)) if name == host && name.contains('.')
    )
}

/// Whether `*.<suffix>` may be signed: an entry of the interceptable-host
/// table marked as a suffix (cw-security's addendum, #4001), which is only
/// `chatgpt.com`, for the Codex slot (#6195).
fn interceptable_suffix(suffix: &str) -> bool {
    codewire_access::FRONT_DOOR_HOSTS
        .iter()
        .any(|entry| entry.suffix && entry.host == suffix)
}

/// An ECDSA P-256 public key from its DER SubjectPublicKeyInfo, which for
/// this curve is one fixed prefix and an uncompressed point.
struct P256PublicKey([u8; 65]);

/// SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused) }.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

impl P256PublicKey {
    fn from_spki(der: &[u8]) -> Result<Self, LeafRefusal> {
        let point = der
            .strip_prefix(&P256_SPKI_PREFIX[..])
            .filter(|point| point.len() == 65 && point[0] == 0x04)
            .ok_or(LeafRefusal::InvalidPublicKey)?;
        let mut key = [0_u8; 65];
        key.copy_from_slice(point);
        Ok(Self(key))
    }
}

impl PublicKeyData for P256PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

/// The Pod a CA is for, as the credential service read it from the cluster.
#[derive(Clone, Copy, Debug)]
pub struct InterceptedPod<'a> {
    pub uid: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
}

/// An unbound Pod's CA row, as the sweep reads it: the Pod to look for.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct UnboundInterceptionCa {
    pub pod_uid: String,
    pub pod_namespace: String,
    pub pod_name: String,
}

/// The stored row's public part.
#[derive(sqlx::FromRow)]
struct CaRow {
    certificate_der: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

impl PlatformCredentialStore {
    /// `pod_uid`'s CA certificate, creating the CA on the Pod's first use.
    ///
    /// Two first uses may race: each inserts with `ON CONFLICT DO NOTHING` and
    /// then reads the row that is stored, never the CA it generated, so both
    /// return the one CA that won. The database refuses a Pod whose binding
    /// was released, and fills the row's environment from a live binding.
    pub async fn ensure_interception_ca(&self, pod: InterceptedPod<'_>) -> Result<Vec<u8>, Error> {
        if let Some(row) = self.interception_ca_row(pod.uid).await? {
            return Ok(row.certificate_der);
        }
        self.insert_interception_ca(pod).await?;
        self.interception_ca_row(pod.uid)
            .await?
            .map(|row| row.certificate_der)
            .ok_or(Error::NotFound)
    }

    /// `pod_uid`'s CA certificate if it has one; never opens the key.
    pub async fn interception_ca_certificate(
        &self,
        pod_uid: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .interception_ca_row(pod_uid)
            .await?
            .map(|row| row.certificate_der))
    }

    /// `pod_uid`'s CA, opened to sign, only when its row is attached to
    /// `environment_id`. An unbound Pod's CA, or another environment's, is
    /// not found.
    pub async fn open_interception_ca(
        &self,
        pod_uid: &str,
        environment_id: &str,
    ) -> Result<InterceptionCa, Error> {
        // One read, so the row whose key opens is the row attached to
        // `environment_id`.
        let (row, material): (CaRow, MaterialRow) = sqlx::query(
            "SELECT certificate_der, \
             EXTRACT(EPOCH FROM not_before)::bigint AS not_before, \
             EXTRACT(EPOCH FROM not_after)::bigint AS not_after, \
             kek_provider, key_name, key_version, wrapped_dek, wrapped_format, ciphertext, \
             nonce, format FROM platform_interception_cas \
             WHERE pod_uid=$1 AND environment_id=$2",
        )
        .bind(pod_uid)
        .bind(environment_id)
        .fetch_optional(&self.reader.pool)
        .await
        .map_err(database_error)?
        .map(|row| Ok::<_, sqlx::Error>((CaRow::from_row(&row)?, MaterialRow::from_row(&row)?)))
        .transpose()
        .map_err(|_| Error::CorruptRecord)?
        .ok_or(Error::NotFound)?;
        let context = DekContext::interception_ca(pod_uid).map_err(|_| Error::InvalidInput)?;
        let prepared = material.prepared(self.provider.kind())?;
        let dek = provider_call(self.provider.unwrap(&context, &prepared.wrapped)).await?;
        let path = path(pod_uid);
        let pkcs8 = decrypt_secret(
            &dek,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: KEY,
            },
            &prepared.envelope,
        )
        .map_err(|_| Error::CorruptRecord)?;
        let key = KeyPair::try_from(pkcs8.as_slice()).map_err(|_| Error::CorruptRecord)?;
        // Clients trust the stored certificate, and leaves are signed by the
        // opened key: a row whose two don't pair would sign leaves nobody
        // accepts, so it is corrupt.
        let (_, certificate) =
            X509Certificate::from_der(&row.certificate_der).map_err(|_| Error::CorruptRecord)?;
        if certificate.public_key().raw != key.public_key_der().as_slice() {
            return Err(Error::CorruptRecord);
        }
        Ok(InterceptionCa {
            key: SecretKey(key),
            certificate_der: row.certificate_der,
            not_before: timestamp(row.not_before)?,
            not_after: timestamp(row.not_after)?,
        })
    }

    /// Every row whose Pod has no environment yet: the Pods the sweep checks
    /// for. A bound Pod's row is deleted by its binding's release instead.
    pub async fn unbound_interception_cas(&self) -> Result<Vec<UnboundInterceptionCa>, Error> {
        sqlx::query_as(
            "SELECT pod_uid, pod_namespace, pod_name FROM platform_interception_cas \
             WHERE environment_id IS NULL ORDER BY created_at",
        )
        .fetch_all(&self.reader.pool)
        .await
        .map_err(database_error)
    }

    /// The sweep's delete, for a Pod gone from the cluster: removes its row
    /// only while it has no live binding. True when a row was removed.
    pub async fn forget_interception_ca(&self, pod_uid: &str) -> Result<bool, Error> {
        sqlx::query_scalar("SELECT forget_interception_ca($1)")
            .bind(pod_uid)
            .fetch_one(&self.reader.pool)
            .await
            .map_err(database_error)
    }

    async fn interception_ca_row(&self, pod_uid: &str) -> Result<Option<CaRow>, Error> {
        sqlx::query_as(
            "SELECT certificate_der, \
             EXTRACT(EPOCH FROM not_before)::bigint AS not_before, \
             EXTRACT(EPOCH FROM not_after)::bigint AS not_after \
             FROM platform_interception_cas WHERE pod_uid=$1",
        )
        .bind(pod_uid)
        .fetch_optional(&self.reader.pool)
        .await
        .map_err(database_error)
    }

    /// Generate a CA, seal its key and insert it unless the Pod has one.
    async fn insert_interception_ca(&self, pod: InterceptedPod<'_>) -> Result<(), Error> {
        let pod_uid = pod.uid;
        let context = DekContext::interception_ca(pod_uid).map_err(|_| Error::InvalidInput)?;
        // Whole seconds, as the row keeps them, so the issuer rebuilt from
        // the row has exactly the stored certificate's validity.
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| Error::InvalidInput)?;
        let not_before = now - BACKDATE;
        let not_after = now + CA_VALIDITY;
        let key = SecretKey(
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .map_err(|_| Error::ProviderUnavailable)?,
        );
        let certificate = ca_params(not_before, not_after)
            .self_signed(&key.0)
            .map_err(|_| Error::ProviderUnavailable)?;
        let pkcs8 = Zeroizing::new(key.0.serialize_der());
        let generated = provider_call(self.provider.generate(&context)).await?;
        validate_wrapper(&generated.wrapped, self.provider.kind())?;
        let path = path(pod_uid);
        let envelope = encrypt_secret(
            &generated.plaintext,
            &SecretCoordinates {
                context: &context,
                path: &path,
                key: KEY,
            },
            pkcs8.as_slice(),
        )
        .map_err(|_| Error::CorruptRecord)?;
        sqlx::query(
            "INSERT INTO platform_interception_cas \
             (pod_uid, pod_namespace, pod_name, certificate_der, not_before, not_after, \
              kek_provider, key_name, key_version, wrapped_dek, wrapped_format, ciphertext, \
              nonce, format) \
             VALUES ($1,$2,$3,$4,to_timestamp($5),to_timestamp($6),$7,$8,$9,$10,$11,$12,$13,$14) \
             ON CONFLICT (pod_uid) DO NOTHING",
        )
        .bind(pod_uid)
        .bind(pod.namespace)
        .bind(pod.name)
        .bind(certificate.der().to_vec())
        .bind(not_before.unix_timestamp())
        .bind(not_after.unix_timestamp())
        .bind(generated.wrapped.provider.as_str())
        .bind(generated.wrapped.key_name)
        .bind(i64::from(generated.wrapped.key_version))
        .bind(generated.wrapped.ciphertext)
        .bind(generated.wrapped.format)
        .bind(envelope.ciphertext)
        .bind(envelope.nonce)
        .bind(SECRET_FORMAT_V1)
        .execute(&self.reader.pool)
        .await
        .map_err(|error| {
            // The insert guard's refusal: the Pod's binding was released, so
            // it gets no CA.
            if error
                .as_database_error()
                .and_then(|error| error.code())
                .is_some_and(|code| code == "23514")
            {
                Error::NotFound
            } else {
                database_error(error)
            }
        })?;
        Ok(())
    }
}

fn timestamp(seconds: i64) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| Error::CorruptRecord)
}

#[cfg(test)]
mod tests;
