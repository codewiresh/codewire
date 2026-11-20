//! The per-environment certificate authority and the leaves it mints.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use codewire_egress_policy::check::CheckDestination;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

/// The most hosts one CA binds.
pub const MAX_BOUND_HOSTS: usize = 32;
/// The most leaves held at once. A subname under a bound suffix is chosen by
/// whoever dials it, so the cache is bounded; past it the oldest subname's
/// leaf is dropped and minted again if it is used again.
pub const MAX_CACHED_LEAVES: usize = 64;
/// How long the CA certificate is valid after it is generated.
pub const CA_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How long a leaf is valid after it is minted, never past the CA's end.
pub const LEAF_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
/// How far every certificate's start is moved back, for environment clocks
/// slightly behind this one.
pub const BACKDATE: Duration = Duration::from_secs(5 * 60);
/// A cached leaf is replaced once it is this old, well before it expires.
const LEAF_RENEW_AFTER: Duration = Duration::from_secs(12 * 60 * 60);
const CA_COMMON_NAME: &str = "Codewire environment egress CA";
/// X.509's upper bound on a common name (RFC 5280, ub-common-name).
const MAX_COMMON_NAME_LEN: usize = 64;

/// Why a CA or a leaf could not be made. Carries no input, so it may be
/// logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CaError {
    #[error("bound hosts must be 1 to 32 distinct canonical DNS names of at least two labels")]
    InvalidBoundHosts,
    #[error("a bound suffix must be one of the bound hosts")]
    InvalidSuffix,
    #[error("host is not bound to this certificate authority")]
    UnboundHost,
    #[error("certificate authority has expired")]
    Expired,
    #[error("certificate generation failed")]
    Generate,
    #[error("a signed leaf is unreadable, not for this key or names no host")]
    InvalidLeaf,
    #[error("a signed leaf starts later than this node's clock allows")]
    NotYetValid,
}

/// An environment's own CA. Its certificate may sign only for the bound
/// hosts: a critical name constraint permits exactly those DNS subtrees and
/// excludes every IP address. It mints leaves for each bound host, and for
/// any exact name strictly under a bound suffix, which is one of the bound
/// hosts. Its key is generated here, never leaves memory and is never printed.
pub struct EnvironmentCa {
    hosts: Vec<String>,
    suffixes: Vec<String>,
    certificate: Certificate,
    key: SecretKey,
    not_after: OffsetDateTime,
    leaves: Mutex<HashMap<String, Leaf>>,
}

/// A key pair whose PKCS#8 encoding is wiped on drop. The ring key schedule
/// rcgen also holds has no wipe of its own.
struct SecretKey(KeyPair);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct Leaf {
    key: Arc<CertifiedKey>,
    renew_at: Instant,
}

impl fmt::Debug for EnvironmentCa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentCa")
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

impl EnvironmentCa {
    /// A new CA, with a new ECDSA P-256 key, for 1 to [`MAX_BOUND_HOSTS`]
    /// distinct hosts. Each must already be a canonical DNS name: lowercase,
    /// no trailing dot, no wildcard, not an IP address, at least two labels.
    pub fn generate<I, H>(bound_hosts: I) -> Result<Self, CaError>
    where
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
    {
        Self::generate_with_suffixes(bound_hosts, Vec::<String>::new())
    }

    /// [`Self::generate`], also minting for any exact name strictly under
    /// each suffix (#3999). Each suffix must be one of the bound hosts, so the
    /// name constraint already permits its subtree.
    pub fn generate_with_suffixes<I, H, S, N>(bound_hosts: I, suffixes: S) -> Result<Self, CaError>
    where
        I: IntoIterator<Item = H>,
        H: AsRef<str>,
        S: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        let hosts = canonical_hosts(bound_hosts)?;
        let mut bound_suffixes: Vec<String> = Vec::new();
        for suffix in suffixes {
            let suffix = suffix.as_ref();
            if !hosts.iter().any(|host| host == suffix) {
                return Err(CaError::InvalidSuffix);
            }
            if !bound_suffixes.iter().any(|bound| bound == suffix) {
                bound_suffixes.push(suffix.to_owned());
            }
        }
        let now = OffsetDateTime::now_utc();
        let not_after = now + CA_VALIDITY;
        let key = SecretKey(
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| CaError::Generate)?,
        );
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, CA_COMMON_NAME);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        // A DNS constraint does not limit IP address names, so exclude them
        // all: this CA never vouches for an address.
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: hosts
                .iter()
                .map(|host| GeneralSubtree::DnsName(host.clone()))
                .collect(),
            excluded_subtrees: vec![
                GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
                GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
            ],
        });
        params.not_before = now - BACKDATE;
        params.not_after = not_after;
        let certificate = params.self_signed(&key.0).map_err(|_| CaError::Generate)?;
        Ok(Self {
            hosts,
            suffixes: bound_suffixes,
            certificate,
            key,
            not_after,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The hosts this CA signs for.
    pub fn bound_hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The bound hosts under which this CA also signs for any exact subname.
    pub fn bound_suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// Whether this CA signs for `host`, without minting a leaf.
    pub(crate) fn signs(&self, host: &str) -> bool {
        self.signed_name(host).is_some()
    }

    /// The canonical name this CA signs `host` as: a bound host, or `host`
    /// itself when it is already canonical and strictly under a bound suffix.
    fn signed_name(&self, host: &str) -> Option<String> {
        if let Some(bound) = self
            .hosts
            .iter()
            .find(|bound| bound.eq_ignore_ascii_case(host))
        {
            return Some(bound.clone());
        }
        let canonical = matches!(
            CheckDestination::parse(host),
            Ok(CheckDestination::Name(name)) if name == host
        );
        let under = |suffix: &String| {
            host.strip_suffix(suffix.as_str())
                .and_then(|label| label.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty())
        };
        (canonical && self.suffixes.iter().any(under)).then(|| host.to_owned())
    }

    /// The CA certificate, DER, for the environment's trust store.
    pub fn certificate_der(&self) -> &CertificateDer<'static> {
        self.certificate.der()
    }

    /// The CA certificate, PEM, for the environment's trust store.
    pub fn certificate_pem(&self) -> String {
        self.certificate.pem()
    }

    /// The canonical bound host matching `host` and its current leaf, minted
    /// on first use and again once it is half way through its life.
    pub(crate) fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError> {
        let host = self.signed_name(host).ok_or(CaError::UnboundHost)?;
        let host = &host;
        let mut leaves = self.leaves.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(leaf) = leaves.get(host)
            && leaf.renew_at > Instant::now()
        {
            return Ok((host.clone(), leaf.key.clone()));
        }
        let key = self.mint(host)?;
        if leaves.len() >= MAX_CACHED_LEAVES && !leaves.contains_key(host) {
            // Only a subname's leaf is ever dropped: the bound hosts' are
            // at most MAX_BOUND_HOSTS, well under the bound.
            let oldest = leaves
                .iter()
                .filter(|(name, _)| !self.hosts.contains(name))
                .min_by_key(|(_, leaf)| leaf.renew_at)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                leaves.remove(&oldest);
            }
        }
        leaves.insert(
            host.clone(),
            Leaf {
                key: key.clone(),
                renew_at: Instant::now() + LEAF_RENEW_AFTER,
            },
        );
        Ok((host.clone(), key))
    }

    fn mint(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let now = OffsetDateTime::now_utc();
        if now >= self.not_after {
            return Err(CaError::Expired);
        }
        let key = SecretKey(
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| CaError::Generate)?,
        );
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|_| CaError::Generate)?;
        params.distinguished_name = DistinguishedName::new();
        // A common name is at most 64 characters; a longer name is named by
        // the subject alternative name alone, which is what clients check.
        if host.len() <= MAX_COMMON_NAME_LEN {
            params.distinguished_name.push(DnType::CommonName, host);
        }
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - BACKDATE;
        params.not_after = (now + LEAF_VALIDITY).min(self.not_after);
        let certificate = params
            .signed_by(&key.0, &self.certificate, &self.key.0)
            .map_err(|_| CaError::Generate)?;
        let pkcs8 = Zeroizing::new(key.0.serialize_der());
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        ))
        .map_err(|_| CaError::Generate)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![certificate.der().clone()],
            signing_key,
        )))
    }

    /// How many leaves are cached now.
    #[cfg(test)]
    pub(crate) fn cached_leaves(&self) -> usize {
        self.leaves
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Signs anything with this CA's key: how tests build certificates the
    /// CA would never mint.
    #[cfg(test)]
    pub(crate) fn sign_for_test(&self, params: CertificateParams, key: &KeyPair) -> Certificate {
        params
            .signed_by(key, &self.certificate, &self.key.0)
            .expect("test certificate")
    }
}

/// The policy crate's canonical host names, taken as they are: a name that
/// needed lowercasing or a trailing dot removed is not exact, and a single
/// label would let the name constraint cover a whole top-level domain.
fn canonical_hosts<I, H>(hosts: I) -> Result<Vec<String>, CaError>
where
    I: IntoIterator<Item = H>,
    H: AsRef<str>,
{
    let mut canonical: Vec<String> = Vec::new();
    for host in hosts {
        let host = host.as_ref();
        let exact = matches!(
            CheckDestination::parse(host),
            Ok(CheckDestination::Name(name)) if name == host && name.contains('.')
        );
        if !exact || canonical.len() == MAX_BOUND_HOSTS || canonical.iter().any(|h| h == host) {
            return Err(CaError::InvalidBoundHosts);
        }
        canonical.push(host.to_owned());
    }
    if canonical.is_empty() {
        return Err(CaError::InvalidBoundHosts);
    }
    Ok(canonical)
}
