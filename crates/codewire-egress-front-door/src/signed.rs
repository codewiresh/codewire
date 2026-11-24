//! Leaves another service signs, for a hosted Sandbox's front door (#4001;
//! `SPEC.md`, cw-egress's front door). The key is made here and never leaves:
//! the caller sends [`SignedLeaves::public_key_spki`] to the signer and
//! installs the certificates it returns. No CA key is ever held here, so a
//! host is served only while a leaf the signer issued covers it and has not
//! expired; otherwise its handshake fails closed.

use std::sync::{Arc, PoisonError, RwLock};

use tokio::sync::watch;

use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use time::OffsetDateTime;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use crate::{CaError, LeafSource};

/// The most leaves one install takes.
const MAX_LEAVES: usize = 32;
/// How far ahead of this node's clock a leaf may start. One that starts later
/// would replace working leaves with ones every handshake refuses, so it is
/// refused and the working set stays.
const CLOCK_SKEW: time::Duration = time::Duration::minutes(2);

/// A front door's own key and the leaves issued for it.
pub struct SignedLeaves {
    signing_key: Arc<dyn SigningKey>,
    spki: Vec<u8>,
    installed: RwLock<Vec<Installed>>,
    /// True from the first install on, for handshakes waiting for it.
    first_installed: watch::Sender<bool>,
}

struct Installed {
    /// Lowercase DNS names, each exact or a one-label `*.` wildcard.
    hosts: Vec<String>,
    not_after: OffsetDateTime,
    key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for SignedLeaves {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        formatter
            .debug_struct("SignedLeaves")
            .finish_non_exhaustive()
    }
}

impl SignedLeaves {
    /// A new ECDSA P-256 key, with no leaf yet: every host fails closed until
    /// [`Self::install`].
    pub fn generate() -> Result<Self, CaError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| CaError::Generate)?;
        let spki = key.public_key_der();
        let pkcs8 = Zeroizing::new(key.serialize_der());
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        ))
        .map_err(|_| CaError::Generate)?;
        Ok(Self {
            signing_key,
            spki,
            installed: RwLock::new(Vec::new()),
            first_installed: watch::Sender::new(false),
        })
    }

    /// The public key, as a DER SubjectPublicKeyInfo: all that leaves.
    pub fn public_key_spki(&self) -> &[u8] {
        &self.spki
    }

    /// Replace every leaf with `leaves`, each a DER certificate. All or
    /// nothing: one that can't be read, isn't for this key, names no DNS
    /// host, has expired or starts more than [`CLOCK_SKEW`] from now installs
    /// none, and the previous leaves stay.
    pub fn install<I, C>(&self, leaves: I) -> Result<(), CaError>
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        let now = OffsetDateTime::now_utc();
        let mut installed = Vec::new();
        for der in leaves {
            if installed.len() == MAX_LEAVES {
                return Err(CaError::InvalidLeaf);
            }
            installed.push(self.read(der.as_ref(), now)?);
        }
        *self
            .installed
            .write()
            .unwrap_or_else(PoisonError::into_inner) = installed;
        self.first_installed.send_replace(true);
        Ok(())
    }

    /// Drop every leaf: intercepted hosts fail closed until the next install.
    pub fn clear(&self) {
        self.installed
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn read(&self, der: &[u8], now: OffsetDateTime) -> Result<Installed, CaError> {
        let (rest, certificate) =
            X509Certificate::from_der(der).map_err(|_| CaError::InvalidLeaf)?;
        if !rest.is_empty() || certificate.public_key().raw != self.spki.as_slice() {
            return Err(CaError::InvalidLeaf);
        }
        let validity = certificate.validity();
        let not_after = validity.not_after.to_datetime();
        if not_after <= now {
            return Err(CaError::Expired);
        }
        if validity.not_before.to_datetime() > now + CLOCK_SKEW {
            return Err(CaError::NotYetValid);
        }
        let hosts: Vec<String> = certificate
            .subject_alternative_name()
            .map_err(|_| CaError::InvalidLeaf)?
            .into_iter()
            .flat_map(|san| san.value.general_names.iter())
            .filter_map(|name| match name {
                GeneralName::DNSName(host) => Some(host.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        if hosts.is_empty() {
            return Err(CaError::InvalidLeaf);
        }
        Ok(Installed {
            hosts,
            not_after,
            key: Arc::new(CertifiedKey::new(
                vec![CertificateDer::from(der.to_vec())],
                Arc::clone(&self.signing_key),
            )),
        })
    }
}

impl LeafSource for SignedLeaves {
    fn first_installed(&self) -> Option<watch::Receiver<bool>> {
        Some(self.first_installed.subscribe())
    }

    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError> {
        let host = host.to_ascii_lowercase();
        let installed = self
            .installed
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let now = OffsetDateTime::now_utc();
        let mut covering = installed
            .iter()
            .filter(|leaf| leaf.hosts.iter().any(|name| covers(name, &host)))
            .peekable();
        if covering.peek().is_none() {
            return Err(CaError::UnboundHost);
        }
        // During a renewal's overlap an older leaf may have expired beside a
        // current one for the same host.
        let leaf = covering
            .find(|leaf| leaf.not_after > now)
            .ok_or(CaError::Expired)?;
        Ok((host, Arc::clone(&leaf.key)))
    }
}

/// Whether a leaf's `name` covers `host`: the same name, or `*.suffix` and a
/// host exactly one label under that suffix, as TLS clients match it.
fn covers(name: &str, host: &str) -> bool {
    match name.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => name == host,
    }
}

#[cfg(test)]
mod tests;
