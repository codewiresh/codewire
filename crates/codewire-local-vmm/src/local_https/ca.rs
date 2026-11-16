//! The per-user certificate authority for local HTTPS hostnames.
//!
//! Unlike an environment's egress CA, which lives only in one process's
//! memory, this CA is kept on disk so the browsers that trust it keep trusting
//! it across supervisor restarts and upgrades. Its name constraint permits
//! only names under [`SUFFIX`] and excludes every IP address, so even a leaked
//! key cannot vouch for any other site. The key is owner-read-only in an
//! owner-only directory, and is never printed or logged.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use codewire_egress_front_door::{CaError, CertifiedKey, LeafSource};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::{Zeroize, Zeroizing};

use super::SUFFIX;

/// The CA's directory under the supervisor's state root.
pub(crate) const CA_DIRECTORY: &str = "local-https";
/// The CA certificate, PEM: what a browser or tool must trust. `cw local-https
/// status` prints its path.
pub(crate) const CA_CERTIFICATE_FILE: &str = "ca.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const CA_COMMON_NAME: &str = "Codewire local HTTPS CA";
const DIRECTORY_MODE: u32 = 0o700;
const KEY_MODE: u32 = 0o400;
const CERTIFICATE_MODE: u32 = 0o444;
/// How long the CA certificate is valid after it is generated.
pub(crate) const CA_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
/// How long a leaf is valid after it is minted, never past the CA's end.
pub(crate) const LEAF_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
/// A cached leaf is replaced once it is this old, well before it expires.
const LEAF_RENEW_AFTER: Duration = Duration::from_secs(12 * 60 * 60);
/// How far every certificate's start is moved back, for a clock that steps.
const BACKDATE: Duration = Duration::from_secs(5 * 60);
/// The most leaves held at once; the cache starts again when it is full.
const MAX_CACHED_LEAVES: usize = 256;

/// Why the CA could not be loaded or made. Carries no key material.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalCaError {
    #[error("local HTTPS CA directory: {0}")]
    Io(#[from] io::Error),
    #[error("the local HTTPS CA key or certificate is unreadable")]
    Invalid,
    #[error("the local HTTPS CA certificate does not match its key")]
    Mismatch,
    /// The key is not this user's alone. `cw local-https rotate` removes the
    /// CA from every store it was trusted in and makes a new one.
    #[error(
        "the local HTTPS CA key {0} must belong to you and be readable only by you; run `cw local-https rotate` for a new CA"
    )]
    Exposed(PathBuf),
    #[error("local HTTPS CA generation failed")]
    Generate,
}

/// The CA, loaded from `<state root>/local-https` or made there on first use.
pub(crate) struct LocalCa {
    /// The CA as an issuer: rebuilt from the stored key with the same
    /// subject, so a leaf it signs chains to the stored certificate.
    issuer: Certificate,
    key: SecretKey,
    not_after: OffsetDateTime,
    leaves: Mutex<HashMap<String, Leaf>>,
}

/// A key pair whose PKCS#8 encoding is wiped on drop.
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

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCa")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// Serialises making and removing the CA's files in this process, so a
/// rotation and the router's first load never pair one call's key with the
/// other's certificate.
static CA_FILES: Mutex<()> = Mutex::new(());

/// Remove the CA's key and certificate, so the next load makes a new CA.
/// Trust stores are the caller's to clean first: `cw local-https rotate`
/// untrusts the old CA before it asks for this.
pub(crate) fn remove(state_root: &Path) -> io::Result<()> {
    let _files = CA_FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let directory = state_root.join(CA_DIRECTORY);
    // The key goes first. Were the certificate removed first, a failure or a
    // crash before the shred would leave the old, perhaps read, key for the
    // next load to sign a fresh certificate with, so the CA would look
    // rotated and wasn't. Without a key, the next load makes a new key and
    // removes any certificate left behind.
    shred(&directory.join(CA_KEY_FILE))?;
    remove_if_present(&directory.join(CA_CERTIFICATE_FILE))
}

/// Overwrite the key file with zeros and sync it before removing it, so the
/// old key's bytes don't stay in the file's blocks. Best effort on
/// copy-on-write and journalling filesystems, which may keep old blocks.
fn shred(path: &Path) -> io::Result<()> {
    let length = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return remove_if_present(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let zeros = vec![0_u8; usize::try_from(length).unwrap_or(usize::MAX).min(1 << 20)];
        file.write_all(&zeros)?;
        file.sync_all()?;
    }
    fs::remove_file(path)
}

impl LocalCa {
    /// The CA under `state_root`: the stored one when present, otherwise a
    /// new one, written owner-only. A stored certificate that no longer
    /// matches its key is refused, never replaced, because browsers may
    /// trust it.
    pub(crate) fn load_or_create(state_root: &Path) -> Result<Self, LocalCaError> {
        let _files = CA_FILES.lock().unwrap_or_else(PoisonError::into_inner);
        let directory = state_root.join(CA_DIRECTORY);
        ensure_private_directory(&directory)?;
        let key_path = directory.join(CA_KEY_FILE);
        let certificate_path = directory.join(CA_CERTIFICATE_FILE);
        let key = match read_private_key(&key_path) {
            Ok(Some(pem)) => SecretKey(KeyPair::from_pem(&pem).map_err(|_| LocalCaError::Invalid)?),
            Ok(None) => return Err(LocalCaError::Exposed(key_path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let key = SecretKey(
                    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                        .map_err(|_| LocalCaError::Generate)?,
                );
                let pem = Zeroizing::new(key.0.serialize_pem());
                // A certificate left from an older key would never match.
                remove_if_present(&certificate_path)?;
                write_once(&key_path, pem.as_bytes(), KEY_MODE)?;
                key
            }
            Err(error) => return Err(error.into()),
        };
        let not_after = match fs::read(&certificate_path) {
            Ok(pem) => stored_not_after(&pem, &key.0)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let now = OffsetDateTime::now_utc();
                let not_after = now + CA_VALIDITY;
                let certificate = ca_params(now - BACKDATE, not_after)
                    .self_signed(&key.0)
                    .map_err(|_| LocalCaError::Generate)?;
                write_once(
                    &certificate_path,
                    certificate.pem().as_bytes(),
                    CERTIFICATE_MODE,
                )?;
                not_after
            }
            Err(error) => return Err(error.into()),
        };
        let now = OffsetDateTime::now_utc();
        let issuer = ca_params(now - BACKDATE, not_after)
            .self_signed(&key.0)
            .map_err(|_| LocalCaError::Generate)?;
        Ok(Self {
            issuer,
            key,
            not_after,
            leaves: Mutex::new(HashMap::new()),
        })
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
        params.distinguished_name.push(DnType::CommonName, host);
        params.serial_number = Some(random_serial());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - BACKDATE;
        params.not_after = (now + LEAF_VALIDITY).min(self.not_after);
        let certificate = params
            .signed_by(&key.0, &self.issuer, &self.key.0)
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
}

/// Tests elsewhere in the crate: where the key is, without naming its file.
#[cfg(test)]
pub(crate) fn key_path_for_test(state_root: &Path) -> PathBuf {
    state_root.join(CA_DIRECTORY).join(CA_KEY_FILE)
}

#[cfg(test)]
impl LocalCa {
    /// Signs anything with this CA's key: how the verifier proofs build
    /// certificates the CA would never mint.
    pub(crate) fn sign_for_test(&self, params: CertificateParams, key: &KeyPair) -> Certificate {
        params
            .signed_by(key, &self.issuer, &self.key.0)
            .expect("test certificate")
    }
}

impl LeafSource for LocalCa {
    /// A leaf for any one name under [`SUFFIX`]. Which names are served is
    /// the router's decision; this only refuses what the CA could never sign.
    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError> {
        let host = host.to_ascii_lowercase();
        if !super::under_suffix(&host) {
            return Err(CaError::UnboundHost);
        }
        let mut leaves = self.leaves.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(leaf) = leaves.get(&host)
            && leaf.renew_at > Instant::now()
        {
            return Ok((host, leaf.key.clone()));
        }
        let key = self.mint(&host)?;
        if leaves.len() >= MAX_CACHED_LEAVES {
            leaves.clear();
        }
        leaves.insert(
            host.clone(),
            Leaf {
                key: key.clone(),
                renew_at: Instant::now() + LEAF_RENEW_AFTER,
            },
        );
        Ok((host, key))
    }
}

/// The CA's certificate parameters. Only the subject and the key decide
/// whether a leaf chains to the stored certificate, so the issuer rebuilt at
/// each load signs leaves that chain to the certificate written at the first.
fn ca_params(not_before: OffsetDateTime, not_after: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.serial_number = Some(random_serial());
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // A verifier that checks a CA's extended key usage then accepts it for
    // TLS servers only, never client authentication or code signing.
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // A DNS constraint does not limit IP address names, so exclude them all.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(SUFFIX.to_owned())],
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    params.not_before = not_before;
    params.not_after = not_after;
    params
}

/// The stored certificate's end, after checking that it carries `key`'s
/// public key and this CA's subject.
fn stored_not_after(pem: &[u8], key: &KeyPair) -> Result<OffsetDateTime, LocalCaError> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem).map_err(|_| LocalCaError::Invalid)?;
    let (_, certificate) =
        X509Certificate::from_der(&block.contents).map_err(|_| LocalCaError::Invalid)?;
    if certificate.public_key().raw != key.public_key_der().as_slice() {
        return Err(LocalCaError::Mismatch);
    }
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok());
    if common_name != Some(CA_COMMON_NAME) {
        return Err(LocalCaError::Mismatch);
    }
    Ok(certificate.validity().not_after.to_datetime())
}

/// A random positive 128-bit serial, so no two certificates this CA makes,
/// itself included, share one.
fn random_serial() -> SerialNumber {
    let mut bytes: [u8; 16] = rand::random();
    // Positive, and always 16 bytes long.
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    SerialNumber::from_slice(&bytes)
}

/// The key's PEM, never through a symbolic link; `None` when it belongs to
/// another user or others may read or write it.
fn read_private_key(path: &Path) -> io::Result<Option<Zeroizing<String>>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Ok(None);
    }
    let mut pem = Zeroizing::new(String::new());
    file.read_to_string(&mut pem)?;
    Ok(Some(pem))
}

pub(super) fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() != rustix::process::geteuid().as_raw() =>
        {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local HTTPS CA directory belongs to another user",
            ))
        }
        Ok(metadata) if metadata.is_dir() => {
            if metadata.permissions().mode() & 0o777 != DIRECTORY_MODE {
                fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))?;
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local HTTPS CA directory is not a directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(DIRECTORY_MODE)
                .create(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(DIRECTORY_MODE))
        }
        Err(error) => Err(error),
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Write `bytes` to `path` with `mode`, atomically: a new file of this
/// process's own, made with `mode` and never through a symbolic link, synced,
/// then renamed into place, and the directory synced.
pub(super) fn write_once(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    remove_if_present(&temporary)?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    match path.parent() {
        Some(directory) => fs::File::open(directory)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
