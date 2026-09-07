use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use base64::Engine as _;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    pem::PemObject,
};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{RootCertStore, ServerConfig};
use tokio::sync::{Semaphore, oneshot};
use zeroize::Zeroizing;

use crate::{TLS_TIMEOUT, TlsError};

pub(crate) const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_KEY_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATES: usize = 32;
const MAX_FILE_JOBS: usize = 32;
static FILE_JOBS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_FILE_JOBS)));

type FileResult = Result<Zeroizing<Vec<u8>>, TlsError>;

/// Fixed mounted paths. Kubernetes' atomic projected symlinks are supported;
/// paths are never derived from a request and private keys stay in this process.
/// Cancellation bounds the caller's wait, not an already-entered OS file call;
/// that call retains its finite loader capacity until it actually finishes.
#[derive(Clone)]
pub struct ServerTlsFiles {
    cert_chain: PathBuf,
    key: PathBuf,
}

impl fmt::Debug for ServerTlsFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerTlsFiles([redacted])")
    }
}

impl ServerTlsFiles {
    pub fn new(cert_chain: PathBuf, key: PathBuf) -> Result<Self, TlsError> {
        validate_path(&cert_chain)?;
        validate_path(&key)?;
        if cert_chain == key {
            return Err(TlsError::Configuration);
        }
        Ok(Self { cert_chain, key })
    }

    /// Validate current files offline, without caching their contents. A later
    /// projection change is independently validated by each new handshake.
    pub async fn validate(&self) -> Result<(), TlsError> {
        tokio::time::timeout(TLS_TIMEOUT, self.load(true))
            .await
            .map_err(|_| TlsError::Timeout)??;
        Ok(())
    }

    pub(crate) async fn load(&self, http1: bool) -> Result<Arc<ServerConfig>, TlsError> {
        let chain = read_regular(&self.cert_chain, MAX_CERTIFICATE_BYTES).await?;
        let certificates = certificates(&chain)?;
        let pem = read_regular(&self.key, MAX_KEY_BYTES).await?;
        let key = private_key(&pem)?;
        // Borrow the zeroizing DER rather than passing an unguarded owned DER
        // allocation into with_single_cert. Ring owns the resulting signing key.
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| TlsError::InvalidPem)?;
        let identity = CertifiedKey::new(certificates, signing_key);
        identity.keys_match().map_err(|_| TlsError::InvalidPem)?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| TlsError::Configuration)?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(identity)));
        config.alpn_protocols = vec![b"h2".to_vec()];
        if http1 {
            config.alpn_protocols.push(b"http/1.1".to_vec());
        }
        Ok(Arc::new(config))
    }
}

pub(crate) fn validate_path(path: &Path) -> Result<(), TlsError> {
    if !path.is_absolute() || path.file_name().is_none() {
        Err(TlsError::Configuration)
    } else {
        Ok(())
    }
}

pub(crate) async fn read_regular(path: &Path, limit: usize) -> FileResult {
    let path = path.to_owned();
    run_file_job(&FILE_JOBS, move |completion| {
        read_regular_blocking(&path, limit, || completion.is_closed())
    })
    .await
}

// A canceled handshake cannot interrupt an entered OS filesystem operation.
// Each actual blocking job retains its process-wide capacity until completion,
// including after its result receiver is dropped. The five-second caller bound
// closes admission/sockets, not a stuck filesystem syscall or runtime shutdown.
// Direct std reads avoid Tokio File's additional non-zeroizing read buffer.
async fn run_file_job(
    capacity: &Arc<Semaphore>,
    operation: impl FnOnce(&oneshot::Sender<FileResult>) -> FileResult + Send + 'static,
) -> FileResult {
    let permit = capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| TlsError::Files)?;
    let (sender, receiver) = oneshot::channel();
    drop(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if sender.is_closed() {
            return;
        }
        let result = operation(&sender);
        // If canceled, dropping the unsent result still zeroizes its buffer.
        let _ = sender.send(result);
    }));
    receiver.await.map_err(|_| TlsError::Files)?
}

fn read_regular_blocking(path: &Path, limit: usize, canceled: impl Fn() -> bool) -> FileResult {
    let check_live = || {
        if canceled() {
            Err(TlsError::Files)
        } else {
            Ok(())
        }
    };
    check_live()?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // Follow projected-volume symlinks, but do not let a raced FIFO open block
    // forever. Validate the opened descriptor, not a pre-open pathname check.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|_| TlsError::Files)?;
    check_live()?;
    let metadata = file.metadata().map_err(|_| TlsError::Files)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err(TlsError::Files);
    }
    check_live()?;
    let length = metadata.len() as usize;
    // Fixed-size reads avoid reallocating an unzeroized former allocation.
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    let mut offset = 0;
    while offset < length {
        check_live()?;
        match file.read(&mut bytes[offset..]) {
            Ok(0) => return Err(TlsError::Files),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(TlsError::Files),
        }
    }
    let mut extra = Zeroizing::new([0u8; 1]);
    loop {
        check_live()?;
        match file.read(&mut extra[..]) {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => return Err(TlsError::Files),
        }
    }
    check_live()?;
    Ok(bytes)
}

pub(crate) fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut remaining = pem;
    let mut certificates = Vec::new();
    let mut validator = RootCertStore::empty();
    while !remaining.trim_ascii().is_empty() {
        if certificates.len() == MAX_CERTIFICATES {
            return Err(TlsError::InvalidPem);
        }
        let section = section(
            &mut remaining,
            b"-----BEGIN CERTIFICATE-----",
            b"-----END CERTIFICATE-----",
        )?;
        let certificate =
            CertificateDer::from_pem_slice(section).map_err(|_| TlsError::InvalidPem)?;
        // Do not let tonic's permissive add_parsable_certificates silently
        // discard a malformed member of a trust bundle.
        validator
            .add(certificate.clone())
            .map_err(|_| TlsError::InvalidPem)?;
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        Err(TlsError::InvalidPem)
    } else {
        Ok(certificates)
    }
}

fn private_key(pem: &[u8]) -> Result<Zeroizing<PrivateKeyDer<'static>>, TlsError> {
    let mut remaining = pem;
    // These are public format delimiters, not embedded private material.
    // Construct each pair at compile time from its explicit PEM label.
    macro_rules! pem_tags {
        ($label:literal) => {
            (
                concat!("-----BEGIN ", $label, "-----").as_bytes(),
                concat!("-----END ", $label, "-----").as_bytes(),
            )
        };
    }
    let tags: &[(&[u8], &[u8])] = &[
        pem_tags!("PRIVATE KEY"),
        pem_tags!("RSA PRIVATE KEY"),
        pem_tags!("EC PRIVATE KEY"),
    ];
    let (begin, end) = tags
        .iter()
        .find(|(begin, _)| pem.trim_ascii_start().starts_with(begin))
        .ok_or(TlsError::InvalidPem)?;
    let section = section(&mut remaining, begin, end)?;
    if !remaining.trim_ascii().is_empty() {
        return Err(TlsError::InvalidPem);
    }
    // PemObject's private-key decoder uses non-zeroizing base64 scratch. Keep
    // both encoded and decoded private-key scratch under explicit ownership.
    let body = &section[begin.len()..section.len() - end.len()];
    let mut encoded = Zeroizing::new(Vec::with_capacity(body.len()));
    encoded.extend(
        body.iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace()),
    );
    let mut decoded = Zeroizing::new(Vec::new());
    base64::engine::general_purpose::STANDARD
        .decode_vec(encoded.as_slice(), &mut decoded)
        .map_err(|_| TlsError::InvalidPem)?;
    let der = std::mem::take(&mut *decoded);
    let key = if *begin == tags[0].0 {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    } else if *begin == tags[1].0 {
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))
    } else {
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))
    };
    Ok(Zeroizing::new(key))
}

fn section<'a>(remaining: &mut &'a [u8], begin: &[u8], end: &[u8]) -> Result<&'a [u8], TlsError> {
    let bytes = remaining.trim_ascii_start();
    if !bytes.starts_with(begin) {
        return Err(TlsError::InvalidPem);
    }
    let end_at = bytes
        .windows(end.len())
        .position(|window| window == end)
        .ok_or(TlsError::InvalidPem)?
        + end.len();
    *remaining = &bytes[end_at..];
    Ok(&bytes[..end_at])
}

#[cfg(test)]
mod tests;
