//! A deployment's own certificate authority, and the TLS trust that pins it to
//! that deployment's exact host names (#4121).
//!
//! A self-hosted deployment may serve HTTPS with a certificate from its own
//! CA. `cw login --ca-file` gives that CA, and every client of the deployment
//! then trusts only it for the pinned host names: never the public WebPKI
//! roots as well, so no public CA can stand in for a host the user tied to
//! their own. Every other host keeps the WebPKI roots and never sees the CA.
//! The CA is a full root, so the exact name check here is the only thing that
//! contains it; a pin is never a suffix or a domain.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::SectionKind;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

/// The largest CA file accepted.
pub const MAX_CA_PEM_BYTES: usize = 64 * 1024;
/// The most certificates a CA file may hold.
pub const MAX_CA_CERTIFICATES: usize = 8;

/// Why a CA file was refused. Certificates are numbered from 1, in file order.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentCaError {
    #[error("the CA file is larger than {MAX_CA_PEM_BYTES} bytes")]
    TooLarge,
    #[error("the CA file is not valid PEM")]
    InvalidPem,
    #[error("the CA file holds a private key; give only the CA certificate")]
    PrivateKey,
    #[error("the CA file holds a PEM block that is not a certificate")]
    NotACertificate,
    #[error("the CA file holds no certificate")]
    Empty,
    #[error("the CA file holds more than {MAX_CA_CERTIFICATES} certificates")]
    TooMany,
    #[error("certificate {index} in the CA file cannot be parsed")]
    Unparseable { index: usize },
    #[error("certificate {index} in the CA file is not a certificate authority")]
    NotACertificateAuthority { index: usize },
    #[error(
        "certificate {index} in the CA file is not valid now (valid from {not_before} to {not_after})"
    )]
    OutOfDate {
        index: usize,
        not_before: String,
        not_after: String,
    },
    #[error("the CA cannot be used for TLS: {0}")]
    Tls(String),
}

/// The certificate authorities a deployment's HTTPS certificates chain to:
/// every one parsed, a CA (`cA=true`) and in date when it was read.
#[derive(Clone, Debug)]
pub struct DeploymentCa {
    certificates: Arc<[CertificateDer<'static>]>,
    fingerprints: Arc<[String]>,
}

impl DeploymentCa {
    /// Read a PEM CA file. Every block must be a certificate: a private key
    /// or any other block refuses the whole file.
    pub fn from_pem(pem: &[u8]) -> Result<Self, DeploymentCaError> {
        Self::from_pem_at(pem, UnixTime::now())
    }

    fn from_pem_at(pem: &[u8], now: UnixTime) -> Result<Self, DeploymentCaError> {
        if pem.len() > MAX_CA_PEM_BYTES {
            return Err(DeploymentCaError::TooLarge);
        }
        let certificates = pem_certificates(pem)?;
        for (offset, certificate) in certificates.iter().enumerate() {
            check_authority(offset + 1, certificate, now)?;
        }
        let fingerprints = certificates.iter().map(fingerprint).collect();
        Ok(Self {
            certificates: certificates.into(),
            fingerprints,
        })
    }

    /// Each certificate's SHA-256 fingerprint over its DER, as `openssl x509
    /// -fingerprint -sha256` prints it: colon-separated uppercase hex.
    pub fn fingerprints(&self) -> &[String] {
        &self.fingerprints
    }

    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, DeploymentCaError> {
    let mut reader = pem;
    let mut certificates = Vec::new();
    loop {
        match rustls::pki_types::pem::from_buf(&mut reader) {
            Ok(None) => break,
            Ok(Some((SectionKind::Certificate, der))) => {
                if certificates.len() == MAX_CA_CERTIFICATES {
                    return Err(DeploymentCaError::TooMany);
                }
                certificates.push(CertificateDer::from(der));
            }
            Ok(Some((
                SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey,
                _,
            ))) => return Err(DeploymentCaError::PrivateKey),
            Ok(Some(_)) => return Err(DeploymentCaError::NotACertificate),
            Err(_) => return Err(DeploymentCaError::InvalidPem),
        }
    }
    if certificates.is_empty() {
        return Err(DeploymentCaError::Empty);
    }
    Ok(certificates)
}

fn check_authority(
    index: usize,
    certificate: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<(), DeploymentCaError> {
    let (rest, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|_| DeploymentCaError::Unparseable { index })?;
    if !rest.is_empty() {
        return Err(DeploymentCaError::Unparseable { index });
    }
    let authority = parsed
        .basic_constraints()
        .map_err(|_| DeploymentCaError::Unparseable { index })?
        .is_some_and(|constraints| constraints.value.ca);
    if !authority {
        return Err(DeploymentCaError::NotACertificateAuthority { index });
    }
    let now = i64::try_from(now.as_secs())
        .ok()
        .and_then(|seconds| x509_parser::time::ASN1Time::from_timestamp(seconds).ok())
        .ok_or(DeploymentCaError::Unparseable { index })?;
    let validity = parsed.validity();
    if !validity.is_valid_at(now) {
        return Err(DeploymentCaError::OutOfDate {
            index,
            not_before: validity.not_before.to_string(),
            not_after: validity.not_after.to_string(),
        });
    }
    Ok(())
}

fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A deployment CA and the exact host names it is trusted for.
#[derive(Clone, Debug)]
pub(crate) struct DeploymentTrust {
    ca: DeploymentCa,
    hosts: Arc<[ServerName<'static>]>,
}

impl DeploymentTrust {
    pub(crate) fn new(ca: DeploymentCa, host: ServerName<'static>) -> Self {
        Self {
            ca,
            hosts: Arc::from([host]),
        }
    }

    pub(crate) fn ca(&self) -> &DeploymentCa {
        &self.ca
    }

    /// TLS settings that verify the pinned hosts against the CA alone, and
    /// every other host against the public WebPKI roots.
    pub(crate) fn tls_config(&self) -> Result<rustls::ClientConfig, DeploymentCaError> {
        self.tls_config_with_public_roots(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    fn tls_config_with_public_roots(
        &self,
        public_roots: RootCertStore,
    ) -> Result<rustls::ClientConfig, DeploymentCaError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut deployment_roots = RootCertStore::empty();
        for certificate in self.ca.certificates.iter() {
            deployment_roots
                .add(certificate.clone())
                .map_err(|error| DeploymentCaError::Tls(error.to_string()))?;
        }
        let verifier = PinnedHostsVerifier {
            hosts: self.hosts.clone(),
            deployment: webpki_verifier(deployment_roots, &provider)?,
            public: webpki_verifier(public_roots, &provider)?,
        };
        // A custom verifier is installed through `dangerous()`; this one only
        // chooses which full WebPKI verifier checks the chain, name and time.
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| DeploymentCaError::Tls(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // Connect streams need HTTP/2; other calls may use HTTP/1.1.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn webpki_verifier(
    roots: RootCertStore,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, DeploymentCaError> {
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| DeploymentCaError::Tls(error.to_string()))
}

/// Verifies a pinned host's certificate against the deployment CA alone and
/// any other host's against the public roots. Both are rustls's own WebPKI
/// verifier, so the chain, the name and the validity period are always
/// checked; this only chooses the roots.
#[derive(Debug)]
struct PinnedHostsVerifier {
    hosts: Arc<[ServerName<'static>]>,
    deployment: Arc<WebPkiServerVerifier>,
    public: Arc<WebPkiServerVerifier>,
}

impl PinnedHostsVerifier {
    fn verifier_for(&self, name: &ServerName<'_>) -> &WebPkiServerVerifier {
        if self.hosts.iter().any(|host| same_host(host, name)) {
            &self.deployment
        } else {
            &self.public
        }
    }
}

/// The exact same host: DNS names compared without regard to ASCII case, IP
/// addresses as addresses. A DNS name never matches an IP address.
fn same_host(pinned: &ServerName<'_>, name: &ServerName<'_>) -> bool {
    match (pinned, name) {
        (ServerName::DnsName(pinned), ServerName::DnsName(name)) => {
            pinned.as_ref().eq_ignore_ascii_case(name.as_ref())
        }
        (ServerName::IpAddress(pinned), ServerName::IpAddress(name)) => pinned == name,
        _ => false,
    }
}

impl ServerCertVerifier for PinnedHostsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verifier_for(server_name).verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.public.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests;
