use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use zeroize::Zeroizing;

use crate::files::{MAX_CERTIFICATE_BYTES, certificates, read_regular, validate_path};
use crate::{TLS_TIMEOUT, TlsError};

/// One exact HTTPS DNS origin and its purpose-specific public roots. No
/// request can override the destination, TLS name or trust configuration.
#[derive(Clone)]
pub struct ClientTlsEndpoint {
    origin: String,
    roots: Roots,
}

/// Where an endpoint's public roots come from.
#[derive(Clone)]
enum Roots {
    /// Mounted roots, reread on every use so a rotation applies at once.
    Mounted(PathBuf),
    /// Roots fixed when the endpoint is built and never reread, for a caller
    /// whose trust is measured and must not follow any file.
    Fixed(Arc<[u8]>),
}

impl fmt::Debug for ClientTlsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientTlsEndpoint([redacted])")
    }
}

impl ClientTlsEndpoint {
    pub fn new(https_origin: String, roots: PathBuf) -> Result<Self, TlsError> {
        validate_path(&roots)?;
        validate_origin(&https_origin)?;
        Ok(Self {
            origin: https_origin,
            roots: Roots::Mounted(roots),
        })
    }

    /// An endpoint that trusts exactly `pem`, parsed in full now and never
    /// reread. Any malformed member refuses the whole bundle.
    pub fn with_fixed_roots(https_origin: String, pem: &[u8]) -> Result<Self, TlsError> {
        validate_origin(&https_origin)?;
        if pem.len() > MAX_CERTIFICATE_BYTES {
            return Err(TlsError::InvalidPem);
        }
        certificates(pem)?;
        Ok(Self {
            origin: https_origin,
            roots: Roots::Fixed(Arc::from(pem)),
        })
    }

    async fn root_bytes(&self) -> Result<Zeroizing<Vec<u8>>, TlsError> {
        match &self.roots {
            Roots::Mounted(path) => read_regular(path, MAX_CERTIFICATE_BYTES).await,
            Roots::Fixed(pem) => Ok(Zeroizing::new(pem.to_vec())),
        }
    }
}

/// An exact `https` DNS origin: no credentials, path, query, fragment, IP
/// literal or zero port.
fn validate_origin(https_origin: &str) -> Result<(), TlsError> {
    let url = url::Url::parse(https_origin).map_err(|_| TlsError::Configuration)?;
    let uri: http::Uri = https_origin.parse().map_err(|_| TlsError::Configuration)?;
    let host = uri.host().ok_or(TlsError::Configuration)?;
    if url.scheme() != "https"
        || uri.scheme_str() != Some("https")
        || !https_origin.is_ascii()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
        || uri.authority().is_none_or(|value| {
            value.as_str().contains('@')
                || (value.as_str() != value.host() && value.port_u16().is_none_or(|port| port == 0))
        })
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || !matches!(ServerName::try_from(host), Ok(ServerName::DnsName(_)))
    {
        return Err(TlsError::Configuration);
    }
    Ok(())
}

impl ClientTlsEndpoint {
    /// Validate current public roots without contacting the endpoint.
    pub async fn validate(&self) -> Result<(), TlsError> {
        tokio::time::timeout(TLS_TIMEOUT, self.tls_config())
            .await
            .map_err(|_| TlsError::Timeout)??;
        Ok(())
    }

    /// A fresh channel with current roots on every invocation. This never
    /// enables native/web roots, key logging, custom verification or redirects.
    /// Tonic uses its ring feature unless the trusted binary installed a
    /// process-wide Rustls provider; both use default-safe protocol versions.
    pub async fn connect(&self) -> Result<Channel, TlsError> {
        tokio::time::timeout(TLS_TIMEOUT, async {
            let tls = self.tls_config().await?;
            Endpoint::from_shared(self.origin.clone())
                .map_err(|_| TlsError::Configuration)?
                .connect_timeout(TLS_TIMEOUT)
                .tls_config(tls)
                .map_err(|_| TlsError::InvalidPem)?
                .connect()
                .await
                .map_err(|_| TlsError::Connect)
        })
        .await
        .map_err(|_| TlsError::Timeout)?
    }

    /// A Rustls client configuration that trusts exactly the current roots.
    /// It names its ring provider rather than a process default, so a binary
    /// that also compiles another provider cannot change or panic its choice.
    pub(crate) async fn rustls_config(&self) -> Result<rustls::ClientConfig, TlsError> {
        let bytes = tokio::time::timeout(TLS_TIMEOUT, self.root_bytes())
            .await
            .map_err(|_| TlsError::Timeout)??;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates(&bytes)? {
            roots.add(certificate).map_err(|_| TlsError::InvalidPem)?;
        }
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }

    async fn tls_config(&self) -> Result<ClientTlsConfig, TlsError> {
        let bytes = self.root_bytes().await?;
        certificates(&bytes)?;
        // Pass the fully checked PEM, not a partially accepted root list. DNS
        // verification is tonic's default URI-host verification: no override.
        Ok(ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(bytes.as_slice()))
            .timeout(TLS_TIMEOUT))
    }
}
