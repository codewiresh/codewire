use std::fmt;
use std::path::PathBuf;

use rustls::pki_types::ServerName;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use crate::files::{MAX_CERTIFICATE_BYTES, certificates, read_regular, validate_path};
use crate::{TLS_TIMEOUT, TlsError};

/// One exact HTTPS DNS origin and its purpose-specific mounted public roots.
/// No request can override the destination, TLS name or trust configuration.
#[derive(Clone)]
pub struct ClientTlsEndpoint {
    origin: String,
    roots: PathBuf,
}

impl fmt::Debug for ClientTlsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientTlsEndpoint([redacted])")
    }
}

impl ClientTlsEndpoint {
    pub fn new(https_origin: String, roots: PathBuf) -> Result<Self, TlsError> {
        validate_path(&roots)?;
        let url = url::Url::parse(&https_origin).map_err(|_| TlsError::Configuration)?;
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
                    || (value.as_str() != value.host()
                        && value.port_u16().is_none_or(|port| port == 0))
            })
            || url.port_or_known_default().is_none_or(|port| port == 0)
            || !matches!(ServerName::try_from(host), Ok(ServerName::DnsName(_)))
        {
            return Err(TlsError::Configuration);
        }
        Ok(Self {
            origin: https_origin,
            roots,
        })
    }

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

    async fn tls_config(&self) -> Result<ClientTlsConfig, TlsError> {
        let bytes = read_regular(&self.roots, MAX_CERTIFICATE_BYTES).await?;
        certificates(&bytes)?;
        // Pass the fully checked PEM, not a partially accepted root list. DNS
        // verification is tonic's default URI-host verification: no override.
        Ok(ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(bytes.as_slice()))
            .timeout(TLS_TIMEOUT))
    }
}
