use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

use zeroize::Zeroizing;

use crate::files::{
    MAX_CERTIFICATE_BYTES, certificates, identity, read_regular, root_store, validate_path,
};
use crate::{TLS_TIMEOUT, TlsError};

/// One exact HTTPS DNS origin and its purpose-specific public roots. No
/// request can override the destination, TLS name or trust configuration.
#[derive(Clone)]
pub struct ClientTlsEndpoint {
    origin: String,
    roots: Roots,
    identity: Option<ClientIdentity>,
}

/// A mounted client certificate chain and key, reread on every use.
#[derive(Clone)]
struct ClientIdentity {
    cert_chain: PathBuf,
    key: PathBuf,
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
            identity: None,
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
            identity: None,
        })
    }

    /// Also present the mounted client certificate to the server, reread on
    /// every use so a rotation applies to the next connection. Only
    /// [`Self::rustls_config`] presents it; [`Self::connect`] refuses such
    /// an endpoint rather than connect without it.
    pub fn with_client_identity(
        mut self,
        cert_chain: PathBuf,
        key: PathBuf,
    ) -> Result<Self, TlsError> {
        validate_path(&cert_chain)?;
        validate_path(&key)?;
        if cert_chain == key {
            return Err(TlsError::Configuration);
        }
        self.identity = Some(ClientIdentity { cert_chain, key });
        Ok(self)
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
    /// Validate current public roots, and the client identity if there is
    /// one, without contacting the endpoint.
    pub async fn validate(&self) -> Result<(), TlsError> {
        self.rustls_config().await.map(|_| ())
    }

    /// A fresh channel with current roots on every invocation. This never
    /// enables native/web roots, key logging, custom verification or redirects.
    /// Tonic uses its ring feature unless the trusted binary installed a
    /// process-wide Rustls provider; both use default-safe protocol versions.
    pub async fn connect(&self) -> Result<Channel, TlsError> {
        if self.identity.is_some() {
            return Err(TlsError::Configuration);
        }
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

    /// A Rustls client configuration that trusts exactly the current roots
    /// and presents the current client identity, if the endpoint has one.
    /// It names its ring provider rather than a process default, so a binary
    /// that also compiles another provider cannot change or panic its choice.
    pub async fn rustls_config(&self) -> Result<rustls::ClientConfig, TlsError> {
        tokio::time::timeout(TLS_TIMEOUT, async {
            let roots = root_store(&self.root_bytes().await?)?;
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsError::Configuration)?
            .with_root_certificates(roots);
            Ok(match &self.identity {
                None => builder.with_no_client_auth(),
                Some(files) => builder.with_client_cert_resolver(Arc::new(
                    identity(&files.cert_chain, &files.key).await?,
                )),
            })
        })
        .await
        .map_err(|_| TlsError::Timeout)?
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
