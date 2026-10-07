//! Connect client transport for one exact cluster-local HTTPS origin.
//!
//! Every call rereads the origin's purpose-specific mounted public roots and
//! opens a verified connection with them. There is no plaintext form, and a
//! request for any other scheme or authority is refused.

use std::path::Path;

use connectrpc::ConnectError;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use http::{Request, Response};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::{ClientTlsEndpoint, TLS_TIMEOUT, TlsError};

/// A Connect transport for one cluster-local HTTPS origin.
#[derive(Clone)]
pub struct ConnectOriginTransport {
    authority: http::uri::Authority,
    endpoint: ClientTlsEndpoint,
    http1_only: bool,
}

impl std::fmt::Debug for ConnectOriginTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectOriginTransport([redacted])")
    }
}

impl ConnectOriginTransport {
    /// Validates without reading or contacting anything: the origin must be an
    /// exact `https` DNS origin and the roots an absolute file path.
    pub fn for_origin(origin: &str, roots: &Path) -> Result<Self, TlsError> {
        let endpoint = ClientTlsEndpoint::new(origin.to_owned(), roots.to_path_buf())?;
        let authority = origin
            .parse::<http::Uri>()
            .map_err(|_| TlsError::Configuration)?
            .authority()
            .cloned()
            .ok_or(TlsError::Configuration)?;
        Ok(Self {
            authority,
            endpoint,
            http1_only: false,
        })
    }

    /// Offer only HTTP/1.1 (ALPN `http/1.1`), for a bounded listener that
    /// refuses HTTP/2, such as the tenant-reachable workspace-binding
    /// listener.
    pub fn http1_only(mut self) -> Self {
        self.http1_only = true;
        self
    }
}

impl ClientTransport for ConnectOriginTransport {
    type ResponseBody = Incoming;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Incoming>, ConnectError>> {
        // A request never leaves the configured origin, whatever base URL its
        // client was given.
        if request.uri().scheme() != Some(&http::uri::Scheme::HTTPS)
            || request.uri().authority() != Some(&self.authority)
        {
            return Box::pin(async {
                Err(ConnectError::invalid_argument(
                    "request does not address the transport's configured origin",
                ))
            });
        }
        let endpoint = self.endpoint.clone();
        let http1_only = self.http1_only;
        Box::pin(async move {
            // The error class carries no path, PEM or peer detail.
            let config = endpoint.rustls_config().await.map_err(|error| {
                ConnectError::unavailable(format!("internal TLS trust unavailable: {error}"))
            })?;
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            http.set_nodelay(true);
            http.set_connect_timeout(Some(TLS_TIMEOUT));
            let https = HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_only();
            let https = if http1_only {
                https.enable_http1().wrap_connector(http)
            } else {
                https.enable_all_versions().wrap_connector(http)
            };
            Client::builder(TokioExecutor::new())
                .build(https)
                .request(request)
                .await
                .map_err(|error| {
                    ConnectError::unavailable_from_transport("HTTPS request failed", error)
                })
        })
    }
}
