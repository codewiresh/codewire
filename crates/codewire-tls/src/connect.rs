//! Connect client transport for one exact cluster-local HTTPS origin.
//!
//! Every call opens a verified connection with the origin's purpose-specific
//! public roots: mounted roots are reread on every call, and fixed roots (a
//! confidential workspace's measured ones) never change. There is no
//! plaintext form, and a request for any other scheme or authority is refused.
//!
//! The origin's host is looked up as an absolute DNS name (#2701). A Pod
//! resolves with `ndots:5`, so a cluster name such as
//! `codewire-orchestration-workspace-binding.dev.svc.cluster.local` would
//! otherwise be tried with each search domain appended first, and a static
//! musl `cw` abandons the whole lookup when one of those answers SERVFAIL.
//! The TLS server name and the HTTP authority keep the origin's host.
//!
//! A caller that must not resolve cluster names at all (cw-egress, whose Pod
//! has no cluster DNS) gives the address to dial instead; the origin's host
//! is then only the name TLS verifies and the request addresses.
//!
//! A hosted Sandbox's daemon also chooses how the socket leaves: every
//! platform connection goes by the Pod interface (#4000).
//! [`ConnectOriginTransport::dialing_through`] gives it a fixed peer address
//! and its own dial, and keeps the origin's names for TLS and HTTP.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use connectrpc::ConnectError;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use http::{Request, Response};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
// `tower_service::Service`, the resolver trait hyper-util's connector takes.
use tonic::codegen::Service;

use crate::{ClientTlsEndpoint, TLS_TIMEOUT, TlsError};

/// Opens the TCP connection to a peer, for a caller that must choose how its
/// sockets leave the host.
pub type PeerDial = Arc<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> + Send + Sync,
>;

/// A Connect transport for one cluster-local HTTPS origin.
#[derive(Clone)]
pub struct ConnectOriginTransport {
    authority: http::uri::Authority,
    endpoint: ClientTlsEndpoint,
    http1_only: bool,
    dial: Option<IpAddr>,
    /// Set by [`Self::dialing_through`]: the origin's fixed address and how
    /// to reach it. It takes precedence over `dial`.
    through: Option<(SocketAddr, PeerDial)>,
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
        Self::with_endpoint(
            origin,
            ClientTlsEndpoint::new(origin.to_owned(), roots.to_path_buf())?,
        )
    }

    /// The same origin rules, trusting exactly `pem`: parsed in full now and
    /// never reread from any file.
    pub fn for_origin_with_fixed_roots(origin: &str, pem: &[u8]) -> Result<Self, TlsError> {
        Self::with_endpoint(
            origin,
            ClientTlsEndpoint::with_fixed_roots(origin.to_owned(), pem)?,
        )
    }

    fn with_endpoint(origin: &str, endpoint: ClientTlsEndpoint) -> Result<Self, TlsError> {
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
            dial: None,
            through: None,
        })
    }

    /// Offer only HTTP/1.1 (ALPN `http/1.1`), for a bounded listener that
    /// refuses HTTP/2, such as the tenant-reachable workspace-binding
    /// listener.
    pub fn http1_only(mut self) -> Self {
        self.http1_only = true;
        self
    }

    /// Connect to `address`, at the origin's port, without looking the
    /// origin's host up.
    pub fn dialing(mut self, address: IpAddr) -> Self {
        self.dial = Some(address);
        self
    }

    /// Reach the origin at `peer` through `dial`, looking up no name. The TLS
    /// server name and the HTTP authority are still the origin's.
    pub fn dialing_through(mut self, peer: SocketAddr, dial: PeerDial) -> Self {
        self.through = Some((peer, dial));
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
        match self.dial {
            Some(address) => self.send_resolving(Dial(address), request),
            None => self.send_resolving(GaiResolver::new(), request),
        }
    }
}

impl ConnectOriginTransport {
    /// Send `request`, looking the origin up through `resolver` as an
    /// absolute name. The system resolver in production; tests substitute it.
    pub(crate) fn send_resolving<R>(
        &self,
        resolver: R,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Incoming>, ConnectError>>
    where
        R: Service<Name> + Clone + Send + Sync + 'static,
        R::Response: Iterator<Item = SocketAddr>,
        R::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        R::Future: Send,
    {
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
        let through = self.through.clone();
        Box::pin(async move {
            // The error class carries no path, PEM or peer detail.
            let config = endpoint.rustls_config().await.map_err(|error| {
                ConnectError::unavailable(format!("internal TLS trust unavailable: {error}"))
            })?;
            match through {
                Some((peer, dial)) => {
                    request_over(FixedPeer { peer, dial }, config, http1_only, request).await
                }
                None => {
                    let mut http = HttpConnector::new_with_resolver(AbsoluteNames(resolver));
                    http.enforce_http(false);
                    http.set_nodelay(true);
                    http.set_connect_timeout(Some(TLS_TIMEOUT));
                    request_over(http, config, http1_only, request).await
                }
            }
        })
    }
}

/// One request over a verified TLS connection that `connector` opens.
async fn request_over<C>(
    connector: C,
    config: rustls::ClientConfig,
    http1_only: bool,
    request: Request<ClientBody>,
) -> Result<Response<Incoming>, ConnectError>
where
    C: Service<http::Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper_util::client::legacy::connect::Connection
        + hyper::rt::Read
        + hyper::rt::Write
        + Send
        + Unpin
        + 'static,
    C::Future: Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only();
    let https = if http1_only {
        https.enable_http1().wrap_connector(connector)
    } else {
        https.enable_all_versions().wrap_connector(connector)
    };
    Client::builder(TokioExecutor::new())
        .build(https)
        .request(request)
        .await
        .map_err(|error| ConnectError::unavailable_from_transport("HTTPS request failed", error))
}

/// Connects every request to one address through the caller's dial, under
/// the same bound as a looked-up connection.
#[derive(Clone)]
struct FixedPeer {
    peer: SocketAddr,
    dial: PeerDial,
}

impl Service<http::Uri> for FixedPeer {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TokioIo<TcpStream>>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Uri) -> Self::Future {
        let connect = (self.dial)(self.peer);
        Box::pin(async move {
            let stream = tokio::time::timeout(TLS_TIMEOUT, connect)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            // As the looked-up connector sets it; a refusal leaves a working,
            // slower connection.
            let _ = stream.set_nodelay(true);
            Ok(TokioIo::new(stream))
        })
    }
}

/// Answers every lookup with the one configured address. The connector then
/// gives it the origin's port.
#[derive(Clone, Copy)]
pub(crate) struct Dial(pub(crate) IpAddr);

impl Service<Name> for Dial {
    type Response = std::iter::Once<SocketAddr>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Name) -> Self::Future {
        std::future::ready(Ok(std::iter::once(SocketAddr::new(self.0, 0))))
    }
}

/// Looks names up through `R` as absolute DNS names, so the resolver never
/// tries a search domain first. The connector calls it only for DNS names,
/// and takes the TLS server name and HTTP authority from the request URI.
#[derive(Clone)]
pub(crate) struct AbsoluteNames<R>(pub(crate) R);

impl<R: Service<Name>> Service<Name> for AbsoluteNames<R> {
    type Response = R::Response;
    type Error = R::Error;
    type Future = R::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), R::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> R::Future {
        self.0.call(absolute_name(name))
    }
}

/// A multi-label name with a trailing dot. A single-label name such as
/// `localhost`, which only the hosts file or the search list answers, and an
/// absolute name are unchanged. This is the rule of
/// `codewire_tailnet::dns::absolute_dns_name`, without its IP-literal cases,
/// which never reach a resolver here.
fn absolute_name(name: Name) -> Name {
    let host = name.as_str();
    if !host.contains('.') || host.ends_with('.') {
        return name;
    }
    format!("{host}.").parse().unwrap_or(name)
}

/// Whether `error`, or anything it came from, is a TLS failure, so a caller
/// can name that class without logging the failure's detail. An I/O error
/// holds its cause in place rather than as a source, and a handshake's comes
/// wrapped twice, so each one is opened.
pub fn is_tls_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(cause) = next {
        if cause.is::<rustls::Error>() {
            return true;
        }
        next = match cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            Some(held) => Some(held as &(dyn std::error::Error + 'static)),
            None => cause.source(),
        };
    }
    false
}
