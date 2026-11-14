//! The TLS front door for an environment's bound egress hosts.
//!
//! An environment's TCP dials to a few bound hosts on port 443 arrive here.
//! The front door reads the ClientHello without answering it. When the server
//! name is the host the dial was attributed to, it completes the handshake
//! with a leaf from the environment's own certificate authority
//! ([`EnvironmentCa`]) and hands each decrypted HTTP request to the caller's
//! [`Backend`]. Every other connection goes back to the caller untouched, with
//! every byte read from it.
//!
//! [`FrontDoor::accept_named`] serves instead whichever host the ClientHello
//! names, when the front door's [`LeafSource`] signs for it: how a caller with
//! its own CA routes several hosts through one listener.
//!
//! The CA private key lives only in this process's memory. The front door
//! holds no credentials and never opens an outbound connection: the back end
//! owns everything upstream. Logs carry the bound host, an outcome category
//! and byte counts, never request or response content.

#![forbid(unsafe_code)]

mod ca;
mod hello;
mod serve;
mod splice;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Request, Response};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub use ca::{BACKDATE, CA_VALIDITY, CaError, EnvironmentCa, LEAF_VALIDITY, MAX_BOUND_HOSTS};
pub use hyper::body::Incoming;
pub use rustls::sign::CertifiedKey;

/// The most bytes read while looking for a ClientHello. A real one is a few
/// hundred bytes to a few KiB, even with post-quantum key shares.
pub const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
/// How long a peer has to send its whole ClientHello.
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the rest of the TLS handshake may take once the ClientHello is in.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The most bytes of request headers: the HTTP/1.1 read buffer and the
/// HTTP/2 header list.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// The most concurrent HTTP/2 streams on one connection.
pub const MAX_CONCURRENT_STREAMS: u32 = 16;
/// How long an HTTP/1.1 client has to send a request's headers, including
/// the wait for the next request on a kept-alive connection.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The default for [`FrontDoorConfig::websocket_idle_timeout`].
pub const DEFAULT_WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// The default for [`FrontDoorConfig::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 32;

/// A response body: anything the back end streams.
pub type ResponseBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;
/// The error type of a [`ResponseBody`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// What [`Backend::upgrade`] decides: the response to send (status 101) and
/// the upstream byte stream to splice, or an ordinary response instead.
pub type UpgradeOutcome = Result<(Response<()>, Box<dyn Duplex>), Response<ResponseBody>>;

/// A byte stream in both directions, such as an upstream WebSocket connection.
pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Where decrypted requests go. The front door has already checked that each
/// request is for `host`, in origin form, and not a tunnel.
pub trait Backend: Send + Sync + 'static {
    /// One decrypted request for `host`. The request's URI is origin-form and
    /// its body streams from the client unbuffered and uncapped.
    fn respond(
        &self,
        host: &str,
        request: Request<Incoming>,
    ) -> impl Future<Output = Response<ResponseBody>> + Send;

    /// An HTTP/1.1 WebSocket opening request for `host`, without a body.
    /// `Ok` gives the 101 response and the upstream stream to splice; the
    /// front door then copies bytes both ways without reading them. `Err`
    /// gives an ordinary response to send instead.
    fn upgrade(
        &self,
        host: &str,
        request: Request<()>,
    ) -> impl Future<Output = UpgradeOutcome> + Send;
}

/// Limits a caller may choose per front door, and the port clients reach it
/// on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontDoorConfig {
    /// Live connections, from accept to close. One more is closed before
    /// anything is read from it.
    pub max_connections: usize,
    /// A spliced WebSocket with no bytes in either direction for this long is
    /// closed at both ends.
    pub websocket_idle_timeout: Duration,
    /// The port clients connect to. A request's authority names the host
    /// alone or with this port; 443 by default.
    pub port: u16,
}

impl Default for FrontDoorConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            websocket_idle_timeout: DEFAULT_WEBSOCKET_IDLE_TIMEOUT,
            port: 443,
        }
    }
}

/// How [`FrontDoor::accept`] ended without an error.
#[derive(Debug)]
pub enum Accepted<S> {
    /// The handshake completed and the connection has ended.
    Served(Served),
    /// Not for this front door. `stream` is untouched apart from `read`, every
    /// byte read from it, which the caller replays; nothing was written to it.
    HandBack {
        stream: S,
        read: Bytes,
        reason: HandBackReason,
    },
}

/// What a served connection did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Served {
    /// Requests received, including those refused before the back end.
    pub requests: u64,
    /// WebSocket connections spliced.
    pub upgraded: u64,
}

/// Why a connection was handed back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandBackReason {
    /// A ClientHello naming a host other than the bound host.
    OtherServerName,
    /// A ClientHello without a server name.
    NoServerName,
    /// Bytes that are not a well-formed TLS ClientHello, or end before one.
    NotClientHello,
}

impl HandBackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::OtherServerName => "other_server_name",
            Self::NoServerName => "no_server_name",
            Self::NotClientHello => "not_client_hello",
        }
    }
}

/// Why [`FrontDoor::accept`] closed a connection. Nothing is handed back.
/// The variants carry no peer input, so they may be logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrontDoorError {
    #[error("front door closed")]
    Closed,
    #[error("live connection limit reached")]
    AtCapacity,
    #[error("host is not bound to this front door")]
    UnboundHost,
    #[error("leaf certificate unavailable")]
    Certificate,
    #[error("ClientHello deadline elapsed")]
    HelloTimeout,
    #[error("ClientHello exceeds its size bound")]
    HelloTooLarge,
    #[error("connection failed while reading the ClientHello")]
    Io,
    #[error("TLS handshake failed")]
    Handshake,
}

/// Where a front door's leaf certificates come from.
pub trait LeafSource: Send + Sync + 'static {
    /// The canonical host `host` names and its current leaf, or
    /// [`CaError::UnboundHost`] when this source signs nothing for it.
    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError>;
}

impl LeafSource for EnvironmentCa {
    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), CaError> {
        EnvironmentCa::leaf(self, host)
    }
}

/// Which host a connection must be for.
#[derive(Clone, Copy)]
enum Expected<'a> {
    /// The host the broker attributed the dial to.
    Bound(&'a str),
    /// Whichever host the ClientHello names, if the leaf source signs for it.
    Named,
}

/// Terminates TLS for one environment's bound hosts and serves their requests
/// to a [`Backend`]. Share it behind an `Arc` to accept concurrently.
pub struct FrontDoor<B, L = EnvironmentCa> {
    leaves: L,
    backend: Arc<B>,
    config: FrontDoorConfig,
    provider: Arc<CryptoProvider>,
    permits: Arc<Semaphore>,
    stop: CancellationToken,
}

impl<B: Backend, L: LeafSource> FrontDoor<B, L> {
    pub fn new(leaves: L, backend: B, config: FrontDoorConfig) -> Self {
        Self {
            leaves,
            backend: Arc::new(backend),
            config,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            permits: Arc::new(Semaphore::new(config.max_connections)),
            stop: CancellationToken::new(),
        }
    }

    /// Where the leaves come from: for an environment, the CA it trusts.
    pub fn ca(&self) -> &L {
        &self.leaves
    }

    /// Serve one connection the broker attributed to `bound_host`. Resolves
    /// when the connection ends, or at once with the stream when it is not
    /// TLS for `bound_host`.
    pub async fn accept<S>(
        &self,
        stream: S,
        bound_host: &str,
    ) -> Result<Accepted<S>, FrontDoorError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let result = self.accept_inner(stream, Expected::Bound(bound_host)).await;
        match &result {
            Ok(Accepted::Served(served)) => tracing::debug!(
                host = bound_host,
                outcome = "served",
                requests = served.requests,
                upgraded = served.upgraded,
            ),
            Ok(Accepted::HandBack { read, reason, .. }) => tracing::debug!(
                host = bound_host,
                outcome = "hand_back",
                reason = reason.as_str(),
                bytes = read.len(),
            ),
            Err(error) => tracing::debug!(host = bound_host, outcome = %error),
        }
        result
    }

    /// Serve one connection for the host its ClientHello names, when the leaf
    /// source signs for that host; a name it does not sign for is
    /// [`FrontDoorError::UnboundHost`]. Resolves when the connection ends, or
    /// at once with the stream when it is not a ClientHello with a server
    /// name. The back end sees the source's canonical host.
    pub async fn accept_named<S>(&self, stream: S) -> Result<Accepted<S>, FrontDoorError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let result = self.accept_inner(stream, Expected::Named).await;
        // The server name is peer input, so it is not logged.
        match &result {
            Ok(Accepted::Served(served)) => tracing::debug!(
                outcome = "served",
                requests = served.requests,
                upgraded = served.upgraded,
            ),
            Ok(Accepted::HandBack { read, reason, .. }) => tracing::debug!(
                outcome = "hand_back",
                reason = reason.as_str(),
                bytes = read.len(),
            ),
            Err(error) => tracing::debug!(outcome = %error),
        }
        result
    }

    async fn accept_inner<S>(
        &self,
        mut stream: S,
        expected: Expected<'_>,
    ) -> Result<Accepted<S>, FrontDoorError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.stop.is_cancelled() {
            return Err(FrontDoorError::Closed);
        }
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return Err(FrontDoorError::AtCapacity);
        };
        // A bound host's leaf comes first, so a host this door never signs
        // for is refused before anything is read.
        let bound = match expected {
            Expected::Bound(host) => Some(self.leaf(host)?),
            Expected::Named => None,
        };

        let mut read = BytesMut::new();
        let hello = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(FrontDoorError::Closed),
            hello = tokio::time::timeout(
                CLIENT_HELLO_TIMEOUT,
                hello::read_client_hello(&mut stream, &mut read),
            ) => hello,
        };
        let name = match hello {
            Err(_elapsed) => return Err(FrontDoorError::HelloTimeout),
            Ok(Err(hello::HelloError::TooLarge)) => return Err(FrontDoorError::HelloTooLarge),
            Ok(Err(hello::HelloError::Io)) => return Err(FrontDoorError::Io),
            Ok(Ok(hello::Hello::NotClientHello)) => Err(HandBackReason::NotClientHello),
            Ok(Ok(hello::Hello::ClientHello { server_name: None })) => {
                Err(HandBackReason::NoServerName)
            }
            Ok(Ok(hello::Hello::ClientHello {
                server_name: Some(name),
            })) => Ok(name),
        };
        let chosen = match (name, bound) {
            (Err(reason), _) => Err(reason),
            (Ok(name), Some((host, leaf))) if name.eq_ignore_ascii_case(host.as_bytes()) => {
                Ok((host, leaf))
            }
            (Ok(_), Some(_)) => Err(HandBackReason::OtherServerName),
            (Ok(name), None) => Ok(self.named_leaf(&name)?),
        };
        let (host, leaf) = match chosen {
            Ok(chosen) => chosen,
            Err(reason) => {
                return Ok(Accepted::HandBack {
                    stream,
                    read: read.freeze(),
                    reason,
                });
            }
        };

        let acceptor = TlsAcceptor::from(self.server_config(host.clone(), leaf)?);
        let handshake = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            acceptor.accept(Replay {
                prefix: read.freeze(),
                inner: stream,
            }),
        );
        let tls = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(FrontDoorError::Closed),
            tls = handshake => match tls {
                Ok(Ok(tls)) => tls,
                _ => return Err(FrontDoorError::Handshake),
            },
        };
        let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let connection = serve::Connection::new(
            host,
            self.backend.clone(),
            self.stop.child_token(),
            self.config.websocket_idle_timeout,
            self.config.port,
        );
        let served = connection.serve(tls, http2).await;
        drop(permit);
        Ok(Accepted::Served(served))
    }

    fn leaf(&self, host: &str) -> Result<(String, Arc<CertifiedKey>), FrontDoorError> {
        self.leaves.leaf(host).map_err(|error| match error {
            CaError::UnboundHost => FrontDoorError::UnboundHost,
            _ => FrontDoorError::Certificate,
        })
    }

    /// The leaf for a server name read from a ClientHello, which need not be
    /// UTF-8.
    fn named_leaf(&self, name: &[u8]) -> Result<(String, Arc<CertifiedKey>), FrontDoorError> {
        let name = std::str::from_utf8(name).map_err(|_| FrontDoorError::UnboundHost)?;
        self.leaf(name)
    }

    /// One handshake's configuration: only `host`'s leaf, for only that
    /// server name, so a disagreement between this crate's ClientHello parser
    /// and Rustls's fails the handshake rather than serving another name.
    fn server_config(
        &self,
        host: String,
        leaf: Arc<CertifiedKey>,
    ) -> Result<Arc<ServerConfig>, FrontDoorError> {
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| FrontDoorError::Handshake)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneHost { host, leaf }));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Each connection gets a fresh configuration, so nothing could resume
        // anyway; say so rather than rely on it. The default ticketer issues
        // no stateless tickets and early data stays off.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Arc::new(config))
    }
}

impl<B, L> FrontDoor<B, L> {
    /// Stop accepting and end every live connection, spliced WebSockets
    /// included. Dropping the front door does the same.
    pub fn close(&self) {
        self.permits.close();
        self.stop.cancel();
    }
}

impl<B, L> Drop for FrontDoor<B, L> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Serves one leaf for one server name.
struct OneHost {
    host: String,
    leaf: Arc<CertifiedKey>,
}

impl std::fmt::Debug for OneHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OneHost")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for OneHost {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        client_hello
            .server_name()
            .filter(|name| name.eq_ignore_ascii_case(&self.host))
            .map(|_| self.leaf.clone())
    }
}

/// A stream that first replays the bytes already read from it.
struct Replay<S> {
    prefix: Bytes,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.is_empty() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let count = self.prefix.len().min(buf.remaining());
        buf.put_slice(&self.prefix.split_to(count));
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
