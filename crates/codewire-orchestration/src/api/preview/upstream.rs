//! The preview proxy's way into a sandbox (#4357). Each upstream connection
//! is one `ForwardTcp` stream through the environment's daemon to the port on
//! the workload's loopback, made as the workload user, so a server bound only
//! to `127.0.0.1` answers, as `cw ports` does for a local VM (#4347).
//! Connections are pooled per environment and port, so a page's assets reuse
//! them. A daemon without `ForwardTcp`, in a Pod from before it, keeps the
//! pod-address path, which [`PreviewUpstream::forwards`] decides.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, Response, Uri};
use codewire_daemon::client::{SessionClient, SessionClientError};
use codewire_daemon_proto::DAEMON_CAPABILITY_FORWARD_TCP;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sqlx::PgPool;
use tokio::io::DuplexStream;
use tonic::Code;

use crate::api::environment_daemon::{EnvironmentDaemonEndpointOverrides, streaming_daemon_client};
use crate::runtime::RuntimeDriver;

/// The workload loopback addresses a port is tried on, in order.
const LOOPBACKS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];
/// How long an idle upstream connection waits for the next request.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle upstream connections kept per environment and port.
const POOL_MAX_IDLE: usize = 8;
/// How long a daemon's answer about `ForwardTcp` is reused.
const SUPPORT_TTL: Duration = Duration::from_secs(5 * 60);
/// Cached answers kept before the cache starts again.
const SUPPORT_CACHE_MAX: usize = 10_000;
/// The synthetic upstream host's suffix. It names a pool, and is never
/// resolved: the connector reads the environment and namespace from it.
const UPSTREAM_SUFFIX: &str = "preview-upstream.invalid";

/// Why a forwarded preview request got no response. Carries no request or
/// response content.
#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum UpstreamError {
    #[error("nothing in the sandbox listens on port {0}")]
    NothingListens(u16),
    #[error("the sandbox's daemon refused the connection: {0}")]
    Refused(String),
    #[error("the environment daemon is unreachable")]
    Unreachable,
    #[error("the upstream request failed")]
    Request,
    #[error("invalid upstream address")]
    Invalid,
}

/// How the proxy reaches an environment's daemon.
#[derive(Clone)]
enum DaemonAccess {
    /// The bound Pod's daemon, with the credential its binding decides.
    Bound {
        pool: PgPool,
        runtime: Option<Arc<dyn RuntimeDriver>>,
        session_secret: String,
        endpoints: EnvironmentDaemonEndpointOverrides,
    },
    /// Tests: one daemon client for every environment.
    #[cfg(test)]
    Fixed(SessionClient),
}

impl DaemonAccess {
    async fn client(
        &self,
        namespace: &str,
        environment_id: &str,
    ) -> Result<SessionClient, UpstreamError> {
        match self {
            Self::Bound {
                pool,
                runtime,
                session_secret,
                endpoints,
            } => streaming_daemon_client(
                pool,
                runtime.as_deref(),
                session_secret,
                endpoints,
                namespace,
                environment_id,
            )
            .await
            .map_err(|_| UpstreamError::Unreachable),
            #[cfg(test)]
            Self::Fixed(client) => Ok(client.clone()),
        }
    }
}

/// The pooled HTTP/1.1 client the preview proxy sends forwarded requests
/// through, and what it has learned about each environment's daemon.
#[derive(Clone)]
pub struct PreviewUpstream {
    client: Client<ForwardConnector, Body>,
    access: DaemonAccess,
    support: Arc<Mutex<HashMap<String, (bool, Instant)>>>,
}

impl PreviewUpstream {
    pub fn new(
        pool: PgPool,
        runtime: Option<Arc<dyn RuntimeDriver>>,
        session_secret: String,
        endpoints: EnvironmentDaemonEndpointOverrides,
    ) -> Self {
        Self::with_access(DaemonAccess::Bound {
            pool,
            runtime,
            session_secret,
            endpoints,
        })
    }

    /// Tests: every environment's daemon is `client`.
    #[cfg(test)]
    fn fixed(client: SessionClient) -> Self {
        Self::with_access(DaemonAccess::Fixed(client))
    }

    fn with_access(access: DaemonAccess) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE)
            .build(ForwardConnector {
                access: access.clone(),
            });
        Self {
            client,
            access,
            support: Arc::default(),
        }
    }

    /// Whether the environment's daemon offers `ForwardTcp`. An answer is
    /// reused for a few minutes. A daemon that can't be asked counts as no,
    /// so the proxy keeps the pod-address path it used before.
    pub(super) async fn forwards(&self, namespace: &str, environment_id: &str) -> bool {
        if let Some((supported, at)) = self
            .support
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(environment_id)
            && at.elapsed() < SUPPORT_TTL
        {
            return *supported;
        }
        let Ok(client) = self.access.client(namespace, environment_id).await else {
            return false;
        };
        let supported = client.get_capabilities(&[]).await.is_ok_and(|response| {
            response
                .capabilities
                .iter()
                .any(|capability| capability == DAEMON_CAPABILITY_FORWARD_TCP)
        });
        let mut support = self.support.lock().unwrap_or_else(PoisonError::into_inner);
        if support.len() >= SUPPORT_CACHE_MAX {
            support.clear();
        }
        support.insert(environment_id.to_owned(), (supported, Instant::now()));
        supported
    }

    /// The upstream URI for `path_and_query` on `port` of an environment.
    pub(super) fn uri(
        namespace: &str,
        environment_id: &str,
        port: u16,
        path_and_query: &str,
    ) -> Result<Uri, UpstreamError> {
        format!("http://{environment_id}.{namespace}.{UPSTREAM_SUFFIX}:{port}{path_and_query}")
            .parse()
            .map_err(|_| UpstreamError::Invalid)
    }

    /// Send one request, built with [`Self::uri`], through the pool.
    pub(super) async fn send(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        self.client.request(request).await.map_err(|error| {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(cause) = source {
                if let Some(upstream) = cause.downcast_ref::<UpstreamError>() {
                    return upstream.clone();
                }
                source = cause.source();
            }
            if error.is_connect() {
                UpstreamError::Unreachable
            } else {
                UpstreamError::Request
            }
        })
    }
}

/// Opens each pooled connection as one `ForwardTcp` stream.
#[derive(Clone)]
struct ForwardConnector {
    access: DaemonAccess,
}

impl tower::Service<Uri> for ForwardConnector {
    type Response = ForwardIo;
    type Error = UpstreamError;
    type Future = Pin<Box<dyn Future<Output = Result<ForwardIo, UpstreamError>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let access = self.access.clone();
        Box::pin(async move {
            let (environment_id, namespace, port) = upstream_target(&uri)?;
            let client = access.client(namespace, environment_id).await?;
            open(&client, port)
                .await
                .map(|stream| ForwardIo(TokioIo::new(stream)))
        })
    }
}

/// The environment, namespace and port a [`PreviewUpstream::uri`] names.
fn upstream_target(uri: &Uri) -> Result<(&str, &str, u16), UpstreamError> {
    let host = uri.host().ok_or(UpstreamError::Invalid)?;
    let names = host
        .strip_suffix(UPSTREAM_SUFFIX)
        .and_then(|rest| rest.strip_suffix('.'))
        .ok_or(UpstreamError::Invalid)?;
    let (environment_id, namespace) = names.split_once('.').ok_or(UpstreamError::Invalid)?;
    let port = uri.port_u16().ok_or(UpstreamError::Invalid)?;
    if environment_id.is_empty() || namespace.is_empty() || namespace.contains('.') {
        return Err(UpstreamError::Invalid);
    }
    Ok((environment_id, namespace, port))
}

/// A stream to `port` on the first workload loopback that accepts it.
async fn open(client: &SessionClient, port: u16) -> Result<DuplexStream, UpstreamError> {
    for address in LOOPBACKS {
        match client.forward_tcp(SocketAddr::new(address, port)).await {
            Ok(stream) => return Ok(stream),
            // A platform listener, or a daemon that doesn't forward: the
            // daemon's own reason, whichever address is tried.
            Err(SessionClientError::Status(status))
                if matches!(
                    status.code(),
                    Code::PermissionDenied | Code::InvalidArgument | Code::Unimplemented
                ) =>
            {
                return Err(UpstreamError::Refused(status.message().to_owned()));
            }
            // Nothing accepted on this address; try the next.
            Err(SessionClientError::Status(_)) => {}
            Err(_) => return Err(UpstreamError::Unreachable),
        }
    }
    Err(UpstreamError::NothingListens(port))
}

/// One forwarded connection, as the pooled client sees it.
struct ForwardIo(TokioIo<DuplexStream>);

impl Connection for ForwardIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for ForwardIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for ForwardIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
