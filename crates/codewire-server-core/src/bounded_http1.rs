//! A single-purpose HTTP/1.1 listener for a port every tenant workload can
//! reach.
//!
//! The canonical [`serve_with_listener`](crate::serve_with_listener) path
//! negotiates cleartext HTTP/2 and keeps connections alive, which suits
//! trusted callers. A port opened to tenant workloads needs the opposite:
//! every bound is enforced at the accept loop, before any request is parsed,
//! so a hostile workload can spend only bounded CPU and memory here.
//!
//! - HTTP/1.1 only. An HTTP/2 preface is a parse error, so there is no
//!   stream multiplexing behind one connection.
//! - A connection limit per peer IP and a global connection limit, refused at
//!   accept by closing the socket.
//! - A header read timeout, a header count and a header buffer cap.
//! - A request body cap, checked from `Content-Length` and while streaming.
//! - One whole-request deadline: the head and the complete body must arrive
//!   within it, before the handler runs, so a trickled body cannot hold a
//!   connection for the full connection deadline without authenticating.
//! - One request per connection and a total connection deadline.
//! - A short, growing pause after accept errors (such as running out of file
//!   descriptors) with a bounded log rate, so the loop never spins.
//!
//! The peer address is attached to every request as a [`PeerAddr`]
//! extension so request-level limits can key on it.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Bounds for one [`serve_bounded_http1`] listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedHttp1Limits {
    /// Open connections across all peers. Further connections are closed at
    /// accept.
    pub max_connections: usize,
    /// Open connections from one peer IP. Further connections from that IP are
    /// closed at accept.
    pub max_connections_per_peer: usize,
    /// Time allowed to receive the complete request head.
    pub header_read_timeout: Duration,
    /// Request header count. More headers are answered with 431.
    pub max_headers: usize,
    /// Connection read buffer, which bounds the request head: hyper reads at
    /// most one more buffer-sized chunk after an incomplete head, so an
    /// accepted head is always smaller than twice this. hyper's minimum is
    /// 8 KiB.
    pub max_header_bytes: usize,
    /// Request body bytes. A larger body is answered with 413 or fails while
    /// streaming.
    pub max_body_bytes: usize,
    /// Time from accept until the head and the whole body have arrived. A
    /// request still incomplete is answered with 408 and the handler never
    /// runs. It must not exceed the connection deadline.
    pub request_read_timeout: Duration,
    /// Lifetime of one connection from accept to close, response included.
    pub connection_deadline: Duration,
}

/// The accepted socket's peer address, attached to every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

/// Serve `app` on `listener` under `limits` until SIGTERM or SIGINT.
pub async fn serve_bounded_http1(
    app: Router,
    listener: TcpListener,
    limits: BoundedHttp1Limits,
) -> anyhow::Result<()> {
    serve_bounded_http1_until(app, listener, limits, crate::shutdown_signal()).await
}

/// [`serve_bounded_http1`] that stops accepting when `shutdown` completes, then
/// waits for open connections, each bounded by its deadline.
pub async fn serve_bounded_http1_until(
    app: Router,
    listener: TcpListener,
    limits: BoundedHttp1Limits,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    validate(&limits)?;
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    let peers = PeerConnections::default();
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    let mut backoff = AcceptBackoff::default();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => {
                        backoff.reset();
                        accepted
                    }
                    Err(error) => {
                        let (pause, log) = backoff.on_error(&error, std::time::Instant::now());
                        if log {
                            tracing::warn!(error = ?error, pause_ms = pause.as_millis() as u64, "bounded listener accept failed");
                        }
                        if !pause.is_zero() {
                            tokio::time::sleep(pause).await;
                        }
                        continue;
                    }
                };
                // Refuse before reading a byte: dropping the socket closes it.
                let Ok(global) = connections.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let Some(per_peer) = peers.try_acquire(peer.ip(), limits.max_connections_per_peer) else {
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                let max_body_bytes = limits.max_body_bytes;
                let read_deadline = tokio::time::Instant::now() + limits.request_read_timeout;
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let app = app.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handle_request(app, peer, max_body_bytes, read_deadline, request).await,
                        )
                    }
                });
                let connection = http1_builder(&limits).serve_connection(TokioIo::new(stream), service);
                let watched = graceful.watch(connection);
                let deadline = limits.connection_deadline;
                tokio::spawn(async move {
                    let _slots = (global, per_peer);
                    match tokio::time::timeout(deadline, watched).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::debug!(error = ?error, "bounded listener connection ended");
                        }
                        // Dropping the connection future closes the socket.
                        Err(_) => tracing::debug!("bounded listener connection deadline reached"),
                    }
                });
            }
            _ = &mut shutdown => break,
        }
    }

    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

fn validate(limits: &BoundedHttp1Limits) -> anyhow::Result<()> {
    anyhow::ensure!(
        limits.max_connections > 0 && limits.max_connections_per_peer > 0,
        "bounded listener connection limits must be positive"
    );
    anyhow::ensure!(
        limits.max_connections_per_peer <= limits.max_connections,
        "bounded listener per-peer limit exceeds the global limit"
    );
    anyhow::ensure!(
        !limits.header_read_timeout.is_zero()
            && !limits.request_read_timeout.is_zero()
            && !limits.connection_deadline.is_zero(),
        "bounded listener timeouts must be positive"
    );
    anyhow::ensure!(
        limits.header_read_timeout <= limits.request_read_timeout
            && limits.request_read_timeout <= limits.connection_deadline,
        "bounded listener timeouts must nest: head, whole request, connection"
    );
    anyhow::ensure!(limits.max_headers > 0, "bounded listener needs headers");
    // hyper panics below its minimum read buffer.
    anyhow::ensure!(
        limits.max_header_bytes >= 8 * 1024,
        "bounded listener header buffer must be at least 8 KiB"
    );
    Ok(())
}

fn http1_builder(limits: &BoundedHttp1Limits) -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .max_headers(limits.max_headers)
        .max_buf_size(limits.max_header_bytes)
        .keep_alive(false)
        .half_close(false);
    builder
}

async fn handle_request(
    app: Router,
    peer: SocketAddr,
    max_body_bytes: usize,
    read_deadline: tokio::time::Instant,
    request: Request<Incoming>,
) -> Response<Body> {
    // hyper has already rejected a malformed or duplicated Content-Length.
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > max_body_bytes as u64) {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let (mut parts, body) = request.into_parts();
    // The whole request must be here before the handler runs: a trickled body
    // never reaches authentication and never holds the connection longer.
    let limited = http_body_util::Limited::new(body, max_body_bytes);
    let collected =
        match tokio::time::timeout_at(read_deadline, http_body_util::BodyExt::collect(limited))
            .await
        {
            Err(_) => return status(StatusCode::REQUEST_TIMEOUT),
            Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
                return status(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Ok(Err(_)) => return status(StatusCode::BAD_REQUEST),
            Ok(Ok(collected)) => collected.to_bytes(),
        };
    parts.extensions.insert(PeerAddr(peer));
    use tower::ServiceExt;
    match app
        .oneshot(Request::from_parts(parts, Body::from(collected)))
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Pause after an accept error, growing while errors repeat (for example the
/// process is out of file descriptors), and log at most once per
/// [`ACCEPT_ERROR_LOG_INTERVAL`]. Per-connection errors such as a reset before
/// accept completed are not the listener's fault and do not pause.
#[derive(Default)]
struct AcceptBackoff {
    pause: Duration,
    last_log: Option<std::time::Instant>,
}

const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const ACCEPT_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(10);

impl AcceptBackoff {
    fn on_error(&mut self, error: &std::io::Error, now: std::time::Instant) -> (Duration, bool) {
        use std::io::ErrorKind;
        let pause = if matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
        ) {
            Duration::ZERO
        } else {
            self.pause = if self.pause.is_zero() {
                ACCEPT_BACKOFF_INITIAL
            } else {
                (self.pause * 2).min(ACCEPT_BACKOFF_MAX)
            };
            self.pause
        };
        let log = self
            .last_log
            .is_none_or(|last| now.saturating_duration_since(last) >= ACCEPT_ERROR_LOG_INTERVAL);
        if log {
            self.last_log = Some(now);
        }
        (pause, log)
    }

    fn reset(&mut self) {
        self.pause = Duration::ZERO;
    }
}

fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = code;
    response
}

/// Open connection counts per peer IP. Entries are removed when their last
/// connection closes, so the map never outgrows the global limit.
#[derive(Clone, Default)]
struct PeerConnections(Arc<Mutex<HashMap<IpAddr, usize>>>);

impl PeerConnections {
    fn try_acquire(&self, peer: IpAddr, limit: usize) -> Option<PeerSlot> {
        let mut peers = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let open = peers.entry(peer).or_insert(0);
        if *open >= limit {
            return None;
        }
        *open += 1;
        Some(PeerSlot {
            peers: self.clone(),
            peer,
        })
    }
}

struct PeerSlot {
    peers: PeerConnections,
    peer: IpAddr,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut peers = self
            .peers
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(open) = peers.get_mut(&self.peer) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests;
