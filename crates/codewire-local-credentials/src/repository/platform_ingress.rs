//! One repository job's private-capability HTTP ingress. This owns no provider
//! material and is not remote worker-drain proof. The retained repository job
//! must keep this owner through cancellation and await `close` before success.

use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codewire_credential_bridge::{CredentialBridge, MANAGED_GITHUB_GIT_PREFIX};
use futures::{FutureExt as _, Stream};
use http::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, WWW_AUTHENTICATE};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::BodyDataStream;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use subtle::ConstantTimeEq as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{RepositoryExecutorError, validate_github_https_source};

const MAX_CONNECTIONS: usize = 8;
const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

#[must_use = "retain the ingress through job finalization and await close"]
pub(crate) struct PlatformRepositoryGitIngress {
    endpoint: String,
    capability: Zeroizing<String>,
    shutdown: watch::Sender<bool>,
    driver: Option<JoinHandle<Result<(), RepositoryExecutorError>>>,
    closed_ok: bool,
}

impl PlatformRepositoryGitIngress {
    pub(crate) async fn bind(
        source: &str,
        bridge: CredentialBridge,
        deadline: Instant,
    ) -> Result<Self, RepositoryExecutorError> {
        validate_github_https_source(source)
            .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
        let source_url =
            url::Url::parse(source).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
        if source_url.as_str() != source {
            return Err(RepositoryExecutorError::InvalidConfiguration);
        }
        if Instant::now() >= deadline {
            return Err(RepositoryExecutorError::GitTimeout);
        }
        let listener =
            tokio::time::timeout_at(deadline, TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
                .await
                .map_err(|_| RepositoryExecutorError::GitTimeout)?
                .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
        let address: SocketAddr = listener
            .local_addr()
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
        let path = format!(
            "{MANAGED_GITHUB_GIT_PREFIX}{}",
            source_url.path().trim_start_matches('/')
        );
        // Two independent OS-random UUIDs provide 244 unpredictable bits. The
        // capability goes only to the inherited private helper RPC, never argv,
        // files, environment, URLs, diagnostic output, or the shared bridge.
        let capability = Zeroizing::new(format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ));
        let credentials = Zeroizing::new(format!("x-access-token:{}", capability.as_str()));
        let encoded = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        let authorization = Zeroizing::new(format!("Basic {}", encoded.as_str()));
        let state = Arc::new(IngressState {
            bridge,
            host: address.to_string(),
            discovery: format!("{path}/info/refs"),
            upload: format!("{path}/git-upload-pack"),
            authorization,
            failed: AtomicBool::new(false),
        });
        let (shutdown, stopped) = watch::channel(false);
        let driver_shutdown = shutdown.clone();
        let driver = tokio::spawn(run_listener(
            listener,
            state,
            deadline,
            driver_shutdown,
            stopped,
        ));
        Ok(Self {
            endpoint: format!("http://{address}{path}"),
            capability,
            shutdown,
            driver: Some(driver),
            closed_ok: false,
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The retained caller passes this only over its existing private helper
    /// channel. Deliberately no Debug implementation exists for this owner.
    pub(crate) fn capability(&self) -> &str {
        self.capability.as_str()
    }

    /// Cancelling this wait does not move or detach the retained driver. The
    /// job finalizer must retry the same owner until this join has completed.
    pub(crate) async fn close(&mut self) -> Result<(), RepositoryExecutorError> {
        let _ = self.shutdown.send(true);
        let Some(driver) = self.driver.as_mut() else {
            return if self.closed_ok {
                Ok(())
            } else {
                Err(RepositoryExecutorError::LeaseUnavailable)
            };
        };
        let result = driver.await;
        self.driver = None;
        self.closed_ok = matches!(&result, Ok(Ok(())));
        result.map_err(|_| RepositoryExecutorError::LeaseUnavailable)?
    }
}

impl Drop for PlatformRepositoryGitIngress {
    fn drop(&mut self) {
        // A drop requests cleanup but is not its acknowledgement. The retained
        // job owner is responsible for close(); no local/remote drain claim is
        // made from this destructor or a lost caller alone.
        let _ = self.shutdown.send(true);
    }
}

struct IngressState {
    bridge: CredentialBridge,
    host: String,
    discovery: String,
    upload: String,
    authorization: Zeroizing<String>,
    failed: AtomicBool,
}

#[derive(Default)]
struct Exchange {
    authenticated: AtomicBool,
    response_complete: AtomicBool,
}

async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    if !*shutdown.borrow() {
        let _ = shutdown.changed().await;
    }
}

async fn run_listener(
    listener: TcpListener,
    state: Arc<IngressState>,
    deadline: Instant,
    shutdown: watch::Sender<bool>,
    mut stopped_rx: watch::Receiver<bool>,
) -> Result<(), RepositoryExecutorError> {
    let mut connections = JoinSet::new();
    // Retain the connection owners outside this borrowed future, including if
    // an unexpected listener/dispatch panic occurs. Cleanup still joins them.
    let outcome = AssertUnwindSafe(async {
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return Err(RepositoryExecutorError::GitTimeout),
                _ = stopped(&mut stopped_rx) => return Ok(()),
                result = connections.join_next(), if !connections.is_empty() => {
                    if result.is_some_and(|result| result.is_err()) {
                        state.failed.store(true, Ordering::Release);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
                    if !peer.ip().is_loopback() || connections.len() >= MAX_CONNECTIONS {
                        // Unauthenticated congestion cannot poison a valid job.
                        drop(stream);
                        continue;
                    }
                    connections.spawn(serve_connection(stream, Arc::clone(&state), deadline, shutdown.subscribe()));
                }
            }
        }
    }).catch_unwind().await;
    drop(listener);
    let _ = shutdown.send(true);
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            state.failed.store(true, Ordering::Release);
        }
    }
    let outcome = outcome.map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    outcome?;
    if state.failed.load(Ordering::Acquire) {
        Err(RepositoryExecutorError::LeaseUnavailable)
    } else {
        Ok(())
    }
}

async fn serve_connection(
    stream: TcpStream,
    state: Arc<IngressState>,
    deadline: Instant,
    mut shutdown: watch::Receiver<bool>,
) {
    let exchange = Arc::new(Exchange::default());
    let request_state = Arc::clone(&state);
    let request_exchange = Arc::clone(&exchange);
    let service = service_fn(move |request| {
        respond(
            request,
            Arc::clone(&request_state),
            Arc::clone(&request_exchange),
        )
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_HEADER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let result = tokio::select! {
        // A completed connection is proof even if shutdown became ready in the
        // same poll. A merely completed response body is not a network flush.
        biased;
        result = &mut connection => result.is_ok(),
        _ = stopped(&mut shutdown) => false,
        _ = tokio::time::sleep_until(deadline) => false,
    };
    if exchange.authenticated.load(Ordering::Acquire)
        && (!result || !exchange.response_complete.load(Ordering::Acquire))
    {
        state.failed.store(true, Ordering::Release);
    }
}

async fn respond(
    mut request: Request<Incoming>,
    state: Arc<IngressState>,
    exchange: Arc<Exchange>,
) -> Result<Response<Body>, Infallible> {
    if !authenticated(request.headers(), &state.authorization) {
        let mut denied = fixed_response(StatusCode::UNAUTHORIZED);
        denied.headers_mut().insert(
            WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Basic realm=\"codewire-repository\""),
        );
        return Ok(denied);
    }
    exchange.authenticated.store(true, Ordering::Release);
    if !valid_route(&request, &state) {
        state.failed.store(true, Ordering::Release);
        return Ok(fixed_response(StatusCode::FORBIDDEN));
    }
    request.headers_mut().remove(AUTHORIZATION);
    let response = state.bridge.respond(request.map(Body::new)).await;
    Ok(completion_gated_response(response, state, exchange))
}

fn completion_gated_response(
    mut response: Response<Body>,
    state: Arc<IngressState>,
    exchange: Arc<Exchange>,
) -> Response<Body> {
    // Do not allow Hyper or Git to consider a known Content-Length sufficient:
    // shared Body EOF is emitted only after the bridge's real ResponseEnd.
    response.headers_mut().remove(CONTENT_LENGTH);
    response.headers_mut().remove(TRANSFER_ENCODING);
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::from_stream(CompletedBody {
            body: http_body_util::BodyExt::into_data_stream(body),
            exchange,
            state,
            terminal: false,
        }),
    )
}

fn authenticated(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(actual) = values.next() else {
        return false;
    };
    values.next().is_none()
        && !headers.contains_key("proxy-authorization")
        && !headers.contains_key("cookie")
        && bool::from(actual.as_bytes().ct_eq(expected.as_bytes()))
}

fn valid_route(request: &Request<Incoming>, state: &IngressState) -> bool {
    let uri = request.uri();
    let mut hosts = request.headers().get_all(HOST).iter();
    if uri.scheme().is_some()
        || uri.authority().is_some()
        || hosts
            .next()
            .is_none_or(|host| host.as_bytes() != state.host.as_bytes())
        || hosts.next().is_some()
        || request.headers().len() > MAX_HEADERS
        || request
            .headers()
            .iter()
            .try_fold(0_usize, |size, (name, value)| {
                size.checked_add(name.as_str().len())?
                    .checked_add(value.as_bytes().len())
            })
            .is_none_or(|size| size > MAX_HEADER_BYTES)
        || request.headers().get(CONTENT_LENGTH).is_some_and(|length| {
            length
                .to_str()
                .ok()
                .and_then(|length| length.parse::<usize>().ok())
                .is_none_or(|length| {
                    length > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES
                })
        })
    {
        return false;
    }
    (request.method() == Method::GET
        && uri.path() == state.discovery
        && uri.query() == Some("service=git-upload-pack")
        && !request.headers().contains_key(TRANSFER_ENCODING)
        && request
            .headers()
            .get(CONTENT_LENGTH)
            .is_none_or(|length| length == "0"))
        || (request.method() == Method::POST && uri.path() == state.upload && uri.query().is_none())
}

fn fixed_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

struct CompletedBody {
    body: BodyDataStream<Body>,
    exchange: Arc<Exchange>,
    state: Arc<IngressState>,
    terminal: bool,
}

impl Stream for CompletedBody {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.body).poll_next(cx) {
            Poll::Ready(None) => {
                self.terminal = true;
                self.exchange
                    .response_complete
                    .store(true, Ordering::Release);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(_))) => {
                self.terminal = true;
                self.state.failed.store(true, Ordering::Release);
                Poll::Ready(Some(Err(io::Error::other(
                    "repository response was incomplete",
                ))))
            }
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CompletedBody {
    fn drop(&mut self) {
        if !self.terminal {
            self.state.failed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
