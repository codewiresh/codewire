//! Serving one decrypted connection's HTTP to the back end.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderValue, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::splice::splice;
use crate::{
    Backend, HEADER_READ_TIMEOUT, MAX_CONCURRENT_STREAMS, MAX_HEADER_BYTES, ResponseBody, Served,
};

/// One TLS connection's state, shared by its requests.
pub(crate) struct Connection<B> {
    host: String,
    backend: Arc<B>,
    /// Ends this connection's request tasks and splices; a child of the
    /// front door's, so closing the front door ends it too.
    stop: CancellationToken,
    splices: TaskTracker,
    websocket_idle_timeout: Duration,
    requests: AtomicU64,
    upgraded: AtomicU64,
}

/// What a request may become, decided before the back end sees it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Route {
    Ordinary,
    WebSocket,
}

impl<B: Backend> Connection<B> {
    pub(crate) fn new(
        host: String,
        backend: Arc<B>,
        stop: CancellationToken,
        websocket_idle_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            backend,
            stop,
            splices: TaskTracker::new(),
            websocket_idle_timeout,
            requests: AtomicU64::new(0),
            upgraded: AtomicU64::new(0),
        })
    }

    /// Serves HTTP/2 when ALPN chose it and HTTP/1.1 otherwise, until the
    /// client is done and every splice has ended, or the front door closes.
    pub(crate) async fn serve<S>(self: Arc<Self>, io: S, http2: bool) -> Served
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(io);
        let service = {
            let connection = self.clone();
            service_fn(move |request| {
                let connection = connection.clone();
                async move { Ok::<_, Infallible>(connection.handle(request).await) }
            })
        };
        let stop = self.stop.clone();
        if http2 {
            let mut builder = http2::Builder::new(Scoped(stop.clone()));
            // Extended CONNECT stays off, so WebSockets over HTTP/2 are never
            // offered.
            builder
                .timer(TokioTimer::new())
                .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
                .max_header_list_size(MAX_HEADER_BYTES as u32);
            tokio::select! {
                _ = builder.serve_connection(io, service) => {}
                () = stop.cancelled() => {}
            }
        } else {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .max_buf_size(MAX_HEADER_BYTES);
            tokio::select! {
                _ = builder.serve_connection(io, service).with_upgrades() => {}
                () = stop.cancelled() => {}
            }
        }
        // An upgraded HTTP/1.1 connection ends as soon as it hands its stream
        // to the splice; the connection lasts until the splice does.
        self.splices.close();
        tokio::select! {
            () = self.splices.wait() => {}
            () = stop.cancelled() => {}
        }
        stop.cancel();
        self.splices.wait().await;
        Served {
            requests: self.requests.load(Ordering::Relaxed),
            upgraded: self.upgraded.load(Ordering::Relaxed),
        }
    }

    async fn handle(self: Arc<Self>, mut request: Request<Incoming>) -> Response<ResponseBody> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let route = match route(&mut request, &self.host) {
            Ok(route) => route,
            Err(status) => {
                tracing::debug!(
                    host = self.host,
                    outcome = "refused",
                    status = status.as_u16()
                );
                return empty(status);
            }
        };
        match route {
            Route::Ordinary => self.backend.respond(&self.host, request).await,
            Route::WebSocket => self.upgrade(request).await,
        }
    }

    async fn upgrade(self: Arc<Self>, mut request: Request<Incoming>) -> Response<ResponseBody> {
        let on_upgrade = hyper::upgrade::on(&mut request);
        let (parts, _empty_body) = request.into_parts();
        let (response, upstream) = match self
            .backend
            .upgrade(&self.host, Request::from_parts(parts, ()))
            .await
        {
            Ok(accepted) => accepted,
            Err(response) => return response,
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            tracing::debug!(host = self.host, outcome = "upgrade_not_switching");
            return empty(StatusCode::BAD_GATEWAY);
        }
        let (mut parts, ()) = response.into_parts();
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        let connection = self.clone();
        self.splices.spawn(async move {
            // Fails when the connection ends before the 101 is written.
            let Ok(client) = on_upgrade.await else {
                return;
            };
            connection.upgraded.fetch_add(1, Ordering::Relaxed);
            let spliced = splice(
                TokioIo::new(client),
                upstream,
                connection.websocket_idle_timeout,
                &connection.stop,
            )
            .await;
            tracing::debug!(
                host = connection.host,
                outcome = "websocket_closed",
                bytes_to_upstream = spliced.to_upstream,
                bytes_to_client = spliced.to_client,
            );
        });
        Response::from_parts(parts, empty_body())
    }
}

/// Checks a request before the back end sees it and puts its URI in origin
/// form. `Err` is the status to answer with instead.
pub(crate) fn route<T>(request: &mut Request<T>, host: &str) -> Result<Route, StatusCode> {
    if request.method() == Method::CONNECT {
        return Err(StatusCode::FORBIDDEN);
    }
    let uri = request.uri();
    let Some(path) = uri
        .path_and_query()
        .filter(|path| path.as_str().starts_with('/'))
        .cloned()
    else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let authority = if request.version() == Version::HTTP_2 {
        // HTTP/2 carries :scheme and :authority in the URI. A Host header may
        // stand in for :authority, and must agree with it when both appear.
        if uri.scheme_str().is_some_and(|scheme| scheme != "https") {
            return Err(StatusCode::BAD_REQUEST);
        }
        match (uri.authority(), single(request.headers(), HOST)) {
            (Some(authority), Ok(Some(header))) if header != authority.as_str() => {
                return Err(StatusCode::BAD_REQUEST);
            }
            (Some(authority), Ok(_)) => Some(authority.as_str()),
            (None, Ok(header)) => header,
            (_, Err(())) => None,
        }
    } else {
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        single(request.headers(), HOST).ok().flatten()
    };
    if !authority.is_some_and(|authority| names_host(authority, host)) {
        return Err(StatusCode::MISDIRECTED_REQUEST);
    }
    let route = if !request.headers().contains_key(UPGRADE) {
        Route::Ordinary
    } else if is_websocket(request) {
        Route::WebSocket
    } else {
        return Err(StatusCode::FORBIDDEN);
    };
    *request.uri_mut() = Uri::from(path);
    Ok(route)
}

/// `authority` is the bound host, optionally with port 443.
fn names_host(authority: &str, host: &str) -> bool {
    authority
        .strip_suffix(":443")
        .unwrap_or(authority)
        .eq_ignore_ascii_case(host)
}

/// An HTTP/1.1 GET without a body, whose only Upgrade token is `websocket`
/// and whose Connection header lists `upgrade`.
fn is_websocket<T>(request: &Request<T>) -> bool {
    let headers = request.headers();
    let upgrade = single(headers, UPGRADE).ok().flatten();
    let connection_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let bodiless = !headers.contains_key(TRANSFER_ENCODING)
        && headers
            .get_all(CONTENT_LENGTH)
            .iter()
            .all(|value| value.as_bytes() == b"0");
    request.version() == Version::HTTP_11
        && request.method() == Method::GET
        && upgrade.is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && connection_upgrade
        && bodiless
}

/// The one value of `name`, if any; `Err` when it repeats or is not text.
fn single(headers: &HeaderMap, name: http::header::HeaderName) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn empty(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status;
    response
}

fn empty_body() -> ResponseBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

/// Spawns HTTP/2 stream tasks that end with the connection, so no back-end
/// call outlives it.
#[derive(Clone)]
struct Scoped(CancellationToken);

impl<F> hyper::rt::Executor<F> for Scoped
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let stop = self.0.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = future => {}
                () = stop.cancelled() => {}
            }
        });
    }
}
