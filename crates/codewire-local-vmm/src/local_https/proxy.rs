//! The router's back end: each decrypted request goes to the route's guest
//! port on the workload's loopback, over HTTP/1.1 on one `ForwardTcp`
//! stream, as a reverse proxy would send it.

use std::sync::Arc;

use bytes::Bytes;
use codewire_egress_front_door::{Backend, BoxError, Incoming, ResponseBody, UpgradeOutcome};
use http::header::{
    CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::TokioIo;
use tokio::io::DuplexStream;

use super::Routes;
use crate::guest_loopback::{GuestLoopbackError, open_guest_loopback};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
/// Hop-by-hop headers (RFC 9110 §7.6.1), never passed on as they came.
const HOP_BY_HOP: [&str; 4] = [
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
];

pub(super) struct Proxy<R> {
    routes: Arc<R>,
    /// The port the router listens on, part of the public authority.
    port: u16,
}

impl<R> Proxy<R> {
    pub(super) fn new(routes: Arc<R>, port: u16) -> Self {
        Self { routes, port }
    }

    /// The authority the browser used: the host, and the port unless it is
    /// HTTPS's own.
    fn authority(&self, host: &str) -> String {
        if self.port == super::DEFAULT_PORT {
            host.to_owned()
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl<R: Routes> Proxy<R> {
    /// A stream to the route's guest port, or why the browser gets none.
    async fn upstream(&self, host: &str) -> Result<DuplexStream, Refusal> {
        let route = self.routes.route(host).ok_or(Refusal::NotServed)?;
        let client = self
            .routes
            .daemon(&route)
            .await
            .ok_or_else(|| Refusal::NotRunning(route.environment.clone()))?;
        open_guest_loopback(&client, route.guest_port)
            .await
            .map_err(|error| match error {
                GuestLoopbackError::NothingListens(port) => {
                    Refusal::NothingListens(route.environment.clone(), port)
                }
                error => Refusal::Failed(route.environment.clone(), error),
            })
    }

    /// The request as the guest server receives it.
    fn forwarded<B>(&self, host: &str, request: Request<B>, upgrade: bool) -> Request<B> {
        let (mut parts, body) = request.into_parts();
        let authority = self.authority(host);
        strip_hop_by_hop(&mut parts.headers, upgrade);
        // HTTP/2 carries the authority in the request line; HTTP/1.1 in Host.
        if !parts.headers.contains_key(HOST)
            && let Ok(value) = HeaderValue::from_str(&authority)
        {
            parts.headers.insert(HOST, value);
        }
        for name in [
            X_FORWARDED_FOR,
            X_FORWARDED_HOST,
            X_FORWARDED_PROTO,
            FORWARDED,
        ] {
            parts.headers.remove(name);
        }
        parts
            .headers
            .insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        if let Ok(value) = HeaderValue::from_str(&authority) {
            parts.headers.insert(X_FORWARDED_HOST, value);
        }
        parts
            .headers
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("127.0.0.1"));
        parts.version = Version::HTTP_11;
        Request::from_parts(parts, body)
    }
}

impl<R: Routes> Backend for Proxy<R> {
    async fn respond(&self, host: &str, request: Request<Incoming>) -> Response<ResponseBody> {
        let stream = match self.upstream(host).await {
            Ok(stream) => stream,
            Err(refusal) => return refusal.response(),
        };
        let Ok((mut sender, connection)) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        else {
            return plain(StatusCode::BAD_GATEWAY, "The server did not answer.\n");
        };
        // It ends when the response body does, or the server closes.
        drop(tokio::spawn(connection));
        match sender
            .send_request(self.forwarded(host, request, false))
            .await
        {
            Ok(response) => {
                let (mut parts, body) = response.into_parts();
                strip_hop_by_hop(&mut parts.headers, false);
                Response::from_parts(parts, body.map_err(BoxError::from).boxed())
            }
            Err(_) => plain(
                StatusCode::BAD_GATEWAY,
                "The server closed the connection.\n",
            ),
        }
    }

    async fn upgrade(&self, host: &str, request: Request<()>) -> UpgradeOutcome {
        let stream = self
            .upstream(host)
            .await
            .map_err(|refusal| refusal.response())?;
        let Ok((mut sender, connection)) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        else {
            return Err(plain(
                StatusCode::BAD_GATEWAY,
                "The server did not answer.\n",
            ));
        };
        drop(tokio::spawn(connection.with_upgrades()));
        let request = self
            .forwarded(host, request, true)
            .map(|()| Empty::<Bytes>::new());
        let mut response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(_) => {
                return Err(plain(
                    StatusCode::BAD_GATEWAY,
                    "The server closed the connection.\n",
                ));
            }
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, body) = response.into_parts();
            strip_hop_by_hop(&mut parts.headers, false);
            return Err(Response::from_parts(
                parts,
                body.map_err(BoxError::from).boxed(),
            ));
        }
        let upgraded = match hyper::upgrade::on(&mut response).await {
            Ok(upgraded) => upgraded,
            Err(_) => {
                return Err(plain(
                    StatusCode::BAD_GATEWAY,
                    "The server's upgrade failed.\n",
                ));
            }
        };
        let (parts, _) = response.into_parts();
        Ok((
            Response::from_parts(parts, ()),
            Box::new(TokioIo::new(upgraded)),
        ))
    }
}

/// Why a request reached no guest server. The browser reads it as plain
/// text.
enum Refusal {
    /// The environment stopped, or its port lost its label, after the
    /// handshake.
    NotServed,
    NotRunning(String),
    NothingListens(String, u16),
    Failed(String, GuestLoopbackError),
}

impl Refusal {
    fn response(self) -> Response<ResponseBody> {
        match self {
            Self::NotServed => plain(StatusCode::NOT_FOUND, "This hostname is not served.\n"),
            Self::NotRunning(environment) => plain(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("{environment} is not running.\n"),
            ),
            Self::NothingListens(environment, port) => plain(
                StatusCode::BAD_GATEWAY,
                format!("Nothing in {environment} listens on 127.0.0.1:{port} yet.\n"),
            ),
            Self::Failed(environment, error) => plain(
                StatusCode::BAD_GATEWAY,
                format!("{environment}: {error}.\n"),
            ),
        }
    }
}

/// Remove the hop-by-hop headers and those `Connection` names. An upgrade
/// keeps `Connection: upgrade` and `Upgrade`, which the guest server needs.
fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .filter(|name| !(upgrade && *name == UPGRADE))
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    if upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}

fn plain(status: StatusCode, text: impl Into<String>) -> Response<ResponseBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(text.into()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}
