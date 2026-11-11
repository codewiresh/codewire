//! A front door back end for the existing credential routes.
//!
//! The TLS front door hands over each decrypted request with the bound host
//! it was made to. This back end maps that host and the request's path to
//! one of the managed path prefixes the loopback credential ingress already
//! serves, then calls [`CredentialBridge::respond`] exactly as that ingress
//! does. The bridge, its classifier and the broker's per-destination checks
//! decide everything after the rewrite; nothing here widens what they admit.
//!
//! Paths are matched as received, never decoded or normalised. A path that
//! could mean something else once a server decodes or resolves it is
//! refused, because the route's own checks see only the rewritten path.

#![forbid(unsafe_code)]

use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use codewire_access::MANAGED_ANTHROPIC_API_PREFIX;
use codewire_credential_bridge::{
    CredentialBridge, MANAGED_GITHUB_GIT_PREFIX, MANAGED_OPENAI_API_PREFIX,
};
use codewire_egress_front_door::{Backend, BoxError, Incoming, ResponseBody, UpgradeOutcome};
use codewire_egress_policy::check::CheckDestination;
use http::header::{HOST, HeaderName};
use http::{HeaderMap, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body as HttpBody, Frame, SizeHint};

/// The most entries one route table holds; never more than a front door's
/// CA binds hosts.
pub const MAX_ROUTES: usize = 32;

/// The path prefix of the Codex route. The bridge's classifier spells it
/// as a literal, so a test feeds it through the classifier to catch drift.
const CODEX_PREFIX: &str = "/v1";

/// The Anthropic API: the route's base is the origin, so every path maps.
const ANTHROPIC_API_HOST: &str = "api.anthropic.com";
/// The OpenAI API: the route's base is `/v1`.
const OPENAI_API_HOST: &str = "api.openai.com";
const OPENAI_API_PATH: &str = "/v1";
/// Codex on a ChatGPT sign-in: the route's base is `/backend-api/codex`.
const CHATGPT_HOST: &str = "chatgpt.com";
const CHATGPT_CODEX_PATH: &str = "/backend-api/codex";

/// The managed path prefixes the bridge's classifier recognises. Each
/// selects one route; a rewritten path is that prefix and the rest of the
/// request's path.
fn route_prefixes() -> [&'static str; 4] {
    [
        MANAGED_ANTHROPIC_API_PREFIX,
        MANAGED_OPENAI_API_PREFIX,
        // The constant carries the slash that begins the rest of the path.
        MANAGED_GITHUB_GIT_PREFIX.trim_end_matches('/'),
        CODEX_PREFIX,
    ]
}

/// One mapping: requests for `host` whose path is `strip_prefix` or below it
/// go to `add_prefix` followed by the rest of the path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRoute {
    /// An exact canonical DNS name, as the front door's CA binds it.
    pub host: String,
    /// `/` for every path, or a path of whole segments without a trailing
    /// slash, matched only at a segment boundary.
    pub strip_prefix: String,
    /// One of the managed prefixes the credential bridge recognises.
    pub add_prefix: String,
}

impl HostRoute {
    pub fn new(
        host: impl Into<String>,
        strip_prefix: impl Into<String>,
        add_prefix: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            strip_prefix: strip_prefix.into(),
            add_prefix: add_prefix.into(),
        }
    }
}

/// Why a route table was refused. Carries no input, so it may be logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteTableError {
    #[error("a route table holds 1 to 32 entries")]
    Count,
    #[error("a route host must be an exact canonical DNS name of at least two labels")]
    Host,
    #[error("a route prefix must be a plain absolute path without dot or empty segments")]
    Prefix,
    #[error("a route must add a prefix the credential bridge recognises")]
    UnknownRoute,
    #[error("two routes share a host and a stripped prefix")]
    Duplicate,
}

/// Validated host routes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTable {
    routes: Vec<HostRoute>,
}

impl RouteTable {
    /// 1 to [`MAX_ROUTES`] entries, no two with the same host and stripped
    /// prefix.
    pub fn new<I>(routes: I) -> Result<Self, RouteTableError>
    where
        I: IntoIterator<Item = HostRoute>,
    {
        let mut table: Vec<HostRoute> = Vec::new();
        for route in routes {
            if table.len() == MAX_ROUTES {
                return Err(RouteTableError::Count);
            }
            if !canonical_host(&route.host) {
                return Err(RouteTableError::Host);
            }
            if !plain_prefix(&route.strip_prefix) || !plain_prefix(&route.add_prefix) {
                return Err(RouteTableError::Prefix);
            }
            if !route_prefixes().contains(&route.add_prefix.as_str()) {
                return Err(RouteTableError::UnknownRoute);
            }
            if table.iter().any(|existing| {
                existing.host == route.host && existing.strip_prefix == route.strip_prefix
            }) {
                return Err(RouteTableError::Duplicate);
            }
            table.push(route);
        }
        if table.is_empty() {
            return Err(RouteTableError::Count);
        }
        Ok(Self { routes: table })
    }

    /// The routes the credential bridge serves today: the Anthropic API on
    /// every path, the OpenAI API under `/v1`, and Codex on a ChatGPT
    /// sign-in under `/backend-api/codex`.
    pub fn defaults() -> Self {
        Self::new([
            HostRoute::new(ANTHROPIC_API_HOST, "/", MANAGED_ANTHROPIC_API_PREFIX),
            HostRoute::new(OPENAI_API_HOST, OPENAI_API_PATH, MANAGED_OPENAI_API_PREFIX),
            HostRoute::new(CHATGPT_HOST, CHATGPT_CODEX_PATH, CODEX_PREFIX),
        ])
        .expect("the built-in routes are valid")
    }

    pub fn routes(&self) -> &[HostRoute] {
        &self.routes
    }

    /// Each host once, in table order: what the front door's CA binds.
    pub fn hosts(&self) -> Vec<&str> {
        let mut hosts: Vec<&str> = Vec::new();
        for route in &self.routes {
            if !hosts.contains(&route.host.as_str()) {
                hosts.push(&route.host);
            }
        }
        hosts
    }

    /// The managed origin-form URI for a request to `host`, its query kept
    /// byte for byte. `Err` is the status to answer with instead: `400` for
    /// a path that decoding or resolution could change, `404` for a path no
    /// route of `host` covers.
    pub fn rewrite(&self, host: &str, uri: &Uri) -> Result<Uri, StatusCode> {
        let path = uri.path();
        if !plain_request_path(path) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let (route, rest) = self
            .routes
            .iter()
            .filter(|route| route.host == host)
            .filter_map(|route| below(path, &route.strip_prefix).map(|rest| (route, rest)))
            .max_by_key(|(route, _)| route.strip_prefix.len())
            .ok_or(StatusCode::NOT_FOUND)?;
        let mut rewritten = String::with_capacity(
            route.add_prefix.len() + rest.len() + uri.query().map_or(0, |query| query.len() + 1),
        );
        rewritten.push_str(&route.add_prefix);
        rewritten.push_str(rest);
        if let Some(query) = uri.query() {
            rewritten.push('?');
            rewritten.push_str(query);
        }
        Uri::try_from(rewritten).map_err(|_| StatusCode::BAD_REQUEST)
    }
}

/// Hands front door requests to the credential bridge by a [`RouteTable`].
pub struct CredentialRouteBackend {
    routes: RouteTable,
    bridge: CredentialBridge,
}

impl CredentialRouteBackend {
    pub fn new(routes: RouteTable, bridge: CredentialBridge) -> Self {
        Self { routes, bridge }
    }

    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// [`Backend::respond`] for any request body. The body is not read here:
    /// the bridge reads it whole, within its request bound, exactly as it
    /// does for the loopback ingress.
    async fn forward<B>(&self, host: &str, request: Request<B>) -> Response<ResponseBody>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let uri = match self.routes.rewrite(host, request.uri()) {
            Ok(uri) => uri,
            Err(status) => {
                tracing::debug!(
                    host,
                    outcome = "no_credential_route",
                    status = status.as_u16()
                );
                return empty(status);
            }
        };
        let (mut parts, body) = request.into_parts();
        parts.uri = uri;
        parts.headers = without_host(std::mem::take(&mut parts.headers));
        self.bridge
            .respond(Request::from_parts(parts, Body::new(body)))
            .await
            .map(|body| BoxBody::new(SyncBody(Mutex::new(body))))
    }
}

impl Backend for CredentialRouteBackend {
    async fn respond(&self, host: &str, request: Request<Incoming>) -> Response<ResponseBody> {
        self.forward(host, request).await
    }

    async fn upgrade(&self, host: &str, _request: Request<()>) -> UpgradeOutcome {
        // The bridge carries HTTP requests only. WebSockets reach the routes
        // with the bridge protocol change in a later slice of #3999.
        tracing::debug!(host, outcome = "upgrade_refused");
        Err(empty(StatusCode::FORBIDDEN))
    }
}

/// The policy crate's canonical names, taken as they are, as the front
/// door's CA takes its bound hosts.
fn canonical_host(host: &str) -> bool {
    matches!(
        CheckDestination::parse(host),
        Ok(CheckDestination::Name(name)) if name == host && name.contains('.')
    )
}

/// `/`, or `/`-separated non-empty segments of unreserved characters with
/// no dot segment: nothing a server could decode, resolve or split.
fn plain_prefix(prefix: &str) -> bool {
    prefix == "/"
        || (prefix.starts_with('/')
            && !prefix.ends_with('/')
            && !prefix.contains("..")
            && !prefix.contains("//")
            && prefix[1..].split('/').all(|segment| segment != ".")
            && prefix.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~')
            }))
}

/// A raw request path with no dot segment, no empty segment and no encoded
/// slash or dot.
fn plain_request_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path[1..]
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        && !path.as_bytes().windows(3).any(|window| {
            window[0] == b'%' && window[1] == b'2' && matches!(window[2], b'e' | b'E' | b'f' | b'F')
        })
}

/// The rest of `path` below `prefix` at a segment boundary: `/v1` covers
/// `/v1` and `/v1/x`, never `/v1x`; `/` covers every path.
fn below<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix == "/" {
        return Some(path);
    }
    path.strip_prefix(prefix)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Every header but Host, in the order received. The rewritten path alone
/// selects the route: a loopback client's Host names the ingress, which the
/// broker drops, but this one names the provider, and `api.github.com` would
/// select another family. `HeaderMap::remove` would reorder the rest.
fn without_host(headers: HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::with_capacity(headers.len());
    let mut current: Option<HeaderName> = None;
    for (name, value) in headers {
        if name.is_some() {
            current = name;
        }
        if let Some(name) = current.as_ref().filter(|name| **name != HOST) {
            kept.append(name.clone(), value);
        }
    }
    kept
}

fn empty(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = status;
    response
}

/// The bridge's response body is `Send` but not `Sync`, which the front
/// door's body type requires. Polling takes `&mut self` and never locks; the
/// lock is only for the size and end queries, which take `&self`.
struct SyncBody(Mutex<Body>);

impl HttpBody for SyncBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let body = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        Pin::new(body).poll_frame(cx).map_err(Into::into)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .size_hint()
    }
}

#[cfg(test)]
mod tests;
