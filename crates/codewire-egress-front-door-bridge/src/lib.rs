//! A front door back end for the existing credential routes.
//!
//! The TLS front door hands over each decrypted request with the bound host
//! it was made to. This back end maps that host and the request's path to
//! one of the managed path prefixes the loopback credential ingress already
//! serves, then calls [`CredentialBridge::respond`] exactly as that ingress
//! does. The bridge, its classifier and the broker's per-destination checks
//! decide everything after the rewrite; nothing here widens what they admit.
//! GitHub's two hosts have no prefix: the bridge selects their routes from
//! the bound host itself, and their paths go on as received.
//!
//! Paths are matched as received, never decoded or normalised. A path that
//! could mean something else once a server decodes or resolves it is
//! refused, because the route's own checks see only the rewritten path.
//!
//! [`EnvironmentFrontDoor`] is one environment's front door as its own
//! process runs it: the streams the egress broker hands over, the TLS front
//! door, this back end, and the bridge session to the credential broker.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod confine;
pub mod control;
mod environment;
pub mod handoff;

pub use codewire_credential_bridge::FRONT_DOOR_SESSION_ROLE_TAG;
pub use environment::{Ended, EnvironmentFrontDoor, INTERCEPT_PORT, StartError};

use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use codewire_access::{
    ANTHROPIC_API_HOST, CHATGPT_HOST, CLAUDE_TOKEN_HOST, GITHUB_HOSTS,
    MANAGED_ANTHROPIC_API_PREFIX, MANAGED_ANTHROPIC_OAUTH_PREFIX, ManagedCredentialClients,
    OPENAI_API_HOST, Refusal, Unforwarded, UpstreamFailure,
};
use codewire_credential_bridge::{
    CredentialBridge, MANAGED_GITHUB_GIT_PREFIX, MANAGED_OPENAI_API_PREFIX, UpgradeAnswer,
    intercepted_host_route, refusal_response,
};
use codewire_egress_front_door::{
    Backend, BoxError, FrontDoorRefusal, Incoming, InterceptedDestination, ResponseBody,
    UpgradeOutcome,
};
use codewire_egress_policy::check::CheckDestination;
use codewire_egress_policy::intercept::{
    InterceptBinding, InterceptError, InterceptSet, InterceptSuffix,
};
use http::header::{HOST, HeaderName};
use http::{HeaderMap, Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use hyper::body::{Body as HttpBody, Frame, SizeHint};

/// The most entries one route table holds; never more than a front door's
/// CA binds hosts.
pub const MAX_ROUTES: usize = 32;

/// The path prefix of the Codex route. The bridge's classifier spells it
/// as a literal, so a test feeds it through the classifier to catch drift.
const CODEX_PREFIX: &str = "/v1";

// The default routes' hosts are codewire-access's `FRONT_DOOR_HOSTS`, which
// hosted interception binds too. Codex on a ChatGPT sign-in maps every path
// whole, and the broker admits only the ones Codex sends its credential to
// (#3999).
/// The OpenAI API route's base.
const OPENAI_API_PATH: &str = "/v1";
// Claude's token host is routed on every path, and the broker forwards every
// request that is not a managed refresh untouched. GitHub's hosts each select
// their route by host, so every path maps as received. Which hosts an
// environment gets is `codewire_access::front_door_hosts`.

/// The managed path prefixes the bridge's classifier recognises. Each
/// selects one route; a rewritten path is that prefix and the rest of the
/// request's path.
fn route_prefixes() -> [&'static str; 5] {
    [
        MANAGED_ANTHROPIC_API_PREFIX,
        MANAGED_ANTHROPIC_OAUTH_PREFIX,
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
    /// One of the managed prefixes the credential bridge recognises, or
    /// empty for a host whose route the bridge selects from the host itself
    /// ([`Self::by_host`]).
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

    /// Every path of `host`, as received: for a host whose route the
    /// credential bridge selects from the intercepted host, with no managed
    /// prefix a loopback client could name.
    pub fn by_host(host: impl Into<String>) -> Self {
        Self::new(host, "/", "")
    }

    fn selected_by_host(&self) -> bool {
        self.add_prefix.is_empty()
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
    #[error("a host that selects its own route covers every path and adds no prefix")]
    HostRoute,
    #[error("two routes share a host and a stripped prefix")]
    Duplicate,
    #[error("a route suffix must be one of the table's own hosts")]
    Suffix,
}

/// Validated host routes, and suffix routes for the names strictly under
/// one of their hosts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTable {
    routes: Vec<HostRoute>,
    /// Routes whose `host` is a suffix: they serve a name strictly under it
    /// that no exact route names (#3999).
    suffixes: Vec<HostRoute>,
}

impl RouteTable {
    /// 1 to [`MAX_ROUTES`] entries, no two with the same host and stripped
    /// prefix.
    pub fn new<I>(routes: I) -> Result<Self, RouteTableError>
    where
        I: IntoIterator<Item = HostRoute>,
    {
        let routes = checked(routes, 0)?;
        if routes.is_empty() {
            return Err(RouteTableError::Count);
        }
        Ok(Self {
            routes,
            suffixes: Vec::new(),
        })
    }

    /// This table, also routing any name strictly under each suffix route's
    /// host that no exact route names (#3999). Each suffix must be one of
    /// this table's hosts, so the CA's name constraint already covers it.
    pub fn with_suffixes<I>(self, suffixes: I) -> Result<Self, RouteTableError>
    where
        I: IntoIterator<Item = HostRoute>,
    {
        let suffixes = checked(suffixes, self.routes.len())?;
        if suffixes
            .iter()
            .any(|suffix| !self.routes.iter().any(|route| route.host == suffix.host))
        {
            return Err(RouteTableError::Suffix);
        }
        Ok(Self {
            routes: self.routes,
            suffixes,
        })
    }

    /// The routes the credential bridge serves today: the Anthropic API on
    /// every path, the OpenAI API under `/v1`, and Codex on a ChatGPT
    /// sign-in on every path, whole, which the broker narrows to Codex's own.
    pub fn defaults() -> Self {
        Self::with_optional_hosts(false, false)
    }

    /// Every host any environment's route table may bind: the hosts a
    /// credential broker needs the network policy's answer for (#5555).
    pub fn bindable_hosts() -> Vec<String> {
        Self::with_optional_hosts(true, true)
            .hosts()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// The routes for an environment whose stock clients are `clients`: one
    /// for each host [`codewire_access::front_door_hosts`] selects, the one
    /// selection a hosted Sandbox's bindings use too (#4001 step P).
    pub fn for_clients(clients: ManagedCredentialClients) -> Self {
        let hosts = codewire_access::front_door_hosts(clients);
        let serves = |name: &str| hosts.iter().any(|host| host.host == name);
        Self::with_optional_hosts(serves(CLAUDE_TOKEN_HOST), serves(GITHUB_HOSTS[0]))
    }

    /// The defaults, with Claude's token host on every path when
    /// `claude_token_host` and GitHub's two hosts when `github`.
    pub(crate) fn with_optional_hosts(claude_token_host: bool, github: bool) -> Self {
        let claude_token = claude_token_host
            .then(|| HostRoute::new(CLAUDE_TOKEN_HOST, "/", MANAGED_ANTHROPIC_OAUTH_PREFIX));
        let github = github
            .then(|| GITHUB_HOSTS.map(HostRoute::by_host))
            .into_iter()
            .flatten();
        Self::new(
            [HostRoute::new(
                ANTHROPIC_API_HOST,
                "/",
                MANAGED_ANTHROPIC_API_PREFIX,
            )]
            .into_iter()
            .chain(claude_token)
            .chain([
                HostRoute::new(OPENAI_API_HOST, OPENAI_API_PATH, MANAGED_OPENAI_API_PREFIX),
                HostRoute::new(CHATGPT_HOST, "/", CODEX_PREFIX),
            ])
            .chain(github),
        )
        .and_then(|table| {
            // Codex's account routing can name an origin under chatgpt.com;
            // the broker serves only the one it recorded, on Codex's path.
            table.with_suffixes([HostRoute::new(CHATGPT_HOST, "/", CODEX_PREFIX)])
        })
        .expect("the built-in routes are valid")
    }

    pub fn routes(&self) -> &[HostRoute] {
        &self.routes
    }

    /// The suffix routes: each serves a name strictly under its host.
    pub fn suffix_routes(&self) -> &[HostRoute] {
        &self.suffixes
    }

    /// Each suffix once, in table order: what the front door's CA also signs
    /// under.
    pub fn suffixes(&self) -> Vec<&str> {
        let mut suffixes: Vec<&str> = Vec::new();
        for route in &self.suffixes {
            if !suffixes.contains(&route.host.as_str()) {
                suffixes.push(&route.host);
            }
        }
        suffixes
    }

    /// What a boot binds for this table on 443: every host, and every name
    /// under each suffix.
    pub fn intercepts(&self) -> Result<InterceptSet, InterceptError> {
        let bindings = self
            .hosts()
            .into_iter()
            .map(|host| InterceptBinding::new(host, INTERCEPT_PORT))
            .collect::<Result<Vec<_>, _>>()?;
        let suffixes = self
            .suffixes()
            .into_iter()
            .map(|suffix| InterceptSuffix::new(suffix, INTERCEPT_PORT))
            .collect::<Result<Vec<_>, _>>()?;
        InterceptSet::with_suffixes(bindings, suffixes)
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
    /// byte for byte. `Err` is the refusal to answer with instead: a path
    /// that decoding or resolution could change isn't forwarded (400), and
    /// one no route of `host` covers isn't served (404).
    pub fn rewrite(&self, host: &str, uri: &Uri) -> Result<Uri, Refusal> {
        let malformed = Refusal::RequestNotForwarded(Unforwarded::Malformed);
        let path = uri.path();
        if !plain_request_path(path) {
            return Err(malformed);
        }
        // A name an exact route names never falls to a suffix route.
        let exact = self.routes.iter().any(|route| route.host == host);
        let candidates: Vec<&HostRoute> = if exact {
            self.routes
                .iter()
                .filter(|route| route.host == host)
                .collect()
        } else {
            self.suffixes
                .iter()
                .filter(|route| strictly_under(host, &route.host))
                .collect()
        };
        let (route, rest) = candidates
            .into_iter()
            .filter_map(|route| below(path, &route.strip_prefix).map(|rest| (route, rest)))
            .max_by_key(|(route, _)| route.strip_prefix.len())
            .ok_or(Refusal::PathNotServed)?;
        let mut rewritten = String::with_capacity(
            route.add_prefix.len() + rest.len() + uri.query().map_or(0, |query| query.len() + 1),
        );
        rewritten.push_str(&route.add_prefix);
        rewritten.push_str(rest);
        if let Some(query) = uri.query() {
            rewritten.push('?');
            rewritten.push_str(query);
        }
        Uri::try_from(rewritten).map_err(|_| malformed)
    }
}

/// Hands front door requests to the credential bridge by a [`RouteTable`],
/// each naming the bound host it was intercepted for.
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
        let request = match self.routed(host, request) {
            Ok(request) => request,
            Err(refusal) => return refused(refusal, host),
        };
        // The front door sets it from the hand-off, never from the request.
        let destination = request
            .extensions()
            .get::<InterceptedDestination>()
            .map(|destination| destination.0);
        boxed(
            self.bridge
                .respond_intercepted_to(host, destination, request.map(Body::new))
                .await,
        )
    }

    /// `request` on its credential route, without Host, or the refusal to
    /// answer with instead. Requests and WebSocket upgrades take the same
    /// route.
    fn routed<B>(&self, host: &str, request: Request<B>) -> Result<Request<B>, Refusal> {
        let uri = self
            .routes
            .rewrite(host, request.uri())
            .inspect_err(|refusal| {
                tracing::debug!(
                    host,
                    outcome = "no_credential_route",
                    status = refusal.status()
                );
            })?;
        let (mut parts, body) = request.into_parts();
        parts.uri = uri;
        parts.headers = without_host(std::mem::take(&mut parts.headers));
        Ok(Request::from_parts(parts, body))
    }
}

/// A bridge response as the front door sends it.
fn boxed(response: Response<Body>) -> Response<ResponseBody> {
    response.map(|body| BoxBody::new(SyncBody(Mutex::new(body))))
}

impl Backend for CredentialRouteBackend {
    async fn respond(&self, host: &str, request: Request<Incoming>) -> Response<ResponseBody> {
        self.forward(host, request).await
    }

    /// The bridge refuses unless its session's host carries WebSockets.
    async fn upgrade(&self, host: &str, request: Request<()>) -> UpgradeOutcome {
        let request = self
            .routed(host, request)
            .map_err(|refusal| refused(refusal, host))?;
        match self.bridge.upgrade_intercepted(host, request).await {
            UpgradeAnswer::Switched { response, socket } => Ok((response, Box::new(socket))),
            UpgradeAnswer::Refused(refused) => {
                tracing::debug!(
                    host,
                    outcome = "upgrade_refused",
                    status = refused.status().as_u16()
                );
                Err(boxed(refused))
            }
        }
    }

    fn refuse(&self, host: &str, refusal: FrontDoorRefusal) -> Response<ResponseBody> {
        refused(
            match refusal {
                FrontDoorRefusal::Malformed => Refusal::RequestNotForwarded(Unforwarded::Malformed),
                FrontDoorRefusal::Forbidden => Refusal::RequestNotForwarded(Unforwarded::Refused),
                FrontDoorRefusal::Misdirected => {
                    Refusal::RequestNotForwarded(Unforwarded::Misdirected)
                }
                FrontDoorRefusal::NotSwitched => Refusal::UpstreamFailed(UpstreamFailure::Failed),
            },
            host,
        )
    }
}

/// `routes` checked one by one, none sharing a host and stripped prefix, and
/// at most [`MAX_ROUTES`] together with `already` routes held elsewhere.
fn checked<I>(routes: I, already: usize) -> Result<Vec<HostRoute>, RouteTableError>
where
    I: IntoIterator<Item = HostRoute>,
{
    let mut table: Vec<HostRoute> = Vec::new();
    for route in routes {
        if already + table.len() == MAX_ROUTES {
            return Err(RouteTableError::Count);
        }
        if !canonical_host(&route.host) {
            return Err(RouteTableError::Host);
        }
        // A host that selects its own route covers every path and adds
        // no prefix: a prefix there would send its requests to a route
        // the bridge then picks by host anyway, under another path.
        let by_host = intercepted_host_route(&route.host).is_some();
        if by_host && (!route.selected_by_host() || route.strip_prefix != "/") {
            return Err(RouteTableError::HostRoute);
        }
        if !plain_prefix(&route.strip_prefix) || (!by_host && !plain_prefix(&route.add_prefix)) {
            return Err(RouteTableError::Prefix);
        }
        if !by_host && !route_prefixes().contains(&route.add_prefix.as_str()) {
            return Err(RouteTableError::UnknownRoute);
        }
        if table.iter().any(|existing| {
            existing.host == route.host && existing.strip_prefix == route.strip_prefix
        }) {
            return Err(RouteTableError::Duplicate);
        }
        table.push(route);
    }
    Ok(table)
}

/// Whether `host` is a name strictly under `suffix`: `a.chatgpt.com` is
/// under `chatgpt.com`, `xchatgpt.com` is not.
fn strictly_under(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix)
        .and_then(|label| label.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty())
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

/// Every header but Host, in the order received. The rewritten path, or for
/// GitHub the bound host the front door names, alone selects the route: a
/// loopback client's Host names the ingress, which the broker drops, but
/// this one is whatever the environment wrote, and `api.github.com` in it
/// would select another family. `HeaderMap::remove` would reorder the rest.
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

/// The front door's answer for a refusal on the bound `host`. Before the
/// request reaches the bridge its provider isn't known, and no body here
/// names one.
fn refused(refusal: Refusal, host: &str) -> Response<ResponseBody> {
    boxed(refusal_response(refusal, None, Some(host)))
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
