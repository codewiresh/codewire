use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use async_trait::async_trait;
use av_credential_proxy::tunnel_ip_allowed;
use codewire_access::HttpProvider;
#[cfg(feature = "platform")]
use codewire_access::{AvailableGrants, CapabilitySlot, FRONT_DOOR_HOSTS, GITHUB_HOSTS};
use codewire_egress_policy::intercept::InterceptBinding;
use futures::StreamExt as _;
use http::{HeaderMap, Method};
use reqwest::redirect::Policy;

use crate::provider_oauth::claude::{CLAUDE_PROFILE_PATH, CLAUDE_TOKEN_HOST, CLAUDE_TOKEN_PATH};
use crate::provider_oauth::{
    CODEX_DEVICE_TOKEN_PATH, CODEX_DEVICE_USERCODE_PATH, CODEX_TOKEN_REVOCATION_PATH,
    GITHUB_ACCESS_TOKEN_PATH, GITHUB_API_HOST, GITHUB_DEVICE_CODE_PATH, OPENAI_AUTH_HOST,
    OPENAI_TOKEN_PATH,
};
use crate::refresh_failure::TransportFailure;
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    BrokerUpstreamUpgrade,
};

const OPENAI_HOST: &str = "api.openai.com";
const CHATGPT_HOST: &str = "chatgpt.com";
const ANTHROPIC_HOST: &str = "api.anthropic.com";
const GITHUB_GIT_HOST: &str = "github.com";
const OPENAI_PORT: u16 = 443;
/// Transparent routes' pinned base paths (#2536); Anthropic's is its origin.
const OPENAI_BASE_PATH: &str = "/v1/";
const CHATGPT_CODEX_BASE_PATH: &str = "/backend-api/codex/";
/// The `chatgpt.com` paths the pinned Codex was observed sending its
/// credential to (#3999): its base, its usage and account namespace, its
/// plugins, and one account check. A loopback target is always under
/// [`CHATGPT_CODEX_BASE_PATH`]; only a front-door request names the others.
const CHATGPT_FRONT_DOOR_PREFIXES: [&str; 4] = [
    CHATGPT_CODEX_BASE_PATH,
    "/backend-api/wham/",
    "/backend-api/plugins/",
    "/backend-api/ps/",
];
const CHATGPT_FRONT_DOOR_PATHS: [&str; 1] = ["/backend-api/accounts/verified_access"];
pub(crate) use codewire_access::ROUTED_SUFFIXES;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole-request bound for a request with a whole body. A streamed GitHub
/// Git request has none: its bridge bounds it by idle time instead (#4280).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a WebSocket opening request waits for its response head. The
/// connect has its own bound; once switched, the socket has none here.
const UPGRADE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// A pooled provider connection unused this long is closed.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Idle connections kept per provider host. Concurrent requests beyond this
/// still get their own connection; only the surplus is closed when idle.
const POOL_MAX_IDLE_PER_HOST: usize = 32;
/// TCP keepalive on pooled connections, so a dead idle peer is noticed and
/// dropped from the pool rather than handed to the next request.
const POOL_TCP_KEEPALIVE: Duration = Duration::from_secs(15);

/// How a [`ProviderHttpsTransport`] reuses provider connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionReuse {
    /// Every request opens its own TCP and TLS connection.
    PerRequest,
    /// HTTP/1.1 keep-alive: a connection carries one request at a time and
    /// returns to the pool only after its response was read to the end.
    Pooled,
}

/// Broker-local selected-provider transport. DNS is resolved once per broker process, every
/// result is classified before dialing, and the admitted addresses are pinned
/// into the TLS client so a second resolver lookup cannot rebind the request.
#[derive(Clone)]
pub struct ProviderHttpsTransport {
    client: reqwest::Client,
    /// HTTP/1.1 only, a connection per request and no whole-request bound,
    /// for a front door's WebSocket upgrade (#3999); pinned like `client`.
    upgrade_client: reqwest::Client,
    selected: BTreeSet<HttpProvider>,
    /// Selected hosts with no pinned address: their lookup failed, or gave
    /// addresses this transport does not admit. Only a transport from
    /// [`Self::available`] has any. A request to one is never sent,
    /// and never looked up again.
    unresolved: BTreeSet<&'static str>,
    /// GitHub's log hosts this transport pinned an address for (#5737). A log
    /// host that is not here is never dialled, and is no provider's.
    log_hosts: BTreeSet<&'static str>,
    resolved_address_count: usize,
    reuse: ConnectionReuse,
}

/// What one broker start's lookups found: each host's admitted addresses, or
/// none for a host left unresolved. Made by [`ProviderHttpsTransport::look_up`].
pub struct LookedUpHosts(BTreeMap<&'static str, Option<Vec<SocketAddr>>>);

impl std::fmt::Debug for ProviderHttpsTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderHttpsTransport")
            .field("selected", &self.selected)
            .field("unresolved", &self.unresolved)
            .field("resolved_address_count", &self.resolved_address_count)
            .field("reuse", &self.reuse)
            .finish_non_exhaustive()
    }
}

impl ProviderHttpsTransport {
    /// Resolve and classify the fixed provider destination before any
    /// credential lease is requested. The admitted addresses remain pinned for
    /// this broker process, so post-confinement requests perform no DNS I/O.
    /// Every request opens its own connection: this is the transport of the
    /// per-environment local and owner-local brokers.
    pub async fn resolve(selected: &BTreeSet<HttpProvider>) -> Result<Self, BrokerUpstreamError> {
        Self::resolve_with(selected, ConnectionReuse::PerRequest, system_lookup)
    }

    /// [`Self::resolve`] with an HTTP/1.1 keep-alive connection pool, for the
    /// long-lived credential service's broker upstream only.
    ///
    /// Resolution, address admission and pinning are identical, so a pooled
    /// connection was dialed to an admitted address like any other, and every
    /// request still passes the destination check before a connection is
    /// chosen. The pool is keyed by scheme and authority (host and port) and
    /// never coalesces hosts, so a connection is reused only for the same
    /// validated destination. Provider authentication is in each request's
    /// headers, and HTTP/1.1 keeps no state between requests on a
    /// connection, so a connection carries nothing from one credential to the
    /// next. A response dropped before its end closes its connection.
    ///
    /// HTTP/2 is deliberately not offered here. One HTTP/2 connection per host
    /// would multiplex every tenant's requests: its shared receive window can
    /// be held by responses a stalled guest is not reading, its stream limit
    /// queues new requests behind long-lived streams, and one connection
    /// error fails them all. With HTTP/1.1, concurrent requests use separate
    /// connections exactly as before; only sequential ones skip the handshake.
    pub async fn resolve_pooled(
        selected: &BTreeSet<HttpProvider>,
    ) -> Result<Self, BrokerUpstreamError> {
        Self::resolve_with(selected, ConnectionReuse::Pooled, system_lookup)
    }

    /// Looks up every host `selections` name, each once and all at the same
    /// time, for a broker that starts whatever resolves (#5286,
    /// `docs/dev/SECRETS-AND-CREDENTIALS.md`, "A provider that can't be
    /// looked up when a local VM starts"). A broker's transports are all
    /// built from this one answer with [`Self::available`], so its start
    /// waits one resolver timeout at most, whatever the number of hosts and
    /// of transports that share them.
    pub async fn look_up(
        selections: &[&BTreeSet<HttpProvider>],
    ) -> Result<LookedUpHosts, BrokerUpstreamError> {
        Self::look_up_with(selections, system_lookup)
    }

    fn look_up_with(
        selections: &[&BTreeSet<HttpProvider>],
        lookup: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Sync,
    ) -> Result<LookedUpHosts, BrokerUpstreamError> {
        let mut hosts = BTreeSet::new();
        for selected in selections {
            hosts.extend(selected_hosts(selected)?);
            hosts.extend(log_hosts_for(selected));
        }
        Ok(LookedUpHosts(look_up_all(hosts, &lookup)))
    }

    /// The transport for `selected` from one start's lookups. A host whose
    /// lookup failed, or gave addresses this transport does not admit, is
    /// left unresolved instead of failing the transport:
    /// [`Self::unresolved_hosts`] names them, and a request to one fails as a
    /// connection failure without being sent. A selection `looked_up` does
    /// not cover is refused.
    pub fn available(
        selected: &BTreeSet<HttpProvider>,
        looked_up: &LookedUpHosts,
    ) -> Result<Self, BrokerUpstreamError> {
        let mut pinned = Vec::new();
        let mut unresolved = BTreeSet::new();
        for host in selected_hosts(selected)? {
            match looked_up.0.get(host) {
                Some(Some(addresses)) => pinned.push((host, addresses.clone())),
                Some(None) => {
                    unresolved.insert(host);
                }
                None => return Err(BrokerUpstreamError::DestinationDenied),
            }
        }
        // A log host without an address is dropped by name; GitHub stays
        // served.
        let logs = log_hosts_for(selected)
            .filter_map(|host| Some((host, looked_up.0.get(host)?.clone()?)))
            .collect::<Vec<_>>();
        Self::pinned(
            selected,
            ConnectionReuse::PerRequest,
            &pinned,
            &logs,
            unresolved,
        )
    }

    /// The selected hosts this transport has no address for.
    pub fn unresolved_hosts(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.unresolved.iter().copied()
    }

    fn resolve_with(
        selected: &BTreeSet<HttpProvider>,
        reuse: ConnectionReuse,
        lookup: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Sync,
    ) -> Result<Self, BrokerUpstreamError> {
        // This deliberately uses the calling thread instead of Tokio's
        // blocking resolver pool. Broker launch is bounded by the authority's
        // readiness timeout, and retaining a resolver worker here would leave
        // an already-running thread outside older Landlock thread domains.
        let hosts = selected_hosts(selected)?;
        let mut pinned = Vec::with_capacity(hosts.len());
        for host in &hosts {
            let addresses = lookup(host, OPENAI_PORT).map_err(|_| BrokerUpstreamError::Connect)?;
            pinned.push((*host, admit_resolved_addresses(addresses)?));
        }
        // The pooled transport is the hosted credential service's, which
        // serves guests' log downloads; a per-request one serves sign-in
        // commands, which follow no log redirect. Log hosts never fail it.
        let logs = match reuse {
            ConnectionReuse::Pooled => look_up_all(log_hosts_for(selected).collect(), &lookup)
                .into_iter()
                .filter_map(|(host, addresses)| Some((host, addresses?)))
                .collect(),
            ConnectionReuse::PerRequest => Vec::new(),
        };
        Self::pinned(selected, reuse, &pinned, &logs, BTreeSet::new())
    }

    /// The transport for `pinned` hosts and their admitted addresses.
    fn pinned(
        selected: &BTreeSet<HttpProvider>,
        reuse: ConnectionReuse,
        pinned: &[(&'static str, Vec<SocketAddr>)],
        logs: &[(&'static str, Vec<SocketAddr>)],
        unresolved: BTreeSet<&'static str>,
    ) -> Result<Self, BrokerUpstreamError> {
        let resolved_address_count = pinned
            .iter()
            .map(|(_, addresses)| addresses.len())
            .sum::<usize>();
        // Both clients take the one pinned list, so they cannot differ.
        let pin = |mut builder: reqwest::ClientBuilder| {
            for (host, addresses) in pinned.iter().chain(logs) {
                builder = builder.resolve_to_addrs(host, addresses);
            }
            builder.build().map_err(|_| BrokerUpstreamError::Protocol)
        };
        let client = pin(client_builder(reuse))?;
        let upgrade_client = pin(upgrade_client_builder())?;
        Ok(Self {
            client,
            upgrade_client,
            selected: selected.clone(),
            unresolved,
            log_hosts: logs.iter().map(|(host, _)| *host).collect(),
            resolved_address_count,
            reuse,
        })
    }

    /// Refuses a request to a host this transport has no address for. The
    /// HTTP client would otherwise look the name up itself, after the
    /// broker's one lookup and outside its pinning.
    fn refuse_unresolved(&self, target: &url::Url) -> Result<(), BrokerUpstreamError> {
        match target.host_str() {
            Some(host) if self.unresolved.contains(host) => Err(BrokerUpstreamError::Connect),
            _ => Ok(()),
        }
    }
}

/// The hosts a slot's requests and refreshes may go to, whichever kind of
/// credential the slot holds: a transport knows the providers selected, not
/// which slot each is in, so a Codex sign-in is also unserved while
/// `api.openai.com`, which only an API key in that slot uses, is selected
/// and unresolved.
fn slot_hosts(slot: &str) -> &'static [&'static str] {
    match slot {
        "openai" => &[OPENAI_HOST],
        "codex" => &[CHATGPT_HOST, OPENAI_AUTH_HOST, OPENAI_HOST],
        "anthropic" => &[ANTHROPIC_HOST, CLAUDE_TOKEN_HOST],
        "github" => &[GITHUB_API_HOST, GITHUB_GIT_HOST],
        _ => &[],
    }
}

fn system_lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// GitHub's log hosts, for a selection that serves GitHub (#5737).
fn log_hosts_for(selected: &BTreeSet<HttpProvider>) -> impl Iterator<Item = &'static str> {
    selected
        .contains(&HttpProvider::GitHubOAuth)
        .then(crate::github::log_hosts::log_hosts)
        .into_iter()
        .flatten()
}

/// Each host's admitted addresses, or none, from lookups that all run at
/// once. One thread a host, all ended when the scope returns: none outlives
/// this call, so none is left outside the confinement the broker applies
/// afterwards.
fn look_up_all(
    hosts: BTreeSet<&'static str>,
    lookup: &(impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> + Sync),
) -> BTreeMap<&'static str, Option<Vec<SocketAddr>>> {
    let looked_up: Vec<_> = std::thread::scope(|scope| {
        let lookups: Vec<_> = hosts
            .iter()
            .map(|host| scope.spawn(|| lookup(host, OPENAI_PORT)))
            .collect();
        lookups.into_iter().map(|lookup| lookup.join()).collect()
    });
    hosts
        .into_iter()
        .zip(looked_up)
        .map(|(host, looked_up)| {
            let admitted = match looked_up {
                Ok(Ok(addresses)) => admit_resolved_addresses(addresses).ok(),
                Ok(Err(_)) | Err(_) => None,
            };
            (host, admitted)
        })
        .collect()
}

/// What every provider client shares: HTTPS to the pinned addresses, no
/// proxy, no decoding, no redirects and a bounded connect.
fn base_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(Policy::none())
        .referer(false)
        .connect_timeout(CONNECT_TIMEOUT)
}

/// A client that reaches `host` only at `address`, already admitted. TLS
/// still verifies the certificate for `host`, so an address that does not
/// serve that name fails the handshake (#3999).
fn pinned_client(
    builder: reqwest::ClientBuilder,
    host: &str,
    address: SocketAddr,
) -> Result<reqwest::Client, BrokerUpstreamError> {
    builder
        .resolve_to_addrs(host, &[address])
        .build()
        .map_err(|_| BrokerUpstreamError::Protocol)
}

/// Everything about the provider client except its pinned addresses.
fn client_builder(reuse: ConnectionReuse) -> reqwest::ClientBuilder {
    let builder =
        base_client_builder().http2_max_header_list_size(MAX_RESPONSE_HEADER_BYTES as u32);
    match reuse {
        ConnectionReuse::PerRequest => builder.pool_max_idle_per_host(0),
        // TLS offers only http/1.1. Its response head is bounded by the
        // HTTP/1.1 parser's buffer, then by `validate_response_headers`.
        ConnectionReuse::Pooled => builder
            .http1_only()
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .tcp_keepalive(POOL_TCP_KEEPALIVE),
    }
}

/// The upgrade client's settings except its pinned addresses. A WebSocket
/// opening request is HTTP/1.1 only, and its connection becomes the socket,
/// so it is never pooled. It has no whole-request bound: an open socket lasts
/// as long as its grant, which the bridge enforces.
fn upgrade_client_builder() -> reqwest::ClientBuilder {
    base_client_builder().http1_only().pool_max_idle_per_host(0)
}

#[async_trait]
impl BrokerUpstreamTransport for ProviderHttpsTransport {
    fn slot_unserved(&self, slot: &str) -> bool {
        slot_hosts(slot)
            .iter()
            .any(|host| self.unresolved.contains(host))
    }

    async fn execute(
        &self,
        mut request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let body_stream = request.take_body_stream();
        let pinned = request.pinned();
        let (method, target, headers, body) = request.into_parts();
        let validate: fn(&url::Url, &Method, &BTreeSet<HttpProvider>) -> _ = if pinned.is_some() {
            validate_pinned_target
        } else {
            validate_target
        };
        validate(&target, &method, &self.selected)?;
        self.refuse_unresolved(&target)?;
        // A routed origin was never resolved here: dial the address the
        // broker admitted for it, checked again, on a client of its own.
        let pinned_client = match pinned {
            None => None,
            Some(pinned) => {
                let address = admit_pinned(pinned.ip())?;
                let host = target
                    .host_str()
                    .ok_or(BrokerUpstreamError::DestinationDenied)?;
                Some(pinned_client(
                    client_builder(ConnectionReuse::PerRequest),
                    host,
                    address,
                )?)
            }
        };
        let client = pinned_client.as_ref().unwrap_or(&self.client);
        let is_refresh = (target.host_str() == Some(OPENAI_AUTH_HOST)
            && target.path() == OPENAI_TOKEN_PATH)
            || (target.host_str() == Some(CLAUDE_TOKEN_HOST) && target.path() == CLAUDE_TOKEN_PATH);
        let provider_host = provider_host(&target);
        let request = client
            .request(method.clone(), target.as_str())
            .headers(headers);
        let request = match body_stream {
            Some(stream) => request.body(reqwest::Body::wrap_stream(stream)),
            None if is_refresh => request.body(body).timeout(REFRESH_REQUEST_TIMEOUT),
            None => request.body(body).timeout(REQUEST_TIMEOUT),
        };
        let response = request
            .send()
            .await
            .map_err(|error| request_failed(provider_host, is_refresh, error))?;
        validate(response.url(), &method, &self.selected)?;
        if pinned_client.is_none() && log_redirect::follows(&target, &method, response.status()) {
            return self.follow_log_redirect(response).await;
        }
        upstream_response(response)
    }

    async fn forward_github(
        &self,
        mut request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let body_stream = request.take_body_stream();
        let (method, target, headers, body) = request.into_parts();
        validate_github_forward_target(&target, &method, &self.selected)?;
        self.refuse_unresolved(&target)?;
        let provider_host = provider_host(&target);
        let request = self
            .client
            .request(method.clone(), target.as_str())
            .headers(headers);
        // A forwarded body may be a push or an upload of any size, so a
        // streamed one is bounded by its idle time at the bridge, not here.
        let request = match body_stream {
            Some(stream) => request.body(reqwest::Body::wrap_stream(stream)),
            None => request.body(body).timeout(REQUEST_TIMEOUT),
        };
        let response = request
            .send()
            .await
            .map_err(|error| request_failed(provider_host, false, error))?;
        validate_github_forward_target(response.url(), &method, &self.selected)?;
        upstream_response(response)
    }

    async fn upgrade(
        &self,
        mut request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
        if request.take_body_stream().is_some() {
            return Err(BrokerUpstreamError::Protocol);
        }
        let (method, target, headers, body) = request.into_parts();
        validate_target(&target, &method, &self.selected)?;
        self.refuse_unresolved(&target)?;
        if method != Method::GET {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        if !body.is_empty()
            || !websocket_handshake(&headers)
            || UPGRADE_FRAMING_HEADERS
                .iter()
                .any(|name| headers.contains_key(name))
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let response = send_upgrade(&self.upgrade_client, &target, headers).await?;
        validate_target(response.url(), &method, &self.selected)?;
        switched_or_response(response).await
    }
}

/// Send a WebSocket opening request as given: the caller has already swapped
/// its credential, and its `Connection`, `Upgrade` and `Sec-WebSocket-*`
/// headers go on the wire unchanged.
async fn send_upgrade(
    client: &reqwest::Client,
    target: &url::Url,
    headers: HeaderMap,
) -> Result<reqwest::Response, BrokerUpstreamError> {
    let provider_host = provider_host(target);
    let sent = client.get(target.as_str()).headers(headers).send();
    match tokio::time::timeout(UPGRADE_RESPONSE_TIMEOUT, sent).await {
        Ok(response) => response.map_err(|error| request_failed(provider_host, false, error)),
        Err(_) => {
            tracing::warn!(
                provider_host,
                failure = "upgrade_response_timeout",
                "provider transport request failed"
            );
            Err(BrokerUpstreamError::Connect)
        }
    }
}

/// A `101` becomes the provider's upgraded connection; any other status is
/// an ordinary response.
async fn switched_or_response(
    response: reqwest::Response,
) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        // The reply body gets `execute`'s whole-request bound, which the
        // upgrade client cannot carry.
        let (status, headers, body) = upstream_response(response)?.into_parts();
        return Ok(BrokerUpstreamUpgrade::Response(
            BrokerUpstreamResponse::new(status, headers, Box::pin(within(body, REQUEST_TIMEOUT))),
        ));
    }
    let headers = response.headers().clone();
    validate_response_headers(&headers)?;
    // Any 101 would become a tunnel; only a WebSocket's may.
    if !websocket_handshake(&headers) {
        return Err(BrokerUpstreamError::Protocol);
    }
    let provider_host = provider_host(response.url());
    let stream = tokio::time::timeout(UPGRADE_RESPONSE_TIMEOUT, response.upgrade())
        .await
        .map_err(|_| BrokerUpstreamError::Connect)?
        .map_err(|error| request_failed(provider_host, false, error))?;
    Ok(BrokerUpstreamUpgrade::Switched {
        headers,
        stream: Box::new(stream),
    })
}

/// Request headers an upgrade refuses: the transport frames the request
/// itself, and only the pinned destination names its `Host`.
const UPGRADE_FRAMING_HEADERS: [http::HeaderName; 3] = [
    http::header::HOST,
    http::header::CONTENT_LENGTH,
    http::header::TRANSFER_ENCODING,
];

/// A WebSocket handshake's headers: exactly one `Upgrade: websocket` and an
/// `upgrade` token in `Connection`. The rest of the handshake is the agent's
/// to verify.
fn websocket_handshake(headers: &HeaderMap) -> bool {
    let mut upgrade = headers.get_all(http::header::UPGRADE).iter();
    let websocket = upgrade
        .next()
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
        && upgrade.next().is_none();
    websocket
        && headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// `body`, ended with a connect failure once `limit` has passed.
fn within(
    body: crate::runtime::BrokerUpstreamBody,
    limit: Duration,
) -> impl futures::Stream<Item = Result<bytes::Bytes, BrokerUpstreamError>> + Send + 'static {
    let deadline = Box::pin(tokio::time::sleep(limit));
    futures::stream::unfold(Some((body, deadline)), |state| async move {
        let (mut body, mut deadline) = state?;
        tokio::select! {
            item = body.next() => item.map(|item| (item, Some((body, deadline)))),
            () = &mut deadline => Some((Err(BrokerUpstreamError::Connect), None)),
        }
    })
}

/// A provider reply whose destination was checked, as the bridge receives it.
fn upstream_response(
    response: reqwest::Response,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let status = response.status();
    let headers = response.headers().clone();
    validate_response_headers(&headers)?;
    let body = response
        .bytes_stream()
        .map(|chunk| chunk.map_err(map_reqwest_error));
    Ok(BrokerUpstreamResponse::new(status, headers, Box::pin(body)))
}

/// Log a failed provider request, then map it. Only fixed classes and an
/// io::ErrorKind name are logged; reqwest and OS error text can carry URLs or
/// peer details.
fn request_failed(
    provider_host: &'static str,
    is_refresh: bool,
    error: reqwest::Error,
) -> BrokerUpstreamError {
    let (failure, io_error_kind) = TransportFailure::classify(
        error.is_timeout(),
        error.is_connect(),
        error.is_request(),
        &error,
    );
    let io_error_kind = io_error_kind.map_or_else(|| "none".to_owned(), |kind| format!("{kind:?}"));
    tracing::warn!(
        provider_host,
        refresh = is_refresh,
        failure = failure.as_str(),
        io_error_kind = %io_error_kind,
        "provider transport request failed"
    );
    map_reqwest_error(error)
}

/// The already-validated destination as a fixed name, never request text.
fn provider_host(target: &url::Url) -> &'static str {
    match target.host_str() {
        Some(OPENAI_HOST) => OPENAI_HOST,
        Some(CHATGPT_HOST) => CHATGPT_HOST,
        Some(OPENAI_AUTH_HOST) => OPENAI_AUTH_HOST,
        Some(ANTHROPIC_HOST) => ANTHROPIC_HOST,
        Some(CLAUDE_TOKEN_HOST) => CLAUDE_TOKEN_HOST,
        Some(GITHUB_API_HOST) => GITHUB_API_HOST,
        Some(GITHUB_GIT_HOST) => GITHUB_GIT_HOST,
        Some(host) if routed_host(host) => "chatgpt-routed-origin",
        _ => "other",
    }
}

/// A provider host a credential route sends its requests to: the only hosts a
/// front-door request may name as the one it was intercepted for. The hosts
/// the broker calls only to refresh a token are no route's, except the
/// agents' token hosts, which their front door also routes: Claude Code
/// refreshes through Claude's, and Codex through Codex's (#6197).
/// `github.com` is both a route's host and where a GitHub App token is
/// exchanged; the route admits only its Git paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteHost {
    OpenAiApi,
    ChatGpt,
    AnthropicApi,
    ClaudeToken,
    CodexToken,
    GitHubApi,
    GitHub,
}

impl RouteHost {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiApi => OPENAI_HOST,
            Self::ChatGpt => CHATGPT_HOST,
            Self::AnthropicApi => ANTHROPIC_HOST,
            Self::ClaudeToken => CLAUDE_TOKEN_HOST,
            Self::CodexToken => OPENAI_AUTH_HOST,
            Self::GitHubApi => GITHUB_API_HOST,
            Self::GitHub => GITHUB_GIT_HOST,
        }
    }

    /// The hosts of the adapters' base URLs for one slot's route, each of
    /// which [`validate_target`] admits for that route's providers. Only the
    /// codex slot may hold a ChatGPT sign-in; an API key goes to the API.
    fn of_route(slot: &str, route: &str) -> &'static [Self] {
        match (slot, route) {
            ("codex", "openai-api") => &[Self::OpenAiApi, Self::ChatGpt, Self::CodexToken],
            ("openai", "openai-api") => &[Self::OpenAiApi],
            ("anthropic", "anthropic-api") => &[Self::AnthropicApi],
            ("anthropic", "claude-oauth-token") => &[Self::ClaudeToken],
            ("github", "github-api") => &[Self::GitHubApi],
            ("github", "github-https") => &[Self::GitHub],
            _ => &[],
        }
    }

    /// The names an interception leaf carries for these grants (#4001): each
    /// front-door host the grants' routes reach, and for a suffix entry its
    /// one-label wildcard. Only the Codex slot's route reaches `chatgpt.com`,
    /// so only it gets `*.chatgpt.com` (#6195). GitHub's two hosts are named
    /// exactly when the grants bind them ([`binds_github`]).
    #[cfg(feature = "platform")]
    pub(crate) fn interceptable(grants: &AvailableGrants) -> BTreeSet<&'static str> {
        Self::interceptable_when(grants, binds_github(grants))
    }

    /// [`Self::interceptable`], with GitHub's two hosts served exactly when
    /// `github_bound`.
    #[cfg(feature = "platform")]
    fn interceptable_when(grants: &AvailableGrants, github_bound: bool) -> BTreeSet<&'static str> {
        grants
            .grants
            .iter()
            .flat_map(|grant| {
                grant.permissions.iter().flat_map(|permission| {
                    Self::of_route(grant.capability_slot.as_str(), permission.route.as_str())
                })
            })
            .flat_map(move |route_host| {
                let host = route_host.as_str();
                FRONT_DOOR_HOSTS
                    .iter()
                    .filter(move |served| served.host == host)
                    .filter_map(|served| served.leaf_name())
                    .chain((github_bound && GITHUB_HOSTS.contains(&host)).then_some(host))
            })
            .collect()
    }

    /// The host a front-door request on this slot and route names, taken as
    /// it is: a name the egress policy could bind for interception on the
    /// provider port (exact and canonical, so nothing to lowercase or strip;
    /// no pattern, IP literal or protected name), and one of the route's own.
    pub(crate) fn intercepted(slot: &str, route: &str, host: &str) -> Option<Self> {
        let binding = InterceptBinding::new(host, OPENAI_PORT).ok()?;
        if binding.hostname() != host {
            return None;
        }
        Self::of_route(slot, route)
            .iter()
            .copied()
            .find(|route_host| route_host.as_str() == host)
    }
}

/// Whether `grants` bind GitHub's two hosts behind the front door: they
/// grant the `github` slot, and the front door serves GitHub's hosts for a
/// GitHub connection ([`codewire_access::binds_github`]), as orchestration
/// binds them in `cw-egress` from the same selection (#4001). The projected
/// placeholders, the leaves and Git's challenge all follow it.
#[cfg(feature = "platform")]
pub(crate) fn binds_github(grants: &AvailableGrants) -> bool {
    grants
        .grants
        .iter()
        .any(|grant| grant.capability_slot == CapabilitySlot::github())
        && codewire_access::ManagedCredentialClients::from_profile_slots(["github"])
            .is_ok_and(codewire_access::binds_github)
}

fn selected_hosts(
    selected: &BTreeSet<HttpProvider>,
) -> Result<BTreeSet<&'static str>, BrokerUpstreamError> {
    if selected.is_empty() {
        return Err(BrokerUpstreamError::DestinationDenied);
    }
    Ok(selected
        .iter()
        .flat_map(|provider| match provider {
            HttpProvider::OpenAiApiKey => &[OPENAI_HOST][..],
            HttpProvider::CodexOAuth => &[CHATGPT_HOST, OPENAI_AUTH_HOST][..],
            HttpProvider::CodexDeviceEnrollment | HttpProvider::CodexTokenRevocation => {
                &[OPENAI_AUTH_HOST][..]
            }
            HttpProvider::AnthropicApiKey | HttpProvider::AnthropicSubscriptionToken => {
                &[ANTHROPIC_HOST][..]
            }
            // The route, and the token endpoint for the broker's refresh.
            HttpProvider::AnthropicClaudeSignIn => &[ANTHROPIC_HOST, CLAUDE_TOKEN_HOST][..],
            // The code exchange and the one OAuth profile read.
            HttpProvider::ClaudeSignInEnrollment => &[ANTHROPIC_HOST, CLAUDE_TOKEN_HOST][..],
            HttpProvider::GitHubOAuth => &[GITHUB_API_HOST, GITHUB_GIT_HOST][..],
            HttpProvider::GitHubAppAuthorization => &[GITHUB_API_HOST, GITHUB_GIT_HOST][..],
            HttpProvider::GitHubAppTokenRevocation => &[GITHUB_API_HOST][..],
        })
        .copied()
        .collect())
}

fn validate_target(
    target: &url::Url,
    method: &Method,
    selected: &BTreeSet<HttpProvider>,
) -> Result<(), BrokerUpstreamError> {
    let allowed = match target.host_str() {
        Some(OPENAI_HOST) => {
            selected.contains(&HttpProvider::OpenAiApiKey)
                && transparent_method(method)
                && target.path().starts_with(OPENAI_BASE_PATH)
        }
        Some(CHATGPT_HOST) => {
            selected.contains(&HttpProvider::CodexOAuth)
                && transparent_method(method)
                && chatgpt_path(target.path())
        }
        // A sign-in's refresh endpoint is also where its front door forwards
        // the user's own token requests untouched (#6197); no other path of
        // the host is sent for a sign-in.
        Some(OPENAI_AUTH_HOST) => {
            method == Method::POST
                && target.query().is_none()
                && ((selected.contains(&HttpProvider::CodexOAuth)
                    && target.path() == OPENAI_TOKEN_PATH)
                    || (selected.contains(&HttpProvider::CodexDeviceEnrollment)
                        && matches!(
                            target.path(),
                            CODEX_DEVICE_USERCODE_PATH
                                | CODEX_DEVICE_TOKEN_PATH
                                | OPENAI_TOKEN_PATH
                        ))
                    || (selected.contains(&HttpProvider::CodexTokenRevocation)
                        && target.path() == CODEX_TOKEN_REVOCATION_PATH))
        }
        Some(ANTHROPIC_HOST) => {
            ((selected.contains(&HttpProvider::AnthropicApiKey)
                || selected.contains(&HttpProvider::AnthropicSubscriptionToken)
                || selected.contains(&HttpProvider::AnthropicClaudeSignIn))
                && transparent_method(method))
                || (selected.contains(&HttpProvider::ClaudeSignInEnrollment)
                    && method == Method::GET
                    && target.path() == CLAUDE_PROFILE_PATH
                    && target.query().is_none())
        }
        // Claude's token host. For a sign-in, the broker's own refresh and
        // any request its front door forwards untouched, which is what the
        // environment's egress would send without interception; the broker
        // refuses one that carries a Codewire value before it gets here. For
        // an enrollment, the code exchange alone.
        Some(CLAUDE_TOKEN_HOST) => {
            (selected.contains(&HttpProvider::AnthropicClaudeSignIn) && transparent_method(method))
                || (selected.contains(&HttpProvider::ClaudeSignInEnrollment)
                    && method == Method::POST
                    && target.path() == CLAUDE_TOKEN_PATH
                    && target.query().is_none())
        }
        Some(GITHUB_API_HOST) => {
            (selected.contains(&HttpProvider::GitHubOAuth)
                && crate::github::classify_request(
                    "github-api",
                    method,
                    target.path(),
                    target.query(),
                )
                .is_ok())
                || (selected.contains(&HttpProvider::GitHubAppAuthorization)
                    && method == Method::GET
                    && matches!(target.path(), "/user" | "/user/installations")
                    && github_app_query(target.path(), target.query()))
                || (selected.contains(&HttpProvider::GitHubAppTokenRevocation)
                    && method == Method::DELETE
                    && github_app_token_path(target.path())
                    && target.query().is_none())
        }
        Some(GITHUB_GIT_HOST) => {
            (selected.contains(&HttpProvider::GitHubOAuth)
                && crate::github::classify_request(
                    "github-https",
                    method,
                    target.path(),
                    target.query(),
                )
                .is_ok())
                || (selected.contains(&HttpProvider::GitHubAppAuthorization)
                    && method == Method::POST
                    && matches!(
                        target.path(),
                        GITHUB_ACCESS_TOKEN_PATH | GITHUB_DEVICE_CODE_PATH
                    )
                    && target.query().is_none())
        }
        _ => false,
    };
    if target.scheme() != "https"
        || !allowed
        || target.port_or_known_default() != Some(OPENAI_PORT)
        || target.fragment().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return Err(BrokerUpstreamError::DestinationDenied);
    }
    Ok(())
}

/// The destination check for a request forwarded to GitHub untouched: one of
/// GitHub's two route hosts, on a session that selected GitHub, by HTTPS on
/// 443 with a plain method. Any path: the request carries nothing of the
/// broker's, so it is what the environment's own egress would send. Never
/// used for a request that carries leased material, which [`validate_target`]
/// holds to the route's exact grammar.
fn validate_github_forward_target(
    target: &url::Url,
    method: &Method,
    selected: &BTreeSet<HttpProvider>,
) -> Result<(), BrokerUpstreamError> {
    if !matches!(target.host_str(), Some(GITHUB_API_HOST | GITHUB_GIT_HOST))
        || !selected.contains(&HttpProvider::GitHubOAuth)
        || !transparent_method(method)
        || target.scheme() != "https"
        || target.port_or_known_default() != Some(OPENAI_PORT)
        || target.fragment().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return Err(BrokerUpstreamError::DestinationDenied);
    }
    Ok(())
}

/// Whether `host` is canonical and exactly one label under one of
/// [`ROUTED_SUFFIXES`] (#6195): `a.chatgpt.com`, never `chatgpt.com`,
/// `a.b.chatgpt.com` or `xchatgpt.com`.
pub(crate) fn routed_host(host: &str) -> bool {
    let canonical =
        InterceptBinding::new(host, OPENAI_PORT).is_ok_and(|binding| binding.hostname() == host);
    canonical && codewire_access::routed_suffix(host).is_some()
}

/// The only path served at a routed origin: Codex's model path.
pub(crate) fn routed_path(path: &str) -> bool {
    path.starts_with(CHATGPT_CODEX_BASE_PATH)
}

/// `address` on the provider port, if the provider transport would ever dial
/// it: the one check every pinned dial passes, the broker's own, whatever
/// process named the address (#3999).
pub(crate) fn admit_pinned(address: IpAddr) -> Result<SocketAddr, BrokerUpstreamError> {
    let admitted = admit_resolved_addresses([SocketAddr::new(address, OPENAI_PORT)])?;
    admitted
        .into_iter()
        .next()
        .ok_or(BrokerUpstreamError::DestinationDenied)
}

/// The destination check for a request dialled at a pinned address: only a
/// routed origin under [`ROUTED_SUFFIXES`] on Codex's model path, for a Codex
/// sign-in. A pin means routed; a bound host is never dialled at an address
/// a request named, so anything else is refused, not handed to
/// [`validate_target`] (#3999).
fn validate_pinned_target(
    target: &url::Url,
    method: &Method,
    selected: &BTreeSet<HttpProvider>,
) -> Result<(), BrokerUpstreamError> {
    let routed = target.host_str().is_some_and(routed_host)
        && selected.contains(&HttpProvider::CodexOAuth)
        && transparent_method(method)
        && routed_path(target.path())
        && target.scheme() == "https"
        && target.port_or_known_default() == Some(OPENAI_PORT)
        && target.fragment().is_none()
        && target.username().is_empty()
        && target.password().is_none();
    if routed {
        Ok(())
    } else {
        Err(BrokerUpstreamError::DestinationDenied)
    }
}

/// A `chatgpt.com` path a Codex request may reach: under Codex's base, or
/// one of the front door's wider paths.
pub(crate) fn chatgpt_path(path: &str) -> bool {
    CHATGPT_FRONT_DOOR_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
        || CHATGPT_FRONT_DOOR_PATHS.contains(&path)
}

/// Transparent provider routes carry any CRUD request on their pinned host.
fn transparent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// `/applications/{client_id}/token`, GitHub's revocation of one App
/// user's token, for a client id of the characters GitHub issues.
fn github_app_token_path(path: &str) -> bool {
    path.strip_prefix("/applications/")
        .and_then(|rest| rest.strip_suffix("/token"))
        .is_some_and(|client_id| {
            !client_id.is_empty()
                && client_id.len() <= 64
                && client_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        })
}

fn github_app_query(path: &str, query: Option<&str>) -> bool {
    match path {
        "/user" => query.is_none(),
        "/user/installations" => query.is_some_and(|query| {
            let mut pairs = url::form_urlencoded::parse(query.as_bytes());
            matches!(
                (pairs.next(), pairs.next(), pairs.next()),
                (Some((per_page, size)), Some((page, number)), None)
                    if per_page == "per_page"
                        && size == "100"
                        && page == "page"
                        && number.parse::<u32>().is_ok_and(|page| (1..=10).contains(&page))
            )
        }),
        _ => false,
    }
}

fn admit_resolved_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, BrokerUpstreamError> {
    let mut admitted = BTreeSet::new();
    for address in addresses {
        if address.port() != OPENAI_PORT || !public_provider_ip(address.ip()) {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        admitted.insert(address);
        if admitted.len() > MAX_RESOLVED_ADDRESSES {
            return Err(BrokerUpstreamError::ResourceLimit);
        }
    }
    if admitted.is_empty() {
        return Err(BrokerUpstreamError::Connect);
    }
    Ok(admitted.into_iter().collect())
}

fn public_provider_ip(address: IpAddr) -> bool {
    // Keep the shared AV classification as the minimum policy, then apply the
    // provider transport's narrower special-purpose exclusions below. In
    // particular, an IPv6 transition address is not admitted merely because
    // it embeds a public IPv4 address.
    if !tunnel_ip_allowed(address, false) {
        return false;
    }
    match address {
        IpAddr::V4(address) => public_ipv4(address),
        IpAddr::V6(address) => match address.to_ipv4() {
            Some(address) => public_ipv4(address),
            None => public_ipv6(address),
        },
    }
}

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let first = segments[0];
    let nat64_well_known =
        first == 0x0064 && segments[1] == 0xff9b && segments[2..6].iter().all(|value| *value == 0);
    if nat64_well_known {
        return public_ipv4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
        || first & 0xff00 == 0xff00
        || (first == 0x0100 && segments[1..4].iter().all(|value| *value == 0))
        || (first == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
        || (first == 0x2001 && segments[1] == 0x0000)
        || (first == 0x2001 && segments[1] == 0x0002)
        || (first == 0x2001 && segments[1] == 0x0db8)
        || (first == 0x2001 && (segments[1] & 0xfff0 == 0x0010))
        || (first == 0x2001 && (segments[1] & 0xfff0 == 0x0020))
        || first == 0x2002)
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), BrokerUpstreamError> {
    let bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
    });
    if bytes.is_none_or(|bytes| bytes > MAX_RESPONSE_HEADER_BYTES) {
        return Err(BrokerUpstreamError::ResourceLimit);
    }
    validate_transfer_coding(headers)?;
    crate::openai::validate_response_encoding(headers).map_err(|_| BrokerUpstreamError::Protocol)
}

/// The broker redacts identity bytes, so HTTP/1.1 framing may only be
/// `chunked`. The client removes chunked framing but would pass any other
/// transfer coding through as body bytes, past the content-coding admission.
/// HTTP/2 responses have no transfer codings.
fn validate_transfer_coding(headers: &HeaderMap) -> Result<(), BrokerUpstreamError> {
    let mut values = headers.get_all(http::header::TRANSFER_ENCODING).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(()),
        (Some(value), None)
            if value
                .as_bytes()
                .trim_ascii()
                .eq_ignore_ascii_case(b"chunked") =>
        {
            Ok(())
        }
        _ => Err(BrokerUpstreamError::Protocol),
    }
}

fn map_reqwest_error(error: reqwest::Error) -> BrokerUpstreamError {
    if error.is_timeout() || error.is_connect() {
        BrokerUpstreamError::Connect
    } else if error.is_builder() {
        BrokerUpstreamError::DestinationDenied
    } else {
        BrokerUpstreamError::Protocol
    }
}

mod log_redirect;

#[cfg(test)]
#[path = "network/upgrade_tests.rs"]
mod upgrade_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "platform")]
    fn grants(pairs: &[(&str, &str)]) -> AvailableGrants {
        use codewire_access::{
            BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId, DerivedGrant,
            EnvironmentId, GrantPermission,
        };
        AvailableGrants {
            grants: pairs
                .iter()
                .map(|(slot, route)| DerivedGrant {
                    environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                    environment_generation: 3,
                    profile: None,
                    capability_slot: CapabilitySlot::parse(*slot).unwrap(),
                    credential_id: CredentialId::parse("11111111-1111-4111-8111-111111111111")
                        .unwrap(),
                    credential_revocation_generation: 7,
                    expires_at_unix: None,
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("responses").unwrap(),
                        route: BrokerRouteId::parse(*route).unwrap(),
                    }]),
                })
                .collect(),
            reconnect_required: Default::default(),
            ungranted_github: codewire_access::UngrantedGitHub::None,
        }
    }

    #[cfg(feature = "platform")]
    #[test]
    fn leaves_name_only_front_door_hosts_the_sessions_grants_reach() {
        assert!(RouteHost::interceptable(&grants(&[])).is_empty());
        assert_eq!(
            RouteHost::interceptable(&grants(&[("anthropic", "anthropic-api")])),
            BTreeSet::from(["api.anthropic.com"])
        );
        assert_eq!(
            RouteHost::interceptable(&grants(&[("codex", "openai-api")])),
            BTreeSet::from([
                "*.chatgpt.com",
                "api.openai.com",
                "auth.openai.com",
                "chatgpt.com"
            ])
        );
        assert_eq!(
            RouteHost::interceptable(&grants(&[("openai", "openai-api")])),
            BTreeSet::from(["api.openai.com"])
        );
        // GitHub's hosts are a route's, but the front door serves them only
        // while they are bound.
        let github = grants(&[
            ("github", "github-api"),
            ("github", "github-https"),
            ("ssh", "ssh-agent"),
        ]);
        assert!(binds_github(&github));
        assert!(RouteHost::interceptable_when(&github, false).is_empty());
        assert_eq!(
            RouteHost::interceptable(&github),
            BTreeSet::from(["api.github.com", "github.com"])
        );
    }

    /// Bound, GitHub's two hosts get leaves exactly as far as the grants'
    /// routes reach them, beside the other hosts; and only grants of the
    /// `github` slot bind them (#4001).
    #[cfg(feature = "platform")]
    #[test]
    fn leaves_name_githubs_hosts_only_while_they_are_bound() {
        let both = grants(&[
            ("anthropic", "anthropic-api"),
            ("github", "github-api"),
            ("github", "github-https"),
        ]);
        assert_eq!(
            RouteHost::interceptable_when(&both, true),
            BTreeSet::from(["api.anthropic.com", "api.github.com", "github.com"])
        );
        assert_eq!(
            RouteHost::interceptable_when(&both, false),
            BTreeSet::from(["api.anthropic.com"])
        );
        assert_eq!(
            RouteHost::interceptable_when(&grants(&[("github", "github-https")]), true),
            BTreeSet::from(["github.com"])
        );
        // Bound or not, a grant that reaches no GitHub host gets none.
        let codex = grants(&[("codex", "openai-api")]);
        let bound = RouteHost::interceptable_when(&codex, true);
        assert_eq!(bound, RouteHost::interceptable_when(&codex, false));
        assert!(GITHUB_HOSTS.iter().all(|host| !bound.contains(host)));
        assert!(!binds_github(&grants(&[("anthropic", "anthropic-api")])));
        assert!(!binds_github(&grants(&[])));
    }

    /// `DestinationDenied` means nothing was sent (#3999): a request-builder
    /// error maps to it, and an error from sending never does.
    #[tokio::test]
    async fn only_an_unsent_request_is_destination_denied() {
        let client = reqwest::Client::new();
        let unbuilt = client.get("not a url").send().await.unwrap_err();
        assert!(unbuilt.is_builder());
        assert_eq!(
            map_reqwest_error(unbuilt),
            BrokerUpstreamError::DestinationDenied
        );
        // Nothing listens on the discard port: the connect is refused.
        let refused = client.get("http://127.0.0.1:9/").send().await.unwrap_err();
        assert!(!refused.is_builder());
        assert_ne!(
            map_reqwest_error(refused),
            BrokerUpstreamError::DestinationDenied
        );
    }

    /// A request forwarded to GitHub untouched may name any path of the two
    /// route hosts, and nothing else; the check for a request that carries
    /// leased material still holds it to the route's grammar (#3999).
    #[test]
    fn a_forward_to_github_reaches_only_its_two_hosts_and_the_exact_check_stays() {
        let github = BTreeSet::from([HttpProvider::GitHubOAuth]);
        let url = |text: &str| url::Url::parse(text).unwrap();
        for target in [
            "https://api.github.com/rate_limit",
            "https://api.github.com/search/code?q=a%20b",
            "https://github.com/owner/repo.git/info/lfs/objects/batch",
            "https://github.com/owner/repo/releases/download/v1/a.tar.gz",
        ] {
            for method in [Method::GET, Method::POST, Method::DELETE] {
                assert_eq!(
                    validate_github_forward_target(&url(target), &method, &github),
                    Ok(()),
                    "{method} {target}"
                );
            }
            // The same destination with leased material is still refused.
            assert_eq!(
                validate_target(&url(target), &Method::GET, &github),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        for (target, method, selected) in [
            ("https://api.github.com/user", Method::CONNECT, &github),
            ("https://api.github.com/user", Method::OPTIONS, &github),
            ("http://api.github.com/user", Method::GET, &github),
            ("https://api.github.com:8443/user", Method::GET, &github),
            ("https://user@api.github.com/user", Method::GET, &github),
            ("https://api.github.com/user#fragment", Method::GET, &github),
            ("https://uploads.github.com/x", Method::GET, &github),
            ("https://codeload.github.com/x", Method::GET, &github),
            ("https://github.com.example.com/x", Method::GET, &github),
            (
                "https://api.anthropic.com/v1/messages",
                Method::GET,
                &github,
            ),
            (
                "https://api.github.com/user",
                Method::GET,
                &BTreeSet::from([HttpProvider::AnthropicApiKey]),
            ),
            (
                "https://api.github.com/user",
                Method::GET,
                &BTreeSet::from([HttpProvider::GitHubAppAuthorization]),
            ),
        ] {
            assert_eq!(
                validate_github_forward_target(&url(target), &method, selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{method} {target}"
            );
        }
    }

    #[test]
    fn selected_http_hosts_are_closed_and_empty_selection_never_resolves() {
        assert_eq!(
            selected_hosts(&BTreeSet::new()),
            Err(BrokerUpstreamError::DestinationDenied)
        );
        assert_eq!(
            selected_hosts(&BTreeSet::from([HttpProvider::AnthropicApiKey])).unwrap(),
            BTreeSet::from(["api.anthropic.com"])
        );
        assert_eq!(
            selected_hosts(&BTreeSet::from([
                HttpProvider::OpenAiApiKey,
                HttpProvider::CodexOAuth,
                HttpProvider::AnthropicApiKey,
                HttpProvider::GitHubOAuth
            ]))
            .unwrap(),
            BTreeSet::from([
                "api.openai.com",
                "chatgpt.com",
                "auth.openai.com",
                "api.anthropic.com",
                "api.github.com",
                "github.com"
            ])
        );
    }

    #[test]
    fn multi_provider_destination_policy_pins_selected_hosts_and_github_routes() {
        let selected = BTreeSet::from([
            HttpProvider::OpenAiApiKey,
            HttpProvider::AnthropicApiKey,
            HttpProvider::GitHubOAuth,
        ]);
        for (method, target) in [
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages?beta=true",
            ),
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages/count_tokens",
            ),
            // The Anthropic route is transparent on its pinned host.
            (Method::GET, "https://api.anthropic.com/v1/messages"),
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages?beta=false",
            ),
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages/batches",
            ),
            (Method::GET, "https://api.openai.com/v1/models?limit=1"),
            (
                Method::GET,
                "https://api.github.com/repos/owner/repo/issues?page=2",
            ),
            (Method::POST, "https://api.github.com/graphql"),
            (
                Method::GET,
                "https://github.com/owner/repo.git/info/refs?service=git-upload-pack",
            ),
            (
                Method::POST,
                "https://github.com/owner/repo.git/git-receive-pack",
            ),
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected).is_ok(),
                "{target}"
            );
        }
        for (method, target) in [
            (Method::POST, "https://auth.openai.com/oauth/token"),
            (Method::OPTIONS, "https://api.anthropic.com/v1/messages"),
            (Method::GET, "https://api.openai.com/v2/models"),
            (Method::GET, "https://chatgpt.com/backend-api/codex/models"),
            (
                Method::GET,
                "https://api.github.com/repos/owner/repo/actions",
            ),
            (
                Method::GET,
                "https://api.github.com/user?url=https://evil.test",
            ),
            (Method::POST, "https://github.com/owner/repo.git/info/lfs"),
            (
                Method::GET,
                "https://github.com/owner/repo.git/info/refs?service=git-upload-archive",
            ),
            (Method::GET, "https://api.github.com.evil.test/user"),
            (Method::GET, "https://user:password@api.github.com/user"),
            (Method::GET, "https://api.github.com:444/user"),
            (Method::GET, "http://api.github.com/user"),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
    }

    #[test]
    fn claude_subscription_token_transport_reaches_only_the_anthropic_api_host() {
        let selected = BTreeSet::from([HttpProvider::AnthropicSubscriptionToken]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["api.anthropic.com"])
        );
        for (method, target) in [
            (Method::POST, "https://api.anthropic.com/v1/messages"),
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages?beta=true",
            ),
            (Method::GET, "https://api.anthropic.com/v1/messages"),
            (Method::GET, "https://api.anthropic.com/api/oauth/usage"),
            (Method::GET, "https://api.anthropic.com/v1/models"),
            (Method::DELETE, "https://api.anthropic.com/v1/files/file_x"),
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected).is_ok(),
                "{target}"
            );
        }
        for (method, target) in [
            (Method::OPTIONS, "https://api.anthropic.com/v1/messages"),
            (Method::POST, "https://console.anthropic.com/v1/oauth/token"),
            (Method::POST, "http://api.anthropic.com/v1/messages"),
            (Method::POST, "https://api.anthropic.com:444/v1/messages"),
            (Method::POST, "https://user@api.anthropic.com/v1/messages"),
            (Method::POST, "https://api.openai.com/v1/responses"),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
    }

    #[test]
    fn claude_sign_in_transport_adds_only_claudes_token_host() {
        let selected = BTreeSet::from([HttpProvider::AnthropicClaudeSignIn]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["api.anthropic.com", "platform.claude.com"])
        );
        // Every CRUD request on Claude's token host: the broker's refresh and
        // the front door's untouched forwards.
        for (method, target) in [
            (Method::POST, "https://api.anthropic.com/v1/messages"),
            (Method::GET, "https://api.anthropic.com/api/oauth/usage"),
            (Method::POST, "https://platform.claude.com/v1/oauth/token"),
            (Method::GET, "https://platform.claude.com/v1/oauth/token"),
            (
                Method::POST,
                "https://platform.claude.com/v1/oauth/token?next=1",
            ),
            (Method::POST, "https://platform.claude.com/v1/oauth/revoke"),
            (
                Method::DELETE,
                "https://platform.claude.com/oauth/authorize",
            ),
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected).is_ok(),
                "{target}"
            );
        }
        for (method, target) in [
            (
                Method::OPTIONS,
                "https://platform.claude.com/v1/oauth/token",
            ),
            (Method::POST, "https://claude.com/cai/oauth/authorize"),
            (
                Method::POST,
                "https://platform.claude.com:444/v1/oauth/token",
            ),
            (Method::POST, "http://platform.claude.com/v1/oauth/token"),
            (Method::OPTIONS, "https://api.anthropic.com/v1/messages"),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        // The other Anthropic forms never reach Claude's token endpoint.
        for provider in [
            HttpProvider::AnthropicApiKey,
            HttpProvider::AnthropicSubscriptionToken,
        ] {
            assert_eq!(
                validate_target(
                    &url::Url::parse("https://platform.claude.com/v1/oauth/token").unwrap(),
                    &Method::POST,
                    &BTreeSet::from([provider]),
                ),
                Err(BrokerUpstreamError::DestinationDenied)
            );
        }
    }

    #[test]
    fn claude_sign_in_enrollment_transport_has_only_the_exchange_and_profile_read() {
        let selected = BTreeSet::from([HttpProvider::ClaudeSignInEnrollment]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["api.anthropic.com", "platform.claude.com"])
        );
        for (method, target) in [
            (Method::POST, "https://platform.claude.com/v1/oauth/token"),
            (Method::GET, "https://api.anthropic.com/api/oauth/profile"),
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected).is_ok(),
                "{target}"
            );
        }
        for (method, target) in [
            (Method::POST, "https://api.anthropic.com/v1/messages"),
            (Method::GET, "https://api.anthropic.com/api/oauth/usage"),
            (Method::POST, "https://api.anthropic.com/api/oauth/profile"),
            (
                Method::GET,
                "https://api.anthropic.com/api/oauth/profile?account=x",
            ),
            (Method::GET, "https://platform.claude.com/v1/oauth/token"),
            (Method::POST, "https://auth.openai.com/oauth/token"),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
    }

    #[test]
    fn github_app_authorization_transport_has_only_exchange_and_identity_routes() {
        let selected = BTreeSet::from([HttpProvider::GitHubAppAuthorization]);
        for (method, target) in [
            (Method::POST, "https://github.com/login/oauth/access_token"),
            (Method::POST, "https://github.com/login/device/code"),
            (Method::GET, "https://api.github.com/user"),
            (
                Method::GET,
                "https://api.github.com/user/installations?per_page=100&page=1",
            ),
            (
                Method::GET,
                "https://api.github.com/user/installations?per_page=100&page=10",
            ),
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected).is_ok(),
                "{target}"
            );
        }
        for (method, target) in [
            (Method::GET, "https://github.com/login/oauth/access_token"),
            (Method::GET, "https://github.com/login/device/code"),
            (
                Method::POST,
                "https://github.com/login/device/code?scope=repo",
            ),
            (Method::POST, "https://github.com/login/device"),
            (Method::POST, "https://api.github.com/user"),
            (
                Method::GET,
                "https://api.github.com/user/installations?page=1&per_page=100",
            ),
            (
                Method::GET,
                "https://api.github.com/user/installations?per_page=99&page=1",
            ),
            (
                Method::GET,
                "https://api.github.com/user/installations?per_page=100&page=11",
            ),
            (Method::GET, "https://api.github.com/user/repos"),
            (Method::GET, "https://api.github.com/repos/owner/repo"),
            (
                Method::GET,
                "https://github.com/owner/repo.git/info/refs?service=git-upload-pack",
            ),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
    }

    #[test]
    fn codex_device_enrollment_transport_has_only_device_login_routes() {
        let selected = BTreeSet::from([HttpProvider::CodexDeviceEnrollment]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["auth.openai.com"])
        );
        for target in [
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            "https://auth.openai.com/api/accounts/deviceauth/token",
            "https://auth.openai.com/oauth/token",
        ] {
            assert!(
                validate_target(&url::Url::parse(target).unwrap(), &Method::POST, &selected)
                    .is_ok(),
                "{target}"
            );
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &Method::GET, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        for target in [
            "https://auth.openai.com/api/accounts/deviceauth/usercode?next=evil",
            "https://auth.openai.com/api/accounts/deviceauth/other",
            "https://auth.openai.com/codex/device",
            "https://auth.openai.com/oauth/revoke",
            "https://chatgpt.com/backend-api/codex/responses",
            "https://api.openai.com/v1/responses",
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &Method::POST, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        // The Codex bridge family keeps refresh only, not the device login.
        assert_eq!(
            validate_target(
                &url::Url::parse("https://auth.openai.com/api/accounts/deviceauth/usercode")
                    .unwrap(),
                &Method::POST,
                &BTreeSet::from([HttpProvider::CodexOAuth]),
            ),
            Err(BrokerUpstreamError::DestinationDenied)
        );
    }

    use crate::openai::response_admission_test_cases::{accepted_encodings, denied_encodings};

    #[test]
    fn response_admission_transport_rejects_nonidentity_or_ambiguous_encoding() {
        for headers in denied_encodings() {
            assert_eq!(
                validate_response_headers(&headers),
                Err(BrokerUpstreamError::Protocol),
                "{headers:?}"
            );
        }
    }

    #[test]
    fn response_admission_transport_accepts_absent_or_single_identity_encoding() {
        for headers in accepted_encodings() {
            assert_eq!(validate_response_headers(&headers), Ok(()), "{headers:?}");
        }
    }

    #[test]
    fn codex_token_revocation_transport_has_only_the_revocation_route() {
        let selected = BTreeSet::from([HttpProvider::CodexTokenRevocation]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["auth.openai.com"])
        );
        let revoke = url::Url::parse("https://auth.openai.com/api/accounts/oauth/revoke").unwrap();
        assert!(validate_target(&revoke, &Method::POST, &selected).is_ok());
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            assert_eq!(
                validate_target(&revoke, &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{method}"
            );
        }
        for target in [
            "https://auth.openai.com/api/accounts/oauth/revoke?token=synthetic",
            "https://auth.openai.com/api/accounts/oauth/revoke#fragment",
            "https://auth.openai.com/api/accounts/oauth/revoke/",
            "https://auth.openai.com/oauth/revoke",
            "https://auth.openai.com/oauth/token",
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            "http://auth.openai.com/api/accounts/oauth/revoke",
            "https://auth.openai.com:8443/api/accounts/oauth/revoke",
            "https://chatgpt.com/backend-api/codex/responses",
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &Method::POST, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        // The Codex bridge's refresh and the device login never reach it.
        for other in [
            HttpProvider::CodexOAuth,
            HttpProvider::CodexDeviceEnrollment,
        ] {
            assert_eq!(
                validate_target(&revoke, &Method::POST, &BTreeSet::from([other])),
                Err(BrokerUpstreamError::DestinationDenied),
                "{other:?}"
            );
        }
    }

    #[test]
    fn the_guest_families_reach_neither_revocation_route() {
        // Every family a Sandbox profile can select: the platform bridge's set.
        let guest = BTreeSet::from([
            HttpProvider::OpenAiApiKey,
            HttpProvider::CodexOAuth,
            HttpProvider::AnthropicApiKey,
            HttpProvider::AnthropicSubscriptionToken,
            HttpProvider::AnthropicClaudeSignIn,
            HttpProvider::GitHubOAuth,
        ]);
        for (method, target) in [
            (
                Method::POST,
                "https://auth.openai.com/api/accounts/oauth/revoke",
            ),
            (
                Method::DELETE,
                "https://api.github.com/applications/Iv23lif1VpZftJWtcQCL/token",
            ),
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(target).unwrap(), &method, &guest),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
    }

    #[test]
    fn github_app_token_revocation_transport_has_only_the_revocation_route() {
        let selected = BTreeSet::from([HttpProvider::GitHubAppTokenRevocation]);
        assert_eq!(
            selected_hosts(&selected).unwrap(),
            BTreeSet::from(["api.github.com"])
        );
        let revoke =
            url::Url::parse("https://api.github.com/applications/Iv23lif1VpZftJWtcQCL/token")
                .unwrap();
        assert!(validate_target(&revoke, &Method::DELETE, &selected).is_ok());
        for method in [Method::GET, Method::POST, Method::PATCH] {
            assert_eq!(
                validate_target(&revoke, &method, &selected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{method}"
            );
        }
        for target in [
            "https://api.github.com/applications/Iv23lif1VpZftJWtcQCL/token?page=1",
            "https://api.github.com/applications/Iv23lif1VpZftJWtcQCL/grant",
            "https://api.github.com/applications/Iv23lif1VpZftJWtcQCL/token/",
            "https://api.github.com/applications//token",
            "https://api.github.com/applications/a%2Fb/token",
            "https://api.github.com/user",
            "https://github.com/applications/Iv23lif1VpZftJWtcQCL/token",
        ] {
            assert_eq!(
                validate_target(
                    &url::Url::parse(target).unwrap(),
                    &Method::DELETE,
                    &selected
                ),
                Err(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        // Neither the agent's GitHub route nor the App's sign-in reaches it.
        for other in [
            HttpProvider::GitHubOAuth,
            HttpProvider::GitHubAppAuthorization,
        ] {
            assert_eq!(
                validate_target(&revoke, &Method::DELETE, &BTreeSet::from([other])),
                Err(BrokerUpstreamError::DestinationDenied),
                "{other:?}"
            );
        }
    }

    #[test]
    fn destination_is_pinned_and_never_redirectable() {
        assert!(
            validate_target(
                &url::Url::parse("https://api.openai.com/v1/responses").unwrap(),
                &Method::POST,
                &BTreeSet::from([HttpProvider::OpenAiApiKey]),
            )
            .is_ok()
        );
        assert!(
            validate_target(
                &url::Url::parse("https://chatgpt.com/backend-api/codex/responses").unwrap(),
                &Method::POST,
                &BTreeSet::from([HttpProvider::CodexOAuth]),
            )
            .is_ok()
        );
        assert!(
            validate_target(
                &url::Url::parse("https://auth.openai.com/oauth/token").unwrap(),
                &Method::POST,
                &BTreeSet::from([HttpProvider::CodexOAuth]),
            )
            .is_ok()
        );
        // Only the token endpoint: the front door's untouched forward of any
        // other path of the token host, the sign-in page among them, is
        // never sent (#6197).
        assert_eq!(
            validate_target(
                &url::Url::parse("https://auth.openai.com/oauth/authorize?response_type=code")
                    .unwrap(),
                &Method::GET,
                &BTreeSet::from([HttpProvider::CodexOAuth]),
            ),
            Err(BrokerUpstreamError::DestinationDenied)
        );
        for allowed in [
            "https://api.openai.com/v1/responses?stream=true",
            "https://api.openai.com/v1/models",
        ] {
            assert!(
                validate_target(
                    &url::Url::parse(allowed).unwrap(),
                    &Method::POST,
                    &BTreeSet::from([HttpProvider::OpenAiApiKey]),
                )
                .is_ok(),
                "{allowed}"
            );
        }
        for denied in [
            "http://api.openai.com/v1/responses",
            "https://api.openai.com.evil.test/v1/responses",
            "https://api.openai.com/v2/responses",
            "https://user@api.openai.com/v1/responses",
            "https://api.openai.com:444/v1/responses",
        ] {
            assert_eq!(
                validate_target(
                    &url::Url::parse(denied).unwrap(),
                    &Method::POST,
                    &BTreeSet::from([HttpProvider::OpenAiApiKey]),
                ),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
        assert!(
            validate_target(
                &url::Url::parse("https://chatgpt.com/backend-api/codex/models?x=1").unwrap(),
                &Method::GET,
                &BTreeSet::from([HttpProvider::CodexOAuth]),
            )
            .is_ok()
        );
        for allowed in [
            "https://chatgpt.com/backend-api/wham/usage",
            "https://chatgpt.com/backend-api/wham/accounts/check",
            "https://chatgpt.com/backend-api/plugins/featured?platform=codex",
            "https://chatgpt.com/backend-api/ps/mcp",
            "https://chatgpt.com/backend-api/accounts/verified_access",
        ] {
            assert!(
                validate_target(
                    &url::Url::parse(allowed).unwrap(),
                    &Method::GET,
                    &BTreeSet::from([HttpProvider::CodexOAuth]),
                )
                .is_ok(),
                "{allowed}"
            );
        }
        for denied in [
            "https://api.openai.com/v1/responses",
            "https://chatgpt.com/backend-api/other",
            "https://chatgpt.com/backend-api/conversation",
            "https://chatgpt.com/backend-api/wham",
            "https://chatgpt.com/backend-api/accounts/verified_access/x",
            "https://chatgpt.com/backend-api/accounts/check",
            "https://chatgpt.com/backend-api/codex/../conversation",
            "https://chatgpt.com/backend-api/codex/%2e%2e/conversation",
            "https://chatgpt.com/backend-api/codex/%2E%2E/conversation",
            "https://chatgpt.com/wham/usage",
            "https://chatgpt.com/",
            "https://auth.openai.com/oauth/revoke",
            "https://user@auth.openai.com/oauth/token",
        ] {
            assert_eq!(
                validate_target(
                    &url::Url::parse(denied).unwrap(),
                    &Method::POST,
                    &BTreeSet::from([HttpProvider::CodexOAuth])
                ),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
    }

    #[test]
    fn resolver_fails_closed_on_any_non_public_or_oversized_answer_set() {
        for denied in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::192.168.0.1",
            "::ffff:127.0.0.1",
            "100::1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let address = denied.parse::<IpAddr>().unwrap();
            assert!(!public_provider_ip(address), "{denied}");
            assert_eq!(
                admit_resolved_addresses([SocketAddr::new(address, OPENAI_PORT)]),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
        for admitted in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_provider_ip(admitted.parse().unwrap()), "{admitted}");
        }
        let too_many = (1..=17)
            .map(|last| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, last)), OPENAI_PORT));
        assert_eq!(
            admit_resolved_addresses(too_many),
            Err(BrokerUpstreamError::ResourceLimit)
        );
    }

    #[test]
    fn response_admission_transport_admits_only_chunked_framing() {
        for value in ["chunked", "Chunked", " chunked\t"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::TRANSFER_ENCODING,
                http::HeaderValue::from_static(value),
            );
            assert_eq!(validate_response_headers(&headers), Ok(()), "{value:?}");
        }
        for values in [
            &["gzip"][..],
            &["gzip, chunked"],
            &["chunked, chunked"],
            &["identity"],
            &["chunked", "chunked"],
            &[""],
        ] {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(
                    http::header::TRANSFER_ENCODING,
                    http::HeaderValue::from_static(value),
                );
            }
            assert_eq!(
                validate_response_headers(&headers),
                Err(BrokerUpstreamError::Protocol),
                "{values:?}"
            );
        }
    }

    fn public(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, last)), OPENAI_PORT)
    }

    /// A broker starts whatever resolves (#5286): a host whose lookup fails,
    /// or gives an address this transport will not dial, is left unresolved
    /// and the others are pinned. Its slot is unserved, and a request to it
    /// is refused as a connection failure before the HTTP client, which
    /// would look the name up itself, sees it.
    #[tokio::test]
    async fn resolution_for_a_start_leaves_a_failed_host_unresolved_and_serves_the_rest() {
        let selected = BTreeSet::from([
            HttpProvider::OpenAiApiKey,
            HttpProvider::AnthropicApiKey,
            HttpProvider::GitHubOAuth,
        ]);
        let looked_up = ProviderHttpsTransport::look_up_with(&[&selected], |host, _| match host {
            ANTHROPIC_HOST => Err(std::io::ErrorKind::TimedOut.into()),
            GITHUB_GIT_HOST => Ok(vec![SocketAddr::from(([10, 0, 0, 1], OPENAI_PORT))]),
            _ => Ok(vec![public(1)]),
        })
        .unwrap();
        let transport = ProviderHttpsTransport::available(&selected, &looked_up).unwrap();
        assert_eq!(
            transport.unresolved_hosts().collect::<Vec<_>>(),
            [ANTHROPIC_HOST, GITHUB_GIT_HOST]
        );
        assert_eq!(transport.resolved_address_count, 2);
        assert_eq!(transport.reuse, ConnectionReuse::PerRequest);
        assert!(transport.slot_unserved("anthropic"));
        assert!(transport.slot_unserved("github"));
        assert!(!transport.slot_unserved("openai"));
        assert!(!transport.slot_unserved("ssh"));

        // Refused at once: sending it would mean a lookup by the HTTP client.
        let refused = tokio::time::timeout(
            Duration::from_secs(1),
            transport.execute(BrokerUpstreamRequest::new(
                Method::POST,
                url::Url::parse("https://api.anthropic.com/v1/messages").unwrap(),
                HeaderMap::new(),
                Vec::new(),
            )),
        )
        .await
        .expect("refused without a lookup");
        assert_eq!(refused.err(), Some(BrokerUpstreamError::Connect));

        // Every host resolving leaves none, as the strict resolution does.
        let all = ProviderHttpsTransport::available(
            &selected,
            &ProviderHttpsTransport::look_up_with(&[&selected], |_, _| Ok(vec![public(1)]))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(all.unresolved_hosts().count(), 0);
        assert!(!all.slot_unserved("anthropic"));
        // The strict resolution, which sign-in commands and the hosted
        // credential service use, still fails on the first host that does
        // not resolve.
        assert_eq!(
            ProviderHttpsTransport::resolve_with(&selected, ConnectionReuse::PerRequest, |_, _| {
                Err(std::io::ErrorKind::TimedOut.into())
            })
            .err(),
            Some(BrokerUpstreamError::Connect)
        );
    }

    /// A broker with GitHub selected builds two transports that share
    /// GitHub's hosts, its own and the App's refresh. One start looks each
    /// host up once for both, all at the same time: with every lookup timing
    /// out, as on a host that is offline altogether, the start waits one
    /// timeout, not one a host or one a transport.
    #[test]
    fn one_start_looks_each_host_up_once_and_all_at_once_for_every_transport() {
        let main = BTreeSet::from([
            HttpProvider::GitHubOAuth,
            HttpProvider::AnthropicClaudeSignIn,
        ]);
        let app = BTreeSet::from([HttpProvider::GitHubAppAuthorization]);
        // GitHub's log hosts are looked up with them (#5737).
        let mut hosts = [
            ANTHROPIC_HOST,
            CLAUDE_TOKEN_HOST,
            GITHUB_API_HOST,
            GITHUB_GIT_HOST,
        ]
        .into_iter()
        .chain(crate::github::log_hosts::log_hosts())
        .collect::<Vec<_>>();
        hosts.sort();
        let asked = std::sync::Mutex::new(Vec::new());
        // A lookup answers only once every host's lookup has begun, so the
        // proof is that they overlap, however slowly a loaded machine runs
        // them. One left waiting alone gives up and is counted.
        let all_begun = std::sync::Condvar::new();
        let waited_alone = std::sync::atomic::AtomicUsize::new(0);
        let looked_up = ProviderHttpsTransport::look_up_with(&[&main, &app], |host, _| {
            let mut asked = asked.lock().unwrap();
            asked.push(host.to_owned());
            all_begun.notify_all();
            let (_asked, wait) = all_begun
                .wait_timeout_while(asked, Duration::from_secs(30), |asked| {
                    asked.len() < hosts.len()
                })
                .unwrap();
            if wait.timed_out() {
                waited_alone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(std::io::ErrorKind::TimedOut.into())
        })
        .unwrap();
        assert_eq!(
            waited_alone.into_inner(),
            0,
            "the lookups did not all run at the same time"
        );
        let mut asked = asked.into_inner().unwrap();
        asked.sort();
        assert_eq!(asked, hosts);
        for selected in [&main, &app] {
            let transport = ProviderHttpsTransport::available(selected, &looked_up).unwrap();
            assert!(transport.slot_unserved("github"));
            assert_eq!(transport.resolved_address_count, 0);
        }
        // A selection these lookups did not cover builds no transport.
        assert_eq!(
            ProviderHttpsTransport::available(
                &BTreeSet::from([HttpProvider::OpenAiApiKey]),
                &looked_up
            )
            .err(),
            Some(BrokerUpstreamError::DestinationDenied)
        );
    }

    #[test]
    fn pooled_resolution_admits_and_pins_exactly_like_per_request_resolution() {
        let openai = BTreeSet::from([HttpProvider::OpenAiApiKey]);
        for reuse in [ConnectionReuse::PerRequest, ConnectionReuse::Pooled] {
            // No selection never reaches the resolver.
            assert_eq!(
                ProviderHttpsTransport::resolve_with(&BTreeSet::new(), reuse, |_, _| {
                    panic!("an empty selection must not resolve")
                })
                .err(),
                Some(BrokerUpstreamError::DestinationDenied)
            );
            for (answer, expected) in [
                (
                    vec![SocketAddr::from(([127, 0, 0, 1], OPENAI_PORT))],
                    BrokerUpstreamError::DestinationDenied,
                ),
                (
                    vec![public(1), SocketAddr::from(([10, 0, 0, 1], OPENAI_PORT))],
                    BrokerUpstreamError::DestinationDenied,
                ),
                (
                    vec![SocketAddr::new(public(1).ip(), 80)],
                    BrokerUpstreamError::DestinationDenied,
                ),
                (
                    (1..=17).map(public).collect(),
                    BrokerUpstreamError::ResourceLimit,
                ),
                (Vec::new(), BrokerUpstreamError::Connect),
            ] {
                assert_eq!(
                    ProviderHttpsTransport::resolve_with(&openai, reuse, |_, _| Ok(answer.clone()))
                        .err(),
                    Some(expected),
                    "{reuse:?} {answer:?}"
                );
            }
            assert_eq!(
                ProviderHttpsTransport::resolve_with(&openai, reuse, |_, _| {
                    Err(std::io::ErrorKind::NotFound.into())
                })
                .err(),
                Some(BrokerUpstreamError::Connect)
            );
            let looked_up = std::sync::Mutex::new(Vec::new());
            let transport = ProviderHttpsTransport::resolve_with(
                &BTreeSet::from([HttpProvider::OpenAiApiKey, HttpProvider::CodexOAuth]),
                reuse,
                |host, port| {
                    looked_up.lock().unwrap().push((host.to_owned(), port));
                    Ok(vec![public(1), public(2)])
                },
            )
            .unwrap();
            assert_eq!(transport.reuse, reuse);
            assert_eq!(transport.resolved_address_count, 6);
            assert_eq!(
                looked_up.into_inner().unwrap(),
                [OPENAI_HOST, OPENAI_AUTH_HOST, CHATGPT_HOST].map(|host| (host.to_owned(), 443))
            );
        }
    }

    /// A loopback HTTP/1.1 provider stand-in. It counts accepted connections
    /// and records which Host each connection served. `/partial` announces
    /// ten body bytes, sends five and waits for the client to close.
    struct ProviderStandIn {
        address: SocketAddr,
        hosts_by_connection: std::sync::Arc<std::sync::Mutex<Vec<BTreeSet<String>>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl ProviderStandIn {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let hosts_by_connection =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::<BTreeSet<String>>::new()));
            let record = hosts_by_connection.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let connection = {
                        let mut hosts = record.lock().unwrap();
                        hosts.push(BTreeSet::new());
                        hosts.len() - 1
                    };
                    tokio::spawn(Self::serve(stream, connection, record.clone()));
                }
            });
            Self {
                address,
                hosts_by_connection,
                task,
            }
        }

        async fn serve(
            stream: tokio::net::TcpStream,
            connection: usize,
            record: std::sync::Arc<std::sync::Mutex<Vec<BTreeSet<String>>>>,
        ) {
            use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = tokio::io::BufReader::new(stream);
            loop {
                let mut request_line = String::new();
                if stream.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("host")
                    {
                        record.lock().unwrap()[connection].insert(value.trim().to_owned());
                    }
                }
                if request_line.starts_with("GET /partial ") {
                    let _ = stream
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhello")
                        .await;
                    let _ = stream.read_to_end(&mut Vec::new()).await;
                    return;
                }
                if stream
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }

        /// The production client settings for `reuse`; only what a plain
        /// loopback stand-in needs differs: http, and both hosts pinned to it.
        fn client(&self, reuse: ConnectionReuse) -> reqwest::Client {
            client_builder(reuse)
                .https_only(false)
                .resolve(OPENAI_HOST, self.address)
                .resolve(CHATGPT_HOST, self.address)
                .build()
                .unwrap()
        }

        fn url(&self, host: &str, path: &str) -> String {
            format!("http://{host}:{}{path}", self.address.port())
        }

        async fn get(&self, client: &reqwest::Client, host: &str, path: &str) -> bytes::Bytes {
            let response = client.get(self.url(host, path)).send().await.unwrap();
            assert_eq!(response.version(), http::Version::HTTP_11);
            response.bytes().await.unwrap()
        }

        fn connections(&self) -> Vec<BTreeSet<String>> {
            self.hosts_by_connection.lock().unwrap().clone()
        }
    }

    impl Drop for ProviderStandIn {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn pooled_transport_reuses_one_connection_for_sequential_requests() {
        let provider = ProviderStandIn::start().await;
        let client = provider.client(ConnectionReuse::Pooled);
        for _ in 0..3 {
            assert_eq!(&provider.get(&client, OPENAI_HOST, "/").await[..], b"ok");
        }
        assert_eq!(
            provider.connections(),
            [BTreeSet::from([format!(
                "{OPENAI_HOST}:{}",
                provider.address.port()
            )])]
        );
    }

    #[tokio::test]
    async fn per_request_transport_opens_a_connection_for_every_request() {
        let provider = ProviderStandIn::start().await;
        let client = provider.client(ConnectionReuse::PerRequest);
        for _ in 0..3 {
            assert_eq!(&provider.get(&client, OPENAI_HOST, "/").await[..], b"ok");
        }
        assert_eq!(provider.connections().len(), 3);
    }

    #[tokio::test]
    async fn pooled_connections_are_never_shared_between_provider_hosts() {
        // Both hosts resolve to the same address, so only the pool key can
        // keep their connections apart.
        let provider = ProviderStandIn::start().await;
        let client = provider.client(ConnectionReuse::Pooled);
        for host in [OPENAI_HOST, CHATGPT_HOST, OPENAI_HOST, CHATGPT_HOST] {
            assert_eq!(&provider.get(&client, host, "/").await[..], b"ok");
        }
        let port = provider.address.port();
        let mut connections = provider.connections();
        connections.sort();
        assert_eq!(
            connections,
            [
                BTreeSet::from([format!("{OPENAI_HOST}:{port}")]),
                BTreeSet::from([format!("{CHATGPT_HOST}:{port}")]),
            ]
        );
    }

    #[tokio::test]
    async fn pooled_connection_closes_when_a_response_is_not_read_to_its_end() {
        let provider = ProviderStandIn::start().await;
        let client = provider.client(ConnectionReuse::Pooled);
        let partial = client
            .get(provider.url(OPENAI_HOST, "/partial"))
            .send()
            .await
            .unwrap();
        assert_eq!(partial.status(), http::StatusCode::OK);
        drop(partial);
        // The next request must not read the rest of the abandoned body.
        assert_eq!(&provider.get(&client, OPENAI_HOST, "/").await[..], b"ok");
        assert_eq!(provider.connections().len(), 2);
    }

    #[tokio::test]
    async fn pooled_transport_checks_the_destination_before_choosing_a_connection() {
        let provider = ProviderStandIn::start().await;
        let transport = ProviderHttpsTransport {
            client: provider.client(ConnectionReuse::Pooled),
            upgrade_client: upgrade_client_builder().build().unwrap(),
            selected: BTreeSet::from([HttpProvider::OpenAiApiKey]),
            unresolved: BTreeSet::new(),
            log_hosts: BTreeSet::new(),
            resolved_address_count: 1,
            reuse: ConnectionReuse::Pooled,
        };
        let port = provider.address.port();
        for target in [
            format!("http://{OPENAI_HOST}:{port}/v1/responses"),
            format!("https://{OPENAI_HOST}:{port}/v1/responses"),
            format!("http://{OPENAI_HOST}/v1/responses"),
            format!("https://{CHATGPT_HOST}/backend-api/codex/responses"),
            format!("https://{OPENAI_HOST}/v2/other"),
        ] {
            let request = BrokerUpstreamRequest::new(
                Method::POST,
                url::Url::parse(&target).unwrap(),
                HeaderMap::new(),
                Vec::new(),
            );
            assert_eq!(
                transport.execute(request).await.err(),
                Some(BrokerUpstreamError::DestinationDenied),
                "{target}"
            );
        }
        assert!(provider.connections().is_empty());
    }

    #[test]
    fn response_headers_are_bounded_before_the_bridge() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("small"));
        assert!(validate_response_headers(&headers).is_ok());
        headers.insert(
            "x-large",
            http::HeaderValue::from_bytes(&vec![b'a'; MAX_RESPONSE_HEADER_BYTES]).unwrap(),
        );
        assert_eq!(
            validate_response_headers(&headers),
            Err(BrokerUpstreamError::ResourceLimit)
        );
    }

    /// A routed origin is a canonical name strictly under the fixed suffix,
    /// reached only on Codex's model path at a pinned address the broker
    /// itself would dial (#3999).
    #[test]
    fn a_routed_origin_is_admitted_only_pinned_on_codex_s_model_path() {
        assert!(routed_host("routed.chatgpt.com"));
        for other in [
            "chatgpt.com",
            "a.b.chatgpt.com",
            ".chatgpt.com",
            "xchatgpt.com",
            "ROUTED.chatgpt.com",
            "routed.chatgpt.com.",
            "routed.chatgpt.com.evil.test",
            "routed.xn--chatgt-frf.com",
            "routed.api.openai.com",
            "*.chatgpt.com",
        ] {
            assert!(!routed_host(other), "{other}");
        }
        let public = IpAddr::from([162, 159, 140, 245]);
        assert_eq!(admit_pinned(public), Ok(SocketAddr::new(public, 443)));
        for protected in [
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([127, 0, 0, 1]),
            IpAddr::from([169, 254, 169, 254]),
            IpAddr::from([100, 64, 0, 1]),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert_eq!(
                admit_pinned(protected),
                Err(BrokerUpstreamError::DestinationDenied),
                "{protected}"
            );
        }
        let codex = BTreeSet::from([HttpProvider::CodexOAuth]);
        let target = |url: &str| url::Url::parse(url).unwrap();
        assert!(
            validate_pinned_target(
                &target("https://routed.chatgpt.com/backend-api/codex/responses"),
                &Method::POST,
                &codex,
            )
            .is_ok()
        );
        for denied in [
            "https://routed.chatgpt.com/backend-api/wham/usage",
            "https://routed.chatgpt.com/",
            "https://routed.chatgpt.com:8443/backend-api/codex/responses",
            "http://routed.chatgpt.com/backend-api/codex/responses",
            "https://user@routed.chatgpt.com/backend-api/codex/responses",
            "https://routed.example.com/backend-api/codex/responses",
        ] {
            assert_eq!(
                validate_pinned_target(&target(denied), &Method::POST, &codex),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
        // Without a pin, or for a key, a routed origin is no destination.
        let routed_target = target("https://routed.chatgpt.com/backend-api/codex/responses");
        assert_eq!(
            validate_target(&routed_target, &Method::POST, &codex),
            Err(BrokerUpstreamError::DestinationDenied)
        );
        assert_eq!(
            validate_pinned_target(
                &routed_target,
                &Method::POST,
                &BTreeSet::from([HttpProvider::OpenAiApiKey])
            ),
            Err(BrokerUpstreamError::DestinationDenied)
        );
        // A pin means routed: a bound host is never dialled at a named
        // address, even on a path its own check admits.
        for bound in [
            "https://chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/wham/usage",
            "https://api.openai.com/v1/responses",
        ] {
            assert_eq!(
                validate_pinned_target(&target(bound), &Method::POST, &codex),
                Err(BrokerUpstreamError::DestinationDenied),
                "{bound}"
            );
        }
    }

    /// The pinned dial still verifies the routed name's certificate: an
    /// address that answers with a certificate for another name, even one
    /// the client's roots sign, fails before any request is sent.
    #[tokio::test]
    async fn a_pinned_address_presenting_another_name_s_certificate_fails() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let routed = "routed.chatgpt.com";
        for (presented, connects) in [(routed, true), ("other.example.com", false)] {
            let leaf_key = KeyPair::generate().unwrap();
            let leaf = CertificateParams::new(vec![presented.to_owned()])
                .unwrap()
                .signed_by(&leaf_key, &ca, &ca_key)
                .unwrap();
            let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return false;
                };
                let mut request = [0_u8; 1024];
                let _ = tls.read(&mut request).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                true
            });
            let client = pinned_client(
                client_builder(ConnectionReuse::PerRequest)
                    .add_root_certificate(reqwest::Certificate::from_der(ca.der()).unwrap()),
                routed,
                address,
            )
            .unwrap();
            let sent = client
                .get(format!(
                    "https://{routed}:{}/backend-api/codex/responses",
                    address.port()
                ))
                .send()
                .await;
            assert_eq!(sent.is_ok(), connects, "{presented}: {sent:?}");
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(30), server)
                    .await
                    .unwrap()
                    .unwrap(),
                connects,
                "{presented}"
            );
        }
    }
}
