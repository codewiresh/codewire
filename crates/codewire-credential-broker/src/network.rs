use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use async_trait::async_trait;
use av_credential_proxy::tunnel_ip_allowed;
use codewire_access::HttpProvider;
use futures::StreamExt as _;
use http::{HeaderMap, Method};
use reqwest::redirect::Policy;

use crate::refresh_failure::TransportFailure;
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};

const OPENAI_HOST: &str = "api.openai.com";
const CHATGPT_HOST: &str = "chatgpt.com";
const OPENAI_AUTH_HOST: &str = "auth.openai.com";
const ANTHROPIC_HOST: &str = "api.anthropic.com";
const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_GIT_HOST: &str = "github.com";
const OPENAI_PORT: u16 = 443;
/// Transparent routes' pinned base paths (#2536); Anthropic's is its origin.
const OPENAI_BASE_PATH: &str = "/v1/";
const CHATGPT_CODEX_BASE_PATH: &str = "/backend-api/codex/";
const OPENAI_REFRESH_PATH: &str = "/oauth/token";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
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
    selected: BTreeSet<HttpProvider>,
    resolved_address_count: usize,
    reuse: ConnectionReuse,
}

impl std::fmt::Debug for ProviderHttpsTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderHttpsTransport")
            .field("selected", &self.selected)
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

    fn resolve_with(
        selected: &BTreeSet<HttpProvider>,
        reuse: ConnectionReuse,
        lookup: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
    ) -> Result<Self, BrokerUpstreamError> {
        // This deliberately uses the calling thread instead of Tokio's
        // blocking resolver pool. Broker launch is bounded by the authority's
        // readiness timeout, and retaining a resolver worker here would leave
        // an already-running thread outside older Landlock thread domains.
        let hosts = selected_hosts(selected)?;
        let mut resolved_address_count = 0_usize;
        let mut builder = client_builder(reuse);
        for host in &hosts {
            let addresses = lookup(host, OPENAI_PORT).map_err(|_| BrokerUpstreamError::Connect)?;
            let addresses = admit_resolved_addresses(addresses)?;
            resolved_address_count = resolved_address_count
                .checked_add(addresses.len())
                .filter(|count| *count <= MAX_RESOLVED_ADDRESSES.saturating_mul(hosts.len()))
                .ok_or(BrokerUpstreamError::ResourceLimit)?;
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        let client = builder.build().map_err(|_| BrokerUpstreamError::Protocol)?;
        Ok(Self {
            client,
            selected: selected.clone(),
            resolved_address_count,
            reuse,
        })
    }
}

fn system_lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// Everything about the provider client except its pinned addresses.
fn client_builder(reuse: ConnectionReuse) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(Policy::none())
        .referer(false)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .http2_max_header_list_size(MAX_RESPONSE_HEADER_BYTES as u32);
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

#[async_trait]
impl BrokerUpstreamTransport for ProviderHttpsTransport {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        validate_target(&target, &method, &self.selected)?;
        let is_refresh =
            target.host_str() == Some(OPENAI_AUTH_HOST) && target.path() == OPENAI_REFRESH_PATH;
        let provider_host = provider_host(&target);
        let mut request = self
            .client
            .request(method.clone(), target.as_str())
            .headers(headers)
            .body(body);
        if is_refresh {
            request = request.timeout(REFRESH_REQUEST_TIMEOUT);
        }
        let response = request.send().await.map_err(|error| {
            // Only fixed classes and an io::ErrorKind name are logged; reqwest
            // and OS error text can carry URLs or peer details.
            let (failure, io_error_kind) = TransportFailure::classify(
                error.is_timeout(),
                error.is_connect(),
                error.is_request(),
                &error,
            );
            let io_error_kind =
                io_error_kind.map_or_else(|| "none".to_owned(), |kind| format!("{kind:?}"));
            tracing::warn!(
                provider_host,
                refresh = is_refresh,
                failure = failure.as_str(),
                io_error_kind = %io_error_kind,
                "provider transport request failed"
            );
            map_reqwest_error(error)
        })?;
        validate_target(response.url(), &method, &self.selected)?;
        let status = response.status();
        let headers = response.headers().clone();
        validate_response_headers(&headers)?;
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(map_reqwest_error));
        Ok(BrokerUpstreamResponse::new(status, headers, Box::pin(body)))
    }
}

/// The already-validated destination as a fixed name, never request text.
fn provider_host(target: &url::Url) -> &'static str {
    match target.host_str() {
        Some(OPENAI_HOST) => OPENAI_HOST,
        Some(CHATGPT_HOST) => CHATGPT_HOST,
        Some(OPENAI_AUTH_HOST) => OPENAI_AUTH_HOST,
        Some(ANTHROPIC_HOST) => ANTHROPIC_HOST,
        Some(GITHUB_API_HOST) => GITHUB_API_HOST,
        Some(GITHUB_GIT_HOST) => GITHUB_GIT_HOST,
        _ => "other",
    }
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
            HttpProvider::AnthropicApiKey | HttpProvider::AnthropicSubscriptionToken => {
                &[ANTHROPIC_HOST][..]
            }
            HttpProvider::GitHubOAuth => &[GITHUB_API_HOST, GITHUB_GIT_HOST][..],
            HttpProvider::GitHubAppAuthorization => &[GITHUB_API_HOST, GITHUB_GIT_HOST][..],
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
                && target.path().starts_with(CHATGPT_CODEX_BASE_PATH)
        }
        Some(OPENAI_AUTH_HOST) => {
            selected.contains(&HttpProvider::CodexOAuth)
                && method == Method::POST
                && target.path() == OPENAI_REFRESH_PATH
                && target.query().is_none()
        }
        Some(ANTHROPIC_HOST) => {
            (selected.contains(&HttpProvider::AnthropicApiKey)
                || selected.contains(&HttpProvider::AnthropicSubscriptionToken))
                && transparent_method(method)
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
                    && target.path() == "/login/oauth/access_token"
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

/// Transparent provider routes carry any CRUD request on their pinned host.
fn transparent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn github_app_authorization_transport_has_only_exchange_and_identity_routes() {
        let selected = BTreeSet::from([HttpProvider::GitHubAppAuthorization]);
        for (method, target) in [
            (Method::POST, "https://github.com/login/oauth/access_token"),
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
        for denied in [
            "https://api.openai.com/v1/responses",
            "https://chatgpt.com/backend-api/other",
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
            selected: BTreeSet::from([HttpProvider::OpenAiApiKey]),
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
}
