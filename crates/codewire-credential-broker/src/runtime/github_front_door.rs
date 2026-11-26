//! GitHub's two hosts behind a front door (#3999).
//!
//! `github.com` and `api.github.com` are intercepted whole, so Git and `gh`
//! use GitHub's own names. Most of what reaches them is not Codewire's to
//! touch: an anonymous clone, a request with the user's own token, a path the
//! managed route never served. The rule, in order:
//!
//! 1. The environment's network policy must allow GitHub's hosts by rule, or
//!    nothing is sent, with or without a credential (#4926).
//! 2. A placeholder beside another credential is refused, as on every route.
//! 3. A request with no placeholder-shaped value is forwarded as it was sent,
//!    on any path, with no lease and nothing of the broker's in it. A hosted
//!    broker forwards nothing untouched: such a request is refused, or, on
//!    Git's smart-HTTP grammar at `github.com` where the binding selects the
//!    `github` slot, answered with GitHub's own challenge, so Git asks its
//!    credential helper for the placeholder (`runtime/untouched.rs`, #4001).
//! 4. A placeholder-shaped value on a request outside the route's grammar
//!    (Git fetch and push, and the API operations the route grants) is
//!    refused without a lease, whoever's placeholder it looks like. It is
//!    never forwarded: a placeholder that reached GitHub on such a path
//!    would only fail there, and nothing should teach a client to send it.
//! 5. On the grammar, the swap rule decides: this environment's placeholder
//!    is served exactly as the loopback route serves it, and any other value
//!    is forwarded untouched. A lease whose placeholder key could not be
//!    read refuses the request, as on Anthropic's route (#5087).
//!
//! Bodies: a forwarded body streams whatever its size. A Git POST given the
//! credential streams as on the loopback route. An API request given the
//! credential keeps that route's 4 MiB bound and is answered 413 above it.

use bytes::Bytes;
use codewire_access::BrokerOperationId;
use futures::{StreamExt as _, stream};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use url::Url;

use super::swap::{Presented, credential_conflict_response, forwarded_body};
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestBodyStream, BrokerRequestError,
    BrokerUpstreamRequest, BrokerUpstreamTransport, OpenAiBroker, Phase, ValidatedGuestRequest,
    map_adapter_error, map_lease_error, map_upstream_error, timing,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::network::RouteHost;
use crate::network_policy;
use crate::transparent::{untouched_request_headers, without_framing};

/// Stable machine-readable code of the refusal of a placeholder outside the
/// route's grammar.
pub(crate) const PLACEHOLDER_OUTSIDE_ROUTE_CODE: &str = "placeholder_outside_route";

const OUTSIDE_ROUTE_MESSAGE: &str = "Codewire's GitHub connection serves Git fetch and push and a fixed set of GitHub API operations. This request is not one of them, so it was not sent. Git LFS is not served. To make this request, use your own GitHub token.";

/// The body of GitHub's challenge, which Git does not show: it asks its
/// credential helper and repeats the request.
const CHALLENGE_MESSAGE: &str = "Authentication required. Git's credential helper answers with Codewire's placeholder for this Sandbox's GitHub connection.\n";

const TOO_LARGE_MESSAGE: &str = "Codewire's GitHub connection accepts GitHub API request bodies up to 4 MiB. This request was not sent.";

/// The most an API request given the credential may carry, as on the
/// loopback route.
const MAX_CREDENTIALED_API_BODY_BYTES: usize = 4 * 1024 * 1024;

const GIT_ROUTE: &str = "github-https";

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Whether the environment's network policy allows GitHub's hosts by
    /// rule. Today this is the answer the broker was started with, from the
    /// environment's selected policy (#4926). The egress broker's signed
    /// decision for the intercepted connection replaces it per request
    /// (#3999, `intercept_decision` on the bridge request): allowed only on
    /// a verified record for `host`, and not allowed without a verifier.
    fn github_allowed_by_rule(&self, _host: RouteHost) -> bool {
        self.network_policy_allows_github
    }

    /// A front-door request to `host`, one of GitHub's two. See the module
    /// documentation for the rule.
    pub(super) async fn execute_github_intercepted(
        &self,
        host: RouteHost,
        mut request: ValidatedGuestRequest,
        mut body_stream: Option<BrokerRequestBodyStream>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        if !self.github_allowed_by_rule(host) {
            return Ok(network_policy::github_refused_response(
                request.route.as_str(),
            ));
        }
        let presented = match Presented::of(&request.headers) {
            Presented::DisallowedPlaceholder => return Err(BrokerRequestError::InvalidRequest),
            Presented::Conflict => return Ok(credential_conflict_response()),
            Presented::Foreign => {
                if self.untouched_forwards.challenges_git(
                    host,
                    &request.method,
                    &request.path,
                    request.query.as_deref(),
                ) {
                    return Ok(challenge_response());
                }
                return self.forward_github(host, request, body_stream).await;
            }
            Presented::Placeholder(placeholder) => placeholder,
        };
        if crate::github::classify_request(
            request.route.as_str(),
            &request.method,
            &request.path,
            request.query.as_deref(),
        )
        .is_err()
        {
            return Ok(outside_route_response(request.route.as_str()));
        }
        if self.placeholders.known_foreign(&request.slot, &presented) {
            return self.forward_github(host, request, body_stream).await;
        }
        // An API request that may be given the credential is read whole,
        // within the route's bound, before anything is leased for it.
        if request.route.as_str() != GIT_ROUTE
            && let Some(stream) = body_stream.take()
        {
            match collect_bounded(stream, MAX_CREDENTIALED_API_BODY_BYTES).await? {
                Some(body) => request.body = body,
                None => return Ok(too_large_response()),
            }
        }
        let validated = if body_stream.is_some() {
            self.github_adapter.validate_streamed_request(
                request.route.as_str(),
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers.clone(),
            )
        } else {
            self.github_adapter.validate_request(
                request.route.as_str(),
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers.clone(),
                request.body.clone(),
            )
        }
        .map_err(map_adapter_error)?;
        let operation = BrokerOperationId::parse(validated.operation().operation_name())
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                request.slot.clone(),
                operation.clone(),
                request.route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &request.route)?;
        if lease.placeholder_failed() {
            // This environment's key could not be read, so neither ours nor a
            // foreign value can be told: refused, and never remembered, as on
            // Anthropic's route (#5087).
            drop(lease);
            return Err(BrokerRequestError::AuthorityUnavailable);
        }
        self.placeholders
            .remember(&request.slot, lease.placeholder());
        if !lease
            .placeholder()
            .is_some_and(|ours| ours.ct_eq(&presented))
        {
            drop(lease);
            return self.forward_github(host, request, body_stream).await;
        }
        self.serve_github(
            request.request_id,
            request.slot,
            request.route,
            operation,
            lease,
            validated,
            body_stream,
        )
        .await
    }

    /// A request that carries no placeholder of this environment's: sent to
    /// `host` as the environment sent it, framing aside, its path and query
    /// byte for byte, and its reply returned whole and unredacted, since
    /// nothing of ours was injected. No header is logged.
    async fn forward_github(
        &self,
        host: RouteHost,
        request: ValidatedGuestRequest,
        body_stream: Option<BrokerRequestBodyStream>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let target = forward_target(host, &request.path, request.query.as_deref())?;
        self.untouched_forward_allowed(&target, false)?;
        let response = timing::timed(
            Phase::Provider,
            self.upstream.forward_github(BrokerUpstreamRequest {
                method: request.method,
                target,
                headers: untouched_request_headers(&request.headers),
                body: request.body,
                body_stream,
                pinned: None,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        Ok(BrokerHttpResponse::new(
            status,
            without_framing(&headers),
            // A clone or a download has no size to bound.
            forwarded_body(body, usize::MAX),
        ))
    }
}

/// `https://HOST` with `path` and `query` exactly as received. A path or
/// query the URL parser would write differently is refused, so what reaches
/// GitHub is what the front door admitted, byte for byte.
fn forward_target(
    host: RouteHost,
    path: &str,
    query: Option<&str>,
) -> Result<Url, BrokerRequestError> {
    let mut text = format!("https://{}{path}", host.as_str());
    if let Some(query) = query {
        text.push('?');
        text.push_str(query);
    }
    let target = Url::parse(&text).map_err(|_| BrokerRequestError::InvalidRequest)?;
    if target.host_str() != Some(host.as_str())
        || target.path() != path
        || target.query() != query
        || target.fragment().is_some()
    {
        return Err(BrokerRequestError::InvalidRequest);
    }
    Ok(target)
}

/// The whole of `stream` when it is at most `limit` bytes, or `None` once it
/// is more. A body that ends in an error was cut short and is refused.
async fn collect_bounded(
    mut stream: BrokerRequestBodyStream,
    limit: usize,
) -> Result<Option<Vec<u8>>, BrokerRequestError> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BrokerRequestError::InvalidRequest)?;
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// The answer to a placeholder outside the route's grammar, in the form the
/// route's client shows: plain text for Git, JSON for `gh`. 403 is final for
/// both. The body is a constant.
fn outside_route_response(route: &str) -> BrokerHttpResponse {
    tracing::info!(
        event = "credential_refused",
        slot = network_policy::GITHUB_SLOT,
        route,
        reason = PLACEHOLDER_OUTSIDE_ROUTE_CODE,
    );
    let (content_type, body) = if route == GIT_ROUTE {
        (
            "text/plain; charset=utf-8",
            format!("{OUTSIDE_ROUTE_MESSAGE}\n"),
        )
    } else {
        (
            "application/json",
            serde_json::json!({
                "message": OUTSIDE_ROUTE_MESSAGE,
                "code": PLACEHOLDER_OUTSIDE_ROUTE_CODE,
            })
            .to_string(),
        )
    };
    fixed_response(StatusCode::FORBIDDEN, content_type, body)
}

/// GitHub's own challenge to Git: 401 with `WWW-Authenticate: Basic
/// realm="GitHub"` and a fixed body. Nothing is leased and nothing is sent.
fn challenge_response() -> BrokerHttpResponse {
    let (status, mut headers, body) = fixed_response(
        StatusCode::UNAUTHORIZED,
        "text/plain; charset=utf-8",
        CHALLENGE_MESSAGE.to_owned(),
    )
    .into_parts();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"GitHub\""),
    );
    BrokerHttpResponse::new(status, headers, body)
}

/// 413 for an API request that would be given the credential and is over
/// the route's bound.
fn too_large_response() -> BrokerHttpResponse {
    fixed_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "application/json",
        serde_json::json!({ "message": TOO_LARGE_MESSAGE }).to_string(),
    )
}

fn fixed_response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> BrokerHttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let body = Bytes::from(body);
    BrokerHttpResponse::new(
        status,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}
