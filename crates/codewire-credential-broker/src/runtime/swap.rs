//! The swap rule for front-door requests (#3999).
//!
//! A request the front door intercepted carries whatever credential the
//! environment put in it. The broker swaps it for the real one only when it is
//! this environment's placeholder for the leased credential, in one of three
//! shapes: the whole `authorization` or `x-api-key` value, `Bearer` or `Token`
//! followed by it, or the password of `Basic`. A request that carries no
//! placeholder takes no lease and is forwarded untouched, so a user's own key
//! works as theirs; a placeholder sent with any other credential header is
//! refused. Loopback requests never come here: their credential is always
//! dropped and the leased one injected.
//!
//! The rule covers the Anthropic route, and Codex on a ChatGPT sign-in at
//! `chatgpt.com`, whose paths are the ones the pinned Codex sends its
//! credential to.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CREDENTIAL_PLACEHOLDER_TAG, CapabilitySlot,
    CredentialAuthKind, CredentialPlaceholder, Refusal,
};
use futures::{Stream, StreamExt as _, stream};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use tokio::time::Instant;

use super::anthropic_route::anthropic_operation;
use super::routed::{self, ACCOUNTS_CHECK_PATH, Carried, FrontDoorSession};
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError,
    BrokerResponseBody, BrokerUpstreamBody, BrokerUpstreamRequest, BrokerUpstreamTransport,
    OPENAI_OPERATION, OPENAI_ROUTE, OpenAiBroker, Phase, ProviderStreamingResponse,
    ValidatedGuestRequest, map_adapter_error, map_lease_error, map_upstream_error, timing,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::anthropic::ValidatedAnthropicRequest;
use crate::gemini::ValidatedGeminiRequest;
use crate::openai::ValidatedOpenAiRequest;
use crate::transparent::without_framing;

/// How long a lease's placeholder is trusted without a new lease. A
/// placeholder-shaped value that is not this environment's is forwarded
/// without a lease while the remembered one is this fresh; a rebind takes
/// effect within the same 60 seconds (#3999).
const PLACEHOLDER_FRESH_FOR: Duration = Duration::from_secs(60);

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A front-door Anthropic request under the swap rule.
    pub(super) async fn execute_swap(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let presented = match Presented::of(&request.headers) {
            Presented::DisallowedPlaceholder => return Err(BrokerRequestError::InvalidRequest),
            Presented::Conflict => return Ok(credential_conflict_response()),
            Presented::Foreign => None,
            Presented::Placeholder(placeholder) => Some(placeholder),
        };
        let validated = self.validate_anthropic(
            &request.method,
            &request.path,
            request.query.as_deref(),
            request.headers,
            request.body,
        )?;
        let Some(presented) = presented else {
            return self.forward_anthropic(validated).await;
        };
        if self.placeholders.known_foreign(&request.slot, &presented) {
            return self.forward_anthropic(validated).await;
        }
        let operation = anthropic_operation()?;
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
            // foreign value can be told: refused, and never remembered, so
            // every request reads the key again until it can (#4001 step C3).
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
            return self.forward_anthropic(validated).await;
        }
        self.serve_anthropic(
            request.request_id,
            request.slot,
            request.route,
            operation,
            lease,
            validated,
        )
        .await
    }

    /// A front-door Codex request to `chatgpt.com` under the swap rule. Only a
    /// ChatGPT sign-in is swapped in; a key never goes to `chatgpt.com`.
    ///
    /// A name under a routed suffix is served only at the origin `session`
    /// recorded for the kind of credential the request carries, on Codex's
    /// model path, dialled at its admitted address: checked before any lease
    /// (`runtime/routed.rs`). An `accounts/check` reply served at
    /// `chatgpt.com` records the origin it names: swapped, for the account
    /// the broker itself sent; forwarded, for the one the environment named.
    pub(super) async fn execute_codex_swap(
        &self,
        request: ValidatedGuestRequest,
        session: &Arc<FrontDoorSession>,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let presented = match Presented::of(&request.headers) {
            Presented::DisallowedPlaceholder => return Err(BrokerRequestError::InvalidRequest),
            Presented::Conflict => return Ok(credential_conflict_response()),
            Presented::Foreign => None,
            Presented::Placeholder(placeholder) => Some(placeholder),
        };
        let carried = match presented {
            Some(_) => Carried::Swapped,
            None => Carried::Forwarded,
        };
        // Codex names its account in every request; a forwarded reply's
        // entry is found by it, a swapped one's by the credential's own.
        let named_account = request
            .headers
            .get("chatgpt-account-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let records = request.routed.is_none()
            && request.method == http::Method::GET
            && request.path == ACCOUNTS_CHECK_PATH;
        let routed = request.routed.clone();
        let path = request.path.clone();
        let provider_request = match &routed {
            None => self.oauth_adapter.validate_front_door(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            ),
            Some(dial) => {
                let pinned = session
                    .recorded_origin_admits(carried, &dial.host, &path, dial.destination)
                    .ok()
                    .flatten()
                    .ok_or(BrokerRequestError::Denied)?;
                self.oauth_adapter.validate_routed(
                    &dial.host,
                    pinned,
                    &request.method,
                    &request.path,
                    request.query.as_deref(),
                    request.headers,
                    request.body,
                )
            }
        }
        .map_err(map_adapter_error)?;
        // A placeholder that proves not to be ours is forwarded at a routed
        // origin only as the forwarded record allows, never on the swapped
        // record's say.
        let forward_allowed = || {
            routed.as_ref().is_none_or(|dial| {
                session
                    .recorded_origin_admits(Carried::Forwarded, &dial.host, &path, dial.destination)
                    .is_ok_and(|admitted| admitted.is_some())
            })
        };
        let (response, served) = self
            .serve_codex_front_door(
                request.request_id,
                &request.slot,
                presented,
                provider_request,
                forward_allowed,
                (session, routed.is_some()),
            )
            .await?;
        if !records || !response.status().is_success() {
            return Ok(response);
        }
        let (carried, account) = match served {
            Served::Swapped { account } => (Carried::Swapped, account),
            Served::Forwarded => (Carried::Forwarded, named_account),
        };
        let (status, headers, body) = response.into_parts();
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            routed::recording(body, Arc::clone(session), carried, account),
        ))
    }

    /// [`Self::execute_codex_swap`] once the request is admitted: forwarded
    /// untouched unless it presents this environment's placeholder, and
    /// then only while `forward_allowed`. `(session, routed)` is the
    /// session and whether the request is to a routed origin, admitted on
    /// the session's swapped record: a lease for another credential than
    /// that record was read for clears it, and refuses a routed request.
    async fn serve_codex_front_door(
        &self,
        request_id: uuid::Uuid,
        slot: &CapabilitySlot,
        presented: Option<CredentialPlaceholder>,
        provider_request: ValidatedOpenAiRequest,
        forward_allowed: impl Fn() -> bool,
        (session, routed): (&FrontDoorSession, bool),
    ) -> Result<(BrokerHttpResponse, Served), BrokerRequestError> {
        let forwarded = |response: BrokerHttpResponse| (response, Served::Forwarded);
        let Some(presented) = presented else {
            return self.forward_chatgpt(provider_request).await.map(forwarded);
        };
        if self.placeholders.known_foreign(slot, &presented) {
            if !forward_allowed() {
                return Err(BrokerRequestError::Denied);
            }
            return self.forward_chatgpt(provider_request).await.map(forwarded);
        }
        let operation = BrokerOperationId::parse(OPENAI_OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(OPENAI_ROUTE).map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(request_id, slot.clone(), operation.clone(), route.clone())
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, slot, &operation, &route)?;
        self.placeholders.remember(slot, lease.placeholder());
        if !lease
            .placeholder()
            .is_some_and(|ours| ours.ct_eq(&presented))
        {
            drop(lease);
            if !forward_allowed() {
                return Err(BrokerRequestError::Denied);
            }
            return self.forward_chatgpt(provider_request).await.map(forwarded);
        }
        if lease.credential_metadata().authentication_kind != CredentialAuthKind::OAuth {
            return Err(BrokerRequestError::Denied);
        }
        if session.credential_changed(&lease.credential_metadata().id) && routed {
            return Err(BrokerRequestError::Denied);
        }
        let (response, account) = self
            .serve_openai_for_account(request_id, slot, operation, route, lease, provider_request)
            .await?;
        Ok((response, Served::Swapped { account }))
    }

    /// A front-door Codex request that carries no placeholder of this
    /// environment's: sent to `chatgpt.com` as the environment sent it,
    /// framing aside, and its reply returned unredacted. No header is logged.
    async fn forward_chatgpt(
        &self,
        provider_request: ValidatedOpenAiRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let forwarded = provider_request
            .into_forwarded()
            .map_err(map_adapter_error)?;
        self.forward(
            forwarded.method,
            forwarded.target,
            &forwarded.headers,
            forwarded.body,
            forwarded.pinned,
            crate::openai::MAX_RESPONSE_BYTES,
        )
        .await
    }

    /// A front-door Gemini API request under the swap rule (#6555).
    ///
    /// Only `x-goog-api-key` carrying this environment's `cwp1_` placeholder
    /// triggers a swap. Any `cwp1_` tag in a raw or percent-decoded query
    /// parameter or in a disallowed credential header fails closed (`400`)
    /// before any lease or untouched-forward check; a swap beside a `key` or
    /// `access_token` query parameter or another credential header is refused
    /// as `400 credential_conflict`.
    pub(super) async fn execute_gemini_swap(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        if query_carries_placeholder_tag(request.query.as_deref()) {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let presented = match Presented::of_for(&request.headers, SwapCarrier::GeminiApiKey) {
            Presented::DisallowedPlaceholder => return Err(BrokerRequestError::InvalidRequest),
            Presented::Conflict => return Ok(credential_conflict_response()),
            Presented::Foreign => None,
            Presented::Placeholder(placeholder) => Some(placeholder),
        };
        if presented.is_some() && query_has_google_credential_param(request.query.as_deref()) {
            return Ok(credential_conflict_response());
        }
        let validated = self
            .gemini_adapter
            .validate_request(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let Some(presented) = presented else {
            return self.forward_gemini(validated).await;
        };
        if self.placeholders.known_foreign(&request.slot, &presented) {
            return self.forward_gemini(validated).await;
        }
        let operation = BrokerOperationId::parse(crate::gemini::OPERATION)
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
            return self.forward_gemini(validated).await;
        }
        self.serve_gemini(lease, validated).await
    }

    async fn serve_gemini(
        &self,
        lease: P::Lease,
        validated: ValidatedGeminiRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let prepared = self
            .gemini_adapter
            .prepare_validated(lease, validated)
            .map_err(map_adapter_error)?;
        let (method, target, headers, body, policy) = prepared.into_parts();
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
                body_stream: None,
                pinned: None,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = policy.begin(&headers).map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(ProviderStreamingResponse::Gemini(redactor)),
                finished: false,
            }),
        ))
    }

    async fn forward_gemini(
        &self,
        validated: ValidatedGeminiRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let (method, target, headers, body) =
            validated.into_forwarded().map_err(map_adapter_error)?;
        self.forward(
            method,
            target,
            &headers,
            body,
            None,
            crate::gemini::MAX_RESPONSE_BYTES,
        )
        .await
    }

    /// A front-door Anthropic request that carries no placeholder of this
    /// environment's: sent to the pinned origin as the environment sent it,
    /// framing aside, and its reply returned unredacted, since nothing of
    /// ours was injected. No header is logged.
    async fn forward_anthropic(
        &self,
        validated: ValidatedAnthropicRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let (method, target, headers, body) =
            validated.into_forwarded().map_err(map_adapter_error)?;
        self.forward(
            method,
            target,
            &headers,
            body,
            None,
            crate::anthropic::MAX_RESPONSE_BYTES,
        )
        .await
    }

    /// One forwarded request, framing aside both ways, its reply bounded at
    /// `max_bytes` and not redacted.
    pub(super) async fn forward(
        &self,
        method: http::Method,
        target: url::Url,
        headers: &HeaderMap,
        body: Vec<u8>,
        pinned: Option<std::net::SocketAddr>,
        max_bytes: usize,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.untouched_forward_allowed(&target, pinned.is_some())?;
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers: crate::transparent::untouched_request_headers(headers),
                body,
                body_stream: None,
                pinned,
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
            forwarded_body(body, max_bytes),
        ))
    }
}

/// How a front-door Codex request was served.
enum Served {
    /// With the credential swapped in, which sent `account`.
    Swapped { account: Option<String> },
    /// As the environment sent it.
    Forwarded,
}

/// Each slot's placeholder as its last lease named it, so a value that is
/// not this environment's costs no lease while that is fresh.
#[derive(Default)]
pub(super) struct PlaceholderCache(
    Mutex<HashMap<CapabilitySlot, (Option<CredentialPlaceholder>, Instant)>>,
);

impl PlaceholderCache {
    pub(super) fn known_foreign(
        &self,
        slot: &CapabilitySlot,
        presented: &CredentialPlaceholder,
    ) -> bool {
        let remembered = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        remembered.get(slot).is_some_and(|(ours, at)| {
            at.elapsed() < PLACEHOLDER_FRESH_FOR
                && !ours.as_ref().is_some_and(|ours| ours.ct_eq(presented))
        })
    }

    pub(super) fn remember(&self, slot: &CapabilitySlot, ours: Option<&CredentialPlaceholder>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(slot.clone(), (ours.cloned(), Instant::now()));
    }
}

/// The answer to a placeholder sent beside another credential: the client
/// must send one or the other. 400 is final, so it is shown at once.
pub(super) fn credential_conflict_response() -> BrokerHttpResponse {
    let mut headers = HeaderMap::new();
    let refusal = Refusal::CredentialConflict;
    for (name, value) in refusal.headers() {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    let body = Bytes::from(refusal.body(None, None));
    BrokerHttpResponse::new(
        StatusCode::BAD_REQUEST,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}

/// Headers that carry a credential. Each route's [`SwapCarrier`] selects which
/// headers may trigger a swap; every other header in this list counts toward
/// conflicts and fails closed when carrying a placeholder on a disallowed route.
pub(super) const CREDENTIAL_HEADERS: [HeaderName; 5] = [
    header::AUTHORIZATION,
    HeaderName::from_static("x-api-key"),
    HeaderName::from_static("x-goog-api-key"),
    header::PROXY_AUTHORIZATION,
    header::COOKIE,
];

/// Which credential headers a route accepts as a swap carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SwapCarrier {
    /// `authorization` and `x-api-key` (Anthropic, Codex, GitHub).
    Standard,
    /// `x-goog-api-key` only (`generativelanguage.googleapis.com`).
    GeminiApiKey,
    /// `authorization: Bearer <cwp1_...>` only (`daily-cloudcode-pa.googleapis.com`,
    /// `cloudcode-pa.googleapis.com`).
    AntigravityBearer,
}

/// What credential a front-door request presents.
#[derive(Debug)]
pub(super) enum Presented {
    /// One placeholder-shaped value, in a swap shape admitted for this route,
    /// and no other credential header. Whether it is this environment's is
    /// decided after the lease.
    Placeholder(CredentialPlaceholder),
    /// No placeholder in a swap shape: forwarded untouched, without a lease.
    Foreign,
    /// A placeholder beside another credential header, or more than one.
    Conflict,
    /// A `cwp1_` placeholder in a credential header disallowed on this route:
    /// refused (`400`), never swapped and never forwarded.
    DisallowedPlaceholder,
}

impl Presented {
    pub(super) fn of(headers: &HeaderMap) -> Self {
        Self::of_for(headers, SwapCarrier::Standard)
    }

    pub(super) fn of_for(headers: &HeaderMap, carrier: SwapCarrier) -> Self {
        let mut credential_values = 0_usize;
        let mut placeholders = Vec::new();
        let mut disallowed = false;
        for name in &CREDENTIAL_HEADERS {
            for value in headers.get_all(name) {
                credential_values += 1;
                if let Some(placeholder) = swap_shape_for(carrier, name, value.as_bytes()) {
                    placeholders.push(placeholder);
                } else if disallowed_placeholder_for(carrier, name, value.as_bytes()) {
                    disallowed = true;
                }
            }
        }
        if disallowed {
            return Self::DisallowedPlaceholder;
        }
        match (placeholders.len(), credential_values) {
            (0, _) => Self::Foreign,
            (1, 1) => Self::Placeholder(placeholders.remove(0)),
            _ => Self::Conflict,
        }
    }
}

fn contains_placeholder_tag(bytes: &[u8]) -> bool {
    let needle = CREDENTIAL_PLACEHOLDER_TAG.as_bytes();
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn disallowed_placeholder_for(carrier: SwapCarrier, name: &HeaderName, value: &[u8]) -> bool {
    match carrier {
        // Non-Gemini routes never accept `x-goog-api-key` as a swap trigger and
        // refuse a `cwp1_` placeholder placed there.
        SwapCarrier::Standard => {
            name.as_str() == "x-goog-api-key" && contains_placeholder_tag(value)
        }
        // On Gemini and Antigravity, any `cwp1_` placeholder in any disallowed
        // credential header (or non-admitted Authorization form, including
        // Basic-decoded) fails closed (`400`).
        SwapCarrier::GeminiApiKey | SwapCarrier::AntigravityBearer => {
            if contains_placeholder_tag(value) {
                return true;
            }
            if *name == header::AUTHORIZATION
                && let Ok(text) = std::str::from_utf8(value)
                && let Some((scheme, rest)) = text.split_once(' ')
                && scheme.eq_ignore_ascii_case("basic")
                && let Ok(decoded) = STANDARD.decode(rest)
            {
                return contains_placeholder_tag(&decoded);
            }
            false
        }
    }
}

/// Whether raw or percent-decoded query parameter names or values carry the
/// `cwp1_` placeholder tag (matching `marked_encoded` in `token_host.rs`).
pub(super) fn query_carries_placeholder_tag(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    contains_placeholder_tag(query.as_bytes())
        || url::form_urlencoded::parse(query.as_bytes()).any(|(name, value)| {
            contains_placeholder_tag(name.as_bytes()) || contains_placeholder_tag(value.as_bytes())
        })
}

/// Whether any decoded query parameter carries a Google API credential
/// parameter (`key` or `access_token`), which conflicts with a swapped header.
pub(super) fn query_has_google_credential_param(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| {
            name.eq_ignore_ascii_case("key") || name.eq_ignore_ascii_case("access_token")
        })
    })
}

/// The placeholder `value` carries in one of the swap shapes admitted for
/// `(carrier, name)`.
fn swap_shape_for(
    carrier: SwapCarrier,
    name: &HeaderName,
    value: &[u8],
) -> Option<CredentialPlaceholder> {
    let value = std::str::from_utf8(value).ok()?;
    let candidate = match carrier {
        SwapCarrier::GeminiApiKey => {
            if name.as_str() == "x-goog-api-key" {
                value.to_owned()
            } else {
                return None;
            }
        }
        SwapCarrier::AntigravityBearer => {
            if *name == header::AUTHORIZATION
                && let Some((scheme, rest)) = value.split_once(' ')
                && scheme.eq_ignore_ascii_case("bearer")
            {
                rest.to_owned()
            } else {
                return None;
            }
        }
        SwapCarrier::Standard => {
            if *name == header::AUTHORIZATION {
                match value.split_once(' ') {
                    None => value.to_owned(),
                    // Exactly one space after the scheme, as RFC 9110 writes it; a
                    // value with more is not a swap shape and is forwarded untouched.
                    Some((scheme, rest)) => {
                        if scheme.eq_ignore_ascii_case("bearer")
                            || scheme.eq_ignore_ascii_case("token")
                        {
                            rest.to_owned()
                        } else if scheme.eq_ignore_ascii_case("basic") {
                            let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
                            decoded.split_once(':')?.1.to_owned()
                        } else {
                            return None;
                        }
                    }
                }
            } else if name.as_str() == "x-api-key" {
                value.to_owned()
            } else {
                return None;
            }
        }
    };
    CredentialPlaceholder::looks_like(&candidate)
        .then(|| CredentialPlaceholder::parse(&candidate).ok())
        .flatten()
}

/// A forwarded reply's body as it came, bounded at `max_bytes`. Nothing of
/// ours was injected, so there is nothing to redact.
pub(super) fn forwarded_body(upstream: BrokerUpstreamBody, max_bytes: usize) -> BrokerResponseBody {
    Box::pin(Bounded {
        upstream,
        remaining: max_bytes,
        finished: false,
    })
}

struct Bounded {
    upstream: BrokerUpstreamBody,
    remaining: usize,
    finished: bool,
}

impl Stream for Bounded {
    type Item = Result<Bytes, BrokerRequestError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        if self.finished {
            return Poll::Ready(None);
        }
        match self.upstream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(chunk))) => match self.remaining.checked_sub(chunk.len()) {
                Some(remaining) => {
                    self.remaining = remaining;
                    Poll::Ready(Some(Ok(chunk)))
                }
                None => {
                    self.finished = true;
                    Poll::Ready(Some(Err(BrokerRequestError::ResponseTooLarge)))
                }
            },
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                Poll::Ready(Some(Err(map_upstream_error(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests;
