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

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use codewire_access::{CapabilitySlot, CredentialPlaceholder};
use futures::{Stream, StreamExt as _, stream};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use tokio::time::Instant;

use super::anthropic_route::anthropic_operation;
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestError, BrokerResponseBody,
    BrokerUpstreamBody, BrokerUpstreamRequest, BrokerUpstreamTransport, OpenAiBroker, Phase,
    ValidatedGuestRequest, map_adapter_error, map_lease_error, map_upstream_error, timing,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::anthropic::ValidatedAnthropicRequest;
use crate::transparent::without_framing;

/// How long a lease's placeholder is trusted without a new lease. A
/// placeholder-shaped value that is not this environment's is forwarded
/// without a lease while the remembered one is this fresh; a rebind takes
/// effect within the same 60 seconds (#3999).
const PLACEHOLDER_FRESH_FOR: Duration = Duration::from_secs(60);

/// Stable machine-readable code of the mixed-credential refusal.
pub(crate) const CREDENTIAL_CONFLICT_CODE: &str = "credential_conflict";

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
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers: without_framing(&headers),
                body,
                body_stream: None,
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
            forwarded_body(body, crate::anthropic::MAX_RESPONSE_BYTES),
        ))
    }
}

/// Each slot's placeholder as its last lease named it, so a value that is
/// not this environment's costs no lease while that is fresh.
#[derive(Default)]
pub(super) struct PlaceholderCache(
    Mutex<HashMap<CapabilitySlot, (Option<CredentialPlaceholder>, Instant)>>,
);

impl PlaceholderCache {
    fn known_foreign(&self, slot: &CapabilitySlot, presented: &CredentialPlaceholder) -> bool {
        let remembered = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        remembered.get(slot).is_some_and(|(ours, at)| {
            at.elapsed() < PLACEHOLDER_FRESH_FOR
                && !ours.as_ref().is_some_and(|ours| ours.ct_eq(presented))
        })
    }

    fn remember(&self, slot: &CapabilitySlot, ours: Option<&CredentialPlaceholder>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(slot.clone(), (ours.cloned(), Instant::now()));
    }
}

/// The answer to a placeholder sent beside another credential: the client
/// must send one or the other. 400 is final, so it is shown at once.
fn credential_conflict_response() -> BrokerHttpResponse {
    let body = serde_json::json!({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "code": CREDENTIAL_CONFLICT_CODE,
            "message": "This request carries the Codewire placeholder and another credential. Send only one.",
        },
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let body = Bytes::from(body.to_string());
    BrokerHttpResponse::new(
        StatusCode::BAD_REQUEST,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}

/// Headers that carry a credential. Only `authorization` and `x-api-key` can
/// carry a placeholder the broker swaps; the other two only count against a
/// placeholder sent beside them.
const CREDENTIAL_HEADERS: [HeaderName; 4] = [
    header::AUTHORIZATION,
    HeaderName::from_static("x-api-key"),
    header::PROXY_AUTHORIZATION,
    header::COOKIE,
];

/// What credential a front-door request presents.
#[derive(Debug)]
pub(super) enum Presented {
    /// One placeholder-shaped value, in a swap shape, and no other credential
    /// header. Whether it is this environment's is decided after the lease.
    Placeholder(CredentialPlaceholder),
    /// No placeholder in a swap shape: forwarded untouched, without a lease.
    Foreign,
    /// A placeholder beside another credential header, or more than one.
    Conflict,
}

impl Presented {
    pub(super) fn of(headers: &HeaderMap) -> Self {
        let mut credential_values = 0_usize;
        let mut placeholders = Vec::new();
        for name in &CREDENTIAL_HEADERS {
            for value in headers.get_all(name) {
                credential_values += 1;
                if let Some(placeholder) = swap_shape(name, value.as_bytes()) {
                    placeholders.push(placeholder);
                }
            }
        }
        match (placeholders.len(), credential_values) {
            (0, _) => Self::Foreign,
            (1, 1) => Self::Placeholder(placeholders.remove(0)),
            _ => Self::Conflict,
        }
    }
}

/// The placeholder `value` carries in one of the swap shapes for `name`.
fn swap_shape(name: &HeaderName, value: &[u8]) -> Option<CredentialPlaceholder> {
    let value = std::str::from_utf8(value).ok()?;
    let candidate = if *name == header::AUTHORIZATION {
        match value.split_once(' ') {
            None => value.to_owned(),
            Some((scheme, rest)) => {
                let rest = rest.trim_start_matches(' ');
                if scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("token") {
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
