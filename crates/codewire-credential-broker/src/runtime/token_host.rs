//! What the token hosts' rules share (#3999, #6197): Claude's
//! (`claude_token.rs`) and Codex's (`codex_token.rs`). Each answers an
//! agent's refresh that carries Codewire's managed marker and forwards the
//! user's own requests untouched, and both read a request body, find a
//! Codewire value in a request and answer in RFC 6749's shape the same way.

use bytes::Bytes;
use codewire_access::{CODEX_MANAGED_REFRESH_TOKEN, CREDENTIAL_PLACEHOLDER_TAG, DerivedGrant};
use futures::stream;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::swap::{Presented, forwarded_body};
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRequestError, BrokerUpstreamRequest,
    BrokerUpstreamTransport, OpenAiBroker, Phase, ValidatedGuestRequest, current_unix_time,
    map_upstream_error, timing,
};
use crate::transparent::{TransparentRequest, untouched_request_headers, without_framing};

/// What a token host logs for each failure, and what its agent is told when
/// its sign-in must be renewed.
pub(super) struct Outcomes {
    pub(super) invalid_grant: &'static str,
    pub(super) managed_refused: &'static str,
    pub(super) forward_failed: &'static str,
    pub(super) renew_sign_in: &'static str,
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// The user's own request, sent to the token host `host` on its own
    /// method, path and query as the environment sent it, framing aside, and
    /// its reply returned as it came, bounded at `max_response_bytes`:
    /// nothing of ours is in either. Only where the untouched-forward rule
    /// allows it.
    pub(super) async fn forward_to_token_host(
        &self,
        host: &str,
        request: ValidatedGuestRequest,
        max_response_bytes: usize,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let admitted = TransparentRequest::admit(
            &request.method,
            &request.path,
            request.query.as_deref(),
            request.headers,
            request.body,
            codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES,
        )
        .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let target = admitted
            .target(&format!("https://{host}"))
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        self.untouched_forward_allowed(&target, false)?;
        let TransparentRequest {
            method,
            headers,
            body,
            ..
        } = admitted;
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers: untouched_request_headers(&headers),
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
        Ok(BrokerHttpResponse::new(
            status,
            without_framing(&headers),
            forwarded_body(body, max_response_bytes),
        ))
    }
}

/// A request body as the token host's rule reads it.
#[derive(Debug, PartialEq)]
pub(super) enum Decoded {
    Json(Value),
    /// Not JSON: only its bytes, as sent and form-decoded, are scanned.
    NotJson,
    /// JSON that repeats a key in some object, at any depth. Parsers differ
    /// on which value wins, so a marker in the one this rule would not read
    /// could reach Claude, or decide a managed refresh: such a body is
    /// refused.
    RepeatedKey,
}

pub(super) fn decode_body(raw: &[u8]) -> Decoded {
    match serde_json::from_slice::<Unique>(raw) {
        Ok(Unique(value)) => Decoded::Json(value),
        // A visitor's own error is the only data error this parse raises.
        Err(error) if error.is_data() => Decoded::RepeatedKey,
        Err(_) => Decoded::NotJson,
    }
}

/// A JSON value with no repeated key in any object.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor).map(Unique)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without a repeated key")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(value)) = items.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(name) = members.next_key::<String>()? {
            if object.contains_key(&name) {
                return Err(de::Error::custom("a repeated key"));
            }
            let Unique(value) = members.next_value()?;
            object.insert(name, value);
        }
        Ok(Value::Object(object))
    }
}

/// Whether `headers` name a content-encoding other than identity, in any
/// `content-encoding` header or any coding listed in one.
pub(super) fn encoded_body(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .any(|value| {
            value.to_str().map_or(true, |codings| {
                codings
                    .split(',')
                    .map(str::trim)
                    .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
            })
        })
}

/// Whether a request about to be forwarded carries anything of Codewire's:
/// a placeholder in a header the swap rule reads, or the placeholder tag or
/// a managed marker anywhere in a header value, the path, the query or the
/// raw body, as sent or form-decoded, or in any decoded JSON key or string
/// of the body. Such a request fails closed.
pub(super) fn carries_codewire_value(
    request: &ValidatedGuestRequest,
    body: Option<&Value>,
) -> bool {
    fn marked(text: &[u8]) -> bool {
        [CREDENTIAL_PLACEHOLDER_TAG, CODEX_MANAGED_REFRESH_TOKEN]
            .iter()
            .any(|needle| {
                text.windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
    }
    // Percent escapes and `+` undone: neither needle has `&`, `=` or `+`.
    fn marked_encoded(text: &[u8]) -> bool {
        marked(text)
            || url::form_urlencoded::parse(text)
                .any(|(name, value)| marked(name.as_bytes()) || marked(value.as_bytes()))
    }
    fn marked_value(value: &Value) -> bool {
        match value {
            Value::String(text) => marked(text.as_bytes()),
            Value::Array(items) => items.iter().any(marked_value),
            Value::Object(members) => members
                .iter()
                .any(|(name, value)| marked(name.as_bytes()) || marked_value(value)),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    !matches!(Presented::of(&request.headers), Presented::Foreign)
        || request
            .headers
            .values()
            .any(|value| marked_encoded(value.as_bytes()))
        || marked_encoded(request.path.as_bytes())
        || request
            .query
            .as_deref()
            .is_some_and(|query| marked_encoded(query.as_bytes()))
        || marked_encoded(&request.body)
        || body.is_some_and(marked_value)
}

/// A refresh refused because the credential's deadline passed while it ran
/// (`validate_request_binding`) failed only for running out of time: the
/// next request's lease decides whether the sign-in can still be used, so
/// this one is a passing failure, not a login to drop.
pub(super) fn passing_if_expired(
    error: BrokerRequestError,
    admitted: &DerivedGrant,
) -> BrokerRequestError {
    let expired = admitted
        .expires_at_unix
        .is_some_and(|deadline| current_unix_time().is_ok_and(|now| deadline <= now));
    if error == BrokerRequestError::Denied && expired {
        BrokerRequestError::UpstreamFailed
    } else {
        error
    }
}

pub(super) fn invalid_request() -> BrokerHttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", None)
}

pub(super) fn temporarily_unavailable() -> BrokerHttpResponse {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        None,
    )
}

pub(super) fn oauth_error(
    status: StatusCode,
    error: &'static str,
    description: Option<&'static str>,
) -> BrokerHttpResponse {
    let body = match description {
        Some(description) => {
            serde_json::json!({ "error": error, "error_description": description })
        }
        None => serde_json::json!({ "error": error }),
    };
    json_response(status, body.to_string().into_bytes())
}

pub(super) fn json_response(status: StatusCode, body: Vec<u8>) -> BrokerHttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // RFC 6749 section 5.1: a token answer is never cached.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let body = Bytes::from(body);
    BrokerHttpResponse::new(
        status,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}

/// A managed refresh that could not be answered. A sign-in that needs
/// Reconnect, or that this environment may not use, is `invalid_grant`; a
/// provider that could not be reached is `temporarily_unavailable`, so the
/// agent keeps the token it has. An authority that could not be reached is
/// no answer: the error ends the bridge epoch (`request_failure_ends_epoch`).
pub(super) fn managed_failure(
    outcomes: &Outcomes,
    error: BrokerRequestError,
) -> Result<BrokerHttpResponse, BrokerRequestError> {
    let invalid_grant = matches!(
        error,
        BrokerRequestError::ReconnectRequired(_)
            | BrokerRequestError::Denied
            | BrokerRequestError::NotSelected
    );
    if invalid_grant {
        // At info: this answer makes the agent drop its login, which the
        // user sees and an operator is asked about.
        tracing::info!(outcome = outcomes.invalid_grant, error = %error);
    } else {
        tracing::debug!(outcome = outcomes.managed_refused, error = %error);
    }
    match error {
        BrokerRequestError::ReconnectRequired(_)
        | BrokerRequestError::Denied
        | BrokerRequestError::CreatorDeparted
        | BrokerRequestError::CreatorDisabled
        | BrokerRequestError::NotSelected => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some(outcomes.renew_sign_in),
        )),
        BrokerRequestError::InvalidRequest
        | BrokerRequestError::NameNotAllowed
        | BrokerRequestError::SelectedCredentialOnly => Ok(invalid_request()),
        BrokerRequestError::UpstreamFailed
        | BrokerRequestError::ResponseTooLarge
        | BrokerRequestError::RefreshRateLimited { .. } => Ok(temporarily_unavailable()),
        BrokerRequestError::AuthorityUnavailable => Err(error),
    }
}

/// A forwarded request that could not be sent. The provider was never asked, so
/// the user's login is not called invalid: a destination this environment's
/// transport does not admit, or one the network policy does not allow
/// (#5555), is refused, anything else but an unreachable authority, which a
/// forward never asks, is temporary. Never `invalid_grant`: the user's own
/// login is not Codewire's to end.
pub(super) fn forward_failure(
    outcomes: &Outcomes,
    error: BrokerRequestError,
) -> Result<BrokerHttpResponse, BrokerRequestError> {
    tracing::debug!(outcome = outcomes.forward_failed, error = %error);
    match error {
        BrokerRequestError::Denied
        | BrokerRequestError::CreatorDeparted
        | BrokerRequestError::CreatorDisabled
        | BrokerRequestError::InvalidRequest
        | BrokerRequestError::NotSelected
        | BrokerRequestError::NameNotAllowed
        | BrokerRequestError::SelectedCredentialOnly => {
            Ok(oauth_error(StatusCode::FORBIDDEN, "invalid_request", None))
        }
        BrokerRequestError::ReconnectRequired(_)
        | BrokerRequestError::UpstreamFailed
        | BrokerRequestError::ResponseTooLarge
        | BrokerRequestError::RefreshRateLimited { .. } => Ok(temporarily_unavailable()),
        BrokerRequestError::AuthorityUnavailable => Err(error),
    }
}
