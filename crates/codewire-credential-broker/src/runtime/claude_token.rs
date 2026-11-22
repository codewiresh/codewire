//! Claude's token host, as the front door intercepts it (#3999).
//!
//! The front door binds `platform.claude.com` only while the environment's
//! Anthropic slot holds a Claude sign-in, and hands every request to it
//! here. Inside the environment Claude Code holds Codewire's placeholders:
//! this environment's credential placeholder as its access token and a
//! managed marker as its refresh token. A refresh at `POST /v1/oauth/token`
//! that carries a managed marker is answered here, outside the environment,
//! and never reaches Claude: the access token is the placeholder again, the
//! refresh token a new marker, and the scopes those the stored sign-in was
//! granted. The stored sign-in is refreshed first,
//! through the one serialized refresh path, when its access token is within
//! the refresh window. Any other request, on any path, a refresh with
//! another token or another grant, is the user's own and is forwarded
//! untouched, as the swap rule forwards a credential that is not ours.
//! Neither a marker nor a placeholder is ever forwarded.

use bytes::Bytes;
use codewire_access::{
    BrokerRouteId, CODEX_MANAGED_REFRESH_TOKEN, CREDENTIAL_PLACEHOLDER_TAG, CapabilitySlot,
    CredentialAuthKind, CredentialPlaceholder, DerivedGrant, is_managed_claude_refresh_token,
    managed_claude_refresh_token,
};
use futures::stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use rand::RngCore as _;
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::anthropic_route::anthropic_operation;
use super::swap::{CREDENTIAL_HEADERS, Presented, forwarded_body};
use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, BrokerHttpResponse, BrokerLeaseProvider,
    BrokerRequestError, BrokerUpstreamRequest, BrokerUpstreamTransport, OAuthPurpose, OpenAiBroker,
    Phase, ValidatedGuestRequest, current_unix_time, map_lease_error, map_upstream_error, timing,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::provider_oauth::claude::{CLAUDE_TOKEN_HOST, CLAUDE_TOKEN_PATH};
use crate::transparent::{TransparentRequest, without_framing};

/// The bridge route of Claude's token host. Only a front-door session may
/// name it.
pub(super) const CLAUDE_TOKEN_ROUTE: &str = "claude-oauth-token";
/// The largest token endpoint request body read; Claude Code's refresh is a
/// few hundred bytes.
const MAX_TOKEN_REQUEST_BYTES: usize = 16 * 1024;
/// The largest forwarded response, as for any forwarded Anthropic request.
const MAX_FORWARDED_RESPONSE_BYTES: usize = crate::anthropic::MAX_RESPONSE_BYTES;
/// Ten years: the placeholder never expires on the agent's side, so it does
/// not refresh again on its own clock. The broker keeps the stored sign-in
/// fresh on every request instead.
const MANAGED_EXPIRES_IN_SECONDS: u64 = 315_360_000;
/// Claude Code blanks its login on `invalid_grant`, and says so.
const RENEW_SIGN_IN: &str = "Codewire: this environment's Claude sign-in needs to be renewed";

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A front-door request to Claude's token host. Every outcome is an
    /// OAuth answer (RFC 6749 section 5) Claude Code acts on, `invalid_grant`
    /// to drop its login, `temporarily_unavailable` to keep running on the
    /// token it has, except an authority that could not be reached: that
    /// error ends the bridge epoch, as it does for any request.
    pub(super) async fn execute_claude_token(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let token_endpoint = request.method == Method::POST
            && request.path == CLAUDE_TOKEN_PATH
            && request.query.is_none();
        // Claude Code's refresh is a few hundred bytes; a larger body is
        // refused before it is parsed.
        if token_endpoint && request.body.len() > MAX_TOKEN_REQUEST_BYTES {
            tracing::debug!(outcome = "claude_token_invalid_request");
            return Ok(invalid_request());
        }
        let body = match decode_body(&request.body) {
            Decoded::Json(body) => Some(body),
            Decoded::NotJson => None,
            Decoded::RepeatedKey => {
                tracing::debug!(outcome = "claude_token_repeated_key_refused");
                return Ok(invalid_request());
            }
        };
        if token_endpoint && body.as_ref().is_some_and(is_managed_refresh) {
            // Claude Code refreshes with no credential header. A managed
            // refresh that carries one mixes ours with another credential,
            // as the swap rule's conflict does, and is answered by neither.
            if CREDENTIAL_HEADERS
                .iter()
                .any(|name| request.headers.contains_key(name))
            {
                tracing::debug!(outcome = "claude_token_credential_conflict");
                return Ok(invalid_request());
            }
            return self
                .answer_managed_refresh(request.request_id, request.slot)
                .await
                .or_else(managed_failure);
        }
        // TODO(#3999): change 7b captures an `authorization_code` exchange,
        // a `claude /login` inside the environment; until then it is the
        // user's own and is forwarded untouched like any other grant.
        // A body in any content-encoding but identity can't be read, so it
        // can't be checked for a Codewire value: it is refused, never
        // forwarded unread (#3999).
        if encoded_body(&request.headers) {
            tracing::debug!(outcome = "claude_token_encoded_body_refused");
            return Ok(invalid_request());
        }
        if carries_codewire_value(&request, body.as_ref()) {
            tracing::debug!(outcome = "claude_token_codewire_value_refused");
            return Ok(invalid_request());
        }
        self.forward_claude_token(request)
            .await
            .or_else(forward_failure)
    }

    /// The answer to a managed refresh, from a lease of the Anthropic slot's
    /// route permission: the same admission the swap rule takes for this
    /// environment's placeholder.
    ///
    /// There is no rate limit here, on purpose. The answer is built locally,
    /// and the provider sees at most one exchange per credential, through the
    /// refresh journal, however many refreshes arrive. A guest that loops
    /// costs only its own machine a lease per request. The hosted relay's
    /// per-environment bound belongs to #4001 (decided on #3999).
    async fn answer_managed_refresh(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let operation = anthropic_operation()?;
        let route = BrokerRouteId::parse(crate::anthropic::ROUTE)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(request_id, slot.clone(), operation.clone(), route.clone())
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &slot, &operation, &route)?;
        if lease.credential_metadata().authentication_kind != CredentialAuthKind::ClaudeSignIn {
            return Err(BrokerRequestError::Denied);
        }
        // The placeholder names the credential and the environment
        // generation, which a refresh never changes.
        let placeholder = lease
            .placeholder()
            .cloned()
            .ok_or(BrokerRequestError::AuthorityUnavailable)?;
        let admitted_grant = lease.grant().clone();
        let purpose = OAuthPurpose::Operation {
            slot,
            operation,
            route,
        };
        let credential = self.claude_oauth_credential(lease, &purpose)?;
        let credential = if credential.should_refresh(current_unix_time()?) {
            drop(credential);
            self.fresh_oauth_credential(
                request_id,
                &purpose,
                |lease| self.claude_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await
            .map_err(|error| passing_if_expired(error.into(), &admitted_grant))?
            .0
        } else {
            credential
        };
        // As for the login's delivery: a scope Claude adds on a refresh is
        // never handed on (#4182).
        if !crate::claude_oauth::within_sign_in_scopes(credential.scopes()) {
            return Err(BrokerRequestError::Denied);
        }
        let scope = credential.scopes().join(" ");
        drop(credential);
        Ok(managed_answer(&placeholder, scope))
    }

    /// The user's own request, sent to Claude's token host on its own
    /// method, path and query as the environment sent it, framing aside, and
    /// its reply returned as it came: nothing of ours is in either.
    async fn forward_claude_token(
        &self,
        request: ValidatedGuestRequest,
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
            .target(&format!("https://{CLAUDE_TOKEN_HOST}"))
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
                headers: without_framing(&headers),
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
            forwarded_body(body, MAX_FORWARDED_RESPONSE_BYTES),
        ))
    }
}

/// A request body as the token host's rule reads it.
#[derive(Debug, PartialEq)]
enum Decoded {
    Json(Value),
    /// Not JSON: only its bytes, as sent and form-decoded, are scanned.
    NotJson,
    /// JSON that repeats a key in some object, at any depth. Parsers differ
    /// on which value wins, so a marker in the one this rule would not read
    /// could reach Claude, or decide a managed refresh: such a body is
    /// refused.
    RepeatedKey,
}

fn decode_body(raw: &[u8]) -> Decoded {
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

/// Whether a decoded token request body is a refresh with Codewire's marker:
/// a JSON object whose `grant_type` is `refresh_token` and whose
/// `refresh_token` is a managed marker, with `client_id` a string and
/// `scope`, if present, a string. Any requested scope is accepted; the answer
/// never repeats it. A marker in any other shape is refused as a Codewire
/// value.
fn is_managed_refresh(body: &Value) -> bool {
    let Some(body) = body.as_object() else {
        return false;
    };
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    text("grant_type") == Some("refresh_token")
        && text("refresh_token").is_some_and(is_managed_claude_refresh_token)
        && text("client_id").is_some()
        && body.get("scope").is_none_or(Value::is_string)
}

/// Whether a request about to be forwarded carries anything of Codewire's:
/// a placeholder in a header the swap rule reads, or the placeholder tag or
/// a managed marker anywhere in a header value, the path, the query or the
/// raw body, as sent or form-decoded, or in any decoded JSON key or string
/// of the body. Such a request fails closed.
/// Whether `headers` name a content-encoding other than identity, in any
/// `content-encoding` header or any coding listed in one.
fn encoded_body(headers: &HeaderMap) -> bool {
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

fn carries_codewire_value(request: &ValidatedGuestRequest, body: Option<&Value>) -> bool {
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

#[derive(Serialize)]
struct ManagedAnswer<'a> {
    access_token: &'a str,
    refresh_token: String,
    expires_in: u64,
    scope: String,
    token_type: &'static str,
}

/// The managed refresh's answer: exactly the members Claude Code reads.
fn managed_answer(placeholder: &CredentialPlaceholder, scope: String) -> BrokerHttpResponse {
    let mut nonce = [0_u8; codewire_access::CLAUDE_MANAGED_REFRESH_NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let answer = ManagedAnswer {
        // Never rotated per answer: Claude Code 2.1.308 that is handed a
        // different access token on each refresh retries with backoff for
        // 90 s and more instead of failing fast (#3999, observed on
        // 2026-11-15). The binding placeholder is stable.
        access_token: placeholder.as_str(),
        // A fresh marker each time: Claude Code remembers a refused refresh
        // token as dead for the life of its process.
        refresh_token: managed_claude_refresh_token(nonce),
        expires_in: MANAGED_EXPIRES_IN_SECONDS,
        scope,
        token_type: "Bearer",
    };
    let body = serde_json::to_vec(&answer).expect("strings and an integer always serialize");
    json_response(StatusCode::OK, body)
}

/// A refresh refused because the credential's deadline passed while it ran
/// (`validate_request_binding`) failed only for running out of time: the
/// next request's lease decides whether the sign-in can still be used, so
/// this one is a passing failure, not a login to drop.
fn passing_if_expired(error: BrokerRequestError, admitted: &DerivedGrant) -> BrokerRequestError {
    let expired = admitted
        .expires_at_unix
        .is_some_and(|deadline| current_unix_time().is_ok_and(|now| deadline <= now));
    if error == BrokerRequestError::Denied && expired {
        BrokerRequestError::UpstreamFailed
    } else {
        error
    }
}

/// A managed refresh that could not be answered. A sign-in that needs
/// Reconnect, or that this environment may not use, is `invalid_grant`; a
/// provider that could not be reached is `temporarily_unavailable`, so the
/// agent keeps the token it has. An authority that could not be reached is
/// no answer: the error ends the bridge epoch (`request_failure_ends_epoch`).
fn managed_failure(error: BrokerRequestError) -> Result<BrokerHttpResponse, BrokerRequestError> {
    let invalid_grant = matches!(
        error,
        BrokerRequestError::ReconnectRequired(_)
            | BrokerRequestError::Denied
            | BrokerRequestError::NotSelected
    );
    if invalid_grant {
        // At info: this answer makes Claude Code drop its login, which the
        // user sees and an operator is asked about.
        tracing::info!(outcome = "claude_token_invalid_grant", error = %error);
    } else {
        tracing::debug!(outcome = "claude_token_managed_refused", error = %error);
    }
    match error {
        BrokerRequestError::ReconnectRequired(_)
        | BrokerRequestError::Denied
        | BrokerRequestError::NotSelected => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some(RENEW_SIGN_IN),
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

/// A forwarded request that could not be sent. Claude was never asked, so
/// the user's login is not called invalid: a destination this environment's
/// transport does not admit, or one the network policy does not allow
/// (#5555), is refused, anything else but an unreachable authority, which a
/// forward never asks, is temporary. Never `invalid_grant`: the user's own
/// login is not Codewire's to end.
fn forward_failure(error: BrokerRequestError) -> Result<BrokerHttpResponse, BrokerRequestError> {
    tracing::debug!(outcome = "claude_token_forward_failed", error = %error);
    match error {
        BrokerRequestError::Denied
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

fn invalid_request() -> BrokerHttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", None)
}

fn temporarily_unavailable() -> BrokerHttpResponse {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        None,
    )
}

fn oauth_error(
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

fn json_response(status: StatusCode, body: Vec<u8>) -> BrokerHttpResponse {
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

#[cfg(test)]
mod tests;
