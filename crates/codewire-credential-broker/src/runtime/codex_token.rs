//! Codex's token host, as the front door intercepts it (#6197).
//!
//! The front door binds `auth.openai.com` while the environment's Codex slot
//! is selected, beside `chatgpt.com`, and hands every request to it here.
//! Inside the environment Codex holds Codewire's placeholders: this
//! environment's credential placeholder as its access token, an unsigned
//! placeholder ID token, and the managed marker as its refresh token. A
//! refresh at `POST /oauth/token` that carries the marker is answered here,
//! outside the environment, and never reaches OpenAI: the access token is the
//! placeholder again, the ID token the login file's placeholder, and the
//! refresh token the marker. The stored sign-in is refreshed first, through
//! the one serialized refresh path, when its access token is within the
//! refresh window; the answer never carries a real token. Any other request,
//! on any path, a refresh with another token or another grant, is the user's
//! own and is forwarded untouched under the untouched-forward rule, which a
//! hosted broker refuses. Neither a marker nor a placeholder is ever
//! forwarded.

use codewire_access::{
    BrokerOperationId, BrokerRouteId, CODEX_MANAGED_REFRESH_TOKEN, CapabilitySlot,
    CredentialAuthKind, CredentialPlaceholder, is_managed_claude_refresh_token,
};
use http::{HeaderMap, Method, StatusCode, header};
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::swap::CREDENTIAL_HEADERS;
use super::token_host::{
    Decoded, Outcomes, carries_codewire_value, decode_body, encoded_body, forward_failure,
    invalid_request, json_response, managed_failure, passing_if_expired,
};
use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, BrokerHttpResponse, BrokerLeaseProvider,
    BrokerRequestError, BrokerUpstreamTransport, OAuthPurpose, OPENAI_OPERATION, OPENAI_ROUTE,
    OpenAiBroker, ValidatedGuestRequest, current_unix_time, map_lease_error,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::provider_oauth::{OPENAI_AUTH_HOST, OPENAI_TOKEN_PATH};

/// The largest token endpoint request body read; Codex's refresh is a few
/// hundred bytes.
const MAX_TOKEN_REQUEST_BYTES: usize = 16 * 1024;
/// The largest forwarded response, as for any forwarded OpenAI request.
const MAX_FORWARDED_RESPONSE_BYTES: usize = crate::openai::MAX_RESPONSE_BYTES;

/// The outcomes this host logs, and what Codex is told on `invalid_grant`.
const OUTCOMES: Outcomes = Outcomes {
    invalid_grant: "codex_token_invalid_grant",
    managed_refused: "codex_token_managed_refused",
    forward_failed: "codex_token_forward_failed",
    renew_sign_in: "Codewire: this environment's Codex sign-in needs to be renewed",
};

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A front-door request to Codex's token host. Every outcome is an OAuth
    /// answer (RFC 6749 section 5) Codex acts on: `invalid_grant` ends its
    /// refreshing, `temporarily_unavailable` keeps the token it has. An
    /// authority that could not be reached is no answer: that error ends the
    /// bridge epoch, as it does for any request.
    pub(super) async fn execute_codex_token(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let token_endpoint = request.method == Method::POST
            && request.path == OPENAI_TOKEN_PATH
            && request.query.is_none();
        if token_endpoint && request.body.len() > MAX_TOKEN_REQUEST_BYTES {
            tracing::debug!(outcome = "codex_token_invalid_request");
            return Ok(invalid_request());
        }
        let body = match token_body(&request.headers, &request.body) {
            Decoded::Json(body) => Some(body),
            Decoded::NotJson => None,
            Decoded::RepeatedKey => {
                tracing::debug!(outcome = "codex_token_repeated_key_refused");
                return Ok(invalid_request());
            }
        };
        if token_endpoint && body.as_ref().is_some_and(is_managed_refresh) {
            // Codex refreshes with no credential header. A managed refresh
            // that carries one mixes ours with another credential, as the
            // swap rule's conflict does, and is answered by neither.
            if CREDENTIAL_HEADERS
                .iter()
                .any(|name| request.headers.contains_key(name))
            {
                tracing::debug!(outcome = "codex_token_credential_conflict");
                return Ok(invalid_request());
            }
            return self
                .answer_codex_managed_refresh(request.request_id, request.slot)
                .await
                .or_else(|error| managed_failure(&OUTCOMES, error));
        }
        // A body in any content-encoding but identity can't be read, so it
        // can't be checked for a Codewire value: it is refused, never
        // forwarded unread.
        if encoded_body(&request.headers) {
            tracing::debug!(outcome = "codex_token_encoded_body_refused");
            return Ok(invalid_request());
        }
        if carries_codewire_value(&request, body.as_ref()) {
            tracing::debug!(outcome = "codex_token_codewire_value_refused");
            return Ok(invalid_request());
        }
        self.forward_to_token_host(OPENAI_AUTH_HOST, request, MAX_FORWARDED_RESPONSE_BYTES)
            .await
            .or_else(|error| forward_failure(&OUTCOMES, error))
    }

    /// The answer to a managed refresh, from a lease of the Codex slot's
    /// route permission: the same admission the swap rule takes for this
    /// environment's placeholder. As on Claude's token host there is no rate
    /// limit: the answer is built here, and OpenAI sees at most one exchange
    /// per credential, through the refresh journal.
    async fn answer_codex_managed_refresh(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let operation = BrokerOperationId::parse(OPENAI_OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route =
            BrokerRouteId::parse(OPENAI_ROUTE).map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(request_id, slot.clone(), operation.clone(), route.clone())
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &slot, &operation, &route)?;
        if lease.credential_metadata().authentication_kind != CredentialAuthKind::OAuth {
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
        let credential = self.codex_oauth_credential(lease, &purpose)?;
        let credential = if credential.should_refresh(current_unix_time()?) {
            drop(credential);
            self.fresh_oauth_credential(
                request_id,
                &purpose,
                |lease| self.codex_oauth_credential(lease, &purpose),
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
        // The login file's own ID token: the same allow-listed claims.
        let id_token = credential
            .placeholder_id_token()
            .map_err(|_| BrokerRequestError::Denied)?;
        drop(credential);
        Ok(managed_answer(&placeholder, &id_token))
    }
}

/// A token request's body: JSON, as the pinned Codex sends it, or a form
/// when the request says it is one. A form that repeats a name is refused
/// as JSON that repeats a key is: which value a parser takes differs.
fn token_body(headers: &HeaderMap, raw: &[u8]) -> Decoded {
    let decoded = decode_body(raw);
    if decoded != Decoded::NotJson || !is_form(headers) {
        return decoded;
    }
    let mut members = Map::new();
    for (name, value) in url::form_urlencoded::parse(raw) {
        if members
            .insert(name.into_owned(), Value::String(value.into_owned()))
            .is_some()
        {
            return Decoded::RepeatedKey;
        }
    }
    Decoded::Json(Value::Object(members))
}

/// Whether the one content type names a form body.
fn is_form(headers: &HeaderMap) -> bool {
    let mut types = headers.get_all(header::CONTENT_TYPE).iter();
    match (types.next(), types.next()) {
        (Some(value), None) => value.to_str().is_ok_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case(FORM))
        }),
        _ => false,
    }
}

const FORM: &str = "application/x-www-form-urlencoded";

/// Whether a decoded token request body is a refresh with Codewire's marker:
/// an object whose `grant_type` is `refresh_token` and whose `refresh_token`
/// is the marker, alone or with a nonce, with `client_id` a string and
/// `scope`, if present, a string. A marker in any other shape is refused as
/// a Codewire value.
fn is_managed_refresh(body: &Value) -> bool {
    let Some(body) = body.as_object() else {
        return false;
    };
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    text("grant_type") == Some("refresh_token")
        && text("refresh_token").is_some_and(|token| {
            token == CODEX_MANAGED_REFRESH_TOKEN || is_managed_claude_refresh_token(token)
        })
        && text("client_id").is_some()
        && body.get("scope").is_none_or(Value::is_string)
}

/// The members the pinned Codex reads from a refresh answer, each optional
/// to it; every one is given.
#[derive(Serialize)]
struct ManagedAnswer<'a> {
    id_token: &'a str,
    access_token: &'a str,
    refresh_token: &'static str,
}

/// The managed refresh's answer. The refresh token is the bare marker,
/// never a nonce form: the daemon knows Codex's `auth.json` as Codewire's
/// by it, and leaves a file with any other refresh token alone as the
/// user's own.
fn managed_answer(placeholder: &CredentialPlaceholder, id_token: &str) -> BrokerHttpResponse {
    let answer = ManagedAnswer {
        id_token,
        access_token: placeholder.as_str(),
        refresh_token: CODEX_MANAGED_REFRESH_TOKEN,
    };
    let body = serde_json::to_vec(&answer).expect("three strings always serialize");
    json_response(StatusCode::OK, body)
}

#[cfg(test)]
mod tests;
