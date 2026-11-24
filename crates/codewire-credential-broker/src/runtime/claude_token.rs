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

use codewire_access::{
    BrokerRouteId, CapabilitySlot, CredentialAuthKind, CredentialPlaceholder,
    is_managed_claude_refresh_token, managed_claude_refresh_token,
};
use http::{Method, StatusCode};
use rand::RngCore as _;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::anthropic_route::anthropic_operation;
use super::swap::CREDENTIAL_HEADERS;
use super::token_host::{
    Decoded, Outcomes, carries_codewire_value, decode_body, encoded_body, forward_failure,
    invalid_request, json_response, managed_failure, passing_if_expired,
};
use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, BrokerHttpResponse, BrokerLeaseProvider,
    BrokerRequestError, BrokerUpstreamTransport, OAuthPurpose, OpenAiBroker, ValidatedGuestRequest,
    current_unix_time, map_lease_error, validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::provider_oauth::claude::{CLAUDE_TOKEN_HOST, CLAUDE_TOKEN_PATH};

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
/// The outcomes this host logs, and what Claude Code is told on
/// `invalid_grant`: it blanks its login, and says so.
const OUTCOMES: Outcomes = Outcomes {
    invalid_grant: "claude_token_invalid_grant",
    managed_refused: "claude_token_managed_refused",
    forward_failed: "claude_token_forward_failed",
    renew_sign_in: "Codewire: this environment's Claude sign-in needs to be renewed",
};

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
                .or_else(|error| managed_failure(&OUTCOMES, error));
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
        self.forward_to_token_host(CLAUDE_TOKEN_HOST, request, MAX_FORWARDED_RESPONSE_BYTES)
            .await
            .or_else(|error| forward_failure(&OUTCOMES, error))
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

#[cfg(test)]
mod tests;
