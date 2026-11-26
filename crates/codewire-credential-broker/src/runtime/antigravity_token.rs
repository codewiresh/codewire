//! Google OAuth token host (`oauth2.googleapis.com`), as the front door
//! intercepts it for Antigravity (#6555).
//!
//! Only `POST /token` with `grant_type=refresh_token` and `refresh_token`
//! equal to Codewire's public managed marker (`ANTIGRAVITY_MANAGED_REFRESH_TOKEN`)
//! is answered locally by the broker (after refreshing the stored sign-in if
//! within the refresh window), returning the environment's `cwp1_` placeholder,
//! `token_type: "Bearer"`, far-future `expires_in`, and the bare managed
//! refresh marker — never a real token.
//!
//! Any Codewire placeholder or managed marker anywhere else on
//! `oauth2.googleapis.com` (including `/revoke`, `/tokeninfo`, `/device/code`)
//! fails closed (`400 invalid_request`).

use codewire_access::{
    ANTIGRAVITY_MANAGED_REFRESH_TOKEN, BrokerOperationId, BrokerRouteId, CapabilitySlot,
    CredentialAuthKind, CredentialPlaceholder,
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
    BrokerRequestError, BrokerUpstreamTransport, OAuthPurpose, OpenAiBroker, ValidatedGuestRequest,
    current_unix_time, map_lease_error, validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::provider_oauth::antigravity::{GOOGLE_OAUTH_HOST, GOOGLE_TOKEN_PATH};

/// The bridge route of Antigravity's intercepted OAuth token host.
/// Only a front-door session may name it.
pub(super) const ANTIGRAVITY_TOKEN_ROUTE: &str = "antigravity-oauth-token";
const MAX_TOKEN_REQUEST_BYTES: usize = 16 * 1024;
const MAX_FORWARDED_RESPONSE_BYTES: usize = crate::antigravity::MAX_RESPONSE_BYTES;
/// Ten years: the placeholder never expires on the agent's side; the broker
/// keeps the stored sign-in fresh outside the environment.
const MANAGED_EXPIRES_IN_SECONDS: u64 = 315_360_000;
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

const OUTCOMES: Outcomes = Outcomes {
    invalid_grant: "antigravity_token_invalid_grant",
    managed_refused: "antigravity_token_managed_refused",
    forward_failed: "antigravity_token_forward_failed",
    renew_sign_in: "Codewire: this environment's Antigravity sign-in needs to be renewed",
};

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    pub(super) async fn execute_antigravity_token(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let token_endpoint = request.method == Method::POST
            && request.path == GOOGLE_TOKEN_PATH
            && request.query.is_none();
        if token_endpoint && request.body.len() > MAX_TOKEN_REQUEST_BYTES {
            tracing::debug!(outcome = "antigravity_token_invalid_request");
            return Ok(invalid_request());
        }
        let body = match token_body(&request.headers, &request.body) {
            Decoded::Json(body) => Some(body),
            Decoded::NotJson => None,
            Decoded::RepeatedKey => {
                tracing::debug!(outcome = "antigravity_token_repeated_key_refused");
                return Ok(invalid_request());
            }
        };
        if token_endpoint && body.as_ref().is_some_and(is_managed_refresh) {
            if CREDENTIAL_HEADERS
                .iter()
                .any(|name| request.headers.contains_key(name))
            {
                tracing::debug!(outcome = "antigravity_token_credential_conflict");
                return Ok(invalid_request());
            }
            return self
                .answer_antigravity_managed_refresh(request.request_id, request.slot)
                .await
                .or_else(|error| managed_failure(&OUTCOMES, error));
        }
        if encoded_body(&request.headers) {
            tracing::debug!(outcome = "antigravity_token_encoded_body_refused");
            return Ok(invalid_request());
        }
        if carries_codewire_value(&request, body.as_ref()) {
            tracing::debug!(outcome = "antigravity_token_codewire_value_refused");
            return Ok(invalid_request());
        }
        self.forward_to_token_host(GOOGLE_OAUTH_HOST, request, MAX_FORWARDED_RESPONSE_BYTES)
            .await
            .or_else(|error| forward_failure(&OUTCOMES, error))
    }

    async fn answer_antigravity_managed_refresh(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let operation = BrokerOperationId::parse(crate::antigravity::OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let route = BrokerRouteId::parse(crate::antigravity::ROUTE)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
        let lease = self
            .leases
            .lease_operation(request_id, slot.clone(), operation.clone(), route.clone())
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &slot, &operation, &route)?;
        if lease.credential_metadata().authentication_kind != CredentialAuthKind::OAuth {
            return Err(BrokerRequestError::Denied);
        }
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
        let credential = self.antigravity_oauth_credential(lease, &purpose)?;
        if credential.should_refresh(current_unix_time()?) {
            drop(credential);
            self.fresh_oauth_credential(
                request_id,
                &purpose,
                |lease| self.antigravity_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await
            .map_err(|error| passing_if_expired(error.into(), &admitted_grant))?;
        }
        Ok(managed_answer(&placeholder))
    }
}

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

fn is_form(headers: &HeaderMap) -> bool {
    let mut types = headers.get_all(header::CONTENT_TYPE).iter();
    match (types.next(), types.next()) {
        (Some(value), None) => value.to_str().is_ok_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case(FORM_CONTENT_TYPE))
        }),
        _ => false,
    }
}

fn is_managed_refresh(body: &Value) -> bool {
    let Some(body) = body.as_object() else {
        return false;
    };
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    text("grant_type") == Some("refresh_token")
        && text("refresh_token") == Some(ANTIGRAVITY_MANAGED_REFRESH_TOKEN)
        && body.get("client_id").is_none_or(Value::is_string)
        && body.get("client_secret").is_none_or(Value::is_string)
        && body.get("scope").is_none_or(Value::is_string)
}

#[derive(Serialize)]
struct ManagedAnswer<'a> {
    access_token: &'a str,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: &'static str,
}

fn managed_answer(placeholder: &CredentialPlaceholder) -> BrokerHttpResponse {
    let answer = ManagedAnswer {
        access_token: placeholder.as_str(),
        token_type: "Bearer",
        expires_in: MANAGED_EXPIRES_IN_SECONDS,
        refresh_token: ANTIGRAVITY_MANAGED_REFRESH_TOKEN,
    };
    let body = serde_json::to_vec(&answer).expect("fixed fields always serialize");
    json_response(StatusCode::OK, body)
}
