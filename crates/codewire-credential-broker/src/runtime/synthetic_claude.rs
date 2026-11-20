//! The featured smoke build's synthetic Claude sign-in (#5374).
//!
//! `SyntheticOpenAiSmokeTransport` sends here every request to Claude's token
//! endpoint and OAuth profile, and the Anthropic model calls that carry a
//! sign-in's access token. Nothing here is forwarded: a request this module
//! does not answer is refused, and the transport it belongs to opens no
//! connection at all. A release never compiles it (`NON_SHIPPING_INPUTS` in
//! `scripts/ci/release/cw_release.py`).
//!
//! The tokens are synthetic, and each one is unique: a fixed prefix, this
//! boot's id, which the smoke's canary scan searches for, and 16 hex
//! characters from the OS random generator. Only tokens of that shape are
//! accepted, so a real sign-in pasted into the featured build is refused,
//! never sent anywhere. The boot id is read only for the code exchange, in
//! the CLI: the broker's Landlock domain denies the read, so a refresh's
//! tokens carry the presented token's boot id, and the broker checks a
//! token's shape alone, as it checks the API-key canary's. Every other
//! request is classified without the boot id at all.
//! A refresh token is spent once in this process: the
//! same one presented again is refused, as Claude refuses a reused one. The
//! record is this process's memory alone. The code exchange runs in the CLI
//! and refreshes in the broker, so a new broker accepts the stored refresh
//! token once more; a file both could read would be a host path the
//! featured build trusts, which it must not have. A
//! refresh answers only after [`REFRESH_DELAY`], so a smoke can stop the
//! credential authority while one is in flight. No token is logged.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rand::RngCore as _;
use serde_json::{Value, json};

use super::{BrokerUpstreamError, BrokerUpstreamResponse};
use crate::provider_oauth::claude::{
    CLAUDE_MANUAL_REDIRECT_URL, CLAUDE_OAUTH_CLIENT_ID, CLAUDE_PROFILE_URL, CLAUDE_SIGN_IN_SCOPES,
    CLAUDE_TOKEN_URL,
};

/// The access and refresh tokens' fixed prefixes, in Claude's own token
/// forms; the boot id and 16 random hex characters follow.
pub(super) const ACCESS_PREFIX: &str = "sk-ant-oat01-cwlocalclaude";
pub(super) const REFRESH_PREFIX: &str = "sk-ant-ort01-cwlocalclauderefresh";
/// The one code the synthetic authorize page "shows"; a smoke pastes
/// `synthetic-smoke#<state>`.
pub(super) const SIGN_IN_CODE: &str = "synthetic-smoke";
/// How long a refresh takes to answer. Only the refresh grant waits. The
/// first refresh happens while the broker delivers the sign-in to the guest,
/// whose login request lasts 20 s (`LOGIN_REQUEST_LIFETIME` in
/// `codewire-credential-bridge`), so the delay stays well inside that.
pub(super) const REFRESH_DELAY: Duration = Duration::from_secs(10);
/// The first access token lasts just past the broker's refresh margin, so its
/// first use refreshes it; a refreshed one lasts a working day.
const FIRST_LIFETIME_SECONDS: u64 = 301;
const REFRESHED_LIFETIME_SECONDS: u64 = 8 * 60 * 60;
const MAX_BODY_BYTES: usize = 64 * 1024;
/// The beta flag every sign-in request to the model API carries.
const OAUTH_BETA: &str = "oauth-2025-04-20";

/// The refresh tokens this process has accepted once.
static SPENT_REFRESH_TOKENS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// What this module makes of one request: an answer, a model call to serve
/// with the sign-in's access token, or nothing of Claude's sign-in at all.
pub(super) enum Classified {
    Answer(BrokerUpstreamResponse),
    ModelCall(String),
    Unrelated,
}

/// The token endpoint and profile are answered here; any other request to
/// the token host is refused. A model call that carries a sign-in's bearer
/// is admitted only with a synthetic access token. `boot` reads this boot's
/// id, and is called only for the code exchange.
pub(super) async fn classify(
    method: &Method,
    target: &url::Url,
    headers: &HeaderMap,
    body: &[u8],
    boot: impl FnOnce() -> Result<String, BrokerUpstreamError>,
) -> Result<Classified, BrokerUpstreamError> {
    if target.host_str() == Some(crate::provider_oauth::claude::CLAUDE_TOKEN_HOST) {
        if *method != Method::POST || target.as_str() != CLAUDE_TOKEN_URL {
            return Err(BrokerUpstreamError::Protocol);
        }
        return token(headers, body, boot).await.map(Classified::Answer);
    }
    if target.as_str() == CLAUDE_PROFILE_URL {
        if *method != Method::GET || !body.is_empty() {
            return Err(BrokerUpstreamError::Protocol);
        }
        bearer(headers)
            .filter(|token| issued(token, ACCESS_PREFIX).is_some())
            .ok_or(BrokerUpstreamError::Protocol)?;
        return Ok(Classified::Answer(json_answer(
            StatusCode::OK,
            &json!({
                "account": {"email": "native-smoke-claude@example.test"},
                "organization": {"organization_type": "claude_max",
                                 "rate_limit_tier": "default_claude_max_20x"},
            }),
        )));
    }
    if target.host_str() == Some("api.anthropic.com") && headers.contains_key("authorization") {
        let token = bearer(headers)
            .filter(|token| issued(token, ACCESS_PREFIX).is_some())
            .ok_or(BrokerUpstreamError::Protocol)?;
        let beta = headers
            .get("anthropic-beta")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|flag| flag.trim() == OAUTH_BETA));
        if !beta || headers.contains_key("x-api-key") {
            return Err(BrokerUpstreamError::Protocol);
        }
        return Ok(Classified::ModelCall(token.to_owned()));
    }
    Ok(Classified::Unrelated)
}

/// The token endpoint: the sign-in's code exchange and its refreshes.
async fn token(
    headers: &HeaderMap,
    body: &[u8],
    boot: impl FnOnce() -> Result<String, BrokerUpstreamError>,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    if headers.get("content-type").map(HeaderValue::as_bytes) != Some(b"application/json")
        || body.len() > MAX_BODY_BYTES
    {
        return Err(BrokerUpstreamError::Protocol);
    }
    let request: Value = serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
    let text = |field: &str| request.get(field).and_then(Value::as_str);
    let random = |field: &str| {
        text(field).is_some_and(|value| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    };
    let scopes = CLAUDE_SIGN_IN_SCOPES.join(" ");
    if text("client_id") != Some(CLAUDE_OAUTH_CLIENT_ID) {
        return Ok(refused());
    }
    let (lifetime, boot) = match text("grant_type") {
        Some("authorization_code")
            if text("code") == Some(SIGN_IN_CODE)
                && text("redirect_uri") == Some(CLAUDE_MANUAL_REDIRECT_URL)
                && random("code_verifier")
                && random("state") =>
        {
            (FIRST_LIFETIME_SECONDS, boot()?)
        }
        Some("refresh_token") if text("scope") == Some(scopes.as_str()) => {
            let Some((presented, boot)) = text("refresh_token")
                .and_then(|token| Some((token, issued(token, REFRESH_PREFIX)?)))
            else {
                return Ok(refused());
            };
            let first_use = SPENT_REFRESH_TOKENS
                .lock()
                .map_err(|_| BrokerUpstreamError::Protocol)?
                .insert(presented.to_owned());
            if !first_use {
                return Ok(refused());
            }
            tokio::time::sleep(REFRESH_DELAY).await;
            (REFRESHED_LIFETIME_SECONDS, boot.to_owned())
        }
        _ => return Ok(refused()),
    };
    Ok(json_answer(
        StatusCode::OK,
        &json!({
            "token_type": "Bearer",
            "access_token": mint(ACCESS_PREFIX, &boot),
            "refresh_token": mint(REFRESH_PREFIX, &boot),
            "expires_in": lifetime,
            "scope": scopes,
        }),
    ))
}

/// Claude's answer to a grant it does not accept.
fn refused() -> BrokerUpstreamResponse {
    json_answer(
        StatusCode::BAD_REQUEST,
        &json!({"error": "invalid_grant", "error_description": "Synthetic smoke refusal"}),
    )
}

fn json_answer(status: StatusCode, value: &Value) -> BrokerUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    let body = Bytes::from(value.to_string());
    BrokerUpstreamResponse::new(status, headers, Box::pin(stream::iter([Ok(body)])))
}

/// A new token: `prefix`, this boot's id and 16 random hex characters.
fn mint(prefix: &str, boot: &str) -> String {
    let mut random = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let random: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}{boot}{random}")
}

/// The boot id of a token this module mints: `prefix`, a 32-character boot
/// id and 16 random characters, all lowercase hex, and nothing else.
pub(super) fn issued<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = token.strip_prefix(prefix)?;
    let hex = |value: &str| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    (rest.len() == 32 + 16 && hex(rest)).then(|| &rest[..32])
}

/// The one `Bearer` value of a request's single `authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.strip_prefix("Bearer ")
}
