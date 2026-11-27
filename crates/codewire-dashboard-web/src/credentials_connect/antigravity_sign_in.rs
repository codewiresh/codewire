//! The Antigravity sign-in's two calls (#6555). Start returns Google's
//! authorize page and a sealed handle, which the dashboard keeps in a cookie
//! and never renders. Complete returns the handle with the pasted callback URL
//! or `code#state`, and the credential service checks that the state is this
//! sign-in's before Google is contacted.

use std::time::Duration;

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    CompleteAntigravitySignInRequest, Credential, CredentialStatus, StartAntigravitySignInRequest,
};
use connectrpc::{ConnectError, ErrorCode, client::CallOptions};
use url::Url;

use super::{
    MAX_MUTATION_RESPONSE_BYTES, credential_form, get_exact_credential, invalid_metadata,
    mutation_client, unix_now, validate_credential_metadata,
};
use crate::error::codewire_reason;
use crate::state::AppState;

/// Google's fixed authorize page; the service never returns another.
const AUTHORIZE_URL_PREFIX: &str = "https://accounts.google.com/o/oauth2/auth?";
const MAX_AUTHORIZE_URL_BYTES: usize = 2048;
/// The service refuses a handle 15 minutes after its start.
const SIGN_IN_LIFETIME_SECONDS: u64 = 15 * 60;
/// A browser keeps a cookie of about 4 KiB at most, name included.
const MAX_HANDLE_BYTES: usize = 3800;
/// Bounded pasted callback URL or `code#state`, matching the broker.
const MAX_PASTE_BYTES: usize = 4096;
/// Longer than the service's own 75 s for the exchange, so the page never
/// reports a failure for a sign-in the service then stores.
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(90);

/// A started sign-in. Deliberately not Debug: the handle is kept private.
pub(crate) struct StartedAntigravitySignIn {
    pub(crate) authorize_url: String,
    pub(crate) handle: String,
    pub(crate) expires_at_unix: u64,
}

pub(crate) async fn start_antigravity_sign_in(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<StartedAntigravitySignIn, ConnectError> {
    let started = mutation_client(state, cookie)
        .start_antigravity_sign_in(StartAntigravitySignInRequest::default())
        .await?
        .into_owned();
    let started = StartedAntigravitySignIn {
        authorize_url: started.authorize_url,
        handle: started.sign_in,
        expires_at_unix: started.expires_at_unix,
    };
    if !valid_start(&started, unix_now()?) {
        return Err(invalid_metadata());
    }
    Ok(started)
}

/// The authorize page is Google's own, the handle can be a cookie value, and
/// the sign-in ends within its lifetime.
fn valid_start(started: &StartedAntigravitySignIn, now: u64) -> bool {
    started.authorize_url.starts_with(AUTHORIZE_URL_PREFIX)
        && started.authorize_url.len() <= MAX_AUTHORIZE_URL_BYTES
        && started
            .authorize_url
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        && !started.handle.is_empty()
        && started.handle.len() <= MAX_HANDLE_BYTES
        && started
            .handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && started.expires_at_unix > now
        && started.expires_at_unix <= now + SIGN_IN_LIFETIME_SECONDS
}

/// Either the callback URL (`https://antigravity.google/oauth-callback?...`)
/// carrying `code` and `state` query parameters, or `code#state`, trimmed.
pub(crate) fn pasted_antigravity_code(pasted: &str) -> Option<Vec<u8>> {
    let trimmed = pasted.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PASTE_BYTES {
        return None;
    }
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        let parsed = Url::parse(trimmed).ok()?;
        let mut has_code = false;
        let mut has_state = false;
        for (name, value) in parsed.query_pairs() {
            if name == "code" {
                if has_code || value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
                    return None;
                }
                has_code = true;
            } else if name == "state" {
                if has_state || value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
                    return None;
                }
                has_state = true;
            }
        }
        (has_code && has_state).then(|| trimmed.as_bytes().to_vec())
    } else {
        let (code, state) = trimmed.split_once('#')?;
        let valid = |part: &str| {
            !part.is_empty()
                && part.len() <= 1024
                && part.bytes().all(|byte| byte.is_ascii_graphic())
        };
        (valid(code) && valid(state)).then(|| trimmed.as_bytes().to_vec())
    }
}

/// Store the sign-in, or reconnect the exact one a row's dialog observed.
pub(crate) async fn complete_antigravity_sign_in(
    state: &AppState,
    cookie: HeaderValue,
    name: String,
    handle: String,
    code: Vec<u8>,
    reconnect: Option<(String, u64)>,
) -> Result<(), ConnectError> {
    let current = match &reconnect {
        None => None,
        Some((credential_id, generation)) => {
            let current = get_exact_credential(state, cookie.clone(), credential_id).await?;
            if current.revocation_generation != *generation
                || current.name != name
                || credential_form(&current)? != "antigravity"
            {
                return Err(ConnectError::aborted("credential metadata changed"));
            }
            Some(current)
        }
    };
    let (credential_id, expected_revocation_generation) = reconnect.unzip();
    let request = CompleteAntigravitySignInRequest {
        name: name.clone(),
        sign_in: handle,
        authorization_code: code,
        credential_id,
        expected_revocation_generation,
        ..Default::default()
    };
    let options = CallOptions::default()
        .with_timeout(COMPLETE_TIMEOUT)
        .with_max_message_size(MAX_MUTATION_RESPONSE_BYTES);
    let response = mutation_client(state, cookie)
        .complete_antigravity_sign_in_with_options(request, options)
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_sign_in_ack(&credential, &name, current.as_ref())
}

fn validate_sign_in_ack(
    credential: &Credential,
    expected_name: &str,
    current: Option<&Credential>,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    if credential_form(credential)? != "antigravity"
        || credential.name != expected_name
        || credential.status != CredentialStatus::Active
        || credential.expires_at_unix.is_some()
    {
        return Err(invalid_metadata());
    }
    let expected_generation = match current {
        None => 1,
        Some(current) if credential.id == current.id => current
            .revocation_generation
            .checked_add(1)
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or_else(invalid_metadata)?,
        Some(_) => return Err(invalid_metadata()),
    };
    if credential.revocation_generation != expected_generation {
        return Err(invalid_metadata());
    }
    Ok(())
}

/// Why Complete refused a sign-in, when the page can say what to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AntigravitySignInRefusal {
    /// The callback URL or code is not this sign-in's, or Google refused it.
    CodeRefused,
    /// The sign-in started 15 minutes ago or more.
    Expired,
}

pub(crate) fn antigravity_sign_in_refusal(
    error: &ConnectError,
) -> Option<AntigravitySignInRefusal> {
    match (codewire_reason(error).ok()??.as_str(), error.code) {
        ("CREDENTIAL_ANTIGRAVITY_SIGN_IN_CODE_INVALID", ErrorCode::InvalidArgument)
        | ("CREDENTIAL_ENROLLMENT_FAILED", ErrorCode::FailedPrecondition) => {
            Some(AntigravitySignInRefusal::CodeRefused)
        }
        ("CREDENTIAL_ANTIGRAVITY_SIGN_IN_EXPIRED", ErrorCode::FailedPrecondition) => {
            Some(AntigravitySignInRefusal::Expired)
        }
        _ => None,
    }
}
