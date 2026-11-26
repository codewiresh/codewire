//! The Claude sign-in's two calls (#4935). Start returns Claude's authorize
//! page and a sealed handle, which the dashboard keeps in a cookie and never
//! renders. Complete returns the handle with the pasted `code#state`, and the
//! credential service checks that the state is this sign-in's before Claude is
//! contacted.

use std::time::Duration;

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    CompleteClaudeSignInRequest, Credential, CredentialStatus, StartClaudeSignInRequest,
};
use connectrpc::{ConnectError, ErrorCode, client::CallOptions};

use super::{
    MAX_MUTATION_RESPONSE_BYTES, credential_form, get_exact_credential, invalid_metadata,
    mutation_client, unix_now, validate_credential_metadata,
};
use crate::error::codewire_reason;
use crate::state::AppState;

/// Claude's fixed authorize page; the service never returns another.
const AUTHORIZE_URL_PREFIX: &str = "https://claude.com/cai/oauth/authorize?";
const MAX_AUTHORIZE_URL_BYTES: usize = 2048;
/// The service refuses a handle 15 minutes after its start.
const SIGN_IN_LIFETIME_SECONDS: u64 = 15 * 60;
/// A browser keeps a cookie of about 4 KiB at most, name included.
const MAX_HANDLE_BYTES: usize = 3800;
/// Each half of `code#state`, as the CLI bounds it.
const MAX_CODE_PART_BYTES: usize = 4096;
/// Longer than the service's own 75 s for the exchange and profile read, so
/// the page never reports a failure for a sign-in the service then stores.
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(90);

/// A started sign-in. Deliberately not Debug: the handle is kept private.
pub(crate) struct StartedClaudeSignIn {
    pub(crate) authorize_url: String,
    pub(crate) handle: String,
    pub(crate) expires_at_unix: u64,
}

pub(crate) async fn start_claude_sign_in(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<StartedClaudeSignIn, ConnectError> {
    let started = mutation_client(state, cookie)
        .start_claude_sign_in(StartClaudeSignInRequest::default())
        .await?
        .into_owned();
    let started = StartedClaudeSignIn {
        authorize_url: started.authorize_url,
        handle: started.sign_in,
        expires_at_unix: started.expires_at_unix,
    };
    if !valid_start(&started, unix_now()?) {
        return Err(invalid_metadata());
    }
    Ok(started)
}

/// The authorize page is Claude's own, the handle can be a cookie value, and
/// the sign-in ends within its lifetime.
fn valid_start(started: &StartedClaudeSignIn, now: u64) -> bool {
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

/// `code#state` as Claude shows it, trimmed, or `None` for any other shape.
/// Both halves are non-empty URL-safe text, as Claude issues them.
pub(crate) fn pasted_claude_code(pasted: &str) -> Option<Vec<u8>> {
    let (code, state) = pasted.trim().split_once('#')?;
    let url_safe = |part: &str| {
        !part.is_empty()
            && part.len() <= MAX_CODE_PART_BYTES
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    };
    (url_safe(code) && url_safe(state)).then(|| format!("{code}#{state}").into_bytes())
}

/// Store the sign-in, or reconnect the exact one a row's dialog observed.
pub(crate) async fn complete_claude_sign_in(
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
                || credential_form(&current)? != "claude"
            {
                return Err(ConnectError::aborted("credential metadata changed"));
            }
            Some(current)
        }
    };
    let (credential_id, expected_revocation_generation) = reconnect.unzip();
    let request = CompleteClaudeSignInRequest {
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
        .complete_claude_sign_in_with_options(request, options)
        .await?
        .into_owned();
    let credential = response
        .credential
        .into_option()
        .ok_or_else(invalid_metadata)?;
    validate_sign_in_ack(&credential, &name, current.as_ref())
}

/// A new sign-in is an Active Claude sign-in at generation 1 with the Claude
/// account's email as its hint; a reconnect keeps its identity and name at the
/// next generation.
fn validate_sign_in_ack(
    credential: &Credential,
    expected_name: &str,
    current: Option<&Credential>,
) -> Result<(), ConnectError> {
    validate_credential_metadata(credential)?;
    if credential_form(credential)? != "claude"
        || credential.name != expected_name
        || credential.status != CredentialStatus::Active
        || credential.account_hint.as_deref().is_none_or(str::is_empty)
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
pub(crate) enum ClaudeSignInRefusal {
    /// The code is not this sign-in's, or Claude refused it.
    CodeRefused,
    /// The sign-in started 15 minutes ago or more.
    Expired,
}

/// The refusal named by the service's closed reason, or `None` for any other
/// answer, which the page treats as it treats any other addition's error.
pub(crate) fn claude_sign_in_refusal(error: &ConnectError) -> Option<ClaudeSignInRefusal> {
    match (codewire_reason(error).ok()??.as_str(), error.code) {
        ("CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID", ErrorCode::InvalidArgument)
        | ("CREDENTIAL_ENROLLMENT_FAILED", ErrorCode::FailedPrecondition) => {
            Some(ClaudeSignInRefusal::CodeRefused)
        }
        ("CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED", ErrorCode::FailedPrecondition) => {
            Some(ClaudeSignInRefusal::Expired)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
