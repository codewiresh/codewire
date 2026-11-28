//! The Antigravity sign-in's two calls (#6555). Start returns Google's
//! authorize page and a sealed handle, which the dashboard keeps in a cookie
//! and never renders. Complete returns the handle with the pasted raw
//! authorization code, callback URL, or `code#state`, and the credential
//! service checks state when supplied before exchanging the code with PKCE.

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
/// Bounded pasted raw authorization code, callback URL, or `code#state`,
/// matching the broker.
const MAX_PASTE_BYTES: usize = 4096;
/// Bounded authorization code or state part, matching the broker.
const MAX_CODE_BYTES: usize = 1024;
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

/// A pasted callback URL (`https://antigravity.google/oauth-callback?code=...`,
/// with optional `state`), `code#state`, or raw Google authorization code,
/// trimmed.
pub(crate) fn pasted_antigravity_code(pasted: &str) -> Option<Vec<u8>> {
    let trimmed = pasted.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PASTE_BYTES {
        return None;
    }
    if is_http_url(trimmed) {
        let parsed = Url::parse(trimmed).ok()?;
        let mut has_code = false;
        let mut has_state = false;
        for (name, value) in parsed.query_pairs() {
            if name == "code" {
                if has_code || !valid_code_part(&value) {
                    return None;
                }
                has_code = true;
            } else if name == "state" {
                if has_state || !valid_code_part(&value) {
                    return None;
                }
                has_state = true;
            }
        }
        has_code.then(|| trimmed.as_bytes().to_vec())
    } else if let Some((code, state)) = trimmed.split_once('#') {
        (valid_code_part(code) && valid_code_part(state) && !state.contains('#'))
            .then(|| trimmed.as_bytes().to_vec())
    } else {
        (!looks_like_malformed_url(trimmed) && valid_code_part(trimmed))
            .then(|| trimmed.as_bytes().to_vec())
    }
}

fn valid_code_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= MAX_CODE_BYTES
        && part.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_http_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        || bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
}

fn looks_like_malformed_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.contains("://")
        || value.contains('?')
        || bytes
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http:"))
        || bytes
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https:"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_antigravity_code_accepts_raw_code_code_hash_state_and_callback_url() {
        assert_eq!(
            pasted_antigravity_code("  4/0AanRRrt_example-code/with_slashes  \n").unwrap(),
            b"4/0AanRRrt_example-code/with_slashes"
        );
        assert_eq!(
            pasted_antigravity_code("4/0AY_synthetic_code#state_123").unwrap(),
            b"4/0AY_synthetic_code#state_123"
        );
        assert_eq!(
            pasted_antigravity_code(
                "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code&state=state_123"
            )
            .unwrap(),
            b"https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code&state=state_123"
        );
        assert_eq!(
            pasted_antigravity_code(
                "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code"
            )
            .unwrap(),
            b"https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code"
        );
    }

    #[test]
    fn pasted_antigravity_code_rejects_malformed_oversized_and_whitespace_inputs() {
        let oversized_code = "a".repeat(1025);
        let oversized_paste = format!(
            "https://antigravity.google/oauth-callback?code={}",
            "a".repeat(MAX_PASTE_BYTES)
        );
        for invalid in [
            "",
            "   ",
            "4/0AY with spaces",
            "4/0AY\ncode",
            "4/0AY\x00code",
            "4/0AY_é",
            "#state_only",
            "4/0AY#",
            "4/0AY#state1#state2",
            "https://antigravity.google/oauth-callback",
            "https://antigravity.google/oauth-callback?state=only_state",
            "https://antigravity.google/oauth-callback?code=",
            "https://antigravity.google/oauth-callback?code=4/0AY&state=",
            "https://antigravity.google/oauth-callback?code=a&code=b&state=s",
            "https://antigravity.google/oauth-callback?code=a&state=s1&state=s2",
            "https://[::1",
            "ftp://antigravity.google/oauth-callback?code=4/0AY",
            "https:antigravity.google/oauth-callback",
            "antigravity.google/oauth-callback?code=4/0AY",
            oversized_code.as_str(),
            oversized_paste.as_str(),
        ] {
            assert!(
                pasted_antigravity_code(invalid).is_none(),
                "expected refusal for {invalid:?}"
            );
        }
    }
}
