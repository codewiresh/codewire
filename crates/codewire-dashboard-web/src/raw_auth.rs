use axum::{
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_server_core::auth::SESSION_COOKIE_NAME;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::state::AppState;

const MAX_IDENTITY_RESPONSE_BYTES: u64 = 64 * 1024;

pub(crate) struct IdentityResponse<T> {
    pub(crate) status: StatusCode,
    pub(crate) body: Option<T>,
    /// A failure's code, only when it is one the dashboard acts on.
    pub(crate) error_code: Option<IdentityErrorCode>,
    /// The single-use token that comes with [`IdentityErrorCode::EmailUnverified`].
    pub(crate) resend_token: Option<String>,
    set_cookies: Vec<HeaderValue>,
}

impl<T> IdentityResponse<T> {
    /// The IdP set a session cookie: a session started, changed or ended.
    pub(crate) fn changes_session(&self) -> bool {
        !self.set_cookies.is_empty()
    }
}

/// The IdP error codes a page distinguishes. Any other code, and the rest of
/// an error body, is discarded.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdentityErrorCode {
    /// The right password for an account that never verified its email.
    EmailUnverified,
}

#[derive(Deserialize)]
struct IdentityErrorBody {
    code: Option<IdentityErrorCode>,
    #[serde(default, rename = "resendToken")]
    resend_token: Option<String>,
}

/// The IdP's tokens are 32 random bytes in lowercase hex.
fn identity_token(token: String) -> Option<String> {
    (token.len() == 64
        && token
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    .then_some(token)
}

pub(crate) async fn get_json<O>(
    state: &AppState,
    path: &str,
    cookie: HeaderValue,
) -> Result<IdentityResponse<O>, ()>
where
    O: DeserializeOwned,
{
    debug_assert!(path.starts_with('/'));
    let response = state
        .http
        .get(format!("{}{}", state.identity_origin_string, path))
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| ())?;
    decode_identity_response(response).await
}

/// The sign-in providers the IdP has configured, as it last said, for the
/// sign-in and sign-up buttons. A minute's answer is kept; a failed read
/// shows no buttons and is asked again after ten seconds.
#[derive(Default)]
pub(crate) struct OAuthProvidersCache(
    tokio::sync::Mutex<Option<(std::time::Instant, std::time::Duration, Vec<&'static str>)>>,
);

const OAUTH_PROVIDERS_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const OAUTH_PROVIDERS_FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(10);
const OAUTH_PROVIDERS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The providers this dashboard knows how to show, in the IdP's order.
pub(crate) const KNOWN_OAUTH_PROVIDERS: [&str; 2] = ["github", "google"];

#[derive(serde::Deserialize)]
struct OAuthProvidersBody {
    providers: Vec<String>,
}

pub(crate) async fn oauth_providers(state: &AppState) -> Vec<&'static str> {
    let mut cached = state.oauth_providers.0.lock().await;
    if let Some((read_at, ttl, providers)) = cached.as_ref()
        && read_at.elapsed() < *ttl
    {
        return providers.clone();
    }
    let read = async {
        let response = state
            .http
            .get(format!(
                "{}/api/auth/oauth/providers",
                state.identity_origin_string
            ))
            .timeout(OAUTH_PROVIDERS_TIMEOUT)
            .send()
            .await
            .ok()?;
        decode_identity_response::<OAuthProvidersBody>(response)
            .await
            .ok()?
            .body
    };
    let (ttl, providers) = match read.await {
        Some(body) => (
            OAUTH_PROVIDERS_TTL,
            KNOWN_OAUTH_PROVIDERS
                .into_iter()
                .filter(|known| body.providers.iter().any(|provider| provider == known))
                .collect(),
        ),
        None => (OAUTH_PROVIDERS_FAILURE_TTL, Vec::new()),
    };
    *cached = Some((std::time::Instant::now(), ttl, providers.clone()));
    providers
}

pub(crate) async fn post_json<I, O>(
    state: &AppState,
    path: &str,
    cookie: Option<HeaderValue>,
    body: &I,
) -> Result<IdentityResponse<O>, ()>
where
    I: Serialize + ?Sized,
    O: DeserializeOwned,
{
    post_json_for_client(state, path, cookie, None, body).await
}

/// [`post_json`] for a call the IdP counts per client address, such as
/// sign-up (#3297). `client` is the one hop this dashboard trusts, the last
/// `X-Forwarded-For` hop the edge wrote on the browser's request, and it is
/// sent as the whole header: never the browser's chain, so no hop the browser
/// chose reaches the IdP. With no trusted hop the header is left out.
pub(crate) async fn post_json_for_client<I, O>(
    state: &AppState,
    path: &str,
    cookie: Option<HeaderValue>,
    client: Option<&str>,
    body: &I,
) -> Result<IdentityResponse<O>, ()>
where
    I: Serialize + ?Sized,
    O: DeserializeOwned,
{
    debug_assert!(path.starts_with('/'));
    let mut request = state
        .http
        .post(format!("{}{}", state.identity_origin_string, path))
        .json(&body);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(client) = client {
        request = request.header("x-forwarded-for", client);
    }
    let response = request.send().await.map_err(|_| ())?;
    decode_identity_response(response).await
}

async fn decode_identity_response<O>(response: reqwest::Response) -> Result<IdentityResponse<O>, ()>
where
    O: DeserializeOwned,
{
    if response
        .content_length()
        .is_some_and(|length| length > MAX_IDENTITY_RESPONSE_BYTES)
    {
        return Err(());
    }
    let status = response.status();
    let set_cookies = approved_session_cookies(response.headers());
    // Error bodies are deliberately discarded: they may contain internal
    // details and are never reflected into browser HTML. The exceptions are a
    // code from the fixed list above and, with `email_unverified`, its hex
    // resend token, which the IdP issues for the browser's resend button. Successful bodies are decoded directly into the
    // route-owned contract type so this bridge does not need a dynamic JSON
    // dependency or unbounded value tree.
    let (body, error_code, resend_token) = if status.is_success() {
        (
            Some(response.json::<O>().await.map_err(|_| ())?),
            None,
            None,
        )
    } else {
        match response.json::<IdentityErrorBody>().await {
            Ok(IdentityErrorBody {
                code: Some(IdentityErrorCode::EmailUnverified),
                resend_token,
            }) => (
                None,
                Some(IdentityErrorCode::EmailUnverified),
                resend_token.and_then(identity_token),
            ),
            _ => (None, None, None),
        }
    };
    Ok(IdentityResponse {
        status,
        body,
        error_code,
        resend_token,
        set_cookies,
    })
}

/// Pass the IdP's session cookie to the browser. A session that starts or
/// ends also gets a new CSRF token: forms keep one token per browser between
/// renders (#4555), and a sign-in or sign-out is where it changes hands.
pub(crate) fn forward_session_cookies<T>(
    response: Response,
    identity: &IdentityResponse<T>,
    public_origin: &str,
) -> Response {
    let mut response = append_session_cookies(response, identity);
    if identity.changes_session()
        && let Ok(rotated) = HeaderValue::from_str(&crate::security::csrf_cookie(
            public_origin,
            &crate::security::new_csrf_token(),
        ))
    {
        response.headers_mut().append(header::SET_COOKIE, rotated);
    }
    response
}

/// Pass the IdP's session cookie to the browser without a CSRF token. Only
/// for a page that renders its forms with the token it sets itself, chosen
/// with [`IdentityResponse::changes_session`].
pub(crate) fn append_session_cookies<T>(
    mut response: Response,
    identity: &IdentityResponse<T>,
) -> Response {
    for cookie in &identity.set_cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    response
}

fn approved_session_cookies(headers: &reqwest::header::HeaderMap) -> Vec<HeaderValue> {
    let prefix = format!("{SESSION_COOKIE_NAME}=");
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.starts_with(&prefix))
        .filter_map(|value| HeaderValue::from_str(value).ok())
        .collect()
}

pub(crate) fn user_message(status: StatusCode, operation: &'static str) -> &'static str {
    match (status, operation) {
        (StatusCode::UNAUTHORIZED, "sign-in") => "Email or password is incorrect.",
        (StatusCode::TOO_MANY_REQUESTS, "sign-in") => {
            "Too many sign-in attempts. Wait a few minutes and try again."
        }
        (StatusCode::CONFLICT, "sign-up") => "An account with this email already exists.",
        (StatusCode::SERVICE_UNAVAILABLE, "sign-up") => {
            "Your request was saved, but verification email delivery is temporarily unavailable. Complete the challenge and submit again shortly."
        }
        (StatusCode::BAD_REQUEST, "reset-password") => {
            "The reset link is invalid or expired, or the password does not meet the requirements."
        }
        (StatusCode::NOT_FOUND, "device") => "The device code is invalid or expired.",
        (StatusCode::BAD_REQUEST, "device") => "The device code has already been used.",
        (StatusCode::UNAUTHORIZED, "two-factor") => "The verification code is invalid.",
        (StatusCode::BAD_REQUEST, "oauth-sign-up") => {
            "Tell us what you want to build and complete the human verification."
        }
        (StatusCode::SERVICE_UNAVAILABLE, "oauth-sign-up") => {
            "Human verification is temporarily unavailable. Try again shortly."
        }
        (StatusCode::BAD_REQUEST, "two-factor-setup") => {
            "The verification code is invalid. Enter the current code from your authenticator."
        }
        _ => "The request could not be completed. Check the form and try again.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canonical_session_cookie_is_forwarded() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("unrelated=discard; Path=/"),
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "codewire.session_token=expected; Path=/; HttpOnly; SameSite=Lax",
            ),
        );
        let cookies = approved_session_cookies(&headers);
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .starts_with("codewire.session_token=")
        );
    }

    #[test]
    fn only_a_session_change_rotates_the_csrf_token() {
        let identity = |set_cookies: Vec<HeaderValue>| IdentityResponse::<()> {
            status: StatusCode::OK,
            body: None,
            error_code: None,
            resend_token: None,
            set_cookies,
        };
        let csrf_cookies = |response: &Response| {
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter(|value| value.to_str().unwrap().starts_with("codewire_ssr_csrf="))
                .count()
        };
        let origin = "https://codewire.test";
        let session = HeaderValue::from_static("codewire.session_token=new; Path=/; HttpOnly");

        let unchanged = identity(Vec::new());
        assert!(!unchanged.changes_session());
        assert_eq!(
            csrf_cookies(&forward_session_cookies(
                Response::default(),
                &unchanged,
                origin
            )),
            0
        );

        let changed = identity(vec![session.clone()]);
        assert!(changed.changes_session());
        let forwarded = forward_session_cookies(Response::default(), &changed, origin);
        assert_eq!(csrf_cookies(&forwarded), 1);
        assert_eq!(
            forwarded
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );

        // A page that renders its own token gets the session cookie alone.
        let appended = append_session_cookies(Response::default(), &changed);
        assert_eq!(csrf_cookies(&appended), 0);
        assert_eq!(appended.headers().get(header::SET_COOKIE), Some(&session));
    }

    #[test]
    fn upstream_error_bodies_are_never_used_as_user_messages() {
        assert_eq!(
            user_message(StatusCode::UNAUTHORIZED, "sign-in"),
            "Email or password is incorrect."
        );
        assert_eq!(
            user_message(StatusCode::INTERNAL_SERVER_ERROR, "sign-in"),
            "The request could not be completed. Check the form and try again."
        );
    }
}
