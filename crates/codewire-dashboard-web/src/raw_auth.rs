use axum::{
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_server_core::auth::SESSION_COOKIE_NAME;
use serde::{Serialize, de::DeserializeOwned};

use crate::state::AppState;

const MAX_IDENTITY_RESPONSE_BYTES: u64 = 64 * 1024;

pub(crate) struct IdentityResponse<T> {
    pub(crate) status: StatusCode,
    pub(crate) body: Option<T>,
    set_cookies: Vec<HeaderValue>,
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
    debug_assert!(path.starts_with('/'));
    let mut request = state
        .http
        .post(format!("{}{}", state.identity_origin_string, path))
        .json(&body);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
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
    // details and are never reflected into browser HTML. Successful bodies
    // are decoded directly into the route-owned contract type so this bridge
    // does not need a dynamic JSON dependency or unbounded value tree.
    let body = if status.is_success() {
        Some(response.json::<O>().await.map_err(|_| ())?)
    } else {
        None
    };
    Ok(IdentityResponse {
        status,
        body,
        set_cookies,
    })
}

pub(crate) fn forward_session_cookies<T>(
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
