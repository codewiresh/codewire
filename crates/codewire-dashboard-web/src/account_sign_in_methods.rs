//! Adapter for the IdP's sign-in methods (#4062): list, connect and
//! disconnect GitHub or Google for the signed-in account. Like the session
//! controls it sends only the browser's session cookie and the exact public
//! Origin, forwards no upstream diagnostics, and follows no redirect.

use axum::http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{account_sessions::valid_id, raw_auth::KNOWN_OAUTH_PROVIDERS, state::AppState};

const RESPONSE_LIMIT: usize = 16 * 1024;
/// The state cookie the IdP sets for a round trip; the callback reads it.
const STATE_COOKIE_PREFIX: &str = "codewire_oauth_state=";
const STATE_COOKIE_PATH: &str = "Path=/api/auth/oauth/";
/// The only places a link may send the browser, and the only form-action
/// sources the Account page adds.
pub(crate) const PROVIDER_AUTHORIZE_ORIGINS: [&str; 2] =
    ["https://github.com", "https://accounts.google.com"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub(crate) provider: String,
    pub(crate) account: Option<String>,
    pub(crate) linked_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Methods {
    account_id: String,
    pub(crate) providers: Vec<String>,
    pub(crate) password: bool,
    pub(crate) identities: Vec<Identity>,
}

/// A link the IdP started: where the browser goes and the state cookie it
/// must carry back.
pub(crate) struct Started {
    pub(crate) location: String,
    pub(crate) state_cookie: HeaderValue,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unauthorized,
    Forbidden,
    /// Start: the provider is unavailable. Unlink: it is not connected.
    NotFound,
    /// Start: the provider is already connected. Unlink: it is the last way
    /// to sign in.
    Conflict,
    Unavailable,
}

pub(crate) fn known_provider(value: &str) -> Option<&'static str> {
    KNOWN_OAUTH_PROVIDERS
        .into_iter()
        .find(|known| *known == value)
}

async fn bounded_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Option<T> {
    if response
        .content_length()
        .is_some_and(|length| length > RESPONSE_LIMIT as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > RESPONSE_LIMIT.saturating_sub(body.len()) {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
}

fn failure(status: StatusCode) -> Failure {
    match status {
        StatusCode::UNAUTHORIZED => Failure::Unauthorized,
        StatusCode::FORBIDDEN => Failure::Forbidden,
        StatusCode::NOT_FOUND => Failure::NotFound,
        StatusCode::CONFLICT => Failure::Conflict,
        _ => Failure::Unavailable,
    }
}

pub(crate) async fn methods(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
) -> Result<Methods, Failure> {
    if !valid_id(account_id) {
        return Err(Failure::Unavailable);
    }
    let mut url = reqwest::Url::parse(&format!(
        "{}/api/auth/oauth/identities",
        state.identity_origin_string
    ))
    .map_err(|_| Failure::Unavailable)?;
    url.query_pairs_mut().append_pair("account_id", account_id);
    let response = state
        .account_http
        .get(url)
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    if response.status() != StatusCode::OK {
        return Err(failure(response.status()));
    }
    let methods: Methods = bounded_json(response).await.ok_or(Failure::Unavailable)?;
    let valid = methods.account_id == account_id
        && methods
            .providers
            .iter()
            .all(|provider| known_provider(provider).is_some())
        && methods.identities.iter().all(|identity| {
            known_provider(&identity.provider).is_some()
                && identity
                    .account
                    .as_deref()
                    .is_none_or(|account| account.len() <= 320)
        });
    if !valid {
        return Err(Failure::Unavailable);
    }
    Ok(methods)
}

#[derive(Serialize)]
struct ProviderRequest<'a> {
    account_id: &'a str,
    provider: &'a str,
}

async fn post(
    state: &AppState,
    path: &str,
    cookie: HeaderValue,
    account_id: &str,
    provider: &str,
) -> Result<reqwest::Response, Failure> {
    if !valid_id(account_id) || known_provider(provider).is_none() {
        return Err(Failure::NotFound);
    }
    let origin = reqwest::Url::parse(&state.public_origin)
        .map_err(|_| Failure::Unavailable)?
        .origin()
        .ascii_serialization();
    let response = state
        .account_http
        .post(format!("{}{path}", state.identity_origin_string))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, origin)
        .json(&ProviderRequest {
            account_id,
            provider,
        })
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    if response.status() != StatusCode::OK {
        return Err(failure(response.status()));
    }
    Ok(response)
}

/// A provider authorize URL this page may send the browser to.
fn authorize_location(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    let origin = url.origin().ascii_serialization();
    (PROVIDER_AUTHORIZE_ORIGINS.contains(&origin.as_str()) && value.len() <= 4096)
        .then(|| url.to_string())
}

fn state_cookie(headers: &reqwest::header::HeaderMap) -> Option<HeaderValue> {
    let mut cookies = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.starts_with(STATE_COOKIE_PREFIX));
    let cookie = cookies.next()?;
    if cookies.next().is_some()
        || !cookie.contains(STATE_COOKIE_PATH)
        || !cookie.contains("HttpOnly")
    {
        return None;
    }
    HeaderValue::from_str(cookie).ok()
}

pub(crate) async fn start_link(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    provider: &str,
) -> Result<Started, Failure> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location: String,
    }
    let response = post(
        state,
        "/api/auth/oauth/identities/link",
        cookie,
        account_id,
        provider,
    )
    .await?;
    let state_cookie = state_cookie(response.headers()).ok_or(Failure::Unavailable)?;
    let body: Body = bounded_json(response).await.ok_or(Failure::Unavailable)?;
    let location = authorize_location(&body.location).ok_or(Failure::Unavailable)?;
    Ok(Started {
        location,
        state_cookie,
    })
}

pub(crate) async fn unlink(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    provider: &str,
) -> Result<(), Failure> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        provider: String,
    }
    let response = post(
        state,
        "/api/auth/oauth/identities/unlink",
        cookie,
        account_id,
        provider,
    )
    .await?;
    let body: Body = bounded_json(response).await.ok_or(Failure::Unavailable)?;
    if body.provider != provider {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_goes_only_to_a_provider_authorize_origin() {
        for allowed in [
            "https://github.com/login/oauth/authorize?state=x",
            "https://accounts.google.com/o/oauth2/v2/auth?state=x",
        ] {
            assert!(authorize_location(allowed).is_some(), "{allowed}");
        }
        for refused in [
            "http://github.com/login/oauth/authorize",
            "https://github.com.evil.example/login",
            "https://evil.example/?https://github.com",
            "/settings/",
            "javascript:alert(1)",
        ] {
            assert!(authorize_location(refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn only_one_scoped_state_cookie_is_forwarded() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("codewire.session_token=x; Path=/; HttpOnly"),
        );
        assert!(state_cookie(&headers).is_none());
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "codewire_oauth_state=abc; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure",
            ),
        );
        assert_eq!(
            state_cookie(&headers).unwrap(),
            "codewire_oauth_state=abc; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("codewire_oauth_state=def; Path=/; HttpOnly"),
        );
        assert!(state_cookie(&headers).is_none());
    }

    #[test]
    fn only_known_providers_are_named() {
        assert_eq!(known_provider("github"), Some("github"));
        assert_eq!(known_provider("google"), Some("google"));
        assert_eq!(known_provider("GitHub"), None);
        assert_eq!(known_provider("gitlab"), None);
    }
}
