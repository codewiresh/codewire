use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use codewire_server_core::auth::{SESSION_COOKIE_NAME, session_cookie};
use rand::{RngCore as _, rngs::OsRng};
use subtle::ConstantTimeEq as _;
use url::Url;

const CSRF_COOKIE_NAME: &str = "codewire_ssr_csrf";
const LEGACY_CSRF_COOKIE_NAME: &str = "codewire_csrf";
const CSRF_TOKEN_BYTES: usize = 32;
pub(crate) const TWO_FACTOR_CHALLENGE_COOKIE: &str = "codewire_2fa_challenge";
pub(crate) const PASSWORD_RESET_COOKIE: &str = "codewire_password_reset";

pub(crate) fn canonical_cookie(headers: &HeaderMap) -> Result<HeaderValue, ()> {
    let token = session_cookie(headers).ok_or(())?;
    HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={token}")).map_err(|_| ())
}

pub(crate) fn new_csrf_token() -> String {
    let mut token = [0_u8; CSRF_TOKEN_BYTES];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}

pub(crate) fn csrf_cookie(public_origin: &str, token: &str) -> String {
    let secure = if public_origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    // The same host-only token protects every server-rendered form. Keeping
    // the path at / lets later route modules share this boundary without
    // weakening SameSite or origin enforcement.
    format!("{CSRF_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict{secure}")
}

pub(crate) fn scoped_secret_cookie(
    public_origin: &str,
    name: &str,
    value: &str,
    path: &str,
    max_age_seconds: u32,
) -> Option<String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',' | b' '))
    {
        return None;
    }
    let secure = if public_origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    Some(format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Strict; Max-Age={max_age_seconds}{secure}"
    ))
}

pub(crate) fn clear_scoped_cookie(public_origin: &str, name: &str, path: &str) -> String {
    let secure = if public_origin.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{name}=; Path={path}; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
}

pub(crate) fn with_response_cookie(mut response: Response, cookie: String) -> Response {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(crate) fn with_csrf_cookie(mut response: Response, cookie: String) -> Response {
    let secure = if cookie.ends_with("; Secure") {
        "; Secure"
    } else {
        ""
    };
    for cookie in [
        cookie,
        format!(
            "{LEGACY_CSRF_COOKIE_NAME}=; Path=/dashboard; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
        ),
        format!("{LEGACY_CSRF_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"),
    ] {
        response = with_response_cookie(response, cookie);
    }
    response
}

pub(crate) fn request_has_same_origin(headers: &HeaderMap, public_origin: &str) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin.to_str().ok() == Some(public_origin);
    }
    headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .is_some_and(|url| url.origin().ascii_serialization() == public_origin)
}

pub(crate) fn valid_csrf_token(headers: &HeaderMap, submitted: &str) -> bool {
    let Some(cookie) = cookie_value(headers, CSRF_COOKIE_NAME) else {
        return false;
    };
    let (Ok(cookie), Ok(submitted)) = (
        URL_SAFE_NO_PAD.decode(cookie),
        URL_SAFE_NO_PAD.decode(submitted),
    ) else {
        return false;
    };
    let (Ok(cookie), Ok(submitted)): (
        Result<[u8; CSRF_TOKEN_BYTES], _>,
        Result<[u8; CSRF_TOKEN_BYTES], _>,
    ) = (cookie.try_into(), submitted.try_into()) else {
        return false;
    };
    bool::from(cookie.ct_eq(&submitted))
}

pub(crate) fn csrf_cookie_value(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, CSRF_COOKIE_NAME)
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (candidate, value) = pair.trim().split_once('=')?;
        (candidate == name).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csrf_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=value; {CSRF_COOKIE_NAME}={token}"))
                .expect("valid cookie"),
        );
        headers
    }

    #[test]
    fn csrf_tokens_are_fixed_width_and_compared_to_the_cookie() {
        let token = new_csrf_token();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&token).expect("decode token").len(),
            CSRF_TOKEN_BYTES
        );

        let headers = csrf_headers(&token);
        assert!(valid_csrf_token(&headers, &token));
        assert!(!valid_csrf_token(&headers, &new_csrf_token()));
        assert!(!valid_csrf_token(&headers, "short"));
        assert!(!valid_csrf_token(&HeaderMap::new(), &token));
    }

    #[test]
    fn csrf_cookie_is_namespaced_host_only_strict_global_and_https_aware() {
        let http = csrf_cookie("http://127.0.0.1:5173", "token");
        assert_eq!(
            http,
            "codewire_ssr_csrf=token; Path=/; HttpOnly; SameSite=Strict"
        );
        assert!(!http.contains("Domain="));
        assert!(!http.contains("Secure"));

        let https = csrf_cookie("https://dashboard.example.test", "token");
        assert!(https.ends_with("; Secure"));
    }

    #[test]
    fn csrf_response_expires_both_legacy_cookie_paths() {
        let response = with_csrf_cookie(
            Response::new(axum::body::Body::empty()),
            csrf_cookie("http://127.0.0.1:8080", "token"),
        );
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 3);
        assert_eq!(
            cookies[0],
            "codewire_ssr_csrf=token; Path=/; HttpOnly; SameSite=Strict"
        );
        assert!(cookies[1].starts_with("codewire_csrf=; Path=/dashboard;"));
        assert!(cookies[2].starts_with("codewire_csrf=; Path=/;"));
    }

    #[test]
    fn sensitive_bridge_cookies_are_short_lived_host_only_and_scoped() {
        let cookie = scoped_secret_cookie(
            "https://dashboard.example.test",
            TWO_FACTOR_CHALLENGE_COOKIE,
            "opaque-token",
            "/two-factor",
            600,
        )
        .unwrap();
        assert!(cookie.contains("Path=/two-factor"));
        assert!(cookie.contains("HttpOnly; SameSite=Strict; Max-Age=600; Secure"));
        assert!(!cookie.contains("Domain="));
        assert!(
            scoped_secret_cookie(
                "https://dashboard.example.test",
                TWO_FACTOR_CHALLENGE_COOKIE,
                "bad;value",
                "/two-factor",
                600,
            )
            .is_none()
        );
    }

    #[test]
    fn form_posts_require_an_exact_same_origin_signal() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://dashboard.example.test"),
        );
        assert!(request_has_same_origin(
            &headers,
            "https://dashboard.example.test"
        ));
        assert!(!request_has_same_origin(
            &headers,
            "https://other.example.test"
        ));

        headers.remove(header::ORIGIN);
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://dashboard.example.test/organizations/new/"),
        );
        assert!(request_has_same_origin(
            &headers,
            "https://dashboard.example.test"
        ));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.example.test"),
        );
        assert!(!request_has_same_origin(
            &headers,
            "https://dashboard.example.test"
        ));
        assert!(!request_has_same_origin(
            &HeaderMap::new(),
            "https://dashboard.example.test"
        ));
    }
}
