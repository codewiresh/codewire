use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, header},
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use codewire_server_core::auth::{SESSION_COOKIE_NAME, session_cookie};
use rand::{RngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use url::Url;

use crate::state::AppState;

const CSRF_COOKIE_NAME: &str = "codewire_ssr_csrf";
const LEGACY_CSRF_COOKIE_NAME: &str = "codewire_csrf";
const CSRF_TOKEN_BYTES: usize = 32;
const GITHUB_APP_AUTHORIZATION_COOKIE: &str = "codewire_github_app_authorization";
const GITHUB_APP_AUTHORIZATION_PATH: &str = "/api/v1/github/oauth/";
const GITHUB_APP_COOKIE_VERSION: u8 = 1;
const GITHUB_APP_NAVIGATION_COOKIE_VERSION: u8 = 2;
const GITHUB_APP_RECONNECT_ID_BYTES: usize = 36;
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

/// Browser-bound state for a GitHub App redirect.  The state itself is opaque
/// to GitHub; the host-only Lax cookie binds it to the exact Codewire session
/// and, when reconnecting, carries only an already fenced credential handle.
pub(crate) struct GitHubAppAuthorizationContinuation {
    pub(crate) credential_id: Option<String>,
    pub(crate) expected_generation: Option<u64>,
    pub(crate) navigation: Option<GitHubAppNavigation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitHubAppNavigation {
    pub(crate) organization_id: String,
    pub(crate) draft_id: Option<String>,
}

// Navigation tail layout: version, organization length, organization bytes,
// draft flag, then an optional canonical draft ID. Organization IDs are opaque
// (currently 32 hex bytes), so their length is explicit and bounded.
const GITHUB_APP_NAVIGATION_LAYOUT_VERSION: u8 = 2;
const GITHUB_APP_NAVIGATION_ORGANIZATION_MAX_BYTES: usize = 128;
const GITHUB_APP_NAVIGATION_DRAFT_BYTES: usize = 36;
const GITHUB_APP_NAVIGATION_MAX_BYTES: usize =
    3 + GITHUB_APP_NAVIGATION_ORGANIZATION_MAX_BYTES + GITHUB_APP_NAVIGATION_DRAFT_BYTES;
const GITHUB_APP_NAVIGATION_MAX_ENCODED: usize = (GITHUB_APP_NAVIGATION_MAX_BYTES * 4).div_ceil(3);

impl GitHubAppNavigation {
    fn encode(&self) -> Option<String> {
        if !crate::environment_drafts::organization_id(&self.organization_id)
            || self
                .draft_id
                .as_deref()
                .is_some_and(|id| !crate::environment_drafts::canonical_id(id))
        {
            return None;
        }
        let organization = self.organization_id.as_bytes();
        let mut bytes = Vec::with_capacity(GITHUB_APP_NAVIGATION_MAX_BYTES);
        bytes.push(GITHUB_APP_NAVIGATION_LAYOUT_VERSION);
        bytes.push(u8::try_from(organization.len()).ok()?);
        bytes.extend_from_slice(organization);
        bytes.push(u8::from(self.draft_id.is_some()));
        if let Some(id) = &self.draft_id {
            bytes.extend_from_slice(id.as_bytes());
        }
        Some(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn decode(encoded: &str) -> Option<Self> {
        // Bound the untrusted tail before decoding it.
        if encoded.len() > GITHUB_APP_NAVIGATION_MAX_ENCODED {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let (&version, rest) = bytes.split_first()?;
        let (&length, rest) = rest.split_first()?;
        let length = usize::from(length);
        if version != GITHUB_APP_NAVIGATION_LAYOUT_VERSION
            || length > GITHUB_APP_NAVIGATION_ORGANIZATION_MAX_BYTES
            || rest.len() <= length
        {
            return None;
        }
        let (organization, rest) = rest.split_at(length);
        let organization_id = std::str::from_utf8(organization).ok()?;
        if !crate::environment_drafts::organization_id(organization_id) {
            return None;
        }
        let draft_id = match rest {
            [0] => None,
            [1, id @ ..] if id.len() == GITHUB_APP_NAVIGATION_DRAFT_BYTES => {
                let id = std::str::from_utf8(id).ok()?;
                if !crate::environment_drafts::canonical_id(id) {
                    return None;
                }
                Some(id.into())
            }
            _ => return None,
        };
        Some(Self {
            organization_id: organization_id.into(),
            draft_id,
        })
    }
}

pub(crate) fn github_app_authorization_cookie(
    public_origin: &str,
    state: &str,
    session: &HeaderValue,
    credential_id: Option<&str>,
    expected_generation: Option<u64>,
    navigation: Option<&GitHubAppNavigation>,
) -> Option<String> {
    let state = decode_fixed_state(state)?;
    let reconnect = match (credential_id, expected_generation) {
        (None, None) => None,
        (Some(id), Some(generation)) if generation > 0 && valid_reconnect_id(id) => {
            Some((id, generation))
        }
        _ => return None,
    };
    let mut bytes = Vec::with_capacity(
        1 + CSRF_TOKEN_BYTES + 32 + 1 + reconnect.map_or(0, |_| GITHUB_APP_RECONNECT_ID_BYTES + 8),
    );
    // Optional navigation cannot invalidate a valid authorization/reconnect.
    let navigation = navigation.and_then(GitHubAppNavigation::encode);
    bytes.push(if navigation.is_some() {
        GITHUB_APP_NAVIGATION_COOKIE_VERSION
    } else {
        GITHUB_APP_COOKIE_VERSION
    });
    bytes.extend_from_slice(&state);
    bytes.extend_from_slice(&Sha256::digest(session.as_bytes()));
    match reconnect {
        None => bytes.push(0),
        Some((id, generation)) => {
            bytes.push(1);
            bytes.extend_from_slice(id.as_bytes());
            bytes.extend_from_slice(&generation.to_be_bytes());
        }
    }
    let mut encoded = URL_SAFE_NO_PAD.encode(bytes);
    if let Some(navigation) = navigation {
        encoded.push('.');
        encoded.push_str(&navigation);
    }
    lax_scoped_secret_cookie(
        public_origin,
        GITHUB_APP_AUTHORIZATION_COOKIE,
        &encoded,
        GITHUB_APP_AUTHORIZATION_PATH,
        10 * 60,
    )
}

pub(crate) fn github_app_authorization_continuation(
    headers: &HeaderMap,
    state: &str,
    session: &HeaderValue,
) -> Option<GitHubAppAuthorizationContinuation> {
    let encoded = unique_cookie_value(headers, GITHUB_APP_AUTHORIZATION_COOKIE)?;
    let (core, navigation) = encoded
        .split_once('.')
        .map_or((encoded, None), |(core, nav)| (core, Some(nav)));
    // Only decode the independently bounded core, even when a malicious
    // navigation tail is huge or not base64. Authorization remains strict.
    if !matches!(core.len(), 88 | 147) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(core).ok()?;
    let state = decode_fixed_state(state)?;
    let fixed = 1 + CSRF_TOKEN_BYTES + 32 + 1;
    if bytes.len() != fixed && bytes.len() != fixed + GITHUB_APP_RECONNECT_ID_BYTES + 8 {
        return None;
    }
    if !matches!(
        bytes[0],
        GITHUB_APP_COOKIE_VERSION | GITHUB_APP_NAVIGATION_COOKIE_VERSION
    ) || (bytes[0] == GITHUB_APP_COOKIE_VERSION && navigation.is_some())
        || !bool::from(bytes[1..1 + CSRF_TOKEN_BYTES].ct_eq(&state))
        || !bool::from(
            bytes[1 + CSRF_TOKEN_BYTES..1 + CSRF_TOKEN_BYTES + 32]
                .ct_eq(Sha256::digest(session.as_bytes()).as_slice()),
        )
    {
        return None;
    }
    let mut continuation = match bytes[fixed - 1] {
        0 if bytes.len() == fixed => Some(GitHubAppAuthorizationContinuation {
            credential_id: None,
            expected_generation: None,
            navigation: None,
        }),
        1 if bytes.len() == fixed + GITHUB_APP_RECONNECT_ID_BYTES + 8 => {
            let id =
                std::str::from_utf8(&bytes[fixed..fixed + GITHUB_APP_RECONNECT_ID_BYTES]).ok()?;
            let generation = u64::from_be_bytes(
                bytes[fixed + GITHUB_APP_RECONNECT_ID_BYTES..]
                    .try_into()
                    .ok()?,
            );
            if generation == 0 || !valid_reconnect_id(id) {
                return None;
            }
            Some(GitHubAppAuthorizationContinuation {
                credential_id: Some(id.into()),
                expected_generation: Some(generation),
                navigation: None,
            })
        }
        _ => None,
    }?;
    if bytes[0] == GITHUB_APP_NAVIGATION_COOKIE_VERSION {
        continuation.navigation = navigation.and_then(GitHubAppNavigation::decode);
    }
    Some(continuation)
}

pub(crate) fn clear_github_app_authorization_cookie(public_origin: &str) -> String {
    lax_scoped_secret_cookie(
        public_origin,
        GITHUB_APP_AUTHORIZATION_COOKIE,
        "deleted",
        GITHUB_APP_AUTHORIZATION_PATH,
        0,
    )
    .expect("static GitHub App authorization cookie")
}

/// Installations that fell short of Codewire's permissions at the GitHub
/// connect that just completed (#2712). The callback sets it for the page it
/// redirects to; that page renders it once and clears it. Carried in this
/// HttpOnly cookie, never the URL, so no crafted link can make the page vouch
/// for an installation the person did not just connect.
const GITHUB_ACCEPT_COOKIE: &str = "codewire_github_accept";
const GITHUB_ACCEPT_PATH: &str = "/settings/credentials/";
const GITHUB_ACCEPT_SECONDS: u32 = 60;

pub(crate) fn github_accept_cookie(public_origin: &str, value: &str) -> Option<String> {
    lax_scoped_secret_cookie(
        public_origin,
        GITHUB_ACCEPT_COOKIE,
        value,
        GITHUB_ACCEPT_PATH,
        GITHUB_ACCEPT_SECONDS,
    )
}

pub(crate) fn clear_github_accept_cookie(public_origin: &str) -> String {
    lax_scoped_secret_cookie(
        public_origin,
        GITHUB_ACCEPT_COOKIE,
        "deleted",
        GITHUB_ACCEPT_PATH,
        0,
    )
    .expect("static GitHub permissions notice cookie")
}

pub(crate) fn github_accept_cookie_value(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, GITHUB_ACCEPT_COOKIE).filter(|value| *value != "deleted")
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

fn lax_scoped_secret_cookie(
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
        "{name}={value}; Path={path}; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}{secure}"
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

/// The token a server-rendered page puts in its forms: the browser's current
/// CSRF cookie when it is well formed, otherwise a fresh one. Reusing the
/// cookie keeps forms in the browser's other open tabs valid.
pub(crate) fn page_csrf_token(headers: &HeaderMap) -> String {
    well_formed_csrf_cookie(headers).map_or_else(new_csrf_token, str::to_owned)
}

fn well_formed_csrf_cookie(headers: &HeaderMap) -> Option<&str> {
    csrf_cookie_value(headers).filter(|value| decode_fixed_state(value).is_some())
}

/// Give a signed-in page read a well-formed CSRF cookie before its handler
/// runs, so every form on the page, including the shared navigation's Sign
/// Out, reads one token through [`page_csrf_token`]. Mutations are untouched:
/// they still need a submitted token matching the cookie the browser sent.
pub(crate) async fn ensure_page_csrf_cookie(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        || session_cookie(headers).is_none()
        || well_formed_csrf_cookie(headers).is_some()
    {
        return next.run(request).await;
    }
    let token = new_csrf_token();
    let cookies = std::iter::once(format!("{CSRF_COOKIE_NAME}={token}"))
        .chain(
            headers
                .get_all(header::COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|raw| raw.split(';'))
                .map(str::trim)
                .filter(|pair| {
                    !pair.is_empty()
                        && pair
                            .split_once('=')
                            .is_none_or(|(name, _)| name != CSRF_COOKIE_NAME)
                })
                .map(str::to_owned),
        )
        .collect::<Vec<_>>()
        .join("; ");
    let Ok(cookies) = HeaderValue::from_str(&cookies) else {
        return next.run(request).await;
    };
    request.headers_mut().insert(header::COOKIE, cookies);
    let response = next.run(request).await;
    let handler_set_token = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| {
            value
                .as_bytes()
                .strip_prefix(CSRF_COOKIE_NAME.as_bytes())
                .is_some_and(|rest| rest.starts_with(b"="))
        });
    if handler_set_token {
        return response;
    }
    with_csrf_cookie(response, csrf_cookie(&state.public_origin, &token))
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (candidate, value) = pair.trim().split_once('=')?;
        (candidate == name).then_some(value)
    })
}

fn unique_cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut value = None;
    for pair in raw.split(';') {
        let (candidate, candidate_value) = pair.trim().split_once('=')?;
        if candidate == name && value.replace(candidate_value).is_some() {
            return None;
        }
    }
    value
}

fn decode_fixed_state(value: &str) -> Option<[u8; CSRF_TOKEN_BYTES]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

fn valid_reconnect_id(value: &str) -> bool {
    value.len() == GITHUB_APP_RECONNECT_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
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
    fn page_tokens_reuse_a_well_formed_cookie_and_replace_anything_else() {
        let token = new_csrf_token();
        assert_eq!(page_csrf_token(&csrf_headers(&token)), token);
        for malformed in ["", "short", "not base64 !!"] {
            let replaced = page_csrf_token(&csrf_headers(malformed));
            assert_ne!(replaced, malformed);
            assert!(valid_csrf_token(&csrf_headers(&replaced), &replaced));
        }
        let fresh = page_csrf_token(&HeaderMap::new());
        assert!(valid_csrf_token(&csrf_headers(&fresh), &fresh));
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
    fn github_permissions_notice_cookie_is_short_lived_lax_and_scoped_to_the_page() {
        assert_eq!(
            github_accept_cookie("https://codewire.sh", "u.octo-user.41").unwrap(),
            "codewire_github_accept=u.octo-user.41; Path=/settings/credentials/; HttpOnly; \
             SameSite=Lax; Max-Age=60; Secure"
        );
        assert_eq!(
            clear_github_accept_cookie("https://codewire.sh"),
            "codewire_github_accept=deleted; Path=/settings/credentials/; HttpOnly; \
             SameSite=Lax; Max-Age=0; Secure"
        );
        assert!(
            github_accept_cookie("http://127.0.0.1:8090", "u.octo-user.41")
                .unwrap()
                .ends_with("Max-Age=60")
        );
        assert!(github_accept_cookie("https://codewire.sh", "u.octo;evil").is_none());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire_github_accept=o.octo-org.43"),
        );
        assert_eq!(github_accept_cookie_value(&headers), Some("o.octo-org.43"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire_github_accept=deleted"),
        );
        assert_eq!(github_accept_cookie_value(&headers), None);
    }

    #[test]
    fn github_app_state_cookie_is_lax_session_bound_and_carries_only_reconnect_fence() {
        let state = new_csrf_token();
        let session = HeaderValue::from_static("codewire.session_token=synthetic-session");
        let id = "00000000-0000-4000-8000-000000000001";
        let cookie = github_app_authorization_cookie(
            "https://dashboard.example.test",
            &state,
            &session,
            Some(id),
            Some(7),
            None,
        )
        .unwrap();
        assert!(cookie.contains("HttpOnly; SameSite=Lax; Max-Age=600; Secure"));
        assert!(!cookie.contains("Domain="));
        let value = cookie.split(';').next().unwrap();
        let headers = HeaderMap::from_iter([(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=value; {value}")).unwrap(),
        )]);
        let continuation =
            github_app_authorization_continuation(&headers, &state, &session).unwrap();
        assert_eq!(continuation.credential_id.as_deref(), Some(id));
        assert_eq!(continuation.expected_generation, Some(7));
        assert!(
            github_app_authorization_continuation(
                &headers,
                &state,
                &HeaderValue::from_static("codewire.session_token=other-session"),
            )
            .is_none()
        );
        assert_eq!(
            clear_github_app_authorization_cookie("https://dashboard.example.test"),
            "codewire_github_app_authorization=deleted; Path=/api/v1/github/oauth/; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
    }

    #[test]
    fn github_navigation_tail_cannot_change_or_repair_authorization_core() {
        let state = new_csrf_token();
        let session = HeaderValue::from_static("codewire.session_token=synthetic-session");
        let id = "00000000-0000-4000-8000-000000000001";
        // Product organization IDs are opaque 32-hex strings, not UUIDs.
        let nav = GitHubAppNavigation {
            organization_id: "6bf8d155e84c4fc5b479b17022fe41dd".into(),
            draft_id: Some("00000000-0000-4000-8000-000000000003".into()),
        };
        let headers = |value: &str| {
            HeaderMap::from_iter([(
                header::COOKIE,
                HeaderValue::from_str(&format!("{GITHUB_APP_AUTHORIZATION_COOKIE}={value}"))
                    .unwrap(),
            )])
        };
        for reconnect in [false, true] {
            let credential_id = reconnect.then_some(id);
            let generation = reconnect.then_some(7);
            let cookie = github_app_authorization_cookie(
                "https://dashboard.synthetic.invalid",
                &state,
                &session,
                credential_id,
                generation,
                Some(&nav),
            )
            .unwrap();
            let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
            let (core, tail) = value.split_once('.').unwrap();
            let continuation =
                github_app_authorization_continuation(&headers(value), &state, &session).unwrap();
            assert_eq!(continuation.navigation, Some(nav.clone()));
            let decoded = URL_SAFE_NO_PAD.decode(tail).unwrap();
            assert_eq!(&decoded[..2], &[GITHUB_APP_NAVIGATION_LAYOUT_VERSION, 32]);
            let mut bad_version = decoded.clone();
            bad_version[0] = 1;
            let mut bad_flag = decoded.clone();
            bad_flag[34] = 2;
            let mut empty_org = decoded.clone();
            empty_org[1] = 0;
            let mut overlong_org = decoded.clone();
            overlong_org[1] = 33;
            let mut delimiter_org = decoded.clone();
            delimiter_org[2] = b':';
            let mut nil_draft = decoded.clone();
            nil_draft[35..].copy_from_slice(b"00000000-0000-0000-0000-000000000000");
            let mut oversize_org = vec![GITHUB_APP_NAVIGATION_LAYOUT_VERSION, 129];
            oversize_org.extend_from_slice(&[b'a'; 129]);
            oversize_org.push(0);
            for malformed in [
                String::new(),
                "not-base64!".into(),
                format!("{tail}.extra"),
                "x".repeat(2048),
                "A".repeat(GITHUB_APP_NAVIGATION_MAX_ENCODED + 1),
                URL_SAFE_NO_PAD.encode(bad_version),
                URL_SAFE_NO_PAD.encode(bad_flag),
                URL_SAFE_NO_PAD.encode(empty_org),
                URL_SAFE_NO_PAD.encode(overlong_org),
                URL_SAFE_NO_PAD.encode(delimiter_org),
                URL_SAFE_NO_PAD.encode(nil_draft),
                URL_SAFE_NO_PAD.encode(oversize_org),
                tail[..tail.len() - 1].into(),
            ] {
                let continuation = github_app_authorization_continuation(
                    &headers(&format!("{core}.{malformed}")),
                    &state,
                    &session,
                )
                .unwrap();
                assert!(continuation.navigation.is_none());
                assert_eq!(continuation.credential_id.as_deref(), credential_id);
                assert_eq!(continuation.expected_generation, generation);
            }
            assert!(
                github_app_authorization_continuation(&headers(core), &state, &session)
                    .unwrap()
                    .navigation
                    .is_none()
            );
            let bytes = URL_SAFE_NO_PAD.decode(core).unwrap();
            for offset in [0, 1, 33, 65] {
                let mut corrupted = bytes.clone();
                corrupted[offset] = if offset == 0 {
                    3
                } else if offset == 65 {
                    2
                } else {
                    corrupted[offset] ^ 1
                };
                assert!(
                    github_app_authorization_continuation(
                        &headers(&format!("{}.{tail}", URL_SAFE_NO_PAD.encode(corrupted))),
                        &state,
                        &session
                    )
                    .is_none()
                );
            }
            if reconnect {
                let mut zero_generation = bytes.clone();
                zero_generation[102..110].fill(0);
                assert!(
                    github_app_authorization_continuation(
                        &headers(&format!(
                            "{}.{tail}",
                            URL_SAFE_NO_PAD.encode(zero_generation)
                        )),
                        &state,
                        &session
                    )
                    .is_none()
                );
                let mut malformed_id = bytes.clone();
                malformed_id[66] = b'z';
                assert!(
                    github_app_authorization_continuation(
                        &headers(&format!("{}.{tail}", URL_SAFE_NO_PAD.encode(malformed_id))),
                        &state,
                        &session
                    )
                    .is_none()
                );
            }
            assert!(
                github_app_authorization_continuation(&headers(value), &new_csrf_token(), &session)
                    .is_none()
            );
            assert!(
                github_app_authorization_continuation(
                    &headers(value),
                    &state,
                    &HeaderValue::from_static("codewire.session_token=other-session")
                )
                .is_none()
            );
            let legacy = github_app_authorization_cookie(
                "https://dashboard.synthetic.invalid",
                &state,
                &session,
                credential_id,
                generation,
                None,
            )
            .unwrap();
            let legacy_value = legacy.split(';').next().unwrap().split_once('=').unwrap().1;
            assert!(
                github_app_authorization_continuation(&headers(legacy_value), &state, &session)
                    .unwrap()
                    .navigation
                    .is_none()
            );
            assert!(
                github_app_authorization_continuation(
                    &headers(&format!("{legacy_value}.{tail}")),
                    &state,
                    &session
                )
                .is_none()
            );
            let invalid_nav = GitHubAppNavigation {
                organization_id: "organization:invalid".into(),
                ..nav.clone()
            };
            assert_eq!(
                github_app_authorization_cookie(
                    "https://dashboard.synthetic.invalid",
                    &state,
                    &session,
                    credential_id,
                    generation,
                    Some(&invalid_nav)
                ),
                Some(legacy)
            );
        }
        let org_only = GitHubAppNavigation {
            draft_id: None,
            ..nav.clone()
        };
        assert_eq!(
            GitHubAppNavigation::decode(&org_only.encode().unwrap()),
            Some(org_only)
        );
        for organization_id in [
            "00000000-0000-4000-8000-000000000002".to_owned(),
            "a".repeat(GITHUB_APP_NAVIGATION_ORGANIZATION_MAX_BYTES),
        ] {
            let bounded = GitHubAppNavigation {
                organization_id,
                ..nav.clone()
            };
            let encoded = bounded.encode().unwrap();
            assert!(encoded.len() <= GITHUB_APP_NAVIGATION_MAX_ENCODED);
            assert_eq!(GitHubAppNavigation::decode(&encoded), Some(bounded));
        }
        assert!(
            GitHubAppNavigation {
                organization_id: "a".repeat(GITHUB_APP_NAVIGATION_ORGANIZATION_MAX_BYTES + 1),
                ..nav
            }
            .encode()
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
