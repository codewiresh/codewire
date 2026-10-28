//! Adapter for the IdP's fresh-proof factor controls: replacing the enrolled
//! authenticator and regenerating recovery codes.
//!
//! It forwards only the canonical session cookie and the validated public
//! Origin, never follows redirects, bounds every response, and accepts only
//! closed, well-formed success bodies. Upstream error bodies are discarded.
//! The one-time setup key and recovery codes it returns belong only in the
//! POST response page; no type here implements `Debug`.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use codewire_server_core::auth::SESSION_COOKIE_NAME;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::account_sessions::{valid_id, valid_time};
use crate::state::AppState;

const RESPONSE_LIMIT: usize = 16 * 1024;
/// Above the IdP's five-second budget, which covers every check but not its
/// commit, so a slow commit is still reported rather than called unknown.
/// This overrides the account client's shorter default for these calls only.
const FACTOR_CHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_USER_AGENT_BYTES: usize = 512;
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LENGTH: usize = 10;

pub(crate) const START_PATH: &str = "/api/auth/two-factor/replace/start";
pub(crate) const CONFIRM_PATH: &str = "/api/auth/two-factor/replace/confirm";
pub(crate) const REGENERATE_PATH: &str = "/api/auth/two-factor/recovery-codes/regenerate";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Started {
    pub(crate) replacement_id: String,
    pub(crate) totp_uri: String,
    pub(crate) secret: String,
    pub(crate) expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    backup_codes: Vec<String>,
    signed_out_sessions: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegenerateBody {
    backup_codes: Vec<String>,
}

pub(crate) struct Replaced {
    pub(crate) backup_codes: Vec<String>,
    /// The IdP's new session cookie for this browser. Every older session of
    /// the account, including the one this request used, is gone.
    pub(crate) session_cookie: Option<HeaderValue>,
}

/// Every way a factor control can fail. Each one tells the page what still
/// works; only `UnknownOutcome` leaves the result undetermined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The session is gone; sign in again.
    Unauthorized,
    /// The request did not belong to this session's account.
    Forbidden,
    /// Wrong password or code. Nothing changed.
    ProofRejected,
    /// The account is locked after repeated failures. Nothing changed.
    Locked,
    /// The account has no enrolled factor.
    NotEnrolled,
    /// The code does not match the new authenticator. Nothing changed.
    CodeRejected,
    /// The pending replacement ended after too many codes or ten minutes.
    Ended,
    /// No pending replacement belongs to this browser.
    NoLongerAvailable,
    /// The control is unavailable, including an IdP without these routes.
    /// Nothing changed.
    Unavailable,
    /// The request may have committed, but its result was not received.
    UnknownOutcome,
}

pub(crate) fn valid_secret(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

fn valid_replacement_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_recovery_codes(codes: &[String]) -> bool {
    codes.len() == RECOVERY_CODE_COUNT
        && codes.iter().all(|code| {
            code.len() == RECOVERY_CODE_LENGTH
                && code.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

impl Started {
    fn validate(&self) -> bool {
        valid_replacement_id(&self.replacement_id)
            && valid_secret(&self.secret)
            && valid_time(&self.expires_at)
            && self.totp_uri.len() <= 1024
            && self.totp_uri.starts_with("otpauth://totp/")
            && self.totp_uri.contains(&format!("secret={}", self.secret))
    }
}

async fn bounded_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > RESPONSE_LIMIT as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > RESPONSE_LIMIT.saturating_sub(body.len()) {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ())
}

/// The browser's User-Agent, which the IdP records on the audit row and on a
/// rotated session. It only describes the client and grants nothing. The
/// browser's X-Forwarded-For is deliberately not forwarded: the IdP takes the
/// first hop of that header without a trusted-proxy list, and no other
/// dashboard call to the IdP forwards it, so relaying it here would let a
/// browser choose the address the IdP records.
pub(crate) fn browser_user_agent(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut values = headers.get_all(header::USER_AGENT).iter();
    let value = values.next()?;
    if values.next().is_some() || value.len() > MAX_USER_AGENT_BYTES || value.to_str().is_err() {
        return None;
    }
    Some(value.clone())
}

fn request<I: Serialize>(
    state: &AppState,
    path: &str,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    body: &I,
) -> Result<reqwest::Request, ()> {
    let origin = reqwest::Url::parse(&state.public_origin)
        .map_err(|_| ())?
        .origin()
        .ascii_serialization();
    let mut request = state
        .account_http
        .post(format!("{}{path}", state.identity_origin_string))
        .timeout(FACTOR_CHANGE_TIMEOUT)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, origin)
        .json(body);
    if let Some(user_agent) = user_agent {
        request = request.header(header::USER_AGENT, user_agent);
    }
    request.build().map_err(|_| ())
}

async fn post<I: Serialize>(
    state: &AppState,
    path: &str,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    body: &I,
) -> Result<reqwest::Response, ()> {
    let request = request(state, path, cookie, user_agent, body)?;
    state.account_http.execute(request).await.map_err(|_| ())
}

/// A failed proof never changes anything except the shared failure counter.
fn proof_failure(status: StatusCode) -> Failure {
    match status {
        StatusCode::UNAUTHORIZED => Failure::Unauthorized,
        StatusCode::FORBIDDEN => Failure::Forbidden,
        StatusCode::CONFLICT => Failure::NotEnrolled,
        StatusCode::UNPROCESSABLE_ENTITY => Failure::ProofRejected,
        StatusCode::TOO_MANY_REQUESTS => Failure::Locked,
        _ => Failure::Unavailable,
    }
}

#[derive(Serialize)]
struct ProofRequest<'a> {
    account_id: &'a str,
    password: &'a str,
    proof: &'a str,
}

fn valid_proof_input(account_id: &str, password: &str, proof: &str) -> bool {
    valid_id(account_id)
        && !password.is_empty()
        && password.len() <= 1024
        && !proof.trim().is_empty()
        && proof.len() <= 64
}

/// Start a replacement. Nothing about the enrolled factor changes, so every
/// failure, including an unreachable IdP, leaves the current one working.
pub(crate) async fn start(
    state: &AppState,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    account_id: &str,
    password: &str,
    proof: &str,
) -> Result<Started, Failure> {
    if !valid_proof_input(account_id, password, proof) {
        return Err(Failure::ProofRejected);
    }
    let response = post(
        state,
        START_PATH,
        cookie,
        user_agent,
        &ProofRequest {
            account_id,
            password,
            proof,
        },
    )
    .await
    .map_err(|_| Failure::Unavailable)?;
    if response.status() != StatusCode::OK {
        return Err(proof_failure(response.status()));
    }
    let started: Started = bounded_json(response)
        .await
        .map_err(|_| Failure::Unavailable)?;
    if !started.validate() {
        return Err(Failure::Unavailable);
    }
    Ok(started)
}

/// Confirm a replacement with a code from the new authenticator. Only a
/// transport or upstream failure after sending can leave the swap unknown.
pub(crate) async fn confirm(
    state: &AppState,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    account_id: &str,
    replacement_id: &str,
    code: &str,
) -> Result<Replaced, Failure> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if !valid_id(account_id) || !valid_replacement_id(replacement_id) {
        return Err(Failure::NoLongerAvailable);
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::CodeRejected);
    }
    #[derive(Serialize)]
    struct Request<'a> {
        account_id: &'a str,
        replacement_id: &'a str,
        code: &'a str,
    }
    let response = post(
        state,
        CONFIRM_PATH,
        cookie,
        user_agent,
        &Request {
            account_id,
            replacement_id,
            code: &code,
        },
    )
    .await
    .map_err(|_| Failure::UnknownOutcome)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => return Err(Failure::Unauthorized),
        StatusCode::FORBIDDEN => return Err(Failure::Forbidden),
        StatusCode::NOT_FOUND => return Err(Failure::NoLongerAvailable),
        StatusCode::CONFLICT => return Err(Failure::NotEnrolled),
        StatusCode::GONE => return Err(Failure::Ended),
        StatusCode::UNPROCESSABLE_ENTITY => return Err(Failure::CodeRejected),
        _ => return Err(Failure::UnknownOutcome),
    }
    let session_cookie = approved_session_cookie(response.headers());
    let body: ConfirmBody = bounded_json(response)
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    if !valid_recovery_codes(&body.backup_codes) || body.signed_out_sessions < 0 {
        return Err(Failure::UnknownOutcome);
    }
    Ok(Replaced {
        backup_codes: body.backup_codes,
        session_cookie,
    })
}

/// Regenerate recovery codes. A lost response may have replaced them.
pub(crate) async fn regenerate(
    state: &AppState,
    cookie: HeaderValue,
    user_agent: Option<HeaderValue>,
    account_id: &str,
    password: &str,
    proof: &str,
) -> Result<Vec<String>, Failure> {
    if !valid_proof_input(account_id, password, proof) {
        return Err(Failure::ProofRejected);
    }
    let response = post(
        state,
        REGENERATE_PATH,
        cookie,
        user_agent,
        &ProofRequest {
            account_id,
            password,
            proof,
        },
    )
    .await
    .map_err(|_| Failure::UnknownOutcome)?;
    match response.status() {
        StatusCode::OK => {}
        // An IdP without this route changed nothing.
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
            return Err(Failure::Unavailable);
        }
        status if status.is_server_error() => return Err(Failure::UnknownOutcome),
        status => return Err(proof_failure(status)),
    }
    let body: RegenerateBody = bounded_json(response)
        .await
        .map_err(|_| Failure::UnknownOutcome)?;
    if !valid_recovery_codes(&body.backup_codes) {
        return Err(Failure::UnknownOutcome);
    }
    Ok(body.backup_codes)
}

/// Exactly one well-formed session cookie, or none.
fn approved_session_cookie(headers: &reqwest::header::HeaderMap) -> Option<HeaderValue> {
    let prefix = format!("{SESSION_COOKIE_NAME}=");
    let mut cookies = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.starts_with(&prefix));
    let cookie = cookies.next()?;
    if cookies.next().is_some() {
        return None;
    }
    let token = cookie[prefix.len()..].split(';').next()?;
    if token.is_empty()
        || token.len() > 256
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return None;
    }
    HeaderValue::from_str(cookie).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, extract::Request, response::Response, routing::any};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const CODES: &str = r#"["0123456789","abcdef0123","1111111111","2222222222","3333333333","4444444444","5555555555","6666666666","7777777777","8888888888"]"#;

    fn started_body() -> String {
        format!(
            r#"{{"replacement_id":"0123456789abcdef0123456789abcdef","totp_uri":"otpauth://totp/Codewire:owner%40example.test?algorithm=SHA1&digits=6&issuer=Codewire&period=30&secret={SECRET}","secret":"{SECRET}","expires_at":"2026-10-01T12:10:00Z"}}"#
        )
    }

    // A synthetic IdP, not a proxy. It answers by case number and records what
    // the adapter sent. No real identity, password or factor is loaded.
    #[tokio::test]
    async fn adapter_sends_exact_origin_and_accepts_only_closed_well_formed_results() {
        let case = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let current = case.clone();
        let requests = observed.clone();
        let router = Router::new().fallback(any(move |request: Request| {
            let case = current.load(Ordering::SeqCst);
            let requests = requests.clone();
            async move {
                assert!(!request.headers().contains_key(header::AUTHORIZATION));
                assert_eq!(
                    request.headers()[header::COOKIE],
                    "codewire.session_token=synthetic"
                );
                assert!(!request.headers().contains_key("x-forwarded-for"));
                let path = request.uri().path().to_owned();
                let origin = request.headers().get(header::ORIGIN).cloned();
                let user_agent = request.headers().get(header::USER_AGENT).cloned();
                let body = axum::body::to_bytes(request.into_body(), 4096).await.unwrap();
                requests.lock().unwrap().push((path, origin, body, user_agent));
                let ok = |body: String| {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap()
                };
                let status = |status: StatusCode| {
                    Response::builder()
                        .status(status)
                        .body(Body::from(r#"{"detail":"upstream-diagnostic-canary"}"#))
                        .unwrap()
                };
                match case {
                    0 => ok(started_body()),
                    1 => ok(started_body().replace("\"}", "\",\"extra\":true}")),
                    2 => ok(started_body().replace("secret=JBSWY", "secret=OTHER")),
                    3 => status(StatusCode::UNPROCESSABLE_ENTITY),
                    4 => status(StatusCode::TOO_MANY_REQUESTS),
                    5 => status(StatusCode::NOT_FOUND),
                    6 => Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(
                            header::SET_COOKIE,
                            "codewire.session_token=rotated-token; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax",
                        )
                        .header(header::SET_COOKIE, "unrelated=discard; Path=/")
                        .body(Body::from(format!(
                            r#"{{"backup_codes":{CODES},"signed_out_sessions":2}}"#
                        )))
                        .unwrap(),
                    7 => status(StatusCode::GONE),
                    8 => status(StatusCode::INTERNAL_SERVER_ERROR),
                    9 => ok(r#"{"backup_codes":["short"],"signed_out_sessions":0}"#.into()),
                    10 => ok(format!(r#"{{"backup_codes":{CODES}}}"#)),
                    11 => status(StatusCode::SERVICE_UNAVAILABLE),
                    _ => Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(header::LOCATION, "/redirect-must-not-be-followed")
                        .body(Body::empty())
                        .unwrap(),
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (finish, finished) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = finished.await;
                })
                .await
                .unwrap();
        });
        let state = AppState::new(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: origin.parse().unwrap(),
            credential_origin: origin.parse().unwrap(),
            identity_origin_string: origin.clone(),
            browser_api_origin: origin.clone(),
            billing_origin: origin.parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        });
        let cookie = HeaderValue::from_static("codewire.session_token=synthetic");
        let start_with = |n| {
            case.store(n, Ordering::SeqCst);
            start(
                &state,
                cookie.clone(),
                None,
                "account-1",
                "synthetic-password",
                "123456",
            )
        };
        let started = start_with(0).await.ok().unwrap();
        assert_eq!(started.secret, SECRET);
        assert_eq!(start_with(1).await.err(), Some(Failure::Unavailable));
        assert_eq!(start_with(2).await.err(), Some(Failure::Unavailable));
        assert_eq!(start_with(3).await.err(), Some(Failure::ProofRejected));
        assert_eq!(start_with(4).await.err(), Some(Failure::Locked));
        assert_eq!(start_with(5).await.err(), Some(Failure::Unavailable));
        assert_eq!(start_with(12).await.err(), Some(Failure::Unavailable));

        let confirm_with = |n| {
            case.store(n, Ordering::SeqCst);
            confirm(
                &state,
                cookie.clone(),
                Some(HeaderValue::from_static("synthetic-browser/1.0")),
                "account-1",
                "0123456789abcdef0123456789abcdef",
                "123 456",
            )
        };
        let replaced = confirm_with(6).await.ok().unwrap();
        assert_eq!(replaced.backup_codes.len(), 10);
        assert_eq!(
            replaced.session_cookie.unwrap(),
            "codewire.session_token=rotated-token; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax"
        );
        assert_eq!(confirm_with(7).await.err(), Some(Failure::Ended));
        assert_eq!(confirm_with(3).await.err(), Some(Failure::CodeRejected));
        assert_eq!(
            confirm_with(5).await.err(),
            Some(Failure::NoLongerAvailable)
        );
        assert_eq!(confirm_with(8).await.err(), Some(Failure::UnknownOutcome));
        assert_eq!(confirm_with(9).await.err(), Some(Failure::UnknownOutcome));
        assert_eq!(confirm_with(12).await.err(), Some(Failure::UnknownOutcome));

        let regenerate_with = |n| {
            case.store(n, Ordering::SeqCst);
            regenerate(
                &state,
                cookie.clone(),
                None,
                "account-1",
                "synthetic-password",
                "abcdef0123",
            )
        };
        assert_eq!(regenerate_with(10).await.ok().unwrap().len(), 10);
        assert_eq!(regenerate_with(3).await.err(), Some(Failure::ProofRejected));
        assert_eq!(regenerate_with(5).await.err(), Some(Failure::Unavailable));
        assert_eq!(
            regenerate_with(11).await.err(),
            Some(Failure::UnknownOutcome)
        );
        assert_eq!(
            regenerate_with(9).await.err(),
            Some(Failure::UnknownOutcome)
        );

        finish.send(()).unwrap();
        server.await.unwrap();
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 19, "a redirect must not add a request");
        for (path, origin, body, user_agent) in requests.iter() {
            assert!([START_PATH, CONFIRM_PATH, REGENERATE_PATH].contains(&path.as_str()));
            assert_eq!(origin.as_ref().unwrap(), "https://app.example.test");
            // Only the browser's own User-Agent is relayed, and only when given.
            assert_eq!(
                user_agent.as_ref().map(|value| value.to_str().unwrap()),
                (path == CONFIRM_PATH).then_some("synthetic-browser/1.0")
            );
            let body: serde_json::Value = serde_json::from_slice(body).unwrap();
            if path == CONFIRM_PATH {
                assert_eq!(
                    body,
                    serde_json::json!({"account_id":"account-1","replacement_id":"0123456789abcdef0123456789abcdef","code":"123456"})
                );
            } else {
                assert_eq!(body["account_id"], "account-1");
                assert_eq!(body.as_object().unwrap().len(), 3);
            }
        }
    }

    #[tokio::test]
    async fn invalid_local_input_is_refused_without_a_request() {
        let state = AppState::new(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: "http://127.0.0.1:9".parse().unwrap(),
            credential_origin: "http://127.0.0.1:9".parse().unwrap(),
            identity_origin_string: "http://127.0.0.1:9".into(),
            browser_api_origin: "http://127.0.0.1:9".into(),
            billing_origin: "http://127.0.0.1:9".parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        });
        let cookie = HeaderValue::from_static("codewire.session_token=synthetic");
        for (password, proof) in [
            ("", "123456"),
            ("password", " "),
            ("password", &"1".repeat(65)),
        ] {
            assert_eq!(
                start(&state, cookie.clone(), None, "account-1", password, proof)
                    .await
                    .err(),
                Some(Failure::ProofRejected)
            );
        }
        assert_eq!(
            confirm(
                &state,
                cookie.clone(),
                None,
                "account-1",
                "../other",
                "123456"
            )
            .await
            .err(),
            Some(Failure::NoLongerAvailable)
        );
        assert_eq!(
            confirm(
                &state,
                cookie,
                None,
                "account-1",
                "0123456789abcdef0123456789abcdef",
                "12345"
            )
            .await
            .err(),
            Some(Failure::CodeRejected)
        );
    }

    #[test]
    fn factor_calls_outlast_the_idp_budget_and_relay_only_a_bounded_user_agent() {
        let state = AppState::new(crate::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            runtime_mode: crate::RuntimeMode::CurrentThread,
            public_origin: "https://app.example.test".into(),
            api_origin: "http://127.0.0.1:9".parse().unwrap(),
            credential_origin: "http://127.0.0.1:9".parse().unwrap(),
            identity_origin_string: "http://127.0.0.1:9".into(),
            browser_api_origin: "http://127.0.0.1:9".into(),
            billing_origin: "http://127.0.0.1:9".parse().unwrap(),
            docs_root: Default::default(),
            confidential_storage_enabled: false,
            turnstile_site_key: String::new(),
            github_app_slug: String::new(),
            github_app_client_id: String::new(),
        });
        let built = request(
            &state,
            CONFIRM_PATH,
            HeaderValue::from_static("codewire.session_token=synthetic"),
            Some(HeaderValue::from_static("synthetic-browser/1.0")),
            &serde_json::json!({}),
        )
        .unwrap();
        // The IdP answers within five seconds plus its commit; the account
        // client's six-second default would report a slow commit as unknown.
        assert_eq!(built.timeout(), Some(&FACTOR_CHANGE_TIMEOUT));
        assert!(FACTOR_CHANGE_TIMEOUT > Duration::from_secs(6));
        assert_eq!(built.headers()[header::USER_AGENT], "synthetic-browser/1.0");
        assert_eq!(built.headers()[header::ORIGIN], "https://app.example.test");
        assert!(!built.headers().contains_key("x-forwarded-for"));

        let mut browser = HeaderMap::new();
        assert!(browser_user_agent(&browser).is_none());
        browser.insert(
            header::USER_AGENT,
            HeaderValue::from_static("synthetic-browser/1.0"),
        );
        browser.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(
            browser_user_agent(&browser).unwrap(),
            "synthetic-browser/1.0"
        );
        browser.append(header::USER_AGENT, HeaderValue::from_static("second"));
        assert!(browser_user_agent(&browser).is_none());
        browser.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&"a".repeat(MAX_USER_AGENT_BYTES + 1)).unwrap(),
        );
        assert!(browser_user_agent(&browser).is_none());
    }

    #[test]
    fn only_one_well_formed_session_cookie_is_forwarded() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(approved_session_cookie(&headers).is_none());
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("codewire.session_token=fresh; Path=/; HttpOnly"),
        );
        assert!(approved_session_cookie(&headers).is_some());
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("codewire.session_token=second; Path=/; HttpOnly"),
        );
        assert!(approved_session_cookie(&headers).is_none());
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("codewire.session_token=bad value; Path=/"),
        );
        assert!(approved_session_cookie(&headers).is_none());
        assert!(valid_secret(SECRET));
        assert!(!valid_secret("jbswy3dpehpk3pxp"));
        assert!(!valid_secret("JBSWY3DP"));
    }
}
