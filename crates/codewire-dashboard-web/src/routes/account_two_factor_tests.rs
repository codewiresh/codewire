//! Registered-route proof for Account › Security factor changes against a
//! synthetic identity service. No real account, password or factor is used.
use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ACCOUNT: &str = "synthetic-account";
const PASSWORD: &str = "synthetic-password-canary";
const BROWSER_USER_AGENT: &str = "synthetic-browser/1.0";
const PROOF: &str = "9f8e7d6c5b";
const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const REPLACEMENT: &str = "0123456789abcdef0123456789abcdef";
const CODES: [&str; 10] = [
    "0a1b2c3d4e",
    "5f6a7b8c9d",
    "e0f1a2b3c4",
    "d5e6f7a8b9",
    "c0d1e2f3a4",
    "b5c6d7e8f9",
    "a0b1c2d3e4",
    "f5a6b7c8d9",
    "e9d8c7b6a5",
    "f4e3d2c1b0",
];

type Calls = Arc<Mutex<Vec<(String, Option<String>, Vec<u8>, BrowserHeaders)>>>;

/// The User-Agent and X-Forwarded-For the identity service received.
type BrowserHeaders = (Option<String>, Option<String>);

struct TestServer {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    TestServer { origin, task }
}

fn config(upstream: &str) -> crate::Config {
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: ORIGIN.into(),
        api_origin: upstream.parse().unwrap(),
        credential_origin: upstream.parse().unwrap(),
        identity_origin_string: upstream.into(),
        browser_api_origin: ORIGIN.into(),
        billing_origin: upstream.parse().unwrap(),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: String::new(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
    }
}

fn factor_path(path: &str) -> bool {
    path.starts_with("/api/auth/two-factor/")
}

/// The synthetic identity service: an enrolled account with two sessions, and
/// a factor-change answer chosen by `mode`.
async fn upstream(mode: &'static str) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            assert_eq!(
                request.headers()[header::COOKIE],
                "codewire.session_token=synthetic-session"
            );
            assert!(!request.headers().contains_key(header::AUTHORIZATION));
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .map(|value| value.to_str().unwrap().to_owned());
            let browser = (
                request
                    .headers()
                    .get(header::USER_AGENT)
                    .map(|value| value.to_str().unwrap().to_owned()),
                request
                    .headers()
                    .get("x-forwarded-for")
                    .map(|value| value.to_str().unwrap().to_owned()),
            );
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls
                .lock()
                .unwrap()
                .push((path.clone(), origin, body.to_vec(), browser));
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {
                    "id": ACCOUNT, "email": "synthetic@example.test",
                    "two_factor_enabled": mode != "not enrolled"
                }}))
                .into_response();
            }
            if path == "/api/auth/sessions" {
                return Json(serde_json::json!({
                    "account_id": ACCOUNT,
                    "current_session": {"id": "session-current", "expires_at": "2026-10-02T00:00:00Z"},
                    "sessions": [
                        {"id": "session-current", "created_at": null, "expires_at": "2026-10-02T00:00:00Z"},
                        {"id": "session-other", "created_at": null, "expires_at": "2026-10-02T00:00:00Z"}
                    ],
                    "next_cursor": null
                }))
                .into_response();
            }
            if path.ends_with("/ListOrganizations") {
                return ([(header::CONTENT_TYPE, "application/proto")], Vec::<u8>::new())
                    .into_response();
            }
            let status = |status: StatusCode| -> Response {
                (status, r#"{"detail":"upstream-diagnostic-canary"}"#).into_response()
            };
            match (path.as_str(), mode) {
                ("/api/auth/two-factor/replace/start", "success") => Json(serde_json::json!({
                    "replacement_id": REPLACEMENT,
                    "totp_uri": format!("otpauth://totp/Codewire:synthetic%40example.test?algorithm=SHA1&digits=6&issuer=Codewire&period=30&secret={SECRET}"),
                    "secret": SECRET,
                    "expires_at": "2026-10-01T12:10:00Z"
                }))
                .into_response(),
                ("/api/auth/two-factor/replace/confirm", "success") => (
                    [(
                        header::SET_COOKIE,
                        "codewire.session_token=rotated-session; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax",
                    )],
                    Json(serde_json::json!({"backup_codes": CODES, "signed_out_sessions": 1})),
                )
                    .into_response(),
                ("/api/auth/two-factor/recovery-codes/regenerate", "success") => {
                    Json(serde_json::json!({"backup_codes": CODES})).into_response()
                }
                (_, "rejected") => status(StatusCode::UNPROCESSABLE_ENTITY),
                (_, "locked") => status(StatusCode::TOO_MANY_REQUESTS),
                (_, "ended") => status(StatusCode::GONE),
                (_, "old identity service") => status(StatusCode::NOT_FOUND),
                (_, "lost") => status(StatusCode::BAD_GATEWAY),
                _ => status(StatusCode::SERVICE_UNAVAILABLE),
            }
        }
    }));
    (serve(router).await, calls)
}

fn authority(csrf: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(header::USER_AGENT, BROWSER_USER_AGENT.parse().unwrap());
    headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
    headers.insert(
        header::COOKIE,
        format!("codewire.session_token=synthetic-session; codewire_ssr_csrf={csrf}")
            .parse()
            .unwrap(),
    );
    headers
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
}

struct Page {
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

async fn post(
    dashboard: &TestServer,
    path: &str,
    headers: HeaderMap,
    form: &[(&str, &str)],
) -> Page {
    let response = client()
        .post(format!("{}{path}", dashboard.origin))
        .headers(headers)
        .form(form)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    Page {
        status,
        headers,
        body,
    }
}

const START: &str = "/settings/_actions/two-factor/replace/start";
const CONFIRM: &str = "/settings/_actions/two-factor/replace/confirm";
const REGENERATE: &str = "/settings/_actions/two-factor/recovery-codes/regenerate";

fn proof_form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("account_id", ACCOUNT),
        ("password", PASSWORD),
        ("proof", PROOF),
    ]
}

fn confirm_form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("account_id", ACCOUNT),
        ("replacement_id", REPLACEMENT),
        ("code", "123 456"),
    ]
}

/// Every factor response is private, never redirects with a secret, and
/// never echoes the password or proof back into the page.
fn assert_private(page: &Page) {
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers[header::VARY], "Cookie");
    if let Some(location) = page.headers.get(header::LOCATION) {
        let location = location.to_str().unwrap();
        for secret in [SECRET, PASSWORD, PROOF, CODES[0], REPLACEMENT] {
            assert!(!location.contains(secret), "{location}");
        }
    }
    for secret in [PASSWORD, PROOF, "upstream-diagnostic-canary"] {
        assert!(!page.body.contains(secret), "page echoed {secret}");
    }
}

/// The page data was read before the factor change and nothing after it.
fn assert_read_before_mutation(calls: &Calls, mutation: &str) {
    let calls = calls.lock().unwrap();
    let paths: Vec<&str> = calls.iter().map(|(path, _, _, _)| path.as_str()).collect();
    let mutation_index = paths.iter().position(|path| *path == mutation).unwrap();
    assert_eq!(mutation_index, paths.len() - 1, "{paths:?}");
    assert!(paths[..mutation_index].contains(&"/api/auth/sessions"));
    assert!(paths[..mutation_index].contains(&"/api/auth/get-session"));
    let (_, origin, body, browser) = &calls[mutation_index];
    assert_eq!(origin.as_deref(), Some(ORIGIN));
    // The browser's User-Agent reaches the IdP's audit row and session; its
    // X-Forwarded-For does not, since the IdP has no trusted-proxy list.
    assert_eq!(browser.0.as_deref(), Some(BROWSER_USER_AGENT));
    assert_eq!(browser.1, None);
    let body: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(body["account_id"], ACCOUNT);
    assert_eq!(body.as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn starting_a_replacement_shows_the_setup_key_once_in_the_post_response() {
    let (identity, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, START, authority(&csrf), &proof_form(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    assert!(page.headers.get(header::LOCATION).is_none());
    assert!(page.body.contains("id=\"replace-authenticator-confirm\""));
    assert_eq!(page.body.matches("data-dialog-auto-open").count(), 1);
    assert!(page.body.contains(&format!(
        "data-testid=\"replacement-totp-secret\">{SECRET}</code>"
    )));
    assert!(page.body.contains("<svg"));
    assert!(
        page.body
            .contains(&format!("name=\"replacement_id\" value=\"{REPLACEMENT}\""))
    );
    assert_read_before_mutation(&calls, "/api/auth/two-factor/replace/start");
    let (_, _, body, _) = calls.lock().unwrap().last().cloned().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["password"], PASSWORD);
    assert_eq!(body["proof"], PROOF);
}

#[tokio::test]
async fn confirming_forwards_the_rotated_cookie_and_shows_new_codes_once() {
    let (identity, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, CONFIRM, authority(&csrf), &confirm_form(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    let cookies: Vec<&str> = page
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| cookie.starts_with("codewire.session_token=rotated-session;"))
            .count(),
        1,
        "{cookies:?}"
    );
    assert!(page.body.contains("Your old authenticator and recovery codes no longer work, and your other browsers were signed out."));
    assert_eq!(
        page.body.matches("data-testid=\"recovery-code\"").count(),
        10
    );
    // The revoked sessions read before the change are not offered for sign-out.
    assert!(!page.body.contains("session-other"));
    assert!(page.body.contains("Reload sessions"));
    assert!(page.body.contains("id=\"sign-out\""));
    assert!(!page.body.contains(SECRET));
    assert_read_before_mutation(&calls, "/api/auth/two-factor/replace/confirm");
    let (_, _, body, _) = calls.lock().unwrap().last().cloned().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"account_id": ACCOUNT, "replacement_id": REPLACEMENT, "code": "123456"})
    );
}

#[tokio::test]
async fn regenerating_shows_new_codes_and_keeps_the_session() {
    let (identity, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, REGENERATE, authority(&csrf), &proof_form(&csrf)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_private(&page);
    assert!(page.body.contains("id=\"recovery-codes-done\""));
    assert_eq!(
        page.body.matches("data-testid=\"recovery-code\"").count(),
        10
    );
    assert!(page.body.contains("session-other"));
    assert!(
        !page
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .unwrap()
                .starts_with("codewire.session_token="))
    );
    assert_read_before_mutation(&calls, "/api/auth/two-factor/recovery-codes/regenerate");
}

#[tokio::test]
async fn failures_reopen_their_dialog_and_say_what_still_works() {
    for (mode, path, status, dialog, copy) in [
        (
            "rejected",
            START,
            StatusCode::UNPROCESSABLE_ENTITY,
            "replace-authenticator",
            "The password or code didn't match. Nothing changed: your current authenticator and recovery codes still work.",
        ),
        (
            "locked",
            REGENERATE,
            StatusCode::TOO_MANY_REQUESTS,
            "regenerate-recovery-codes",
            "Too many incorrect attempts. Wait 15 minutes, then try again. Your current authenticator and recovery codes still work.",
        ),
        (
            "old identity service",
            START,
            StatusCode::SERVICE_UNAVAILABLE,
            "replace-authenticator",
            "Authenticator replacement is unavailable right now. Nothing changed",
        ),
        (
            "old identity service",
            REGENERATE,
            StatusCode::SERVICE_UNAVAILABLE,
            "regenerate-recovery-codes",
            "Recovery codes can't be regenerated right now. Nothing changed",
        ),
        (
            "lost",
            REGENERATE,
            StatusCode::SERVICE_UNAVAILABLE,
            "regenerate-recovery-codes",
            "We couldn't confirm whether new recovery codes were made. Your authenticator still works.",
        ),
        (
            "rejected",
            CONFIRM,
            StatusCode::UNPROCESSABLE_ENTITY,
            "replace-authenticator-confirm",
            "That code doesn't match the new authenticator.",
        ),
        (
            "ended",
            CONFIRM,
            StatusCode::GONE,
            "replace-authenticator",
            "This replacement ended after five incorrect codes or ten minutes. Start again. Your current authenticator still works.",
        ),
    ] {
        let (identity, _) = upstream(mode).await;
        let dashboard = serve(crate::app(config(&identity.origin))).await;
        let csrf = crate::security::new_csrf_token();
        let form = if path == CONFIRM {
            confirm_form(&csrf)
        } else {
            proof_form(&csrf)
        };
        let page = post(&dashboard, path, authority(&csrf), &form).await;
        assert_eq!(page.status, status, "{mode} {path}");
        assert_private(&page);
        // Copy is HTML-escaped; compare it as the browser reads it.
        let text = page.body.replace("&#39;", "'").replace("&#x27;", "'");
        assert!(text.contains(copy), "{mode} {path}");
        assert_eq!(page.body.matches("data-dialog-auto-open").count(), 1);
        assert!(page.body.contains(&format!(
            "id=\"{dialog}\" aria-labelledby=\"{dialog}-title\""
        )));
        let opened = page
            .body
            .split("<dialog")
            .find(|dialog| dialog.contains("data-dialog-auto-open"))
            .unwrap();
        assert!(
            opened.contains(&format!("id=\"{dialog}\"")),
            "{mode} {path}"
        );
        // A rejected confirmation never shows the setup key again.
        assert!(!page.body.contains(SECRET));
        assert!(!page.body.contains("data-testid=\"recovery-code\""));
    }
}

#[tokio::test]
async fn boundary_failures_never_reach_the_identity_service() {
    let (identity, calls) = upstream("success").await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    for path in [START, CONFIRM, REGENERATE] {
        let form = if path == CONFIRM {
            confirm_form(&csrf)
        } else {
            proof_form(&csrf)
        };
        let mut no_origin = authority(&csrf);
        no_origin.remove(header::ORIGIN);
        let mut foreign_origin = authority(&csrf);
        foreign_origin.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
        let mut bearer = authority(&csrf);
        bearer.insert(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
        for (case, headers, expected_location) in [
            ("no origin", no_origin, None),
            ("foreign origin", foreign_origin, None),
            ("bearer", bearer, Some("/login")),
        ] {
            let page = post(&dashboard, path, headers, &form).await;
            assert_private(&page);
            match expected_location {
                Some(prefix) => assert!(
                    page.headers[header::LOCATION]
                        .to_str()
                        .unwrap()
                        .starts_with(prefix),
                    "{path} {case}"
                ),
                None => assert_eq!(page.status, StatusCode::FORBIDDEN, "{path} {case}"),
            }
        }
        let mut wrong_csrf = form.clone();
        wrong_csrf[0].1 = "wrong-csrf";
        let page = post(&dashboard, path, authority(&csrf), &wrong_csrf).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{path} csrf");
        let mut foreign_account = form.clone();
        foreign_account[1].1 = "another-account";
        let page = post(&dashboard, path, authority(&csrf), &foreign_account).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER);
        assert_eq!(
            page.headers[header::LOCATION],
            "/settings/?security=account-changed#security"
        );
        let mut extra = form.clone();
        extra.push(("secret", SECRET));
        let page = post(&dashboard, path, authority(&csrf), &extra).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{path} unknown field");
        assert!(!page.body.contains(SECRET));
    }
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _, _, _)| factor_path(path)),
        "a refused request reached a factor route"
    );
}

#[tokio::test]
async fn an_account_without_a_factor_is_sent_to_security_without_a_change() {
    let (identity, calls) = upstream("not enrolled").await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let page = post(&dashboard, START, authority(&csrf), &proof_form(&csrf)).await;
    // Without an enrolled factor the dashboard requires setup first.
    assert_eq!(page.status, StatusCode::SEE_OTHER);
    assert_private(&page);
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _, _, _)| factor_path(path))
    );
}
