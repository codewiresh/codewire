//! The dashboard's sign-up calls send the IdP exactly the one client hop the
//! dashboard trusts, the last `X-Forwarded-For` hop the edge wrote, as the
//! whole header (#3297): never a hop the browser chose, and nothing when
//! there is no trusted hop. An invitation's sign-up carries its token in the
//! form and to the IdP, never in a URL (#3840). Against a synthetic identity
//! service.
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
/// What the browser sent: a hop it chose, then the one the edge appended.
const BROWSER_CHAIN: &str = "203.0.113.66, 198.51.100.7";
const EDGE_HOP: &str = "198.51.100.7";

/// Each identity call's path and the X-Forwarded-For it carried.
type Calls = Arc<Mutex<Vec<(String, Option<String>)>>>;

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
        support_email: None,
        updates_site: None,
    }
}

/// The synthetic identity service: a pending GitHub sign-up for the provider
/// path, and a refusal for every sign-up, which is enough to see the call.
async fn identity() -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let forwarded = request
                .headers()
                .get("x-forwarded-for")
                .map(|value| value.to_str().unwrap().to_owned());
            calls.lock().unwrap().push((path.clone(), forwarded));
            if path == "/api/auth/oauth/signup/pending" {
                return Json(serde_json::json!({
                    "provider": "github",
                    "email": "synthetic@example.invalid",
                }))
                .into_response();
            }
            StatusCode::TOO_MANY_REQUESTS.into_response()
        }
    }));
    (serve(router).await, calls)
}

fn browser(csrf: &str, forwarded: Option<&str>, oauth_signup: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    if let Some(forwarded) = forwarded {
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
    }
    let mut cookie = format!("codewire_ssr_csrf={csrf}");
    if oauth_signup {
        cookie.push_str(&format!(
            "; {}={}",
            crate::security::OAUTH_SIGNUP_COOKIE,
            "ab".repeat(32)
        ));
    }
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    headers
}

async fn post(dashboard: &TestServer, path: &str, headers: HeaderMap, form: &[(&str, &str)]) {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .post(format!("{}{path}", dashboard.origin))
        .headers(headers)
        .form(form)
        .send()
        .await
        .unwrap();
}

fn sign_up_form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("email", "synthetic@example.invalid"),
        ("password", "Synthetic-password-1"),
        ("confirm_password", "Synthetic-password-1"),
        ("name", "Synthetic"),
        ("reason", "a synthetic sign-up"),
    ]
}

/// The X-Forwarded-For the identity service saw on `path`.
fn forwarded_on(calls: &Calls, path: &str) -> Option<String> {
    let calls = calls.lock().unwrap();
    let matching: Vec<_> = calls.iter().filter(|(called, _)| called == path).collect();
    assert_eq!(matching.len(), 1, "one call to {path}: {calls:?}");
    matching[0].1.clone()
}

#[tokio::test]
async fn email_sign_up_sends_only_the_edge_hop_and_nothing_without_one() {
    for (inbound, expected) in [(Some(BROWSER_CHAIN), Some(EDGE_HOP)), (None, None)] {
        let (identity, calls) = identity().await;
        let dashboard = serve(crate::app(config(&identity.origin))).await;
        let csrf = crate::security::new_csrf_token();
        post(
            &dashboard,
            "/signup/_actions/sign-up",
            browser(&csrf, inbound, false),
            &sign_up_form(&csrf),
        )
        .await;
        assert_eq!(
            forwarded_on(&calls, "/api/auth/sign-up").as_deref(),
            expected,
            "inbound {inbound:?}"
        );
    }
}

#[tokio::test]
async fn provider_sign_up_sends_only_the_edge_hop_and_nothing_without_one() {
    for (inbound, expected) in [(Some(BROWSER_CHAIN), Some(EDGE_HOP)), (None, None)] {
        let (identity, calls) = identity().await;
        let dashboard = serve(crate::app(config(&identity.origin))).await;
        let csrf = crate::security::new_csrf_token();
        post(
            &dashboard,
            "/signup/complete/_actions/complete",
            browser(&csrf, inbound, true),
            &[("_csrf", csrf.as_str()), ("reason", "a synthetic sign-up")],
        )
        .await;
        assert_eq!(
            forwarded_on(&calls, "/api/auth/oauth/signup/complete").as_deref(),
            expected,
            "inbound {inbound:?}"
        );
        // The pending lookup counts nothing, so it carries no client hop.
        assert_eq!(forwarded_on(&calls, "/api/auth/oauth/signup/pending"), None);
    }
}

/// An identity service whose sign-ups are refused with `status`, `code` and,
/// when given, `Retry-After`, as the IdP's sign-up limits refuse them. An
/// empty `code` sends none, as the IdP's uncoded errors do.
async fn refusing_identity(
    status: StatusCode,
    code: &str,
    retry_after: Option<&str>,
) -> TestServer {
    let code = code.to_owned();
    let retry_after = retry_after.map(str::to_owned);
    serve(
        Router::new().fallback(any(move |request: axum::extract::Request| {
            let code = code.clone();
            let retry_after = retry_after.clone();
            async move {
                if request.uri().path() == "/api/auth/oauth/signup/pending" {
                    return Json(serde_json::json!({
                        "provider": "github",
                        "email": "synthetic@example.invalid",
                    }))
                    .into_response();
                }
                let mut body = serde_json::json!({
                    "detail": "internal detail the page never shows",
                });
                if !code.is_empty() {
                    body["code"] = code.into();
                }
                let body = Json(body);
                match retry_after {
                    Some(seconds) => {
                        (status, [(header::RETRY_AFTER, seconds)], body).into_response()
                    }
                    None => (status, body).into_response(),
                }
            }
        })),
    )
    .await
}

/// The page a refused sign-up renders: its status and text.
async fn page(
    dashboard: &TestServer,
    path: &str,
    headers: HeaderMap,
    form: &[(&str, &str)],
) -> (StatusCode, String) {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .post(format!("{}{path}", dashboard.origin))
        .headers(headers)
        .form(form)
        .send()
        .await
        .unwrap();
    (response.status(), response.text().await.unwrap())
}

/// A sign-up the IdP's limits refused says what was limited and when to try
/// again, from the refusal's code and `Retry-After`, never the IdP's detail;
/// an unavailable limit says sign-up is unavailable, not that mail is late
/// (#4695).
#[tokio::test]
async fn a_limited_sign_up_says_so_and_when_to_try_again() {
    let cases = [
        (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some("690"),
            "Too many sign-ups right now. Try again in 12 minutes.",
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some("1"),
            "Too many sign-ups right now. Try again in a minute.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "rate_limit_unavailable",
            None,
            "Sign-up is temporarily unavailable. Try again in a few minutes.",
        ),
    ];
    for (status, code, retry_after, expected) in cases {
        let identity = refusing_identity(status, code, retry_after).await;
        let dashboard = serve(crate::app(config(&identity.origin))).await;
        let csrf = crate::security::new_csrf_token();
        for (path, form, provider) in [
            ("/signup/_actions/sign-up", sign_up_form(&csrf), false),
            (
                "/signup/complete/_actions/complete",
                vec![("_csrf", csrf.as_str()), ("reason", "a synthetic sign-up")],
                true,
            ),
        ] {
            let (answered, body) = page(
                &dashboard,
                path,
                browser(&csrf, Some(EDGE_HOP), provider),
                &form,
            )
            .await;
            assert_eq!(answered, status, "{path} {code}");
            assert!(body.contains(expected), "{path} {code}: {body}");
            assert!(!body.contains("internal detail"), "{path} {code}");
            assert!(!body.contains("Wait a moment"), "{path} {code}");
        }
    }
}

/// Only a sign-up whose account was saved but whose verification email
/// couldn't be sent says the request was saved; any other unavailable sign-up
/// says sign-up is unavailable and nothing more (#4723).
#[tokio::test]
async fn an_unavailable_sign_up_says_it_was_saved_only_when_it_was() {
    const UNAVAILABLE: &str = "Sign-up is temporarily unavailable. Try again in a few minutes.";
    const SAVED: &str = "Your request was saved";
    for (code, expected, absent) in [
        ("", UNAVAILABLE, SAVED),
        ("verification_email_unsent", SAVED, UNAVAILABLE),
    ] {
        let identity = refusing_identity(StatusCode::SERVICE_UNAVAILABLE, code, None).await;
        let dashboard = serve(crate::app(config(&identity.origin))).await;
        let csrf = crate::security::new_csrf_token();
        let (answered, body) = page(
            &dashboard,
            "/signup/_actions/sign-up",
            browser(&csrf, Some(EDGE_HOP), false),
            &sign_up_form(&csrf),
        )
        .await;
        assert_eq!(answered, StatusCode::SERVICE_UNAVAILABLE, "{code}");
        assert!(body.contains(expected), "{code}: {body}");
        assert!(!body.contains(absent), "{code}: {body}");
        assert!(!body.contains("internal detail"), "{code}");
    }
}

const INVITATION_TOKEN: &str = "synthetic-invitation-token";
const MASKED: &str = "s\u{2022}\u{2022}\u{2022}@example.invalid";
const SITE_KEY: &str = "synthetic-site-key";

/// The sign-up bodies an identity service received.
type Bodies = Arc<Mutex<Vec<serde_json::Value>>>;

/// An identity service in sign-up `mode` that records each sign-up and
/// refuses it as an invite-only server refuses.
async fn identity_in_mode(mode: &'static str) -> (TestServer, Bodies) {
    let bodies = Bodies::default();
    let captured = bodies.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let bodies = captured.clone();
        async move {
            match request.uri().path() {
                "/api/auth/sign-up/mode" => {
                    return Json(serde_json::json!({"mode": mode, "reason": true})).into_response();
                }
                "/api/auth/oauth/providers" => {
                    return Json(serde_json::json!({"providers": ["github"]})).into_response();
                }
                "/api/auth/sign-up" => {}
                _ => return StatusCode::NOT_FOUND.into_response(),
            }
            let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
                .await
                .unwrap();
            bodies
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&bytes).unwrap());
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"code": "invite_only", "detail": "refused"})),
            )
                .into_response()
        }
    }));
    (serve(router).await, bodies)
}

async fn dashboard_for(identity: &TestServer) -> TestServer {
    let mut config = config(&identity.origin);
    config.turnstile_site_key = SITE_KEY.into();
    serve(crate::app(config)).await
}

fn invited_form(csrf: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", csrf),
        ("invitation_token", INVITATION_TOKEN),
        ("email_hint", MASKED),
    ]
}

/// The `<input>` tag named `name` in `body`.
fn input_named<'a>(body: &'a str, name: &str) -> &'a str {
    let at = body
        .find(&format!(r#"name="{name}""#))
        .unwrap_or_else(|| panic!("no {name} input: {body}"));
    let start = body[..at].rfind("<input").unwrap();
    let end = at + body[at..].find('>').unwrap();
    &body[start..=end]
}

/// On an invite-only server the invitation page's Create account opens
/// sign-up with the token in a hidden field, the masked address as a hint
/// and the address for the person to type; no Turnstile, reason, invite
/// code or provider, since the IdP admits a live invitation without the
/// first three and a provider sign-up can't carry it (#4121).
#[tokio::test]
async fn an_invitation_opens_sign_up_with_its_token_hidden_and_its_address_a_hint() {
    let (identity, _) = identity_in_mode("invite-only").await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    let (status, body) = page(
        &dashboard,
        "/signup/invited",
        browser(&csrf, None, false),
        &invited_form(&csrf),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#"action="/signup/_actions/sign-up""#));
    assert!(input_named(&body, "invitation_token").contains(INVITATION_TOKEN));
    assert!(body.contains(
        "Your invitation is for <strong>s\u{2022}\u{2022}\u{2022}@example.invalid</strong>."
    ));
    assert!(!input_named(&body, "email").contains("value="));
    assert!(input_named(&body, "return_to").contains(r#"value="/accept-invite""#));
    assert!(body.contains("Create account"));
    for absent in [
        r#"name="reason""#,
        r#"name="invite_code""#,
        SITE_KEY,
        "Continue with GitHub",
    ] {
        assert!(!body.contains(absent), "{absent}: {body}");
    }
}

/// Anywhere but an invite-only server the IdP ignores the token, so sign-up
/// asks what it always asks, and still carries the token and the hint.
#[tokio::test]
async fn an_invitation_elsewhere_keeps_the_usual_sign_up() {
    let (identity, _) = identity_in_mode("review").await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    let (status, body) = page(
        &dashboard,
        "/signup/invited",
        browser(&csrf, None, false),
        &invited_form(&csrf),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(input_named(&body, "invitation_token").contains(INVITATION_TOKEN));
    for present in [
        r#"name="reason""#,
        r#"name="invite_code""#,
        SITE_KEY,
        "Continue with GitHub",
    ] {
        assert!(body.contains(present), "{present}: {body}");
    }
}

#[tokio::test]
async fn an_invitation_sign_up_needs_the_page_csrf() {
    let (identity, _) = identity_in_mode("invite-only").await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    let other = crate::security::new_csrf_token();
    let (status, body) = page(
        &dashboard,
        "/signup/invited",
        browser(&other, None, false),
        &invited_form(&csrf),
    )
    .await;

    assert_ne!(status, StatusCode::OK);
    assert!(!body.contains(INVITATION_TOKEN));
}

/// The invited sign-up hands its token to the IdP with no reason, and a
/// refusal shows the form again with the invitation kept.
#[tokio::test]
async fn an_invited_sign_up_hands_its_token_to_the_identity_service() {
    let (identity, bodies) = identity_in_mode("invite-only").await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    let mut form = sign_up_form(&csrf);
    form.retain(|(name, _)| *name != "reason");
    form.extend([
        ("invitation_token", INVITATION_TOKEN),
        ("email_hint", MASKED),
    ]);
    let (status, body) = page(
        &dashboard,
        "/signup/_actions/sign-up",
        browser(&csrf, None, false),
        &form,
    )
    .await;

    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1, "{body}");
    assert_eq!(bodies[0]["invitation_token"], INVITATION_TOKEN);
    assert_eq!(bodies[0]["reason"], "");
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(input_named(&body, "invitation_token").contains(INVITATION_TOKEN));
    assert!(!body.contains(SITE_KEY));
}

#[test]
fn only_a_plausible_token_and_an_address_hint_are_kept() {
    assert_eq!(super::invitation_token(" token-1 "), "token-1");
    assert_eq!(super::invitation_token("two words"), "");
    assert_eq!(super::invitation_token(&"t".repeat(513)), "");
    assert_eq!(super::email_hint(MASKED), MASKED);
    assert_eq!(super::email_hint("not an address"), "");
    assert_eq!(super::email_hint("a@b\ninjected"), "");
}
