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
        analytics: None,
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
/// refuses it as an invite-only server refuses. It reports a reason as
/// required in every mode but open, as the IdP does by default.
async fn identity_in_mode(mode: &'static str) -> (TestServer, Bodies) {
    let bodies = Bodies::default();
    let captured = bodies.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let bodies = captured.clone();
        async move {
            match request.uri().path() {
                "/api/auth/sign-up/mode" => {
                    return Json(serde_json::json!({"mode": mode, "reason": mode != "open"}))
                        .into_response();
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

/// What a sign-up page asks besides the account: the second step, the
/// reason, the invite code, Turnstile and a provider.
const ACCESS_REQUEST: [&str; 6] = [
    "data-signup-step=\"2\"",
    "What would you like to build?",
    r#"name="reason""#,
    r#"name="invite_code""#,
    SITE_KEY,
    "Continue with GitHub",
];

/// The invitation page's Create account on a server in sign-up `mode`.
async fn invited_sign_up_page(mode: &'static str) -> String {
    let (identity, _) = identity_in_mode(mode).await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    let (status, body) = page(
        &dashboard,
        "/signup/invited",
        browser(&csrf, None, false),
        &invited_form(&csrf),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{mode}: {body}");
    body
}

/// The invitation page's Create account opens sign-up with the token in a
/// hidden field, the masked address as a hint and the address for the
/// person to type, in one step with Create account. It asks for no reason,
/// invite code, Turnstile or provider, since on every server the IdP admits
/// a live invitation without the first three and a provider sign-up can't
/// carry it (#4121).
fn assert_invited_sign_up(mode: &str, body: &str) {
    assert!(
        body.contains(r#"action="/signup/_actions/sign-up""#),
        "{mode}"
    );
    assert!(
        input_named(body, "invitation_token").contains(INVITATION_TOKEN),
        "{mode}"
    );
    assert!(
        body.contains(
            "Your invitation is for <strong>s\u{2022}\u{2022}\u{2022}@example.invalid</strong>."
        ),
        "{mode}"
    );
    assert!(!input_named(body, "email").contains("value="), "{mode}");
    assert!(
        input_named(body, "return_to").contains(r#"value="/accept-invite""#),
        "{mode}"
    );
    assert!(body.contains("Create account"), "{mode}");
    assert!(body.contains("By creating an account"), "{mode}");
    for absent in ACCESS_REQUEST {
        assert!(!body.contains(absent), "{mode}, {absent}: {body}");
    }
}

#[tokio::test]
async fn an_invitation_opens_the_invited_sign_up_on_an_invite_only_server() {
    let body = invited_sign_up_page("invite-only").await;
    assert_invited_sign_up("invite-only", &body);
}

/// The hosted default (#5908): review mode used to ask an invitee what it
/// would build, which the IdP ignores.
#[tokio::test]
async fn an_invitation_opens_the_invited_sign_up_on_a_review_server() {
    let body = invited_sign_up_page("review").await;
    assert_invited_sign_up("review", &body);
}

#[tokio::test]
async fn an_invitation_opens_the_invited_sign_up_on_an_open_server() {
    let body = invited_sign_up_page("open").await;
    assert_invited_sign_up("open", &body);
}

/// Without a token the IdP can read, a review server's sign-up asks what it
/// always asks: two steps, the reason, the invite code, Turnstile and a
/// provider.
#[tokio::test]
async fn a_sign_up_without_an_invitation_asks_what_it_always_asks() {
    let (identity, _) = identity_in_mode("review").await;
    let dashboard = dashboard_for(&identity).await;
    let csrf = crate::security::new_csrf_token();
    for token in [None, Some("two words")] {
        let mut form = vec![("_csrf", csrf.as_str()), ("email_hint", MASKED)];
        form.extend(token.map(|token| ("invitation_token", token)));
        let (status, body) = page(
            &dashboard,
            "/signup/invited",
            browser(&csrf, None, false),
            &form,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{token:?}: {body}");
        assert!(body.contains("Request access"), "{token:?}");
        assert!(!body.contains(r#"name="invitation_token""#), "{token:?}");
        for present in ACCESS_REQUEST {
            assert!(body.contains(present), "{token:?}, {present}: {body}");
        }
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

/// On a server in sign-up `mode`, the invited sign-up hands its token to the
/// IdP with no reason, and a refusal shows the invited form again with the
/// invitation kept.
async fn assert_invited_sign_up_reaches_the_identity_service(mode: &'static str) {
    let (identity, bodies) = identity_in_mode(mode).await;
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
    assert_eq!(bodies.len(), 1, "{mode}: {body}");
    assert_eq!(bodies[0]["invitation_token"], INVITATION_TOKEN, "{mode}");
    assert_eq!(bodies[0]["reason"], "", "{mode}");
    assert_eq!(status, StatusCode::FORBIDDEN, "{mode}");
    assert_invited_sign_up(mode, &body);
}

#[tokio::test]
async fn an_invited_sign_up_hands_its_token_to_the_identity_service() {
    assert_invited_sign_up_reaches_the_identity_service("invite-only").await;
}

/// A review server doesn't hold an invited sign-up back for the reason the
/// IdP ignores (#5908).
#[tokio::test]
async fn an_invited_sign_up_on_a_review_server_asks_no_reason() {
    assert_invited_sign_up_reaches_the_identity_service("review").await;
}

#[tokio::test]
async fn an_invited_sign_up_on_an_open_server_is_the_invited_form() {
    assert_invited_sign_up_reaches_the_identity_service("open").await;
}

const NO_LONGER_VALID: &str = "This invitation is no longer valid. Ask for a new one.";
const CHECK_THE_FORM: &str = "The request could not be completed. Check the form and try again.";

/// The page an email sign-up gets when the IdP refuses it with `status` and
/// `code`, from the invitation's form when `invited`.
async fn refused_sign_up(status: StatusCode, code: &str, invited: bool) -> String {
    let identity = refusing_identity(status, code, None).await;
    let dashboard = serve(crate::app(config(&identity.origin))).await;
    let csrf = crate::security::new_csrf_token();
    let mut form = sign_up_form(&csrf);
    if invited {
        form.extend([
            ("invitation_token", INVITATION_TOKEN),
            ("email_hint", MASKED),
        ]);
    }
    let (answered, body) = page(
        &dashboard,
        "/signup/_actions/sign-up",
        browser(&csrf, None, false),
        &form,
    )
    .await;
    assert_eq!(answered, status, "{code}: {body}");
    assert!(!body.contains("internal detail"), "{code}");
    body
}

/// A token that names no live invitation for the address says the
/// invitation is no longer valid (#5908).
#[tokio::test]
async fn a_dead_invitation_says_it_is_no_longer_valid() {
    let body = refused_sign_up(StatusCode::FORBIDDEN, "invitation_invalid", true).await;
    assert!(body.contains(NO_LONGER_VALID), "{body}");
    assert!(input_named(&body, "invitation_token").contains(INVITATION_TOKEN));
}

/// On a server with Turnstile's keys only a live invitation skips the
/// challenge the invited page doesn't show, so an invited sign-up that fails
/// it had a dead invitation (#5908).
#[tokio::test]
async fn an_invited_sign_up_that_fails_the_challenge_says_the_invitation_is_no_longer_valid() {
    let body = refused_sign_up(StatusCode::BAD_REQUEST, "human_verification_failed", true).await;
    assert!(body.contains(NO_LONGER_VALID), "{body}");
}

/// Without a token a failed challenge says what it said before.
#[tokio::test]
async fn a_sign_up_without_an_invitation_that_fails_the_challenge_keeps_its_words() {
    let body = refused_sign_up(StatusCode::BAD_REQUEST, "human_verification_failed", false).await;
    assert!(body.contains(CHECK_THE_FORM), "{body}");
    assert!(!body.contains(NO_LONGER_VALID), "{body}");
}

/// An unavailable sign-up, such as a server without mail or Turnstile's
/// keys, is not a dead invitation.
#[tokio::test]
async fn an_unavailable_invited_sign_up_keeps_its_words() {
    let body = refused_sign_up(StatusCode::SERVICE_UNAVAILABLE, "", true).await;
    assert!(
        body.contains("Sign-up is temporarily unavailable. Try again in a few minutes."),
        "{body}"
    );
    assert!(!body.contains(NO_LONGER_VALID), "{body}");
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
