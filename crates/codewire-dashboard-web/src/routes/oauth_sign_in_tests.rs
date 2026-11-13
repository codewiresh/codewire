//! Sign in with GitHub or Google (#4062) through the registered routes,
//! against a synthetic identity service: the buttons follow the providers the
//! IdP names, a failed provider sign-in shows a fixed message, and
//! `/signup/complete` finishes a pending provider sign-up.
use axum::{
    Json, Router,
    body::to_bytes,
    http::{StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const REQUESTER: &str = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2";
const RESEND_TOKEN: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
const HANDLE: &str = "5f5e5d5c5b5a59585756555453525150f5e5d5c5b5a59585756555453525150f";

type Calls = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

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

fn config(identity: &str, turnstile_site_key: &str) -> crate::Config {
    crate::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        runtime_mode: crate::RuntimeMode::CurrentThread,
        public_origin: ORIGIN.into(),
        api_origin: "http://127.0.0.1:9".parse().unwrap(),
        credential_origin: "http://127.0.0.1:9".parse().unwrap(),
        identity_origin_string: identity.into(),
        browser_api_origin: ORIGIN.into(),
        billing_origin: "http://127.0.0.1:9".parse().unwrap(),
        docs_root: std::path::PathBuf::new(),
        confidential_storage_enabled: false,
        turnstile_site_key: turnstile_site_key.into(),
        github_app_slug: String::new(),
        github_app_client_id: String::new(),
    }
}

/// The synthetic identity service. `providers` is what it says is
/// configured (`None` answers 500); `complete` is the status the sign-up
/// completion answers with.
async fn identity(
    providers: Option<&'static [&'static str]>,
    complete: StatusCode,
) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            calls.lock().unwrap().push((path.clone(), json.clone()));
            match path.as_str() {
                "/api/auth/oauth/providers" => match providers {
                    Some(providers) => Json(serde_json::json!({ "providers": providers })).into_response(),
                    None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                },
                "/api/auth/oauth/signup/pending" => {
                    if json["token"] == HANDLE {
                        Json(serde_json::json!({
                            "provider": "github",
                            "email": "new-person@example.test",
                            "auth_request_id": "oidc-request",
                        }))
                        .into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
                "/api/auth/oauth/signup/complete" => match complete {
                    StatusCode::OK => (
                        [(
                            header::SET_COOKIE,
                            "codewire.session_token=synthetic-session; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax",
                        )],
                        Json(serde_json::json!({
                            "user": { "id": "u", "email": "new-person@example.test" },
                            "session": { "id": "s", "expires_at": "2026-11-12T00:00:00Z" },
                            "auth_request_id": "oidc-request",
                        })),
                    )
                        .into_response(),
                    StatusCode::ACCEPTED => (
                        StatusCode::ACCEPTED,
                        Json(serde_json::json!({
                            "user": { "id": "u", "email": "new-person@example.test" },
                            "accessPending": true,
                        })),
                    )
                        .into_response(),
                    status => (
                        status,
                        Json(serde_json::json!({ "detail": "<script>upstream detail</script>" })),
                    )
                        .into_response(),
                },
                // An email sign-up signs no one in: it waits for the emailed
                // link, and without an invite code for review as well.
                "/api/auth/sign-up" => (
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({
                        "user": { "id": "u", "email": json["email"] },
                        "accessPending": json["invite_code"] == "",
                        "verificationPending": true,
                    })),
                )
                    .into_response(),
                // The right password for an account still waiting for access.
                "/api/auth/sign-in" if json["password"] == "right" => (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "code": "account_disabled" })),
                )
                    .into_response(),
                // The right password for an account that never verified its email.
                "/api/auth/sign-in" if json["password"] == "unverified" => (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "code": "email_unverified",
                        "detail": "<script>upstream detail</script>",
                        "resendToken": RESEND_TOKEN,
                    })),
                )
                    .into_response(),
                "/api/auth/sign-in" => StatusCode::UNAUTHORIZED.into_response(),
                "/api/auth/resend-verification" if json["token"] == RESEND_TOKEN => {
                    (StatusCode::ACCEPTED, Json(serde_json::json!({ "sent": true })))
                        .into_response()
                }
                "/api/auth/resend-verification" => StatusCode::BAD_REQUEST.into_response(),
                "/api/auth/oauth/link/pending" => {
                    if json["token"] == HANDLE {
                        Json(serde_json::json!({ "provider": "github", "account": "octocat" }))
                            .into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
                "/api/auth/oauth/link/confirm" => match complete {
                    StatusCode::OK if json["token"] == HANDLE && json["requester"] == REQUESTER => {
                        Json(serde_json::json!({ "provider": "github", "account": "octocat" }))
                            .into_response()
                    }
                    StatusCode::OK if json["token"] == HANDLE => {
                        StatusCode::PRECONDITION_FAILED.into_response()
                    }
                    StatusCode::OK => StatusCode::NOT_FOUND.into_response(),
                    status => (
                        status,
                        Json(serde_json::json!({ "detail": "<script>upstream detail</script>" })),
                    )
                        .into_response(),
                },
                other => panic!("unexpected identity call {other}"),
            }
        }
    }));
    (serve(router).await, calls)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn dashboard(identity_origin: &str, turnstile_site_key: &str) -> TestServer {
    serve(crate::app(config(identity_origin, turnstile_site_key))).await
}

async fn page(
    server: &TestServer,
    path: &str,
    cookie: Option<&str>,
) -> (StatusCode, reqwest::header::HeaderMap, String) {
    let mut request = client().get(format!("{}{path}", server.origin));
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (status, headers, response.text().await.unwrap())
}

#[tokio::test]
async fn provider_buttons_follow_the_providers_the_identity_service_names() {
    for (providers, github, google) in [
        (Some(&["github"][..]), true, false),
        (Some(&["github", "google"][..]), true, true),
        (Some(&["google", "gitlab"][..]), false, true),
        (Some(&[][..]), false, false),
        // On an error there are no buttons, and the pages still work.
        (None, false, false),
    ] {
        let (idp, _) = identity(providers, StatusCode::OK).await;
        let server = dashboard(&idp.origin, "").await;
        for path in [
            "/login?authRequestID=oidc-request",
            "/signup?return_to=%2Fdevice",
        ] {
            let (status, headers, body) = page(&server, path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                body.contains("Continue with GitHub"),
                github,
                "{providers:?} {path}"
            );
            assert_eq!(
                body.contains("Continue with Google"),
                google,
                "{providers:?} {path}"
            );
            assert_eq!(body.contains("cw-auth-providers"), github || google);
            // The password form is always there.
            assert!(body.contains("name=\"password\""));
            // The buttons are links, so the page policy is unchanged.
            assert!(
                headers[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("form-action 'self';")
            );
        }
        if github {
            let (_, _, body) = page(&server, "/login?authRequestID=oidc-request", None).await;
            let providers_markup = body
                .split_once("<ul class=\"cw-auth-providers\">")
                .and_then(|(_, rest)| rest.split_once("</ul>"))
                .map(|(list, _)| list.to_owned())
                .unwrap_or_default();
            // The button keeps the OIDC request and the return target; its icon
            // comes from the sprite, whose URL carries the asset's content hash.
            assert!(providers_markup.contains(
                "<a class=\"cw-button cw-button--outline cw-button--pill cw-button--large\" href=\"/api/auth/oauth/github/start?authRequestID=oidc-request&#38;return_to=%2Fdashboard%2F\"><svg class=\"cw-icon\" aria-hidden=\"true\"><use href=\"/assets/codewire/icons-v2.svg"
            ), "{providers_markup}");
            assert!(
                providers_markup
                    .contains("#icon-github\"/></svg><span>Continue with GitHub</span></a>"),
                "{providers_markup}"
            );
            let (_, _, body) = page(&server, "/signup?return_to=%2Fdevice", None).await;
            assert!(body.contains("href=\"/api/auth/oauth/github/start?return_to=%2Fdevice\""));
        }
    }
}

#[tokio::test]
async fn the_provider_list_is_read_once_a_minute() {
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    for _ in 0..3 {
        page(&server, "/login", None).await;
        page(&server, "/signup", None).await;
    }
    let reads = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == "/api/auth/oauth/providers")
        .count();
    assert_eq!(reads, 1);
}

#[tokio::test]
async fn a_failed_provider_sign_in_shows_a_fixed_message() {
    let (idp, _) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    for (code, message) in [
        ("cancelled", "Sign-in was cancelled."),
        ("expired", "expired or was started in another browser"),
        ("unverified_email", "has no verified email address"),
        (
            "link_required",
            "Sign in with your email and password, then link the provider from Settings.",
        ),
        ("locked", "Too many sign-in attempts."),
        ("unavailable", "isn&#39;t available right now"),
        ("failed", "didn&#39;t finish"),
        ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "didn&#39;t finish"),
    ] {
        let (status, _, body) = page(&server, &format!("/login?oauth_error={code}"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("cw-alert cw-alert--error"), "{code}");
        assert!(body.contains(message), "{code}: {body}");
        assert!(!body.contains("<script>alert"), "{code}");
        assert!(!body.contains("alert(1)"), "{code}");
    }
    let (_, _, body) = page(&server, "/login", None).await;
    assert!(!body.contains("cw-alert cw-alert--error"));
}

#[tokio::test]
async fn the_completion_page_shows_the_provider_identity_and_the_access_request() {
    let (idp, _) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "site-key-marker").await;
    let cookie = format!("codewire_oauth_signup={HANDLE}");
    let (status, headers, body) = page(&server, "/signup/complete", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    for fragment in [
        "<h1 id=\"auth-title\" class=\"cw-page-title\">Finish creating your account</h1>",
        "You're signing up with GitHub as <strong>new-person@example.test</strong>.",
        "action=\"/signup/complete/_actions/complete\"",
        "name=\"reason\"",
        "name=\"invite_code\"",
        "data-sitekey=\"site-key-marker\" data-action=\"signup\"",
        "challenges.cloudflare.com/turnstile/v0/api.js",
        ">Request access</button>",
    ] {
        assert!(body.contains(fragment), "missing {fragment}");
    }
    // No password, no email field, no provider buttons.
    for absent in ["name=\"password\"", "id=\"email\"", "Continue with GitHub"] {
        assert!(!body.contains(absent), "{absent}");
    }
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-src https://challenges.cloudflare.com")
    );

    // Without the cookie, or with a used one, the page says to start again.
    for cookie in [None, Some("codewire_oauth_signup=deadbeef")] {
        let (status, _, body) = page(&server, "/signup/complete", cookie).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("Sign-up expired"));
        assert!(body.contains("href=\"/signup\""));
    }
}

#[tokio::test]
async fn an_account_waiting_for_access_is_told_it_is_on_the_list() {
    let (idp, _) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let notice = "<div class=\"cw-alert cw-alert--info\" role=\"status\">You&#39;re on the list. We&#39;ll email you as soon as we open up more capacity — no need to sign up again.</div>";
    let check_email = "Check your email to verify your address. <form class=\"cw-auth-resend\" method=\"post\" action=\"/login/_actions/resend-verification\">";
    // With the right password, sign-in says so instead of a generic failure.
    let csrf = crate::security::new_csrf_token();
    for (password, waiting, unverified) in [
        ("right", true, false),
        ("unverified", false, true),
        ("wrong", false, false),
    ] {
        let response = client()
            .post(format!("{}/login/_actions/sign-in", server.origin))
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, format!("codewire_ssr_csrf={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "_csrf={csrf}&email=waiting%40example.test&password={password}"
            ))
            .send()
            .await
            .unwrap();
        let body = response.text().await.unwrap();
        assert_eq!(body.contains(notice), waiting, "{password}: {body}");
        assert_eq!(body.contains(check_email), unverified, "{password}: {body}");
        // The button posts the token in its form, never a URL.
        assert_eq!(
            body.contains(&format!(
                "<input type=\"hidden\" name=\"resend_token\" value=\"{RESEND_TOKEN}\">"
            )),
            unverified,
            "{password}"
        );
        assert_eq!(body.matches(RESEND_TOKEN).count(), usize::from(unverified));
        assert_eq!(
            body.contains("<button class=\"cw-link-button cw-auth-resend-link\" type=\"submit\">Resend verification email</button></form></div>"),
            unverified,
            "{password}"
        );
        assert!(!body.contains("upstream detail"));
        assert_eq!(
            !body.contains("cw-alert--error"),
            waiting || unverified,
            "{password}"
        );
        assert!(!body.contains("Check the form and try again"));
    }
    // A provider sign-in to the same kind of account says the same.
    let (status, _, body) = page(&server, "/login?oauth_error=disabled", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(notice), "{body}");
    assert!(!body.contains("cw-alert--error"));
}

/// An email sign-up never signs in (#4481): with an invite code it asks for
/// the emailed link, and without one it also says the request waits for
/// review.
#[tokio::test]
async fn an_email_sign_up_waits_for_its_verification_link() {
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let csrf = crate::security::new_csrf_token();
    for (invite_code, title, detail) in [
        (
            "INVITE-1",
            "Check your email",
            "We sent a verification link to your email address. Open it, then sign in with the password you chose.",
        ),
        (
            "",
            "Verify your email",
            "Once you verify your email, you&#39;re on the list",
        ),
    ] {
        let response = client()
            .post(format!("{}/signup/_actions/sign-up", server.origin))
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, format!("codewire_ssr_csrf={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!(
                "_csrf={csrf}&name=New+Person&email=new%40example.test\
                 &password=Sup3r%21Strong-pass&confirm_password=Sup3r%21Strong-pass\
                 &reason=Build+things&invite_code={invite_code}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{invite_code}");
        assert!(
            response.headers().get(header::SET_COOKIE).is_none()
                || !response.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("session_token"),
            "a sign-up forwards no session"
        );
        let body = response.text().await.unwrap();
        assert!(body.contains(title), "{invite_code}: {body}");
        assert!(body.contains(detail), "{invite_code}: {body}");
        assert!(body.contains("href=\"/login\""), "{invite_code}: {body}");
        assert!(!body.contains("setup-2fa"), "{invite_code}: {body}");
    }
    let sign_ups = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == "/api/auth/sign-up")
        .count();
    assert_eq!(sign_ups, 2);
}

#[tokio::test]
async fn one_click_sends_a_new_verification_link() {
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let csrf = crate::security::new_csrf_token();
    for (token, expected) in [
        (
            RESEND_TOKEN,
            "Sent. Check your email; the link works for 24 hours.",
        ),
        (
            "used-or-expired",
            "That request expired. Sign in again to resend the verification email.",
        ),
    ] {
        let response = client()
            .post(format!(
                "{}/login/_actions/resend-verification",
                server.origin
            ))
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, format!("codewire_ssr_csrf={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("_csrf={csrf}&resend_token={token}"))
            .send()
            .await
            .unwrap();
        let body = response.text().await.unwrap();
        assert!(body.contains(expected), "{token}: {body}");
        assert!(!body.contains("name=\"resend_token\""));
    }
    let sent: Vec<_> = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == "/api/auth/resend-verification")
        .map(|(_, body)| body["token"].clone())
        .collect();
    assert_eq!(sent, [RESEND_TOKEN, "used-or-expired"]);
}

async fn submit(server: &TestServer, reason: &str) -> reqwest::Response {
    let csrf = crate::security::new_csrf_token();
    client()
        .post(format!(
            "{}/signup/complete/_actions/complete",
            server.origin
        ))
        .header(header::ORIGIN, ORIGIN)
        .header(
            header::COOKIE,
            format!("codewire_oauth_signup={HANDLE}; codewire_ssr_csrf={csrf}"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "_csrf={csrf}&reason={reason}&invite_code=&cf-turnstile-response=turnstile-marker"
        ))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn completing_a_provider_sign_up_signs_in_or_waits_for_review() {
    // Active: the session is forwarded, the pending cookie cleared, and the
    // browser offered two-factor setup before its return target.
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let response = submit(&server, "Build+agents").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/setup-2fa?return_to=%2Fapi%2Foidc%2Fcallback%3Fid%3Doidc-request"
    );
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("codewire.session_token=synthetic-session"))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("codewire_oauth_signup=;")
                && cookie.contains("Path=/signup/complete")
                && cookie.contains("Max-Age=0"))
    );
    let sent = calls
        .lock()
        .unwrap()
        .iter()
        .find(|(path, _)| path == "/api/auth/oauth/signup/complete")
        .map(|(_, body)| body.clone())
        .unwrap();
    assert_eq!(sent["token"], HANDLE);
    assert_eq!(sent["reason"], "Build agents");
    assert_eq!(sent["turnstile_token"], "turnstile-marker");

    // Pending review: the existing access-pending page.
    let (idp, _) = identity(Some(&["github"]), StatusCode::ACCEPTED).await;
    let server = dashboard(&idp.origin, "").await;
    let response = submit(&server, "Build+agents").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("You&#39;re on the list"));
    assert!(body.contains("as soon as we open up more capacity"));
}

#[tokio::test]
async fn completion_failures_show_fixed_messages() {
    for (status, expected_status, message) in [
        (
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            "complete the human verification",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            "Human verification is temporarily unavailable",
        ),
        (
            StatusCode::CONFLICT,
            StatusCode::CONFLICT,
            "Account already exists",
        ),
        (
            StatusCode::NOT_FOUND,
            StatusCode::BAD_REQUEST,
            "Sign-up expired",
        ),
    ] {
        let (idp, _) = identity(Some(&["github"]), status).await;
        let server = dashboard(&idp.origin, "").await;
        let response = submit(&server, "Build+agents").await;
        assert_eq!(response.status(), expected_status, "{status}");
        let body = response.text().await.unwrap();
        assert!(body.contains(message), "{status}: {body}");
        assert!(!body.contains("upstream detail"), "{status}");
    }

    // A missing reason is caught before the identity service is asked.
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let response = submit(&server, "+").await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("Tell us what you want to build.")
    );
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == "/api/auth/oauth/signup/complete")
    );

    // A cross-site post is refused.
    let refused = client()
        .post(format!(
            "{}/signup/complete/_actions/complete",
            server.origin
        ))
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, format!("codewire_oauth_signup={HANDLE}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("_csrf=x&reason=r")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_link_sent_notice_names_only_a_known_provider() {
    let (idp, _) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let (status, _, body) = page(
        &server,
        "/login?oauth_notice=link_sent&provider=github",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(
        "<div class=\"cw-alert cw-alert--info\" role=\"status\">We emailed a link to your account&#39;s address. Open it to connect GitHub, then sign in with GitHub.</div>"
    ));
    assert!(!body.contains("cw-alert--error"));
    let (_, _, body) = page(
        &server,
        "/login?oauth_notice=link_sent&provider=google",
        None,
    )
    .await;
    assert!(body.contains("Open it to connect Google, then sign in with Google."));
    for path in [
        "/login?oauth_notice=link_sent&provider=gitlab",
        "/login?oauth_notice=other&provider=github",
        "/login?oauth_notice=%3Cscript%3E&provider=github",
    ] {
        let (_, _, body) = page(&server, path, None).await;
        assert!(!body.contains("cw-alert--info"), "{path}");
        assert!(!body.contains("<script>"), "{path}");
    }
    let (_, _, body) = page(&server, "/login?oauth_error=rate_limited", None).await;
    assert!(body.contains("Too many sign-in attempts from this network."));
}

#[tokio::test]
async fn opening_an_emailed_link_confirmation_uses_nothing_up() {
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;

    // The link in the email: the token moves into a Lax cookie for this page.
    let entry = client()
        .get(format!("{}/login/link?token={HANDLE}", server.origin))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(entry.status(), StatusCode::SEE_OTHER);
    assert_eq!(entry.headers()[header::LOCATION], "/login/link");
    let cookie = entry.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        cookie,
        format!(
            "codewire_oauth_link={HANDLE}; Path=/login/link; HttpOnly; SameSite=Lax; Max-Age=1800; Secure"
        )
    );

    // The page, fetched any number of times, only reads the confirmation.
    let pair = format!("codewire_oauth_link={HANDLE}");
    for _ in 0..2 {
        let (status, _, body) = page(&server, "/login/link", Some(&pair)).await;
        assert_eq!(status, StatusCode::OK);
        for fragment in [
            "<h1 id=\"auth-title\" class=\"cw-page-title\">Connect GitHub to your Codewire account</h1>",
            "action=\"/login/link/_actions/confirm\"",
            "name=\"_csrf\"",
            ">Connect GitHub</button>",
            "Connect the GitHub account <strong>octocat</strong> to your Codewire account?",
        ] {
            assert!(body.contains(fragment), "missing {fragment}");
        }
        assert!(!body.contains("name=\"password\""));
    }
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path == "/api/auth/oauth/link/confirm"),
        "a GET never confirms"
    );

    // An unknown or used token says to start again.
    for cookie in [None, Some("codewire_oauth_link=deadbeef")] {
        let (status, _, body) = page(&server, "/login/link", cookie).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("Link expired"));
    }
}

async fn confirm(server: &TestServer) -> reqwest::Response {
    confirm_from(server, Some(REQUESTER)).await
}

/// Confirm from a browser holding `requester`, or none.
async fn confirm_from(server: &TestServer, requester: Option<&str>) -> reqwest::Response {
    let csrf = crate::security::new_csrf_token();
    let mut cookie = format!("codewire_oauth_link={HANDLE}; codewire_ssr_csrf={csrf}");
    if let Some(requester) = requester {
        cookie.push_str(&format!("; codewire_oauth_link_requester={requester}"));
    }
    client()
        .post(format!("{}/login/link/_actions/confirm", server.origin))
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("_csrf={csrf}"))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn confirming_a_link_connects_without_signing_in() {
    let (idp, calls) = identity(Some(&["github"]), StatusCode::OK).await;
    let server = dashboard(&idp.origin, "").await;
    let response = confirm(&server).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert!(
        !cookies
            .iter()
            .any(|cookie| cookie.starts_with("codewire.session_token="))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("codewire_oauth_link=;")
                && cookie.contains("Path=/login/link")
                && cookie.contains("Max-Age=0"))
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("GitHub is connected"));
    assert!(body.contains("href=\"/login\""));
    let sent = calls
        .lock()
        .unwrap()
        .iter()
        .find(|(path, _)| path == "/api/auth/oauth/link/confirm")
        .map(|(_, body)| body.clone())
        .unwrap();
    assert_eq!(sent["token"], HANDLE);
    assert_eq!(sent["requester"], REQUESTER);
    assert!(cookies.iter().any(
        |cookie| cookie.starts_with("codewire_oauth_link_requester=;")
            && cookie.contains("Path=/login/link")
            && cookie.contains("Max-Age=0")
    ));

    // Another browser (no requester secret, or another one) is told to open
    // the link where the sign-in started, and keeps the link usable.
    for requester in [None, Some("f".repeat(64))] {
        let response = confirm_from(&server, requester.as_deref()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{requester:?}");
        assert!(
            !response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|cookie| cookie.to_str().unwrap().contains("Max-Age=0")),
            "nothing is cleared"
        );
        let body = response.text().await.unwrap();
        assert!(
            body.contains(
                "Open this link in the browser where you started signing in with GitHub."
            )
        );
        assert!(!body.contains("GitHub is connected"));
    }

    for (status, expected, message) in [
        (
            StatusCode::NOT_FOUND,
            StatusCode::BAD_REQUEST,
            "Link expired",
        ),
        (
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
            "can&#39;t be connected",
        ),
        (
            StatusCode::CONFLICT,
            StatusCode::CONFLICT,
            "Already connected elsewhere",
        ),
    ] {
        let (idp, _) = identity(Some(&["github"]), status).await;
        let server = dashboard(&idp.origin, "").await;
        let response = confirm(&server).await;
        assert_eq!(response.status(), expected, "{status}");
        let body = response.text().await.unwrap();
        assert!(body.contains(message), "{status}: {body}");
        assert!(!body.contains("upstream detail"));
    }

    // A cross-site post is refused before the identity service is asked.
    let refused = client()
        .post(format!("{}/login/link/_actions/confirm", server.origin))
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, format!("codewire_oauth_link={HANDLE}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("_csrf=x")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

#[test]
fn cookie_names_match_the_identity_service() {
    let idp = include_str!("../../../codewire-idp/src/oauth.rs");
    assert!(idp.contains(&format!(
        "const SIGNUP_COOKIE: &str = \"{}\";",
        crate::security::OAUTH_SIGNUP_COOKIE
    )));
    assert!(idp.contains(&format!(
        "const SIGNUP_COOKIE_PATH: &str = \"{}\";",
        crate::security::OAUTH_SIGNUP_PATH
    )));
    assert!(idp.contains(&format!(
        "const TWO_FACTOR_CHALLENGE_COOKIE: &str = \"{}\";",
        crate::security::TWO_FACTOR_CHALLENGE_COOKIE
    )));
    assert!(idp.contains(&format!(
        "const LINK_REQUESTER_COOKIE: &str = \"{}\";",
        crate::security::OAUTH_LINK_REQUESTER_COOKIE
    )));
    assert!(idp.contains(&format!(
        "const LINK_REQUESTER_PATH: &str = \"{}\";",
        crate::security::OAUTH_LINK_PATH
    )));
    assert!(idp.contains("const TWO_FACTOR_CHALLENGE_PATH: &str = \"/two-factor\";"));
    // The routes the IdP redirects to.
    for path in [
        "\"/signup/complete\"",
        "\"/two-factor\"",
        "/setup-2fa?",
        "/login?",
        "/login/link?token=",
    ] {
        assert!(idp.contains(path), "{path}");
    }
    assert!(
        include_str!("mod.rs")
            .contains("\"/signup/complete\", get(authentication::signup_complete)")
    );
}
