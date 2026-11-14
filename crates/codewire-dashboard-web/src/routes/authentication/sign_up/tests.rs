//! The dashboard's sign-up calls send the IdP exactly the one client hop the
//! dashboard trusts, the last `X-Forwarded-For` hop the edge wrote, as the
//! whole header (#3297): never a hop the browser chose, and nothing when
//! there is no trusted hop. Against a synthetic identity service.
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
