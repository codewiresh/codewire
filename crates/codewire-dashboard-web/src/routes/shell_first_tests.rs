//! codewire#3395: an organization page answers with its shell before any
//! inventory is read, and the session check and the organization read leave
//! together. A synthetic upstream records each call; no real account is used.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    ListEnvironmentsResponse, ListOrganizationsResponse, Organization, OrganizationMembership,
};
use tokio::sync::Barrier;

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ORG: &str = "00000000-0000-4000-8000-000000000002";
type Calls = Arc<Mutex<Vec<String>>>;

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

/// An upstream whose session check and organization read each answer only
/// once both have arrived, or fail after `wait`. A dashboard that sends them
/// one after another therefore fails the session check.
async fn upstream(wait: Duration) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let together = Arc::new(Barrier::new(2));
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        let together = together.clone();
        async move {
            let path = request.uri().path().to_owned();
            calls.lock().unwrap().push(path.clone());
            let paired = path == "/api/auth/get-session" || path.ends_with("/ListOrganizations");
            if paired && tokio::time::timeout(wait, together.wait()).await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": true}})).into_response();
            }
            let bytes = if path.ends_with("/ListOrganizations") {
                ListOrganizationsResponse {
                    organizations: vec![OrganizationMembership {
                        organization: Some(Organization {
                            id: ORG.into(),
                            name: "Synthetic organization".into(),
                            slug: "synthetic".into(),
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/ListEnvironments") {
                ListEnvironmentsResponse::default().encode_to_vec()
            } else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
        }
    }));
    (serve(router).await, calls)
}

fn session() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    headers.insert(
        header::COOKIE,
        "codewire.session_token=synthetic-session".parse().unwrap(),
    );
    headers
}

async fn get(path: &str) -> (StatusCode, String, Vec<String>) {
    let (upstream, calls) = upstream(Duration::from_secs(5)).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!("{}{path}", dashboard.origin))
        .headers(session())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let html = response.text().await.unwrap();
    let calls = calls.lock().unwrap().clone();
    (status, html, calls)
}

fn count(calls: &[String], operation: &str) -> usize {
    calls
        .iter()
        .filter(|path| path.ends_with(operation))
        .count()
}

#[tokio::test]
async fn the_organization_page_renders_its_shell_before_any_inventory() {
    for path in ["/synthetic/", "/synthetic/new/"] {
        let (status, html, calls) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        // One session check and one organization read; inventory, Create
        // choices and credentials load afterwards as fragments.
        assert_eq!(
            count(&calls, "/api/auth/get-session"),
            1,
            "{path} {calls:?}"
        );
        assert_eq!(count(&calls, "/ListOrganizations"), 1, "{path} {calls:?}");
        assert_eq!(calls.len(), 2, "{path} {calls:?}");
        assert!(
            html.contains(
                r#"hx-get="/synthetic/_fragments/sandboxes" hx-trigger="load, every 5s""#
            ),
            "{path} loads the Sandbox list"
        );
        // The start panel's marker rides along, so its refresh can stand still.
        assert!(
            html.contains(r##"hx-include="#environment-filters, [data-sandbox-start-state]""##),
            "{path} refreshes with the start panel's marker"
        );
        assert!(
            html.contains(
                r#"hx-get="/synthetic/_fragments/sandbox-rail" hx-trigger="sandbox-rail-refresh""#
            ),
            "{path} loads the rail"
        );
        assert!(
            html.contains(r#"data-create-options-loading="true""#),
            "{path}"
        );
        assert!(
            html.contains(r#"data-create-draft-actor="synthetic-account""#),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_page_that_opens_a_sandbox_panel_still_reads_inventory_first() {
    let (_, _, calls) = get("/synthetic/?ports=00000000-0000-4000-8000-000000000005").await;
    assert_eq!(count(&calls, "/api/auth/get-session"), 1, "{calls:?}");
    assert!(count(&calls, "/ListEnvironments") >= 1, "{calls:?}");
}

#[tokio::test]
async fn fragments_send_the_session_check_and_organization_read_together() {
    for path in [
        "/synthetic/_fragments/sandbox-rail",
        "/synthetic/_fragments/sandboxes",
    ] {
        let (status, _, calls) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path} {calls:?}");
        assert_eq!(
            count(&calls, "/api/auth/get-session"),
            1,
            "{path} {calls:?}"
        );
        assert_eq!(count(&calls, "/ListOrganizations"), 1, "{path} {calls:?}");
    }
}

/// The settings pages answer like organization pages: the session check and
/// the organization read leave together, or the paired upstream fails the
/// session check and no later read is sent.
#[tokio::test]
async fn settings_pages_send_the_session_check_and_organization_read_together() {
    for (path, next) in [
        ("/settings/", "/api/auth/sessions"),
        ("/settings/credentials/", "/GetGitIdentity"),
    ] {
        let (_, _, calls) = get(path).await;
        assert_eq!(
            count(&calls, "/api/auth/get-session"),
            1,
            "{path} {calls:?}"
        );
        assert_eq!(count(&calls, "/ListOrganizations"), 1, "{path} {calls:?}");
        assert!(
            count(&calls, next) >= 1,
            "{path} reads past the shell: {calls:?}"
        );
    }
}

/// An upstream for the credentials page: the session, organizations, Git
/// identity, credentials and profiles answer at once, with a GitHub
/// credential when `github` is set. The live GitHub permission check never
/// answers, so a page that waits for it would take its full deadline.
async fn credentials_upstream(github: bool) -> TestServer {
    use codewire_proto::codewire::{
        console::v1::GetGitIdentityResponse,
        v1::{
            Credential, CredentialAuthenticationKind, CredentialStatus, ListAccessProfilesResponse,
            ListCredentialsResponse,
        },
    };
    let router = Router::new().fallback(any(move |request: axum::extract::Request| async move {
        let path = request.uri().path().to_owned();
        if path == "/api/auth/get-session" {
            return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": true}})).into_response();
        }
        if path.ends_with("/ListGithubPendingPermissions") {
            std::future::pending::<()>().await;
        }
        let bytes = if path.ends_with("/ListOrganizations") {
            ListOrganizationsResponse::default().encode_to_vec()
        } else if path.ends_with("/GetGitIdentity") {
            GetGitIdentityResponse::default().encode_to_vec()
        } else if path.ends_with("/ListAccessProfiles") {
            ListAccessProfilesResponse::default().encode_to_vec()
        } else if path.ends_with("/ListCredentials") {
            ListCredentialsResponse {
                credentials: if github {
                    vec![Credential {
                        id: "00000000-0000-4000-8000-000000000021".into(),
                        name: "Synthetic GitHub".into(),
                        provider: "github".into(),
                        authentication_kind: CredentialAuthenticationKind::Oauth.into(),
                        status: CredentialStatus::Active.into(),
                        revocation_generation: 1,
                        ..Default::default()
                    }]
                } else {
                    Vec::new()
                },
                ..Default::default()
            }
            .encode_to_vec()
        } else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
    }));
    serve(router).await
}

/// The page never waits for GitHub (#5206). With a GitHub connection it carries
/// a placeholder that asks for the permission notice after load; without one it
/// carries none. Its timing never has a `github` phase.
#[tokio::test]
async fn the_credentials_page_never_waits_for_github_and_asks_only_when_connected() {
    for github in [false, true] {
        let upstream = credentials_upstream(github).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        let started = std::time::Instant::now();
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
            .build()
            .unwrap()
            .get(format!("{}/settings/credentials/", dashboard.origin))
            .headers(session())
            .send()
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(response.status(), StatusCode::OK, "github {github}");
        let timing = response
            .headers()
            .get("server-timing")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let phases: Vec<&str> = timing
            .split(", ")
            .map(|phase| phase.split(';').next().unwrap_or_default())
            .filter(|phase| *phase != "total")
            .collect();
        assert_eq!(phases, ["shell", "reads"], "{timing}");
        // The check's own deadline is 2 s; the page never reaches it.
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        let body = response.text().await.unwrap();
        assert_eq!(
            body.contains(r#"hx-get="/settings/credentials/_fragments/github-permissions""#),
            github,
            "github {github}"
        );
        assert!(!body.contains("GitHub is waiting"), "github {github}");
        // The placeholder fetches only if the page loads htmx, with the config
        // that keeps a refused (4xx) answer out of the page.
        assert!(
            body.contains("/assets/codewire/htmx-2.0.10.min.js"),
            "github {github}"
        );
        assert!(body.contains(r#"name="htmx-config""#), "github {github}");
    }
}

/// An organization with no Sandboxes gets the start panel, which reads
/// billing once. Its refresh, while the organization stays empty, answers 204
/// so htmx leaves the panel (focus and copy feedback) as it is and billing is
/// not read again. A search that matches nothing still shows the table.
#[tokio::test]
async fn an_empty_organization_gets_the_start_panel_and_its_refresh_changes_nothing() {
    let (status, html, calls) = get("/synthetic/_fragments/sandboxes").await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert!(html.contains("Start your first sandbox"), "{html}");
    assert_eq!(count(&calls, "/GetBillingOverview"), 1, "{calls:?}");

    let (status, html, calls) = get("/synthetic/_fragments/sandboxes?showing=start").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{calls:?}");
    assert!(html.is_empty());
    assert_eq!(count(&calls, "/GetBillingOverview"), 0, "{calls:?}");

    let (status, html, calls) = get("/synthetic/_fragments/sandboxes?search=nothing").await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert!(html.contains("No Sandboxes found"), "{html}");
    assert_eq!(count(&calls, "/GetBillingOverview"), 0, "{calls:?}");
}

/// Only platform admins read feedback: a signed-in member who isn't one is
/// sent away before the admin RPC is ever called (#4061).
#[tokio::test]
async fn a_member_who_is_not_an_admin_never_reaches_feedback() {
    // Admin pages check the session before reading organizations, so this
    // upstream answers each call at once rather than in pairs.
    let calls = Calls::default();
    let captured = calls.clone();
    let upstream = serve(Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            calls.lock().unwrap().push(path.clone());
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": true}})).into_response();
            }
            if path.ends_with("/ListOrganizations") {
                let bytes = ListOrganizationsResponse::default().encode_to_vec();
                return ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response();
            }
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    })))
    .await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!("{}/admin/feedback/", dashboard.origin))
        .headers(session())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_redirection(), "{}", response.status());
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/dashboard/")
    );
    let calls = calls.lock().unwrap().clone();
    assert_eq!(count(&calls, "/api/auth/get-session"), 1, "{calls:?}");
    assert_eq!(count(&calls, "/ListFeedback"), 0, "{calls:?}");
}

/// An upstream that records every path it is asked and answers the GitHub
/// permission check with a failure that carries words the page must never
/// show.
async fn recording_upstream(two_factor: bool) -> (TestServer, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let seen = seen.clone();
        async move {
            let path = request.uri().path().to_owned();
            seen.lock().unwrap().push(path.clone());
            if path == "/api/auth/get-session" {
                return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": two_factor}})).into_response();
            }
            (StatusCode::BAD_GATEWAY, "SYNTHETIC-GITHUB-ERROR-BODY").into_response()
        }
    }));
    (serve(router).await, calls)
}

/// The deferred GitHub check answers only a fetch this dashboard's own page
/// started (#2712, #5206): anything else is refused before anything is read,
/// and no upstream is asked.
#[tokio::test]
async fn the_github_notice_fragment_refuses_what_the_page_did_not_ask_for() {
    let (upstream, calls) = recording_upstream(true).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let url = format!(
        "{}/settings/credentials/_fragments/github-permissions",
        dashboard.origin
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap();
    for extra in [
        vec![],
        vec![("sec-fetch-site", "same-origin")],
        vec![("hx-request", "true")],
        vec![("sec-fetch-site", "cross-site"), ("hx-request", "true")],
        vec![("sec-fetch-site", "same-site"), ("hx-request", "true")],
        vec![("sec-fetch-site", "none"), ("hx-request", "true")],
    ] {
        let mut headers = session();
        for (name, value) in &extra {
            headers.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        let response = client.get(&url).headers(headers).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{extra:?}");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store",
            "{extra:?}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "{extra:?}"
        );
    }
    assert!(calls.lock().unwrap().is_empty(), "{:?}", calls.lock());
}

/// A check that fails shows no notice and none of the failure's words, and
/// the answer is never cached.
#[tokio::test]
async fn a_failed_github_check_shows_nothing_and_never_the_upstream_words() {
    let (upstream, calls) = recording_upstream(true).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let mut headers = session();
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("hx-request", "true".parse().unwrap());
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!(
            "{}/settings/credentials/_fragments/github-permissions",
            dashboard.origin
        ))
        .headers(headers)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    let body = response.text().await.unwrap();
    assert!(!body.contains("SYNTHETIC"), "{body}");
    assert!(!body.contains("GitHub is waiting"), "{body}");
    assert_eq!(
        count(&calls.lock().unwrap(), "/ListGithubPendingPermissions"),
        1
    );
}

fn fragment_headers() -> HeaderMap {
    let mut headers = session();
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("hx-request", "true".parse().unwrap());
    headers
}

async fn fetch_fragment(dashboard: &TestServer) -> reqwest::Response {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!(
            "{}/settings/credentials/_fragments/github-permissions",
            dashboard.origin
        ))
        .headers(fragment_headers())
        .send()
        .await
        .unwrap()
}

/// The page's gate comes first (#5206): a session whose account has not set up
/// two-factor, which every page sends to setup, makes no call for GitHub.
#[tokio::test]
async fn a_session_without_two_factor_gets_an_empty_notice_and_no_check() {
    let (upstream, calls) = recording_upstream(false).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let response = fetch_fragment(&dashboard).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "");
    assert_eq!(
        count(&calls.lock().unwrap(), "/ListGithubPendingPermissions"),
        0
    );
}

/// One person asks GitHub once in the window, however often the page loads.
#[tokio::test]
async fn one_person_fetching_the_notice_twice_asks_the_credential_service_once() {
    let (upstream, calls) = recording_upstream(true).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    for _ in 0..2 {
        assert_eq!(fetch_fragment(&dashboard).await.status(), StatusCode::OK);
    }
    assert_eq!(
        count(&calls.lock().unwrap(), "/ListGithubPendingPermissions"),
        1
    );
}

/// What a span's `outcome` field was recorded as.
#[derive(Clone, Default)]
struct Outcomes(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Outcomes {
    fn on_record(
        &self,
        _span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Find<'a>(&'a Outcomes);
        impl tracing::field::Visit for Find<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "outcome" {
                    self.0.0.lock().unwrap().push(value.to_owned());
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        values.record(&mut Find(self));
    }
}

/// A failed check leaves its cause on its span, a code or a timeout and never
/// a message (#5206).
#[tokio::test]
async fn the_check_span_says_how_the_call_ended() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let outcomes = Outcomes::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(outcomes.clone()));
    let (unavailable, _) = recording_upstream(true).await;
    let silent = credentials_upstream(true).await;
    for origin in [&unavailable.origin, &silent.origin] {
        let state = crate::state::AppState::new(config(origin));
        let found = crate::github_check::github_pending_checked(
            &state,
            "synthetic-account",
            "codewire.session_token=synthetic".parse().unwrap(),
        )
        .await;
        assert!(found.is_empty());
    }
    let outcomes = outcomes.0.lock().unwrap().clone();
    assert_eq!(outcomes.len(), 2, "{outcomes:?}");
    assert!(!outcomes[0].contains("SYNTHETIC"), "{outcomes:?}");
    assert_ne!(outcomes[0], "ok", "{outcomes:?}");
    assert_eq!(outcomes[1], "deadline_exceeded");
}
