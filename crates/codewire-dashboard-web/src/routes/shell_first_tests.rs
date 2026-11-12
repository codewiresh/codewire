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

/// Without a GitHub connection the page does not wait for the live GitHub
/// permission check; with one it does, and its timing says so.
#[tokio::test]
async fn the_credentials_page_waits_for_github_only_while_github_is_connected() {
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
            .collect();
        if github {
            assert_eq!(phases, ["shell", "reads", "github"], "{timing}");
        } else {
            assert_eq!(phases, ["shell", "reads"], "{timing}");
            // The check's own deadline is 2 s; the page never reaches it.
            assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        }
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
