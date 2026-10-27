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
        confidential_admin_only: true,
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
        .timeout(Duration::from_secs(10))
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
        assert!(
            html.contains(
                r#"hx-get="/synthetic/_fragments/sandbox-rail" hx-trigger="load, every 10s""#
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
