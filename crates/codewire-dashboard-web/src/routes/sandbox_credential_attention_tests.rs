//! #2361 registered-route proof with a synthetic upstream: the Sandbox row and
//! page name each bound capability whose credential needs the viewer, and
//! render as before when there is nothing to say or the read fails. No real
//! account, provider or credential material is involved.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    AccessProfile, AccessProfileEntry, Credential, CredentialAuthenticationKind, CredentialStatus,
    Environment, EnvironmentSourceSelection, EnvironmentState, GetAccessProfileRequest,
    GetAccessProfileResponse, GetEnvironmentResponse, ListAccessProfilesResponse,
    ListCredentialsResponse, ListEnvironmentsRequest, ListEnvironmentsResponse,
    ListOrganizationsResponse, Organization, OrganizationMembership, ProjectCredentialBinding,
};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ORG: &str = "00000000-0000-4000-8000-000000000002";
const SANDBOX: &str = "00000000-0000-4000-8000-000000000005";
const PROFILE: &str = "00000000-0000-4000-8000-000000000006";
const CODEX: &str = "00000000-0000-4000-8000-000000000007";
const ANTHROPIC: &str = "00000000-0000-4000-8000-000000000008";
const BOUND_REVISION: u64 = 7;
/// Upstream text that must never reach the page: credential names and errors.
const CANARY: &str = "upstream-canary";
const NOTICE: &str = "<ul class=\"cw-credential-attention\"><li><a class=\"cw-link-button\" href=\"/settings/credentials/\">Codex needs Reconnect</a></li></ul>";
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

/// The listed Sandbox, bound to revision 7 of `PROFILE` unless `no profile`.
fn sandbox(mode: &str) -> Environment {
    let bound = mode != "no profile";
    Environment {
        id: SANDBOX.into(),
        org_id: ORG.into(),
        name: "quiet-mesa".into(),
        state: EnvironmentState::Running.into(),
        setup_complete: true,
        operation_generation: 3,
        source_selection: Some(EnvironmentSourceSelection {
            credentials: bound
                .then(|| ProjectCredentialBinding {
                    profile: format!("platform:id:{PROFILE}"),
                    ..Default::default()
                })
                .into(),
            profile_revision: bound.then_some(BOUND_REVISION),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn credential(id: &str, provider: &str, kind: CredentialAuthenticationKind) -> Credential {
    Credential {
        id: id.into(),
        name: format!("{CANARY} {provider}"),
        provider: provider.into(),
        authentication_kind: kind.into(),
        status: CredentialStatus::Active.into(),
        revocation_generation: 1,
        ..Default::default()
    }
}

/// The viewer's credentials: Codex, refresh failed unless `healthy`, and a
/// healthy Anthropic key.
fn credentials(mode: &str) -> Vec<Credential> {
    let mut codex = credential(CODEX, "openai", CredentialAuthenticationKind::Oauth);
    if mode != "healthy" {
        codex.status = CredentialStatus::RefreshFailed.into();
    }
    vec![
        codex,
        credential(ANTHROPIC, "anthropic", CredentialAuthenticationKind::ApiKey),
    ]
}

fn profile(revision: u64) -> AccessProfile {
    AccessProfile {
        id: PROFILE.into(),
        name: "work".into(),
        revision,
        entries: [("codex", CODEX), ("anthropic", ANTHROPIC)]
            .into_iter()
            .map(|(slot, id)| AccessProfileEntry {
                capability_slot: slot.into(),
                credential_id: id.into(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

async fn fixture(mode: &'static str) -> (TestServer, Calls) {
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
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push(path.clone());
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
                let request = ListEnvironmentsRequest::decode(&mut body.as_ref()).unwrap();
                let deleting = request.state == EnvironmentState::Destroying;
                ListEnvironmentsResponse {
                    environments: if deleting { vec![] } else { vec![sandbox(mode)] },
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/GetEnvironment") {
                GetEnvironmentResponse {
                    environment: Some(sandbox(mode)).into(),
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/ListCredentials") {
                if mode == "credential read fails" {
                    return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"code": "unavailable", "message": CANARY}))).into_response();
                }
                ListCredentialsResponse {
                    credentials: credentials(mode),
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/ListAccessProfiles") {
                // Another member's profile is never in the viewer's list.
                let current = if mode == "newer revision" { BOUND_REVISION + 1 } else { BOUND_REVISION };
                ListAccessProfilesResponse {
                    access_profiles: if mode == "other account" { vec![] } else { vec![profile(current)] },
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/GetAccessProfile") {
                if mode == "other account" {
                    return (StatusCode::NOT_FOUND, Json(serde_json::json!({"code": "not_found", "message": CANARY}))).into_response();
                }
                let request = GetAccessProfileRequest::decode(&mut body.as_ref()).unwrap();
                GetAccessProfileResponse {
                    access_profile: Some(profile(request.revision.unwrap())).into(),
                    ..Default::default()
                }
                .encode_to_vec()
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

/// The polled Sandbox list and the Sandbox page, with the upstream calls each made.
async fn render(mode: &'static str) -> [(String, Vec<String>); 2] {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let mut rendered = Vec::new();
    for path in [
        "/synthetic/_fragments/sandboxes".to_owned(),
        format!("/synthetic/{SANDBOX}/"),
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        let response = client
            .get(format!("{}{path}", dashboard.origin))
            .headers(session())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{mode} {path}");
        let html = response.text().await.unwrap();
        assert!(html.contains(SANDBOX), "{mode} {path} renders the Sandbox");
        rendered.push((html, calls.lock().unwrap().clone()));
    }
    rendered.try_into().unwrap()
}

fn count(calls: &[String], operation: &str) -> usize {
    calls
        .iter()
        .filter(|path| path.ends_with(operation))
        .count()
}

#[tokio::test]
async fn sandbox_row_and_page_name_the_capability_that_needs_reconnect() {
    let [(list, list_calls), (page, page_calls)] = render("reconnect").await;
    for html in [&list, &page] {
        // Only the refresh-failed Codex credential: the Anthropic key is healthy.
        assert_eq!(html.matches(NOTICE).count(), 1);
        assert_eq!(html.matches("needs Reconnect").count(), 1);
        assert!(!html.contains("needs replacing"));
        assert!(!html.contains(CANARY));
    }
    assert!(list.contains(&format!("<dt>Needs attention</dt><dd>{NOTICE}</dd>")));
    // The viewer's own profile reads by name, not its storage reference.
    assert!(list.contains("<dt>Credential profile</dt><dd>work · revision"));
    // The workspace names it in a notice under its header.
    assert!(page.contains(&format!(
        "<h2 id=\"sandbox-attention-title\">Needs attention</h2>{NOTICE}</section>"
    )));
    // One credential read per render: the list reads current profiles; the
    // page reads its exact bound revision.
    assert_eq!(count(&list_calls, "/ListCredentials"), 1);
    assert_eq!(count(&list_calls, "/ListAccessProfiles"), 1);
    assert_eq!(count(&list_calls, "/GetAccessProfile"), 0);
    assert_eq!(count(&page_calls, "/ListCredentials"), 1);
    assert_eq!(count(&page_calls, "/GetAccessProfile"), 1);
    assert_eq!(count(&page_calls, "/ListAccessProfiles"), 0);
}

#[tokio::test]
async fn nothing_to_say_or_nothing_readable_renders_no_notice() {
    for mode in [
        "healthy",
        "no profile",
        "credential read fails",
        "other account",
    ] {
        let [(list, list_calls), (page, page_calls)] = render(mode).await;
        for html in [&list, &page] {
            assert!(!html.contains("cw-credential-attention"), "{mode}");
            assert!(!html.contains("Needs attention"), "{mode}");
            assert!(!html.contains(CANARY), "{mode} leaks upstream text");
        }
        if mode == "other account" {
            // Another member's profile is never named for the viewer.
            assert!(!list.contains("<dd>work · revision"), "{mode}");
        }
        if mode == "no profile" {
            // Without a bound profile there is nothing to read.
            for calls in [&list_calls, &page_calls] {
                for operation in [
                    "/ListCredentials",
                    "/ListAccessProfiles",
                    "/GetAccessProfile",
                ] {
                    assert_eq!(count(calls, operation), 0, "{operation}");
                }
            }
        }
    }
}

#[tokio::test]
async fn the_list_marks_only_the_current_revision_and_the_page_its_exact_one() {
    // The profile was edited after the Sandbox bound revision 7. The list
    // knows only the current revision, so it says nothing; the page reads
    // revision 7 itself.
    let [(list, _), (page, _)] = render("newer revision").await;
    assert!(!list.contains("cw-credential-attention"));
    assert_eq!(page.matches(NOTICE).count(), 1);
}
