//! Synthetic registered-route proof. No real accounts, provider or secret data.

use super::*;
use axum::{Json, Router, body::to_bytes, http::header, response::IntoResponse as _, routing::any};
use buffa::Message as _;
use codewire_proto::codewire::v1::{
    ListOrganizationsResponse, ListProjectSecretsResponse, ListSecretProjectsResponse,
    ListSecretsResponse, ListUserSecretsResponse, OrgRole, Organization, OrganizationMembership,
    SecretMetadata, SecretProject,
};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const DRAFT: &str = "00000000-0000-4000-8000-000000000003";
const ORG: &str = "00000000-0000-4000-8000-000000000002";
const PROJECT: &str = "00000000-0000-4000-8000-000000000004";
const PRIVATE_MARKER: &str = "synthetic-write-only-value-canary";
type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

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
    }
}

fn mutation(path: &str) -> bool {
    [
        "/CreateSecretProject",
        "/DeleteSecretProject",
        "/SetSecret",
        "/SetUserSecret",
        "/SetProjectSecret",
        "/DeleteSecret",
        "/DeleteUserSecret",
        "/DeleteProjectSecret",
        "/RenameSecret",
        "/RenameUserSecret",
        "/RenameProjectSecret",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

async fn fixture(mode: &'static str) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            assert_eq!(request.headers()[header::COOKIE], "codewire.session_token=synthetic-session");
            assert!(!request.headers().contains_key(header::AUTHORIZATION));
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.lock().unwrap().push((path.clone(), body.to_vec()));
            if path == "/api/auth/get-session" {
                if mode == "unauthenticated" { return StatusCode::UNAUTHORIZED.into_response(); }
                return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": mode != "two factor"}})).into_response();
            }
            let metadata = SecretMetadata { key: "SYNTHETIC_KEY".into(), ..Default::default() };
            let bytes = if path.ends_with("/ListOrganizations") {
                ListOrganizationsResponse {
                    organizations: if mode == "no membership" { vec![] } else { vec![OrganizationMembership {
                        organization: Some(Organization { id: ORG.into(), name: "Synthetic organization".into(), slug: "synthetic".into(), ..Default::default() }).into(),
                        role: if mode == "member" { OrgRole::Member } else { OrgRole::Owner }.into(),
                        ..Default::default()
                    }] }, ..Default::default()
                }.encode_to_vec()
            } else if path.ends_with("/ListSecretProjects") {
                ListSecretProjectsResponse { secret_projects: vec![SecretProject { id: PROJECT.into(), org_id: ORG.into(), name: "Synthetic project".into(), ..Default::default() }], ..Default::default() }.encode_to_vec()
            } else if path.ends_with("/ListSecrets") {
                ListSecretsResponse { secrets: vec![metadata], ..Default::default() }.encode_to_vec()
            } else if path.ends_with("/ListUserSecrets") {
                ListUserSecretsResponse { secrets: vec![metadata], ..Default::default() }.encode_to_vec()
            } else if path.ends_with("/ListProjectSecrets") {
                ListProjectSecretsResponse { secrets: vec![metadata], ..Default::default() }.encode_to_vec()
            } else if mutation(&path) {
                if mode == "mutation denied" || mode == "mutation unauthenticated" {
                    let (status, code) = if mode == "mutation denied" { (StatusCode::FORBIDDEN, "permission_denied") } else { (StatusCode::UNAUTHORIZED, "unauthenticated") };
                    return (status, Json(serde_json::json!({"code": code, "message": "synthetic failure"}))).into_response();
                }
                Vec::new()
            } else {
                // Rail unavailability is supported. Every unexpected write is
                // separately rejected by the captured operation assertions.
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
        }
    }));
    (serve(router).await, calls)
}

fn authority(csrf: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
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
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

#[test]
fn navigation_is_exact_and_feedback_has_one_query_without_private_input() {
    let valid = format!("creation_draft={DRAFT}");
    let draft = secret_draft(Some(&valid));
    assert_eq!(draft, DraftReturn::Exact(DRAFT.into()));
    assert_eq!(
        secret_creation_return("fresh-org", &draft),
        format!("/fresh-org/new/?{valid}")
    );
    assert_eq!(
        secret_feedback_target("/fresh-org/secrets/".into(), &draft, "project-created", ""),
        format!("/fresh-org/secrets/?{valid}&message=project-created")
    );
    for raw in [
        String::new(),
        format!("{valid}&creation_draft={DRAFT}"),
        "creation_draft=https%3A%2F%2Fforeign.invalid".into(),
        "creation_draft=".into(),
        "creation_draft=00000000-0000-0000-0000-000000000000".into(),
        format!("{valid}&private={}", "x".repeat(1024)),
    ] {
        let draft = secret_draft(Some(&raw));
        assert_eq!(draft, DraftReturn::NoRequest);
        assert!(secret_creation_return("fresh-org", &draft).is_empty());
        assert_eq!(
            secret_feedback_target("/fresh-org/secrets/".into(), &draft, "", "invalid"),
            "/fresh-org/secrets/?error=invalid"
        );
    }
    assert_eq!(
        secret_feedback_target(
            "/fresh-org/secrets/".into(),
            &DraftReturn::NoRequest,
            "",
            ""
        ),
        "/fresh-org/secrets/"
    );
    let target = secret_feedback_target(
        "/fresh-org/secrets/".into(),
        &secret_draft(Some(&format!(
            "{valid}&value={PRIVATE_MARKER}&return_to=https://foreign.invalid"
        ))),
        "secret-saved",
        "",
    );
    assert!(!target.contains(PRIVATE_MARKER) && !target.contains("foreign.invalid"));
    assert_eq!(target.matches('?').count(), 1);
}

#[tokio::test]
async fn registered_secret_pages_keep_context_only_in_own_links_and_actions() {
    let (upstream, _) = fixture("success").await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    for path in [
        "/synthetic/secrets/".into(),
        "/synthetic/secrets/user/".into(),
        "/synthetic/secrets/organization/".into(),
        format!("/synthetic/secrets/{PROJECT}/"),
    ] {
        for query in [
            format!("creation_draft={DRAFT}"),
            format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
            String::new(),
        ] {
            let response = client()
                .get(format!("{}{path}?{query}", dashboard.origin))
                .headers(authority("unused"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let html = response.text().await.unwrap();
            let exact = query == format!("creation_draft={DRAFT}");
            assert_eq!(html.contains("Return to Sandbox creation"), exact);
            if exact {
                assert!(html.contains(&format!("href=\"/synthetic/new/?creation_draft={DRAFT}\"")));
                // Scope to the page-owned content; the shared Settings nav
                // intentionally does not carry a Create draft.
                let content = html.split_once("id=\"organization-content\"").unwrap().1;
                for field in content
                    .split('"')
                    .filter(|field| field.starts_with("/synthetic/secrets/"))
                {
                    assert!(
                        field.ends_with(&format!("?creation_draft={DRAFT}")),
                        "own link/action lost navigation"
                    );
                }
                // The unrelated shell never inherits page-owned navigation.
                assert!(!html.contains(&format!(
                    "/settings/?org=synthetic&amp;creation_draft={DRAFT}"
                )));
            } else {
                assert!(!html.contains("creation_draft="));
            }
            assert!(!html.contains(PRIVATE_MARKER));
        }
    }
}

#[tokio::test]
async fn native_and_htmx_validation_errors_preserve_return_errors_and_csrf_not_values() {
    let (upstream, calls) = fixture("success").await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    for htmx in [false, true] {
        for (path, fields) in [
            (
                "/synthetic/secrets/_actions/projects/create",
                vec![("name", "")],
            ),
            (
                "/synthetic/secrets/user/_actions/set",
                vec![("key", "bad-key"), ("value", PRIVATE_MARKER)],
            ),
        ] {
            let csrf = crate::security::new_csrf_token();
            let mut headers = authority(&csrf);
            if htmx {
                headers.insert(HTMX_REQUEST, "true".parse().unwrap());
            }
            let mut form = fields;
            form.push(("_csrf", &csrf));
            let response = client()
                .post(format!("{}{path}?creation_draft={DRAFT}", dashboard.origin))
                .headers(headers)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            let html = response.text().await.unwrap();
            assert!(html.contains("Return to Sandbox creation") && html.contains("role=\"alert\""));
            assert!(html.contains(&format!("name=\"_csrf\" value=\"{csrf}\"")));
            assert!(html.contains(&format!("href=\"/synthetic/new/?creation_draft={DRAFT}\"")));
            assert!(!html.contains(PRIVATE_MARKER) && !html.contains("synthetic-session"));
            assert_eq!(
                html.contains("<!DOCTYPE") || html.contains("<!doctype"),
                !htmx
            );
        }
    }
    assert!(!calls.lock().unwrap().iter().any(|(path, _)| mutation(path)));
}

#[tokio::test]
async fn navigation_does_not_change_authority_outcomes_or_dispatch_rejected_writes() {
    for mode in [
        "foreign origin",
        "bad csrf",
        "unauthenticated",
        "two factor",
        "no membership",
        "member",
    ] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        let mut statuses = Vec::new();
        for query in [
            String::new(),
            format!("creation_draft={DRAFT}"),
            format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
        ] {
            let csrf = crate::security::new_csrf_token();
            let mut headers = authority(&csrf);
            if mode == "foreign origin" {
                headers.insert(header::ORIGIN, "https://foreign.invalid".parse().unwrap());
            }
            let form_csrf = if mode == "bad csrf" {
                "bad-token"
            } else {
                &csrf
            };
            let response = client()
                .post(format!(
                    "{}/synthetic/secrets/organization/_actions/set?{query}",
                    dashboard.origin
                ))
                .headers(headers)
                .form(&[
                    ("_csrf", form_csrf),
                    ("key", "SYNTHETIC_KEY"),
                    ("value", PRIVATE_MARKER),
                ])
                .send()
                .await
                .unwrap();
            statuses.push(response.status());
            assert!(!response.text().await.unwrap().contains(PRIVATE_MARKER));
        }
        assert!(
            statuses.iter().all(|status| status == &statuses[0]),
            "navigation changed authority in {mode}"
        );
        let expected = match mode {
            "foreign origin" | "bad csrf" => StatusCode::FORBIDDEN,
            "no membership" => StatusCode::NOT_FOUND,
            _ => StatusCode::SEE_OTHER,
        };
        assert_eq!(statuses[0], expected, "wrong authority outcome in {mode}");
        assert!(
            !calls.lock().unwrap().iter().any(|(path, _)| mutation(path)),
            "rejected write dispatched in {mode}"
        );
        if mode == "foreign origin" || mode == "bad csrf" {
            assert!(calls.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn every_secret_mutation_preserves_navigation_without_changing_connect_payloads() {
    struct Operation {
        path: String,
        target: String,
        fields: Vec<(&'static str, String)>,
        message: &'static str,
        suffix: String,
    }
    let mut operations = vec![
        Operation {
            path: "/synthetic/secrets/_actions/projects/create".into(),
            target: "/synthetic/secrets/".into(),
            fields: vec![("name", "Synthetic new project".into())],
            message: "project-created",
            suffix: "/CreateSecretProject".into(),
        },
        Operation {
            path: "/synthetic/secrets/_actions/projects/delete".into(),
            target: "/synthetic/secrets/".into(),
            fields: vec![("project_id", PROJECT.into())],
            message: "project-deleted",
            suffix: "/DeleteSecretProject".into(),
        },
    ];
    for (bucket, kind) in [("organization", ""), ("user", "User"), (PROJECT, "Project")] {
        for (action, message, suffix, fields) in [
            (
                "set",
                "secret-saved",
                "Set",
                vec![
                    ("key", "SYNTHETIC_KEY".into()),
                    ("value", PRIVATE_MARKER.into()),
                ],
            ),
            (
                "delete",
                "secret-deleted",
                "Delete",
                vec![("key", "SYNTHETIC_KEY".into())],
            ),
            (
                "rename",
                "secret-renamed",
                "Rename",
                vec![
                    ("key", "SYNTHETIC_KEY".into()),
                    ("new_key", "RENAMED_KEY".into()),
                ],
            ),
        ] {
            operations.push(Operation {
                path: format!("/synthetic/secrets/{bucket}/_actions/{action}"),
                target: format!("/synthetic/secrets/{bucket}/"),
                fields,
                message,
                suffix: format!("/{suffix}{kind}Secret"),
            });
        }
    }
    for mode in ["success", "mutation denied", "mutation unauthenticated"] {
        let (upstream, calls) = fixture(mode).await;
        let dashboard = serve(crate::app(config(&upstream.origin))).await;
        for operation in &operations {
            let mut baseline = None;
            for htmx in [false, true] {
                for query in [
                    String::new(),
                    format!("creation_draft={DRAFT}"),
                    format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
                ] {
                    let exact = query == format!("creation_draft={DRAFT}");
                    let csrf = crate::security::new_csrf_token();
                    let mut headers = authority(&csrf);
                    if htmx {
                        headers.insert(HTMX_REQUEST, "true".parse().unwrap());
                    }
                    let mut form = operation.fields.clone();
                    form.push(("_csrf", csrf.clone()));
                    calls.lock().unwrap().clear();
                    let response = client()
                        .post(format!("{}{}?{query}", dashboard.origin, operation.path))
                        .headers(headers)
                        .form(&form)
                        .send()
                        .await
                        .unwrap();
                    let captured = calls.lock().unwrap().clone();
                    let writes: Vec<_> =
                        captured.iter().filter(|(path, _)| mutation(path)).collect();
                    assert_eq!(writes.len(), 1, "operation must dispatch exactly once");
                    assert!(writes[0].0.ends_with(&operation.suffix));
                    if let Some(expected) = &baseline {
                        assert!(
                            expected == &writes[0].1,
                            "navigation changed Connect payload"
                        );
                    } else {
                        baseline = Some(writes[0].1.clone());
                    }
                    assert!(
                        !writes[0]
                            .1
                            .windows(DRAFT.len())
                            .any(|bytes| bytes == DRAFT.as_bytes())
                    );
                    let validation_error = mode == "mutation denied"
                        && (operation.message == "project-created"
                            || operation.message == "secret-saved");
                    if validation_error {
                        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                        assert!(!response.headers().contains_key(header::SET_COOKIE));
                    } else {
                        assert_eq!(
                            response.status(),
                            if htmx {
                                StatusCode::OK
                            } else {
                                StatusCode::SEE_OTHER
                            }
                        );
                        let target = response.headers()
                            [if htmx { "hx-redirect" } else { "location" }]
                        .to_str()
                        .unwrap();
                        let draft = if exact {
                            DraftReturn::Exact(DRAFT.into())
                        } else {
                            DraftReturn::NoRequest
                        };
                        if mode == "mutation unauthenticated" {
                            let url = url::Url::parse(&format!("{ORIGIN}{target}")).unwrap();
                            assert_eq!(url.path(), "/login");
                            let next = url
                                .query_pairs()
                                .find(|(key, _)| key == "return_to")
                                .unwrap()
                                .1;
                            assert_eq!(
                                next,
                                secret_navigation_path(operation.target.clone(), &draft)
                            );
                            assert!(!response.headers().contains_key(header::SET_COOKIE));
                        } else {
                            assert_eq!(
                                target,
                                secret_feedback_target(
                                    operation.target.clone(),
                                    &draft,
                                    if mode == "success" {
                                        operation.message
                                    } else {
                                        ""
                                    },
                                    if mode == "mutation denied" {
                                        "not-authorized"
                                    } else {
                                        ""
                                    }
                                )
                            );
                            let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
                            assert!(cookie.starts_with("codewire_ssr_csrf="));
                            assert!(!cookie.contains(&csrf));
                        }
                    }
                    let html = response.text().await.unwrap();
                    if validation_error {
                        assert_eq!(html.contains("Return to Sandbox creation"), exact);
                        assert!(html.contains(&format!("name=\"_csrf\" value=\"{csrf}\"")));
                    }
                    assert!(!html.contains(PRIVATE_MARKER) && !html.contains("synthetic-session"));
                }
            }
        }
    }
}
