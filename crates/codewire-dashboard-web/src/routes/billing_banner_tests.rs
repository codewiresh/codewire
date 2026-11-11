//! The billing banner and Create Sandbox's credit refusal, against a
//! synthetic upstream that records each call. No real account is used.

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
use codewire_proto::codewire::{
    console::v1::{GetBillingOverviewResponse, GetEnvironmentCreateOptionsResponse},
    v1::{
        Environment, EnvironmentState, ListEnvironmentsResponse, ListInvitationsResponse,
        ListMembersResponse, ListOrganizationsResponse, OrgRole, Organization,
        OrganizationMembership,
    },
};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const ORG: &str = "00000000-0000-4000-8000-000000000002";
const DRAFT: &str = "00000000-0000-4000-8000-000000000003";
const CSRF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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

/// What the synthetic organization looks like to its viewer.
#[derive(Clone)]
struct Scenario {
    role: OrgRole,
    /// `None` answers the overview with 503.
    overview: Option<GetBillingOverviewResponse>,
    running: bool,
}

/// Ran out of credit with no card, 25 hours ago, so running Sandboxes stop
/// now (the time of day is the state function's to test).
fn exhausted() -> GetBillingOverviewResponse {
    let mut overview = GetBillingOverviewResponse {
        billing_enabled: true,
        auto_top_up_enabled: true,
        ..Default::default()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    overview.credit_exhausted_at.get_or_insert_default().seconds = now - 25 * 3_600;
    overview
}

/// €50 of credit with a card that tops it up.
fn healthy() -> GetBillingOverviewResponse {
    let mut overview = GetBillingOverviewResponse {
        billing_enabled: true,
        has_payment_method: true,
        auto_top_up_enabled: true,
        credit_balance_nano_eur: 50_000_000_000,
        ..Default::default()
    };
    let rates = overview.rates.get_or_insert_default();
    rates.cpu_nano_eur_per_vcpu_hour = 43_800_000;
    rates.memory_nano_eur_per_gib_hour = 14_100_000;
    rates.disk_nano_eur_per_gib_hour = 87_000;
    overview
}

async fn upstream(scenario: Scenario) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        let scenario = scenario.clone();
        async move {
            let path = request.uri().path().to_owned();
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
                        role: scenario.role.into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/ListEnvironments") {
                ListEnvironmentsResponse {
                    environments: vec![Environment {
                        id: "00000000-0000-4000-8000-000000000005".into(),
                        name: "synthetic-sandbox".into(),
                        state: if scenario.running {
                            EnvironmentState::Running
                        } else {
                            EnvironmentState::Stopped
                        }
                        .into(),
                        cpu_millicores: 2_000,
                        memory_mb: 8_192,
                        disk_gb: 10,
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/GetBillingOverview") {
                match scenario.overview {
                    Some(overview) => overview.encode_to_vec(),
                    None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            } else if path.ends_with("/ListMembers") {
                ListMembersResponse::default().encode_to_vec()
            } else if path.ends_with("/ListInvitations") {
                ListInvitationsResponse::default().encode_to_vec()
            } else if path.ends_with("/GetEnvironmentCreateOptions") {
                GetEnvironmentCreateOptionsResponse::default().encode_to_vec()
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
        format!("codewire.session_token=synthetic-session; codewire_ssr_csrf={CSRF}")
            .parse()
            .unwrap(),
    );
    headers
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn finish(response: reqwest::Response, calls: &Calls) -> (StatusCode, String, Vec<String>) {
    let status = response.status();
    let html = response.text().await.unwrap();
    let calls = calls.lock().unwrap().clone();
    (status, html, calls)
}

async fn get(scenario: Scenario, path: &str) -> (StatusCode, String, Vec<String>) {
    let (upstream, calls) = upstream(scenario).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let response = client()
        .get(format!("{}{path}", dashboard.origin))
        .headers(session())
        .send()
        .await
        .unwrap();
    finish(response, &calls).await
}

async fn create_options(scenario: Scenario) -> (StatusCode, String, Vec<String>) {
    let (upstream, calls) = upstream(scenario).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("_csrf", CSRF)
        .append_pair("actor", "synthetic-account")
        .append_pair("organization", ORG)
        .append_pair("draft_id", DRAFT)
        .append_pair("draft_return", "")
        .finish();
    let response = client()
        .post(format!(
            "{}/synthetic/_fragments/create-options",
            dashboard.origin
        ))
        .headers(session())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    finish(response, &calls).await
}

fn count(calls: &[String], operation: &str) -> usize {
    calls
        .iter()
        .filter(|path| path.ends_with(operation))
        .count()
}

/// The page renders without billing: the banner's placeholder is the first
/// thing in its body, and the banner loads after it.
#[tokio::test]
async fn organization_pages_load_the_banner_after_they_render() {
    for (path, body) in [
        (
            "/synthetic/",
            r#"<body class="cw-body" data-route="sandboxes">"#,
        ),
        (
            "/synthetic/members/",
            r#"<body class="cw-body" data-route="organization">"#,
        ),
    ] {
        let scenario = Scenario {
            role: OrgRole::Owner,
            overview: Some(exhausted()),
            running: true,
        };
        let (status, html, calls) = get(scenario, path).await;
        assert_eq!(status, StatusCode::OK, "{path} {calls:?}");
        assert!(
            html.contains(&format!(
                "{body}\n    <div hx-get=\"/synthetic/_fragments/billing-banner\" hx-trigger=\"load\" hx-swap=\"outerHTML\"></div>\n"
            )),
            "{path}: {html}"
        );
        assert_eq!(count(&calls, "/GetBillingOverview"), 0, "{path} {calls:?}");
    }
}

#[tokio::test]
async fn an_organization_out_of_credit_gets_the_danger_banner() {
    let (status, html, calls) = get(
        Scenario {
            role: OrgRole::Owner,
            overview: Some(exhausted()),
            running: true,
        },
        "/synthetic/_fragments/billing-banner",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert_eq!(
        html.trim(),
        "<aside class=\"cw-banner\" data-tone=\"danger\" aria-label=\"Billing\"><p>Out of credit: cloud sandboxes can’t start, and running ones stop now.</p><a class=\"cw-banner-action\" href=\"/synthetic/billing/\">Add a card</a></aside>"
    );
    assert_eq!(count(&calls, "/GetBillingOverview"), 1, "{calls:?}");
    assert_eq!(count(&calls, "/ListEnvironments"), 1, "{calls:?}");

    // A member reads the same sentence, without the action.
    let (_, html, _) = get(
        Scenario {
            role: OrgRole::Member,
            overview: Some(exhausted()),
            running: false,
        },
        "/synthetic/_fragments/billing-banner",
    )
    .await;
    assert_eq!(
        html.trim(),
        "<aside class=\"cw-banner\" data-tone=\"danger\" aria-label=\"Billing\"><p>Out of credit: cloud sandboxes can’t start.</p></aside>"
    );
}

/// Nothing to say, or billing that does not answer: an empty body, which
/// removes the placeholder. A healthy organization's Sandboxes are not read.
#[tokio::test]
async fn a_healthy_organization_or_unavailable_billing_gets_an_empty_body() {
    for (overview, sandbox_reads) in [(Some(healthy()), 0), (None, 0)] {
        let (status, html, calls) = get(
            Scenario {
                role: OrgRole::Owner,
                overview,
                running: true,
            },
            "/synthetic/_fragments/billing-banner",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{calls:?}");
        assert_eq!(html.trim(), "", "{calls:?}");
        assert_eq!(
            count(&calls, "/ListEnvironments"),
            sandbox_reads,
            "{calls:?}"
        );
    }
}

/// Create Sandbox's choices carry the refusal: the alert, and billing in
/// place of Create for an admin; a member gets the alert and no footer.
#[tokio::test]
async fn create_choices_replace_create_with_billing_while_out_of_credit() {
    let (status, html, calls) = create_options(Scenario {
        role: OrgRole::Owner,
        overview: Some(exhausted()),
        running: false,
    })
    .await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert!(
        html.contains(r#"<div data-create-credit><p class="cw-alert cw-alert--info" role="status">Synthetic organization has no card yet, so it can't run cloud sandboxes. <a href="/synthetic/billing/" data-create-draft-setup>Add a card on its Billing page</a>; this draft is kept. Local sandboxes stay free: <code>cw create --local</code>.</p></div>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<footer class="cw-drawer-footer" data-create-footer><a class="cw-button cw-button--accent cw-button--pill" href="/synthetic/billing/" data-create-draft-setup>Add a card</a></footer>"#),
        "{html}"
    );
    assert!(!html.contains(r#"type="submit""#), "{html}");

    let (_, html, _) = create_options(Scenario {
        role: OrgRole::Member,
        overview: Some(exhausted()),
        running: false,
    })
    .await;
    assert!(
        html.contains("Synthetic organization has no card yet, so it can't run cloud sandboxes. An organization owner or admin adds one on its Billing page. Local sandboxes stay free:"),
        "{html}"
    );
    assert!(
        html.contains(r#"<footer class="cw-drawer-footer" data-create-footer hidden></footer>"#),
        "{html}"
    );
    assert!(!html.contains("/synthetic/billing/"), "{html}");

    for overview in [Some(healthy()), None] {
        let (status, html, calls) = create_options(Scenario {
            role: OrgRole::Owner,
            overview,
            running: false,
        })
        .await;
        assert_eq!(status, StatusCode::OK, "{calls:?}");
        assert!(
            html.contains("<div data-create-credit hidden></div>"),
            "{html}"
        );
        assert!(
            html.contains(r#"<footer class="cw-drawer-footer" data-create-footer><button class="cw-button cw-button--accent cw-button--pill" type="submit">"#),
            "{html}"
        );
    }
}

/// With a card on file the refusal is about credit.
#[test]
fn a_card_on_file_asks_for_credit() {
    use askama::Template as _;

    let organization = crate::view::OrganizationContext::from_row(&crate::view::OrganizationRow {
        id: ORG.into(),
        name: "Synthetic organization".into(),
        slug: "synthetic".into(),
        role: "Owner",
        can_admin: true,
        billing_plan: String::new(),
        url: "/synthetic/".into(),
    });
    let mut form = super::super::environments::default_create_form(CSRF.into(), true);
    form.credit_refusal = Some(crate::billing_banner::CreditRefusal { has_card: true });
    let html = crate::templates::EnvironmentCreateFormTemplate {
        organization: &organization,
        form: &form,
    }
    .render()
    .unwrap();
    assert!(
        html.contains(r#"Synthetic organization is out of credit, so it can't run cloud sandboxes. <a href="/synthetic/billing/" data-create-draft-setup>Add credit on its Billing page</a>; this draft is kept."#),
        "{html}"
    );
    assert!(
        html.contains(r#"data-create-draft-setup>Add credit</a></footer>"#),
        "{html}"
    );

    let member = crate::view::OrganizationContext {
        can_admin: false,
        ..organization
    };
    let html = crate::templates::EnvironmentCreateFormTemplate {
        organization: &member,
        form: &form,
    }
    .render()
    .unwrap();
    assert!(
        html.contains("An organization owner or admin adds credit on its Billing page."),
        "{html}"
    );
}
