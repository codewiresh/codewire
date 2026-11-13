//! The account home, "Welcome to Codewire", against a synthetic upstream that
//! records each call. No real account is used.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use askama::Template as _;
use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse as _,
    routing::any,
};
use buffa::Message as _;
use codewire_proto::codewire::{
    console::v1::{
        EnvironmentUsageHour, GetBillingOverviewRequest, GetBillingOverviewResponse,
        GetEnvironmentUsageRequest, GetEnvironmentUsageResponse,
    },
    v1::{
        Environment, EnvironmentState, ListEnvironmentsRequest, ListEnvironmentsResponse,
        ListOrganizationsResponse, OrgRole, Organization, OrganizationMembership,
    },
};
use tokio::sync::Barrier;

use crate::{
    account_home::{AccountOverviewView, CardStats, GetStartedView, OrganizationCardView},
    templates::AccountOverviewTemplate,
};

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
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

/// How one organization answers.
#[derive(Clone)]
struct Org {
    id: &'static str,
    slug: &'static str,
    role: OrgRole,
    /// `None` answers the billing overview with 503.
    overview: Option<GetBillingOverviewResponse>,
    /// The overview never answers.
    hang: bool,
    environments: Vec<EnvironmentState>,
    /// Cost in cents this many hours ago.
    hourly: Vec<(i64, i32)>,
}

#[derive(Clone)]
struct Scenario {
    cli_signed_in: bool,
    organizations: Vec<Org>,
    /// Every billing overview waits until this many have arrived, or answers
    /// 503 after a second: a dashboard that reads them one after another
    /// gets no figures.
    together: Option<Arc<Barrier>>,
}

fn card_on_file() -> GetBillingOverviewResponse {
    GetBillingOverviewResponse {
        billing_enabled: true,
        has_payment_method: true,
        credit_balance_nano_eur: 42_180_000_000,
        month_usage_nano_eur: 17_820_000_000,
        ..Default::default()
    }
}

fn no_card() -> GetBillingOverviewResponse {
    GetBillingOverviewResponse {
        billing_enabled: true,
        ..Default::default()
    }
}

fn owner(id: &'static str, slug: &'static str) -> Org {
    Org {
        id,
        slug,
        role: OrgRole::Owner,
        overview: Some(no_card()),
        hang: false,
        environments: Vec::new(),
        hourly: Vec::new(),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn upstream(scenario: Scenario) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        let scenario = scenario.clone();
        async move {
            let path = request.uri().path().to_owned();
            if path == "/api/auth/get-session" {
                calls.lock().unwrap().push(path);
                return Json(serde_json::json!({"user": {"id": "synthetic-account", "email": "synthetic@example.test", "two_factor_enabled": true, "cli_signed_in": scenario.cli_signed_in}})).into_response();
            }
            let body = to_bytes(request.into_body(), 8192).await.unwrap();
            let organization = |id: &str| {
                scenario
                    .organizations
                    .iter()
                    .find(|organization| organization.id == id)
                    .cloned()
            };
            let bytes = if path.ends_with("/ListOrganizations") {
                calls.lock().unwrap().push(path);
                ListOrganizationsResponse {
                    organizations: scenario
                        .organizations
                        .iter()
                        .map(|organization| OrganizationMembership {
                            organization: Some(Organization {
                                id: organization.id.into(),
                                name: organization.slug.into(),
                                slug: organization.slug.into(),
                                ..Default::default()
                            })
                            .into(),
                            role: organization.role.into(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/ListEnvironments") {
                let request = ListEnvironmentsRequest::decode_from_slice(&body).unwrap();
                calls.lock().unwrap().push(format!(
                    "{path} {} destroyed={}",
                    request.org_id, request.include_destroyed
                ));
                let Some(organization) = organization(&request.org_id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                ListEnvironmentsResponse {
                    environments: organization
                        .environments
                        .iter()
                        .enumerate()
                        .map(|(index, state)| Environment {
                            id: format!("00000000-0000-4000-8000-0000000000{index:02}"),
                            name: format!("sandbox-{index}"),
                            state: (*state).into(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }
                .encode_to_vec()
            } else if path.ends_with("/GetBillingOverview") {
                let request = GetBillingOverviewRequest::decode_from_slice(&body).unwrap();
                calls
                    .lock()
                    .unwrap()
                    .push(format!("{path} {}", request.org_id));
                let Some(organization) = organization(&request.org_id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if organization.hang {
                    std::future::pending::<()>().await;
                }
                if let Some(together) = &scenario.together
                    && tokio::time::timeout(Duration::from_secs(1), together.wait())
                        .await
                        .is_err()
                {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                match organization.overview {
                    Some(overview) => overview.encode_to_vec(),
                    None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            } else if path.ends_with("/GetEnvironmentUsage") {
                let request = GetEnvironmentUsageRequest::decode_from_slice(&body).unwrap();
                calls
                    .lock()
                    .unwrap()
                    .push(format!("{path} {}", request.org_id));
                let Some(organization) = organization(&request.org_id) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let current = now() - now() % 3_600;
                GetEnvironmentUsageResponse {
                    hourly_breakdown: organization
                        .hourly
                        .iter()
                        .map(|(back, cents)| {
                            let mut hour = EnvironmentUsageHour {
                                cost_nano_eur: i64::from(*cents) * 10_000_000,
                                ..Default::default()
                            };
                            hour.hour.get_or_insert_default().seconds = current - back * 3_600;
                            hour
                        })
                        .collect(),
                    ..Default::default()
                }
                .encode_to_vec()
            } else {
                calls.lock().unwrap().push(path);
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
        }
    }));
    (serve(router).await, calls)
}

fn session(remembered: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, ORIGIN.parse().unwrap());
    let cookie = match remembered {
        Some(slug) => {
            format!("codewire.session_token=synthetic-session; codewire_current_org={slug}")
        }
        None => "codewire.session_token=synthetic-session".to_owned(),
    };
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    headers
}

async fn get(
    scenario: Scenario,
    path: &str,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, String, Vec<String>) {
    let (upstream, calls) = upstream(scenario).await;
    let dashboard = serve(crate::app(config(&upstream.origin))).await;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
        .get(format!("{}{path}", dashboard.origin))
        .headers(headers)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let html = response.text().await.unwrap();
    let calls = calls.lock().unwrap().clone();
    (status, headers, html, calls)
}

fn count(calls: &[String], operation: &str) -> usize {
    calls.iter().filter(|call| call.contains(operation)).count()
}

fn two_organizations() -> Scenario {
    Scenario {
        cli_signed_in: false,
        organizations: vec![
            owner("org-first", "first-org"),
            Org {
                role: OrgRole::Member,
                ..owner("org-second", "second-org")
            },
        ],
        together: None,
    }
}

/// `/dashboard/` is the account home, not a redirect (owner, 2026-11-10). It
/// answers after the session check and the organization read, before any
/// organization is read, naming the remembered organization or else the
/// first; its checklist and cards load as one fragment.
#[tokio::test]
async fn the_account_home_renders_its_shell_before_reading_any_organization() {
    for (remembered, current) in [(None, "first-org"), (Some("second-org"), "second-org")] {
        let (status, _, html, calls) =
            get(two_organizations(), "/dashboard/", session(remembered)).await;
        assert_eq!(status, StatusCode::OK, "{remembered:?} {calls:?}");
        assert_eq!(count(&calls, "/api/auth/get-session"), 1, "{calls:?}");
        assert_eq!(count(&calls, "/ListOrganizations"), 1, "{calls:?}");
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(html.contains("<title>Welcome to Codewire</title>"));
        assert!(html.contains(r#"<h1 class="cw-page-title">Welcome to Codewire</h1>"#));
        assert!(html.contains(r#"<div class="cw-console-breadcrumb"><strong>home</strong></div>"#));
        assert!(html.contains(&format!(
            r#"hx-get="/dashboard/_fragments/overview?current={current}" hx-trigger="load, account-overview-retry" hx-swap="innerHTML" aria-busy="true" data-account-overview>"#
        )));
        assert!(
            html.contains(
                r#"<span data-account-overview-status>Loading your organizations…</span>"#
            )
        );
        // One skeleton card per organization while they load.
        assert_eq!(
            html.matches(
                r#"<li class="cw-card"><div class="cw-card-body"><div class="cw-row-skeleton">"#
            )
            .count(),
            2
        );
        // The sidebar names the organization and loads its rail afterwards.
        assert!(html.contains(&format!(
            r#"<span class="cw-org-switcher-label">{current}</span>"#
        )));
        assert!(html.contains(&format!(
            r#"hx-get="/{current}/_fragments/sandbox-rail" hx-trigger="sandbox-rail-refresh""#
        )));
        assert!(html.contains(r#"data-rail-loading="true""#));
        assert!(html.contains("/assets/codewire/routes/overview-v1.css"));
    }
}

/// An account without an organization keeps the page that offers to create
/// one; there is nothing to load.
#[tokio::test]
async fn an_account_without_organizations_is_offered_one() {
    let scenario = Scenario {
        cli_signed_in: false,
        organizations: Vec::new(),
        together: None,
    };
    let (status, _, html, calls) = get(scenario, "/dashboard/", session(None)).await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert!(html.contains("No organizations yet"));
    assert!(html.contains(r#"href="/organizations/new/">Create Organization</a>"#));
    assert!(!html.contains("data-account-overview"));
}

/// Switching organization from the home opens that organization, as before.
#[tokio::test]
async fn switching_organization_from_the_home_opens_it() {
    let (status, headers, _, _) = get(
        two_organizations(),
        "/dashboard/?org=second-org",
        session(None),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/second-org/");
}

/// The fragment reads every organization's billing, its Sandbox list
/// (destroyed ones included) and its usage once each, and reads the
/// organizations at once: the overviews answer only when both have arrived.
#[tokio::test]
async fn the_overview_reads_every_organization_once_and_at_once() {
    let mut scenario = two_organizations();
    scenario.together = Some(Arc::new(Barrier::new(2)));
    scenario.organizations[0].overview = Some(card_on_file());
    scenario.organizations[0].environments =
        vec![EnvironmentState::Running, EnvironmentState::Stopped];
    scenario.organizations[0].hourly = vec![(0, 84), (3, 21)];
    let (status, _, html, calls) = get(
        scenario,
        "/dashboard/_fragments/overview?current=first-org",
        session(None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    for organization in ["org-first", "org-second"] {
        assert_eq!(
            count(&calls, &format!("/GetBillingOverview {organization}")),
            1,
            "{calls:?}"
        );
        assert_eq!(
            count(
                &calls,
                &format!("/ListEnvironments {organization} destroyed=true")
            ),
            1,
            "{calls:?}"
        );
        assert_eq!(
            count(&calls, &format!("/GetEnvironmentUsage {organization}")),
            1,
            "{calls:?}"
        );
    }
    assert!(!html.contains("<script"));
    // first-org: a card on file and a Sandbox, so only the CLI is left.
    assert!(
        html.contains(
            "2 of 3 done. Each step ticks itself off, and this goes away when all three are."
        ),
        "{html}"
    );
    assert!(html.contains("<code>curl -fsSL https://get.codewire.sh | sh</code>"));
    assert!(html.contains("A card is on file."));
    assert!(html.contains("Created in this organization."));
    assert_eq!(html.matches(r#"<li data-done="true">"#).count(), 2);
    // Its card: the balance, this month and the running count, and the chart.
    assert!(
        html.contains(
            r#"<h3 id="first-org-name">first-org</h3><span class="cw-badge">Owner</span>"#
        )
    );
    assert!(html.contains("<dt>Balance</dt><dd>€42.18</dd>"));
    assert!(html.contains("<dt>This month</dt><dd>€17.82</dd>"));
    assert!(html.contains("<dt>Running</dt><dd>1</dd>"));
    assert!(html.contains(
        r#"<title id="first-org-chart-title">Hourly Sandbox cost for first-org</title>"#
    ));
    assert_eq!(html.matches(r#"<rect class="cw-chart-bar""#).count(), 24);
    assert!(html.contains(r#"x="280" y="8" width="8" height="72" tabindex="0">"#));
    assert!(html.contains(r#"<a class="cw-button cw-button--small cw-button--outline" href="/first-org/billing/">Billing</a>"#));
    // second-org: never had a Sandbox, and a member gets no Billing link.
    assert!(html.contains(
        r#"<h3 id="second-org-name">second-org</h3><span class="cw-badge">Member</span>"#
    ));
    assert!(html.contains(r#"<p class="cw-muted">No cloud usage yet.</p>"#));
    assert!(!html.contains(r#"href="/second-org/billing/">Billing</a>"#));
    assert!(html.contains(r#"href="/second-org/">Sandboxes</a>"#));
}

/// A failing or silent organization keeps its card without the figures it
/// could not read; the others and the page are unaffected, and the fragment
/// answers within the read deadline.
#[tokio::test]
async fn a_failing_or_silent_organization_keeps_its_card() {
    let mut scenario = two_organizations();
    scenario.organizations[0].overview = None;
    scenario.organizations[1].hang = true;
    scenario.organizations.push(Org {
        overview: Some(card_on_file()),
        environments: vec![EnvironmentState::Running],
        ..owner("org-third", "third-org")
    });
    let started = Instant::now();
    let (status, _, html, calls) = get(
        scenario,
        "/dashboard/_fragments/overview?current=third-org",
        session(None),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_eq!(
        html.matches(r#"<p class="cw-muted">Its balance and usage are unavailable right now.</p>"#)
            .count(),
        2,
        "{html}"
    );
    for slug in ["first-org", "second-org", "third-org"] {
        assert!(
            html.contains(&format!(r#"<h3 id="{slug}-name">{slug}</h3>"#)),
            "{slug}"
        );
        assert!(
            html.contains(&format!(r#"href="/{slug}/">Sandboxes</a>"#)),
            "{slug}"
        );
    }
    assert!(html.contains("<dt>Running</dt><dd>1</dd>"));
}

/// The fragment answers a signed-out browser with the sign-in page, which
/// htmx follows as a whole-page navigation.
#[tokio::test]
async fn the_overview_sends_a_signed_out_browser_to_sign_in() {
    let mut headers = HeaderMap::new();
    headers.insert("HX-Request", "true".parse().unwrap());
    let (status, response, _, calls) = get(
        two_organizations(),
        "/dashboard/_fragments/overview",
        headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{calls:?}");
    assert_eq!(response["HX-Redirect"], "/login?return_to=%2Fdashboard%2F");
    assert!(calls.is_empty(), "{calls:?}");
}

fn render(overview: &AccountOverviewView) -> String {
    AccountOverviewTemplate { overview }.render().unwrap()
}

fn steps(cli: bool, card: bool, sandbox: bool, can_admin: bool) -> GetStartedView {
    GetStartedView {
        done: [cli, card, sandbox]
            .into_iter()
            .filter(|step| *step)
            .count(),
        cli,
        card,
        unmetered: false,
        sandbox,
        can_admin,
        billing_url: "/example-org/billing/".into(),
        new_sandbox_url: "/example-org/new/".into(),
    }
}

fn card(stats: Option<CardStats>) -> OrganizationCardView {
    OrganizationCardView {
        name: "example-org".into(),
        slug: "example-org".into(),
        role: "Owner",
        stats,
        bars: Vec::new(),
        no_usage: true,
        sandboxes_url: "/example-org/".into(),
        billing_url: Some("/example-org/billing/".into()),
    }
}

/// Each step's markup follows its state: to do with its action, or done
/// with a check and no action; the card goes away at 3 of 3.
#[test]
fn the_checklist_markup_follows_each_step() {
    let to_do = render(&AccountOverviewView {
        get_started: Some(steps(false, false, false, true)),
        organizations: vec![card(None)],
        shared_scale: false,
    });
    assert!(to_do.contains("0 of 3 done."));
    assert_eq!(
        to_do
            .matches(
                r#"<span class="cw-checklist-mark"><span class="cw-sr-only">To do:</span></span>"#
            )
            .count(),
        3
    );
    assert!(to_do.contains(r#"data-copy-command aria-label="Copy install command""#));
    assert!(to_do.contains("data-copy-prompt"));
    assert!(to_do.contains(
        r#"<a class="cw-button cw-button--small" href="/example-org/billing/">Add a card</a>"#
    ));
    assert!(to_do.contains(r#"<a class="cw-button cw-button--small cw-button--outline" href="/example-org/new/">Create Sandbox</a>"#));
    assert!(to_do.contains("<p>From here, or with <code>cw create --cloud</code>.</p>"));

    let done = render(&AccountOverviewView {
        get_started: Some(steps(true, true, false, true)),
        organizations: vec![card(None)],
        shared_scale: false,
    });
    assert!(done.contains("2 of 3 done."));
    assert_eq!(
        done.matches(r##"#icon-check"/></svg><span class="cw-sr-only">Done:</span>"##)
            .count(),
        2
    );
    assert!(done.contains("<p>Signed in from the CLI.</p>"));
    assert!(!done.contains("data-copy-command"));
    assert!(!done.contains("Add a card</a>"));

    let all = render(&AccountOverviewView {
        get_started: None,
        organizations: vec![card(None)],
        shared_scale: false,
    });
    assert!(!all.contains("Get started"));
    assert!(all.contains(r#"<h3 id="example-org-name">example-org</h3>"#));
}

/// A member cannot add the card: the step says who can, and offers no link.
#[test]
fn a_member_is_told_who_adds_the_card() {
    let html = render(&AccountOverviewView {
        get_started: Some(steps(false, false, false, false)),
        organizations: vec![card(None)],
        shared_scale: false,
    });
    assert!(
        html.contains("<p>An organization owner or admin adds a card on the Billing page.</p>")
    );
    assert!(!html.contains("Add a card</a>"));
    assert!(!html.contains(r#"href="/example-org/billing/">Add a card"#));
}

/// An unmetered organization: the card step is done with nothing to add, and
/// its card says Unlimited instead of a balance.
#[test]
fn an_unmetered_organization_shows_unlimited() {
    let mut get_started = steps(false, true, false, true);
    get_started.unmetered = true;
    let html = render(&AccountOverviewView {
        get_started: Some(get_started),
        organizations: vec![card(Some(CardStats {
            balance: "Unlimited".into(),
            month: "€0.00".into(),
            running: 0,
        }))],
        shared_scale: false,
    });
    assert!(html.contains("<p>Nothing to add: cloud use isn’t charged here.</p>"));
    assert!(html.contains("<dt>Balance</dt><dd>Unlimited</dd>"));
}

/// The reviewed design fixtures show exactly what the template renders for
/// their two states, through the same builder: a new account (0 of 3, one
/// organization, no usage) and an active one (the checklist gone, two
/// organizations whose charts share a scale). Only links and asset paths
/// differ, so the fixtures stay clickable.
#[test]
fn the_design_fixtures_are_what_the_home_renders() {
    use crate::{
        account_home::{OrganizationReads, SandboxSummary, build},
        billing_connect::{BillingSummary, HourCost},
        view::OrganizationRow,
    };
    let organization = |slug: &str, can_admin: bool| OrganizationRow {
        id: format!("id-{slug}"),
        name: slug.to_owned(),
        slug: slug.to_owned(),
        role: if can_admin { "Owner" } else { "Member" },
        can_admin,
        billing_plan: String::new(),
        url: format!("/{slug}/"),
    };
    // 2026-11-10 23:20 UTC: the last 24 hours are that day's.
    let now = 1_794_352_800;
    let midnight = now - 23 * 3_600 - 20 * 60;
    let day = |cents: [i32; 24]| {
        cents
            .iter()
            .enumerate()
            .map(|(hour, cents)| HourCost {
                hour: midnight + hour as i64 * 3_600,
                cost_nano_eur: i64::from(*cents) * 10_000_000,
            })
            .collect::<Vec<_>>()
    };
    let new_account = build(
        false,
        &[organization("example-org", true)],
        &[OrganizationReads {
            billing: Some(BillingSummary {
                has_card: false,
                metered: true,
                balance_nano_eur: 0,
                month_nano_eur: 0,
            }),
            sandboxes: Some(SandboxSummary {
                running: 0,
                ever: false,
            }),
            hourly: Some(Vec::new()),
        }],
        "example-org",
        now,
    );
    let active = build(
        true,
        &[
            organization("example-org", true),
            organization("acme-research", false),
        ],
        &[
            OrganizationReads {
                billing: Some(BillingSummary {
                    has_card: true,
                    metered: true,
                    balance_nano_eur: 42_180_000_000,
                    month_nano_eur: 17_820_000_000,
                }),
                sandboxes: Some(SandboxSummary {
                    running: 2,
                    ever: true,
                }),
                hourly: Some(day([
                    0, 0, 0, 0, 0, 0, 0, 21, 42, 42, 63, 63, 42, 42, 63, 84, 84, 42, 21, 21, 42,
                    42, 21, 42,
                ])),
            },
            OrganizationReads {
                billing: Some(BillingSummary {
                    has_card: true,
                    metered: true,
                    balance_nano_eur: 118_400_000_000,
                    month_nano_eur: 3_100_000_000,
                }),
                sandboxes: Some(SandboxSummary {
                    running: 1,
                    ever: true,
                }),
                hourly: Some(day([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 20, 20, 20, 20, 20, 20, 20, 0, 0, 0, 0, 0, 0, 0,
                ])),
            },
        ],
        "example-org",
        now,
    );
    for (name, fixture, overview, sandboxes) in [
        (
            "account-overview.html",
            include_str!(
                "../../../../packages/codewire-design/reference/fixtures/account-overview.html"
            ),
            new_account,
            "sandboxes-empty.html",
        ),
        (
            "account-overview-active.html",
            include_str!(
                "../../../../packages/codewire-design/reference/fixtures/account-overview-active.html"
            ),
            active,
            "sandboxes.html",
        ),
    ] {
        let mut html = render(&overview);
        for (production, local) in [
            (
                "/assets/codewire/icons-v2.svg",
                "../../assets/icons.svg".to_owned(),
            ),
            (
                r#"href="/example-org/billing/""#,
                r##"href="#example-org-billing""##.to_owned(),
            ),
            (
                r#"href="/example-org/new/""#,
                r#"href="create-sandbox.html""#.to_owned(),
            ),
            (r#"href="/example-org/""#, format!(r#"href="{sandboxes}""#)),
            (
                r#"href="/acme-research/""#,
                r##"href="#acme-research-sandboxes""##.to_owned(),
            ),
        ] {
            html = html.replace(production, &local);
        }
        let region = format!(
            r#"<div class="cw-overview" id="account-overview" aria-busy="false" data-account-overview>{html}    </div>"#
        );
        assert!(
            fixture.contains(&region),
            "{name} drifted from production; it renders:\n{region}"
        );
        for shell in [
            r#"<div class="cw-console-breadcrumb"><strong>home</strong></div>"#,
            r#"<header class="cw-page-header"><div class="cw-list-title"><h1 class="cw-page-title">Welcome to Codewire</h1></div></header>"#,
            r#"<link rel="stylesheet" href="../../routes/billing-admin.css">"#,
            r#"<link rel="stylesheet" href="../../routes/overview.css">"#,
            r#"<body class="cw-body" data-route="overview">"#,
        ] {
            assert!(fixture.contains(shell), "{name} lacks {shell}");
        }
    }
    let page = include_str!("../../templates/account-home.html");
    for shell in [
        r#"<div class="cw-console-breadcrumb"><strong>home</strong></div>"#,
        r#"<header class="cw-page-header"><div class="cw-list-title"><h1 class="cw-page-title">Welcome to Codewire</h1></div></header>"#,
        r#"<link rel="stylesheet" href="/assets/codewire/routes/billing-admin-v1.css">"#,
        r#"<link rel="stylesheet" href="/assets/codewire/routes/overview-v1.css">"#,
        r#"<body class="cw-body" data-route="overview">"#,
    ] {
        assert!(page.contains(shell), "account-home.html lacks {shell}");
    }
}
