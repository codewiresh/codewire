//! Registered-route proof for the admin Pricing page (#5782) against a
//! synthetic session and billing service. No real account or price is used.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::any,
};
use buffa::Message as _;
use codewire_admin_proto::codewire::admin::v1::{
    ListRateCardsResponse, RateCard, UpdateRateCardRequest, UpdateRateCardResponse,
};
use serde_json::json;

const ORIGIN: &str = "https://dashboard.synthetic.invalid";
const CSRF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REVIEW: &str = "/admin/pricing/_actions/review";
const UPDATE: &str = "/admin/pricing/_actions/update";
/// Regular's `updated_at` as the synthetic service sends it.
const VERSION: &str = "1795392000.123456000";

/// What the synthetic billing service answers.
#[derive(Clone, Copy)]
struct Scenario {
    admin: bool,
    /// `None` answers ListRateCards with 503.
    cards: Option<&'static [&'static str]>,
    /// UpdateRateCard's answer: "ok", "stale" or "invalid".
    update: &'static str,
}

const ADMIN: Scenario = Scenario {
    admin: true,
    cards: Some(&["regular", "discounted", "unlimited"]),
    update: "ok",
};

/// The paths the service was called on, and every UpdateRateCard request.
#[derive(Clone, Default)]
struct Calls {
    paths: Arc<Mutex<Vec<String>>>,
    updates: Arc<Mutex<Vec<UpdateRateCardRequest>>>,
}

impl Calls {
    fn count(&self, method: &str) -> usize {
        self.paths
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.ends_with(&format!("/{method}")))
            .count()
    }
}

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

fn card(key: &str) -> RateCard {
    let (display_name, rates) = match key {
        "regular" => ("Regular", [43_800_000, 14_100_000, 87_000, 0]),
        "discounted" => ("Discounted", [21_900_000, 7_050_000, 43_500, 0]),
        _ => ("Unlimited", [0, 0, 0, 0]),
    };
    let mut card = RateCard {
        rate_card: key.into(),
        display_name: display_name.into(),
        cpu_nano_eur_per_vcpu_hour: rates[0],
        memory_nano_eur_per_gib_hour: rates[1],
        disk_nano_eur_per_gib_hour: rates[2],
        parked_storage_nano_eur_per_gib_hour: rates[3],
        ..Default::default()
    };
    let updated_at = card.updated_at.get_or_insert_default();
    updated_at.seconds = 1_795_392_000;
    updated_at.nanos = 123_456_000;
    card
}

fn connect_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"code": code, "message": message}))).into_response()
}

fn proto(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/proto")], bytes).into_response()
}

async fn upstream(scenario: Scenario) -> (TestServer, Calls) {
    let calls = Calls::default();
    let captured = calls.clone();
    let router = Router::new().fallback(any(move |request: axum::extract::Request| {
        let calls = captured.clone();
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 32 * 1024).await.unwrap();
            calls.paths.lock().unwrap().push(path.clone());
            if path == "/api/auth/get-session" {
                return Json(json!({"user": {
                    "id": "synthetic-account", "email": "synthetic@example.test",
                    "is_admin": scenario.admin, "two_factor_enabled": true
                }}))
                .into_response();
            }
            if path.ends_with("/ListOrganizations") {
                return proto(Vec::new());
            }
            if path.ends_with("/ListRateCards") {
                let Some(cards) = scenario.cards else {
                    return connect_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "down");
                };
                return proto(
                    ListRateCardsResponse {
                        rate_cards: cards.iter().map(|key| card(key)).collect(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                );
            }
            if path.ends_with("/UpdateRateCard") {
                calls
                    .updates
                    .lock()
                    .unwrap()
                    .push(UpdateRateCardRequest::decode_from_slice(&body).unwrap());
                return match scenario.update {
                    "stale" => connect_error(
                        StatusCode::BAD_REQUEST,
                        "failed_precondition",
                        "the rate card changed since it was read",
                    ),
                    "invalid" => connect_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_argument",
                        "cpu_nano_eur_per_vcpu_hour must not be negative",
                    ),
                    _ => proto(UpdateRateCardResponse::default().encode_to_vec()),
                };
            }
            (StatusCode::NOT_FOUND, "unexpected").into_response()
        }
    }));
    (serve(router).await, calls)
}

async fn start(scenario: Scenario) -> (TestServer, TestServer, Calls) {
    let (services, calls) = upstream(scenario).await;
    let dashboard = serve(crate::app(config(&services.origin))).await;
    (services, dashboard, calls)
}

fn authority() -> HeaderMap {
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
        .timeout(crate::test_support::LOOPBACK_HANG_GUARD)
        .build()
        .unwrap()
}

struct Page {
    status: StatusCode,
    location: String,
    body: String,
}

async fn send(request: reqwest::RequestBuilder) -> Page {
    let response = request.headers(authority()).send().await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = response.text().await.unwrap();
    Page {
        status,
        location,
        body,
    }
}

async fn get(dashboard: &TestServer, path: &str) -> Page {
    send(client().get(format!("{}{path}", dashboard.origin))).await
}

async fn post(dashboard: &TestServer, action: &str, form: &[(&str, &str)]) -> Page {
    send(
        client()
            .post(format!("{}{action}", dashboard.origin))
            .form(form),
    )
    .await
}

/// Regular's edit form as the page shows it, with `typed` in place of the
/// amounts it names.
fn review_form<'a>(typed: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![
        ("_csrf", CSRF),
        ("rate_card", "regular"),
        ("display_name", "Regular"),
        ("expected_updated_at", VERSION),
        ("now_cpu", "43800000"),
        ("now_memory", "14100000"),
        ("now_disk", "87000"),
        ("now_storage", "0"),
        ("cpu", "0.0438"),
        ("memory", "0.0141"),
        ("disk", "0.000087"),
        ("storage", "0"),
    ];
    for (name, value) in typed {
        form.iter_mut().find(|(field, _)| field == name).unwrap().1 = value;
    }
    form
}

/// The review's form for Regular with vCPU at `cpu_nano`.
fn update_form(cpu_nano: &str) -> Vec<(&str, &str)> {
    vec![
        ("_csrf", CSRF),
        ("rate_card", "regular"),
        ("expected_updated_at", VERSION),
        ("cpu_nano", cpu_nano),
        ("memory_nano", "14100000"),
        ("disk_nano", "87000"),
        ("storage_nano", "0"),
    ]
}

#[tokio::test]
async fn a_non_admin_cannot_open_the_page_or_post_either_action() {
    let (_services, dashboard, calls) = start(Scenario {
        admin: false,
        ..ADMIN
    })
    .await;
    let page = get(&dashboard, "/admin/pricing/").await;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    assert_eq!(page.location, "/dashboard/");
    let review = post(&dashboard, REVIEW, &review_form(&[("cpu", "1")])).await;
    assert_eq!(review.status, StatusCode::SEE_OTHER, "{}", review.body);
    assert_eq!(review.location, "/dashboard/");
    let mut confirmed = update_form("100000000");
    confirmed.push(("confirm_increase", "yes"));
    let update = post(&dashboard, UPDATE, &confirmed).await;
    assert_eq!(update.status, StatusCode::SEE_OTHER, "{}", update.body);
    assert_eq!(update.location, "/dashboard/");
    assert_eq!(calls.count("ListRateCards"), 0);
    assert_eq!(calls.count("UpdateRateCard"), 0);

    // Without the page's CSRF token, neither action reaches the service.
    let (_services, dashboard, calls) = start(ADMIN).await;
    let mut forged = update_form("43800000");
    forged[0].1 = "forged";
    let refused = post(&dashboard, UPDATE, &forged).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(calls.count("UpdateRateCard"), 0);
}

#[tokio::test]
async fn the_page_shows_each_card_and_edits_only_the_charged_ones() {
    let (_services, dashboard, _) = start(ADMIN).await;
    assert_eq!(
        get(&dashboard, "/admin/pricing").await.location,
        "/admin/pricing/"
    );
    let page = get(&dashboard, "/admin/pricing/").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    for text in [
        "<title>Pricing · Codewire</title>",
        "<h1 class=\"cw-page-title\">Pricing</h1><p>A change applies from the next metering draw and never re-prices past usage.</p>",
        "<a class=\"cw-nav-link\" href=\"/admin/pricing/\">Pricing</a>",
        "<h2 id=\"rate-card-regular-title\" class=\"cw-section-title\">Regular</h2><p class=\"cw-section-description\">Updated <time datetime=\"2026-11-23T00:00:00Z\">Nov 23, 2026, 00:00 UTC</time></p>",
        "<input type=\"hidden\" name=\"expected_updated_at\" value=\"1795392000.123456000\">",
        "<label class=\"cw-label\" for=\"rate-regular-cpu\">vCPU, per hour<span class=\"cw-sr-only\">, in dollars</span></label><span class=\"cw-input-group\"><span aria-hidden=\"true\">$</span><input id=\"rate-regular-cpu\" name=\"cpu\" type=\"text\" inputmode=\"decimal\" value=\"0.0438\"",
        "name=\"memory\" type=\"text\" inputmode=\"decimal\" value=\"0.0141\"",
        "name=\"disk\" type=\"text\" inputmode=\"decimal\" value=\"0.000087\"",
        "for=\"rate-regular-storage\">Storage while suspended or hibernated, per GiB-hour<",
        "<button class=\"cw-button\" type=\"submit\">Review</button>",
        "<dt>vCPU, per hour</dt><dd>$0</dd>",
        "<p class=\"cw-muted\">Unlimited is never charged.</p>",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }
    // In the order the call returns them; Unlimited has no form.
    let order = ["Regular</h2>", "Discounted</h2>", "Unlimited</h2>"]
        .map(|heading| page.body.find(heading).unwrap());
    assert!(order.is_sorted(), "{order:?}");
    assert_eq!(page.body.matches(REVIEW).count(), 2);
    assert!(!page.body.contains("rate-unlimited-cpu"));

    let saved = get(&dashboard, "/admin/pricing/?message=saved&card=discounted").await;
    assert!(saved.body.contains("Discounted&#39;s prices are saved."));
    let stale = get(&dashboard, "/admin/pricing/?error=stale").await;
    assert!(stale.body.contains(
        "role=\"alert\">These prices changed since you opened them. Review them again.</div>"
    ));
    let reflected = get(
        &dashboard,
        "/admin/pricing/?message=saved&card=%3Cscript%3E",
    )
    .await;
    assert!(!reflected.body.contains("prices are saved"));
}

#[tokio::test]
async fn a_failed_read_or_no_cards_still_renders_the_page() {
    let (_services, dashboard, _) = start(Scenario {
        cards: None,
        ..ADMIN
    })
    .await;
    let page = get(&dashboard, "/admin/pricing/").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(
        "<div class=\"cw-alert cw-alert--error\" role=\"alert\">Prices can&#39;t be loaded right now.</div>"
    ));
    assert!(!page.body.contains("<form class=\"cw-form\""));
    assert!(!page.body.contains("No rate cards"));

    let (_services, dashboard, _) = start(Scenario {
        cards: Some(&[]),
        ..ADMIN
    })
    .await;
    let page = get(&dashboard, "/admin/pricing/").await;
    assert!(page.body.contains(
        "<section class=\"cw-empty\" aria-labelledby=\"rate-cards-empty-title\"><h2 id=\"rate-cards-empty-title\" class=\"cw-empty-title\">No rate cards</h2></section>"
    ));
}

#[tokio::test]
async fn the_review_shows_now_and_new_for_changed_rates_only() {
    let (_services, dashboard, calls) = start(ADMIN).await;
    let page = post(
        &dashboard,
        REVIEW,
        &review_form(&[("cpu", " $0.0538 "), ("storage", "0.0")]),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    for text in [
        "<h2 id=\"price-review-title\" class=\"cw-section-title\">Review Regular's prices</h2>",
        "<thead><tr><th scope=\"col\">Rate</th><th scope=\"col\">Now</th><th scope=\"col\">New</th></tr></thead><tbody><tr><th scope=\"row\">vCPU, per hour</th><td>$0.0438</td><td>$0.0538</td></tr></tbody>",
        "<input type=\"hidden\" name=\"rate_card\" value=\"regular\"><input type=\"hidden\" name=\"expected_updated_at\" value=\"1795392000.123456000\"><input type=\"hidden\" name=\"cpu_nano\" value=\"53800000\"><input type=\"hidden\" name=\"memory_nano\" value=\"14100000\"><input type=\"hidden\" name=\"disk_nano\" value=\"87000\"><input type=\"hidden\" name=\"storage_nano\" value=\"0\">",
        "<a class=\"cw-button cw-button--outline\" href=\"/admin/pricing/\">Back</a><button class=\"cw-button\" type=\"submit\">Save prices</button>",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }
    assert!(!page.body.contains("More than double"));
    assert!(!page.body.contains("confirm_increase"));
    // It reads and saves nothing.
    assert_eq!(calls.count("ListRateCards"), 0);
    assert_eq!(calls.count("UpdateRateCard"), 0);

    let large = post(&dashboard, REVIEW, &review_form(&[("storage", "0.0001")])).await;
    assert!(large.body.contains(
        "<th scope=\"row\">Storage while suspended or hibernated, per GiB-hour</th><td>$0</td><td>$0.0001<span class=\"cw-status cw-status--quiet\" data-tone=\"warning\">More than double</span></td>"
    ));
    assert!(large.body.contains(
        "<label class=\"cw-choice\"><input class=\"cw-checkbox\" type=\"checkbox\" name=\"confirm_increase\" value=\"yes\" required><span>I confirm these increases.</span></label>"
    ));
}

#[tokio::test]
async fn an_unchanged_review_goes_back_with_nothing_changed() {
    let (_services, dashboard, calls) = start(ADMIN).await;
    let page = post(&dashboard, REVIEW, &review_form(&[("cpu", "0.043800000")])).await;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    assert_eq!(page.location, "/admin/pricing/?message=unchanged");
    let back = get(&dashboard, &page.location).await;
    assert!(back.body.contains(
        "<div class=\"cw-alert cw-alert--success\" role=\"status\">Nothing changed.</div>"
    ));
    assert_eq!(calls.count("UpdateRateCard"), 0);
}

#[tokio::test]
async fn a_refused_amount_keeps_what_was_typed_and_marks_its_field() {
    let (_services, dashboard, calls) = start(ADMIN).await;
    let page = post(
        &dashboard,
        REVIEW,
        &review_form(&[("cpu", "0,05"), ("disk", "10.000000001")]),
    )
    .await;
    assert_eq!(
        page.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        page.body
    );
    for text in [
        "name=\"cpu\" type=\"text\" inputmode=\"decimal\" value=\"0,05\" required maxlength=\"32\" autocomplete=\"off\" spellcheck=\"false\" aria-invalid=\"true\" aria-describedby=\"rate-regular-cpu-error\">",
        "<p class=\"cw-field-error\" id=\"rate-regular-cpu-error\">Enter an amount from $0 to $10, with at most 9 decimal places.</p>",
        "value=\"10.000000001\" required maxlength=\"32\" autocomplete=\"off\" spellcheck=\"false\" aria-invalid=\"true\"",
        "name=\"memory\" type=\"text\" inputmode=\"decimal\" value=\"0.0141\" required maxlength=\"32\" autocomplete=\"off\" spellcheck=\"false\"></span>",
    ] {
        assert!(page.body.contains(text), "missing {text}");
    }
    assert_eq!(page.body.matches("class=\"cw-field-error\"").count(), 2);
    assert_eq!(calls.count("UpdateRateCard"), 0);
}

#[tokio::test]
async fn a_large_increase_needs_the_confirmation_checked_against_the_current_card() {
    let (_services, dashboard, calls) = start(ADMIN).await;
    // $0.0438 to $0.1: more than double, sent without the checkbox.
    let refused = post(&dashboard, UPDATE, &update_form("100000000")).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.body
    );
    assert!(refused.body.contains(
        "<td>$0.0438</td><td>$0.1<span class=\"cw-status cw-status--quiet\" data-tone=\"warning\">More than double</span></td>"
    ));
    assert!(refused.body.contains("I confirm these increases."));
    assert_eq!(calls.count("ListRateCards"), 1);
    assert_eq!(calls.count("UpdateRateCard"), 0);

    let mut confirmed = update_form("100000000");
    confirmed.push(("confirm_increase", "yes"));
    let saved = post(&dashboard, UPDATE, &confirmed).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert_eq!(saved.location, "/admin/pricing/?message=saved&card=regular");
    let updates = calls.updates.lock().unwrap().clone();
    assert_eq!(updates.len(), 1);
    let request = &updates[0];
    assert_eq!(request.rate_card, "regular");
    assert_eq!(request.cpu_nano_eur_per_vcpu_hour, 100_000_000);
    assert_eq!(request.memory_nano_eur_per_gib_hour, 14_100_000);
    assert_eq!(request.disk_nano_eur_per_gib_hour, 87_000);
    assert_eq!(request.parked_storage_nano_eur_per_gib_hour, 0);
    let expected = request.expected_updated_at.as_option().unwrap();
    assert_eq!(
        (expected.seconds, expected.nanos),
        (1_795_392_000, 123_456_000)
    );

    // A rise that is not large needs no confirmation.
    let small = post(&dashboard, UPDATE, &update_form("53800000")).await;
    assert_eq!(small.location, "/admin/pricing/?message=saved&card=regular");
    assert_eq!(calls.updates.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_stale_update_asks_for_a_new_review_and_a_refused_one_says_why() {
    let (_services, dashboard, _) = start(Scenario {
        update: "stale",
        ..ADMIN
    })
    .await;
    let stale = post(&dashboard, UPDATE, &update_form("53800000")).await;
    assert_eq!(stale.status, StatusCode::SEE_OTHER, "{}", stale.body);
    assert_eq!(stale.location, "/admin/pricing/?error=stale");

    let (_services, dashboard, _) = start(Scenario {
        update: "invalid",
        ..ADMIN
    })
    .await;
    let invalid = post(&dashboard, UPDATE, &update_form("53800000")).await;
    assert_eq!(
        invalid.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        invalid.body
    );
    assert!(
        invalid
            .body
            .contains("role=\"alert\">cpu_nano_eur_per_vcpu_hour must not be negative</div>")
    );
    assert!(invalid.body.contains("Regular</h2>"));
}
