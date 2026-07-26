//! Black-box wire contract for the billing service.
//!
//! The selected service and Kind gates start the real `codewire-billing`
//! binary, load the deterministic fixture, and run this test over its network
//! listener. Stripe configuration is mandatory for this contract. The suite
//! uses an inert key and exercises only checks that complete before outbound
//! Stripe I/O.

use std::env;
use std::time::Duration;

use codewire_proto::codewire::admin::v1::{
    BillingCatalogServiceClient, GetCatalogRequest, ListSubscriptionMigrationsRequest,
};
use connectrpc::{CodecFormat, ErrorCode};
use reqwest::header::COOKIE;
use reqwest::{Client, Method, StatusCode};
use serde_json::{Map, Value, json};

const SESSION_COOKIE: &str = "codewire.session_token";
const BILLING_SERVICE: &str = "/codewire.console.v1.BillingService";
const BILLING_CATALOG_SERVICE: &str = "/codewire.admin.v1.BillingCatalogService";

#[derive(Debug)]
struct WireResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl WireResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "decode HTTP {} body {:?} as JSON: {error}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn assert_status(&self, expected: StatusCode, label: &str) {
        assert_eq!(
            self.status,
            expected,
            "{label}: body={:?}",
            String::from_utf8_lossy(&self.body)
        );
    }
}

struct Harness {
    base_url: String,
    frontend_url: String,
    admin_token: String,
    user_token: String,
    skip_health: bool,
    client: Client,
}

impl Harness {
    fn from_env() -> Self {
        assert_eq!(
            required_env("BILLING_SEEDED"),
            "1",
            "BILLING_SEEDED must declare the deterministic fixture"
        );
        assert_eq!(
            required_env("BILLING_STRIPE_CONFIGURED"),
            "1",
            "Stripe configuration is mandatory for the billing wire contract"
        );

        let base_url = trim_url(&required_env("BILLING_BASE_URL"));
        let frontend_url = env::var("BILLING_FRONTEND_URL")
            .map(|value| trim_url(&value))
            .unwrap_or_else(|_| base_url.clone());

        Self {
            base_url,
            frontend_url,
            admin_token: required_env("BILLING_ADMIN_SESSION_TOKEN"),
            user_token: required_env("BILLING_USER_SESSION_TOKEN"),
            skip_health: env::var("BILLING_SKIP_HEALTH").as_deref() == Ok("1"),
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("build billing contract HTTP client"),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> WireResponse {
        let mut request = self
            .client
            .request(method.clone(), format!("{}{}", self.base_url, path));
        if let Some(token) = token {
            request = request.header("cookie", format!("{SESSION_COOKIE}={token}"));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|error| panic!("{method} {path}: {error}"));
        let status = response.status();
        let body = response
            .bytes()
            .await
            .unwrap_or_else(|error| panic!("read {method} {path} response: {error}"))
            .to_vec();
        WireResponse { status, body }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> WireResponse {
        self.request(Method::GET, path, token, None).await
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> WireResponse {
        self.request(Method::POST, path, token, Some(&body)).await
    }

    async fn connect(&self, method: &str, token: Option<&str>, body: Value) -> WireResponse {
        self.connect_service(BILLING_SERVICE, method, token, body)
            .await
    }

    async fn connect_catalog(
        &self,
        method: &str,
        token: Option<&str>,
        body: Value,
    ) -> WireResponse {
        self.connect_service(BILLING_CATALOG_SERVICE, method, token, body)
            .await
    }

    async fn connect_service(
        &self,
        service: &str,
        method: &str,
        token: Option<&str>,
        body: Value,
    ) -> WireResponse {
        self.post(&format!("{service}/{method}"), token, body).await
    }

    fn connect_client_config(&self, codec: CodecFormat) -> connectrpc::client::ClientConfig {
        connectrpc::client::ClientConfig::new(self.base_url.parse().expect("Connect base URI"))
            .with_codec_format(codec)
            .with_default_timeout(Duration::from_secs(10))
            .with_default_header(COOKIE, format!("{SESSION_COOKIE}={}", self.admin_token))
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required by the selected billing contract"))
}

fn trim_url(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

fn object<'a>(value: &'a Value, label: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{label}: expected object, got {value}"))
}

fn array<'a>(value: &'a Value, label: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label}: expected array, got {value}"))
}

fn assert_keys(value: &Value, keys: &[&str], label: &str) {
    let value = object(value, label);
    for key in keys {
        assert!(value.contains_key(*key), "{label}: missing key {key:?}");
    }
}

fn assert_coded_error(response: &WireResponse, status: StatusCode, code: &str, detail: &str) {
    response.assert_status(status, "coded error");
    let body = response.json();
    assert_eq!(body["status"], json!(status.as_u16()));
    assert_eq!(body["code"], code);
    assert_eq!(body["detail"], detail);
}

fn assert_connect_error(response: &WireResponse, status: StatusCode, code: &str) -> Value {
    response.assert_status(status, "Connect error");
    let body = response.json();
    assert_eq!(body["code"], code, "Connect error body={body}");
    body
}

fn assert_validation(response: &WireResponse, field: &str) {
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY, "validation error");
    let body = response.json();
    assert_eq!(body["status"], 422);
    assert_eq!(body["title"], "Unprocessable Entity");
    assert_eq!(body["detail"], "validation failed");
    let errors = array(&body["errors"], "validation errors");
    assert!(
        errors.iter().any(|error| error["message"]
            .as_str()
            .is_some_and(|message| message.contains(field))),
        "validation errors did not mention {field:?}: {errors:?}"
    );
}

async fn assert_health(harness: &Harness) {
    if harness.skip_health {
        return;
    }
    harness
        .get("/healthz", None)
        .await
        .assert_status(StatusCode::OK, "GET /healthz");
    harness
        .get("/readyz", None)
        .await
        .assert_status(StatusCode::OK, "GET /readyz");
}

async fn assert_rest_auth(harness: &Harness) {
    for path in [
        "/api/v1/admin/billing/catalog",
        "/api/v1/billing/plans/sandbox",
        "/api/v1/billing/plans/org",
        "/api/v1/organizations/org_contract_1/billing/invoices",
        "/api/v1/organizations/org_contract_1/billing/events",
        "/api/v1/organizations/org_contract_1/billing",
        "/api/v1/organizations/org_contract_1/environments/usage",
    ] {
        let response = harness.get(path, None).await;
        assert_coded_error(
            &response,
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "unauthorized",
        );
        let body = response.json();
        assert_eq!(body["title"], "Unauthorized");
    }

    harness
        .get(
            "/api/v1/billing/plans/sandbox",
            Some("contract-stale-session-token"),
        )
        .await
        .assert_status(StatusCode::UNAUTHORIZED, "expired session");

    let response = harness
        .get("/api/v1/admin/billing/catalog", Some(&harness.user_token))
        .await;
    assert_coded_error(&response, StatusCode::FORBIDDEN, "forbidden", "forbidden");
    assert_eq!(response.json()["title"], "Forbidden");
}

async fn assert_catalog_and_plans(harness: &Harness) -> (Value, Value, Value) {
    let response = harness
        .get("/api/v1/admin/billing/catalog", Some(&harness.admin_token))
        .await;
    response.assert_status(StatusCode::OK, "admin billing catalog");
    let catalog = response.json();
    for name in ["plans", "prices", "settings"] {
        array(&catalog[name], name);
    }
    for plan in array(&catalog["plans"], "catalog plans") {
        assert_keys(
            plan,
            &[
                "resource_type",
                "plan_key",
                "display_name",
                "price_cents",
                "is_contact_us",
                "is_admin_only",
                "archived",
            ],
            "catalog plan",
        );
    }
    for price in array(&catalog["prices"], "catalog prices") {
        assert_keys(
            price,
            &[
                "resource_type",
                "plan_key",
                "stripe_mode",
                "price_kind",
                "stripe_price_id",
                "archived",
            ],
            "catalog price",
        );
    }
    assert!(
        array(&catalog["plans"], "catalog plans")
            .iter()
            .any(|plan| plan["plan_key"] == "legacy" && plan["archived"] == true),
        "admin catalog omitted seeded archived plan"
    );
    assert!(
        array(&catalog["plans"], "catalog plans")
            .iter()
            .any(|plan| plan["plan_key"] == "internal-admin" && plan["is_admin_only"] == true),
        "admin catalog omitted seeded admin-only plan"
    );
    assert!(!array(&catalog["prices"], "catalog prices").is_empty());
    assert!(!array(&catalog["settings"], "catalog settings").is_empty());

    let org_response = harness
        .get("/api/v1/billing/plans/org", Some(&harness.user_token))
        .await;
    org_response.assert_status(StatusCode::OK, "REST org plans");
    let org_plans = org_response.json();
    for (key, plan) in object(&org_plans, "REST org plans") {
        assert_keys(
            plan,
            &[
                "display_name",
                "price_cents",
                "included_devs",
                "max_concurrent_ws",
                "max_team_members",
                "storage_gb",
                "is_contact_us",
            ],
            &format!("REST org plan {key}"),
        );
        assert_ne!(plan.get("archived"), Some(&Value::Bool(false)));
        assert_ne!(plan.get("is_admin_only"), Some(&Value::Bool(false)));
    }

    let resource_response = harness
        .get("/api/v1/billing/plans/sandbox", Some(&harness.user_token))
        .await;
    resource_response.assert_status(StatusCode::OK, "REST resource plans");
    let resource_plans = resource_response.json();
    for (key, plan) in object(&resource_plans, "REST resource plans") {
        assert_keys(
            plan,
            &[
                "display_name",
                "price_cents",
                "included_devs",
                "max_concurrent_ws",
                "max_team_members",
                "storage_gb",
                "is_contact_us",
                "included_cpu_hours",
                "included_mem_gb_hours",
                "included_disk_gb_hours",
                "cpu_overage_cents",
                "mem_overage_cents",
                "disk_overage_cents",
            ],
            &format!("REST resource plan {key}"),
        );
        assert_ne!(plan.get("archived"), Some(&Value::Bool(false)));
        assert_ne!(plan.get("is_admin_only"), Some(&Value::Bool(false)));
    }

    let admin_resource_response = harness
        .get("/api/v1/billing/plans/sandbox", Some(&harness.admin_token))
        .await;
    admin_resource_response.assert_status(StatusCode::OK, "admin REST resource plans");
    let admin_resource_plans = admin_resource_response.json();

    assert_eq!(org_plans["starter"]["display_name"], "Starter");
    assert_eq!(org_plans["starter"]["price_cents"], 4900);
    assert!(object(&resource_plans, "user resource plans").contains_key("standard"));
    assert!(!object(&resource_plans, "user resource plans").contains_key("internal-admin"));
    assert!(object(&admin_resource_plans, "admin resource plans").contains_key("internal-admin"));
    assert!(!object(&resource_plans, "user resource plans").contains_key("legacy"));
    assert!(!object(&admin_resource_plans, "admin resource plans").contains_key("legacy"));

    (catalog, org_plans, resource_plans)
}

async fn assert_billing_catalog_connect_contract(harness: &Harness, rest_catalog: &Value) {
    let response = harness.connect_catalog("GetCatalog", None, json!({})).await;
    assert_connect_error(&response, StatusCode::UNAUTHORIZED, "unauthenticated");

    let response = harness
        .connect_catalog("GetCatalog", Some(&harness.user_token), json!({}))
        .await;
    assert_connect_error(&response, StatusCode::FORBIDDEN, "permission_denied");

    let response = harness
        .connect_catalog("GetCatalog", Some(&harness.admin_token), json!({}))
        .await;
    response.assert_status(StatusCode::OK, "BillingCatalogService.GetCatalog");
    let catalog = response.json();
    assert_eq!(
        catalog["plans"].as_array().map(Vec::len),
        rest_catalog["plans"].as_array().map(Vec::len)
    );
    assert_eq!(
        catalog["prices"].as_array().map(Vec::len),
        rest_catalog["prices"].as_array().map(Vec::len)
    );
    assert_eq!(
        catalog["settings"].as_array().map(Vec::len),
        rest_catalog["settings"].as_array().map(Vec::len)
    );
    let starter = array(&catalog["plans"], "Connect catalog plans")
        .iter()
        .find(|plan| plan["resourceType"] == "org" && plan["planKey"] == "starter")
        .expect("Connect catalog omitted org/starter");
    let rest_starter = array(&rest_catalog["plans"], "REST catalog plans")
        .iter()
        .find(|plan| plan["resource_type"] == "org" && plan["plan_key"] == "starter")
        .expect("REST catalog omitted org/starter");
    assert_eq!(starter["plan"]["displayName"], rest_starter["display_name"]);
    assert_eq!(starter["plan"]["priceCents"], rest_starter["price_cents"]);
    let standard = array(&catalog["plans"], "Connect catalog plans")
        .iter()
        .find(|plan| plan["resourceType"] == "sandbox" && plan["planKey"] == "standard")
        .expect("Connect catalog omitted sandbox/standard");
    let rest_standard = array(&rest_catalog["plans"], "REST catalog plans")
        .iter()
        .find(|plan| plan["resource_type"] == "sandbox" && plan["plan_key"] == "standard")
        .expect("REST catalog omitted sandbox/standard");
    assert_eq!(
        standard["plan"]["cpuOverageCents"],
        rest_standard["cpu_overage_cents"]
    );

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = BillingCatalogServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.connect_client_config(codec),
        );
        let catalog = client
            .get_catalog(GetCatalogRequest::default())
            .await
            .expect("BillingCatalogService GetCatalog codec round trip")
            .into_owned();
        assert!(!catalog.plans.is_empty());
        assert!(!catalog.prices.is_empty());
        assert!(!catalog.settings.is_empty());
    }

    // Empty command bodies are rejected by the Connect adapter before any
    // catalog write or Stripe path. This both proves every command route and
    // keeps the deterministic fixture safe to reuse.
    for method in [
        "CreatePlan",
        "UpdatePlan",
        "SetPlanArchived",
        "CreatePrice",
        "UpdatePrice",
        "SetPriceArchived",
        "UpdateSetting",
        "PreviewSubscriptionMigration",
        "RunSubscriptionMigration",
    ] {
        let response = harness
            .connect_catalog(method, Some(&harness.admin_token), json!({}))
            .await;
        assert_connect_error(&response, StatusCode::BAD_REQUEST, "invalid_argument");
    }

    let response = harness
        .connect_catalog(
            "ListSubscriptionMigrations",
            Some(&harness.admin_token),
            json!({"limit": 101}),
        )
        .await;
    let limit_error = assert_connect_error(&response, StatusCode::BAD_REQUEST, "invalid_argument");
    assert_eq!(limit_error["message"], "validation failed");

    let client = BillingCatalogServiceClient::new(
        connectrpc::client::HttpClient::plaintext(),
        harness.connect_client_config(CodecFormat::Proto),
    );
    let error = client
        .list_subscription_migrations(ListSubscriptionMigrationsRequest {
            limit: 101,
            ..Default::default()
        })
        .await
        .expect_err("limit above 100 must be invalid_argument");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.details.iter().any(|detail| {
        detail.type_url == "google.rpc.BadRequest"
            || detail.type_url.rsplit('/').next() == Some("google.rpc.BadRequest")
    }));

    let response = harness
        .connect_catalog(
            "ListSubscriptionMigrations",
            Some(&harness.admin_token),
            json!({}),
        )
        .await;
    response.assert_status(
        StatusCode::OK,
        "BillingCatalogService.ListSubscriptionMigrations",
    );
    let response = response.json();
    assert!(
        response.get("migrations").is_none_or(|migrations| array(
            migrations,
            "Connect subscription migrations"
        )
        .is_empty())
    );
}

async fn assert_rest_reads(harness: &Harness) -> (Value, Value, Value, Value) {
    for suffix in [
        "billing/invoices",
        "billing/events",
        "billing",
        "environments/usage",
    ] {
        let response = harness
            .get(
                &format!("/api/v1/organizations/org_does_not_exist/{suffix}"),
                Some(&harness.user_token),
            )
            .await;
        response.assert_status(StatusCode::NOT_FOUND, "unknown organization read");
        let body = response.json();
        assert_eq!(body["title"], "Not Found");
        assert_eq!(body["detail"], "organization not found");
    }

    let response = harness
        .get(
            "/api/v1/organizations/org_contract_1/billing/invoices",
            Some(&harness.user_token),
        )
        .await;
    response.assert_status(StatusCode::OK, "REST invoices");
    let invoices = response.json();
    let invoice_rows = array(&invoices, "REST invoices");
    assert_eq!(invoice_rows.len(), 2);
    assert_eq!(invoice_rows[0]["stripe_invoice_id"], "in_fixture_2");
    assert_eq!(invoice_rows[1]["stripe_invoice_id"], "in_fixture_1");
    for invoice in invoice_rows {
        assert_keys(
            invoice,
            &[
                "id",
                "stripe_invoice_id",
                "status",
                "amount_due",
                "amount_paid",
                "currency",
                "hosted_invoice_url",
                "invoice_pdf",
                "period_start",
                "period_end",
                "created_at",
            ],
            "REST invoice",
        );
    }
    assert_eq!(invoice_rows[1]["period_start"], "2026-05-01T00:00:00Z");
    assert_eq!(invoice_rows[1]["period_end"], "2026-06-01T00:00:00Z");
    assert_eq!(invoice_rows[1]["created_at"], "2026-06-02T10:30:00Z");
    for key in [
        "hosted_invoice_url",
        "invoice_pdf",
        "period_start",
        "period_end",
    ] {
        assert!(invoice_rows[0][key].is_null(), "{key} must be null");
    }

    let response = harness
        .get(
            "/api/v1/organizations/org_contract_1/billing/events",
            Some(&harness.user_token),
        )
        .await;
    response.assert_status(StatusCode::OK, "REST billing events");
    let events = response.json();
    let event_rows = array(&events, "REST billing events");
    assert_eq!(event_rows.len(), 2);
    assert_eq!(event_rows[0]["event_type"], "environment_usage");
    assert_eq!(event_rows[1]["event_type"], "invoice_paid");
    for event in event_rows {
        assert_keys(
            event,
            &[
                "id",
                "event_type",
                "org_id",
                "amount_cents",
                "currency",
                "stripe_item_id",
                "created_at",
            ],
            "REST billing event",
        );
        assert!(event.get("resource_id").is_none());
        assert!(event.get("resource_name").is_none());
    }
    assert_eq!(event_rows[1]["amount_cents"], 4900);
    assert_eq!(event_rows[1]["stripe_item_id"], "in_fixture_1");
    assert_eq!(event_rows[1]["metadata"]["source"], "fixture");
    assert_eq!(event_rows[1]["created_at"], "2026-06-02T10:30:00Z");
    assert!(event_rows[0]["amount_cents"].is_null());
    assert!(event_rows[0]["stripe_item_id"].is_null());

    let response = harness
        .get(
            "/api/v1/organizations/org_contract_1/billing",
            Some(&harness.user_token),
        )
        .await;
    response.assert_status(StatusCode::OK, "REST billing overview");
    let overview = response.json();
    assert_keys(
        &overview,
        &[
            "billing_enabled",
            "has_payment_method",
            "plan",
            "plan_display_name",
            "status",
            "trial_end",
            "trial_days",
            "seat_count",
            "included_devs",
            "extra_seat_price_cents",
            "limits",
            "current_period_end",
            "active_subscriptions",
            "total_monthly_cost_cents",
            "subscriptions",
            "current_month_usage",
        ],
        "REST billing overview",
    );
    assert_eq!(overview["billing_enabled"], true);
    assert_eq!(overview["has_payment_method"], false);
    assert_eq!(overview["plan"], "starter");
    assert_eq!(overview["plan_display_name"], "Starter");
    assert_eq!(overview["status"], "active");
    assert_eq!(overview["active_subscriptions"], 1);
    assert_eq!(overview["total_monthly_cost_cents"], 4900);
    assert!(overview["subscriptions"].is_null());
    assert_eq!(overview["trial_days"], 14);
    assert_eq!(overview["extra_seat_price_cents"], 1800);
    assert_eq!(overview["limits"]["team_members"]["used"], 2);
    assert_eq!(overview["limits"]["concurrent_workspaces"], 10);
    assert_eq!(overview["current_month_usage"]["cpu_hours"], 2);
    assert_eq!(overview["current_month_usage"]["memory_gb_hours"], 4);
    assert_eq!(overview["current_month_usage"]["storage_gb_hours"], 14);

    let response = harness
        .get(
            "/api/v1/organizations/org_contract_1/environments/usage",
            Some(&harness.user_token),
        )
        .await;
    response.assert_status(StatusCode::OK, "REST environment usage");
    let usage = response.json();
    assert_eq!(usage["current_month"]["included_cpu_hours"], 200);
    assert_eq!(usage["current_month"]["included_mem_gb_hours"], 400);
    assert_eq!(usage["current_month"]["cpu_hours"], 2);
    assert_eq!(usage["current_month"]["mem_gb_hours"], 4);
    assert_eq!(usage["current_month"]["disk_gb_hours"], 14);
    assert_eq!(usage["current_month"]["cost_cents"], 16);
    let per_environment = array(&usage["per_environment"], "REST per_environment");
    assert_eq!(per_environment.len(), 1);
    assert_eq!(per_environment[0]["id"], "env_contract_1");
    assert_eq!(per_environment[0]["running_seconds"], 7200);
    assert_eq!(per_environment[0]["cpu_millicores"], 1000);
    assert_eq!(per_environment[0]["memory_mb"], 2048);
    assert_eq!(per_environment[0]["cost_cents"], 16);
    assert_eq!(per_environment[0]["hourly_cents"], 8);

    (invoices, events, overview, usage)
}

async fn assert_session_and_webhook_guards(harness: &Harness) {
    for endpoint in ["checkout", "portal", "setup"] {
        harness
            .post(
                &format!("/api/v1/organizations/org_contract_1/billing/{endpoint}"),
                None,
                json!({}),
            )
            .await
            .assert_status(
                StatusCode::UNAUTHORIZED,
                "anonymous billing session request",
            );
    }

    for (endpoint, body, field) in [
        (
            "checkout",
            json!({"plan": "starter", "success_url": "https://x/s"}),
            "cancel_url",
        ),
        ("portal", json!({}), "return_url"),
        ("setup", json!({"success_url": "https://x/s"}), "cancel_url"),
    ] {
        let response = harness
            .post(
                &format!("/api/v1/organizations/org_contract_1/billing/{endpoint}"),
                Some(&harness.admin_token),
                body,
            )
            .await;
        assert_validation(&response, field);
    }

    let response = harness
        .post(
            "/api/v1/organizations/org_checkout_guard/billing/checkout",
            Some(&harness.admin_token),
            json!({
                "plan": "starter",
                "success_url": format!("{}/success", harness.frontend_url),
                "cancel_url": format!("{}/cancel", harness.frontend_url),
            }),
        )
        .await;
    response.assert_status(StatusCode::CONFLICT, "duplicate subscription guard");
    assert_eq!(
        response.json()["detail"],
        "organization already has a Stripe subscription; use the billing portal to manage it"
    );

    let response = harness.post("/api/webhooks/stripe", None, json!({})).await;
    response.assert_status(
        StatusCode::BAD_REQUEST,
        "unsigned configured Stripe webhook",
    );
    assert_eq!(response.json()["error"], "invalid signature");
}

async fn assert_catalog_write_guards(harness: &Harness) {
    let cases = [
        (
            Method::POST,
            "/api/v1/admin/billing/catalog/plans",
            json!({"resource_type":"org","plan_key":"x","display_name":"x","price_cents":0}),
        ),
        (
            Method::PUT,
            "/api/v1/admin/billing/catalog/plans/org/starter",
            json!({"display_name":"x","price_cents":0}),
        ),
        (
            Method::PUT,
            "/api/v1/admin/billing/catalog/plans/org/starter/archive",
            json!({"archived":true}),
        ),
        (
            Method::POST,
            "/api/v1/admin/billing/catalog/subscription-migrations/preview",
            json!({"resource_type":"org","source_plan_key":"starter","target_plan_key":"starter"}),
        ),
        (
            Method::POST,
            "/api/v1/admin/billing/catalog/subscription-migrations",
            json!({"resource_type":"org","source_plan_key":"starter","target_plan_key":"starter"}),
        ),
    ];
    for (method, path, body) in cases {
        let response = harness.request(method, path, None, Some(&body)).await;
        assert_coded_error(
            &response,
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "unauthorized",
        );
    }
    let response = harness
        .get(
            "/api/v1/admin/billing/catalog/subscription-migrations",
            None,
        )
        .await;
    assert_coded_error(
        &response,
        StatusCode::UNAUTHORIZED,
        "session_expired",
        "unauthorized",
    );

    let response = harness
        .post(
            "/api/v1/admin/billing/catalog/plans",
            Some(&harness.user_token),
            json!({"resource_type":"org","plan_key":"x","display_name":"x","price_cents":0}),
        )
        .await;
    assert_coded_error(&response, StatusCode::FORBIDDEN, "forbidden", "forbidden");

    for (method, path, body, field) in [
        (
            Method::PUT,
            "/api/v1/admin/billing/catalog/plans/org/does-not-exist",
            json!({"display_name":"x","price_cents":0}),
            "included_devs",
        ),
        (
            Method::POST,
            "/api/v1/admin/billing/catalog/prices",
            json!({"resource_type":"org","plan_key":"x"}),
            "stripe_mode",
        ),
        (
            Method::PUT,
            "/api/v1/admin/billing/catalog/settings/does-not-exist",
            json!({}),
            "int_value",
        ),
    ] {
        let response = harness
            .request(method, path, Some(&harness.admin_token), Some(&body))
            .await;
        assert_validation(&response, field);
    }

    let full_plan = json!({
        "display_name":"x", "price_cents":0, "included_devs":0,
        "max_concurrent_ws":0, "max_team_members":0, "storage_gb":0,
        "is_contact_us":false, "is_admin_only":false,
        "included_cpu_hours":0, "included_mem_gb_hours":0,
        "included_disk_gb_hours":0, "cpu_overage_cents":0,
        "mem_overage_cents":0, "disk_overage_cents":0
    });
    for (path, body) in [
        (
            "/api/v1/admin/billing/catalog/plans/org/does-not-exist",
            full_plan,
        ),
        (
            "/api/v1/admin/billing/catalog/plans/org/does-not-exist/archive",
            json!({"archived":true}),
        ),
    ] {
        let response = harness
            .request(Method::PUT, path, Some(&harness.admin_token), Some(&body))
            .await;
        response.assert_status(StatusCode::NOT_FOUND, "missing catalog plan");
        assert_eq!(response.json()["detail"], "billing catalog plan not found");
    }

    for path in [
        "/api/v1/admin/billing/catalog/subscription-migrations/preview",
        "/api/v1/admin/billing/catalog/subscription-migrations",
    ] {
        let response = harness
            .post(path, Some(&harness.admin_token), json!({}))
            .await;
        assert_validation(&response, "resource_type");
    }
    let response = harness
        .get(
            "/api/v1/admin/billing/catalog/subscription-migrations",
            Some(&harness.admin_token),
        )
        .await;
    response.assert_status(StatusCode::OK, "list subscription migrations");
    assert!(array(&response.json(), "subscription migrations").is_empty());
}

async fn assert_connect_reads_and_parity(
    harness: &Harness,
    rest_org_plans: &Value,
    rest_resource_plans: &Value,
    rest_invoices: &Value,
    rest_events: &Value,
    rest_overview: &Value,
    rest_usage: &Value,
) {
    let response = harness
        .connect("ListOrgPlans", Some(&harness.user_token), json!({}))
        .await;
    response.assert_status(StatusCode::OK, "Connect ListOrgPlans");
    let org_plans = response.json();
    assert_eq!(org_plans["plans"]["starter"]["displayName"], "Starter");
    assert_eq!(org_plans["plans"]["starter"]["priceCents"], 4900);
    assert_eq!(
        org_plans["plans"]["starter"]["displayName"],
        rest_org_plans["starter"]["display_name"]
    );
    assert_eq!(
        org_plans["plans"]["starter"]["priceCents"],
        rest_org_plans["starter"]["price_cents"]
    );

    let response = harness
        .connect(
            "ListResourcePlans",
            Some(&harness.user_token),
            json!({"resourceType":"sandbox"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "Connect ListResourcePlans");
    let resource_plans = response.json();
    let standard = &resource_plans["plans"]["standard"];
    assert_eq!(standard["displayName"], "Standard");
    assert_eq!(standard["cpuOverageMillicents"], "500");
    assert_eq!(standard["memOverageMillicents"], "250");
    assert_eq!(standard["diskOverageMillicents"], "125");
    assert!(resource_plans["plans"].get("internal-admin").is_none());
    assert_eq!(
        standard["displayName"],
        rest_resource_plans["standard"]["display_name"]
    );
    assert_eq!(
        rest_resource_plans["standard"]["cpu_overage_cents"],
        json!(0.5)
    );
    assert_eq!(
        rest_resource_plans["standard"]["mem_overage_cents"],
        json!(0.25)
    );
    assert_eq!(
        rest_resource_plans["standard"]["disk_overage_cents"],
        json!(0.125)
    );

    let response = harness
        .connect(
            "GetBillingOverview",
            Some(&harness.user_token),
            json!({"orgId":"org_contract_1"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "Connect GetBillingOverview");
    let overview = response.json();
    assert_eq!(overview["plan"], "starter");
    assert_eq!(overview["status"], "active");
    assert_eq!(overview["currentMonthUsage"]["cpuHours"], json!(2.0));
    assert_eq!(overview["currentMonthUsage"]["memoryGbHours"], json!(4.0));
    assert_eq!(overview["currentMonthUsage"]["storageGbHours"], json!(14.0));
    assert_eq!(overview["plan"], rest_overview["plan"]);
    assert_eq!(overview["status"], rest_overview["status"]);
    assert_eq!(
        overview["activeSubscriptions"],
        rest_overview["active_subscriptions"]
    );
    assert_eq!(
        overview["totalMonthlyCostCents"],
        rest_overview["total_monthly_cost_cents"]
    );

    let response = harness
        .connect(
            "ListInvoices",
            Some(&harness.user_token),
            json!({"orgId":"org_contract_1"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "Connect ListInvoices");
    let invoices = response.json();
    let connect_invoices = array(&invoices["invoices"], "Connect invoices");
    let rest_invoices = array(rest_invoices, "REST invoices");
    assert_eq!(connect_invoices.len(), 2);
    assert_eq!(connect_invoices[1]["id"], "inv_fixture_1");
    assert_eq!(connect_invoices[1]["periodStart"], "2026-05-01T00:00:00Z");
    assert_eq!(connect_invoices.len(), rest_invoices.len());
    assert_eq!(connect_invoices[1]["id"], rest_invoices[1]["id"]);
    assert_eq!(
        connect_invoices[1]["stripeInvoiceId"],
        rest_invoices[1]["stripe_invoice_id"]
    );

    let response = harness
        .connect(
            "ListBillingEvents",
            Some(&harness.user_token),
            json!({"orgId":"org_contract_1"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "Connect ListBillingEvents");
    let events = response.json();
    let connect_events = array(&events["events"], "Connect billing events");
    let rest_events = array(rest_events, "REST billing events");
    assert_eq!(connect_events.len(), 2);
    assert_eq!(connect_events[1]["eventType"], "invoice_paid");
    assert_eq!(connect_events[1]["metadata"]["source"], "fixture");
    assert_eq!(connect_events[1]["amountCents"], 4900);
    assert_eq!(connect_events.len(), rest_events.len());
    assert_eq!(connect_events[1]["eventType"], rest_events[1]["event_type"]);
    assert_eq!(
        connect_events[1]["metadata"]["source"],
        rest_events[1]["metadata"]["source"]
    );

    let response = harness
        .connect(
            "GetEnvironmentUsage",
            Some(&harness.user_token),
            json!({"orgId":"org_contract_1"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "Connect GetEnvironmentUsage");
    let usage = response.json();
    assert_eq!(usage["currentMonth"]["cpuHours"], json!(2.0));
    assert_eq!(usage["currentMonth"]["memGbHours"], json!(4.0));
    assert_eq!(usage["currentMonth"]["diskGbHours"], json!(14.0));
    assert_eq!(
        array(&usage["perEnvironment"], "Connect perEnvironment").len(),
        1
    );
    assert_eq!(usage["perEnvironment"][0]["id"], "env_contract_1");
    assert_eq!(
        usage["currentMonth"]["cpuHours"].as_f64(),
        rest_usage["current_month"]["cpu_hours"].as_f64()
    );
    assert_eq!(
        usage["currentMonth"]["memGbHours"].as_f64(),
        rest_usage["current_month"]["mem_gb_hours"].as_f64()
    );
    assert_eq!(
        usage["currentMonth"]["diskGbHours"].as_f64(),
        rest_usage["current_month"]["disk_gb_hours"].as_f64()
    );
    assert_eq!(
        usage["perEnvironment"][0]["id"],
        rest_usage["per_environment"][0]["id"]
    );
}

async fn assert_connect_guards(harness: &Harness) {
    let response = harness.connect("ListOrgPlans", None, json!({})).await;
    assert_connect_error(&response, StatusCode::UNAUTHORIZED, "unauthenticated");

    let response = harness
        .connect(
            "GetBillingOverview",
            Some(&harness.user_token),
            json!({"orgId":"org_does_not_exist"}),
        )
        .await;
    assert_connect_error(&response, StatusCode::NOT_FOUND, "not_found");

    let valid_checkout = json!({
        "orgId":"org_contract_2",
        "plan":"starter",
        "successUrl":format!("{}/success", harness.frontend_url),
        "cancelUrl":format!("{}/cancel", harness.frontend_url)
    });
    let response = harness
        .connect(
            "CreateCheckoutSession",
            Some(&harness.admin_token),
            valid_checkout,
        )
        .await;
    assert_connect_error(&response, StatusCode::NOT_FOUND, "not_found");

    let response = harness
        .connect(
            "CreateCheckoutSession",
            Some(&harness.user_token),
            json!({
                "orgId":"org_contract_1", "plan":"starter",
                "successUrl":format!("{}/success", harness.frontend_url),
                "cancelUrl":format!("{}/cancel", harness.frontend_url)
            }),
        )
        .await;
    assert_connect_error(&response, StatusCode::FORBIDDEN, "permission_denied");

    let response = harness
        .connect(
            "CreateCheckoutSession",
            Some(&harness.admin_token),
            json!({
                "orgId":"org_checkout_guard", "plan":"starter",
                "successUrl":format!("{}/success", harness.frontend_url),
                "cancelUrl":format!("{}/cancel", harness.frontend_url)
            }),
        )
        .await;
    assert_connect_error(&response, StatusCode::CONFLICT, "already_exists");

    let origin_cases = [
        (
            "CreateCheckoutSession",
            "/api/v1/organizations/org_contract_1/billing/checkout",
            json!({
                "orgId":"org_contract_1", "plan":"starter",
                "successUrl":"https://evil.test/success",
                "cancelUrl":format!("{}/cancel", harness.frontend_url)
            }),
            json!({
                "plan":"starter", "success_url":"https://evil.test/success",
                "cancel_url":format!("{}/cancel", harness.frontend_url)
            }),
        ),
        (
            "CreatePortalSession",
            "/api/v1/organizations/org_contract_1/billing/portal",
            json!({"orgId":"org_contract_1", "returnUrl":"https://evil.test/return"}),
            json!({"return_url":"https://evil.test/return"}),
        ),
        (
            "CreateSetupSession",
            "/api/v1/organizations/org_contract_1/billing/setup",
            json!({
                "orgId":"org_contract_1",
                "successUrl":format!("{}/success", harness.frontend_url),
                "cancelUrl":"https://evil.test/cancel"
            }),
            json!({
                "success_url":format!("{}/success", harness.frontend_url),
                "cancel_url":"https://evil.test/cancel"
            }),
        ),
    ];
    for (method, rest_path, connect_body, rest_body) in origin_cases {
        let response = harness
            .connect(method, Some(&harness.admin_token), connect_body)
            .await;
        let body = assert_connect_error(&response, StatusCode::BAD_REQUEST, "invalid_argument");
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("configured frontend origin"))
        );

        let response = harness
            .post(rest_path, Some(&harness.admin_token), rest_body)
            .await;
        response.assert_status(StatusCode::BAD_REQUEST, "REST redirect-origin guard");
        assert!(
            response.json()["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("configured frontend origin"))
        );
    }

    let response = harness
        .connect(
            "GetEnvironmentUsage",
            Some(&harness.admin_token),
            json!({"orgId":"org_checkout_guard"}),
        )
        .await;
    response.assert_status(StatusCode::OK, "empty Connect environment usage");
    let body_text = String::from_utf8_lossy(&response.body);
    assert!(!body_text.contains("\"hourlyBreakdown\":null"));
    assert!(!body_text.contains("\"perEnvironment\":null"));
    let body = response.json();
    for field in ["hourlyBreakdown", "perEnvironment"] {
        if let Some(value) = body.get(field) {
            assert_eq!(array(value, field).len(), 0, "{field} must be empty");
        }
    }
}

#[tokio::test]
#[ignore = "requires a configured real billing listener and deterministic seed"]
async fn configured_billing_wire_contract() {
    let harness = Harness::from_env();

    assert_health(&harness).await;
    assert_rest_auth(&harness).await;
    let (rest_catalog, rest_org_plans, rest_resource_plans) =
        assert_catalog_and_plans(&harness).await;
    let (rest_invoices, rest_events, rest_overview, rest_usage) = assert_rest_reads(&harness).await;
    assert_session_and_webhook_guards(&harness).await;
    assert_catalog_write_guards(&harness).await;
    assert_connect_reads_and_parity(
        &harness,
        &rest_org_plans,
        &rest_resource_plans,
        &rest_invoices,
        &rest_events,
        &rest_overview,
        &rest_usage,
    )
    .await;
    assert_billing_catalog_connect_contract(&harness, &rest_catalog).await;
    assert_connect_guards(&harness).await;
}
