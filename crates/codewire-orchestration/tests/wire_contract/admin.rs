use buffa_types::Duration;
use codewire_proto::codewire::admin::v1::{AdminServiceClient, GetStatsRequest};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{Auth, Harness, array, assert_connect_error, assert_error_info};

const SERVICE: &str = "codewire.admin.v1.AdminService";
const ENVIRONMENT: &str = "env_admin_contract_read";

pub(super) async fn run(harness: &Harness) {
    assert_auth_boundaries(harness).await;
    assert_stats(harness).await;
    assert_organizations(harness).await;
    assert_audit_logs(harness).await;
    assert_lifecycle_journal(harness).await;
    assert_startup_summary(harness).await;
    assert_startup_timings(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn assert_auth_boundaries(harness: &Harness) {
    let unauthenticated = call(harness, "GetStats", json!({}), Auth::None).await;
    assert_connect_error(
        &unauthenticated,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "unauthorized",
    );

    let non_admin = call(harness, "GetStats", json!({}), Auth::Admin).await;
    let body = assert_connect_error(
        &non_admin,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "forbidden",
    );
    assert_error_info(&non_admin, &body, "FORBIDDEN");
}

async fn assert_stats(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = AdminServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::GlobalAdmin, codec),
        );
        let stats = client
            .get_stats(GetStatsRequest::default())
            .await
            .expect("GetStats codec round trip")
            .into_owned();
        assert!(stats.total_environments > 0);
        assert!(stats.active_environments > 0);
        assert!(stats.monthly_cpu_hours >= 1.0);
        assert!(stats.monthly_memory_gb_hours >= 1.0);
        assert!(stats.monthly_cost_cents >= 123);
    }

    let connect = call(harness, "GetStats", json!({}), Auth::GlobalAdmin).await;
    connect.assert_status(StatusCode::OK, "AdminService.GetStats");
    let connect = connect.json();
    let rest = harness
        .rest(Method::GET, "/api/v1/admin/stats", None, Auth::GlobalAdmin)
        .await;
    rest.assert_status(StatusCode::OK, "REST admin stats");
    let rest = rest.json();
    assert_eq!(
        i64_value(&connect["totalEnvironments"]),
        rest["total_environments"]
    );
    assert_eq!(
        i64_value(&connect["activeEnvironments"]),
        rest["active_environments"]
    );
    assert_eq!(
        connect["monthlyCpuHours"].as_f64(),
        rest["monthly_cpu_hours"].as_f64()
    );
    assert_eq!(
        connect["monthlyMemoryGbHours"].as_f64(),
        rest["monthly_memory_gb_hours"].as_f64()
    );
    assert_eq!(
        i64_value(&connect["monthlyCostCents"]),
        rest["monthly_cost"]
    );
}

async fn assert_organizations(harness: &Harness) {
    let connect = call(harness, "ListOrganizations", json!({}), Auth::GlobalAdmin).await;
    connect.assert_status(StatusCode::OK, "AdminService.ListOrganizations");
    let connect = connect.json();
    let organizations = array(&connect["organizations"], "Connect admin organizations");
    assert!(
        organizations
            .windows(2)
            .all(|pair| pair[0]["name"].as_str() <= pair[1]["name"].as_str())
    );
    let primary = find_by_id(organizations, "org_apikey_contract_1");

    let rest = harness
        .rest(
            Method::GET,
            "/api/v1/admin/organizations",
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST admin organizations");
    let rest = rest.json();
    let rest_primary = find_by_id(
        array(&rest, "REST admin organizations"),
        "org_apikey_contract_1",
    );
    assert_eq!(primary["name"], rest_primary["name"]);
    assert_eq!(primary["slug"], rest_primary["slug"]);
    assert_eq!(primary["createdAt"], rest_primary["created_at"]);
}

async fn assert_audit_logs(harness: &Harness) {
    let connect = call(
        harness,
        "ListAuditLogs",
        json!({"limit": 1, "action": "contract.admin.fixture"}),
        Auth::GlobalAdmin,
    )
    .await;
    connect.assert_status(StatusCode::OK, "AdminService.ListAuditLogs");
    let connect = connect.json();
    let entries = array(&connect["auditLogs"], "Connect admin audit logs");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "audit_admin_contract_1");
    assert_eq!(entries[0]["userEmail"], "global-admin@codewire.test");
    assert_eq!(entries[0]["metadata"]["attempt"].as_f64(), Some(1.0));
    assert_eq!(entries[0]["metadata"]["source"], "contract");

    let rest = harness
        .rest(
            Method::GET,
            "/api/v1/admin/audit-logs?limit=1&action=contract.admin.fixture",
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST admin audit logs");
    let rest = rest.json();
    let rest = array(&rest, "REST admin audit logs");
    assert_eq!(rest.len(), 1);
    assert_eq!(entries[0]["timestamp"], rest[0]["timestamp"]);
    assert_eq!(entries[0]["userEmail"], rest[0]["user_email"]);
    assert_eq!(rest[0]["metadata"]["attempt"].as_i64(), Some(1));
    assert_eq!(rest[0]["metadata"]["source"], "contract");

    let connect = call(
        harness,
        "ListAuditLogs",
        json!({"limit": 1, "action": "contract.admin.null-metadata"}),
        Auth::GlobalAdmin,
    )
    .await;
    connect.assert_status(
        StatusCode::OK,
        "AdminService.ListAuditLogs with JSON null metadata",
    );
    let connect = connect.json();
    let entries = array(&connect["auditLogs"], "Connect null-metadata audit logs");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "audit_admin_contract_null_metadata_1");
    assert!(entries[0].get("metadata").is_none());

    let rest = harness
        .rest(
            Method::GET,
            "/api/v1/admin/audit-logs?limit=1&action=contract.admin.null-metadata",
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST null-metadata admin audit logs");
    let rest = rest.json();
    let rest = array(&rest, "REST null-metadata admin audit logs");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0]["id"], "audit_admin_contract_null_metadata_1");
    assert_eq!(rest[0]["metadata"], Value::Null);

    let invalid = call(
        harness,
        "ListAuditLogs",
        json!({"limit": 201}),
        Auth::GlobalAdmin,
    )
    .await;
    assert_connect_error(
        &invalid,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "limit must be between 1 and 200",
    );
}

async fn assert_lifecycle_journal(harness: &Harness) {
    let connect = call(
        harness,
        "ListEnvironmentLifecycleJournal",
        json!({"environmentId": ENVIRONMENT}),
        Auth::GlobalAdmin,
    )
    .await;
    connect.assert_status(
        StatusCode::OK,
        "AdminService.ListEnvironmentLifecycleJournal",
    );
    let connect = connect.json();
    let entries = array(&connect["entries"], "Connect lifecycle journal");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "elj_admin_contract_1");
    assert_eq!(entries[0]["metadata"], json!({"source": "contract"}));

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/admin/environments/{ENVIRONMENT}/lifecycle-journal"),
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST lifecycle journal");
    let rest = rest.json();
    let rest = array(&rest, "REST lifecycle journal");
    assert_eq!(entries[0]["createdAt"], rest[0]["created_at"]);
    assert_eq!(entries[0]["fromState"], rest[0]["from_state"]);
    assert_eq!(entries[0]["metadata"], rest[0]["metadata"]);

    let missing = call(
        harness,
        "ListEnvironmentLifecycleJournal",
        json!({"environmentId": "env_admin_contract_missing"}),
        Auth::GlobalAdmin,
    )
    .await;
    assert_connect_error(
        &missing,
        StatusCode::NOT_FOUND,
        "not_found",
        "environment not found",
    );
}

async fn assert_startup_summary(harness: &Harness) {
    let connect = call(
        harness,
        "GetEnvironmentStartupSummary",
        json!({}),
        Auth::GlobalAdmin,
    )
    .await;
    connect.assert_status(StatusCode::OK, "AdminService.GetEnvironmentStartupSummary");
    let connect = connect.json();
    assert_eq!(duration_millis(&connect["window"]), 240 * 60 * 1_000);
    let phases = array(&connect["phaseDurations"], "Connect startup phases");
    assert_eq!(phases.len(), 4);
    assert_eq!(phases[0]["phase"], "create_claim");
    assert_eq!(duration_millis(&phases[0]["p50"]), 100);
    assert_eq!(duration_millis(&phases[1]["p50"]), 251);

    let rest = harness
        .rest(
            Method::GET,
            "/api/v1/admin/environments/startup-summary",
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST startup summary");
    let rest = rest.json();
    assert_eq!(
        connect["startingBacklogCount"],
        rest["starting_backlog_count"]
    );
    assert_eq!(
        connect["runningWithoutGatewayReadyCount"],
        rest["running_without_gateway_ready_count"]
    );
    let rest_phases = array(&rest["phase_durations"], "REST startup phases");
    assert_eq!(phases[0]["sampleCount"], rest_phases[0]["sample_count"]);
    assert_eq!(duration_millis(&phases[0]["p50"]), 100);
}

async fn assert_startup_timings(harness: &Harness) {
    let connect = call(
        harness,
        "GetEnvironmentStartupTimings",
        json!({"environmentId": ENVIRONMENT}),
        Auth::GlobalAdmin,
    )
    .await;
    connect.assert_status(StatusCode::OK, "AdminService.GetEnvironmentStartupTimings");
    let connect = connect.json();
    assert_eq!(connect["environmentId"], ENVIRONMENT);
    let timings = array(&connect["timings"], "Connect startup timings");
    assert_eq!(timings.len(), 4);
    assert_eq!(timings[0]["phase"], "create_claim");
    assert_eq!(duration_millis(&timings[0]["duration"]), 100);
    assert_eq!(timings[3]["metadata"], Value::Null);

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/admin/environments/{ENVIRONMENT}/startup-timings"),
            None,
            Auth::GlobalAdmin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST startup timings");
    let rest = rest.json();
    assert_eq!(connect["createdAt"], rest["created_at"]);
    let rest_timings = array(&rest["timings"], "REST startup timings");
    assert_eq!(timings[0]["createdAt"], rest_timings[0]["created_at"]);
    assert_eq!(
        duration_millis(&timings[0]["duration"]),
        rest_timings[0]["duration_ms"]
    );
    assert_eq!(
        timings[0]["metadata"]["duration_ms"].as_f64(),
        rest_timings[0]["metadata"]["duration_ms"].as_f64()
    );

    let missing = call(
        harness,
        "GetEnvironmentStartupTimings",
        json!({"environmentId": "env_admin_contract_missing"}),
        Auth::GlobalAdmin,
    )
    .await;
    assert_connect_error(
        &missing,
        StatusCode::NOT_FOUND,
        "not_found",
        "environment not found",
    );
}

fn find_by_id<'a>(values: &'a [Value], id: &str) -> &'a Value {
    values
        .iter()
        .find(|value| value["id"] == id)
        .unwrap_or_else(|| panic!("missing id {id} in {values:?}"))
}

fn i64_value(value: &Value) -> Value {
    match value {
        Value::String(value) => json!(value.parse::<i64>().expect("proto int64 string")),
        Value::Number(_) => value.clone(),
        _ => panic!("expected proto int64, got {value}"),
    }
}

fn duration_millis(value: &Value) -> i64 {
    let duration: Duration = serde_json::from_value(value.clone())
        .unwrap_or_else(|error| panic!("decode protobuf duration {value}: {error}"));
    duration.seconds * 1_000 + i64::from(duration.nanos) / 1_000_000
}
