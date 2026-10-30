use codewire_proto::codewire::v1::{
    EnvironmentResizeExecutionMode, EnvironmentServiceClient, ListOrganizationsRequest,
    OrganizationServiceClient, PlanEnvironmentResizeRequest,
};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::json;

use super::{Auth, Harness, PRIMARY_ORG, assert_connect_error};

const ADMIN_SERVICE: &str = "codewire.admin.v1.AdminService";
const API_KEY_SERVICE: &str = "codewire.v1.ApiKeyService";
const ACCOUNT_SERVICE: &str = "codewire.console.v1.AccountService";
const ENVIRONMENT_SETUP_SERVICE: &str = "codewire.console.v1.EnvironmentSetupService";
const ORGANIZATION_SERVICE: &str = "codewire.v1.OrganizationService";
const SECRET_SERVICE: &str = "codewire.v1.SecretService";
const PRESET_SERVICE: &str = "codewire.v1.PresetService";
const PORT_SERVICE: &str = "codewire.v1.PortService";
const ENVIRONMENT_SERVICE: &str = "codewire.v1.EnvironmentService";

pub(super) async fn run(harness: &Harness) {
    assert_json_connect_routes(harness).await;
    assert_proto_connect_route(harness).await;
    assert_auth_boundary(harness).await;
    assert_resize_contract(harness).await;
    assert_retired_github_and_detection_surfaces_absent(harness).await;
    assert_retired_routes_absent(harness).await;
}

pub(super) async fn assert_retired_github_and_detection_surfaces_absent(harness: &Harness) {
    for (service, method) in [
        ("codewire.console.v1.GitHubService", "GetGitHubConfig"),
        (ENVIRONMENT_SETUP_SERVICE, "DetectRepo"),
        (ACCOUNT_SERVICE, "ListLoginKeys"),
        (ACCOUNT_SERVICE, "CreateLoginKey"),
        (ACCOUNT_SERVICE, "DeleteLoginKey"),
    ] {
        harness
            .connect_json(service, method, json!({}), Auth::User)
            .await
            .assert_status(StatusCode::NOT_FOUND, &format!("{service}/{method}"));
    }

    for path in [
        "/api/v1/github/oauth/authorize",
        "/api/v1/github/oauth/callback",
    ] {
        harness
            .rest(Method::GET, path, None, Auth::User)
            .await
            .assert_status(StatusCode::NOT_FOUND, path);
    }
}

async fn assert_json_connect_routes(harness: &Harness) {
    for (service, method, body, auth, result_field) in [
        (
            ADMIN_SERVICE,
            "GetStats",
            json!({}),
            Auth::GlobalAdmin,
            Some("totalEnvironments"),
        ),
        (
            ADMIN_SERVICE,
            "GetOrganizationEnvironmentQuota",
            json!({"organizationId": PRIMARY_ORG}),
            Auth::GlobalAdmin,
            Some("effective"),
        ),
        (
            API_KEY_SERVICE,
            "ListApiKeys",
            json!({"orgId": PRIMARY_ORG}),
            Auth::Admin,
            Some("apiKeys"),
        ),
        (
            ACCOUNT_SERVICE,
            "GetGitIdentity",
            json!({}),
            Auth::Admin,
            Some("gitIdentity"),
        ),
        (
            ACCOUNT_SERVICE,
            "GetAccountDeletionPlan",
            json!({}),
            Auth::Admin,
            Some("email"),
        ),
        (
            ENVIRONMENT_SETUP_SERVICE,
            "GetEnvironmentCreateOptions",
            json!({"orgId": PRIMARY_ORG}),
            Auth::User,
            None,
        ),
        (
            ORGANIZATION_SERVICE,
            "ListOrganizations",
            json!({}),
            Auth::Admin,
            Some("organizations"),
        ),
        (
            SECRET_SERVICE,
            "ListSecrets",
            json!({"orgId": PRIMARY_ORG}),
            Auth::Admin,
            None,
        ),
        (
            PRESET_SERVICE,
            "ListPresets",
            json!({"orgId": PRIMARY_ORG}),
            Auth::Admin,
            None,
        ),
        (
            PORT_SERVICE,
            "ListPorts",
            json!({"orgId": PRIMARY_ORG, "environmentId": "env_port_contract_operator"}),
            Auth::Admin,
            None,
        ),
        (
            ENVIRONMENT_SERVICE,
            "ListEnvironments",
            json!({"orgId": PRIMARY_ORG}),
            Auth::Admin,
            None,
        ),
    ] {
        let response = harness.connect_json(service, method, body, auth).await;
        response.assert_status(StatusCode::OK, &format!("{service}/{method}"));
        if let Some(result_field) = result_field {
            assert!(
                response.json().get(result_field).is_some(),
                "{service}/{method} response lacks {result_field}"
            );
        }
    }
}

async fn assert_proto_connect_route(harness: &Harness) {
    let client = OrganizationServiceClient::new(
        connectrpc::client::HttpClient::plaintext(),
        harness.client_config(Auth::Admin, CodecFormat::Proto),
    );
    let response = client
        .list_organizations(ListOrganizationsRequest::default())
        .await
        .expect("OrganizationService ListOrganizations Proto round trip")
        .into_owned();
    assert_eq!(response.organizations.len(), 2);

    let client = EnvironmentServiceClient::new(
        connectrpc::client::HttpClient::plaintext(),
        harness.client_config(Auth::Admin, CodecFormat::Proto),
    );
    let response = client
        .plan_environment_resize(PlanEnvironmentResizeRequest {
            org_id: PRIMARY_ORG.into(),
            environment_id: "env_environment_contract_invalid_state".into(),
            cpu_millicores: 3_000,
            memory_mb: 4_096,
            disk_gb: 10,
            ..Default::default()
        })
        .await
        .expect("PlanEnvironmentResize Proto round trip")
        .into_owned();
    assert_eq!(
        response.plan.as_option().unwrap().execution_mode,
        EnvironmentResizeExecutionMode::ApplyOnStart
    );
}

async fn assert_auth_boundary(harness: &Harness) {
    let response = harness
        .connect_json(
            ORGANIZATION_SERVICE,
            "ListOrganizations",
            json!({}),
            Auth::None,
        )
        .await;
    assert_connect_error(
        &response,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "unauthorized",
    );

    // An organization administrator is not a global administrator: the
    // quota write is refused before it reaches the database.
    let denied = harness
        .connect_json(
            ADMIN_SERVICE,
            "SetOrganizationEnvironmentQuota",
            json!({
                "organizationId": PRIMARY_ORG,
                "quota": {
                    "maxConcurrentEnvironments": -1,
                    "maxConcurrentSandbox": -1,
                    "maxCpuMillicores": -1,
                    "maxMemoryMb": -1,
                },
            }),
            Auth::Admin,
        )
        .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");

    // Nor may one switch a rate card or move credit (#3381).
    for (method, body) in [
        (
            "SetOrganizationRateCard",
            json!({"organizationId": PRIMARY_ORG, "rateCard": "unlimited"}),
        ),
        (
            "AdjustOrganizationCredit",
            json!({
                "organizationId": PRIMARY_ORG,
                "amountNanoEur": "50000000000",
                "reason": "contract",
                "idempotencyKey": "contract",
            }),
        ),
    ] {
        let denied = harness
            .connect_json(ADMIN_SERVICE, method, body, Auth::Admin)
            .await;
        assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    }
}

async fn assert_resize_contract(harness: &Harness) {
    let operation_id = "resize_environment_contract_completed";
    let got = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "GetEnvironmentResizeOperation",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": "env_environment_contract_read",
                "operationId": operation_id,
            }),
            Auth::Admin,
        )
        .await;
    got.assert_status(StatusCode::OK, "GetEnvironmentResizeOperation");
    let body = got.json();
    assert_eq!(body["operation"]["id"], operation_id);
    assert_eq!(
        body["operation"]["state"],
        "ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED"
    );
    assert_eq!(
        body["operation"]["disruptionPolicy"],
        "ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY"
    );
    assert_eq!(
        body["operation"]["appliedMode"],
        "ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE"
    );
    assert!(
        body["operation"]["podReplaced"].is_null() || body["operation"]["podReplaced"] == false
    );
    assert_eq!(
        body["operation"]["previousResources"]["cpuMillicores"],
        2000
    );
    assert_eq!(body["operation"]["desiredResources"]["diskGb"], 20);
    assert_eq!(body["operation"]["lastAppliedResources"]["memoryMb"], 6144);
    assert!(body.get("pollInterval").is_none());

    let denied = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "GetEnvironmentResizeOperation",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": "env_environment_contract_read",
                "operationId": operation_id,
            }),
            Auth::User,
        )
        .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");

    let denied_plan = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "PlanEnvironmentResize",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": "env_environment_contract_read",
                "cpuMillicores": 3000,
                "memoryMb": 4096,
                "diskGb": 10,
            }),
            Auth::User,
        )
        .await;
    assert_connect_error(&denied_plan, StatusCode::FORBIDDEN, "permission_denied", "");

    let invalid = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "ResizeEnvironment",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": "env_environment_contract_read",
                "cpuMillicores": 0,
                "memoryMb": 4096,
                "diskGb": 10,
                "requestId": "wire-invalid-resize",
            }),
            Auth::Admin,
        )
        .await;
    assert_connect_error(&invalid, StatusCode::BAD_REQUEST, "invalid_argument", "");
}

async fn assert_retired_routes_absent(harness: &Harness) {
    for path in [
        "/api/v1/admin/stats",
        "/api/v1/organizations",
        "/api/v1/github/status",
        "/api/v1/secrets",
        "/api/v1/organizations/org_apikey_contract_1/presets",
        "/api/v1/organizations/org_apikey_contract_1/environments",
        "/api/v1/organizations/org_apikey_contract_1/repo-configs",
        "/api/v1/internal/gateway/binding",
    ] {
        harness
            .rest(Method::GET, path, None, Auth::Admin)
            .await
            .assert_status(StatusCode::NOT_FOUND, path);
    }
    harness
        .rest(
            Method::POST,
            "/api/v1/terminal/ticket",
            Some(json!({})),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::NOT_FOUND, "retired terminal ticket route");
}
