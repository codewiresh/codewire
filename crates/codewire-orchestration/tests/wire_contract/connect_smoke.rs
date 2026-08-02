use codewire_proto::codewire::v1::{ListOrganizationsRequest, OrganizationServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::json;

use super::{Auth, Harness, PRIMARY_ORG, assert_connect_error};

const ADMIN_SERVICE: &str = "codewire.admin.v1.AdminService";
const API_KEY_SERVICE: &str = "codewire.v1.ApiKeyService";
const ACCOUNT_SERVICE: &str = "codewire.console.v1.AccountService";
const GITHUB_SERVICE: &str = "codewire.console.v1.GitHubService";
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
    assert_retired_routes_absent(harness).await;
}

pub(super) async fn assert_detection_unconfigured(harness: &Harness) {
    let response = harness
        .connect_json(
            ENVIRONMENT_SETUP_SERVICE,
            "DetectRepo",
            json!({"repoUrl": "codewire/codewire", "branch": "main"}),
            Auth::User,
        )
        .await;
    assert_connect_error(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "AI detection is not configured",
    );
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
            API_KEY_SERVICE,
            "ListApiKeys",
            json!({"orgId": PRIMARY_ORG}),
            Auth::Admin,
            Some("apiKeys"),
        ),
        (
            ACCOUNT_SERVICE,
            "ListLoginKeys",
            json!({}),
            Auth::Admin,
            None,
        ),
        (
            GITHUB_SERVICE,
            "GetGitHubConfig",
            json!({}),
            Auth::Admin,
            None,
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
