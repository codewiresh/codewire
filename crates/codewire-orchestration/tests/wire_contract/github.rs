use codewire_proto::codewire::console::v1::{GetGitHubStatusRequest, GitHubServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{Auth, Harness, PRIMARY_ORG, assert_connect_error, assert_error_info};

const SERVICE: &str = "codewire.console.v1.GitHubService";

pub(super) async fn run(harness: &Harness) {
    disconnect(harness).await;
    assert_config_status_lifecycle_and_parity(harness).await;
    assert_not_connected_parity(harness).await;
    assert_api_key_boundary(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn disconnect(harness: &Harness) {
    call(harness, "DeleteGitHubToken", json!({}), Auth::Admin)
        .await
        .assert_status(StatusCode::OK, "DeleteGitHubToken");
}

async fn assert_config_status_lifecycle_and_parity(harness: &Harness) {
    let config = call(harness, "GetGitHubConfig", json!({}), Auth::Admin).await;
    config.assert_status(StatusCode::OK, "GetGitHubConfig");
    let config = config.json();
    let rest = harness
        .rest(Method::GET, "/api/v1/github/config", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST GitHub config");
    let rest = rest.json();
    assert_eq!(
        config["clientId"].as_str().unwrap_or(""),
        rest["client_id"].as_str().unwrap_or("")
    );
    assert_eq!(
        config["appSlug"].as_str().unwrap_or(""),
        rest["app_slug"].as_str().unwrap_or("")
    );

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = GitHubServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let status = client
            .get_git_hub_status(GetGitHubStatusRequest::default())
            .await
            .expect("GetGitHubStatus codec round trip")
            .into_owned();
        assert!(!status.connected);
    }

    call(
        harness,
        "SaveGitHubToken",
        json!({
            "accessToken": "gho_contract_secret",
            "refreshToken": "ghr_contract_secret",
            "tokenType": "bearer",
            "expiresAt": "2027-07-18T00:00:00.123456Z",
            "refreshTokenExpiresAt": "2028-07-18T00:00:00.654321Z",
            "installationId": "4242",
            "githubUsername": "contract-octocat"
        }),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SaveGitHubToken");

    let connected = call(harness, "GetGitHubStatus", json!({}), Auth::Admin).await;
    connected.assert_status(StatusCode::OK, "connected GetGitHubStatus");
    let connected = connected.json();
    assert_eq!(connected["connected"], true);
    assert_eq!(connected["username"], "contract-octocat");
    assert_eq!(connected["installationId"], "4242");
    assert!(connected["connectedAt"].is_string());
    let rest = harness
        .rest(Method::GET, "/api/v1/github/status", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST GitHub status");
    let rest = rest.json();
    assert_eq!(rest["connected"], connected["connected"]);
    assert_eq!(rest["username"], connected["username"]);
    assert_eq!(rest["installation_id"], 4242);

    disconnect(harness).await;
    let disconnected = call(harness, "GetGitHubStatus", json!({}), Auth::Admin).await;
    assert!(!disconnected.json()["connected"].as_bool().unwrap_or(false));
}

async fn assert_not_connected_parity(harness: &Harness) {
    let connect = call(
        harness,
        "ListGitHubRepos",
        json!({"page": 0, "perPage": 0, "search": "codewire"}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &connect,
        StatusCode::BAD_REQUEST,
        "failed_precondition",
        "GitHub not connected",
    );
    let rest = harness
        .rest(
            Method::GET,
            "/api/v1/github/repos?page=0&per_page=0&search=codewire",
            None,
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::BAD_REQUEST, "REST GitHub disconnected");
    let rest = rest.json();
    assert_eq!(rest["status"], 400);
    assert_eq!(rest["title"], "Bad Request");
    assert_eq!(rest["detail"], body["message"]);
}

async fn assert_api_key_boundary(harness: &Harness) {
    let created = harness
        .connect_json(
            "codewire.v1.ApiKeyService",
            "CreateApiKey",
            json!({"orgId": PRIMARY_ORG, "name": "github-boundary"}),
            Auth::Admin,
        )
        .await;
    created.assert_status(StatusCode::OK, "create GitHub-boundary API key");
    let created = created.json();
    let id = created["apiKey"]["id"].as_str().unwrap();
    let raw = created["key"].as_str().unwrap();
    let denied = call(harness, "GetGitHubStatus", json!({}), Auth::Bearer(raw)).await;
    let body = assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    assert_error_info(&denied, &body, "API_KEY_SCOPE_VIOLATION");
    harness
        .connect_json(
            "codewire.v1.ApiKeyService",
            "DeleteApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": id}),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "delete GitHub-boundary API key");
}
