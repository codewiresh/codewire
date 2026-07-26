use codewire_proto::codewire::console::v1::{AccountServiceClient, ListLoginKeysRequest};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, array, assert_connect_error, assert_error_info, assert_rpc_error,
};

const SERVICE: &str = "codewire.console.v1.AccountService";

pub(super) async fn run(harness: &Harness) {
    assert_login_keys(harness).await;
    assert_ssh_key(harness).await;
    assert_git_identity(harness).await;
    assert_git_credentials(harness).await;
    assert_auth_boundaries(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn assert_login_keys(harness: &Harness) {
    const PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl contract@codewire.test";
    let created = call(
        harness,
        "CreateLoginKey",
        json!({"name": "contract laptop", "publicKey": format!("  {PUBLIC_KEY}  ")}),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreateLoginKey");
    let created = created.json()["loginKey"].clone();
    let id = created["id"]
        .as_str()
        .expect("created login-key id")
        .to_owned();
    assert_eq!(created["name"], "contract laptop");
    assert_eq!(created["publicKey"], PUBLIC_KEY);
    assert!(
        created["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    assert!(created["createdAt"].is_string());

    let duplicate = call(
        harness,
        "CreateLoginKey",
        json!({"name": "duplicate", "publicKey": PUBLIC_KEY}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&duplicate, StatusCode::CONFLICT, "already_exists", "");

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = AccountServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let listed = client
            .list_login_keys(ListLoginKeysRequest::default())
            .await
            .expect("ListLoginKeys codec round trip")
            .into_owned();
        let key = listed
            .login_keys
            .iter()
            .find(|key| key.id == id)
            .expect("created key in ListLoginKeys");
        assert_eq!(key.public_key, PUBLIC_KEY);
        assert_eq!(key.fingerprint, created["fingerprint"]);
    }

    let rest = harness
        .rest(Method::GET, "/api/v1/user/login-keys", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST login-key list");
    let rest = rest.json();
    let keys = array(&rest, "REST login keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], id);
    assert_eq!(keys[0]["name"], created["name"]);
    assert_eq!(keys[0]["public_key"], created["publicKey"]);
    assert_eq!(keys[0]["fingerprint"], created["fingerprint"]);

    call(harness, "DeleteLoginKey", json!({"id": id}), Auth::Admin)
        .await
        .assert_status(StatusCode::OK, "DeleteLoginKey");
    let rest = harness
        .rest(Method::GET, "/api/v1/user/login-keys", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "empty REST login-key list");
    assert!(array(&rest.json(), "REST login keys").is_empty());
}

async fn user_secret_keys(harness: &Harness) -> Vec<String> {
    let response = harness
        .rest(Method::GET, "/api/v1/user/secrets", None, Auth::Admin)
        .await;
    response.assert_status(StatusCode::OK, "REST user-secret list");
    array(&response.json()["secrets"], "user secrets")
        .iter()
        .map(|secret| {
            secret["key"]
                .as_str()
                .expect("secret metadata key")
                .to_owned()
        })
        .collect()
}

async fn assert_ssh_key(harness: &Harness) {
    let missing = call(harness, "GetSshKey", json!({}), Auth::Admin).await;
    assert_connect_error(
        &missing,
        StatusCode::NOT_FOUND,
        "not_found",
        "ssh key not found",
    );

    let ensured = call(harness, "EnsureSshKey", json!({}), Auth::Admin).await;
    ensured.assert_status(StatusCode::OK, "EnsureSshKey");
    let ensured = ensured.json()["sshKey"].clone();
    assert!(
        ensured["publicKey"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert!(ensured["publicKey"].as_str().unwrap().ends_with('\n'));
    assert!(
        ensured["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    assert!(ensured["createdAt"].is_string());
    assert!(ensured.get("regeneratedAt").is_none());

    for method in ["GetSshKey", "EnsureSshKey"] {
        let response = call(harness, method, json!({}), Auth::Admin).await;
        response.assert_status(StatusCode::OK, method);
        assert_eq!(
            response.json()["sshKey"],
            ensured,
            "{method} changed SSH key"
        );
    }

    let rest = harness
        .rest(Method::GET, "/api/v1/user/ssh-key", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST SSH key");
    let rest = rest.json();
    assert_eq!(rest["public_key"], ensured["publicKey"]);
    assert_eq!(rest["fingerprint"], ensured["fingerprint"]);
    assert!(
        user_secret_keys(harness)
            .await
            .iter()
            .any(|key| key == "SSH_PRIVATE_KEY")
    );

    let rotated = call(harness, "RegenerateSshKey", json!({}), Auth::Admin).await;
    rotated.assert_status(StatusCode::OK, "RegenerateSshKey");
    let rotated = rotated.json()["sshKey"].clone();
    assert_ne!(rotated["publicKey"], ensured["publicKey"]);
    assert_ne!(rotated["fingerprint"], ensured["fingerprint"]);
    assert!(rotated["regeneratedAt"].is_string());
    let read = call(harness, "GetSshKey", json!({}), Auth::Admin).await;
    assert_eq!(read.json()["sshKey"], rotated);
}

async fn assert_git_identity(harness: &Harness) {
    let custom = call(
        harness,
        "UpdateGitIdentity",
        json!({"gitName": "Contract Author", "gitEmail": "contract-author@codewire.test"}),
        Auth::Admin,
    )
    .await;
    custom.assert_status(StatusCode::OK, "UpdateGitIdentity custom");
    assert_eq!(custom.json()["gitIdentity"]["gitName"], "Contract Author");

    let cleared = call(harness, "UpdateGitIdentity", json!({}), Auth::Admin).await;
    cleared.assert_status(StatusCode::OK, "UpdateGitIdentity clear");
    let cleared = cleared.json()["gitIdentity"].clone();
    assert_eq!(cleared["gitName"], "API Key Contract Admin");
    assert_eq!(cleared["gitEmail"], "apikey-admin@codewire.test");
    let read = call(harness, "GetGitIdentity", json!({}), Auth::Admin).await;
    assert_eq!(read.json()["gitIdentity"], cleared);
    let rest = harness
        .rest(Method::GET, "/api/v1/user/git-identity", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST Git identity");
    let rest = rest.json();
    assert_eq!(rest["git_name"], cleared["gitName"]);
    assert_eq!(rest["git_email"], cleared["gitEmail"]);
}

async fn assert_git_credentials(harness: &Harness) {
    for body in [
        json!({"name": "GitHub", "host": "github.com", "authType": "basic", "password": "secret"}),
        json!({"name": "Forge", "host": "git.example.com", "authType": "token", "password": "secret"}),
    ] {
        let invalid = call(harness, "CreateGitCredential", body, Auth::Admin).await;
        assert_connect_error(&invalid, StatusCode::BAD_REQUEST, "invalid_argument", "");
    }

    const INITIAL: &str = "account-contract-secret-initial";
    let created = call(
        harness,
        "CreateGitCredential",
        json!({
            "name": "Contract Forge",
            "host": " GITEA.Contract.Test ",
            "authType": "basic",
            "username": "contract-user",
            "password": INITIAL
        }),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreateGitCredential");
    assert!(
        !created
            .body
            .windows(INITIAL.len())
            .any(|part| part == INITIAL.as_bytes())
    );
    assert!(!String::from_utf8_lossy(&created.body).contains("password"));
    let created = created.json()["gitCredential"].clone();
    let id = created["id"]
        .as_str()
        .expect("git credential id")
        .to_owned();
    assert_eq!(created["host"], "gitea.contract.test");
    assert_eq!(created["authType"], "basic");
    assert_eq!(created["username"], "contract-user");

    let listed = call(harness, "ListGitCredentials", json!({}), Auth::Admin).await;
    listed.assert_status(StatusCode::OK, "ListGitCredentials");
    assert!(
        array(&listed.json()["gitCredentials"], "git credentials")
            .iter()
            .any(|credential| credential["id"] == id)
    );
    let rest = harness
        .rest(Method::GET, "/api/v1/git-credentials", None, Auth::Admin)
        .await;
    rest.assert_status(StatusCode::OK, "REST git credentials");
    let rest = rest.json();
    let rest = array(&rest, "REST git credentials");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0]["id"], id);
    assert_eq!(rest[0]["name"], created["name"]);
    assert_eq!(rest[0]["host"], created["host"]);
    assert_eq!(rest[0]["auth_type"], created["authType"]);
    assert_eq!(rest[0]["username"], created["username"]);
    assert!(
        user_secret_keys(harness)
            .await
            .iter()
            .any(|key| key == "GIT_TOKEN_GITEA_CONTRACT_TEST")
    );

    let updated = call(
        harness,
        "UpdateGitCredential",
        json!({
            "credentialId": id,
            "name": "Renamed Contract Forge",
            "username": "renamed-user",
            "password": "account-contract-secret-rotated"
        }),
        Auth::Admin,
    )
    .await;
    updated.assert_status(StatusCode::OK, "UpdateGitCredential");
    let updated = updated.json()["gitCredential"].clone();
    assert_eq!(updated["name"], "Renamed Contract Forge");
    assert_eq!(updated["username"], "renamed-user");
    assert_eq!(updated["host"], created["host"]);

    call(
        harness,
        "DeleteGitCredential",
        json!({"credentialId": id}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeleteGitCredential");
    assert!(
        user_secret_keys(harness)
            .await
            .iter()
            .all(|key| key != "GIT_TOKEN_GITEA_CONTRACT_TEST")
    );
    let rest = harness
        .rest(Method::GET, "/api/v1/git-credentials", None, Auth::Admin)
        .await;
    assert!(array(&rest.json(), "REST git credentials").is_empty());
}

async fn create_api_key(harness: &Harness) -> (String, String) {
    let response = harness
        .connect_json(
            "codewire.v1.ApiKeyService",
            "CreateApiKey",
            json!({"orgId": PRIMARY_ORG, "name": "account-boundary"}),
            Auth::Admin,
        )
        .await;
    response.assert_status(StatusCode::OK, "create account-boundary API key");
    let body = response.json();
    (
        body["apiKey"]["id"].as_str().unwrap().to_owned(),
        body["key"].as_str().unwrap().to_owned(),
    )
}

async fn assert_auth_boundaries(harness: &Harness) {
    let unauthenticated = call(harness, "ListLoginKeys", json!({}), Auth::None).await;
    assert_connect_error(
        &unauthenticated,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "unauthorized",
    );

    let (id, raw) = create_api_key(harness).await;
    let denied = call(harness, "ListLoginKeys", json!({}), Auth::Bearer(&raw)).await;
    let body = assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    assert_error_info(&denied, &body, "API_KEY_SCOPE_VIOLATION");

    let client = AccountServiceClient::new(
        connectrpc::client::HttpClient::plaintext(),
        harness.client_config(Auth::Bearer(&raw), CodecFormat::Proto),
    );
    let error = client
        .list_login_keys(ListLoginKeysRequest::default())
        .await
        .expect_err("binary AccountService API-key denial");
    assert_rpc_error(&error, connectrpc::ErrorCode::PermissionDenied, "");

    harness
        .connect_json(
            "codewire.v1.ApiKeyService",
            "DeleteApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": id}),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "delete account-boundary API key");
}
