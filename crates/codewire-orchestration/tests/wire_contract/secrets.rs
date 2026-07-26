use codewire_proto::codewire::v1::{ListSecretsRequest, SecretServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, WireResponse, array, assert_bad_request,
    assert_connect_error,
};

const SERVICE: &str = "codewire.v1.SecretService";
const ORG_MARKER: &str = "org-connect-secret-marker";
const USER_MARKER: &str = "user-connect-secret-marker";
const PROJECT_MARKER: &str = "project-connect-secret-marker";

pub(super) async fn run(harness: &Harness) {
    assert_org_lifecycle(harness).await;
    assert_user_lifecycle(harness).await;
    assert_project_lifecycle(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> WireResponse {
    let response = harness.connect_json(SERVICE, method, body, auth).await;
    for marker in [ORG_MARKER, USER_MARKER, PROJECT_MARKER] {
        assert!(
            !response
                .body
                .windows(marker.len())
                .any(|part| part == marker.as_bytes()),
            "{method} disclosed submitted secret material"
        );
    }
    if response.status.is_success() {
        assert_write_only(&response.json());
    }
    response
}

fn assert_write_only(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    !key.eq_ignore_ascii_case("value") && !key.eq_ignore_ascii_case("secretValue"),
                    "secret response exposed forbidden field {key}"
                );
                assert_write_only(value);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_write_only),
        _ => {}
    }
}

fn has_key(body: &Value, key: &str) -> bool {
    body.get("secrets")
        .and_then(Value::as_array)
        .is_some_and(|secrets| secrets.iter().any(|secret| secret["key"] == key))
}

async fn assert_org_lifecycle(harness: &Harness) {
    const ORIGINAL: &str = "ORG_CONNECT_ALPHA";
    const RENAMED: &str = "ORG_CONNECT_RENAMED";
    const CONFLICT: &str = "ORG_CONNECT_CONFLICT";
    call(
        harness,
        "SetSecret",
        json!({"orgId": PRIMARY_ORG, "key": ORIGINAL, "value": ORG_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetSecret");
    let listed = call(
        harness,
        "ListSecrets",
        json!({"orgId": PRIMARY_ORG, "pageSize": 1}),
        Auth::User,
    )
    .await;
    listed.assert_status(StatusCode::OK, "ListSecrets");
    assert!(has_key(&listed.json(), ORIGINAL));

    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = SecretServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::User, codec),
        );
        let listed = client
            .list_secrets(ListSecretsRequest {
                org_id: PRIMARY_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("ListSecrets codec round trip")
            .into_owned();
        assert!(listed.secrets.iter().any(|secret| secret.key == ORIGINAL));
        assert!(listed.next_page_token.is_empty());
    }

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/secrets?org_id={PRIMARY_ORG}"),
            None,
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST organization secrets");
    assert_write_only(&rest.json());
    assert!(has_key(&rest.json(), ORIGINAL));

    let denied = call(
        harness,
        "SetSecret",
        json!({"orgId": PRIMARY_ORG, "key": "MEMBER_DENIED", "value": ORG_MARKER}),
        Auth::User,
    )
    .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    let rest_denied = harness
        .rest(
            Method::PUT,
            "/api/v1/secrets",
            Some(json!({"org_id": PRIMARY_ORG, "key": "MEMBER_DENIED", "value": ORG_MARKER})),
            Auth::User,
        )
        .await;
    rest_denied.assert_status(StatusCode::FORBIDDEN, "REST member SetSecret denial");
    let hidden = call(
        harness,
        "ListSecrets",
        json!({"orgId": SECONDARY_ORG}),
        Auth::User,
    )
    .await;
    assert_connect_error(&hidden, StatusCode::NOT_FOUND, "not_found", "");

    let same = call(
        harness,
        "RenameSecret",
        json!({"orgId": PRIMARY_ORG, "key": ORIGINAL, "newKey": ORIGINAL}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&same, StatusCode::BAD_REQUEST, "invalid_argument", "");
    let missing = call(
        harness,
        "RenameSecret",
        json!({"orgId": PRIMARY_ORG, "key": "ORG_CONNECT_MISSING", "newKey": RENAMED}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&missing, StatusCode::NOT_FOUND, "not_found", "");
    call(
        harness,
        "SetSecret",
        json!({"orgId": PRIMARY_ORG, "key": CONFLICT, "value": ORG_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetSecret conflict fixture");
    let conflict = call(
        harness,
        "RenameSecret",
        json!({"orgId": PRIMARY_ORG, "key": ORIGINAL, "newKey": CONFLICT}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&conflict, StatusCode::CONFLICT, "already_exists", "");
    call(
        harness,
        "RenameSecret",
        json!({"orgId": PRIMARY_ORG, "key": ORIGINAL, "newKey": RENAMED}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "RenameSecret");
    call(
        harness,
        "DeleteSecret",
        json!({"orgId": PRIMARY_ORG, "key": RENAMED}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeleteSecret");
    call(
        harness,
        "DeleteSecret",
        json!({"orgId": PRIMARY_ORG, "key": CONFLICT}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeleteSecret conflict fixture");

    let invalid = call(
        harness,
        "SetSecret",
        json!({"orgId": PRIMARY_ORG, "key": "unsafe/path", "value": ORG_MARKER}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &invalid,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "validation failed",
    );
    assert_bad_request(&body, &["key"]);
    let page = call(
        harness,
        "ListSecrets",
        json!({"orgId": PRIMARY_ORG, "pageToken": "unknown"}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&page, StatusCode::BAD_REQUEST, "invalid_argument", "");
    let unauthenticated = call(
        harness,
        "ListSecrets",
        json!({"orgId": PRIMARY_ORG}),
        Auth::None,
    )
    .await;
    assert_connect_error(
        &unauthenticated,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "unauthorized",
    );
}

async fn assert_user_lifecycle(harness: &Harness) {
    const ORIGINAL: &str = "USER_CONNECT_ALPHA";
    const RENAMED: &str = "USER_CONNECT_RENAMED";
    const CONFLICT: &str = "USER_CONNECT_CONFLICT";
    call(
        harness,
        "SetUserSecret",
        json!({"key": ORIGINAL, "value": USER_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetUserSecret");
    let admin = call(
        harness,
        "ListUserSecrets",
        json!({"pageSize": 1}),
        Auth::Admin,
    )
    .await;
    assert!(has_key(&admin.json(), ORIGINAL));
    let rest = harness
        .rest(Method::GET, "/api/v1/user/secrets", None, Auth::Admin)
        .await;
    assert_write_only(&rest.json());
    assert!(has_key(&rest.json(), ORIGINAL));
    let user = call(harness, "ListUserSecrets", json!({}), Auth::User).await;
    assert!(!has_key(&user.json(), ORIGINAL));

    let same = call(
        harness,
        "RenameUserSecret",
        json!({"key": ORIGINAL, "newKey": ORIGINAL}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&same, StatusCode::BAD_REQUEST, "invalid_argument", "");
    let missing = call(
        harness,
        "RenameUserSecret",
        json!({"key": "USER_CONNECT_MISSING", "newKey": RENAMED}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&missing, StatusCode::NOT_FOUND, "not_found", "");
    call(
        harness,
        "SetUserSecret",
        json!({"key": CONFLICT, "value": USER_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetUserSecret conflict fixture");
    let conflict = call(
        harness,
        "RenameUserSecret",
        json!({"key": ORIGINAL, "newKey": CONFLICT}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&conflict, StatusCode::CONFLICT, "already_exists", "");
    call(
        harness,
        "RenameUserSecret",
        json!({"key": ORIGINAL, "newKey": RENAMED}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "RenameUserSecret");
    for key in [RENAMED, CONFLICT] {
        call(
            harness,
            "DeleteUserSecret",
            json!({"key": key}),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "DeleteUserSecret");
    }
}

async fn assert_project_lifecycle(harness: &Harness) {
    const ORIGINAL: &str = "PROJECT_CONNECT_ALPHA";
    const RENAMED: &str = "PROJECT_CONNECT_RENAMED";
    const CONFLICT: &str = "PROJECT_CONNECT_CONFLICT";
    let created = call(
        harness,
        "CreateSecretProject",
        json!({"orgId": PRIMARY_ORG, "name": "Secret Connect Contract Project"}),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreateSecretProject");
    let project = created.json()["secretProject"].clone();
    let id = project["id"]
        .as_str()
        .expect("secret project id")
        .to_owned();
    assert_eq!(project["orgId"], PRIMARY_ORG);
    assert_eq!(project["secretCount"].as_str().unwrap_or("0"), "0");

    let listed = call(
        harness,
        "ListSecretProjects",
        json!({"orgId": PRIMARY_ORG, "pageSize": 1}),
        Auth::User,
    )
    .await;
    listed.assert_status(StatusCode::OK, "ListSecretProjects");
    assert!(
        array(&listed.json()["secretProjects"], "secret projects")
            .iter()
            .any(|candidate| candidate["id"] == id)
    );
    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/secret-projects"),
            None,
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST secret projects");
    assert!(
        array(&rest.json(), "REST secret projects")
            .iter()
            .any(|p| p["id"] == id)
    );

    let denied = call(
        harness,
        "CreateSecretProject",
        json!({"orgId": PRIMARY_ORG, "name": "Member Denied Project"}),
        Auth::User,
    )
    .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    let hidden = call(
        harness,
        "ListSecretProjects",
        json!({"orgId": SECONDARY_ORG}),
        Auth::User,
    )
    .await;
    assert_connect_error(&hidden, StatusCode::NOT_FOUND, "not_found", "");

    call(
        harness,
        "SetProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": ORIGINAL, "value": PROJECT_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetProjectSecret");
    let project_secrets = call(
        harness,
        "ListProjectSecrets",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id}),
        Auth::User,
    )
    .await;
    assert!(has_key(&project_secrets.json(), ORIGINAL));
    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/secret-projects/{id}/secrets"),
            None,
            Auth::User,
        )
        .await;
    assert!(has_key(&rest.json(), ORIGINAL));

    let member_write = call(
        harness,
        "SetProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": "MEMBER_DENIED", "value": PROJECT_MARKER}),
        Auth::User,
    )
    .await;
    assert_connect_error(
        &member_write,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "",
    );
    let same = call(
        harness,
        "RenameProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": ORIGINAL, "newKey": ORIGINAL}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&same, StatusCode::BAD_REQUEST, "invalid_argument", "");
    let missing = call(
        harness,
        "RenameProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": "PROJECT_CONNECT_MISSING", "newKey": RENAMED}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&missing, StatusCode::NOT_FOUND, "not_found", "");
    call(
        harness,
        "SetProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": CONFLICT, "value": PROJECT_MARKER}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "SetProjectSecret conflict fixture");
    let conflict = call(
        harness,
        "RenameProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": ORIGINAL, "newKey": CONFLICT}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&conflict, StatusCode::CONFLICT, "already_exists", "");
    call(
        harness,
        "RenameProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": ORIGINAL, "newKey": RENAMED}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "RenameProjectSecret");
    call(
        harness,
        "DeleteProjectSecret",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id, "key": RENAMED}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeleteProjectSecret");

    let counted = call(
        harness,
        "ListSecretProjects",
        json!({"orgId": PRIMARY_ORG}),
        Auth::Admin,
    )
    .await;
    let counted = array(&counted.json()["secretProjects"], "secret projects")
        .iter()
        .find(|project| project["id"] == id)
        .expect("created project before count verification")
        .clone();
    assert_eq!(counted["secretCount"], "1");
    call(
        harness,
        "DeleteSecretProject",
        json!({"orgId": PRIMARY_ORG, "secretProjectId": id}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeleteSecretProject");
}
