use codewire_proto::codewire::v1::{ApiKeyServiceClient, ListApiKeysRequest};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, array, assert_bad_request, assert_connect_error,
    assert_error_info, assert_rpc_error,
};

const SERVICE: &str = "codewire.v1.ApiKeyService";
const PARITY_KEY: &str = "ak_apikey_contract_parity";

struct CreatedKey {
    id: String,
    raw: String,
}

pub(super) async fn run(harness: &Harness) {
    assert_binary_and_json_reads(harness).await;
    assert_lifecycle_and_secret_non_leakage(harness).await;
    assert_organization_scoping(harness).await;
    assert_canonical_errors(harness).await;
    assert_rest_parity(harness).await;
}

async fn assert_binary_and_json_reads(harness: &Harness) {
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = ApiKeyServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let response = client
            .list_api_keys(ListApiKeysRequest {
                org_id: PRIMARY_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("ListApiKeys codec round trip")
            .into_owned();
        assert!(!response.api_keys.is_empty());
        assert!(response.next_page_token.is_empty());
        assert!(response.api_keys.iter().any(|key| key.id == PARITY_KEY));
        assert!(
            response
                .api_keys
                .iter()
                .all(|key| key.org_id == PRIMARY_ORG)
        );
    }
}

async fn create_key(harness: &Harness, org_id: &str, name: &str) -> CreatedKey {
    let response = harness
        .connect_json(
            SERVICE,
            "CreateApiKey",
            json!({
                "orgId": org_id,
                "name": name,
                "scopes": ["environments:read", "secrets:read"]
            }),
            Auth::Admin,
        )
        .await;
    response.assert_status(StatusCode::OK, "CreateApiKey");
    let body = response.json();
    let raw = body["key"].as_str().expect("one-time raw key").to_owned();
    let key = &body["apiKey"];
    let id = key["id"].as_str().expect("created API-key id").to_owned();
    assert_eq!(raw.len(), 67);
    assert!(raw.starts_with("cw_"));
    assert!(raw[3..].chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(key["orgId"], org_id);
    assert_eq!(key["name"], name);
    assert_eq!(key["keyPrefix"], &raw[3..11]);
    CreatedKey { id, raw }
}

async fn delete_key(harness: &Harness, org_id: &str, id: &str) {
    harness
        .connect_json(
            SERVICE,
            "DeleteApiKey",
            json!({"orgId": org_id, "keyId": id}),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "DeleteApiKey cleanup");
}

async fn list_json(harness: &Harness, org_id: &str, auth: Auth<'_>) -> (Value, Vec<u8>) {
    let response = harness
        .connect_json(SERVICE, "ListApiKeys", json!({"orgId": org_id}), auth)
        .await;
    response.assert_status(StatusCode::OK, "ListApiKeys");
    (response.json(), response.body)
}

async fn assert_lifecycle_and_secret_non_leakage(harness: &Harness) {
    let created = create_key(harness, PRIMARY_ORG, "rust-contract-lifecycle").await;
    let (listed, raw) = list_json(harness, PRIMARY_ORG, Auth::Admin).await;
    assert!(
        array(&listed["apiKeys"], "apiKeys")
            .iter()
            .any(|key| key["id"] == created.id)
    );
    assert!(listed["nextPageToken"].as_str().unwrap_or("").is_empty());
    assert!(
        !raw.windows(created.raw.len())
            .any(|part| part == created.raw.as_bytes())
    );
    assert!(!String::from_utf8_lossy(&raw).contains("cw_"));
    for key in array(&listed["apiKeys"], "apiKeys") {
        assert!(
            key.get("key").is_none(),
            "ListApiKeys exposed raw key field"
        );
    }

    let disabled = harness
        .connect_json(
            SERVICE,
            "UpdateApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": created.id, "disabled": true}),
            Auth::Admin,
        )
        .await;
    disabled.assert_status(StatusCode::OK, "disable API key");
    assert!(disabled.json()["apiKey"]["disabledAt"].is_string());
    let enabled = harness
        .connect_json(
            SERVICE,
            "UpdateApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": created.id, "disabled": false}),
            Auth::Admin,
        )
        .await;
    enabled.assert_status(StatusCode::OK, "re-enable API key");
    assert!(enabled.json()["apiKey"].get("disabledAt").is_none());

    delete_key(harness, PRIMARY_ORG, &created.id).await;
    let (listed, _) = list_json(harness, PRIMARY_ORG, Auth::Admin).await;
    assert!(
        array(&listed["apiKeys"], "apiKeys")
            .iter()
            .all(|key| key["id"] != created.id)
    );
}

async fn assert_organization_scoping(harness: &Harness) {
    let primary_a = create_key(harness, PRIMARY_ORG, "rust-contract-primary-a").await;
    let primary_b = create_key(harness, PRIMARY_ORG, "rust-contract-primary-b").await;
    let secondary_a = create_key(harness, SECONDARY_ORG, "rust-contract-secondary-a").await;
    let secondary_b = create_key(harness, SECONDARY_ORG, "rust-contract-secondary-b").await;

    for (org_id, own, foreign) in [
        (
            PRIMARY_ORG,
            [&primary_a.id, &primary_b.id],
            [&secondary_a.id, &secondary_b.id],
        ),
        (
            SECONDARY_ORG,
            [&secondary_a.id, &secondary_b.id],
            [&primary_a.id, &primary_b.id],
        ),
    ] {
        let response = harness
            .connect_json(
                SERVICE,
                "ListApiKeys",
                json!({"orgId": org_id, "pageSize": 1}),
                Auth::Admin,
            )
            .await;
        response.assert_status(StatusCode::OK, "organization-scoped ListApiKeys");
        let body = response.json();
        let keys = array(&body["apiKeys"], "apiKeys");
        assert!(keys.len() > 1);
        for id in own {
            assert!(keys.iter().any(|key| key["id"] == id.as_str()));
        }
        for id in foreign {
            assert!(keys.iter().all(|key| key["id"] != id.as_str()));
        }
    }

    let unsupported = harness
        .connect_json(
            SERVICE,
            "ListApiKeys",
            json!({"orgId": PRIMARY_ORG, "pageSize": 1, "pageToken": "future"}),
            Auth::Admin,
        )
        .await;
    assert_connect_error(
        &unsupported,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "unrecognized page_token",
    );

    let (own, _) = list_json(harness, PRIMARY_ORG, Auth::Bearer(&primary_a.raw)).await;
    assert!(
        array(&own["apiKeys"], "apiKeys")
            .iter()
            .any(|key| key["id"] == primary_a.id)
    );
    let foreign = harness
        .connect_json(
            SERVICE,
            "ListApiKeys",
            json!({"orgId": SECONDARY_ORG}),
            Auth::Bearer(&primary_a.raw),
        )
        .await;
    assert_connect_error(
        &foreign,
        StatusCode::NOT_FOUND,
        "not_found",
        "organization not found",
    );

    let organizations = harness
        .rest(
            Method::GET,
            "/api/v1/organizations",
            None,
            Auth::Bearer(&primary_a.raw),
        )
        .await;
    organizations.assert_status(StatusCode::OK, "API-key organization list");
    let organizations = organizations.json();
    let organizations = array(&organizations, "organizations");
    assert_eq!(organizations.len(), 1);
    assert_eq!(organizations[0]["id"], PRIMARY_ORG);

    for (method, path, body) in [
        (
            Method::POST,
            "/api/v1/organizations",
            Some(json!({"name": "must-not-exist", "slug": "must-not-exist"})),
        ),
        (Method::POST, "/api/v1/terminal/ticket", Some(json!({}))),
        (Method::GET, "/api/v1/admin/stats", None),
    ] {
        let denied = harness
            .rest(method, path, body, Auth::Bearer(&primary_a.raw))
            .await;
        denied.assert_status(StatusCode::FORBIDDEN, "account-global API-key denial");
        assert_eq!(denied.json()["code"], "api_key_scope_violation");
    }

    for (org, key) in [
        (PRIMARY_ORG, primary_a),
        (PRIMARY_ORG, primary_b),
        (SECONDARY_ORG, secondary_a),
        (SECONDARY_ORG, secondary_b),
    ] {
        delete_key(harness, org, &key.id).await;
    }
}

async fn assert_canonical_errors(harness: &Harness) {
    for (body, field) in [
        (json!({"orgId": PRIMARY_ORG, "name": " \t "}), "name"),
        (
            json!({"orgId": PRIMARY_ORG, "name": "invalid-expiry", "expiresInDays": 0}),
            "expires_in_days",
        ),
    ] {
        let response = harness
            .connect_json(SERVICE, "CreateApiKey", body, Auth::Admin)
            .await;
        let body = assert_connect_error(
            &response,
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "validation failed",
        );
        assert_bad_request(&body, &[field]);
    }

    let created = create_key(harness, PRIMARY_ORG, "rust-contract-errors").await;
    let missing_disabled = harness
        .connect_json(
            SERVICE,
            "UpdateApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": created.id}),
            Auth::Admin,
        )
        .await;
    let body = assert_connect_error(
        &missing_disabled,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "validation failed",
    );
    assert_bad_request(&body, &["disabled"]);

    let denied = harness
        .connect_json(
            SERVICE,
            "DeleteApiKey",
            json!({"orgId": PRIMARY_ORG, "keyId": created.id}),
            Auth::User,
        )
        .await;
    let body = assert_connect_error(
        &denied,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "only owner or admin can revoke api keys",
    );
    assert_error_info(&denied, &body, "");

    let hidden = harness
        .connect_json(
            SERVICE,
            "ListApiKeys",
            json!({"orgId": SECONDARY_ORG}),
            Auth::User,
        )
        .await;
    assert_connect_error(
        &hidden,
        StatusCode::NOT_FOUND,
        "not_found",
        "organization not found",
    );
    let unauthenticated = harness
        .connect_json(
            SERVICE,
            "ListApiKeys",
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

    let client = ApiKeyServiceClient::new(
        connectrpc::client::HttpClient::plaintext(),
        harness.client_config(Auth::User, CodecFormat::Proto),
    );
    let error = client
        .list_api_keys(ListApiKeysRequest {
            org_id: SECONDARY_ORG.into(),
            ..Default::default()
        })
        .await
        .expect_err("binary nonmembership must remain hidden");
    assert_rpc_error(
        &error,
        connectrpc::ErrorCode::NotFound,
        "organization not found",
    );

    delete_key(harness, PRIMARY_ORG, &created.id).await;
}

async fn assert_rest_parity(harness: &Harness) {
    let (connect, _) = list_json(harness, PRIMARY_ORG, Auth::Admin).await;
    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/api-keys"),
            None,
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST API-key list");
    let rest = rest.json();
    let connect = array(&connect["apiKeys"], "Connect API keys");
    let rest = array(&rest, "REST API keys");
    assert_eq!(connect.len(), rest.len());
    for connect_key in connect {
        let id = connect_key["id"].as_str().expect("Connect key id");
        let rest_key = rest
            .iter()
            .find(|key| key["id"] == id)
            .unwrap_or_else(|| panic!("REST list missing Connect API key {id}"));
        assert_eq!(connect_key["name"], rest_key["name"]);
        assert_eq!(connect_key["keyPrefix"], rest_key["key_prefix"]);
        assert_eq!(connect_key["scopes"], rest_key["scopes"]);
    }
    assert!(connect.iter().any(|key| key["id"] == PARITY_KEY));
}
