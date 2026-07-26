use codewire_proto::codewire::v1::{ListPortsRequest, PortServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, array, assert_bad_request, assert_connect_error,
    assert_error_info,
};

const SERVICE: &str = "codewire.v1.PortService";
const VIEWER_ENV: &str = "env_port_contract_viewer";
const OPERATOR_ENV: &str = "env_port_contract_operator";
const OWNER_ENV: &str = "env_port_contract_owner";

pub(super) async fn run(harness: &Harness) {
    assert_lifecycle_parity_access_and_pagination(harness).await;
    assert_errors_range_and_default(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn delete(harness: &Harness, environment_id: &str, port_id: &str, auth: Auth<'_>) {
    call(
        harness,
        "DeletePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": environment_id, "portId": port_id}),
        auth,
    )
    .await
    .assert_status(StatusCode::OK, "DeletePort");
}

async fn assert_lifecycle_parity_access_and_pagination(harness: &Harness) {
    let created = call(
        harness,
        "CreatePort",
        json!({
            "orgId": PRIMARY_ORG,
            "environmentId": OPERATOR_ENV,
            "port": 8080,
            "label": "connect-web",
            "access": "PORT_ACCESS_PUBLIC"
        }),
        Auth::User,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreatePort");
    let created = created.json()["port"].clone();
    let id = created["id"].as_str().expect("created port id").to_owned();
    assert_eq!(created["environmentId"], OPERATOR_ENV);
    assert_eq!(created["port"], 8080);
    assert_eq!(created["label"], "connect-web");
    assert_eq!(created["access"], "PORT_ACCESS_PUBLIC");

    let listed = call(
        harness,
        "ListPorts",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "pageSize": 1}),
        Auth::User,
    )
    .await;
    listed.assert_status(StatusCode::OK, "ListPorts");
    let body = listed.json();
    assert!(
        array(&body["ports"], "ports")
            .iter()
            .any(|port| port["id"] == id)
    );
    assert!(body["nextPageToken"].as_str().unwrap_or("").is_empty());
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = PortServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::User, codec),
        );
        let listed = client
            .list_ports(ListPortsRequest {
                org_id: PRIMARY_ORG.into(),
                environment_id: OPERATOR_ENV.into(),
                ..Default::default()
            })
            .await
            .expect("ListPorts codec round trip")
            .into_owned();
        assert!(listed.ports.iter().any(|port| port.id == id));
        assert!(listed.next_page_token.is_empty());
    }

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/environments/{OPERATOR_ENV}/ports"),
            None,
            Auth::User,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST port list");
    let rest_body = rest.json();
    let rest = array(&rest_body, "REST ports")
        .iter()
        .find(|port| port["id"] == id)
        .expect("created port in REST list");
    assert_eq!(rest["environment_id"], created["environmentId"]);
    assert_eq!(rest["port"], created["port"]);
    assert_eq!(rest["label"], created["label"]);
    assert_eq!(rest["access"], "public");
    assert_eq!(rest["preview_url"], created["previewUrl"]);

    call(
        harness,
        "ListPorts",
        json!({"orgId": PRIMARY_ORG, "environmentId": VIEWER_ENV}),
        Auth::User,
    )
    .await
    .assert_status(StatusCode::OK, "viewer ListPorts");
    let viewer_write = call(
        harness,
        "CreatePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": VIEWER_ENV, "port": 8081, "label": "viewer-denied"}),
        Auth::User,
    )
    .await;
    let body = assert_connect_error(
        &viewer_write,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "",
    );
    assert_error_info(&viewer_write, &body, "ACCESS_DENIED");
    let operator_delete = call(
        harness,
        "DeletePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "portId": id}),
        Auth::User,
    )
    .await;
    let body = assert_connect_error(
        &operator_delete,
        StatusCode::FORBIDDEN,
        "permission_denied",
        "",
    );
    assert_error_info(&operator_delete, &body, "ACCESS_DENIED");

    let owner = call(
        harness,
        "CreatePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": OWNER_ENV, "port": 8082, "label": "owner-delete"}),
        Auth::Admin,
    )
    .await;
    let owner_id = owner.json()["port"]["id"].as_str().unwrap().to_owned();
    delete(harness, OWNER_ENV, &owner_id, Auth::User).await;

    let page = call(
        harness,
        "ListPorts",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "pageToken": "future"}),
        Auth::User,
    )
    .await;
    assert_connect_error(&page, StatusCode::BAD_REQUEST, "invalid_argument", "");
    let hidden = call(
        harness,
        "ListPorts",
        json!({"orgId": SECONDARY_ORG, "environmentId": OPERATOR_ENV}),
        Auth::User,
    )
    .await;
    let body = assert_connect_error(&hidden, StatusCode::NOT_FOUND, "not_found", "");
    assert_error_info(&hidden, &body, "ORG_NOT_FOUND");
    let unauthenticated = call(
        harness,
        "ListPorts",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV}),
        Auth::None,
    )
    .await;
    assert_connect_error(
        &unauthenticated,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "unauthorized",
    );
    delete(harness, OPERATOR_ENV, &id, Auth::Admin).await;
}

async fn assert_errors_range_and_default(harness: &Harness) {
    let created = call(
        harness,
        "CreatePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "port": 9090, "label": "creator-default"}),
        Auth::Admin,
    )
    .await;
    created.assert_status(StatusCode::OK, "CreatePort default access");
    let created = created.json()["port"].clone();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["access"], "PORT_ACCESS_CREATOR");

    for (body, code, reason, field) in [
        (
            json!({"port": 2222, "label": "reserved"}),
            "invalid_argument",
            "PORT_RESERVED",
            None,
        ),
        (
            json!({"port": 9091, "label": "bad-access", "access": 99}),
            "invalid_argument",
            "INVALID_ACCESS",
            None,
        ),
        (
            json!({"port": 0, "label": "below-range"}),
            "invalid_argument",
            "",
            Some("port"),
        ),
        (
            json!({"port": 65536, "label": "above-range"}),
            "invalid_argument",
            "",
            None,
        ),
    ] {
        let mut full = body.as_object().unwrap().clone();
        full.insert("orgId".into(), json!(PRIMARY_ORG));
        full.insert("environmentId".into(), json!(OPERATOR_ENV));
        let response = call(harness, "CreatePort", Value::Object(full), Auth::Admin).await;
        let error = assert_connect_error(&response, StatusCode::BAD_REQUEST, code, "");
        if !reason.is_empty() {
            assert_error_info(&response, &error, reason);
        }
        if let Some(field) = field {
            assert_bad_request(&error, &[field]);
        }
    }

    let rest = harness
        .rest(
            Method::POST,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/environments/{OPERATOR_ENV}/ports"),
            Some(json!({"port": 0, "label": "rest-below-range", "access": "creator"})),
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::BAD_REQUEST, "REST port range");
    let conflict = call(
        harness,
        "CreatePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "port": 9090, "label": "duplicate-port"}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(&conflict, StatusCode::CONFLICT, "already_exists", "");
    assert_error_info(&conflict, &body, "PORT_CONFLICT");
    let missing = call(
        harness,
        "DeletePort",
        json!({"orgId": PRIMARY_ORG, "environmentId": OPERATOR_ENV, "portId": "port_contract_missing"}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(&missing, StatusCode::NOT_FOUND, "not_found", "");
    assert_error_info(&missing, &body, "PORT_NOT_FOUND");
    delete(harness, OPERATOR_ENV, &id, Auth::Admin).await;
}
