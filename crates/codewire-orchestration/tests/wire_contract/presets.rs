use codewire_proto::codewire::v1::{ListPresetsRequest, PresetServiceClient};
use connectrpc::CodecFormat;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    Auth, Harness, PRIMARY_ORG, SECONDARY_ORG, array, assert_bad_request, assert_connect_error,
    assert_error_info,
};

const SERVICE: &str = "codewire.v1.PresetService";
const SECRET_PROJECT: &str = "sp_preset_contract_1";
const OFFICIAL: &str = "preset_contract_official";
const IN_USE: &str = "preset_contract_in_use";

pub(super) async fn run(harness: &Harness) {
    assert_lifecycle_and_parity(harness).await;
    assert_patch_presence(harness).await;
    assert_in_use_error(harness).await;
}

async fn call(harness: &Harness, method: &str, body: Value, auth: Auth<'_>) -> super::WireResponse {
    harness.connect_json(SERVICE, method, body, auth).await
}

async fn create(harness: &Harness, slug: &str) -> Value {
    let response = call(
        harness,
        "CreatePreset",
        json!({
            "orgId": PRIMARY_ORG,
            "name": "Contract Preset",
            "slug": slug,
            "description": "Connect preset contract",
            "defaultCpuMillicores": 1500,
            "defaultMemoryMb": 3072,
            "defaultDiskGb": 12,
            "defaultTtlSeconds": 1800,
            "image": "ghcr.io/codewiresh/sandbox:contract",
            "installCommand": "cargo fetch",
            "startupScript": "cargo run",
            "envVars": {"SURFACE": "create"},
            "agents": [{"type": "codex"}],
            "installAgents": true,
            "agent": "codex",
            "agentEnv": {"CODEWIRE": "true"},
            "appPorts": [{"port": 8080, "label": "web", "access": "public"}],
            "includeOrgSecrets": true,
            "includeUserSecrets": false,
            "secretProjectId": SECRET_PROJECT
        }),
        Auth::Admin,
    )
    .await;
    response.assert_status(StatusCode::OK, "CreatePreset");
    let preset = response.json()["preset"].clone();
    assert!(preset["id"].is_string());
    preset
}

async fn get(harness: &Harness, org_id: &str, preset_id: &str) -> Value {
    let response = call(
        harness,
        "GetPreset",
        json!({"orgId": org_id, "presetId": preset_id}),
        Auth::Admin,
    )
    .await;
    response.assert_status(StatusCode::OK, "GetPreset");
    response.json()["preset"].clone()
}

async fn delete(harness: &Harness, id: &str) {
    call(
        harness,
        "DeletePreset",
        json!({"orgId": PRIMARY_ORG, "presetId": id}),
        Auth::Admin,
    )
    .await
    .assert_status(StatusCode::OK, "DeletePreset");
}

async fn assert_lifecycle_and_parity(harness: &Harness) {
    let created = create(harness, "preset-contract-lifecycle").await;
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["orgId"], PRIMARY_ORG);
    assert_eq!(created["secretProjectId"], SECRET_PROJECT);
    assert_eq!(
        created["defaultSetupConfig"]["envVars"]["SURFACE"],
        "create"
    );

    let listed = call(
        harness,
        "ListPresets",
        json!({"orgId": PRIMARY_ORG, "pageSize": 1}),
        Auth::Admin,
    )
    .await;
    listed.assert_status(StatusCode::OK, "ListPresets");
    let listed_body = listed.json();
    let connect = array(&listed_body["presets"], "presets")
        .iter()
        .find(|preset| preset["id"] == id)
        .expect("created preset in Connect list")
        .clone();
    assert!(
        listed_body["nextPageToken"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
    for codec in [CodecFormat::Proto, CodecFormat::Json] {
        let client = PresetServiceClient::new(
            connectrpc::client::HttpClient::plaintext(),
            harness.client_config(Auth::Admin, codec),
        );
        let response = client
            .list_presets(ListPresetsRequest {
                org_id: PRIMARY_ORG.into(),
                ..Default::default()
            })
            .await
            .expect("ListPresets codec round trip")
            .into_owned();
        assert!(response.presets.iter().any(|preset| preset.id == id));
        assert!(response.next_page_token.is_empty());
    }

    let rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/presets"),
            None,
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::OK, "REST preset list");
    let rest_body = rest.json();
    let rest = array(&rest_body, "REST presets")
        .iter()
        .find(|preset| preset["id"] == id)
        .expect("created preset in REST list");
    for (connect_name, rest_name) in [
        ("id", "id"),
        ("orgId", "org_id"),
        ("name", "name"),
        ("slug", "slug"),
        ("description", "description"),
        ("buildStatus", "build_status"),
        ("defaultCpuMillicores", "default_cpu_millicores"),
        ("defaultMemoryMb", "default_memory_mb"),
        ("defaultDiskGb", "default_disk_gb"),
        ("defaultTtlSeconds", "default_ttl_seconds"),
        ("image", "image"),
        ("secretProjectId", "secret_project_id"),
    ] {
        assert_eq!(connect[connect_name], rest[rest_name]);
    }
    assert!(!connect["official"].as_bool().unwrap_or(false));
    assert_eq!(rest["official"], false);
    assert_eq!(
        connect["defaultSetupConfig"]["envVars"]["SURFACE"],
        rest["default_setup_config"]["env_vars"]["SURFACE"]
    );

    let official = get(harness, SECONDARY_ORG, OFFICIAL).await;
    assert_eq!(official["id"], OFFICIAL);
    assert_eq!(official["official"], true);
    assert!(official.get("orgId").is_none());
    let official_rest = harness
        .rest(
            Method::GET,
            &format!("/api/v1/organizations/{SECONDARY_ORG}/presets/{OFFICIAL}"),
            None,
            Auth::Admin,
        )
        .await;
    official_rest.assert_status(StatusCode::OK, "REST official preset");
    assert_eq!(official_rest.json()["id"], OFFICIAL);

    let hidden = call(
        harness,
        "GetPreset",
        json!({"orgId": SECONDARY_ORG, "presetId": id}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&hidden, StatusCode::NOT_FOUND, "not_found", "");
    let denied = call(
        harness,
        "CreatePreset",
        json!({"orgId": PRIMARY_ORG, "name": "Member denied preset"}),
        Auth::User,
    )
    .await;
    assert_connect_error(&denied, StatusCode::FORBIDDEN, "permission_denied", "");
    let collision = call(
        harness,
        "CreatePreset",
        json!({"orgId": PRIMARY_ORG, "name": "Preset collision", "slug": created["slug"]}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(&collision, StatusCode::CONFLICT, "already_exists", "");
    let invalid = call(
        harness,
        "CreatePreset",
        json!({"orgId": PRIMARY_ORG, "name": ""}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(
        &invalid,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "validation failed",
    );
    assert_bad_request(&body, &["name"]);
    let page = call(
        harness,
        "ListPresets",
        json!({"orgId": PRIMARY_ORG, "pageToken": "unsupported"}),
        Auth::Admin,
    )
    .await;
    assert_connect_error(
        &page,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "unrecognized page_token",
    );
    delete(harness, &id).await;
}

fn assert_patch_state(preset: &Value, slug: &str, project: &str, surface: &str) {
    assert_eq!(preset["slug"].as_str().unwrap_or(""), slug);
    assert_eq!(preset["secretProjectId"].as_str().unwrap_or(""), project);
    assert_eq!(
        preset["defaultSetupConfig"]["envVars"]["SURFACE"]
            .as_str()
            .unwrap_or(""),
        surface
    );
}

async fn update(harness: &Harness, body: Value) -> Value {
    let response = call(harness, "UpdatePreset", body, Auth::Admin).await;
    response.assert_status(StatusCode::OK, "UpdatePreset");
    response.json()["preset"].clone()
}

async fn assert_patch_presence(harness: &Harness) {
    let created = create(harness, "preset-contract-patch").await;
    let id = created["id"].as_str().unwrap().to_owned();
    let value = update(
        harness,
        json!({
            "orgId": PRIMARY_ORG,
            "presetId": id,
            "slug": "preset-connect-value",
            "secretProjectId": SECRET_PROJECT,
            "envVars": {"values": {"SURFACE": "connect"}}
        }),
    )
    .await;
    assert_patch_state(&value, "preset-connect-value", SECRET_PROJECT, "connect");
    let absent = update(
        harness,
        json!({"orgId": PRIMARY_ORG, "presetId": id, "name": "Connect absent patch"}),
    )
    .await;
    assert_patch_state(&absent, "preset-connect-value", SECRET_PROJECT, "connect");
    let empty = update(
        harness,
        json!({
            "orgId": PRIMARY_ORG,
            "presetId": id,
            "slug": "",
            "secretProjectId": "",
            "envVars": {"values": {}}
        }),
    )
    .await;
    assert_patch_state(&empty, "", "", "");

    let rest_value = harness
        .rest(
            Method::PATCH,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/presets/{id}"),
            Some(json!({
                "slug": "preset-rest-value",
                "secret_project": "preset-contract-secrets",
                "env_vars": {"SURFACE": "rest"}
            })),
            Auth::Admin,
        )
        .await;
    rest_value.assert_status(StatusCode::OK, "REST preset value patch");
    assert_patch_state(
        &get(harness, PRIMARY_ORG, &id).await,
        "preset-rest-value",
        SECRET_PROJECT,
        "rest",
    );
    harness
        .rest(
            Method::PATCH,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/presets/{id}"),
            Some(json!({"name": "REST absent patch"})),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "REST preset absent patch");
    assert_patch_state(
        &get(harness, PRIMARY_ORG, &id).await,
        "preset-rest-value",
        SECRET_PROJECT,
        "rest",
    );
    harness
        .rest(
            Method::PATCH,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/presets/{id}"),
            Some(json!({"slug": "", "secret_project": "", "env_vars": {}})),
            Auth::Admin,
        )
        .await
        .assert_status(StatusCode::OK, "REST preset empty patch");
    assert_patch_state(&get(harness, PRIMARY_ORG, &id).await, "", "", "");
    delete(harness, &id).await;
}

async fn assert_in_use_error(harness: &Harness) {
    let connect = call(
        harness,
        "DeletePreset",
        json!({"orgId": PRIMARY_ORG, "presetId": IN_USE}),
        Auth::Admin,
    )
    .await;
    let body = assert_connect_error(&connect, StatusCode::BAD_REQUEST, "failed_precondition", "");
    assert_error_info(&connect, &body, "PRESET_IN_USE");
    let rest = harness
        .rest(
            Method::DELETE,
            &format!("/api/v1/organizations/{PRIMARY_ORG}/presets/{IN_USE}"),
            None,
            Auth::Admin,
        )
        .await;
    rest.assert_status(StatusCode::CONFLICT, "REST preset in use");
    assert_eq!(rest.json()["code"], "preset_in_use");
}
