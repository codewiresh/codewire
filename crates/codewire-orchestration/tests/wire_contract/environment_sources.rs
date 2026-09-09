use reqwest::StatusCode;
use serde_json::{Value, json};

use super::{Auth, Harness, PRIMARY_ORG, assert_connect_error};

const ENVIRONMENT_SERVICE: &str = "codewire.v1.EnvironmentService";
const SOURCE_ENVIRONMENT: &str = "env_environment_contract_sources";
const PROJECT_ID: &str = "11111111-1111-4111-8111-111111111115";
const PROFILE_ID: &str = "22222222-2222-4222-8222-222222222226";
const GENERATION: &str = "7";
const PROFILE_REVISION: &str = "1";

fn empty_selection() -> Value {
    json!({})
}

fn named_selection() -> Value {
    json!({
        "secrets": {
            "project": "platform:wire-contract-project",
            "organization": true,
            "user": "PROJECT_STORAGE_PLACEMENT_PLATFORM",
        },
        "credentials": {"profile": "platform:user/wire-contract-empty"},
        "profileRevision": PROFILE_REVISION,
    })
}

fn canonical_selection() -> Value {
    json!({
        "secrets": {
            "project": format!("platform:id:{PROJECT_ID}"),
            "organization": true,
            "user": "PROJECT_STORAGE_PLACEMENT_PLATFORM",
        },
        "credentials": {"profile": format!("platform:id:{PROFILE_ID}")},
        "profileRevision": PROFILE_REVISION,
    })
}

fn update_request(expected_generation: &str, expected: Value, replacement: Value) -> Value {
    json!({
        "orgId": PRIMARY_ORG,
        "environmentId": SOURCE_ENVIRONMENT,
        "expectedOperationGeneration": expected_generation,
        "expected": expected,
        "replacement": replacement,
        "allowRestart": false,
        "confirmPersonalCredentials": true,
        "confirmPersonalSecrets": true,
    })
}

async fn get_environment(harness: &Harness) -> Value {
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "GetEnvironment",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": SOURCE_ENVIRONMENT,
            }),
            Auth::Admin,
        )
        .await;
    response.assert_status(StatusCode::OK, "GetEnvironment source contract");
    response.json()["environment"].clone()
}

fn assert_stopped_selection(environment: &Value, expected: &Value) {
    assert_eq!(environment["id"], SOURCE_ENVIRONMENT);
    assert_eq!(environment["state"], "ENVIRONMENT_STATE_STOPPED");
    assert_eq!(environment["desiredState"], "DESIRED_STATE_STOPPED");
    assert_eq!(environment["operationGeneration"], GENERATION);
    assert_eq!(&environment["sourceSelection"], expected);
}

pub(super) async fn run(harness: &Harness) {
    assert_create_resolves_named_sources(harness).await;

    let empty = empty_selection();
    assert_stopped_selection(&get_environment(harness).await, &empty);

    let denied = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "UpdateEnvironmentSources",
            update_request(GENERATION, empty.clone(), named_selection()),
            Auth::User,
        )
        .await;
    assert_connect_error(&denied, StatusCode::NOT_FOUND, "not_found", "");
    assert_stopped_selection(&get_environment(harness).await, &empty);

    let missing_consent = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "UpdateEnvironmentSources",
            json!({
                "orgId": PRIMARY_ORG,
                "environmentId": SOURCE_ENVIRONMENT,
                "expectedOperationGeneration": GENERATION,
                "expected": empty,
                "replacement": named_selection(),
                "allowRestart": false,
                "confirmPersonalCredentials": false,
                "confirmPersonalSecrets": false,
            }),
            Auth::Admin,
        )
        .await;
    assert_connect_error(
        &missing_consent,
        StatusCode::BAD_REQUEST,
        "failed_precondition",
        "",
    );
    let empty = empty_selection();
    assert_stopped_selection(&get_environment(harness).await, &empty);

    let updated = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "UpdateEnvironmentSources",
            update_request(GENERATION, empty.clone(), named_selection()),
            Auth::Admin,
        )
        .await;
    updated.assert_status(StatusCode::OK, "UpdateEnvironmentSources named selection");
    let updated = updated.json();
    let canonical = canonical_selection();
    assert_eq!(updated["environmentId"], SOURCE_ENVIRONMENT);
    assert_eq!(updated["operationGeneration"], GENERATION);
    assert_eq!(
        updated["outcome"],
        "ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED"
    );
    assert_eq!(updated["selection"], canonical);
    assert_stopped_selection(&get_environment(harness).await, &canonical);

    for stale in [
        update_request(GENERATION, empty, named_selection()),
        update_request("8", canonical.clone(), empty_selection()),
    ] {
        let response = harness
            .connect_json(
                ENVIRONMENT_SERVICE,
                "UpdateEnvironmentSources",
                stale,
                Auth::Admin,
            )
            .await;
        // The shared AppError::Conflict renderer preserves HTTP 409 as AlreadyExists.
        assert_connect_error(&response, StatusCode::CONFLICT, "already_exists", "");
        assert_stopped_selection(&get_environment(harness).await, &canonical);
    }

    let cleared = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "UpdateEnvironmentSources",
            update_request(GENERATION, canonical, empty_selection()),
            Auth::Admin,
        )
        .await;
    cleared.assert_status(StatusCode::OK, "UpdateEnvironmentSources clear");
    let cleared = cleared.json();
    assert_eq!(cleared["environmentId"], SOURCE_ENVIRONMENT);
    assert_eq!(cleared["operationGeneration"], GENERATION);
    assert_eq!(
        cleared["outcome"],
        "ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED"
    );
    assert_eq!(cleared["selection"], empty_selection());
    assert_stopped_selection(&get_environment(harness).await, &empty_selection());
}

async fn assert_create_resolves_named_sources(harness: &Harness) {
    let named = named_selection();
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "CreateEnvironment",
            json!({
                "orgId": PRIMARY_ORG,
                "presetId": "preset_contract_in_use",
                "name": "environment-contract-created-sources",
                "projectSpec": {
                    "schemaVersion": 1,
                    "workingDirectory": "/workspace",
                    "secrets": named["secrets"].clone(),
                    "credentials": named["credentials"].clone(),
                },
                "expectedProfileRevision": PROFILE_REVISION,
                "confirmPersonalCredentials": true,
                "confirmPersonalSecrets": true,
            }),
            Auth::Admin,
        )
        .await;
    response.assert_status(StatusCode::OK, "CreateEnvironment named sources");
    let body = response.json();
    let environment = &body["environment"];
    assert!(!environment["id"].as_str().unwrap_or_default().is_empty());
    assert_eq!(environment["orgId"], PRIMARY_ORG);
    assert_eq!(environment["name"], "environment-contract-created-sources");
    assert_eq!(environment["state"], "ENVIRONMENT_STATE_PENDING");
    assert_eq!(environment["desiredState"], "DESIRED_STATE_STARTED");
    assert!(
        environment["operationGeneration"].is_null() || environment["operationGeneration"] == "0",
        "pending create must not claim a completed operation generation: {environment:?}"
    );
    assert_eq!(environment["sourceSelection"], canonical_selection());
}
