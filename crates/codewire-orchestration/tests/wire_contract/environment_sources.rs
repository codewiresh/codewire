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
    assert_ssh_profile_admission_precedes_writes(harness).await;
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

async fn assert_ssh_profile_admission_precedes_writes(harness: &Harness) {
    // This URL is supplied only by the selected synthetic service harness,
    // never inferred from an ambient developer database or browser identity.
    let database = std::env::var("TEST_DATABASE_URL")
        .expect("SSH admission contract requires the isolated service-harness database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database)
        .await
        .unwrap();
    let preset = format!("ssh-admission-{}", uuid::Uuid::new_v4());
    let pin = "example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";
    let default_spec = json!({
        "schema_version": 1,
        "working_directory": "/workspace/app",
        "repositories": [{"source": "git@example.test:private-admission/app.git",
            "destination": "/workspace/app", "known_hosts": [pin]}],
        "credentials": {"profile": "platform:user/wire-contract-empty"},
    });
    sqlx::query("INSERT INTO environment_presets(id,org_id,name,project_spec) VALUES($1,$2,$1,$3)")
        .bind(&preset)
        .bind(PRIMARY_ORG)
        .bind(&default_spec)
        .execute(&pool)
        .await
        .unwrap();
    async fn counts(pool: &sqlx::PgPool) -> (i64, i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT count(*) FROM environment_presets WHERE org_id=$1), \
            (SELECT count(*) FROM environments WHERE org_id=$1), \
            (SELECT count(*) FROM sandbox_template_config WHERE preset_id IN \
                (SELECT id FROM environment_presets WHERE org_id=$1))",
        )
        .bind(PRIMARY_ORG)
        .fetch_one(pool)
        .await
        .unwrap()
    }
    let before = counts(&pool).await;
    for source in [
        "git@example.test:private-admission/app.git",
        "ssh://git@example.test/private-admission/app.git",
    ] {
        let response = harness.connect_json(ENVIRONMENT_SERVICE, "CreateEnvironment", json!({
            "orgId": PRIMARY_ORG,
            "projectSpec": {"schemaVersion": 1, "image": format!("example.test/ssh-admission-{preset}"),
                "workingDirectory": "/workspace/app",
                "repositories": [{"source": source, "destination": "/workspace/app", "knownHosts": [pin]}]},
        }), Auth::Admin).await;
        let error = assert_connect_error(
            &response,
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "SSH repository checkout requires an explicitly selected credential profile containing an SSH identity",
        );
        assert!(!error.to_string().contains("private-admission"));
        assert_eq!(
            counts(&pool).await,
            before,
            "rejected direct SSH wrote a preset/environment/preset image configuration"
        );
    }
    // A selected profile without an SSH key is refused inside the create
    // transaction, so the environment row it inserted is rolled back.
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "CreateEnvironment",
            json!({
                "orgId": PRIMARY_ORG, "presetId": "preset_contract_in_use",
                "projectSpec": {"schemaVersion": 1, "workingDirectory": "/workspace/app",
                    "repositories": [{"source": "git@example.test:private-admission/app.git",
                        "destination": "/workspace/app", "knownHosts": [pin]}],
                    "credentials": {"profile": "platform:user/wire-contract-empty"}},
                "expectedProfileRevision": PROFILE_REVISION,
                "confirmPersonalCredentials": true,
            }),
            Auth::Admin,
        )
        .await;
    let error = assert_connect_error(
        &response,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "SSH repository checkout needs an SSH key in the selected credential profile; \
         add one, or use an https://github.com URL with a GitHub connection",
    );
    assert!(!error.to_string().contains("private-admission"));
    assert_eq!(
        counts(&pool).await,
        before,
        "a profile without an SSH key left a preset/environment/preset image configuration"
    );
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "CreateEnvironment",
            json!({
                "orgId": PRIMARY_ORG, "presetId": preset,
                "projectSpec": {"schemaVersion": 1, "workingDirectory": "/workspace"},
            }),
            Auth::Admin,
        )
        .await;
    assert_connect_error(
        &response,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "SSH repository checkout requires an explicitly selected credential profile containing an SSH identity",
    );
    assert_eq!(
        counts(&pool).await,
        before,
        "rejected inherited SSH wrote a preset/environment/preset image configuration"
    );
    // The saved-repository path may otherwise auto-create an image preset
    // before its final validation. Preview defaults remain validated there,
    // with no provider authority inherited from workload configuration.
    let saved_source = format!("https://example.test/{preset}/app.git");
    let saved_spec = json!({
        "schema_version": 1,
        "image": format!("example.test/saved-{preset}"),
        "working_directory": "/workspace/app",
        "application_ports": [{"port": 2222, "label": "ssh", "access": "creator"}],
    });
    let inserted = sqlx::query(
        "INSERT INTO repo_configs(id,org_id,repo_url,project_spec,created_by) \
        SELECT $1,id,$3,$4,created_by FROM organizations WHERE id=$2",
    )
    .bind(&preset)
    .bind(PRIMARY_ORG)
    .bind(&saved_source)
    .bind(&saved_spec)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(inserted.rows_affected(), 1);
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "CreateEnvironment",
            json!({
                "orgId": PRIMARY_ORG,
                "projectSpec": {"schemaVersion": 1, "workingDirectory": "/workspace/app",
                    "repositories": [{"source": saved_source, "destination": "/workspace/app"}]},
            }),
            Auth::Admin,
        )
        .await;
    assert_connect_error(
        &response,
        StatusCode::BAD_REQUEST,
        "invalid_argument",
        "port is reserved by the agent",
    );
    assert_eq!(
        counts(&pool).await,
        before,
        "invalid saved defaults auto-created a preset before runtime validation"
    );
    sqlx::query("DELETE FROM repo_configs WHERE id=$1 AND org_id=$2")
        .bind(&preset)
        .bind(PRIMARY_ORG)
        .execute(&pool)
        .await
        .unwrap();

    let response = harness.connect_json(ENVIRONMENT_SERVICE, "CreateEnvironment", json!({
        "orgId": PRIMARY_ORG, "presetId": "preset_contract_in_use",
        "projectSpec": {"schemaVersion": 1, "workingDirectory": "/workspace/app",
            "repositories": [{"source": "https://example.test/org/app.git", "destination": "/workspace/app"}]},
    }), Auth::Admin).await;
    response.assert_status(StatusCode::OK, "HTTPS without a profile remains admitted");
    let environment = response.json()["environment"].clone();
    assert!(
        environment["sourceSelection"]["credentials"].is_null(),
        "ordinary HTTPS silently selected a credential profile"
    );
    let environment_id = environment["id"]
        .as_str()
        .expect("HTTPS creation returned an environment");
    assert!(!environment_id.is_empty());
    sqlx::query("DELETE FROM environments WHERE id=$1 AND org_id=$2")
        .bind(environment_id)
        .bind(PRIMARY_ORG)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(counts(&pool).await, before);
    sqlx::query("DELETE FROM environment_presets WHERE id=$1 AND org_id=$2")
        .bind(&preset)
        .bind(PRIMARY_ORG)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
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
