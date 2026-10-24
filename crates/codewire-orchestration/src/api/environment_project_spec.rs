//! An environment's saved declarative configuration, for `cw export`
//! (GetEnvironmentProjectSpec). The caller is authorized exactly as for
//! GetEnvironment. Declared environment values are withheld: only their names
//! leave, as GetEnvironment's source metadata never reads them either. A
//! stored spec that does not decode or validate is unavailable, never an
//! empty configuration a client could write out as if it were the real one.

use codewire_project::ProjectSpec;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

use super::ApiState;
use super::environments::get_environment_core;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedProjectSpec {
    /// The stored spec with `environment` emptied.
    pub spec: ProjectSpec,
    /// Sorted names of the declared environment values withheld from `spec`.
    pub withheld_environment_keys: Vec<String>,
}

pub async fn get_environment_project_spec_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<SavedProjectSpec> {
    let environment = get_environment_core(state, user, org_id, environment_id).await?;
    let stored: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT project_spec FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(&environment.id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        tracing::warn!(environment_id = %environment.id, %error, "read saved project spec failed");
        unavailable()
    })?;
    let stored = stored.ok_or_else(|| {
        super::environments::coded(
            axum::http::StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })?;
    withhold_environment_values(stored)
}

fn unavailable() -> AppError {
    AppError::ServiceUnavailable("the environment's saved configuration is unavailable".into())
}

/// The stored spec, validated, with its environment values removed.
fn withhold_environment_values(stored: serde_json::Value) -> AppResult<SavedProjectSpec> {
    let mut spec: ProjectSpec = serde_json::from_value(stored).map_err(|_| {
        tracing::warn!("saved project spec does not decode");
        unavailable()
    })?;
    spec.validate().map_err(|_| {
        tracing::warn!("saved project spec is not canonical");
        unavailable()
    })?;
    let withheld_environment_keys = std::mem::take(&mut spec.environment).into_keys().collect();
    Ok(SavedProjectSpec {
        spec,
        withheld_environment_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "synthetic-canary-never-returned";

    #[test]
    fn environment_values_are_withheld_and_only_their_names_returned() {
        let saved = withhold_environment_values(serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace/app",
            "repositories": [{
                "source": "https://example.test/org/app.git",
                "branch": "main",
                "destination": "/workspace/app"
            }],
            "install_command": "npm ci",
            "environment": {"ZETA": CANARY, "ALPHA": CANARY},
            "secrets": {"project": "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd"},
            "credentials": {"profile": "platform:id:7c0e2a4b-3f1d-4e5a-9b8c-0d1e2f3a4b5c"}
        }))
        .unwrap();
        assert_eq!(saved.withheld_environment_keys, ["ALPHA", "ZETA"]);
        assert!(saved.spec.environment.is_empty());
        assert_eq!(saved.spec.install_command, "npm ci");
        assert_eq!(saved.spec.repositories.len(), 1);
        assert!(saved.spec.credentials.is_some());
        let proto = codewire_project_proto::to_proto(saved.spec);
        assert!(!format!("{proto:?}").contains(CANARY));
    }

    #[test]
    fn a_spec_without_values_withholds_nothing() {
        let saved = withhold_environment_values(serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace"
        }))
        .unwrap();
        assert!(saved.withheld_environment_keys.is_empty());
        assert_eq!(saved.spec, ProjectSpec::default());
    }

    #[test]
    fn an_undecodable_or_invalid_stored_spec_is_unavailable_never_empty() {
        for stored in [
            serde_json::json!({}),
            serde_json::json!(null),
            serde_json::json!({"schema_version": 1, "working_directory": "/workspace", "unknown": 1}),
            serde_json::json!({"schema_version": 2, "working_directory": "/workspace"}),
            serde_json::json!({"schema_version": 1, "working_directory": "/etc"}),
        ] {
            assert!(
                matches!(
                    withhold_environment_values(stored.clone()),
                    Err(AppError::ServiceUnavailable(_))
                ),
                "{stored}"
            );
        }
    }
}
