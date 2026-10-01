//! Environment/backend row loads shared by the environment job handlers.
//! Runtime intent is persisted and consumed only as a validated `ProjectSpec`.

use codewire_project::{
    PlatformProjectionSelection, PlatformProjectionSelectionError, ProjectSpec,
};
use sqlx::PgPool;
use sqlx::Row;

mod projection;

/// Mirrors `worker.environmentRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvironmentRow {
    pub id: String,
    pub org_id: String,
    pub preset_id: Option<String>,
    pub env_type: String,
    pub state: String,
    pub desired_state: String,
    pub external_cleanup_completed_at: Option<chrono::NaiveDateTime>,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
    pub isolation_tier: String,
    pub ttl_seconds: Option<i32>,
    pub project_spec: ProjectSpec,
    /// Existing lifecycle authority captured with this exact metadata read.
    pub operation_generation: i64,
    /// Rendering must require a valid selection and matching operation authority.
    /// Cleanup may still load a generation-zero row or an already-removed binding.
    pub projection_selection:
        Result<Option<PlatformProjectionSelection>, PlatformProjectionSelectionError>,
    /// Exact pinned profile slots from the same SQL capture, not provider DNS
    /// families or process-wide administrator configuration. GitHub is a
    /// managed client only while its owner's connection is active.
    pub managed_credential_clients:
        Result<codewire_access::ManagedCredentialClients, PlatformProjectionSelectionError>,
}

fn decode_project_spec(value: serde_json::Value) -> anyhow::Result<ProjectSpec> {
    let spec: ProjectSpec = serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("decode environment project_spec: {error}"))?;
    spec.validate()
        .map_err(|error| anyhow::anyhow!("invalid environment project_spec: {error}"))?;
    Ok(spec)
}

pub async fn load_environment(pool: &PgPool, env_id: &str) -> anyhow::Result<EnvironmentRow> {
    let row = sqlx::query(projection::ENVIRONMENT_QUERY)
        .bind(env_id)
        .fetch_one(pool)
        .await
        .map_err(|e| anyhow::anyhow!("load environment {env_id}: {e}"))?;
    decode_environment(row)
}

/// The caller retains the existing environment authority row lock.
pub(super) async fn load_environment_in(
    connection: &mut sqlx::PgConnection,
    env_id: &str,
) -> anyhow::Result<EnvironmentRow> {
    let row = sqlx::query(projection::ENVIRONMENT_QUERY)
        .bind(env_id)
        .fetch_one(connection)
        .await?;
    decode_environment(row)
}

fn decode_environment(row: sqlx::postgres::PgRow) -> anyhow::Result<EnvironmentRow> {
    let project_spec = decode_project_spec(row.try_get("project_spec")?)?;
    let org_id: String = row.try_get("org_id")?;
    let operation_generation: i64 = row.try_get("environment_operation_generation")?;
    let captured = projection::ProjectionCapture {
        creator: row.try_get("created_by")?,
        profile_id: row.try_get("profile_id")?,
        profile_revision: row.try_get("profile_revision")?,
        profile_revision_exists: row.try_get("profile_revision_exists")?,
        profile_slots: row.try_get("profile_slots")?,
        profile_slots_overflow: row.try_get("profile_slots_overflow")?,
        github_connected: row.try_get("github_connected")?,
    };
    let projection_selection = captured.selection(&project_spec, &org_id, operation_generation);
    let managed_credential_clients = projection_selection
        .as_ref()
        .map_err(|error| *error)
        .and_then(|_| captured.managed_credential_clients(&project_spec));

    Ok(EnvironmentRow {
        id: row.try_get("id")?,
        org_id,
        preset_id: row.try_get("preset_id")?,
        env_type: row.try_get("type")?,
        state: row.try_get("state")?,
        desired_state: row.try_get("desired_state")?,
        external_cleanup_completed_at: row.try_get("external_cleanup_completed_at")?,
        cpu_millicores: row.try_get("cpu_millicores")?,
        memory_mb: row.try_get("memory_mb")?,
        disk_gb: row.try_get("disk_gb")?,
        isolation_tier: row.try_get("isolation_tier")?,
        ttl_seconds: row.try_get("ttl_seconds")?,
        project_spec,
        operation_generation,
        projection_selection,
        managed_credential_clients,
    })
}

/// Mirrors `worker.BackendRow`.
#[derive(Debug, Clone, Default)]
pub struct BackendRow {
    pub namespace: String,
    pub claim_name: String,
    pub claim_uid: String,
    pub pod_ip: String,
    pub pod_name: String,
    pub setup_phase: i32,
    pub setup_complete: bool,
    pub setup_error: String,
}

pub async fn load_backend_row(pool: &PgPool, env_id: &str) -> anyhow::Result<BackendRow> {
    let row = sqlx::query(
        r#"SELECT namespace, COALESCE(sandbox_claim_name, '') AS claim_name,
                  COALESCE(sandbox_claim_uid, '') AS claim_uid,
                  COALESCE(pod_ip, '') AS pod_ip, COALESCE(pod_name, '') AS pod_name,
                  COALESCE(setup_phase, 0) AS setup_phase,
                  COALESCE(setup_complete, false) AS setup_complete,
                  COALESCE(setup_error, '') AS setup_error
           FROM sandbox_environment_backend WHERE environment_id = $1"#,
    )
    .bind(env_id)
    .fetch_one(pool)
    .await?;
    Ok(BackendRow {
        namespace: row.try_get("namespace")?,
        claim_name: row.try_get("claim_name")?,
        claim_uid: row.try_get("claim_uid")?,
        pod_ip: row.try_get("pod_ip")?,
        pod_name: row.try_get("pod_name")?,
        setup_phase: row.try_get("setup_phase")?,
        setup_complete: row.try_get("setup_complete")?,
        setup_error: row.try_get("setup_error")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_spec_is_validated_at_the_storage_boundary() {
        let project = decode_project_spec(serde_json::json!({
            "schema_version": 1,
            "working_directory": "/workspace/app",
            "repositories": [{
                "source": "https://github.com/org/app.git",
                "revision": "deadbeef",
                "destination": "/workspace/app"
            }],
            "credentials": {"profile": "user/work"}
        }))
        .unwrap();
        assert_eq!(project.schema_version, 1);
        assert_eq!(project.repositories[0].revision, "deadbeef");
        assert_eq!(
            project
                .credentials
                .expect("credential binding")
                .profile
                .to_string(),
            "user/work"
        );
    }

    #[test]
    fn legacy_setup_wrapper_is_rejected() {
        let error = decode_project_spec(serde_json::json!({
            "project_spec": {
                "schema_version": 1,
                "working_directory": "/workspace"
            }
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
