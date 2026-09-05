//! Environment/backend row loads shared by the environment job handlers.
//! Runtime intent is persisted and consumed only as a validated `ProjectSpec`.

use codewire_project::ProjectSpec;
use sqlx::PgPool;
use sqlx::Row;

/// Mirrors `worker.environmentRow`.
#[derive(Debug, Clone)]
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
}

fn decode_project_spec(value: serde_json::Value) -> anyhow::Result<ProjectSpec> {
    let spec: ProjectSpec = serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("decode environment project_spec: {error}"))?;
    spec.validate()
        .map_err(|error| anyhow::anyhow!("invalid environment project_spec: {error}"))?;
    Ok(spec)
}

pub async fn load_environment(pool: &PgPool, env_id: &str) -> anyhow::Result<EnvironmentRow> {
    let row = sqlx::query(
        r#"SELECT id, org_id, preset_id, type, state, desired_state,
                  external_cleanup_completed_at,
                  cpu_millicores, memory_mb, disk_gb, isolation_tier, ttl_seconds,
                  project_spec
           FROM environments WHERE id = $1"#,
    )
    .bind(env_id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("load environment {env_id}: {e}"))?;

    let project_spec = decode_project_spec(row.try_get("project_spec")?)?;

    Ok(EnvironmentRow {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
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
    })
}

/// Mirrors `worker.BackendRow`.
#[derive(Debug, Clone, Default)]
pub struct BackendRow {
    pub namespace: String,
    pub claim_name: String,
    pub pod_ip: String,
    pub pod_name: String,
    pub setup_phase: i32,
    pub setup_complete: bool,
    pub setup_error: String,
}

pub async fn load_backend_row(pool: &PgPool, env_id: &str) -> anyhow::Result<BackendRow> {
    let row = sqlx::query(
        r#"SELECT namespace, COALESCE(sandbox_claim_name, '') AS claim_name,
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
            "access": {"profile": "user/work"}
        }))
        .unwrap();
        assert_eq!(project.schema_version, 1);
        assert_eq!(project.repositories[0].revision, "deadbeef");
        assert_eq!(
            project.access.expect("access binding").profile.to_string(),
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
