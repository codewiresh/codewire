//! Environment/backend row loads shared by the environment job handlers. The
//! stable `setupConfig` JSON field names preserve stored `setup_config` data.

use std::collections::BTreeMap;

use serde::Deserialize;
use sqlx::PgPool;
use sqlx::Row;

/// Mirrors `worker.appPort`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppPort {
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub access: String,
}

/// Mirrors `worker.repoEntry`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoEntry {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub mount_path: String,
    #[serde(default)]
    pub revision: String,
}

/// Mirrors `worker.setupAgent`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SetupAgent {
    #[serde(default, rename = "type")]
    pub agent_type: String,
}

/// Mirrors `worker.setupConfig`. Maps are BTreeMaps because every
/// consumer of the env vars (scripts, exec env) sorts keys, exactly
/// like the Go builders do before emitting.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SetupConfig {
    #[serde(default)]
    pub repo_url: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub repos: Vec<RepoEntry>,
    #[serde(default)]
    pub install_command: String,
    #[serde(default)]
    pub startup_script: String,
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default)]
    pub agents: Vec<SetupAgent>,
    #[serde(default)]
    pub install_agents: Option<bool>,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub agent_env: BTreeMap<String, String>,
    #[serde(default)]
    pub app_ports: Vec<AppPort>,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
    #[serde(default)]
    pub project_spec: Option<codewire_project::ProjectSpec>,
}

impl SetupConfig {
    /// Mirrors `normalizedRepos`.
    pub fn normalized_repos(&self) -> Vec<RepoEntry> {
        if !self.repos.is_empty() {
            return self.repos.clone();
        }
        if !self.repo_url.is_empty() {
            return vec![RepoEntry {
                url: self.repo_url.clone(),
                branch: self.branch.clone(),
                mount_path: String::new(),
                revision: String::new(),
            }];
        }
        Vec::new()
    }

    /// Mirrors `configuredAgents`.
    pub fn configured_agents(&self) -> Vec<SetupAgent> {
        if !self.agents.is_empty() {
            return self.agents.clone();
        }
        if !self.agent.is_empty() {
            return vec![SetupAgent {
                agent_type: self.agent.clone(),
            }];
        }
        Vec::new()
    }

    /// Mirrors `hasConfiguredAgent`.
    pub fn has_configured_agent(&self, agent_type: &str) -> bool {
        self.configured_agents()
            .iter()
            .any(|a| a.agent_type == agent_type)
    }
}

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
    pub auth_token: Option<String>,
    pub ttl_seconds: Option<i32>,
    pub setup_config: Option<SetupConfig>,
    pub secret_project_id: Option<String>,
}

pub async fn load_environment(pool: &PgPool, env_id: &str) -> anyhow::Result<EnvironmentRow> {
    let row = sqlx::query(
        r#"SELECT id, org_id, preset_id, type, state, desired_state,
                  external_cleanup_completed_at,
                  cpu_millicores, memory_mb, disk_gb, isolation_tier, auth_token, ttl_seconds,
                  setup_config, secret_project_id
           FROM environments WHERE id = $1"#,
    )
    .bind(env_id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("load environment {env_id}: {e}"))?;

    let setup_json: Option<serde_json::Value> = row.try_get("setup_config")?;
    let setup_config = match setup_json {
        Some(v) if !v.is_null() => {
            let config: SetupConfig = serde_json::from_value(v)
                .map_err(|e| anyhow::anyhow!("unmarshal setup_config: {e}"))?;
            if let Some(project) = &config.project_spec {
                project
                    .validate()
                    .map_err(|e| anyhow::anyhow!("invalid setup_config project_spec: {e}"))?;
            }
            Some(config)
        }
        _ => None,
    };

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
        auth_token: row.try_get("auth_token")?,
        ttl_seconds: row.try_get("ttl_seconds")?,
        setup_config,
        secret_project_id: row.try_get("secret_project_id")?,
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
    fn setup_config_parses_go_field_names() {
        let json = r#"{
            "repo_url": "https://github.com/org/app.git",
            "branch": "develop",
            "install_command": "npm ci",
            "env_vars": {"B": "2", "A": "1"},
            "agents": [{"type": "claude-code"}],
            "install_agents": true,
            "app_ports": [{"port": 3000, "label": "web", "access": "public"}],
            "include_org_secrets": false
        }"#;
        let sc: SetupConfig = serde_json::from_str(json).unwrap();
        assert_eq!(sc.repo_url, "https://github.com/org/app.git");
        assert_eq!(sc.install_command, "npm ci");
        assert_eq!(sc.env_vars.get("A").map(String::as_str), Some("1"));
        assert_eq!(sc.agents[0].agent_type, "claude-code");
        assert_eq!(sc.install_agents, Some(true));
        assert_eq!(sc.app_ports[0].port, 3000);
        assert_eq!(sc.include_org_secrets, Some(false));
        assert_eq!(sc.include_user_secrets, None);
        assert!(sc.project_spec.is_none());
    }

    #[test]
    fn setup_config_reads_versioned_project_specs_without_reinterpreting_old_rows() {
        let json = r#"{
            "repo_url": "https://github.com/org/app.git",
            "project_spec": {
                "schema_version": 1,
                "working_directory": "/workspace/app",
                "repositories": [{
                    "source": "https://github.com/org/app.git",
                    "revision": "deadbeef",
                    "destination": "/workspace/app"
                }],
                "credentials": {
                    "work": {"provider": "openai", "account": "acct-work"}
                },
                "workspace_mode": "clone"
            }
        }"#;
        let setup: SetupConfig = serde_json::from_str(json).unwrap();
        let project = setup.project_spec.expect("project spec");
        project.validate().unwrap();
        assert_eq!(project.schema_version, 1);
        assert_eq!(project.repositories[0].revision, "deadbeef");
        assert_eq!(project.credentials["work"].account, "acct-work");
    }

    #[test]
    fn normalized_repos_falls_back_to_repo_url() {
        let sc: SetupConfig =
            serde_json::from_str(r#"{"repo_url": "https://x/y/z.git", "branch": "b"}"#).unwrap();
        let repos = sc.normalized_repos();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].url, "https://x/y/z.git");
        assert_eq!(repos[0].branch, "b");

        let sc: SetupConfig = serde_json::from_str(
            r#"{"repo_url": "https://x/y/z.git", "repos": [{"url": "https://a/b/c"}]}"#,
        )
        .unwrap();
        assert_eq!(sc.normalized_repos().len(), 1);
        assert_eq!(sc.normalized_repos()[0].url, "https://a/b/c");
    }

    #[test]
    fn configured_agents_falls_back_to_single_agent() {
        let sc: SetupConfig = serde_json::from_str(r#"{"agent": "codex"}"#).unwrap();
        assert_eq!(sc.configured_agents()[0].agent_type, "codex");
        assert!(sc.has_configured_agent("codex"));
        assert!(!sc.has_configured_agent("aider"));
    }
}
