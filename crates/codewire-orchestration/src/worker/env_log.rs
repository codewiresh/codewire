//! Environment log + lifecycle journal emission.

use sqlx::{PgPool, Postgres, Transaction};

use super::activity_authority::ActivityAuthority;

/// Mirrors `envPhaseLabel`.
pub fn env_phase_label(phase: &str) -> &str {
    match phase {
        "ensure_namespace" => "Creating namespace",
        "create_claim" => "Creating sandbox",
        "wait_for_ready" => "Waiting for sandbox ready",
        "resume_workspace" => "Resuming suspended sandbox",
        "store_backend" => "Storing backend info",
        "workspace_bind" => "Binding workspace",
        "access_ready" => "SSH access ready",
        "pod_scheduled" => "Workspace pod scheduled",
        "pod_initialized" => "Workspace pod initialized",
        "pod_running" => "Workspace containers started",
        "pod_containers_ready" => "Workspace containers ready",
        "mark_running" => "Marking running",
        "publish_setup" => "Starting setup",
        "health_check" => "Checking sidecar readiness",
        "configure_environment" => "Configuring environment",
        "git_clone" => "Cloning repositories",
        "install" => "Running install command",
        "startup_script" => "Running startup script",
        "agent_install" => "Installing agent tools",
        "register_ports" => "Registering ports",
        "file_ready" => "First successful file write",
        "complete" => "Setup complete",
        other => other,
    }
}

/// Mirrors `environmentlifecycle.ShouldRecordWorkerCheckpoint`. Fine-grained
/// timing rows (the `pod_*` start marks) are deliberately not checkpoints:
/// they describe how long a start took, not a lifecycle transition.
pub fn should_record_worker_checkpoint(phase: &str, status: &str) -> bool {
    // `progress` rows are transient telemetry inside a running stage
    // (A5a contract v1), never a lifecycle transition.
    if status == "warning" || status == "progress" {
        return false;
    }
    matches!(
        phase,
        "reconcile_enqueue"
            | "ensure_namespace"
            | "create_claim"
            | "wait_for_ready"
            | "store_backend"
            | "workspace_bind"
            | "access_ready"
            | "mark_running"
            | "publish_setup"
            | "health_check"
            | "configure_environment"
            | "git_clone"
            | "install"
            | "startup_script"
            | "agent_install"
            | "register_ports"
            | "complete"
    )
}

/// A row scoped to one repository (`repo_index`) nests under its phase-level
/// row and is not a checkpoint of its own: the phase-level row is.
fn records_worker_checkpoint(
    phase: &str,
    status: &str,
    metadata: Option<&serde_json::Value>,
) -> bool {
    should_record_worker_checkpoint(phase, status)
        && metadata.is_none_or(|metadata| metadata.get("repo_index").is_none())
}

/// Mirrors `environmentlifecycle.JournalEntry`.
#[derive(Debug, Clone, Default)]
pub struct JournalEntry {
    pub kind: String,
    pub actor: String,
    pub phase: String,
    pub status: String,
    pub from_state: String,
    pub to_state: String,
    pub checkpoint: String,
    pub reason: String,
    pub metadata: Option<serde_json::Value>,
}

fn null_if_empty(v: &str) -> Option<&str> {
    if v.is_empty() { None } else { Some(v) }
}

/// Mirrors `environmentlifecycle.InsertJournal`.
pub async fn insert_journal(
    pool: &PgPool,
    env_id: &str,
    entry: &JournalEntry,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT INTO environment_lifecycle_journal
           (id, environment_id, kind, actor, phase, status, from_state, to_state, checkpoint, reason, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(env_id)
    .bind(&entry.kind)
    .bind(&entry.actor)
    .bind(&entry.phase)
    .bind(&entry.status)
    .bind(null_if_empty(&entry.from_state))
    .bind(null_if_empty(&entry.to_state))
    .bind(null_if_empty(&entry.checkpoint))
    .bind(null_if_empty(&entry.reason))
    .bind(&entry.metadata)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mirrors `emitEnvironmentLog`: insert a log row, mirror worker
/// checkpoints into the lifecycle journal, then notify SSE listeners.
/// Failures are warn-only, never fatal to the job — same as Go.
pub async fn emit_environment_log(
    pool: &PgPool,
    env_id: &str,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let message = if message.is_empty() {
        env_phase_label(phase)
    } else {
        message
    };

    let res = sqlx::query(
        r#"INSERT INTO environment_logs (id, environment_id, phase, status, message, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(&id)
    .bind(env_id)
    .bind(phase)
    .bind(status)
    .bind(message)
    .bind(&metadata)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(environment_id = env_id, phase, error = %e, "worker: failed to emit environment log");
        return;
    }

    if records_worker_checkpoint(phase, status, metadata.as_ref()) {
        let mut entry = JournalEntry {
            kind: "checkpoint".into(),
            actor: "worker".into(),
            phase: phase.into(),
            status: status.into(),
            checkpoint: phase.into(),
            reason: message.into(),
            metadata: metadata.clone(),
            ..Default::default()
        };
        if phase == "reconcile_enqueue" {
            entry.kind = "reconcile_request".into();
            entry.actor = "reconciler".into();
        }
        if let Err(e) = insert_journal(pool, env_id, &entry).await {
            tracing::warn!(environment_id = env_id, phase, error = %e, "worker: failed to emit lifecycle journal");
        }
    }

    let _ = sqlx::query("SELECT pg_notify('environment_logs', $1)")
        .bind(env_id)
        .execute(pool)
        .await;
}

/// Activity-only log emission. The environment row is locked and its
/// captured desired-state authority is checked before the log, mirrored
/// journal checkpoint, and notification are committed together. Stale work
/// therefore cannot leave a durable audit trail after a replacement command.
pub async fn emit_authoritative_environment_log(
    authority: &ActivityAuthority,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    emit_authoritative_environment_log_inner(authority, None, phase, status, message, metadata)
        .await
}

/// State-aware variant used where a same-intent replacement may already have
/// advanced beyond the phase whose result is being logged.
pub async fn emit_authoritative_environment_log_for_states(
    authority: &ActivityAuthority,
    states: &[&str],
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    emit_authoritative_environment_log_inner(
        authority,
        Some(states),
        phase,
        status,
        message,
        metadata,
    )
    .await
}

async fn emit_authoritative_environment_log_inner(
    authority: &ActivityAuthority,
    states: Option<&[&str]>,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    let env_id = authority.environment_id();
    let mut tx = authority.pool().begin().await?;
    if let Some(states) = states {
        authority
            .lock_transaction_for_states(&mut tx, states)
            .await?;
    } else {
        authority.lock_transaction(&mut tx).await?;
    }

    emit_environment_log_in_transaction(&mut tx, env_id, phase, status, message, metadata).await?;
    tx.commit().await?;
    Ok(())
}

/// Insert a log, matching lifecycle checkpoint, and notification inside a
/// transaction whose caller already holds the required authority/lease locks.
pub(crate) async fn emit_environment_log_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    env_id: &str,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let message = if message.is_empty() {
        env_phase_label(phase)
    } else {
        message
    };
    sqlx::query(
        r#"INSERT INTO environment_logs (id, environment_id, phase, status, message, metadata)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(&id)
    .bind(env_id)
    .bind(phase)
    .bind(status)
    .bind(message)
    .bind(&metadata)
    .execute(&mut **tx)
    .await?;

    if records_worker_checkpoint(phase, status, metadata.as_ref()) {
        let mut kind = "checkpoint";
        let mut actor = "worker";
        if phase == "reconcile_enqueue" {
            kind = "reconcile_request";
            actor = "reconciler";
        }
        sqlx::query(
            r#"INSERT INTO environment_lifecycle_journal
               (id, environment_id, kind, actor, phase, status, from_state, to_state, checkpoint, reason, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7, $8, $9)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(env_id)
        .bind(kind)
        .bind(actor)
        .bind(phase)
        .bind(status)
        .bind(phase)
        .bind(message)
        .bind(&metadata)
        .execute(&mut **tx)
        .await?;
    }

    sqlx::query("SELECT pg_notify('environment_logs', $1)")
        .bind(env_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_predicate_mirrors_go() {
        assert!(should_record_worker_checkpoint("health_check", "completed"));
        assert!(should_record_worker_checkpoint("complete", "completed"));
        assert!(should_record_worker_checkpoint(
            "reconcile_enqueue",
            "started"
        ));
        assert!(!should_record_worker_checkpoint("health_check", "warning"));
        assert!(!should_record_worker_checkpoint("git_clone", "progress"));
        assert!(records_worker_checkpoint("git_clone", "started", None));
        assert!(records_worker_checkpoint(
            "git_clone",
            "completed",
            Some(&serde_json::json!({"duration_ms": 5}))
        ));
        assert!(!records_worker_checkpoint(
            "git_clone",
            "completed",
            Some(&serde_json::json!({"repo_index": 1, "repo_count": 2}))
        ));
        assert!(!should_record_worker_checkpoint("ssh_public_key", "info"));
        assert!(!should_record_worker_checkpoint(
            "unknown_phase",
            "completed"
        ));
    }

    #[test]
    fn every_measured_start_stage_has_a_label_and_pod_marks_are_not_checkpoints() {
        for stage in crate::start_metrics::StartStage::ALL {
            let phase = stage.as_str();
            assert_ne!(env_phase_label(phase), phase, "{phase} needs a label");
        }
        for phase in [
            "pod_scheduled",
            "pod_initialized",
            "pod_running",
            "pod_containers_ready",
        ] {
            assert!(!should_record_worker_checkpoint(phase, "completed"));
        }
        assert!(should_record_worker_checkpoint("access_ready", "started"));
        assert!(should_record_worker_checkpoint("access_ready", "completed"));
    }

    #[test]
    fn phase_labels_mirror_go() {
        assert_eq!(
            env_phase_label("health_check"),
            "Checking sidecar readiness"
        );
        assert_eq!(env_phase_label("complete"), "Setup complete");
        assert_eq!(env_phase_label("unknown_phase"), "unknown_phase");
    }
}
