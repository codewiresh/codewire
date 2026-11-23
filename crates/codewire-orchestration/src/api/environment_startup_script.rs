//! An existing Sandbox's startup script (SetEnvironmentStartupScript, #5949).
//!
//! SPEC.md, "The rules for the startup script after create": this is the one
//! writer of the saved script after create. Only the Sandbox's creator may
//! change it, with no organization owner or admin override, and only while
//! it is running or stopped. It changes `project_spec.startup_script` and
//! nothing else, in one statement, so a concurrent source update keeps its
//! own fields; setup's completion and phase are on the backend row and are
//! never touched, so install doesn't run again. The audit row carries the
//! script's SHA-256 and length, never its text, and nothing here logs it.

use std::borrow::Cow;

use axum::http::StatusCode;
use codewire_project::ProjectSpec;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

use super::ApiState;
use super::environment_sources::{lock_membership_in, lock_source_owners_in};
use super::environments::require_org_member;

/// The audit action of a saved change.
pub const AUDIT_ACTION: &str = "environment.startup_script.set";

/// The two states in which the script may change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptableState {
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupScriptUpdate {
    /// False when the saved script was already this one: nothing was written.
    pub changed: bool,
    pub state: ScriptableState,
}

pub(crate) async fn set_environment_startup_script_core(
    state: &ApiState,
    user: &AuthUser,
    organization: &str,
    environment: &str,
    script: &str,
) -> AppResult<StartupScriptUpdate> {
    require_org_member(&state.pool, user, organization).await?;
    validate_startup_script(script)?;
    run_organization_database_mutation(&state.pool, organization, async {
        let mut tx = state.pool.begin().await.map_err(database_error)?;
        let update =
            set_startup_script_in(&mut tx, user, organization, environment, script).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(update)
    })
    .await
}

/// The script, checked exactly as create checks codewire.yaml's
/// `startup_script`: the same size limit, no NUL, no surrounding whitespace.
pub fn validate_startup_script(script: &str) -> AppResult<()> {
    ProjectSpec {
        startup_script: script.to_owned(),
        ..Default::default()
    }
    .validate()
    .map_err(|error| AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed("/startup_script"),
            message: Cow::Owned(error.to_string()),
        }],
    })
}

#[derive(Debug, sqlx::FromRow)]
struct ScriptRow {
    created_by: Option<String>,
    state: String,
    desired_state: String,
    startup_script: Option<String>,
}

/// Saves `script` (empty removes it) in the caller's transaction, which
/// commits it. It locks the user, the organization, the membership and then
/// the environment: a departure deletes the membership before it clears the
/// scripts ([`codewire_server_core::org::clear_departed_creator_startup_scripts`]),
/// so the two never wait on each other in a cycle, and a script saved just
/// before the departure is cleared by it.
pub async fn set_startup_script_in(
    tx: &mut Transaction<'_, Postgres>,
    user: &AuthUser,
    organization: &str,
    environment: &str,
    script: &str,
) -> AppResult<StartupScriptUpdate> {
    validate_startup_script(script)?;
    lock_source_owners_in(tx, user, organization).await?;
    lock_membership_in(tx, user, organization).await?;
    let row: Option<ScriptRow> = sqlx::query_as(
        "SELECT created_by, state, desired_state, project_spec->>'startup_script' AS startup_script \
         FROM environments WHERE id=$1 AND org_id=$2 AND type='sandbox' \
         AND deletion_requested_at IS NULL AND desired_state<>'destroyed' \
         AND state NOT IN ('destroyed','destroying') FOR UPDATE",
    )
    .bind(environment)
    .bind(organization)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    // A missing Sandbox and another member's answer alike, as
    // `require_environment_access` does.
    let row = row
        .filter(|row| row.created_by.as_deref() == Some(user.user_id.as_str()))
        .ok_or_else(creator_only)?;
    let state = scriptable_state(&row.state, &row.desired_state)?;
    if state == ScriptableState::Running && !setup_finished_in(tx, environment).await? {
        return Err(AppError::Precondition(
            "the Sandbox's setup must finish before its startup script changes; \
             try again when it has, or stop it first"
                .into(),
        ));
    }
    if row.startup_script.as_deref().unwrap_or_default() == script {
        return Ok(StartupScriptUpdate {
            changed: false,
            state,
        });
    }
    sqlx::query(
        "UPDATE environments SET project_spec = CASE WHEN $2 = '' \
         THEN project_spec - 'startup_script' \
         ELSE jsonb_set(project_spec, '{startup_script}', to_jsonb($2::text), true) END \
         WHERE id=$1",
    )
    .bind(environment)
    .bind(script)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    sqlx::query(
        "INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity) \
         VALUES ($1, NOW(), $2, $3, '', '', $4, 'info')",
    )
    .bind(uuid::Uuid::new_v4().simple().to_string())
    .bind(AUDIT_ACTION)
    .bind(&user.user_id)
    .bind(audit_metadata(organization, environment, script))
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(StartupScriptUpdate {
        changed: true,
        state,
    })
}

/// What the audit row records: the script's SHA-256 and length in bytes,
/// never the script. A removal records no hash and a length of zero.
fn audit_metadata(organization: &str, environment: &str, script: &str) -> serde_json::Value {
    let sha256 = (!script.is_empty()).then(|| format!("{:x}", Sha256::digest(script.as_bytes())));
    serde_json::json!({
        "org_id": organization,
        "environment_id": environment,
        "startup_script_sha256": sha256,
        "startup_script_bytes": script.len(),
    })
}

fn scriptable_state(state: &str, desired: &str) -> AppResult<ScriptableState> {
    match (state, desired) {
        ("running", "started") => Ok(ScriptableState::Running),
        ("stopped", "stopped") => Ok(ScriptableState::Stopped),
        _ => Err(AppError::Precondition(
            "the Sandbox must be running or stopped to change its startup script; \
             wait for the current operation to finish"
                .into(),
        )),
    }
}

/// Whether the Sandbox's setup finished and nothing owns it, as a running
/// source update requires: a setup still running, or one retried later,
/// would otherwise run the new script now instead of at the next start.
async fn setup_finished_in(
    tx: &mut Transaction<'_, Postgres>,
    environment: &str,
) -> AppResult<bool> {
    let finished: Option<bool> = sqlx::query_scalar(
        "SELECT setup_complete AND setup_owner_generation IS NULL \
         AND setup_owner_activity_id IS NULL AND setup_owner_attempt IS NULL \
         AND setup_owner_phase IS NULL AND setup_owner_status IS NULL \
         AND setup_owner_pod_uid IS NULL FROM sandbox_environment_backend \
         WHERE environment_id=$1 FOR SHARE",
    )
    .bind(environment)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(finished == Some(true))
}

fn creator_only() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "access_denied",
        detail: "only the Sandbox's creator may change its startup script".into(),
    }
}

fn database_error(_: sqlx::Error) -> AppError {
    AppError::ServiceUnavailable("the environment's saved configuration is unavailable".into())
}

#[cfg(test)]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_is_checked_as_create_checks_it() {
        validate_startup_script("").unwrap();
        validate_startup_script("echo started > /workspace/started\nnpm run dev").unwrap();
        validate_startup_script(&"x".repeat(64 * 1024)).unwrap();
        for refused in [
            " echo leading".to_owned(),
            "echo trailing\n".to_owned(),
            "echo \0".to_owned(),
            "x".repeat(64 * 1024 + 1),
        ] {
            assert!(
                matches!(
                    validate_startup_script(&refused),
                    Err(AppError::Validation { .. })
                ),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn the_audit_names_the_script_by_hash_and_length_never_its_text() {
        let script = "echo synthetic-script-canary";
        let metadata = audit_metadata("org", "env", script);
        assert_eq!(
            metadata["startup_script_sha256"],
            format!("{:x}", Sha256::digest(script.as_bytes()))
        );
        assert_eq!(metadata["startup_script_bytes"], script.len());
        assert!(!metadata.to_string().contains("synthetic-script-canary"));
        let removed = audit_metadata("org", "env", "");
        assert!(removed["startup_script_sha256"].is_null());
        assert_eq!(removed["startup_script_bytes"], 0);
    }

    #[test]
    fn only_a_running_or_stopped_sandbox_takes_a_script() {
        assert_eq!(
            scriptable_state("running", "started").unwrap(),
            ScriptableState::Running
        );
        assert_eq!(
            scriptable_state("stopped", "stopped").unwrap(),
            ScriptableState::Stopped
        );
        for (state, desired) in [
            ("running", "stopped"),
            ("stopping", "stopped"),
            ("starting", "started"),
            ("stopped", "started"),
            ("creating", "started"),
            ("error", "started"),
        ] {
            assert!(
                matches!(
                    scriptable_state(state, desired),
                    Err(AppError::Precondition(_))
                ),
                "{state} {desired}"
            );
        }
    }
}
