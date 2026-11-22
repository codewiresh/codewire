//! Retry setup (#4767): run a running Sandbox's failed project setup again,
//! from the step it failed at.
//!
//! The setup worker resumes from the recorded checkpoint, so steps that
//! completed are not run again. A retry whose signal is lost leaves the
//! Sandbox exactly as it was: the recorded failure is cleared only when the
//! retry's setup claims its lease (`worker::setup_lease`).

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_environment_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};

use super::ApiState;
use super::environments::{
    fetch_env_summary, require_environment_access, require_org_member, trigger_environment,
};
use crate::repository_mount::validate_repository_mounts;

/// The setup checkpoint at or before which a run clones the repositories
/// (`Runner::run`: health check 0, configure 1, clone 2).
const CLONE_PHASE: i32 = 2;

fn coded(status: StatusCode, code: &'static str, detail: impl Into<Cow<'static, str>>) -> AppError {
    AppError::Coded {
        status,
        code,
        detail: detail.into(),
    }
}

fn invalid_state(detail: &'static str) -> AppError {
    coded(StatusCode::CONFLICT, "invalid_state", detail)
}

/// What a retry needs to know about the Sandbox's setup.
#[derive(Debug, sqlx::FromRow)]
struct SetupRetryRow {
    state: String,
    desired_state: String,
    complete: bool,
    owner: Option<String>,
    error: Option<String>,
    phase: i32,
}

/// Whether setup can be retried now: the Sandbox runs, its setup recorded a
/// failure, and nothing owns setup. The refusal says which.
fn require_retryable(row: &SetupRetryRow) -> AppResult<()> {
    if row.state != "running" || row.desired_state != "started" {
        return Err(invalid_state(
            "setup can be retried only on a running Sandbox; start it first",
        ));
    }
    if row.complete {
        return Err(invalid_state("this Sandbox's setup completed"));
    }
    if row.owner.is_some() {
        return Err(invalid_state(
            "this Sandbox's setup is running; wait for it to finish",
        ));
    }
    if row
        .error
        .as_deref()
        .is_none_or(|error| error.trim().is_empty())
    {
        return Err(invalid_state(
            "this Sandbox's setup has not failed; it is still starting",
        ));
    }
    Ok(())
}

/// The directories a retry from `phase` deletes before cloning into them, or
/// none when it does not clone.
fn reclone_directories(phase: i32, repositories: &[(String, String)]) -> AppResult<Vec<String>> {
    if phase > CLONE_PHASE || repositories.is_empty() {
        return Ok(Vec::new());
    }
    validate_repository_mounts(
        repositories
            .iter()
            .map(|(url, mount)| (url.as_str(), mount.as_str())),
    )
    .map_err(|_| invalid_state("this Sandbox's repositories are not valid"))
}

fn reclone_unconfirmed(directories: &[String]) -> AppError {
    coded(
        StatusCode::CONFLICT,
        "reclone_unconfirmed",
        format!(
            "retrying setup clones the repositories again, which deletes {} and any edits made there; confirm to retry",
            directories.join(", ")
        ),
    )
}

pub(crate) async fn retry_environment_setup_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    confirm_reclone: bool,
) -> AppResult<()> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "operator",
        "access denied",
    )
    .await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;
    super::environments::require_bring_up_access(state, user, org_id, &env).await?;

    let dispatch_ambiguous = AtomicBool::new(false);
    let owned_state = state.clone();
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async move {
        let state = &owned_state;
        let result: AppResult<()> = async {
            let row = sqlx::query_as::<_, SetupRetryRow>(
                "SELECT e.state, e.desired_state, \
                        COALESCE(b.setup_complete, false) AS complete, \
                        b.setup_owner_status AS owner, b.setup_error AS error, \
                        COALESCE(b.setup_phase, 0) AS phase \
                   FROM environments e \
                   JOIN sandbox_environment_backend b ON b.environment_id = e.id \
                  WHERE e.id = $1",
            )
            .bind(&env.id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to read setup",
                )
            })?
            .ok_or_else(|| invalid_state("this Sandbox has no setup to retry"))?;
            require_retryable(&row)?;
            let environment = crate::worker::env_data::load_environment(&state.pool, &env.id)
                .await
                .map_err(|_| {
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "failed to read setup",
                    )
                })?;
            let repositories: Vec<(String, String)> = environment
                .project_spec
                .repositories
                .iter()
                .map(|repository| (repository.source.clone(), repository.destination.clone()))
                .collect();
            let directories = reclone_directories(row.phase, &repositories)?;
            if !directories.is_empty() && !confirm_reclone {
                return Err(reclone_unconfirmed(&directories));
            }
            if trigger_environment(state, &env.id, "retry_setup")
                .await
                .is_err()
            {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request setup retry",
                ));
            }
            tracing::info!(
                environment_id = env.id,
                phase = row.phase,
                reclone = !directories.is_empty(),
                "environment setup retry requested"
            );
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: &str, complete: bool, owner: Option<&str>, error: Option<&str>) -> SetupRetryRow {
        SetupRetryRow {
            state: state.into(),
            desired_state: "started".into(),
            complete,
            owner: owner.map(str::to_owned),
            error: error.map(str::to_owned),
            phase: 3,
        }
    }

    fn refused(row: &SetupRetryRow) -> Cow<'static, str> {
        match require_retryable(row) {
            Err(AppError::Coded {
                code: "invalid_state",
                detail,
                ..
            }) => detail,
            other => panic!("expected invalid_state, got {other:?}"),
        }
    }

    #[test]
    fn only_a_running_sandbox_whose_setup_failed_with_no_owner_retries() {
        assert!(require_retryable(&row("running", false, None, Some("install: exited 1"))).is_ok());
        assert!(
            refused(&row("stopped", false, None, Some("install: exited 1"))).contains("start it")
        );
        assert!(refused(&row("running", true, None, None)).contains("completed"));
        // A retry or first setup in progress holds the lease.
        assert!(refused(&row("running", false, Some("running"), None)).contains("running"));
        assert!(refused(&row("running", false, Some("reaping"), Some("x"))).contains("running"));
        assert!(refused(&row("running", false, None, None)).contains("still starting"));
        assert!(refused(&row("running", false, None, Some(" "))).contains("still starting"));
    }

    #[test]
    fn a_retry_that_clones_names_the_directories_it_deletes() {
        let repositories = vec![(
            "https://github.com/example/app.git".to_owned(),
            "/workspace/app".to_owned(),
        )];
        // From the clone, or from before it, the retry clones.
        for phase in [0, 1, 2] {
            let directories = reclone_directories(phase, &repositories).unwrap();
            assert_eq!(directories.len(), 1, "phase {phase}");
            let AppError::Coded { code, detail, .. } = reclone_unconfirmed(&directories) else {
                panic!("coded");
            };
            assert_eq!(code, "reclone_unconfirmed");
            assert!(detail.contains(&directories[0]), "{detail}");
        }
        // After the clone it never clones, and without repositories nothing is.
        assert!(reclone_directories(3, &repositories).unwrap().is_empty());
        assert!(reclone_directories(0, &[]).unwrap().is_empty());
    }
}
