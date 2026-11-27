//! A Sandbox's own idle hibernate and manual hibernate (#6647,
//! `docs/dev/SANDBOX-SLEEP.md`): only a `standard` Sandbox's VM can hibernate
//! to its encrypted volume, so a timeout or manual hibernate on any other
//! runtime profile is refused naming that profile. Turning idle hibernate off
//! is accepted on any. When both `idle_suspend` and `idle_hibernate` are on,
//! `idle_hibernate` must be strictly greater than `idle_suspend`.

use super::*;

/// An idle hibernate the platform accepts: 0 (off), or five minutes to seven
/// days.
pub(crate) fn validate_idle_hibernate_seconds(seconds: i32) -> AppResult<()> {
    codewire_project::validate_idle_hibernate_seconds(seconds).map_err(|error| {
        AppError::Validation {
            errors: vec![codewire_server_core::ValidationIssue {
                path: Cow::Borrowed("/idle_hibernate_seconds"),
                message: Cow::Owned(error.to_string()),
            }],
        }
    })
}

/// Refuses `idle_hibernate` <= `idle_suspend` when both are on.
pub(crate) fn validate_idle_hibernate_after_suspend(
    idle_suspend_seconds: i32,
    idle_hibernate_seconds: i32,
) -> AppResult<()> {
    codewire_project::validate_idle_hibernate_after_suspend(
        idle_suspend_seconds,
        idle_hibernate_seconds,
    )
    .map_err(|error| AppError::Validation {
        errors: vec![codewire_server_core::ValidationIssue {
            path: Cow::Borrowed("/idle_hibernate_seconds"),
            message: Cow::Owned(error.to_string()),
        }],
    })
}

/// Refuses a timeout or manual hibernate for a Sandbox whose recorded runtime
/// profile isn't `standard`.
pub(crate) fn require_standard_for_idle_hibernate(
    runtime_profile: &str,
    seconds: i32,
) -> AppResult<()> {
    if seconds == 0 || runtime_profile == crate::sandbox::template::RUNTIME_PROFILE_STANDARD {
        return Ok(());
    }
    Err(coded_owned(
        StatusCode::PRECONDITION_FAILED,
        "idle_hibernate_unsupported",
        format!(
            "only a sandbox on the standard runtime can hibernate; this one runs on {}",
            if runtime_profile.is_empty() {
                "none"
            } else {
                runtime_profile
            }
        ),
    ))
}

/// Sets how long the environment may have no activity before its VM hibernates
/// to its encrypted volume. It only records the setting: nothing is woken,
/// hibernated or stopped.
pub(crate) async fn set_environment_idle_hibernate_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    seconds: i32,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "owner", "access denied").await?;
    validate_idle_hibernate_seconds(seconds)?;
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT runtime_profile, idle_suspend_seconds FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((profile, idle_suspend_seconds)) = row else {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment is already destroyed or not found",
        ));
    };
    require_standard_for_idle_hibernate(&profile, seconds)?;
    validate_idle_hibernate_after_suspend(idle_suspend_seconds, seconds)?;

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        match lifecycle.set_idle_hibernate(env_id, seconds).await {
            Err(_) => Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to set the idle hibernate",
            )),
            Ok(false) => Err(coded(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "environment is already destroyed or not found",
            )),
            Ok(true) => Ok(StatusResponse {
                status: "idle_hibernate_set",
            }),
        }
    })
    .await
}

/// Manually hibernates a running or suspended `standard` Sandbox now (#6647).
/// Already-hibernated Sandboxes return an idempotent no-op; plain stopped
/// Sandboxes are refused explaining there is no running VM to hibernate.
pub(crate) async fn hibernate_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "owner", "access denied").await?;

    let row: Option<(String, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT state, runtime_profile, hibernated_at FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((env_state, runtime_profile, hibernated_at)) = row else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        ));
    };
    require_standard_for_idle_hibernate(&runtime_profile, 1)?;

    if env_state == "stopped" && hibernated_at.is_some() {
        return Ok(StatusResponse {
            status: "already_hibernated",
        });
    }
    if env_state == "stopped" {
        return Err(coded(
            StatusCode::PRECONDITION_FAILED,
            "environment_stopped",
            "a stopped sandbox has no running VM to hibernate",
        ));
    }
    if env_state != "running" {
        return Err(coded_owned(
            StatusCode::PRECONDITION_FAILED,
            "invalid_state",
            format!("cannot hibernate environment in state '{env_state}'"),
        ));
    }

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        let transitioned = lifecycle
            .request_hibernate(env_id, org_id, "hibernate_user")
            .await
            .map_err(|_| {
                coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request hibernate",
                )
            })?;
        if !transitioned {
            return Err(coded(
                StatusCode::CONFLICT,
                "invalid_state",
                "environment state changed while requesting hibernate",
            ));
        }
        if let Err(error) = trigger_environment(state, env_id, "stop").await {
            tracing::error!(
                environment_id = env_id,
                error = %error,
                "hibernate_environment: failed to trigger stop workflow"
            );
            return Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to trigger hibernate",
            ));
        }
        Ok(StatusResponse {
            status: "hibernating",
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_takes_a_timeout_and_off_is_always_accepted() {
        assert!(require_standard_for_idle_hibernate("standard", 21_600).is_ok());
        for profile in ["commodity", "confidential", "runc", "none", ""] {
            assert!(
                require_standard_for_idle_hibernate(profile, 0).is_ok(),
                "{profile}"
            );
            let error = require_standard_for_idle_hibernate(profile, 21_600).unwrap_err();
            let text = format!("{error:?}");
            assert!(
                text.contains("idle_hibernate_unsupported"),
                "{profile}: {text}"
            );
        }
    }

    #[test]
    fn idle_hibernate_must_be_strictly_greater_than_idle_suspend() {
        assert!(validate_idle_hibernate_after_suspend(900, 21_600).is_ok());
        assert!(validate_idle_hibernate_after_suspend(900, 0).is_ok());
        assert!(validate_idle_hibernate_after_suspend(0, 900).is_ok());
        assert!(validate_idle_hibernate_after_suspend(900, 900).is_err());
        assert!(validate_idle_hibernate_after_suspend(1800, 900).is_err());
    }

    #[test]
    fn the_range_is_idle_stops() {
        for seconds in [0, 300, 21_600, 604_800] {
            assert!(
                validate_idle_hibernate_seconds(seconds).is_ok(),
                "{seconds}"
            );
        }
        for seconds in [-1, 1, 299, 604_801] {
            assert!(
                validate_idle_hibernate_seconds(seconds).is_err(),
                "{seconds}"
            );
        }
    }
}
