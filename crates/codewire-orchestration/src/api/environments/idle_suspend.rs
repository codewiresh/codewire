//! A Sandbox's own idle suspend (#5529, `docs/dev/IDLE-STOP.md`, "Suspend"):
//! only a `standard` Sandbox's VM can pause inside its Pod, so a timeout set
//! on any other is refused by name. Turning it off is accepted on any.

use super::*;

/// An idle suspend the platform accepts: 0 (off), or five minutes to seven
/// days.
pub(crate) fn validate_idle_suspend_seconds(seconds: i32) -> AppResult<()> {
    codewire_project::validate_idle_suspend_seconds(seconds).map_err(|error| AppError::Validation {
        errors: vec![codewire_server_core::ValidationIssue {
            path: Cow::Borrowed("/idle_suspend_seconds"),
            message: Cow::Owned(error.to_string()),
        }],
    })
}

/// Refuses a timeout for a Sandbox whose recorded runtime profile isn't
/// `standard`.
pub(crate) fn require_standard_for_idle_suspend(
    runtime_profile: &str,
    seconds: i32,
) -> AppResult<()> {
    if seconds == 0 || runtime_profile == crate::sandbox::template::RUNTIME_PROFILE_STANDARD {
        return Ok(());
    }
    Err(coded_owned(
        StatusCode::PRECONDITION_FAILED,
        "idle_suspend_unsupported",
        format!(
            "only a sandbox on the standard runtime can suspend; this one runs on {}",
            if runtime_profile.is_empty() {
                "none"
            } else {
                runtime_profile
            }
        ),
    ))
}

/// Sets how long the environment may have no activity before its VM pauses.
/// It only records the setting: nothing is paused, woken or stopped.
pub(crate) async fn set_environment_idle_suspend_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    seconds: i32,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(&state.pool, user, env_id, org_id, "owner", "access denied").await?;
    validate_idle_suspend_seconds(seconds)?;
    let profile: Option<String> = sqlx::query_scalar(
        "SELECT runtime_profile FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(profile) = profile else {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment is already destroyed or not found",
        ));
    };
    require_standard_for_idle_suspend(&profile, seconds)?;

    run_organization_database_mutation(&state.pool, org_id, async {
        let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
        match lifecycle.set_idle_suspend(env_id, seconds).await {
            Err(_) => Err(coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to set the idle suspend",
            )),
            Ok(false) => Err(coded(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "environment is already destroyed or not found",
            )),
            Ok(true) => Ok(StatusResponse {
                status: "idle_suspend_set",
            }),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_takes_a_timeout_and_off_is_always_accepted() {
        assert!(require_standard_for_idle_suspend("standard", 900).is_ok());
        for profile in ["commodity", "confidential", "runc", "none", ""] {
            assert!(
                require_standard_for_idle_suspend(profile, 0).is_ok(),
                "{profile}"
            );
            let error = require_standard_for_idle_suspend(profile, 900).unwrap_err();
            let text = format!("{error:?}");
            assert!(
                text.contains("idle_suspend_unsupported"),
                "{profile}: {text}"
            );
        }
    }

    #[test]
    fn the_range_is_idle_stops() {
        for seconds in [0, 300, 900, 604_800] {
            assert!(validate_idle_suspend_seconds(seconds).is_ok(), "{seconds}");
        }
        for seconds in [-1, 1, 299, 604_801] {
            assert!(validate_idle_suspend_seconds(seconds).is_err(), "{seconds}");
        }
    }
}
