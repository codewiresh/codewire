//! A create's idle stop (#3384), idle suspend (#5529) and idle hibernate
//! (#6647): checked before anything is written, then resolved against its
//! snapshot's.

use super::*;

/// Refuses out-of-range idle timeouts or an idle hibernate that isn't strictly
/// greater than idle suspend, without checking the runtime profile yet (used
/// before default-image preset resolution when a create omits `image`).
pub(super) fn validate_bounds(body: &CreateEnvironmentBody) -> AppResult<()> {
    if let Some(idle_stop_seconds) = body.idle_stop_seconds {
        super::super::environments::validate_idle_stop_seconds(idle_stop_seconds)?;
    }
    if let Some(seconds) = body.idle_suspend_seconds {
        super::super::environments::validate_idle_suspend_seconds(seconds)?;
    }
    if let Some(seconds) = body.idle_hibernate_seconds {
        super::super::environments::validate_idle_hibernate_seconds(seconds)?;
    }
    super::super::environments::validate_idle_hibernate_after_suspend(
        body.idle_suspend_seconds.unwrap_or(0),
        body.idle_hibernate_seconds.unwrap_or(0),
    )?;
    Ok(())
}

/// Refuses a timeout out of range, an idle suspend or hibernate on a Sandbox
/// whose recorded runtime profile isn't `standard`, or an idle hibernate that
/// isn't strictly greater than idle suspend when both are set explicitly.
pub(super) fn validate(body: &CreateEnvironmentBody, runtime_profile: &str) -> AppResult<()> {
    validate_bounds(body)?;
    if let Some(seconds) = body.idle_suspend_seconds {
        super::super::environments::require_standard_for_idle_suspend(runtime_profile, seconds)?;
    }
    if let Some(seconds) = body.idle_hibernate_seconds {
        super::super::environments::require_standard_for_idle_hibernate(runtime_profile, seconds)?;
    }
    Ok(())
}

/// The create's own, else its snapshot's, else off (owner, 2026-11-19: "not
/// on by default"). A snapshot's suspend or hibernate carries only onto a fork
/// that runs on `standard`, and cross-field ordering (`idle_hibernate >
/// idle_suspend`) is checked on the resolved pair.
pub(super) fn resolve(
    body: &CreateEnvironmentBody,
    snapshot: SnapshotTimeouts,
    runtime_profile: &str,
) -> AppResult<(i32, i32, i32)> {
    let idle_stop = body
        .idle_stop_seconds
        .or(snapshot.idle_stop_seconds)
        .unwrap_or(0);
    let is_standard = runtime_profile == crate::sandbox::template::RUNTIME_PROFILE_STANDARD;
    let idle_suspend = body.idle_suspend_seconds.unwrap_or_else(|| {
        snapshot
            .idle_suspend_seconds
            .filter(|_| is_standard)
            .unwrap_or(0)
    });
    let idle_hibernate = body.idle_hibernate_seconds.unwrap_or_else(|| {
        snapshot
            .idle_hibernate_seconds
            .filter(|_| is_standard)
            .unwrap_or(0)
    });
    super::super::environments::validate_idle_hibernate_after_suspend(
        idle_suspend,
        idle_hibernate,
    )?;
    Ok((idle_stop, idle_suspend, idle_hibernate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        idle_stop: Option<i32>,
        idle_suspend: Option<i32>,
        idle_hibernate: Option<i32>,
    ) -> SnapshotTimeouts {
        SnapshotTimeouts {
            idle_stop_seconds: idle_stop,
            idle_suspend_seconds: idle_suspend,
            idle_hibernate_seconds: idle_hibernate,
        }
    }

    #[test]
    fn a_fork_takes_its_snapshots_suspend_and_hibernate_only_onto_standard() {
        let body = CreateEnvironmentBody::default();
        let from = snapshot(Some(21_600), Some(900), Some(21_600));
        assert_eq!(
            resolve(&body, from, "standard").unwrap(),
            (21_600, 900, 21_600)
        );
        assert_eq!(resolve(&body, from, "commodity").unwrap(), (21_600, 0, 0));
        assert_eq!(
            resolve(&body, SnapshotTimeouts::default(), "standard").unwrap(),
            (0, 0, 0)
        );
        let own = CreateEnvironmentBody {
            idle_stop_seconds: Some(0),
            idle_suspend_seconds: Some(1800),
            idle_hibernate_seconds: Some(7200),
            ..Default::default()
        };
        assert_eq!(resolve(&own, from, "standard").unwrap(), (0, 1800, 7200));
    }

    #[test]
    fn a_timeout_off_standard_or_inverted_hibernate_is_refused() {
        let suspend = |seconds| CreateEnvironmentBody {
            idle_suspend_seconds: Some(seconds),
            ..Default::default()
        };
        assert!(validate(&suspend(900), "standard").is_ok());
        assert!(validate(&suspend(900), "commodity").is_err());
        assert!(validate(&suspend(0), "commodity").is_ok());
        assert!(validate(&suspend(60), "standard").is_err());

        let hibernate = |seconds| CreateEnvironmentBody {
            idle_hibernate_seconds: Some(seconds),
            ..Default::default()
        };
        assert!(validate(&hibernate(21_600), "standard").is_ok());
        assert!(validate(&hibernate(21_600), "commodity").is_err());
        assert!(validate(&hibernate(0), "commodity").is_ok());
        assert!(validate(&hibernate(60), "standard").is_err());

        let inverted = CreateEnvironmentBody {
            idle_suspend_seconds: Some(3600),
            idle_hibernate_seconds: Some(3600),
            ..Default::default()
        };
        assert!(validate(&inverted, "standard").is_err());

        // Default-image creates omit `image`, so early validation checks
        // range and ordering via `validate_bounds` before preset resolution,
        // then `validate` enforces the `standard` profile gate once the
        // default image resolves.
        assert!(validate_bounds(&suspend(900)).is_ok());
        assert!(validate_bounds(&hibernate(300)).is_ok());
        assert!(validate_bounds(&suspend(60)).is_err());
        assert!(validate_bounds(&hibernate(60)).is_err());
        assert!(validate_bounds(&inverted).is_err());
        assert!(validate(&hibernate(300), "standard").is_ok());
        assert!(validate(&hibernate(300), "commodity").is_err());
    }
}
