//! A create's idle stop (#3384) and idle suspend (#5529): checked before
//! anything is written, then resolved against its snapshot's.

use super::*;

/// Refuses a timeout out of range, or an idle suspend on a Sandbox whose
/// recorded runtime profile isn't `standard`.
pub(super) fn validate(body: &CreateEnvironmentBody, runtime_profile: &str) -> AppResult<()> {
    if let Some(idle_stop_seconds) = body.idle_stop_seconds {
        super::super::environments::validate_idle_stop_seconds(idle_stop_seconds)?;
    }
    if let Some(seconds) = body.idle_suspend_seconds {
        super::super::environments::validate_idle_suspend_seconds(seconds)?;
        super::super::environments::require_standard_for_idle_suspend(runtime_profile, seconds)?;
    }
    Ok(())
}

/// The create's own, else its snapshot's, else off (owner, 2026-11-19: "not
/// on by default"). A snapshot's suspend carries only onto a fork that can
/// suspend.
pub(super) fn resolve(
    body: &CreateEnvironmentBody,
    snapshot: SnapshotTimeouts,
    runtime_profile: &str,
) -> (i32, i32) {
    let idle_stop = body
        .idle_stop_seconds
        .or(snapshot.idle_stop_seconds)
        .unwrap_or(0);
    let idle_suspend = body.idle_suspend_seconds.unwrap_or_else(|| {
        snapshot
            .idle_suspend_seconds
            .filter(|_| runtime_profile == crate::sandbox::template::RUNTIME_PROFILE_STANDARD)
            .unwrap_or(0)
    });
    (idle_stop, idle_suspend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(idle_stop: Option<i32>, idle_suspend: Option<i32>) -> SnapshotTimeouts {
        SnapshotTimeouts {
            idle_stop_seconds: idle_stop,
            idle_suspend_seconds: idle_suspend,
        }
    }

    #[test]
    fn a_fork_takes_its_snapshots_suspend_only_onto_standard() {
        let body = CreateEnvironmentBody::default();
        let from = snapshot(Some(21_600), Some(900));
        assert_eq!(resolve(&body, from, "standard"), (21_600, 900));
        assert_eq!(resolve(&body, from, "commodity"), (21_600, 0));
        assert_eq!(
            resolve(&body, SnapshotTimeouts::default(), "standard"),
            (0, 0)
        );
        let own = CreateEnvironmentBody {
            idle_stop_seconds: Some(0),
            idle_suspend_seconds: Some(1800),
            ..Default::default()
        };
        assert_eq!(resolve(&own, from, "standard"), (0, 1800));
    }

    #[test]
    fn a_timeout_off_standard_is_refused_and_off_is_not() {
        let suspend = |seconds| CreateEnvironmentBody {
            idle_suspend_seconds: Some(seconds),
            ..Default::default()
        };
        assert!(validate(&suspend(900), "standard").is_ok());
        assert!(validate(&suspend(900), "commodity").is_err());
        assert!(validate(&suspend(0), "commodity").is_ok());
        assert!(validate(&suspend(60), "standard").is_err());
    }
}
