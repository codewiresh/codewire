//! `idle_suspend`: how long a `standard` cloud sandbox may have no activity
//! before its VM pauses inside its Pod (#5529, `docs/dev/IDLE-STOP.md`,
//! "Suspend"). Written as `idle_stop` is: `off` (or `false`, or `0`) never
//! suspends it, `on` (or `true`) is fifteen minutes, and otherwise a duration
//! from `5m` to `7d`. A sandbox that names none is off.
//!
//! Like `idle_stop`, it is a setting of the environment, never part of
//! [`ProjectSpec`](crate::ProjectSpec).

use crate::ProjectError;

/// The `codewire.yaml` key, and the field named in its errors.
pub const IDLE_SUSPEND_FIELD: &str = "idle_suspend";
/// What `on` means: fifteen minutes.
pub const IDLE_SUSPEND_ON_SECONDS: i32 = 15 * 60;

/// An idle suspend reads back as an idle stop does: `off`, `15m`, `1h30m`.
pub use crate::idle_stop::format_idle_stop as format_idle_suspend;

/// `idle_suspend` as `codewire.yaml` may write it: `15m`, `on`, `true`, `0`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum IdleSuspendValue {
    Switch(bool),
    Number(i64),
    Text(String),
}

impl IdleSuspendValue {
    /// Its seconds, as [`parse_idle_suspend`] reads them.
    pub(crate) fn seconds(&self) -> Result<i32, ProjectError> {
        match self {
            Self::Switch(true) => Ok(IDLE_SUSPEND_ON_SECONDS),
            Self::Switch(false) | Self::Number(0) => Ok(0),
            Self::Number(_) => Err(unreadable()),
            Self::Text(text) => parse_idle_suspend(text),
        }
    }
}

fn unreadable() -> ProjectError {
    ProjectError::InvalidField {
        field: IDLE_SUSPEND_FIELD,
        detail: "must be on, off or a duration such as 15m, 1h or 7d".into(),
    }
}

/// Seconds for an idle suspend as people write it: 0 for `off`, `false` or
/// `0`; fifteen minutes for `on` or `true`; otherwise a duration such as
/// `15m` or `1h30m`, from five minutes to seven days.
pub fn parse_idle_suspend(value: &str) -> Result<i32, ProjectError> {
    let value = value.trim();
    if ["off", "false", "0"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
    {
        return Ok(0);
    }
    if ["on", "true"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
    {
        return Ok(IDLE_SUSPEND_ON_SECONDS);
    }
    let seconds = crate::idle_stop::duration_seconds(value).ok_or_else(unreadable)?;
    validate_idle_suspend_seconds(seconds)?;
    Ok(seconds)
}

/// Whether `seconds` is an idle suspend the platform accepts: 0 (off), or
/// the same five minutes to seven days as an idle stop.
pub fn validate_idle_suspend_seconds(seconds: i32) -> Result<(), ProjectError> {
    if seconds == 0
        || (crate::MIN_IDLE_STOP_SECONDS..=crate::MAX_IDLE_STOP_SECONDS).contains(&seconds)
    {
        Ok(())
    } else {
        Err(ProjectError::InvalidField {
            field: IDLE_SUSPEND_FIELD,
            detail: "must be off, or from 5m to 7d".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_off_on_and_durations() {
        for off in ["off", " OFF ", "false", "0"] {
            assert_eq!(parse_idle_suspend(off).unwrap(), 0, "{off}");
        }
        for on in ["on", "On", "true"] {
            assert_eq!(parse_idle_suspend(on).unwrap(), 15 * 60, "{on}");
        }
        assert_eq!(parse_idle_suspend("15m").unwrap(), 900);
        assert_eq!(parse_idle_suspend("5m").unwrap(), 300);
        assert_eq!(parse_idle_suspend("7d").unwrap(), 604_800);
        assert_eq!(format_idle_suspend(900), "15m");
        assert_eq!(format_idle_suspend(0), "off");
    }

    #[test]
    fn refuses_what_it_cannot_read_or_is_out_of_range() {
        for value in ["", "soon", "15", "1h1h", "yes"] {
            let error = parse_idle_suspend(value).unwrap_err().to_string();
            assert!(error.contains("idle_suspend"), "{value:?}: {error}");
        }
        for value in ["4m", "299s", "8d"] {
            let error = parse_idle_suspend(value).unwrap_err().to_string();
            assert!(error.contains("from 5m to 7d"), "{value}: {error}");
        }
        assert!(validate_idle_suspend_seconds(-1).is_err());
        assert!(validate_idle_suspend_seconds(604_801).is_err());
    }

    #[test]
    fn yaml_values_read_as_written() {
        for (value, seconds) in [
            (IdleSuspendValue::Switch(true), 900),
            (IdleSuspendValue::Switch(false), 0),
            (IdleSuspendValue::Number(0), 0),
            (IdleSuspendValue::Text("30m".into()), 1800),
        ] {
            assert_eq!(value.seconds().unwrap(), seconds, "{value:?}");
        }
        assert!(IdleSuspendValue::Number(900).seconds().is_err());
    }
}
