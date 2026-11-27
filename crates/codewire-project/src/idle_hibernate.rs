//! `idle_hibernate`: how long a `standard` cloud sandbox may have no activity
//! before its VM writes its memory and device state to its volume and its Pod
//! ends (#6647, `docs/dev/SANDBOX-SLEEP.md`). Written as `idle_stop` and
//! `idle_suspend` are: `off` (or `false`, or `0`) never hibernates it, `on`
//! (or `true`) is six hours, and otherwise a duration from `5m` to `7d`. A
//! sandbox that names none is off.
//!
//! When both `idle_suspend` and `idle_hibernate` are enabled, `idle_hibernate`
//! must be strictly longer than `idle_suspend`.
//!
//! Like `idle_stop` and `idle_suspend`, it is a setting of the environment,
//! never part of [`ProjectSpec`](crate::ProjectSpec).

use crate::ProjectError;

/// The `codewire.yaml` key, and the field named in its errors.
pub const IDLE_HIBERNATE_FIELD: &str = "idle_hibernate";
/// What `on` means: six hours (`docs/dev/SANDBOX-SLEEP.md`).
pub const IDLE_HIBERNATE_ON_SECONDS: i32 = 6 * 3600;

/// An idle hibernate reads back as an idle stop does: `off`, `6h`, `1h30m`.
pub use crate::idle_stop::format_idle_stop as format_idle_hibernate;

/// `idle_hibernate` as `codewire.yaml` may write it: `6h`, `on`, `true`, `0`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum IdleHibernateValue {
    Switch(bool),
    Number(i64),
    Text(String),
}

impl IdleHibernateValue {
    /// Its seconds, as [`parse_idle_hibernate`] reads them.
    pub(crate) fn seconds(&self) -> Result<i32, ProjectError> {
        match self {
            Self::Switch(true) => Ok(IDLE_HIBERNATE_ON_SECONDS),
            Self::Switch(false) | Self::Number(0) => Ok(0),
            Self::Number(_) => Err(unreadable()),
            Self::Text(text) => parse_idle_hibernate(text),
        }
    }
}

fn unreadable() -> ProjectError {
    ProjectError::InvalidField {
        field: IDLE_HIBERNATE_FIELD,
        detail: "must be on, off or a duration such as 30m, 6h or 7d".into(),
    }
}

/// Seconds for an idle hibernate as people write it: 0 for `off`, `false` or
/// `0`; six hours for `on` or `true`; otherwise a duration such as `6h` or
/// `1h30m`, from five minutes to seven days.
pub fn parse_idle_hibernate(value: &str) -> Result<i32, ProjectError> {
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
        return Ok(IDLE_HIBERNATE_ON_SECONDS);
    }
    let seconds = crate::idle_stop::duration_seconds(value).ok_or_else(unreadable)?;
    validate_idle_hibernate_seconds(seconds)?;
    Ok(seconds)
}

/// Whether `seconds` is an idle hibernate the platform accepts: 0 (off), or
/// the same five minutes to seven days as an idle stop.
pub fn validate_idle_hibernate_seconds(seconds: i32) -> Result<(), ProjectError> {
    if seconds == 0
        || (crate::MIN_IDLE_STOP_SECONDS..=crate::MAX_IDLE_STOP_SECONDS).contains(&seconds)
    {
        Ok(())
    } else {
        Err(ProjectError::InvalidField {
            field: IDLE_HIBERNATE_FIELD,
            detail: "must be off, or from 5m to 7d".into(),
        })
    }
}

/// When both `idle_suspend` and `idle_hibernate` are enabled (> 0),
/// `idle_hibernate` must be strictly longer than `idle_suspend`
/// (`docs/dev/SANDBOX-SLEEP.md`).
pub fn validate_idle_hibernate_after_suspend(
    idle_suspend_seconds: i32,
    idle_hibernate_seconds: i32,
) -> Result<(), ProjectError> {
    if idle_suspend_seconds > 0
        && idle_hibernate_seconds > 0
        && idle_hibernate_seconds <= idle_suspend_seconds
    {
        return Err(ProjectError::InvalidField {
            field: IDLE_HIBERNATE_FIELD,
            detail: format!(
                "must be longer than {} ({})",
                crate::IDLE_SUSPEND_FIELD,
                crate::format_idle_suspend(idle_suspend_seconds)
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_off_on_and_durations() {
        for off in ["off", " OFF ", "false", "0"] {
            assert_eq!(parse_idle_hibernate(off).unwrap(), 0, "{off}");
        }
        for on in ["on", "On", "true"] {
            assert_eq!(parse_idle_hibernate(on).unwrap(), 6 * 3600, "{on}");
        }
        assert_eq!(parse_idle_hibernate("6h").unwrap(), 21_600);
        assert_eq!(parse_idle_hibernate("5m").unwrap(), 300);
        assert_eq!(parse_idle_hibernate("7d").unwrap(), 604_800);
        assert_eq!(format_idle_hibernate(21_600), "6h");
        assert_eq!(format_idle_hibernate(0), "off");
    }

    #[test]
    fn refuses_what_it_cannot_read_or_is_out_of_range() {
        for value in ["", "soon", "15", "1h1h", "yes"] {
            let error = parse_idle_hibernate(value).unwrap_err().to_string();
            assert!(error.contains("idle_hibernate"), "{value:?}: {error}");
        }
        for value in ["4m", "299s", "8d"] {
            let error = parse_idle_hibernate(value).unwrap_err().to_string();
            assert!(error.contains("from 5m to 7d"), "{value}: {error}");
        }
        assert!(validate_idle_hibernate_seconds(-1).is_err());
        assert!(validate_idle_hibernate_seconds(604_801).is_err());
    }

    #[test]
    fn requires_hibernate_strictly_longer_than_suspend_when_both_are_on() {
        validate_idle_hibernate_after_suspend(0, 0).unwrap();
        validate_idle_hibernate_after_suspend(900, 0).unwrap();
        validate_idle_hibernate_after_suspend(0, 900).unwrap();
        validate_idle_hibernate_after_suspend(900, 901).unwrap();
        validate_idle_hibernate_after_suspend(900, 21_600).unwrap();

        for (suspend, hibernate) in [(900, 900), (1800, 900)] {
            let error = validate_idle_hibernate_after_suspend(suspend, hibernate)
                .unwrap_err()
                .to_string();
            assert!(error.contains("idle_hibernate"), "{error}");
            assert!(error.contains("idle_suspend"), "{error}");
        }
    }

    #[test]
    fn yaml_values_read_as_written() {
        for (value, seconds) in [
            (IdleHibernateValue::Switch(true), 21_600),
            (IdleHibernateValue::Switch(false), 0),
            (IdleHibernateValue::Number(0), 0),
            (IdleHibernateValue::Text("2h".into()), 7_200),
        ] {
            assert_eq!(value.seconds().unwrap(), seconds, "{value:?}");
        }
        assert!(IdleHibernateValue::Number(900).seconds().is_err());
    }
}
