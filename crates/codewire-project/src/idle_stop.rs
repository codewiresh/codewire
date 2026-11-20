//! `idle_stop`: how long a cloud sandbox may have no activity before it stops
//! itself, keeping its disk (#3384). `off` (or `false`, or `0`) never stops
//! it, `on` (or `true`) is six hours, and otherwise a duration such as `30m`,
//! `6h`, `1h30m` or `7d`. A sandbox that names none is off (owner,
//! 2026-11-19: "not on by default. stop is pretty destructive. maybe 6 hours
//! default?").
//!
//! It is a setting of the environment, not of what runs in it, so it is never
//! part of [`ProjectSpec`](crate::ProjectSpec): a create sends it beside the
//! spec, and the server keeps it in its own column.

use crate::ProjectError;

/// The `codewire.yaml` key, and the field named in its errors.
pub const IDLE_STOP_FIELD: &str = "idle_stop";
/// The shortest idle stop: five minutes.
pub const MIN_IDLE_STOP_SECONDS: i32 = 5 * 60;
/// The longest idle stop: seven days.
pub const MAX_IDLE_STOP_SECONDS: i32 = 7 * 24 * 60 * 60;
/// What `on` means: six hours.
pub const IDLE_STOP_ON_SECONDS: i32 = 6 * 60 * 60;

/// `idle_stop` as `codewire.yaml` may write it: `30m`, `on`, `true`, `0`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum IdleStopValue {
    Switch(bool),
    Number(i64),
    Text(String),
}

impl IdleStopValue {
    /// Its seconds, as [`parse_idle_stop`] reads them.
    pub(crate) fn seconds(&self) -> Result<i32, ProjectError> {
        match self {
            Self::Switch(true) => Ok(IDLE_STOP_ON_SECONDS),
            Self::Switch(false) | Self::Number(0) => Ok(0),
            Self::Number(_) => Err(unreadable()),
            Self::Text(text) => parse_idle_stop(text),
        }
    }
}

fn unreadable() -> ProjectError {
    ProjectError::InvalidField {
        field: IDLE_STOP_FIELD,
        detail: "must be on, off or a duration such as 30m, 6h or 7d".into(),
    }
}

/// Seconds for an idle stop as people write it: 0 for `off`, `false` or `0`;
/// six hours for `on` or `true`; otherwise a whole number of days, hours,
/// minutes and seconds in that order, such as `30m` or `1h30m`, from five
/// minutes to seven days.
pub fn parse_idle_stop(value: &str) -> Result<i32, ProjectError> {
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
        return Ok(IDLE_STOP_ON_SECONDS);
    }
    let seconds = duration_seconds(value).ok_or_else(unreadable)?;
    validate_idle_stop_seconds(seconds)?;
    Ok(seconds)
}

/// Whether `seconds` is an idle stop the platform accepts: 0 (off), or five
/// minutes to seven days.
pub fn validate_idle_stop_seconds(seconds: i32) -> Result<(), ProjectError> {
    if seconds == 0 || (MIN_IDLE_STOP_SECONDS..=MAX_IDLE_STOP_SECONDS).contains(&seconds) {
        Ok(())
    } else {
        Err(ProjectError::InvalidField {
            field: IDLE_STOP_FIELD,
            detail: "must be off, or from 5m to 7d".into(),
        })
    }
}

/// An idle stop as [`parse_idle_stop`] reads it back: `off`, or its largest
/// whole units, such as `30m`, `6h` or `1h30m`.
pub fn format_idle_stop(seconds: i32) -> String {
    if seconds <= 0 {
        return "off".into();
    }
    let (days, hours, minutes, rest) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
        seconds % 60,
    );
    let mut text = String::new();
    for (count, unit) in [(days, 'd'), (hours, 'h'), (minutes, 'm'), (rest, 's')] {
        if count > 0 {
            text.push_str(&format!("{count}{unit}"));
        }
    }
    text
}

/// An idle stop in words, for people: `6 hours`, `1 hour 30 minutes`,
/// `7 days`.
pub fn idle_stop_words(seconds: i32) -> String {
    let parts = [
        (seconds / 86_400, "day"),
        (seconds % 86_400 / 3600, "hour"),
        (seconds % 3600 / 60, "minute"),
        (seconds % 60, "second"),
    ];
    let words: Vec<String> = parts
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, unit)| format!("{count} {unit}{}", if *count == 1 { "" } else { "s" }))
        .collect();
    if words.is_empty() {
        "0 minutes".into()
    } else {
        words.join(" ")
    }
}

/// What a Sandbox that stopped itself says, wherever it says why (owner,
/// 2026-11-19, on #3384): `cw info`, a refused connection, the dashboard.
pub fn idle_stop_notice(name: &str, idle_stop_seconds: i32) -> String {
    format!(
        "Stopped itself after {} idle (CPU under 10%, no traffic or input). Files are kept. \
         Start it with `cw start {name}`.",
        idle_stop_words(idle_stop_seconds)
    )
}

/// `1h30m` as seconds: whole numbers, each unit at most once, in d, h, m, s
/// order. `None` for anything else.
fn duration_seconds(value: &str) -> Option<i32> {
    let mut rest = value;
    let mut total: i64 = 0;
    let mut units = ['d', 'h', 'm', 's'].into_iter();
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        let number: i64 = rest[..digits].parse().ok()?;
        let unit = rest[digits..].chars().next()?;
        let scale = match units.find(|candidate| *candidate == unit)? {
            'd' => 86_400,
            'h' => 3600,
            'm' => 60,
            _ => 1,
        };
        total += number * scale;
        rest = &rest[digits + 1..];
    }
    if value.is_empty() {
        return None;
    }
    i32::try_from(total).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_off_and_durations() {
        for off in ["off", " OFF ", "false", "0"] {
            assert_eq!(parse_idle_stop(off).unwrap(), 0, "{off}");
        }
        for on in ["on", "On", "true"] {
            assert_eq!(parse_idle_stop(on).unwrap(), 6 * 3600, "{on}");
        }
        assert_eq!(parse_idle_stop("30m").unwrap(), 1800);
        assert_eq!(parse_idle_stop("2h").unwrap(), 7200);
        assert_eq!(parse_idle_stop("1h30m").unwrap(), 5400);
        assert_eq!(parse_idle_stop("5m").unwrap(), MIN_IDLE_STOP_SECONDS);
        assert_eq!(parse_idle_stop("168h").unwrap(), MAX_IDLE_STOP_SECONDS);
        assert_eq!(parse_idle_stop("7d").unwrap(), MAX_IDLE_STOP_SECONDS);
        assert_eq!(parse_idle_stop("1d12h").unwrap(), 36 * 3600);
        assert_eq!(parse_idle_stop("600s").unwrap(), 600);
    }

    #[test]
    fn refuses_what_it_cannot_read_or_is_out_of_range() {
        for value in [
            "", "soon", "30", "m", "30m1h", "1h1h", "1h1d", "-30m", "1.5h", "30 m", "yes",
        ] {
            assert!(parse_idle_stop(value).is_err(), "{value:?}");
        }
        for value in ["4m", "299s", "169h", "8d"] {
            let error = parse_idle_stop(value).unwrap_err().to_string();
            assert!(error.contains("from 5m to 7d"), "{value}: {error}");
        }
        assert!(validate_idle_stop_seconds(-1).is_err());
    }

    #[test]
    fn formats_what_it_reads() {
        for (seconds, text) in [
            (0, "off"),
            (1800, "30m"),
            (5400, "1h30m"),
            (7200, "2h"),
            (21_600, "6h"),
            (604_800, "7d"),
            (93_600, "1d2h"),
            (610, "10m10s"),
        ] {
            assert_eq!(format_idle_stop(seconds), text);
            assert_eq!(parse_idle_stop(text).unwrap(), seconds);
        }
    }

    #[test]
    fn says_why_it_stopped_with_its_own_timeout() {
        for (seconds, words) in [
            (21_600, "6 hours"),
            (300, "5 minutes"),
            (5400, "1 hour 30 minutes"),
            (604_800, "7 days"),
            (86_460, "1 day 1 minute"),
        ] {
            assert_eq!(idle_stop_words(seconds), words);
        }
        assert_eq!(
            idle_stop_notice("builder", 21_600),
            "Stopped itself after 6 hours idle (CPU under 10%, no traffic or input). Files are \
             kept. Start it with `cw start builder`."
        );
    }

    #[test]
    fn yaml_values_read_as_written() {
        for (value, seconds) in [
            (IdleStopValue::Switch(true), 6 * 3600),
            (IdleStopValue::Switch(false), 0),
            (IdleStopValue::Number(0), 0),
            (IdleStopValue::Text("45m".into()), 2700),
        ] {
            assert_eq!(value.seconds().unwrap(), seconds, "{value:?}");
        }
        assert!(IdleStopValue::Number(1800).seconds().is_err());
    }
}
