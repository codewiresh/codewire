//! An unplanned restart in `cw info` and `cw ls` (#5997): when a running
//! Sandbox was running again without anyone asking, and why.

use chrono::{DateTime, TimeZone, Utc};

use crate::presentation::Environment;

/// What a `cw ls` row carries of an unplanned restart, beside its `state`.
#[derive(Clone, Debug, Default, serde::Serialize, PartialEq, Eq)]
pub(crate) struct UnplannedRestart {
    /// Running again after its Pod failed, with every process lost (#3772).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) restarted: bool,
    /// When it was running again, RFC 3339. Absent from a server older than
    /// the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) restarted_at: Option<String>,
    /// Why: `pod_failed`, `runtime_replaced`, `node_lost` or
    /// `configuration_changed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) restart_cause: Option<String>,
}

impl UnplannedRestart {
    pub(crate) fn of(environment: &Environment) -> Self {
        Self {
            restarted: environment.error_code.as_deref() == Some("sandbox_restarted"),
            restarted_at: environment.restarted_at.clone(),
            restart_cause: environment.restart_cause.clone(),
        }
    }

    /// Whether the server said when, so a note under the list says so and
    /// the STATE cell needs no `(restarted)`.
    pub(crate) fn recorded(&self) -> bool {
        self.restarted_at.is_some()
    }

    /// The note under `cw ls` for a Sandbox called `name`:
    /// `app restarted on its own 2 h ago: its runtime was replaced. Programs
    /// that were running stopped.` `None` when the server did not say when.
    pub(crate) fn list_note(&self, name: &str, now: DateTime<Utc>) -> Option<String> {
        let at = self.restarted_at.as_deref()?;
        let ago = parse(at)
            .map(|at| format!(" {}", ago(at, now)))
            .unwrap_or_default();
        Some(format!(
            "{name} restarted on its own{ago}{}. Programs that were running stopped.",
            cause_clause(self.restart_cause.as_deref())
        ))
    }
}

/// `cw info`'s `Restarted:` value, with the time in `zone`:
/// `22 Nov 12:00 (2 h ago) on its own: its runtime was replaced. Files are
/// safe; programs that were running stopped.`
pub(crate) fn info_value<Tz: TimeZone>(
    environment: &Environment,
    now: DateTime<Utc>,
    zone: &Tz,
) -> Option<String>
where
    Tz::Offset: std::fmt::Display,
{
    let at = environment.restarted_at.as_deref()?;
    let when = parse(at)
        .map(|at| {
            format!(
                "{} ({}) ",
                at.with_timezone(zone).format("%-d %b %H:%M"),
                ago(at, now)
            )
        })
        .unwrap_or_default();
    Some(format!(
        "{when}on its own{}. Files are safe; programs that were running stopped.",
        cause_clause(environment.restart_cause.as_deref())
    ))
}

/// `: <why>`, or nothing for a cause this `cw` does not know.
fn cause_clause(cause: Option<&str>) -> String {
    let words = match cause {
        Some("pod_failed") => "it stopped unexpectedly",
        Some("runtime_replaced") => "its runtime was replaced",
        Some("node_lost") => "the machine it ran on stopped responding, so it moved to another",
        Some("configuration_changed") => "its credentials or settings changed",
        _ => return String::new(),
    };
    format!(": {words}")
}

fn parse(at: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(at.trim())
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// `just now`, `5 min ago`, `2 h ago` or `3 d ago`.
fn ago(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let seconds = now.signed_duration_since(at).num_seconds();
    if seconds < 60 {
        "just now".to_owned()
    } else if seconds < 60 * 60 {
        format!("{} min ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{} h ago", seconds / (60 * 60))
    } else {
        format!("{} d ago", seconds / (24 * 60 * 60))
    }
}
