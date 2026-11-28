//! What `cw secrets` prints for a key's delivery (#4003;
//! `private-docs: designs/2026-11-22-host-bound-credentials.md`, "The
//! CLI"): a set's outcome, the key list with its DELIVERY column, and the
//! preset table. Text only; the JSON forms are the rows themselves.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use codewire_access::{BindingPreset, StoredBinding, StoredPresentation};
use serde::Serialize;

use super::progress::terminal_text;
use crate::output::{Charset, Status, Style};
use crate::secret_client::{NO_SCHEME, SecretBindingView, SecretMetadata};

/// The `→` line for an environment that must start again; the CLI can't yet
/// name the running environments that select the key's source.
const RESTART: &str = "cw restart ENV";

/// One set's result, from the key's binding before and after it.
pub(crate) struct SetOutcome<'a> {
    pub(crate) key: &'a str,
    /// Where the key lives, after `set`: ` in project myapp`, or empty.
    pub(crate) place: String,
    pub(crate) before: Option<&'a StoredBinding>,
    pub(crate) after: Option<&'a StoredBinding>,
    pub(crate) value_changed: bool,
}

impl SetOutcome<'_> {
    pub(crate) fn render(&self, style: Style) -> String {
        let key = terminal_text(self.key);
        // Sanitised without its leading space, which the sanitiser trims.
        let place = match self.place.trim_start() {
            "" => String::new(),
            place => format!(" {}", terminal_text(place)),
        };
        let mut out = String::new();
        let mut line = |text: String| {
            out.push_str(&text);
            out.push('\n');
        };
        let sep = style.separator();
        let done = style.status(Status::Done);
        let attention = style.status(Status::Attention);
        let next = style.status(Status::Next);
        let Some(after) = self.after else {
            line(format!("{done} Secret {key} set{place}{sep}plain"));
            line(format!(
                "  {attention} Every process in an environment can read a plain secret."
            ));
            if self.before.is_some() {
                line(format!(
                    "{next} Environments already running keep the placeholder until they start again: {RESTART}"
                ));
            }
            return out;
        };
        let hosts = |binding: &StoredBinding| -> BTreeSet<String> {
            binding.hosts.iter().cloned().collect()
        };
        let now = hosts(after);
        let was = self.before.map(hosts).unwrap_or_default();
        let added = joined(now.difference(&was));
        let removed = joined(was.difference(&now));
        let sent_to = joined(now.iter());
        let presentation_changed = self
            .before
            .is_none_or(|before| before.presentation != after.presentation);
        let prefix_changed = self
            .before
            .is_none_or(|before| before.prefix != after.prefix);
        let binding_changed = presentation_changed || prefix_changed || !added.is_empty();

        if !binding_changed && !removed.is_empty() && !self.value_changed {
            line(format!(
                "{done} {key} is no longer sent to {removed}{sep}still sent to {sent_to}"
            ));
            line("  Running environments stopped sending it there.".to_owned());
            return out;
        }
        let verb = if self.value_changed { "set" } else { "updated" };
        line(format!(
            "{done} Secret {key} {verb}{place}{sep}sent only to {sent_to}"
        ));
        if !binding_changed {
            if !removed.is_empty() {
                line(format!(
                    "  Running environments stopped sending it to {removed}."
                ));
            }
            line("  Running environments use the new value from their next request.".to_owned());
            return out;
        }
        line(format!("  Sent as   {}", sent_as(&after.presentation, sep)));
        line(format!(
            "  Inside    a placeholder, {}cwp1_{}; the value never enters an environment",
            terminal_text(after.prefix.as_deref().unwrap_or_default()),
            ellipsis(style),
        ));
        if !removed.is_empty() {
            line(format!(
                "  Running environments stopped sending it to {removed}."
            ));
        }
        if added.is_empty() {
            line(format!(
                "{next} Environments already running get the change when they start again: {RESTART}"
            ));
        } else {
            line(format!(
                "  {attention} In a cloud Sandbox, requests to {added} without this secret are refused."
            ));
            line(format!(
                "{next} Environments already running get {added} when they start again: {RESTART}"
            ));
        }
        out
    }
}

fn joined<'a>(hosts: impl Iterator<Item = &'a String>) -> String {
    hosts
        .map(|host| terminal_text(host))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Authorization: Bearer <value>`, or how Basic auth carries it.
fn sent_as(presentation: &StoredPresentation, sep: &str) -> String {
    match presentation {
        StoredPresentation::Header { headers, scheme } => headers
            .iter()
            .map(|header| match scheme {
                Some(scheme) => format!(
                    "{}: {} <value>",
                    terminal_text(header),
                    terminal_text(scheme)
                ),
                None => format!("{}: <value>", terminal_text(header)),
            })
            .collect::<Vec<_>>()
            .join(sep),
        StoredPresentation::Basic { username } => format!(
            "Authorization: Basic, user {} and <value> as the password",
            terminal_text(username)
        ),
        StoredPresentation::BasicUser => {
            "Authorization: Basic, <value> as the user and no password".to_owned()
        }
    }
}

fn ellipsis(style: Style) -> &'static str {
    match style.charset() {
        Charset::Unicode => "…",
        Charset::Ascii => "...",
    }
}

/// A `set --output json` row: the key's row as `list` prints it, and what
/// the set did.
#[derive(Debug, Serialize)]
pub(crate) struct SetRow<'a> {
    #[serde(flatten)]
    pub(crate) secret: &'a SecretMetadata,
    pub(crate) value_changed: bool,
    /// `null`: the CLI can't count the running environments that select
    /// the key's source yet.
    pub(crate) running_environments: Option<u64>,
}

/// The DELIVERY cell: `plain`, or the first host with `+N` for the rest and
/// what else says more. With `every_host`, every host and the preset.
fn delivery(binding: Option<&SecretBindingView>, every_host: bool, sep: &str) -> String {
    let Some(binding) = binding else {
        return "plain".to_owned();
    };
    let stored = binding.stored();
    let mut parts = Vec::new();
    if every_host {
        parts.push(joined(stored.hosts.iter()));
    } else {
        let first = stored.hosts.first().map(|host| terminal_text(host));
        let more = stored.hosts.len().saturating_sub(1);
        parts.push(match (first, more) {
            (Some(first), 0) => first,
            (Some(first), more) => format!("{first} +{more}"),
            (None, _) => String::new(),
        });
        match &stored.presentation {
            StoredPresentation::Basic { .. } => parts.push("Basic".to_owned()),
            StoredPresentation::BasicUser => parts.push("Basic user".to_owned()),
            StoredPresentation::Header { headers, .. } => {
                let other: Vec<String> = headers
                    .iter()
                    .filter(|header| !header.eq_ignore_ascii_case("Authorization"))
                    .map(|header| terminal_text(header))
                    .collect();
                if !other.is_empty() {
                    parts.push(other.join(", "));
                }
            }
        }
    }
    if let Some(preset) = &stored.preset {
        parts.push(format!("preset {}", terminal_text(preset)));
    }
    parts.join(sep)
}

/// The HEADER and SCHEME cells of `list -v`.
fn header_and_scheme(binding: Option<&SecretBindingView>) -> (String, String) {
    match binding
        .map(SecretBindingView::stored)
        .map(|stored| stored.presentation)
    {
        None => ("-".to_owned(), "-".to_owned()),
        Some(StoredPresentation::Header { headers, scheme }) => (
            headers
                .iter()
                .map(|header| terminal_text(header))
                .collect::<Vec<_>>()
                .join(", "),
            terminal_text(scheme.as_deref().unwrap_or(NO_SCHEME)),
        ),
        Some(StoredPresentation::Basic { username }) => (
            "Authorization".to_owned(),
            format!("Basic, user {}", terminal_text(&username)),
        ),
        Some(StoredPresentation::BasicUser) => {
            ("Authorization".to_owned(), "Basic user".to_owned())
        }
    }
}

/// The key list: KEY, DELIVERY and UPDATED; `-v` adds HEADER, SCHEME,
/// PREFIX, CREATED and every host.
pub(crate) fn key_list(
    secrets: &[SecretMetadata],
    verbose: bool,
    now: DateTime<Utc>,
    style: Style,
) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    rows.push(if verbose {
        [
            "KEY", "DELIVERY", "HEADER", "SCHEME", "PREFIX", "CREATED", "UPDATED",
        ]
        .map(str::to_owned)
        .to_vec()
    } else {
        ["KEY", "DELIVERY", "UPDATED"].map(str::to_owned).to_vec()
    });
    for secret in secrets {
        let binding = secret.binding.as_ref();
        let mut row = vec![
            terminal_text(&secret.key),
            delivery(binding, verbose, style.separator()),
        ];
        if verbose {
            let (header, scheme) = header_and_scheme(binding);
            row.extend([
                header,
                scheme,
                binding
                    .and_then(|binding| binding.prefix.as_deref())
                    .map_or_else(|| "-".to_owned(), terminal_text),
                ago(&secret.created_at, now),
            ]);
        }
        row.push(ago(&secret.updated_at, now));
        rows.push(row);
    }
    table(&rows)
}

/// Columns as wide as their widest cell, two spaces apart; the last column
/// is never padded.
fn table(rows: &[Vec<String>]) -> String {
    let columns = rows.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..columns)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (column, cell) in row.iter().enumerate() {
            if column + 1 == columns {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}  ", width = widths[column]));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// `just now`, `5 min ago`, `2 h ago` or `3 d ago`, the words `cw info`
/// uses; `-` for a time the store didn't give.
pub(crate) fn ago(at: &str, now: DateTime<Utc>) -> String {
    let Ok(at) = DateTime::parse_from_rfc3339(at.trim()) else {
        return "-".to_owned();
    };
    let seconds = now
        .signed_duration_since(at.with_timezone(&Utc))
        .num_seconds();
    match seconds {
        ..60 => "just now".to_owned(),
        60..3_600 => format!("{} min ago", seconds / 60),
        3_600..86_400 => format!("{} h ago", seconds / 3_600),
        _ => format!("{} d ago", seconds / 86_400),
    }
}

/// One row of `cw secrets presets --output json`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct PresetRow {
    pub(crate) name: &'static str,
    pub(crate) hosts: &'static [&'static str],
    pub(crate) presentation: &'static str,
    pub(crate) headers: [&'static str; 1],
    pub(crate) scheme: &'static str,
    pub(crate) prefix: Option<&'static str>,
}

impl From<&BindingPreset> for PresetRow {
    fn from(preset: &BindingPreset) -> Self {
        Self {
            name: preset.name,
            hosts: preset.hosts,
            presentation: "header",
            headers: [preset.header],
            scheme: preset.scheme.unwrap_or(NO_SCHEME),
            prefix: preset.prefix,
        }
    }
}

/// The preset table: NAME, HOSTS, PRESENTATION and PREFIX.
pub(crate) fn preset_list(presets: &[BindingPreset]) -> String {
    let mut rows = vec![
        ["NAME", "HOSTS", "PRESENTATION", "PREFIX"]
            .map(str::to_owned)
            .to_vec(),
    ];
    for preset in presets {
        rows.push(vec![
            preset.name.to_owned(),
            preset.hosts.join(", "),
            match preset.scheme {
                Some(scheme) => format!("{}: {scheme}", preset.header),
                None => format!("{}, no scheme", preset.header),
            },
            preset.prefix.unwrap_or("none").to_owned(),
        ]);
    }
    table(&rows)
}

#[cfg(test)]
mod tests;
