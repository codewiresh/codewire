//! The `standard` runtime's own pause records (#5529, `docs/dev/IDLE-STOP.md`,
//! "Billing"): the lines `cw __pod-runtime` writes to its container's log at
//! each pause and resume, and every 30 seconds for the boot's state. Guest
//! output reaches that log only escaped and prefixed `guest-daemon: `, so a
//! line whose text starts with a marker was written by the runtime. Billing
//! and the suspend's checks read only these lines; nothing the guest says
//! moves a second between rates.

use std::time::Duration;

use serde::Deserialize;

/// The marker of a pause or resume record.
pub const RECORD_MARKER: &str = "standard runtime: vm-pause-record ";
/// The marker of a state record.
pub const STATE_MARKER: &str = "standard runtime: vm-pause-state ";

/// How far back a read for the suspend's checks looks, and how much it reads
/// at most: guest output is capped at 64 KiB a second.
pub const READ_WINDOW: Duration = Duration::from_secs(90);
pub const READ_LIMIT_BYTES: i64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PauseEvent {
    Paused,
    Resumed,
}

/// One pause or resume the runtime performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseRecord {
    pub event: PauseEvent,
    /// The boot.
    pub generation: u64,
    /// The boot's records counted from 1.
    pub sequence: u64,
    pub at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Paused,
    Running,
}

/// A boot's state as of its latest pause or resume record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub generation: u64,
    pub sequence: u64,
    pub state: VmState,
    pub since_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Pause(PauseRecord),
    State(StateRecord),
}

/// A record, with the time the kubelet logged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logged {
    pub at_unix_ms: i64,
    pub record: Record,
}

/// What a read of the runtime's log held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// In the order they were logged.
    pub logged: Vec<Logged>,
    /// Marked lines that didn't parse strictly. Only the count is kept.
    pub refused: usize,
}

impl Read {
    pub fn records(&self) -> Vec<Record> {
        self.logged.iter().map(|logged| logged.record).collect()
    }
}

/// The records in `log`, the runtime container's log read with timestamps:
/// each line is the kubelet's RFC 3339 time, a space, then what the runtime
/// wrote. A line is read only when its text after the time starts with a
/// marker, and then only when the rest is exactly one record's JSON: unknown
/// fields, wrong types, duplicates and trailing text are refused. Nothing of
/// a dropped or refused line is kept or logged.
pub fn read(log: &[u8]) -> Read {
    let mut read = Read::default();
    for line in log.split(|byte| *byte == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let Some((time, text)) = line.split_once(' ') else {
            continue;
        };
        let Some(at_unix_ms) = kubelet_time(time) else {
            continue;
        };
        let parsed = if let Some(json) = text.strip_prefix(RECORD_MARKER) {
            serde_json::from_str(json).map(Record::Pause)
        } else if let Some(json) = text.strip_prefix(STATE_MARKER) {
            serde_json::from_str(json).map(Record::State)
        } else {
            continue;
        };
        match parsed {
            Ok(record) => read.logged.push(Logged { at_unix_ms, record }),
            Err(_) => read.refused += 1,
        }
    }
    read
}

/// `time` as the kubelet writes it, RFC 3339, in Unix milliseconds.
fn kubelet_time(time: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|time| time.timestamp_millis())
}

#[cfg(test)]
mod tests;
