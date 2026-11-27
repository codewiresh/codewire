//! The `standard` runtime's own hibernate, restore and fallback records (#6647,
//! `docs/dev/SANDBOX-SLEEP.md`, "Hibernating a Sandbox" and "Restoring a
//! hibernated Sandbox"): the lines `cw __pod-runtime` writes to its container's
//! log after hibernating, restoring, falling back to a cold boot, or failing to
//! hibernate. Guest output reaches that log only escaped and prefixed
//! `guest-daemon: `, so a line whose text starts with [`RECORD_MARKER`] was
//! written by the host-side runtime. Orchestration and billing read only these
//! lines; nothing the guest says transitions a Sandbox into `hibernated` or
//! moves a second between rates.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The marker of a hibernate, restore, fallback or hibernate-failed record.
pub const RECORD_MARKER: &str = "standard runtime: vm-hibernate-record ";

/// How far back a read for hibernate or restore completion looks, and how much
/// it reads at most: guest output is capped at 64 KiB a second.
pub const READ_WINDOW: Duration = Duration::from_secs(120);
pub const READ_LIMIT_BYTES: i64 = 8 * 1024 * 1024;

/// A completed host-observed hibernate record emitted by `cw __pod-runtime`
/// after `CloudHypervisorRunner::hibernate` and durable metadata write succeed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HibernatedRecord {
    pub restore_generation: u64,
    pub vmm_sha256: String,
    pub runtime_image_digest: String,
    pub image_disk_id: String,
    pub build_id: String,
    pub memory_bytes: u64,
    pub at_unix_ms: u64,
}

impl HibernatedRecord {
    fn is_valid(&self) -> bool {
        self.restore_generation >= 1
            && self.memory_bytes > 0
            && is_lowercase_hex(&self.vmm_sha256, 64)
            && is_sha256_digest(&self.runtime_image_digest)
            && is_lowercase_hex(&self.image_disk_id, 64)
            && is_lowercase_hex(&self.build_id, 32)
    }

    /// Serializes the host-observed record for `environments.hibernate_record`.
    pub fn to_metadata_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("HibernatedRecord serialization is infallible")
    }

    /// Parses a stored `environments.hibernate_record` JSONB payload strictly.
    pub fn from_metadata_json(value: &serde_json::Value) -> Option<Self> {
        let record: Self = serde_json::from_value(value.clone()).ok()?;
        record.is_valid().then_some(record)
    }
}

/// A completed host-observed restore record emitted after `rebind-ok\n`
/// succeeds, the memory file is deleted, and Pod ports open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredRecord {
    pub restore_generation: u64,
    pub at_unix_ms: u64,
}

/// A host-observed fallback record emitted when a restoring Pod could not
/// restore its memory image and fell back to a clean cold disk boot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackRecord {
    pub restore_generation: u64,
    pub reason: String,
    pub at_unix_ms: u64,
}

/// A host-observed record emitted when `runner.hibernate` could not complete
/// cleanly and the runtime fell back to an ordinary stop.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HibernateFailedRecord {
    pub reason: String,
    pub at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "event", deny_unknown_fields)]
pub enum HibernateRecord {
    #[serde(rename = "hibernated")]
    Hibernated(HibernatedRecord),
    #[serde(rename = "restored")]
    Restored(RestoredRecord),
    #[serde(rename = "fallback")]
    Fallback(FallbackRecord),
    #[serde(rename = "hibernate-failed")]
    HibernateFailed(HibernateFailedRecord),
}

impl HibernateRecord {
    fn is_valid(&self) -> bool {
        match self {
            Self::Hibernated(record) => record.is_valid(),
            Self::Restored(record) => record.restore_generation >= 1,
            Self::Fallback(record) => {
                record.restore_generation >= 1 && is_known_fallback_reason(&record.reason)
            }
            Self::HibernateFailed(record) => is_valid_reason_token(&record.reason),
        }
    }
}

/// A record, with the time the kubelet logged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub at_unix_ms: i64,
    pub record: HibernateRecord,
}

/// What a read of the runtime's log held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// In the order they were logged.
    pub logged: Vec<Logged>,
    /// Marked lines that did not parse or validate strictly. Only the count is
    /// kept; nothing of any dropped or refused line is retained.
    pub refused: usize,
}

impl Read {
    pub fn records(&self) -> Vec<HibernateRecord> {
        self.logged
            .iter()
            .map(|logged| logged.record.clone())
            .collect()
    }

    /// Returns the last host-observed `hibernated` record in the read, if any.
    pub fn last_hibernated(&self) -> Option<(i64, &HibernatedRecord)> {
        self.logged
            .iter()
            .rev()
            .find_map(|entry| match &entry.record {
                HibernateRecord::Hibernated(record) => Some((entry.at_unix_ms, record)),
                _ => None,
            })
    }

    /// Returns the last host-observed `restored` or `fallback` record for
    /// `restore_generation`, if any.
    pub fn last_restore_outcome(&self, restore_generation: u64) -> Option<&HibernateRecord> {
        self.logged
            .iter()
            .rev()
            .find_map(|entry| match &entry.record {
                HibernateRecord::Restored(record)
                    if record.restore_generation == restore_generation =>
                {
                    Some(&entry.record)
                }
                HibernateRecord::Fallback(record)
                    if record.restore_generation == restore_generation =>
                {
                    Some(&entry.record)
                }
                _ => None,
            })
    }
}

/// The records in `log`, the runtime container's log read with timestamps:
/// each line is the kubelet's RFC 3339 time, a space, then what the runtime
/// wrote. A line is read only when its text after the time starts with
/// [`RECORD_MARKER`], and then only when the rest is exactly one valid record's
/// JSON: unknown fields, wrong types, duplicates, invalid digests/reasons and
/// trailing text are refused. Nothing of a dropped or refused line is kept or
/// logged.
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
        let Some(json) = text.strip_prefix(RECORD_MARKER) else {
            continue;
        };
        match serde_json::from_str::<HibernateRecord>(json) {
            Ok(record) if record.is_valid() => {
                read.logged.push(Logged { at_unix_ms, record });
            }
            _ => read.refused += 1,
        }
    }
    read
}

fn kubelet_time(time: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(time)
        .ok()
        .map(|time| time.timestamp_millis())
}

fn is_lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_lowercase_hex(hex, 64))
}

fn is_known_fallback_reason(reason: &str) -> bool {
    matches!(
        reason,
        "generation-consumed"
            | "generation-mismatch"
            | "vmm-digest-mismatch"
            | "runtime-image-digest-mismatch"
            | "image-disk-mismatch"
            | "vm-config-mismatch"
            | "damaged-memory-file"
            | "restore-failed"
            | "rebind-failed"
    )
}

fn is_valid_reason_token(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests;
