//! The subject bound on refusals (SPEC.md "Sandbox audit log", "Bounds"):
//! at most [`SUBJECT_BOUND`] subjects fold for one Sandbox and hour. Past
//! it, every further subject's events add to the hour's one overflow row,
//! which counts the events and, exactly up to the bound, the subjects.
//!
//! The overflow row is a fold like any other, with the columns
//! [`What::RefusedOverflow`] gives (`action` and `subject` `overflow`), actor
//! `sandbox`, moved by the flush when its hour ends. Its `detail` is that
//! event's [`RefusalOverflow`] for the read, and the set of the overflowed
//! subjects' hashes under `subject_hashes`, which the read ignores. Once the set is
//! full, a subject not in it sets `at_least` and `subjects` stays at the
//! bound: a lower bound, never a guess.
//!
//! The check and the write hold one transaction-scoped lock per Sandbox,
//! kind and hour, so two writers can't both take the last place.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::PgConnection;

use super::event::{Columns, RefusalOverflow, What};
use super::store::{AuditError, Event};

/// The most subjects that fold for one Sandbox, kind and hour, and the most
/// overflowed subjects the overflow row counts exactly.
pub(super) const SUBJECT_BOUND: usize = 1_000;

/// The overflow row's `detail`: what the read returns, and the subjects
/// counted so far.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Overflow {
    #[serde(flatten)]
    read: RefusalOverflow,
    /// Each overflowed subject's hash, at most [`SUBJECT_BOUND`].
    #[serde(default)]
    subject_hashes: Vec<String>,
}

impl Default for Overflow {
    fn default() -> Self {
        Self {
            read: RefusalOverflow {
                subjects: 0,
                at_least: false,
            },
            subject_hashes: Vec::new(),
        }
    }
}

impl Overflow {
    /// Counts `subject` once: a repeat adds nothing, and past the set's
    /// bound a new one only says there were more.
    fn add(&mut self, subject: &str) {
        let hash = subject_hash(subject);
        if self.subject_hashes.contains(&hash) {
            return;
        }
        if self.subject_hashes.len() >= SUBJECT_BOUND {
            self.read.at_least = true;
            return;
        }
        self.subject_hashes.push(hash);
        self.read.subjects = u64::try_from(self.subject_hashes.len()).unwrap_or(u64::MAX);
    }
}

/// Sixteen hex digits of the subject's SHA-256: a collision among a
/// thousand subjects is out of reach, and the text never leaves the row.
fn subject_hash(subject: &str) -> String {
    Sha256::digest(subject.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Adds `event` to the hour's overflow row when its subject has no fold
/// this hour and the hour already holds [`SUBJECT_BOUND`] of them; returns
/// whether it did. The caller's transaction holds the lock until it ends,
/// so its own fold write, when this returns false, is inside the check.
pub(super) async fn overflowed(
    connection: &mut PgConnection,
    event: &Event,
    columns: &Columns,
    hour: DateTime<Utc>,
    pending_key: &str,
) -> Result<bool, AuditError> {
    // The overflow's own columns, as the read decodes them. An overflow
    // names no subject, so it is never held to the bound itself.
    let read = What::RefusedOverflow(RefusalOverflow {
        subjects: 0,
        at_least: false,
    })
    .columns("")?;
    if columns.action == read.action {
        return Ok(false);
    }
    let hour_key = hour.to_rfc3339();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "sandbox-audit-bound|{}|{}|{hour_key}",
            event.environment_id,
            columns.kind.as_str()
        ))
        .execute(&mut *connection)
        .await?;
    let (exists, folds): (Option<bool>, i64) = sqlx::query_as(
        "SELECT bool_or(pending_key = $3), count(*) FILTER (WHERE action <> $5) \
           FROM sandbox_audit_pending \
          WHERE environment_id = $1 AND kind = $2 AND pending = 'fold' \
            AND right(pending_key, length($4)) = $4",
    )
    .bind(&event.environment_id)
    .bind(columns.kind.as_str())
    .bind(pending_key)
    .bind(format!("|{hour_key}"))
    .bind(&read.action)
    .fetch_one(&mut *connection)
    .await?;
    if exists.unwrap_or(false) || usize::try_from(folds).is_ok_and(|folds| folds < SUBJECT_BOUND) {
        return Ok(false);
    }
    let overflow_key = format!("{}|{hour_key}", read.subject);
    let stored: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT detail FROM sandbox_audit_pending \
          WHERE environment_id = $1 AND kind = $2 AND pending_key = $3",
    )
    .bind(&event.environment_id)
    .bind(columns.kind.as_str())
    .bind(&overflow_key)
    .fetch_optional(&mut *connection)
    .await?;
    let mut overflow = stored
        .map(serde_json::from_value::<Overflow>)
        .transpose()?
        .unwrap_or_default();
    overflow.add(&columns.subject);
    sqlx::query(
        "INSERT INTO sandbox_audit_pending (org_id, environment_id, kind, action, subject, \
         pending, pending_key, first_at, last_at, count, actor_type, detail) \
         VALUES ($1, $2, $3, $4, $5, 'fold', $6, $7, $8, $9, 'sandbox', $10) \
         ON CONFLICT (environment_id, kind, pending_key) DO UPDATE SET \
           count = sandbox_audit_pending.count + EXCLUDED.count, \
           first_at = LEAST(sandbox_audit_pending.first_at, EXCLUDED.first_at), \
           last_at = GREATEST(sandbox_audit_pending.last_at, EXCLUDED.last_at), \
           detail = EXCLUDED.detail",
    )
    .bind(&event.org_id)
    .bind(&event.environment_id)
    .bind(read.kind.as_str())
    .bind(&read.action)
    .bind(&read.subject)
    .bind(&overflow_key)
    .bind(event.first)
    .bind(event.last.max(event.first))
    .bind(i64::try_from(event.count.max(1)).unwrap_or(i64::MAX))
    .bind(serde_json::to_value(&overflow)?)
    .execute(&mut *connection)
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_counts_once_and_past_the_bound_only_says_at_least() {
        let mut overflow = Overflow::default();
        overflow.add("a");
        overflow.add("a");
        overflow.add("b");
        assert_eq!((overflow.read.subjects, overflow.read.at_least), (2, false));
        for index in 2..SUBJECT_BOUND {
            overflow.add(&format!("s{index}"));
        }
        assert_eq!(
            (overflow.read.subjects, overflow.read.at_least),
            (u64::try_from(SUBJECT_BOUND).unwrap(), false)
        );
        overflow.add("a");
        assert!(!overflow.read.at_least, "a subject already counted");
        overflow.add("one more");
        assert_eq!(
            (overflow.read.subjects, overflow.read.at_least),
            (u64::try_from(SUBJECT_BOUND).unwrap(), true)
        );
        assert_eq!(overflow.subject_hashes.len(), SUBJECT_BOUND);
    }

    #[test]
    fn the_read_sees_its_two_fields_and_the_hashes_hide_the_subject() {
        let mut overflow = Overflow::default();
        overflow.add("evil.example.com|tcp|443|name_not_allowed|walk|1");
        let detail = serde_json::to_value(&overflow).unwrap();
        assert_eq!(detail["subjects"], 1);
        assert_eq!(detail["at_least"], false);
        assert!(!detail.to_string().contains("evil"));
        assert_eq!(
            serde_json::from_value::<Overflow>(detail).unwrap(),
            overflow
        );
    }
}
