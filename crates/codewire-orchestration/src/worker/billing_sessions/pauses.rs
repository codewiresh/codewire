//! The session loop's side of a `standard` Sandbox's pauses (#5529,
//! `docs/dev/BILLING.md`, "A suspended stretch"): at each poll it reads the
//! runtime's new pause records from the Pod's log and writes the splits
//! [`super::pause_split`] decides, in one transaction.
//!
//! A paused session is observed only up to its latest record, so it draws no
//! second past one; a gap after that record is settled when the next record,
//! or the session's end, shows how long it was.

use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use prometheus::{IntCounter, register_int_counter};
use sqlx::PgPool;

use super::Identity;
use super::pause_split::{self, Kind, Mark, PAUSE_RECORDS_GAP, Session, Split};
use crate::pause_records;
use crate::runtime::{Placement, RuntimeDriver};

/// The read reaches this far before the session's last observation, so a
/// record logged just before it is still read; the mark skips it if applied.
const READ_OVERLAP: Duration = Duration::from_secs(30);

static GAPS: OnceLock<IntCounter> = OnceLock::new();

fn gaps() -> &'static IntCounter {
    GAPS.get_or_init(|| {
        register_int_counter!(
            "codewire_billing_pause_record_gaps_total",
            "Paused standard Sandbox sessions billed running from a gap in their runtime's pause records."
        )
        .expect("pause record gap metric registration must be unique")
    })
}

/// What a poll found of a Sandbox's pauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Records {
    /// Not `standard`: it is billed running, as before.
    NotStandard,
    /// Read and applied: observe its open session up to this time.
    Observed(DateTime<Utc>),
    /// Not read, or not written: its open session's last observation stays.
    Unread,
}

/// The open session, as the last split or heartbeat left it.
struct Open {
    id: String,
    session: Session,
    last_observed_at: DateTime<Utc>,
}

/// Reads `id`'s new pause records and splits its open session at each one.
pub(super) async fn advance(
    pool: &PgPool,
    runtime: &dyn RuntimeDriver,
    id: &Identity,
    now: DateTime<Utc>,
) -> Records {
    let pod = match standard_pod(pool, &id.environment_id).await {
        Ok(None) => return Records::NotStandard,
        Ok(Some(pod)) => pod,
        Err(error) => {
            tracing::error!(environment_id = id.environment_id, %error, "billing-session: read a sandbox's runtime profile");
            return Records::Unread;
        }
    };
    let open = match open_session(pool, &id.runtime_uid).await {
        // Nothing to split: a session opens running at bind.
        Ok(None) => return Records::Observed(now),
        Ok(Some(open)) => open,
        Err(error) => {
            tracing::error!(environment_id = id.environment_id, %error, "billing-session: read an open session's pause mark");
            return Records::Unread;
        }
    };
    let placement = Placement::new(&id.namespace);
    let pod = match pod.filter(|pod| !pod.trim().is_empty()) {
        Some(pod) => pod,
        None => match runtime.member_name(&placement, &id.environment_id).await {
            Ok(pod) => pod,
            Err(error) => {
                tracing::warn!(environment_id = id.environment_id, %error, "billing-session: find a standard sandbox's pod");
                return Records::Unread;
            }
        },
    };
    let since = (now - open.last_observed_at).to_std().unwrap_or_default() + READ_OVERLAP;
    let log = match runtime
        .runtime_log_since(
            &placement,
            &pod,
            since.max(pause_records::READ_WINDOW),
            pause_records::READ_LIMIT_BYTES,
        )
        .await
    {
        Ok(log) => log,
        Err(_) => {
            // The error may quote what was read; only that it failed is kept.
            tracing::warn!(
                environment_id = id.environment_id,
                "billing-session: read a standard sandbox's pause records"
            );
            return Records::Unread;
        }
    };
    let read = pause_records::read(&log);
    if read.refused > 0 {
        tracing::warn!(
            environment_id = id.environment_id,
            refused = read.refused,
            "billing-session: refused malformed pause records"
        );
    }
    let plan = pause_split::plan(open.session, &read.logged);
    for missing in &plan.missing {
        tracing::warn!(
            environment_id = id.environment_id,
            generation = missing.generation,
            first = missing.first,
            last = missing.last,
            "billing-session: pause records missing"
        );
    }
    match apply(pool, &open, &plan.splits, plan.session).await {
        Ok(observed) => {
            for split in plan.splits.iter().filter(|split| split.review) {
                gaps().inc();
                tracing::warn!(
                    environment_id = id.environment_id,
                    at = %at(split, &open),
                    "billing-session: a gap in a paused sandbox's pause records is billed running, for review"
                );
            }
            Records::Observed(match plan.session.kind {
                Kind::Running => now,
                Kind::Paused => observed,
            })
        }
        Err(error) => {
            tracing::error!(environment_id = id.environment_id, %error, "billing-session: split a session at its pause records");
            Records::Unread
        }
    }
}

/// Settles a paused session's last stretch before it closes at `ended_at`,
/// its Pod gone: past its last record, a gap.
pub(super) async fn settle_end(
    pool: &PgPool,
    runtime_uid: &str,
    ended_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let Some(open) = open_session(pool, runtime_uid).await? else {
        return Ok(());
    };
    let splits = pause_split::end(open.session, ended_at.timestamp_millis());
    let Some(last) = splits.last() else {
        return Ok(());
    };
    let after = Session {
        kind: last.kind,
        mark: open.session.mark,
        paused_seen_ms: None,
        started_at_ms: open.session.started_at_ms,
    };
    apply(pool, &open, &splits, after).await?;
    gaps().inc();
    tracing::warn!(
        runtime_uid,
        at = %at(last, &open),
        "billing-session: a paused sandbox's last records end in a gap, billed running for review"
    );
    Ok(())
}

/// The Pod name the backend recorded, when `environment_id` is `standard`;
/// `None` when it isn't.
async fn standard_pod(
    pool: &PgPool,
    environment_id: &str,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT b.pod_name FROM environments e \
         LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id \
         WHERE e.id = $1 AND e.runtime_profile = 'standard'",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await
}

async fn open_session(pool: &PgPool, runtime_uid: &str) -> Result<Option<Open>, sqlx::Error> {
    type Row = (
        String,
        String,
        Option<i64>,
        Option<i64>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
        DateTime<Utc>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, rate_kind, pause_generation, pause_sequence, paused_seen_at, \
                started_at, last_observed_at \
           FROM sandbox_running_sessions \
          WHERE runtime_type = 'sandbox' AND runtime_uid = $1 AND ended_at IS NULL",
    )
    .bind(runtime_uid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id, kind, generation, sequence, paused_seen_at, started_at, last_observed_at)| Open {
            id,
            session: Session {
                kind: if kind == "paused" {
                    Kind::Paused
                } else {
                    Kind::Running
                },
                mark: generation.zip(sequence).map(|(generation, sequence)| Mark {
                    generation: generation.unsigned_abs(),
                    sequence: sequence.unsigned_abs(),
                }),
                paused_seen_ms: paused_seen_at.map(|at| at.timestamp_millis()),
                started_at_ms: Some(started_at.timestamp_millis()),
            },
            last_observed_at,
        },
    ))
}

/// Where `split` falls: never before the session's last observation, which
/// may already be drawn.
fn at(split: &Split, open: &Open) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(split.at_ms)
        .unwrap_or(open.last_observed_at)
        .max(open.last_observed_at)
}

fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Running => "running",
        Kind::Paused => "paused",
    }
}

/// Writes `splits` of `open` and leaves `session`'s mark on the session
/// open after them. Returns that session's latest observation: the last
/// split, or its own last observation, or its latest paused record.
async fn apply(
    pool: &PgPool,
    open: &Open,
    splits: &[Split],
    session: Session,
) -> anyhow::Result<DateTime<Utc>> {
    let mut transaction = pool.begin().await?;
    // Only the open row this read started from is split.
    let still_open: Option<String> = sqlx::query_scalar(
        "SELECT id FROM sandbox_running_sessions WHERE id = $1 AND ended_at IS NULL FOR UPDATE",
    )
    .bind(&open.id)
    .fetch_optional(&mut *transaction)
    .await?;
    anyhow::ensure!(still_open.is_some(), "the session closed during the read");
    let mut current = open.id.clone();
    let mut observed = open.last_observed_at;
    for split in splits {
        let at = at(split, open);
        sqlx::query(
            "UPDATE sandbox_running_sessions SET ended_at = $2, end_reason = $3, updated_at = now() \
             WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(&current)
        .bind(at)
        .bind(split.reason)
        .execute(&mut *transaction)
        .await?;
        current = sqlx::query_scalar(
            "INSERT INTO sandbox_running_sessions ( \
                 environment_id, organization_id, runtime_type, runtime_uid, runtime_name, \
                 runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_class, \
                 runtime_tier, started_at, last_observed_at, updated_at, rate_kind, review_reason) \
             SELECT environment_id, organization_id, runtime_type, runtime_uid, runtime_name, \
                    runtime_namespace, cpu_millicores, memory_mib, disk_gib, runtime_class, \
                    runtime_tier, $2, $2, now(), $3, $4 \
               FROM sandbox_running_sessions WHERE id = $1 \
             RETURNING id",
        )
        .bind(&current)
        .bind(at)
        .bind(kind(split.kind))
        .bind(split.review.then_some(PAUSE_RECORDS_GAP))
        .fetch_one(&mut *transaction)
        .await?;
        observed = at;
    }
    let paused_seen_at = session
        .paused_seen_ms
        .and_then(DateTime::from_timestamp_millis);
    sqlx::query(
        "UPDATE sandbox_running_sessions \
            SET pause_generation = $2, pause_sequence = $3, paused_seen_at = $4 \
          WHERE id = $1",
    )
    .bind(&current)
    .bind(
        session
            .mark
            .map(|mark| i64::try_from(mark.generation).unwrap_or(i64::MAX)),
    )
    .bind(
        session
            .mark
            .map(|mark| i64::try_from(mark.sequence).unwrap_or(i64::MAX)),
    )
    .bind(paused_seen_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(paused_seen_at.map_or(observed, |seen| seen.max(observed)))
}

#[cfg(test)]
#[path = "pauses/database_tests.rs"]
mod database_tests;
