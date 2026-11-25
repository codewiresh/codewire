//! What cw-egress reports, stored (#4000, P2b; migration 0030): what each
//! sandbox Pod enforces, and each environment's folded egress records.
//!
//! A Pod's environment is written only by the bind transaction
//! ([`record_bind`]), or taken back from the live binding when a row is
//! re-created; a report never names one. Records are kept for the
//! environment the bind recorded, at most [`EGRESS_RECORD_LIMIT`] of them,
//! and each refused one is also a `refused` event in the environment's audit
//! log ([`audit`]), written in the same transaction.
//!
//! One column is orchestration's own (migration 0033, #5068): the lockdown
//! check's refusal of the Pod. No report writes it, and it outlives every
//! report until [`clear_lockdown_refusal`], a bind elsewhere or the release.

use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::EGRESS_RECORD_LIMIT;
use sqlx::{PgConnection, PgPool};
use thiserror::Error;

use super::lockdown::LockdownRefusal;

/// The most records one `ReportRecords` call may carry.
pub const MAX_RECORDS_PER_REPORT: usize = 256;
/// The highest revision a stored policy reaches (`MAX_REVISIONS`).
pub const MAX_POLICY_REVISION: i32 = 10_000;
/// A policy reference: `platform:id:UUID` or a name, well within this.
pub const MAX_REFERENCE_LEN: usize = 256;
/// The longest IP address text.
pub const MAX_ADDRESS_LEN: usize = 64;

/// What a Pod enforces, as cw-egress reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    Enforced { revision: u32, digest: [u8; 32] },
    FailedClosed { detail: FailureCode },
    Disconnected,
}

/// The fixed codes a fail-closed report may carry; anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCode {
    SelfCheckFailed,
    PolicyDigestMismatch,
}

impl FailureCode {
    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "self_check_failed" => Some(Self::SelfCheckFailed),
            "policy_digest_mismatch" => Some(Self::PolicyDigestMismatch),
            _ => None,
        }
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::SelfCheckFailed => "self_check_failed",
            Self::PolicyDigestMismatch => "policy_digest_mismatch",
        }
    }
}

/// What a record was about, as orchestration keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportedDestination {
    /// A name that passed the host check.
    Name(String),
    /// An address no name leads to.
    Address(String),
    /// A name that failed the host check: counted, never its text. Only the
    /// audit log keeps it; the records table names every row.
    Withheld,
}

/// One folded record as cw-egress reported it. Its count is a delta: the
/// observations since cw-egress last reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedRecord {
    pub destination: ReportedDestination,
    pub address: Option<String>,
    pub transport: Transport,
    pub outcome: Option<RefusalReason>,
    pub policy_reference: String,
    pub policy_revision: u32,
    pub policy_digest: [u8; 32],
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Dns,
    Tcp { port: u16 },
    Udp { port: u16 },
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("store egress reports: {0}")]
    Store(#[from] sqlx::Error),
    #[error("a report carries more than {MAX_RECORDS_PER_REPORT} records")]
    TooManyRecords,
    #[error("a record's times or count are out of range")]
    InvalidRecord,
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
}

/// The bind transaction's part: the Pod now serves `environment_id`, and
/// the bind is announced. An existing report keeps its state; a Pod that has
/// not reported yet starts disconnected. The environment's other Pods' rows
/// go: a re-placed environment's earlier Pod no longer describes it.
pub async fn record_bind(
    tx: &mut PgConnection,
    pod_uid: &str,
    environment_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM sandbox_egress_enforcement WHERE environment_id = $2 AND pod_uid <> $1",
    )
    .bind(pod_uid)
    .bind(environment_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_egress_enforcement (pod_uid, environment_id, node, state)
         VALUES ($1, $2, '', 'disconnected')
         ON CONFLICT (pod_uid) DO UPDATE SET environment_id = EXCLUDED.environment_id,
            lockdown_refusal = CASE
                WHEN sandbox_egress_enforcement.environment_id IS DISTINCT FROM EXCLUDED.environment_id
                THEN NULL ELSE sandbox_egress_enforcement.lockdown_refusal END",
    )
    .bind(pod_uid)
    .bind(environment_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(crate::workspace_binding::WORKSPACE_BINDINGS_CHANNEL)
        .bind(pod_uid)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// The unbind's part: the Pod no longer serves an environment.
pub async fn release_pod(tx: &mut PgConnection, pod_uid: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sandbox_egress_enforcement WHERE pod_uid = $1")
        .bind(pod_uid)
        .execute(tx)
        .await?;
    Ok(())
}

/// Records that the lockdown check refused `pod_uid` and ended its stream, so
/// the environment's status reads `FAILED_CLOSED` whatever cw-egress reports
/// after. The environment comes from the live binding, as for a report.
pub async fn record_lockdown_refusal(
    pool: &PgPool,
    pod_uid: &str,
    refusal: &LockdownRefusal,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sandbox_egress_enforcement
            (pod_uid, environment_id, node, state, lockdown_refusal)
         VALUES ($1, (SELECT environment_id FROM sandbox_workspace_bindings
                       WHERE pod_uid = $1 AND released_at IS NULL),
                 '', 'disconnected', $2)
         ON CONFLICT (pod_uid) DO UPDATE SET lockdown_refusal = EXCLUDED.lockdown_refusal",
    )
    .bind(pod_uid)
    .bind(refusal.reason())
    .execute(pool)
    .await?;
    Ok(())
}

/// The Pod's lockdown check passed: an earlier refusal no longer describes it.
pub async fn clear_lockdown_refusal(pool: &PgPool, pod_uid: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sandbox_egress_enforcement SET lockdown_refusal = NULL
          WHERE pod_uid = $1 AND lockdown_refusal IS NOT NULL",
    )
    .bind(pod_uid)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records what `pod_uid` enforces, reported from `node`. The environment is
/// left as the bind transaction wrote it.
///
/// The last write wins, stamped with the server's `now()`. That is ordered
/// only because cw-egress sends one Pod's reports serially on one call path; a
/// sender that reports one Pod in parallel must add a sequence number here.
pub async fn record_enforcement(
    pool: &PgPool,
    pod_uid: &str,
    node: &str,
    enforcement: &Enforcement,
) -> Result<(), ReportError> {
    let (state, revision, digest, detail) = match enforcement {
        Enforcement::Enforced { revision, digest } => (
            "enforced",
            Some(
                i32::try_from(*revision)
                    .ok()
                    .filter(|revision| *revision <= MAX_POLICY_REVISION)
                    .ok_or(ReportError::InvalidRecord)?,
            ),
            Some(digest.to_vec()),
            "",
        ),
        Enforcement::FailedClosed { detail } => ("failed_closed", None, None, detail.code()),
        Enforcement::Disconnected => ("disconnected", None, None, ""),
    };
    // A row the sweep removed while its Pod stayed bound takes its
    // environment back from the live binding, orchestration's own record,
    // never from the report.
    sqlx::query(
        "INSERT INTO sandbox_egress_enforcement
            (pod_uid, environment_id, node, state, revision, digest, detail)
         VALUES ($1, (SELECT environment_id FROM sandbox_workspace_bindings
                       WHERE pod_uid = $1 AND released_at IS NULL),
                 $2, $3, $4, $5, $6)
         ON CONFLICT (pod_uid) DO UPDATE
            SET environment_id = COALESCE(sandbox_egress_enforcement.environment_id,
                                          EXCLUDED.environment_id),
                node = EXCLUDED.node, state = EXCLUDED.state, revision = EXCLUDED.revision,
                digest = EXCLUDED.digest, detail = EXCLUDED.detail, reported_at = now()",
    )
    .bind(pod_uid)
    .bind(node)
    .bind(state)
    .bind(revision)
    .bind(digest)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Folds `records` into the environment `pod_uid` was bound to, then trims
/// the environment to [`EGRESS_RECORD_LIMIT`], least recently seen first.
/// Returns false, storing nothing, when the Pod is not bound to an
/// environment: an unbound warm member has no log.
pub async fn record_records(
    pool: &PgPool,
    pod_uid: &str,
    records: &[ReportedRecord],
) -> Result<bool, ReportError> {
    if records.len() > MAX_RECORDS_PER_REPORT {
        return Err(ReportError::TooManyRecords);
    }
    let mut tx = pool.begin().await?;
    let environment: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT s.environment_id, e.org_id FROM sandbox_egress_enforcement s \
           LEFT JOIN environments e ON e.id = s.environment_id \
          WHERE s.pod_uid = $1",
    )
    .bind(pod_uid)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((Some(environment), Some(org))) = environment else {
        // An unbound warm member has no log. Visible, never silent.
        tracing::info!(
            pod_uid,
            records = records.len(),
            "egress records dropped: the Pod serves no environment"
        );
        return Ok(false);
    };
    // A reporter's clock never puts a record in the future.
    let now = chrono::Utc::now();
    let mut names = audit::PolicyNames::default();
    for record in records {
        let (transport, port) = match record.transport {
            Transport::Dns => ("dns", 0_i32),
            Transport::Tcp { port } => ("tcp", i32::from(port)),
            Transport::Udp { port } => ("udp", i32::from(port)),
        };
        let (outcome, reason) = match record.outcome {
            None => ("passed", ""),
            Some(reason) => ("refused", reason.code()),
        };
        let first = unix_ms(record.first_seen_unix_ms)?;
        let last = unix_ms(record.last_seen_unix_ms)?;
        let count = i64::try_from(record.count).map_err(|_| ReportError::InvalidRecord)?;
        if first > last
            || count < 1
            || record.policy_revision > MAX_POLICY_REVISION.unsigned_abs()
            || record.policy_reference.len() > MAX_REFERENCE_LEN
            || record
                .address
                .as_ref()
                .is_some_and(|address| address.len() > MAX_ADDRESS_LEN)
        {
            return Err(ReportError::InvalidRecord);
        }
        let (first, last) = (first.min(now), last.min(now));
        if record.outcome.is_some() {
            let policy = names.name(&mut tx, &org, &record.policy_reference).await?;
            if let Some(event) = audit::refused(&org, &environment, record, policy, first, last) {
                crate::audit::record(&mut tx, &event).await?;
            }
        }
        let (destination, destination_is_name) = match &record.destination {
            ReportedDestination::Name(name) => (name, true),
            ReportedDestination::Address(address) => (address, false),
            ReportedDestination::Withheld => continue,
        };
        sqlx::query(
            "INSERT INTO environment_egress_records
                (environment_id, destination, destination_is_name, transport, port, outcome,
                 reason, address, policy_reference, policy_revision, policy_digest,
                 first_seen, last_seen, count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (environment_id, destination, transport, port, outcome, reason)
             DO UPDATE SET
                address = COALESCE(EXCLUDED.address, environment_egress_records.address),
                policy_reference = EXCLUDED.policy_reference,
                policy_revision = EXCLUDED.policy_revision,
                policy_digest = EXCLUDED.policy_digest,
                first_seen = LEAST(environment_egress_records.first_seen, EXCLUDED.first_seen),
                last_seen = LEAST(GREATEST(environment_egress_records.last_seen,
                                           EXCLUDED.last_seen), now()),
                count = environment_egress_records.count + EXCLUDED.count",
        )
        .bind(&environment)
        .bind(destination)
        .bind(destination_is_name)
        .bind(transport)
        .bind(port)
        .bind(outcome)
        .bind(reason)
        .bind(&record.address)
        .bind(&record.policy_reference)
        .bind(i32::try_from(record.policy_revision).map_err(|_| ReportError::InvalidRecord)?)
        .bind(record.policy_digest.to_vec())
        .bind(first)
        .bind(last)
        .bind(count)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM environment_egress_records r
          WHERE r.environment_id = $1
            AND (r.destination, r.transport, r.port, r.outcome, r.reason) IN (
                SELECT destination, transport, port, outcome, reason
                  FROM environment_egress_records
                 WHERE environment_id = $1
                 ORDER BY last_seen DESC
                OFFSET $2)",
    )
    .bind(&environment)
    .bind(i64::try_from(EGRESS_RECORD_LIMIT).map_err(|_| ReportError::InvalidRecord)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// How long an unbound Pod's row lives without a report. cw-egress must
/// refresh every live Pod's report every 5 minutes, idle or not (a stated
/// requirement of the cw-egress binary, with its own test), so only a Pod that
/// is gone goes quiet this long. Never stretch that refresh towards this bound.
pub const UNBOUND_REPORT_TTL_SECONDS: i64 = 30 * 60;

/// Deletes the rows of identity-free warm members that are gone, without
/// listing Pods: an unbound row after [`UNBOUND_REPORT_TTL_SECONDS`] without
/// a report. cw-egress refreshes every live Pod's report every 5 minutes, so
/// a live member's row never ages that far; a bound row goes with its unbind,
/// its re-placement or its environment.
pub async fn sweep(pool: &PgPool) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM sandbox_egress_enforcement
          WHERE environment_id IS NULL AND reported_at < now() - make_interval(secs => $1)",
    )
    .bind(UNBOUND_REPORT_TTL_SECONDS)
    .execute(pool)
    .await?
    .rows_affected())
}

fn unix_ms(ms: u64) -> Result<chrono::DateTime<chrono::Utc>, ReportError> {
    let ms = i64::try_from(ms).map_err(|_| ReportError::InvalidRecord)?;
    chrono::DateTime::from_timestamp_millis(ms).ok_or(ReportError::InvalidRecord)
}

mod audit;
#[cfg(test)]
mod database_tests;
