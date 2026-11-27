//! What a create from a snapshot may be, and its admission.

use super::*;

/// What a create from a snapshot can't be, checked before anything is written.
/// Confidential environments never have snapshots (owner, 2026-10-29). A
/// repository would be cloned over the restored checkout, which fails.
pub(super) fn validate_source_snapshot_request(
    body: &CreateEnvironmentBody,
    isolation_tier: &str,
    volume_snapshot_class: &str,
) -> AppResult<()> {
    let Some(snapshot_id) = body.source_snapshot_id.as_deref() else {
        return Ok(());
    };
    if snapshot_id.trim().is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_source_snapshot",
            "source_snapshot_id must name a snapshot",
        ));
    }
    if volume_snapshot_class.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "snapshots_unavailable",
            "this deployment does not offer hosted snapshots",
        ));
    }
    if isolation_tier == "confidential" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "snapshot_source_confidential",
            "a confidential environment cannot start from a snapshot",
        ));
    }
    if !body.project_spec.repositories.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "snapshot_source_repository",
            "an environment started from a snapshot takes its files from the snapshot, not a repository",
        ));
    }
    Ok(())
}

/// A snapshot's size in whole GiB, rounded up: the smallest disk it restores to.
fn snapshot_disk_gib(size_bytes: i64) -> u64 {
    u64::try_from(size_bytes).unwrap_or(0).div_ceil(1 << 30)
}

/// A create from a snapshot whose request names no disk gets at least the
/// snapshot's size, so a plain restore of a disk larger than the default works
/// (#6276). A snapshot it can't read is left to the admission to refuse.
pub(super) async fn fit_disk_to_source_snapshot(
    pool: &PgPool,
    org_id: &str,
    user_id: &str,
    body: &mut CreateEnvironmentBody,
) -> AppResult<()> {
    let Some(snapshot_id) = body.source_snapshot_id.as_deref() else {
        return Ok(());
    };
    let size_bytes: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT size_bytes FROM hosted_snapshots
          WHERE id = $1 AND org_id = $2 AND created_by = $3 AND state = 'ready'",
    )
    .bind(snapshot_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    if let Some(size_bytes) = size_bytes.flatten() {
        let disk_gib = body.project_spec.resources.disk_gib.get_or_insert(0);
        *disk_gib = (*disk_gib).max(snapshot_disk_gib(size_bytes));
    }
    Ok(())
}

/// A snapshot is private to its creator, so another member's reads as absent.
/// The share lock holds off a delete until this create commits, and a use of a
/// snapshot counts toward its expiry in the transaction that authorizes it.
/// Admitted, it answers the idle stop its source had when it was captured,
/// which a fork takes unless its create names one (#3384).
/// A ready snapshot's row, as a create from it reads it.
#[derive(sqlx::FromRow)]
struct SourceSnapshotRow {
    state: String,
    size_bytes: Option<i64>,
    idle_stop_seconds: Option<i32>,
    idle_suspend_seconds: Option<i32>,
    idle_hibernate_seconds: Option<i32>,
}

/// The source's timeouts when it was captured, which a fork takes unless its
/// create names its own. `None` for a snapshot captured before each existed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SnapshotTimeouts {
    pub(crate) idle_stop_seconds: Option<i32>,
    pub(crate) idle_suspend_seconds: Option<i32>,
    pub(crate) idle_hibernate_seconds: Option<i32>,
}

pub(crate) async fn admit_source_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    user_id: &str,
    snapshot_id: &str,
    disk_gib: i32,
) -> AppResult<SnapshotTimeouts> {
    let row: Option<SourceSnapshotRow> = sqlx::query_as(
        "SELECT state, size_bytes, idle_stop_seconds, idle_suspend_seconds, idle_hibernate_seconds FROM hosted_snapshots
          WHERE id = $1 AND org_id = $2 AND created_by = $3
          FOR SHARE",
    )
    .bind(snapshot_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(SourceSnapshotRow {
        state: snapshot_state,
        size_bytes,
        idle_stop_seconds,
        idle_suspend_seconds,
        idle_hibernate_seconds,
    }) = row
    else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "snapshot_not_found",
            "no such snapshot",
        ));
    };
    if snapshot_state != "ready" {
        return Err(coded(
            StatusCode::CONFLICT,
            "snapshot_not_ready",
            "this snapshot is not ready",
        ));
    }
    if size_bytes.unwrap_or(0) > i64::from(disk_gib) * (1 << 30) {
        return Err(crate::api::environments::coded_owned(
            StatusCode::BAD_REQUEST,
            "snapshot_disk_too_small",
            format!(
                "the disk must be at least as large as the snapshot, {} GiB",
                snapshot_disk_gib(size_bytes.unwrap_or(0))
            ),
        ));
    }
    sqlx::query("UPDATE hosted_snapshots SET last_used_at = now() WHERE id = $1")
        .bind(snapshot_id)
        .execute(&mut **transaction)
        .await?;
    Ok(SnapshotTimeouts {
        idle_stop_seconds,
        idle_suspend_seconds,
        idle_hibernate_seconds,
    })
}
