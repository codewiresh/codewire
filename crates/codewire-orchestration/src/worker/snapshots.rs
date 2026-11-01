//! The activity bodies of a hosted disk snapshot (#3046 H1).
//!
//! Capture: take a raw snapshot of a stopped environment's disk, clear a restore
//! of it in a clearing Sandbox, keep a snapshot of that, delete the rest. Every
//! step is idempotent and keyed by the snapshot's id, so a Temporal retry resumes
//! it. The raw snapshot holds delivered sign-ins whole, so any failure ends in
//! [`abandon_capture`], which retries until it is gone.
//!
//! The environment's row is only ever read here. Holding its lock while the raw
//! snapshot is taken serializes with every lifecycle write the API commits, as
//! [`super::activity_authority::ExternalMutationGuard`] does for other external
//! mutations.

use std::time::Duration;

use anyhow::Context as _;
use sqlx::{PgPool, Row};

use super::WorkerContext;
use super::activity_authority::EXTERNAL_MUTATION_TIMEOUT;
use super::env_data::{load_backend_row, workspace_pvc_anchor};
use crate::sandbox::client::{ClearingProgress, KeptSnapshot, SandboxClient};
use crate::sandbox::snapshots::{
    ClearingOpts, VolumeMode, clearing_volume_name, kept_snapshot_name, quantity_bytes,
    raw_snapshot_name,
};
use crate::sandbox::template::runtime_profile_spec;

/// The source environment wasn't stopped when the raw snapshot was to be taken.
pub const FAILURE_NOT_STOPPED: &str = "environment_not_stopped";
/// The clearing container failed, so nothing is kept.
pub const FAILURE_CLEARING: &str = "clearing_failed";
/// Any other failure, after its retries.
pub const FAILURE_CAPTURE: &str = "capture_failed";

/// How long the clearing container may take to start and finish.
const CLEARING_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// The rate a Block clearing's timeout plans for, if every range fell back to
/// writes: a third of the 80 GiB worst case measured on Dev (211.4 s to write,
/// 32.5 s to read back, 2026-11-01).
const BLOCK_CLEARING_PLANNED_BYTES_PER_SECOND: u64 = 128 * 1024 * 1024;
/// The longest a Block clearing may wait, inside its activity's 30 minutes.
const BLOCK_CLEARING_TIMEOUT_CAP: Duration = Duration::from_secs(25 * 60);
const CLEARING_POLL: Duration = Duration::from_secs(1);
/// How long one Kubernetes teardown or the kept snapshot may take.
const OBJECT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// A capture or delete untouched for this long may have no workflow.
const STRANDED_AFTER_MINUTES: i32 = 15;
/// How long organization deletion waits for captures in progress.
const CAPTURE_SETTLE_LIMIT: Duration = Duration::from_secs(10 * 60);

fn client(ctx: &WorkerContext) -> anyhow::Result<SandboxClient> {
    let kube = ctx
        .kube
        .as_ref()
        .context("hosted snapshots require Kubernetes")?;
    Ok(SandboxClient::new(
        kube.clone(),
        &ctx.sandbox_cfg.sandbox_namespace,
    ))
}

fn snapshot_class(ctx: &WorkerContext) -> anyhow::Result<&str> {
    let class = ctx.sandbox_cfg.volume_snapshot_class.as_str();
    anyhow::ensure!(!class.is_empty(), "hosted snapshots are not configured");
    Ok(class)
}

/// Hold the row's capture open and return its source. An attempt whose heartbeat
/// was lost keeps running after Temporal retries it, and could otherwise create an
/// object after [`abandon_capture`] finished. Every create runs under this share
/// lock; [`abandon_capture`] marks the row first, so it waits for any create in
/// flight, and none starts after it.
async fn lock_capturing(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot_id: &str,
) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT source_environment_id FROM hosted_snapshots
          WHERE id = $1 AND state = 'capturing' FOR SHARE",
    )
    .bind(snapshot_id)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Run one create while the capture is open, bounded because a lock is held.
/// `None` means the capture has settled and nothing was created.
async fn create_while_capturing<F>(
    pool: &PgPool,
    snapshot_id: &str,
    create: F,
) -> anyhow::Result<Option<()>>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    tokio::time::timeout(EXTERNAL_MUTATION_TIMEOUT, async {
        let mut tx = pool.begin().await?;
        if lock_capturing(&mut tx, snapshot_id).await?.is_none() {
            return anyhow::Ok(None);
        }
        create.await?;
        tx.rollback().await?;
        Ok(Some(()))
    })
    .await
    .map_err(|_| anyhow::anyhow!("a capture's create did not finish in time"))?
}

/// The row's source, while its capture is still running. `None` means there is
/// nothing to do, as after a retry of a settled capture.
async fn capturing_source(pool: &PgPool, snapshot_id: &str) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT source_environment_id FROM hosted_snapshots
          WHERE id = $1 AND state = 'capturing'",
    )
    .bind(snapshot_id)
    .fetch_optional(pool)
    .await?)
}

/// A disk may be captured only while nothing has it mounted or is about to. A
/// confidential volume is a raw device only its guest can read.
fn source_capturable(state: &str, desired_state: &str, isolation_tier: &str) -> bool {
    state == "stopped" && desired_state == "stopped" && isolation_tier != "confidential"
}

/// Step 1: under the source's row lock, require it stopped and standard, and take
/// the raw snapshot. Returns a failure code when the source can't be captured.
/// The whole of it runs under one bound, because the lock is held throughout.
pub async fn capture_raw(ctx: &WorkerContext, snapshot_id: &str) -> anyhow::Result<Option<String>> {
    let client = client(ctx)?;
    let class = snapshot_class(ctx)?.to_owned();
    let raw = raw_snapshot_name(snapshot_id);
    tokio::time::timeout(EXTERNAL_MUTATION_TIMEOUT, async {
        let mut tx = ctx.pool.begin().await?;
        let Some(environment_id) = lock_capturing(&mut tx, snapshot_id).await? else {
            return anyhow::Ok(None);
        };
        // NO KEY UPDATE conflicts with every lifecycle write and still lets
        // other connections insert rows that reference the environment, as
        // `ExternalMutationGuard` does.
        let row = sqlx::query(
            "SELECT state, desired_state, isolation_tier
               FROM environments WHERE id = $1 FOR NO KEY UPDATE",
        )
        .bind(&environment_id)
        .fetch_optional(&mut *tx)
        .await?;
        let capturable = row.is_some_and(|row| {
            source_capturable(
                &row.get::<String, _>("state"),
                &row.get::<String, _>("desired_state"),
                &row.get::<String, _>("isolation_tier"),
            )
        });
        if !capturable {
            return Ok(Some(FAILURE_NOT_STOPPED.to_owned()));
        }
        let backend = load_backend_row(&ctx.pool, &environment_id).await?;
        let storage = client
            .workspace_storage(&workspace_pvc_anchor(&backend))
            .await?;
        // A confidential source never reaches here (`source_capturable`), so
        // a Block source is a commodity one the guest formats.
        let source_mode = if storage.raw_block {
            VolumeMode::Block
        } else {
            VolumeMode::Filesystem
        };
        client
            .ensure_volume_snapshot(
                &raw,
                snapshot_id,
                &storage.pvc_name,
                &class,
                Some(source_mode),
            )
            .await?;
        // The lock is held until the snapshot exists, so a start can't mount the
        // disk under it. Measured at about 1.2 s.
        client
            .wait_for_volume_snapshot(&raw, EXTERNAL_MUTATION_TIMEOUT)
            .await?;
        tx.rollback().await?;
        Ok(None)
    })
    .await
    .map_err(|_| anyhow::anyhow!("the raw snapshot was not taken in time"))?
}

/// Step 2: clear a restore of the raw snapshot.
pub async fn run_clearing(
    ctx: &WorkerContext,
    snapshot_id: &str,
) -> anyhow::Result<Option<String>> {
    let client = client(ctx)?;
    let Some(environment_id) = capturing_source(&ctx.pool, snapshot_id).await? else {
        return Ok(None);
    };
    let raw = raw_snapshot_name(snapshot_id);
    let restore_size = client
        .wait_for_volume_snapshot(&raw, EXTERNAL_MUTATION_TIMEOUT)
        .await?;
    let volume_mode = client.raw_snapshot_volume_mode(snapshot_id).await?;
    let cfg = &ctx.sandbox_cfg;
    let runtime = runtime_profile_spec(&cfg.runtime_profile, &cfg.docker_mode, cfg.dind_enabled);
    let backend = load_backend_row(&ctx.pool, &environment_id).await;
    // The source's storage class, when it is still there; a source destroyed
    // since the raw snapshot restores into the deployment's class.
    let storage_class = match backend {
        Ok(backend) => client
            .workspace_storage(&workspace_pvc_anchor(&backend))
            .await
            .map(|storage| storage.storage_class_name)
            .unwrap_or_else(|_| cfg.workspace_storage_class.clone()),
        Err(_) => cfg.workspace_storage_class.clone(),
    };
    let opts = ClearingOpts {
        namespace: &cfg.sandbox_namespace,
        snapshot_id,
        support_image: cfg.support_image(),
        runtime_class: &runtime.runtime_class_name,
        storage_class: &storage_class,
        restore_size: &restore_size,
        volume_mode,
    };
    if create_while_capturing(
        &ctx.pool,
        snapshot_id,
        client.ensure_clearing_sandbox(&opts),
    )
    .await?
    .is_none()
    {
        return Ok(None);
    }
    let wait = async {
        loop {
            match client.clearing_progress(snapshot_id).await? {
                ClearingProgress::Succeeded { report } => {
                    log_clearing_report(snapshot_id, volume_mode, report.as_deref());
                    return anyhow::Ok(None);
                }
                ClearingProgress::Failed => return Ok(Some(FAILURE_CLEARING.to_owned())),
                ClearingProgress::Pending => tokio::time::sleep(CLEARING_POLL).await,
            }
        }
    };
    let restore_bytes = quantity_bytes(&restore_size).and_then(|bytes| u64::try_from(bytes).ok());
    let timeout = clearing_timeout(volume_mode, restore_bytes);
    tokio::time::timeout(timeout, wait).await.map_err(|_| match volume_mode {
        VolumeMode::Filesystem => anyhow::anyhow!("clearing did not finish in time"),
        VolumeMode::Block => anyhow::anyhow!(
            "clearing a {restore_size} Block restore did not finish within {} s, planned at {} MiB/s of writes beyond {} s",
            timeout.as_secs(),
            BLOCK_CLEARING_PLANNED_BYTES_PER_SECOND / (1024 * 1024),
            CLEARING_TIMEOUT.as_secs()
        ),
    })?
}

/// A Filesystem clearing touches files only. A Block clearing may overwrite
/// all of its free space when discards don't clear it, so it is given time for
/// that at the planned rate, within the cap. A size that can't be read takes
/// the cap.
fn clearing_timeout(volume_mode: VolumeMode, restore_bytes: Option<u64>) -> Duration {
    match volume_mode {
        VolumeMode::Filesystem => CLEARING_TIMEOUT,
        VolumeMode::Block => restore_bytes
            .map(|bytes| {
                CLEARING_TIMEOUT
                    + Duration::from_secs(bytes / BLOCK_CLEARING_PLANNED_BYTES_PER_SECOND)
            })
            .unwrap_or(BLOCK_CLEARING_TIMEOUT_CAP)
            .min(BLOCK_CLEARING_TIMEOUT_CAP),
    }
}

/// Log a Block clearing's report (`cw __snapshot-clear --block`), a warning
/// when any range was overwritten because discards didn't clear it: such a
/// capture takes minutes rather than seconds, and that has to show.
fn log_clearing_report(snapshot_id: &str, volume_mode: VolumeMode, report: Option<&str>) {
    if volume_mode != VolumeMode::Block {
        return;
    }
    let Some(report) = report else {
        tracing::warn!(
            snapshot_id,
            "hosted snapshot: Block clearing left no report"
        );
        return;
    };
    let field = |name: &str| {
        report
            .split_whitespace()
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or("?")
    };
    let (ranges, discard, fallback, written, ms) = (
        field("ranges"),
        field("discard"),
        field("fallback"),
        field("written"),
        field("ms"),
    );
    if discard != "true" || fallback != "0" {
        tracing::warn!(
            snapshot_id,
            ranges,
            discard,
            fallback_ranges = fallback,
            written_bytes = written,
            ms,
            "hosted snapshot: Block clearing overwrote free space because discards didn't clear it"
        );
    } else {
        tracing::info!(
            snapshot_id,
            ranges,
            fallback_ranges = fallback,
            written_bytes = written,
            ms,
            "hosted snapshot: Block clearing discarded its free space"
        );
    }
}

/// Step 3: once the clearing Pod is gone, take the kept snapshot and record it.
/// The row turns `ready` only after everything else is deleted, in the same
/// activity, so `ready` means the raw snapshot is gone.
pub async fn keep_and_finish(ctx: &WorkerContext, snapshot_id: &str) -> anyhow::Result<()> {
    let client = client(ctx)?;
    let class = snapshot_class(ctx)?.to_owned();
    if capturing_source(&ctx.pool, snapshot_id).await?.is_none() {
        return Ok(());
    }
    let kept = kept_snapshot_name(snapshot_id);
    client
        .stop_clearing_pod(snapshot_id, OBJECT_TIMEOUT)
        .await?;
    if create_while_capturing(
        &ctx.pool,
        snapshot_id,
        client.ensure_volume_snapshot(
            &kept,
            snapshot_id,
            &clearing_volume_name(snapshot_id),
            &class,
            None,
        ),
    )
    .await?
    .is_none()
    {
        return Ok(());
    }
    let restore_size = client
        .wait_for_volume_snapshot(&kept, OBJECT_TIMEOUT)
        .await?;
    client
        .delete_capture_objects(snapshot_id, KeptSnapshot::Retain, OBJECT_TIMEOUT)
        .await?;
    sqlx::query(
        "UPDATE hosted_snapshots
            SET state = 'ready', size_bytes = $2, updated_at = now()
          WHERE id = $1 AND state = 'capturing'",
    )
    .bind(snapshot_id)
    .bind(quantity_bytes(&restore_size))
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Close a failed capture, then delete everything it made. The row turns `failed`
/// first, so no attempt still running can create anything after the deletes (see
/// [`lock_capturing`]). The workflow retries this until it succeeds, so the raw
/// snapshot never outlives a capture. A capture that finished, whose last attempt
/// only failed to report it, keeps its snapshot.
pub async fn abandon_capture(
    ctx: &WorkerContext,
    snapshot_id: &str,
    failure_code: &str,
) -> anyhow::Result<()> {
    if !mark_failed(&ctx.pool, snapshot_id, failure_code).await? {
        return Ok(());
    }
    client(ctx)?
        .delete_capture_objects(snapshot_id, KeptSnapshot::Delete, OBJECT_TIMEOUT)
        .await
}

/// Whether the capture is `failed`, by this call or an earlier attempt's.
async fn mark_failed(pool: &PgPool, snapshot_id: &str, failure_code: &str) -> anyhow::Result<bool> {
    sqlx::query(
        "UPDATE hosted_snapshots
            SET state = 'failed', failure_code = $2, updated_at = now()
          WHERE id = $1 AND state = 'capturing'",
    )
    .bind(snapshot_id)
    .bind(failure_code)
    .execute(pool)
    .await?;
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM hosted_snapshots WHERE id = $1")
            .bind(snapshot_id)
            .fetch_optional(pool)
            .await?;
    Ok(state.as_deref() == Some("failed"))
}

/// Delete a snapshot's objects, then its row.
pub async fn delete_snapshot(ctx: &WorkerContext, snapshot_id: &str) -> anyhow::Result<()> {
    client(ctx)?
        .delete_capture_objects(snapshot_id, KeptSnapshot::Delete, OBJECT_TIMEOUT)
        .await?;
    sqlx::query("DELETE FROM hosted_snapshots WHERE id = $1 AND state = 'deleting'")
        .bind(snapshot_id)
        .execute(&ctx.pool)
        .await?;
    Ok(())
}

/// The leader's sweep: mark a deleted creator's snapshots for deletion, and
/// restart any capture or delete that has gone quiet. Starting a workflow that
/// is running changes nothing, so a slow capture is unaffected.
pub async fn reconcile_snapshots(ctx: &WorkerContext) -> anyhow::Result<()> {
    for (snapshot_id, state) in unsettled_snapshots(&ctx.pool).await? {
        let started = if state == "capturing" {
            ctx.temporal_trigger
                .trigger_snapshot_capture(&snapshot_id)
                .await
        } else {
            ctx.temporal_trigger
                .trigger_snapshot_delete(&snapshot_id)
                .await
        };
        if let Err(error) = started {
            tracing::warn!(snapshot_id, error = %error, "hosted snapshot: restart failed");
        }
    }
    Ok(())
}

/// Mark a deleted creator's snapshots for deletion, already overdue, and return
/// every capture or delete that has gone quiet.
async fn unsettled_snapshots(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    sqlx::query(
        "UPDATE hosted_snapshots
            SET state = 'deleting', updated_at = now() - make_interval(mins => $1)
          WHERE state IN ('ready', 'failed')
            AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = hosted_snapshots.created_by)",
    )
    .bind(STRANDED_AFTER_MINUTES)
    .execute(pool)
    .await?;
    Ok(sqlx::query_as(
        "SELECT id, state FROM hosted_snapshots
          WHERE state IN ('capturing', 'deleting')
            AND updated_at <= now() - make_interval(mins => $1)",
    )
    .bind(STRANDED_AFTER_MINUTES)
    .fetch_all(pool)
    .await?)
}

/// Organization deletion: wait for captures in progress, then delete every
/// snapshot's objects and row. Part of the environments phase, so it finishes
/// before the organization's row goes; its foreign key has no cascade.
pub async fn delete_organization_snapshots(
    ctx: &WorkerContext,
    organization_id: &str,
) -> anyhow::Result<usize> {
    let deadline = tokio::time::Instant::now() + CAPTURE_SETTLE_LIMIT;
    loop {
        let capturing: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM hosted_snapshots WHERE org_id = $1 AND state = 'capturing'",
        )
        .bind(organization_id)
        .fetch_one(&ctx.pool)
        .await?;
        if capturing == 0 {
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "organization snapshot captures have not settled"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let snapshots: Vec<String> = sqlx::query_scalar(
        "UPDATE hosted_snapshots SET state = 'deleting', updated_at = now()
          WHERE org_id = $1 RETURNING id",
    )
    .bind(organization_id)
    .fetch_all(&ctx.pool)
    .await?;
    for snapshot_id in &snapshots {
        delete_snapshot(ctx, snapshot_id).await?;
    }
    Ok(snapshots.len())
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    #[test]
    fn a_block_clearing_has_time_to_overwrite_its_volume_and_never_outlives_its_activity() {
        const GIB: u64 = 1 << 30;
        assert_eq!(
            clearing_timeout(VolumeMode::Filesystem, Some(80 * GIB)),
            CLEARING_TIMEOUT
        );
        // 80 GiB at 128 MiB/s is 640 s, against 244 s measured on Dev.
        assert_eq!(
            clearing_timeout(VolumeMode::Block, Some(80 * GIB)),
            Duration::from_secs(300 + 640)
        );
        assert_eq!(
            clearing_timeout(VolumeMode::Block, Some(200 * GIB)),
            BLOCK_CLEARING_TIMEOUT_CAP
        );
        assert_eq!(
            clearing_timeout(VolumeMode::Block, None),
            BLOCK_CLEARING_TIMEOUT_CAP
        );
        assert!(BLOCK_CLEARING_TIMEOUT_CAP < Duration::from_secs(30 * 60));
    }

    #[test]
    fn only_a_stopped_standard_environment_may_be_captured() {
        assert!(source_capturable("stopped", "stopped", "standard"));
        for (state, desired, tier) in [
            ("running", "running", "standard"),
            ("stopped", "running", "standard"),
            ("stopping", "stopped", "standard"),
            ("stopped", "destroyed", "standard"),
            ("destroyed", "destroyed", "standard"),
            ("stopped", "stopped", "confidential"),
        ] {
            assert!(
                !source_capturable(state, desired, tier),
                "{state} {desired} {tier}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_the_sweep_finds_quiet_work_and_a_deleted_creators_snapshots_only() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user = format!("user_snapshot_sweep_{suffix}");
        let org = format!("org-sweep-{suffix}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user)
            .bind(format!("{user}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $1, $2)",
        )
        .bind(&org)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
        let gone = format!("deleted-user-{suffix}");
        let rows = [
            ("quiet-capture", &user, "capturing", None, 60),
            ("busy-capture", &user, "capturing", None, 0),
            ("quiet-delete", &user, "deleting", None, 60),
            ("kept", &user, "ready", None, 60),
            ("failed", &user, "failed", Some("capture_failed"), 60),
            ("orphan-ready", &gone, "ready", None, 0),
            ("orphan-failed", &gone, "failed", Some("capture_failed"), 0),
            ("orphan-capture", &gone, "capturing", None, 0),
        ];
        for (name, creator, state, failure, age_minutes) in rows {
            sqlx::query(
                "INSERT INTO hosted_snapshots
                   (id, org_id, created_by, source_environment_id, name, state, failure_code,
                    updated_at)
                 VALUES ($1, $2, $3, 'env', $4, $5, $6, now() - make_interval(mins => $7))",
            )
            .bind(format!("{name}-{suffix}"))
            .bind(&org)
            .bind(creator)
            .bind(name)
            .bind(state)
            .bind(failure)
            .bind(age_minutes)
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut found: Vec<(String, String)> = unsettled_snapshots(&pool)
            .await
            .unwrap()
            .into_iter()
            .filter(|(id, _)| id.ends_with(&suffix))
            .map(|(id, state)| (id.trim_end_matches(&format!("-{suffix}")).to_owned(), state))
            .collect();
        found.sort();
        let expected = [
            ("orphan-failed", "deleting"),
            ("orphan-ready", "deleting"),
            ("quiet-capture", "capturing"),
            ("quiet-delete", "deleting"),
        ]
        .map(|(id, state)| (id.to_owned(), state.to_owned()));
        assert_eq!(found, expected);

        // Its creator's own settled snapshots are untouched.
        let kept: String = sqlx::query_scalar("SELECT state FROM hosted_snapshots WHERE id = $1")
            .bind(format!("kept-{suffix}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kept, "ready");

        // A failed capture admits no further create; a finished one stays ready.
        let quiet = format!("quiet-capture-{suffix}");
        let ran = create_while_capturing(&pool, &quiet, async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(ran, Some(()));
        assert!(mark_failed(&pool, &quiet, FAILURE_CAPTURE).await.unwrap());
        assert!(
            mark_failed(&pool, &quiet, FAILURE_CLEARING).await.unwrap(),
            "a retried abandonment still deletes"
        );
        let code: Option<String> =
            sqlx::query_scalar("SELECT failure_code FROM hosted_snapshots WHERE id = $1")
                .bind(&quiet)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(code.as_deref(), Some(FAILURE_CAPTURE));
        let ran = create_while_capturing(&pool, &quiet, async {
            panic!("no create runs once the capture has settled")
        })
        .await
        .unwrap();
        assert_eq!(ran, None);
        assert!(
            !mark_failed(&pool, &format!("kept-{suffix}"), FAILURE_CAPTURE)
                .await
                .unwrap(),
            "a capture that finished keeps its snapshot"
        );

        sqlx::query("DELETE FROM hosted_snapshots WHERE org_id = $1")
            .bind(&org)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
