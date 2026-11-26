//! Disposable-PostgreSQL proof that the session loop splits a `standard`
//! Sandbox's session at its runtime's pause records (#5529,
//! `docs/dev/BILLING.md`, "A suspended stretch"). Only synthetic rows in an
//! isolated test database are used.

use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, SubsecRound, Utc};
use sqlx::PgPool;

use super::super::database_tests::{ENV, SANDBOX, bind, member, seed_profile};
use super::super::{Phase, reconcile};
use crate::runtime::fake::FakeRuntimeDriver;
use crate::test_database_support::TestDatabase;

const POD_NAME: &str = "cw-pool-1000m-4096mi-10gi-78909fe3-x7k2p";

/// A bound `standard` Sandbox with an open running session last observed
/// ten minutes ago; returns that time.
async fn standard_session(db: &TestDatabase, runtime: &FakeRuntimeDriver) -> Result<DateTime<Utc>> {
    seed_profile(db, "standard").await?;
    bind(&db.pool).await?;
    sqlx::query("UPDATE sandbox_environment_backend SET pod_name = $2 WHERE environment_id = $1")
        .bind(ENV)
        .bind(POD_NAME)
        .execute(&db.pool)
        .await?;
    // No open session yet: it opens running at bind, unread.
    reconcile(&db.pool, runtime, &member(Phase::Running, "")).await;
    let observed = (Utc::now() - Duration::minutes(10)).trunc_subsecs(3);
    sqlx::query(
        "UPDATE sandbox_running_sessions SET started_at = $2 - interval '1 minute', \
                last_observed_at = $2 \
          WHERE environment_id = $1",
    )
    .bind(ENV)
    .bind(observed)
    .execute(&db.pool)
    .await?;
    ensure!(
        rows(&db.pool).await?.len() == 1,
        "one session opened at bind"
    );
    Ok(observed)
}

fn line(logged: DateTime<Utc>, text: &str) -> String {
    format!(
        "{} {text}\n",
        logged.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    )
}

fn pause(logged: DateTime<Utc>, event: &str, sequence: u64) -> String {
    line(
        logged,
        &format!(
            "standard runtime: vm-pause-record {{\"event\":\"{event}\",\"generation\":1,\
             \"sequence\":{sequence},\"at_unix_ms\":{}}}",
            logged.timestamp_millis()
        ),
    )
}

fn state(logged: DateTime<Utc>, state: &str, sequence: u64, since: DateTime<Utc>) -> String {
    line(
        logged,
        &format!(
            "standard runtime: vm-pause-state {{\"generation\":1,\"sequence\":{sequence},\
             \"state\":\"{state}\",\"since_unix_ms\":{}}}",
            since.timestamp_millis()
        ),
    )
}

fn script(runtime: &FakeRuntimeDriver, lines: &[String]) {
    *runtime.runtime_log.lock().unwrap() = Some(Ok(lines.concat().into_bytes()));
}

/// (rate_kind, started_at, last_observed_at, ended_at, end_reason,
/// review_reason, pause_sequence) of each session, oldest first.
type Row = (
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

async fn rows(pool: &PgPool) -> Result<Vec<Row>> {
    Ok(sqlx::query_as(
        "SELECT rate_kind, started_at, last_observed_at, ended_at, end_reason, review_reason, \
                pause_sequence \
           FROM sandbox_running_sessions WHERE environment_id = $1 \
          ORDER BY started_at, ended_at NULLS LAST, id",
    )
    .bind(ENV)
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pause_and_its_resume_split_the_session_at_their_records() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let runtime = FakeRuntimeDriver::default();
        let observed = standard_session(&db, &runtime).await?;
        let paused = observed + Duration::minutes(2);
        let seen = paused + Duration::seconds(30);
        script(
            &runtime,
            &[pause(paused, "paused", 1), state(seen, "paused", 1, paused)],
        );
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;

        let split = rows(&db.pool).await?;
        ensure!(split.len() == 2, "{split:?}");
        let (kind, _, _, ended, reason, _, _) = &split[0];
        ensure!(
            kind == "running" && *ended == Some(paused) && reason.as_deref() == Some("vm_paused"),
            "{split:?}"
        );
        // Paused from its record, observed only up to the latest one.
        let (kind, started, last, ended, _, review, sequence) = &split[1];
        ensure!(
            kind == "paused" && *started == paused && *last == seen && ended.is_none(),
            "{split:?}"
        );
        ensure!(review.is_none() && *sequence == Some(1), "{split:?}");

        // The same records again change nothing.
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;
        ensure!(rows(&db.pool).await? == split, "a record is applied once");

        let resumed = seen + Duration::seconds(20);
        script(
            &runtime,
            &[
                pause(paused, "paused", 1),
                state(seen, "paused", 1, paused),
                pause(resumed, "resumed", 2),
            ],
        );
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;
        let resumed_rows = rows(&db.pool).await?;
        ensure!(resumed_rows.len() == 3, "{resumed_rows:?}");
        let (kind, _, _, ended, reason, _, _) = &resumed_rows[1];
        ensure!(
            kind == "paused" && *ended == Some(resumed) && reason.as_deref() == Some("vm_resumed"),
            "{resumed_rows:?}"
        );
        let (kind, started, last, ended, _, _, sequence) = &resumed_rows[2];
        ensure!(
            kind == "running" && *started == resumed && ended.is_none() && *sequence == Some(2),
            "{resumed_rows:?}"
        );
        ensure!(*last > resumed, "a running session is observed now");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_unread_log_leaves_the_session_where_it_was() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let runtime = FakeRuntimeDriver::default();
        let observed = standard_session(&db, &runtime).await?;
        let before = rows(&db.pool).await?;
        *runtime.runtime_log.lock().unwrap() = Some(Err("log unavailable".into()));
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;
        let after = rows(&db.pool).await?;
        ensure!(after == before && after[0].2 == observed, "{after:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_gap_in_a_paused_sandboxs_records_is_billed_running_for_review() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let runtime = FakeRuntimeDriver::default();
        let observed = standard_session(&db, &runtime).await?;
        let paused = observed + Duration::minutes(1);
        script(&runtime, &[pause(paused, "paused", 1)]);
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;

        // Three minutes with no record, then one that says paused again.
        let again = paused + Duration::minutes(3);
        script(
            &runtime,
            &[
                pause(paused, "paused", 1),
                state(again, "paused", 1, paused),
            ],
        );
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;
        let split = rows(&db.pool).await?;
        ensure!(split.len() == 4, "{split:?}");
        let (kind, _, _, ended, reason, _, _) = &split[1];
        ensure!(
            kind == "paused"
                && *ended == Some(paused)
                && reason.as_deref() == Some("pause_records_gap"),
            "{split:?}"
        );
        let (kind, started, _, ended, _, review, _) = &split[2];
        ensure!(
            kind == "running" && *started == paused && *ended == Some(again),
            "{split:?}"
        );
        ensure!(review.as_deref() == Some("pause_records_gap"), "{split:?}");
        let (kind, started, _, ended, _, review, _) = &split[3];
        ensure!(
            kind == "paused" && *started == again && ended.is_none() && review.is_none(),
            "{split:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_paused_session_whose_pod_ends_long_after_its_last_record_ends_in_a_gap() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let runtime = FakeRuntimeDriver::default();
        let observed = standard_session(&db, &runtime).await?;
        let paused = observed + Duration::minutes(1);
        script(&runtime, &[pause(paused, "paused", 1)]);
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;

        let stopped = paused + Duration::minutes(5);
        let ended = super::super::RuntimeMember {
            stopped_at: Some(stopped),
            ..member(Phase::Terminated, "Evicted")
        };
        reconcile(&db.pool, &runtime, &ended).await;
        let closed = rows(&db.pool).await?;
        ensure!(closed.len() == 3, "{closed:?}");
        let (kind, _, _, end, reason, _, _) = &closed[1];
        ensure!(kind == "paused" && *end == Some(paused) && reason.as_deref() == Some("pause_records_gap"), "{closed:?}");
        let (kind, started, _, end, reason, review, _) = &closed[2];
        ensure!(kind == "running" && *started == paused && *end == Some(stopped), "{closed:?}");
        ensure!(reason.as_deref() == Some("Evicted") && review.as_deref() == Some("pause_records_gap"), "{closed:?}");
        ensure!(sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sandbox_running_sessions WHERE runtime_uid = $1 AND ended_at IS NULL"
        )
        .bind(SANDBOX)
        .fetch_one(&db.pool)
        .await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stop_reads_the_wake_its_sigterm_recorded_before_the_session_ends() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let runtime = FakeRuntimeDriver::default();
        let observed = standard_session(&db, &runtime).await?;
        let paused = observed + Duration::minutes(1);
        script(&runtime, &[pause(paused, "paused", 1)]);
        reconcile(&db.pool, &runtime, &member(Phase::Running, "")).await;

        // Stopped five minutes later: the SIGTERM woke the VM first.
        let woke = paused + Duration::minutes(5);
        let stopped = woke + Duration::seconds(2);
        // The runtime records its state every 30 s while paused.
        let mut log = vec![pause(paused, "paused", 1)];
        log.extend((1..10).map(|n| state(paused + Duration::seconds(30 * n), "paused", 1, paused)));
        log.push(pause(woke, "resumed", 2));
        script(&runtime, &log);
        let ended = super::super::RuntimeMember {
            stopped_at: Some(stopped),
            ..member(Phase::Terminated, "suspended")
        };
        reconcile(&db.pool, &runtime, &ended).await;
        let closed = rows(&db.pool).await?;
        ensure!(closed.len() == 3, "{closed:?}");
        let (kind, _, _, end, reason, _, _) = &closed[1];
        ensure!(
            kind == "paused" && *end == Some(woke) && reason.as_deref() == Some("vm_resumed"),
            "{closed:?}"
        );
        let (kind, started, _, end, reason, review, _) = &closed[2];
        ensure!(
            kind == "running" && *started == woke && *end == Some(stopped),
            "{closed:?}"
        );
        ensure!(
            reason.as_deref() == Some("suspended") && review.is_none(),
            "no gap: {closed:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
