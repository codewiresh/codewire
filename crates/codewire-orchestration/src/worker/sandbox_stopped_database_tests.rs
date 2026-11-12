//! Disposable-PostgreSQL proof of what a user is told when a running sandbox's
//! Pod fails and it comes back (#3772), and of when that notice ends.

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use crate::api::environments::OrgQuota;
use crate::lifecycle::{
    PgLifecycleStore, SANDBOX_RESTARTED_ERROR_CODE, SANDBOX_STOPPED_ERROR_CODE,
    SANDBOX_STOPPED_MESSAGE, Service, StartQuota,
};
use crate::runtime::RuntimeProbe;
use crate::runtime::fake::FakeRuntimeDriver;
use crate::test_database_support::TestDatabase;
use crate::worker::loops::{LivenessRow, observe_sandbox_liveness};

const CREATOR: &str = "stopped-creator";
const ORGANIZATION: &str = "stopped-organization";
const PRESET: &str = "stopped-preset";
const ENVIRONMENT: &str = "6d2e8b14-3f7a-4c95-a1d0-7e9c4b2f8a10";

async fn seed(db: &TestDatabase, state: &str) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Stopped','stopped',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,$5,'started',$6)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(state)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// (state, code, reason)
async fn row(pool: &PgPool) -> Result<(String, Option<String>, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT state, error_code, error_reason FROM environments WHERE id = $1")
            .bind(ENVIRONMENT)
            .fetch_one(pool)
            .await?,
    )
}

async fn set_state(pool: &PgPool, state: &str) -> Result<()> {
    sqlx::query("UPDATE environments SET state = $2 WHERE id = $1")
        .bind(ENVIRONMENT)
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

/// Stopped unexpectedly, then back to running, as liveness and a start do it.
async fn stopped_and_restarted(svc: &Service<PgLifecycleStore>, pool: &PgPool) -> Result<()> {
    ensure!(svc.mark_sandbox_stopped(ENVIRONMENT).await?);
    set_state(pool, "running").await?;
    svc.mark_started(ENVIRONMENT).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stopped_sandbox_says_so_then_becomes_a_notice() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        ensure!(svc.mark_sandbox_stopped(ENVIRONMENT).await?);
        let (state, code, reason) = row(pool).await?;
        ensure!(state == "error", "{state}");
        ensure!(
            code.as_deref() == Some(SANDBOX_STOPPED_ERROR_CODE),
            "{code:?}"
        );
        ensure!(
            reason.as_deref() == Some(SANDBOX_STOPPED_MESSAGE),
            "{reason:?}"
        );
        // Already not running: nothing to say twice.
        ensure!(!svc.mark_sandbox_stopped(ENVIRONMENT).await?);

        // Back to running: it says what happened, and not that it is failing.
        set_state(pool, "running").await?;
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(
            code.as_deref() == Some(SANDBOX_RESTARTED_ERROR_CODE),
            "{code:?}"
        );
        let reason = reason.unwrap_or_default();
        ensure!(
            reason.starts_with("Restarted at ")
                && reason
                    .ends_with(" UTC after stopping unexpectedly. Running processes were lost."),
            "{reason}"
        );

        // Recording the start again keeps the notice.
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, again) = row(pool).await?;
        ensure!(
            code.as_deref() == Some(SANDBOX_RESTARTED_ERROR_CODE),
            "{code:?}"
        );
        ensure!(again.as_deref() == Some(reason.as_str()), "{again:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_sandbox_not_running_is_never_marked_stopped() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "creating").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        ensure!(!svc.mark_sandbox_stopped(ENVIRONMENT).await?);
        let (state, code, reason) = row(pool).await?;
        ensure!(state == "creating" && code.is_none() && reason.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_notice_ends_at_the_next_stop_or_start() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // A stop.
        stopped_and_restarted(&svc, pool).await?;
        set_state(pool, "stopped").await?;
        svc.mark_stopped(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");

        // A start.
        set_state(pool, "running").await?;
        stopped_and_restarted(&svc, pool).await?;
        set_state(pool, "stopped").await?;
        let quota = StartQuota {
            quota: OrgQuota {
                max_concurrent_environments: -1,
                max_concurrent_sandbox: -1,
                max_cpu_millicores: -1,
                max_memory_mb: -1,
            },
            env_type: "sandbox",
            cpu_millicores: 1000,
            memory_mb: 1024,
            credit_enforcement: Default::default(),
        };
        svc.admit_start(ENVIRONMENT, ORGANIZATION, "standard", quota)
            .await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_running_again_clears_any_old_reason_and_another_failure_replaces_the_notice()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // Another failure on a restarted sandbox has its own reason and no notice.
        stopped_and_restarted(&svc, pool).await?;
        svc.mark_error_for_states(ENVIRONMENT, "sandbox pod missing", &["running"])
            .await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none(), "{code:?}");
        ensure!(
            reason.as_deref() == Some("sandbox pod missing"),
            "{reason:?}"
        );

        // A reason from an earlier failure doesn't outlive the return to running.
        set_state(pool, "running").await?;
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A running sandbox as liveness reads it, `running_for` after it got there.
fn liveness_row(generation: i64, running_for: chrono::Duration) -> LivenessRow {
    LivenessRow {
        id: ENVIRONMENT.into(),
        state: "running".into(),
        desired_state: "started".into(),
        operation_generation: generation,
        state_changed_at: chrono::Utc::now() - running_for,
        namespace: "stopped-sandboxes".into(),
        pod_name: "sandbox-stopped".into(),
        pod_ip: "10.0.0.1".into(),
        bound_pod_uid: Some("pod-uid".into()),
        setup_owner_generation: None,
        setup_owner_status: String::new(),
    }
}

fn runtime_reporting(claim_ready: bool, reason: &str, phase: &str) -> FakeRuntimeDriver {
    FakeRuntimeDriver {
        probe: RuntimeProbe {
            claim_exists: true,
            claim_ready,
            claim_reason: reason.into(),
            pod_exists: true,
            pod_name: "sandbox-stopped".into(),
            pod_uid: "pod-uid".into(),
            pod_ip: "10.0.0.1".into(),
            pod_phase: phase.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// An operation generation, as a workflow's claim gives a running sandbox.
async fn generation(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "UPDATE environments SET environment_operation_generation = 3 WHERE id = $1 \
         RETURNING environment_operation_generation",
    )
    .bind(ENVIRONMENT)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_failed_pod_asks_for_recovery_once_it_is_marked() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let failed = runtime_reporting(false, "PodFailed", "Failed");
        let now = chrono::Utc::now();

        // Nothing else would look at it for five minutes (#3851).
        let asked = observe_sandbox_liveness(&db.pool, &failed, now, &row).await;
        ensure!(asked.is_some(), "no recovery asked for");
        let (state, code, _) = self::row(&db.pool).await?;
        ensure!(state == "error", "{state}");
        ensure!(
            code.as_deref() == Some(SANDBOX_STOPPED_ERROR_CODE),
            "{code:?}"
        );

        // A second look, from a row read before the mark, asks for nothing more.
        let asked = observe_sandbox_liveness(&db.pool, &failed, now, &row).await;
        ensure!(asked.is_none(), "{asked:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_sandbox_that_fails_soon_after_starting_waits_for_the_sweep() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::seconds(10));
        let failed = runtime_reporting(false, "PodFailed", "Failed");

        let asked = observe_sandbox_liveness(&db.pool, &failed, chrono::Utc::now(), &row).await;
        ensure!(asked.is_none(), "{asked:?}");
        // It is still marked, so the user is told and the sweep can find it.
        let (state, code, _) = self::row(&db.pool).await?;
        ensure!(state == "error", "{state}");
        ensure!(
            code.as_deref() == Some(SANDBOX_STOPPED_ERROR_CODE),
            "{code:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_healthy_or_replaced_runtime_marks_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let now = chrono::Utc::now();

        let healthy = runtime_reporting(true, "", "Running");
        let asked = observe_sandbox_liveness(&db.pool, &healthy, now, &row).await;
        ensure!(asked.is_none(), "{asked:?}");

        // A Pod replaced under the same name still takes the identity reconcile.
        let mut replaced = runtime_reporting(true, "", "Running");
        replaced.probe.pod_uid = "new-pod-uid".into();
        let asked = observe_sandbox_liveness(&db.pool, &replaced, now, &row).await;
        ensure!(asked.is_some(), "no reconcile asked for");

        let (state, code, _) = self::row(&db.pool).await?;
        ensure!(state == "running" && code.is_none(), "{state} {code:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

fn deleting_at(at: chrono::DateTime<chrono::Utc>) -> k8s_openapi::jiff::Timestamp {
    k8s_openapi::jiff::Timestamp::from_second(at.timestamp()).unwrap()
}

/// #3944: a daemon repair deletes the Pod, whose containers then exit. On the
/// real race the claim said `PodSucceeded`, the repair lost its authority and
/// the sandbox stayed in `error`.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pod_being_deleted_marks_nothing_however_it_exited() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let now = chrono::Utc::now();

        for (reason, phase) in [("PodSucceeded", "Succeeded"), ("PodFailed", "Failed")] {
            let mut leaving = runtime_reporting(false, reason, phase);
            leaving.probe.pod_deleting_at = Some(deleting_at(now));
            let asked = observe_sandbox_liveness(&db.pool, &leaving, now, &row).await;
            ensure!(asked.is_none(), "{phase}: {asked:?}");
            let (state, code, _) = self::row(&db.pool).await?;
            ensure!(
                state == "running" && code.is_none(),
                "{phase}: {state} {code:?}"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The old Pod is gone and the claim still reports how it ended, with no
/// replacement yet: a reconcile, as for any missing runtime, and no error.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_gap_before_a_replacement_asks_for_a_reconcile_and_marks_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let now = chrono::Utc::now();

        let mut gone = runtime_reporting(false, "PodSucceeded", "");
        gone.probe.pod_exists = false;
        gone.probe.pod_name = String::new();
        gone.probe.pod_uid = String::new();
        gone.probe.pod_ip = String::new();
        let asked = observe_sandbox_liveness(&db.pool, &gone, now, &row).await;
        ensure!(asked.is_some(), "no reconcile asked for");

        // The replacement exists under the same name and isn't ready.
        let mut pending = runtime_reporting(false, "SandboxNotReady", "Pending");
        pending.probe.pod_uid = "new-pod-uid".into();
        pending.probe.pod_ip = String::new();
        let asked = observe_sandbox_liveness(&db.pool, &pending, now, &row).await;
        ensure!(asked.is_some(), "no reconcile asked for");

        let (state, code, _) = self::row(&db.pool).await?;
        ensure!(state == "running" && code.is_none(), "{state} {code:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A non-zero exit, with the replacement already up: the claim's `PodFailed` is
/// about the old Pod, so it takes the identity reconcile and stops nothing.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_claim_still_reporting_the_old_pods_failure_stops_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let now = chrono::Utc::now();

        for phase in ["Pending", "Running"] {
            let mut replaced = runtime_reporting(false, "PodFailed", phase);
            replaced.probe.pod_uid = "new-pod-uid".into();
            let asked = observe_sandbox_liveness(&db.pool, &replaced, now, &row).await;
            ensure!(asked.is_some(), "{phase}: no reconcile asked for");
            let (state, code, _) = self::row(&db.pool).await?;
            ensure!(
                state == "running" && code.is_none(),
                "{phase}: {state} {code:?}"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The other direction: a Pod that finished by itself has no deletion mark.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pod_that_really_finished_still_marks_an_error() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let finished = runtime_reporting(false, "PodSucceeded", "Succeeded");

        observe_sandbox_liveness(&db.pool, &finished, chrono::Utc::now(), &row).await;
        let (state, _, reason) = self::row(&db.pool).await?;
        ensure!(state == "error", "{state}");
        ensure!(
            reason.as_deref() == Some("sandbox claim not ready: PodSucceeded"),
            "{reason:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The bound: a Pod stuck going can't hide a dead sandbox.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_pod_stuck_being_deleted_marks_an_error_after_the_grace() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let row = liveness_row(generation(&db.pool).await?, chrono::Duration::minutes(10));
        let now = chrono::Utc::now();
        let mut stuck = runtime_reporting(false, "PodSucceeded", "Succeeded");

        stuck.probe.pod_deleting_at = Some(deleting_at(now - chrono::Duration::seconds(59)));
        observe_sandbox_liveness(&db.pool, &stuck, now, &row).await;
        ensure!(
            self::row(&db.pool).await?.0 == "running",
            "marked inside the grace"
        );

        stuck.probe.pod_deleting_at = Some(deleting_at(now - chrono::Duration::seconds(61)));
        observe_sandbox_liveness(&db.pool, &stuck, now, &row).await;
        ensure!(
            self::row(&db.pool).await?.0 == "error",
            "not marked after the grace"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
