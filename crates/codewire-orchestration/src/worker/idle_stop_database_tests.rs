//! Disposable-PostgreSQL proof that an environment's own idle stop is
//! recorded and read back, that a gone environment refuses one, and that the
//! idle check finds, holds off and stops the right Sandboxes (#3384).

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use crate::api::environments::{ENV_SELECT_COLS, ENV_SELECT_JOINS, Environment, scan_environment};
use crate::lifecycle::Service;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "idle-stop-creator";
const ORGANIZATION: &str = "idle-stop-organization";
const PRESET: &str = "idle-stop-preset";
const ENVIRONMENT: &str = "7c41a9e2-5b3d-4f08-9a6e-2d8b1c4f6e93";

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Idle stop','idle-stop',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'running','started',$5)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// The environment as the API reads it.
async fn read(pool: &PgPool) -> Result<Environment> {
    let row = sqlx::query(&format!(
        "SELECT {ENV_SELECT_COLS} FROM environments e {ENV_SELECT_JOINS} WHERE e.id = $1"
    ))
    .bind(ENVIRONMENT)
    .fetch_one(pool)
    .await?;
    Ok(scan_environment(&row)?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_idle_stop_is_recorded_without_touching_the_lifecycle() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // An environment created without one is off.
        ensure!(read(pool).await?.idle_stop_seconds == 0);

        for seconds in [1800, 0] {
            ensure!(svc.set_idle_stop(ENVIRONMENT, seconds).await?);
            let environment = read(pool).await?;
            ensure!(
                environment.idle_stop_seconds == seconds,
                "{:?}",
                environment.idle_stop_seconds
            );
            // Recording it starts, stops and restarts nothing.
            ensure!(environment.state == "running" && environment.desired_state == "started");
        }

        sqlx::query("UPDATE environments SET state = 'destroyed' WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(pool)
            .await?;
        ensure!(!svc.set_idle_stop(ENVIRONMENT, 1800).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The idle check's candidates, by id.
async fn candidate_ids(pool: &PgPool) -> Result<Vec<String>> {
    Ok(crate::worker::idle_stop::candidates(pool)
        .await?
        .into_iter()
        .map(|candidate| candidate.id)
        .collect())
}

async fn set_activity(pool: &PgPool, seconds_ago: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    set_activity_of(pool, ENVIRONMENT, seconds_ago).await
}

async fn set_activity_of(
    pool: &PgPool,
    environment: &str,
    seconds_ago: i64,
) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(sqlx::query_scalar(
        "UPDATE environments SET last_activity_at = NOW() - make_interval(secs => $2) \
         WHERE id = $1 RETURNING last_activity_at",
    )
    .bind(environment)
    .bind(seconds_ago as f64)
    .fetch_one(pool)
    .await?)
}

/// A running cloud Sandbox, started an hour ago, with its backend row.
async fn sandbox(pool: &PgPool, environment: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
           project_spec,started_at) \
         SELECT $1,org_id,created_by,type,preset_id,'running','started',project_spec, \
           NOW() - interval '1 hour' FROM environments WHERE id = $2 \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(environment)
    .bind(ENVIRONMENT)
    .execute(pool)
    .await?;
    sqlx::query("UPDATE environments SET started_at = NOW() - interval '1 hour' WHERE id = $1")
        .bind(environment)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend(environment_id, namespace) VALUES ($1, 'idle-ns')",
    )
    .bind(environment)
    .execute(pool)
    .await?;
    Ok(())
}

/// One `cw` runtime request of `environment`, admitted `hours_ago`, open
/// unless `closed` (cancelled before dispatch).
async fn request(
    pool: &PgPool,
    environment: &str,
    id: &str,
    hours_ago: i32,
    closed: bool,
) -> Result<()> {
    let pod = "4b8f0c1e-2d3a-4e5f-8a9b-0c1d2e3f4a5b";
    sqlx::query(
        "INSERT INTO environment_cw_runtime_requests \
           (request_id,organization_id,environment_id,actor_user_id,via_api_key,pod_uid, \
            fingerprint,request_json,binding_json,expected_store_generation,owner_id, \
            mutation_lease_id,phase,checkpoint,effect,error_code,issued_at,terminal_at,admitted_at) \
         VALUES ($1::uuid,$2,$3,'idle-stop-user',false,$4::uuid,repeat('a',64), \
            '{\"expected_store_generation\":\"1\"}'::jsonb, \
            jsonb_build_object('organization_id',$2::text,'environment_id',$3::text,'pod_uid',$4::text), \
            '1',gen_random_uuid(),'lease-'||$1, \
            CASE WHEN $6 THEN 'failed' ELSE 'admitted' END, 0, NULL, \
            CASE WHEN $6 THEN 'cw_runtime_cancelled_before_dispatch' END, \
            NULL, CASE WHEN $6 THEN NOW() END, \
            NOW() - make_interval(hours => $5))",
    )
    .bind(id)
    .bind(ORGANIZATION)
    .bind(environment)
    .bind(pod)
    .bind(hours_ago)
    .bind(closed)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_idle_check_finds_an_unused_sandbox_and_activity_or_a_request_holds_it() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        sandbox(pool, ENVIRONMENT).await?;
        set_activity(pool, 600).await?;

        // Off: never a candidate.
        ensure!(candidate_ids(pool).await?.is_empty());

        // Five minutes, unused for ten: a candidate.
        ensure!(svc.set_idle_stop(ENVIRONMENT, 300).await?);
        ensure!(candidate_ids(pool).await? == [ENVIRONMENT]);

        // Used a minute ago: not.
        set_activity(pool, 60).await?;
        ensure!(candidate_ids(pool).await?.is_empty());
        set_activity(pool, 600).await?;

        // A closed request holds nothing, and nor does one left open for
        // over a day.
        request(
            pool,
            ENVIRONMENT,
            "0e7d1c2b-3a4f-4b5c-8d6e-7f8091a2b3c4",
            0,
            true,
        )
        .await?;
        ensure!(candidate_ids(pool).await? == [ENVIRONMENT]);
        request(
            pool,
            ENVIRONMENT,
            "1f8e2d3c-4b5a-4c6d-9e7f-8091a2b3c4d5",
            25,
            false,
        )
        .await?;
        ensure!(candidate_ids(pool).await? == [ENVIRONMENT]);

        // A request still open holds its Sandbox, however long it has
        // waited, up to a day.
        let busy = "8d2c6b1a-4e3f-4a5b-9c8d-7e6f5a4b3c2d";
        sandbox(pool, busy).await?;
        ensure!(svc.set_idle_stop(busy, 300).await?);
        set_activity_of(pool, busy, 600).await?;
        ensure!(candidate_ids(pool).await? == [ENVIRONMENT, busy]);
        request(pool, busy, "2a9f3e4d-5c6b-4d7e-8f9a-0b1c2d3e4f5a", 2, false).await?;
        ensure!(candidate_ids(pool).await? == [ENVIRONMENT]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_idle_stop_loses_to_activity_during_the_check_and_a_start_resets_the_clock()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        ensure!(svc.set_idle_stop(ENVIRONMENT, 300).await?);
        let seen = set_activity(pool, 600).await?;

        // Activity arrived after the check read it.
        let newer = set_activity(pool, 10).await?;
        ensure!(!svc.request_idle_stop(ENVIRONMENT, Some(seen)).await?);

        // As read, it stops, with its reason.
        ensure!(svc.request_idle_stop(ENVIRONMENT, Some(newer)).await?);
        let environment = read(pool).await?;
        ensure!(
            environment.desired_state == "stopped"
                && environment.stop_reason.as_deref() == Some("idle"),
            "{:?} {:?}",
            environment.desired_state,
            environment.stop_reason
        );
        // A second check stops nothing more.
        ensure!(!svc.request_idle_stop(ENVIRONMENT, Some(newer)).await?);

        // A start sets the clock to now.
        sqlx::query("UPDATE environments SET last_activity_at = NULL WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(pool)
            .await?;
        svc.mark_started(ENVIRONMENT).await?;
        let recent: bool = sqlx::query_scalar(
            "SELECT last_activity_at > NOW() - interval '1 minute' FROM environments WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .fetch_one(pool)
        .await?;
        ensure!(recent, "a start records activity");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A suspended Sandbox stays a candidate, marked so its daemon isn't asked:
/// its time counts toward the stop (#5529, `docs/dev/IDLE-STOP.md`,
/// "Calls that must not wake a suspended Sandbox").
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_suspended_sandbox_is_a_candidate_marked_suspended() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        sandbox(pool, ENVIRONMENT).await?;
        ensure!(svc.set_idle_stop(ENVIRONMENT, 300).await?);
        set_activity(pool, 600).await?;
        let suspended = |pool: &PgPool| {
            let pool = pool.clone();
            async move {
                Ok::<_, anyhow::Error>(
                    crate::worker::idle_stop::candidates(&pool)
                        .await?
                        .into_iter()
                        .map(|candidate| (candidate.id, candidate.suspended))
                        .collect::<Vec<_>>(),
                )
            }
        };
        ensure!(suspended(pool).await? == [(ENVIRONMENT.to_owned(), false)]);
        sqlx::query("UPDATE environments SET suspended_at = NOW() WHERE id = $1")
            .bind(ENVIRONMENT)
            .execute(pool)
            .await?;
        ensure!(suspended(pool).await? == [(ENVIRONMENT.to_owned(), true)]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Idle suspend (#5529): only a running, unmarked `standard` Sandbox with
/// idle suspend on and older activity is a candidate; the daemon's
/// acknowledgement marks a running one once; a failed pause clears only its
/// own mark.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_idle_suspend_finds_marks_and_clears_the_right_sandboxes() -> Result<()> {
    use crate::worker::idle_suspend;

    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        const STANDARD: &str = "3b9e6c2d-1f4a-4e8b-9c7d-5a6b7c8d9e0f";
        const KATA: &str = "5d2e8f1a-3c4b-4a6d-8e9f-0a1b2c3d4e5f";
        // The runtime record is written once, at create.
        for (environment, profile) in [(STANDARD, "standard"), (KATA, "commodity")] {
            sqlx::query(
                "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
                   project_spec,started_at,runtime_profile,idle_suspend_seconds) \
                 SELECT $1,org_id,created_by,type,preset_id,'running','started',project_spec, \
                   NOW() - interval '1 hour',$3,900 FROM environments WHERE id = $2",
            )
            .bind(environment)
            .bind(ENVIRONMENT)
            .bind(profile)
            .execute(pool)
            .await?;
            sqlx::query(
                "INSERT INTO sandbox_environment_backend(environment_id, namespace) \
                 VALUES ($1, 'idle-ns')",
            )
            .bind(environment)
            .execute(pool)
            .await?;
        }
        let ids = |candidates: Vec<idle_suspend::Candidate>| {
            candidates.into_iter().map(|c| c.id).collect::<Vec<_>>()
        };

        // Recent activity: no candidate. Older than 15 minutes: the
        // standard one only.
        set_activity_of(pool, STANDARD, 60).await?;
        set_activity_of(pool, KATA, 1_000).await?;
        ensure!(ids(idle_suspend::candidates(pool).await?).is_empty());
        set_activity_of(pool, STANDARD, 1_000).await?;
        ensure!(ids(idle_suspend::candidates(pool).await?) == [STANDARD]);

        // The acknowledgement marks it, once; a marked one is no candidate.
        idle_suspend::mark(pool, STANDARD).await?;
        let marked = idle_suspend::marked(pool).await?;
        ensure!(marked.len() == 1 && marked[0].id == STANDARD);
        let first = marked[0].suspended_at;
        idle_suspend::mark(pool, STANDARD).await?;
        ensure!(idle_suspend::marked(pool).await?[0].suspended_at == first);
        ensure!(idle_suspend::candidates(pool).await?.is_empty());

        // Clearing a mark other than the one in force changes nothing.
        idle_suspend::clear_mark(pool, STANDARD, first - chrono::Duration::seconds(1)).await?;
        ensure!(idle_suspend::marked(pool).await?.len() == 1);
        idle_suspend::clear_mark(pool, STANDARD, first).await?;
        ensure!(idle_suspend::marked(pool).await?.is_empty());
        ensure!(ids(idle_suspend::candidates(pool).await?) == [STANDARD]);

        // A stopped Sandbox is neither marked nor a candidate.
        sqlx::query("UPDATE environments SET state = 'stopped' WHERE id = $1")
            .bind(STANDARD)
            .execute(pool)
            .await?;
        idle_suspend::mark(pool, STANDARD).await?;
        ensure!(idle_suspend::marked(pool).await?.is_empty());
        ensure!(idle_suspend::candidates(pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
