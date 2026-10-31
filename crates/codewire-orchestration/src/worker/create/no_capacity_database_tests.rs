//! Disposable-PostgreSQL proof of how a create or start the cluster had no room
//! for ends (#3635): only a sandbox that never ran is destroyed, every other one
//! stops with its files, and the next start clears the message.

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use super::*;

use crate::api::environments::OrgQuota;
use crate::lifecycle::{Action, NoCapacityRefusal, Snapshot, StartQuota};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "no-capacity-creator";
const ORGANIZATION: &str = "no-capacity-organization";
const PRESET: &str = "no-capacity-preset";

/// One seeded sandbox, by what it has been through.
struct Seed {
    state: &'static str,
    desired_state: &'static str,
    retry_count: i32,
    started: bool,
    stopped: bool,
}

const FIRST_ATTEMPT: Seed = Seed {
    state: "creating",
    desired_state: "started",
    retry_count: 0,
    started: false,
    stopped: false,
};

async fn seed_parents(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'No capacity','no-capacity',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(to_value(codewire_project::ProjectSpec::default())?)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn seed(pool: &PgPool, id: &str, seed: &Seed) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,retry_count, \
         started_at,stopped_at,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,$5,$6,$7, \
         CASE WHEN $8 THEN NOW() END,CASE WHEN $9 THEN NOW() END,$10)",
    )
    .bind(id)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(seed.state)
    .bind(seed.desired_state)
    .bind(seed.retry_count)
    .bind(seed.started)
    .bind(seed.stopped)
    .bind(to_value(codewire_project::ProjectSpec::default())?)
    .execute(pool)
    .await?;
    Ok(())
}

/// (state, desired state, error code, error reason)
async fn outcome(pool: &PgPool, id: &str) -> Result<(String, String, String, String)> {
    Ok(sqlx::query_as(
        "SELECT state, desired_state, COALESCE(error_code, ''), COALESCE(error_reason, '') \
         FROM environments WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

async fn refusal_logs(pool: &PgPool, id: &str) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM environment_logs \
         WHERE environment_id = $1 AND phase = 'lifecycle_no_capacity'",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_no_capacity_destroys_only_a_sandbox_that_never_ran() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_parents(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        let cases = [
            (
                "never ran, pending",
                Seed {
                    state: "pending",
                    ..FIRST_ATTEMPT
                },
                true,
            ),
            ("never ran, creating", FIRST_ATTEMPT, true),
            // A start resumed through the create handler.
            (
                "resumed start",
                Seed {
                    state: "starting",
                    ..FIRST_ATTEMPT
                },
                false,
            ),
            // Reached running, whatever happened after.
            (
                "has run",
                Seed {
                    started: true,
                    ..FIRST_ATTEMPT
                },
                false,
            ),
            // Stopped, with `started_at` lost to a failed write.
            (
                "has stopped",
                Seed {
                    stopped: true,
                    ..FIRST_ATTEMPT
                },
                false,
            ),
            // An errored sandbox retried; it may have run with `started_at` lost.
            (
                "retried",
                Seed {
                    retry_count: 1,
                    ..FIRST_ATTEMPT
                },
                false,
            ),
        ];
        for (index, (name, case, never_ran)) in cases.iter().enumerate() {
            let id = format!("3f1c7a52-8e64-4d0b-9c21-5a7e6b8f0d{index:02}");
            seed(pool, &id, case).await?;
            let env = load_environment(pool, &id).await?;
            ensure!(
                env.never_ran == *never_ran,
                "{name}: never_ran {}",
                env.never_ran
            );

            let refusal = NoCapacityRefusal::for_create(env.never_ran);
            ensure!(
                svc.refuse_for_no_capacity(&id, refusal, CREATE_MUTATION_STATES)
                    .await?,
                "{name}: not refused"
            );
            let (state, desired, code, reason) = outcome(pool, &id).await?;
            let expected = if *never_ran {
                ("error", "destroyed", NoCapacityRefusal::CREATE.message)
            } else {
                ("stopping", "stopped", NoCapacityRefusal::START.message)
            };
            ensure!(
                (state.as_str(), desired.as_str(), reason.as_str()) == expected,
                "{name}: {state} {desired} {reason}"
            );
            ensure!(
                code == crate::lifecycle::NO_CAPACITY_ERROR_CODE,
                "{name}: {code}"
            );
            ensure!(
                refusal_logs(pool, &id).await? == 1,
                "{name}: not logged once"
            );

            // The queued reconcile takes the normal way out, never a retry.
            let action = svc
                .reconcile(&Snapshot {
                    id: id.clone(),
                    state,
                    desired_state: desired,
                    external_cleanup_complete: false,
                })
                .await?;
            let want = if *never_ran {
                Action::Destroy
            } else {
                Action::Stop
            };
            ensure!(action == want, "{name}: {action:?}");

            // A second attempt at the same refusal finds nothing to change.
            ensure!(
                !svc.refuse_for_no_capacity(&id, refusal, CREATE_MUTATION_STATES)
                    .await?,
                "{name}: refused twice"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_no_capacity_never_overrides_a_newer_intent() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_parents(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        // Destroyed while its start waited: stopping now would undo that.
        let id = "3f1c7a52-8e64-4d0b-9c21-5a7e6b8f0d20";
        let case = Seed {
            state: "starting",
            desired_state: "destroyed",
            ..FIRST_ATTEMPT
        };
        seed(pool, id, &case).await?;
        ensure!(
            !svc.refuse_for_no_capacity(id, NoCapacityRefusal::START, CREATE_MUTATION_STATES)
                .await?
        );
        let (state, desired, code, reason) = outcome(pool, id).await?;
        ensure!(
            state == "starting" && desired == "destroyed",
            "{state} {desired}"
        );
        ensure!(code.is_empty() && reason.is_empty(), "{code} {reason}");
        ensure!(refusal_logs(pool, id).await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}

fn start_quota() -> StartQuota<'static> {
    StartQuota {
        credit_enforcement: Default::default(),
        quota: OrgQuota {
            max_concurrent_environments: -1,
            max_concurrent_sandbox: -1,
            max_cpu_millicores: -1,
            max_memory_mb: -1,
        },
        env_type: "sandbox",
        cpu_millicores: 1000,
        memory_mb: 1024,
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_next_start_clears_only_the_no_capacity_message() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_parents(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        let stopped = Seed {
            state: "stopped",
            desired_state: "stopped",
            stopped: true,
            ..FIRST_ATTEMPT
        };

        let refused = "3f1c7a52-8e64-4d0b-9c21-5a7e6b8f0d30";
        seed(pool, refused, &stopped).await?;
        sqlx::query("UPDATE environments SET error_code = $2, error_reason = 'full' WHERE id = $1")
            .bind(refused)
            .bind(crate::lifecycle::NO_CAPACITY_ERROR_CODE)
            .execute(pool)
            .await?;
        svc.admit_start(refused, ORGANIZATION, "standard", start_quota())
            .await?;
        let (_, desired, code, reason) = outcome(pool, refused).await?;
        ensure!(
            desired == "started" && code.is_empty() && reason.is_empty(),
            "{desired} {code} {reason}"
        );

        // Any other reason stays, as it always has.
        let other = "3f1c7a52-8e64-4d0b-9c21-5a7e6b8f0d31";
        seed(pool, other, &stopped).await?;
        sqlx::query("UPDATE environments SET error_reason = 'setup failed' WHERE id = $1")
            .bind(other)
            .execute(pool)
            .await?;
        svc.admit_start(other, ORGANIZATION, "standard", start_quota())
            .await?;
        let (_, _, _, reason) = outcome(pool, other).await?;
        ensure!(reason == "setup failed", "{reason}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
