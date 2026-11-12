//! Disposable-PostgreSQL proof of the confidential activation bound (#4281):
//! no more than the bound hold slots, retries keep the slot they hold, a slot
//! frees on release, when its environment leaves the active states and when
//! its lease passes, two acquisitions can't both take the last slot, and a
//! waiting activation stops at its queue limit or when it is no longer wanted.

use std::time::Duration;

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use super::*;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "slots-creator";
const ORGANIZATION: &str = "slots-organization";
const PRESET: &str = "slots-preset";
const LEASE: Duration = Duration::from_secs(35 * 60);

async fn seed(db: &TestDatabase, environments: &[(&str, &str)]) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Slots','slots',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(to_value(codewire_project::ProjectSpec::default())?)
    .execute(&db.pool)
    .await?;
    for (id, state) in environments {
        sqlx::query(
            "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
             isolation_tier,project_spec) \
             VALUES ($1,$2,$3,'sandbox',$4,$5,'started','confidential',$6)",
        )
        .bind(id)
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .bind(PRESET)
        .bind(state)
        .bind(to_value(codewire_project::ProjectSpec::default())?)
        .execute(&db.pool)
        .await?;
    }
    Ok(())
}

async fn holders(pool: &PgPool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT environment_id FROM confidential_activation_slots ORDER BY environment_id",
    )
    .fetch_all(pool)
    .await?)
}

async fn set_state(pool: &PgPool, id: &str, state: &str) -> Result<()> {
    sqlx::query("UPDATE environments SET state = $2 WHERE id = $1")
        .bind(id)
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn no_more_than_the_bound_hold_slots_and_a_retry_keeps_its_own() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(
            &db,
            &[
                ("env-a", "creating"),
                ("env-b", "starting"),
                ("env-c", "creating"),
            ],
        )
        .await?;
        ensure!(try_acquire(&db.pool, "env-a", 2, LEASE).await?);
        ensure!(try_acquire(&db.pool, "env-b", 2, LEASE).await?);
        ensure!(
            !try_acquire(&db.pool, "env-c", 2, LEASE).await?,
            "a third waits"
        );
        // A retry by a holder keeps its slot and takes no other.
        ensure!(try_acquire(&db.pool, "env-a", 2, LEASE).await?);
        ensure!(holders(&db.pool).await? == ["env-a", "env-b"]);
        // Released, the slot goes to the next.
        release(&db.pool, "env-a").await?;
        ensure!(try_acquire(&db.pool, "env-c", 2, LEASE).await?);
        ensure!(holders(&db.pool).await? == ["env-b", "env-c"]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_slot_frees_when_its_environment_is_no_longer_active() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, &[("env-a", "creating"), ("env-b", "creating")]).await?;
        for state in ["error", "stopped", "destroying", "destroyed"] {
            set_state(&db.pool, "env-a", "creating").await?;
            release(&db.pool, "env-b").await?;
            ensure!(try_acquire(&db.pool, "env-a", 1, LEASE).await?);
            ensure!(!try_acquire(&db.pool, "env-b", 1, LEASE).await?);
            // A create that fails or is torn down leaves the active states,
            // and the next acquisition sweeps its slot.
            set_state(&db.pool, "env-a", state).await?;
            ensure!(
                try_acquire(&db.pool, "env-b", 1, LEASE).await?,
                "a slot held by an environment in {state} is swept"
            );
            ensure!(holders(&db.pool).await? == ["env-b"], "{state}");
        }
        // A running environment still holds its slot until it releases it:
        // a running member's replacement activates its volume again.
        release(&db.pool, "env-b").await?;
        set_state(&db.pool, "env-a", "running").await?;
        ensure!(try_acquire(&db.pool, "env-a", 1, LEASE).await?);
        ensure!(!try_acquire(&db.pool, "env-b", 1, LEASE).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_stuck_activation_holds_its_slot_only_until_its_lease_passes() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, &[("env-a", "creating"), ("env-b", "creating")]).await?;
        ensure!(try_acquire(&db.pool, "env-a", 1, LEASE).await?);
        ensure!(!try_acquire(&db.pool, "env-b", 1, LEASE).await?);
        // env-a never finishes and stays `creating`; its lease passes.
        sqlx::query(
            "UPDATE confidential_activation_slots \
             SET acquired_at = now() - interval '40 minutes', \
                 expires_at = now() - interval '1 second' \
             WHERE environment_id = 'env-a'",
        )
        .execute(&db.pool)
        .await?;
        ensure!(try_acquire(&db.pool, "env-b", 1, LEASE).await?);
        ensure!(holders(&db.pool).await? == ["env-b"]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_acquisitions_cannot_both_take_the_last_slot() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let ids: Vec<String> = (0..8).map(|i| format!("env-{i}")).collect();
        let environments: Vec<(&str, &str)> =
            ids.iter().map(|id| (id.as_str(), "creating")).collect();
        seed(&db, &environments).await?;
        for _ in 0..5 {
            sqlx::query("DELETE FROM confidential_activation_slots")
                .execute(&db.pool)
                .await?;
            let attempts = ids.iter().map(|id| try_acquire(&db.pool, id, 1, LEASE));
            let taken = futures::future::try_join_all(attempts)
                .await?
                .into_iter()
                .filter(|taken| *taken)
                .count();
            ensure!(taken == 1, "{taken} of 8 took one slot");
            ensure!(holders(&db.pool).await?.len() == 1);
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_waiting_activation_takes_a_freed_slot_or_stops() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, &[("env-a", "creating"), ("env-b", "creating")]).await?;
        ensure!(try_acquire(&db.pool, "env-a", 1, LEASE).await?);
        let fast = Duration::from_millis(20);

        // Nothing frees: it fails at its queue limit, with the reason.
        let refused = wait_for_slot(
            &db.pool,
            "env-b",
            1,
            Duration::from_millis(200),
            fast,
            || async { Ok(()) },
        )
        .await;
        let error = refused.expect_err("no slot came free");
        ensure!(error.is::<QueueTimedOut>(), "{error:#}");
        ensure!(holders(&db.pool).await? == ["env-a"]);

        // No longer wanted (lost authority, cancelled): it stops at once.
        let cancelled = wait_for_slot(
            &db.pool,
            "env-b",
            1,
            Duration::from_secs(60),
            fast,
            || async { Err(anyhow::anyhow!("lost authority")) },
        )
        .await;
        ensure!(format!("{:#}", cancelled.expect_err("stops")) == "lost authority");

        // A slot freed while it waits is taken.
        let pool = db.pool.clone();
        let freer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            release(&pool, "env-a").await
        });
        wait_for_slot(
            &db.pool,
            "env-b",
            1,
            Duration::from_secs(10),
            fast,
            || async { Ok(()) },
        )
        .await?;
        freer.await??;
        ensure!(holders(&db.pool).await? == ["env-b"]);
        Ok(())
    }
    .await;
    db.finish(result).await
}
