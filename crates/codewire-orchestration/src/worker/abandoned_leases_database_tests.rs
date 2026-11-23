//! The ownerless-lease sweep (#4523) against PostgreSQL: a lease is settled
//! only once its owner has written no heartbeat for the grace, and the lease
//! itself is that old, all on the database's clock. Each case owns a
//! disposable database; times are set in the past rather than waited for.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;
use crate::lease_owner::WRITE_HEARTBEAT;
use crate::test_database_support::TestDatabase;

const ORG: &str = "lease-owner-org";
const ENV: &str = "550e8400-e29b-41d4-a716-446655440524";
const OWNER: i64 = 0x4523_0001;

/// An active runtime lease of `owner`, admitted `age` seconds ago.
async fn lease(pool: &PgPool, id: &str, owner: Option<i64>, age: u32) -> Result<()> {
    sqlx::query(
        "INSERT INTO organization_mutation_leases \
           (id,organization_id,mutation_class,admitted_at,deadline_at,environment_id,owner_incarnation) \
         VALUES ($1,$2,'environment_runtime_dispatch', \
                 LOCALTIMESTAMP - make_interval(secs => $5), \
                 LOCALTIMESTAMP - make_interval(secs => $5) + interval '60 seconds',$3,$4)",
    )
    .bind(id)
    .bind(ORG)
    .bind(ENV)
    .bind(owner)
    .bind(f64::from(age))
    .execute(pool)
    .await?;
    Ok(())
}

/// `owner`'s last heartbeat, `age` seconds ago.
async fn heartbeat(pool: &PgPool, owner: i64, age: u32) -> Result<()> {
    sqlx::query(
        "INSERT INTO lease_owner_heartbeats(incarnation,last_seen) \
         VALUES ($1, LOCALTIMESTAMP - make_interval(secs => $2)) \
         ON CONFLICT (incarnation) DO UPDATE SET last_seen = EXCLUDED.last_seen",
    )
    .bind(owner)
    .bind(f64::from(age))
    .execute(pool)
    .await?;
    Ok(())
}

async fn state(pool: &PgPool, id: &str) -> Result<(String, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT state,recovery_code FROM organization_mutation_leases WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await?,
    )
}

fn sweep(pool: &PgPool) -> OwnerlessLeases {
    OwnerlessLeases::new(pool.clone(), INCARNATION_GRACE)
}

macro_rules! database_case {
    ($name:ident, $pool:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let database = TestDatabase::create().await?;
            let result = async {
                database.organization(ORG).await?;
                let $pool = &database.pool;
                $body
                Ok(())
            }
            .await;
            database.finish(result).await
        }
    };
}

database_case!(
    db_a_lease_whose_owner_keeps_writing_heartbeats_is_never_settled,
    pool,
    {
        lease(pool, "lease-live", Some(OWNER), 600).await?;
        heartbeat(pool, OWNER, 0).await?;
        ensure!(sweep(pool).sweep(32).await? == 0);
        ensure!(state(pool, "lease-live").await? == ("active".into(), None));
    }
);

database_case!(
    db_a_lease_is_settled_once_its_owner_wrote_no_heartbeat_for_the_grace,
    pool,
    {
        lease(pool, "lease-gone", Some(OWNER), 600).await?;
        heartbeat(pool, OWNER, 310).await?;
        // An owner that died before its first heartbeat: only its lease's age.
        lease(pool, "lease-never", Some(OWNER + 1), 600).await?;
        ensure!(sweep(pool).sweep(32).await? == 2);
        for id in ["lease-gone", "lease-never"] {
            ensure!(
                state(pool, id).await?
                    == (
                        "resolution_required".into(),
                        Some("environment_runtime_dispatch_owner_lost".into())
                    ),
                "{id}"
            );
        }
        ensure!(sweep(pool).sweep(32).await? == 0);
    }
);

database_case!(
    db_a_heartbeat_just_inside_the_grace_keeps_every_lease_of_its_owner,
    pool,
    {
        // The review's case: an owner that went quiet, came back and admitted a
        // lease, and wrote its last heartbeat ten seconds before the grace would
        // have run out from its first quiet moment.
        lease(pool, "lease-old", Some(OWNER), 600).await?;
        lease(pool, "lease-readmitted", Some(OWNER), 240).await?;
        heartbeat(pool, OWNER, 10).await?;
        ensure!(sweep(pool).sweep(32).await? == 0);
        // An owner quiet for longer than the grace, whose lease is younger than
        // it: it was alive when it admitted that lease.
        lease(pool, "lease-young", Some(OWNER + 2), 290).await?;
        heartbeat(pool, OWNER + 2, 400).await?;
        ensure!(sweep(pool).sweep(32).await? == 0);
        for id in ["lease-old", "lease-readmitted", "lease-young"] {
            ensure!(state(pool, id).await?.0 == "active", "{id}");
        }
    }
);

database_case!(
    db_leases_without_an_owner_or_held_by_a_journal_are_left_alone,
    pool,
    {
        // Admitted before owners were recorded.
        lease(pool, "lease-unowned", None, 600).await?;
        // Held by a cw runtime request, which its own kind settles.
        lease(pool, "lease-journal", Some(OWNER), 600).await?;
        sqlx::query(
            "INSERT INTO environment_cw_runtime_requests \
           (request_id,organization_id,environment_id,actor_user_id,via_api_key,pod_uid, \
            fingerprint,request_json,binding_json,expected_store_generation,owner_id, \
            mutation_lease_id) \
         VALUES (gen_random_uuid(),$1,$2,'lease-owner-user',false, \
            '7e7b20f6-0bd2-4f11-8b16-9c239851eb52'::uuid,repeat('a',64), \
            '{\"expected_store_generation\":\"1\"}'::jsonb, \
            jsonb_build_object('organization_id',$1::text,'environment_id',$2::text, \
                               'pod_uid','7e7b20f6-0bd2-4f11-8b16-9c239851eb52'), \
            '1',gen_random_uuid(),'lease-journal')",
        )
        .bind(ORG)
        .bind(ENV)
        .execute(pool)
        .await?;
        ensure!(sweep(pool).sweep(32).await? == 0);
        ensure!(state(pool, "lease-unowned").await?.0 == "active");
        ensure!(state(pool, "lease-journal").await?.0 == "active");
    }
);

database_case!(db_the_heartbeat_records_and_refreshes_its_owner, pool, {
    heartbeat(pool, OWNER, 900).await?;
    sqlx::query(WRITE_HEARTBEAT)
        .bind(OWNER)
        .execute(pool)
        .await?;
    let fresh: bool = sqlx::query_scalar(
        "SELECT last_seen > LOCALTIMESTAMP - interval '5 seconds' \
         FROM lease_owner_heartbeats WHERE incarnation=$1",
    )
    .bind(OWNER)
    .fetch_one(pool)
    .await?;
    ensure!(fresh, "the heartbeat did not refresh its row");
    sqlx::query(WRITE_HEARTBEAT)
        .bind(OWNER + 3)
        .execute(pool)
        .await?;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM lease_owner_heartbeats")
        .fetch_one(pool)
        .await?;
    ensure!(rows == 2);
});

database_case!(
    db_day_old_heartbeats_go_once_their_owner_holds_no_active_lease,
    pool,
    {
        heartbeat(pool, OWNER, 2 * 86_400).await?;
        heartbeat(pool, OWNER + 4, 2 * 86_400).await?;
        lease(pool, "lease-held", Some(OWNER + 4), 2 * 86_400).await?;
        // A fresh heartbeat with no lease stays: its process is alive.
        heartbeat(pool, OWNER + 5, 0).await?;
        // The pass settles the held lease first, so both day-old rows then have
        // no active lease and go.
        ensure!(sweep(pool).sweep(32).await? == 1);
        let left: Vec<i64> = sqlx::query_scalar(
            "SELECT incarnation FROM lease_owner_heartbeats ORDER BY incarnation",
        )
        .fetch_all(pool)
        .await?;
        ensure!(left == vec![OWNER + 5], "{left:?}");
    }
);
