//! Database proof of the running path's release (#6251). Each case runs in
//! its own disposable database from `TEST_DATABASE_URL`.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use sqlx::PgPool;

use super::super::{PhaseAcquire, PhasePreparation};
use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::activity_authority::is_authority_lost;

/// The phase a set-up Sandbox's post-start mutation runs at.
const PHASE: i32 = 2;
const RUN: &str = "run-a";
const WAIT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct StoredOwner {
    generation: i64,
    activity_id: String,
    attempt: i32,
    phase: i32,
    status: String,
    pod_uid: Option<String>,
}

/// A running, started Sandbox with `setup_complete` as given, its setup at
/// [`PHASE`], and generation 1 claimed by [`RUN`].
async fn seed(pool: &PgPool, setup_complete: bool) -> Result<String> {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let org_id = format!("org_stale_claim_{suffix}");
    let preset_id = format!("pre_stale_claim_{suffix}");
    let environment_id = format!("env_stale_claim_{suffix}");
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by)
         VALUES ($1, $1, $2, 'fixture-admin')",
    )
    .bind(&org_id)
    .bind(format!("stale-claim-{suffix}"))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
         VALUES ($1, $2, $1, $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&preset_id)
    .bind(&org_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments
                (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
         VALUES ($1, $2, 'fixture-admin', 'sandbox', 'running', 'started', $3,
                 '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&environment_id)
    .bind(&org_id)
    .bind(&preset_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend
                (environment_id, namespace, setup_phase, setup_complete)
         VALUES ($1, 'stale-claim-test', $2, $3)",
    )
    .bind(&environment_id)
    .bind(PHASE)
    .bind(setup_complete)
    .execute(pool)
    .await?;
    let generation = ActivityAuthority::claim(pool, &environment_id, RUN, 10).await?;
    ensure!(
        generation == 1,
        "the seeded Sandbox's first claim is generation 1"
    );
    Ok(environment_id)
}

/// Activity `activity_id`, attempt `attempt`, of [`RUN`] at generation 1.
async fn activity(
    pool: &PgPool,
    environment_id: &str,
    activity_id: &str,
    attempt: u32,
) -> Result<SetupPhaseAuthority> {
    let authority = ActivityAuthority::capture_for_run(pool, environment_id, 1, RUN).await?;
    SetupPhaseAuthority::new(
        authority,
        SetupActivityIdentity::new(1, activity_id.into(), attempt)?,
    )
}

/// Activity 118's first attempt takes the post-start lease, as
/// `handle_post_start_configuration` does, and stops there.
async fn claimed_owner(pool: &PgPool, environment_id: &str) -> Result<SetupPhaseAuthority> {
    let owner = activity(pool, environment_id, "118", 1).await?;
    ensure!(
        owner.prepare_post_start_mutation(PHASE).await?
            == PhasePreparation::Ready(PhaseAcquire::Acquired)
    );
    Ok(owner)
}

async fn stored_owner(pool: &PgPool, environment_id: &str) -> Result<Option<StoredOwner>> {
    Ok(sqlx::query_as::<_, StoredOwner>(
        "SELECT setup_owner_generation AS generation,
                setup_owner_activity_id AS activity_id,
                setup_owner_attempt AS attempt,
                setup_owner_phase AS phase,
                setup_owner_status AS status,
                setup_owner_pod_uid AS pod_uid
           FROM sandbox_environment_backend
          WHERE environment_id = $1 AND setup_owner_generation IS NOT NULL",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?)
}

fn owner_118(status: &str, pod_uid: Option<&str>) -> StoredOwner {
    StoredOwner {
        generation: 1,
        activity_id: "118".into(),
        attempt: 1,
        phase: PHASE,
        status: status.into(),
        pod_uid: pod_uid.map(str::to_owned),
    }
}

fn authority_lost<T>(result: anyhow::Result<T>) -> bool {
    result.is_err_and(|error| is_authority_lost(&error))
}

/// The owner a release reports: activity 118's first attempt, `claimed`.
fn released_118(released: Option<SetupLeaseRecord>) -> bool {
    released.is_some_and(|owner| {
        owner.identity == SetupActivityIdentity::new(1, "118".into(), 1).unwrap()
            && owner.phase == PHASE
            && owner.status == SetupLeaseStatus::Claimed
            && owner.pod_uid.is_none()
    })
}

macro_rules! database_case {
    ($name:ident, $pool:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let database = TestDatabase::create().await?;
            let result = async {
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
    db_a_later_attempt_releases_its_earlier_attempts_claim,
    pool,
    {
        let environment_id = seed(pool, true).await?;
        claimed_owner(pool, &environment_id).await?;
        let before = releases_metric().get();
        let retry = activity(pool, &environment_id, "118", 2).await?;
        ensure!(released_118(retry.release_stale_claimed_owner().await?));
        ensure!(stored_owner(pool, &environment_id).await?.is_none());
        ensure!(releases_metric().get() > before, "a release is counted");
    }
);

database_case!(db_a_later_activity_of_the_run_releases_the_claim, pool, {
    let environment_id = seed(pool, true).await?;
    claimed_owner(pool, &environment_id).await?;
    let later = activity(pool, &environment_id, "123", 1).await?;
    ensure!(released_118(later.release_stale_claimed_owner().await?));
    ensure!(stored_owner(pool, &environment_id).await?.is_none());
});

database_case!(db_a_released_owner_cannot_move_to_running_or_exec, pool, {
    let environment_id = seed(pool, true).await?;
    let zombie = claimed_owner(pool, &environment_id).await?;
    let later = activity(pool, &environment_id, "123", 1).await?;
    ensure!(released_118(later.release_stale_claimed_owner().await?));
    ensure!(authority_lost(
        zombie.mark_running(PHASE, "pod-zombie").await
    ));
    ensure!(authority_lost(
        zombie.begin_exec(PHASE, "pod-zombie").await.map(drop)
    ));
    ensure!(
        stored_owner(pool, &environment_id).await?.is_none(),
        "nothing recorded a launch"
    );
});

database_case!(
    db_a_running_or_reaping_owner_is_left_for_the_reap_path,
    pool,
    {
        let environment_id = seed(pool, true).await?;
        let owner = claimed_owner(pool, &environment_id).await?;
        owner.mark_running(PHASE, "pod-live").await?;
        let later = activity(pool, &environment_id, "123", 1).await?;
        ensure!(later.release_stale_claimed_owner().await?.is_none());
        ensure!(
            stored_owner(pool, &environment_id).await?
                == Some(owner_118("running", Some("pod-live")))
        );
        ensure!(owner.mark_current_reaping(PHASE).await?.is_some());
        ensure!(later.release_stale_claimed_owner().await?.is_none());
        ensure!(
            stored_owner(pool, &environment_id).await?
                == Some(owner_118("reaping", Some("pod-live")))
        );
    }
);

database_case!(db_the_activitys_own_claim_is_left, pool, {
    let environment_id = seed(pool, true).await?;
    let owner = claimed_owner(pool, &environment_id).await?;
    ensure!(owner.release_stale_claimed_owner().await?.is_none());
    ensure!(stored_owner(pool, &environment_id).await? == Some(owner_118("claimed", None)));
});

database_case!(db_a_claim_while_setup_is_incomplete_is_left, pool, {
    let environment_id = seed(pool, false).await?;
    let setup = activity(pool, &environment_id, "118", 1).await?;
    ensure!(setup.prepare_phase(PHASE).await? == PhasePreparation::Ready(PhaseAcquire::Acquired));
    let later = activity(pool, &environment_id, "123", 1).await?;
    ensure!(later.release_stale_claimed_owner().await?.is_none());
    ensure!(stored_owner(pool, &environment_id).await? == Some(owner_118("claimed", None)));
});

/// Waits until `count` sessions in this test's database wait on a lock.
async fn lock_waiters(pool: &PgPool, count: i64) -> Result<()> {
    tokio::time::timeout(WAIT, async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                  WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(pool)
            .await?;
            if waiting >= count {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("lock waiters did not queue in time")?
}

/// Runs `first` then `second` against the Sandbox's rows in that order: a
/// blocker holds the environment row while each queues behind it, so the
/// first to queue is the first to take the setup locks once it commits.
async fn race_in_order<A, B>(
    pool: &PgPool,
    environment_id: &str,
    first: A,
    second: B,
) -> Result<(A::Output, B::Output)>
where
    A: std::future::Future + Send + 'static,
    A::Output: Send + 'static,
    B: std::future::Future + Send + 'static,
    B::Output: Send + 'static,
{
    let mut blocker = pool.begin().await?;
    sqlx::query("SELECT 1 FROM environments WHERE id = $1 FOR UPDATE")
        .bind(environment_id)
        .execute(&mut *blocker)
        .await?;
    let first = tokio::spawn(first);
    lock_waiters(pool, 1).await?;
    let second = tokio::spawn(second);
    lock_waiters(pool, 2).await?;
    blocker.commit().await?;
    let (first, second) = tokio::time::timeout(WAIT, async { tokio::join!(first, second) })
        .await
        .context("the ordered setup writes did not finish in time")?;
    Ok((first?, second?))
}

database_case!(
    db_a_zombie_that_moves_to_running_first_is_not_released,
    pool,
    {
        let environment_id = seed(pool, true).await?;
        let zombie = claimed_owner(pool, &environment_id).await?;
        let retry = activity(pool, &environment_id, "118", 2).await?;
        let (launched, released) = race_in_order(
            pool,
            &environment_id,
            async move { zombie.mark_running(PHASE, "pod-zombie").await },
            async move { retry.release_stale_claimed_owner().await },
        )
        .await?;
        launched?;
        ensure!(released?.is_none(), "a running owner is not released");
        ensure!(
            stored_owner(pool, &environment_id).await?
                == Some(owner_118("running", Some("pod-zombie"))),
            "the running owner stays for the reap path"
        );
    }
);

database_case!(db_a_zombie_released_first_cannot_move_to_running, pool, {
    let environment_id = seed(pool, true).await?;
    let zombie = claimed_owner(pool, &environment_id).await?;
    let retry = activity(pool, &environment_id, "118", 2).await?;
    let exec_check = zombie.clone();
    let (released, launched) = race_in_order(
        pool,
        &environment_id,
        async move { retry.release_stale_claimed_owner().await },
        async move { zombie.mark_running(PHASE, "pod-zombie").await },
    )
    .await?;
    ensure!(released_118(released?));
    ensure!(authority_lost(launched));
    ensure!(authority_lost(
        exec_check.begin_exec(PHASE, "pod-zombie").await.map(drop)
    ));
    ensure!(stored_owner(pool, &environment_id).await?.is_none());
});
