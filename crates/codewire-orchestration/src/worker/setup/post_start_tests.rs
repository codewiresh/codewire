//! Database proof of the post-start error exit (#6258): an activity that
//! errors after taking the post-start lease releases its own lease while it
//! is still `claimed`, leaves any other owner alone, and returns its error.
//! Each case runs in its own disposable database from `TEST_DATABASE_URL`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use super::*;
use crate::test_database_support::TestDatabase;
use crate::worker::activity_authority::AuthorityLost;

/// The phase a set-up Sandbox's post-start mutation runs at.
const PHASE: i32 = 2;
const RUN: &str = "run-a";
const WAIT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct StoredOwner {
    activity_id: String,
    attempt: i32,
    status: String,
    pod_uid: Option<String>,
}

fn owner(activity_id: &str, attempt: i32, status: &str, pod_uid: Option<&str>) -> StoredOwner {
    StoredOwner {
        activity_id: activity_id.into(),
        attempt,
        status: status.into(),
        pod_uid: pod_uid.map(str::to_owned),
    }
}

/// A running, started, set-up Sandbox at [`PHASE`], generation 1 claimed by
/// [`RUN`].
async fn seed(pool: &PgPool) -> Result<String> {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let org_id = format!("org_post_start_{suffix}");
    let preset_id = format!("pre_post_start_{suffix}");
    let environment_id = format!("env_post_start_{suffix}");
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by)
         VALUES ($1, $1, $2, 'fixture-admin')",
    )
    .bind(&org_id)
    .bind(format!("post-start-{suffix}"))
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
         VALUES ($1, 'post-start-test', $2, true)",
    )
    .bind(&environment_id)
    .bind(PHASE)
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

/// Takes the post-start lease as `handle_post_start_configuration` does.
async fn claim(authority: &SetupPhaseAuthority) -> Result<()> {
    ensure!(
        authority.prepare_post_start_mutation(PHASE).await?
            == PhasePreparation::Ready(PhaseAcquire::Acquired)
    );
    Ok(())
}

async fn stored_owner(pool: &PgPool, environment_id: &str) -> Result<Option<StoredOwner>> {
    Ok(sqlx::query_as::<_, StoredOwner>(
        "SELECT setup_owner_activity_id AS activity_id,
                setup_owner_attempt AS attempt,
                setup_owner_status AS status,
                setup_owner_pod_uid AS pod_uid
           FROM sandbox_environment_backend
          WHERE environment_id = $1 AND setup_owner_generation IS NOT NULL",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?)
}

/// The error the post-start steps fail with, recognisable after it returns.
#[derive(Debug)]
struct StepFailed;

impl std::fmt::Display for StepFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("synthetic post-start step failure")
    }
}

impl std::error::Error for StepFailed {}

/// Whether `result` is exactly the error the steps returned: the root
/// cause `T` and the context `step` added on top of it, nothing more.
fn is_original<T: std::error::Error + Send + Sync + 'static>(
    result: &anyhow::Result<()>,
    step: &str,
) -> bool {
    let Err(error) = result else {
        return false;
    };
    error.to_string() == step && error.chain().count() == 2 && error.root_cause().is::<T>()
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

/// Log lines written as JSON while a case runs.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Captured {
    fn lines(&self) -> Result<Vec<serde_json::Value>> {
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }
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

database_case!(db_an_authority_loss_after_the_claim_releases_it, pool, {
    let environment_id = seed(pool).await?;
    let post_start = activity(pool, &environment_id, "118", 1).await?;
    claim(&post_start).await?;
    let result = under_post_start_lease(&post_start, PHASE, async {
        Err(anyhow::Error::new(AuthorityLost).context("ensure_can_commit"))
    })
    .await;
    ensure!(
        is_original::<AuthorityLost>(&result, "ensure_can_commit"),
        "the original error is returned: {result:?}"
    );
    ensure!(stored_owner(pool, &environment_id).await?.is_none());
});

database_case!(db_a_cancel_after_the_claim_leaves_no_claimed_owner, pool, {
    let environment_id = seed(pool).await?;
    let post_start = activity(pool, &environment_id, "118", 1).await?;
    claim(&post_start).await?;
    let result = under_post_start_lease(&post_start, PHASE, async {
        Err(anyhow::Error::new(SetupActivityCancelled).context("startup_script"))
    })
    .await;
    ensure!(
        is_original::<SetupActivityCancelled>(&result, "startup_script"),
        "the original error is returned: {result:?}"
    );
    ensure!(stored_owner(pool, &environment_id).await?.is_none());
});

database_case!(db_a_running_owner_is_unchanged_by_the_error_exit, pool, {
    let environment_id = seed(pool).await?;
    let post_start = activity(pool, &environment_id, "118", 1).await?;
    claim(&post_start).await?;
    let result = under_post_start_lease(&post_start, PHASE, async {
        post_start.mark_running(PHASE, "pod-live").await?;
        Err(anyhow::Error::new(SetupActivityCancelled).context("startup_script"))
    })
    .await;
    ensure!(
        is_original::<SetupActivityCancelled>(&result, "startup_script"),
        "the original error is returned: {result:?}"
    );
    ensure!(
        stored_owner(pool, &environment_id).await?
            == Some(owner("118", 1, "running", Some("pod-live"))),
        "a running owner is left for the reap path, not cleared or reaped"
    );
});

database_case!(
    db_a_taken_over_activitys_error_exit_leaves_the_newer_owners_claim,
    pool,
    {
        let environment_id = seed(pool).await?;
        let post_start = activity(pool, &environment_id, "118", 1).await?;
        claim(&post_start).await?;
        let retry = activity(pool, &environment_id, "118", 2).await?;
        let result = under_post_start_lease(&post_start, PHASE, async {
            claim(&retry).await?;
            Err(anyhow::Error::new(StepFailed).context("emit_log"))
        })
        .await;
        ensure!(
            is_original::<StepFailed>(&result, "emit_log"),
            "the original error is returned: {result:?}"
        );
        ensure!(
            stored_owner(pool, &environment_id).await? == Some(owner("118", 2, "claimed", None)),
            "the newer owner keeps its claim"
        );
    }
);

database_case!(db_a_takeover_that_commits_first_is_left_alone, pool, {
    let environment_id = seed(pool).await?;
    let post_start = activity(pool, &environment_id, "118", 1).await?;
    claim(&post_start).await?;
    let retry = activity(pool, &environment_id, "118", 2).await?;
    let (taken, exited) = race_in_order(
        pool,
        &environment_id,
        async move { claim(&retry).await },
        async move {
            under_post_start_lease(&post_start, PHASE, async {
                Err(anyhow::Error::new(StepFailed).context("emit_log"))
            })
            .await
        },
    )
    .await?;
    taken?;
    ensure!(
        is_original::<StepFailed>(&exited, "emit_log"),
        "the original error is returned: {exited:?}"
    );
    ensure!(
        stored_owner(pool, &environment_id).await? == Some(owner("118", 2, "claimed", None)),
        "the release read the newer owner under its locks and left it"
    );
});

database_case!(
    db_a_failed_release_is_logged_and_the_original_error_returned,
    pool,
    {
        let environment_id = seed(pool).await?;
        // The activity's own pool, closed by its steps, so only the release
        // fails; the case reads the row through `pool`.
        let own_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with((*pool.connect_options()).clone())
            .await?;
        let authority =
            ActivityAuthority::capture_for_run(&own_pool, &environment_id, 1, RUN).await?;
        let post_start =
            SetupPhaseAuthority::new(authority, SetupActivityIdentity::new(1, "118".into(), 1)?)?;
        claim(&post_start).await?;
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .finish();
        let result = {
            let _logs = tracing::subscriber::set_default(subscriber);
            under_post_start_lease(&post_start, PHASE, async {
                own_pool.close().await;
                Err(anyhow::Error::new(SetupActivityCancelled).context("startup_script"))
            })
            .await
        };
        ensure!(
            is_original::<SetupActivityCancelled>(&result, "startup_script"),
            "the original error is returned, not the release's: {result:?}"
        );
        let lines = captured.lines()?;
        let logged = lines.iter().any(|line| {
            let fields = &line["fields"];
            line["level"] == "WARN"
                && fields["message"] == "post-start: releasing its own claimed setup lease failed"
                && fields["environment_id"] == environment_id.as_str()
                && fields["activity_generation"] == 1
                && fields["activity_id"] == "118"
                && fields["activity_attempt"] == 1
                && fields["phase"] == PHASE
                && fields["error"] == "startup_script: environment setup activity cancelled"
                && fields["release_error"]
                    .as_str()
                    .is_some_and(|error| !error.is_empty())
        });
        ensure!(logged, "the failed release is logged: {lines:?}");
        ensure!(
            stored_owner(pool, &environment_id).await? == Some(owner("118", 1, "claimed", None)),
            "nothing was released"
        );
    }
);

database_case!(
    db_success_still_clears_through_complete_post_start_mutation,
    pool,
    {
        let environment_id = seed(pool).await?;
        let post_start = activity(pool, &environment_id, "118", 1).await?;
        claim(&post_start).await?;
        let result = under_post_start_lease(&post_start, PHASE, async {
            post_start.mark_running(PHASE, "pod-live").await
        })
        .await;
        ensure!(result.is_ok(), "{result:?}");
        ensure!(
            stored_owner(pool, &environment_id).await?.is_none(),
            "complete_post_start_mutation clears the running owner"
        );
    }
);
