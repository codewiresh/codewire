//! Leadership handover when a replica drains (#4426), against PostgreSQL.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{Leadership, leader_loop};

/// One replica's leader election, as `start_loops` runs it.
struct Replica {
    leadership: Arc<Leadership>,
    draining: CancellationToken,
    task: JoinHandle<()>,
}

impl Replica {
    fn start(database_url: &str) -> Self {
        let leadership = Arc::new(Leadership::default());
        let draining = CancellationToken::new();
        let task = tokio::spawn({
            let database_url = database_url.to_owned();
            let leadership = leadership.clone();
            let draining = draining.clone();
            async move {
                leader_loop(&database_url, leadership, Arc::new(Notify::new()), draining).await;
            }
        });
        Self {
            leadership,
            draining,
            task,
        }
    }

    fn leads(&self) -> bool {
        self.leadership.leads()
    }

    /// Drains this replica and waits for its election loop to end.
    async fn drain(self) -> Result<()> {
        self.draining.cancel();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .context("a draining replica's election loop did not end")??;
        ensure!(!self.leadership.leads(), "a drained replica still leads");
        Ok(())
    }
}

async fn until(what: &str, bound: Duration, check: impl Fn() -> bool) -> Result<()> {
    let deadline = Instant::now() + bound;
    while !check() {
        ensure!(Instant::now() < deadline, "{what} within {bound:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

// One test, so nothing else in this binary contends for the leader lock.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_draining_leader_hands_over_after_its_running_pass_and_a_draining_follower_never_leads()
-> Result<()> {
    let url = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL is required")?;

    let first = Replica::start(&url);
    until("the first replica leads", Duration::from_secs(10), || {
        first.leads()
    })
    .await?;
    let second = Replica::start(&url);
    let third = Replica::start(&url);
    tokio::time::sleep(Duration::from_secs(1)).await;
    ensure!(
        !second.leads() && !third.leads(),
        "a follower leads while the lock is held"
    );

    // A draining follower stops trying: it never leads, even once the lock
    // is free.
    third.drain().await?;

    // The leader drains under a running pass: no new pass starts, and it keeps
    // the lock, with the follower waiting, until that pass ends.
    let running = first.leadership.pass().context("a leader starts a pass")?;
    let first_leadership = first.leadership.clone();
    let draining = tokio::spawn(first.drain());
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(
        first_leadership.pass().is_none(),
        "a pass started after the drain decided"
    );
    ensure!(
        !draining.is_finished(),
        "the drain released under a running pass"
    );
    ensure!(!second.leads(), "the follower leads beside a running pass");

    // The pass ends: the lock goes at once, and the waiting follower leads
    // within one retry instead of after the old replica exits.
    let released = Instant::now();
    drop(running);
    draining.await.context("drain task")??;
    until(
        "the follower leads after the handover",
        Duration::from_secs(10),
        || second.leads(),
    )
    .await?;
    ensure!(
        released.elapsed() < Duration::from_secs(7),
        "the handover took {:?}, longer than one retry",
        released.elapsed()
    );

    second.drain().await
}
