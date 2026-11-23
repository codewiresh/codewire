//! This process as the owner of its runtime leases (#4523). It picks a random
//! incarnation at start, records it on every environment runtime lease it
//! admits (`codewire_server_core::lease_owner`), and writes a heartbeat for it
//! (`lease_owner_heartbeats`) every [`INCARNATION_CHECK`] on a connection of
//! its own. The leader's abandoned-leases sweep settles a lease whose owner has
//! written no heartbeat for [`INCARNATION_GRACE`]: that owner has died, or
//! fenced and stopped acting for it.
//!
//! A failed heartbeat is retried every [`INCARNATION_RETRY`]. Failures for
//! less than [`INCARNATION_FENCE`] change nothing. After that long without a
//! successful heartbeat the process fences: it stops acting for the runtime
//! leases it holds and admits no new ones, which puts the fence at most about
//! 77 s after the last successful heartbeat, well inside the grace. The process
//! never exits for this; the next successful heartbeat lifts the fence.
//! `docs/dev/CW-RUNTIME-JOURNAL.md` gives the reasoning for each bound.

use std::time::Duration;

use async_trait::async_trait;
use codewire_server_core::AppError;
use sqlx::{Connection, PgConnection};
use tokio::sync::watch;
use tokio::time::Instant;

/// How often a failed heartbeat is tried again.
pub const INCARNATION_RETRY: Duration = Duration::from_secs(2);
/// How often a healthy process writes its heartbeat, and how long one write
/// may take.
pub const INCARNATION_CHECK: Duration = Duration::from_secs(5);
/// How long a process may go without a successful heartbeat before it fences.
pub const INCARNATION_FENCE: Duration = Duration::from_secs(60);
/// How long an owner must have written no heartbeat before the sweep settles
/// its leases: well past the fence, so its holders have stopped.
pub const INCARNATION_GRACE: Duration = Duration::from_secs(5 * 60);

/// Whether this process is fenced, and how many times it has been. A holder
/// waits for the count to change, so it never misses a fence that lifted at
/// once, as one does when a frozen process resumes and its next heartbeat
/// succeeds.
#[derive(Clone, Copy, Debug, Default)]
struct Fence {
    up: bool,
    raised: u64,
}

/// This process as the owner of its runtime leases: its incarnation, and
/// whether it is fenced.
#[derive(Clone)]
pub struct LeaseOwner {
    key: Option<i64>,
    fenced: watch::Receiver<Fence>,
    /// A test's fence, raised inside [`Self::admit`] between taking the fence
    /// and checking it, the moment its order exists to cover.
    #[cfg(test)]
    raised_during_admission: Option<std::sync::Arc<watch::Sender<Fence>>>,
}

impl LeaseOwner {
    /// An owner with no incarnation, never fenced, for a process that records
    /// no owner on its leases.
    pub fn none() -> Self {
        let (_never, fenced) = watch::channel(Fence::default());
        Self {
            key: None,
            fenced,
            #[cfg(test)]
            raised_during_admission: None,
        }
    }

    /// The key this process's leases record, if it has one.
    pub fn key(&self) -> Option<i64> {
        self.key
    }

    fn is_fenced(&self) -> bool {
        self.fenced.borrow().up
    }

    /// Admits a new runtime lease holder. It takes the fence first, then
    /// refuses while fenced, and returns the fence for the holder to watch for
    /// as long as it acts for its lease. A fence raised after the check is
    /// seen by the returned future, and one raised before it is refused here,
    /// so no holder can miss one. This is the only way to get the fence.
    #[must_use = "a holder keeps the fence it was admitted under, and stops when it completes"]
    pub fn admit(
        &self,
    ) -> Result<impl std::future::Future<Output = ()> + Send + 'static, AppError> {
        let fenced = self.fenced();
        #[cfg(test)]
        if let Some(fence) = &self.raised_during_admission {
            raise(fence, Duration::ZERO);
        }
        self.admitting()?;
        Ok(fenced)
    }

    /// Completes once this process fences after this call; never, if it
    /// cannot.
    fn fenced(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut fenced = self.fenced.clone();
        let since = fenced.borrow().raised;
        async move {
            if fenced
                .wait_for(|fence| fence.raised != since)
                .await
                .is_err()
            {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Refuses a new runtime lease while fenced: the sweep may already count
    /// this process as gone.
    fn admitting(&self) -> Result<(), AppError> {
        if self.is_fenced() {
            return Err(AppError::ServiceUnavailable(
                "this Codewire server's lease-owner heartbeat is failing; try again".into(),
            ));
        }
        Ok(())
    }
}

/// Picks this process's incarnation, records it for lease admission, and
/// starts writing its heartbeat.
pub fn spawn(database_url: String) -> LeaseOwner {
    let key = loop {
        let key: i64 = rand::random();
        if key != 0 {
            break key;
        }
    };
    if !codewire_server_core::lease_owner::set_incarnation(key) {
        tracing::error!("lease owner: an incarnation was already set; leases keep the first");
    }
    let (fenced_tx, fenced) = watch::channel(Fence::default());
    tokio::spawn(beat(PgHeartbeat::new(database_url), key, fenced_tx));
    tracing::info!("lease owner: writing this process's heartbeat");
    LeaseOwner {
        key: Some(key),
        fenced,
        #[cfg(test)]
        raised_during_admission: None,
    }
}

#[async_trait]
trait Heartbeat: Send {
    /// Records that `key`'s process is alive now; true once written.
    async fn write(&mut self, key: i64) -> bool;
}

async fn beat<H: Heartbeat>(mut heartbeat: H, key: i64, fence: watch::Sender<Fence>) {
    let mut last_written = Instant::now();
    loop {
        // A process that was frozen, a SIGSTOP or a paused VM, may have been
        // counted gone meanwhile: it fences before it acts again.
        if last_written.elapsed() >= INCARNATION_FENCE {
            raise(&fence, last_written.elapsed());
        }
        if heartbeat.write(key).await {
            // The write itself may have spanned such a freeze.
            if last_written.elapsed() >= INCARNATION_FENCE {
                raise(&fence, last_written.elapsed());
            }
            last_written = Instant::now();
            if fence.send_if_modified(|fence| std::mem::replace(&mut fence.up, false)) {
                tracing::info!("lease owner: heartbeat written again; lifting the fence");
            }
            tokio::time::sleep(INCARNATION_CHECK).await;
            continue;
        }
        if last_written.elapsed() >= INCARNATION_FENCE {
            raise(&fence, last_written.elapsed());
        }
        tokio::time::sleep(INCARNATION_RETRY).await;
    }
}

/// Fences this process, once per loss, so every holder stops.
fn raise(fence: &watch::Sender<Fence>, without: Duration) {
    let raised = fence.send_if_modified(|fence| {
        if fence.up {
            return false;
        }
        fence.up = true;
        fence.raised += 1;
        true
    });
    if raised {
        tracing::error!(
            ?without,
            "lease owner: fencing; this process stops acting for its runtime leases"
        );
    }
}

/// A fence a test raises by hand, to prove a holder stops on it.
#[cfg(test)]
pub(crate) struct FenceSwitch(watch::Sender<Fence>);

#[cfg(test)]
impl FenceSwitch {
    pub(crate) fn fence(&self) {
        raise(&self.0, Duration::ZERO);
    }
}

#[cfg(test)]
impl LeaseOwner {
    /// An owner with an incarnation whose fence the test controls.
    pub(crate) fn switchable() -> (Self, FenceSwitch) {
        let (switch, fenced) = watch::channel(Fence::default());
        (
            Self {
                key: Some(7),
                fenced,
                raised_during_admission: None,
            },
            FenceSwitch(switch),
        )
    }

    /// An owner whose process fences inside every admission, between taking
    /// the fence and checking it.
    pub(crate) fn fencing_during_admission() -> Self {
        let (switch, fenced) = watch::channel(Fence::default());
        Self {
            key: Some(7),
            fenced,
            raised_during_admission: Some(std::sync::Arc::new(switch)),
        }
    }
}

struct PgHeartbeat {
    database_url: String,
    connection: Option<PgConnection>,
}

impl PgHeartbeat {
    fn new(database_url: String) -> Self {
        Self {
            database_url,
            connection: None,
        }
    }
}

/// The heartbeat itself, on the database's clock, as the leases' own times.
pub(crate) const WRITE_HEARTBEAT: &str = "INSERT INTO lease_owner_heartbeats(incarnation,last_seen) \
     VALUES ($1, LOCALTIMESTAMP) \
     ON CONFLICT (incarnation) DO UPDATE SET last_seen = LOCALTIMESTAMP";

#[async_trait]
impl Heartbeat for PgHeartbeat {
    async fn write(&mut self, key: i64) -> bool {
        let attempt = async {
            if self.connection.is_none() {
                self.connection = Some(PgConnection::connect(&self.database_url).await?);
            }
            let connection = self.connection.as_mut().expect("connected above");
            sqlx::query(WRITE_HEARTBEAT)
                .bind(key)
                .execute(connection)
                .await?;
            Ok::<_, sqlx::Error>(())
        };
        match tokio::time::timeout(INCARNATION_CHECK, attempt).await {
            Ok(Ok(())) => true,
            failed => {
                if let Ok(Err(error)) = failed {
                    tracing::warn!(error = %error, "lease owner: heartbeat failed");
                }
                // A connection that failed or hung is dropped, closing it.
                self.connection = None;
                false
            }
        }
    }
}

#[cfg(test)]
#[path = "lease_owner_tests.rs"]
mod tests;
