//! The bridge service's one budget of concurrent leases.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::BrokerLeaseError;
use crate::timing::{self, Phase};

/// One process-wide budget of concurrent leases, shared by every epoch of one
/// bridge service. A slot covers exactly one lease: its record read, any
/// authority evaluation it runs or waits for (or its full per-request checks),
/// and its protected-material read (SQL and the KEK unwrap) or reuse from its
/// epoch's material cache; never provider I/O, a refresh or a response body.
/// A lease waits for a slot in arrival order until its connected
/// identity's original expiry, the deadline that already bounds that lease, so
/// a burst queues instead of failing.
#[derive(Clone)]
pub(crate) struct LeaseBudget {
    pub(super) permits: Arc<tokio::sync::Semaphore>,
    capacity: usize,
}

impl LeaseBudget {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            capacity,
        }
    }

    /// Fail every waiting and later lease; held slots finish normally.
    pub(crate) fn close(&self) {
        self.permits.close();
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.permits.available_permits()
    }

    pub(super) async fn acquire(
        &self,
        expires_at_unix: u64,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, BrokerLeaseError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let deadline = Duration::from_secs(expires_at_unix)
            .checked_sub(now)
            .and_then(|remaining| tokio::time::Instant::now().checked_add(remaining))
            .ok_or(BrokerLeaseError::Denied)?;
        let acquired = timing::timed(
            Phase::LeaseWait,
            tokio::time::timeout_at(deadline, Arc::clone(&self.permits).acquire_owned()),
        )
        .await;
        match acquired {
            Ok(Ok(permit)) => Ok(permit),
            // Closed by shutdown.
            Ok(Err(_)) => Err(BrokerLeaseError::Unavailable),
            Err(_) => {
                timing::capacity_rejected(
                    "broker_leases",
                    "lease",
                    self.capacity,
                    self.capacity
                        .saturating_sub(self.permits.available_permits()),
                );
                Err(BrokerLeaseError::Unavailable)
            }
        }
    }
}
