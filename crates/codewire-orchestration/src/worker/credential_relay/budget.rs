//! Byte budgets for the frames the relay holds on their way to the broker.
//!
//! The workspace daemon produces those frames, and one orchestration process
//! relays every environment. A frame is read from the daemon only once its
//! bytes fit both its epoch stream's budget and its environment's, so a broker
//! that stops reading back-pressures the daemon instead of growing a queue
//! here. Frames toward the daemon come from the broker, which bounds their
//! size itself; the relay holds one at a time and waits for the daemon only
//! [`STALL_TIMEOUT`].

use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One epoch stream: two of the largest frames the bridge admits.
pub(super) const STREAM_BUDGET_BYTES: usize = 2 * CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
/// Every epoch of one environment together. At most two epochs relay at once,
/// so one that stalls still leaves the other room for a largest frame.
pub(super) const ENVIRONMENT_BUDGET_BYTES: usize = 3 * CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
/// A frame that makes no progress for this long, waiting for budget or for
/// its receiver, ends its epoch. The relay then starts a fresh one.
pub(super) const STALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) stream: usize,
    pub(super) environment: usize,
    pub(super) stall: Duration,
}

impl Limits {
    pub(super) const DEFAULT: Self = Self {
        stream: STREAM_BUDGET_BYTES,
        environment: ENVIRONMENT_BUDGET_BYTES,
        stall: STALL_TIMEOUT,
    };
}

/// One environment's budget, shared by all of its epochs.
#[derive(Clone)]
pub(super) struct EnvironmentBudget {
    limits: Limits,
    environment: Arc<Semaphore>,
}

impl EnvironmentBudget {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            environment: Arc::new(Semaphore::new(limits.environment)),
        }
    }

    pub(super) fn stall(&self) -> Duration {
        self.limits.stall
    }

    /// A fresh budget for one epoch stream, drawing on this environment's.
    pub(super) fn stream(&self) -> StreamBudget {
        StreamBudget {
            limit: self.limits.stream.min(self.limits.environment),
            stream: Arc::new(Semaphore::new(self.limits.stream)),
            environment: self.environment.clone(),
        }
    }

    #[cfg(test)]
    pub(super) fn available(&self) -> usize {
        self.environment.available_permits()
    }
}

pub(super) struct StreamBudget {
    limit: usize,
    stream: Arc<Semaphore>,
    environment: Arc<Semaphore>,
}

/// The frame can never fit: it is larger than a whole budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Oversized;

/// Bytes held for one queued frame, returned to both budgets on drop.
pub(super) struct Charge {
    _stream: OwnedSemaphorePermit,
    _environment: OwnedSemaphorePermit,
}

impl StreamBudget {
    /// Waits until `bytes` fit both budgets. The caller bounds the wait.
    pub(super) async fn charge(&self, bytes: usize) -> Result<Charge, Oversized> {
        if bytes > self.limit {
            return Err(Oversized);
        }
        let permits = u32::try_from(bytes).map_err(|_| Oversized)?;
        // Neither semaphore is ever closed.
        let stream = self
            .stream
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| Oversized)?;
        let environment = self
            .environment
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| Oversized)?;
        Ok(Charge {
            _stream: stream,
            _environment: environment,
        })
    }

    #[cfg(test)]
    pub(super) fn available(&self) -> usize {
        self.stream.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        stream: 100,
        environment: 150,
        stall: Duration::from_secs(1),
    };

    #[test]
    fn the_defaults_admit_a_largest_frame_in_every_epoch() {
        let limits = Limits::DEFAULT;
        assert!(limits.stream >= CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        // A stream holding all of its budget leaves another a largest frame.
        assert!(limits.environment - limits.stream >= CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        assert!(u32::try_from(limits.environment).is_ok());
    }

    #[tokio::test]
    async fn a_frame_larger_than_its_budget_is_refused_at_once() {
        let budget = EnvironmentBudget::new(LIMITS);
        let stream = budget.stream();
        assert!(matches!(stream.charge(101).await, Err(Oversized)));
        let narrow = EnvironmentBudget::new(Limits {
            environment: 50,
            ..LIMITS
        });
        assert!(matches!(narrow.stream().charge(51).await, Err(Oversized)));
        assert_eq!((stream.available(), budget.available()), (100, 150));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_waits_for_its_own_and_its_environments_bytes() {
        let budget = EnvironmentBudget::new(LIMITS);
        let first = budget.stream();
        let second = budget.stream();
        let held = first.charge(100).await.unwrap();
        // The first stream is full; the second still has room in the rest of
        // the environment's budget.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), first.charge(1))
                .await
                .is_err()
        );
        let other = second.charge(50).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), second.charge(1))
                .await
                .is_err()
        );
        assert_eq!(budget.available(), 0);
        // Returned bytes are available again, to either stream.
        drop(held);
        let again = second.charge(50).await.unwrap();
        assert_eq!((first.available(), second.available()), (100, 0));
        assert_eq!(budget.available(), 50);
        drop((other, again));
        assert_eq!(budget.available(), 150);
    }
}
