//! When a stopping cw-egress drains, and when it gives up (#4000, item 5).
//!
//! A new cw-egress version starts on a node beside the one it replaces, and
//! the old Pod is told to stop only once the new one is Ready. From then on
//! new streams reach the new Pod. The old one drains: a sandbox that holds
//! no open flow is moved at once, by ending its pair so its
//! guest redials, and a sandbox that still holds one at the deadline is cut
//! then, which resets its connections once.

use std::future::Future;
use std::time::Duration;

use thiserror::Error;

use crate::supervisor::Signals;

/// How long a stopping cw-egress keeps a sandbox that has open connections,
/// in seconds. The Pod's grace period is longer, so the deadline cuts the
/// last streams before the kubelet kills the process.
pub const DRAIN_SECONDS: &str = "CODEWIRE_EGRESS_DRAIN_SECONDS";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DrainSettingError {
    #[error("{DRAIN_SECONDS} is not set")]
    Missing,
    #[error("{DRAIN_SECONDS} is {0:?}, not a whole number of seconds")]
    Invalid(String),
}

/// The drain's length from the setting's value. Zero cuts every stream as
/// soon as cw-egress is told to stop.
pub fn drain_deadline(value: Option<&str>) -> Result<Duration, DrainSettingError> {
    let value = value.ok_or(DrainSettingError::Missing)?;
    value
        .trim()
        .parse()
        .map(Duration::from_secs)
        .map_err(|_| DrainSettingError::Invalid(value.to_owned()))
}

/// Starts the drain when `told_to_stop` resolves, and shuts the supervisor
/// down `deadline` later. The supervisor may return sooner, once the drain
/// has moved every sandbox.
pub async fn drain_then_shut_down(
    signals: Signals,
    told_to_stop: impl Future<Output = ()>,
    deadline: Duration,
) {
    told_to_stop.await;
    signals.drain.cancel();
    tokio::time::sleep(deadline).await;
    signals.shutdown.cancel();
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn the_setting_is_a_whole_number_of_seconds_and_has_no_default() {
        assert_eq!(drain_deadline(Some("1800")), Ok(Duration::from_secs(1800)));
        assert_eq!(drain_deadline(Some(" 0 ")), Ok(Duration::ZERO));
        assert_eq!(drain_deadline(None), Err(DrainSettingError::Missing));
        for value in ["", "30m", "-1", "1.5"] {
            assert_eq!(
                drain_deadline(Some(value)),
                Err(DrainSettingError::Invalid(value.to_owned()))
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_starts_when_told_to_stop_and_the_shutdown_follows_at_the_deadline() {
        let signals = Signals::default();
        let (stop, told) = oneshot::channel::<()>();
        let deadline = Duration::from_secs(1800);
        let policy = tokio::spawn(drain_then_shut_down(
            signals.clone(),
            async move {
                let _stopped = told.await;
            },
            deadline,
        ));

        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(
            !signals.drain.is_cancelled(),
            "nothing drains before the stop"
        );

        stop.send(()).unwrap();
        // Lets the policy see the stop before any time passes.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let stopped_at = tokio::time::Instant::now();
        assert!(signals.drain.is_cancelled());

        tokio::time::advance(deadline - Duration::from_millis(1)).await;
        assert!(
            !signals.shutdown.is_cancelled(),
            "the deadline has not come"
        );

        // The paused clock runs on to the policy's timer and no further.
        policy.await.unwrap();
        assert!(signals.shutdown.is_cancelled());
        assert_eq!(stopped_at.elapsed(), deadline);
    }
}
