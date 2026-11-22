//! While a managed agent's turn runs, a fixed line a minute on the driver's
//! stderr, so idle stop sees a Sandbox whose agent waits on a long tool or
//! its model as in use (#5897, docs/dev/IDLE-STOP.md). The daemon counts any
//! session output as activity; the line carries no content.
//!
//! Only idle stop reads it. Credit, spend and lifetime limits, and any
//! suspension, apply whatever the agent is doing.

use tokio::time::{Duration, Instant};

use super::{Driver, DriverPhase, log};

/// At most this often: under the shortest idle timeout (5 minutes), and the
/// daemon's activity clock counts minutes.
pub(super) const INTERVAL: Duration = Duration::from_secs(60);

/// One turn stops holding its Sandbox up after this long, so a hung agent
/// can't keep it running for ever: the bound idle stop puts on an open
/// request (`NO_OPEN_REQUEST`).
pub(super) const CAP: Duration = Duration::from_secs(24 * 60 * 60);

/// The line, after the driver's own `cw agent driver: ` prefix. Fixed: no
/// prompt, tool, model or path.
pub(super) const LINE: &str = "turn running";

/// When the line is next due, for the turn running now.
#[derive(Debug, Default)]
pub(super) struct TurnHeartbeat {
    busy_since: Option<Instant>,
    last: Option<Instant>,
}

impl TurnHeartbeat {
    /// Whether to write the line now. `busy` is whether a turn runs: any
    /// other phase (idle, failed, stopped) ends the turn, so the next one
    /// starts its own count.
    pub(super) fn due(&mut self, busy: bool, now: Instant) -> bool {
        if !busy {
            *self = Self::default();
            return false;
        }
        let since = *self.busy_since.get_or_insert(now);
        if now.duration_since(since) >= CAP {
            return false;
        }
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < INTERVAL)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

impl Driver {
    /// On the driver's scan tick: the line, when a turn runs and one is due.
    pub(super) fn heartbeat_tick(&mut self) {
        let busy = self.state.phase == DriverPhase::Busy;
        if self.heartbeat.due(busy, Instant::now()) {
            log(LINE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The driver's scan ticks every 10 s; the line comes once a minute of a
    /// turn, never between turns, and stops at the cap.
    #[tokio::test(start_paused = true)]
    async fn a_running_turn_writes_the_line_once_a_minute_until_it_ends_or_the_cap() {
        let tick = Duration::from_secs(10);
        let mut heartbeat = TurnHeartbeat::default();
        let mut lines = 0;
        // Two idle minutes: nothing.
        for _ in 0..12 {
            assert!(!heartbeat.due(false, Instant::now()));
            tokio::time::advance(tick).await;
        }
        // A busy turn of 5 minutes: at its start, then each minute.
        for _ in 0..30 {
            lines += usize::from(heartbeat.due(true, Instant::now()));
            tokio::time::advance(tick).await;
        }
        assert_eq!(lines, 5);
        // It ends 20 s into a minute: nothing more, though a line was due.
        tokio::time::advance(Duration::from_secs(50)).await;
        assert!(!heartbeat.due(false, Instant::now()));
        assert!(!heartbeat.due(false, Instant::now() + INTERVAL));
        // The next turn writes at once, on its own count.
        assert!(heartbeat.due(true, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_turn_past_the_cap_no_longer_holds_its_sandbox_up() {
        let mut heartbeat = TurnHeartbeat::default();
        assert!(heartbeat.due(true, Instant::now()));
        tokio::time::advance(CAP - INTERVAL).await;
        assert!(heartbeat.due(true, Instant::now()));
        tokio::time::advance(INTERVAL).await;
        assert!(!heartbeat.due(true, Instant::now()));
        tokio::time::advance(INTERVAL * 10).await;
        assert!(!heartbeat.due(true, Instant::now()));
        // A new turn starts its own count.
        assert!(!heartbeat.due(false, Instant::now()));
        assert!(heartbeat.due(true, Instant::now()));
    }

    /// The line is fixed text in the driver's stderr form, never agent
    /// output: it names nothing the turn does.
    #[test]
    fn the_line_is_a_fixed_marker_in_the_driver_s_stderr_form() {
        assert_eq!(
            super::super::driver_line(LINE),
            "cw agent driver: turn running"
        );
    }
}
