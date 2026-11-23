//! Pings on every public WebSocket (#6100).
//!
//! A terminal with no output, a still desktop or a quiet shell sends nothing,
//! and a proxy in front of us (the gateway, the CDN) closes a WebSocket that
//! is silent for long enough. So each socket's writer pings its client every
//! [`PING_EVERY`] whatever else it sends; a browser answers a ping by itself.

use std::time::Duration;

use axum::extract::ws::Message;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};

/// Far below any idle timeout in front of us.
pub(crate) const PING_EVERY: Duration = Duration::from_secs(30);

/// Ticks every [`PING_EVERY`], the first one [`PING_EVERY`] from now.
pub(crate) fn pings() -> Interval {
    let mut pings = interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
    pings
}

pub(crate) fn ping() -> Message {
    Message::Ping(Default::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_first_ping_is_due_one_interval_from_now_and_then_every_interval() {
        let started = Instant::now();
        let mut pings = pings();
        pings.tick().await;
        assert_eq!(started.elapsed(), PING_EVERY);
        pings.tick().await;
        assert_eq!(started.elapsed(), 2 * PING_EVERY);
    }
}
