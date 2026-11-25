//! The warn line for a bound host this front door has no route for (#6421):
//! at most one per host per [`UNROUTED_LOG_INTERVAL`], with how many requests
//! were refused since the last, because an agent refused by name may retry in
//! a loop. It names the host and the count, never a request, header,
//! placeholder or body; the front door's span names the environment and Pod.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The least time between two warn lines for one host.
pub(crate) const UNROUTED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Per host: when it was last logged and how many refusals since.
#[derive(Default)]
pub(crate) struct UnroutedLog(Mutex<HashMap<String, (Option<Instant>, u64)>>);

impl UnroutedLog {
    /// Counts one refusal of `host`, and logs it when the host's interval
    /// has passed. `true` when this call logged.
    pub(crate) fn refused(&self, host: &str, now: Instant) -> bool {
        let mut hosts = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (last, count) = hosts.entry(host.to_owned()).or_default();
        *count += 1;
        if last.is_some_and(|last| now.duration_since(last) < UNROUTED_LOG_INTERVAL) {
            return false;
        }
        tracing::warn!(
            host,
            refused = *count,
            reason = "route_not_served",
            "refused a bound host this front door has no route for"
        );
        *last = Some(now);
        *count = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_per_host_per_interval_with_the_count_since() {
        let log = UnroutedLog::default();
        let start = Instant::now();
        assert!(log.refused("api.github.com", start));
        assert!(!log.refused("api.github.com", start + Duration::from_secs(1)));
        assert!(!log.refused("api.github.com", start + Duration::from_secs(59)));
        // Another host has its own interval.
        assert!(log.refused("github.com", start + Duration::from_secs(2)));
        assert!(log.refused("api.github.com", start + UNROUTED_LOG_INTERVAL));
        let hosts = log.0.lock().unwrap();
        assert_eq!(
            hosts["api.github.com"].1, 0,
            "the count restarts at each line"
        );
    }
}
