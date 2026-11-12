//! Shared by the crate's route tests.

use std::time::Duration;

/// A hang guard for a route test's request to its own in-process server on
/// 127.0.0.1, not a speed expectation (docs/dev/AGENT-WORKFLOW.md "Failure
/// convergence"). The routes answer well under a second, but on a starved CI
/// guest fixed 5 s client timeouts failed requests that were still being
/// served (#4225, #4169).
pub(crate) const LOOPBACK_HANG_GUARD: Duration = Duration::from_secs(60);
