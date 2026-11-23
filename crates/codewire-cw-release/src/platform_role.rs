//! Bounds of the platform cw runtime role (`cw __platform-cw-runtime`), shared
//! by the role inside a sandbox and the orchestration owner that waits for it
//! and settles what it leaves.

use std::time::Duration;

/// How long one role command may work.
pub const BUDGET: Duration = Duration::from_secs(120);

/// When the role's alarm ends it, measured from its start: one second past
/// [`BUDGET`]. The alarm stops it even inside a blocking file call.
pub const ALARM: Duration = Duration::from_secs(BUDGET.as_secs() + 1);
