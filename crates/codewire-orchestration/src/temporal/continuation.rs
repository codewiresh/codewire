//! When an environment workflow run continues as new, so a replay stays
//! bounded (docs/dev/ORCHESTRATION-FENCING.md, "A run's history is bounded").

use temporalio_sdk::{WorkflowContext, WorkflowResult};

use super::{EnvironmentCommand, EnvironmentWorkflow};

/// A run continues as new once its history reaches this many events.
pub(super) const HISTORY_EVENTS: u32 = 2_000;

/// Whether a run continues as new now. Only on the live path, where the
/// end of history is, and only while nothing is queued or running.
pub(super) fn due(replaying: bool, idle: bool, history_length: u32, suggested: bool) -> bool {
    !replaying && idle && (suggested || history_length >= HISTORY_EVENTS)
}

/// Continues the run as new, with no command, when [`due`].
pub(super) fn continue_when_due(ctx: &WorkflowContext<EnvironmentWorkflow>) -> WorkflowResult<()> {
    let idle = ctx.state(|s| s.queue.is_empty()) && ctx.all_handlers_finished();
    let suggested = ctx.continue_as_new_suggested();
    if due(ctx.is_replaying(), idle, ctx.history_length(), suggested) {
        ctx.continue_as_new(EnvironmentCommand::default(), Default::default())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_idle_run_continues_once_its_history_is_long_or_temporal_suggests_it() {
        assert!(due(false, true, HISTORY_EVENTS, false));
        assert!(due(false, true, 10, true));
        assert!(!due(false, true, HISTORY_EVENTS - 1, false));
        // Replay never decides it: an open run's history never holds its end.
        assert!(!due(true, true, HISTORY_EVENTS * 10, true));
        // A queued command or a running handler is finished first.
        assert!(!due(false, false, HISTORY_EVENTS * 10, true));
    }
}
