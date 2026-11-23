//! Whether a local VM's delivered agent logins have settled since its daemon
//! started (#6123): each kept login writer's first decided outcome, whether
//! the login was written, the user's own was kept, or delivery was refused.
//! The VM's start waits for it, bounded, so the first agent command after
//! `cw start` finds its login. GetHealth reports it as the
//! [`AGENT_LOGINS_DIAGNOSTIC`] diagnostic; it never changes the daemon's
//! state.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use codewire_daemon_proto::daemon::v1;

/// The health diagnostic's name, which the local VM supervisor waits on.
pub const AGENT_LOGINS_DIAGNOSTIC: &str = "agent-logins";

/// The agents whose writers have not settled yet, shared by the writers and
/// the health that reports them.
#[derive(Clone, Debug, Default)]
pub struct LoginReadiness {
    pending: Arc<Mutex<BTreeSet<&'static str>>>,
}

impl LoginReadiness {
    /// Waits on `agent` until its writer settles. The writers run on Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn track(&self, agent: &'static str) -> Settle {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(agent);
        Settle {
            readiness: self.clone(),
            agent,
        }
    }

    /// Healthy once every tracked writer has settled, and when none was.
    pub(crate) fn diagnostic(&self) -> v1::HealthDiagnostic {
        let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        v1::HealthDiagnostic {
            name: AGENT_LOGINS_DIAGNOSTIC.to_owned(),
            healthy: pending.is_empty(),
            message: if pending.is_empty() {
                String::new()
            } else {
                format!(
                    "waiting for {}",
                    pending.iter().copied().collect::<Vec<_>>().join(", ")
                )
            },
        }
    }
}

/// Two handles are equal when they report the same now, as a daemon's
/// runtime states are compared.
impl PartialEq for LoginReadiness {
    fn eq(&self, other: &Self) -> bool {
        // One lock at a time: the two may share their writers.
        let ours = self.diagnostic();
        ours == other.diagnostic()
    }
}

/// One writer's handle: it settles once, on its first decided outcome.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct Settle {
    readiness: LoginReadiness,
    agent: &'static str,
}

#[cfg(target_os = "linux")]
impl Settle {
    pub(crate) fn settled(&self) {
        self.readiness
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(self.agent);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn healthy_only_once_every_tracked_writer_settles() {
        let readiness = LoginReadiness::default();
        assert!(readiness.diagnostic().healthy);
        let claude = readiness.track("claude");
        let codex = readiness.track("codex");
        let waiting = readiness.diagnostic();
        assert_eq!(waiting.name, AGENT_LOGINS_DIAGNOSTIC);
        assert!(!waiting.healthy);
        assert_eq!(waiting.message, "waiting for claude, codex");
        claude.settled();
        assert_eq!(readiness.diagnostic().message, "waiting for codex");
        codex.settled();
        codex.settled();
        let settled = readiness.diagnostic();
        assert!(settled.healthy);
        assert!(settled.message.is_empty());
    }
}
