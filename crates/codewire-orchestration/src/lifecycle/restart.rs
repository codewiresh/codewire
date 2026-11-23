//! An unplanned restart of a running Sandbox, recorded with #3772's
//! `sandbox_restarted` code: when it was running again and why (#5997,
//! SPEC.md "Unplanned restarts").

use super::*;

/// Why a running Sandbox restarted without a member asking. The names are
/// `environments.restart_cause`'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartCause {
    /// Its Pod failed on a node that is still there.
    PodFailed,
    /// Its Pod was deleted or replaced, as in a node drain or reboot.
    RuntimeReplaced,
    /// Its node was lost and it came back on another.
    NodeLost,
    /// The bootstrap check restarted it because its credential selection,
    /// managed clients or generation changed.
    ConfigurationChanged,
}

impl RestartCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PodFailed => "pod_failed",
            Self::RuntimeReplaced => "runtime_replaced",
            Self::NodeLost => "node_lost",
            Self::ConfigurationChanged => "configuration_changed",
        }
    }

    /// The notice's words for the cause, after "Restarted at HH:MM UTC
    /// after", as `mark_started` words the first two.
    fn after(self) -> &'static str {
        match self {
            Self::PodFailed => "stopping unexpectedly",
            Self::RuntimeReplaced => "its runtime was replaced",
            Self::NodeLost => "the machine it ran on stopped responding",
            Self::ConfigurationChanged => "its credentials or settings changed",
        }
    }
}

impl PgLifecycleStore {
    /// Records a restart of a running Sandbox that stayed `running`
    /// throughout, as the bootstrap check's restart does. `false` when it was
    /// no longer running.
    pub(super) async fn mark_restarted_now(
        &self,
        env_id: &str,
        cause: RestartCause,
    ) -> anyhow::Result<bool> {
        let rows = self
            .exec_logged(
                env_id,
                sqlx::query(
                    "UPDATE environments SET error_code = $2,
                       error_reason = 'Restarted at ' || to_char(NOW() AT TIME ZONE 'UTC', 'HH24:MI')
                         || ' UTC after ' || $3 || '. Running processes were lost.',
                       restarted_at = NOW(), restart_cause = $4
                      WHERE id = $1 AND state = 'running'",
                )
                .bind(env_id)
                .bind(SANDBOX_RESTARTED_ERROR_CODE)
                .bind(cause.after())
                .bind(cause.as_str()),
                LogEntry {
                    phase: "lifecycle_checkpoint",
                    status: "completed",
                    message: format!("unplanned restart recorded ({})", cause.as_str()),
                    metadata: serde_json::json!({
                        "kind": "unplanned_restart",
                        "cause": cause.as_str(),
                    }),
                },
            )
            .await?;
        Ok(rows > 0)
    }
}
