//! What is wrong with an environment, as `cw info` shows it: its error code
//! and how the runner's failed process ended (#4953), or a running VM's
//! egress, unavailable while its egress broker is past its deadline (#4965),
//! or its interception, lost once its front door ended unasked (#5216).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_local_vmm::control::v1;
use serde::Serialize;

use crate::commands::collaboration::trimmed_str;
use crate::commands::environment::progress::format_duration;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ErrorView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner_exit: Option<RunnerExitView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) egress_unavailable: Option<EgressUnavailableView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interception: Option<InterceptionView>,
    /// The environment's name, for the next step a line names.
    #[serde(skip)]
    pub(crate) name: String,
}

/// Egress refused because the VM's egress broker is past its deadline: how
/// many requests it refused, and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EgressUnavailableView {
    pub(crate) late_answers: u64,
    pub(crate) since_unix_ms: i64,
}

/// A running boot's interception, as `--output json` carries it: the same
/// `{"state", "reason"}` a hosted Sandbox can report (#4912). Only `lost` is
/// shown yet; #4912 adds the boot's other states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct InterceptionView {
    pub(crate) state: InterceptionStateView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InterceptionStateView {
    /// The front door ended after the start: agents can't reach their
    /// providers until the VM restarts (#5216).
    Lost,
}

/// How a runner's process ended: its exit status, absent when a signal
/// ended it, and that status's name, when its process names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RunnerExitView {
    pub(crate) status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

impl ErrorView {
    pub(crate) fn of(environment: &v1::Environment) -> Self {
        let error_code = trimmed_str(&environment.error_code).map(str::to_owned);
        let runner_exit = error_code
            .as_ref()
            .and(environment.runner_exit.as_ref())
            .map(|exit| RunnerExitView {
                status: exit.status,
                reason: trimmed_str(&exit.reason).map(str::to_owned),
            });
        let egress_unavailable =
            environment
                .egress_unavailable
                .as_ref()
                .map(|egress| EgressUnavailableView {
                    late_answers: egress.late_answers,
                    since_unix_ms: egress.since_unix_ms,
                });
        Self {
            error_code,
            runner_exit,
            egress_unavailable,
            interception: environment
                .interception
                .filter(|interception| interception.state == v1::InterceptionState::Lost as i32)
                .map(|_| InterceptionView {
                    state: InterceptionStateView::Lost,
                }),
            name: environment.name.clone(),
        }
    }

    /// The `Error:` line, then the `Egress:` line, each only when it applies.
    pub(crate) fn line(&self) -> String {
        self.line_at(SystemTime::now())
    }

    fn line_at(&self, now: SystemTime) -> String {
        let mut lines = self.error_line();
        if let Some(egress) = self.egress_unavailable {
            let since =
                UNIX_EPOCH + Duration::from_millis(egress.since_unix_ms.max(0).unsigned_abs());
            let refusing = now.duration_since(since).unwrap_or_default();
            lines.push_str(&format!(
                "Egress:      unavailable for {} (the egress broker is past its deadline; requests are refused until it answers, or `cw --local stop {name}` then `cw --local start {name}` restarts it)\n",
                format_duration(refusing, false),
                name = self.name,
            ));
        }
        if self.interception.is_some() {
            lines.push_str(&format!(
                "Credentials: ! agents can't reach their providers; restart the VM\n             → cw --local restart {name}\n",
                name = self.name,
            ));
        }
        lines
    }

    /// The `Error:` line, or nothing when the environment isn't in error.
    fn error_line(&self) -> String {
        let Some(error_code) = &self.error_code else {
            return String::new();
        };
        let how = match &self.runner_exit {
            None => return format!("Error:       {error_code}\n"),
            Some(RunnerExitView { status: None, .. }) => "ended by a signal".to_owned(),
            Some(RunnerExitView {
                status: Some(status),
                reason: None,
            }) => format!("exited {status}"),
            Some(RunnerExitView {
                status: Some(status),
                reason: Some(reason),
            }) => format!("exited {status}: {reason}"),
        };
        format!("Error:       {error_code} ({how})\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(error_code: &str, exit: Option<(Option<i32>, &str)>) -> ErrorView {
        ErrorView::of(&v1::Environment {
            error_code: error_code.to_owned(),
            runner_exit: exit.map(|(status, reason)| v1::RunnerExit {
                status,
                reason: reason.to_owned(),
            }),
            ..Default::default()
        })
    }

    #[test]
    fn the_error_line_names_how_the_process_ended() {
        assert_eq!(
            shown(
                "egress_broker_exit",
                Some((Some(72), "egress_broker_protocol"))
            )
            .line(),
            "Error:       egress_broker_exit (exited 72: egress_broker_protocol)\n"
        );
        assert_eq!(
            shown("vmm_exit", Some((Some(1), ""))).line(),
            "Error:       vmm_exit (exited 1)\n"
        );
        assert_eq!(
            shown("network_worker_exit", Some((None, ""))).line(),
            "Error:       network_worker_exit (ended by a signal)\n"
        );
        assert_eq!(
            shown("runner_exit", None).line(),
            "Error:       runner_exit\n"
        );
    }

    #[test]
    fn no_error_shows_no_line_and_no_exit() {
        let view = shown("", Some((Some(72), "egress_broker_protocol")));
        assert_eq!(view.line(), "");
        assert_eq!(view.runner_exit, None);
        assert_eq!(serde_json::to_value(&view).unwrap(), serde_json::json!({}));
    }

    #[test]
    fn json_carries_the_exit_beside_the_code() {
        let view = shown(
            "egress_broker_exit",
            Some((Some(72), "egress_broker_protocol")),
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({
                "error_code": "egress_broker_exit",
                "runner_exit": {"status": 72, "reason": "egress_broker_protocol"},
            })
        );
    }

    /// A running VM whose egress broker is past its deadline shows how long
    /// requests have been refused; the line goes once one is answered (#4965).
    #[test]
    fn unavailable_egress_shows_how_long_it_has_refused() {
        let since = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let environment = |egress: Option<v1::EgressUnavailable>| v1::Environment {
            name: "app".to_owned(),
            state: v1::EnvironmentState::Running as i32,
            egress_unavailable: egress,
            ..Default::default()
        };
        let view = ErrorView::of(&environment(Some(v1::EgressUnavailable {
            late_answers: 4,
            since_unix_ms: 1_700_000_000_000,
        })));
        assert_eq!(
            view.line_at(since + Duration::from_secs(130)),
            "Egress:      unavailable for 2m 10s (the egress broker is past its deadline; requests are refused until it answers, or `cw --local stop app` then `cw --local start app` restarts it)\n"
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({
                "egress_unavailable": {"late_answers": 4, "since_unix_ms": 1_700_000_000_000_i64},
            })
        );
        let answered = ErrorView::of(&environment(None));
        assert_eq!(answered.line_at(since), "");
        assert_eq!(
            serde_json::to_value(&answered).unwrap(),
            serde_json::json!({})
        );
    }

    /// A running VM whose interception was lost says its agents can't reach
    /// their providers and how to restart it; nothing shows otherwise yet
    /// (#5216, #4912).
    #[test]
    fn lost_interception_says_agents_cant_reach_their_providers() {
        let environment = |state: Option<v1::InterceptionState>| v1::Environment {
            name: "app".to_owned(),
            state: v1::EnvironmentState::Running as i32,
            interception: state.map(|state| v1::Interception {
                state: state as i32,
                reason: v1::InterceptionReason::Unspecified as i32,
            }),
            ..Default::default()
        };
        let view = ErrorView::of(&environment(Some(v1::InterceptionState::Lost)));
        assert_eq!(
            view.line_at(UNIX_EPOCH),
            "Credentials: ! agents can't reach their providers; restart the VM\n             → cw --local restart app\n"
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({"interception": {"state": "lost"}})
        );
        for other in [None, Some(v1::InterceptionState::Intercepted)] {
            let view = ErrorView::of(&environment(other));
            assert_eq!(view.line_at(UNIX_EPOCH), "", "{other:?}");
            assert_eq!(serde_json::to_value(&view).unwrap(), serde_json::json!({}));
        }
    }
}
