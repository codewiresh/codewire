//! An environment's error as `cw info` shows it: the code, and how the
//! runner's failed process ended when the supervisor could read it (#4953).

use codewire_local_vmm::control::v1;
use serde::Serialize;

use crate::commands::collaboration::trimmed_str;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ErrorView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runner_exit: Option<RunnerExitView>,
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
        Self {
            error_code,
            runner_exit,
        }
    }

    /// The `Error:` line, or nothing when the environment isn't in error.
    pub(crate) fn line(&self) -> String {
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
}
