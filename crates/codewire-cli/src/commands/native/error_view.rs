//! What is wrong with an environment, as `cw info` shows it: its error code
//! and how the runner's failed process ended (#4953), or a running VM's
//! egress, unavailable while its egress broker is past its deadline (#4965).
//! Beside them, what a running boot's agents hold (#4912), which needs action
//! only once its interception is lost (#5216), and how many requests its
//! egress broker refused (#5058).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_local_vmm::control::v1;
use serde::Serialize;

use crate::commands::collaboration::trimmed_str;
use crate::commands::environment::progress::format_duration;
use crate::output::{CredentialsNote, Status, Style};

/// Requests a running VM's egress broker refused since it started, and when
/// the last was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EgressRefusalsView {
    pub(crate) refused: u64,
    pub(crate) last_unix_ms: i64,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) egress_refusals: Option<EgressRefusalsView>,
    /// The environment's name, for the next step a line names.
    #[serde(skip)]
    pub(crate) name: String,
    /// Whether the environment is in `error` now; its code outlives that.
    #[serde(skip)]
    in_error: bool,
}

/// Egress refused because the VM's egress broker is past its deadline: how
/// many requests it refused, and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EgressUnavailableView {
    pub(crate) late_answers: u64,
    pub(crate) since_unix_ms: i64,
}

/// A running boot's interception, as `--output json` carries it: the same
/// `{"state", "reason"}` a hosted Sandbox can report (#4912).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct InterceptionView {
    pub(crate) state: InterceptionStateView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<InterceptionReasonView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InterceptionStateView {
    /// The switch was on and the boot intercepts: agents hold placeholders.
    Intercepted,
    /// The switch was on but the boot does not intercept; the reason says
    /// why.
    NotIntercepted,
    /// The per-host switch was off for the boot: no text, only JSON.
    Off,
    /// The front door ended after the start: agents can't reach their
    /// providers until the VM restarts (#5216).
    Lost,
}

/// Why a switched-on boot does not intercept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InterceptionReasonView {
    /// Goes once a platform profile's boot intercepts (#4909).
    PlatformCredentials,
    NoCredentials,
    CredentialServiceOutdated,
    /// Told to intercept, it bound nothing: none of its credentials goes
    /// through the front door yet (#5670).
    NothingToIntercept,
}

impl InterceptionView {
    /// What the environment's runner reports, if anything: nothing for a
    /// stopped VM, or from a runner that predates the report.
    pub(crate) fn of(environment: &v1::Environment) -> Option<Self> {
        use v1::{InterceptionReason as Reason, InterceptionState as State};
        let interception = environment.interception?;
        let state = match State::try_from(interception.state).ok()? {
            State::Unspecified => return None,
            State::Intercepted => InterceptionStateView::Intercepted,
            State::NotIntercepted => InterceptionStateView::NotIntercepted,
            State::Off => InterceptionStateView::Off,
            State::Lost => InterceptionStateView::Lost,
        };
        let reason = match Reason::try_from(interception.reason) {
            Ok(Reason::PlatformCredentials) => Some(InterceptionReasonView::PlatformCredentials),
            Ok(Reason::NoCredentials) => Some(InterceptionReasonView::NoCredentials),
            Ok(Reason::NothingToIntercept) => Some(InterceptionReasonView::NothingToIntercept),
            Ok(Reason::CredentialServiceOutdated) => {
                Some(InterceptionReasonView::CredentialServiceOutdated)
            }
            Ok(Reason::Unspecified) | Err(_) => None,
        };
        Some(Self { state, reason })
    }

    /// What the boot's agents hold, in the user's terms, for the
    /// `Credentials` line. A boot the switch turned off names the switch's
    /// file, so a rollback left in place is visible (#3999).
    pub(crate) fn note(self) -> Option<CredentialsNote> {
        self.note_with(switch_path)
    }

    /// [`Self::note`], with the switch file's path from `switch`.
    fn note_with(self, switch: impl FnOnce() -> Option<String>) -> Option<CredentialsNote> {
        let text = match (self.state, self.reason) {
            (InterceptionStateView::Off, _) => format!(
                "no placeholders: interception is switched off in {}",
                switch()?
            ),
            (InterceptionStateView::Lost, _) => {
                return Some(CredentialsNote::attention(
                    "agents can't reach their providers; restart the VM".to_owned(),
                ));
            }
            (InterceptionStateView::Intercepted, _) => {
                "placeholders only: agents never hold your tokens".to_owned()
            }
            (_, Some(InterceptionReasonView::PlatformCredentials)) => {
                "no placeholders: they come from the platform".to_owned()
            }
            (_, Some(InterceptionReasonView::NoCredentials)) => {
                "no placeholders: none are selected".to_owned()
            }
            (_, Some(InterceptionReasonView::NothingToIntercept)) => {
                "no placeholders: none of its credentials is intercepted yet".to_owned()
            }
            (_, Some(InterceptionReasonView::CredentialServiceOutdated)) => format!(
                "no placeholders: {}, then start this one",
                codewire_local_vmm::supervisor_config::OUTDATED_CREDENTIAL_SERVICE
            ),
            (InterceptionStateView::NotIntercepted, None) => "no placeholders".to_owned(),
        };
        Some(CredentialsNote::plain(text))
    }
}

/// The interception switch's file, as `cw` would name it, if the local VM
/// runtime's configuration can be read.
fn switch_path() -> Option<String> {
    crate::commands::native_runtime_config()
        .ok()
        .map(|config| config.egress_intercept_switch().display().to_string())
}

/// How a runner's process ended: its exit status, absent when a signal
/// ended it, that status's name, when its process names it, and the signal,
/// which a supervisor before #4953's follow-up does not report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RunnerExitView {
    pub(crate) status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signal: Option<i32>,
}

/// Looks `name` up for a command that runs in it, with the credential
/// service it needs, and refuses a VM that is in `error` with why and what to
/// do (#5359).
pub(crate) async fn reachable(name: &str) -> anyhow::Result<()> {
    let mut supervisor = super::native_client().await?;
    let found =
        super::get_native_environment_with_required_authority(&mut supervisor, name).await?;
    ErrorView::of(&found).refusal().map_or(Ok(()), Err)
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
                signal: exit.signal,
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
            interception: InterceptionView::of(environment),
            egress_refusals: environment
                .egress_refusals
                .filter(|refusals| refusals.refused > 0)
                .map(|refusals| EgressRefusalsView {
                    refused: refusals.refused,
                    last_unix_ms: refusals.last_unix_ms,
                }),
            name: environment.name.clone(),
            in_error: environment.state == v1::EnvironmentState::Error as i32,
        }
    }

    /// What the error code means for whoever uses the VM, where the code
    /// alone does not say (#5359).
    fn meaning(&self) -> Option<&'static str> {
        match self.error_code.as_deref()? {
            "egress_broker_exit" => {
                Some("the VM's network broker stopped, so nothing can leave the VM")
            }
            "network_worker_exit" => {
                Some("the VM's network worker stopped, so nothing can leave the VM")
            }
            _ => None,
        }
    }

    /// The code of a VM that is in `error` now, as `cw ls --output json`
    /// carries it.
    pub(crate) fn current_code(&self) -> Option<&str> {
        self.error_code.as_deref().filter(|_| self.in_error)
    }

    /// Why a command cannot run in a VM that is in `error`, with its next
    /// step; `None` for a VM in any other state, which the command's own
    /// error covers.
    pub(crate) fn refusal(&self) -> Option<anyhow::Error> {
        if !self.in_error {
            return None;
        }
        let name = crate::commands::progress::terminal_text(&self.name);
        let (message, step) = match (self.meaning(), &self.error_code) {
            (Some(meaning), _) => (
                format!("local VM {name} can't be reached: {meaning}"),
                format!("cw --local start {name}"),
            ),
            (None, Some(code)) => (
                format!("local VM {name} is in error ({code})"),
                format!("cw --local info {name}"),
            ),
            (None, None) => (
                format!("local VM {name} is in error"),
                format!("cw --local info {name}"),
            ),
        };
        Some(crate::error_report::with_next_step(
            anyhow::anyhow!(message),
            step,
        ))
    }

    /// The `Error:` line, then the `Egress:` line, each only when it
    /// applies.
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
        lines
    }

    /// The `Refused:` line, naming the command that lists them, only when a
    /// running VM's egress broker refused something. It names the command in
    /// the line, so `cw info`'s fields stay one block.
    pub(crate) fn refusals_line(&self) -> String {
        self.refusals_line_at(SystemTime::now())
    }

    fn refusals_line_at(&self, now: SystemTime) -> String {
        let Some(refusals) = self.egress_refusals else {
            return String::new();
        };
        let last = UNIX_EPOCH + Duration::from_millis(refusals.last_unix_ms.max(0).unsigned_abs());
        let ago = now.duration_since(last).unwrap_or_default();
        format!(
            "Refused:     {} {} since the VM started, the last {} ago; `cw --local policy log {}` lists them\n",
            refusals.refused,
            if refusals.refused == 1 {
                "request"
            } else {
                "requests"
            },
            format_duration(ago, false),
            self.name,
        )
    }

    /// What a running boot's agents hold, for the lines under `cw info`'s
    /// `Credentials` row, with `style`'s glyphs and colour, and a next step
    /// only once interception is lost.
    pub(crate) fn credentials_note(&self, style: Style) -> Vec<String> {
        self.credentials_note_with(style, switch_path)
    }

    /// [`Self::credentials_note`], with the switch file's path from `switch`.
    fn credentials_note_with(
        &self,
        style: Style,
        switch: impl FnOnce() -> Option<String>,
    ) -> Vec<String> {
        let Some(interception) = self.interception else {
            return Vec::new();
        };
        let mut lines: Vec<String> = interception
            .note_with(switch)
            .map(|note| note.render(style))
            .into_iter()
            .collect();
        if interception.state == InterceptionStateView::Lost {
            lines.push(format!(
                "{} cw --local restart {}",
                style.status(Status::Next),
                self.name
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
            None => String::new(),
            Some(RunnerExitView {
                status: None,
                signal: Some(signal),
                ..
            }) => format!(" (ended by signal {signal})"),
            Some(RunnerExitView { status: None, .. }) => " (ended by a signal)".to_owned(),
            Some(RunnerExitView {
                status: Some(status),
                reason: None,
                ..
            }) => format!(" (exited {status})"),
            Some(RunnerExitView {
                status: Some(status),
                reason: Some(reason),
                ..
            }) => format!(" (exited {status}: {reason})"),
        };
        match self.meaning().filter(|_| self.in_error) {
            Some(meaning) => format!(
                "Error:       {error_code}{how}: {meaning}; `cw --local start {name}` starts it again\n",
                name = self.name,
            ),
            None => format!("Error:       {error_code}{how}\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    fn shown(error_code: &str, exit: Option<(Option<i32>, &str)>) -> ErrorView {
        ErrorView::of(&v1::Environment {
            error_code: error_code.to_owned(),
            runner_exit: exit.map(|(status, reason)| v1::RunnerExit {
                status,
                reason: reason.to_owned(),
                signal: None,
            }),
            ..Default::default()
        })
    }

    /// A VM in `error` with `error_code`, named `ed`.
    fn in_error(error_code: &str) -> ErrorView {
        ErrorView::of(&v1::Environment {
            name: "ed".to_owned(),
            state: v1::EnvironmentState::Error as i32,
            error_code: error_code.to_owned(),
            runner_exit: Some(v1::RunnerExit {
                status: None,
                reason: String::new(),
                signal: None,
            }),
            ..Default::default()
        })
    }

    fn said(error: &anyhow::Error) -> (String, Option<String>) {
        let step = error
            .downcast_ref::<crate::error_report::NextStep>()
            .map(ToString::to_string);
        (error.root_cause().to_string(), step)
    }

    /// A VM whose network process ended says what that means and how to
    /// get it back, on its `Error:` line and to a command run in it.
    #[test]
    fn a_vm_that_lost_its_network_says_so_and_what_to_do() {
        let broker = in_error("egress_broker_exit");
        assert_eq!(
            broker.line(),
            "Error:       egress_broker_exit (ended by a signal): the VM's network broker stopped, so nothing can leave the VM; `cw --local start ed` starts it again\n"
        );
        assert_eq!(
            said(&broker.refusal().unwrap()),
            (
                "local VM ed can't be reached: the VM's network broker stopped, so nothing can leave the VM".to_owned(),
                Some("cw --local start ed".to_owned())
            )
        );
        assert_eq!(broker.current_code(), Some("egress_broker_exit"));
        let worker = in_error("network_worker_exit");
        assert!(
            worker
                .line()
                .contains("the VM's network worker stopped, so nothing can leave the VM;")
        );
        assert!(
            said(&worker.refusal().unwrap())
                .0
                .ends_with("the VM's network worker stopped, so nothing can leave the VM")
        );
    }

    /// Any other cause is named by its code, and sends to `cw info`.
    #[test]
    fn a_vm_in_error_for_another_cause_is_named_by_its_code() {
        let vmm = in_error("vmm_exit");
        assert_eq!(vmm.line(), "Error:       vmm_exit (ended by a signal)\n");
        assert_eq!(
            said(&vmm.refusal().unwrap()),
            (
                "local VM ed is in error (vmm_exit)".to_owned(),
                Some("cw --local info ed".to_owned())
            )
        );
        assert_eq!(
            said(&in_error("").refusal().unwrap()),
            (
                "local VM ed is in error".to_owned(),
                Some("cw --local info ed".to_owned())
            )
        );
    }

    /// A code outlives the error it named: a VM that is running or stopped
    /// is refused nothing here, and its line says only the code.
    #[test]
    fn a_code_left_on_a_vm_that_is_not_in_error_refuses_nothing() {
        for state in [
            v1::EnvironmentState::Running,
            v1::EnvironmentState::Stopped,
            v1::EnvironmentState::Starting,
        ] {
            let view = ErrorView::of(&v1::Environment {
                name: "ed".to_owned(),
                state: state as i32,
                error_code: "egress_broker_exit".to_owned(),
                ..Default::default()
            });
            assert!(view.refusal().is_none(), "{state:?}");
            assert_eq!(view.current_code(), None, "{state:?}");
            assert_eq!(
                view.line(),
                "Error:       egress_broker_exit\n",
                "{state:?}"
            );
        }
    }

    #[test]
    fn info_counts_the_refusals_since_the_vm_started_and_points_at_the_log() {
        let view = |refused| {
            ErrorView::of(&v1::Environment {
                name: "walk-log".to_owned(),
                egress_refusals: Some(v1::EgressRefusalSummary {
                    refused,
                    last_unix_ms: 1_000_000,
                }),
                ..Default::default()
            })
        };
        let now = UNIX_EPOCH + Duration::from_millis(1_000_000 + 125_000);
        assert_eq!(
            view(6).refusals_line_at(now),
            "Refused:     6 requests since the VM started, the last 2m 05s ago; `cw --local policy log walk-log` lists them\n"
        );
        assert!(
            view(1)
                .refusals_line_at(now)
                .starts_with("Refused:     1 request since")
        );
        assert_eq!(view(0).refusals_line_at(now), "");
        assert_eq!(
            ErrorView::of(&v1::Environment::default()).refusals_line_at(now),
            ""
        );
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

    /// A signal is named, in the line and in JSON, when the supervisor
    /// reports it (#4953).
    #[test]
    fn a_signal_that_ended_the_process_is_named() {
        let view = ErrorView::of(&v1::Environment {
            error_code: "egress_broker_exit".to_owned(),
            runner_exit: Some(v1::RunnerExit {
                status: None,
                reason: String::new(),
                signal: Some(9),
            }),
            ..Default::default()
        });
        assert_eq!(
            view.line(),
            "Error:       egress_broker_exit (ended by signal 9)\n"
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({
                "error_code": "egress_broker_exit",
                "runner_exit": {"status": null, "signal": 9},
            })
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

    fn intercepting(
        state: Option<v1::InterceptionState>,
        reason: v1::InterceptionReason,
    ) -> v1::Environment {
        v1::Environment {
            name: "app".to_owned(),
            state: v1::EnvironmentState::Running as i32,
            interception: state.map(|state| v1::Interception {
                state: state as i32,
                reason: reason as i32,
            }),
            ..Default::default()
        }
    }

    /// A running VM whose interception was lost says its agents can't reach
    /// their providers and how to restart it (#5216).
    #[test]
    fn lost_interception_says_agents_cant_reach_their_providers() {
        let environment = |state| intercepting(state, v1::InterceptionReason::Unspecified);
        let view = ErrorView::of(&environment(Some(v1::InterceptionState::Lost)));
        assert_eq!(view.line_at(UNIX_EPOCH), "");
        assert_eq!(
            view.credentials_note(PLAIN),
            [
                "! agents can't reach their providers; restart the VM",
                "→ cw --local restart app"
            ]
        );
        assert_eq!(
            view.credentials_note(Style::new(false, Charset::Ascii)),
            [
                "! agents can't reach their providers; restart the VM",
                "-> cw --local restart app"
            ]
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({"interception": {"state": "lost"}})
        );
        for other in [None, Some(v1::InterceptionState::Unspecified)] {
            let view = ErrorView::of(&environment(other));
            assert!(view.credentials_note(PLAIN).is_empty(), "{other:?}");
            assert_eq!(serde_json::to_value(&view).unwrap(), serde_json::json!({}));
        }
    }

    /// Each other state of a running boot says what its agents hold, in
    /// the user's terms and with no next step, and `--output json` carries
    /// its state and reason; with the switch off only JSON says so (#4912).
    #[test]
    fn a_running_boot_says_what_its_agents_hold() {
        use v1::{InterceptionReason as Reason, InterceptionState as State};
        let outdated = format!(
            "no placeholders: {}, then start this one",
            codewire_local_vmm::supervisor_config::OUTDATED_CREDENTIAL_SERVICE
        );
        for (state, reason, line, json) in [
            (
                State::Intercepted,
                Reason::Unspecified,
                Some("placeholders only: agents never hold your tokens"),
                serde_json::json!({"state": "intercepted"}),
            ),
            (
                State::NotIntercepted,
                Reason::PlatformCredentials,
                Some("no placeholders: they come from the platform"),
                serde_json::json!({"state": "not_intercepted", "reason": "platform_credentials"}),
            ),
            (
                State::NotIntercepted,
                Reason::NoCredentials,
                Some("no placeholders: none are selected"),
                serde_json::json!({"state": "not_intercepted", "reason": "no_credentials"}),
            ),
            (
                State::NotIntercepted,
                Reason::NothingToIntercept,
                Some("no placeholders: none of its credentials is intercepted yet"),
                serde_json::json!({"state": "not_intercepted", "reason": "nothing_to_intercept"}),
            ),
            (
                State::NotIntercepted,
                Reason::CredentialServiceOutdated,
                Some(outdated.as_str()),
                serde_json::json!({"state": "not_intercepted", "reason": "credential_service_outdated"}),
            ),
            (
                State::Off,
                Reason::Unspecified,
                Some(
                    "no placeholders: interception is switched off in \
                     /home/u/.codewire/native-v1/egress-intercept",
                ),
                serde_json::json!({"state": "off"}),
            ),
        ] {
            let view = ErrorView::of(&intercepting(Some(state), reason));
            assert_eq!(view.line_at(UNIX_EPOCH), "", "{state:?} {reason:?}");
            assert_eq!(
                view.credentials_note_with(PLAIN, || Some(
                    "/home/u/.codewire/native-v1/egress-intercept".to_owned()
                )),
                line.map(str::to_owned).into_iter().collect::<Vec<_>>(),
                "{state:?} {reason:?}"
            );
            assert_eq!(
                serde_json::to_value(&view).unwrap(),
                serde_json::json!({"interception": json}),
                "{state:?} {reason:?}"
            );
        }
    }
}
