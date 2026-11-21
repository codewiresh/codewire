//! What is wrong with an environment, as `cw info` shows it: its error code
//! and how the runner's failed process ended (#4953), or a running VM's
//! egress, unavailable while its egress broker is past its deadline (#4965).
//! Beside them, what a running boot's agents hold (#4912), which needs action
//! only once its interception is lost (#5216).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_local_vmm::control::v1;
use serde::Serialize;

use crate::commands::collaboration::trimmed_str;
use crate::commands::environment::progress::format_duration;
use crate::output::{CredentialsNote, Status, Style};

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
    /// `Credentials` line; none while the switch is off.
    pub(crate) fn note(self) -> Option<CredentialsNote> {
        let text = match (self.state, self.reason) {
            (InterceptionStateView::Off, _) => return None,
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
            interception: InterceptionView::of(environment),
            name: environment.name.clone(),
        }
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

    /// What a running boot's agents hold, for the lines under `cw info`'s
    /// `Credentials` row, with `style`'s glyphs and colour: none while the
    /// switch is off, and a next step only once interception is lost.
    pub(crate) fn credentials_note(&self, style: Style) -> Vec<String> {
        let Some(interception) = self.interception else {
            return Vec::new();
        };
        let mut lines: Vec<String> = interception
            .note()
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
    use crate::output::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);

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
                None,
                serde_json::json!({"state": "off"}),
            ),
        ] {
            let view = ErrorView::of(&intercepting(Some(state), reason));
            assert_eq!(view.line_at(UNIX_EPOCH), "", "{state:?} {reason:?}");
            assert_eq!(
                view.credentials_note(PLAIN),
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
