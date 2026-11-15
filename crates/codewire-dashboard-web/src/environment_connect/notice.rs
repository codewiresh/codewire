//! The one thing a Sandbox's page says about its state (#3772).

use super::*;

/// The one thing a Sandbox's page says about its state, and the one action it
/// offers there (#3772). The owner's rule (2026-11-13, on #3772): a banner
/// while something still shows below it, a centred message when nothing runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SandboxNotice {
    /// `banner` runs across the top of the terminal column, above the
    /// terminal or its startup; `message` is centred where the terminal would
    /// be; `setup` lists setup's steps there; `none` says nothing.
    pub(crate) kind: &'static str,
    pub(crate) text: String,
    /// `neutral`, `info`, `warning` or `danger`.
    pub(crate) tone: &'static str,
    /// `start`, `retry` (a start after a refusal), `delete`, `refresh`, or none.
    pub(crate) action: &'static str,
    /// The action's button text; empty with no action.
    pub(crate) label: &'static str,
    /// Whether the banner can be dismissed until the notice changes.
    pub(crate) dismissible: bool,
    /// A message's drawing: `crashed`, `no-capacity`, `stopped`, or none.
    pub(crate) graphic: &'static str,
}

impl SandboxNotice {
    /// A centred message offers its own Start, so the header's waits (owner,
    /// 2026-11-13, #3772).
    pub(crate) fn offers_start(&self) -> bool {
        self.kind == "message" && matches!(self.action, "start" | "retry")
    }

    fn none() -> Self {
        Self::banner(String::new(), "neutral").kind("none")
    }

    fn banner(text: String, tone: &'static str) -> Self {
        Self {
            kind: "banner",
            text,
            tone,
            action: "",
            label: "",
            dismissible: false,
            graphic: "",
        }
    }

    fn message(graphic: &'static str, text: String, tone: &'static str) -> Self {
        Self {
            graphic,
            ..Self::banner(text, tone).kind("message")
        }
    }

    fn kind(self, kind: &'static str) -> Self {
        Self { kind, ..self }
    }

    /// Offers `action` under `label` when `allowed`, and nothing otherwise.
    fn offering(self, allowed: bool, action: &'static str, label: &'static str) -> Self {
        if !allowed {
            return self;
        }
        Self {
            action,
            label,
            ..self
        }
    }
}

pub(super) const SETTING_UP: &str = "Setting up this Sandbox. Terminals open when setup completes.";
pub(super) const STARTING: &str = "This Sandbox is starting. Terminals open when it is ready.";
pub(super) const PENDING: &str =
    "A Sandbox operation is pending. Waiting for the observed state to match its requested state.";
pub(super) const NO_ROOM: &str = "No room to start this sandbox right now.";

/// What the page says for a Sandbox's state. A reason the API wrote is said
/// as written, except a refusal for capacity, which the page says in one line;
/// otherwise the state is, and only an action the state allows is offered. A
/// Sandbox on its way to a state offers none; a crashed one offers Start again
/// when a start is allowed.
pub(crate) fn sandbox_notice(row: &EnvironmentRow) -> SandboxNotice {
    let actions = lifecycle_actions(row);
    let reason = row.status_message.as_str();
    let said = |default: &str| {
        if reason.is_empty() {
            default.to_owned()
        } else {
            reason.to_owned()
        }
    };
    let failed = |text: String| {
        SandboxNotice::message("crashed", text, "danger").offering(
            actions.start,
            "start",
            "Start again",
        )
    };
    match (row.state, row.status_code.as_str()) {
        ("destroying" | "destroyed", _) => SandboxNotice::none(),
        ("running", _) if !row.confidential_actions_allowed => SandboxNotice::none(),
        // A setup that failed says so from its recorded run, so a page that
        // followed only the latest start still shows why terminals stay shut.
        ("running", _) if !row.setup_failure.is_empty() => SandboxNotice::banner(
            format!("Setup failed: {}", row.setup_failure)
                .chars()
                .take(300)
                .collect(),
            "danger",
        )
        .kind("setup"),
        ("running", _) if row.setup_running => {
            SandboxNotice::banner(SETTING_UP.to_owned(), "neutral").kind("setup")
        }
        ("running", _) if !reason.is_empty() => SandboxNotice {
            dismissible: true,
            ..SandboxNotice::banner(said(""), "info")
        },
        ("running", _) => SandboxNotice::none(),
        ("error" | "build failed", _) if row.desired_state == "destroyed" => {
            let notice = SandboxNotice::message(
                "crashed",
                "This Sandbox could not be deleted.".to_owned(),
                "danger",
            );
            if actions.delete {
                notice.offering(true, "delete", "Delete")
            } else {
                notice.offering(true, "refresh", "Refresh status")
            }
        }
        ("error" | "stopped", "no_capacity") => SandboxNotice::message(
            "no-capacity",
            NO_ROOM.to_owned(),
            "warning",
        )
        .offering(actions.start, "retry", "Try again"),
        ("error", "sandbox_stopped") => {
            failed(said("This sandbox stopped unexpectedly and is restarting."))
        }
        ("error" | "build failed", _) => {
            let notice = failed(said("The Sandbox operation failed."));
            let unoffered = notice.action.is_empty();
            notice.offering(unoffered, "refresh", "Refresh status")
        }
        // Only a pending start is "starting"; a stopped Sandbox being archived
        // or deleted is a pending operation like any other.
        // A start says itself through the step list (#3772, the owner's
        // journey); other pending operations stay a banner.
        ("stopped", _) if actions.pending && row.desired_state == "started" => {
            SandboxNotice::banner(STARTING.to_owned(), "neutral").kind("setup")
        }
        ("stopped", _) if actions.pending => SandboxNotice::banner(PENDING.to_owned(), "info"),
        ("stopped", _) => SandboxNotice::message(
            "stopped",
            "This Sandbox is stopped. Its files are kept.".to_owned(),
            "neutral",
        )
        .offering(actions.start, "start", "Start"),
        (_, "sandbox_replacing") => SandboxNotice::banner(said(STARTING), "info"),
        ("stopping", _) => SandboxNotice::banner("This Sandbox is stopping.".to_owned(), "info"),
        ("resizing", _) => SandboxNotice::banner(
            "This Sandbox is being resized. Terminals open when it is ready.".to_owned(),
            "info",
        ),
        (_, _) if actions.pending && row.desired_state == "started" => {
            SandboxNotice::banner(STARTING.to_owned(), "neutral").kind("setup")
        }
        (_, _) if actions.pending => SandboxNotice::banner(PENDING.to_owned(), "info"),
        (_, _) => SandboxNotice::none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A running Sandbox whose setup has not completed: running it, or failed
    // with `setup_error`, as orchestration records it.
    fn running(setup_running: bool, setup_error: &str) -> EnvironmentRow {
        environment_row(Environment {
            id: "00000000-0000-4000-8000-000000000001".into(),
            state: EnvironmentState::Running.into(),
            desired_state: DesiredState::Started.into(),
            setup_complete: false,
            setup_error: if setup_running {
                String::new()
            } else {
                setup_error.into()
            },
            ..Default::default()
        })
    }

    #[test]
    fn a_recorded_setup_failure_is_said_from_its_run() {
        let failed = sandbox_notice(&running(false, "Running install command: exited 1"));
        assert_eq!(
            (failed.kind, failed.tone, failed.text.as_str()),
            (
                "setup",
                "danger",
                "Setup failed: Running install command: exited 1"
            )
        );
        let long = sandbox_notice(&running(false, &"x".repeat(400)));
        assert_eq!(long.text.chars().count(), 300);
        let setting_up = sandbox_notice(&running(true, ""));
        assert_eq!(
            (setting_up.kind, setting_up.tone, setting_up.text.as_str()),
            ("setup", "neutral", SETTING_UP)
        );
    }
}
