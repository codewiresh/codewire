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
    /// `start`, `retry` (a start after a refusal), `retry-setup` (#4767),
    /// `delete`, `refresh`, or none.
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

/// The prefix the setup worker (`worker/setup.rs`) puts before a failed
/// step's error, and that step in the words of the page's step list. The
/// recorded `setup_phase` cannot name the step: it is the last checkpoint,
/// which steps with nothing to do never advance.
const FAILED_STEPS: [(&str, &str); 3] = [
    ("health check: ", "Checking sidecar readiness"),
    ("git clone: ", "Cloning repositories"),
    ("install: ", "Running install command"),
];

/// What the page says of a recorded setup failure: the step it failed at, as
/// the step list names it, when the error names one, and the error without
/// that prefix. Empty when no failure is recorded.
pub(super) fn setup_failure(error: &str) -> String {
    let error = display_line(error);
    if error.is_empty() {
        return error;
    }
    let text = FAILED_STEPS
        .iter()
        .find_map(|(prefix, label)| {
            error
                .strip_prefix(prefix)
                .map(|rest| format!("Setup failed at {label}: {rest}"))
        })
        .unwrap_or_else(|| format!("Setup failed: {error}"));
    text.chars().take(300).collect()
}

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
        // A failed setup leaves the Sandbox usable: the failure stays above
        // the terminals, which open so a person can fix it, then retry (#4767).
        ("running", _) if !row.setup_failure.is_empty() => SandboxNotice::banner(
            row.setup_failure.clone(),
            "danger",
        )
        .offering(true, "retry-setup", "Retry setup"),
        ("running", _) if row.setup_running => {
            SandboxNotice::banner(SETTING_UP.to_owned(), "neutral").kind("setup")
        }
        ("running", _) if !row.hibernate_fallback_reason.is_empty() => SandboxNotice {
            dismissible: true,
            ..SandboxNotice::banner(
                format!(
                    "Could not restore from hibernate ({}); booted cleanly from disks — running processes were lost while files were kept.",
                    row.hibernate_fallback_reason
                ),
                "warning",
            )
        },
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
        ("stopped", _) if row.hibernated => {
            let when = if row.hibernated_at.is_empty() {
                String::new()
            } else {
                format!(" ({})", row.hibernated_at)
            };
            let text = if row.hibernate_reason == "idle" && row.idle_hibernate_seconds > 0 {
                format!(
                    "Hibernated after {} idle{when}. Processes and files are saved.",
                    codewire_project::idle_stop_words(row.idle_hibernate_seconds)
                )
            } else if row.hibernate_reason == "idle" {
                format!("Hibernated after being idle{when}. Processes and files are saved.")
            } else {
                format!("Hibernated{when}. Processes and files are saved.")
            };
            SandboxNotice::message("stopped", text, "neutral").offering(
                actions.start,
                "start",
                "Start",
            )
        }
        // It stopped itself: how long it was idle, as briefly as it can be
        // said (#3384). `cw info` gives the full reason. Start, beside it, is
        // how to start it again.
        ("stopped", _) if row.stop_reason == "idle" => SandboxNotice::message(
            "stopped",
            format!(
                "Stopped after {} idle. Files are kept.",
                codewire_project::idle_stop_words(row.idle_stop_seconds)
            ),
            "neutral",
        )
        .offering(actions.start, "start", "Start"),
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
    fn a_recorded_setup_failure_is_a_banner_naming_its_step() {
        let failed = sandbox_notice(&running(false, "install: npm ci exited 1"));
        assert_eq!(
            (
                failed.kind,
                failed.tone,
                failed.text.as_str(),
                failed.action,
                failed.label
            ),
            (
                "banner",
                "danger",
                "Setup failed at Running install command: npm ci exited 1",
                "retry-setup",
                "Retry setup"
            )
        );
        let long = sandbox_notice(&running(false, &"x".repeat(400)));
        assert_eq!(long.text.chars().count(), 300);
        assert!(running(false, "  ").setup_failure.is_empty());
        let setting_up = sandbox_notice(&running(true, ""));
        assert_eq!(
            (setting_up.kind, setting_up.tone, setting_up.text.as_str()),
            ("setup", "neutral", SETTING_UP)
        );
    }

    #[test]
    fn a_failure_names_the_step_its_error_names() {
        assert_eq!(
            setup_failure("git clone: authentication failed"),
            "Setup failed at Cloning repositories: authentication failed"
        );
        // Kind, 2026-11-15: an install failure in a Sandbox with no
        // repositories, whose recorded phase still says the clone's.
        assert_eq!(
            setup_failure("install: workspace exec exited 1"),
            "Setup failed at Running install command: workspace exec exited 1"
        );
        // An error that names no step is said as written.
        assert_eq!(
            setup_failure("ports: refused"),
            "Setup failed: ports: refused"
        );
        assert_eq!(setup_failure(" \n"), "");
    }

    /// Each step is named as the page's step list names it, and each prefix
    /// is one the worker writes.
    #[test]
    fn failed_steps_match_the_step_list_and_the_worker() {
        const PAGE: &str = include_str!("../../../../packages/codewire-design/setup-progress.js");
        const WORKER: &str = include_str!("../../../codewire-orchestration/src/worker/setup.rs");
        let body = PAGE
            .split("const SETUP_PHASES = new Map([")
            .nth(1)
            .and_then(|rest| rest.split("]);").next())
            .expect("setup-progress.js defines SETUP_PHASES");
        let labels: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("[\""))
            .filter_map(|entry| entry.split('"').nth(2))
            .collect();
        for (prefix, label) in FAILED_STEPS {
            assert!(labels.contains(&label), "the step list has no {label:?}");
            assert!(
                WORKER.contains(&format!("anyhow::anyhow!(\"{prefix}{{e:#}}\")")),
                "the setup worker no longer writes {prefix:?}"
            );
        }
    }

    #[test]
    fn a_hibernated_sandbox_pill_reads_hibernated_and_fallback_warns_naming_reason() {
        let mut hibernated_env = Environment {
            id: "00000000-0000-4000-8000-000000000002".into(),
            state: EnvironmentState::Stopped.into(),
            desired_state: DesiredState::Stopped.into(),
            idle_hibernate_seconds: 6 * 3600,
            hibernate_reason: "idle".into(),
            ..Default::default()
        };
        let mut ts = hibernated_env
            .hibernated_at
            .into_option()
            .unwrap_or_default();
        ts.seconds = chrono::Utc::now().timestamp() - 600;
        hibernated_env.hibernated_at = Some(ts).into();
        let hibernated = environment_row(hibernated_env);
        assert!(hibernated.hibernated);
        assert_eq!(hibernated.state_label(), "hibernated");
        let notice = sandbox_notice(&hibernated);
        assert_eq!(notice.kind, "message");
        assert_eq!(notice.action, "start");
        assert_eq!(notice.label, "Start");
        assert!(
            notice.text.contains("Hibernated after 6 hours idle"),
            "{}",
            notice.text
        );
        assert!(
            notice.text.contains("Processes and files are saved"),
            "{}",
            notice.text
        );

        let fallback = environment_row(Environment {
            id: "00000000-0000-4000-8000-000000000003".into(),
            state: EnvironmentState::Running.into(),
            desired_state: DesiredState::Started.into(),
            setup_complete: true,
            hibernate_fallback_reason: "runtime_image_expired".into(),
            ..Default::default()
        });
        assert!(!fallback.hibernated);
        assert_eq!(fallback.state_label(), "running");
        let banner = sandbox_notice(&fallback);
        assert_eq!(banner.kind, "banner");
        assert_eq!(banner.tone, "warning");
        assert!(
            banner.text.contains("runtime_image_expired"),
            "{}",
            banner.text
        );
        assert!(
            banner
                .text
                .contains("running processes were lost while files were kept"),
            "{}",
            banner.text
        );
    }
}
