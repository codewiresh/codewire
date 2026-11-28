//! A hosted environment's setup, as a session launch sees it (#4767). A
//! setup that failed leaves the environment usable: `cw shell` and `cw run`
//! say the step it failed at and go on, so a person can fix it there. While
//! setup runs, the server refuses sessions; `cw` says so before launching.

use super::*;
use crate::commands::progress::terminal_text;
use crate::output::Status;

/// The prefix the setup worker puts before a failed step's error, and that
/// step in the words of the setup's step list, as the dashboard says them
/// (`codewire-dashboard-web`'s `environment_connect/notice.rs`).
const FAILED_STEPS: [(&str, &str); 3] = [
    ("health check: ", "Checking sidecar readiness"),
    ("git clone: ", "Cloning repositories"),
    ("install: ", "Running install command"),
];

/// What a running environment's setup means for a session launched now.
#[derive(Debug, PartialEq, Eq)]
enum Setup {
    /// Complete, or the environment is not running: the launch decides.
    Ready,
    /// Failed: the launch goes on under this line.
    Failed(String),
    /// Still running, a first setup or a retry: the server refuses sessions.
    Running,
}

fn setup_of(environment: &codewire_client::Environment) -> Setup {
    if environment.setup_complete
        || environment.state.as_known() != Some(codewire_client::EnvironmentState::Running)
    {
        return Setup::Ready;
    }
    match failed_line(&environment.setup_error) {
        Some(line) => Setup::Failed(line),
        None => Setup::Running,
    }
}

/// The recorded failure as the dashboard says it: the step it failed at,
/// when the error names one, and the error without that prefix.
fn failed_line(error: &str) -> Option<String> {
    let error = terminal_text(&without_escapes(error));
    if error.is_empty() {
        return None;
    }
    Some(
        FAILED_STEPS
            .iter()
            .find_map(|(prefix, step)| {
                error
                    .strip_prefix(prefix)
                    .map(|rest| format!("Setup failed at {step}: {rest}"))
            })
            .unwrap_or_else(|| format!("Setup failed: {error}")),
    )
}

/// `text` without terminal escape sequences: ESC and what follows it up to
/// its final byte, so none of a sequence's text is left behind.
fn without_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: parameters, then one final byte in `@`..=`~`.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: up to BEL or ST.
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The failed setup's line, then the command that runs it again once it is
/// fixed in the session that follows.
fn failed_warning(line: &str, name: &str, style: crate::output::Style) -> String {
    format!(
        "{} {line}\n{} cw retry {name}\n",
        style.status(Status::Attention),
        style.status(Status::Next)
    )
}

// Not led by the name: the error line capitalises its first letter.
fn setup_running(name: &str) -> String {
    format!(
        "The setup of {name} is running; wait for it, or follow it with `cw logs {name} --setup --follow`"
    )
}

pub(super) async fn ready_for_run(target: &EnvironmentSessionTarget) -> anyhow::Result<()> {
    let EnvironmentSessionTarget::Platform {
        org_id,
        environment_id,
        client,
        ..
    } = target
    else {
        return Ok(());
    };
    ready(client, org_id, environment_id).await
}

/// Before a session launch in a hosted environment: a warning under a failed
/// setup, a refusal while setup runs. When the environment can't be read,
/// the launch itself says what is wrong.
pub(crate) async fn ready(
    client: &codewire_client::CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let Ok((environment, _)) = restart::ask_environment(client, org_id, environment_id).await
    else {
        return Ok(());
    };
    let name = match terminal_text(&environment.name) {
        name if name.is_empty() => environment.id.clone(),
        name => name,
    };
    match setup_of(&environment) {
        Setup::Ready => Ok(()),
        Setup::Failed(line) => {
            let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
                .stderr_style();
            eprint!("{}", failed_warning(&line, &name, style));
            Ok(())
        }
        Setup::Running => anyhow::bail!(setup_running(&name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_client::EnvironmentState;

    fn environment(
        state: EnvironmentState,
        complete: bool,
        error: &str,
    ) -> codewire_client::Environment {
        codewire_client::Environment {
            id: "env_demo".into(),
            name: "app".into(),
            state: state.into(),
            setup_complete: complete,
            setup_error: error.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_failed_setup_names_its_step_as_the_dashboard_does() {
        assert_eq!(
            failed_line("install: workspace exec exited 1").as_deref(),
            Some("Setup failed at Running install command: workspace exec exited 1")
        );
        assert_eq!(
            failed_line("git clone: authentication failed").as_deref(),
            Some("Setup failed at Cloning repositories: authentication failed")
        );
        // An error that names no step is said as written, on one line.
        assert_eq!(
            failed_line("ports: refused\n\x1b[31m\x1b]8;;https://x\x07").as_deref(),
            Some("Setup failed: ports: refused")
        );
        assert_eq!(failed_line(" \n"), None);
    }

    #[test]
    fn a_failed_setup_warning_names_the_retry() {
        let style = crate::output::Style::new(false, crate::output::Charset::Unicode);
        assert_eq!(
            failed_warning(
                "Setup failed at Running install command: exited 1",
                "app",
                style
            ),
            "! Setup failed at Running install command: exited 1\n→ cw retry app\n"
        );
    }

    #[test]
    fn a_session_waits_only_for_a_running_setup() {
        let running = EnvironmentState::Running;
        assert_eq!(setup_of(&environment(running, true, "")), Setup::Ready);
        assert_eq!(setup_of(&environment(running, false, "")), Setup::Running);
        assert_eq!(setup_of(&environment(running, false, "  ")), Setup::Running);
        assert_eq!(
            setup_of(&environment(running, false, "install: exited 1")),
            Setup::Failed("Setup failed at Running install command: exited 1".into())
        );
        // Starting, stopped or failed environments are the launch's to refuse.
        for state in [
            EnvironmentState::Starting,
            EnvironmentState::Stopped,
            EnvironmentState::Error,
        ] {
            assert_eq!(
                setup_of(&environment(state, false, "")),
                Setup::Ready,
                "{state:?}"
            );
        }
        assert_eq!(
            setup_running("app"),
            "The setup of app is running; wait for it, or follow it with `cw logs app --setup --follow`"
        );
    }
}
