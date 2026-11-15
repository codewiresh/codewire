//! A cloud environment that refuses a session because it isn't running
//! (#4689). The server answers "environment must be running" whatever the
//! state (orchestration's `session_state_refusal`, and the coordinator); it is
//! typed once here, from `display_client_error`, and a command that hits it
//! asks the environment's state once, then says what that state means.

use codewire_client::{ClientError, EnvironmentState, ErrorCode};

/// The server's refusal of a session in an environment that isn't running.
#[derive(Debug, thiserror::Error)]
#[error("the environment isn't running")]
pub(crate) struct EnvironmentNotRunning;

const NOT_RUNNING: &str = "environment must be running";

/// A client error as the CLI keeps it: the refusal typed, anything else as
/// it is.
pub(crate) fn typed(error: ClientError) -> anyhow::Error {
    let refused = matches!(
        error.code(),
        ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition
    ) && error.message() == NOT_RUNNING;
    if refused {
        EnvironmentNotRunning.into()
    } else {
        error.into()
    }
}

/// Whether `error` is, or wraps, the refusal.
pub(crate) fn is_refusal(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<EnvironmentNotRunning>())
}

/// What to say when a command couldn't reach cloud environment `name` in
/// `state`: `None` when it is running, so the command's own error stands;
/// with no state, that it isn't running and where to look. The command that
/// helps is the error's next step, printed on its own `→` line.
pub(crate) fn state_error(name: &str, state: Option<EnvironmentState>) -> Option<anyhow::Error> {
    let start = format!("cw --cloud start {name}");
    let info = format!("cw --cloud info {name}");
    let (message, step) = match state {
        Some(EnvironmentState::Running) => return None,
        Some(EnvironmentState::Stopped) => (format!("cloud environment {name} is stopped"), start),
        Some(EnvironmentState::Stopping) => (
            format!("cloud environment {name} is stopping; start it once it has stopped"),
            info,
        ),
        Some(
            EnvironmentState::Pending
            | EnvironmentState::PendingBuild
            | EnvironmentState::Building
            | EnvironmentState::PullingSnapshot
            | EnvironmentState::Creating
            | EnvironmentState::Starting
            | EnvironmentState::Restoring
            | EnvironmentState::Resizing,
        ) => (
            format!("cloud environment {name} is still starting; try again once it is running"),
            info,
        ),
        Some(EnvironmentState::BuildFailed | EnvironmentState::Error) => {
            (format!("cloud environment {name} failed"), info)
        }
        Some(EnvironmentState::Destroying | EnvironmentState::Destroyed) => {
            return Some(anyhow::anyhow!("cloud environment {name} is being removed"));
        }
        _ => (format!("cloud environment {name} isn't running"), info),
    };
    Some(crate::error_report::with_next_step(
        anyhow::anyhow!(message),
        step,
    ))
}

/// `error` from reaching a cloud environment, explained by what the lookup
/// `found` (its name and state), or `None` when the lookup failed. A running
/// environment keeps `error`. A failed lookup keeps it too, unless the server
/// had refused it as not running; then `fallback` names it.
pub(crate) fn explain(
    error: anyhow::Error,
    fallback: &str,
    found: Option<(&str, Option<EnvironmentState>)>,
) -> anyhow::Error {
    let (name, state) = match found {
        Some(found) => found,
        None if is_refusal(&error) => (fallback, None),
        None => return error,
    };
    state_error(&crate::commands::progress::terminal_text(name), state).unwrap_or(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_report::NextStep;

    /// What an error says, and the next step it carries.
    fn said(error: &anyhow::Error) -> (String, Option<String>) {
        let step = error.downcast_ref::<NextStep>().map(ToString::to_string);
        (error.root_cause().to_string(), step)
    }

    fn says(message: &str, step: Option<&str>) -> (String, Option<String>) {
        (message.to_owned(), step.map(str::to_owned))
    }

    #[test]
    fn the_refusal_is_typed_and_nothing_else_is() {
        let refused = typed(ClientError::new(ErrorCode::InvalidArgument, NOT_RUNNING));
        assert!(is_refusal(&refused));
        assert!(
            is_refusal(&refused.context("upload")),
            "found under a context"
        );
        let coordinator = typed(ClientError::new(ErrorCode::FailedPrecondition, NOT_RUNNING));
        assert!(is_refusal(&coordinator));
        let other = typed(ClientError::new(
            ErrorCode::InvalidArgument,
            "bad session name",
        ));
        assert!(!is_refusal(&other));
    }

    /// exec's connect error, or a refusal, explained by the state found.
    #[test]
    fn a_lookup_explains_the_failure_or_leaves_it() {
        let connect = || anyhow::anyhow!("no host key is recorded for the environment's bound Pod");
        let stopped = Some(("walk", Some(EnvironmentState::Stopped)));
        assert_eq!(
            said(&explain(connect(), "env-1", stopped)),
            says(
                "cloud environment walk is stopped",
                Some("cw --cloud start walk")
            )
        );
        let running = Some(("walk", Some(EnvironmentState::Running)));
        assert_eq!(
            said(&explain(connect(), "env-1", running)),
            says(
                "no host key is recorded for the environment's bound Pod",
                None
            ),
            "a running environment keeps exec's own error"
        );
        assert_eq!(
            said(&explain(connect(), "env-1", None)),
            says(
                "no host key is recorded for the environment's bound Pod",
                None
            ),
            "a failed lookup keeps exec's own error"
        );
        let refused = typed(ClientError::new(ErrorCode::InvalidArgument, NOT_RUNNING));
        assert_eq!(
            said(&explain(refused, "walk", None)),
            says(
                "cloud environment walk isn't running",
                Some("cw --cloud info walk")
            ),
            "a failed lookup after a refusal still names it"
        );
    }

    #[test]
    fn each_state_says_what_it_means_and_only_stopped_is_told_to_start() {
        let state = |state| state_error("walk", state).as_ref().map(said);
        assert_eq!(
            state(Some(EnvironmentState::Stopped)),
            Some(says(
                "cloud environment walk is stopped",
                Some("cw --cloud start walk")
            ))
        );
        assert_eq!(
            state(Some(EnvironmentState::Stopping)),
            Some(says(
                "cloud environment walk is stopping; start it once it has stopped",
                Some("cw --cloud info walk")
            ))
        );
        assert_eq!(
            state(Some(EnvironmentState::Running)),
            None,
            "a running environment keeps the command's own error"
        );
        assert_eq!(
            state(Some(EnvironmentState::Starting)),
            Some(says(
                "cloud environment walk is still starting; try again once it is running",
                Some("cw --cloud info walk")
            ))
        );
        assert_eq!(
            state(Some(EnvironmentState::Error)),
            Some(says(
                "cloud environment walk failed",
                Some("cw --cloud info walk")
            ))
        );
        assert_eq!(
            state(Some(EnvironmentState::Destroying)),
            Some(says("cloud environment walk is being removed", None))
        );
        assert_eq!(
            state(None),
            Some(says(
                "cloud environment walk isn't running",
                Some("cw --cloud info walk")
            )),
            "a lookup that failed"
        );
        for other in [
            EnvironmentState::Stopping,
            EnvironmentState::Starting,
            EnvironmentState::Error,
            EnvironmentState::Destroying,
        ] {
            let (_, step) = state(Some(other)).unwrap();
            assert_ne!(
                step.as_deref(),
                Some("cw --cloud start walk"),
                "{other:?} is not told to start"
            );
        }
    }
}
