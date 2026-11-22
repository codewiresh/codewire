//! An environment that refuses a session because it isn't running (#4689).
//! The cloud answers "environment must be running" whatever the state
//! (orchestration's `session_state_refusal`, and the coordinator); it is
//! typed once here, from `display_client_error`. A local VM's supervisor
//! answers `failed_precondition` with its own words. A command that hits
//! either asks the environment's state once, then says what that state
//! means, in one wording for both placements ([`state_error`]).

use codewire_client::{ClientError, EnvironmentState, ErrorCode};

use crate::commands::lifecycle_output::environment_command;
use crate::output::VmLocation;

/// The server's refusal of a session in an environment that isn't running.
#[derive(Debug, thiserror::Error)]
#[error("the environment isn't running")]
pub(crate) struct EnvironmentNotRunning;

const NOT_RUNNING: &str = "environment must be running";

/// The local supervisor's public API refusal of a session in a VM that
/// isn't running (`codewire-local-vmm`, `public_api/status.rs`).
const LOCAL_NOT_RUNNING: &str = "local environment is not in the required state";

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

/// Whether `error` is, or wraps, a local VM's refusal of a session because
/// it isn't running.
pub(crate) fn is_local_refusal(error: &anyhow::Error) -> bool {
    let refused = |code: ErrorCode, message: &str| {
        code == ErrorCode::FailedPrecondition && message == LOCAL_NOT_RUNNING
    };
    error.chain().any(|cause| {
        if let Some(error) = cause.downcast_ref::<ClientError>() {
            return refused(error.code(), error.message());
        }
        if let Some(error) = cause.downcast_ref::<connectrpc::ConnectError>() {
            return refused(error.code, error.message.as_deref().unwrap_or_default());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(error) =
            cause.downcast_ref::<codewire_local_vmm::public_client::NativePublicClientError>()
        {
            use codewire_local_vmm::public_client::NativePublicClientError as Native;
            return match error {
                Native::Rpc(error) => {
                    refused(error.code, error.message.as_deref().unwrap_or_default())
                }
                Native::Client(error) => refused(error.code(), error.message()),
                _ => false,
            };
        }
        false
    })
}

/// A local VM's state as [`state_error`] reads it. An orphaned VM has lost
/// its runtime, so it reads as failed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_state(state: i32) -> Option<EnvironmentState> {
    use codewire_local_vmm::control::v1::EnvironmentState as Local;
    Some(match Local::try_from(state).ok()? {
        Local::Running => EnvironmentState::Running,
        Local::Stopped => EnvironmentState::Stopped,
        Local::Starting => EnvironmentState::Starting,
        Local::Error | Local::Orphaned => EnvironmentState::Error,
        Local::Unspecified => return None,
    })
}

/// `error`, or, when a local VM refused it because it isn't running, what
/// its `state` means and what to do, in [`state_error`]'s words. `state` is
/// `None` when it couldn't be read.
pub(crate) fn explain_local(
    error: anyhow::Error,
    name: &str,
    state: Option<EnvironmentState>,
) -> anyhow::Error {
    if !is_local_refusal(&error) {
        return error;
    }
    state_error(VmLocation::Local, name, state, None).unwrap_or(error)
}

/// What to say when a command couldn't reach environment `name` at
/// `location` in `state`: `None` when it is running, so the command's own
/// error stands; with no state, that it isn't running and where to look.
/// `idle_stop` is its timeout when it stopped itself for being idle
/// (#3384). The command that helps is the error's next step, printed on its
/// own `→` line. Both placements say it in these words.
pub(crate) fn state_error(
    location: VmLocation,
    name: &str,
    state: Option<EnvironmentState>,
    idle_stop: Option<i32>,
) -> Option<anyhow::Error> {
    let start = environment_command(location, "start", name);
    let info = environment_command(location, "info", name);
    let environment = match location {
        VmLocation::Local => "local environment",
        VmLocation::Cloud => "cloud environment",
    };
    let (message, step) = match state {
        Some(EnvironmentState::Running) => return None,
        Some(EnvironmentState::Stopped) => match idle_stop {
            Some(seconds) => (
                format!(
                    "{environment} {name}: {}",
                    codewire_project::idle_stop_reason(seconds)
                ),
                start,
            ),
            None => (format!("{environment} {name} is stopped"), start),
        },
        Some(EnvironmentState::Stopping) => (
            format!("{environment} {name} is stopping; start it once it has stopped"),
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
            format!("{environment} {name} is still starting; try again once it is running"),
            info,
        ),
        Some(EnvironmentState::BuildFailed | EnvironmentState::Error) => {
            (format!("{environment} {name} failed"), info)
        }
        Some(EnvironmentState::Destroying | EnvironmentState::Destroyed) => {
            return Some(anyhow::anyhow!("{environment} {name} is being removed"));
        }
        _ => (format!("{environment} {name} isn't running"), info),
    };
    Some(crate::error_report::with_next_step(
        anyhow::anyhow!(message),
        step,
    ))
}

/// The coordinator's own answer, when reaching an environment's tailnet failed
/// because the coordinator refused this client rather than because the way
/// there broke: the refusal as the API's errors are shown, without the
/// transport steps it surfaced through. `None` for any other failure, which a
/// retry may fix and which keeps its chain.
pub(crate) fn coordinator_answer(error: &anyhow::Error) -> Option<anyhow::Error> {
    let refused = error.chain().find_map(|cause| {
        match cause.downcast_ref::<codewire_client::CoordinatorError>() {
            Some(codewire_client::CoordinatorError::Connect(refused)) => Some(refused),
            _ => None,
        }
    })?;
    matches!(
        refused.code,
        ErrorCode::PermissionDenied
            | ErrorCode::Unauthenticated
            | ErrorCode::FailedPrecondition
            | ErrorCode::NotFound
            | ErrorCode::InvalidArgument
    )
    .then(|| crate::environment_client::display_client_error(refused.clone().into()))
}

/// `error` from reaching a cloud environment, explained by what the lookup
/// `found` (its name and state), or `None` when the lookup failed. A running
/// environment keeps `error`. A failed lookup keeps it too, unless the server
/// had refused it as not running; then `fallback` names it.
pub(crate) fn explain(
    error: anyhow::Error,
    fallback: &str,
    found: Option<(&str, Option<EnvironmentState>, Option<i32>)>,
) -> anyhow::Error {
    let (name, state, idle_stop) = match found {
        Some(found) => found,
        None if is_refusal(&error) => (fallback, None, None),
        None => return error,
    };
    state_error(
        VmLocation::Cloud,
        &crate::commands::progress::terminal_text(name),
        state,
        idle_stop,
    )
    .unwrap_or(error)
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

    /// How the tailnet connect surfaces the coordinator's answer: under the
    /// transport steps that carried it.
    fn through_tailnet(answer: connectrpc::ConnectError) -> anyhow::Error {
        anyhow::Error::new(codewire_client::CoordinatorError::Connect(answer))
            .context("connect typed coordinator")
            .context("fetch coordinator DERP map")
            .context("reach the environment over its tailnet")
    }

    #[test]
    fn the_coordinators_answer_is_shown_without_the_steps_it_came_through() {
        let deleting = coordinator_answer(&through_tailnet(
            connectrpc::ConnectError::failed_precondition("organization is being deleted"),
        ))
        .expect("a refusal is the coordinator's answer");
        assert_eq!(deleting.to_string(), "organization is being deleted");
        assert!(!is_refusal(&deleting));

        let missing = coordinator_answer(&through_tailnet(connectrpc::ConnectError::not_found(
            "organization not found",
        )))
        .expect("not found is an answer");
        assert_eq!(missing.to_string(), "organization not found");

        // Not running stays the typed refusal that the state lookup explains.
        let stopped = coordinator_answer(&through_tailnet(
            connectrpc::ConnectError::failed_precondition(NOT_RUNNING),
        ))
        .expect("not running is an answer");
        assert!(is_refusal(&stopped));
    }

    #[test]
    fn a_broken_way_there_keeps_its_steps() {
        for broken in [
            connectrpc::ConnectError::unavailable("connection refused"),
            connectrpc::ConnectError::deadline_exceeded("timed out"),
            connectrpc::ConnectError::internal("internal error"),
        ] {
            assert!(coordinator_answer(&through_tailnet(broken)).is_none());
        }
        assert!(coordinator_answer(&anyhow::anyhow!("no host key is recorded")).is_none());
    }

    /// exec's connect error, or a refusal, explained by the state found.
    #[test]
    fn a_lookup_explains_the_failure_or_leaves_it() {
        let connect = || anyhow::anyhow!("no host key is recorded for the environment's bound Pod");
        let stopped = Some(("walk", Some(EnvironmentState::Stopped), None));
        assert_eq!(
            said(&explain(connect(), "env-1", stopped)),
            says(
                "cloud environment walk is stopped",
                Some("cw --cloud start walk")
            )
        );
        let running = Some(("walk", Some(EnvironmentState::Running), None));
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

    /// One that stopped itself says why, in the owner's words, with its own
    /// timeout (#3384).
    #[test]
    fn an_idle_stop_says_it_stopped_itself_and_how_to_start_it() {
        let idle = Some(("walk", Some(EnvironmentState::Stopped), Some(21_600)));
        assert_eq!(
            said(&explain(anyhow::anyhow!("not running"), "env-1", idle)),
            says(
                "cloud environment walk: Stopped itself after 6 hours idle (CPU under 10%, no \
                 traffic or input). Files are kept.",
                Some("cw --cloud start walk")
            )
        );
    }

    /// docs/dev/CLI-PARITY.md, N2: a local VM's refusal of a session in a
    /// stopped VM says so in the cloud's words, with the local command,
    /// not "failed_precondition … required state". Any other failure, or a
    /// running VM, keeps its own error.
    #[test]
    fn a_stopped_local_vm_is_refused_in_the_same_words_as_a_cloud_one() {
        let refused = || {
            anyhow::Error::new(connectrpc::ConnectError::failed_precondition(
                LOCAL_NOT_RUNNING,
            ))
            .context("run the session")
        };
        assert!(is_local_refusal(&refused()));
        assert_eq!(
            said(&explain_local(
                refused(),
                "walk",
                Some(EnvironmentState::Stopped)
            )),
            says(
                "local environment walk is stopped",
                Some("cw --local start walk")
            )
        );
        assert_eq!(
            said(&explain_local(refused(), "walk", None)),
            says(
                "local environment walk isn't running",
                Some("cw --local info walk")
            )
        );
        let client = anyhow::Error::new(ClientError::new(
            ErrorCode::FailedPrecondition,
            LOCAL_NOT_RUNNING,
        ));
        assert!(is_local_refusal(&client));
        // A running VM, or another refusal, keeps its own error.
        let running = explain_local(refused(), "walk", Some(EnvironmentState::Running));
        assert!(is_local_refusal(&running));
        assert_eq!(said(&running).1, None);
        let other = || {
            anyhow::Error::new(connectrpc::ConnectError::failed_precondition(
                "local request is invalid",
            ))
        };
        assert!(!is_local_refusal(&other()));
        let kept = explain_local(other(), "walk", Some(EnvironmentState::Stopped));
        assert_eq!(said(&kept), said(&other()));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_local_vms_state_reads_as_the_clouds() {
        use codewire_local_vmm::control::v1::EnvironmentState as Local;
        assert_eq!(
            local_state(Local::Stopped as i32),
            Some(EnvironmentState::Stopped)
        );
        assert_eq!(
            local_state(Local::Running as i32),
            Some(EnvironmentState::Running)
        );
        assert_eq!(
            local_state(Local::Orphaned as i32),
            Some(EnvironmentState::Error)
        );
        assert_eq!(local_state(Local::Unspecified as i32), None);
    }

    #[test]
    fn each_state_says_what_it_means_and_only_stopped_is_told_to_start() {
        let state = |state| {
            state_error(VmLocation::Cloud, "walk", state, None)
                .as_ref()
                .map(said)
        };
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
