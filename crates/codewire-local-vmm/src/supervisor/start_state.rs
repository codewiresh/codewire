//! The runner's state as a start of its environment finds it (#4953).

use super::*;

/// The runner's state for a start of `environment_id`. A runner in `error`
/// may still hold its failed VMM: one whose egress broker, network worker or
/// Mesh transport ended keeps it, fail-closed, for an explicit stop. A start
/// means "make it run", so that VMM is stopped first, as `cw stop` would stop
/// it, and the start boots from `stopped`.
pub(super) async fn runner_state_for_start(
    client: &mut RunnerClient,
    environment_id: Uuid,
) -> Result<(v1::RunnerInfo, StoredEnvironmentState), SupervisorError> {
    let mut current = client
        .info()
        .await
        .map_err(|_| SupervisorError::RunnerUnavailable)?;
    if current.environment_id != environment_id.to_string() {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    if StoredEnvironmentState::from_proto(current.state)? == StoredEnvironmentState::Error {
        // The start fails then, with the runner's own reason.
        current = client
            .stop()
            .await
            .map_err(|status| SupervisorError::VmStart(status.message().to_owned()))?;
    }
    let state = StoredEnvironmentState::from_proto(current.state)?;
    Ok((current, state))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::supervisor::tests::spawn_stateful_test_runner_server;

    /// What a start of `started` finds of a runner reporting `state` for
    /// `reported`, and how many times it stopped that runner.
    async fn found_by_start(
        state: v1::EnvironmentState,
        reported: Uuid,
        started: Uuid,
    ) -> (Result<StoredEnvironmentState, SupervisorError>, usize) {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.path().join("runner.sock");
        let info = v1::RunnerInfo {
            environment_id: reported.to_string(),
            state: state as i32,
            generation: 3,
            ..Default::default()
        };
        let (identity, stops, stop_server, server) =
            spawn_stateful_test_runner_server(&socket, info);
        let mut client = RunnerClient::connect(&socket).await.unwrap();
        let found = runner_state_for_start(&mut client, started)
            .await
            .map(|(_, state)| state);
        drop(client);
        stop_server.send(()).unwrap();
        server.await.unwrap();
        crate::uds::remove_bound_socket(&socket, &identity).unwrap();
        (found, stops.load(Ordering::Relaxed))
    }

    /// #4953: a runner in `error` is stopped first, as `cw stop` would stop
    /// it, so the start boots from `stopped`.
    #[tokio::test]
    async fn a_start_stops_a_runner_in_error_first() {
        let id = Uuid::new_v4();
        let (found, stops) = found_by_start(v1::EnvironmentState::Error, id, id).await;
        assert_eq!(found.unwrap(), StoredEnvironmentState::Stopped);
        assert_eq!(stops, 1);
    }

    /// A runner in any other state is left as it reports.
    #[tokio::test]
    async fn a_start_leaves_a_runner_in_any_other_state_alone() {
        for (state, stored) in [
            (
                v1::EnvironmentState::Stopped,
                StoredEnvironmentState::Stopped,
            ),
            (
                v1::EnvironmentState::Running,
                StoredEnvironmentState::Running,
            ),
        ] {
            let id = Uuid::new_v4();
            let (found, stops) = found_by_start(state, id, id).await;
            assert_eq!(found.unwrap(), stored);
            assert_eq!(stops, 0, "{state:?} was stopped");
        }
    }

    /// A runner that answers for another environment is never stopped.
    #[tokio::test]
    async fn a_start_refuses_a_runner_for_another_environment() {
        let (found, stops) =
            found_by_start(v1::EnvironmentState::Error, Uuid::new_v4(), Uuid::new_v4()).await;
        assert!(matches!(found, Err(SupervisorError::InvalidRunnerResponse)));
        assert_eq!(stops, 0);
    }
}
