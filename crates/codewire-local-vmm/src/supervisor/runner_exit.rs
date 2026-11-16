//! How the process that failed an environment closed ended, read from its
//! runner when the environment is shown (#4953).

use super::*;

/// How long showing an environment waits for its runner's answer.
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

/// `environment` with how its runner's failed process ended, while the
/// runner still reports the error `environment` shows. A runner that isn't
/// reached in time, or answers otherwise, adds nothing, and the error code
/// alone is shown, as before.
pub(super) async fn with_runner_exit(
    supervisor: &Supervisor,
    mut environment: v1::Environment,
) -> v1::Environment {
    let Ok(id) = Uuid::parse_str(&environment.id) else {
        return environment;
    };
    if environment.error_code.is_empty() {
        return environment;
    }
    let socket = supervisor.config.runner_socket(id);
    let info = tokio::time::timeout(RUNNER_EXIT_TIMEOUT, async {
        let mut client = RunnerClient::connect(&socket).await.ok()?;
        client.info().await.ok()
    })
    .await;
    if let Ok(Some(info)) = info {
        environment.runner_exit = reported_exit(&environment, &info);
    }
    environment
}

/// The exit `info` reports for the error `environment` shows: only from the
/// same environment's runner, for the same error code, with a reason in the
/// error-code vocabulary.
fn reported_exit(environment: &v1::Environment, info: &v1::RunnerInfo) -> Option<v1::RunnerExit> {
    let exit = info.exit.clone()?;
    (info.environment_id == environment.id
        && info.error_code == environment.error_code
        && (exit.reason.is_empty() || runner_event_error_code_valid(&exit.reason)))
    .then_some(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(error_code: &str) -> v1::Environment {
        v1::Environment {
            id: "0d8f6f28-5d3c-4f86-a5b1-6a2f6d0b7f3e".to_owned(),
            error_code: error_code.to_owned(),
            ..Default::default()
        }
    }

    fn reported(environment_id: &str, error_code: &str, reason: &str) -> v1::RunnerInfo {
        v1::RunnerInfo {
            environment_id: environment_id.to_owned(),
            error_code: error_code.to_owned(),
            exit: Some(v1::RunnerExit {
                status: Some(72),
                reason: reason.to_owned(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_runners_exit_is_shown_for_the_same_environment_and_error() {
        let environment = shown("egress_broker_exit");
        let info = reported(
            &environment.id,
            "egress_broker_exit",
            "egress_broker_protocol",
        );
        assert_eq!(
            reported_exit(&environment, &info),
            Some(v1::RunnerExit {
                status: Some(72),
                reason: "egress_broker_protocol".to_owned(),
            })
        );
    }

    /// Another environment's runner, another error, or a reason outside the
    /// error-code vocabulary adds nothing.
    #[test]
    fn anything_else_the_runner_reports_is_left_out() {
        let environment = shown("egress_broker_exit");
        for info in [
            reported(
                "6c1a1c55-5d0b-4f7e-9d38-0c8d9c2f4a11",
                "egress_broker_exit",
                "egress_broker_protocol",
            ),
            reported(
                &environment.id,
                "network_worker_exit",
                "egress_broker_protocol",
            ),
            reported(&environment.id, "egress_broker_exit", "Protocol error!"),
            v1::RunnerInfo {
                environment_id: environment.id.clone(),
                error_code: "egress_broker_exit".to_owned(),
                ..Default::default()
            },
        ] {
            assert_eq!(reported_exit(&environment, &info), None, "{info:?}");
        }
    }
}
