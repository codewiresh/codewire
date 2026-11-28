//! What an environment's runner reports when the environment is shown: how
//! the process that failed it closed ended (#4953), or that a running VM's
//! egress is unavailable (#4965) and how much it refused (#5058).

use super::*;

/// How long showing an environment in error waits for its runner's answer.
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long showing a running environment waits: `cw info` of a working VM
/// stays quick.
const RUNNER_EGRESS_TIMEOUT: Duration = Duration::from_millis(500);

/// `environment` with what its runner reports: for an environment in error,
/// how its failed process ended; for a running one, whether its egress is
/// unavailable. A runner that isn't reached in time, or answers otherwise,
/// adds nothing, and the environment is shown as before.
pub(super) async fn with_runner_report(
    supervisor: &Supervisor,
    mut environment: v1::Environment,
) -> v1::Environment {
    let Ok(id) = Uuid::parse_str(&environment.id) else {
        return environment;
    };
    let running = environment.state == v1::EnvironmentState::Running as i32;
    let deadline = match (environment.error_code.is_empty(), running) {
        (false, _) => RUNNER_EXIT_TIMEOUT,
        (true, true) => RUNNER_EGRESS_TIMEOUT,
        (true, false) => return environment,
    };
    let socket = supervisor.config.runner_socket(id);
    let info = tokio::time::timeout(deadline, async {
        let mut client = RunnerClient::connect(&socket).await.ok()?;
        client.info().await.ok()
    })
    .await;
    if let Ok(Some(info)) = info {
        apply_runner_info(&mut environment, &info);
    }
    environment
}

/// Copies live fields from `info` onto `environment` when identity and state
/// match.
pub(super) fn apply_runner_info(environment: &mut v1::Environment, info: &v1::RunnerInfo) {
    environment.runner_exit = reported_exit(environment, info);
    environment.egress_unavailable = reported_egress(environment, info);
    environment.interception = reported_interception(environment, info);
    environment.egress_refusals = reports_running(environment, info)
        .then_some(info.egress_refusals)
        .flatten();
    if reports_running(environment, info) {
        environment.suspended_at_unix_ms = info.suspended_at_unix_ms;
        environment.suspend_reason = if info.suspended_at_unix_ms > 0 {
            info.suspend_reason.clone()
        } else {
            String::new()
        };
        environment.last_wake_duration_ms = info.last_wake_duration_ms;
    }
}

/// The egress `info` reports for a running `environment`: only from the same
/// environment's runner, at the same generation, while both say running.
fn reported_egress(
    environment: &v1::Environment,
    info: &v1::RunnerInfo,
) -> Option<v1::EgressUnavailable> {
    reports_running(environment, info)
        .then_some(info.egress_unavailable)
        .flatten()
}

/// The interception `info` reports for a running `environment`: only from
/// its own runner, at the same generation, while both say running (#4912,
/// #5216).
fn reported_interception(
    environment: &v1::Environment,
    info: &v1::RunnerInfo,
) -> Option<v1::Interception> {
    reports_running(environment, info)
        .then_some(info.interception)
        .flatten()
}

/// Whether `info` is the running `environment`'s own runner, at the same
/// generation, while both say running.
fn reports_running(environment: &v1::Environment, info: &v1::RunnerInfo) -> bool {
    let running = v1::EnvironmentState::Running as i32;
    info.environment_id == environment.id
        && info.generation == environment.generation
        && info.state == running
        && environment.state == running
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
                signal: None,
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
                signal: None,
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

    /// A running VM's runner reporting unavailable egress is shown only for
    /// the same environment, at the same generation, while both say running
    /// (#4965).
    #[test]
    fn unavailable_egress_is_shown_only_for_the_same_running_environment() {
        let running = v1::EnvironmentState::Running as i32;
        let egress = v1::EgressUnavailable {
            late_answers: 4,
            since_unix_ms: 1_700_000_000_000,
        };
        let environment = v1::Environment {
            id: "0d8f6f28-5d3c-4f86-a5b1-6a2f6d0b7f3e".to_owned(),
            state: running,
            generation: 3,
            ..Default::default()
        };
        let info = v1::RunnerInfo {
            environment_id: environment.id.clone(),
            state: running,
            generation: 3,
            egress_unavailable: Some(egress),
            ..Default::default()
        };
        assert_eq!(reported_egress(&environment, &info), Some(egress));
        for other in [
            v1::RunnerInfo {
                environment_id: "6c1a1c55-5d0b-4f7e-9d38-0c8d9c2f4a11".to_owned(),
                ..info.clone()
            },
            v1::RunnerInfo {
                generation: 2,
                ..info.clone()
            },
            v1::RunnerInfo {
                state: v1::EnvironmentState::Stopped as i32,
                ..info.clone()
            },
            v1::RunnerInfo {
                egress_unavailable: None,
                ..info.clone()
            },
        ] {
            assert_eq!(reported_egress(&environment, &other), None, "{other:?}");
        }
    }

    /// A running VM's runner reporting its interception lost is shown only
    /// for the same environment, at the same generation, while both say
    /// running (#5216).
    #[test]
    fn lost_interception_is_shown_only_for_the_same_running_environment() {
        let running = v1::EnvironmentState::Running as i32;
        let lost = v1::Interception {
            state: v1::InterceptionState::Lost as i32,
            reason: v1::InterceptionReason::Unspecified as i32,
        };
        let environment = v1::Environment {
            id: "0d8f6f28-5d3c-4f86-a5b1-6a2f6d0b7f3e".to_owned(),
            state: running,
            generation: 3,
            ..Default::default()
        };
        let info = v1::RunnerInfo {
            environment_id: environment.id.clone(),
            state: running,
            generation: 3,
            interception: Some(lost),
            ..Default::default()
        };
        assert_eq!(reported_interception(&environment, &info), Some(lost));
        for other in [
            v1::RunnerInfo {
                environment_id: "6c1a1c55-5d0b-4f7e-9d38-0c8d9c2f4a11".to_owned(),
                ..info.clone()
            },
            v1::RunnerInfo {
                generation: 2,
                ..info.clone()
            },
            v1::RunnerInfo {
                state: v1::EnvironmentState::Stopped as i32,
                ..info.clone()
            },
            v1::RunnerInfo {
                interception: None,
                ..info.clone()
            },
        ] {
            assert_eq!(
                reported_interception(&environment, &other),
                None,
                "{other:?}"
            );
        }
    }

    #[test]
    fn suspend_state_and_wake_duration_apply_only_to_matching_running_vm() {
        let running = v1::EnvironmentState::Running as i32;
        let mut environment = v1::Environment {
            id: "0d8f6f28-5d3c-4f86-a5b1-6a2f6d0b7f3e".to_owned(),
            state: running,
            generation: 4,
            ..Default::default()
        };
        let info = v1::RunnerInfo {
            environment_id: environment.id.clone(),
            state: running,
            generation: 4,
            suspended_at_unix_ms: 1_764_300_000_000,
            suspend_reason: "user".to_owned(),
            last_wake_duration_ms: 42,
            ..Default::default()
        };
        apply_runner_info(&mut environment, &info);
        assert_eq!(environment.suspended_at_unix_ms, 1_764_300_000_000);
        assert_eq!(environment.suspend_reason, "user");
        assert_eq!(environment.last_wake_duration_ms, 42);

        let mut stale = v1::Environment {
            id: environment.id.clone(),
            state: running,
            generation: 5,
            ..Default::default()
        };
        apply_runner_info(&mut stale, &info);
        assert_eq!(stale.suspended_at_unix_ms, 0);
        assert!(stale.suspend_reason.is_empty());
        assert_eq!(stale.last_wake_duration_ms, 0);
    }
}
