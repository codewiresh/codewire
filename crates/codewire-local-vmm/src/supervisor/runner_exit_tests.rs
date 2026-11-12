use super::tests::{project_environment, test_supervisor_core};
use super::*;

fn running_with_a_runner(core: &mut SupervisorCore) -> Uuid {
    let environment = core.environment_mut("dev").unwrap();
    let artifact_generation = environment
        .active_artifact_generation
        .clone()
        .unwrap_or_else(|| "a".repeat(64));
    environment.state = StoredEnvironmentState::Running;
    environment.runner = Some(RunnerRecord {
        cw_runtime_catalog_generation: None,
        process: ProcessIdentity {
            pid: 42,
            boot_id: "boot".to_owned(),
            start_time_ticks: 7,
            executable: PathBuf::from("/proc/self/exe"),
            executable_file: crate::host::path::FileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                uid: 4,
                mode: 0o100500,
                links: 1,
                pin: Default::default(),
            },
            executable_sha256: "f".repeat(64),
        },
        socket: SocketIdentity {
            device: 1,
            inode: 2,
            uid: 4,
            mode: 0o140600,
            pin: Default::default(),
        },
        artifact_generation,
        error_code: None,
    });
    let id = environment.id;
    core.save().unwrap();
    id
}

fn shown_error_code(core: &SupervisorCore) -> String {
    core.environment_proto("dev").unwrap().error_code
}

fn operation(core: &SupervisorCore, id: Uuid, kind: OperationKind) -> OperationRecord {
    core.store
        .begin_operation(
            Uuid::new_v4(),
            Some(id),
            kind,
            &serde_json::json!({"name": "dev"}),
        )
        .unwrap()
}

#[test]
fn runner_death_says_runner_exit_until_the_environment_leaves_error() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let id = running_with_a_runner(&mut core);
    core.mark_runner_dead("dev").unwrap();
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert!(environment.runner.is_none());
    assert_eq!(shown_error_code(&core), RUNNER_EXIT_ERROR_CODE);

    // Operations recorded while it stays in Error do not replace why it
    // failed: a failed stop, and another observation of Error.
    let stop = operation(&core, id, OperationKind::Stop);
    core.fail_operation(&stop, "stop_failed").unwrap();
    let generation = core.environment("dev").unwrap().generation;
    core.record_reconcile_observation(
        "dev",
        StoredEnvironmentState::Error,
        generation + 1,
        true,
        None,
    )
    .unwrap();
    assert_eq!(shown_error_code(&core), RUNNER_EXIT_ERROR_CODE);

    // Once it has run again, a later failure that records no reconcile
    // never shows the old code.
    core.record_reconcile_observation(
        "dev",
        StoredEnvironmentState::Running,
        generation + 1,
        false,
        None,
    )
    .unwrap();
    assert_eq!(shown_error_code(&core), "");
    let start = operation(&core, id, OperationKind::Start);
    core.fail_operation_with_environment_error(&start, "dev", "start_interrupted")
        .unwrap();
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Error
    );
    assert_eq!(shown_error_code(&core), "start_interrupted");
}

#[test]
fn a_failed_operation_into_error_says_its_own_code() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let id = core.environment("dev").unwrap().id;
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
    core.save().unwrap();
    let start = operation(&core, id, OperationKind::Start);
    let failed = core
        .fail_operation_with_environment_error(&start, "dev", "start_interrupted")
        .unwrap();
    assert_eq!(failed.phase, OperationPhase::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("start_interrupted"));
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Error
    );
    assert_eq!(shown_error_code(&core), "start_interrupted");

    // A failure that leaves the state alone does not replace it, nor does
    // another failure into Error while it is still there.
    let stop = operation(&core, id, OperationKind::Stop);
    core.fail_operation(&stop, "stop_failed").unwrap();
    let restart = operation(&core, id, OperationKind::Restart);
    core.fail_operation_with_environment_error(&restart, "dev", "restart_interrupted")
        .unwrap();
    assert_eq!(shown_error_code(&core), "start_interrupted");
}

#[test]
fn a_failed_operation_with_a_live_runner_records_the_code_on_it() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let id = running_with_a_runner(&mut core);
    let start = operation(&core, id, OperationKind::Restart);
    core.fail_operation_with_environment_error(&start, "dev", "restart_interrupted")
        .unwrap();
    let environment = core.environment("dev").unwrap();
    assert_eq!(environment.state, StoredEnvironmentState::Error);
    assert_eq!(
        environment
            .runner
            .as_ref()
            .and_then(|runner| runner.error_code.as_deref()),
        Some("restart_interrupted")
    );
    assert_eq!(shown_error_code(&core), "restart_interrupted");
}

#[test]
fn a_failed_operation_shows_its_code_until_one_succeeds() {
    // Either the operation records the move into Error, or the runner
    // reported its start failure first and moved it there unrecorded.
    for runner_reported_first in [false, true] {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let id = running_with_a_runner(&mut core);
        if runner_reported_first {
            core.record_runner_start_failure("dev", "network_worker_start_timeout")
                .unwrap();
        }
        let update = operation(&core, id, OperationKind::UpdateEnvironmentSources);
        core.fail_operation_with_environment_error(
            &update,
            "dev",
            "environment_sources_network_worker_start_timeout",
        )
        .unwrap();

        // The runner then reports the VM stopped with no code of its own,
        // and later goes away: the environment is stopped and retryable,
        // and still says why the update failed (#2626).
        let generation = core.environment("dev").unwrap().generation;
        core.record_reconcile_observation(
            "dev",
            StoredEnvironmentState::Stopped,
            generation,
            false,
            None,
        )
        .unwrap();
        core.record_reconcile_observation(
            "dev",
            StoredEnvironmentState::Stopped,
            generation,
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Stopped
        );
        assert_eq!(
            shown_error_code(&core),
            "environment_sources_network_worker_start_timeout",
            "runner reported first: {runner_reported_first}"
        );

        // A retry that succeeds clears it.
        let retry = operation(&core, id, OperationKind::UpdateEnvironmentSources);
        let result = environment_operation_result(core.environment("dev").unwrap());
        core.store
            .advance_operation(
                retry.operation_id,
                retry.checkpoint,
                OperationPhase::Completed,
                Some(&result),
                None,
            )
            .unwrap();
        assert_eq!(shown_error_code(&core), "");
    }
}

#[test]
fn a_runner_with_its_own_code_keeps_it() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    running_with_a_runner(&mut core);
    let generation = core.environment("dev").unwrap().generation;
    core.record_reconcile_observation(
        "dev",
        StoredEnvironmentState::Error,
        generation,
        false,
        Some("vmm_exit"),
    )
    .unwrap();
    assert_eq!(shown_error_code(&core), "vmm_exit");
}

#[test]
fn a_cleared_runner_carries_a_code_only_into_error() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let id = running_with_a_runner(&mut core);
    let environment = core.environment("dev").unwrap().clone();
    let validate = |state: StoredEnvironmentState, code: Option<&str>| {
        let payload = reconcile_operation_payload(&environment, state, 1, true, code);
        let operation = core
            .store
            .begin_operation(Uuid::new_v4(), Some(id), OperationKind::Reconcile, &payload)
            .unwrap();
        reconcile_operation_parameters(&operation).is_ok()
    };
    // Written before #2568: a cleared runner and no code.
    assert!(validate(StoredEnvironmentState::Error, None));
    assert!(validate(StoredEnvironmentState::Stopped, None));
    assert!(validate(
        StoredEnvironmentState::Error,
        Some(RUNNER_EXIT_ERROR_CODE)
    ));
    assert!(!validate(
        StoredEnvironmentState::Stopped,
        Some(RUNNER_EXIT_ERROR_CODE)
    ));
    assert!(!validate(
        StoredEnvironmentState::Running,
        Some(RUNNER_EXIT_ERROR_CODE)
    ));
}
