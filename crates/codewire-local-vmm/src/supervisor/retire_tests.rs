use super::tests::{
    attach_named_test_runner_process, project_environment, test_supervisor, test_supervisor_core,
    test_supervisor_service,
};
use super::*;

fn with_runner(core: &mut SupervisorCore, state: StoredEnvironmentState) {
    let environment = core.environment_mut("dev").unwrap();
    environment.state = state;
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
        artifact_generation: "a".repeat(64),
        error_code: Some(RUNNER_EXIT_ERROR_CODE.to_owned()),
    });
}

async fn retire(service: &SupervisorRpc, successor: u32) -> Result<(), Status> {
    service
        .retire_supervisor(Request::new(v1::RetireSupervisorRequest {
            successor_protocol: successor,
        }))
        .await
        .map(drop)
}

#[test]
fn only_a_stopped_environment_or_one_whose_runner_is_gone_has_no_vm() {
    let mut environment = project_environment();
    for (state, may_run) in [
        (StoredEnvironmentState::Stopped, false),
        (StoredEnvironmentState::Error, false),
        (StoredEnvironmentState::Starting, true),
        (StoredEnvironmentState::Running, true),
        (StoredEnvironmentState::Orphaned, cfg!(target_os = "macos")),
    ] {
        environment.state = state;
        assert_eq!(may_run_a_vm(&environment), may_run, "{state:?}");
    }
}

/// #3793: a supervisor that holds nothing exits once no client has been
/// connected for [`IDLE_RUNNER_WINDOW`]; an environment it holds keeps it,
/// and a connection or held work starts the window again. Time is tokio's
/// paused clock: nothing sleeps.
#[tokio::test(start_paused = true)]
async fn a_supervisor_holding_nothing_exits_after_an_idle_window() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let supervisor = test_supervisor(core);
    let connections = crate::uds::Connections::new();
    let mut quiet_since = None;
    let due = |quiet_since: &mut Option<tokio::time::Instant>| {
        supervisor.idle_exit_due(quiet_since, &connections, tokio::time::Instant::now())
    };

    tokio::time::advance(IDLE_RUNNER_WINDOW * 2).await;
    assert!(
        !due(&mut quiet_since),
        "an environment keeps its supervisor"
    );

    supervisor.core().state.environments.clear();
    assert!(!due(&mut quiet_since));
    tokio::time::advance(IDLE_RUNNER_WINDOW - Duration::from_secs(1)).await;
    assert!(!due(&mut quiet_since));

    // A client connects: the window starts again when it leaves.
    let open = connections.opened();
    tokio::time::advance(IDLE_RUNNER_WINDOW).await;
    assert!(!due(&mut quiet_since), "a connected client keeps it");
    drop(open);
    tokio::time::advance(IDLE_RUNNER_WINDOW - Duration::from_secs(1)).await;
    assert!(!due(&mut quiet_since));

    // Held work also starts the window again.
    supervisor.core().content_writers += 1;
    assert!(!due(&mut quiet_since));
    supervisor.core().content_writers -= 1;
    // The window counts from the first sweep that finds nothing held.
    assert!(!due(&mut quiet_since));
    tokio::time::advance(IDLE_RUNNER_WINDOW - Duration::from_secs(1)).await;
    assert!(!due(&mut quiet_since));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(due(&mut quiet_since), "a whole quiet window ends it");
}

/// #3270: a stopped environment's runner stays for [`IDLE_RUNNER_WINDOW`]
/// so a restart can reuse it, then the reaper retires it, process and
/// record. Time is tokio's paused clock: nothing sleeps.
#[tokio::test(start_paused = true)]
async fn an_idle_runner_stays_for_its_window_then_is_retired() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    // This supervisor's own runner, not another cw's, which reconcile ends
    // at once.
    core.config.executable = fs::canonicalize("/bin/sleep").unwrap();
    let socket = SocketIdentity {
        device: 1,
        inode: 2,
        uid: 4,
        mode: 0o140600,
        pin: Default::default(),
    };
    let (environment_id, process) = attach_named_test_runner_process(&mut core, "dev", socket);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    core.save().unwrap();
    let supervisor = test_supervisor(core);

    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    tokio::time::advance(IDLE_RUNNER_WINDOW - Duration::from_secs(1)).await;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    supervisor.retire_expired_idle_runner("dev").await.unwrap();
    assert_eq!(
        supervisor
            .environment("dev")
            .unwrap()
            .runner
            .as_ref()
            .map(|runner| &runner.process),
        Some(&process),
        "a start within the window reuses the runner"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        supervisor.expired_idle_runners(tokio::time::Instant::now()),
        ["dev"]
    );
    supervisor.retire_expired_idle_runner("dev").await.unwrap();
    let environment = supervisor.environment("dev").unwrap();
    assert!(environment.runner.is_none());
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert!(!supervisor.core().live_runners.contains_key(&environment_id));
    assert!(!supervisor.core().idle_runners.contains_key(&environment_id));
    assert!(
        rustix::process::test_kill_process(
            rustix::process::Pid::from_raw(process.pid as i32).unwrap()
        )
        .is_err(),
        "the idle runner {} still runs",
        process.pid
    );
}

/// #3270: a runner that is not idle, or whose environment started again,
/// starts no window; a restart's new runner starts its own.
#[tokio::test(start_paused = true)]
async fn only_a_stopped_environment_runner_counts_as_idle() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    core.config.executable = fs::canonicalize("/bin/sleep").unwrap();
    let socket = SocketIdentity {
        device: 1,
        inode: 2,
        uid: 4,
        mode: 0o140600,
        pin: Default::default(),
    };
    let (environment_id, _process) = attach_named_test_runner_process(&mut core, "dev", socket);
    let supervisor = test_supervisor(core);
    // Running: never idle, however long.
    tokio::time::advance(IDLE_RUNNER_WINDOW * 2).await;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    assert!(!supervisor.core().idle_runners.contains_key(&environment_id));
    // Stopped: the window starts now, not when the runner started.
    supervisor.core().environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    // Started again within it: the window is forgotten.
    tokio::time::advance(IDLE_RUNNER_WINDOW / 2).await;
    supervisor.core().environment_mut("dev").unwrap().state = StoredEnvironmentState::Running;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    assert!(!supervisor.core().idle_runners.contains_key(&environment_id));
    // Stopped once more: a full window again.
    supervisor.core().environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    tokio::time::advance(IDLE_RUNNER_WINDOW / 2).await;
    assert!(
        supervisor
            .expired_idle_runners(tokio::time::Instant::now())
            .is_empty()
    );
    tokio::time::advance(IDLE_RUNNER_WINDOW / 2).await;
    assert_eq!(
        supervisor.expired_idle_runners(tokio::time::Instant::now()),
        ["dev"]
    );
}

#[tokio::test]
async fn a_retiring_supervisor_ends_its_idle_runners_first() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let socket = SocketIdentity {
        device: 1,
        inode: 2,
        uid: 4,
        mode: 0o140600,
        pin: Default::default(),
    };
    let (environment_id, process) = attach_named_test_runner_process(&mut core, "dev", socket);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    core.save().unwrap();
    let service = test_supervisor_service(core);
    retire(&service, NATIVE_SUPERVISOR_PROTOCOL_VERSION)
        .await
        .unwrap();
    let core = &service.supervisor;
    let environment = core.environment("dev").unwrap();
    assert!(environment.runner.is_none());
    assert_eq!(environment.state, StoredEnvironmentState::Stopped);
    assert!(!core.core().live_runners.contains_key(&environment_id));
    assert!(
        rustix::process::test_kill_process(
            rustix::process::Pid::from_raw(process.pid as i32).unwrap()
        )
        .is_err(),
        "the idle runner {} still runs",
        process.pid
    );
}

#[tokio::test]
async fn a_supervisor_retires_only_for_its_protocol_or_newer_and_with_no_vm() {
    let ours = NATIVE_SUPERVISOR_PROTOCOL_VERSION;
    for state in [
        StoredEnvironmentState::Running,
        StoredEnvironmentState::Starting,
        // A failure its runner reports keeps the VM (runner_service).
        StoredEnvironmentState::Error,
        #[cfg(target_os = "macos")]
        StoredEnvironmentState::Orphaned,
    ] {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        with_runner(&mut core, state);
        let service = test_supervisor_service(core);
        let shutdown = service.supervisor.shutdown.subscribe();
        let refused = retire(&service, ours + 1).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition, "{state:?}");
        assert!(
            refused.message().contains("\"dev\" may still run a VM"),
            "{refused:?}"
        );
        assert!(!*shutdown.borrow(), "{state:?}");
        assert!(!service.supervisor.core().retiring, "{state:?}");
    }

    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    let shutdown = service.supervisor.shutdown.subscribe();
    assert_eq!(
        retire(&service, ours - 1).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    assert!(!*shutdown.borrow());
    retire(&service, ours).await.unwrap();
    assert!(*shutdown.borrow());
    // Every later request is refused while it exits.
    let listed = service
        .list_environments(Request::new(v1::ListEnvironmentsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(listed.code(), tonic::Code::Unavailable);
    let started = service
        .start_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: Uuid::new_v4().to_string(),
            environment_id: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(started.code(), tonic::Code::Unavailable);
}
