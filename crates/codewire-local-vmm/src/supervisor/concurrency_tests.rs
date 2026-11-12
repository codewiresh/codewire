use std::time::Duration;

use tokio::time::timeout;

use super::tests::{
    RunnerInfoGate, TestRunnerProtocolReply, attach_named_test_runner_process,
    begin_and_advance_test_operation, project_environment, project_environment_with_access,
    spawn_gated_test_runner_server, test_supervisor_core, test_supervisor_service,
};
use super::*;

/// Bounds a wait that its own event ends: a read's answer, an admitted
/// mutation, a refusal, a writer let in, a shutdown signalled. Each
/// test holds what it must not wait for (a stuck create's gate, a lease)
/// for as long as it waits, so a request that blocked on it would never
/// answer. The bound only turns that hang into a failure; 2 s failed on
/// a loaded CI slot (#3325).
const HANG_GUARD: Duration = Duration::from_secs(120);

/// A test's own setup steps, on a loaded host: never the bound of the
/// behaviour under test.
const SETUP: Duration = Duration::from_secs(60);

/// A create of `name` journaled up to its runner, with a recorded runner
/// whose info call waits at the returned gate: drained, the create is
/// stuck in its runner across an await, as one whose runner will not
/// answer is.
fn stuck_create(
    core: &mut SupervisorCore,
    name: &str,
) -> (
    OperationRecord,
    RunnerInfoGate,
    tokio::sync::oneshot::Sender<()>,
) {
    let mut environment = project_environment_with_access();
    environment.id = Uuid::new_v4();
    environment.name = name.to_owned();
    if let Some(binding) = environment.access_binding.as_mut() {
        binding.environment_id = access_environment_id(environment.id).unwrap();
    }
    // Its workspace generation was staged before its runner.
    environment.active_workspace_generation =
        Some(super::tests::test_workspace_generation_with_artifact(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            environment.active_artifact_generation.as_deref().unwrap(),
            name.as_bytes(),
        ));
    let environment_id = environment.id;
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: name.to_owned(),
        source_path: "/workspace/source".to_owned(),
        vcpus: u32::from(environment.vcpus),
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
        docker_disk_bytes: environment.docker_disk_bytes,
        request_id: Uuid::new_v4().to_string(),
        project_spec_json: environment.project_spec_json.clone().unwrap(),
        project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
        implicit_path_mode: "clone".to_owned(),
        local_mounts: Vec::new(),
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        access_profile_revision: 7,
        access_profile_reference: "user/work".to_owned(),
        platform_source_authority: None,
    };
    let payload = create_operation_payload(&request, &environment.workspace_plan).unwrap();
    core.state.environments.insert(name.to_owned(), environment);
    core.save().unwrap();
    let gate = RunnerInfoGate::default();
    let (socket, _calls, stop_runner, _server) = spawn_gated_test_runner_server(
        &core.config.runner_socket(environment_id),
        TestRunnerProtocolReply::Version(10),
        Some(gate.clone()),
    );
    attach_named_test_runner_process(core, name, socket);
    core.environment_mut(name).unwrap().state = StoredEnvironmentState::Starting;
    core.save().unwrap();
    let checkpoint = crate::lifecycle::effects(OperationKind::Create)
        .iter()
        .position(|effect| *effect == LifecycleEffect::EnsureRunner)
        .unwrap();
    let create = begin_and_advance_test_operation(
        &core.store,
        environment_id,
        OperationKind::Create,
        &payload,
        u32::try_from(checkpoint).unwrap(),
    );
    (create, gate, stop_runner)
}

/// End a stuck create's runner process, which outlives the test.
fn end_runner(service: &SupervisorRpc, name: &str) {
    let id = service.supervisor.environment(name).unwrap().id;
    let runner = service.supervisor.core().children.remove(&id);
    if let Some(mut runner) = runner {
        let _ = runner.kill();
        let _ = runner.wait();
    }
}

/// Stopped environments "dev" and "other".
fn two_environments() -> (tempfile::TempDir, SupervisorRpc) {
    let (parent, mut core) = test_supervisor_core(project_environment());
    let mut other = project_environment();
    other.id = Uuid::new_v4();
    other.name = "other".to_owned();
    let mut next_state = core.state.clone();
    next_state.environments.insert("other".to_owned(), other);
    core.state = next_state;
    core.save().unwrap();
    (parent, test_supervisor_service(core))
}

fn selector(service: &SupervisorRpc, name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
        request_id: Uuid::new_v4().to_string(),
        environment_id: service.supervisor.environment(name).unwrap().id.to_string(),
    }
}

async fn finished(
    service: &SupervisorRpc,
    operation: &v1::Operation,
    within: Duration,
) -> OperationRecord {
    let id = Uuid::parse_str(&operation.operation_id).unwrap();
    timeout(within, async {
        loop {
            let operation = service.operation(id).await.unwrap();
            if operation.phase.terminal() {
                return operation;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the operation runs to its end")
}

/// The issue's done-when: a create stuck in its runner holds only its
/// own environment. Meanwhile `cw ls`, `cw info` of it and of another,
/// `cw select`, daemon access and another environment's stop all answer;
/// only a mutation of its own environment waits for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_create_blocks_neither_reads_nor_another_environment() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let (create, gate, _stop_runner) = stuck_create(&mut core, "new");
    let service = test_supervisor_service(core);
    // As `cw create` admits it here.
    service.supervisor.admit(&create);
    service.spawn_drain("new");
    timeout(SETUP, gate.entered.notified())
        .await
        .expect("the create reaches its runner");

    let listed = timeout(
        HANG_GUARD,
        service.list_environments(Request::new(v1::ListEnvironmentsRequest::default())),
    )
    .await
    .expect("ls answers")
    .unwrap()
    .into_inner();
    assert_eq!(listed.environments.len(), 2);
    let new = timeout(
        HANG_GUARD,
        service.get_environment(Request::new(selector(&service, "new"))),
    )
    .await
    .expect("info on the stuck environment answers with its recorded state")
    .unwrap()
    .into_inner();
    assert_eq!(new.state, v1::EnvironmentState::Starting as i32);
    timeout(
        HANG_GUARD,
        service.get_environment(Request::new(selector(&service, "dev"))),
    )
    .await
    .expect("info on another environment answers")
    .unwrap();
    timeout(
        HANG_GUARD,
        service.select_environment(Request::new(selector(&service, "dev"))),
    )
    .await
    .expect("select of another environment answers")
    .unwrap();
    // "dev" runs no VM, so its daemon access is refused, but at once.
    timeout(
        HANG_GUARD,
        service.get_daemon_access(Request::new(read_selector("dev"))),
    )
    .await
    .expect("daemon access of another environment answers")
    .unwrap_err();
    let dev_id = service.supervisor.environment("dev").unwrap().id;
    timeout(HANG_GUARD, service.environment_daemon_access(dev_id))
        .await
        .expect("public daemon access of another environment answers")
        .unwrap_err();
    let stop = timeout(
        HANG_GUARD,
        service.stop_environment(Request::new(selector(&service, "dev"))),
    )
    .await
    .expect("another environment's mutation is admitted")
    .unwrap()
    .into_inner();
    assert_eq!(
        finished(&service, &stop, HANG_GUARD).await.phase,
        OperationPhase::Completed
    );

    let waiting = tokio::spawn({
        let service = service.clone();
        let request = selector(&service, "new");
        async move { service.stop_environment(Request::new(request)).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "its own mutation waits for it");
    assert!(
        !service
            .operation(create.operation_id)
            .await
            .unwrap()
            .phase
            .terminal(),
        "the create is still stuck"
    );
    waiting.abort();
    end_runner(&service, "new");
}

/// A request dropped while its drain runs an operation, as when its
/// client goes away mid-wait, cuts that operation short nowhere: the
/// drain finishes it and forgets its admission (#2978).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_dropped_during_its_drain_leaves_the_operation_running() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let (create, gate, _stop_runner) = stuck_create(&mut core, "new");
    let service = test_supervisor_service(core);
    // Only the request's own drain runs it, as one admitted here.
    service
        .hold_drains
        .store(true, std::sync::atomic::Ordering::Release);
    service.supervisor.admit(&create);
    let request = tokio::spawn({
        let service = service.clone();
        let request = read_selector("new");
        async move { service.get_daemon_access(Request::new(request)).await }
    });
    timeout(SETUP, gate.entered.notified())
        .await
        .expect("the request's drain reaches the create's runner");
    assert!(
        !service
            .operation(create.operation_id)
            .await
            .unwrap()
            .phase
            .terminal()
    );
    request.abort();
    let _ = request.await;
    gate.release.notify_one();
    // Its runner then fails it, but it runs to its end.
    assert_eq!(
        finished(&service, &operation_proto(&create).unwrap(), SETUP)
            .await
            .phase,
        OperationPhase::Failed
    );
    // Its drain, rollback included, ends and lets go of the name.
    drop(
        timeout(SETUP, service.supervisor.lease("new").lock_owned())
            .await
            .expect("the drain ends"),
    );
    assert!(
        !service
            .supervisor
            .core()
            .admitted_here
            .contains_key(&create.operation_id)
    );
    end_runner(&service, "new");
}

/// A caller dropped during a collection, as a request's client going
/// away drops it, never leaves it running for good: a writer waits only
/// until the walk ends (#2978).
#[tokio::test]
async fn a_collection_its_caller_dropped_still_ends_and_lets_writers_in() {
    let (_parent, service) = two_environments();
    let supervisor = &service.supervisor;
    {
        let mut collection = std::pin::pin!(supervisor.collect_if_idle());
        assert!(futures::poll!(collection.as_mut()).is_pending());
    }
    assert!(supervisor.core().collecting, "dropped mid-collection");
    let mut writer = std::pin::pin!(supervisor.content_writer());
    assert!(
        futures::poll!(writer.as_mut()).is_pending(),
        "a writer waits while a collection runs"
    );
    let _writer = timeout(HANG_GUARD, writer)
        .await
        .expect("the collection ends without its caller");
    let core = supervisor.core();
    assert!(!core.collecting);
    assert_eq!(core.content_writers, 1);
}

/// A retire dropped after it set `retiring` still hands over, or keeps
/// serving; it never leaves the supervisor retiring for good (#2978).
#[tokio::test]
async fn a_retire_its_caller_dropped_still_hands_over() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let socket = SocketIdentity {
        device: 1,
        inode: 2,
        uid: 4,
        mode: 0o140600,
        pin: Default::default(),
    };
    attach_named_test_runner_process(&mut core, "dev", socket);
    core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Stopped;
    core.save().unwrap();
    let service = test_supervisor_service(core);
    let mut shutdown = service.supervisor.shutdown.subscribe();
    {
        let mut retire = std::pin::pin!(service.retire_supervisor(Request::new(
            v1::RetireSupervisorRequest {
                successor_protocol: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
            }
        )));
        // It reaches the idle runner it ends before handing over.
        assert!(futures::poll!(retire.as_mut()).is_pending());
        assert!(service.supervisor.core().retiring);
    }
    timeout(HANG_GUARD, shutdown.wait_for(|stopping| *stopping))
        .await
        .expect("the retirement completes without its caller")
        .unwrap();
    assert!(
        service
            .supervisor
            .environment("dev")
            .unwrap()
            .runner
            .is_none()
    );
}

#[tokio::test]
async fn retire_refuses_at_once_while_an_environment_is_busy() {
    let (_parent, service) = two_environments();
    // A recorded environment's, and a create's whose name has no record
    // yet.
    for name in ["other", "new"] {
        let held = service.supervisor.lease(name).lock_owned().await;
        let refused = timeout(
            HANG_GUARD,
            service.retire_supervisor(Request::new(v1::RetireSupervisorRequest {
                successor_protocol: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
            })),
        )
        .await
        .expect("retire never waits")
        .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains(name), "{refused:?}");
        assert!(!service.supervisor.core().retiring);
        drop(held);
    }
    let held = service.supervisor.lease("other").lock_owned().await;
    timeout(
        HANG_GUARD,
        service.list_environments(Request::new(v1::ListEnvironmentsRequest::default())),
    )
    .await
    .expect("ls keeps answering")
    .unwrap();
    drop(held);
}

#[tokio::test]
async fn a_read_skips_an_environment_a_delete_removed() {
    let (_parent, service) = two_environments();
    service
        .supervisor
        .reconcile_if_idle("removed")
        .await
        .unwrap();
}

#[test]
fn workspace_staging_is_checked_for_the_drained_name_only() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let mut other = project_environment();
    other.id = Uuid::new_v4();
    other.name = "other".to_owned();
    let generation = super::tests::test_workspace_generation_with_artifact(
        other.project_spec_json.as_deref().unwrap(),
        other.project_spec_sha256.as_deref().unwrap(),
        "a".repeat(64).as_str(),
        b"other",
    );
    other.active_workspace_generation = Some(generation.clone());
    other.staging_workspace_generation = Some(generation);
    core.state.environments.insert("other".to_owned(), other);
    // "other" is mid-update; "dev"'s drain ending must not trip on it.
    core.ensure_no_unowned_workspace_staging("dev").unwrap();
    assert!(core.ensure_no_unowned_workspace_staging("other").is_err());
}

/// `cw select` of the VM selected already, during a create admitted
/// here, stands: the create no longer selects itself (#2978).
#[tokio::test]
async fn a_select_of_the_selected_vm_during_a_create_stands() {
    let (_parent, service) = two_environments();
    service
        .hold_drains
        .store(true, std::sync::atomic::Ordering::Release);
    let create = service
        .supervisor
        .core()
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            OperationKind::Create,
            &serde_json::json!({ "name": "new" }),
        )
        .unwrap();
    service.supervisor.admit(&create);
    let selects_itself = || {
        let core = service.supervisor.core();
        create_selects_itself(
            core.admitted_here.get(&create.operation_id).copied(),
            core.selections,
        )
    };
    assert!(selects_itself());
    assert_eq!(
        service.supervisor.core().state.current.as_deref(),
        Some("dev")
    );
    service
        .select_environment(Request::new(selector(&service, "dev")))
        .await
        .unwrap();
    assert!(!selects_itself());
}

/// After a fatal error, such as a panic under the state lock, nothing
/// more is written and no drain runs another operation (#2978).
#[tokio::test]
async fn a_fatal_error_stops_every_later_commit_and_drain() {
    let (_parent, service) = two_environments();
    let supervisor = &service.supervisor;
    let shutdown = supervisor.shutdown.subscribe();
    let panicked = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _core = supervisor.core.lock().unwrap();
                panic!("a synthetic panic under the state lock");
            })
            .join()
    });
    assert!(panicked.is_err());
    assert!(matches!(
        supervisor.core().save(),
        Err(SupervisorError::Store(SupervisorStoreError::Stopping))
    ));
    assert!(*shutdown.borrow());
    assert!(matches!(
        supervisor.drain("dev").await,
        Err(SupervisorError::Store(SupervisorStoreError::Stopping))
    ));
}

/// A pull keeps the cached layers of names with an environment or a
/// pending create, and its own; another failed create's go (#2978).
#[test]
fn a_pull_frees_the_layers_of_names_with_no_environment_or_create() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let layer = |seed: &[u8]| {
        (
            Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(seed))).unwrap(),
            1,
        )
    };
    core.store
        .begin_operation(
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            OperationKind::Create,
            &serde_json::json!({ "name": "creating" }),
        )
        .unwrap();
    core.download_cache = BTreeMap::from([
        ("dev".to_owned(), BTreeMap::from([layer(b"dev")])),
        ("creating".to_owned(), BTreeMap::from([layer(b"creating")])),
        ("failed".to_owned(), BTreeMap::from([layer(b"failed")])),
    ]);
    core.cache_download("new", BTreeMap::from([layer(b"new")]))
        .unwrap();
    assert_eq!(
        core.download_cache
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["creating", "dev", "new"]
    );
}

/// While an operation of its own boots the environment, a reconcile
/// that finds its fresh runner `stopped` keeps it `starting`; with no
/// such operation the runner's state stands (#3143).
#[test]
fn a_booting_environment_reads_as_starting_until_its_operation_ends() {
    let mut environment = project_environment();
    environment.state = StoredEnvironmentState::Starting;
    let generation = environment.generation;
    let environment_id = environment.id;
    let (_parent, mut core) = test_supervisor_core(environment);
    let start = core
        .store
        .begin_operation(
            Uuid::new_v4(),
            Some(environment_id),
            OperationKind::Start,
            &serde_json::json!({ "name": "dev" }),
        )
        .unwrap();
    core.record_reconcile_observation(
        "dev",
        StoredEnvironmentState::Stopped,
        generation,
        false,
        None,
    )
    .unwrap();
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Starting
    );
    core.fail_operation(&start, "start_failed").unwrap();
    core.record_reconcile_observation(
        "dev",
        StoredEnvironmentState::Stopped,
        generation,
        false,
        None,
    )
    .unwrap();
    assert_eq!(
        core.environment("dev").unwrap().state,
        StoredEnvironmentState::Stopped
    );
}

/// A fatal error in a drain a request waits on stops the supervisor, as
/// one in a spawned drain does (#3143).
#[tokio::test]
async fn a_fatal_error_in_a_request_drain_stops_the_supervisor() {
    let (_parent, service) = two_environments();
    let shutdown = service.supervisor.shutdown.subscribe();
    {
        // "other" mid-update with no operation of its own: its drain
        // ends on the staging check, a fatal error.
        let mut core = service.supervisor.core();
        let other = core.state.environments.get_mut("other").unwrap();
        let generation = super::tests::test_workspace_generation_with_artifact(
            other.project_spec_json.as_deref().unwrap(),
            other.project_spec_sha256.as_deref().unwrap(),
            "a".repeat(64).as_str(),
            b"other",
        );
        other.active_workspace_generation = Some(generation.clone());
        other.staging_workspace_generation = Some(generation);
    }
    service
        .select_environment(Request::new(selector(&service, "other")))
        .await
        .unwrap_err();
    assert!(service.supervisor.core().store.stopping());
    assert!(*shutdown.borrow());
}

/// A create that passed every earlier check, but reaches its journal
/// write after a retire began, is refused with nothing journaled
/// (#3143).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_reaching_its_journal_after_a_retire_began_is_refused() {
    let (_parent, core) = test_supervisor_core(project_environment());
    let service = test_supervisor_service(core);
    service
        .hold_drains
        .store(true, std::sync::atomic::Ordering::Release);
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("README.md"), b"new").unwrap();
    let environment = project_environment();
    let request_id = Uuid::new_v4();
    let request = v1::CreateEnvironmentRequest {
        snapshot: None,
        network_policy: String::new(),
        implicit_vm_only: Vec::new(),
        name: "new".to_owned(),
        source_path: source.path().to_str().unwrap().to_owned(),
        vcpus: u32::from(environment.vcpus),
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
        docker_disk_bytes: 0,
        request_id: request_id.to_string(),
        project_spec_json: environment.project_spec_json.unwrap(),
        project_spec_sha256: environment.project_spec_sha256.unwrap(),
        implicit_path_mode: "copy".to_owned(),
        local_mounts: Vec::new(),
        host_ports: Vec::new(),
        mesh: None,
        access_profile_id: String::new(),
        access_profile_revision: 0,
        access_profile_reference: String::new(),
        platform_source_authority: None,
    };
    // A running collection holds the create at its content writer, past
    // the request's entry check and its drain.
    service.supervisor.core().collecting = true;
    let create = tokio::spawn({
        let service = service.clone();
        async move { service.create_environment(Request::new(request)).await }
    });
    timeout(SETUP, async {
        while service.supervisor.lease("new").try_lock().is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the create takes its name's lease");
    tokio::time::sleep(Duration::from_millis(200)).await;
    service.supervisor.core().retiring = true;
    service.supervisor.end_collection();
    let refused = timeout(SETUP, create)
        .await
        .expect("the create answers")
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unavailable, "{refused:?}");
    assert!(
        service
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_create_selects_itself_unless_a_select_came_since_admission() {
    // Recovered: no admission here.
    assert!(create_selects_itself(None, 3));
    // Admitted here, and no select since.
    assert!(create_selects_itself(Some(3), 3));
    // Any select since stands, one of the VM selected already included.
    assert!(!create_selects_itself(Some(3), 4));
}
