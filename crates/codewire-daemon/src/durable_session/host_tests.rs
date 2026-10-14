use super::*;

#[cfg(target_os = "linux")]
use crate::host_control::tests as control_fixture;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

#[cfg(target_os = "linux")]
async fn completed_directory_command(engine: &SessionEngine, session: &str) -> v1::SessionRecord {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let record = engine.get(session).await.unwrap();
            if !is_live_state(record.state) {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned directory command completed")
}

#[cfg(target_os = "linux")]
fn retained_directory_metadata(engine: &SessionEngine, session: &str) -> PersistedSession {
    serde_json::from_slice(
        &std::fs::read(engine.inner.root.join(session).join(METADATA_FILE)).unwrap(),
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_directory_default_uses_workspace_and_keeps_generic_home() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let workspace = engine.inner.config.workspace_root.clone();
    let home = engine.inner.config.home_root.clone();
    assert_ne!(workspace, home);
    let launched = owner
        .mutate(control_fixture::launch(
            3,
            &control_fixture::scope(),
            "pwd > member-default-cwd",
        ))
        .await
        .unwrap();
    let controlled = completed_directory_command(&engine, &launched.session_id).await;
    let default_marker = std::fs::read_to_string(workspace.join("member-default-cwd"));
    let generic = engine
        .launch(request("pwd > local-generic-cwd", false))
        .await
        .unwrap();
    let generic = completed_directory_command(&engine, &generic.session_id).await;
    let generic_marker = std::fs::read_to_string(home.join("local-generic-cwd"));
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();

    assert_eq!(controlled.exit_code, Some(0));
    assert_eq!(controlled.working_dir, workspace.to_string_lossy());
    assert_eq!(
        retained_directory_metadata(&engine, &controlled.session_id).working_dir,
        workspace.to_string_lossy()
    );
    assert_eq!(
        default_marker.unwrap(),
        format!("{}\n", workspace.display())
    );
    assert!(!home.join("member-default-cwd").exists());
    assert_eq!(generic.exit_code, Some(0));
    assert_eq!(generic.working_dir, home.to_string_lossy());
    assert_eq!(
        retained_directory_metadata(&engine, &generic.session_id).working_dir,
        home.to_string_lossy()
    );
    assert_eq!(generic_marker.unwrap(), format!("{}\n", home.display()));
    assert!(!workspace.join("local-generic-cwd").exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_directory_explicit_override_is_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let selected = temp.path().join("explicit");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&selected)
        .unwrap();
    let mutation = crate::host_control::Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: uuid::Uuid::from_u128(3).to_string(),
        scope: Some(control_fixture::scope().to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::Launch(
            v1::HostControlLaunch {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "pwd > member-explicit-cwd".into(),
                ],
                working_dir: selected.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )),
    })
    .unwrap();
    let launched = owner.mutate(mutation).await.unwrap();
    let record = completed_directory_command(&engine, &launched.session_id).await;
    let marker = std::fs::read_to_string(selected.join("member-explicit-cwd"));
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();

    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.working_dir, selected.to_string_lossy());
    assert_eq!(
        retained_directory_metadata(&engine, &record.session_id).working_dir,
        selected.to_string_lossy()
    );
    assert_eq!(marker.unwrap(), format!("{}\n", selected.display()));
    for directory in ["home", "workspace"] {
        assert!(
            !temp
                .path()
                .join(directory)
                .join("member-explicit-cwd")
                .exists()
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_directory_missing_workspace_refuses_before_session_publication() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    std::fs::remove_dir(&engine.inner.config.workspace_root).unwrap();
    let launched = owner
        .mutate(control_fixture::launch(
            3,
            &control_fixture::scope(),
            "printf ran > must-not-execute",
        ))
        .await
        .unwrap();
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();

    assert_eq!(launched.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert!(!temp.path().join("home/must-not-execute").exists());
    assert!(
        engine
            .get(&format!("session-{}", uuid::Uuid::from_u128(3)))
            .await
            .is_err()
    );
    assert!(
        !engine
            .inner
            .root
            .join(format!("session-{}", uuid::Uuid::from_u128(3)))
            .exists()
    );
}

#[cfg(target_os = "linux")]
async fn managed_test_owner(root: &Path) -> (crate::host_control::Owner, SessionEngine) {
    let config = control_fixture::config(root);
    let engine = SessionEngine::new(&config, CredentialBridge::new(None));
    let owner = crate::host_control::Owner::new(
        &config,
        crate::host_control::HostControlBinding::new(control_fixture::scope().environment_id)
            .unwrap()
            .with_managed_agents(),
        engine.clone(),
    )
    .await
    .unwrap();
    let mut grant = control_fixture::grant(&control_fixture::scope(), 0);
    grant.grant.as_mut().unwrap().verbs = (1..=11).collect();
    owner.put_grant(grant).await.unwrap();
    (owner, engine)
}

#[cfg(target_os = "linux")]
async fn managed_test_session(
    owner: &crate::host_control::Owner,
    engine: &SessionEngine,
) -> String {
    let request = control_fixture::launch(3, &control_fixture::scope(), "sleep 60");
    let receipt = owner.mutate(request).await.unwrap();
    let handle = engine.handle(&receipt.session_id).unwrap();
    // Only the durable record is shaped as a managed driver. The live child
    // remains synthetic sleep; invalid admissions must never reach the helper.
    let mut metadata = handle.metadata.lock().await;
    let driver = receipt.session_id.strip_prefix("session-").unwrap();
    metadata.command = vec![
        "/retained/cw".into(),
        "_agent-driver".into(),
        "--environment".into(),
        control_fixture::scope().environment_id,
        "--driver-id".into(),
        driver.into(),
        "--registry-root".into(),
        "/private/hosts".into(),
    ];
    receipt.session_id
}

#[cfg(target_os = "linux")]
fn managed_test_message(id: u128, sid: &str, generation: u64) -> crate::host_control::Mutation {
    crate::host_control::Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: uuid::Uuid::from_u128(id).to_string(),
        scope: Some(control_fixture::scope().to_wire()),
        operation: Some(
            v1::host_control_mutation_request::Operation::ManagedControl(
                v1::HostControlManagedControl {
                    action: v1::HostManagedAction::Message as i32,
                    session_id: sid.into(),
                    driver_id: sid.strip_prefix("session-").unwrap().into(),
                    expected_launch_generation: generation,
                    text: "must-not-deliver".into(),
                    ..Default::default()
                },
            ),
        ),
    })
    .unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn member_managed_stale_generation_refuses_before_helper_or_current_process_effect() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = managed_test_owner(temp.path()).await;
    let sid = managed_test_session(&owner, &engine).await;
    let before = engine.get(&sid).await.unwrap();
    let receipt = owner
        .mutate(managed_test_message(4, &sid, 2))
        .await
        .unwrap();
    assert_eq!(receipt.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert_eq!(receipt.generation, 2);
    assert!(!receipt.input_acknowledged);
    assert_eq!(engine.get(&sid).await.unwrap(), before);
    assert!(lock(&engine.inner.active).contains_key(&sid));
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn member_managed_caller_drop_and_revoke_serialize_before_queue_effect_and_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = managed_test_owner(temp.path()).await;
    let sid = managed_test_session(&owner, &engine).await;
    let handle = engine.handle(&sid).unwrap();
    let operation = handle.operation.lock().await;
    let request = managed_test_message(4, &sid, 1);
    let waiting = owner.clone();
    let message = request.clone();
    let waiter = tokio::spawn(async move { waiting.mutate(message).await });
    wait_control_pending(&owner, &request).await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    owner
        .revoke_grant(v1::HostControlRevokeGrantRequest {
            expected_book_revision: 1,
            grant_id: request.scope.grant_id.clone(),
            expected_grant_revision: 1,
        })
        .await
        .unwrap();
    drop(operation);
    let terminal = control_fixture::settled(&owner, &request).await;
    assert_eq!(terminal.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert!(!terminal.input_acknowledged);
    assert_eq!(
        owner.mutate(request.clone()).await.unwrap().to_wire(),
        terminal.to_wire()
    );
    assert_eq!(
        owner
            .observe(&request.request_id, &request.scope)
            .await
            .unwrap()
            .to_wire(),
        terminal.to_wire()
    );
    assert!(lock(&engine.inner.active).contains_key(&sid));
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn member_managed_generic_restart_refuses_before_launch_cancel_but_legacy_stop_remains() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = managed_test_owner(temp.path()).await;
    let sid = managed_test_session(&owner, &engine).await;
    let handle = engine.handle(&sid).unwrap();
    let before = engine.get(&sid).await.unwrap();
    let messages = temp
        .path()
        .join("state/agents")
        .join(sid.strip_prefix("session-").unwrap())
        .join("messages");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&messages)
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let at = "2026-10-04T00:00:00Z";
    // A closed generation-A queued-record fixture. The generic engine must
    // refuse without reaching any private mailbox recovery/adoption path.
    let queue=serde_json::to_vec(&serde_json::json!({"version":1,"id":id,"driver_id":sid.strip_prefix("session-").unwrap(),
        "target_session_id":sid,"action":"message","text":"queued A","reply_to":null,"expected_turn_id":null,
        "expected_active_message_id":null,"turn_id":null,"state":"accepted","created_at":at,"updated_at":at,
        "accepted_at":at,"started_at":null,"finished_at":null,"native_acknowledged":false,"member_launch_generation":1,
        "result":null,"result_truncated":false,"error":null,"usage":null,"source":null,"notification":null})).unwrap();
    let path = messages.join(format!("{id}.json"));
    std::fs::write(&path, &queue).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    for expected in [None, Some(1)] {
        assert!(
            engine
                .restart_with_generation(&sid, expected)
                .await
                .is_err()
        );
        assert!(!*handle.launch_cancellation.borrow());
        assert_eq!(engine.get(&sid).await.unwrap(), before);
        assert_eq!(std::fs::read(&path).unwrap(), queue);
    }
    let stopped = engine.stop(&sid).await.unwrap();
    assert!(!is_live_state(stopped.state));
    assert_eq!(stopped.launch_generation, 1);
    assert!(!stopped.cleanup_unknown);
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn member_managed_read_queued_behind_operation_readmits_revocation_before_helper() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = managed_test_owner(temp.path()).await;
    let sid = managed_test_session(&owner, &engine).await;
    let handle = engine.handle(&sid).unwrap();
    let operation = handle.operation.lock().await;
    let scope = control_fixture::scope();
    let driver = sid.strip_prefix("session-").unwrap().to_owned();
    let reading = owner.clone();
    let read_scope = scope.clone();
    let request = v1::HostControlManagedReadRequest {
        scope: Some(scope.to_wire()),
        session_id: sid.clone(),
        driver_id: driver,
        expected_launch_generation: 1,
        ..Default::default()
    };
    let reader = tokio::spawn(async move { reading.read_managed(&request, &read_scope).await });
    tokio::task::yield_now().await;
    owner
        .revoke_grant(v1::HostControlRevokeGrantRequest {
            expected_book_revision: 1,
            grant_id: scope.grant_id,
            expected_grant_revision: 1,
        })
        .await
        .unwrap();
    drop(operation);
    assert!(matches!(
        reader.await.unwrap(),
        Err(crate::host_control::Error::Denied)
    ));
    assert!(lock(&engine.inner.active).contains_key(&sid));
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
async fn wait_control_pending(
    owner: &crate::host_control::Owner,
    request: &crate::host_control::Mutation,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if owner
                .observe(&request.request_id, &request.scope)
                .await
                .is_ok_and(|record| record.phase == v1::HostControlRequestPhase::Pending as i32)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_caller_drop_keeps_one_target_owned_pending_launch() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let admission = engine.inner.retention_admission.lock().await;
    let marker = temp.path().join("one-spawn");
    let request = control_fixture::launch(
        3,
        &control_fixture::scope(),
        &format!("printf x >> '{}'; sleep 60", marker.display()),
    );
    let waiting_owner = owner.clone();
    let waiting_request = request.clone();
    let waiter = tokio::spawn(async move { waiting_owner.mutate(waiting_request).await });
    wait_control_pending(&owner, &request).await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(!marker.exists());
    drop(admission);
    let receipt = control_fixture::settled(&owner, &request).await;
    assert_eq!(receipt.phase, v1::HostControlRequestPhase::Completed as i32);
    owner.mutate(request.clone()).await.unwrap();
    wait_file(&marker).await;
    assert_eq!(std::fs::read(marker).unwrap(), b"x");
    assert_eq!(engine.list().await.unwrap().len(), 1);
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_revoke_before_issue_prevents_launch_publication_and_pruning() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let admission = engine.inner.retention_admission.lock().await;
    let request = control_fixture::launch(3, &control_fixture::scope(), "sleep 60");
    let waiting_owner = owner.clone();
    let waiting_request = request.clone();
    let waiter = tokio::spawn(async move { waiting_owner.mutate(waiting_request).await });
    wait_control_pending(&owner, &request).await;
    owner
        .revoke_grant(v1::HostControlRevokeGrantRequest {
            expected_book_revision: 1,
            grant_id: request.scope.grant_id.clone(),
            expected_grant_revision: 1,
        })
        .await
        .unwrap();
    drop(admission);
    let receipt = waiter.await.unwrap().unwrap();
    assert_eq!(receipt.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert!(engine.list().await.unwrap().is_empty());
    assert!(
        !temp
            .path()
            .join("state/host-control/launch-stages")
            .exists()
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("state/sessions"))
            .unwrap()
            .count(),
        0
    );
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_revoke_queued_input_and_stop_precedes_write_and_cancel() {
    for stopping in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (owner, engine) = control_fixture::owner(temp.path()).await;
        let marker = temp.path().join("input-effect");
        let launched = owner
            .mutate(control_fixture::launch(
                3,
                &control_fixture::scope(),
                &format!(
                    "read value; printf '%s' \"$value\" > '{}'; sleep 60",
                    marker.display()
                ),
            ))
            .await
            .unwrap();
        let handle = engine.handle(&launched.session_id).unwrap();
        let operation = handle.operation.lock().await;
        let request = if stopping {
            control_fixture::stop(4, &control_fixture::scope(), &launched.session_id, 1)
        } else {
            control_fixture::input(
                4,
                &control_fixture::scope(),
                &launched.session_id,
                1,
                b"must-not-write\n",
            )
        };
        let waiting_owner = owner.clone();
        let waiting_request = request.clone();
        let waiter = tokio::spawn(async move { waiting_owner.mutate(waiting_request).await });
        wait_control_pending(&owner, &request).await;
        owner
            .revoke_grant(v1::HostControlRevokeGrantRequest {
                expected_book_revision: 1,
                grant_id: request.scope.grant_id.clone(),
                expected_grant_revision: 1,
            })
            .await
            .unwrap();
        assert!(!*handle.launch_cancellation.borrow());
        drop(operation);
        let receipt = waiter.await.unwrap().unwrap();
        assert_eq!(receipt.phase, v1::HostControlRequestPhase::Rejected as i32);
        assert!(!*handle.launch_cancellation.borrow());
        assert!(!marker.exists());
        assert_eq!(
            engine.get(&launched.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Running as i32
        );
        owner.drain().await.unwrap();
        engine.shutdown().await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_stale_generation_never_signals_or_inputs_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let marker = temp.path().join("input-effect");
    let launched = owner
        .mutate(control_fixture::launch(
            3,
            &control_fixture::scope(),
            &format!(
                "read value; printf '%s' \"$value\" > '{}'; sleep 60",
                marker.display()
            ),
        ))
        .await
        .unwrap();
    owner
        .mutate(control_fixture::stop(
            4,
            &control_fixture::scope(),
            &launched.session_id,
            1,
        ))
        .await
        .unwrap();
    let replacement = engine
        .restart_with_generation(&launched.session_id, Some(1))
        .await
        .unwrap();
    assert_eq!(replacement.launch_generation, 2);
    for request in [
        control_fixture::input(
            5,
            &control_fixture::scope(),
            &launched.session_id,
            1,
            b"stale\n",
        ),
        control_fixture::stop(6, &control_fixture::scope(), &launched.session_id, 1),
    ] {
        assert_eq!(
            owner.mutate(request).await.unwrap().phase,
            v1::HostControlRequestPhase::Rejected as i32
        );
    }
    assert!(!marker.exists());
    let handle = engine.handle(&launched.session_id).unwrap();
    assert!(!*handle.launch_cancellation.borrow());
    assert_eq!(
        engine.get(&launched.session_id).await.unwrap().state,
        v1::SessionLifecycleState::Running as i32
    );
    assert!(
        owner
            .mutate(control_fixture::input(
                7,
                &control_fixture::scope(),
                &launched.session_id,
                2,
                b"current\n"
            ))
            .await
            .unwrap()
            .input_acknowledged
    );
    assert_eq!(wait_file(&marker).await, "current");
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_issued_input_timeout_is_retained_ambiguous_without_replay() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let ready = temp.path().join("pipe-ready");
    // Exercise actual kernel backpressure, independent of the host's default
    // pipe capacity. Only the owned child's anonymous stdin pipe is resized.
    let script = format!(
        "exec /usr/bin/python3 -c 'import fcntl,time; fcntl.fcntl(0,fcntl.F_SETPIPE_SZ,4096); open(\"{}\",\"w\").write(\"ready\"); time.sleep(60)'",
        ready.display()
    );
    let launched = owner
        .mutate(control_fixture::launch(
            3,
            &control_fixture::scope(),
            &script,
        ))
        .await
        .unwrap();
    assert_eq!(wait_file(&ready).await, "ready");
    let request = control_fixture::input(
        4,
        &control_fixture::scope(),
        &launched.session_id,
        1,
        &vec![b'x'; 65536],
    );
    let receipt = owner.mutate(request.clone()).await.unwrap();
    assert!(receipt.unsettled());
    let terminal = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let receipt = owner
                .observe(&request.request_id, &request.scope)
                .await
                .unwrap();
            if !receipt.unsettled() {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(terminal.phase, v1::HostControlRequestPhase::Unknown as i32);
    assert!(!terminal.input_acknowledged);
    assert_eq!(owner.mutate(request).await.unwrap().phase, terminal.phase);
    assert_eq!(
        engine.get(&launched.session_id).await.unwrap().state,
        v1::SessionLifecycleState::Running as i32
    );
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_control_preserves_legacy_local_stop_prelock_projection_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, engine) = control_fixture::owner(temp.path()).await;
    let launched = owner
        .mutate(control_fixture::launch(
            3,
            &control_fixture::scope(),
            "sleep 60",
        ))
        .await
        .unwrap();
    let handle = engine.handle(&launched.session_id).unwrap();
    let operation = handle.operation.lock().await;
    let stopping_engine = engine.clone();
    let session = launched.session_id;
    let stopper = tokio::spawn(async move { stopping_engine.stop(&session).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if *handle.launch_cancellation.borrow() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop(operation);
    assert_eq!(
        stopper.await.unwrap().unwrap().state,
        v1::SessionLifecycleState::Stopped as i32
    );
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

/// A host owner's engine, whose state root is named by its environment ID.
#[cfg(target_os = "linux")]
fn environment_engine(root: &Path) -> (SessionEngine, String) {
    let environment = uuid::Uuid::from_u128(41).to_string();
    std::fs::create_dir_all(root.join("home")).unwrap();
    let mut config = tests::test_engine(root).inner.config.clone();
    config.host = Some(crate::HostConfig {
        state_root: root.join("hosts").join(&environment),
    });
    (
        SessionEngine::new(&config, CredentialBridge::new(None)),
        environment,
    )
}

/// A running session with a managed driver's command line. `sh` reads the
/// driver argument as a script in its working directory: a synthetic sleep.
#[cfg(target_os = "linux")]
async fn driver_shaped_session(engine: &SessionEngine, root: &Path, environment: &str) -> String {
    driver_shaped_session_running(engine, root, environment, "exec sleep 60\n").await
}

/// [`driver_shaped_session`] whose driver argument is `script`.
#[cfg(target_os = "linux")]
async fn driver_shaped_session_running(
    engine: &SessionEngine,
    root: &Path,
    environment: &str,
    script: &str,
) -> String {
    let directory = root.join("driver");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("_agent-driver"), script).unwrap();
    let record = engine
        .launch(v1::LaunchSessionRequest {
            command: vec![
                "/bin/sh".into(),
                "_agent-driver".into(),
                "--environment".into(),
                environment.into(),
                "--driver-id".into(),
                uuid::Uuid::from_u128(42).to_string(),
                "--registry-root".into(),
                root.join("hosts").display().to_string(),
            ],
            working_dir: directory.display().to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);
    record.session_id
}

/// A session with a managed driver's command line whose process notes, when
/// it is signalled, what the daemon had written by then: `intent` for the
/// session's stop intent, `marker` for the environment's takedown marker,
/// then `signalled`. It uses shell builtins only, so it is done well inside
/// the time a signalled process has.
#[cfg(target_os = "linux")]
async fn witnessing_driver_session(
    engine: &SessionEngine,
    root: &Path,
    environment: &str,
) -> String {
    let state = root.join("hosts").join(environment);
    let script = format!(
        "trap 'set -- {state}/sessions/*/{intent}; [ -e \"$1\" ] && echo intent >> seen; \
         [ -e {state}/{marker} ] && echo marker >> seen; echo signalled >> seen; exit 0' TERM\n\
         echo ready > ready\nsleep 60 &\nwait\n",
        state = state.display(),
        intent = crate::stop_evidence::STOP_INTENT_FILE,
        marker = crate::stop_evidence::SHUTDOWN_MARKER,
    );
    let session = driver_shaped_session_running(engine, root, environment, &script).await;
    witness_ready(root).await;
    session
}

/// The witness has its handler: a signal now is noted, not fatal at once.
#[cfg(target_os = "linux")]
async fn witness_ready(root: &Path) {
    let ready = root.join("driver").join("ready");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the witnessing driver started");
    std::fs::remove_file(ready).unwrap();
}

/// What the witness noted since it was last asked.
#[cfg(target_os = "linux")]
fn witnessed(root: &Path) -> Vec<String> {
    let seen = root.join("driver").join("seen");
    let noted = std::fs::read_to_string(&seen).unwrap_or_default();
    let _ = std::fs::remove_file(seen);
    noted.lines().map(str::to_owned).collect()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_daemon_records_what_a_stop_means_before_it_signals_whatever_the_record_helper_does() {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let state = temp.path().join("hosts").join(&environment);
    let driver = witnessing_driver_session(&engine, temp.path(), &environment).await;
    let ordinary = engine.launch(request("sleep 60", false)).await.unwrap();
    let intended = |session: &str| crate::stop_evidence::stop_intended(&state, session);
    // What a conversation's next start does once it has acted on the intent.
    let acted_on = |session: &str| crate::stop_evidence::clear_stop_intent(&state, session);

    // An explicit stop. This test image is no cw-bearing host daemon, so the
    // record helper is refused and records nothing: the daemon's own stop
    // intent is on disk when the conversation is signalled all the same.
    engine.stop(&driver).await.unwrap();
    assert_eq!(witnessed(temp.path()), ["intent", "signalled"]);
    assert!(intended(&driver));
    // Only a host owner's managed conversation gets one.
    engine.stop(&ordinary.session_id).await.unwrap();
    assert!(!intended(&ordinary.session_id));

    // Stopping a conversation that is not running records it too, so its
    // next start does not resume what it left. Nothing is signalled.
    acted_on(&driver).unwrap();
    engine.stop(&driver).await.unwrap();
    assert!(intended(&driver));
    assert!(witnessed(temp.path()).is_empty());

    // Restarting a conversation that is not running stops nothing and
    // records nothing: it is how a run resumes.
    acted_on(&driver).unwrap();
    engine.restart(&driver).await.unwrap();
    witness_ready(temp.path()).await;
    assert!(!intended(&driver));
    assert!(witnessed(temp.path()).is_empty());

    // Restarting a running one stops that incarnation explicitly.
    let restarted = engine.restart(&driver).await.unwrap();
    assert_eq!(restarted.launch_generation, 3);
    witness_ready(temp.path()).await;
    assert_eq!(witnessed(temp.path()), ["intent", "signalled"]);
    assert!(intended(&driver));
    acted_on(&driver).unwrap();

    // A shutdown takes the whole environment down: its marker is on disk
    // when the conversation is signalled, and no stop intent is.
    assert!(!crate::stop_evidence::takedown_marked(&state));
    engine.shutdown().await.unwrap();
    assert_eq!(witnessed(temp.path()), ["marker", "signalled"]);
    assert!(crate::stop_evidence::takedown_marked(&state));
    assert!(!intended(&driver));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_explicit_stop_that_cannot_be_recorded_signals_nothing_and_fails() {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let driver = witnessing_driver_session(&engine, temp.path(), &environment).await;
    // Nothing can be written where the intent goes.
    let blocked = engine
        .inner
        .root
        .join(&driver)
        .join(crate::stop_evidence::STOP_INTENT_FILE);
    std::fs::create_dir(&blocked).unwrap();

    for restart in [false, true] {
        let refused = if restart {
            engine.restart(&driver).await
        } else {
            engine.stop(&driver).await
        };
        assert!(
            matches!(
                &refused,
                Err(SessionError::Internal(message)) if message.contains("nothing was signalled")
            ),
            "{restart}: {refused:?}"
        );
        // The conversation runs on, in the same incarnation, unsignalled.
        let after = engine.get(&driver).await.unwrap();
        assert_eq!(after.state, v1::SessionLifecycleState::Running as i32);
        assert_eq!(after.launch_generation, 1);
        assert!(witnessed(temp.path()).is_empty(), "{restart}");
    }

    std::fs::remove_dir(&blocked).unwrap();
    engine.stop(&driver).await.unwrap();
    assert_eq!(witnessed(temp.path()), ["intent", "signalled"]);
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
fn stop_interrupt_checks(engine: &SessionEngine) -> usize {
    engine
        .inner
        .stop_interrupt_checks
        .load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn explicit_stop_and_restart_check_for_a_run_to_interrupt_and_shutdown_never_does() {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let driver = driver_shaped_session(&engine, temp.path(), &environment).await;
    let ordinary = engine.launch(request("sleep 60", false)).await.unwrap();
    let stopped_state = v1::SessionLifecycleState::Stopped as i32;

    // Only a running managed driver is checked.
    assert_eq!(
        engine.stop(&ordinary.session_id).await.unwrap().state,
        stopped_state
    );
    assert_eq!(stop_interrupt_checks(&engine), 0);

    // This test image is no cw-bearing host daemon, so the record helper is
    // refused: the explicit stop still checks once and then stops at once.
    let started = Instant::now();
    let stopped = engine.stop(&driver).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(stopped.state, stopped_state);
    assert!(!stopped.cleanup_unknown);
    assert_eq!(stop_interrupt_checks(&engine), 1);
    engine.stop(&driver).await.unwrap();
    assert_eq!(stop_interrupt_checks(&engine), 1);

    // Restarting a stopped conversation has no run to interrupt; restarting
    // a running one checks before it stops the old incarnation.
    engine.restart(&driver).await.unwrap();
    assert_eq!(stop_interrupt_checks(&engine), 1);
    let restarted = engine.restart(&driver).await.unwrap();
    assert_eq!(restarted.launch_generation, 3);
    assert_eq!(stop_interrupt_checks(&engine), 2);

    // Daemon shutdown stops the running conversation without checking: a
    // shutdown, like a crash or reboot, leaves the run resumable.
    engine.shutdown().await.unwrap();
    assert_eq!(stop_interrupt_checks(&engine), 2);
    let after = engine.get(&driver).await.unwrap();
    assert_eq!(after.state, stopped_state);
    assert!(!after.cleanup_unknown);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sessions_outside_a_host_owner_never_check_for_a_run_to_interrupt() {
    let temp = tempfile::tempdir().unwrap();
    let engine = tests::test_engine(temp.path());
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    let environment = uuid::Uuid::from_u128(41).to_string();
    let driver = driver_shaped_session(&engine, temp.path(), &environment).await;
    engine.stop(&driver).await.unwrap();
    engine.restart(&driver).await.unwrap();
    engine.restart(&driver).await.unwrap();
    engine.shutdown().await.unwrap();
    engine.stop(&driver).await.unwrap();
    assert_eq!(stop_interrupt_checks(&engine), 0);
    // Nor for one to pause, nor for one that can never resume, nor for a
    // paused one to end.
    assert_eq!(shutdown_pause_checks(&engine), 0);
    assert_eq!(stopped_pause_checks(&engine), 0);
    // And nothing records what their stops mean: only a host daemon writes a
    // stop intent or a takedown marker.
    let intents = std::fs::read_dir(&engine.inner.root)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .join(crate::stop_evidence::STOP_INTENT_FILE)
                .exists()
        })
        .count();
    assert_eq!(intents, 0);
    let _admission = engine.inner.retention_admission.lock().await;
    prune_session_records(&engine.inner, 0, true).await.unwrap();
    assert_eq!(prune_retire_checks(&engine), 0);
}

#[cfg(target_os = "linux")]
fn shutdown_pause_checks(engine: &SessionEngine) -> usize {
    engine
        .inner
        .shutdown_pause_checks
        .load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "linux")]
fn prune_retire_checks(engine: &SessionEngine) -> usize {
    engine
        .inner
        .prune_retire_checks
        .load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shutdown_checks_each_running_conversation_for_a_run_to_pause_and_an_explicit_stop_never_does()
 {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let driver = driver_shaped_session(&engine, temp.path(), &environment).await;
    let ordinary = engine.launch(request("sleep 60", false)).await.unwrap();
    let stopped_state = v1::SessionLifecycleState::Stopped as i32;

    // An explicit stop or restart interrupts a run; it never pauses one.
    engine.stop(&driver).await.unwrap();
    engine.restart(&driver).await.unwrap();
    engine.restart(&driver).await.unwrap();
    assert_eq!(shutdown_pause_checks(&engine), 0);
    let interrupts = stop_interrupt_checks(&engine);

    // Shutdown checks the one running managed driver before it signals it,
    // and no other session. This test image is no cw-bearing host daemon, so
    // the record helper is refused and the stop goes on at once.
    let started = Instant::now();
    engine.shutdown().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(shutdown_pause_checks(&engine), 1);
    assert_eq!(stop_interrupt_checks(&engine), interrupts);
    for id in [&driver, &ordinary.session_id] {
        let after = engine.get(id).await.unwrap();
        assert_eq!(after.state, stopped_state);
        assert!(!after.cleanup_unknown);
    }
}

#[cfg(target_os = "linux")]
fn stopped_pause_checks(engine: &SessionEngine) -> usize {
    engine
        .inner
        .stopped_pause_checks
        .load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_explicit_stop_of_a_stopped_conversation_checks_for_a_paused_message_to_end() {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let driver = driver_shaped_session(&engine, temp.path(), &environment).await;
    let ordinary = engine.launch(request("sleep 60", false)).await.unwrap();
    let stopped_state = v1::SessionLifecycleState::Stopped as i32;

    // Stopping a running conversation interrupts its run; nothing of it is
    // paused.
    engine.stop(&driver).await.unwrap();
    engine.stop(&ordinary.session_id).await.unwrap();
    assert_eq!(stopped_pause_checks(&engine), 0);

    // Stopped already, it may hold a message its environment's takedown
    // paused, which this stop must keep from resuming. The refused helper is
    // logged and the stop answers as before.
    let started = Instant::now();
    let again = engine.stop(&driver).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(again.state, stopped_state);
    assert_eq!(stopped_pause_checks(&engine), 1);
    // Only a host owner's managed conversation is asked.
    engine.stop(&ordinary.session_id).await.unwrap();
    assert_eq!(stopped_pause_checks(&engine), 1);

    // A restart continues a paused run instead, and shutdown pauses.
    engine.restart(&driver).await.unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(stopped_pause_checks(&engine), 1);
    assert_eq!(shutdown_pause_checks(&engine), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn retention_asks_a_stopped_conversation_what_can_never_resume_before_removing_its_record() {
    let temp = tempfile::tempdir().unwrap();
    let (engine, environment) = environment_engine(temp.path());
    let driver = driver_shaped_session(&engine, temp.path(), &environment).await;
    let ordinary = engine.launch(request("sleep 60", false)).await.unwrap();
    engine.stop(&driver).await.unwrap();
    engine.stop(&ordinary.session_id).await.unwrap();
    assert_eq!(prune_retire_checks(&engine), 0);

    // Only the managed conversation is asked. The refused helper is logged
    // and its record is removed all the same.
    let admission = engine.inner.retention_admission.lock().await;
    let started = Instant::now();
    prune_session_records(&engine.inner, 0, true).await.unwrap();
    drop(admission);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(prune_retire_checks(&engine), 1);
    for id in [&driver, &ordinary.session_id] {
        assert!(matches!(
            engine.get(id).await,
            Err(SessionError::NotFound(_))
        ));
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn refused_session_store_is_admitted_once_corrected() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let sessions = temp.path().join("state/sessions");
    std::fs::create_dir_all(temp.path().join("state")).unwrap();
    std::fs::create_dir_all(temp.path().join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(temp.path().join("elsewhere"), &sessions).unwrap();
    let refused = engine.list().await.unwrap_err();
    assert!(
        refused.to_string().contains("must not be a symlink"),
        "{refused}"
    );
    // The refusal is not remembered: the corrected store opens on the next call.
    std::fs::remove_file(&sessions).unwrap();
    assert!(engine.list().await.unwrap().is_empty());
    engine.shutdown().await.unwrap();
}

fn host_engine(root: &Path) -> SessionEngine {
    std::fs::create_dir_all(root.join("home")).unwrap();
    let mut config = tests::test_engine(root).inner.config.clone();
    config.host = Some(crate::HostConfig {
        state_root: root.join("state"),
    });
    SessionEngine::new(&config, CredentialBridge::new(None))
}

fn request(command: &str, pty: bool) -> v1::LaunchSessionRequest {
    v1::LaunchSessionRequest {
        command: vec!["/bin/sh".into(), "-c".into(), command.into()],
        pty,
        ..Default::default()
    }
}

async fn wait_file(path: &Path) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(value) = tokio::fs::read_to_string(path).await
                && !value.trim().is_empty()
            {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned child published PID")
}

fn alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        && stat
            .rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    {
        return false; // Dead orphans may await the test host's init reaper.
    }
    #[cfg(target_os = "macos")]
    return crate::host_process::live(pid as i32); // Zombies may await their reaper.
    #[cfg(not(target_os = "macos"))]
    unsafe {
        libc::kill(pid as i32, 0) == 0
    }
}

#[cfg(target_os = "linux")]
fn assert_no_fixture_children() {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let result = unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
        )
    };
    let error = std::io::Error::last_os_error();
    assert!(
        result == -1 && error.raw_os_error() == Some(libc::ECHILD),
        "isolated descendant fixture still owns children: result={result}, error={error}"
    );
}

#[cfg(target_os = "linux")]
async fn isolated_descendant_fixture(case: &str) -> bool {
    const MARKER: &str = "CW_TEST_HOST_DESCENDANT_OWNER";
    let test = format!("durable_session::host_tests::{case}");
    if let Some(marker) = std::env::var_os(MARKER) {
        assert_eq!(marker, std::ffi::OsStr::new(&test));
        assert_eq!(
            std::env::args().skip(1).collect::<Vec<_>>(),
            ["--exact", &test, "--nocapture", "--test-threads=1"]
        );
        assert!(std::env::vars_os().all(|(name, _)| {
            [MARKER, "HOME", "PATH", "SHELL", "TMPDIR"]
                .iter()
                .any(|allowed| name == std::ffi::OsStr::new(allowed))
        }));
        // Only this exact, isolated test process adopts its real orphaned
        // descendants. The parallel test runner never becomes a subreaper.
        assert_no_fixture_children();
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut active = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut active, 0, 0, 0) },
            0
        );
        assert_eq!(active, 1);
        return false;
    }

    let home = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(MARKER, &test)
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .env("TMPDIR", std::env::temp_dir())
        .current_dir(home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = match tokio::time::timeout(Duration::from_secs(20), child.wait()).await {
        Ok(Ok(status)) => status,
        outcome => {
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .expect("isolated descendant fixture cleanup remains unknown")
                .expect("isolated descendant fixture child was not reaped");
            panic!("isolated descendant fixture failed (case={case}): {outcome:?}");
        }
    };
    assert!(
        status.success(),
        "isolated descendant fixture failed: {case}"
    );
    true
}

#[cfg(target_os = "linux")]
struct FixtureDescendant {
    pid: u32,
    birth: u64,
    pidfd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl FixtureDescendant {
    fn children(pid: u32) -> std::collections::BTreeSet<u32> {
        let mut children = std::collections::BTreeSet::new();
        for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
            let task = task.unwrap();
            for child in std::fs::read_to_string(task.path().join("children"))
                .unwrap()
                .split_whitespace()
            {
                let child = child.parse::<u32>().unwrap();
                assert_ne!(child, 0);
                children.insert(child);
            }
        }
        children
    }

    fn assert_parent(&self, parent: u32, session: u32) {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)).unwrap();
        let fields = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(fields[1].parse::<u32>().unwrap(), parent);
        assert_eq!(fields[3].parse::<u32>().unwrap(), session);
        assert_eq!(fields[19].parse::<u64>().unwrap(), self.birth);
    }

    fn capture_fixture_descendants() -> (Self, Vec<Self>) {
        // This dedicated test owns exactly one live session at a time. Discover
        // only its original leader and that leader's children before Stop.
        let owner = std::process::id();
        let children = Self::children(owner);
        assert_eq!(children.len(), 1);
        let leader = Self::capture(*children.iter().next().unwrap());
        leader.assert_parent(owner, leader.pid);
        assert_eq!(
            unsafe { libc::getpgid(leader.pid.try_into().unwrap()) },
            libc::pid_t::try_from(leader.pid).unwrap()
        );
        assert!(alive(leader.pid));
        let descendants = Self::children(leader.pid)
            .into_iter()
            .map(|pid| {
                let descendant = Self::capture(pid);
                descendant.assert_parent(leader.pid, leader.pid);
                descendant
            })
            .collect();
        leader.assert_parent(owner, leader.pid);
        assert!(alive(leader.pid));
        assert_eq!(
            unsafe { libc::getpgid(leader.pid.try_into().unwrap()) },
            libc::pid_t::try_from(leader.pid).unwrap()
        );
        // Retain the leader's identity, but let production Child.wait reap it.
        // Any missed/raced descendant still refuses final ECHILD.
        (leader, descendants)
    }

    fn birth(pid: u32) -> std::io::Result<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        stat.rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|birth| birth.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid descendant birth")
            })
    }

    fn capture(pid: u32) -> Self {
        // Natural exit can precede capture. A zombie still has an exact
        // identity; binding does not require authority to signal it.
        let birth = Self::birth(pid).unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw.try_into().unwrap()) };
        assert_eq!(Self::birth(pid).unwrap(), birth);
        Self { pid, birth, pidfd }
    }

    fn reap(&self) {
        // The original !alive assertion comes first. This fixture only joins
        // an ended original process; it never signals or fabricates cleanup.
        let mut ready = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 0) }, 1);
        assert_ne!(ready.revents & libc::POLLIN, 0);
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd().try_into().unwrap(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::__WALL,
            )
        };
        let error = std::io::Error::last_os_error();
        if result == 0 {
            assert_eq!(
                unsafe { info.si_pid() },
                libc::pid_t::try_from(self.pid).unwrap()
            );
            assert!(matches!(
                info.si_code,
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
            ));
        } else {
            assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
            // The original waiting shell may already have reaped its child.
            // Terminal pidfd plus absence of the original birth proves that
            // path; ECHILD alone and a remaining same-birth zombie do not.
            match Self::birth(self.pid) {
                Ok(birth) => assert_ne!(birth, self.birth, "original descendant was not reaped"),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
            }
        }
    }
}

#[tokio::test]
async fn host_stop_owns_shell_descendants_for_pipe_and_pty_preserving_unrelated_child() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture(
        "host_stop_owns_shell_descendants_for_pipe_and_pty_preserving_unrelated_child",
    )
    .await
    {
        return;
    }
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let engine = host_engine(temp.path());
        let mut unrelated = unrelated_sleep();
        let unrelated_pid = unrelated.id().unwrap();
        let descendant = temp.path().join("descendant.pid");
        let script = format!(
            "trap '' TERM; sleep 60 & echo $! > '{}'; wait",
            descendant.display()
        );
        let record = engine.launch(request(&script, pty)).await.unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);
        assert!(!record.cleanup_unknown);
        let descendant_pid: u32 = wait_file(&descendant).await.trim().parse().unwrap();
        #[cfg(target_os = "linux")]
        let descendant = FixtureDescendant::capture(descendant_pid);
        let stopped = tokio::time::timeout(Duration::from_secs(4), engine.stop(&record.session_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stopped.state,
            v1::SessionLifecycleState::Stopped as i32,
            "{}",
            stopped.status_message
        );
        assert!(!stopped.cleanup_unknown);
        assert!(
            !alive(descendant_pid),
            "ordinary descendant survived host Stop (pty={pty})"
        );
        #[cfg(target_os = "linux")]
        descendant.reap();
        assert!(alive(unrelated_pid), "unrelated process was signaled");
        assert!(!temp.path().join("home/.codewire").exists());
        engine.shutdown().await.unwrap();
        unrelated.kill().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

/// PTY job control moves a background job into its own process group, which
/// a signal to the leader's group misses. Stop must still reach it through the
/// owned session.
#[tokio::test]
async fn host_stop_reaches_job_control_groups_in_the_owned_session() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture("host_stop_reaches_job_control_groups_in_the_owned_session")
        .await
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let descendant = temp.path().join("descendant.pid");
    let script = format!(
        "set -m; trap '' TERM; sleep 60 & echo $! > '{}'; wait",
        descendant.display()
    );
    let record = engine.launch(request(&script, true)).await.unwrap();
    let pid: u32 = wait_file(&descendant).await.trim().parse().unwrap();
    #[cfg(target_os = "linux")]
    let fixture = FixtureDescendant::capture(pid);
    assert_eq!(
        unsafe { libc::getpgid(pid as i32) },
        pid as i32,
        "job control did not give the background job its own group"
    );
    let stopped = tokio::time::timeout(Duration::from_secs(4), engine.stop(&record.session_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stopped.state,
        v1::SessionLifecycleState::Stopped as i32,
        "{}",
        stopped.status_message
    );
    assert!(!stopped.cleanup_unknown);
    assert!(!alive(pid), "job-control group survived host Stop");
    #[cfg(target_os = "linux")]
    fixture.reap();
    engine.shutdown().await.unwrap();
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

#[tokio::test]
async fn host_exit_cleans_remaining_descendants_before_reaping_group_leader() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture(
        "host_exit_cleans_remaining_descendants_before_reaping_group_leader",
    )
    .await
    {
        return;
    }
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let engine = host_engine(temp.path());
        let descendant = temp.path().join("descendant.pid");
        let script = format!(
            "trap '' TERM; sleep 60 & echo $! > '{}'; exit 7",
            descendant.display()
        );
        let record = engine.launch(request(&script, pty)).await.unwrap();
        let pid: u32 = wait_file(&descendant).await.trim().parse().unwrap();
        #[cfg(target_os = "linux")]
        let descendant = FixtureDescendant::capture(pid);
        let ended = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let record = engine.get(&record.session_id).await.unwrap();
                if !is_live_state(record.state) {
                    break record;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            ended.state,
            v1::SessionLifecycleState::Exited as i32,
            "{}",
            ended.status_message
        );
        assert_eq!(ended.exit_code, Some(7));
        assert!(!ended.cleanup_unknown);
        assert!(!alive(pid));
        #[cfg(target_os = "linux")]
        descendant.reap();
        engine.shutdown().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

#[tokio::test]
async fn host_shutdown_cleans_owned_groups_and_records_confirmed_completion() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture(
        "host_shutdown_cleans_owned_groups_and_records_confirmed_completion",
    )
    .await
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let mut ids = Vec::new();
    #[cfg(target_os = "linux")]
    let mut descendants = std::collections::BTreeMap::new();
    for pty in [false, true] {
        let path = temp.path().join(format!("descendant-{pty}.pid"));
        let script = format!(
            "trap '' TERM; sleep 60 & echo $! > '{}'; wait",
            path.display()
        );
        let record = engine.launch(request(&script, pty)).await.unwrap();
        let pid: u32 = wait_file(&path).await.trim().parse().unwrap();
        #[cfg(target_os = "linux")]
        descendants.insert(pid, FixtureDescendant::capture(pid));
        ids.push((record.session_id, pid));
    }
    tokio::time::timeout(Duration::from_secs(5), engine.shutdown())
        .await
        .unwrap()
        .unwrap();
    let recovered = host_engine(temp.path());
    for (id, pid) in ids {
        assert!(!alive(pid));
        #[cfg(target_os = "linux")]
        descendants.get(&pid).unwrap().reap();
        let record = recovered.get(&id).await.unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Stopped as i32);
        assert!(!record.cleanup_unknown);
    }
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

#[tokio::test]
async fn recovered_host_live_records_are_fenced_without_signaling_persisted_pid() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let mut unrelated = unrelated_sleep();
    for state in [
        v1::SessionLifecycleState::Starting,
        v1::SessionLifecycleState::Running,
        v1::SessionLifecycleState::Stopping,
    ] {
        let session_id = engine.create_session_id().await.unwrap();
        let metadata = PersistedSession {
            session_id: session_id.clone(),
            #[cfg(target_os = "linux")]
            control_origin: None,
            #[cfg(target_os = "linux")]
            platform_managed_origin: None,
            launch_generation: 1,
            name: String::new(),
            parent_session_id: None,
            state: state as i32,
            command: vec!["/bin/true".into()],
            working_dir: temp.path().to_string_lossy().into_owned(),
            env: vec![],
            environment_projection_required: false,
            pty: false,
            term: String::new(),
            width: 0,
            height: 0,
            created_at: PersistedTimestamp::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            cleanup_confirmed: false,
            cleanup_unknown: false,
            status_message: String::new(),
        };
        let mut old = serde_json::to_value(&metadata).unwrap();
        old.as_object_mut().unwrap().remove("name");
        old.as_object_mut().unwrap().remove("parent_session_id");
        old["pid"] = unrelated.id().unwrap().into(); // Never an ownership capability.
        tokio::fs::write(
            engine.inner.root.join(session_id).join(METADATA_FILE),
            serde_json::to_vec(&old).unwrap(),
        )
        .await
        .unwrap();
    }
    let recovered = host_engine(temp.path());
    let records = recovered.list().await.unwrap();
    assert_eq!(records.len(), 3);
    for record in records {
        assert_eq!(record.state, v1::SessionLifecycleState::Interrupted as i32);
        assert!(record.cleanup_unknown);
        assert!(record.name.is_empty());
        assert_eq!(record.parent_session_id, None);
        assert!(matches!(
            recovered.restart(&record.session_id).await,
            Err(SessionError::NeverRestarts(
                NeverRestarts::CleanupUnconfirmed,
                _
            ))
        ));
    }
    assert!(matches!(
        prune_session_records(&recovered.inner, 0, true).await,
        Err(SessionError::ResourceExhausted(_))
    ));
    assert!(alive(unrelated.id().unwrap()));
    unrelated.kill().await.unwrap();
}

#[tokio::test]
async fn concurrent_named_admission_is_atomic_and_restart_keeps_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let mut launches = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let engine = engine.clone();
        launches.spawn(async move {
            let mut request = request("sleep 60", false);
            request.name = "build_1.main".into();
            engine.launch(request).await
        });
    }
    let mut admitted = Vec::new();
    let mut duplicates = 0;
    while let Some(result) = launches.join_next().await {
        match result.unwrap() {
            Ok(record) => admitted.push(record),
            Err(SessionError::AlreadyExists(_)) => duplicates += 1,
            other => panic!("unexpected admission: {other:?}"),
        }
    }
    assert_eq!(admitted.len(), 1);
    assert_eq!(duplicates, 7);
    let id = &admitted[0].session_id;
    engine.stop(id).await.unwrap();
    assert_eq!(engine.restart(id).await.unwrap().name, "build_1.main");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn host_launch_projection_is_memory_only_and_recovery_refuses_stale_replay() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let marker = temp.path().join("projection-marker");
    let script = format!(
        "printf %s \"$CW_FIXTURE_VALUE\" > '{}'; sleep 60",
        marker.display()
    );
    let mut launch = request(&script, false);
    launch.env = vec![
        "CW_FIXTURE_VALUE=synthetic-launch-only-2255".into(),
        "CW_FIXTURE_EMPTY=".into(),
    ];
    let record = engine.launch(launch).await.unwrap();
    assert_eq!(wait_file(&marker).await, "synthetic-launch-only-2255");
    let path = engine
        .inner
        .root
        .join(&record.session_id)
        .join(METADATA_FILE);
    let saved: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    assert!(saved.get("env").is_none());
    assert_eq!(saved["environment_projection_required"], true);
    assert!(!saved.to_string().contains("synthetic-launch-only-2255"));

    engine.stop(&record.session_id).await.unwrap();
    tokio::fs::remove_file(&marker).await.unwrap();
    engine.restart(&record.session_id).await.unwrap();
    assert_eq!(wait_file(&marker).await, "synthetic-launch-only-2255");
    engine.shutdown().await.unwrap();
    drop(engine);

    let recovered = host_engine(temp.path());
    let before = recovered.get(&record.session_id).await.unwrap();
    assert!(matches!(
        recovered.restart(&record.session_id).await,
        Err(SessionError::NeverRestarts(NeverRestarts::ProjectionLost, message))
            if message.contains("launch a new session")
    ));
    let after = recovered.get(&record.session_id).await.unwrap();
    assert_eq!(before.state, after.state);
    assert_eq!(before.started_at, after.started_at);
    recovered.shutdown().await.unwrap();
    drop(recovered);

    // Accepted older records may contain launch values. Recovery must remove
    // those bytes before publishing a handle, rather than using them again.
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("environment_projection_required");
    legacy["env"] = serde_json::json!(["CW_FIXTURE_VALUE=legacy-launch-only"]);
    tokio::fs::write(&path, serde_json::to_vec(&legacy).unwrap())
        .await
        .unwrap();
    let recovered = host_engine(temp.path());
    recovered.get(&record.session_id).await.unwrap();
    let rewritten: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    assert!(rewritten.get("env").is_none());
    assert_eq!(rewritten["environment_projection_required"], true);
    assert!(!rewritten.to_string().contains("legacy-launch-only"));
    assert!(matches!(
        recovered.restart(&record.session_id).await,
        Err(SessionError::NeverRestarts(
            NeverRestarts::ProjectionLost,
            _
        ))
    ));
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn names_and_same_environment_parents_validate_before_admission_and_pin_retirement() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    for name in [
        "../bad".into(),
        "a b".into(),
        "-bad".into(),
        "é".into(),
        "x".repeat(65),
    ] {
        let mut req = request("true", false);
        req.name = name;
        assert!(matches!(
            engine.launch(req).await,
            Err(SessionError::InvalidArgument(_))
        ));
    }
    let mut parent_req = request("sleep 60", false);
    parent_req.name = "parent".into();
    let parent = engine.launch(parent_req.clone()).await.unwrap();
    for id in [
        parent.session_id.to_uppercase(),
        format!("session-{}", Uuid::new_v4()),
    ] {
        let mut req = request("true", false);
        req.parent_session_id = Some(id);
        assert!(matches!(
            engine.launch(req).await,
            Err(SessionError::InvalidArgument(_) | SessionError::NotFound(_))
        ));
    }
    let mut child_req = request("sleep 60", false);
    child_req.parent_session_id = Some(parent.session_id.clone());
    child_req.name = "child".into();
    let child = engine.launch(child_req).await.unwrap();
    engine.stop(&parent.session_id).await.unwrap();
    engine.stop(&child.session_id).await.unwrap();
    assert_eq!(
        engine
            .get(&child.session_id)
            .await
            .unwrap()
            .parent_session_id,
        Some(parent.session_id.clone())
    );
    assert!(matches!(
        engine.launch(parent_req).await,
        Err(SessionError::AlreadyExists(_))
    ));
    let _admission = engine.inner.retention_admission.lock().await;
    prune_session_records(&engine.inner, 1, true).await.unwrap();
    assert!(engine.get(&parent.session_id).await.is_ok());
    assert!(matches!(
        engine.get(&child.session_id).await,
        Err(SessionError::NotFound(_))
    ));
    prune_session_records(&engine.inner, 0, true).await.unwrap();
    assert!(engine.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn acknowledged_host_input_reaches_owned_stdin_and_rejects_empty_oversized_or_ended() {
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let engine = host_engine(temp.path());
        let record = engine
            .launch(request(
                "read value; printf 'received:%s\\n' \"$value\"; sleep 60",
                pty,
            ))
            .await
            .unwrap();
        for data in [vec![], vec![b'x'; SESSION_INPUT_MAX_BYTES + 1]] {
            assert!(matches!(
                engine.send_input(&record.session_id, data).await,
                Err(SessionError::InvalidArgument(_))
            ));
        }
        engine
            .send_input(&record.session_id, b"acknowledged\n".to_vec())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let output = engine
                    .read_output(v1::ReadSessionOutputRequest {
                        session_id: record.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let bytes = output
                    .chunks
                    .into_iter()
                    .flat_map(|chunk| chunk.data)
                    .collect::<Vec<_>>();
                if String::from_utf8_lossy(&bytes).contains("received:acknowledged") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        engine.stop(&record.session_id).await.unwrap();
        assert!(matches!(
            engine
                .send_input(&record.session_id, b"ended".to_vec())
                .await,
            Err(SessionError::FailedPrecondition(_))
        ));
        engine.shutdown().await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_pty_cleanup_includes_ordinary_terminal_job_control_groups() {
    if isolated_descendant_fixture("host_pty_cleanup_includes_ordinary_terminal_job_control_groups")
        .await
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let descendant = temp.path().join("job.pid");
    let script = format!(
        "trap '' TERM; sleep 60 & echo $! > '{}'; wait",
        descendant.display()
    );
    let mut req = request("unused", true);
    req.command = vec![
        "/bin/bash".into(),
        "--noprofile".into(),
        "--norc".into(),
        "-ic".into(),
        script,
    ];
    let record = engine.launch(req).await.unwrap();
    let pid: u32 = wait_file(&descendant).await.trim().parse().unwrap();
    let descendant = FixtureDescendant::capture(pid);
    // Interactive bash puts jobs in a separate group in the same owned session.
    assert_ne!(unsafe { libc::getpgid(pid as i32) }, unsafe {
        libc::getsid(pid as i32)
    });
    let stopped = engine.stop(&record.session_id).await.unwrap();
    assert_eq!(
        stopped.state,
        v1::SessionLifecycleState::Stopped as i32,
        "{}",
        stopped.status_message
    );
    assert!(!stopped.cleanup_unknown);
    assert!(!alive(pid));
    descendant.reap();
    engine.shutdown().await.unwrap();
    assert_no_fixture_children();
}

#[tokio::test]
async fn host_launch_cancellation_cleans_spawned_descendants_before_failed_acknowledgement() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture(
        "host_launch_cancellation_cleans_spawned_descendants_before_failed_acknowledgement",
    )
    .await
    {
        return;
    }
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let engine = host_engine(temp.path());
        engine.ensure_initialized().await.unwrap();
        let marker = temp.path().join("cancel-descendant.pid");
        let handle = tests::pending_handle(&engine, &marker).await;
        let mut metadata = handle.metadata.lock().await;
        metadata.pty = pty;
        metadata.command = request(
            &format!(
                "trap '' TERM; sleep 60 & echo $! > '{}'; wait",
                marker.display()
            ),
            pty,
        )
        .command;
        let snapshot = metadata.clone();
        let cancel = CancellationToken::new();
        let launching = engine.clone();
        let launching_handle = handle.clone();
        let launching_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            if pty {
                launching
                    .start_pty_process(launching_handle, snapshot, &launching_cancel)
                    .await
            } else {
                launching
                    .start_pipe_process(launching_handle, snapshot, &launching_cancel)
                    .await
            }
        });
        // The persisted Running transition is held until after cancellation.
        let pid: u32 = wait_file(&marker).await.trim().parse().unwrap();
        #[cfg(target_os = "linux")]
        let descendant = FixtureDescendant::capture(pid);
        cancel.cancel();
        drop(metadata);
        // The fixture ignores TERM, and the launcher allows up to
        // LAUNCH_CLEANUP_TIMEOUT (5 s) for confirmed termination, so on a
        // loaded host cancellation and cleanup take longer than they do
        // alone. The bound only catches a hang; the outcome is asserted below.
        let record = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            record.state,
            v1::SessionLifecycleState::Failed as i32,
            "pty={pty}: {}",
            record.status_message
        );
        assert!(!record.cleanup_unknown);
        assert!(!alive(pid));
        #[cfg(target_os = "linux")]
        descendant.reap();
        engine.shutdown().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

#[tokio::test]
async fn acknowledged_host_input_accepts_maximum_and_times_out_without_replay_or_wedged_stop() {
    #[cfg(target_os = "linux")]
    if isolated_descendant_fixture(
        "acknowledged_host_input_accepts_maximum_and_times_out_without_replay_or_wedged_stop",
    )
    .await
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let draining = engine
        .launch(request("cat >/dev/null", false))
        .await
        .unwrap();
    engine
        .send_input(&draining.session_id, vec![b'x'; SESSION_INPUT_MAX_BYTES])
        .await
        .unwrap();
    #[cfg(target_os = "linux")]
    let (_draining_leader, draining_descendants) = FixtureDescendant::capture_fixture_descendants();
    engine.stop(&draining.session_id).await.unwrap();
    #[cfg(target_os = "linux")]
    for descendant in draining_descendants {
        assert!(!alive(descendant.pid));
        descendant.reap();
    }
    let blocked = engine.launch(request("sleep 60", false)).await.unwrap();
    // Pipe capacity varies by host. Each successful acknowledgement is a new
    // write; stop on the FIRST ambiguous result, never replay a timed-out write.
    let mut ambiguous = None;
    for number in 0..64 {
        match engine
            .send_input(&blocked.session_id, vec![number; SESSION_INPUT_MAX_BYTES])
            .await
        {
            Ok(()) => {}
            Err(error) => {
                ambiguous = Some(error);
                break;
            }
        }
    }
    assert!(
        matches!(ambiguous, Some(SessionError::DeadlineExceeded(_))),
        "{ambiguous:?}"
    );
    #[cfg(target_os = "linux")]
    let (_blocked_leader, blocked_descendants) = FixtureDescendant::capture_fixture_descendants();
    let stopped = tokio::time::timeout(Duration::from_secs(3), engine.stop(&blocked.session_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stopped.state,
        v1::SessionLifecycleState::Stopped as i32,
        "{}",
        stopped.status_message
    );
    #[cfg(target_os = "linux")]
    for descendant in blocked_descendants {
        assert!(!alive(descendant.pid));
        descendant.reap();
    }
    engine.shutdown().await.unwrap();
    #[cfg(target_os = "linux")]
    assert_no_fixture_children();
}

#[tokio::test]
async fn host_recovery_rejects_state_links_without_reading_home_records() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let id = engine.create_session_id().await.unwrap();
    let external = temp.path().join("home/.codewire/session.json");
    std::fs::create_dir_all(external.parent().unwrap()).unwrap();
    std::fs::write(&external, b"must-not-read-as-host-metadata").unwrap();
    std::os::unix::fs::symlink(&external, engine.inner.root.join(id).join(METADATA_FILE)).unwrap();
    let recovered = host_engine(temp.path());
    let error = recovered.list().await.unwrap_err();
    assert!(error.to_string().contains("only regular files"));
    assert_eq!(
        std::fs::read(external).unwrap(),
        b"must-not-read-as-host-metadata"
    );
}

#[tokio::test]
async fn restart_cannot_overwrite_cleanup_fence_published_by_its_dispatched_stop() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let marker = temp.path().join("must-not-restart");
    let handle = tests::pending_handle(&engine, &marker).await;
    let id = {
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Running as i32;
        metadata.cleanup_unknown = false;
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
        metadata.session_id.clone()
    };
    let (control, mut receiver) = mpsc::channel(1);
    let stopping = handle.clone();
    let inner = engine.inner.clone();
    let stopping_id = id.clone();
    let task = tokio::spawn(async move {
        let Some(SessionControl::Stop { reply }) = receiver.recv().await else {
            panic!("restart must first dispatch Stop")
        };
        let mut metadata = stopping.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Interrupted as i32;
        metadata.cleanup_unknown = true;
        metadata.finished_at = Some(PersistedTimestamp::now());
        persist_metadata(&inner.root, &metadata).await.unwrap();
        lock(&inner.active).remove(&stopping_id);
        let _ = reply.send(());
    });
    lock(&engine.inner.active).insert(
        id.clone(),
        ActiveSession {
            token: Uuid::new_v4(),
            control,
            task,
        },
    );
    assert!(matches!(
        engine.restart(&id).await,
        Err(SessionError::NeverRestarts(
            NeverRestarts::CleanupUnconfirmed,
            _
        ))
    ));
    assert!(engine.get(&id).await.unwrap().cleanup_unknown);
    assert!(!marker.exists());
    assert!(engine.shutdown().await.is_err());
}

async fn assert_guarded_restart_has_no_effects(
    engine: &SessionEngine,
    id: &str,
    expected: u64,
) -> SessionError {
    let handle = engine.handle(id).unwrap();
    let before = engine.get(id).await.unwrap();
    let metadata_path = engine.inner.root.join(id).join(METADATA_FILE);
    let saved = tokio::fs::read(&metadata_path).await.unwrap();
    let cancellation = *handle.launch_cancellation.borrow();
    let active = lock(&engine.inner.active)
        .get(id)
        .map(|active| active.token);
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        engine.restart_with_generation(id, Some(expected)),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(engine.get(id).await.unwrap(), before);
    assert_eq!(tokio::fs::read(metadata_path).await.unwrap(), saved);
    assert_eq!(*handle.launch_cancellation.borrow(), cancellation);
    assert_eq!(
        lock(&engine.inner.active)
            .get(id)
            .map(|active| active.token),
        active
    );
    error
}

#[tokio::test]
async fn guarded_restart_duplicate_callers_cannot_stop_an_admitted_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let pid_path = temp.path().join("peer.pid");
    let launches = temp.path().join("launches");
    let command = format!(
        "printf x >> '{}'; printf '%s' \"$$\" > '{}'; exec sleep 60",
        launches.display(),
        pid_path.display()
    );
    let original = engine.launch(request(&command, false)).await.unwrap();
    assert_eq!(original.launch_generation, 1);
    let original_pid: u32 = wait_file(&pid_path).await.parse().unwrap();
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&engine, &original.session_id, 1).await,
        SessionError::FailedPrecondition(_)
    ));
    assert!(alive(original_pid));
    engine.stop(&original.session_id).await.unwrap();
    assert!(!alive(original_pid));
    tokio::fs::remove_file(&pid_path).await.unwrap();

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let engine = engine.clone();
        let id = original.session_id.clone();
        let barrier = barrier.clone();
        calls.spawn(async move {
            barrier.wait().await;
            engine.restart_with_generation(&id, Some(1)).await
        });
    }
    barrier.wait().await;
    let mut admitted = Vec::new();
    let mut refused = 0;
    while let Some(result) = tokio::time::timeout(Duration::from_secs(3), calls.join_next())
        .await
        .unwrap()
    {
        match result.unwrap() {
            Ok(record) => admitted.push(record),
            Err(SessionError::FailedPrecondition(_)) => refused += 1,
            other => panic!("unexpected guarded admission: {other:?}"),
        }
    }
    assert_eq!(admitted.len(), 1);
    assert_eq!(refused, 1);
    assert_eq!(admitted[0].launch_generation, 2);
    let replacement_pid: u32 = wait_file(&pid_path).await.parse().unwrap();
    assert!(alive(replacement_pid));
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&engine, &original.session_id, 1).await,
        SessionError::FailedPrecondition(_)
    ));
    assert!(alive(replacement_pid));
    assert_eq!(tokio::fs::read_to_string(launches).await.unwrap(), "xx");
    engine.shutdown().await.unwrap();
    assert!(!alive(replacement_pid));
}

#[tokio::test]
async fn guarded_restart_cancelled_while_waiting_cannot_cancel_or_consume_an_incarnation() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let marker = temp.path().join("must-not-spawn");
    let handle = tests::pending_handle(&engine, &marker).await;
    let id = {
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Stopped as i32;
        metadata.cleanup_unknown = false;
        metadata.cleanup_confirmed = true;
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
        metadata.session_id.clone()
    };
    let before = engine.get(&id).await.unwrap();
    let held_operation = handle.operation.lock().await;
    let (entered, observed) = oneshot::channel();
    let (settled, finished) = oneshot::channel();
    let owner = engine.clone();
    let worker = engine.clone();
    let worker_id = id.clone();
    let caller = tokio::spawn(async move {
        owner
            .own_launch(move |cancel| async move {
                let _ = entered.send(());
                let result = worker.restart_inner(&worker_id, Some(1), cancel).await;
                let _ = settled.send(());
                result
            })
            .await
    });
    observed.await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if engine.inner.retention_admission.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    assert!(handle.operation.try_lock().is_err());
    assert!(!caller.is_finished());
    assert!(!*handle.launch_cancellation.borrow());
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(3), finished)
        .await
        .unwrap()
        .unwrap();
    assert!(!*handle.launch_cancellation.borrow());
    assert_eq!(engine.get(&id).await.unwrap(), before);
    assert!(!marker.exists());
    drop(held_operation);
    let admitted = engine.restart_with_generation(&id, Some(1)).await.unwrap();
    assert_eq!(admitted.launch_generation, 2);
    assert_eq!(wait_file(&marker).await, "spawned");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn guarded_restart_lost_response_keeps_new_process_and_consumed_generation() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let pid_path = temp.path().join("peer.pid");
    let command = format!(
        "printf '%s' \"$$\" > '{}'; exec sleep 60",
        pid_path.display()
    );
    let original = engine.launch(request(&command, false)).await.unwrap();
    wait_file(&pid_path).await;
    engine.stop(&original.session_id).await.unwrap();
    tokio::fs::remove_file(&pid_path).await.unwrap();
    let (handed_off, observed) = oneshot::channel();
    let (settled, finished) = oneshot::channel();
    let owner = engine.clone();
    let worker = engine.clone();
    let id = original.session_id.clone();
    let caller = tokio::spawn(async move {
        owner
            .own_launch(move |cancel| async move {
                let record = worker.restart_inner(&id, Some(1), cancel.clone()).await?;
                handed_off.send(record.clone()).unwrap();
                // The restart is admitted, but its RPC caller has not received
                // the result. Lose that caller after monitor handoff.
                cancel.cancelled().await;
                let _ = settled.send(());
                Ok(record)
            })
            .await
    });
    let admitted = tokio::time::timeout(Duration::from_secs(3), observed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admitted.launch_generation, 2);
    let replacement_pid: u32 = wait_file(&pid_path).await.parse().unwrap();
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(3), finished)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&engine, &original.session_id, 1).await,
        SessionError::FailedPrecondition(_)
    ));
    assert!(alive(replacement_pid));
    engine.shutdown().await.unwrap();
    assert!(!alive(replacement_pid));
    let recovered = host_engine(temp.path());
    assert_eq!(
        recovered
            .get(&original.session_id)
            .await
            .unwrap()
            .launch_generation,
        2
    );
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&recovered, &original.session_id, 1).await,
        SessionError::FailedPrecondition(_)
    ));
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn guarded_restart_failed_launch_consumes_generation_across_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let original = engine
        .launch(request("exec sleep 60", false))
        .await
        .unwrap();
    engine.stop(&original.session_id).await.unwrap();
    let handle = engine.handle(&original.session_id).unwrap();
    {
        let mut metadata = handle.metadata.lock().await;
        metadata.command = vec![
            temp.path()
                .join("absent-executable")
                .to_string_lossy()
                .into_owned(),
        ];
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
    }
    let failed = engine
        .restart_with_generation(&original.session_id, Some(1))
        .await
        .unwrap();
    assert_eq!(failed.state, v1::SessionLifecycleState::Failed as i32);
    assert_eq!(failed.launch_generation, 2);
    assert!(failed.started_at.is_none());
    assert!(!failed.cleanup_unknown);
    engine.shutdown().await.unwrap();
    drop(handle);
    drop(engine);
    let recovered = host_engine(temp.path());
    assert_eq!(recovered.get(&original.session_id).await.unwrap(), failed);
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&recovered, &original.session_id, 1).await,
        SessionError::FailedPrecondition(_)
    ));
    let next = recovered
        .restart_with_generation(&original.session_id, Some(2))
        .await
        .unwrap();
    assert_eq!(next.state, v1::SessionLifecycleState::Failed as i32);
    assert_eq!(next.launch_generation, 3);
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn guarded_restart_rejects_unknown_cleanup_and_exhaustion_before_effects() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let marker = temp.path().join("must-not-spawn");
    let handle = tests::pending_handle(&engine, &marker).await;
    let id = handle.metadata.lock().await.session_id.clone();
    for state in [
        v1::SessionLifecycleState::Unspecified,
        v1::SessionLifecycleState::Starting,
        v1::SessionLifecycleState::Running,
        v1::SessionLifecycleState::Stopping,
    ] {
        {
            let mut metadata = handle.metadata.lock().await;
            metadata.state = state as i32;
            metadata.cleanup_unknown = false;
            persist_metadata(&engine.inner.root, &metadata)
                .await
                .unwrap();
        }
        assert!(matches!(
            assert_guarded_restart_has_no_effects(&engine, &id, 1).await,
            SessionError::FailedPrecondition(_)
        ));
    }
    {
        let mut metadata = handle.metadata.lock().await;
        metadata.state = v1::SessionLifecycleState::Stopped as i32;
        metadata.cleanup_unknown = true;
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
    }
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&engine, &id, 1).await,
        SessionError::NeverRestarts(NeverRestarts::CleanupUnconfirmed, _)
    ));
    {
        let mut metadata = handle.metadata.lock().await;
        metadata.launch_generation = u64::MAX;
        metadata.cleanup_unknown = false;
        metadata.cleanup_confirmed = true;
        persist_metadata(&engine.inner.root, &metadata)
            .await
            .unwrap();
    }
    for expected in [0, u64::MAX - 1] {
        assert!(matches!(
            assert_guarded_restart_has_no_effects(&engine, &id, expected).await,
            SessionError::FailedPrecondition(_)
        ));
    }
    assert!(matches!(
        assert_guarded_restart_has_no_effects(&engine, &id, u64::MAX).await,
        SessionError::NeverRestarts(NeverRestarts::GenerationExhausted, _)
    ));
    assert!(!marker.exists());
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn guarded_restart_legacy_records_remain_unfenced_until_actual_new_admission() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let original = engine
        .launch(request("exec sleep 60", false))
        .await
        .unwrap();
    engine.shutdown().await.unwrap();
    drop(engine);
    let path = temp
        .path()
        .join("state/sessions")
        .join(&original.session_id)
        .join(METADATA_FILE);
    let mut saved: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    saved.as_object_mut().unwrap().remove("launch_generation");
    tokio::fs::write(&path, serde_json::to_vec(&saved).unwrap())
        .await
        .unwrap();
    let recovered = host_engine(temp.path());
    assert_eq!(
        recovered
            .get(&original.session_id)
            .await
            .unwrap()
            .launch_generation,
        0
    );
    for expected in [0, 1] {
        assert!(matches!(
            assert_guarded_restart_has_no_effects(&recovered, &original.session_id, expected).await,
            SessionError::FailedPrecondition(_)
        ));
    }
    let replacement = recovered.restart(&original.session_id).await.unwrap();
    assert_eq!(replacement.launch_generation, 1);
    assert_eq!(replacement.state, v1::SessionLifecycleState::Running as i32);
    recovered.shutdown().await.unwrap();
}

/// A process outside every owned session. It must not keep another test's
/// socket or pipe open, so on Darwin it gets the host launch's descriptor sweep.
fn unrelated_sleep() -> tokio::process::Child {
    let mut command = tokio::process::Command::new("/bin/sleep");
    // SAFETY: the sweep makes only scalar libc calls.
    #[cfg(target_os = "macos")]
    unsafe {
        command.pre_exec(|| {
            super::mark_inherited_descriptors_close_on_exec();
            Ok(())
        });
    }
    command.arg("60").kill_on_drop(true).spawn().unwrap()
}
