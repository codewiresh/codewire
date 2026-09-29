use super::*;

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
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[tokio::test]
async fn host_stop_owns_shell_descendants_for_pipe_and_pty_preserving_unrelated_child() {
    for pty in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let engine = host_engine(temp.path());
        let mut unrelated = tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
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
        let stopped = tokio::time::timeout(Duration::from_secs(4), engine.stop(&record.session_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.state, v1::SessionLifecycleState::Stopped as i32);
        assert!(!stopped.cleanup_unknown);
        assert!(
            !alive(descendant_pid),
            "ordinary descendant survived host Stop (pty={pty})"
        );
        assert!(alive(unrelated_pid), "unrelated process was signaled");
        assert!(!temp.path().join("home/.codewire").exists());
        engine.shutdown().await.unwrap();
        unrelated.kill().await.unwrap();
    }
}

#[tokio::test]
async fn host_exit_cleans_remaining_descendants_before_reaping_group_leader() {
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
        assert_eq!(ended.state, v1::SessionLifecycleState::Exited as i32);
        assert_eq!(ended.exit_code, Some(7));
        assert!(!ended.cleanup_unknown);
        assert!(!alive(pid));
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn host_shutdown_cleans_owned_groups_and_records_confirmed_completion() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    let mut ids = Vec::new();
    for pty in [false, true] {
        let path = temp.path().join(format!("descendant-{pty}.pid"));
        let script = format!(
            "trap '' TERM; sleep 60 & echo $! > '{}'; wait",
            path.display()
        );
        let record = engine.launch(request(&script, pty)).await.unwrap();
        let pid: u32 = wait_file(&path).await.trim().parse().unwrap();
        ids.push((record.session_id, pid));
    }
    tokio::time::timeout(Duration::from_secs(5), engine.shutdown())
        .await
        .unwrap()
        .unwrap();
    let recovered = host_engine(temp.path());
    for (id, pid) in ids {
        assert!(!alive(pid));
        let record = recovered.get(&id).await.unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Stopped as i32);
        assert!(!record.cleanup_unknown);
    }
}

#[tokio::test]
async fn recovered_host_live_records_are_fenced_without_signaling_persisted_pid() {
    let temp = tempfile::tempdir().unwrap();
    let engine = host_engine(temp.path());
    engine.ensure_initialized().await.unwrap();
    let mut unrelated = tokio::process::Command::new("/bin/sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for state in [
        v1::SessionLifecycleState::Starting,
        v1::SessionLifecycleState::Running,
        v1::SessionLifecycleState::Stopping,
    ] {
        let session_id = engine.create_session_id().await.unwrap();
        let metadata = PersistedSession {
            session_id: session_id.clone(),
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
            Err(SessionError::FailedPrecondition(_))
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
        Err(SessionError::FailedPrecondition(message))
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
        Err(SessionError::FailedPrecondition(_))
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
    // Interactive bash puts jobs in a separate group in the same owned session.
    assert_ne!(unsafe { libc::getpgid(pid as i32) }, unsafe {
        libc::getsid(pid as i32)
    });
    let stopped = engine.stop(&record.session_id).await.unwrap();
    assert_eq!(stopped.state, v1::SessionLifecycleState::Stopped as i32);
    assert!(!stopped.cleanup_unknown);
    assert!(!alive(pid));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn host_launch_cancellation_cleans_spawned_descendants_before_failed_acknowledgement() {
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
        cancel.cancel();
        drop(metadata);
        let record = tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Failed as i32);
        assert!(!record.cleanup_unknown);
        assert!(!alive(pid));
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn acknowledged_host_input_accepts_maximum_and_times_out_without_replay_or_wedged_stop() {
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
    engine.stop(&draining.session_id).await.unwrap();
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
    let stopped = tokio::time::timeout(Duration::from_secs(3), engine.stop(&blocked.session_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.state, v1::SessionLifecycleState::Stopped as i32);
    engine.shutdown().await.unwrap();
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
        Err(SessionError::FailedPrecondition(_))
    ));
    assert!(engine.get(&id).await.unwrap().cleanup_unknown);
    assert!(!marker.exists());
    assert!(engine.shutdown().await.is_err());
}
