//! Proposed owning fixtures: real SessionEngine child/pipe/pidfd and barriers,
//! synthetic platform metadata only. They do NOT prove an actual platform
//! image, Pod channel, provider launch, guardian or public durable request.
use super::*;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

struct Fixture {
    temp: tempfile::TempDir,
    engine: SessionEngine,
    origin: Origin,
    session: String,
    handle: Arc<SessionHandle>,
    pidfd: OwnedFd,
    pid: u32,
    birth: u64,
}
fn birth(pid: u32) -> u64 {
    let file = std::fs::File::open(format!("/proc/{pid}/stat")).unwrap();
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text).unwrap();
    assert!(text.len() <= 4096);
    text.rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}
fn terminal(pidfd: &OwnedFd) -> bool {
    let mut item = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut item, 1, 0) == 1 }
}
async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
impl Fixture {
    async fn spawn() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_owned(),
            home_root: temp.path().to_owned(),
            auth_token: crate::DaemonAuthToken::new("synthetic-platform-fence").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
        };
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        let record = engine.launch(v1::LaunchSessionRequest {
            command: vec!["/bin/sh".into(), "-c".into(),
                "printf '%s' \"$$\" > pid; : > ready; while IFS= read -r line; do [ \"$line\" = exit ] && exit 0; printf '%s\\n' \"$line\" >> received; done".into()],
            ..Default::default()
        }).await.unwrap();
        wait_file(&temp.path().join("ready")).await;
        let pid: u32 = std::fs::read_to_string(temp.path().join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        let start_ticks = birth(pid);
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0);
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let session = record.session_id;
        let driver = session.strip_prefix("session-").unwrap().to_owned();
        let origin = Origin {
            version: 1,
            environment_id: Uuid::new_v4().to_string(),
            org_id: "fixture-org".into(),
            pod_uid: Uuid::new_v4().to_string(),
            binding_generation: u64::MAX,
            projection_selection_sha256: [7; 32],
            driver_id: driver,
            agent: crate::platform_managed::Agent::Codex,
            support_image_sha256: [8; 32],
            support_image_size: 1024,
            provider: crate::platform_managed::ProviderIdentity {
                sha256: [9; 32],
                size: 1024,
                version: "0.157.0".into(),
            },
            parent_generation: None,
        };
        let handle = engine.handle(&session).unwrap();
        {
            let _operation = handle.operation.lock().await;
            let mut metadata = handle.metadata.lock().await;
            // Isolate the locking/refusal model while retaining an actual child.
            // The test does not present the shell as a verified CW driver image.
            metadata.platform_managed_origin = Some(origin.clone());
            metadata.command = origin.command();
            persist_metadata(&engine.inner.root, &metadata)
                .await
                .unwrap();
        }
        assert!(!terminal(&pidfd));
        assert_eq!(birth(pid), start_ticks);
        Self {
            temp,
            engine,
            origin,
            session,
            handle,
            pidfd,
            pid,
            birth: start_ticks,
        }
    }
    async fn close(self) {
        // Exact owned original monitor, not ordinary managed bypass or PID kill.
        {
            let _operation = self.handle.operation.lock().await;
            let _ = self
                .engine
                .stop_active(&self.session, &self.handle)
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while !terminal(&self.pidfd) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        self.engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn platform_managed_generation_writer_blocks_until_original_pipe_effect_finishes() {
    let fixture = Fixture::spawn().await;
    let (entered, started) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let engine = fixture.engine.clone();
    let origin = fixture.origin.clone();
    let session = fixture.session.clone();
    let owner = tokio::spawn(async move {
        engine
            .with_platform_incarnation(&origin, &session, 1, |captured| async move {
                let _ = entered.send(());
                released.await.map_err(|_| Error::Unknown)?;
                let (reply, received) = oneshot::channel();
                captured
                    .control
                    .ok_or(Error::Unknown)?
                    .send(SessionControl::Input {
                        data: b"owned-before-generation\n".to_vec(),
                        reply,
                    })
                    .await
                    .map_err(|_| Error::Unknown)?;
                received
                    .await
                    .map_err(|_| Error::Unknown)?
                    .map_err(|_| Error::Unknown)
            })
            .await
    });
    started.await.unwrap();
    let handle = fixture.handle.clone();
    let (advanced, mut advance) = oneshot::channel();
    let writer = tokio::spawn(async move {
        let _operation = handle.operation.lock().await;
        handle.metadata.lock().await.launch_generation = 2;
        let _ = advanced.send(());
    });
    let blocked = tokio::time::timeout(Duration::from_millis(50), &mut advance)
        .await
        .is_err();
    release.send(()).unwrap();
    let effect = owner.await.unwrap();
    advance.await.unwrap();
    writer.await.unwrap();
    wait_file(&fixture.temp.path().join("received")).await;
    let bytes = std::fs::read(fixture.temp.path().join("received")).unwrap();
    let stale_effect = fixture.temp.path().join("stale-effect");
    let stale = fixture
        .engine
        .with_platform_incarnation(&fixture.origin, &fixture.session, 1, |_| async {
            std::fs::write(&stale_effect, b"must-not-run").unwrap();
            Ok(())
        })
        .await;
    let absent = !stale_effect.exists();
    let live = !terminal(&fixture.pidfd) && birth(fixture.pid) == fixture.birth;
    fixture.close().await;
    assert!(blocked && effect.is_ok() && absent && live);
    assert!(matches!(stale, Err(Error::Refused)));
    assert_eq!(bytes, b"owned-before-generation\n");
}

#[tokio::test]
async fn platform_managed_ordinary_input_stop_restart_refuse_without_cancellation_or_effect() {
    let fixture = Fixture::spawn().await;
    let before = serde_json::to_vec(&*fixture.handle.metadata.lock().await).unwrap();
    let token = lock(&fixture.engine.inner.active)
        .get(&fixture.session)
        .unwrap()
        .token;
    let input = fixture
        .engine
        .input(&fixture.session, b"ordinary\n".to_vec())
        .await;
    let stop = fixture.engine.stop(&fixture.session).await;
    let restart = fixture.engine.restart(&fixture.session).await;
    let guarded = fixture
        .engine
        .restart_with_generation(&fixture.session, Some(1))
        .await;
    let after = serde_json::to_vec(&*fixture.handle.metadata.lock().await).unwrap();
    let unchanged = !*fixture.handle.launch_cancellation.borrow()
        && lock(&fixture.engine.inner.active)
            .get(&fixture.session)
            .unwrap()
            .token
            == token
        && !fixture.temp.path().join("received").exists()
        && !terminal(&fixture.pidfd)
        && birth(fixture.pid) == fixture.birth;
    fixture.close().await;
    assert!(matches!(input, Err(SessionError::FailedPrecondition(_))));
    for result in [stop, restart, guarded] {
        assert!(matches!(result, Err(SessionError::FailedPrecondition(_))));
    }
    assert!(unchanged);
    assert_eq!(before, after);
}

#[tokio::test]
async fn platform_managed_changed_origin_and_legacy_refuse_before_guarded_effect() {
    let fixture = Fixture::spawn().await;
    let marker = fixture.temp.path().join("forbidden");
    let mut foreign = fixture.origin.clone();
    foreign.pod_uid = Uuid::new_v4().to_string();
    let mismatch = fixture
        .engine
        .with_platform_incarnation(&foreign, &fixture.session, 1, |_| async {
            std::fs::write(&marker, b"bad").unwrap();
            Ok(())
        })
        .await;
    {
        let _operation = fixture.handle.operation.lock().await;
        fixture.handle.metadata.lock().await.platform_managed_origin = None;
    }
    let legacy = fixture
        .engine
        .with_platform_incarnation(&fixture.origin, &fixture.session, 1, |_| async {
            std::fs::write(&marker, b"bad").unwrap();
            Ok(())
        })
        .await;
    let absent = !marker.exists();
    fixture.close().await;
    assert!(matches!(mismatch, Err(Error::Refused)));
    assert!(matches!(legacy, Err(Error::Refused)));
    assert!(absent);
}

#[test]
fn platform_managed_origin_serialization_preserves_full_u64_and_denies_unknown_fields() {
    let origin = Origin {
        version: 1,
        environment_id: Uuid::new_v4().to_string(),
        org_id: "org".into(),
        pod_uid: Uuid::new_v4().to_string(),
        binding_generation: u64::MAX,
        projection_selection_sha256: [1; 32],
        driver_id: Uuid::new_v4().to_string(),
        agent: crate::platform_managed::Agent::Codex,
        support_image_sha256: [2; 32],
        support_image_size: 1024,
        provider: crate::platform_managed::ProviderIdentity {
            sha256: [3; 32],
            size: 1024,
            version: "0.157.0".into(),
        },
        parent_generation: None,
    };
    let bytes = serde_json::to_vec(&origin).unwrap();
    let saved: Origin = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved, origin);
    let mut unknown = serde_json::to_value(origin).unwrap();
    unknown["program"] = json!("untrusted");
    assert!(serde_json::from_value::<Origin>(unknown).is_err());
}

#[tokio::test]
async fn platform_managed_caller_drop_keeps_owned_original_pipe_effect_until_settled() {
    let fixture = Fixture::spawn().await;
    let (entered, started) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (settled, finished) = oneshot::channel();
    let owner = fixture.engine.clone();
    let worker = fixture.engine.clone();
    let origin = fixture.origin.clone();
    let session = fixture.session.clone();
    let caller = tokio::spawn(async move {
        owner
            .own_platform_effect(async move {
                let result = worker
                    .with_platform_incarnation(&origin, &session, 1, |captured| async move {
                        let _ = entered.send(());
                        released.await.map_err(|_| Error::Unknown)?;
                        let (reply, ack) = oneshot::channel();
                        captured
                            .control
                            .ok_or(Error::Unknown)?
                            .send(SessionControl::Input {
                                data: b"owned-after-caller-drop\n".to_vec(),
                                reply,
                            })
                            .await
                            .map_err(|_| Error::Unknown)?;
                        ack.await
                            .map_err(|_| Error::Unknown)?
                            .map_err(|_| Error::Unknown)
                    })
                    .await;
                let _ = settled.send(result.is_ok());
                result
            })
            .await
    });
    started.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let pending = !fixture.engine.inner.launches.is_empty();
    release.send(()).unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(3), finished)
        .await
        .unwrap()
        .unwrap();
    wait_file(&fixture.temp.path().join("received")).await;
    let bytes = std::fs::read(fixture.temp.path().join("received")).unwrap();
    let original = !terminal(&fixture.pidfd) && birth(fixture.pid) == fixture.birth;
    fixture.close().await;
    assert!(pending && completed && original);
    assert_eq!(bytes, b"owned-after-caller-drop\n");
}

#[tokio::test]
async fn platform_managed_shutdown_closes_effect_admission_without_running_it() {
    let fixture = Fixture::spawn().await;
    let marker = fixture.temp.path().join("after-shutdown");
    fixture.engine.cancel_launches();
    let result = fixture
        .engine
        .own_platform_effect(async {
            std::fs::write(marker, b"must-not-run").unwrap();
            Ok(())
        })
        .await;
    let absent = !fixture.temp.path().join("after-shutdown").exists();
    fixture.close().await;
    assert!(matches!(result, Err(Error::Refused)));
    assert!(absent);
}
