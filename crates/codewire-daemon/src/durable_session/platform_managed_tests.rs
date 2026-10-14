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
            session_working_dir: None,
        };
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        let record = engine.launch(v1::LaunchSessionRequest {
            command: vec!["/bin/sh".into(), "-c".into(),
                "printf '%s' \"$$\" > pid; : > ready; while IFS= read -r line; do [ \"$line\" = exit ] && exit 0; printf '%s\\n' \"$line\" >> received && : > received-complete; done".into()],
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
                version: "0.160.0".into(),
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
    // Redirection creates `received` before printf finishes writing its bytes.
    wait_file(&fixture.temp.path().join("received-complete")).await;
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

/// A managed agent's driver is prepared exactly as an ordinary session is:
/// the one shared environment, then the launch projection through the same
/// launcher and rendezvous, so the application-secret environment reaches it
/// with the same per-launch authority check. Synthetic records, a synthetic
/// daemon environment and a real prepared process; nothing is spawned, and
/// no image or broker is proved.
#[tokio::test]
async fn platform_managed_driver_is_prepared_through_the_launch_projection_like_any_session() {
    use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _};
    const TOKEN: &str = "synthetic-platform-projection-token";
    let temp = tempfile::tempdir().unwrap();
    let processes = temp.path().join("processes");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&processes)
        .unwrap();
    // Stands in for the installed cw with its hidden launcher entry point.
    let helper = std::fs::canonicalize("/bin/sh").unwrap();
    let environment = Uuid::new_v4();
    let driver = Uuid::new_v4().to_string();
    let bridge = crate::CredentialBridgeConfig {
        transport: crate::CredentialBridgeTransport::Hosted,
        environment_id: environment,
        environment_generation: 7,
        ingress_socket: temp.path().join("credentials.sock"),
        ingress_uid: unsafe { libc::geteuid() },
        ingress_gid: unsafe { libc::getegid() },
    };
    let selected =
        codewire_access::ManagedCredentialClients::from_profile_slots(["codex", "github", "ssh"])
            .unwrap();
    let mut config = Config {
        listen_addr: "unused:0".into(),
        workspace_root: temp.path().to_owned(),
        home_root: temp.path().to_owned(),
        auth_token: crate::DaemonAuthToken::new(TOKEN).unwrap(),
        process_execution: ProcessExecution::Native,
        credential_bridge: Some(bridge.clone()),
        managed_credential_clients: selected,
        host: None,
        launch_projection: Some(crate::LaunchProjectionConfig {
            selection_sha256: [7; 32],
            native: Some(crate::NativeLaunchProjectionConfig {
                helper_path: helper.clone(),
                process_directory: processes.clone(),
            }),
        }),
        session_working_dir: None,
    };
    let origin = Origin {
        version: 1,
        environment_id: environment.to_string(),
        org_id: "fixture-org".into(),
        pod_uid: Uuid::new_v4().to_string(),
        binding_generation: 7,
        projection_selection_sha256: [7; 32],
        driver_id: driver.clone(),
        agent: crate::platform_managed::Agent::Codex,
        support_image_sha256: [8; 32],
        support_image_size: 1024,
        provider: crate::platform_managed::ProviderIdentity {
            sha256: [9; 32],
            size: 1024,
            version: "0.160.0".into(),
        },
        parent_generation: None,
    };
    let session = |command: Vec<String>, origin: Option<Origin>| PersistedSession {
        session_id: format!("session-{driver}"),
        control_origin: None,
        platform_managed_origin: origin,
        launch_generation: 1,
        name: String::new(),
        parent_session_id: None,
        state: v1::SessionLifecycleState::Starting as i32,
        command,
        working_dir: temp.path().to_string_lossy().into_owned(),
        env: Vec::new(),
        environment_projection_required: false,
        pty: false,
        term: String::new(),
        width: 0,
        height: 0,
        created_at: PersistedTimestamp::now(),
        started_at: None,
        finished_at: None,
        exit_code: None,
        output_start_offset: 0,
        output_end_offset: 0,
        cleanup_confirmed: false,
        cleanup_unknown: true,
        status_message: String::new(),
    };
    let ordinary = session(vec!["/bin/sh".into(), "-c".into(), "exit 0".into()], None);
    let managed = session(origin.command(), Some(origin.clone()));
    // The daemon's own environment as a hosted Pod renders it: its internal
    // configuration beside what a session may see. Nothing of the environment
    // this test runs in is read.
    let daemon_environment = || {
        [
            (crate::config::DAEMON_AUTH_TOKEN_ENV, TOKEN),
            (
                crate::config::MANAGED_CREDENTIAL_CLIENTS_ENV,
                selected.encode(),
            ),
            ("CODEWIRE_ENVIRONMENT_ID", "synthetic-environment"),
            ("HOME", "/home/codewire"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("IMAGE_VALUE", "visible"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    };
    // What the daemon would start: the program, its arguments and the
    // environment it supplies before the projection is added.
    let describe = |prepared: &PreparedProcess| {
        let command = prepared.tokio_command();
        let command = command.as_std();
        let text = |value: &std::ffi::OsStr| value.to_str().unwrap().to_owned();
        (
            command.get_program().to_owned(),
            command.get_args().map(text).collect::<Vec<_>>(),
            command
                .get_envs()
                .map(|(name, value)| (text(name), text(value.unwrap())))
                .collect::<BTreeMap<_, _>>(),
        )
    };

    let credential_bridge = CredentialBridge::new(Some(bridge));
    let prepared_ordinary =
        prepare_pipe_process(&config, &credential_bridge, &ordinary, daemon_environment()).unwrap();
    let prepared_managed =
        prepare_pipe_process(&config, &credential_bridge, &managed, daemon_environment()).unwrap();
    let (ordinary_program, ordinary_arguments, ordinary_environment) = describe(&prepared_ordinary);
    let (managed_program, managed_arguments, managed_environment) = describe(&prepared_managed);
    // Both run the projection launcher, each with its own one-launch
    // rendezvous socket in the daemon's private directory, then the command.
    for (program, arguments, command) in [
        (&ordinary_program, &ordinary_arguments, &ordinary.command),
        (&managed_program, &managed_arguments, &managed.command),
    ] {
        assert_eq!(program.as_os_str(), helper.as_os_str());
        assert_eq!(
            arguments[..2],
            ["__environment-launch", "--projection-socket"]
        );
        let socket = Path::new(&arguments[2]);
        assert_eq!(socket.parent(), Some(processes.as_path()));
        assert!(
            std::fs::symlink_metadata(socket)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(arguments[3], "--");
        assert_eq!(&arguments[4..], command.as_slice());
    }
    assert_ne!(ordinary_arguments[2], managed_arguments[2]);
    // The environment the projection is added to is the same shared one,
    // with the Git route and the signer socket. Only names are reported.
    let differing: Vec<&String> = ordinary_environment
        .keys()
        .chain(managed_environment.keys())
        .filter(|name| ordinary_environment.get(*name) != managed_environment.get(*name))
        .collect();
    assert!(differing.is_empty(), "{differing:?}");
    // GitHub with the SSH key rewrites GitHub's HTTPS and `git://` forms.
    assert!(managed_environment["GIT_CONFIG_COUNT"] == "2");
    assert!(managed_environment["SSH_AUTH_SOCK"] == codewire_access::SSH_PLATFORM_AUTH_SOCK);
    assert!(managed_environment["IMAGE_VALUE"] == "visible");
    // The daemon's internal configuration reaches neither launch: not as a
    // name, and the daemon token not as any value or argument.
    for (label, arguments, launch_environment) in [
        ("ordinary", &ordinary_arguments, &ordinary_environment),
        ("managed", &managed_arguments, &managed_environment),
    ] {
        for name in [
            crate::config::DAEMON_AUTH_TOKEN_ENV,
            crate::config::MANAGED_CREDENTIAL_CLIENTS_ENV,
        ] {
            assert!(!launch_environment.contains_key(name), "{label} {name}");
        }
        assert!(
            !launch_environment
                .values()
                .any(|value| value.contains(TOKEN) || value == selected.encode()),
            "{label} environment"
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains(TOKEN) || argument == selected.encode()),
            "{label} arguments"
        );
    }
    // A session record carries no value and no marker for it.
    assert!(managed.env.is_empty() && !managed.environment_projection_required);
    drop((prepared_ordinary, prepared_managed));

    // With no launch projection configured the same call starts both plainly:
    // the driver gets nothing an ordinary session would not.
    config.launch_projection = None;
    config.managed_credential_clients = Default::default();
    for snapshot in [&ordinary, &managed] {
        let prepared =
            prepare_pipe_process(&config, &credential_bridge, snapshot, daemon_environment())
                .unwrap();
        let (program, arguments, _) = describe(&prepared);
        assert_eq!(program.to_str(), Some(snapshot.command[0].as_str()));
        assert_eq!(arguments, snapshot.command[1..]);
    }
    // A selected projection never falls back to a plain launch.
    config.launch_projection = Some(crate::LaunchProjectionConfig {
        selection_sha256: [7; 32],
        native: None,
    });
    assert!(
        prepare_pipe_process(&config, &credential_bridge, &managed, daemon_environment()).is_err()
    );
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
            version: "0.160.0".into(),
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
    wait_file(&fixture.temp.path().join("received-complete")).await;
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

fn retained_config(root: &Path) -> Config {
    Config {
        listen_addr: "unused:0".into(),
        workspace_root: root.to_owned(),
        home_root: root.to_owned(),
        auth_token: crate::DaemonAuthToken::new("synthetic-platform-retained").unwrap(),
        process_execution: ProcessExecution::Native,
        credential_bridge: None,
        managed_credential_clients: Default::default(),
        host: None,
        launch_projection: None,
        session_working_dir: None,
    }
}

fn retained_scope(origin: &Origin) -> v1::PlatformManagedScope {
    v1::PlatformManagedScope {
        environment_id: origin.environment_id.clone(),
        org_id: origin.org_id.clone(),
        pod_uid: origin.pod_uid.clone(),
        binding_generation: origin.binding_generation,
        projection_selection_sha256: origin.projection_selection_sha256.to_vec(),
        support_image_sha256: origin.support_image_sha256.to_vec(),
        support_image_size: origin.support_image_size,
    }
}

/// The record an earlier daemon leaves: a real finished child's record carrying
/// a synthetic platform origin at `version`, saved as `state`.
async fn retain(
    engine: &SessionEngine,
    agent: crate::platform_managed::Agent,
    version: &str,
    state: v1::SessionLifecycleState,
) -> (String, Origin) {
    let session = engine
        .launch(v1::LaunchSessionRequest {
            command: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            ..Default::default()
        })
        .await
        .unwrap()
        .session_id;
    tokio::time::timeout(Duration::from_secs(3), async {
        while engine.get(&session).await.unwrap().state != v1::SessionLifecycleState::Exited as i32
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let origin = Origin {
        version: 1,
        environment_id: Uuid::new_v4().to_string(),
        org_id: "fixture-org".into(),
        pod_uid: Uuid::new_v4().to_string(),
        binding_generation: u64::MAX,
        projection_selection_sha256: [7; 32],
        driver_id: session.strip_prefix("session-").unwrap().to_owned(),
        agent,
        support_image_sha256: [8; 32],
        support_image_size: 1024,
        provider: crate::platform_managed::ProviderIdentity {
            sha256: [9; 32],
            size: 1024,
            version: version.into(),
        },
        parent_generation: None,
    };
    let handle = engine.handle(&session).unwrap();
    let _operation = handle.operation.lock().await;
    let mut metadata = handle.metadata.lock().await;
    metadata.platform_managed_origin = Some(origin.clone());
    metadata.command = origin.command();
    metadata.state = state as i32;
    persist_metadata(&engine.inner.root, &metadata)
        .await
        .unwrap();
    (session, origin)
}

#[tokio::test]
async fn platform_managed_records_an_earlier_provider_wrote_load_list_and_refuse_only_restart() {
    use crate::platform_managed::Agent;
    use v1::SessionLifecycleState as S;
    let temp = tempfile::tempdir().unwrap();
    let config = retained_config(temp.path());
    let writer = SessionEngine::new(&config, CredentialBridge::new(None));
    // Claude Code 2.1.238 left live by a daemon that stopped; Codex 0.157.0
    // finished; one record of this release's provider beside them.
    let claude = retain(&writer, Agent::Claude, "2.1.238", S::Running).await;
    let codex = retain(&writer, Agent::Codex, "0.157.0", S::Exited).await;
    let current = retain(&writer, Agent::Claude, "2.1.288", S::Exited).await;
    writer.shutdown().await.unwrap();

    let engine = SessionEngine::new(&config, CredentialBridge::new(None));
    let listed = engine.list().await.unwrap();
    assert_eq!(listed.len(), 3);
    assert!(engine.store_diagnostic().is_none());
    // Today's semantics: a record left live is interrupted on load.
    let interrupted = engine.get(&claude.0).await.unwrap();
    assert_eq!(interrupted.state, S::Interrupted as i32);
    assert_eq!(engine.get(&codex.0).await.unwrap().state, S::Exited as i32);
    for (session, origin) in [&claude, &codex, &current] {
        let page = engine
            .platform_list(&retained_scope(origin), "", 8)
            .await
            .unwrap();
        assert_eq!(page.sessions.len(), 1);
        assert_eq!(&page.sessions[0].session_id, session);
        // Stop's incarnation fence checks shape, not the provider pin.
        engine
            .with_platform_incarnation(origin, session, 1, |_| async { Ok(()) })
            .await
            .unwrap();
    }
    for ((session, _), product) in [(&claude, "Claude Code"), (&codex, "Codex")] {
        let refused = engine.platform_restartable(session).await.unwrap_err();
        assert!(matches!(refused, Error::EarlierProvider(_)));
        assert_eq!(
            refused.to_string(),
            format!(
                "this managed agent was started with an earlier {product}; start a new conversation"
            )
        );
    }
    engine.platform_restartable(&current.0).await.unwrap();
    // Launch admission and the driver spawn still require this release's pin.
    assert!(matches!(claude.1.validate(&claude.0), Err(Error::Refused)));
    assert!(matches!(codex.1.validate(&codex.0), Err(Error::Refused)));
    current.1.validate(&current.0).unwrap();
    // Ordinary control of a platform record refuses, as before.
    assert!(matches!(
        engine.restart(&claude.0).await,
        Err(SessionError::FailedPrecondition(_))
    ));
    // A new launch works beside them.
    let launched = engine
        .launch(v1::LaunchSessionRequest {
            command: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(launched.launch_generation, 1);
    assert_eq!(engine.list().await.unwrap().len(), 4);
    // Nothing was migrated: each record keeps the provider that wrote it.
    for (session, version) in [(&claude.0, "2.1.238"), (&codex.0, "0.157.0")] {
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(engine.inner.root.join(session).join(METADATA_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            saved["platform_managed_origin"]["provider"]["version"],
            version
        );
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn platform_managed_malformed_retained_record_refuses_the_store_with_its_reason() {
    const SENTINEL: &str = "retained-env-or-argument-must-not-be-reported";
    let temp = tempfile::tempdir().unwrap();
    let config = retained_config(temp.path());
    let writer = SessionEngine::new(&config, CredentialBridge::new(None));
    let (session, _) = retain(
        &writer,
        crate::platform_managed::Agent::Claude,
        "2.1.238",
        v1::SessionLifecycleState::Exited,
    )
    .await;
    writer.shutdown().await.unwrap();
    let path = temp
        .path()
        .join(SESSION_DIRECTORY)
        .join(&session)
        .join(METADATA_FILE);
    let saved: PersistedSession = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    type Damage = (fn(&mut PersistedSession), &'static str);
    let damage: [Damage; 5] = [
        (
            |r| r.platform_managed_origin.as_mut().unwrap().provider.version = "v?".into(),
            "the origin provider version is malformed",
        ),
        (
            |r| r.platform_managed_origin.as_mut().unwrap().org_id = " org".into(),
            "the origin organization is malformed",
        ),
        (
            |r| r.platform_managed_origin.as_mut().unwrap().pod_uid = "not-a-uuid".into(),
            "an origin identity is not a canonical UUID",
        ),
        (
            |r| r.env = vec![format!("TOKEN={SENTINEL}")],
            "it carries an environment",
        ),
        (
            |r| r.command.push(SENTINEL.into()),
            "its command is not its fixed driver command",
        ),
    ];
    for (damage, check) in damage {
        let mut record = saved.clone();
        damage(&mut record);
        // A daemon never saves `env`; a legacy record on disk can carry it.
        let mut bytes = serde_json::to_value(&record).unwrap();
        if !record.env.is_empty() {
            bytes["env"] = json!(record.env);
        }
        std::fs::write(&path, serde_json::to_vec(&bytes).unwrap()).unwrap();
        let engine = SessionEngine::new(&config, CredentialBridge::new(None));
        let refused = engine.list().await.unwrap_err();
        let SessionError::StoreRefused(reason) = &refused else {
            panic!("a malformed origin must refuse the store: {refused:?}");
        };
        let reason = reason.clone();
        assert_eq!(reason, format!("platform record {session}: {check}"));
        let diagnostic = engine.store_diagnostic().unwrap();
        assert_eq!(diagnostic.name, "session-store");
        assert!(!diagnostic.healthy);
        assert_eq!(diagnostic.message, format!("refused: {reason}"));
        assert!(!format!("{refused:?}{diagnostic:?}").contains(SENTINEL));
        let status = status_from_session_error(refused);
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert_eq!(status.message(), format!("session store refused: {reason}"));
        // Corrected on disk, the same daemon admits the store and clears it.
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert_eq!(engine.list().await.unwrap().len(), 1);
        assert!(engine.store_diagnostic().is_none());
        engine.shutdown().await.unwrap();
    }
}

#[test]
fn a_launch_is_denied_before_run_only_when_its_projection_failed_and_cleanup_is_confirmed() {
    let denied = v1::SessionRecord {
        state: v1::SessionLifecycleState::Failed as i32,
        cleanup_unknown: false,
        status_message: crate::durable_session::LAUNCH_PROJECTION_DENIED.into(),
        launch_generation: 1,
        ..Default::default()
    };
    assert!(denied_before_run(&denied));
    // Unconfirmed cleanup, a program that started, another failure, an exit
    // status or another state each keep the outcome unknown.
    let mut unconfirmed = denied.clone();
    unconfirmed.cleanup_unknown = true;
    let mut started = denied.clone();
    started.started_at = Some(prost_types::Timestamp::default());
    let mut other = denied.clone();
    other.status_message = "session stdin pipe is unavailable".into();
    let mut exited = denied.clone();
    exited.exit_code = Some(1);
    let mut interrupted = denied.clone();
    interrupted.state = v1::SessionLifecycleState::Interrupted as i32;
    for record in [unconfirmed, started, other, exited, interrupted] {
        assert!(!denied_before_run(&record));
    }
}
