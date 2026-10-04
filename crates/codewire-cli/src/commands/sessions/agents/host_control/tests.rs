use super::*;

struct Fixture {
    _temp: tempfile::TempDir,
    environment: DriverEnvironment,
    scope: Scope,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("host-records");
        private_directory(&root).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        Self {
            _temp: temp,
            environment: DriverEnvironment::Guest {
                id: id.clone(),
                root,
            },
            scope: Scope {
                environment_id: id,
                org_id: "test-org".into(),
                network_id: "test-network".into(),
                caller_key: [1; 32],
                target_key: [2; 32],
                grant_id: uuid::Uuid::new_v4().to_string(),
                grant_revision: 1,
            },
        }
    }
    fn origin(&self) -> Origin {
        Origin {
            request_id: uuid::Uuid::new_v4().to_string(),
            fingerprint: "ab".repeat(32),
            scope: self.scope.clone(),
        }
    }
    fn run(&self, request: Request) -> anyhow::Result<Value> {
        handle(&self.environment, request, &|agent| {
            Ok(PathBuf::from(format!("/synthetic/bin/{}", agent.name())))
        })
    }
    fn prepare(&self, parent: Option<(&str, u64)>, prompt: bool) -> String {
        let origin = self.origin();
        let id = origin.request_id.clone();
        self.run(Request::Prepare {
            origin,
            agent: AgentKind::Codex,
            model: "synthetic-codex".into(),
            effort: Some("max".into()),
            working_dir: self.environment.root().display().to_string(),
            name: "worker".into(),
            prompt: prompt.then(|| "first".into()),
            parent_session_id: parent
                .map(|p| format!("session-{}", p.0))
                .unwrap_or_default(),
            expected_parent_launch_generation: parent.map(|p| p.1).unwrap_or(0),
        })
        .unwrap();
        id
    }
    fn dir(&self, id: &str) -> PathBuf {
        agents_root(&self.environment).join(id)
    }
    fn queue(&self, driver: &str, generation: u64) -> (String, anyhow::Result<Value>) {
        let origin = self.origin();
        let id = origin.request_id.clone();
        (
            id,
            self.run(Request::Queue {
                origin,
                driver_id: driver.into(),
                session_id: format!("session-{driver}"),
                action: MessageAction::Message,
                text: "next".into(),
                reply_to: None,
                expected_turn_id: None,
                expected_active_message_id: None,
                launch_generation: generation,
            }),
        )
    }
    fn read(&self, driver: &str, id: &str, generation: u64) -> anyhow::Result<Value> {
        self.run(Request::Read {
            scope: self.scope.clone(),
            driver_id: driver.into(),
            session_id: format!("session-{driver}"),
            message_id: id.into(),
            limit: 20,
            launch_generation: generation,
        })
    }
    fn set_generation(&self, driver: &str, generation: u64) {
        write_private_json(
            &self.dir(driver).join(GENERATION),
            &Generation {
                version: PROTOCOL,
                driver_id: driver.into(),
                session_id: format!("session-{driver}"),
                generation,
            },
        )
        .unwrap();
    }
    fn driver(&self, id: &str) -> Driver {
        let dir = self.dir(id);
        let config: AgentConfig = private_record(&dir.join("config.json")).unwrap();
        let binding: AgentBinding = private_record(&dir.join("binding.json")).unwrap();
        let at = now();
        let state = DriverState {
            version: 1,
            driver_id: id.into(),
            agent: config.agent,
            phase: DriverPhase::Idle,
            native_thread_id: Some("native-thread".into()),
            native_thread_established: true,
            current_turn_id: None,
            active_message_id: None,
            queued: 0,
            capabilities: AgentCapabilities {
                steer: true,
                interrupt: true,
                note: "synthetic".into(),
            },
            policy: CODEX_POLICY.into(),
            last_error: None,
            started_at: at.clone(),
            updated_at: at.clone(),
        };
        Driver {
            environment: self.environment.clone(),
            dir,
            config,
            binding,
            state,
            started_at: at,
            queue: VecDeque::new(),
            active: None,
            pending: HashMap::new(),
            control_pending: HashMap::new(),
            settled: HashSet::new(),
        }
    }
}

#[test]
fn member_helper_closed_grammar_never_admits_program_registry_or_zero_generation() {
    let f = Fixture::new();
    let id = f.prepare(None, false);
    let request = json!({"op":"read","scope":f.scope,"driver_id":id,"session_id":format!("session-{id}"),
        "message_id":"","limit":20,"launch_generation":1});
    assert!(serde_json::from_value::<Request>(request.clone()).is_ok());
    for field in [
        "program",
        "registry_root",
        "provider_endpoint",
        "env",
        "arbitrary",
    ] {
        let mut value = request.clone();
        value[field] = json!("private-canary");
        assert!(serde_json::from_value::<Request>(value).is_err(), "{field}");
    }
    assert!(f.read(&id, "", 0).is_err());
    assert_eq!(message_ids(&f.dir(&id)).unwrap().len(), 0);
}

#[test]
fn member_helper_reserves_original_driver_and_message_before_a_second_prepare() {
    let f = Fixture::new();
    let id = f.prepare(None, true);
    let message: MessageRecord = private_record(&message_path(&f.dir(&id), &id)).unwrap();
    assert_eq!(message.member_launch_generation, Some(1));
    assert_eq!(message.target_session_id, format!("session-{id}"));
    let marker = marker(&f.environment, &id).unwrap().unwrap();
    assert_eq!(marker.origin.request_id, id);
    assert!(guardian_required(&f.environment, &id).unwrap());
    let mut origin = f.origin();
    origin.request_id = id.clone();
    assert!(
        f.run(Request::Prepare {
            origin,
            agent: AgentKind::Codex,
            model: "synthetic-codex".into(),
            effort: Some("max".into()),
            working_dir: f.environment.root().display().to_string(),
            name: "worker".into(),
            prompt: Some("changed".into()),
            parent_session_id: String::new(),
            expected_parent_launch_generation: 0
        })
        .is_err()
    );
    assert_eq!(load_message(&f.dir(&id), &id).unwrap().text, "first");
    assert_eq!(message_ids(&f.dir(&id)).unwrap(), vec![id.clone()]);
    for leaf in [MARKER, GENERATION, "config.json", "binding.json"] {
        let meta = fs::symlink_metadata(f.dir(&id).join(leaf)).unwrap();
        assert_eq!(
            (meta.uid(), meta.mode() & 0o7777, meta.nlink()),
            (euid(), 0o600, 1)
        );
    }
}

#[test]
fn member_helper_refuses_foreign_scope_and_stale_queue_before_any_message() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    let (stale, result) = f.queue(&driver, 2);
    assert!(result.is_err());
    assert!(!message_path(&f.dir(&driver), &stale).exists());
    let mut scope = f.scope.clone();
    scope.caller_key[0] ^= 1;
    assert!(
        f.run(Request::Read {
            scope,
            driver_id: driver.clone(),
            session_id: format!("session-{driver}"),
            message_id: String::new(),
            limit: 20,
            launch_generation: 1
        })
        .is_err()
    );
    assert_eq!(message_ids(&f.dir(&driver)).unwrap().len(), 0);
}

#[test]
fn member_helper_control_requires_same_active_message_and_native_turn() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    let mut owner = f.driver(&driver);
    let active = uuid::Uuid::new_v4().to_string();
    owner.state.phase = DriverPhase::Busy;
    owner.state.current_turn_id = Some("turn-A".into());
    owner.state.active_message_id = Some(active.clone());
    owner.persist_state().unwrap();
    for (turn, expected, action) in [
        (Some("turn-B"), Some(active.as_str()), MessageAction::Steer),
        (
            Some("turn-A"),
            Some("00000000-0000-0000-0000-000000000009"),
            MessageAction::Steer,
        ),
        (None, Some(active.as_str()), MessageAction::Interrupt),
    ] {
        let origin = f.origin();
        let id = origin.request_id.clone();
        assert!(
            f.run(Request::Queue {
                origin,
                driver_id: driver.clone(),
                session_id: format!("session-{driver}"),
                action,
                text: if action == MessageAction::Steer {
                    "steer".into()
                } else {
                    String::new()
                },
                reply_to: None,
                expected_turn_id: turn.map(str::to_owned),
                expected_active_message_id: expected.map(str::to_owned),
                launch_generation: 1
            })
            .is_err()
        );
        assert!(!message_path(&f.dir(&driver), &id).exists());
    }
    let origin = f.origin();
    let id = origin.request_id.clone();
    f.run(Request::Queue {
        origin,
        driver_id: driver.clone(),
        session_id: format!("session-{driver}"),
        action: MessageAction::Steer,
        text: "steer".into(),
        reply_to: None,
        expected_turn_id: Some("turn-A".into()),
        expected_active_message_id: Some(active),
        launch_generation: 1,
    })
    .unwrap();
    assert_eq!(
        load_message(&f.dir(&driver), &id)
            .unwrap()
            .member_launch_generation,
        Some(1)
    );
}

#[test]
fn member_helper_written_ack_preserves_native_state_without_fabricating_acceptance() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    for state in [
        MessageState::Requested,
        MessageState::PipeWritten,
        MessageState::Accepted,
        MessageState::Running,
        MessageState::Completed,
        MessageState::Unknown,
    ] {
        let (id, result) = f.queue(&driver, 1);
        result.unwrap();
        let acknowledged = matches!(
            state,
            MessageState::Accepted | MessageState::Running | MessageState::Completed
        );
        update_message(&f.dir(&driver), &id, |r| {
            r.transition(state);
            // This is synthetic persisted receiver evidence, never a claim
            // that a pipe acknowledgement itself establishes native delivery.
            r.native_acknowledged = acknowledged;
            r.turn_id = acknowledged.then(|| "original-native-turn".into());
        })
        .unwrap();
        let count = message_ids(&f.dir(&driver)).unwrap().len();
        for _ in 0..2 {
            let reply = f
                .run(Request::MarkDelivery {
                    scope: f.scope.clone(),
                    driver_id: driver.clone(),
                    session_id: format!("session-{driver}"),
                    message_id: id.clone(),
                    outcome: native::DeliveryOutcome::Written,
                })
                .unwrap();
            let saved = load_message(&f.dir(&driver), &id).unwrap();
            assert_eq!(
                saved.state,
                if state == MessageState::Requested {
                    MessageState::PipeWritten
                } else {
                    state
                }
            );
            assert_eq!(reply["state"], saved.state.name());
            assert_eq!(saved.native_acknowledged, acknowledged);
            assert_eq!(
                saved.turn_id.as_deref(),
                acknowledged.then_some("original-native-turn")
            );
            assert_eq!(saved.member_launch_generation, Some(1));
            assert_eq!(saved.driver_id, driver);
            assert_eq!(saved.target_session_id, format!("session-{driver}"));
            assert_eq!(message_ids(&f.dir(&driver)).unwrap().len(), count);
        }
    }
}

#[test]
fn member_helper_lost_pipe_ack_preserves_durable_acceptance_and_never_resurrects_unknown() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    for state in [
        MessageState::Accepted,
        MessageState::Running,
        MessageState::Completed,
        MessageState::Requested,
    ] {
        let (id, result) = f.queue(&driver, 1);
        result.unwrap();
        update_message(&f.dir(&driver), &id, |r| {
            r.transition(state);
        })
        .unwrap();
        f.run(Request::MarkDelivery {
            scope: f.scope.clone(),
            driver_id: driver.clone(),
            session_id: format!("session-{driver}"),
            message_id: id.clone(),
            outcome: native::DeliveryOutcome::AmbiguousFailure,
        })
        .unwrap();
        let saved = load_message(&f.dir(&driver), &id).unwrap();
        assert_eq!(
            saved.state,
            if state == MessageState::Requested {
                MessageState::Unknown
            } else {
                state
            }
        );
        if saved.state == MessageState::Unknown {
            assert!(
                !update_message(&f.dir(&driver), &id, |r| {
                    r.transition(MessageState::Accepted);
                })
                .unwrap()
                .native_acknowledged
            );
        }
    }
}

#[tokio::test]
async fn member_helper_restart_recovery_retains_history_but_never_adopts_old_or_unproven_messages()
{
    let f = Fixture::new();
    let driver = f.prepare(None, true);
    let (old, result) = f.queue(&driver, 1);
    result.unwrap();
    update_message(&f.dir(&driver), &old, |r| {
        r.transition(MessageState::Accepted);
    })
    .unwrap();
    let (missing, result) = f.queue(&driver, 1);
    result.unwrap();
    update_message(&f.dir(&driver), &missing, |r| {
        r.member_launch_generation = None;
    })
    .unwrap();
    let (terminal, result) = f.queue(&driver, 1);
    result.unwrap();
    update_message(&f.dir(&driver), &terminal, |r| {
        r.result = Some("durable A result".into());
        r.transition(MessageState::Completed);
    })
    .unwrap();
    f.set_generation(&driver, 2);
    let (current, result) = f.queue(&driver, 2);
    result.unwrap();
    update_message(&f.dir(&driver), &current, |r| {
        r.transition(MessageState::Accepted);
    })
    .unwrap();
    let mut owner = f.driver(&driver);
    owner.recover().await.unwrap();
    assert_eq!(owner.queue, VecDeque::from([current]));
    for id in [&driver, &old, &missing] {
        assert_eq!(
            load_message(&f.dir(&driver), id).unwrap().state,
            MessageState::Unknown
        );
    }
    let historical = f.read(&driver, &terminal, 2).unwrap();
    assert_eq!(historical["record"]["result"], "durable A result");
    assert_eq!(historical["record"]["member_launch_generation"], 1);
    assert!(f.read(&driver, &missing, 2).is_err());
    let (old_active, result) = f.queue(&driver, 2);
    result.unwrap();
    f.set_generation(&driver, 3);
    assert!(f.read(&driver, &old_active, 3).is_err());
    assert!(
        f.read(&driver, &terminal, 2).is_err(),
        "request view must be current even for historical results"
    );
}

#[tokio::test]
async fn member_helper_parent_outbox_adopts_once_and_refuses_rebound_parent() {
    let f = Fixture::new();
    let parent = f.prepare(None, false);
    let child = f.prepare(Some((&parent, 1)), true);
    update_message(&f.dir(&child), &child, |r| {
        r.result = Some("child finished".into());
        r.transition(MessageState::Completed);
    })
    .unwrap();
    let source = load_message(&f.dir(&child), &child).unwrap();
    let mut child_owner = f.driver(&child);
    child_owner.try_notify_parent(&source).await.unwrap();
    child_owner.try_notify_parent(&source).await.unwrap();
    let notification = notification_id(&child);
    assert_eq!(
        message_ids(&f.dir(&parent)).unwrap(),
        vec![notification.clone()]
    );
    assert_eq!(
        load_message(&f.dir(&parent), &notification)
            .unwrap()
            .member_launch_generation,
        Some(1)
    );
    let mut parent_owner = f.driver(&parent);
    parent_owner.adopt_notifications().await.unwrap();
    parent_owner.adopt_notifications().await.unwrap();
    assert_eq!(parent_owner.queue, VecDeque::from([notification]));
    f.set_generation(&parent, 2);
    assert!(child_owner.try_notify_parent(&source).await.is_err());
    let mut replacement = f.driver(&parent);
    replacement.recover().await.unwrap();
    assert!(replacement.queue.is_empty());
}

#[tokio::test]
async fn member_helper_parent_outbox_stays_queued_without_a_stopped_or_absent_host_owner() {
    for state in ["stopped", "running"] {
        let mut f = Fixture::new();
        let parent = f.prepare(None, false);
        let child = f.prepare(Some((&parent, 1)), true);
        let root = f.environment.root();
        let environment = HostEnvironment {
            id: f.environment.id().into(),
            name: "synthetic-parent".into(),
            path: root.clone(),
            created_at: now(),
            state: state.into(),
            runtime_root: Some(root.clone()),
        };
        if state == "stopped" {
            write_private_json(&root.join("host.json"), &environment).unwrap();
        }
        f.environment = DriverEnvironment::Host(environment);
        update_message(&f.dir(&child), &child, |r| {
            r.result = Some("child finished without an owner".into());
            r.transition(MessageState::Completed);
        })
        .unwrap();
        let source = load_message(&f.dir(&child), &child).unwrap();
        let mut child_owner = f.driver(&child);
        child_owner.try_notify_parent(&source).await.unwrap();
        child_owner.try_notify_parent(&source).await.unwrap();
        let notification = notification_id(&child);
        let queued = load_message(&f.dir(&parent), &notification).unwrap();
        assert_eq!(queued.state, MessageState::Requested);
        assert!(!queued.native_acknowledged);
        assert_eq!(queued.member_launch_generation, Some(1));
        assert_eq!(queued.source.as_ref().unwrap().driver_id, child);
        assert_eq!(
            load_message(&f.dir(&child), &child)
                .unwrap()
                .notification
                .unwrap()
                .state,
            NotificationState::Pending
        );
        for file in [
            "daemon.lock",
            "lifecycle.lock",
            "daemon.sock",
            "daemon.json",
        ] {
            assert!(!root.join(file).exists(), "no host-owner access: {file}");
        }
        let mut parent_owner = f.driver(&parent);
        parent_owner.adopt_notifications().await.unwrap();
        parent_owner.adopt_notifications().await.unwrap();
        assert_eq!(parent_owner.queue, VecDeque::from([notification.clone()]));
        assert_eq!(
            load_message(&f.dir(&parent), &notification).unwrap().state,
            MessageState::Accepted
        );
        assert!(
            !load_message(&f.dir(&parent), &notification)
                .unwrap()
                .native_acknowledged
        );
        f.set_generation(&parent, 2);
        assert!(child_owner.try_notify_parent(&source).await.is_err());
        let mut replacement = f.driver(&parent);
        replacement.recover().await.unwrap();
        replacement.adopt_notifications().await.unwrap();
        assert!(replacement.queue.is_empty());
        assert_eq!(
            load_message(&f.dir(&parent), &notification).unwrap().state,
            MessageState::Unknown
        );
    }
}

#[test]
fn member_helper_generation_advance_refuses_missing_unknown_family_and_live_driver() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    let request = || Request::AdvanceGeneration {
        origin: f.origin(),
        driver_id: driver.clone(),
        session_id: format!("session-{driver}"),
        expected_generation: 1,
    };
    assert!(f.run(request()).is_err());
    assert_eq!(generation(&f.environment, &driver).unwrap(), Some(1));
    let identity = guest_peer::prepare(
        &f.dir(&driver),
        f.environment.id(),
        &driver,
        &format!("session-{driver}"),
        &now(),
    )
    .unwrap();
    let receipt_path = guest_peer::receipt_path(&f.dir(&driver), &identity.instance_id).unwrap();
    let clean = guest_peer::PeerReceipt {
        version: 1,
        identity: identity.clone(),
        guardian_pid: Some(identity.driver_pid),
        guardian_start_ticks: Some(identity.driver_start_ticks),
        provider_pid: None,
        cleanup_unknown: false,
        finished_at: Some(now()),
        exit_code: Some(0),
        error: None,
    };
    for field in ["unknown", "stale-instance", "foreign-environment"] {
        let mut bad = clean.clone();
        match field {
            "unknown" => bad.cleanup_unknown = true,
            "stale-instance" => bad.identity.instance_id = uuid::Uuid::new_v4().to_string(),
            "foreign-environment" => bad.identity.environment_id = uuid::Uuid::new_v4().to_string(),
            _ => unreachable!(),
        }
        write_private_json(&receipt_path, &bad).unwrap();
        assert!(f.run(request()).is_err(), "{field}");
        assert_eq!(generation(&f.environment, &driver).unwrap(), Some(1));
    }
    write_private_json(&receipt_path, &clean).unwrap();
    let _live = StateLock::try_acquire(&f.dir(&driver).join("driver.lock"))
        .unwrap()
        .unwrap();
    assert!(f.run(request()).is_err());
    assert_eq!(generation(&f.environment, &driver).unwrap(), Some(1));
}

#[test]
fn member_helper_generation_cas_preserves_old_rows_and_refuses_stale_or_exhausted_selection() {
    let f = Fixture::new();
    let driver = f.prepare(None, true);
    let dir = f.dir(&driver);
    let session = format!("session-{driver}");
    let identity =
        guest_peer::prepare(&dir, f.environment.id(), &driver, &session, &now()).unwrap();
    // Synthetic closed receipt for private-state CAS validation. Actual
    // ECHILD/family completeness is proved separately by the kernel fixture.
    let receipt = guest_peer::PeerReceipt {
        version: 1,
        identity: identity.clone(),
        guardian_pid: Some(identity.driver_pid),
        guardian_start_ticks: Some(identity.driver_start_ticks),
        provider_pid: None,
        cleanup_unknown: false,
        finished_at: Some(now()),
        exit_code: Some(0),
        error: None,
    };
    write_private_json(
        &guest_peer::receipt_path(&dir, &identity.instance_id).unwrap(),
        &receipt,
    )
    .unwrap();
    let old = fs::read(message_path(&dir, &driver)).unwrap();
    let advance = |expected| Request::AdvanceGeneration {
        origin: f.origin(),
        driver_id: driver.clone(),
        session_id: session.clone(),
        expected_generation: expected,
    };
    assert_eq!(f.run(advance(1)).unwrap()["launch_generation"], 2);
    assert_eq!(fs::read(message_path(&dir, &driver)).unwrap(), old);
    assert!(f.run(advance(1)).is_err());
    assert_eq!(generation(&f.environment, &driver).unwrap(), Some(2));
    f.set_generation(&driver, u64::MAX);
    assert!(f.run(advance(u64::MAX)).is_err());
    assert_eq!(generation(&f.environment, &driver).unwrap(), Some(u64::MAX));
}

#[test]
fn member_helper_private_records_and_locks_refuse_links_fifo_and_unsafe_ancestors() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    let dir = f.dir(&driver);
    let path = dir.join(GENERATION);
    let original = fs::read(&path).unwrap();
    fs::hard_link(&path, dir.join("external-alias")).unwrap();
    assert!(f.read(&driver, "", 1).is_err());
    fs::remove_file(dir.join("external-alias")).unwrap();
    fs::remove_file(&path).unwrap();
    symlink("config.json", &path).unwrap();
    assert!(f.read(&driver, "", 1).is_err());
    fs::remove_file(&path).unwrap();
    write_private_json(
        &path,
        &serde_json::from_slice::<Generation>(&original).unwrap(),
    )
    .unwrap();
    let lock = dir.join("unsafe.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(StateLock::try_acquire(&lock).is_err());
    fs::remove_file(&lock).unwrap();
    let name = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid owned path; nonblocking open must refuse without hanging.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(StateLock::try_acquire(&lock).is_err());
    fs::set_permissions(
        agents_root(&f.environment),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(f.read(&driver, "", 1).is_err());
}

#[test]
fn member_helper_generation_addition_keeps_ordinary_record_bytes_and_refuses_zero() {
    let f = Fixture::new();
    let driver = f.prepare(None, false);
    let ordinary = MessageRecord::new(
        &driver,
        &format!("session-{driver}"),
        MessageAction::Message,
        "plain".into(),
    );
    assert!(
        serde_json::to_value(&ordinary)
            .unwrap()
            .get("member_launch_generation")
            .is_none()
    );
    assert!(member_message_generation_matches(None, &ordinary));
    let mut member = ordinary;
    member.member_launch_generation = Some(1);
    assert!(!member_message_generation_matches(None, &member));
    assert!(member_message_generation_matches(Some(1), &member));
    assert!(!member_message_generation_matches(Some(2), &member));
    member.member_launch_generation = Some(0);
    assert!(member.validate(&f.dir(&driver), &member.id).is_err());
}
