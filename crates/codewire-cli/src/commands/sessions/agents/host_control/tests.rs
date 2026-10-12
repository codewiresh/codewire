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
                resume: false,
                note: "synthetic".into(),
            },
            policy: CODEX_POLICY.into(),
            last_error: None,
            started_at: at.clone(),
            updated_at: at.clone(),
        };
        Driver {
            #[cfg(target_os = "linux")]
            platform: None,
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
            stopping: false,
            noel: noel::Recovery::default(),
        }
    }
}

#[test]
fn member_helper_intake_preserves_escaped_text_and_refuses_excess_or_trailing_data() {
    let f = Fixture::new();
    let text = "\u{1}".repeat(MAX_TEXT_BYTES);
    let origin = f.origin();
    let driver = origin.request_id.clone();
    let prepare = json!({"op":"prepare","origin":origin,"agent":"codex",
        "model":"synthetic-codex","effort":"max","working_dir":f.environment.root(),
        "name":"worker","prompt":text,"parent_session_id":"",
        "expected_parent_launch_generation":0});
    let encoded = serde_json::to_vec(&prepare).unwrap();
    assert!(encoded.len() > 256 * 1024);
    f.run(read_request(encoded.as_slice()).unwrap()).unwrap();
    assert_eq!(load_message(&f.dir(&driver), &driver).unwrap().text, text);

    let queue = |text: &str| {
        let origin = f.origin();
        let id = origin.request_id.clone();
        let value = json!({"op":"queue","origin":origin,"driver_id":driver,
            "session_id":format!("session-{driver}"),"action":"message","text":text,
            "reply_to":null,"expected_turn_id":null,"expected_active_message_id":null,
            "launch_generation":1});
        (id, value)
    };
    let (id, request) = queue(&text);
    let encoded = serde_json::to_vec(&request).unwrap();
    f.run(read_request(encoded.as_slice()).unwrap()).unwrap();
    let record = load_message(&f.dir(&driver), &id).unwrap();
    assert_eq!(record.text, text);
    assert_eq!(record.member_launch_generation, Some(1));
    let before: Vec<_> = message_ids(&f.dir(&driver))
        .unwrap()
        .into_iter()
        .map(|id| {
            let bytes = fs::read(message_path(&f.dir(&driver), &id)).unwrap();
            (id, bytes)
        })
        .collect();

    let (_, oversized) = queue(&"x".repeat(REQUEST_BYTES));
    let mut input = std::io::Cursor::new(serde_json::to_vec(&oversized).unwrap());
    assert!(read_request(&mut input).is_err());
    assert_eq!(input.position(), REQUEST_BYTES as u64 + 1);
    let (_, request) = queue(&text);
    let mut trailing = serde_json::to_vec(&request).unwrap();
    trailing.extend_from_slice(b" {}");
    assert!(read_request(trailing.as_slice()).is_err());
    for text in [
        "\u{1}".repeat(MAX_TEXT_BYTES + 1),
        String::new(),
        "\0".into(),
    ] {
        let (_, request) = queue(&text);
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(f.run(read_request(bytes.as_slice()).unwrap()).is_err());
    }
    assert_eq!(
        message_ids(&f.dir(&driver)).unwrap(),
        before.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
    );
    for (id, bytes) in before {
        assert_eq!(fs::read(message_path(&f.dir(&driver), &id)).unwrap(), bytes);
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

#[test]
fn platform_home_alone_admits_a_shared_volume_root() {
    use std::os::unix::fs::PermissionsExt as _;
    // A Kubernetes home volume is root-owned 0777 (local-path) or a setgid
    // 2775 fsGroup root; only the exact home is admitted that way.
    let temp = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(temp.path()).unwrap().join("home");
    let below = home.join(".local");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&below).unwrap();
    for mode in [0o777, 0o2775] {
        fs::set_permissions(&home, fs::Permissions::from_mode(mode)).unwrap();
        fs::set_permissions(&below, fs::Permissions::from_mode(mode)).unwrap();
        let meta = |path: &Path| fs::symlink_metadata(path).unwrap();
        assert!(admitted_ancestor(&home, &meta(&home), &home));
        assert!(!admitted_ancestor(&below, &meta(&below), &home));
        assert!(!admitted_ancestor(&home, &meta(&home), &below));
    }
    let file = home.join("file");
    fs::write(&file, b"").unwrap();
    assert!(!admitted_ancestor(
        &file,
        &fs::symlink_metadata(&file).unwrap(),
        &file
    ));
    fs::set_permissions(&below, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
}

const RUN: &str = "6c1a4f0e-3b2d-4e5f-8a9b-0c1d2e3f4a5b";

impl Fixture {
    /// A conversation the host user launched: no member marker.
    fn local(&self, agent: AgentKind, parent: Option<ParentLink>) -> (String, String) {
        let driver = uuid::Uuid::new_v4().to_string();
        let session = format!("session-{}", uuid::Uuid::new_v4());
        let dir = agents_root(&self.environment).join(&driver);
        for path in [&agents_root(&self.environment), &dir, &dir.join("messages")] {
            private_directory(path).unwrap();
        }
        write_private_json(
            &dir.join("config.json"),
            &AgentConfig {
                version: 1,
                driver_id: driver.clone(),
                environment_id: self.environment.id().into(),
                agent,
                program: PathBuf::from(format!("/synthetic/bin/{}", agent.name())),
                program_fallback: None,
                model: "synthetic/model".into(),
                effort: None,
                working_dir: "/workspace".into(),
                name: String::new(),
                parent,
                initial_message_id: None,
                created_at: now(),
            },
        )
        .unwrap();
        write_private_json(
            &dir.join("binding.json"),
            &AgentBinding {
                driver_id: driver.clone(),
                session_id: session.clone(),
                bound_at: now(),
            },
        )
        .unwrap();
        (driver, session)
    }

    /// The conversation's driver is running `task` as `run`, if it has one.
    fn busy(&self, driver: &str, session: &str, run: Option<&str>) -> MessageRecord {
        let dir = self.dir(driver);
        let config: AgentConfig = private_record(&dir.join("config.json")).unwrap();
        let mut task = MessageRecord::new(driver, session, MessageAction::Message, "task".into());
        task.transition(MessageState::Accepted);
        task.transition(MessageState::Running);
        task.turn_id = run.map(str::to_owned);
        assert!(create_message(&dir, &task).unwrap());
        self.set_state(driver, config.agent, Some(&task.id), run);
        task
    }

    fn set_state(&self, driver: &str, agent: AgentKind, active: Option<&str>, run: Option<&str>) {
        let at = now();
        write_private_json(
            &self.dir(driver).join("state.json"),
            &DriverState {
                version: 1,
                driver_id: driver.into(),
                agent,
                phase: if active.is_some() {
                    DriverPhase::Busy
                } else {
                    DriverPhase::Idle
                },
                native_thread_id: Some("native-thread".into()),
                native_thread_established: true,
                current_turn_id: run.map(str::to_owned),
                active_message_id: active.map(str::to_owned),
                queued: 0,
                capabilities: AgentCapabilities {
                    steer: true,
                    interrupt: true,
                    resume: false,
                    note: "synthetic".into(),
                },
                policy: NOEL_POLICY.into(),
                last_error: None,
                started_at: at.clone(),
                updated_at: at,
            },
        )
        .unwrap();
    }

    fn interrupt_before_stop(&self, driver: &str, session: &str) -> anyhow::Result<Value> {
        // The exact request the host daemon writes.
        let request = json!({"op": "interrupt_before_stop", "driver_id": driver,
            "session_id": session});
        self.run(read_request(
            serde_json::to_vec(&request).unwrap().as_slice(),
        )?)
    }

    fn await_interrupt(&self, driver: &str, session: &str, message: &str) -> anyhow::Result<Value> {
        let request = json!({"op": "await_interrupt_before_stop", "driver_id": driver,
            "session_id": session, "message_id": message});
        self.run(read_request(
            serde_json::to_vec(&request).unwrap().as_slice(),
        )?)
    }
}

#[test]
fn stop_interrupt_is_recorded_only_for_a_noel_run_and_codex_and_claude_get_nothing() {
    let f = Fixture::new();
    for agent in [AgentKind::Codex, AgentKind::Claude] {
        let (driver, session) = f.local(agent, None);
        f.busy(&driver, &session, Some("turn-A"));
        let before = message_ids(&f.dir(&driver)).unwrap();
        let started = Instant::now();
        assert_eq!(
            f.interrupt_before_stop(&driver, &session).unwrap(),
            json!({"agent": agent.name(), "interrupt": null})
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(message_ids(&f.dir(&driver)).unwrap(), before);
    }

    let (driver, session) = f.local(AgentKind::Noel, None);
    // Before its driver reports, and while idle, there is no run to interrupt.
    assert_eq!(
        f.interrupt_before_stop(&driver, &session).unwrap()["interrupt"],
        Value::Null
    );
    f.set_state(&driver, AgentKind::Noel, None, None);
    assert_eq!(
        f.interrupt_before_stop(&driver, &session).unwrap()["interrupt"],
        Value::Null
    );
    assert!(message_ids(&f.dir(&driver)).unwrap().is_empty());

    let task = f.busy(&driver, &session, Some(RUN));
    let reply = f.interrupt_before_stop(&driver, &session).unwrap();
    let id = stop_interrupt_id(&task.id);
    assert_eq!(
        reply,
        json!({"agent": "noel", "interrupt": {"message_id": id, "active_message_id": task.id,
            "run_id": RUN, "deliver": true}})
    );
    let interrupt = load_message(&f.dir(&driver), &id).unwrap();
    assert_eq!(interrupt.action, MessageAction::Interrupt);
    assert_eq!(interrupt.state, MessageState::Requested);
    assert_eq!(interrupt.target_session_id, session);
    assert_eq!(interrupt.text, "");
    assert_eq!(
        interrupt.expected_active_message_id.as_deref(),
        Some(task.id.as_str())
    );
    assert_eq!(interrupt.expected_turn_id.as_deref(), Some(RUN));

    // A repeated stop reuses the record; it is delivered again only while no
    // driver has seen it.
    assert_eq!(f.interrupt_before_stop(&driver, &session).unwrap(), reply);
    update_message(&f.dir(&driver), &id, |r| {
        r.transition(MessageState::Accepted);
    })
    .unwrap();
    assert_eq!(
        f.interrupt_before_stop(&driver, &session).unwrap()["interrupt"]["deliver"],
        false
    );
    assert_eq!(message_ids(&f.dir(&driver)).unwrap().len(), 2);

    // The conversation must be bound to the session being stopped.
    let other = format!("session-{}", uuid::Uuid::new_v4());
    assert!(f.interrupt_before_stop(&driver, &other).is_err());
    assert!(f.await_interrupt(&driver, &other, &id).is_err());
}

#[test]
fn stop_interrupt_waits_briefly_for_a_starting_run_to_report_its_id() {
    let f = Fixture::new();
    let (driver, session) = f.local(AgentKind::Noel, None);
    let task = f.busy(&driver, &session, None);
    let started = Instant::now();
    assert_eq!(
        f.interrupt_before_stop(&driver, &session).unwrap()["interrupt"],
        Value::Null
    );
    let waited = started.elapsed();
    assert!(waited >= STOP_INTERRUPT_RUN_WAIT && waited < Duration::from_secs(5));
    assert_eq!(message_ids(&f.dir(&driver)).unwrap(), vec![task.id.clone()]);

    let reporting = {
        let (dir, task) = (f.dir(&driver), task.id.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut state: DriverState = private_record(&dir.join("state.json")).unwrap();
            assert_eq!(state.active_message_id.as_deref(), Some(task.as_str()));
            state.current_turn_id = Some(RUN.into());
            write_private_json(&dir.join("state.json"), &state).unwrap();
        })
    };
    let reply = f.interrupt_before_stop(&driver, &session).unwrap();
    reporting.join().unwrap();
    assert_eq!(reply["interrupt"]["run_id"], RUN);
    assert_eq!(
        reply["interrupt"]["message_id"],
        stop_interrupt_id(&task.id)
    );
}

#[test]
fn stop_interrupt_wait_ends_when_the_message_ends_and_its_parent_notification_is_written() {
    let f = Fixture::new();
    let (lead, lead_session) = f.local(AgentKind::Noel, None);
    let (driver, session) = f.local(
        AgentKind::Noel,
        Some(ParentLink {
            session_id: lead_session.clone(),
            driver_id: lead.clone(),
        }),
    );
    let task = f.busy(&driver, &session, Some(RUN));
    let reply = f.interrupt_before_stop(&driver, &session).unwrap();
    let id = reply["interrupt"]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = f.dir(&driver);
    // The driver ends the run, then sets the parent notification pending and
    // records how its delivery went.
    let driver_thread = {
        let (dir, task, id) = (dir.clone(), task.id.clone(), id.clone());
        std::thread::spawn(move || {
            let pause = || std::thread::sleep(Duration::from_millis(150));
            pause();
            update_message(&dir, &task, |r| {
                r.transition(MessageState::Interrupted);
            })
            .unwrap();
            update_message(&dir, &id, |r| {
                r.transition(MessageState::Accepted);
                r.transition(MessageState::Running);
                r.transition(MessageState::Completed);
            })
            .unwrap();
            pause();
            let mut notification = ParentNotification {
                message_id: notification_id(&task),
                parent_session_id: lead_session,
                parent_driver_id: lead,
                state: NotificationState::Pending,
                detail: None,
                updated_at: now(),
            };
            let pending = notification.clone();
            update_message(&dir, &task, |r| r.notification = Some(pending)).unwrap();
            pause();
            notification.state = NotificationState::PipeWritten;
            update_message(&dir, &task, |r| r.notification = Some(notification)).unwrap();
        })
    };
    let started = Instant::now();
    let settled = f.await_interrupt(&driver, &session, &id).unwrap();
    driver_thread.join().unwrap();
    assert_eq!(
        settled,
        json!({"settled": true, "message_state": "interrupted", "interrupt_state": "completed",
            "notification_state": "pipe_written"})
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(450) && waited < Duration::from_secs(5));

    // An interrupt the driver or noel refused leaves the run going, so the
    // wait ends at once rather than at its bound.
    let next = f.busy(&driver, &session, Some("another-run"));
    let reply = f.interrupt_before_stop(&driver, &session).unwrap();
    let refused = reply["interrupt"]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(refused, stop_interrupt_id(&next.id));
    update_message(&dir, &refused, |r| {
        r.fail(MessageState::Error, "noel refused the interrupt");
    })
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        f.await_interrupt(&driver, &session, &refused).unwrap(),
        json!({"settled": false, "message_state": "running", "interrupt_state": "error",
            "notification_state": null})
    );
    assert!(started.elapsed() < Duration::from_secs(1));

    // Only a stop interrupt is awaited.
    let mut other = MessageRecord::new(&driver, &session, MessageAction::Interrupt, String::new());
    other.expected_active_message_id = Some(next.id.clone());
    assert!(create_message(&dir, &other).unwrap());
    assert!(f.await_interrupt(&driver, &session, &other.id).is_err());
}
