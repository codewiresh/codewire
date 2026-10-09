//! Proposed source-only fixture tests. No provider or production path override.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _temp: tempfile::TempDir,
    environment: DriverEnvironment,
    origin: Origin,
    session: String,
    dir: PathBuf,
    message: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let driver = uuid::Uuid::new_v4().to_string();
        let environment = DriverEnvironment::Guest {
            id: id.clone(),
            root: temp.path().to_owned(),
        };
        let session = format!("session-{driver}");
        private_directory(&agents_root(&environment)).unwrap();
        let dir = agents_root(&environment).join(&driver);
        private_directory(&dir).unwrap();
        private_directory(&dir.join("messages")).unwrap();
        let origin = Origin {
            version: 1,
            environment_id: id.clone(),
            org_id: "fixture-org".into(),
            pod_uid: uuid::Uuid::new_v4().to_string(),
            binding_generation: u64::MAX,
            projection_selection_sha256: [1; 32],
            driver_id: driver.clone(),
            agent: AgentKind::Codex,
            support_image_sha256: [2; 32],
            support_image_size: 1024,
            provider: codewire_daemon::platform_managed::ProviderIdentity {
                sha256: [3; 32],
                size: 1024,
                version: "0.157.0".into(),
            },
            parent_generation: None,
        };
        write_private_json(&dir.join(ORIGIN), &origin).unwrap();
        write_private_json(
            &dir.join(GENERATION),
            &Generation {
                version: 1,
                driver_id: driver.clone(),
                session_id: session.clone(),
                generation: 1,
            },
        )
        .unwrap();
        write_private_json(
            &dir.join("config.json"),
            &AgentConfig {
                version: 1,
                driver_id: driver.clone(),
                environment_id: id,
                agent: AgentKind::Codex,
                program: PathBuf::from("/usr/bin/false"),
                model: "synthetic".into(),
                effort: Some("high".into()),
                working_dir: temp.path().to_string_lossy().into_owned(),
                name: String::new(),
                parent: None,
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
        let mut record = MessageRecord::new(
            &driver,
            &session,
            MessageAction::Message,
            "synthetic".into(),
        );
        record.platform_launch_generation = Some(1);
        let message = record.id.clone();
        write_private_json(&message_path(&dir, &message), &record).unwrap();
        Self {
            _temp: temp,
            environment,
            origin,
            session,
            dir,
            message,
        }
    }
    fn request(&self) -> Envelope {
        Envelope {
            version: 1,
            origin: self.origin.clone(),
            session_id: self.session.clone(),
            launch_generation: 1,
            request: Request::GetMessage {
                driver_id: self.origin.driver_id.clone(),
                message_id: self.message.clone(),
            },
        }
    }
    fn clean_peer(&self) -> guest_peer::PeerIdentity {
        // Synthetic retained custody records exercise the actual file/lock/CAS
        // helper. They are not an observed guardian or provider qualification.
        let at = now();
        let peer = guest_peer::PeerIdentity {
            environment_id: self.environment.id().into(),
            driver_id: self.origin.driver_id.clone(),
            session_id: self.session.clone(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            driver_started_at: at.clone(),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim()
                .into(),
            driver_pid: 42,
            driver_start_ticks: 100,
        };
        write_private_json(
            &self.dir.join("state.json"),
            &DriverState {
                version: 1,
                driver_id: self.origin.driver_id.clone(),
                agent: AgentKind::Codex,
                phase: DriverPhase::Stopped,
                native_thread_id: Some("synthetic-thread".into()),
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
            },
        )
        .unwrap();
        write_private_json(&self.dir.join("peer-current.json"), &peer).unwrap();
        write_private_json(
            &self.dir.join(format!("peer-{}.json", peer.instance_id)),
            &guest_peer::PeerReceipt {
                version: 1,
                identity: peer.clone(),
                guardian_pid: Some(43),
                guardian_start_ticks: Some(101),
                provider_pid: Some(44),
                cleanup_unknown: false,
                finished_at: Some(at),
                exit_code: Some(0),
                error: None,
            },
        )
        .unwrap();
        peer
    }
}
#[test]
fn platform_control_ordinary_native_role_cannot_mutate_scoped_records() {
    let f = Fixture::new();
    let path = message_path(&f.dir, &f.message);
    let before = fs::read(&path).unwrap();
    assert!(
        native::handle(
            &f.environment,
            native::ControlRequest::MarkDelivery {
                driver_id: f.origin.driver_id.clone(),
                session_id: f.session.clone(),
                message_id: f.message.clone(),
                outcome: native::DeliveryOutcome::Written,
                error: None
            },
            &|_| panic!("no provider resolution")
        )
        .is_err()
    );
    assert_eq!(before, fs::read(path).unwrap());
}
#[test]
fn platform_control_historical_read_requires_saved_original_message_generation() {
    let f = Fixture::new();
    write_private_json(
        &f.dir.join(GENERATION),
        &Generation {
            version: 1,
            driver_id: f.origin.driver_id.clone(),
            session_id: f.session.clone(),
            generation: 2,
        },
    )
    .unwrap();
    assert_eq!(
        handle_fixed(&f.environment, f.request()).unwrap()["record"]["id"],
        f.message
    );
    let mut wrong = f.request();
    wrong.launch_generation = 2;
    assert!(handle_fixed(&f.environment, wrong).is_err());
    update_message(&f.dir, &f.message, |r| r.platform_launch_generation = None).unwrap();
    assert!(handle_fixed(&f.environment, f.request()).is_err());
}
#[test]
fn platform_control_parent_generation_and_original_scope_never_adopt_ordinary_records() {
    let f = Fixture::new();
    let other = uuid::Uuid::new_v4().to_string();
    assert!(parent_generation(&f.environment, &other, &f.origin.driver_id).is_err());
    let mut changed = f.origin.clone();
    changed.parent_generation = Some(1);
    changed.org_id = "another-org".into();
    assert!(!same_scope(&f.origin, &changed));
    changed.org_id = f.origin.org_id.clone();
    assert!(same_scope(&f.origin, &changed));
}
#[test]
fn platform_control_generation_filter_refuses_mixed_or_replayed_messages() {
    let f = Fixture::new();
    let mut record: MessageRecord = private_record(&message_path(&f.dir, &f.message)).unwrap();
    assert!(managed_message_generation_matches((None, Some(1)), &record));
    assert!(!managed_message_generation_matches(
        (None, Some(2)),
        &record
    ));
    assert!(!managed_message_generation_matches((None, None), &record));
    record.member_launch_generation = Some(1);
    assert!(!managed_message_generation_matches(
        (Some(1), None),
        &record
    ));
}
#[test]
fn platform_control_private_proxy_homes_never_copy_inherited_auth_or_routes() {
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    let sentinel = f._temp.path().join("unrelated-auth.json");
    fs::write(&sentinel, b"synthetic unrelated login").unwrap();
    proxy::prepare(&f.dir, &config).unwrap();
    let environment = proxy::environment(&f.dir, &config)
        .unwrap()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(environment["OPENAI_BASE_URL"], proxy::OPENAI);
    assert_eq!(environment["OPENAI_API_KEY"], "codewire-managed");
    assert!(!f.dir.join("codex/auth.json").exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"synthetic unrelated login");
    assert!(!environment.contains_key("HTTP_PROXY"));
    assert!(!environment.contains_key("CODEWIRE_DAEMON_TOKEN"));
    assert!(environment["HOME"].ends_with("/home"));
    fs::write(
        f.dir.join("codex/config.toml"),
        b"model_provider=\"unrelated\"\n",
    )
    .unwrap();
    assert!(proxy::environment(&f.dir, &config).is_err());
}

#[test]
fn platform_control_directories_below_a_setgid_home_are_exactly_private() {
    // A Pod fsGroup home is setgid; directories made below it inherit setgid.
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o2700)).unwrap();
    let leaf = temp.path().join("state").join("agents");
    make_directory(&leaf).unwrap();
    for made in [temp.path().join("state"), leaf] {
        assert_eq!(
            fs::metadata(&made).unwrap().mode() & 0o7777,
            0o700,
            "{made:?}"
        );
    }
}

#[test]
fn platform_control_claude_prefix_uses_the_pinned_cli_option_names() {
    // Claude 2.1.238 exits during startup on an unknown option such as
    // `--settings-sources`; these are the names it accepts.
    assert_eq!(
        proxy::arguments(AgentKind::Claude),
        [
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--disable-slash-commands",
        ]
    );
}

#[test]
fn platform_control_codex_private_config_allows_only_its_exact_project_suffix() {
    let f = Fixture::new();
    let config: AgentConfig = private_record(&f.dir.join("config.json")).unwrap();
    proxy::prepare(&f.dir, &config).unwrap();
    let path = f.dir.join("codex/config.toml");
    let baseline = fs::read(&path).unwrap();
    let suffix = format!(
        "\n[projects.{}]\ntrust_level = \"trusted\"\n",
        serde_json::to_string(&config.working_dir).unwrap()
    );
    let mut admitted = baseline.clone();
    admitted.extend(suffix.as_bytes());
    fs::write(&path, &admitted).unwrap();
    assert!(proxy::environment(&f.dir, &config).is_ok());
    for extra in [
        b"\n[projects.\"/other\"]\ntrust_level = \"trusted\"\n".as_slice(),
        b"\nmodel_provider = \"unrelated\"\n",
    ] {
        let mut invalid = admitted.clone();
        invalid.extend(extra);
        fs::write(&path, &invalid).unwrap();
        assert!(proxy::environment(&f.dir, &config).is_err());
    }
    fs::write(&path, admitted).unwrap();
    let mut changed = config.clone();
    changed.working_dir = "/other".into();
    assert!(proxy::environment(&f.dir, &changed).is_err());
}

#[test]
fn platform_control_reads_full_admitted_record_without_provider_resolution() {
    let fixture = Fixture::new();
    let value = handle_fixed(&fixture.environment, fixture.request()).unwrap();
    assert_eq!(value["record"]["id"], fixture.message);
    assert_eq!(value["record"]["text"], "synthetic");
}
#[test]
fn platform_control_stale_or_changed_origin_refuses_without_changing_record() {
    let fixture = Fixture::new();
    let path = message_path(&fixture.dir, &fixture.message);
    let before = fs::read(&path).unwrap();
    let mut stale = fixture.request();
    stale.launch_generation = 2;
    assert!(handle_fixed(&fixture.environment, stale).is_err());
    let mut changed = fixture.request();
    changed.origin.pod_uid = uuid::Uuid::new_v4().to_string();
    assert!(handle_fixed(&fixture.environment, changed).is_err());
    assert_eq!(before, fs::read(path).unwrap());
}
#[test]
fn platform_control_legacy_and_mixed_member_scope_refuse() {
    let fixture = Fixture::new();
    fs::rename(fixture.dir.join(ORIGIN), fixture.dir.join("saved-origin")).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    fs::rename(fixture.dir.join("saved-origin"), fixture.dir.join(ORIGIN)).unwrap();
    fs::write(fixture.dir.join("member-origin.json"), b"unrecognized").unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
}
#[test]
fn platform_control_linked_or_nonprivate_record_refuses_without_repairing_it() {
    let fixture = Fixture::new();
    let path = message_path(&fixture.dir, &fixture.message);
    let linked = fixture.dir.join("unrelated-link");
    fs::hard_link(&path, &linked).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    fs::remove_file(&linked).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(handle_fixed(&fixture.environment, fixture.request()).is_err());
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o644);
}
#[test]
fn platform_control_raw_queue_and_unknown_envelope_fields_cannot_reach_native_intake() {
    let fixture = Fixture::new();
    let base = json!({"version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"queue","driver_id":"ignored"}});
    assert!(serde_json::from_value::<Envelope>(base).is_err());
    let mut extra = json!({"version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"peer_status", "driver_id":fixture.origin.driver_id,
        "session_id":fixture.session}});
    extra["program"] = json!("untrusted");
    assert!(serde_json::from_value::<Envelope>(extra).is_err());
}

#[test]
fn platform_control_production_reader_refuses_trailing_data_and_overbound_before_io() {
    let fixture = Fixture::new();
    let mut body = serde_json::to_vec(&json!({
        "version":1,"origin":fixture.origin,"session_id":fixture.session,
        "launch_generation":1,"request":{"op":"get_message", "driver_id":fixture.origin.driver_id,
        "message_id":fixture.message},
    }))
    .unwrap();
    let parsed = parse_envelope(body.as_slice()).unwrap();
    assert_eq!(
        handle_fixed(&fixture.environment, parsed).unwrap()["record"]["id"],
        fixture.message
    );
    body.extend_from_slice(b" {}");
    assert!(parse_envelope(body.as_slice()).is_err());
    let oversized = vec![b' '; 512 * 1024 + 1];
    assert!(
        parse_envelope(oversized.as_slice())
            .err()
            .unwrap()
            .to_string()
            .contains("too large")
    );
}

#[test]
fn platform_control_linked_generation_cas_retains_peer_and_historical_messages_after_lost_ack() {
    let f = Fixture::new();
    let peer = f.clean_peer();
    let before = fs::read(message_path(&f.dir, &f.message)).unwrap();
    let peer_before = fs::read(f.dir.join("peer-current.json")).unwrap();
    let mut advance = f.request();
    advance.request = Request::AdvanceGeneration {
        expected_generation: 1,
        expected_peer: peer.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, advance).unwrap()["launch_generation"],
        2
    );
    // A later explicit cleanup observes to; it never replays the from->to CAS.
    let mut observed = f.request();
    observed.request = Request::GenerationStatus {
        driver_id: f.origin.driver_id.clone(),
        session_id: f.session.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, observed).unwrap()["launch_generation"],
        2
    );
    let mut confirmed = f.request();
    confirmed.launch_generation = 2;
    confirmed.request = Request::ConfirmCleanGeneration {
        expected_peer: peer.clone(),
    };
    assert_eq!(
        handle_fixed(&f.environment, confirmed).unwrap()["peer"]["identity"]["instance_id"],
        peer.instance_id
    );
    let mut repeated = f.request();
    repeated.request = Request::AdvanceGeneration {
        expected_generation: 1,
        expected_peer: peer,
    };
    assert!(handle_fixed(&f.environment, repeated).is_err());
    assert_eq!(before, fs::read(message_path(&f.dir, &f.message)).unwrap());
    assert_eq!(
        peer_before,
        fs::read(f.dir.join("peer-current.json")).unwrap()
    );
    assert_eq!(
        handle_fixed(&f.environment, f.request()).unwrap()["record"]["id"],
        f.message
    );
}

#[test]
fn platform_control_generation_refuses_live_lock_changed_peer_and_active_turn_without_advance() {
    let f = Fixture::new();
    let peer = f.clean_peer();
    let before = fs::read(f.dir.join(GENERATION)).unwrap();
    let request = |expected_peer| Envelope {
        request: Request::AdvanceGeneration {
            expected_generation: 1,
            expected_peer,
        },
        ..f.request()
    };
    let driver = StateLock::acquire(&f.dir.join("driver.lock")).unwrap();
    assert!(handle_fixed(&f.environment, request(peer.clone())).is_err());
    drop(driver);
    let mut changed = peer.clone();
    changed.instance_id = uuid::Uuid::new_v4().to_string();
    assert!(handle_fixed(&f.environment, request(changed)).is_err());
    let mut state: DriverState = private_record(&f.dir.join("state.json")).unwrap();
    state.active_message_id = Some(f.message.clone());
    state.current_turn_id = Some("new-turn".into());
    write_private_json(&f.dir.join("state.json"), &state).unwrap();
    assert!(handle_fixed(&f.environment, request(peer)).is_err());
    assert_eq!(before, fs::read(f.dir.join(GENERATION)).unwrap());
}

#[test]
fn platform_control_identity_accepts_only_fixed_platform_driver_shape_and_preserves_native_role() {
    let environment = uuid::Uuid::new_v4().to_string();
    let driver = uuid::Uuid::new_v4().to_string();
    let command = vec![
        "/codewire/bin/cw".into(),
        "__platform-agent-driver".into(),
        "--environment".into(),
        environment.clone(),
        "--driver-id".into(),
        driver.clone(),
    ];
    assert_eq!(
        driver_identity(&command),
        Some((environment.clone(), driver.clone()))
    );
    for field in 0..3 {
        let mut wrong = command.clone();
        match field {
            0 => wrong[0] = "/usr/local/bin/cw".into(),
            1 => wrong.push("--program".into()),
            _ => wrong[4] = "--unknown".into(),
        };
        assert!(driver_identity(&wrong).is_none());
    }
    let native = vec![
        "cw".into(),
        DRIVER_COMMAND.into(),
        "--environment".into(),
        environment.clone(),
        "--driver-id".into(),
        driver.clone(),
    ];
    assert_eq!(driver_identity(&native), Some((environment, driver)));
}
