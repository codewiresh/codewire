#[test]
fn attach_navigation_uses_only_ctrl_b_prefix_and_preserves_literal_input() {
    let mut decoder = AttachNavigationDecoder::default();

    assert_eq!(decoder.feed(b"echo"), (None, b"echo".to_vec()));
    assert_eq!(decoder.feed(b"\x02"), (None, Vec::new()));
    assert_eq!(decoder.feed(b"b"), (None, vec![0x02]));
    assert_eq!(
        decoder.feed(b"\x02l"),
        (Some(AttachExit::NextSession), Vec::new())
    );
    assert_eq!(
        decoder.feed(b"\x02k"),
        (Some(AttachExit::PreviousEnvironment), Vec::new())
    );
    assert_eq!(decoder.feed(b"\x02x"), (None, vec![0x02, b'x']));
    assert_eq!(decoder.feed(b"\x02"), (None, Vec::new()));
    assert_eq!(decoder.finish(), vec![0x02]);
}

#[test]
fn attach_navigation_recognizes_every_session_action() {
    let cases = [
        (b"\x02h".as_slice(), AttachExit::PreviousSession),
        (b"\x02l".as_slice(), AttachExit::NextSession),
        (b"\x02k".as_slice(), AttachExit::PreviousEnvironment),
        (b"\x02j".as_slice(), AttachExit::NextEnvironment),
        (b"\x02w".as_slice(), AttachExit::OpenWorkspaces),
        (b"\x02r".as_slice(), AttachExit::Restart),
        (b"\x02d".as_slice(), AttachExit::Detached),
    ];
    for (input, expected) in cases {
        let mut decoder = AttachNavigationDecoder::default();
        assert_eq!(decoder.feed(input), (Some(expected), Vec::new()));
    }
}

#[test]
fn attachment_reconnect_budget_is_bounded_and_resets_on_output_progress() {
    let mut budget = AttachmentReconnectBudget::default();
    assert_eq!(budget.retry_delay(0).unwrap(), ATTACH_RECONNECT_BASE_DELAY);
    assert_eq!(
        budget.retry_delay(0).unwrap(),
        ATTACH_RECONNECT_BASE_DELAY * 2
    );
    assert_eq!(
        budget.retry_delay(0).unwrap(),
        ATTACH_RECONNECT_BASE_DELAY * 3
    );
    assert!(budget.retry_delay(0).is_err());

    assert_eq!(budget.retry_delay(1).unwrap(), ATTACH_RECONNECT_BASE_DELAY);
}

#[cfg(target_os = "linux")]
#[test]
fn native_session_default_working_dir_uses_the_recorded_project_intent() {
    let environment = codewire_local_vmm::control::v1::Environment {
        name: "native".to_owned(),
        working_directory: "/workspace/github".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        native_environment_session_working_dir(&environment),
        "/workspace/github"
    );

    let fallback = codewire_local_vmm::control::v1::Environment {
        name: "native".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        native_environment_session_working_dir(&fallback),
        LOCAL_WORKSPACE_PATH
    );
}

#[cfg(target_os = "linux")]
#[test]
fn selected_native_session_target_accepts_only_its_name_or_exact_id() {
    let environment = codewire_local_vmm::control::v1::Environment {
        id: "8fc6e44a-047a-4e65-8e56-26df709fee44".to_owned(),
        name: "native".to_owned(),
        ..Default::default()
    };
    assert!(native_session_request_matches(&environment, "native"));
    assert!(native_session_request_matches(
        &environment,
        "8fc6e44a-047a-4e65-8e56-26df709fee44"
    ));
    assert!(!native_session_request_matches(&environment, "nat"));
    assert!(!native_session_request_matches(&environment, "platform"));
}

#[cfg(target_os = "linux")]
#[test]
fn selected_native_session_target_refuses_a_replacement_named_as_the_deleted_uuid() {
    let old = "8fc6e44a-047a-4e65-8e56-26df709fee44";
    let replacement = codewire_local_vmm::control::v1::Environment {
        id: "d52a6f57-0f19-4b8c-b89b-b941abfc90b3".to_owned(),
        name: old.to_owned(),
        ..Default::default()
    };
    assert!(!native_session_request_matches(&replacement, old));
    assert!(native_session_request_matches(
        &replacement,
        &replacement.id
    ));
    let named = codewire_local_vmm::control::v1::Environment {
        name: "team-vm".to_owned(),
        ..replacement
    };
    assert!(native_session_request_matches(&named, "team-vm"));
}

#[test]
fn environment_run_tty_selection_preserves_interactive_and_machine_modes() {
    let Command::Run(interactive) = Cli::try_parse_from(["cw", "run", "builder", "--", "codex"])
        .unwrap()
        .command
    else {
        panic!("expected run command");
    };
    assert!(environment_run_allocates_tty_for_streams(
        &interactive,
        true,
        true
    ));
    assert!(!environment_run_allocates_tty_for_streams(
        &interactive,
        true,
        false
    ));

    let Command::Run(no_tty) =
        Cli::try_parse_from(["cw", "run", "--no-tty", "builder", "--", "codex"])
            .unwrap()
            .command
    else {
        panic!("expected run command");
    };
    assert!(!environment_run_allocates_tty_for_streams(
        &no_tty, true, true
    ));

    let Command::Run(json) =
        Cli::try_parse_from(["cw", "run", "--output", "json", "builder", "--", "codex"])
            .unwrap()
            .command
    else {
        panic!("expected run command");
    };
    assert!(!environment_run_allocates_tty_for_streams(
        &json, true, true
    ));
}

#[test]
fn platform_session_states_match_local_presentation_names() {
    use codewire_client::EnvironmentSessionState;

    let cases = [
        (EnvironmentSessionState::Unspecified, "Unspecified"),
        (EnvironmentSessionState::Starting, "Starting"),
        (EnvironmentSessionState::Running, "Running"),
        (EnvironmentSessionState::Stopping, "Stopping"),
        (EnvironmentSessionState::Stopped, "Stopped"),
        (EnvironmentSessionState::Exited, "Exited"),
        (EnvironmentSessionState::Failed, "Failed"),
        (EnvironmentSessionState::Interrupted, "Interrupted"),
    ];
    for (state, expected) in cases {
        assert_eq!(
            platform_environment_session_state_name(Some(state)),
            expected
        );
    }
    assert_eq!(platform_environment_session_state_name(None), "Unknown");
}

#[test]
fn session_output_tail_is_line_based() {
    assert_eq!(
        tail_session_output(b"one\ntwo\nthree\n", Some(2)),
        b"two\nthree\n"
    );
    assert_eq!(tail_session_output(b"one\ntwo\n", Some(0)), b"");
    assert_eq!(tail_session_output(b"one\ntwo\n", None), b"one\ntwo\n");
}

#[test]
fn adjacent_session_wraps_without_mutating_selected_environment() {
    let sessions = vec![
        EnvironmentSessionView {
            name: String::new(),
            parent_session_id: String::new(),
            started_at: String::new(),
            cleanup_unknown: false,
            launch_generation: 1,
            session_id: "a".to_string(),
            state: "Running".to_string(),
            command: vec!["first".to_string()],
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        },
        EnvironmentSessionView {
            name: String::new(),
            parent_session_id: String::new(),
            started_at: String::new(),
            cleanup_unknown: false,
            launch_generation: 1,
            session_id: "b".to_string(),
            state: "Running".to_string(),
            command: vec!["second".to_string()],
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        },
    ];

    assert_eq!(
        adjacent_session(&sessions, "a", true).unwrap().session_id,
        "b"
    );
    assert_eq!(
        adjacent_session(&sessions, "a", false).unwrap().session_id,
        "b"
    );
}

#[test]
fn session_grammar_uses_environment_as_first_positional() {
    let list = Cli::try_parse_from(["cw", "list", "builder"]).unwrap();
    let Command::List(args) = list.command else {
        panic!("expected list command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));

    let logs = Cli::try_parse_from(["cw", "logs", "builder", "session-1"]).unwrap();
    let Command::Logs(args) = logs.command else {
        panic!("expected logs command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.session.as_deref(), Some("session-1"));

    let attach = Cli::try_parse_from(["cw", "attach", "session-1"]).unwrap();
    let Command::Attach(args) = attach.command else {
        panic!("expected attach command");
    };
    assert_eq!(args.environment.as_deref(), Some("session-1"));
    assert_eq!(args.session, None);
}

#[test]
fn orchestration_arguments_preserve_terminal_and_semantic_boundaries() {
    let Command::Run(args) = Cli::try_parse_from([
        "cw",
        "run",
        "--name",
        "lead",
        "--agent",
        "codex",
        "--model",
        "gpt-6.1-sol",
        "--effort",
        "max",
        "--detach",
    ])
    .unwrap()
    .command
    else {
        panic!("run expected");
    };
    assert_eq!(args.name.as_deref(), Some("lead"));
    assert_eq!(args.agent.as_deref(), Some("codex"));
    assert!(args.command.is_empty());
    assert!(Cli::try_parse_from(["cw", "run", "--agent", "codex", "--", "sh"]).is_err());
    let Command::Send(args) = Cli::try_parse_from([
        "cw",
        "send",
        "host-team",
        "shell",
        "partial",
        "--no-newline",
    ])
    .unwrap()
    .command
    else {
        panic!("send expected");
    };
    assert_eq!(args.target_and_text, ["host-team", "shell", "partial"]);
    assert!(args.no_newline);
    assert!(
        Cli::try_parse_from(["cw", "send", "shell", "--no-newline", "--key", "ctrl-c"]).is_err()
    );
    assert!(Cli::try_parse_from(["cw", "list", "--all", "host-team"]).is_err());
    assert!(Cli::try_parse_from(["cw", "wait", "--message", "task-id", "shell"]).is_err());
}

/// A Mac host cannot be a member: Codewire has no public macOS API to keep
/// custody of a session's whole process family. Every member-control entry
/// point says so and why, before reading its arguments.
#[cfg(not(target_os = "linux"))]
#[test]
fn member_control_is_refused_off_linux_with_its_reason() {
    // The complete command future needs more than a test thread's stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            for arguments in [
                &["cw", "member", "up", "--json"][..],
                &["cw", "control", "status"][..],
                &["cw", "--member", "studio", "list"][..],
            ] {
                let error = runtime
                    .block_on(crate::run_from(arguments.iter().copied()))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("requires Linux"), "{error}");
                assert!(error.contains("process"), "{error}");
                assert!(error.contains("cw env create --local"), "{error}");
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(unix)]
#[test]
fn host_creation_is_explicit_and_rejects_vm_or_provider_projection_options() {
    let Command::Env(args) = Cli::try_parse_from([
        "cw", "env", "create", "--local", "--type", "host", "--name", "team", "--path", ".",
    ])
    .unwrap()
    .command
    else {
        panic!("env expected");
    };
    let placement = args.placement();
    let EnvCommand::Create(create) = args.command else {
        panic!("create expected");
    };
    assert_eq!(create.environment_type, EnvironmentTypeArg::Host);
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        assert!(
            validate_host_create(&create, placement)
                .unwrap_err()
                .to_string()
                .contains("supported on Linux and macOS")
        );
        return;
    }
    validate_host_create(&create, placement).unwrap();
    assert!(validate_host_create(&create, Some(EnvironmentPlacement::Platform)).is_err());
    for option in ["--image", "--backend", "--profile", "--secrets"] {
        let Command::Env(args) = Cli::try_parse_from([
            "cw", "env", "create", "--local", "--type", "host", "--name", "team", option, "native",
        ])
        .unwrap()
        .command
        else {
            panic!("env expected");
        };
        let placement = args.placement();
        let EnvCommand::Create(create) = args.command else {
            panic!("create expected");
        };
        assert!(validate_host_create(&create, placement).is_err());
    }
}

#[test]
fn foreground_run_fails_closed_on_session_exit_status() {
    let session = EnvironmentSessionView {
        name: String::new(),
        parent_session_id: String::new(),
        started_at: String::new(),
        cleanup_unknown: false,
        launch_generation: 1,
        session_id: "session-1".to_string(),
        state: "Exited".to_string(),
        command: vec!["false".to_string()],
        working_dir: LOCAL_WORKSPACE_PATH.to_string(),
        pty: false,
        exit_code: Some(42),
        output_end_offset: 0,
        output_start_offset: 0,
        status_message: String::new(),
    };
    assert_eq!(
        ensure_environment_session_succeeded(&session)
            .unwrap_err()
            .to_string(),
        "session exited with code 42"
    );

    let mut success = session.clone();
    success.exit_code = Some(0);
    ensure_environment_session_succeeded(&success).unwrap();
    let mut uncertain = success.clone();
    uncertain.cleanup_unknown = true;
    assert!(ensure_environment_session_succeeded(&uncertain).is_err());
    uncertain.cleanup_unknown = false;
    uncertain.state = "Interrupted".into();
    assert!(ensure_environment_session_succeeded(&uncertain).is_err());

    let mut missing = session;
    missing.exit_code = None;
    missing.status_message = "worker disconnected".to_string();
    assert_eq!(
        ensure_environment_session_succeeded(&missing)
            .unwrap_err()
            .to_string(),
        "session reached terminal state Exited without an exit code: worker disconnected"
    );
}

#[test]
fn an_exact_session_id_wins_over_another_sessions_name() {
    let first = EnvironmentSessionView {
        session_id: "session-other".into(),
        name: "session-real".into(),
        parent_session_id: String::new(),
        started_at: String::new(),
        cleanup_unknown: false,
        launch_generation: 1,
        state: "Running".into(),
        command: vec!["sh".into()],
        working_dir: "/workspace".into(),
        pty: false,
        exit_code: None,
        output_end_offset: 0,
        output_start_offset: 0,
        status_message: String::new(),
    };
    let mut real = first.clone();
    real.session_id = "session-real".into();
    real.name = "real".into();
    let views = vec![first, real];
    assert_eq!(
        requested_environment_session(&views, "session-real")
            .unwrap()
            .session_id,
        "session-real"
    );
}

#[test]
fn a_deleted_session_id_never_selects_a_replacement_with_that_name() {
    let old = "session-8fc6e44a-047a-4e65-8e56-26df709fee44";
    let replacement = EnvironmentSessionView {
        session_id: "session-d52a6f57-0f19-4b8c-b89b-b941abfc90b3".into(),
        name: old.into(),
        parent_session_id: String::new(),
        started_at: String::new(),
        cleanup_unknown: false,
        launch_generation: 1,
        state: "Running".into(),
        command: vec!["sh".into()],
        working_dir: "/workspace".into(),
        pty: false,
        exit_code: None,
        output_end_offset: 0,
        output_start_offset: 0,
        status_message: String::new(),
    };
    let views = [replacement];
    assert!(requested_environment_session(&views, old).is_none());
    assert_eq!(
        requested_environment_session(&views, &views[0].session_id)
            .unwrap()
            .session_id,
        views[0].session_id
    );
    let mut named = views[0].clone();
    named.name = "worker".into();
    assert!(requested_environment_session(&[named], "worker").is_some());
}
