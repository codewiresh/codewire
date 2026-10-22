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
fn saved_message_location_selects_its_own_placement() {
    let globals = Globals {
        server: Some("https://codewire.test".to_owned()),
        member: Some("trusted-host".to_owned()),
        placement: None,
    };
    let cloud = globals_for_message_placement(&globals, EnvironmentPlacement::Platform);
    assert_eq!(cloud.server, globals.server);
    assert_eq!(cloud.member, globals.member);
    assert_eq!(cloud.placement, Some(EnvironmentPlacement::Platform));

    let local = globals_for_message_placement(&cloud, EnvironmentPlacement::Local);
    assert_eq!(local.server, globals.server);
    assert_eq!(local.member, globals.member);
    assert_eq!(local.placement, Some(EnvironmentPlacement::Local));
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
    let Command::Run(interactive) = Cli::try_parse_from(["cw", "run", "--in", "builder", "--", "codex"])
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
        Cli::try_parse_from(["cw", "run", "--no-tty", "--in", "builder", "--", "codex"])
            .unwrap()
            .command
    else {
        panic!("expected run command");
    };
    assert!(!environment_run_allocates_tty_for_streams(
        &no_tty, true, true
    ));

    let Command::Run(json) =
        Cli::try_parse_from(["cw", "run", "--output", "json", "--in", "builder", "--", "codex"])
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
fn session_table_aligns_columns_and_names_the_parent() {
    let session = |id: &str, name: &str, parent: &str, command: &str| EnvironmentSessionView {
        name: name.to_string(),
        parent_session_id: parent.to_string(),
        started_at: String::new(),
        cleanup_unknown: false,
        launch_generation: 1,
        session_id: id.to_string(),
        state: "Running".to_string(),
        command: vec![command.to_string()],
        working_dir: String::new(),
        pty: false,
        exit_code: None,
        output_end_offset: 0,
        output_start_offset: 0,
        status_message: String::new(),
    };
    let sessions = [
        session("session-1", "lead", "", "bash"),
        session("session-2", "", "session-1", "cargo test"),
        session("session-3", "orphan", "session-9", "sleep 5"),
    ];
    let mut owners = std::collections::BTreeSet::from(["session-1".to_string()]);
    let children: Vec<String> = running_children(&sessions, &owners)
        .into_iter()
        .map(|child| child.session_id)
        .collect();
    assert_eq!(children, ["session-2"]);
    owners.insert("session-2".to_string());
    assert!(running_children(&sessions, &owners).is_empty());
    assert_eq!(
        running_children_hints(&sessions[1..2], &sessions[0], Some("team")),
        [
            "cw: child session session-2 is still running",
            "cw: stop them with `cw stop team --session lead --all`",
        ]
    );
    assert_eq!(
        running_children_hints(&sessions[1..2], &sessions[0], None)[1],
        "cw: stop them with `cw stop --session lead --all`"
    );
    let Command::Stop(stop) = Cli::try_parse_from(["cw", "stop", "--all", "team", "--session", "lead"])
        .unwrap()
        .command
    else {
        panic!("stop expected");
    };
    assert!(stop.all);
    assert_eq!(stop.scope.environment.as_deref(), Some("team"));
    assert_eq!(stop.scope.session.as_deref(), Some("lead"));
    assert!(Cli::try_parse_from(["cw", "restart", "--all", "--session", "lead"]).is_err());
    let mut stopped = sessions[1].clone();
    stopped.state = "Stopped".to_string();
    assert!(running_children(&[stopped], &std::collections::BTreeSet::from(["session-1".to_string()])).is_empty());
    assert_eq!(
        format_environment_sessions(&sessions, "  "),
        concat!(
            "  NAME    STATE    MODE    PARENT     SESSION    COMMAND\n",
            "  lead    Running  normal  -          session-1  bash\n",
            "  -       Running  normal  lead       session-2  cargo test\n",
            "  orphan  Running  normal  session-9  session-3  sleep 5\n",
        )
    );
}

#[test]
fn session_grammar_uses_environment_as_first_positional() {
    let Command::Ls(args) = Cli::try_parse_from(["cw", "ls", "builder"]).unwrap().command else {
        panic!("expected ls command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    for argv in [vec!["cw", "ls"], vec!["cw", "ls", "--all"], vec!["cw", "--local", "ls"]] {
        let Command::Ls(args) = Cli::try_parse_from(argv).unwrap().command else {
            panic!("expected ls command");
        };
        assert_eq!(args.environment, None, "no ENV lists every environment");
    }

    let logs = Cli::try_parse_from(["cw", "logs", "builder", "--session", "session-1"]).unwrap();
    let Command::Logs(args) = logs.command else {
        panic!("expected logs command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.session.as_deref(), Some("session-1"));

    // A lone positional is always the environment, whatever it is called.
    let attach = Cli::try_parse_from(["cw", "attach", "session-1"]).unwrap();
    let Command::Attach(args) = attach.command else {
        panic!("expected attach command");
    };
    assert_eq!(args.environment.as_deref(), Some("session-1"));
    assert_eq!(args.session, None);
    let attach = Cli::try_parse_from(["cw", "attach", "--in", "app", "--session", "coding"]).unwrap();
    let Command::Attach(args) = attach.command else {
        panic!("expected attach command");
    };
    assert_eq!(args.in_environment.as_deref(), Some("app"));
    assert_eq!(args.session.as_deref(), Some("coding"));
}

fn no_placement() -> Globals {
    Globals {
        server: None,
        member: None,
        placement: None,
    }
}

/// The error a session command gives for its argv. Each case fails on its
/// selectors alone: no environment or session is looked up.
async fn selector_error(argv: &[&str]) -> String {
    let cli = Cli::try_parse_from(argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
    let globals = Globals {
        server: None,
        member: cli.member.clone(),
        placement: cli.placement().unwrap(),
    };
    let result = match cli.command {
        Command::Attach(args) => handle_attach_command(&globals, args).await,
        Command::Send(args) => send_request(&args).map(|_| ()),
        Command::Wait(args) => handle_wait_command(&globals, args).await,
        #[cfg(unix)]
        Command::Interrupt(args) => selector_target("interrupt", args).map(|_| ()),
        Command::Shell(args) => handle_environment_shell_command(&globals, args).await,
        Command::Vscode(args) => handle_vscode_command(&globals, args).await,
        // Without a terminal to ask on, as for any script.
        Command::Run(args) => check_run_request(&args, false).map(|_| ()),
        other => panic!("unexpected {other:?}"),
    };
    result.unwrap_err().to_string()
}

#[tokio::test]
async fn session_commands_refuse_missing_contradictory_or_retired_selectors_before_effects() {
    for (argv, message) in [
        (
            vec!["cw", "attach"],
            "missing environment: `cw attach ENV` attaches to its session; `cw attach --session SESSION` attaches in the selected environment",
        ),
        (
            vec!["cw", "attach", "app", "coding"],
            "`cw attach ENV SESSION` no longer selects a session; use `cw attach app --session coding`",
        ),
        (
            vec!["cw", "attach", "app", "--in", "app"],
            "name the environment once: `cw attach ENV` or `cw attach --in ENV`, not both",
        ),
        (
            vec!["cw", "send", "app", "coding", "text"],
            "`cw send ENV SESSION TEXT` no longer selects a session; use `cw send app --session coding TEXT`",
        ),
        (
            vec!["cw", "send", "coding", "text"],
            "missing session: `cw send coding --session SESSION` (`cw ls coding` lists its sessions)",
        ),
        (
            vec!["cw", "send", "--session", "coding"],
            "missing TEXT: `cw send ENV --session SESSION TEXT`, or `--key KEY` for one key",
        ),
        (
            vec!["cw", "send", "app", "--in", "app", "--session", "coding", "text"],
            "name the environment once: `cw send ENV` or `cw send --in ENV`, not both",
        ),
        (
            vec!["cw", "send", "app", "text", "--session", "coding", "--key", "enter"],
            "--key sends one key and no TEXT: `cw send ENV --session SESSION --key KEY`",
        ),
        (
            vec!["cw", "wait", "app", "coding"],
            "`cw wait ENV SESSION` no longer selects a session; use `cw wait app --session coding`",
        ),
        (
            vec!["cw", "wait", "coding"],
            "missing session: `cw wait coding --session SESSION` (`cw ls coding` lists its sessions)",
        ),
        (
            vec!["cw", "wait", "--in", "app", "--session", "coding", "--message", "task-id"],
            "a message ID already names its session; run `cw wait --message task-id` without ENV or SESSION",
        ),
        (
            vec!["cw", "--cloud", "wait", "--message", "task-id"],
            "a message ID already names its session and environment; run `cw wait --message task-id` without --local or --cloud",
        ),
        (
            vec!["cw", "shell", "app", "--in", "app"],
            "name the environment once: `cw shell ENV` or `cw shell --in ENV`, not both",
        ),
        (
            vec!["cw", "vscode", "app", "--in", "app"],
            "name the environment once: `cw vscode ENV` or `cw vscode --in ENV`, not both",
        ),
        (
            vec!["cw", "vscode", "--local", "app"],
            "`cw vscode` opens cloud environments; for a local VM use `cw shell ENV`",
        ),
        (
            vec!["cw", "run"],
            "`cw run` needs an agent or a command: `cw run claude --in ENV`, `cw run codex --in ENV`, or `cw run --in ENV -- COMMAND`",
        ),
        (
            vec!["cw", "run", "claude", "--in", "app", "--name", "a/b"],
            "--name \"a/b\" is not a session name: 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or digit",
        ),
    ] {
        assert_eq!(selector_error(&argv).await, message, "{argv:?}");
    }
    #[cfg(unix)]
    for (argv, message) in [
        (
            vec!["cw", "interrupt", "app", "review"],
            "`cw interrupt ENV SESSION` no longer selects a session; use `cw interrupt app --session review`",
        ),
        (
            vec!["cw", "interrupt"],
            "missing session: `cw interrupt ENV --session SESSION`, or `cw interrupt --session SESSION` in the selected environment",
        ),
    ] {
        assert_eq!(selector_error(&argv).await, message, "{argv:?}");
    }
}

#[test]
fn session_selectors_build_the_handler_target_from_flags() {
    let parse = |argv: &[&str]| Cli::try_parse_from(argv).unwrap().command;
    let Command::Send(args) = parse(&["cw", "send", "--session", "coding", "hello"]) else {
        panic!("send expected");
    };
    let request = send_request(&args).unwrap();
    assert_eq!(request.selection.values(), ["coding"]);
    assert_eq!(request.data, b"hello\n");
    let Command::Send(args) =
        parse(&["cw", "send", "app", "--session", "coding", "partial", "--no-newline"])
    else {
        panic!("send expected");
    };
    let request = send_request(&args).unwrap();
    assert_eq!(request.selection.values(), ["app", "coding"]);
    assert_eq!(request.data, b"partial");
    let Command::Send(args) = parse(&["cw", "send", "--in", "app", "--session", "coding", "--key", "ctrl-c"])
    else {
        panic!("send expected");
    };
    let request = send_request(&args).unwrap();
    assert_eq!(request.selection.values(), ["app", "coding"]);
    assert_eq!(request.data, [3]);
    let Command::Send(args) = parse(&["cw", "send", "app", "--session", "coding", "--key", "enter"]) else {
        panic!("send expected");
    };
    assert_eq!(send_request(&args).unwrap().selection.values(), ["app", "coding"]);

    let Command::Wait(args) = parse(&["cw", "wait", "--in", "app", "--session", "build"]) else {
        panic!("wait expected");
    };
    assert_eq!(wait_selection(&args).unwrap().unwrap().values(), ["app", "build"]);
    let Command::Wait(args) = parse(&["cw", "wait", "--message", "task-id"]) else {
        panic!("wait expected");
    };
    assert_eq!(wait_selection(&args).unwrap(), None);

    #[cfg(unix)]
    {
        let Command::Interrupt(args) =
            parse(&["cw", "interrupt", "--session", "review", "-o", "json"])
        else {
            panic!("interrupt expected");
        };
        let target = selector_target("interrupt", args).unwrap();
        assert_eq!(target.target, ["review"]);
        assert!(matches!(target.output, OutputFormat::Json));
        let Command::Interrupt(args) = parse(&["cw", "interrupt", "app", "--session", "review"])
        else {
            panic!("interrupt expected");
        };
        assert_eq!(selector_target("interrupt", args).unwrap().target, ["app", "review"]);
    }
}

/// The scope errors `stop`, `restart` and `logs` give before any lookup.
async fn scope_error(argv: &[&str]) -> String {
    let cli = Cli::try_parse_from(argv).unwrap();
    let globals = Globals {
        server: None,
        member: cli.member.clone(),
        placement: cli.placement().unwrap(),
    };
    let error = match cli.command {
        Command::Stop(args) => crate::commands::flat::handle_stop(&globals, args).await,
        Command::Restart(args) => crate::commands::flat::handle_restart(&globals, args).await,
        Command::Logs(args) => crate::commands::flat::handle_logs(&globals, args).await,
        Command::Update(args) => crate::commands::flat::handle_update(&globals, args).await,
        other => panic!("unexpected {other:?}"),
    }
    .unwrap_err();
    error.to_string()
}

#[tokio::test]
async fn stop_restart_and_logs_refuse_unscoped_or_retired_selectors_before_effects() {
    for (argv, message) in [
        (
            vec!["cw", "stop"],
            "missing environment: `cw stop ENV` acts on a whole environment; `cw stop --session SESSION` acts on one session in the selected environment",
        ),
        (
            vec!["cw", "restart"],
            "missing environment: `cw restart ENV` acts on a whole environment; `cw restart --session SESSION` acts on one session in the selected environment",
        ),
        (
            vec!["cw", "stop", "app", "coding"],
            "`cw stop ENV SESSION` no longer selects a session; use `cw stop app --session coding`",
        ),
        (
            vec!["cw", "restart", "app", "coding"],
            "`cw restart ENV SESSION` no longer selects a session; use `cw restart app --session coding`",
        ),
        (
            vec!["cw", "logs", "app", "coding"],
            "`cw logs ENV SESSION` no longer selects a session; use `cw logs app --session coding`",
        ),
        (
            vec!["cw", "stop", "--all", "app"],
            "--all stops a session's running descendants; add --session SESSION",
        ),
        (
            vec!["cw", "stop", "app", "--in", "app", "--session", "coding"],
            "name the environment once: `cw stop ENV` or `cw stop --in ENV`, not both",
        ),
        (
            vec!["cw", "logs", "app", "--in", "app", "--session", "coding"],
            "name the environment once: `cw logs ENV` or `cw logs --in ENV`, not both",
        ),
        (
            vec!["cw", "stop", "app", "--cleanup-request-id", "11111111-1111-4111-8111-111111111111"],
            "--request-id, --expected-launch-generation and --cleanup-request-id apply to one --session",
        ),
        (
            vec!["cw", "logs", "app", "--setup", "--tail", "5"],
            "--tail and --raw apply to session output, not to --setup logs",
        ),
        (
            vec!["cw", "--local", "logs", "app", "--setup"],
            "setup logs are kept for cloud environments; a local environment shows its setup as `cw start` or `cw create` runs",
        ),
        (
            vec!["cw", "update"],
            "missing environment: `cw update ENV` changes an environment's secrets and credential profile; `cw upgrade` upgrades the CLI",
        ),
        (
            vec!["cw", "update", "--restart-vms", "app"],
            "`cw update ENV` changes an environment and takes no --restart-vms; `cw upgrade` upgrades the CLI and restarts local VMs (see `cw upgrade --help`)",
        ),
        (
            vec!["cw", "update", "rollback", "--to", "v0.3.391"],
            "`cw update ENV` changes an environment and takes no --to; `cw upgrade` upgrades the CLI and restarts local VMs (see `cw upgrade --help`)",
        ),
    ] {
        assert_eq!(scope_error(&argv).await, message, "{argv:?}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_member_never_controls_a_whole_environment() {
    for argv in [
        vec!["cw", "--member", "build", "stop", "app"],
        vec!["cw", "--member", "build", "restart", "app"],
    ] {
        let message = scope_error(&argv).await;
        assert!(
            message.contains("a member never controls a whole environment"),
            "{argv:?}: {message}"
        );
    }
    assert_eq!(
        scope_error(&["cw", "--member", "build", "logs", "app", "--setup"]).await,
        "--setup is not available with --member; name the --session"
    );
}

#[test]
fn update_takes_environment_names_that_once_were_updater_subcommands() {
    for name in ["status", "rollback"] {
        let cli = Cli::try_parse_from(["cw", "update", name, "--clear-profile"]).unwrap();
        let (_, _, EnvCommand::Update(args)) = env_operation(cli) else {
            panic!("expected update");
        };
        assert_eq!(args.environment, name);
        assert!(args.clear_profile);
    }
    let cli = Cli::try_parse_from(["cw", "update", "--in", "app", "--profile", "local:work"]).unwrap();
    let (_, _, EnvCommand::Update(args)) = env_operation(cli) else {
        panic!("expected update");
    };
    assert_eq!(args.environment, "app");
    assert_eq!(args.profile.as_deref(), Some("local:work"));
}

#[test]
fn placement_is_refused_by_commands_that_do_not_read_it() {
    for (argv, name) in [
        (vec!["cw", "--local", "login"], "login"),
        (vec!["cw", "--cloud", "whoami"], "whoami"),
        (vec!["cw", "--local", "upgrade", "status"], "upgrade"),
        (vec!["cw", "--cloud", "help"], "help"),
    ] {
        let matches = crate::cli_command().try_get_matches_from(argv.clone()).unwrap();
        let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
        let error = crate::validate_placement_scope(
            &cli.command,
            matches.subcommand_name().unwrap(),
            cli.placement().unwrap(),
            false,
        )
        .unwrap_err();
        let flag = if argv.contains(&"--local") { "--local" } else { "--cloud" };
        assert_eq!(error.to_string(), format!("{flag} does not apply to `cw {name}`"));
    }
    for argv in [
        vec!["cw", "run", "--cloud", "claude", "--in", "app"],
        vec!["cw", "--local", "run", "--in", "app", "--", "true"],
        vec!["cw", "--local", "attach", "app"],
        vec!["cw", "attach", "--session", "coding", "--cloud"],
        vec!["cw", "--cloud", "shell", "app"],
        vec!["cw", "--local", "send", "--session", "coding", "text"],
        vec!["cw", "--local", "wait", "--session", "coding"],
        vec!["cw", "--cloud", "vscode", "app"],
        vec!["cw", "--local", "stop", "app"],
        vec!["cw", "stop", "app", "--cloud"],
        vec!["cw", "--cloud", "credentials", "list"],
        vec!["cw", "secrets", "--local", "--user", "list"],
        vec!["cw", "--local", "use", "app"],
        vec!["cw", "--cloud", "prune"],
    ] {
        let matches = crate::cli_command().try_get_matches_from(argv.clone()).unwrap();
        let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
        crate::validate_placement_scope(
            &cli.command,
            matches.subcommand_name().unwrap(),
            cli.placement().unwrap(),
            false,
        )
        .unwrap_or_else(|error| panic!("{argv:?}: {error}"));
    }
    // The managed session controls, which exist only on Unix, read it too.
    #[cfg(unix)]
    for argv in [
        vec!["cw", "--cloud", "interrupt", "--session", "review"],
        vec!["cw", "--local", "steer", "app", "review", "text"],
    ] {
        let matches = crate::cli_command().try_get_matches_from(argv.clone()).unwrap();
        let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
        crate::validate_placement_scope(
            &cli.command,
            matches.subcommand_name().unwrap(),
            cli.placement().unwrap(),
            false,
        )
        .unwrap_or_else(|error| panic!("{argv:?}: {error}"));
    }
    let matches = crate::cli_command()
        .try_get_matches_from(["cw", "--member", "build", "--local", "ls"])
        .unwrap();
    let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
    assert!(
        crate::validate_placement_scope(&cli.command, "ls", cli.placement().unwrap(), true)
            .is_err()
    );
}

#[test]
fn retired_env_routes_keep_only_the_exact_updater_handoff() {
    use crate::commands::flat::{RetiredEnvRoute, retired_env_route};
    fn route(argv: &[&str]) -> RetiredEnvRoute {
        let cli = Cli::try_parse_from(argv).unwrap();
        let placement = cli.placement().unwrap();
        let Command::Env(args) = cli.command else {
            panic!("expected the hidden env route for {argv:?}");
        };
        let raw: Vec<std::ffi::OsString> = argv.iter().map(Into::into).collect();
        retired_env_route(&raw, placement, &args.arguments)
    }
    // Exactly the argv every updater since #2870 runs, in both directions.
    assert_eq!(
        route(&["cw", "env", "--local", "upgrade", "--help"]),
        RetiredEnvRoute::HandoffProbe
    );
    assert_eq!(
        route(&["cw", "env", "--local", "upgrade", "--after-update"]),
        RetiredEnvRoute::Handoff { yes: false }
    );
    assert_eq!(
        route(&["cw", "env", "--local", "upgrade", "--after-update", "--yes"]),
        RetiredEnvRoute::Handoff { yes: true }
    );
    for (argv, replacement) in [
        (vec!["cw", "env", "stop", "app"], "`cw stop app`"),
        (vec!["cw", "env", "list"], "`cw ls`"),
        (vec!["cw", "env", "--cloud", "list", "--output", "json"], "`cw --cloud ls --output json`"),
        (vec!["cw", "env", "--local", "upgrade"], "`cw upgrade --vms`"),
        (vec!["cw", "env", "upgrade", "--after-update"], "`cw upgrade --vms`"),
        (vec!["cw", "env", "--local", "upgrade", "--yes", "--after-update"], "`cw upgrade --vms`"),
        (vec!["cw", "--local", "env", "upgrade", "--help"], "`cw upgrade --vms`"),
        (vec!["cw", "env", "logs", "app"], "`cw logs app --setup`"),
        (vec!["cw", "env", "port", "add", "3000", "--env", "app"], "`cw ports app --publish 3000`"),
        (vec!["cw", "env", "port", "rm", "3000", "-e", "app"], "`cw ports app --unpublish 3000`"),
        (vec!["cw", "env", "--local", "port", "ls"], "`cw --local ports ENV`"),
        (vec!["cw", "env", "create", "--local", "--name", "my app"], "`cw create --local --name \"my app\"`"),
        (vec!["cw", "env"], "the top-level environment commands (`cw help`)"),
        (vec!["cw", "env", "--help"], "the top-level environment commands (`cw help --all`)"),
        (vec!["cw", "env", "bogus"], "the top-level environment commands (`cw help --all`)"),
    ] {
        assert_eq!(
            route(&argv),
            RetiredEnvRoute::Refused(format!("`cw env` was removed; use {replacement}")),
            "{argv:?}"
        );
    }
    // The hidden route stays out of every help.
    for all in [false, true] {
        let help = crate::cli_command_with(all).render_help().to_string();
        assert!(!help.lines().any(|line| line.trim_start().starts_with("env ")));
    }
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
        "--session",
        "shell",
        "partial",
        "--no-newline",
    ])
    .unwrap()
    .command
    else {
        panic!("send expected");
    };
    assert_eq!(args.first.as_deref(), Some("host-team"));
    assert_eq!(args.second.as_deref(), Some("partial"));
    assert_eq!(args.session.as_deref(), Some("shell"));
    assert!(args.no_newline);
    assert!(
        Cli::try_parse_from(["cw", "send", "--session", "shell", "--no-newline", "--key", "ctrl-c"])
            .is_err()
    );
    // The inventory filters parse beside ENV and are refused before any lookup.
    assert!(Cli::try_parse_from(["cw", "ls", "--all", "host-team"]).is_ok());
}

#[tokio::test]
async fn wait_for_a_message_explains_that_its_id_names_the_session() {
    let Command::Wait(args) =
        Cli::try_parse_from(["cw", "wait", "builder", "--session", "shell", "--message", "task-id"])
            .unwrap()
            .command
    else {
        panic!("wait expected");
    };
    let error = handle_wait_command(&no_placement(), args).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "a message ID already names its session; run `cw wait --message task-id` without ENV or SESSION"
    );
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
                assert!(error.contains("cw create --local"), "{error}");
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(unix)]
#[test]
fn host_creation_is_explicit_and_rejects_vm_or_provider_projection_options() {
    let cli = Cli::try_parse_from([
        "cw", "create", "--local", "--type", "host", "--name", "team", "--path", ".",
    ])
    .unwrap();
    let placement = cli.placement().unwrap();
    let (_, _, EnvCommand::Create(create)) = env_operation(cli) else {
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
        let cli = Cli::try_parse_from([
            "cw", "create", "--local", "--type", "host", "--name", "team", option, "native",
        ])
        .unwrap();
        let placement = cli.placement().unwrap();
        let (_, _, EnvCommand::Create(create)) = env_operation(cli) else {
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
