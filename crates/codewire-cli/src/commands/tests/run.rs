#[test]
fn vscode_command_parser_accepts_folder_and_org() {
    let cli = Cli::try_parse_from([
        "cw",
        "vscode",
        "cw-env_123",
        "--folder",
        "/workspace/app",
        "--org",
        "acme",
    ])
    .unwrap();

    let Command::Vscode(args) = cli.command else {
        panic!("expected vscode command");
    };
    assert_eq!(args.environment.as_deref(), Some("cw-env_123"));
    assert_eq!(args.folder, "/workspace/app");
    assert_eq!(args.org.as_deref(), Some("acme"));
}

#[test]
fn vscode_uri_helpers_use_environment_ids() {
    let plain = |environment_ref| SshAlias {
        placement: AliasPlacement::Plain,
        environment_ref,
    };
    // The bare `cw-<ref>` alias is retired: it is a plain reference as given.
    assert_eq!(SshAlias::parse("cw-env_123"), Some(plain("cw-env_123")));
    assert_eq!(SshAlias::parse("env_123"), Some(plain("env_123")));
    assert_eq!(SshAlias::parse(" "), None);
    // The editor connects through the placement-qualified alias.
    assert_eq!(
        vscode_remote_uri("cw-cloud-env_123", "/workspace/app"),
        "vscode://vscode-remote/ssh-remote+cw-cloud-env_123//workspace/app"
    );
    assert_eq!(
        vscode_remote_uri("cw-local-0b6f2c1e-7d4a-4f3b-9c2a-5e8d1f0a6b3c", "/workspace"),
        "vscode://vscode-remote/ssh-remote+cw-local-0b6f2c1e-7d4a-4f3b-9c2a-5e8d1f0a6b3c//workspace"
    );
}

#[test]
fn session_commands_take_an_organization_for_one_invocation() {
    let Command::Shell(shell) = Cli::try_parse_from(["cw", "shell", "--org", "acme", "builder"])
        .unwrap()
        .command
    else {
        panic!("expected shell command");
    };
    assert_eq!(shell.org.as_deref(), Some("acme"));
    let Command::Attach(attach) =
        Cli::try_parse_from(["cw", "attach", "--org", "acme", "builder", "--session", "s"])
            .unwrap()
            .command
    else {
        panic!("expected attach command");
    };
    assert_eq!(attach.org.as_deref(), Some("acme"));
    let Command::Run(run) =
        Cli::try_parse_from(["cw", "run", "--org", "acme", "--in", "builder", "--", "true"])
            .unwrap()
            .command
    else {
        panic!("expected run command");
    };
    assert_eq!(run.org.as_deref(), Some("acme"));
}

#[test]
fn shell_command_parser_accepts_session_and_proxy_forms() {
    let cli = Cli::try_parse_from(["cw", "shell", "builder"]).unwrap();
    let Command::Shell(args) = cli.command else {
        panic!("expected shell command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert!(!args.stdio);

    let cli = Cli::try_parse_from(["cw", "shell", "--stdio", "cw-env_123"]).unwrap();
    let Command::Shell(args) = cli.command else {
        panic!("expected shell command");
    };
    assert_eq!(args.environment.as_deref(), Some("cw-env_123"));
    assert!(args.stdio);

    let selected = Cli::try_parse_from(["cw", "shell"]).unwrap();
    let Command::Shell(args) = selected.command else {
        panic!("expected shell command");
    };
    assert_eq!(args.environment, None);
    assert!(!args.stdio);

    let flag = Cli::try_parse_from(["cw", "shell", "--in", "builder"]).unwrap();
    let Command::Shell(args) = flag.command else {
        panic!("expected shell command");
    };
    assert_eq!(args.in_environment.as_deref(), Some("builder"));
    assert_eq!(args.environment, None);
}

#[test]
fn doctor_tailnet_parser_accepts_transport_probe_flags() {
    let cli = Cli::try_parse_from([
        "cw",
        "doctor",
        "tailnet",
        "builder",
        "--output",
        "json",
        "--direct-wait",
        "250ms",
        "--peer-timeout",
        "5s",
        "--expect",
        "udp_relay",
        "--skip-forced-derp",
    ])
    .unwrap();

    let Command::Doctor(args) = cli.command else {
        panic!("expected doctor command");
    };
    let Some(DoctorCommand::Tailnet(args)) = args.command else {
        panic!("expected doctor tailnet command");
    };
    assert_eq!(args.environment, "builder");
    assert!(matches!(args.output, OutputFormat::Json));
    assert_eq!(args.direct_wait, "250ms");
    assert_eq!(args.peer_timeout, "5s");
    assert_eq!(args.expect, "udp_relay");
    assert!(args.skip_forced_derp);
}

fn parse_run(argv: &[&str]) -> EnvironmentRunArgs {
    let Command::Run(args) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected run command");
    };
    args
}

#[test]
fn run_command_parser_keeps_environment_and_trailing_command() {
    let args = parse_run(&[
        "cw",
        "run",
        "--workdir",
        "/workspace/app",
        "--in",
        "builder",
        "--",
        "npm",
        "test",
    ]);
    assert_eq!(args.native_agent, None);
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.workdir.as_deref(), Some("/workspace/app"));
    assert_eq!(args.command, vec!["npm", "test"]);
}

#[test]
fn run_command_parser_reserves_short_t_for_tty() {
    let args = parse_run(&["cw", "run", "-t", "--in", "builder", "--", "claude"]);
    assert!(args.tty);
    assert!(!args.no_tty);
    assert_eq!(args.environment.as_deref(), Some("builder"));
}

#[test]
fn run_command_parser_rejects_conflicting_tty_overrides() {
    let err = Cli::try_parse_from(["cw", "run", "--tty", "--no-tty", "--", "true"]).unwrap_err();
    assert!(err.to_string().contains("cannot be used with"));
}

#[test]
fn run_takes_an_agent_positional_and_names_the_environment_with_in() {
    let args = parse_run(&[
        "cw", "run", "claude", "--in", "app", "--name", "coding", "--env", "FOO=bar", "--",
        "--resume", "abc",
    ]);
    assert_eq!(args.native_agent, Some(NativeAgent::Claude));
    assert_eq!(args.environment.as_deref(), Some("app"));
    assert_eq!(args.name.as_deref(), Some("coding"));
    assert_eq!(args.env, ["FOO=bar"]);
    assert_eq!(args.command, ["--resume", "abc"], "after --, the agent's own arguments");
    assert_eq!(args.agent, None);

    let args = parse_run(&["cw", "run", "codex"]);
    assert_eq!(args.native_agent, Some(NativeAgent::Codex));
    assert_eq!(args.environment, None);

    // An environment called claude is selected with --in; the positional
    // never becomes an environment.
    let args = parse_run(&["cw", "run", "--in", "claude", "--", "true"]);
    assert_eq!(args.native_agent, None);
    assert_eq!(args.environment.as_deref(), Some("claude"));
    let args = parse_run(&["cw", "run", "claude", "--in", "claude"]);
    assert_eq!(args.native_agent, Some(NativeAgent::Claude));
    assert_eq!(args.environment.as_deref(), Some("claude"));

    // Bare `cw run` parses; the handler asks or refuses.
    let args = parse_run(&["cw", "run"]);
    assert_eq!((args.native_agent, args.environment, args.command.len()), (None, None, 0));
}

#[test]
fn run_refuses_anything_but_an_agent_as_its_positional() {
    for (argv, environment) in [
        (vec!["cw", "run", "notanagent"], "notanagent"),
        (vec!["cw", "run", "app", "--", "npm", "test"], "app"),
        (vec!["cw", "run", "kimi"], "kimi"),
    ] {
        let error = Cli::try_parse_from(&argv).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation, "{argv:?}");
        let message = error.to_string();
        assert!(
            message.contains(&format!("`cw run --in {environment} -- COMMAND`")),
            "{argv:?}: {message}"
        );
    }
}

#[test]
fn managed_launch_conflicts_with_native_forms_at_parse_time() {
    let args = parse_run(&[
        "cw", "run", "--in", "app", "--agent", "claude", "--name", "review", "--detach",
        "--prompt", "Review", "--model", "m", "--effort", "high", "--parent", "lead",
    ]);
    assert_eq!(args.agent.as_deref(), Some("claude"));
    assert_eq!(args.native_agent, None);
    assert!(args.detach);
    for argv in [
        vec!["cw", "run", "claude", "--agent", "claude"],
        vec!["cw", "run", "--agent", "codex", "--", "sh"],
        vec!["cw", "run", "--agent", "codex", "--tty"],
        vec!["cw", "run", "--in", "app", "--prompt", "x"],
    ] {
        let error = Cli::try_parse_from(&argv).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict
                    | clap::error::ErrorKind::MissingRequiredArgument
            ),
            "{argv:?}: {error}"
        );
    }
}

#[test]
fn session_names_come_from_the_agent_or_command_and_stay_unique() {
    let names = |names: &[&str]| {
        names
            .iter()
            .map(|name| EnvironmentSessionView {
                session_id: format!("session-{name}"),
                name: (*name).to_owned(),
                parent_session_id: String::new(),
                cleanup_unknown: false,
                started_at: String::new(),
                launch_generation: 1,
                state: "Running".into(),
                command: Vec::new(),
                working_dir: String::new(),
                pty: true,
                exit_code: None,
                output_end_offset: 0,
                output_start_offset: 0,
                status_message: String::new(),
            })
            .collect::<Vec<_>>()
    };
    let command = |argv: &[&str]| argv.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
    assert_eq!(session_name_base(&command(&["claude", "--resume", "x"])), "claude");
    assert_eq!(session_name_base(&command(&["npm", "test"])), "npm");
    assert_eq!(session_name_base(&command(&["/usr/bin/python3", "-m", "x"])), "python3");
    assert_eq!(session_name_base(&command(&["./-build.sh"])), "build.sh");
    assert_eq!(session_name_base(&command(&["/"])), "session");
    assert_eq!(session_name_base(&[]), "session");
    assert_eq!(session_name_base(&command(&[&"x".repeat(80)])).len(), 48);

    assert_eq!(unique_session_name("claude".into(), &names(&[])), "claude");
    assert_eq!(unique_session_name("claude".into(), &names(&["codex"])), "claude");
    assert_eq!(unique_session_name("claude".into(), &names(&["claude"])), "claude-2");
    assert_eq!(
        unique_session_name("claude".into(), &names(&["claude", "claude-2", "claude-4"])),
        "claude-3"
    );
    for name in ["claude", "claude-2", "npm", "session", "build.sh"] {
        assert!(codewire_daemon_proto::valid_session_name(name), "{name}");
    }
}

#[test]
fn top_level_help_has_only_environment_session_commands() {
    let help = crate::cli_command_with(true).render_help().to_string();
    for retained in [
        "run ",
        "ls, list ",
        "attach ",
        "logs ",
        "send ",
        "wait ",
        "stop ",
        "restart ",
        "msg ",
        "steer ",
        "interrupt ",
        "inbox ",
    ] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(retained)),
            "{retained}"
        );
    }
    for removed in [
        "local ",
        "exec ",
        "node ",
        "tasks ",
        "request ",
        "reply ",
        "listen ",
        "subscribe ",
        "status ",
        "kill ",
        "watch ",
        "hook ",
        "gateway ",
        "mcp-server ",
    ] {
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with(removed)),
            "{removed}"
        );
    }
}
