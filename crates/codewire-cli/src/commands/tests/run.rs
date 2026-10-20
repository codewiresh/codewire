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
    assert_eq!(vscode_environment_ref("cw-env_123"), Some("env_123"));
    assert_eq!(vscode_environment_ref("env_123"), Some("env_123"));
    assert_eq!(vscode_environment_ref(" "), None);
    assert_eq!(
        vscode_remote_uri("env_123", "/workspace/app"),
        "vscode://vscode-remote/ssh-remote+cw-env_123//workspace/app"
    );
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

#[test]
fn run_command_parser_keeps_environment_and_trailing_command() {
    let cli = Cli::try_parse_from([
        "cw",
        "run",
        "--workdir",
        "/workspace/app",
        "builder",
        "--",
        "npm",
        "test",
    ])
    .unwrap();

    let Command::Run(args) = cli.command else {
        panic!("expected run command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.workdir.as_deref(), Some("/workspace/app"));
    assert_eq!(args.command, vec!["npm", "test"]);
}

#[test]
fn run_command_parser_reserves_short_t_for_tty() {
    let cli = Cli::try_parse_from(["cw", "run", "-t", "builder", "--", "claude"]).unwrap();

    let Command::Run(args) = cli.command else {
        panic!("expected run command");
    };
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
