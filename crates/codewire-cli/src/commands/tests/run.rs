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
        let cli = Cli::try_parse_from(["cw", "run", "-t", "builder", "--", "claude"])
            .unwrap();

        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert!(args.tty);
        assert!(!args.no_tty);
        assert_eq!(args.environment.as_deref(), Some("builder"));
    }

    #[test]
    fn run_command_parser_rejects_conflicting_tty_overrides() {
        let err =
            Cli::try_parse_from(["cw", "run", "--tty", "--no-tty", "--", "true"]).unwrap_err();
        assert!(err.to_string().contains("cannot be used with"));
    }

    #[test]
    fn top_level_help_has_only_environment_session_commands() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for retained in ["run ", "list ", "attach ", "logs "] {
            assert!(
                help.lines()
                    .any(|line| line.trim_start().starts_with(retained)),
                "{retained}"
            );
        }
        for removed in [
            "local ", "exec ", "node ", "tasks ", "msg ", "request ", "reply ", "listen ",
            "subscribe ", "status ", "wait ", "kill ", "send ", "watch ", "inbox ", "access ",
            "hook ", "gateway ", "mcp-server ",
        ] {
            assert!(
                !help
                    .lines()
                    .any(|line| line.trim_start().starts_with(removed)),
                "{removed}"
            );
        }
    }

    #[test]
    fn removed_grammar_has_exact_migration_guidance() {
        let cases = [
            (
                vec!["cw", "local", "list"],
                "`cw local` was removed; use `cw env COMMAND --local ...`",
            ),
            (
                vec!["cw", "--server", "https://example.test", "exec", "--", "true"],
                "`cw exec` was removed; use `cw run [ENV] -- COMMAND`",
            ),
            (
                vec!["cw", "node", "status"],
                "`cw node` was removed; use `cw env daemon ...` for environment-daemon diagnostics or `cw network nodes` for Mesh inventory",
            ),
            (
                vec!["cw", "run", "--local", "--", "true"],
                "`cw run --local` was removed; use `cw run ENV -- COMMAND`",
            ),
            (
                vec!["cw", "run", "--node=builder", "--", "true"],
                "`cw run --node` was removed; use `cw run ENV -- COMMAND`",
            ),
            (
                vec!["cw", "attach", "builder:session-1"],
                "`node:session` locators were removed; pass `ENV SESSION`",
            ),
            (
                vec!["cw", "env", "create", "--agent", "codex"],
                "`--agent` was renamed; use `--coding-agent`",
            ),
        ];

        for (args, expected) in cases {
            let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
            assert_eq!(legacy_cli_migration_error(&args).as_deref(), Some(expected));
        }
    }

    #[test]
    fn current_grammar_does_not_trigger_migration_guidance() {
        for args in [
            vec!["cw", "env", "--local", "list"],
            vec!["cw", "run", "builder", "--", "echo", "--node"],
            vec!["cw", "attach", "builder", "session-1"],
            vec!["cw", "env", "create", "--coding-agent", "codex"],
            vec!["cw", "network", "nodes"],
        ] {
            let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
            assert_eq!(legacy_cli_migration_error(&args), None);
        }
    }
