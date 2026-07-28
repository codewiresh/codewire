
    #[test]
    fn short_env_id_does_not_panic_on_non_ascii_refs() {
        assert_eq!(short_env_id("env😀abcdef"), "env😀a");
    }

    #[test]
    fn env_placement_parser_accepts_explicit_local_and_platform_lifecycle_forms() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "--local",
            "create",
            "--backend",
            "docker",
            "--name",
            "workspace",
            "--output",
            "json",
        ])
        .unwrap();
        let Command::Env(EnvArgs {
            local,
            platform,
            command: EnvCommand::Create(args),
        }) = cli.command
        else {
            panic!("expected local env create command");
        };
        assert!(local);
        assert!(!platform);
        assert_eq!(args.backend.as_deref(), Some("docker"));
        assert_eq!(args.name.as_deref(), Some("workspace"));
        assert_eq!(args.output, OutputFormat::Json);

        let cli = Cli::try_parse_from(["cw", "env", "--platform", "list"]).unwrap();
        let Command::Env(EnvArgs {
            local,
            platform,
            command: EnvCommand::List(_),
        }) = cli.command
        else {
            panic!("expected platform env list command");
        };
        assert!(!local);
        assert!(platform);

        assert!(Cli::try_parse_from(["cw", "env", "--local", "--platform", "list"]).is_err());
        assert!(Cli::try_parse_from(["cw", "environment", "list"]).is_err());
        assert!(Cli::try_parse_from(["cw", "env", "--local", "resize", "workspace"]).is_err());
    }

    #[test]
    fn unified_environment_list_marks_selection_and_daemon_health() {
        let local = LocalInstanceEntry {
            name: "workbench".to_string(),
            backend: "docker".to_string(),
            status: "running".to_string(),
            runtime_name: "cw-workbench".to_string(),
            repo_path: String::new(),
            workdir: "/workspace".to_string(),
            image: String::new(),
            preset: String::new(),
            install: String::new(),
            startup: String::new(),
            secrets: String::new(),
            agent: String::new(),
            env: BTreeMap::new(),
            ports: Vec::new(),
            mounts: Vec::new(),
            cpu: 0,
            memory: 0,
            disk: 0,
            created_at: String::new(),
            last_used_at: String::new(),
            lima: None,
        };
        let platform = test_environment("env-platform", Some("cloud"), "running");
        let current = config::CurrentTargetConfig {
            kind: "env".to_string(),
            target_ref: platform.id.clone(),
            name: "cloud".to_string(),
        };

        let entries = unified_environment_list_entries(
            std::slice::from_ref(&local),
            &[(platform, "ready".to_string())],
            Some(&current),
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "cloud");
        assert_eq!(entries[0].placement, "platform");
        assert!(entries[0].selected);
        assert_eq!(entries[0].daemon_health, "ready");
        assert_eq!(entries[1].name, "workbench");
        assert_eq!(entries[1].placement, "local");
        assert!(!entries[1].selected);
        assert_eq!(entries[1].daemon_health, "unknown");

        let selected_local = config::CurrentTargetConfig {
            kind: "local".to_string(),
            target_ref: "local-instance-key".to_string(),
            name: "workbench".to_string(),
        };
        let entries = unified_environment_list_entries(&[local], &[], Some(&selected_local));
        assert!(entries[0].selected);
    }

    #[test]
    fn platform_daemon_readiness_requires_a_ready_daemon() {
        let mut status = EnvironmentDaemonStatus {
            state: "starting".to_string(),
            ..EnvironmentDaemonStatus::default()
        };
        assert!(!environment_daemon_readiness(&status).unwrap());

        status.state = "ready".to_string();
        assert!(environment_daemon_readiness(&status).unwrap());

        status.state = "upgrade_required".to_string();
        assert_eq!(
            environment_daemon_readiness(&status).unwrap_err().to_string(),
            "environment daemon requires an upgrade; run `cw env daemon repair`"
        );

        status.state = "unhealthy".to_string();
        status.message = "session store unavailable".to_string();
        assert_eq!(
            environment_daemon_readiness(&status).unwrap_err().to_string(),
            "environment daemon is unhealthy (session store unavailable); run `cw env daemon status` or `cw env daemon repair`"
        );
    }

    #[test]
    fn local_and_platform_create_options_do_not_cross_placements() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "--local",
            "create",
            "--backend",
            "docker",
            "--repo",
            "https://example.invalid/repo.git",
        ])
        .unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::Create(args),
            ..
        }) = cli.command
        else {
            panic!("expected local environment create");
        };
        assert_eq!(
            local_create_args_from_environment_args(*args)
                .unwrap_err()
                .to_string(),
            "repository arguments are only supported for --platform environment creation"
        );

        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "--platform",
            "create",
            "--backend",
            "docker",
        ])
        .unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::Create(args),
            ..
        }) = cli.command
        else {
            panic!("expected platform environment create");
        };
        assert_eq!(
            reject_local_create_options(&args).unwrap_err().to_string(),
            "--backend, --path, --file, and --spec require `cw env --local create`"
        );
    }

    #[test]
    fn ambiguous_placement_error_gives_both_exact_commands() {
        assert_eq!(
            ambiguous_environment_placement_error("start", "workspace").to_string(),
            "environment \"workspace\" exists in both placements; use `cw env --local start workspace` or `cw env --platform start workspace`"
        );
    }

    #[test]
    fn use_parser_accepts_explicit_environment_placement() {
        let cli = Cli::try_parse_from(["cw", "use", "--local", "workbench"]).unwrap();
        let Command::Use(UseTargetArgs {
            local,
            platform,
            target,
        }) = cli.command
        else {
            panic!("expected use command");
        };
        assert!(local);
        assert!(!platform);
        assert_eq!(target, "workbench");
        assert!(Cli::try_parse_from(["cw", "use", "--local", "--platform", "workbench"])
            .is_err());
    }

    #[test]
    fn env_command_parser_accepts_filters_without_a_legacy_alias() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "list",
            "--type",
            "sandbox",
            "--state",
            "running",
            "--all",
            "--output",
            "json",
        ])
        .unwrap();

        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::List(args) = command else {
            panic!("expected env list command");
        };
        assert_eq!(args.environment_type.as_deref(), Some("sandbox"));
        assert_eq!(args.state.as_deref(), Some("running"));
        assert!(args.all);
        assert!(matches!(args.output, OutputFormat::Json));
    }

    #[test]
    fn list_command_parser_rejects_legacy_platform_flags() {
        let error = Cli::try_parse_from([
            "cw",
            "list",
            "--runs",
            "--network",
            "project-alpha",
            "--org",
            "noel-labs",
            "--output",
            "json",
            "--status",
            "all",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("unexpected argument"));
    }

    #[test]
    fn env_create_parser_accepts_direct_create_flags() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "https://github.com/codewiresh/codewire@main",
            "--repo",
            "git@github.com:codewiresh/sdk",
            "--preset",
            "go",
            "--name",
            "builder",
            "--ttl",
            "1h",
            "--cpu",
            "2000",
            "--memory",
            "4096",
            "--disk",
            "40",
            "--image",
            "workspace",
            "--install",
            "go mod download",
            "--startup",
            "go test ./...",
            "--coding-agent",
            "codex",
            "--env",
            "FOO=bar",
            "--secrets",
            "prod",
            "--no-org-secrets",
            "--no-user-secrets",
            "--no-wait",
            "--yes",
        ])
        .unwrap();

        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };

        assert_eq!(
            args.repo_urls,
            vec!["https://github.com/codewiresh/codewire@main"]
        );
        assert_eq!(args.repo_flags, vec!["git@github.com:codewiresh/sdk"]);
        assert_eq!(args.preset_slug.as_deref(), Some("go"));
        assert_eq!(args.name.as_deref(), Some("builder"));
        assert_eq!(args.ttl.as_deref(), Some("1h"));
        assert_eq!(args.cpu, Some(2000));
        assert_eq!(args.memory, Some(4096));
        assert_eq!(args.disk, Some(40));
        assert_eq!(args.image.as_deref(), Some("workspace"));
        assert_eq!(args.coding_agent.as_deref(), Some("codex"));
        assert!(args.no_org_secrets);
        assert!(args.no_user_secrets);
        assert!(args.no_wait);
        assert!(args.yes);
    }

    #[test]
    fn env_create_request_matches_go_direct_flags() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "https://github.com/codewiresh/codewire@main",
            "--preset",
            "go",
            "--preset-id",
            "preset_123",
            "--name",
            "builder",
            "--ttl",
            "1h30m",
            "--cpu",
            "2000",
            "--memory",
            "4096",
            "--disk",
            "40",
            "--image",
            "workspace",
            "--install",
            "go mod download",
            "--startup",
            "go test ./...",
            "--coding-agent",
            "codex",
            "--env",
            "FOO=bar",
            "--secrets",
            "prod",
            "--no-org-secrets",
            "--no-user-secrets",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };

        let request = prepare_platform_env_create_request(&args).unwrap();

        assert_eq!(request.preset_id.as_deref(), Some("preset_123"));
        assert_eq!(request.name.as_deref(), Some("builder"));
        assert_eq!(request.cpu_millicores, Some(2000));
        assert_eq!(request.memory_mb, Some(4096));
        assert_eq!(request.disk_gb, Some(40));
        assert_eq!(request.ttl_seconds, Some(5400));
        assert_eq!(request.preset_slug, "go");
        assert_eq!(request.repo_url, "https://github.com/codewiresh/codewire");
        assert_eq!(request.branch, "main");
        assert_eq!(request.repos.len(), 1);
        assert_eq!(request.repos[0].branch, "main");
        assert_eq!(request.image, "ghcr.io/codewiresh/workspace:latest");
        assert_eq!(request.install_command, "go mod download");
        assert_eq!(request.startup_script, "go test ./...");
        assert_eq!(request.env_vars["FOO"], "bar");
        assert_eq!(request.agents[0].agent_type, "codex");
        assert_eq!(request.agent, "codex");
        assert_eq!(request.secret_project, "prod");
        assert_eq!(request.include_org_secrets, Some(false));
        assert_eq!(request.include_user_secrets, Some(false));
    }

    #[test]
    fn env_create_preset_authoring_flags_do_not_block_request_resolution() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "--image",
            "workspace",
            "--write-preset",
            "--save-preset",
            "Fullstack Dev",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };

        let request = prepare_platform_env_create_request(&args).unwrap();

        assert!(args.write_preset);
        assert_eq!(args.save_preset.as_deref(), Some("Fullstack Dev"));
        assert_eq!(request.image, "ghcr.io/codewiresh/workspace:latest");
    }

    #[test]
    fn env_create_bare_defaults_to_workspace_image() {
        let cli = Cli::try_parse_from(["cw", "env", "create"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };

        let request = prepare_platform_env_create_request(&args).unwrap();

        assert_eq!(request.image, "ghcr.io/codewiresh/workspace:latest");
        assert!(request.preset_id.is_none());
        assert!(request.preset_slug.is_empty());
        assert!(request.repo_url.is_empty());
    }

    #[test]
    fn env_create_explicit_sources_do_not_add_the_default_image() {
        let cli = Cli::try_parse_from(["cw", "env", "create", "--preset", "rust"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        let request = prepare_platform_env_create_request(&args).unwrap();
        assert_eq!(request.preset_slug, "rust");
        assert!(request.image.is_empty());

        let cli =
            Cli::try_parse_from(["cw", "env", "create", "--preset-id", "preset_123"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        let request = prepare_platform_env_create_request(&args).unwrap();
        assert_eq!(request.preset_id.as_deref(), Some("preset_123"));
        assert!(request.image.is_empty());

        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "https://github.com/codewiresh/codewire",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        let request = prepare_platform_env_create_request(&args).unwrap();
        assert_eq!(
            request.repo_url,
            "https://github.com/codewiresh/codewire"
        );
        assert!(request.image.is_empty());
    }

    #[test]
    fn init_command_parser_accepts_direct_flags() {
        let cli = Cli::try_parse_from([
            "cw",
            "init",
            "--image",
            "workspace",
            "--install",
            "pnpm install",
            "--startup",
            "pnpm dev",
            "--coding-agent",
            "codex",
            "--env",
            "FOO=bar",
            "--secrets",
            "prod",
            "--no-user-secrets",
            "--file",
            "project/codewire.yaml",
            "--force",
            "--yes",
        ])
        .unwrap();

        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        assert_eq!(args.image.as_deref(), Some("workspace"));
        assert_eq!(args.install.as_deref(), Some("pnpm install"));
        assert_eq!(args.startup.as_deref(), Some("pnpm dev"));
        assert_eq!(args.coding_agent.as_deref(), Some("codex"));
        assert_eq!(args.env, vec!["FOO=bar"]);
        assert_eq!(args.secret_project.as_deref(), Some("prod"));
        assert!(args.no_user_secrets);
        assert_eq!(args.file, PathBuf::from("project/codewire.yaml"));
        assert!(args.force);
        assert!(args.yes);
    }

    #[tokio::test]
    async fn init_command_writes_codewire_yaml_from_direct_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/codewire.yaml");
        let cli = Cli::try_parse_from(vec![
            "cw".to_string(),
            "init".to_string(),
            "--image".to_string(),
            "workspace".to_string(),
            "--install".to_string(),
            "pnpm install".to_string(),
            "--startup".to_string(),
            "pnpm dev".to_string(),
            "--coding-agent".to_string(),
            "claude-code".to_string(),
            "--env".to_string(),
            "FOO=bar".to_string(),
            "--secrets".to_string(),
            "prod".to_string(),
            "--cpu".to_string(),
            "2000".to_string(),
            "--memory".to_string(),
            "4096".to_string(),
            "--disk".to_string(),
            "40".to_string(),
            "--no-user-secrets".to_string(),
            "--file".to_string(),
            path.display().to_string(),
        ])
        .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        let globals = Globals {
            server: None,
            token: None,
        };
        handle_init_command(&globals, args).await.unwrap();

        let yaml = fs::read_to_string(&path).unwrap();
        let parsed: config::CodewireConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.image, "ghcr.io/codewiresh/workspace:latest");
        assert_eq!(parsed.install, "pnpm install");
        assert_eq!(parsed.startup, "pnpm dev");
        assert_eq!(parsed.env["FOO"], "bar");
        assert_eq!(parsed.cpu, 2000);
        assert_eq!(parsed.memory, 4096);
        assert_eq!(parsed.disk, 40);
        assert_eq!(parsed.secrets.as_ref().unwrap().project, "prod");
        assert_eq!(parsed.secrets.as_ref().unwrap().user, Some(false));
        assert_eq!(
            parsed.agents.as_ref().unwrap().tools,
            vec!["claude".to_string()]
        );
    }

    #[tokio::test]
    async fn init_command_refuses_existing_file_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(&path, "image: old\n").unwrap();
        let cli = Cli::try_parse_from(vec![
            "cw".to_string(),
            "init".to_string(),
            "--image".to_string(),
            "workspace".to_string(),
            "--file".to_string(),
            path.display().to_string(),
        ])
        .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        let globals = Globals {
            server: None,
            token: None,
        };
        let err = handle_init_command(&globals, args).await.unwrap_err();

        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read_to_string(path).unwrap(), "image: old\n");
    }

    #[test]
    fn init_command_builds_prepare_request_for_server_side_modes() {
        let cli = Cli::try_parse_from([
            "cw",
            "init",
            "https://github.com/codewiresh/codewire@main",
            "--repo",
            "git@github.com:codewiresh/sdk",
            "--preset",
            "go",
            "--preset-id",
            "preset_123",
            "--name",
            "builder",
            "--ttl",
            "1h",
            "--cpu",
            "2000",
            "--memory",
            "4096",
            "--disk",
            "40",
            "--coding-agent",
            "codex",
            "--env",
            "FOO=bar",
            "--secrets",
            "prod",
            "--no-user-secrets",
        ])
        .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        assert!(init_needs_platform_resolution(&args));
        let request = init_prepare_request_from_args_with_repo_detector(&args, || {
            panic!("explicit repo inputs should not call local repo detection")
        })
        .unwrap();

        assert_eq!(request.analyze, None);
        assert_eq!(request.draft.preset_id.as_deref(), Some("preset_123"));
        assert_eq!(request.draft.preset_slug, "go");
        assert_eq!(request.draft.name.as_deref(), Some("builder"));
        assert_eq!(request.draft.ttl_seconds, Some(3600));
        assert_eq!(
            request.draft.repo_url,
            "https://github.com/codewiresh/codewire"
        );
        assert_eq!(request.draft.branch, "");
        assert_eq!(request.draft.repos.len(), 2);
        assert_eq!(request.draft.repos[0].branch, "main");
        assert_eq!(request.draft.repos[1].url, "git@github.com:codewiresh/sdk");
        assert_eq!(request.draft.cpu_millicores, Some(2000));
        assert_eq!(request.draft.memory_mb, Some(4096));
        assert_eq!(request.draft.disk_gb, Some(40));
        assert_eq!(request.draft.env_vars["FOO"], "bar");
        assert_eq!(request.draft.agents[0].agent_type, "codex");
        assert_eq!(request.draft.secret_project, "prod");
        assert_eq!(request.draft.include_user_secrets, Some(false));
    }

    #[test]
    fn init_command_detects_local_repo_when_no_direct_inputs() {
        let cli = Cli::try_parse_from(["cw", "init", "--branch", "dev"]).unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        let request = init_prepare_request_from_args_with_repo_detector(&args, || {
            Ok((
                "https://github.com/codewiresh/codewire".to_string(),
                "main".to_string(),
            ))
        })
        .unwrap();

        assert!(init_needs_platform_resolution(&args));
        assert_eq!(
            request.draft.repo_url,
            "https://github.com/codewiresh/codewire"
        );
        assert_eq!(request.draft.branch, "dev");
    }

    #[test]
    fn init_command_rejects_branch_without_repo_for_direct_modes() {
        let cli = Cli::try_parse_from(["cw", "init", "--image", "workspace", "--branch", "main"])
            .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        let err = init_prepare_request_from_args_with_repo_detector(&args, || {
            panic!("direct branch validation should not call local repo detection")
        })
        .unwrap_err();

        assert!(err.to_string().contains("--branch requires a repo URL"));
    }

    #[test]
    fn init_direct_request_keeps_ttl_for_save_preset_but_yaml_omits_it() {
        let cli = Cli::try_parse_from([
            "cw",
            "init",
            "--image",
            "workspace",
            "--name",
            "builder",
            "--ttl",
            "2h",
            "--save-preset",
            "Builder",
        ])
        .unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init command");
        };

        assert!(!init_needs_platform_resolution(&args));
        let request = init_request_from_args(&args).unwrap();
        let yaml = serde_yaml::to_string(&codewire_yaml_from_request(&request)).unwrap();

        assert_eq!(request.name.as_deref(), Some("builder"));
        assert_eq!(request.ttl_seconds, Some(7200));
        assert!(!yaml.contains("name:"));
        assert!(!yaml.contains("ttl"));
    }

    #[test]
    fn normalize_git_url_matches_go_helper() {
        assert_eq!(
            normalize_git_url("git@github.com:codewiresh/codewire.git"),
            "https://github.com/codewiresh/codewire"
        );
        assert_eq!(
            normalize_git_url("ssh://git@github.com/codewiresh/codewire.git"),
            "https://github.com/codewiresh/codewire"
        );
        assert_eq!(
            normalize_git_url("https://github.com/codewiresh/codewire.git"),
            "https://github.com/codewiresh/codewire"
        );
    }

    #[test]
    fn codewire_yaml_from_request_matches_go_authoring_shape() {
        let request = CreateEnvironmentRequest {
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            install_command: "bun install".to_string(),
            startup_script: "bun dev".to_string(),
            env_vars: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
            cpu_millicores: Some(2000),
            memory_mb: Some(4096),
            disk_gb: Some(40),
            agents: vec![SetupAgent {
                agent_type: "claude-code".to_string(),
            }],
            secret_project: "prod".to_string(),
            include_user_secrets: Some(false),
            app_ports: vec![crate::presentation::AppPort {
                port: 8080,
                label: "web".to_string(),
                access: String::new(),
            }],
            ..CreateEnvironmentRequest::default()
        };
        let yaml = serde_yaml::to_string(&codewire_yaml_from_request(&request)).unwrap();
        let parsed: config::CodewireConfig = serde_yaml::from_str(&yaml).unwrap();

        assert!(!yaml.contains("preset:"));
        assert_eq!(parsed.image, "ghcr.io/codewiresh/workspace:latest");
        assert_eq!(parsed.install, "bun install");
        assert_eq!(parsed.startup, "bun dev");
        assert_eq!(parsed.env["FOO"], "bar");
        assert_eq!(parsed.cpu, 2000);
        assert_eq!(parsed.memory, 4096);
        assert_eq!(parsed.disk, 40);
        assert_eq!(parsed.ports[0].port, 8080);
        assert_eq!(parsed.ports[0].label, "web");
        assert_eq!(
            parsed.agents.as_ref().unwrap().tools,
            vec!["claude".to_string()]
        );
        let secrets = parsed.secrets.as_ref().unwrap();
        assert_eq!(secrets.org, Some(true));
        assert_eq!(secrets.user, Some(false));
        assert_eq!(secrets.project, "prod");
    }

    #[test]
    fn write_resolved_codewire_yaml_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/codewire.yaml");
        let request = CreateEnvironmentRequest {
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            install_command: "go mod download".to_string(),
            ..CreateEnvironmentRequest::default()
        };

        write_resolved_codewire_yaml(&path, &request).unwrap();

        let parsed = config::load_codewire_config(&path).unwrap();
        assert_eq!(parsed.image, "ghcr.io/codewiresh/workspace:latest");
        assert_eq!(parsed.install, "go mod download");
    }

    #[test]
    fn create_preset_request_from_environment_matches_go_shape() {
        let request = CreateEnvironmentRequest {
            cpu_millicores: Some(2000),
            memory_mb: Some(4096),
            disk_gb: Some(40),
            ttl_seconds: Some(3600),
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            install_command: "bun install".to_string(),
            startup_script: "bun dev".to_string(),
            env_vars: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
            agents: vec![SetupAgent {
                agent_type: "claude-code".to_string(),
            }],
            install_agents: Some(true),
            agent: "claude-code".to_string(),
            agent_env: BTreeMap::from([("ANTHROPIC_MODEL".to_string(), "opus".to_string())]),
            app_ports: vec![crate::presentation::AppPort {
                port: 8080,
                label: "web".to_string(),
                access: "public".to_string(),
            }],
            include_org_secrets: Some(false),
            include_user_secrets: Some(true),
            secret_project: "prod".to_string(),
            ..CreateEnvironmentRequest::default()
        };

        let preset = create_preset_request_from_environment("Fullstack Dev!", &request).unwrap();

        assert_eq!(preset.name, "Fullstack Dev!");
        assert_eq!(preset.slug, "fullstack-dev");
        assert_eq!(preset.default_cpu_millicores, Some(2000));
        assert_eq!(preset.default_ttl_seconds, Some(3600));
        assert_eq!(preset.image, "ghcr.io/codewiresh/workspace:latest");
        assert_eq!(preset.env_vars["FOO"], "bar");
        assert_eq!(preset.agents[0]["type"], "claude-code");
        assert_eq!(preset.app_ports[0]["port"], 8080);
        assert_eq!(preset.include_org_secrets, Some(false));
        assert_eq!(preset.secret_project, "prod");
    }

    #[test]
    fn env_create_repo_specs_match_go_branch_parsing() {
        assert_eq!(
            parse_env_create_repo_spec("https://github.com/codewiresh/codewire@main").unwrap(),
            (
                "https://github.com/codewiresh/codewire".to_string(),
                "main".to_string()
            )
        );
        assert_eq!(
            parse_env_create_repo_spec("git@github.com:codewiresh/codewire").unwrap(),
            (
                "git@github.com:codewiresh/codewire".to_string(),
                String::new()
            )
        );
        assert_eq!(
            parse_env_create_repo_spec("git@github.com:codewiresh/codewire@dev").unwrap(),
            (
                "git@github.com:codewiresh/codewire".to_string(),
                "dev".to_string()
            )
        );

        let (repo_url, branch, repos) = collect_env_create_repos(
            &[
                "https://github.com/codewiresh/codewire@main".to_string(),
                "https://github.com/codewiresh/sdk@v1".to_string(),
            ],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(repo_url, "https://github.com/codewiresh/codewire");
        assert_eq!(branch, "");
        assert_eq!(repos[0].branch, "main");
        assert_eq!(repos[1].branch, "v1");
    }

    #[test]
    fn env_create_accepts_mesh_bootstrap_flags() {
        let cli =
            Cli::try_parse_from(["cw", "env", "create", "--network", "project-alpha"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        let request = env_create_request_from_args(&args).unwrap();
        assert_eq!(
            request.env_vars.get(config::CODEWIRE_MESH_NETWORK_ENV),
            None,
            "network invite bootstrap is injected only after Mesh resolution"
        );

        let cli = Cli::try_parse_from(["cw", "env", "create", "--no-network"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        assert!(args.no_network);
        env_create_request_from_args(&args).unwrap();
    }

    #[test]
    fn env_create_mesh_bootstrap_injects_mesh_first_setup_env() {
        let mut request = CreateEnvironmentRequest::default();

        inject_env_create_mesh_bootstrap(
            &mut request,
            "https://mesh.example.com",
            "project-alpha",
            "cw_invite_123",
        )
        .unwrap();

        assert_eq!(
            request.env_vars.get(config::CODEWIRE_MESH_URL_ENV).unwrap(),
            "https://mesh.example.com"
        );
        assert_eq!(
            request
                .env_vars
                .get(config::CODEWIRE_MESH_NETWORK_ENV)
                .unwrap(),
            "project-alpha"
        );
        assert_eq!(
            request
                .env_vars
                .get(config::CODEWIRE_MESH_INVITE_CODE_ENV)
                .unwrap(),
            "cw_invite_123"
        );
    }

    #[test]
    fn env_create_mesh_bootstrap_rejects_reserved_env_collision() {
        let mut request = CreateEnvironmentRequest {
            env_vars: BTreeMap::from([(
                config::CODEWIRE_MESH_NETWORK_ENV.to_string(),
                "user-value".to_string(),
            )]),
            ..CreateEnvironmentRequest::default()
        };

        let error = inject_env_create_mesh_bootstrap(
            &mut request,
            "https://mesh.example.com",
            "project-alpha",
            "cw_invite_123",
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "CODEWIRE_MESH_NETWORK is reserved for mesh bootstrap"
        );
        assert_eq!(
            request.env_vars,
            BTreeMap::from([(
                config::CODEWIRE_MESH_NETWORK_ENV.to_string(),
                "user-value".to_string(),
            )]),
            "validation must not partially inject bootstrap variables"
        );
    }

    #[test]
    fn platform_env_create_validates_reserved_mesh_env_before_bootstrap() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "--env",
            "CODEWIRE_MESH_URL=https://mesh.example.com",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };

        assert_eq!(
            prepare_platform_env_create_request(&args)
                .unwrap_err()
                .to_string(),
            "CODEWIRE_MESH_URL is reserved for mesh bootstrap"
        );

        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "create",
            "--no-network",
            "--env",
            "CODEWIRE_MESH_URL=https://mesh.example.com",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Create(args) = command else {
            panic!("expected env create command");
        };
        let request = prepare_platform_env_create_request(&args).unwrap();
        assert_eq!(
            request.env_vars.get(config::CODEWIRE_MESH_URL_ENV),
            Some(&"https://mesh.example.com".to_string())
        );
    }

    #[test]
    fn platform_env_mesh_bootstrap_pins_explicit_network_to_hosted_origin() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        for (server_url, expected_mesh_url) in [
            ("https://codewire.sh", "https://mesh.codewire.sh"),
            ("https://codewire-dev.sh", "https://mesh.codewire-dev.sh"),
        ] {
            let platform = config::ResolvedPlatformConfig::static_token(
                server_url,
                "platform-token",
                true,
                None,
            );
            let bootstrap = resolve_env_create_mesh_bootstrap(
                &paths,
                &env,
                &platform,
                "org-alpha",
                true,
                Some("local-dev"),
                false,
            )
            .unwrap()
            .unwrap();

            assert_eq!(bootstrap.mesh.mesh_url, expected_mesh_url);
            assert_eq!(bootstrap.organization_id, "org-alpha");
            assert_eq!(bootstrap.network_id, "local-dev");
        }
    }

    #[test]
    fn platform_env_mesh_bootstrap_does_not_inherit_saved_local_mesh_pairing() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        config::save_mesh_connection(
            &paths.mesh_data_dir,
            "http://127.0.0.1:18090",
            "local-token",
        )
        .unwrap();
        config::save_selected_mesh_network(&paths.mesh_data_dir, "local-dev").unwrap();
        let identity = config::ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap();
        let globals = Globals {
            server: None,
            token: Some("platform-token".to_string()),
        };
        let platform = config::ResolvedPlatformConfig::static_token(
            "https://codewire-dev.sh",
            "platform-token",
            true,
            None,
        );

        assert!(
            resolve_env_create_mesh_bootstrap(
                &paths,
                &env,
                &platform,
                "org-alpha",
                true,
                None,
                false,
            )
            .unwrap()
            .is_none(),
            "a saved local origin-network pair must not become a platform bootstrap"
        );

        let local = resolve_local_mesh_bootstrap(&globals, &paths, &env, true, None, false)
            .unwrap()
            .unwrap();
        assert_eq!(local.mesh.mesh_url, "http://127.0.0.1:18090");
        assert_eq!(local.organization_id, identity.organization_id);
        assert_eq!(local.network_id, "local-dev");

        config::save_mesh_connection(
            &paths.mesh_data_dir,
            "https://mesh.codewire-dev.sh",
            "hosted-token",
        )
        .unwrap();
        let hosted = resolve_env_create_mesh_bootstrap(
            &paths,
            &env,
            &platform,
            "org-alpha",
            true,
            None,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(hosted.mesh.mesh_url, "https://mesh.codewire-dev.sh");
        assert_eq!(hosted.network_id, "local-dev");
    }

    #[test]
    fn platform_env_mesh_prompt_names_hosted_origin_and_network() {
        assert_eq!(
            env_create_mesh_prompt("https://mesh.codewire-dev.sh", "local-dev"),
            "Join hosted Mesh network \"local-dev\" at https://mesh.codewire-dev.sh for this platform environment. Continue"
        );
    }

    #[test]
    fn env_create_text_matches_go_messages() {
        let mut environment = test_environment("env_123", Some("builder"), "creating");
        environment.environment_type = "sandbox".to_string();
        environment.cpu_millicores = 2000;
        environment.memory_mb = 4096;
        environment.disk_gb = 40;

        assert_eq!(
            format_env_create_text(&environment),
            concat!(
                "Environment created: builder\n",
                "  ID:    env_123\n",
                "  State: creating\n",
                "  Type:  sandbox\n",
                "  CPU:   2000m\n",
                "  Mem:   4096MB\n",
                "  Disk:  40GB\n",
            )
        );
    }

    #[test]
    fn env_lifecycle_parsers_accept_targets_and_output() {
        let cli =
            Cli::try_parse_from(["cw", "env", "start", "builder", "--output", "json"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Start(args) = command else {
            panic!("expected env start command");
        };
        assert_eq!(args.environment, "builder");
        assert!(matches!(args.output, OutputFormat::Json));

        let cli = Cli::try_parse_from(["cw", "env", "rm", "builder", "--yes"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Rm(args) = command else {
            panic!("expected env delete command");
        };
        assert_eq!(args.environment, "builder");
        assert!(args.yes);
        assert!(Cli::try_parse_from(["cw", "env", "delete", "builder"]).is_err());
        assert!(Cli::try_parse_from(["cw", "env", "ls"]).is_err());
    }

    #[test]
    fn env_daemon_parsers_accept_status_logs_and_repair() {
        let cli = Cli::try_parse_from(["cw", "daemon"]).unwrap();
        assert!(
            matches!(cli.command, Command::Daemon),
            "the self-contained binary must retain its managed daemon entrypoint"
        );

        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "daemon",
            "status",
            "builder",
            "--output",
            "json",
        ])
        .unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::Daemon(args),
            ..
        }) = cli.command
        else {
            panic!("expected env daemon command");
        };
        let EnvDaemonCommand::Status(args) = args.command else {
            panic!("expected daemon status");
        };
        assert_eq!(args.environment.as_deref(), Some("builder"));
        assert!(matches!(args.output, OutputFormat::Json));

        let cli =
            Cli::try_parse_from(["cw", "env", "daemon", "logs", "builder"]).unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::Daemon(args),
            ..
        }) = cli.command
        else {
            panic!("expected env daemon command");
        };
        let EnvDaemonCommand::Logs(args) = args.command else {
            panic!("expected daemon logs");
        };
        assert_eq!(args.environment.as_deref(), Some("builder"));

        let cli =
            Cli::try_parse_from(["cw", "env", "daemon", "repair", "builder"]).unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::Daemon(args),
            ..
        }) = cli.command
        else {
            panic!("expected env daemon command");
        };
        assert!(matches!(args.command, EnvDaemonCommand::Repair(_)));

        let cli =
            Cli::try_parse_from(["cw", "env", "--local", "daemon", "status"]).unwrap();
        let Command::Env(EnvArgs {
            local,
            command: EnvCommand::Daemon(args),
            ..
        }) = cli.command
        else {
            panic!("expected selected local daemon command");
        };
        assert!(local);
        let EnvDaemonCommand::Status(args) = args.command else {
            panic!("expected selected daemon status");
        };
        assert!(args.environment.is_none());
    }

    #[test]
    fn local_daemon_state_names_match_public_diagnostic_vocabulary() {
        use codewire_daemon::client::v1::DaemonState;

        assert_eq!(local_daemon_state_name(DaemonState::Unspecified), "unspecified");
        assert_eq!(local_daemon_state_name(DaemonState::Unsupported), "unsupported");
        assert_eq!(local_daemon_state_name(DaemonState::Starting), "starting");
        assert_eq!(local_daemon_state_name(DaemonState::Ready), "ready");
        assert_eq!(local_daemon_state_name(DaemonState::Unhealthy), "unhealthy");
        assert_eq!(
            local_daemon_state_name(DaemonState::UpgradeRequired),
            "upgrade_required"
        );
    }

    #[test]
    fn env_daemon_status_renders_actionable_upgrade_state_without_credentials() {
        let status = EnvironmentDaemonStatus {
            state: "upgrade_required".into(),
            protocol_version: 1,
            minimum_protocol_version: 1,
            daemon_version: "0.1.0".into(),
            capabilities: vec!["health.v1".into(), "sessions.v1".into()],
            message: "upgrade the environment daemon".into(),
            diagnostics: vec![crate::presentation::EnvironmentDaemonDiagnostic {
                name: "protocol".into(),
                healthy: false,
                message: "client protocol is newer".into(),
            }],
            pod_name: "workspace-pod".into(),
        };

        let rendered = format_environment_daemon_status(&status);
        assert!(rendered.contains("Environment daemon: upgrade_required"));
        assert!(rendered.contains("upgrade the environment daemon"));
        assert!(rendered.contains("protocol: unhealthy (client protocol is newer)"));
        assert!(!rendered.to_ascii_lowercase().contains("token"));
    }

    #[test]
    fn env_cp_parser_accepts_source_and_destination() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "cp",
            "local.txt",
            "builder:/workspace/local.txt",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Cp(args) = command else {
            panic!("expected env cp command");
        };
        assert_eq!(args.src, "local.txt");
        assert_eq!(args.dst, "builder:/workspace/local.txt");
    }

    #[test]
    fn env_cp_remote_path_parsing_matches_go() {
        assert_eq!(
            parse_env_remote_path("builder:/workspace/file.txt"),
            Some(("builder", "/workspace/file.txt"))
        );
        assert_eq!(parse_env_remote_path("relative.txt"), None);
        assert_eq!(parse_env_remote_path(":missing-env"), None);
        assert_eq!(parse_env_remote_path("C:\\Users\\Noel\\file.txt"), None);

        let (src, dst) = env_cp_remote_paths("local.txt", "builder:/workspace/local.txt").unwrap();
        assert_eq!(src, None);
        assert_eq!(dst, Some(("builder", "/workspace/local.txt")));

        let (src, dst) = env_cp_remote_paths("builder:/workspace/file.txt", "./file.txt").unwrap();
        assert_eq!(src, Some(("builder", "/workspace/file.txt")));
        assert_eq!(dst, None);

        assert_eq!(
            env_cp_remote_paths("one:/a", "two:/b")
                .unwrap_err()
                .to_string(),
            "cannot copy between two remote environments"
        );
        assert_eq!(
            env_cp_remote_paths("one.txt", "two.txt")
                .unwrap_err()
                .to_string(),
            "at least one path must be remote (<env_id>:<path>)"
        );
    }

    #[test]
    fn env_cp_text_matches_go_messages() {
        assert_eq!(
            format_env_cp_upload_text("local.txt", "env_123", "/workspace/local.txt"),
            "Uploaded local.txt -> env_123:/workspace/local.txt\n"
        );
        assert_eq!(
            format_env_cp_download_text("env_123", "/workspace/file.txt", "./file.txt", 42),
            "Downloaded env_123:/workspace/file.txt -> ./file.txt (42 bytes)\n"
        );
    }

    #[test]
    fn env_protection_parsers_accept_targets_and_hours() {
        let cli = Cli::try_parse_from(["cw", "env", "protect", "builder"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Protect(args) = command else {
            panic!("expected env protect command");
        };
        assert_eq!(args.environment, "builder");

        let cli = Cli::try_parse_from(["cw", "env", "extend", "builder", "--hours", "3"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Extend(args) = command else {
            panic!("expected env extend command");
        };
        assert_eq!(args.environment, "builder");
        assert_eq!(args.hours, 3);
    }

    #[test]
    fn env_access_parsers_accept_targets_user_and_permission() {
        let cli =
            Cli::try_parse_from(["cw", "env", "access", "list", "builder", "--output", "json"])
                .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Access(args) = command else {
            panic!("expected env access command");
        };
        let EnvAccessCommand::List(args) = args.command else {
            panic!("expected env access list command");
        };
        assert_eq!(args.environment, "builder");
        assert!(matches!(args.output, OutputFormat::Json));

        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "access",
            "grant",
            "builder",
            "--user",
            "user-2",
            "--permission",
            "operator",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Access(args) = command else {
            panic!("expected env access command");
        };
        let EnvAccessCommand::Grant(args) = args.command else {
            panic!("expected env access grant command");
        };
        assert_eq!(args.environment, "builder");
        assert_eq!(args.user, "user-2");
        assert_eq!(args.permission, "operator");

        let cli = Cli::try_parse_from([
            "cw", "env", "access", "revoke", "builder", "--user", "user-2",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Access(args) = command else {
            panic!("expected env access command");
        };
        let EnvAccessCommand::Revoke(args) = args.command else {
            panic!("expected env access revoke command");
        };
        assert_eq!(args.environment, "builder");
        assert_eq!(args.user, "user-2");
    }

    #[test]
    fn env_port_parsers_accept_add_list_rm() {
        let cli = Cli::try_parse_from([
            "cw", "env", "port", "add", "3000", "--label", "web", "--access", "public", "--env",
            "builder", "--output", "json",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Port(args) = command else {
            panic!("expected env port command");
        };
        let EnvPortCommand::Add(args) = args.command else {
            panic!("expected env port add command");
        };
        assert_eq!(args.port, "3000");
        assert_eq!(args.label, "web");
        assert_eq!(args.access, "public");
        assert_eq!(args.env.as_deref(), Some("builder"));
        assert!(matches!(args.output, OutputFormat::Json));

        let cli = Cli::try_parse_from(["cw", "env", "port", "ls", "--env", "builder"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Port(args) = command else {
            panic!("expected env port command");
        };
        let EnvPortCommand::List(args) = args.command else {
            panic!("expected env port list command");
        };
        assert_eq!(args.env.as_deref(), Some("builder"));

        let cli = Cli::try_parse_from(["cw", "env", "port", "rm", "web"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Port(args) = command else {
            panic!("expected env port command");
        };
        let EnvPortCommand::Rm(args) = args.command else {
            panic!("expected env port rm command");
        };
        assert_eq!(args.port, "web");
    }

    #[test]
    fn env_logs_parser_accepts_follow_flag_forms() {
        let cli = Cli::try_parse_from(["cw", "env", "logs", "builder"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Logs(args) = command else {
            panic!("expected env logs command");
        };
        assert_eq!(args.environment, "builder");
        assert!(args.follow);

        let cli = Cli::try_parse_from(["cw", "env", "logs", "builder", "--follow=false"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Logs(args) = command else {
            panic!("expected env logs command");
        };
        assert_eq!(args.environment, "builder");
        assert!(!args.follow);
    }

    #[test]
    fn env_prune_nuke_parsers_accept_safety_flags() {
        let cli = Cli::try_parse_from([
            "cw",
            "env",
            "prune",
            "--state",
            "error,failed",
            "--dry-run",
            "--yes",
        ])
        .unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Prune(args) = command else {
            panic!("expected env prune command");
        };
        assert_eq!(args.state, "error,failed");
        assert!(args.dry_run);
        assert!(args.yes);

        let cli = Cli::try_parse_from(["cw", "env", "nuke", "--yes"]).unwrap();
        let Command::Env(EnvArgs { command, .. }) = cli.command else {
            panic!("expected env command");
        };
        let EnvCommand::Nuke(args) = command else {
            panic!("expected env nuke command");
        };
        assert!(args.yes);
    }

    #[test]
    fn env_bulk_selection_skips_protected_targets() {
        let error = test_environment(
            "11111111-abcd-4000-9000-000000000001",
            Some("errored"),
            "error",
        );
        let mut creating = test_environment(
            "22222222-abcd-4000-9000-000000000002",
            Some("creating"),
            "creating",
        );
        creating.protected = true;
        let running = test_environment(
            "33333333-abcd-4000-9000-000000000003",
            Some("running"),
            "running",
        );
        let environments = vec![error.clone(), creating.clone(), running.clone()];
        let states = parse_prune_states("error, creating");

        let prune = select_prune_environments(&environments, &states);
        assert_eq!(prune.targets, vec![error.clone()]);
        assert_eq!(prune.skipped_protected, 1);

        let nuke = select_nuke_environments(&environments);
        assert_eq!(nuke.targets, vec![error, running]);
        assert_eq!(nuke.skipped_protected, 1);
    }

    #[test]
    fn env_bulk_target_text_matches_go_table_shape() {
        let mut environment = test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "error",
        );
        environment.created_at = "age".to_string();

        assert_eq!(
            format_env_prune_targets_text(std::slice::from_ref(&environment)),
            "ID\tNAME\tSTATE\tAGE\n12345678\tbuilder\terror\tage\n"
        );
        assert_eq!(
            format_env_nuke_targets_text(&[environment]),
            "ID\tNAME\tSTATE\n12345678\tbuilder\terror\n"
        );
    }

    #[test]
    fn env_status_and_delete_text_match_go_messages() {
        assert_eq!(
            format_env_status_text(
                "builder",
                &StatusResponse {
                    status: "stopped".to_string(),
                },
            ),
            "Environment builder: stopped.\n"
        );
        assert_eq!(
            format_env_delete_text("builder"),
            "Environment builder deleted.\n"
        );
        assert_eq!(
            format_env_extend_status_text(
                "builder",
                &StatusResponse {
                    status: "running".to_string(),
                },
                3,
            ),
            "Environment builder: running (3 hours added).\n"
        );
    }

    #[test]
    fn env_access_text_matches_go_messages() {
        assert_eq!(
            format_env_access_list_text(&[]),
            "No explicit access grants (creator has implicit owner access).\n"
        );

        let grants = vec![EnvironmentAccessGrant {
            id: "grant-1".to_string(),
            environment_id: "env-1".to_string(),
            user_id: "user-2".to_string(),
            permission: "viewer".to_string(),
            granted_by: "user-1".to_string(),
            created_at: "2026-07-05 03:00:00+00".to_string(),
        }];
        assert_eq!(
            format_env_access_list_text(&grants),
            "USER ID\tPERMISSION\tGRANTED BY\tCREATED AT\nuser-2\tviewer\tuser-1\t2026-07-05 03:00:00+00\n"
        );
        assert_eq!(
            format_env_access_grant_text("builder", "user-2", "operator"),
            "Granted operator access to builder for user user-2.\n"
        );
        assert_eq!(
            format_env_access_revoke_text("builder", "user-2"),
            "Revoked access for user user-2 on builder.\n"
        );
    }

    #[test]
    fn env_port_text_matches_go_messages() {
        let port = EnvironmentPort {
            id: "port-1".to_string(),
            environment_id: "env-1".to_string(),
            port: 3000,
            label: "web".to_string(),
            access: "creator".to_string(),
            preview_url: "https://web.example".to_string(),
            created_at: "2026-07-05T03:00:00Z".to_string(),
        };

        assert_eq!(
            format_env_port_add_text(&port),
            "  * Port 3000 registered as web\n  URL: https://web.example\n  Access: creator\n"
        );
        assert_eq!(
            format_env_port_list_text(std::slice::from_ref(&port)),
            "PORT\tLABEL\tACCESS\tPREVIEW URL\n3000\tweb\tcreator\thttps://web.example\n"
        );
        assert_eq!(
            format_env_port_rm_text(&port),
            "  * Port 3000 (web) removed\n"
        );
        assert_eq!(format_env_port_list_text(&[]), "No ports registered.\n");
    }

    #[test]
    fn env_log_text_matches_go_event_shapes() {
        let started = EnvironmentLog {
            id: "log-1".to_string(),
            environment_id: "env-1".to_string(),
            phase: "clone".to_string(),
            status: "started".to_string(),
            message: "Cloning repository".to_string(),
            metadata: None,
            created_at: "2026-07-05T03:00:00Z".to_string(),
        };
        let completed = EnvironmentLog {
            id: "log-2".to_string(),
            environment_id: "env-1".to_string(),
            phase: "clone".to_string(),
            status: "completed".to_string(),
            message: "Repository cloned".to_string(),
            metadata: None,
            created_at: "2026-07-05T03:00:07Z".to_string(),
        };
        let warning = EnvironmentLog {
            id: "log-3".to_string(),
            environment_id: "env-1".to_string(),
            phase: "install".to_string(),
            status: "warning".to_string(),
            message: "Package cache unavailable".to_string(),
            metadata: None,
            created_at: "2026-07-05T03:00:08Z".to_string(),
        };
        let failed = EnvironmentLog {
            id: "log-4".to_string(),
            environment_id: "env-1".to_string(),
            phase: "install".to_string(),
            status: "failed".to_string(),
            message: "Install failed".to_string(),
            metadata: None,
            created_at: "2026-07-05T03:00:09Z".to_string(),
        };
        let mut phases = HashMap::new();

        assert_eq!(
            format_environment_log_event_historical(&started, &mut phases),
            "  ◌ Cloning repository...\n"
        );
        assert_eq!(
            format_environment_log_event_historical(&completed, &mut phases),
            "  ✓ Repository cloned  7s\n"
        );
        assert_eq!(
            format_environment_log_event_historical(&warning, &mut phases),
            "  ! Package cache unavailable\n"
        );
        assert_eq!(
            format_environment_log_event_historical(&failed, &mut phases),
            "  ✗ Install failed\n"
        );
        assert!(is_terminal_environment_log(&failed));
        assert_eq!(format_elapsed_seconds(ChronoDuration::seconds(-1)), "0s");
    }

    #[test]
    fn env_port_resolution_matches_label_number_or_id() {
        let ports = vec![EnvironmentPort {
            id: "port-1".to_string(),
            environment_id: "env-1".to_string(),
            port: 3000,
            label: "web".to_string(),
            access: "creator".to_string(),
            preview_url: String::new(),
            created_at: String::new(),
        }];

        assert_eq!(
            resolve_environment_port(&ports, "web").unwrap().id,
            "port-1"
        );
        assert_eq!(
            resolve_environment_port(&ports, "3000").unwrap().id,
            "port-1"
        );
        assert_eq!(
            resolve_environment_port(&ports, "port-1").unwrap().id,
            "port-1"
        );
        assert_eq!(
            resolve_environment_port(&ports, "missing")
                .unwrap_err()
                .to_string(),
            "port \"missing\" not found"
        );
        assert_eq!(parse_env_port_number("1").unwrap(), 1);
        assert_eq!(parse_env_port_number("65535").unwrap(), 65535);
        assert_eq!(
            parse_env_port_number("0").unwrap_err().to_string(),
            "invalid port number: 0"
        );
    }

    #[test]
    fn map_env_delete_error_keeps_actionable_go_wording() {
        let protected = map_env_delete_error(
            "builder",
            anyhow::anyhow!("HTTP 400: environment_protected"),
        );
        assert_eq!(
            protected.to_string(),
            "environment is protected. Run 'cw env unprotect builder' first"
        );

        let denied = map_env_delete_error("builder", anyhow::anyhow!("access_denied"));
        assert_eq!(
            denied.to_string(),
            "access denied: only the environment owner can delete it"
        );
    }

    #[test]
    fn filter_environments_honors_type_state_and_destroyed_default() {
        let mut running = test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        );
        running.environment_type = "sandbox".to_string();
        let mut stopped = test_environment(
            "87654321-abcd-4000-9000-000000000002",
            Some("tester"),
            "stopped",
        );
        stopped.environment_type = "sandbox".to_string();
        let mut destroyed = test_environment(
            "99999999-abcd-4000-9000-000000000003",
            Some("old"),
            "destroyed",
        );
        destroyed.environment_type = "sandbox".to_string();
        let environments = vec![running.clone(), stopped, destroyed.clone()];

        assert_eq!(
            filter_environments(&environments, Some("sandbox"), Some("running"), false),
            vec![running]
        );
        assert_eq!(
            filter_environments(&environments, Some("sandbox"), Some("destroyed"), false),
            Vec::<Environment>::new()
        );
        assert_eq!(
            filter_environments(&environments, Some("sandbox"), Some("destroyed"), true),
            vec![destroyed]
        );
    }

    #[test]
    fn format_env_list_text_marks_current_and_connectable_sandbox() {
        let mut environment = test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        );
        environment.environment_type = "sandbox".to_string();
        environment.cpu_millicores = 2000;
        environment.memory_mb = 4096;
        environment.ttl_seconds = Some(3600);
        environment.network = Some("mesh-dev".to_string());
        let current = config::CurrentTargetConfig {
            kind: "env".to_string(),
            target_ref: environment.id.clone(),
            name: "builder".to_string(),
        };

        assert_eq!(
            format_env_list_text(&[environment], Some(&current)),
            concat!(
                "builder [12345678]  running  -- (current)\n",
                "  sandbox  2000m/4096MB  ttl 3600s\n",
                "  network: mesh-dev\n",
                "  connect: cw shell 12345678\n",
            )
        );
    }


    #[test]
    fn format_env_info_text_uses_go_style_labels() {
        let mut environment = test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        );
        environment.environment_type = "sandbox".to_string();
        environment.desired_state = "running".to_string();
        environment.preset_id = "preset_123".to_string();
        environment.network = Some("mesh-dev".to_string());
        environment.cpu_millicores = 2000;
        environment.memory_mb = 4096;
        environment.disk_gb = 30;
        environment.created_by = "user_123".to_string();
        environment.created_at = "2026-07-05T00:00:00Z".to_string();
        environment.ttl_seconds = Some(3600);
        environment.recoverable = true;
        environment.total_running_seconds = 120;
        environment.protected = true;

        let text = format_env_info_text(&environment);
        assert!(text.contains("ID:            12345678-abcd-4000-9000-000000000001\n"));
        assert!(text.contains("Name:          builder\n"));
        assert!(text.contains("Type:          sandbox\n"));
        assert!(text.contains("State:         running\n"));
        assert!(text.contains("Network:       mesh-dev\n"));
        assert!(text.contains("TTL:           3600s\n"));
        assert!(text.contains("Protected:     yes\n"));
    }
