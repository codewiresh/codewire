#[test]
fn short_env_id_does_not_panic_on_non_ascii_refs() {
    assert_eq!(short_env_id("env😀abcdef"), "env😀a");
}

#[cfg(target_os = "linux")]
#[test]
fn native_delete_replacement_persists_an_existing_or_unselected_target_without_stale_identity() {
    let data = private_mesh_data_fixture();
    config::save_current_target(
        data.path(),
        &config::CurrentTargetConfig {
            kind: "local".into(),
            target_ref: "deleted-vm".into(),
            name: "deleted-vm".into(),
        },
    )
    .unwrap();
    for selected in [Some("remaining-vm".to_owned()), None] {
        let replacement = super::environment::native_current_target_after_delete(selected.clone());
        config::save_current_target(data.path(), &replacement).unwrap();
        let saved = config::current_target(data.path()).unwrap();
        assert_eq!(saved, replacement);
        assert_ne!(saved.target_ref, "deleted-vm");
        if let Some(name) = selected {
            assert_eq!(saved.target_ref, name);
        } else {
            assert_eq!(saved, config::default_current_target());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn private_environment_launcher_preserves_argument_boundary_and_requires_a_command() {
    let cli = Cli::try_parse_from([
        "cw",
        "__environment-launch",
        "--projection-socket",
        "/run/synthetic/launch.sock",
        "--",
        "/usr/bin/printf",
        "--server",
        "%s",
    ])
    .unwrap();
    let Command::EnvironmentLaunch(args) = cli.command else {
        panic!("wrong command")
    };
    assert_eq!(
        args.projection_socket,
        PathBuf::from("/run/synthetic/launch.sock")
    );
    assert_eq!(
        args.command,
        ["/usr/bin/printf", "--server", "%s"].map(std::ffi::OsString::from)
    );
    assert!(
        Cli::try_parse_from([
            "cw",
            "__environment-launch",
            "--projection-socket",
            "/run/synthetic/launch.sock",
            "--"
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["cw", "__environment-launch", "--", "/bin/true"]).is_err());
    let help = crate::cli_command().render_help().to_string();
    assert!(!help.contains("__environment-launch"));
}

#[cfg(target_os = "linux")]
#[test]
fn private_launcher_failure_is_value_blind_and_does_not_dispatch_normal_cli() {
    let error = crate::run_environment_launcher_from(["cw", "config", "inspect"]).unwrap_err();
    assert_eq!(error.to_string(), "environment launch failed");
    let error = crate::run_environment_launcher_from([
        "cw",
        "__environment-launch",
        "--unknown=synthetic-canary",
    ])
    .unwrap_err();
    assert_eq!(error.to_string(), "environment launch failed");
}

#[test]
fn env_placement_parser_accepts_explicit_local_and_platform_lifecycle_forms() {
    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "--local",
        "--name",
        "workspace",
        "--cpu",
        "2",
        "--memory",
        "8GB",
        "--docker-disk",
        "12Gi",
        "--path",
        ".",
        "--path-mode",
        "copy",
        "--output",
        "json",
    ])
    .unwrap();
    let (local, platform, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("expected local env create command");
    };
    assert!(local);
    assert!(!platform);
    assert_eq!(args.backend, None);
    assert_eq!(args.name.as_deref(), Some("workspace"));
    assert_eq!(args.cpu.as_deref(), Some("2"));
    assert_eq!(args.memory.as_deref(), Some("8GB"));
    assert_eq!(args.docker_disk.as_deref(), Some("12Gi"));
    assert!(!args.no_docker);
    assert_eq!(args.path.as_deref(), Some(std::path::Path::new(".")));
    assert_eq!(args.path_mode, Some(PathModeArg::Copy));
    assert_eq!(args.output, OutputFormat::Json);

    for backend in ["docker", "lima"] {
        assert!(
            Cli::try_parse_from([
                "cw",
                "--local",
                "create",
                "--backend",
                backend,
                "--name",
                "legacy",
            ])
            .is_err()
        );
    }
    for backend in ["native", "cloud-hypervisor"] {
        assert!(
            Cli::try_parse_from([
                "cw",
                "--local",
                "create",
                "--backend",
                backend,
                "--name",
                "workspace",
            ])
            .is_ok()
        );
    }

    // The one global placement pair, before or after the command.
    for argv in [["cw", "--cloud", "ls"], ["cw", "ls", "--cloud"]] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.placement().unwrap(), Some(EnvironmentPlacement::Platform));
        assert!(matches!(cli.command, Command::Ls(_)));
    }
    for argv in [
        vec!["cw", "--local", "--cloud", "ls"],
        vec!["cw", "--local", "ls", "--cloud"],
        vec!["cw", "ls", "--cloud", "--local"],
    ] {
        let cli = Cli::try_parse_from(argv.clone()).unwrap();
        assert_eq!(
            cli.placement().unwrap_err().to_string(),
            "--local and --cloud select different placements; pass only one",
            "{argv:?}"
        );
    }
    assert!(Cli::try_parse_from(["cw", "environment", "list"]).is_err());
    assert!(
        Cli::try_parse_from([
            "cw",
            "create",
            "--local",
            "--docker-disk",
            "8Gi",
            "--no-docker",
        ])
        .is_err()
    );
    let cli = Cli::try_parse_from([
        "cw",
        "--local",
        "resize",
        "workspace",
        "--cpu",
        "0.5",
        "--memory",
        "512MB",
        "--disk",
        "40GB",
        "--yes",
    ])
    .unwrap();
    let (local, platform, EnvCommand::Resize(args)) = env_operation(cli)
    else {
        panic!("expected local env resize command");
    };
    assert!(local);
    assert!(!platform);
    assert_eq!(args.environment, "workspace");
    assert_eq!(args.cpu.as_deref(), Some("0.5"));
    assert_eq!(args.memory.as_deref(), Some("512MB"));
    assert_eq!(args.disk.as_deref(), Some("40GB"));
    assert!(args.yes);
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_local_parser_keeps_orphan_inventory_explicit() {
    let cli = Cli::try_parse_from(["cw", "doctor", "local", "--output", "json"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Doctor(DoctorArgs {
            command: Some(DoctorCommand::Local(DoctorLocalArgs {
                output: OutputFormat::Json,
            })),
            ..
        })
    ));
}

#[test]
fn resize_quantity_and_automation_validation_is_human_safe() {
    assert_eq!(parse_resize_cpu("500m").unwrap(), 500);
    assert_eq!(parse_resize_cpu("0.5").unwrap(), 500);
    assert_eq!(parse_resize_cpu("4").unwrap(), 4000);
    assert!(parse_resize_cpu("0").is_err());
    assert!(parse_resize_cpu("1.2345").is_err());
    assert_eq!(parse_resize_memory("512Mi").unwrap(), 512);
    assert_eq!(parse_resize_memory("4Gi").unwrap(), 4096);
    assert_eq!(parse_resize_memory("16gi").unwrap(), 16 * 1024);
    assert_eq!(parse_resize_memory("16gb").unwrap(), 16 * 1024);
    assert_eq!(parse_resize_memory("1024mb").unwrap(), 1024);
    assert_eq!(parse_resize_memory("2048mb").unwrap(), 2048);
    assert_eq!(parse_resize_memory("8GB").unwrap(), 8192);
    assert_eq!(parse_resize_memory("8GiB").unwrap(), 8192);
    assert_eq!(parse_resize_disk("20Gi").unwrap(), 20);
    assert_eq!(parse_resize_disk("1024mb").unwrap(), 1);
    assert_eq!(parse_resize_disk("2048mb").unwrap(), 2);
    assert!(parse_resize_disk("1536mb").is_err());
    assert_eq!(parse_resize_disk("40gb").unwrap(), 40);
    assert_eq!(parse_resize_disk("40GB").unwrap(), 40);
    assert_eq!(parse_resize_disk("40GiB").unwrap(), 40);
    assert!(parse_resize_disk("0Gi").is_err());

    let args = EnvResizeArgs {
        environment: "workspace".to_string(),
        cpu: None,
        memory: None,
        disk: None,
        force: false,
        allow_restart: false,
        yes: false,
        output: OutputFormat::Text,
    };
    assert!(resize_requires_interactive_wizard(&args, true).unwrap());
    assert!(resize_requires_interactive_wizard(&args, false).is_err());

    let explicit = EnvResizeArgs {
        cpu: Some("4".to_string()),
        ..args
    };
    assert!(!resize_requires_interactive_wizard(&explicit, true).unwrap());
    assert!(resize_requires_interactive_wizard(&explicit, false).is_err());
    assert!(
        resize_requires_interactive_wizard(
            &EnvResizeArgs {
                yes: true,
                output: OutputFormat::Json,
                ..explicit
            },
            false
        )
        .is_ok()
    );
}

#[test]
fn platform_resize_plan_preserves_millicores_and_requires_force_for_automation() {
    let args = EnvResizeArgs {
        environment: "workspace".to_string(),
        cpu: Some("500m".to_string()),
        memory: Some("6Gi".to_string()),
        disk: Some("30Gi".to_string()),
        force: false,
        allow_restart: false,
        yes: true,
        output: OutputFormat::Json,
    };
    let mut plan = resolve_platform_resize_plan(
        &args,
        EnvironmentResizeResources {
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 20,
        },
    )
    .unwrap();
    plan.active_session_count = 1;
    plan.execution_mode = "restart".to_string();
    plan.reason = "runtime requires replacement".to_string();
    plan.warnings = vec![
        "The required restart will terminate active sessions".to_string(),
        "Disk growth cannot be reversed".to_string(),
    ];

    assert_eq!(plan.desired.cpu_millicores, 500);
    assert_eq!(plan.desired.memory_mb, 6144);
    assert_eq!(plan.desired.disk_gb, 30);
    let rendered = format_platform_resize_plan("workspace", &plan);
    assert!(rendered.contains("Current   Requested"));
    assert!(rendered.contains("restart will terminate active sessions"));
    assert!(rendered.contains("Disk growth cannot be reversed"));
    assert!(validate_platform_resize_force(1, "restart", false, false).is_err());
    assert!(validate_platform_resize_force(1, "restart", true, false).is_ok());
    assert!(validate_platform_resize_force(1, "restart", false, true).is_ok());
    assert!(validate_platform_resize_force(1, "in_place", false, false).is_ok());
}

#[test]
fn platform_resize_restart_consent_error_names_the_runtime_reason() {
    let message = platform_resize_restart_consent_error(
        "runtime class commodity sizes the workspace VM when the Pod starts; memory growth needs a replacement Pod to reach the guest",
    );
    assert!(
        message.contains("sizes the workspace VM when the Pod starts"),
        "{message}"
    );
    assert!(
        message.ends_with("non-interactive use requires --allow-restart"),
        "{message}"
    );
    assert_eq!(
        platform_resize_restart_consent_error("  "),
        "this resize requires workspace Pod replacement; non-interactive use requires --allow-restart"
    );
}

#[test]
fn native_resize_requires_whole_cores_and_never_shrinks_disk() {
    let current = NativeResizeResources {
        vcpus: 2,
        memory_mib: 16 * 1024,
        disk_bytes: 20 * 1024 * 1024 * 1024,
    };
    let args = EnvResizeArgs {
        environment: "workspace".to_string(),
        cpu: Some("3".to_string()),
        memory: Some("12Gi".to_string()),
        disk: Some("21Gi".to_string()),
        force: true,
        allow_restart: false,
        yes: true,
        output: OutputFormat::Json,
    };
    let plan =
        resolve_native_resize_plan(&args, current.clone(), vec!["session-1".into()]).unwrap();
    assert_eq!(plan.desired.vcpus, 3);
    assert_eq!(plan.desired.memory_mib, 12 * 1024);
    assert_eq!(plan.desired.disk_bytes, 21 * 1024 * 1024 * 1024);
    assert!(format_native_resize_plan("workspace", &plan).contains(NATIVE_VMM_NAME));

    let mut fractional = args;
    fractional.cpu = Some("1500m".to_string());
    assert!(resolve_native_resize_plan(&fractional, current.clone(), Vec::new()).is_err());
    fractional.cpu = None;
    fractional.disk = Some("19Gi".to_string());
    assert!(resolve_native_resize_plan(&fractional, current, Vec::new()).is_err());
}

#[test]
fn platform_environment_list_marks_selection_and_daemon_health() {
    let platform = test_environment("env-platform", Some("cloud"), "running");
    let current = config::CurrentTargetConfig {
        kind: "env".to_string(),
        target_ref: platform.id.clone(),
        name: "cloud".to_string(),
    };

    let entries =
        unified_environment_list_entries(&[(platform, "ready".to_string())], Some(&current));

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "cloud");
    assert_eq!(entries[0].placement, "platform");
    assert!(entries[0].selected);
    assert_eq!(entries[0].daemon_health, "ready");
}

#[tokio::test]
async fn platform_environment_list_asks_daemon_status_only_for_running_environments() {
    use buffa::Message as _;
    const STATUS_PATH: &str = "/codewire.v1.EnvironmentService/GetEnvironmentDaemonStatus";
    let environments = || {
        vec![
            test_environment("env-creating", Some("creating"), "creating"),
            test_environment("env-running", Some("running"), "running"),
            test_environment("env-stopped", Some("stopped"), "stopped"),
            test_environment("env-error", Some("error"), "error"),
            test_environment("env-destroying", Some("destroying"), "destroying"),
            test_environment("env-destroyed", Some("destroyed"), "destroyed"),
            test_environment("env-running-2", Some("running-2"), "running"),
        ]
    };
    let client = |server: &wiremock::MockServer| {
        EnvironmentClient::new(&config::ResolvedPlatformConfig::static_token(
            server.uri(),
            "synthetic-daemon-status-token",
            true,
            None,
        ))
        .unwrap()
    };

    let server = wiremock::MockServer::start().await;
    let ready = codewire_client::GetEnvironmentDaemonStatusResponse {
        status: Some(codewire_client::EnvironmentDaemonStatus {
            state: codewire_client::EnvironmentDaemonState::Ready.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path(STATUS_PATH))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(ready.encode_to_vec()),
        )
        .mount(&server)
        .await;
    let health =
        platform_environment_daemon_health(&client(&server), "org_test", environments()).await;
    let health = health
        .iter()
        .map(|(environment, health)| (environment.id.as_str(), health.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        health,
        [
            ("env-creating", "unavailable"),
            ("env-running", "ready"),
            ("env-stopped", "unavailable"),
            ("env-error", "unavailable"),
            ("env-destroying", "unavailable"),
            ("env-destroyed", "unavailable"),
            ("env-running-2", "ready"),
        ]
    );
    let asked = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            let mut body = request.body.as_slice();
            codewire_client::GetEnvironmentDaemonStatusRequest::decode(&mut body)
                .unwrap()
                .environment_id
        })
        .collect::<Vec<_>>();
    assert_eq!(asked, ["env-running", "env-running-2"]);

    // A running environment whose status call fails is still listed, as before.
    let failing = wiremock::MockServer::start().await;
    let health =
        platform_environment_daemon_health(&client(&failing), "org_test", environments()).await;
    assert!(health.iter().all(|(_, health)| health == "unavailable"));
    assert_eq!(failing.received_requests().await.unwrap().len(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn native_environment_list_uses_explicit_current_then_supervisor_selection() {
    let environment = codewire_local_vmm::control::v1::Environment {
        id: "native-id".to_owned(),
        name: "native-name".to_owned(),
        selected: true,
        ..Default::default()
    };
    assert!(native_environment_is_selected(&environment, None));
    assert!(native_environment_is_selected(
        &environment,
        Some(&config::CurrentTargetConfig {
            kind: "local".to_owned(),
            target_ref: "native-id".to_owned(),
            name: "native-name".to_owned(),
        })
    ));
    assert!(!native_environment_is_selected(
        &environment,
        Some(&config::CurrentTargetConfig {
            kind: "env".to_owned(),
            target_ref: "platform-id".to_owned(),
            name: "platform-name".to_owned(),
        })
    ));
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
        environment_daemon_readiness(&status)
            .unwrap_err()
            .to_string(),
        "environment daemon requires an upgrade; run `cw daemon repair`"
    );

    status.state = "unhealthy".to_string();
    status.message = "session store unavailable".to_string();
    assert_eq!(
        environment_daemon_readiness(&status)
            .unwrap_err()
            .to_string(),
        "environment daemon is unhealthy (session store unavailable); run `cw daemon status` or `cw daemon repair`"
    );
}

#[test]
fn platform_lifecycle_wait_horizon_matches_server_class() {
    assert_eq!(
        platform_lifecycle_ready_timeout("standard"),
        Duration::from_secs(600)
    );
    assert_eq!(
        platform_lifecycle_ready_timeout(""),
        Duration::from_secs(600)
    );
    assert_eq!(
        platform_lifecycle_ready_timeout("confidential"),
        Duration::from_secs(1800)
    );
}

#[test]
fn platform_create_rejects_native_only_options() {
    let cli =
        Cli::try_parse_from(["cw", "--cloud", "create", "--backend", "native"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("expected platform environment create");
    };
    assert_eq!(
        reject_local_create_options(&args).unwrap_err().to_string(),
        "--backend, --path, --path-mode, --spec, --docker-disk, and --no-docker require `cw create --local`"
    );

    let cli = Cli::try_parse_from([
        "cw",
        "--local",
        "create",
        "--name",
        "dev",
        "--profile",
        "user/work",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("expected native local environment create");
    };
    assert_eq!(args.profile.as_deref(), Some("user/work"));
    #[cfg(target_os = "linux")]
    assert!(native_create_selected(&args).unwrap());

    let cli = Cli::try_parse_from([
        "cw",
        "--cloud",
        "create",
        "--profile",
        "user/work",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("expected platform environment create");
    };
    reject_local_create_options(&args).unwrap();
    assert_eq!(
        prepare_platform_env_create_request(&args)
            .unwrap()
            .project_spec
            .credentials
            .unwrap()
            .profile,
        "user/work"
    );
    assert!(Cli::try_parse_from(["cw", "create", "--access-profile", "work"]).is_err());

    assert!(
        Cli::try_parse_from(["cw", "create", "--local", "--path-mode", "direct",]).is_err()
    );
}

#[test]
fn ambiguous_placement_error_gives_both_exact_commands() {
    assert_eq!(
        ambiguous_environment_placement_error("start", "workspace").to_string(),
        "environment \"workspace\" exists in both placements; use `cw --local start workspace` or `cw --cloud start workspace`"
    );
}

#[test]
fn use_parser_accepts_explicit_environment_placement() {
    for argv in [
        ["cw", "use", "--local", "workbench"],
        ["cw", "--local", "use", "workbench"],
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.placement().unwrap(), Some(EnvironmentPlacement::Local));
        let Command::Use(UseTargetArgs { target }) = cli.command else {
            panic!("expected use command");
        };
        assert_eq!(target, "workbench");
    }
    let cli = Cli::try_parse_from(["cw", "--cloud", "use", "--local", "workbench"]).unwrap();
    assert!(cli.placement().is_err());
}

#[test]
fn env_command_parser_accepts_filters_without_a_legacy_alias() {
    let cli = Cli::try_parse_from([
        "cw", "ls", "--type", "sandbox", "--state", "running", "--all", "--output", "json",
    ])
    .unwrap();

    let Command::Ls(args) = cli.command else {
        panic!("expected ls command");
    };
    assert_eq!(args.environment, None);
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
        "8gb",
        "--disk",
        "40gb",
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
        "--no-wait",
        "--yes",
    ])
    .unwrap();

    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
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
    assert_eq!(args.cpu.as_deref(), Some("2000"));
    assert_eq!(args.memory.as_deref(), Some("8gb"));
    assert_eq!(args.disk.as_deref(), Some("40gb"));
    assert_eq!(args.image.as_deref(), Some("workspace"));
    assert_eq!(args.coding_agent.as_deref(), Some("codex"));
    assert!(args.no_wait);
    assert!(args.yes);

    for unsupported in [
        "--no-org-secrets",
        "--no-user-secrets",
        "--organization-secrets",
        "--user-secrets",
    ] {
        assert!(
            Cli::try_parse_from(["cw", "create", unsupported]).is_err(),
            "unsupported secret-scope flag {unsupported:?} must fail closed"
        );
        assert!(
            Cli::try_parse_from(["cw", "init", unsupported]).is_err(),
            "unsupported init secret-scope flag {unsupported:?} must fail closed"
        );
    }
}

#[test]
fn creation_commands_reject_retired_secret_project_flags_without_echoing_the_value() {
    const MARKER: &str = "synthetic-retired-secret-project-canary";
    for args in [
        vec!["cw", "init", "--secrets-project", MARKER],
        vec!["cw", "create", "--secrets-project", MARKER],
        vec![
            "cw",
            "preset",
            "create",
            "example",
            "--image",
            "workspace",
            "--secrets-project",
            MARKER,
        ],
    ] {
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("--secrets-project"));
        assert!(!error.to_string().contains(MARKER));
    }
}

#[test]
fn env_create_request_builds_one_canonical_project_spec() {
    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "https://github.com/codewiresh/codewire@main",
        "--preset",
        "go",
        "--name",
        "builder",
        "--ttl",
        "1h30m",
        "--cpu",
        "2000",
        "--memory",
        "8gb",
        "--disk",
        "40gb",
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
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };

    let request = prepare_platform_env_create_request(&args).unwrap();
    let spec = &request.project_spec;

    assert!(request.preset_id.is_none());
    assert_eq!(request.name.as_deref(), Some("builder"));
    assert_eq!(spec.resources.cpu_millicores, Some(2000));
    assert_eq!(spec.resources.memory_mib, Some(8 * 1024));
    assert_eq!(spec.resources.disk_gib, Some(40));
    assert_eq!(request.ttl_seconds, Some(5400));
    assert_eq!(spec.preset, "go");
    assert_eq!(
        spec.repositories[0].source,
        "https://github.com/codewiresh/codewire"
    );
    assert_eq!(spec.repositories[0].branch, "main");
    assert_eq!(
        spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
    assert_eq!(spec.install_command, "go mod download");
    assert_eq!(spec.startup_script, "go test ./...");
    assert_eq!(spec.environment["FOO"], "bar");
    assert_eq!(spec.agents.tools, ["codex"]);
    assert!(spec.secrets.project.is_empty());
    let secrets = &spec.secrets;
    assert!(!secrets.organization);
    assert!(secrets.user.is_none());
}

#[test]
fn environment_commands_reject_two_preset_selectors() {
    for command in [["create"].as_slice(), ["init"].as_slice()] {
        let mut args = vec!["cw"];
        args.extend_from_slice(command);
        args.extend_from_slice(&["--preset", "go", "--preset-id", "preset_123"]);
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn platform_create_explicit_yaml_and_flags_preserve_portable_setup_and_source_intent() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("selected.yaml");
    fs::write(
        &file,
        r#"
image: ghcr.io/example/workspace:1
install_command: npm ci
startup_script: npm run dev
environment: {LOG_LEVEL: info, KEEP: present}
agents: {install: false, tools: [codex]}
ports: [{port: 8080, label: web, access: private}]
cpu: "2"
memory: "8Gi"
disk: "40Gi"
secrets: {project: platform:original, user: platform}
credentials: {profile: platform:user/work}
"#,
    )
    .unwrap();
    let cli = Cli::try_parse_from([
        "cw",
        "--cloud",
        "create",
        "--file",
        file.to_str().unwrap(),
        "--name",
        "builder",
        "--secrets=platform:replacement",
        "--org-secrets",
        "--env=LOG_LEVEL=debug",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("create");
    };
    reject_local_create_options(&args).unwrap();
    let request = prepare_platform_env_create_request(&args).unwrap();
    assert_eq!(request.project_spec.install_command, "npm ci");
    assert_eq!(request.project_spec.startup_script, "npm run dev");
    assert_eq!(request.project_spec.environment["LOG_LEVEL"], "debug");
    assert_eq!(request.project_spec.environment["KEEP"], "present");
    assert_eq!(request.project_spec.agents.install, Some(false));
    assert_eq!(request.project_spec.application_ports[0].port, 8080);
    assert_eq!(request.project_spec.resources.cpu_millicores, Some(2000));
    assert_eq!(request.project_spec.resources.memory_mib, Some(8192));
    assert_eq!(request.project_spec.secrets.project, "platform:replacement");
    assert_eq!(
        request.project_spec.secrets.user,
        Some(codewire_project::StoragePlacement::Platform)
    );
    assert!(request.project_spec.secrets.organization);
    assert_eq!(
        request.project_spec.credentials.unwrap().profile,
        "platform:user/work"
    );
    assert_eq!(
        request.expected_profile_revision, None,
        "metadata resolution happens before confirmation"
    );
    assert!(!request.confirm_personal_credentials);
    assert!(!request.confirm_personal_secrets);
}

#[test]
fn platform_create_rejects_local_origins_and_local_yaml_intent() {
    for selection in [
        "--profile=local:work",
        "--secrets=local:development",
        "--user-secrets=local",
    ] {
        let cli = Cli::try_parse_from(["cw", "create", selection]).unwrap();
        let (_, _, EnvCommand::Create(args)) = env_operation(cli)
        else {
            panic!("create");
        };
        assert!(
            prepare_platform_env_create_request(&args).is_err(),
            "{selection}"
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("selected.yaml");
    for yaml in [
        "mounts: [{source: ., destination: /workspace, mode: copy}]\n",
        "ports: [{port: 8080, host_port: 8080}]\n",
        "secrets: {user: local}\n",
        "credentials: {profile: local:work}\n",
    ] {
        fs::write(&file, yaml).unwrap();
        let cli =
            Cli::try_parse_from(["cw", "create", "--file", file.to_str().unwrap()]).unwrap();
        let (_, _, EnvCommand::Create(args)) = env_operation(cli)
        else {
            panic!("create");
        };
        assert!(
            prepare_platform_env_create_request(&args).is_err(),
            "{yaml}"
        );
    }
    fs::write(
        &file,
        " ".repeat(codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1),
    )
    .unwrap();
    let cli =
        Cli::try_parse_from(["cw", "create", "--file", file.to_str().unwrap()]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli)
    else {
        panic!("create");
    };
    assert!(
        format!("{:#}", prepare_platform_env_create_request(&args).unwrap_err())
            .contains("maximum")
    );
}

#[test]
fn env_create_preset_authoring_flags_do_not_block_request_resolution() {
    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "--image",
        "workspace",
        "--write-preset",
        "--save-preset",
        "Fullstack Dev",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };

    let request = prepare_platform_env_create_request(&args).unwrap();

    assert!(args.write_preset);
    assert_eq!(args.save_preset.as_deref(), Some("Fullstack Dev"));
    assert_eq!(
        request.project_spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
}

#[test]
fn env_create_bare_defaults_to_workspace_image() {
    let cli = Cli::try_parse_from(["cw", "create"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };

    let request = prepare_platform_env_create_request(&args).unwrap();

    assert_eq!(
        request.project_spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
    assert!(request.preset_id.is_none());
    assert!(request.project_spec.preset.is_empty());
    assert!(request.project_spec.repositories.is_empty());
    let secrets = &request.project_spec.secrets;
    assert!(!secrets.organization);
    assert!(secrets.user.is_none());
}

#[test]
fn direct_cli_and_codewire_yaml_produce_identical_portable_intent() {
    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "https://example.test/org/app.git@main::/workspace/app",
        "--image",
        "ghcr.io/example/workspace:1",
        "--install",
        "cargo fetch",
        "--startup",
        "cargo test",
        "--coding-agent",
        "claude-code",
        "--env",
        "RUST_LOG=info",
        "--cpu",
        "2000",
        "--memory",
        "4096",
        "--disk",
        "40",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let from_cli = env_create_request_from_args(&args).unwrap().project_spec;
    let from_yaml = codewire_project::parse_project_yaml(
        r#"
    version: 1
    image: ghcr.io/example/workspace:1
    repositories:
      - source: https://example.test/org/app.git
        branch: main
        destination: /workspace/app
    install_command: cargo fetch
    startup_script: cargo test
    environment: {RUST_LOG: info}
    agents: {tools: [claude-code]}
    cpu: "2000m"
    memory: "4096"
    disk: "40"
    "#,
    )
    .unwrap()
    .spec;

    assert_eq!(from_cli, from_yaml);
    assert_eq!(
        from_cli.canonical_json().unwrap(),
        from_yaml.canonical_json().unwrap()
    );
}

#[test]
fn env_create_explicit_sources_do_not_add_the_default_image() {
    let cli = Cli::try_parse_from(["cw", "create", "--preset", "rust"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let request = prepare_platform_env_create_request(&args).unwrap();
    assert_eq!(request.project_spec.preset, "rust");
    assert!(request.project_spec.image.is_empty());

    let cli = Cli::try_parse_from(["cw", "create", "--preset-id", "preset_123"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let request = prepare_platform_env_create_request(&args).unwrap();
    assert_eq!(request.preset_id.as_deref(), Some("preset_123"));
    assert!(request.project_spec.image.is_empty());

    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "https://github.com/codewiresh/codewire",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let request = prepare_platform_env_create_request(&args).unwrap();
    assert_eq!(
        request.project_spec.repositories[0].source,
        "https://github.com/codewiresh/codewire"
    );
    assert!(request.project_spec.image.is_empty());
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
        "--cpu".to_string(),
        "2000".to_string(),
        "--memory".to_string(),
        "4096".to_string(),
        "--disk".to_string(),
        "40".to_string(),
        "--file".to_string(),
        path.display().to_string(),
    ])
    .unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected init command");
    };

    let globals = Globals {
        server: None,
        member: None,
        placement: None,
    };
    handle_init_command(&globals, args).await.unwrap();

    let yaml = fs::read_to_string(&path).unwrap();
    let parsed = codewire_project::parse_project_yaml(&yaml).unwrap();
    let spec = parsed.spec;
    assert_eq!(
        spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
    assert_eq!(spec.install_command, "pnpm install");
    assert_eq!(spec.startup_script, "pnpm dev");
    assert_eq!(spec.environment["FOO"], "bar");
    assert_eq!(spec.resources.cpu_millicores, Some(2000));
    assert_eq!(spec.resources.memory_mib, Some(4096));
    assert_eq!(spec.resources.disk_gib, Some(40));
    assert!(spec.secrets.project.is_empty());
    assert!(!spec.secrets.organization);
    assert!(spec.secrets.user.is_none());
    assert_eq!(spec.agents.tools, vec!["claude-code".to_string()]);
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
        member: None,
        placement: None,
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
        "https://github.com/codewiresh/sdk",
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

    assert_eq!(request.draft.preset_id.as_deref(), Some("preset_123"));
    assert!(request.draft.project_spec.preset.is_empty());
    assert_eq!(request.draft.name.as_deref(), Some("builder"));
    assert_eq!(request.draft.ttl_seconds, Some(3600));
    assert_eq!(
        request.draft.project_spec.repositories[0].source,
        "https://github.com/codewiresh/codewire"
    );
    assert_eq!(request.draft.project_spec.repositories.len(), 2);
    assert_eq!(request.draft.project_spec.repositories[0].branch, "main");
    assert_eq!(
        request.draft.project_spec.repositories[1].source,
        "https://github.com/codewiresh/sdk"
    );
    assert_eq!(
        request.draft.project_spec.resources.cpu_millicores,
        Some(2000)
    );
    assert_eq!(request.draft.project_spec.resources.memory_mib, Some(4096));
    assert_eq!(request.draft.project_spec.resources.disk_gib, Some(40));
    assert_eq!(request.draft.project_spec.environment["FOO"], "bar");
    assert_eq!(request.draft.project_spec.agents.tools, ["codex"]);
    assert!(request.draft.project_spec.secrets.project.is_empty());
}

#[test]
fn init_repository_flags_cannot_silently_import_ssh_host_trust() {
    let cli = Cli::try_parse_from(["cw", "init", "git@example.com:team/app.git"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected init command")
    };
    let error = init_prepare_request_from_args_with_repo_detector(&args, || {
        panic!("explicit SSH intent must not consult ambient repository configuration")
    })
    .unwrap_err();
    assert!(error.to_string().contains("repositories.known_hosts"));
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
        request.draft.project_spec.repositories[0].source,
        "https://github.com/codewiresh/codewire"
    );
    assert_eq!(request.draft.project_spec.repositories[0].branch, "dev");
}

#[test]
fn init_command_rejects_ambient_https_credentials_without_echoing_them() {
    let cli = Cli::try_parse_from(["cw", "init"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected init command");
    };
    let synthetic_secret = "synthetic-ambient-token-do-not-print";

    let error = init_prepare_request_from_args_with_repo_detector(&args, || {
        Ok((
            format!("https://user:{synthetic_secret}@example.test/org/repo.git"),
            "main".to_owned(),
        ))
    })
    .expect_err("an ambient credential-bearing remote must be rejected");
    let rendered = error.to_string();

    assert!(rendered.contains("must not embed URL credentials"));
    assert!(!rendered.contains(synthetic_secret));
}

#[test]
fn init_command_rejects_branch_without_repo_for_direct_modes() {
    let cli =
        Cli::try_parse_from(["cw", "init", "--image", "workspace", "--branch", "main"]).unwrap();
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
fn codewire_yaml_from_request_round_trips_the_canonical_project_spec() {
    let project_spec = codewire_project::parse_project_yaml(
                &r#"
    version: 1
    image: CANONICAL_WORKSPACE_IMAGE
    repositories:
      - source: https://example.test/org/api.git
        revision: deadbeef
        destination: /workspace/api
      - source: https://example.test/org/web.git
        branch: main
        destination: /workspace/web
    working_directory: /workspace/api
    install_command: bun install
    startup_script: bun dev
    environment: {FOO: bar}
    agents: {install: false, tools: [claude-code, codex]}
    skills:
      - {source: repository, path: .agents/skills/rust, agents: [codex]}
      - {source: user, name: personal}
    ports: [{port: 8080, label: web, access: private}]
    cpu: "2000m"
    memory: "4096Mi"
    disk: "40Gi"
    secrets: {project: prod, organization: true, user: platform}
    credentials: {profile: platform:user/work}
    "#.replace("CANONICAL_WORKSPACE_IMAGE", CANONICAL_WORKSPACE_IMAGE),
            )
            .unwrap()
            .spec;
    let request = CreateEnvironmentRequest {
        name: Some("must-not-enter-codewire-yaml".to_string()),
        ttl_seconds: Some(7_200),
        project_spec: project_spec.clone(),
        ..CreateEnvironmentRequest::default()
    };
    let yaml = serde_yaml::to_string(&codewire_yaml_from_request(&request)).unwrap();
    let parsed = codewire_project::parse_project_yaml(&yaml).unwrap();

    assert_eq!(parsed.spec, project_spec);
    assert_eq!(
        parsed.spec.canonical_json().unwrap(),
        project_spec.canonical_json().unwrap()
    );
    assert!(!yaml.contains("must-not-enter-codewire-yaml"));
    assert!(!yaml.contains("7200"));
    assert!(yaml.contains("ports:"));
    assert!(!yaml.contains("app_ports:"));
}

#[test]
fn write_resolved_codewire_yaml_creates_parent_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/codewire.yaml");
    let request = CreateEnvironmentRequest {
                project_spec: codewire_project::ProjectSpec {
                    image: CANONICAL_WORKSPACE_IMAGE.to_string(),
                    install_command: "go mod download".to_string(),
                    ..Default::default()
                },
                ..CreateEnvironmentRequest::default()
            };

    write_resolved_codewire_yaml(&path, &request).unwrap();

    let parsed = config::load_project_document(&path).unwrap();
    assert_eq!(
        parsed.spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
    assert_eq!(parsed.spec.install_command, "go mod download");
    assert!(!parsed.spec.secrets.organization);
    assert!(parsed.spec.secrets.user.is_none());
}

#[test]
fn create_preset_request_from_environment_copies_one_canonical_spec() {
    let request = CreateEnvironmentRequest {
                ttl_seconds: Some(3600),
                project_spec: codewire_project::ProjectSpec {
                    preset: "base".to_string(),
                    image: CANONICAL_WORKSPACE_IMAGE.to_string(),
                    install_command: "bun install".to_string(),
                    startup_script: "bun dev".to_string(),
                    environment: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
                    agents: codewire_project::AgentsSpec {
                        install: Some(true),
                        tools: vec!["claude-code".to_string()],
                    },
                    application_ports: vec![codewire_project::ApplicationPort {
                        port: 8080,
                        label: "web".to_string(),
                        access: "public".to_string(),
                    }],
                    resources: codewire_project::ResourceSpec {
                        cpu_millicores: Some(2000),
                        memory_mib: Some(4096),
                        disk_gib: Some(40),
                    },
                    secrets: codewire_project::SecretBindings {
                        project: "prod".to_string(),
                        user: Some(codewire_project::StoragePlacement::Platform),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..CreateEnvironmentRequest::default()
            };

    let preset = create_preset_request_from_environment("Fullstack Dev!", &request).unwrap();

    assert_eq!(preset.name, "Fullstack Dev!");
    assert_eq!(preset.slug, "fullstack-dev");
    assert_eq!(preset.default_ttl_seconds, Some(3600));
    assert!(preset.project_spec.preset.is_empty());
    assert_eq!(preset.project_spec.resources.cpu_millicores, Some(2000));
    assert_eq!(
        preset.project_spec.image,
        CANONICAL_WORKSPACE_IMAGE
    );
    assert_eq!(preset.project_spec.environment["FOO"], "bar");
    assert_eq!(preset.project_spec.agents.tools, ["claude-code"]);
    assert_eq!(preset.project_spec.application_ports[0].port, 8080);
    assert!(!preset.project_spec.secrets.organization);
    assert_eq!(preset.project_spec.secrets.project, "prod");
}

#[test]
fn env_create_repo_specs_match_go_branch_parsing() {
    assert_eq!(
        parse_env_create_repo_spec("https://github.com/codewiresh/codewire@main").unwrap(),
        (
            "https://github.com/codewiresh/codewire".to_string(),
            "main".to_string(),
            String::new()
        )
    );
    assert_eq!(
        parse_env_create_repo_spec("git@github.com:codewiresh/codewire").unwrap(),
        (
            "git@github.com:codewiresh/codewire".to_string(),
            String::new(),
            String::new()
        )
    );
    assert_eq!(
        parse_env_create_repo_spec("git@github.com:codewiresh/codewire@dev").unwrap(),
        (
            "git@github.com:codewiresh/codewire".to_string(),
            "dev".to_string(),
            String::new()
        )
    );
    // The SSH user of an `ssh://` URL is not a branch.
    for (spec, url, branch) in [
        (
            "ssh://git@github.com/codewiresh/codewire",
            "ssh://git@github.com/codewiresh/codewire",
            "",
        ),
        (
            "ssh://git@github.com/codewiresh/codewire@dev",
            "ssh://git@github.com/codewiresh/codewire",
            "dev",
        ),
        (
            "git://github.com/codewiresh/codewire@dev",
            "git://github.com/codewiresh/codewire",
            "dev",
        ),
    ] {
        assert_eq!(
            parse_env_create_repo_spec(spec).unwrap(),
            (url.to_string(), branch.to_string(), String::new()),
            "{spec}"
        );
    }
    assert_eq!(
        parse_env_create_repo_spec(
            "https://github.com/codewiresh/codewire@dev::/workspace/platform"
        )
        .unwrap(),
        (
            "https://github.com/codewiresh/codewire".to_string(),
            "dev".to_string(),
            "/workspace/platform".to_string()
        )
    );

    let repos = collect_env_create_repos(
        &[
            "https://github.com/codewiresh/codewire@main".to_string(),
            "https://github.com/codewiresh/sdk@v1".to_string(),
        ],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(repos[0].source, "https://github.com/codewiresh/codewire");
    assert_eq!(repos[0].branch, "main");
    assert_eq!(repos[1].branch, "v1");
    assert_eq!(repos[0].destination, "/workspace/codewire");
    assert_eq!(repos[1].destination, "/workspace/sdk");
}

/// A github.com repository in either SSH form needs no pasted host key: it
/// gets GitHub's published keys and is a valid project. Any other SSH host
/// still has no trust, and validation names the missing pins.
#[test]
fn env_create_github_ssh_repositories_carry_githubs_published_host_keys() {
    for source in [
        "git@github.com:noeljackson/md.git",
        "ssh://git@github.com/noeljackson/md.git",
    ] {
        let repos = collect_env_create_repos(&[source.to_string()], &[], None).unwrap();
        assert_eq!(repos[0].source, source);
        assert_eq!(
            repos[0].known_hosts,
            codewire_project::GITHUB_SSH_KNOWN_HOSTS.map(str::to_owned)
        );
        let spec = codewire_project::ProjectSpec {
            repositories: repos,
            working_directory: "/workspace/md".into(),
            ..Default::default()
        };
        spec.validate().unwrap();
    }
    for source in [
        "https://github.com/noeljackson/md.git",
        "git://github.com/noeljackson/md.git",
    ] {
        let repos = collect_env_create_repos(&[source.to_string()], &[], None).unwrap();
        assert!(repos[0].known_hosts.is_empty(), "{source}");
    }
    let repos =
        collect_env_create_repos(&["git@example.com:team/app.git".to_string()], &[], None).unwrap();
    assert!(repos[0].known_hosts.is_empty());
    let spec = codewire_project::ProjectSpec {
        repositories: repos,
        working_directory: "/workspace/app".into(),
        ..Default::default()
    };
    assert!(
        spec.validate()
            .unwrap_err()
            .to_string()
            .contains("must pin at least one SSH host key")
    );
}

#[test]
fn env_create_accepts_mesh_bootstrap_flags() {
    let cli = Cli::try_parse_from(["cw", "create", "--network", "project-alpha"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let request = env_create_request_from_args(&args).unwrap();
    assert_eq!(
        request
            .project_spec
            .environment
            .get(config::CODEWIRE_MESH_NETWORK_ENV),
        None,
        "network invite bootstrap is injected only after Mesh resolution"
    );

    let cli = Cli::try_parse_from(["cw", "create", "--no-network"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    assert!(args.no_network);
    env_create_request_from_args(&args).unwrap();
}

#[test]
fn env_create_requires_canonical_agent_ids() {
    let cli = Cli::try_parse_from(["cw", "create", "--coding-agent", "kimi-code"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    let request = env_create_request_from_args(&args).unwrap();
    assert_eq!(request.project_spec.agents.tools, ["kimi-code"]);

    let cli = Cli::try_parse_from(["cw", "create", "--coding-agent", "kimi"]).unwrap();
    let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
        panic!("expected env create command");
    };
    assert_eq!(
        env_create_request_from_args(&args).unwrap_err().to_string(),
        "invalid agents: unsupported agent \"kimi\""
    );
}

#[test]
fn platform_project_boundary_rejects_all_reserved_runtime_environment_keys() {
    for key in codewire_project::RESERVED_RUNTIME_ENVIRONMENT_KEYS {
        let expected =
            format!("invalid environment: {key} is reserved for Codewire runtime control");
        let spec = codewire_project::ProjectSpec {
            environment: BTreeMap::from([(key.to_string(), "synthetic".to_string())]),
            ..Default::default()
        };
        assert_eq!(spec.validate().unwrap_err().to_string(), expected);

        let value = format!("{key}=synthetic");
        let cli =
            Cli::try_parse_from(["cw", "create", "--no-network", "--env", &value]).unwrap();
        let (_, _, EnvCommand::Create(args)) = env_operation(cli) else {
            panic!("expected env create command");
        };
        assert_eq!(
            prepare_platform_env_create_request(&args)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn platform_env_mesh_bootstrap_pins_explicit_network_to_hosted_origin() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    for (server_url, expected_mesh_url) in [
        ("https://codewire.sh", "https://mesh.codewire.sh"),
        ("https://codewire-dev.sh", "https://mesh.codewire-dev.sh"),
    ] {
        let platform =
            config::ResolvedPlatformConfig::static_token(server_url, "platform-token", true, None);
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
        assert_eq!(bootstrap.network_id, "local-dev");
    }
}

#[test]
fn platform_env_mesh_bootstrap_honors_only_the_matching_auto_connect_owner() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    save_local_mesh_owner_context(
        &paths.mesh_data_dir,
        &LocalMeshOwnerContext {
            schema_version: 1,
            auth_source: LocalMeshOwnerAuthSource::HostedCurrent,
            mesh_url: "https://mesh.codewire-dev.sh".to_owned(),
            organization_id: "org-alpha".to_owned(),
            selected_network: Some("shared-dev".to_owned()),
            auto_connect: true,
        },
    )
    .unwrap();
    let platform = config::ResolvedPlatformConfig::static_token(
        "https://codewire-dev.sh",
        "platform-token",
        true,
        None,
    );

    let automatic =
        resolve_env_create_mesh_bootstrap(&paths, &env, &platform, "org-alpha", false, None, false)
            .unwrap()
            .unwrap();
    assert_eq!(automatic.network_id, "shared-dev");
    assert_eq!(automatic.mesh.mesh_url, "https://mesh.codewire-dev.sh");

    assert!(
        resolve_env_create_mesh_bootstrap(&paths, &env, &platform, "org-beta", false, None, false,)
            .unwrap()
            .is_none(),
        "a default from another organization must not attach"
    );
}

#[test]
fn platform_env_mesh_bootstrap_does_not_inherit_saved_local_mesh_pairing() {
    let home = tempfile::tempdir().unwrap();
    let env = config::MapEnv::default();
    let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env).unwrap();
    config::save_mesh_connection(
        &paths.mesh_data_dir,
        "http://127.0.0.1:18090",
        "local-token",
    )
    .unwrap();
    config::save_selected_mesh_network(&paths.mesh_data_dir, "local-dev").unwrap();
    let platform = config::ResolvedPlatformConfig::static_token(
        "https://codewire-dev.sh",
        "platform-token",
        true,
        None,
    );

    assert!(
        resolve_env_create_mesh_bootstrap(&paths, &env, &platform, "org-alpha", true, None, false,)
            .unwrap()
            .is_none(),
        "a saved local origin-network pair must not become a platform bootstrap"
    );

    config::save_mesh_connection(
        &paths.mesh_data_dir,
        "https://mesh.codewire-dev.sh",
        "hosted-token",
    )
    .unwrap();
    let hosted =
        resolve_env_create_mesh_bootstrap(&paths, &env, &platform, "org-alpha", true, None, false)
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
    environment.isolation_tier = "confidential".to_string();
    environment.cpu_millicores = 2000;
    environment.memory_mb = 4096;
    environment.disk_gb = 40;

    assert_eq!(
        format_env_create_text(&environment),
        concat!(
            "Environment created: builder\n",
            "  ID:        env_123\n",
            "  State:     creating\n",
            "  Type:      sandbox\n",
            "  Isolation: confidential\n",
            "  CPU:       2000m\n",
            "  Mem:       4096MB\n",
            "  Disk:      40GB\n",
        )
    );
}

#[test]
fn env_lifecycle_parsers_accept_targets_and_output() {
    let cli = Cli::try_parse_from(["cw", "start", "builder", "--output", "json"]).unwrap();
    let (_, _, EnvCommand::Start(args)) = env_operation(cli) else {
        panic!("expected env start command");
    };
    assert_eq!(args.environment, "builder");
    assert!(matches!(args.output, OutputFormat::Json));

    // Without --session, stop and restart name a whole environment.
    for (argv, expected) in [
        (vec!["cw", "restart", "--local", "builder", "--output", "json"], "restart"),
        (vec!["cw", "--local", "stop", "--in", "builder", "-o", "json"], "stop"),
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert!(cli.local);
        let scope = match cli.command {
            Command::Restart(scope) if expected == "restart" => scope,
            Command::Stop(stop) if expected == "stop" => {
                assert!(!stop.all);
                stop.scope
            }
            other => panic!("expected {expected}, got {other:?}"),
        };
        assert_eq!(
            scope.environment.as_deref().or(scope.in_environment.as_deref()),
            Some("builder")
        );
        assert_eq!(scope.session, None);
        assert!(scope.retired_session.is_empty());
        assert!(matches!(scope.output, OutputFormat::Json));
    }
    let Command::Stop(stop) = Cli::try_parse_from(["cw", "stop", "--session", "coding"])
        .unwrap()
        .command
    else {
        panic!("expected stop");
    };
    assert_eq!(stop.scope.environment, None);
    assert_eq!(stop.scope.session.as_deref(), Some("coding"));

    let cli = Cli::try_parse_from([
        "cw",
        "refresh-skills",
        "--local",
        "builder",
        "--output",
        "json",
    ])
    .unwrap();
    let (local, _, EnvCommand::RefreshSkills(args)) = env_operation(cli) else {
        panic!("expected env refresh-skills command");
    };
    assert!(local);
    assert_eq!(args.environment, "builder");
    assert!(matches!(args.output, OutputFormat::Json));

    let cli = Cli::try_parse_from(["cw", "rm", "builder", "--yes"]).unwrap();
    let (_, _, EnvCommand::Rm(args)) = env_operation(cli) else {
        panic!("expected env delete command");
    };
    assert_eq!(args.environment, "builder");
    assert!(args.yes);
    assert!(Cli::try_parse_from(["cw", "delete", "builder"]).is_err());
    assert!(Cli::try_parse_from(["cw", "ls"]).is_ok());
}

#[test]
fn env_daemon_parsers_accept_status_logs_and_repair() {
    assert!(Cli::try_parse_from(["cw", "daemon"]).is_err());
    assert!(Cli::try_parse_from(["cw", "codewire-daemon"]).is_err());
    let cli = Cli::try_parse_from(["cw", "__hosted-daemon"]).unwrap();
    assert!(
        matches!(cli.command, Command::HostedDaemon),
        "the self-contained binary must retain only its private hosted daemon entrypoint"
    );

    let cli = Cli::try_parse_from([
        "cw", "daemon", "status", "builder", "--output", "json",
    ])
    .unwrap();
    let (_, _, EnvCommand::Daemon(args)) = env_operation(cli)
    else {
        panic!("expected env daemon command");
    };
    let EnvDaemonCommand::Status(args) = args.command else {
        panic!("expected daemon status");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert!(matches!(args.output, OutputFormat::Json));

    let cli = Cli::try_parse_from(["cw", "daemon", "logs", "builder"]).unwrap();
    let (_, _, EnvCommand::Daemon(args)) = env_operation(cli)
    else {
        panic!("expected env daemon command");
    };
    let EnvDaemonCommand::Logs(args) = args.command else {
        panic!("expected daemon logs");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));

    let cli = Cli::try_parse_from(["cw", "daemon", "repair", "builder"]).unwrap();
    let (_, _, EnvCommand::Daemon(args)) = env_operation(cli)
    else {
        panic!("expected env daemon command");
    };
    assert!(matches!(args.command, EnvDaemonCommand::Repair(_)));

    let cli = Cli::try_parse_from(["cw", "--local", "daemon", "status"]).unwrap();
    let (local, _, EnvCommand::Daemon(args)) = env_operation(cli)
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
        "cp",
        "--local",
        "local.txt",
        "builder:/workspace/local.txt",
    ])
    .unwrap();
    let (local, platform, EnvCommand::Cp(args)) = env_operation(cli) else {
        panic!("expected environment command");
    };
    assert!(local);
    assert!(!platform);
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
    let cli = Cli::try_parse_from(["cw", "protect", "builder"]).unwrap();
    let (_, _, EnvCommand::Protect(args)) = env_operation(cli) else {
        panic!("expected env protect command");
    };
    assert_eq!(args.environment, "builder");

    let cli = Cli::try_parse_from(["cw", "extend", "builder", "--hours", "3"]).unwrap();
    let (_, _, EnvCommand::Extend(args)) = env_operation(cli) else {
        panic!("expected env extend command");
    };
    assert_eq!(args.environment, "builder");
    assert_eq!(args.hours, 3);
}

#[test]
fn env_access_and_share_parsers_keep_profiles_and_collaborators_separate() {
    let cli = Cli::try_parse_from([
        "cw", "--local", "access", "builder", "--output", "json",
    ])
    .unwrap();
    let (_, _, EnvCommand::Access(args)) = env_operation(cli) else {
        panic!("expected env access command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert!(matches!(args.output, OutputFormat::Json));

    assert!(
        Cli::try_parse_from([
            "cw",
            "--local",
            "access",
            "apply",
            "builder",
            "--profile",
            "user/work",
            "--output",
            "json",
        ])
        .is_err()
    );

    assert!(
        Cli::try_parse_from([
            "cw",
            "--local",
            "access",
            "apply",
            "builder",
            "--profile",
            "user/work",
            "--clear",
        ])
        .is_err()
    );

    for retired in ["list", "grant", "revoke"] {
        assert!(
            Cli::try_parse_from(["cw", "access", retired, "builder"]).is_err(),
            "retired environment-access collaborator command {retired:?} must fail closed"
        );
    }

    let cli = Cli::try_parse_from([
        "cw",
        "--cloud",
        "share",
        "list",
        "builder",
        "--output",
        "json",
    ])
    .unwrap();
    let (local, platform, EnvCommand::Share(args)) = env_operation(cli) else {
        panic!("expected environment command");
    };
    assert!(!local);
    assert!(platform);
    let EnvShareCommand::List(args) = args.command else {
        panic!("expected env share list command");
    };
    assert_eq!(args.environment, "builder");
    assert!(matches!(args.output, OutputFormat::Json));

    let cli = Cli::try_parse_from([
        "cw",
        "share",
        "grant",
        "builder",
        "--user",
        "user-2",
        "--permission",
        "operator",
    ])
    .unwrap();
    let (_, _, EnvCommand::Share(args)) = env_operation(cli) else {
        panic!("expected env share command");
    };
    let EnvShareCommand::Grant(args) = args.command else {
        panic!("expected env share grant command");
    };
    assert_eq!(args.environment, "builder");
    assert_eq!(args.user, "user-2");
    assert_eq!(args.permission, "operator");

    let cli = Cli::try_parse_from([
        "cw", "share", "revoke", "builder", "--user", "user-2",
    ])
    .unwrap();
    let (_, _, EnvCommand::Share(args)) = env_operation(cli) else {
        panic!("expected env share command");
    };
    let EnvShareCommand::Revoke(args) = args.command else {
        panic!("expected env share revoke command");
    };
    assert_eq!(args.environment, "builder");
    assert_eq!(args.user, "user-2");

    assert!(Cli::try_parse_from(["cw", "share", "ls", "builder"]).is_ok());
}

#[tokio::test]
async fn env_share_rejects_local_before_platform_resolution() {
    let cli = Cli::try_parse_from(["cw", "--local", "share", "list", "builder"]).unwrap();
    let placement = cli.placement().unwrap();
    let (_, _, operation) = env_operation(cli);
    let globals = Globals {
        server: None,
        member: None,
        placement,
    };

    let error = handle_env_command(&globals, placement, operation)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "environment sharing is available only with --cloud"
    );
}

#[test]
fn ports_parser_lists_publishes_and_unpublishes_one_port() {
    let cli = Cli::try_parse_from([
        "cw", "ports", "builder", "--publish", "3000", "--label", "web", "--access", "public",
        "--output", "json",
    ])
    .unwrap();
    let Command::Ports(args) = cli.command else {
        panic!("expected ports command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!(args.publish, Some(3000));
    assert_eq!(args.label.as_deref(), Some("web"));
    assert_eq!(args.access.as_deref(), Some("public"));
    assert_eq!(args.host_port, None);
    assert!(matches!(args.output, OutputFormat::Json));

    for argv in [
        vec!["cw", "--local", "ports", "web", "--publish", "47321", "--host-port", "18080"],
        vec!["cw", "ports", "--in", "web", "--publish", "47321", "--host-port", "18080", "--local"],
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.placement().unwrap(), Some(EnvironmentPlacement::Local));
        let Command::Ports(args) = cli.command else {
            panic!("expected ports command");
        };
        assert_eq!(
            args.environment.as_deref().or(args.in_environment.as_deref()),
            Some("web")
        );
        assert_eq!(args.publish, Some(47_321));
        assert_eq!(args.host_port, Some(18_080));
    }
    for invalid in [
        vec!["cw", "ports", "web", "--publish", "47321", "--host-port", "0"],
        vec!["cw", "ports", "web", "--publish", "0"],
        vec!["cw", "ports", "web", "--publish", "3000", "--unpublish", "3000"],
        vec!["cw", "ports", "web", "--publish", "web"],
        vec!["cw", "ports", "web", "--env", "web"],
        vec!["cw", "ports", "web", "--unpublish", "3000", "--unpublish", "3001"],
    ] {
        assert!(Cli::try_parse_from(invalid.clone()).is_err(), "{invalid:?}");
    }

    let cli = Cli::try_parse_from(["cw", "ports", "builder"]).unwrap();
    let Command::Ports(args) = cli.command else {
        panic!("expected ports command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert_eq!((args.publish, args.unpublish), (None, None));
}

#[tokio::test]
async fn ports_refuses_combinations_and_ignored_options_before_any_lookup() {
    let globals = Globals {
        server: None,
        member: None,
        placement: None,
    };
    for (argv, message) in [
        (
            vec!["cw", "ports", "web", "--host-port", "3001"],
            "--host-port, --label and --access apply to --publish PORT or --unpublish PORT",
        ),
        (
            vec!["cw", "ports", "web", "--label", "site"],
            "--host-port, --label and --access apply to --publish PORT or --unpublish PORT",
        ),
        (
            vec!["cw", "ports", "web", "--unpublish", "3000", "--access", "public"],
            "--access applies to --publish; an unpublished port has no access level",
        ),
        (
            vec!["cw", "ports", "web", "--in", "web"],
            "name the environment once: `cw ports ENV` or `cw ports --in ENV`, not both",
        ),
    ] {
        let Command::Ports(args) = Cli::try_parse_from(argv.clone()).unwrap().command else {
            panic!("expected ports command");
        };
        let error = crate::commands::flat::handle_ports(&globals, args)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), message, "{argv:?}");
    }
}

#[test]
fn setup_logs_and_session_logs_are_explicit_sources() {
    let cli = Cli::try_parse_from(["cw", "logs", "builder", "--setup"]).unwrap();
    let Command::Logs(args) = cli.command else {
        panic!("expected logs command");
    };
    assert_eq!(args.environment.as_deref(), Some("builder"));
    assert!(args.setup && !args.follow);

    let cli = Cli::try_parse_from(["cw", "logs", "builder", "--setup", "--follow"]).unwrap();
    let Command::Logs(args) = cli.command else {
        panic!("expected logs command");
    };
    assert!(args.setup && args.follow);

    let cli = Cli::try_parse_from(["cw", "logs", "--in", "builder", "--session", "coding", "-f"])
        .unwrap();
    let Command::Logs(args) = cli.command else {
        panic!("expected logs command");
    };
    assert_eq!(args.in_environment.as_deref(), Some("builder"));
    assert_eq!(args.session.as_deref(), Some("coding"));
    assert!(args.follow && !args.setup);

    assert!(Cli::try_parse_from(["cw", "logs", "builder", "--setup", "--session", "coding"]).is_err());
    assert!(Cli::try_parse_from(["cw", "logs", "builder", "--follow=false"]).is_err());
}

#[test]
fn env_prune_nuke_parsers_accept_safety_flags() {
    let cli = Cli::try_parse_from([
        "cw",
        "prune",
        "--state",
        "error,failed",
        "--dry-run",
        "--yes",
    ])
    .unwrap();
    let (_, _, EnvCommand::Prune(args)) = env_operation(cli) else {
        panic!("expected env prune command");
    };
    assert_eq!(args.state, "error,failed");
    assert!(args.dry_run);
    assert!(args.yes);

    let cli = Cli::try_parse_from(["cw", "nuke", "--yes"]).unwrap();
    let (_, _, EnvCommand::Nuke(args)) = env_operation(cli) else {
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
fn env_share_text_preserves_platform_access_grant_messages() {
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
fn cloud_unpublish_selects_one_preview_by_guest_port_and_label() {
    let preview = |id: &str, port, label: &str| EnvironmentPort {
        id: id.to_string(),
        environment_id: "env-1".to_string(),
        port,
        label: label.to_string(),
        access: "creator".to_string(),
        preview_url: String::new(),
        created_at: String::new(),
    };
    let ports = vec![
        preview("port-1", 3000, "web"),
        preview("port-2", 8080, "api"),
        preview("port-3", 8080, "admin"),
    ];
    assert_eq!(select_unpublished_preview(&ports, 3000, None).unwrap().id, "port-1");
    assert_eq!(
        select_unpublished_preview(&ports, 8080, Some("admin"))
            .unwrap()
            .id,
        "port-3"
    );
    assert_eq!(
        select_unpublished_preview(&ports, 8080, None)
            .unwrap_err()
            .to_string(),
        "port 8080 is published as api, admin; choose one with --label"
    );
    assert_eq!(
        select_unpublished_preview(&ports, 22, None)
            .unwrap_err()
            .to_string(),
        "no preview publishes port 22"
    );
    // A label never stands in for the guest port.
    assert!(select_unpublished_preview(&ports, 3000, Some("api")).is_err());
    assert_eq!(default_port_label(3000), "port-3000");
}

#[test]
fn map_env_delete_error_keeps_actionable_go_wording() {
    let protected = map_env_delete_error(
        "builder",
        anyhow::anyhow!("HTTP 400: environment_protected"),
    );
    assert_eq!(
        protected.to_string(),
        "environment is protected. Run 'cw unprotect builder' first"
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
