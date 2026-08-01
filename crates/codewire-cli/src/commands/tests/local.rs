
    #[test]
    fn mesh_status_command_parser_accepts_json_output() {
        let cli = Cli::try_parse_from(["cw", "mesh", "status", "--output", "json"]).unwrap();

        let Command::Mesh {
            command: MeshCommand::Status(args),
        } = cli.command
        else {
            panic!("expected mesh status command");
        };
        assert!(matches!(args.output, OutputFormat::Json));
    }

    #[test]
    fn mesh_up_command_parser_accepts_loopback_overrides() {
        let cli = Cli::try_parse_from([
            "cw",
            "mesh",
            "up",
            "--binary",
            "/usr/local/bin/codewire-mesh",
            "--derp-binary",
            "/usr/local/bin/codewire-derp",
            "--base-url",
            "http://127.0.0.1:19090",
            "--listen",
            "127.0.0.1:19090",
            "--derp-url",
            "http://127.0.0.1:19091",
            "--derp-listen",
            "127.0.0.1:19091",
            "--output",
            "json",
        ])
        .unwrap();

        let Command::Mesh {
            command: MeshCommand::Up(args),
        } = cli.command
        else {
            panic!("expected mesh up command");
        };
        assert_eq!(
            args.binary.as_deref(),
            Some(Path::new("/usr/local/bin/codewire-mesh"))
        );
        assert_eq!(
            args.derp_binary.as_deref(),
            Some(Path::new("/usr/local/bin/codewire-derp"))
        );
        assert_eq!(args.base_url, "http://127.0.0.1:19090");
        assert_eq!(args.listen, "127.0.0.1:19090");
        assert_eq!(args.derp_url, "http://127.0.0.1:19091");
        assert_eq!(args.derp_listen, "127.0.0.1:19091");
        assert!(!args.no_derp);
        assert!(matches!(args.output, OutputFormat::Json));
    }

    #[test]
    fn mesh_down_command_parser_accepts_json_output() {
        let cli = Cli::try_parse_from(["cw", "mesh", "down", "--output", "json"]).unwrap();

        let Command::Mesh {
            command: MeshCommand::Down(args),
        } = cli.command
        else {
            panic!("expected mesh down command");
        };
        assert!(matches!(args.output, OutputFormat::Json));
    }

    #[test]
    fn local_mesh_start_spec_defaults_to_loopback_and_explicit_local_identity() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let args = MeshUpArgs {
            binary: Some(PathBuf::from("/opt/codewire/bin/codewire-mesh")),
            derp_binary: Some(PathBuf::from("/opt/codewire/bin/codewire-derp")),
            base_url: DEFAULT_LOCAL_MESH_URL.to_string(),
            listen: DEFAULT_LOCAL_MESH_LISTEN_ADDR.to_string(),
            derp_url: DEFAULT_LOCAL_DERP_URL.to_string(),
            derp_listen: DEFAULT_LOCAL_DERP_LISTEN_ADDR.to_string(),
            no_derp: false,
            output: OutputFormat::Text,
        };

        let identity = config::ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap();
        let spec = local_mesh_start_spec(&paths, &args, identity.clone()).unwrap();

        assert_eq!(
            spec.binary,
            PathBuf::from("/opt/codewire/bin/codewire-mesh")
        );
        assert_eq!(spec.base_url, "http://127.0.0.1:18090");
        assert_eq!(spec.listen_addr, "127.0.0.1:18090");
        assert_eq!(spec.auth_token, identity.api_key);
        assert_eq!(spec.local_identity.organization_id, identity.organization_id);
        assert!(spec.auth_token.starts_with("cw_"));
        assert_eq!(spec.log_path, paths.mesh_data_dir.join(LOCAL_MESH_LOG_FILE));
        let derp = spec.derp.expect("default managed DERP");
        assert_eq!(
            derp.binary,
            PathBuf::from("/opt/codewire/bin/codewire-derp")
        );
        assert_eq!(derp.url, DEFAULT_LOCAL_DERP_URL);
        assert_eq!(derp.listen_addr, DEFAULT_LOCAL_DERP_LISTEN_ADDR);
        assert_eq!(derp.log_path, paths.mesh_data_dir.join(LOCAL_DERP_LOG_FILE));
    }



    #[test]
    fn local_mesh_runtime_matches_requested_args() {
        let Command::Mesh {
            command: MeshCommand::Up(args),
        } = Cli::try_parse_from(["cw", "mesh", "up"]).unwrap().command
        else {
            panic!("expected mesh up command");
        };
        let runtime = LocalMeshRuntime {
            pid: 42,
            base_url: args.base_url.clone(),
            listen_addr: args.listen.clone(),
            binary: "codewire-mesh".to_string(),
            log_path: "codewire-mesh.log".to_string(),
            started_at: "2026-07-09T00:00:00Z".to_string(),
            derp: Some(LocalDerpRuntime {
                pid: 43,
                url: args.derp_url.clone(),
                listen_addr: args.derp_listen.clone(),
                binary: "codewire-derp".to_string(),
                log_path: "codewire-derp.log".to_string(),
            }),
        };

        assert!(local_mesh_runtime_matches_args(&runtime, &args));

        let mut mismatched = runtime.clone();
        mismatched.listen_addr = "127.0.0.1:28090".to_string();
        assert!(!local_mesh_runtime_matches_args(&mismatched, &args));
    }

    #[test]
    fn mesh_status_report_shows_configured_mesh_without_auth() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([
            (config::CODEWIRE_MESH_URL_ENV, "https://mesh.example.com"),
            (config::CODEWIRE_MESH_NETWORK_ENV, "project-alpha"),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let globals = Globals {
            server: None,
            token: None,
        };

        let report = mesh_status_report(&globals, &paths, &env);

        assert!(report.configured);
        assert_eq!(report.mesh_url.as_deref(), Some("https://mesh.example.com"));
        assert_eq!(report.selected_network.as_deref(), Some("project-alpha"));
        assert!(!report.auth_configured);
        assert_eq!(report.auth_source, None);
        let text = format_mesh_status_report(&report);
        assert!(text.contains("Mesh:        configured\n"));
        assert!(text.contains("Auth:        unconfigured\n"));
        assert!(text.contains("Local:       not_running\n"));
    }

    #[test]
    fn mesh_status_report_includes_auth_source_when_ready() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([
            (config::CODEWIRE_MESH_URL_ENV, "https://mesh.example.com"),
            (config::CODEWIRE_MESH_AUTH_TOKEN_ENV, "mesh-token"),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let globals = Globals {
            server: None,
            token: None,
        };

        let report = mesh_status_report(&globals, &paths, &env);

        assert!(report.auth_configured);
        assert_eq!(report.auth_source, Some(config::MeshAuthSource::MeshEnv));
        assert!(format_mesh_status_report(&report).contains("Auth source: mesh_env\n"));
    }

    #[test]
    fn mesh_status_report_includes_saved_mesh_auth_source() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        config::save_mesh_connection(&paths.mesh_data_dir, "http://127.0.0.1:18090", "token")
            .unwrap();
        let globals = Globals {
            server: None,
            token: None,
        };

        let report = mesh_status_report(&globals, &paths, &env);

        assert!(report.auth_configured);
        assert_eq!(report.auth_source, Some(config::MeshAuthSource::MeshConfig));
        assert!(format_mesh_status_report(&report).contains("Auth source: mesh_config\n"));
    }

    #[test]
    fn local_mesh_runtime_round_trips_and_reports_stale_process() {
        let dir = tempfile::tempdir().unwrap();
        let stale_mesh_pid = 1_000_000_000;
        let stale_derp_pid = 999_999_999;
        assert!(!local_process_is_running(stale_mesh_pid));
        assert!(!local_process_is_running(stale_derp_pid));

        let runtime = LocalMeshRuntime {
            pid: stale_mesh_pid,
            base_url: "http://127.0.0.1:18090".to_string(),
            listen_addr: "127.0.0.1:18090".to_string(),
            binary: "codewire-mesh".to_string(),
            log_path: dir.path().join(LOCAL_MESH_LOG_FILE).display().to_string(),
            started_at: "2026-07-05T12:00:00Z".to_string(),
            derp: Some(LocalDerpRuntime {
                pid: stale_derp_pid,
                url: DEFAULT_LOCAL_DERP_URL.to_string(),
                listen_addr: DEFAULT_LOCAL_DERP_LISTEN_ADDR.to_string(),
                binary: "codewire-derp".to_string(),
                log_path: dir.path().join(LOCAL_DERP_LOG_FILE).display().to_string(),
            }),
        };

        save_local_mesh_runtime(dir.path(), &runtime).unwrap();

        assert_eq!(load_local_mesh_runtime(dir.path()).unwrap(), Some(runtime));
        let status = local_mesh_status(dir.path());
        assert_eq!(status.state, "stale");
        assert_eq!(status.pid, Some(stale_mesh_pid));
        assert_eq!(
            status.derp.as_ref().map(|derp| derp.state.as_str()),
            Some("stale")
        );
        remove_local_mesh_runtime(dir.path()).unwrap();
        assert!(load_local_mesh_runtime(dir.path()).unwrap().is_none());
    }

    #[test]
    fn resolve_local_instance_target_matches_key_or_runtime_name() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("local_instances.toml"),
            r#"
[instances.repo]
name = "repo"
backend = "lima"
runtime_name = "cw-repo"
"#,
        )
        .unwrap();

        let (key, by_key) = resolve_local_instance_target(dir.path(), "repo").unwrap();
        assert_eq!(key, "repo");
        assert_eq!(by_key.backend, "lima");

        let (key, by_runtime) = resolve_local_instance_target(dir.path(), "cw-repo").unwrap();
        assert_eq!(key, "repo");
        assert_eq!(by_runtime.name, "repo");

        assert!(resolve_local_instance_target(dir.path(), "missing").is_none());
    }






    #[test]
    fn local_runtime_mesh_url_translates_loopback_for_docker_and_lima() {
        let mut instance = config::LocalInstanceConfig {
            backend: "docker".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        assert_eq!(
            local_runtime_mesh_url(&instance, "http://127.0.0.1:18090"),
            "http://host.docker.internal:18090/"
        );

        instance.backend = "lima".to_string();
        assert_eq!(
            local_runtime_mesh_url(&instance, "http://localhost:18090"),
            "http://host.lima.internal:18090/"
        );

        assert_eq!(
            local_runtime_mesh_url(&instance, "https://mesh.codewire.sh"),
            "https://mesh.codewire.sh"
        );
    }


    #[test]
    fn local_runtime_command_spec_builds_docker_exec() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            workdir: "/workspace".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let spec = local_runtime_command_spec(
            &instance,
            Some("/workspace/app"),
            &["npm".to_string(), "test".to_string()],
            &BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
        )
        .unwrap();

        assert_eq!(spec.program, "docker");
        assert_eq!(
            spec.args,
            vec![
                "exec",
                "-i",
                "-w",
                "/workspace/app",
                "-e",
                "FOO=bar",
                "cw-repo",
                "npm",
                "test"
            ]
        );
    }



    #[test]
    fn local_runtime_command_spec_allocates_docker_tty() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            workdir: "/workspace".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let spec = local_runtime_command_spec_with_tty(
            &instance,
            None,
            &["claude".to_string()],
            &BTreeMap::new(),
            true,
        )
        .unwrap();

        assert_eq!(spec.program, "docker");
        assert_eq!(
            spec.args,
            vec!["exec", "-i", "-t", "-w", "/workspace", "cw-repo", "claude"]
        );
    }


    #[test]
    fn local_runtime_command_spec_builds_lima_exec() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            workdir: "/workspace".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let spec = local_runtime_command_spec(
            &instance,
            None,
            &["cargo".to_string(), "test".to_string()],
            &BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]),
        )
        .unwrap();

        assert_eq!(spec.program, "limactl");
        assert_eq!(
            spec.args,
            vec![
                "shell",
                "--workdir",
                "/",
                "cw-repo-vm",
                "sudo",
                "docker",
                "exec",
                "-i",
                "-w",
                "/workspace",
                "-e",
                "RUST_LOG=debug",
                "cw-workspace",
                "cargo",
                "test"
            ]
        );
    }

    #[test]
    fn local_runtime_command_spec_allocates_lima_docker_tty() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            workdir: "/workspace".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let spec = local_runtime_command_spec_with_tty(
            &instance,
            None,
            &["claude".to_string()],
            &BTreeMap::new(),
            true,
        )
        .unwrap();

        assert_eq!(spec.program, "limactl");
        assert_eq!(
            spec.args,
            vec![
                "shell",
                "--workdir",
                "/",
                "cw-repo-vm",
                "sudo",
                "docker",
                "exec",
                "-i",
                "-t",
                "-w",
                "/workspace",
                "cw-workspace",
                "claude"
            ]
        );
    }


    #[test]
    fn local_runtime_command_spec_rejects_unknown_backend() {
        let instance = config::LocalInstanceConfig {
            backend: "podman".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let err =
            local_runtime_command_spec(&instance, None, &["true".to_string()], &BTreeMap::new())
                .unwrap_err();

        assert!(err.to_string().contains("unsupported local backend"));
    }





    #[test]
    fn resolve_local_mesh_bootstrap_uses_explicit_network() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([
            (config::CODEWIRE_MESH_URL_ENV, "https://mesh.example.com"),
            (config::CODEWIRE_MESH_AUTH_TOKEN_ENV, "mesh-token"),
            (config::CODEWIRE_MESH_NETWORK_ENV, "ignored-selected"),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let identity = config::ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap();
        let globals = Globals {
            server: None,
            token: None,
        };

        let bootstrap = resolve_local_mesh_bootstrap(
            &globals,
            &paths,
            &env,
            false,
            Some("project-alpha"),
            false,
        )
        .unwrap()
        .unwrap();

        assert_eq!(bootstrap.mesh.mesh_url, "https://mesh.example.com");
        assert_eq!(bootstrap.organization_id, identity.organization_id);
        assert_eq!(bootstrap.network_id, "project-alpha");
        assert_eq!(
            bootstrap.mesh.selected_network.as_deref(),
            Some("project-alpha")
        );
    }

    #[test]
    fn resolve_local_mesh_bootstrap_uses_selected_network_with_yes() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([
            (config::CODEWIRE_MESH_URL_ENV, "https://mesh.example.com"),
            (config::CODEWIRE_MESH_AUTH_TOKEN_ENV, "mesh-token"),
            (config::CODEWIRE_MESH_NETWORK_ENV, "project-selected"),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        config::ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap();
        let globals = Globals {
            server: None,
            token: None,
        };

        let bootstrap = resolve_local_mesh_bootstrap(&globals, &paths, &env, true, None, false)
            .unwrap()
            .unwrap();

        assert_eq!(bootstrap.network_id, "project-selected");
    }

    #[test]
    fn resolve_local_mesh_bootstrap_honors_no_network() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([
            (config::CODEWIRE_MESH_URL_ENV, "https://mesh.example.com"),
            (config::CODEWIRE_MESH_AUTH_TOKEN_ENV, "mesh-token"),
            (config::CODEWIRE_MESH_NETWORK_ENV, "project-selected"),
        ]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let globals = Globals {
            server: None,
            token: None,
        };

        assert!(
            resolve_local_mesh_bootstrap(&globals, &paths, &env, true, Some("project-alpha"), true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn mesh_enrollment_redeem_command_uses_mesh_url() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let enrollment = NodeEnrollment {
            id: "enr_123".to_string(),
            org_id: "org-alpha".to_string(),
            network_id: "project-alpha".to_string(),
            node_name: "repo".to_string(),
            owner_user_id: "user-alpha".to_string(),
            issued_by_user_id: "user-alpha".to_string(),
            enrollment_code: "cw_enr_abc123".to_string(),
            expires_at: "2026-07-05T00:10:00Z".to_string(),
            created_at: "2026-07-05T00:00:00Z".to_string(),
            redeemed_at: String::new(),
        };

        assert_eq!(
            mesh_enrollment_redeem_command(&instance, "https://mesh.example.com", &enrollment)
                .unwrap(),
            vec![
                "cw",
                "network",
                "enroll",
                "redeem",
                "cw_enr_abc123",
                "--node-name",
                "repo",
                "--mesh-url",
                "https://mesh.example.com",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn redeem_mesh_enrollment_runtime_command_matches_docker_and_lima_shapes() {
        let enrollment = NodeEnrollment {
            id: "enr_123".to_string(),
            org_id: "org-alpha".to_string(),
            network_id: "project-alpha".to_string(),
            node_name: "repo".to_string(),
            owner_user_id: "user-alpha".to_string(),
            issued_by_user_id: "user-alpha".to_string(),
            enrollment_code: "cw_enr_abc123".to_string(),
            expires_at: "2026-07-05T00:10:00Z".to_string(),
            created_at: "2026-07-05T00:00:00Z".to_string(),
            redeemed_at: String::new(),
        };
        let command =
            mesh_enrollment_redeem_command(&named_local_instance("docker"), "", &enrollment)
                .unwrap();

        assert_eq!(
            local_runtime_command_spec(
                &named_local_instance("docker"),
                None,
                &command,
                &BTreeMap::new()
            )
            .unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec![
                    "exec",
                    "-i",
                    "-w",
                    "/workspace",
                    "cw-repo",
                    "cw",
                    "network",
                    "enroll",
                    "redeem",
                    "cw_enr_abc123",
                    "--node-name",
                    "repo",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }
        );

        let lima = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            workdir: "/repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let command =
            mesh_enrollment_redeem_command(&lima, "https://mesh.example.com", &enrollment).unwrap();

        assert_eq!(
            local_runtime_command_spec(&lima, None, &command, &BTreeMap::new()).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell",
                    "--workdir",
                    "/",
                    "cw-repo-vm",
                    "sudo",
                    "docker",
                    "exec",
                    "-i",
                    "-w",
                    "/repo",
                    "cw-workspace",
                    "cw",
                    "network",
                    "enroll",
                    "redeem",
                    "cw_enr_abc123",
                    "--node-name",
                    "repo",
                    "--mesh-url",
                    "https://mesh.example.com",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }
        );
    }



    #[test]
    fn prepare_local_instance_uses_codewire_yaml_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("My Repo!");
        let mount = project.join("data");
        fs::create_dir_all(&mount).unwrap();
        fs::write(
            project.join("codewire.yaml"),
            r#"
preset: workspace
image: ghcr.io/codewiresh/workspace:latest
install: pnpm install
startup: pnpm dev
cpu: 1000
env:
  B: "2"
ports:
  - "18080:8080"
mounts:
  - source: data
    target: /data
    readonly: true
secrets:
  org: false
  user: true
  project: dev
agents:
  tools:
    - claude
"#,
        )
        .unwrap();

        let instance = prepare_local_instance(&LocalCreateArgs {
            backend: "docker".to_string(),
            name: None,
            path: project.clone(),
            file: PathBuf::from("codewire.yaml"),
            spec: None,
            preset: None,
            image: Some("base".to_string()),
            install: None,
            startup: None,
            agent: None,
            secrets: None,
            env: vec!["A=1".to_string()],
            cpu: 0,
            memory: 4096,
            disk: 0,
            no_org_secrets: false,
            no_user_secrets: false,
            network: None,
            no_network: true,
            yes: false,
        })
        .unwrap();

        assert_eq!(instance.name, "my-repo");
        assert_eq!(instance.backend, "docker");
        assert_eq!(instance.runtime_name, "cw-my-repo");
        assert_eq!(instance.workdir, LOCAL_WORKSPACE_PATH);
        assert_eq!(instance.image, "ghcr.io/codewiresh/base:latest");
        assert_eq!(instance.install, "pnpm install");
        assert_eq!(instance.startup, "pnpm dev");
        assert_eq!(instance.cpu, 1000);
        assert_eq!(instance.memory, 4096);
        assert_eq!(instance.env.get("A").map(String::as_str), Some("1"));
        assert_eq!(instance.env.get("B").map(String::as_str), Some("2"));
        assert_eq!(instance.ports[0].host_port, 18080);
        assert_eq!(instance.ports[0].guest_port, 8080);
        assert_eq!(instance.mounts[0].source, mount.display().to_string());
        assert_eq!(instance.mounts[0].target, "/data");
        assert_eq!(instance.mounts[0].readonly, Some(true));
        assert_eq!(instance.secrets, "dev");
        assert_eq!(instance.agent, "claude-code");
        assert_eq!(instance.include_org_secrets, Some(false));
        assert_eq!(instance.include_user_secrets, Some(true));
        assert_ne!(instance.daemon_host_port, 0);
        assert_eq!(instance.daemon_auth_token.len(), 43);
        assert!(!instance.created_at.is_empty());
    }

    #[test]
    fn local_docker_create_command_supervises_environment_daemon() {
        let mut env = BTreeMap::new();
        env.insert("B".to_string(), "2".to_string());
        env.insert("A".to_string(), "1".to_string());
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/tmp/repo".to_string(),
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            cpu: 1500,
            memory: 4096,
            env,
            daemon_host_port: 17777,
            daemon_auth_token: "daemon-test-token".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let context = LocalDockerHostContext {
            claude_dir: Some(PathBuf::from("/home/testuser/.claude")),
            claude_json: Some(PathBuf::from("/home/testuser/.claude.json")),
            gh_config_dir: Some(PathBuf::from("/home/testuser/.config/gh")),
            git_config_path: Some(PathBuf::from("/home/testuser/.gitconfig")),
            ssh_auth_sock: Some(PathBuf::from("/home/testuser/.1password/agent.sock")),
            ssh_dir: Some(PathBuf::from("/home/testuser/.ssh")),
            codex_dir: Some(PathBuf::from("/home/testuser/.codex")),
            github_token: Some("gho_test".to_string()),
            claude_oauth_token: Some("sk-ant-oat-test".to_string()),
            anthropic_api_key: Some("sk-ant-api-test".to_string()),
        };

        let spec = local_docker_create_command_spec(&instance, &context).unwrap();

        assert_eq!(spec.program, "docker");
        assert_eq!(
            spec.args,
            vec![
                "create",
                "--name",
                "cw-repo",
                "--restart",
                "unless-stopped",
                "--hostname",
                "cw-repo",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--publish",
                "127.0.0.1:17777:7777/tcp",
                "--entrypoint",
                "/bin/sh",
                "--workdir",
                "/workspace",
                "--volume",
                "/tmp/repo:/workspace",
                "--volume",
                "/home/testuser/.claude:/home/codewire/.claude",
                "--volume",
                "/home/testuser/.claude.json:/home/codewire/.claude.json",
                "--volume",
                "/home/testuser/.config/gh:/home/codewire/.config/gh",
                "--volume",
                "/home/testuser/.gitconfig:/home/codewire/.gitconfig:ro",
                "--volume",
                "/home/testuser/.1password/agent.sock:/tmp/codewire-ssh-agent.sock",
                "--volume",
                "/home/testuser/.ssh:/home/codewire/.ssh:ro",
                "--volume",
                "/home/testuser/.codex:/home/codewire/.codex",
                "--cpus",
                "1.500",
                "--memory",
                "4096m",
                "--env",
                "GH_TOKEN=gho_test",
                "--env",
                "SSH_AUTH_SOCK=/tmp/codewire-ssh-agent.sock",
                "--env",
                "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat-test",
                "--env",
                "ANTHROPIC_API_KEY=sk-ant-api-test",
                "--env",
                "CODEWIRE_WORKSPACE_SHIM_ADDR=0.0.0.0:7777",
                "--env",
                "CODEWIRE_DAEMON_AUTH_TOKEN=daemon-test-token",
                "--env",
                "A=1",
                "--env",
                "B=2",
                "ghcr.io/codewiresh/workspace:latest",
                "-lc",
                "exec /usr/local/bin/cw daemon",
            ]
        );
    }

    #[test]
    fn prepare_local_instance_uses_repo_path_workdir_for_lima() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("repo");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("codewire.yaml"),
            r#"
image: ubuntu:24.04
ports:
  - "3000"
"#,
        )
        .unwrap();

        let instance = prepare_local_instance(&LocalCreateArgs {
            backend: "lima".to_string(),
            name: None,
            path: project.clone(),
            file: PathBuf::from("codewire.yaml"),
            spec: None,
            preset: None,
            image: None,
            install: None,
            startup: None,
            agent: None,
            secrets: None,
            env: Vec::new(),
            cpu: 0,
            memory: 0,
            disk: 0,
            no_org_secrets: false,
            no_user_secrets: false,
            network: None,
            no_network: true,
            yes: false,
        })
        .unwrap();

        assert_eq!(instance.name, "repo");
        assert_eq!(instance.backend, "lima");
        assert_eq!(instance.runtime_name, "cw-repo");
        assert_eq!(instance.lima_instance_name, "cw-repo");
        assert_eq!(instance.repo_path, project.display().to_string());
        assert_eq!(instance.workdir, project.display().to_string());
        assert!(!instance.lima_vm_type.is_empty());
        assert!(!instance.lima_mount_type.is_empty());
    }

    #[test]
    fn local_lima_create_command_matches_go_shape() {
        let data = tempfile::tempdir().unwrap();
        let git_dir = data.path().join("lima").join("cw-repo").join("git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join(".gitconfig"), "[user]\n\tname = Test User\n").unwrap();
        let context = LocalDockerHostContext {
            gh_config_dir: Some(PathBuf::from("/home/testuser/.config/gh")),
            git_config_path: Some(PathBuf::from("/home/testuser/.gitconfig")),
            ssh_auth_sock: Some(PathBuf::from("/home/testuser/.1password/agent.sock")),
            ssh_dir: Some(PathBuf::from("/home/testuser/.ssh")),
            codex_dir: Some(PathBuf::from("/home/testuser/.codex")),
            ..LocalDockerHostContext::default()
        };
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo".to_string(),
            lima_instance_name: "cw-repo".to_string(),
            lima_vm_type: "qemu".to_string(),
            lima_mount_type: "9p".to_string(),
            repo_path: "/tmp/repo".to_string(),
            workdir: "/tmp/repo".to_string(),
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            cpu: 1500,
            memory: 4096,
            disk: 20,
            daemon_host_port: 17777,
            daemon_auth_token: "daemon-test-token".to_string(),
            ports: vec![
                config::LocalPortConfig {
                    port: 3000,
                    label: "web".to_string(),
                    ..config::LocalPortConfig::default()
                },
                config::LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    label: "api".to_string(),
                    ..config::LocalPortConfig::default()
                },
            ],
            mounts: vec![config::LocalMountConfig {
                source: "/tmp/shared".to_string(),
                target: "/mnt/shared".to_string(),
                readonly: Some(true),
            }],
            ..config::LocalInstanceConfig::default()
        };

        let spec = local_lima_create_command_spec(&instance, data.path(), &context).unwrap();
        let want_mount_set = format!(
            ".mounts={}",
            serde_json::json!([
                {"location":"/tmp/repo","mountPoint":"/tmp/repo","writable":true},
                {"location":"/home/testuser/.config/gh","mountPoint":"/home/{{.User}}.guest/.config/gh","writable":true},
                {"location":git_dir.display().to_string(),"mountPoint":"/home/{{.User}}.guest/.codewire-git","writable":false},
                {"location":"/home/testuser/.ssh","mountPoint":"/mnt/host-ssh","writable":false},
                {"location":"/home/testuser/.codex","mountPoint":"/home/{{.User}}.guest/.codex","writable":true},
                {"location":"/tmp/shared","mountPoint":"/mnt/shared","writable":false}
            ])
        );

        assert_eq!(spec.program, "limactl");
        assert_eq!(
            spec.args,
            vec![
                "start",
                "--tty=false",
                "--name",
                "cw-repo",
                "--vm-type",
                "qemu",
                "--mount-type",
                "9p",
                "--mount-none",
                "--set",
                &want_mount_set,
                "--set",
                r#".portForwards = ((.portForwards // []) | map(select(.guestSocket != "/tmp/codewire-ssh-agent.sock")) + [{"guestSocket":"/tmp/codewire-ssh-agent.sock","hostSocket":"/home/testuser/.1password/agent.sock"}])"#,
                "--set",
                r#".portForwards = ((.portForwards // []) | map(select(.guestPort != 7777)) + [{"guestPort":7777,"hostPort":17777,"guestIP":"127.0.0.1","hostIP":"127.0.0.1","proto":"tcp","static":true}])"#,
                "--cpus",
                "2",
                "--memory",
                "4",
                "--disk",
                "20",
                "--port-forward",
                "3000:3000,static=true",
                "--port-forward",
                "18080:8080,static=true",
                "template:docker"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn local_lima_workspace_run_command_supervises_environment_daemon() {
        let data = tempfile::tempdir().unwrap();
        let git_dir = data.path().join("lima").join("cw-repo").join("git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join(".gitconfig"), "[user]\n\tname = Test User\n").unwrap();
        let context = LocalDockerHostContext {
            gh_config_dir: Some(PathBuf::from("/home/testuser/.config/gh")),
            git_config_path: Some(PathBuf::from("/home/testuser/.gitconfig")),
            ssh_auth_sock: Some(PathBuf::from("/home/testuser/.1password/agent.sock")),
            ssh_dir: Some(PathBuf::from("/home/testuser/.ssh")),
            codex_dir: Some(PathBuf::from("/home/testuser/.codex")),
            github_token: Some("gho_test".to_string()),
            anthropic_api_key: Some("sk-ant-api-test".to_string()),
            claude_oauth_token: Some("sk-ant-oat-test".to_string()),
            ..LocalDockerHostContext::default()
        };
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo".to_string(),
            lima_instance_name: "cw-repo".to_string(),
            repo_path: "/tmp/repo".to_string(),
            workdir: "/tmp/repo".to_string(),
            image: "ghcr.io/codewiresh/workspace:latest".to_string(),
            daemon_host_port: 17777,
            daemon_auth_token: "daemon-test-token".to_string(),
            mounts: vec![config::LocalMountConfig {
                source: "/tmp/shared".to_string(),
                target: "/mnt/shared".to_string(),
                readonly: Some(true),
            }],
            ..config::LocalInstanceConfig::default()
        };
        let vm_user = env::var("USER").unwrap_or_default();

        let spec =
            local_lima_workspace_run_command_spec(&instance, data.path(), &context, "988").unwrap();

        assert_eq!(spec.program, "limactl");
        assert_eq!(
            spec.args,
            vec![
                "shell",
                "--workdir",
                "/",
                "cw-repo",
                "sudo",
                "docker",
                "run",
                "-d",
                "--name",
                "cw-workspace",
                "--restart",
                "unless-stopped",
                "--network",
                "host",
                "--group-add",
                "988",
                "--entrypoint",
                "/bin/sh",
                "-e",
                "DOCKER_HOST=unix:///var/run/docker.sock",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                "/tmp/repo:/tmp/repo",
                "-v",
                "/var/lib/codewire/cw:/usr/local/bin/cw:ro",
                "-e",
                "CODEWIRE_WORKSPACE_SHIM_ADDR=127.0.0.1:7777",
                "-e",
                "CODEWIRE_DAEMON_AUTH_TOKEN=daemon-test-token",
                "-e",
                "GH_TOKEN=gho_test",
                "-e",
                "SSH_AUTH_SOCK=/tmp/codewire-ssh-agent.sock",
                "-e",
                "ANTHROPIC_API_KEY=sk-ant-api-test",
                "-e",
                "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat-test",
                "-v",
                "/tmp/codewire-ssh-agent.sock:/tmp/codewire-ssh-agent.sock",
                "-v",
                &format!(
                    "/home/{vm_user}.guest/.codewire-git/.gitconfig:/home/codewire/.gitconfig:ro"
                ),
                "-v",
                &format!("/home/{vm_user}.guest/.config/gh:/home/codewire/.config/gh"),
                "-v",
                "/mnt/host-ssh:/home/codewire/.ssh:ro",
                "-v",
                &format!("/home/{vm_user}.guest/.codex:/home/codewire/.codex"),
                "-v",
                "/tmp/shared:/mnt/shared:ro",
                "--workdir",
                "/tmp/repo",
                "ghcr.io/codewiresh/workspace:latest",
                "-lc",
                "exec /usr/local/bin/cw daemon"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn local_create_helpers_match_go_cases() {
        assert_eq!(format_docker_cpus(1500), "1.500");
        assert_eq!(format_docker_cpus(2000), "2");
        assert_eq!(sanitize_local_name(" My Repo! "), "my-repo");
        assert_eq!(sanitize_local_name("___"), "");
    }


    #[test]
    fn parse_published_port_spec_matches_go_canonical_shape() {
        assert_eq!(
            parse_published_port_spec("18080:8080").unwrap(),
            config::LocalPortConfig {
                host_port: 18080,
                guest_port: 8080,
                ..config::LocalPortConfig::default()
            }
        );
        assert_eq!(
            parse_published_port_spec("3000:3000").unwrap(),
            config::LocalPortConfig {
                port: 3000,
                ..config::LocalPortConfig::default()
            }
        );

        for spec in ["", "8080", "0:1", "1:0", "a:1", "1:2:3"] {
            let err = parse_published_port_spec(spec).unwrap_err().to_string();
            assert!(
                err.contains("invalid port spec"),
                "unexpected error for {spec:?}: {err}"
            );
        }
        assert!(parse_published_port_spec("7777:7777")
            .unwrap_err()
            .to_string()
            .contains("reserved for the managed environment daemon"));
    }

    #[test]
    fn local_daemon_configuration_fails_closed_and_redacts_credentials() {
        let instance = config::LocalInstanceConfig::default();
        assert!(local_daemon_host_port(&instance)
            .unwrap_err()
            .to_string()
            .contains("recreate the local environment"));
        assert!(local_daemon_auth_token(&instance)
            .unwrap_err()
            .to_string()
            .contains("recreate the local environment"));

        let rendered = display_local_runtime_args(&[
            "--env".to_string(),
            "CODEWIRE_DAEMON_AUTH_TOKEN=daemon-test-token".to_string(),
        ]);
        assert_eq!(
            rendered,
            "--env CODEWIRE_DAEMON_AUTH_TOKEN=<redacted>"
        );
        assert!(!rendered.contains("daemon-test-token"));

        let rendered = display_local_runtime_args(&[
            "--env".to_string(),
            "GH_TOKEN=github-test-token".to_string(),
            "-e".to_string(),
            "DATABASE_URL=postgres://user:password@example.invalid/database".to_string(),
            "--env".to_string(),
            "VISIBLE=value".to_string(),
        ]);
        assert_eq!(
            rendered,
            "--env GH_TOKEN=<redacted> -e DATABASE_URL=<redacted> --env VISIBLE=<redacted>"
        );
        assert!(!rendered.contains("github-test-token"));
        assert!(!rendered.contains("password"));
    }

    #[test]
    fn plan_lima_port_forwards_adds_only_new_mappings() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ports: vec![
                config::LocalPortConfig {
                    port: 3000,
                    ..config::LocalPortConfig::default()
                },
                config::LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    label: "web".to_string(),
                    ..config::LocalPortConfig::default()
                },
            ],
            ..config::LocalInstanceConfig::default()
        };

        let publish = vec!["18080:8080".to_string(), "19090:9090".to_string()];
        let plan = plan_lima_port_forwards(&instance, &publish).unwrap();

        assert_eq!(plan.added, 1);
        assert_eq!(
            plan.updated_ports,
            vec![
                config::LocalPortConfig {
                    port: 3000,
                    ..config::LocalPortConfig::default()
                },
                config::LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    label: "web".to_string(),
                    ..config::LocalPortConfig::default()
                },
                config::LocalPortConfig {
                    host_port: 19090,
                    guest_port: 9090,
                    ..config::LocalPortConfig::default()
                },
            ]
        );
        assert_eq!(
            plan.forwards,
            vec![LimaPortForwardEdit {
                guest_port: 9090,
                host_port: 19090,
                proto: "tcp".to_string(),
            }]
        );
    }

    #[test]
    fn lima_add_port_forwards_command_spec_matches_go_edit() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let spec = lima_add_port_forwards_command_spec(
            &instance,
            &[LimaPortForwardEdit {
                guest_port: 9090,
                host_port: 19090,
                proto: "tcp".to_string(),
            }],
        )
        .unwrap();

        assert_eq!(
            spec,
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "edit",
                    "--tty=false",
                    "cw-repo-vm",
                    "--set",
                    ".portForwards = (.portForwards // []) + [{\"guestPort\":9090,\"hostPort\":19090,\"proto\":\"tcp\"}]",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }
        );
    }

    #[test]
    fn plan_lima_port_forwards_rejects_host_conflicts() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            ports: vec![config::LocalPortConfig {
                host_port: 18080,
                guest_port: 8080,
                ..config::LocalPortConfig::default()
            }],
            ..config::LocalInstanceConfig::default()
        };
        let err = plan_lima_port_forwards(&instance, &["18080:3000".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "host port 18080 is already forwarded to guest port 8080"
        );

        let conflicting = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            ports: vec![
                config::LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    ..config::LocalPortConfig::default()
                },
                config::LocalPortConfig {
                    host_port: 18080,
                    guest_port: 9090,
                    ..config::LocalPortConfig::default()
                },
            ],
            ..config::LocalInstanceConfig::default()
        };
        let err = plan_lima_port_forwards(&conflicting, &[])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Lima instance \"repo\" has conflicting host port 18080 mapped to guest ports 8080 and 9090"
        );
    }

    #[test]
    fn publish_local_ports_rejects_docker() {
        let mut instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let err = publish_local_ports(&mut instance, &["18080:8080".to_string()])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "interactive 'cw env --local ports' forwarding is only available for Lima; use backend-native port mapping for docker"
        );
    }

    #[test]
    fn local_instance_entry_matches_go_json_shape() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            repo_path: "/home/user/src/repo".to_string(),
            workdir: "/workspace".to_string(),
            image: "ubuntu:24.04".to_string(),
            preset: "full".to_string(),
            install: "npm install".to_string(),
            startup: "npm test".to_string(),
            secrets: "dev".to_string(),
            agent: "claude".to_string(),
            env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
            ports: vec![config::LocalPortConfig {
                host_port: 18080,
                guest_port: 8080,
                label: "web".to_string(),
                ..config::LocalPortConfig::default()
            }],
            mounts: vec![config::LocalMountConfig {
                source: "/tmp/data".to_string(),
                target: "/data".to_string(),
                readonly: Some(true),
            }],
            cpu: 2000,
            memory: 4096,
            disk: 20,
            lima_mount_type: "virtiofs".to_string(),
            lima_vm_type: "vz".to_string(),
            created_at: "2026-07-05T01:00:00Z".to_string(),
            last_used_at: "2026-07-05T01:05:00Z".to_string(),
            ..config::LocalInstanceConfig::default()
        };

        let entry = local_instance_entry("repo", &instance, "unknown");
        let json = serde_json::to_value(&entry).unwrap();

        assert_eq!(json["name"], "repo");
        assert_eq!(json["backend"], "lima");
        assert_eq!(json["status"], "unknown");
        assert_eq!(json["runtime_name"], "cw-repo");
        assert_eq!(json["ports"][0]["host_port"], 18080);
        assert_eq!(json["ports"][0]["guest_port"], 8080);
        assert_eq!(json["ports"][0]["label"], "web");
        assert_eq!(json["mounts"][0]["readonly"], true);
        assert_eq!(json["lima"]["instance_name"], "cw-repo-vm");
        assert_eq!(json["lima"]["mount_type"], "virtiofs");
        assert_eq!(json["lima"]["vm_type"], "vz");
    }

    #[test]
    fn format_local_instance_list_text_matches_go_columns() {
        let entry = LocalInstanceEntry {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            status: "unknown".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/home/user/src/repo".to_string(),
            workdir: "/workspace".to_string(),
            image: "ubuntu:24.04".to_string(),
            preset: String::new(),
            install: String::new(),
            startup: String::new(),
            secrets: String::new(),
            agent: String::new(),
            env: BTreeMap::new(),
            ports: vec![LocalPortEntry {
                host_port: 8080,
                guest_port: 8080,
                label: "web".to_string(),
            }],
            mounts: Vec::new(),
            cpu: 0,
            memory: 0,
            disk: 0,
            created_at: String::new(),
            last_used_at: String::new(),
            lima: None,
        };

        let text = format_local_instance_list_text(&[entry]);
        assert!(text.starts_with("NAME"));
        assert!(text.contains("BACKEND"));
        assert!(text.contains("STATE"));
        assert!(text.contains("PORTS"));
        assert!(text.contains("repo"));
        assert!(text.contains("8080 (web)"));
    }

    #[test]
    fn format_local_instance_info_text_reports_details() {
        let entry = LocalInstanceEntry {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            status: "unknown".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/home/user/src/repo".to_string(),
            workdir: "/workspace".to_string(),
            image: "ubuntu:24.04".to_string(),
            preset: "full".to_string(),
            install: "npm install".to_string(),
            startup: "npm test".to_string(),
            secrets: String::new(),
            agent: String::new(),
            env: BTreeMap::new(),
            ports: vec![LocalPortEntry {
                host_port: 18080,
                guest_port: 8080,
                label: "web".to_string(),
            }],
            mounts: Vec::new(),
            cpu: 0,
            memory: 0,
            disk: 0,
            created_at: "2026-07-05T01:00:00Z".to_string(),
            last_used_at: String::new(),
            lima: Some(LocalLimaEntry {
                instance_name: "cw-repo-vm".to_string(),
                mount_type: "virtiofs".to_string(),
                vm_type: "vz".to_string(),
            }),
        };

        assert_eq!(
            format_local_instance_info_text(&entry),
            concat!(
                "Name:      repo\n",
                "Backend:   lima\n",
                "State:     unknown\n",
                "Runtime:   cw-repo\n",
                "Image:     ubuntu:24.04\n",
                "Repo:      /home/user/src/repo\n",
                "Workdir:   /workspace\n",
                "Ports:     18080 -> 8080 (web)\n",
                "VMType:    vz\n",
                "MountType: virtiofs\n",
                "Preset:    full\n",
                "Install:   npm install\n",
                "Startup:   npm test\n",
                "Created:   2026-07-05T01:00:00Z\n",
            )
        );
    }

    #[test]
    fn format_local_ports_text_matches_go_lines() {
        let entry = LocalInstanceEntry {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            status: "unknown".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/home/user/src/repo".to_string(),
            workdir: "/workspace".to_string(),
            image: "ubuntu:24.04".to_string(),
            preset: String::new(),
            install: String::new(),
            startup: String::new(),
            secrets: String::new(),
            agent: String::new(),
            env: BTreeMap::new(),
            ports: vec![LocalPortEntry {
                host_port: 18080,
                guest_port: 8080,
                label: "web".to_string(),
            }],
            mounts: Vec::new(),
            cpu: 0,
            memory: 0,
            disk: 0,
            created_at: String::new(),
            last_used_at: String::new(),
            lima: None,
        };

        assert_eq!(format_local_ports_text(&entry), "  18080 -> 8080 (web)\n");
    }

    #[test]
    fn format_local_ports_text_reports_empty() {
        let entry = LocalInstanceEntry {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            status: "unknown".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/home/user/src/repo".to_string(),
            workdir: "/workspace".to_string(),
            image: "ubuntu:24.04".to_string(),
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

        assert_eq!(format_local_ports_text(&entry), "No ports configured.\n");
    }


    #[test]
    fn local_files_command_spec_builds_docker_and_lima_exec() {
        let docker = config::LocalInstanceConfig {
            backend: "docker".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        assert_eq!(
            local_files_command_spec(&docker, &["cat".to_string(), "/tmp/a".to_string()]).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec!["exec", "-i", "cw-repo-runtime", "cat", "/tmp/a"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            }
        );

        let lima = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        assert_eq!(
            local_files_command_spec(&lima, &["ls".to_string(), "/workspace".to_string()]).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell",
                    "--workdir",
                    "/",
                    "cw-repo-vm",
                    "sudo",
                    "docker",
                    "exec",
                    "-i",
                    "cw-workspace",
                    "ls",
                    "/workspace",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }
        );
    }

    #[test]
    fn parse_ls_output_matches_go_local_file_shape() {
        let entries = parse_ls_output(
            r#"
total 8
drwxr-xr-x 2 root root 4096 2026-07-05 01:00:00.000000000 +0000 .
drwxr-xr-x 3 root root 4096 2026-07-05 01:00:00.000000000 +0000 ..
-rw-r--r-- 1 root root   12 2026-07-05 01:01:02.000000000 +0000 file with spaces.txt
lrwxrwxrwx 1 root root    7 2026-07-05 01:01:03.000000000 +0000 latest -> current
drwxr-xr-x 2 root root 4096 2026-07-05 01:01:04.000000000 +0000 src
"#,
        );

        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            LocalFileEntry {
                name: "file with spaces.txt".to_string(),
                size: 12,
                is_dir: false,
                mode: "-rw-r--r--".to_string(),
                mtime: "2026-07-05 01:01:02.000000000 +0000".to_string(),
            }
        );
        assert_eq!(entries[1].name, "latest");
        assert!(entries[2].is_dir);
    }

    #[test]
    fn local_files_text_and_upload_shell_helpers_match_go_behavior() {
        let entries = vec![
            LocalFileEntry {
                name: "src".to_string(),
                size: 4096,
                is_dir: true,
                mode: "drwxr-xr-x".to_string(),
                mtime: "2026-07-05 01:01:04.000000000 +0000".to_string(),
            },
            LocalFileEntry {
                name: "app.txt".to_string(),
                size: 12,
                is_dir: false,
                mode: "-rw-r--r--".to_string(),
                mtime: "2026-07-05 01:01:02.000000000 +0000".to_string(),
            },
        ];

        assert_eq!(
            format_local_files_text(&entries),
            "dir\tdrwxr-xr-x\t4096\tsrc\nfile\t-rw-r--r--\t12\tapp.txt\n"
        );
        assert_eq!(parent_dir("/workspace/a/b.txt"), "/workspace/a");
        assert_eq!(parent_dir("file.txt"), "/");
        assert_eq!(shell_quote("/tmp/it's.txt"), "'/tmp/it'\\''s.txt'");
    }

    #[test]
    fn resolve_local_instance_entry_matches_runtime_name_and_repo_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let subdir = repo.join("crates").join("app");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(
            dir.path().join("local_instances.toml"),
            format!(
                r#"
[instances.repo]
name = "repo"
backend = "docker"
runtime_name = "cw-repo"
repo_path = "{}"
workdir = "/workspace"
"#,
                repo.display()
            ),
        )
        .unwrap();

        let by_runtime =
            resolve_local_instance_entry(dir.path(), Some("cw-repo"), &subdir).unwrap();
        assert_eq!(by_runtime.name, "repo");

        let by_repo = resolve_local_instance_entry(dir.path(), None, &subdir).unwrap();
        assert_eq!(by_repo.runtime_name, "cw-repo");
    }

    #[test]
    fn local_lifecycle_command_spec_builds_docker_start_stop() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };

        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Start).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec!["start".to_string(), "cw-repo".to_string()],
            }
        );
        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Stop).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec!["stop".to_string(), "cw-repo".to_string()],
            }
        );
        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Remove).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec!["rm".to_string(), "-f".to_string(), "cw-repo".to_string()],
            }
        );
    }

    #[test]
    fn docker_workspace_status_parser_preserves_running_and_missing_states() {
        assert_eq!(
            parse_docker_workspace_container_status(true, 0, b"running", b"").unwrap(),
            "running"
        );
        assert_eq!(
            parse_docker_workspace_container_status(
                false,
                1,
                b"",
                b"Error: No such object: cw-workbench",
            )
            .unwrap(),
            "missing"
        );
    }

    #[test]
    fn local_lifecycle_command_spec_builds_lima_start_stop() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };

        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Start).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec!["start".to_string(), "cw-repo-vm".to_string()],
            }
        );
        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Stop).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec!["stop".to_string(), "cw-repo-vm".to_string()],
            }
        );
        assert_eq!(
            local_lifecycle_command_spec(&instance, LocalLifecycleAction::Remove).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "delete".to_string(),
                    "--force".to_string(),
                    "cw-repo-vm".to_string()
                ],
            }
        );
        assert_eq!(
            local_lima_docker_service_start_command_spec(&instance).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell".to_string(),
                    "--workdir".to_string(),
                    "/".to_string(),
                    "cw-repo-vm".to_string(),
                    "sudo".to_string(),
                    "systemctl".to_string(),
                    "start".to_string(),
                    "docker".to_string(),
                ],
            }
        );
        assert_eq!(
            local_lima_workspace_start_command_spec(&instance).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell".to_string(),
                    "--workdir".to_string(),
                    "/".to_string(),
                    "cw-repo-vm".to_string(),
                    "sudo".to_string(),
                    "docker".to_string(),
                    "start".to_string(),
                    "cw-workspace".to_string(),
                ],
            }
        );
    }

    #[test]
    fn stopped_lima_workspace_recovery_starts_only_the_missing_layer() {
        assert_eq!(
            classify_local_lima_workspace_recovery("stopped", None).unwrap(),
            LocalLimaWorkspaceRecovery::StartVmAndWorkspace
        );
        assert_eq!(
            classify_local_lima_workspace_recovery("running", Some("exited")).unwrap(),
            LocalLimaWorkspaceRecovery::StartWorkspace
        );
        assert_eq!(
            classify_local_lima_workspace_recovery("running", Some("running")).unwrap(),
            LocalLimaWorkspaceRecovery::AlreadyRunning
        );
        assert!(classify_local_lima_workspace_recovery("missing", None)
            .unwrap_err()
            .to_string()
            .contains("recreate"));
        assert!(classify_local_lima_workspace_recovery("running", Some("missing"))
            .unwrap_err()
            .to_string()
            .contains("recreate"));
    }

    #[test]
    fn lima_workspace_recovery_runs_vm_container_steps_before_session_launch() {
        let instance = config::LocalInstanceConfig {
            backend: "lima".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };

        assert_eq!(
            local_lima_workspace_recovery_command_specs(
                &instance,
                LocalLimaWorkspaceRecovery::StartVmAndWorkspace,
            )
            .unwrap(),
            vec![
                LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "start".to_string(),
                        "--tty=false".to_string(),
                        "cw-repo-vm".to_string(),
                    ],
                },
                local_lima_docker_service_start_command_spec(&instance).unwrap(),
                local_lima_workspace_start_command_spec(&instance).unwrap(),
            ]
        );
        assert_eq!(
            local_lima_workspace_recovery_command_specs(
                &instance,
                LocalLimaWorkspaceRecovery::StartWorkspace,
            )
            .unwrap(),
            vec![local_lima_workspace_start_command_spec(&instance).unwrap()]
        );
    }

    #[test]
    fn local_daemon_supervisor_commands_are_backend_native_and_bounded() {
        let docker = config::LocalInstanceConfig {
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        assert_eq!(
            local_daemon_logs_command_spec(&docker).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec![
                    "logs".to_string(),
                    "--tail".to_string(),
                    "200".to_string(),
                    "cw-repo".to_string(),
                ],
            }
        );
        assert_eq!(
            local_daemon_repair_command_spec(&docker).unwrap(),
            LocalRuntimeCommand {
                program: "docker".to_string(),
                args: vec!["restart".to_string(), "cw-repo".to_string()],
            }
        );

        let lima = config::LocalInstanceConfig {
            backend: "lima".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        assert_eq!(
            local_daemon_logs_command_spec(&lima).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell".to_string(),
                    "--workdir".to_string(),
                    "/".to_string(),
                    "cw-repo-vm".to_string(),
                    "sudo".to_string(),
                    "docker".to_string(),
                    "logs".to_string(),
                    "--tail".to_string(),
                    "200".to_string(),
                    "cw-workspace".to_string(),
                ],
            }
        );
        assert_eq!(
            local_daemon_repair_command_spec(&lima).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "shell".to_string(),
                    "--workdir".to_string(),
                    "/".to_string(),
                    "cw-repo-vm".to_string(),
                    "sudo".to_string(),
                    "docker".to_string(),
                    "restart".to_string(),
                    "cw-workspace".to_string(),
                ],
            }
        );
    }

    #[test]
    fn validate_local_resize_args_matches_go_rules() {
        let none = LocalResizeArgs {
            name: None,
            cpu: 0,
            memory: 0,
            disk: 0,
            restart: false,
        };
        assert!(
            validate_local_resize_args(&none)
                .unwrap_err()
                .to_string()
                .contains("at least one")
        );

        let negative_cpu = LocalResizeArgs { cpu: -1, ..none };
        assert_eq!(
            validate_local_resize_args(&negative_cpu)
                .unwrap_err()
                .to_string(),
            "--cpu must be positive"
        );

        let valid = LocalResizeArgs {
            name: Some("repo".to_string()),
            cpu: 0,
            memory: 4096,
            disk: 0,
            restart: true,
        };
        validate_local_resize_args(&valid).unwrap();
    }

    #[test]
    fn local_resize_command_spec_builds_lima_edit() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo-runtime".to_string(),
            lima_instance_name: "cw-repo-vm".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let args = LocalResizeArgs {
            name: Some("repo".to_string()),
            cpu: 2500,
            memory: 3072,
            disk: 40,
            restart: true,
        };

        assert_eq!(
            local_resize_command_spec(&instance, &args).unwrap(),
            LocalRuntimeCommand {
                program: "limactl".to_string(),
                args: vec![
                    "edit".to_string(),
                    "--tty=false".to_string(),
                    "cw-repo-vm".to_string(),
                    "--cpus".to_string(),
                    "3".to_string(),
                    "--memory".to_string(),
                    "3".to_string(),
                    "--disk".to_string(),
                    "40".to_string(),
                ],
            }
        );

        let half_gib = LocalResizeArgs {
            memory: 512,
            ..args
        };
        let command = local_resize_command_spec(&instance, &half_gib).unwrap();
        let memory = command
            .args
            .windows(2)
            .find(|args| args[0] == "--memory")
            .map(|args| args[1].as_str());
        assert_eq!(memory, Some("0.5"));
    }

    #[test]
    fn local_resize_command_spec_rejects_docker() {
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "docker".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };
        let args = LocalResizeArgs {
            name: Some("repo".to_string()),
            cpu: 1000,
            memory: 0,
            disk: 0,
            restart: false,
        };

        assert!(
            local_resize_command_spec(&instance, &args)
                .unwrap_err()
                .to_string()
                .contains("only supported for Lima")
        );
    }

    #[test]
    fn parse_lima_instance_status_handles_array_and_json_lines() {
        let array =
            br#"[{"name":"cw-repo","status":"Running"},{"name":"other","status":"Stopped"}]"#;
        assert_eq!(
            parse_lima_instance_status("cw-repo", array).unwrap(),
            "running"
        );

        let lines = br#"
{"name":"other","status":"Stopped"}
not-json
{"name":"cw-repo","status":""}
"#;
        assert_eq!(
            parse_lima_instance_status("cw-repo", lines).unwrap(),
            "unknown"
        );
        assert_eq!(
            parse_lima_instance_status("missing", lines).unwrap(),
            "missing"
        );
    }

    #[test]
    fn parse_lima_instance_resources_uses_the_runtime_not_stale_local_defaults() {
        let lines = br#"
{"name":"cw-repo","status":"Running","cpus":4,"memory":8589934592,"disk":107374182400}
"#;
        assert_eq!(
            parse_lima_instance_resources("cw-repo", lines).unwrap(),
            LocalLimaResources {
                cpu_millicores: 4000,
                memory_mb: 8192,
                disk_gb: 100,
            }
        );
        assert!(parse_lima_instance_resources("missing", lines).is_err());
    }

    #[test]
    fn format_local_resize_text_matches_go_shape() {
        let entry = LocalInstanceEntry {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            status: "stopped".to_string(),
            runtime_name: "cw-repo".to_string(),
            repo_path: "/repo".to_string(),
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
            cpu: 2500,
            memory: 3072,
            disk: 40,
            created_at: String::new(),
            last_used_at: String::new(),
            lima: None,
        };

        assert_eq!(
            format_local_resize_text(&entry),
            concat!(
                "State:     stopped\n",
                "CPU:       2500m\n",
                "Memory:    3GiB\n",
                "Disk:      40GiB\n",
            )
        );
    }

    #[test]
    fn format_current_target_text_reports_local_instance_details() {
        let target = config::CurrentTargetConfig {
            kind: "local".to_string(),
            target_ref: "repo".to_string(),
            name: "cached-repo".to_string(),
        };
        let instance = config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: "lima".to_string(),
            runtime_name: "cw-repo".to_string(),
            ..config::LocalInstanceConfig::default()
        };

        assert_eq!(
            format_current_target_text(&target, None, Some(&instance), None, false),
            "repo [lima]\n"
        );
        assert_eq!(
            format_current_target_text(&target, None, Some(&instance), None, true),
            concat!(
                "Kind:      local\n",
                "Target:    repo\n",
                "Backend:   lima\n",
                "Runtime:   cw-repo\n",
            )
        );
    }

    #[test]
    fn format_current_target_text_reports_environment_details() {
        let target = config::CurrentTargetConfig {
            kind: "env".to_string(),
            target_ref: "12345678-abcd-4000-9000-000000000001".to_string(),
            name: "cached-name".to_string(),
        };
        let environment = test_environment(
            "12345678-abcd-4000-9000-000000000001",
            Some("builder"),
            "running",
        );

        assert_eq!(
            format_current_target_text(&target, Some(&environment), None, Some("mesh-dev"), false),
            "builder [12345678] running  network: mesh-dev\n"
        );
        assert_eq!(
            format_current_target_text(&target, Some(&environment), None, Some("mesh-dev"), true),
            concat!(
                "Kind:      env\n",
                "Network:   mesh-dev\n",
                "Target:    builder\n",
                "ID:        12345678-abcd-4000-9000-000000000001\n",
                "ShortID:   12345678\n",
                "Name:      builder\n",
                "State:     running\n",
            )
        );
    }
