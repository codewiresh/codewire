    #[test]
    fn accepted_organization_deletion_is_not_reported_as_deleted() {
        let started = organization_deletion_started_message("op_test");
        let stopped = organization_deletion_polling_stopped_message("op_test");

        assert_eq!(
            started,
            "Organization deletion started (operation op_test)."
        );
        assert!(!started.to_ascii_lowercase().contains("deleted"));
        assert!(stopped.contains("server work continues"));
        assert!(!stopped.to_ascii_lowercase().contains("deleted"));
    }

    fn named_local_instance(backend: &str) -> config::LocalInstanceConfig {
        config::LocalInstanceConfig {
            name: "repo".to_string(),
            backend: backend.to_string(),
            runtime_name: "cw-repo".to_string(),
            workdir: LOCAL_WORKSPACE_PATH.to_string(),
            ..config::LocalInstanceConfig::default()
        }
    }

    #[test]
    fn replace_managed_ssh_section_appends_go_compatible_block() {
        let rendered =
            replace_managed_ssh_section("", &ssh_config_block(&SshConfigOptions::default()))
                .unwrap();

        assert!(rendered.contains("ProxyCommand cw shell --stdio %n"));
        assert!(rendered.contains("StrictHostKeyChecking accept-new"));
        assert!(rendered.contains("UserKnownHostsFile "));
        assert!(rendered.contains(SSH_CONFIG_MARKER_START));
        assert!(rendered.contains(SSH_CONFIG_MARKER_END));
    }

    #[test]
    fn replace_managed_ssh_section_replaces_existing_block() {
        let existing = [
            "Host github.com",
            "    User git",
            "",
            SSH_CONFIG_MARKER_START,
            "Host cw-*",
            "    ProxyCommand old",
            SSH_CONFIG_MARKER_END,
            "",
            "Host other",
            "    User someone",
            "",
        ]
        .join("\n");

        let rendered = replace_managed_ssh_section(
            &existing,
            &ssh_config_block(&SshConfigOptions {
                ssh_options: vec!["ForwardAgent yes".to_string()],
            }),
        )
        .unwrap();

        assert!(!rendered.contains("ProxyCommand old"));
        assert!(rendered.contains("ForwardAgent yes"));
        assert!(rendered.contains("Host github.com"));
        assert!(rendered.contains("Host other"));
    }

    #[test]
    fn replace_managed_ssh_section_rejects_incomplete_markers() {
        let err = replace_managed_ssh_section(SSH_CONFIG_MARKER_START, "managed").unwrap_err();

        assert!(
            err.to_string()
                .contains("malformed ssh config: Codewire markers are incomplete")
        );
    }

    #[test]
    fn render_managed_ssh_config_detects_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        let content = ssh_config_block(&SshConfigOptions {
            ssh_options: vec!["ForwardAgent yes".to_string()],
        }) + "\n";
        fs::write(&config_path, &content).unwrap();

        let (rendered, changed) = render_managed_ssh_config(
            &config_path,
            &SshConfigOptions {
                ssh_options: vec!["ForwardAgent yes".to_string()],
            },
        )
        .unwrap();

        assert!(!changed);
        assert_eq!(rendered, content);
    }

    #[test]
    fn format_doctor_text_reports_paths_and_checks() {
        let report = DoctorReport {
            platform_config_dir: "/tmp/cw-config".to_string(),
            mesh_data_dir: "/tmp/cw-data".to_string(),
            checks: vec![
                doctor_check("platform", DoctorStatus::Ok, "Noel on https://codewire.sh"),
                doctor_check("local node", DoctorStatus::Warn, "not running"),
            ],
        };

        assert_eq!(
            format_doctor_text(&report),
            concat!(
                "Config:      /tmp/cw-config\n",
                "Mesh data:   /tmp/cw-data\n",
                "\n",
                "platform     ok     Noel on https://codewire.sh\n",
                "local node   warn   not running\n",
            )
        );
    }

    fn test_tailnet_diagnostic(transport: &str) -> tailnet_ssh::EnvironmentTailnetDiagnostic {
        tailnet_ssh::EnvironmentTailnetDiagnostic {
            environment_id: "env_123".to_string(),
            server_url: "https://codewire.test/".to_string(),
            forced_derp: false,
            direct_wait: "15s".to_string(),
            stages: vec![tailnet_ssh::TailnetDiagnosticStage {
                name: "path".to_string(),
                status: "ok",
                detail: format!("transport={transport} expected=any"),
                duration_ms: Some(12),
            }],
            derp_map: Some(tailnet_ssh::TailnetDerpMapDiagnostic {
                regions: 1,
                derp_nodes: 1,
                stun_nodes: 1,
            }),
            peer: Some(tailnet_ssh::TailnetPeerDiagnostic {
                id: "env_123".to_string(),
                preferred_derp: 1,
                endpoints: vec!["203.0.113.10:41641".to_string()],
                addresses: vec!["fd7a:115c:a1e0::1/128".to_string()],
            }),
            direct_path: None,
            final_path: Some(tailnet_ssh::TailnetPathDiagnostic {
                ready: true,
                transport: transport.to_string(),
                endpoint: "203.0.113.10:41641".to_string(),
                derp_region_id: None,
                error: String::new(),
            }),
        }
    }



    #[test]
    fn format_tailnet_doctor_text_uses_current_transport_terms() {
        let report = TailnetDoctorReport {
            environment_id: "env_123".to_string(),
            server_url: "https://codewire.test/".to_string(),
            expect: "udp_relay".to_string(),
            direct: test_tailnet_diagnostic("udp_relay"),
            forced_derp: Some(test_tailnet_diagnostic("derp")),
        };

        let text = format_tailnet_doctor_text(&report);
        assert!(text.contains("Expect:      udp_relay"));
        assert!(text.contains("transport=udp_relay"));
        assert!(text.contains("transport=derp"));
        assert!(text.contains("Probe:       forced derp"));
        assert!(!text.contains("peer_relay"));
        assert!(!text.contains("derp_relay"));
    }

    #[test]
    fn validate_tailnet_doctor_report_checks_transport_expectations() {
        let report = TailnetDoctorReport {
            environment_id: "env_123".to_string(),
            server_url: "https://codewire.test/".to_string(),
            expect: "udp_relay".to_string(),
            direct: test_tailnet_diagnostic("udp_relay"),
            forced_derp: None,
        };
        validate_tailnet_doctor_report(&report).unwrap();

        let missing = TailnetDoctorReport {
            expect: "direct_udp".to_string(),
            ..report
        };
        assert!(
            validate_tailnet_doctor_report(&missing)
                .unwrap_err()
                .to_string()
                .contains("expected direct_udp")
        );
    }

    #[test]
    fn parse_tailnet_doctor_duration_accepts_ms_seconds_and_minutes() {
        assert_eq!(
            parse_tailnet_doctor_duration("direct-wait", "250ms", true).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_tailnet_doctor_duration("direct-wait", "15s", true).unwrap(),
            Duration::from_secs(15)
        );
        assert_eq!(
            parse_tailnet_doctor_duration("peer-timeout", "1m", false).unwrap(),
            Duration::from_secs(60)
        );
        assert!(parse_tailnet_doctor_duration("peer-timeout", "0s", false).is_err());
    }

    #[test]
    fn doctor_ssh_config_check_at_reports_missing_and_managed_section() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");

        let missing = doctor_ssh_config_check_at(&config_path);
        assert_eq!(missing.status, DoctorStatus::Warn);
        assert!(missing.detail.contains("missing"));

        fs::write(&config_path, "Host github.com\n  User git\n").unwrap();
        let unmanaged = doctor_ssh_config_check_at(&config_path);
        assert_eq!(unmanaged.status, DoctorStatus::Warn);
        assert!(unmanaged.detail.contains("Codewire section missing"));

        fs::write(
            &config_path,
            format!(
                "{}\nHost cw-*\n{}\n",
                SSH_CONFIG_MARKER_START, SSH_CONFIG_MARKER_END
            ),
        )
        .unwrap();
        let managed = doctor_ssh_config_check_at(&config_path);
        assert_eq!(managed.status, DoctorStatus::Ok);
        assert_eq!(managed.detail, config_path.display().to_string());
    }




    #[test]
    fn network_invite_parser_rejects_removed_browser_qr_flag() {
        let cli = Cli::try_parse_from([
            "cw",
            "network",
            "invite",
            "--org",
            "org-alpha",
            "--network",
            "project-alpha",
            "--ttl",
            "2h",
            "--qr",
        ])
        .unwrap_err();

        assert_eq!(cli.kind(), clap::error::ErrorKind::UnknownArgument);
    }




    #[test]
    fn normalize_login_server_url_trims_trailing_slash() {
        assert_eq!(
            normalize_login_server_url(Some(" https://codewire.sh/ ")).as_deref(),
            Some("https://codewire.sh")
        );
        assert_eq!(normalize_login_server_url(Some("   ")), None);
        assert_eq!(normalize_login_server_url(None), None);
    }

    #[test]
    fn save_login_platform_config_persists_only_reconciled_default_org() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        config::save_platform_config(
            &paths.platform_config_dir,
            &config::PlatformConfig {
                server_url: "https://old.codewire.sh".to_string(),
                session_token: "old-token".to_string(),
                default_org: "org_123".to_string(),
            },
        )
        .unwrap();

        let credentials = codewire_client::OAuthCredentials::new(
            "https://new.codewire.sh",
            codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "access-token",
            "refresh-token",
            u64::MAX,
            codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .unwrap();
        assert_eq!(
            saved_login_default_org(&paths, "https://old.codewire.sh").as_deref(),
            Some("org_123")
        );
        assert_eq!(
            saved_login_default_org(&paths, "https://new.codewire.sh"),
            None
        );
        save_login_platform_config(
            &paths,
            "https://new.codewire.sh",
            &credentials,
            Some("org_new"),
        )
        .unwrap();

        let saved = config::load_platform_config(&paths.platform_config_dir).unwrap();
        assert_eq!(saved.server_url, "https://new.codewire.sh");
        assert!(saved.session_token.is_empty());
        assert_eq!(saved.default_org, "org_new");
        assert!(config::oauth_credentials_path(&paths.platform_config_dir).is_file());
        let resolved = config::resolve_platform(
            config::PlatformResolveOptions::default(),
            &paths,
            &env,
        )
        .unwrap();
        let orgs = vec![OrgWithRole {
            id: "org_new".to_string(),
            name: "New Org".to_string(),
            slug: "new-org".to_string(),
            role: "owner".to_string(),
            ..OrgWithRole::default()
        }];
        assert_eq!(current_org_id(&resolved, &orgs).unwrap(), "org_new");
        assert_eq!(
            doctor_org_selection_check(&resolved, &orgs),
            doctor_check("org", DoctorStatus::Ok, "New Org")
        );

        save_login_platform_config(&paths, "https://new.codewire.sh", &credentials, None).unwrap();
        let saved = config::load_platform_config(&paths.platform_config_dir).unwrap();
        assert!(saved.default_org.is_empty());
    }

    #[test]
    fn login_parser_accepts_default_org() {
        let cli = Cli::try_parse_from(["cw", "login", "--org", "codewire"]).unwrap();
        let Command::Login(args) = cli.command else {
            panic!("expected login command");
        };
        assert_eq!(args.org.as_deref(), Some("codewire"));
    }

    #[test]
    fn setup_parser_accepts_noninteractive_flags() {
        let cli = Cli::try_parse_from([
            "cw",
            "setup",
            "--org",
            "codewire",
            "--github",
            "--skip-ssh",
        ])
        .unwrap();

        let Command::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert_eq!(args.org.as_deref(), Some("codewire"));
        assert!(args.github);
        assert!(args.skip_ssh);
    }

    #[test]
    fn native_login_commands_do_not_accept_password_flags() {
        for command in [
            vec!["cw", "login", "--password"],
            vec!["cw", "setup", "--password"],
        ] {
            let error = Cli::try_parse_from(command).unwrap_err();
            assert!(error.to_string().contains("unexpected argument '--password'"));
        }
    }

    #[test]
    fn setup_parser_requires_create_org_for_org_slug() {
        let err = Cli::try_parse_from(["cw", "setup", "--org-slug", "codewire"]).unwrap_err();

        assert!(err.to_string().contains("--create-org"));
    }

    #[test]
    fn attach_command_parser_accepts_environment_and_session() {
        let cli = Cli::try_parse_from(["cw", "attach", "builder", "worker"]).unwrap();

        let Command::Attach(args) = cli.command else {
            panic!("expected attach command");
        };
        assert_eq!(args.environment.as_deref(), Some("builder"));
        assert_eq!(args.session.as_deref(), Some("worker"));
        assert_eq!(args.selected_session, None);
    }

    #[test]
    fn attach_command_parser_accepts_selected_environment_session_flag() {
        let cli = Cli::try_parse_from(["cw", "attach", "--session", "worker"]).unwrap();

        let Command::Attach(args) = cli.command else {
            panic!("expected attach command");
        };
        assert_eq!(args.environment, None);
        assert_eq!(args.session, None);
        assert_eq!(args.selected_session.as_deref(), Some("worker"));
    }

    #[test]
    fn resolve_setup_server_url_defaults_to_hosted_codewire() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::default();
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let globals = Globals {
            server: None,
            token: None,
        };

        assert_eq!(
            resolve_setup_server_url(&globals, &paths, &env),
            "https://codewire.sh"
        );
    }

    #[test]
    fn resolve_setup_server_url_prefers_global_server() {
        let home = tempfile::tempdir().unwrap();
        let env = config::MapEnv::new([("CODEWIRE_SERVER_URL", "https://env.codewire.sh")]);
        let paths = ResolvePaths::from_home_and_env(home.path().to_path_buf(), &env);
        let globals = Globals {
            server: Some(" https://flag.codewire.sh/ ".to_string()),
            token: None,
        };

        assert_eq!(
            resolve_setup_server_url(&globals, &paths, &env),
            "https://flag.codewire.sh"
        );
    }

    #[test]
    fn oauth_user_display_name_prefers_name_then_email() {
        let named = OAuthUserInfo {
            name: Some("Noel".to_string()),
            email: Some("n@example.com".to_string()),
            ..OAuthUserInfo::default()
        };
        let email_only = OAuthUserInfo {
            email: Some("n@example.com".to_string()),
            ..OAuthUserInfo::default()
        };

        assert_eq!(oauth_user_display_name(&named), "Noel");
        assert_eq!(oauth_user_display_name(&email_only), "n@example.com");
        assert_eq!(oauth_user_display_name(&OAuthUserInfo::default()), "(unknown)");
    }

    #[test]
    fn nodes_have_multiple_networks_ignores_blank_networks() {
        let nodes = vec![
            Node {
                network_id: String::new(),
                name: "legacy".to_string(),
                peer_url: String::new(),
                connected: false,
            },
            Node {
                network_id: "project-alpha".to_string(),
                name: "builder".to_string(),
                peer_url: String::new(),
                connected: true,
            },
        ];

        assert!(!nodes_have_multiple_networks(&nodes));
    }

    #[test]
    fn nodes_have_multiple_networks_detects_distinct_networks() {
        let nodes = vec![
            Node {
                network_id: "project-alpha".to_string(),
                name: "builder".to_string(),
                peer_url: String::new(),
                connected: true,
            },
            Node {
                network_id: "project-beta".to_string(),
                name: "planner".to_string(),
                peer_url: String::new(),
                connected: false,
            },
        ];

        assert!(nodes_have_multiple_networks(&nodes));
    }

    #[test]
    fn format_whoami_text_matches_go_layout() {
        let user = PlatformUser {
            name: "Example Owner".to_string(),
            email: "n@example.com".to_string(),
            ..PlatformUser::default()
        };

        assert_eq!(
            format_whoami_text(&user, "https://codewire.sh", Some("noel")),
            concat!(
                "User:      Example Owner (n@example.com)\n",
                "Server:    https://codewire.sh\n",
                "Org:       noel\n",
            )
        );
    }

    #[test]
    fn format_whoami_text_omits_empty_default_org() {
        let user = PlatformUser {
            email: "n@example.com".to_string(),
            ..PlatformUser::default()
        };

        assert_eq!(
            format_whoami_text(&user, "https://codewire.sh", Some("  ")),
            concat!(
                "User:       (n@example.com)\n",
                "Server:    https://codewire.sh\n",
            )
        );
    }

    fn test_environment(id: &str, name: Option<&str>, state: &str) -> Environment {
        Environment {
            id: id.to_string(),
            name: name.map(str::to_string),
            state: state.to_string(),
            ..Environment::default()
        }
    }

    #[test]
    fn env_trust_report_command_parser_accepts_json_and_alias() {
        let cli = Cli::try_parse_from(["cw", "env", "trust-report", "builder", "--output", "json"])
            .unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::TrustReport(args),
            ..
        }) = cli.command
        else {
            panic!("expected env trust-report command");
        };
        assert_eq!(args.environment, "builder");
        assert_eq!(args.output, OutputFormat::Json);

        let cli = Cli::try_parse_from(["cw", "env", "attest", "builder"]).unwrap();
        let Command::Env(EnvArgs {
            command: EnvCommand::TrustReport(args),
            ..
        }) = cli.command
        else {
            panic!("expected env attest alias");
        };
        assert_eq!(args.environment, "builder");
        assert_eq!(args.output, OutputFormat::Text);
    }

    #[test]
    fn format_env_trust_report_text_marks_confidential_dev_proof() {
        let report: EnvironmentTrustReport = serde_json::from_value(serde_json::json!({
            "environment": {
                "id": "env_123",
                "org_id": "org_123",
                "type": "sandbox",
                "state": "running"
            },
            "runtime": {
                "profile": "confidential",
                "runtime_class": "confidential",
                "handler": "kata-qemu-snp",
                "confidential": true
            },
            "placement": {
                "namespace": "dev-sandboxes",
                "workspace_pod": "workspace-env-123",
                "pod_ip": "10.42.0.12",
                "node": "node1-codewire-dev",
                "zone": "hel1",
                "region": "eu-central"
            },
            "images": {
                "workspace_image": "ghcr.io/codewiresh/workspace@sha256:abc",
                "workspace_image_id": "docker-pullable://ghcr.io/codewiresh/workspace@sha256:abc",
                "gateway_image": "ghcr.io/codewiresh/codewire-gateway@sha256:def",
                "gateway_image_id": "docker-pullable://ghcr.io/codewiresh/codewire-gateway@sha256:def",
                "dind_image": "docker:dind",
                "dind_image_id": "docker-pullable://docker:dind@sha256:123",
                "daemon_init_image": "ghcr.io/codewiresh/codewire-daemon@sha256:456",
                "daemon_init_image_id": "docker-pullable://ghcr.io/codewiresh/codewire-daemon@sha256:456"
            },
            "provenance": {
                "status": "not_available",
                "notes": [
                    "Guest kernel, initrd/image, and firmware provenance are not persisted by the runtime API yet."
                ]
            },
            "attestation": {
                "status": "dev_evidence_available",
                "tee": "sev-snp",
                "report_available": false,
                "report_source": "Gitea #618 dev smoke",
                "metadata": {
                    "report_version": "5",
                    "vmpl": "1"
                }
            },
            "trustee": {
                "status": "dev_policy_matched",
                "resource_uri": "kbs:///default/codewire/runtime-test-resource",
                "reference_values": "dev_reference_values_registered",
                "policy": "claim_bound_dev_policy",
                "evidence_issues": ["#619", "#620"]
            },
            "summary": {
                "trust_level": "dev_proof",
                "production_verified": false,
                "warnings": [
                    "Current confidential evidence is dev-only.",
                    "Raw SEV-SNP reports are intentionally not exposed."
                ]
            }
        }))
        .unwrap();

        let text = format_env_trust_report_text(&report);

        assert!(text.contains("Trust report: env_123\n"));
        assert!(text.contains("Trust level: dev_proof\n"));
        assert!(text.contains(
            "Runtime: confidential / RuntimeClass confidential / handler kata-qemu-snp\n"
        ));
        assert!(text.contains("Node: node1-codewire-dev\n"));
        assert!(text.contains(
            "Gateway image ID: docker-pullable://ghcr.io/codewiresh/codewire-gateway@sha256:def\n"
        ));
        assert!(text.contains("Provenance: not_available\n"));
        assert!(text.contains("Attestation: dev_evidence_available (sev-snp)\n"));
        assert!(text.contains("Resource: kbs:///default/codewire/runtime-test-resource\n"));
        assert!(text.contains("Evidence issues: #619, #620\n"));
        assert!(text.contains("Raw SEV-SNP reports are intentionally not exposed."));
    }

    #[test]
    fn resolve_environment_id_matches_name_exactly_then_id_prefix() {
        let environments = vec![
            test_environment(
                "12345678-abcd-4000-9000-000000000001",
                Some("builder"),
                "running",
            ),
            test_environment(
                "87654321-abcd-4000-9000-000000000002",
                Some("tester"),
                "stopped",
            ),
        ];

        assert_eq!(
            resolve_environment_id_from_list(&environments, "builder").unwrap(),
            "12345678-abcd-4000-9000-000000000001"
        );
        assert_eq!(
            resolve_environment_id_from_list(&environments, "87654321").unwrap(),
            "87654321-abcd-4000-9000-000000000002"
        );
    }

    #[test]
    fn resolve_environment_id_rejects_ambiguous_targets() {
        let environments = vec![
            test_environment(
                "12345678-abcd-4000-9000-000000000001",
                Some("builder"),
                "running",
            ),
            test_environment(
                "12345679-abcd-4000-9000-000000000002",
                Some("builder"),
                "stopped",
            ),
        ];

        let name_err = resolve_environment_id_from_list(&environments, "builder").unwrap_err();
        assert!(
            name_err
                .to_string()
                .contains("multiple environments named \"builder\"")
        );

        let prefix_err = resolve_environment_id_from_list(&environments, "1234567").unwrap_err();
        assert!(
            prefix_err
                .to_string()
                .contains("matched multiple IDs, use a longer prefix")
        );
    }

    #[test]
    fn format_current_target_text_reports_local_and_mesh_network() {
        let target = config::default_current_target();

        assert_eq!(
            format_current_target_text(&target, None, None, Some("project-alpha"), false),
            "local  network: project-alpha\n"
        );
        assert_eq!(
            format_current_target_text(&target, None, None, Some("project-alpha"), true),
            concat!(
                "Kind:      local\n",
                "Network:   project-alpha\n",
                "Target:    local\n"
            )
        );
    }
