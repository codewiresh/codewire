
    #[test]
    fn parse_env_overrides_requires_key_value_shape() {
        let parsed = parse_env_overrides(&["FOO=bar".to_string(), "EMPTY=".to_string()]).unwrap();
        assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));

        let err = parse_env_overrides(&["missing".to_string()]).unwrap_err();
        assert!(err.to_string().contains("KEY=VALUE"));
    }

    fn test_billing_overview(plan: &str, plan_display_name: &str) -> BillingOverview {
        BillingOverview {
            billing_enabled: true,
            has_payment_method: true,
            plan: plan.to_string(),
            plan_display_name: plan_display_name.to_string(),
            status: "active".to_string(),
            trial_days: 14,
            seat_count: 3,
            included_devs: 5,
            extra_seat_price_cents: 2000,
            active_subscriptions: 2,
            total_monthly_cost_cents: 12345,
            current_month_usage: crate::console_client::UsageSummary {
                cpu_hours: 12.5,
                memory_gb_hours: 32.0,
                storage_gb_hours: 90.25,
            },
            limits: crate::console_client::BillingLimits {
                team_members: crate::console_client::LimitUsage { used: 3, max: 10 },
                concurrent_workspaces: 4,
                storage_gb: 100,
            },
            ..BillingOverview::default()
        }
    }

    #[test]
    fn billing_plan_label_falls_back_to_plan_then_none() {
        assert_eq!(
            billing_plan_label(&test_billing_overview("team", "Team")),
            "Team"
        );
        assert_eq!(
            billing_plan_label(&test_billing_overview("team", "")),
            "team"
        );
        assert_eq!(billing_plan_label(&test_billing_overview("", "")), "none");
    }

    #[test]
    fn cost_org_matches_slug_or_id() {
        let org = OrgWithRole {
            id: "org_123".to_string(),
            slug: "codewire".to_string(),
            ..OrgWithRole::default()
        };

        assert!(cost_org_matches(&org, None));
        assert!(cost_org_matches(&org, Some("codewire")));
        assert!(cost_org_matches(&org, Some("org_123")));
        assert!(!cost_org_matches(&org, Some("other")));
    }

    #[test]
    fn format_cost_text_matches_existing_cli_shape() {
        let reports = vec![
            OrgCostReport {
                org: OrgWithRole {
                    id: "org_123".to_string(),
                    slug: "codewire".to_string(),
                    ..OrgWithRole::default()
                },
                billing: Some(test_billing_overview("team", "Team")),
            },
            OrgCostReport {
                org: OrgWithRole {
                    id: "org_456".to_string(),
                    slug: "missing".to_string(),
                    ..OrgWithRole::default()
                },
                billing: None,
            },
        ];

        assert_eq!(
            format_cost_text(&reports),
            concat!(
                "# codewire\n",
                "\n",
                "  Plan             Status       Seats $/mo     CPU hrs Mem GB·hrs Storage GB·hrs\n",
                "  Team             active       3     $123.45  12.5    32.0       90.2\n",
                "\n",
                "  Included developers: 5\n",
                "  Active subscriptions: 2\n",
                "\n",
                "# missing (billing unavailable)\n",
                "\n",
            )
        );
    }

    #[test]
    fn cost_json_omits_unavailable_billing() {
        let reports = vec![OrgCostReport {
            org: OrgWithRole {
                id: "org_123".to_string(),
                slug: "codewire".to_string(),
                ..OrgWithRole::default()
            },
            billing: None,
        }];

        let value = serde_json::to_value(reports).unwrap();

        assert_eq!(value[0]["org"]["slug"], "codewire");
        assert!(value[0].get("billing").is_none());
    }

    #[test]
    fn format_github_status_text_reports_disconnected() {
        assert_eq!(
            format_github_status_text(&GitHubStatus::default()),
            "GitHub: not connected\n  Run 'cw github login' to connect.\n"
        );
    }

    #[test]
    fn format_github_status_text_reports_connected_details() {
        let status = GitHubStatus {
            connected: true,
            username: "noel".to_string(),
            installation_id: Some(12345),
            connected_at: Some("2026-07-04T19:00:00Z".to_string()),
        };

        assert_eq!(
            format_github_status_text(&status),
            concat!(
                "GitHub: connected as @noel\n",
                "  Installation ID: 12345\n",
                "  Connected: 2026-07-04T19:00:00Z\n",
            )
        );
    }

    #[test]
    fn github_expiry_at_formats_future_rfc3339_seconds() {
        assert_eq!(github_expiry_at(0), None);
        assert_eq!(github_expiry_at(-5), None);

        let before = Utc::now() - ChronoDuration::seconds(1);
        let expiry = github_expiry_at(60).unwrap();
        let parsed = DateTime::<Utc>::from_timestamp(expiry.seconds, expiry.nanos as u32)
            .expect("expiry timestamp");

        assert!(parsed > before);
    }

    fn test_org(id: &str, name: &str, slug: &str, role: &str) -> OrgWithRole {
        OrgWithRole {
            id: id.to_string(),
            name: name.to_string(),
            slug: slug.to_string(),
            role: role.to_string(),
            ..OrgWithRole::default()
        }
    }

    #[test]
    fn format_org_list_text_marks_current_org() {
        let orgs = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];

        assert_eq!(
            format_org_list_text(&orgs, Some("org_2")),
            concat!(
                "NAME                     SLUG                     ROLE\n",
                "Noel Labs                noel-labs                owner\n",
                "Codewire *               codewire                 admin\n",
            )
        );
    }

    #[test]
    fn format_org_current_text_matches_go_layout() {
        let org = test_org("org_123", "Codewire", "codewire", "owner");

        assert_eq!(
            format_org_current_text(&org),
            concat!(
                "Name:      Codewire\n",
                "Slug:      codewire\n",
                "ID:        org_123\n",
                "Role:      owner\n",
            )
        );
    }

    #[test]
    fn select_org_accepts_id_or_slug() {
        let orgs = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];

        assert_eq!(select_org(&orgs, Some("org_1")).unwrap().slug, "noel-labs");
        assert_eq!(select_org(&orgs, Some("codewire")).unwrap().id, "org_2");
    }

    #[test]
    fn select_org_without_arg_requires_single_org() {
        let one = vec![test_org("org_1", "Noel Labs", "noel-labs", "owner")];
        assert_eq!(select_org(&one, None).unwrap().id, "org_1");

        let many = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];
        assert!(
            select_org(&many, None)
                .unwrap_err()
                .to_string()
                .contains("multiple organizations found")
        );
    }

    #[test]
    fn current_org_id_validates_saved_default_for_config_auth() {
        let orgs = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];
        let platform = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            true,
            Some("org_2".to_string()),
        );
        assert_eq!(current_org_id(&platform, &orgs).unwrap(), "org_2");

        let stale = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            true,
            Some("org_stale".to_string()),
        );
        let error = current_org_id(&stale, &orgs).unwrap_err().to_string();
        assert!(error.contains("org_stale"));
        assert!(error.contains("cw org set"));

        let platform = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            false,
            Some("org_2".to_string()),
        );
        assert!(
            current_org_id(&platform, &orgs)
                .unwrap_err()
                .to_string()
                .contains("no org selected")
        );
    }

    #[test]
    fn login_org_resolution_preserves_valid_and_replaces_stale_defaults() {
        let orgs = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];

        let LoginOrgResolution::Selected(selected) =
            resolve_login_org(&orgs, Some("org_2"), None).unwrap()
        else {
            panic!("expected configured organization");
        };
        assert_eq!(selected.id, "org_2");

        assert!(matches!(
            resolve_login_org(&orgs, Some("org_stale"), None).unwrap(),
            LoginOrgResolution::SelectionRequired
        ));

        let LoginOrgResolution::Selected(selected) =
            resolve_login_org(&orgs[..1], Some("org_stale"), None).unwrap()
        else {
            panic!("expected sole organization");
        };
        assert_eq!(selected.id, "org_1");
    }

    #[test]
    fn login_org_resolution_honors_explicit_selection_and_empty_membership() {
        let orgs = vec![
            test_org("org_1", "Noel Labs", "noel-labs", "owner"),
            test_org("org_2", "Codewire", "codewire", "admin"),
        ];

        let LoginOrgResolution::Selected(selected) =
            resolve_login_org(&orgs, Some("org_1"), Some("codewire")).unwrap()
        else {
            panic!("expected requested organization");
        };
        assert_eq!(selected.id, "org_2");
        assert!(matches!(
            resolve_login_org(&[], Some("org_stale"), None).unwrap(),
            LoginOrgResolution::NoOrganizations
        ));
    }

    #[test]
    fn doctor_warns_for_stale_org_and_is_ok_only_for_live_org() {
        let orgs = vec![test_org(
            "org_1",
            "Noel Labs",
            "noel-labs",
            "owner",
        )];
        let stale = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            true,
            Some("org_stale".to_string()),
        );
        let warning = doctor_org_selection_check(&stale, &orgs);
        assert_eq!(warning.status, DoctorStatus::Warn);
        assert!(warning.detail.contains("cw org set"));

        let valid = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            true,
            Some("org_1".to_string()),
        );
        assert_eq!(
            doctor_org_selection_check(&valid, &orgs),
            doctor_check("org", DoctorStatus::Ok, "Noel Labs")
        );
    }

    #[test]
    fn resolve_org_id_accepts_go_org_id_forms_and_slugs() {
        let orgs = vec![test_org("org_1", "Noel Labs", "noel-labs", "owner")];
        let platform = config::ResolvedPlatformConfig::static_token(
            "https://codewire.sh",
            "session-token",
            true,
            Some("org_1".to_string()),
        );

        assert_eq!(
            resolve_org_id(&platform, &orgs, Some("org_abc-123")).unwrap(),
            "org_abc-123"
        );
        assert_eq!(
            resolve_org_id(&platform, &orgs, Some("ORG_ABC-123")).unwrap(),
            "ORG_ABC-123"
        );
        assert_eq!(
            resolve_org_id(&platform, &orgs, Some("d1573a66b8cb40b8b00e48ab97aa7c48")).unwrap(),
            "d1573a66b8cb40b8b00e48ab97aa7c48"
        );
        assert_eq!(
            resolve_org_id(
                &platform,
                &orgs,
                Some("d1573a66-b8cb-40b8-b00e-48ab97aa7c48")
            )
            .unwrap(),
            "d1573a66-b8cb-40b8-b00e-48ab97aa7c48"
        );
        assert_eq!(
            resolve_org_id(&platform, &orgs, Some("noel-labs")).unwrap(),
            "org_1"
        );
        assert_eq!(resolve_org_id(&platform, &orgs, None).unwrap(), "org_1");
    }

    #[test]
    fn slugify_matches_go_cases() {
        for (input, expected) in [
            ("Acme Corp", "acme-corp"),
            ("My Cool Project", "my-cool-project"),
            ("  hello  world  ", "hello-world"),
            ("foo--bar", "foo-bar"),
            ("UPPER CASE", "upper-case"),
            ("special!@#chars", "special-chars"),
            ("-leading-trailing-", "leading-trailing"),
            ("a", "a"),
            ("", ""),
        ] {
            assert_eq!(slugify(input), expected);
        }
    }

    #[test]
    fn slugify_truncates_to_go_limit_without_trailing_dash() {
        assert_eq!(
            slugify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbb"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    fn test_api_key(prefix: &str, name: &str, id: &str, created_at: i64) -> ApiKey {
        let mut key = ApiKey {
            key_prefix: prefix.to_string(),
            name: name.to_string(),
            id: id.to_string(),
            ..ApiKey::default()
        };
        let timestamp = key.created_at.get_or_insert_default();
        timestamp.seconds = created_at;
        // The Connect surface preserves database microseconds, while the
        // existing CLI table intentionally stays second-precision.
        timestamp.nanos = 123_456_000;
        key
    }

    #[test]
    fn format_api_key_list_text_matches_go_columns() {
        let keys = vec![
            test_api_key("cw_abcd", "automation", "key_123", 1_783_123_200),
            test_api_key("cw_wxyz", "deploy", "key_456", 1_783_209_600),
        ];

        assert_eq!(
            format_api_key_list_text(&keys),
            concat!(
                "PREFIX           NAME                     ID                                   CREATED\n",
                "cw_abcd          automation               key_123                              2026-07-04T00:00:00Z\n",
                "cw_wxyz          deploy                   key_456                              2026-07-05T00:00:00Z\n",
            )
        );
    }

    #[test]
    fn format_api_key_list_text_keeps_empty_table_header() {
        assert_eq!(
            format_api_key_list_text(&[]),
            "PREFIX           NAME                     ID                                   CREATED\n",
        );
    }

    #[test]
    fn api_key_client_errors_keep_cli_display_semantics() {
        let unauthenticated = display_client_error(codewire_client::ClientError::new(
            codewire_client::ErrorCode::Unauthenticated,
            "unauthorized",
        ));
        assert_eq!(unauthenticated.to_string(), "session expired or invalid");

        let not_found = display_client_error(codewire_client::ClientError::new(
            codewire_client::ErrorCode::NotFound,
            "api key not found",
        ));
        assert_eq!(not_found.to_string(), "api key not found");
    }

    fn test_secret_project(name: &str, secret_count: i64) -> SecretProject {
        SecretProject {
            id: format!("sp_{name}"),
            org_id: "org_123".to_string(),
            name: name.to_string(),
            secret_count,
            created_at: "2026-07-04T00:00:00Z".to_string(),
        }
    }

    fn test_secret(key: &str) -> SecretMetadata {
        SecretMetadata {
            key: key.to_string(),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-05T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn format_secret_project_list_text_matches_go_columns() {
        let projects = vec![
            test_secret_project("prod", 2),
            test_secret_project("dev", 0),
        ];

        assert_eq!(
            format_secret_project_list_text(&projects),
            concat!(
                "NAME                     SECRETS  CREATED\n",
                "prod                     2        2026-07-04T00:00:00Z\n",
                "dev                      0        2026-07-04T00:00:00Z\n",
            )
        );
    }

    #[test]
    fn format_secret_project_list_text_reports_empty() {
        assert_eq!(
            format_secret_project_list_text(&[]),
            "No secret projects found.\n"
        );
    }

    #[test]
    fn format_secret_metadata_list_text_matches_go_columns() {
        let secrets = vec![test_secret("DATABASE_URL"), test_secret("TOKEN")];

        assert_eq!(
            format_secret_metadata_list_text(&secrets, "No secrets found."),
            concat!(
                "KEY                              CREATED                  UPDATED\n",
                "DATABASE_URL                     2026-07-04T00:00:00Z     2026-07-05T00:00:00Z\n",
                "TOKEN                            2026-07-04T00:00:00Z     2026-07-05T00:00:00Z\n",
            )
        );
    }

    #[test]
    fn format_secret_metadata_list_text_reports_custom_empty_message() {
        assert_eq!(
            format_secret_metadata_list_text(&[], "No user secrets found."),
            "No user secrets found.\n"
        );
    }

    #[test]
    fn find_secret_project_by_name_matches_exact_name_only() {
        let projects = vec![
            test_secret_project("prod", 1),
            SecretProject {
                id: "sp_exact".to_string(),
                name: "sp_exact".to_string(),
                ..test_secret_project("other", 0)
            },
        ];

        assert_eq!(
            find_secret_project_by_name(&projects, "prod").unwrap().id,
            "sp_prod"
        );
        assert_eq!(
            find_secret_project_by_name(&projects, "sp_exact")
                .unwrap()
                .name,
            "sp_exact"
        );
        assert!(find_secret_project_by_name(&projects, "sp_other").is_none());
    }

    fn test_preset(id: &str, name: &str, slug: &str, image: &str) -> Preset {
        Preset {
            id: id.to_string(),
            name: name.to_string(),
            slug: Some(slug.to_string()),
            language: Some("rust".to_string()),
            build_status: "ready".to_string(),
            default_cpu_millicores: 2000,
            default_memory_mb: 4096,
            default_disk_gb: 20,
            image: Some(image.to_string()),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            ..Preset::default()
        }
    }

    #[test]
    fn format_preset_list_text_matches_go_columns() {
        let presets = vec![
            Preset {
                official: true,
                ..test_preset(
                    "preset_1",
                    "Workspace",
                    "workspace",
                    "ghcr.io/codewiresh/workspace:latest",
                )
            },
            Preset {
                language: None,
                image: None,
                default_disk_gb: 10,
                ..test_preset("preset_2", "Private", "private", "unused")
            },
        ];

        assert_eq!(
            format_preset_list_text(&presets),
            concat!(
                "NAME                     LANGUAGE     IMAGE                                    OFFICIAL CPU/MEM/DISK\n",
                "workspace                rust         ghcr.io/codewiresh/workspace:latest      yes      2000m/4096MB/20GB\n",
                "private                  --           --                                                2000m/4096MB/10GB\n",
            )
        );
    }

    #[test]
    fn format_preset_list_text_reports_empty() {
        assert_eq!(format_preset_list_text(&[]), "No presets found.\n");
    }

    #[test]
    fn format_preset_info_text_matches_go_layout() {
        let preset = test_preset(
            "preset_1",
            "Workspace",
            "workspace",
            "ghcr.io/codewiresh/workspace:latest",
        );

        assert_eq!(
            format_preset_info_text(&preset),
            concat!(
                "ID:        preset_1\n",
                "Name:      Workspace\n",
                "Slug:      workspace\n",
                "Language:  rust\n",
                "Image:     ghcr.io/codewiresh/workspace:latest\n",
                "Official:  false\n",
                "Build:     ready\n",
                "CPU:      2000m\n",
                "Memory:   4096MB\n",
                "Disk:     20GB\n",
            )
        );
    }

    #[test]
    fn find_preset_accepts_id_or_slug() {
        let presets = vec![test_preset(
            "preset_1",
            "Workspace",
            "workspace",
            "ghcr.io/codewiresh/workspace:latest",
        )];

        assert_eq!(find_preset(&presets, "preset_1").unwrap().name, "Workspace");
        assert_eq!(find_preset(&presets, "workspace").unwrap().id, "preset_1");
        assert!(find_preset(&presets, "missing").is_none());
    }

    #[test]
    fn expand_image_ref_matches_go_direct_preset_shorthand() {
        assert_eq!(
            expand_image_ref("workspace"),
            "ghcr.io/codewiresh/workspace:latest"
        );
        assert_eq!(
            expand_image_ref("workspace:v2"),
            "ghcr.io/codewiresh/workspace:v2"
        );
        assert_eq!(expand_image_ref("go"), "docker.io/library/go:latest");
        assert_eq!(expand_image_ref("node:20"), "docker.io/library/node:20");
        assert_eq!(
            expand_image_ref("ghcr.io/codewiresh/base:latest"),
            "ghcr.io/codewiresh/base:latest"
        );
        assert_eq!(expand_image_ref("noel/app:v1"), "docker.io/noel/app:v1");
    }

    #[test]
    fn parse_go_duration_seconds_accepts_common_ttls() {
        assert_eq!(parse_go_duration_seconds("30m").unwrap(), 1800);
        assert_eq!(parse_go_duration_seconds("1h30m").unwrap(), 5400);
        assert_eq!(parse_go_duration_seconds("1500ms").unwrap(), 1);
        assert_eq!(parse_go_duration_seconds("-1h").unwrap(), -3600);
        assert!(parse_go_duration_seconds("soon").is_err());
        assert!(parse_go_duration_seconds("1d").is_err());
    }
