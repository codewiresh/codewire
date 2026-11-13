#[test]
fn parse_env_overrides_requires_key_value_shape() {
    let parsed = parse_env_overrides(&["FOO=bar".to_string(), "EMPTY=".to_string()]).unwrap();
    assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(parsed.get("EMPTY").map(String::as_str), Some(""));

    let canary = "synthetic-bearer-do-not-render";
    let err = parse_env_overrides(&[canary.to_string()]).unwrap_err();
    let rendered = err.to_string();
    assert_eq!(rendered, "environment override must be KEY=VALUE");
    assert!(!rendered.contains(canary));
}

fn test_billing_overview() -> BillingOverview {
    BillingOverview {
        billing_enabled: true,
        has_payment_method: true,
        credit_balance_nano_eur: 42_500_000_000,
        month_usage_nano_eur: 3_100_000_000,
        rates: crate::console_client::CreditRates {
            cpu_per_vcpu_hour: 43_800_000,
            memory_per_gib_hour: 14_100_000,
            disk_per_gib_hour: 87_000,
        },
        auto_top_up_enabled: true,
        auto_top_up_cents: 2000,
        current_month_usage: crate::console_client::UsageSummary {
            cpu_hours: 12.5,
            memory_gb_hours: 32.0,
            storage_gb_hours: 90.25,
        },
        ..BillingOverview::default()
    }
}

#[test]
fn euros_show_cents_or_the_fraction_a_rate_needs() {
    assert_eq!(format_euros(42_500_000_000), "€42.50");
    assert_eq!(format_euros(-1_000_000), "-€0.001");
    assert_eq!(format_euros(87_000), "€0.000087");
    assert_eq!(format_euros(0), "€0.00");
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
fn format_cost_text_shows_credit_rates_and_top_up() {
    let reports = vec![
        OrgCostReport {
            org: OrgWithRole {
                id: "org_123".to_string(),
                slug: "codewire".to_string(),
                ..OrgWithRole::default()
            },
            billing: Some(test_billing_overview()),
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
            "  Balance      This month   CPU hrs Mem GB·hrs Storage GB·hrs\n",
            "  €42.50       €3.10        12.5    32.0       90.2\n",
            "\n",
            "  Rates: €0.0438 per vCPU-hour, €0.0141 per GiB-hour of memory, €0.000087 per GiB-hour of disk\n",
            "  Automatic top-up: €20.00\n",
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
fn login_succeeds_without_an_organization_and_names_where_to_go_next() {
    let org = test_org("org_1", "Noel Labs", "noel-labs", "owner");
    assert_eq!(
        super::login::login_outcome(&LoginOrgResolution::Selected(org)).unwrap(),
        "Default org: Noel Labs (noel-labs)."
    );

    let notice = super::login::login_outcome(&LoginOrgResolution::NoOrganizations).unwrap();
    assert!(notice.contains("not in an organization yet"));
    assert!(notice.contains("'cw org invitations'"));
    assert!(notice.contains("'cw org create <name>'"));

    let error = super::login::login_outcome(&LoginOrgResolution::SelectionRequired)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no default organization is selected"));
}

#[test]
fn doctor_warns_for_stale_org_and_is_ok_only_for_live_org() {
    let orgs = vec![test_org("org_1", "Noel Labs", "noel-labs", "owner")];
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
fn doctor_reports_the_build_revision_and_target() {
    let record = |revision: Option<&str>| codewire_cw_release::build_record::BuildRecord {
        package_version: "0.3.386".into(),
        rustc: "rustc 1.93.0".into(),
        source_revision: revision.map(Into::into),
        source_tree_sha256: None,
        target: "x86_64-unknown-linux-gnu".into(),
    };
    assert_eq!(
        doctor_build_check(Ok(record(Some("086c8b8ca32aaaff26ce317d3a2a7cb612a9ba95")))),
        doctor_check(
            "cw",
            DoctorStatus::Ok,
            "0.3.386 086c8b8ca32a x86_64-unknown-linux-gnu"
        )
    );
    assert_eq!(
        doctor_build_check(Ok(record(None))).status,
        DoctorStatus::Warn
    );
    assert_eq!(
        doctor_build_check(Err(anyhow::anyhow!("no record"))).detail,
        "build record unreadable: no record"
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

fn test_preset(id: &str, name: &str, slug: &str, image: &str) -> Preset {
    Preset {
        id: id.to_string(),
        name: name.to_string(),
        slug: Some(slug.to_string()),
        language: Some("rust".to_string()),
        build_status: "ready".to_string(),
        project_spec: codewire_project::ProjectSpec {
            image: image.to_string(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2000),
                memory_mib: Some(4096),
                disk_gib: Some(20),
            },
            ..Default::default()
        },
        created_at: "2026-07-04T00:00:00Z".to_string(),
        ..Preset::default()
    }
}

#[test]
fn format_preset_list_text_reads_canonical_project_resources() {
    let workspace_image = CANONICAL_WORKSPACE_IMAGE;
    let mut private = test_preset("preset_2", "Private", "private", "unused");
    private.language = None;
    private.project_spec.image.clear();
    private.project_spec.resources.disk_gib = Some(10);
    let presets = vec![
        Preset {
            official: true,
            ..test_preset("preset_1", "Workspace", "workspace", workspace_image)
        },
        private,
    ];

    let image_width = workspace_image.len();
    let expected = format!(
        "{:<24} {:<12} {:<image_width$} {:<8} CPU/MEM/DISK\n\
                 {:<24} {:<12} {:<image_width$} {:<8} 2000m/4096MB/20GB\n\
                 {:<24} {:<12} {:<image_width$} {:<8} 2000m/4096MB/10GB\n",
        "NAME",
        "LANGUAGE",
        "IMAGE",
        "OFFICIAL",
        "workspace",
        "rust",
        workspace_image,
        "yes",
        "private",
        "--",
        "--",
        "",
    );
    assert_eq!(format_preset_list_text(&presets), expected);
}

#[test]
fn format_preset_list_text_reports_empty() {
    assert_eq!(format_preset_list_text(&[]), "No presets found.\n");
}

#[test]
fn format_preset_info_text_reads_canonical_project_resources() {
    let preset = test_preset(
        "preset_1",
        "Workspace",
        "workspace",
        CANONICAL_WORKSPACE_IMAGE,
    );

    assert_eq!(
        format_preset_info_text(&preset),
        format!(
            concat!(
                "ID:        preset_1\n",
                "Name:      Workspace\n",
                "Slug:      workspace\n",
                "Language:  rust\n",
                "Image:     {}\n",
                "Official:  false\n",
                "Build:     ready\n",
                "CPU:      2000m\n",
                "Memory:   4096MB\n",
                "Disk:     20GB\n",
            ),
            CANONICAL_WORKSPACE_IMAGE
        )
    );
}

#[test]
fn find_preset_uses_explicit_id_and_server_slug_precedence() {
    let mut official = test_preset("collision", "Official", "workspace", "official:1");
    official.official = true;
    let mut organization = test_preset("organization-id", "Organization", "workspace", "org:1");
    organization.org_id = Some("org-test".to_owned());
    let mut id_slug_collision = test_preset("another-id", "Slug wins", "collision", "collision:1");
    id_slug_collision.org_id = Some("org-test".to_owned());
    let presets = vec![official, organization, id_slug_collision];

    assert_eq!(
        find_preset(&presets, "org-test", "workspace")
            .unwrap()
            .unwrap()
            .name,
        "Organization"
    );
    assert_eq!(
        find_preset(&presets, "org-test", "slug:workspace")
            .unwrap()
            .unwrap()
            .name,
        "Organization"
    );
    assert_eq!(
        find_preset(&presets, "org-test", "collision")
            .unwrap()
            .unwrap()
            .name,
        "Slug wins"
    );
    assert_eq!(
        find_preset(&presets, "org-test", "id:collision")
            .unwrap()
            .unwrap()
            .name,
        "Official"
    );
    assert!(
        find_preset(&presets, "org-test", "id:missing")
            .unwrap()
            .is_none()
    );
    assert!(find_preset(&presets, "org-test", "kind:value").is_err());
}

#[test]
fn find_preset_rejects_same_precedence_slug_ambiguity() {
    let mut first = test_preset("first", "First", "duplicate", "first:1");
    first.official = true;
    let mut second = test_preset("second", "Second", "duplicate", "second:1");
    second.official = true;

    assert!(find_preset(&[first, second], "org-test", "duplicate").is_err());
}

#[test]
fn expand_image_ref_matches_go_direct_preset_shorthand() {
    assert_eq!(
        expand_image_ref("workspace"),
        CANONICAL_WORKSPACE_IMAGE
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
