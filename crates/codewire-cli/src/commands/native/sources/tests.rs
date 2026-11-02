use super::*;

const ENV_ID: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID: &str = "22222222-2222-4222-8222-222222222222";
const PROFILE_ID: &str = "33333333-3333-4333-8333-333333333333";
const REVISION: u64 = 9_007_199_254_740_993;

fn args(flags: &[&str]) -> EnvUpdateArgs {
    let mut argv = vec!["cw", "update", "--local", "dev"];
    argv.extend_from_slice(flags);
    let cli = Cli::try_parse_from(argv).unwrap();
    let (_, _, EnvCommand::Update(args)) = env_operation(cli) else {
        panic!("update");
    };
    args
}

fn profile() -> ResolvedProfile {
    ResolvedProfile {
        anthropic_form: String::new(),
        id: PROFILE_ID.into(),
        reference: "user/work".into(),
        revision: REVISION,
        profile_slots: BTreeSet::new(),
    }
}

fn authority() -> v1::PlatformSourceAuthority {
    v1::PlatformSourceAuthority {
        anthropic_form: String::new(),
        server_url: "https://platform.example.test".into(),
        organization_id: "org_test".into(),
        user_id: "user_test".into(),
        profile_slots: Vec::new(),
    }
}

fn spec() -> ProjectSpec {
    ProjectSpec {
        environment: BTreeMap::from([(
            "PUBLIC_SETTING".into(),
            "VALUE_MUST_NOT_ENTER_SOURCE_PREVIEW".into(),
        )]),
        install_command: "npm ci".into(),
        startup_script: "npm start".into(),
        credentials: Some(CredentialBinding {
            profile: format!("local:id:{PROFILE_ID}"),
        }),
        secrets: SecretBindings {
            project: format!("local:id:{PROJECT_ID}"),
            user: Some(StoragePlacement::Local),
            organization: false,
        },
        ..Default::default()
    }
}

fn environment(spec: &ProjectSpec) -> v1::Environment {
    let json = spec.canonical_json().unwrap();
    v1::Environment {
        id: ENV_ID.into(),
        name: "dev".into(),
        generation: 9_007_199_254_740_995,
        state: v1::EnvironmentState::Running as i32,
        project_spec_sha256: format!("{:x}", Sha256::digest(&json)),
        project_spec_json: json,
        access_profile_id: if spec.credentials.is_some() {
            PROFILE_ID.into()
        } else {
            String::new()
        },
        access_profile_revision: if spec.credentials.is_some() {
            REVISION
        } else {
            0
        },
        access_profile: if spec.credentials.is_some() {
            "user/work".into()
        } else {
            String::new()
        },
        platform_source_authority: uses_platform(spec).then(authority),
        ..Default::default()
    }
}

fn candidate(placement: StoragePlacement, name: &str) -> Candidate {
    Candidate {
        anthropic_credential: None,
        placement,
        id: PROJECT_ID.into(),
        name: name.into(),
        profile: None,
    }
}

#[test]
fn source_selectors_prove_unique_origin_and_never_pick_the_first_match() {
    let candidates = vec![
        candidate(StoragePlacement::Local, "Development"),
        candidate(StoragePlacement::Platform, "development"),
    ];
    assert!(
        select_candidate(
            candidates.clone(),
            StorageReference::project("development").unwrap()
        )
        .is_err()
    );
    assert_eq!(
        select_candidate(
            candidates.clone(),
            StorageReference::project("local:development").unwrap()
        )
        .unwrap()
        .placement,
        StoragePlacement::Local
    );
    assert_eq!(
        select_candidate(
            candidates,
            StorageReference::project(&format!("platform:id:{PROJECT_ID}")).unwrap()
        )
        .unwrap()
        .placement,
        StoragePlacement::Platform
    );
    assert!(
        select_candidate(
            vec![
                candidate(StoragePlacement::Local, "work"),
                candidate(StoragePlacement::Local, "WORK")
            ],
            StorageReference::project("local:work").unwrap()
        )
        .is_err()
    );
    assert!(select_candidate(vec![], StorageReference::project("work").unwrap()).is_err());
}

#[test]
fn only_a_missing_platform_configuration_proves_an_ineligible_backend() {
    let missing = config::ConfigError::NoPlatformServer {
        cause: Some(Box::new(config::ConfigError::ReadConfig {
            path: PathBuf::from("/synthetic/missing/config.json"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        })),
    };
    assert!(platform_is_proven_unconfigured(&missing));
    for error in [
        config::ConfigError::NoPlatformServer { cause: None },
        config::ConfigError::NoPlatformToken { cause: None },
        config::ConfigError::NoPlatformServer {
            cause: Some(Box::new(config::ConfigError::ReadConfig {
                path: PathBuf::from("/synthetic/unreadable/config.json"),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            })),
        },
    ] {
        assert!(!platform_is_proven_unconfigured(&error));
    }
}

#[test]
fn update_preserves_omitted_pins_and_clears_only_explicit_collections() {
    let current = spec();
    let replacement = patch_sources(&current, &args(&["--secrets=platform:other"]));
    assert_eq!(replacement.credentials, current.credentials);
    assert_eq!(replacement.environment, current.environment);
    assert_eq!(replacement.install_command, current.install_command);
    assert_eq!(replacement.secrets.user, current.secrets.user);
    let cleared = patch_sources(&current, &args(&["--clear-secrets"]));
    assert!(cleared.secrets.is_empty());
    assert_eq!(cleared.credentials, current.credentials);
    let cleared = patch_sources(&current, &args(&["--clear-secrets", "--clear-profile"]));
    assert!(cleared.secrets.is_empty());
    assert!(cleared.credentials.is_none());
    assert_eq!(cleared.environment, current.environment);
}

#[test]
fn canonical_update_binds_generation_digest_profile_and_clear_in_one_request() {
    let current = spec();
    let environment = environment(&current);
    let target = patch_sources(&current, &args(&["--clear-secrets"]));
    let request = update_request(&environment, &target, Some(&profile()), None).unwrap();
    assert_eq!(request.expected_environment_id, ENV_ID);
    assert_eq!(request.expected_generation, 9_007_199_254_740_995);
    assert_eq!(
        request.expected_project_spec_sha256,
        environment.project_spec_sha256
    );
    assert_eq!(request.expected_access_profile_id, PROFILE_ID);
    assert_eq!(request.expected_access_profile_revision, REVISION);
    assert_eq!(
        request.access_profile_revision, REVISION,
        "unrelated edits preserve the immutable pin"
    );
    assert!(request.allow_restart);
    assert!(!Uuid::parse_str(&request.request_id).unwrap().is_nil());
    assert_eq!(request.project_spec_json, target.canonical_json().unwrap());
    assert_eq!(
        request.project_spec_sha256,
        format!("{:x}", Sha256::digest(&request.project_spec_json))
    );
    let clear_all = patch_sources(&current, &args(&["--clear-secrets", "--clear-profile"]));
    let request = update_request(&environment, &clear_all, None, None).unwrap();
    assert!(request.access_profile_id.is_empty());
    assert_eq!(request.access_profile_revision, 0);
    assert!(request.access_profile_reference.is_empty());
}

#[test]
fn source_update_rejects_changed_non_sources_or_invalid_current_metadata() {
    let current = spec();
    let original = environment(&current);
    let mut target = current.clone();
    target.startup_script = "unapproved command".into();
    assert!(update_request(&original, &target, Some(&profile()), None).is_err());
    for mutation in 0..7 {
        let mut environment = original.clone();
        match mutation {
            0 => environment.project_spec_json.clear(),
            1 => environment.project_spec_sha256 = "f".repeat(64),
            2 => environment.project_spec_json.push(b' '),
            3 => environment.access_profile_id = PROJECT_ID.into(),
            4 => environment.access_profile_revision = 0,
            5 => environment.platform_source_authority = Some(authority()),
            6 => {
                environment.project_spec_json =
                    vec![b' '; codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1]
            }
            _ => unreachable!(),
        }
        assert!(
            project_from_environment(&environment).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn source_update_never_implicitly_starts_failed_or_transitional_environments() {
    let current = spec();
    let mut environment = environment(&current);
    assert!(
        !update_request(&environment, &current, Some(&profile()), None)
            .unwrap()
            .allow_restart,
        "unchanged running source selection has no restart"
    );
    let target = patch_sources(&current, &args(&["--clear-secrets"]));
    environment.state = v1::EnvironmentState::Stopped as i32;
    assert!(
        !update_request(&environment, &target, Some(&profile()), None)
            .unwrap()
            .allow_restart
    );
    for state in [
        v1::EnvironmentState::Error as i32,
        v1::EnvironmentState::Starting as i32,
        v1::EnvironmentState::Orphaned as i32,
        999,
    ] {
        environment.state = state;
        assert!(update_request(&environment, &target, Some(&profile()), None).is_err());
    }
}

#[test]
fn platform_origin_cannot_retarget_retained_sources_through_current_context() {
    let mut current = spec();
    current.secrets.project = format!("platform:id:{PROJECT_ID}");
    let original = authority();
    let mut other = authority();
    other.organization_id = "other_org".into();
    let flags = args(&["--profile=platform:work"]);
    assert!(retained_platform_source(&current, &flags));
    assert!(
        select_platform_authority(Some(&original), Some(other.clone()), true, &current, None)
            .is_err()
    );
    assert_eq!(
        select_platform_authority(Some(&original), None, true, &current, None).unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        select_platform_authority(Some(&original), Some(other.clone()), false, &current, None,)
            .unwrap(),
        Some(other)
    );
    assert_eq!(
        select_platform_authority(Some(&original), None, false, &ProjectSpec::default(), None,)
            .unwrap(),
        None
    );
    assert!(select_platform_authority(None, None, true, &current, None).is_err());

    current.credentials = Some(CredentialBinding {
        profile: format!("platform:id:{PROFILE_ID}"),
    });
    let selected_profile = ResolvedProfile {
        profile_slots: BTreeSet::from(["codex".into(), "openai".into()]),
        ..profile()
    };
    let mut prior = original.clone();
    prior.profile_slots = vec!["anthropic".into()];
    let rebound = select_platform_authority(
        Some(&prior),
        Some(original),
        true,
        &current,
        Some(&selected_profile),
    )
    .unwrap()
    .unwrap();
    assert_eq!(rebound.profile_slots, ["codex", "openai"]);
}

#[test]
fn unrelated_platform_source_edit_retains_pinned_profile_slots_without_refresh() {
    let mut target = spec();
    target.credentials = Some(CredentialBinding {
        profile: format!("platform:id:{PROFILE_ID}"),
    });
    let pinned = ResolvedProfile {
        profile_slots: BTreeSet::from(["codex".into(), "ssh".into()]),
        ..profile()
    };
    let mut current = authority();
    current.profile_slots = vec!["codex".into(), "ssh".into()];
    let requested = authority();

    assert_eq!(
        platform_profile_slots(&target, None, false).unwrap(),
        Vec::<String>::new(),
        "an unrelated app-source resolution must not require or refresh the profile"
    );
    let retained = select_platform_authority(
        Some(&current),
        Some(requested),
        true,
        &target,
        Some(&pinned),
    )
    .unwrap()
    .unwrap();
    assert_eq!(retained.profile_slots, ["codex", "ssh"]);
    assert!(platform_profile_slots(&target, None, true).is_err());
}

#[test]
fn a_platform_profile_pins_its_anthropic_form_with_its_slots() {
    let mut target = spec();
    target.credentials = Some(CredentialBinding {
        profile: format!("platform:id:{PROFILE_ID}"),
    });
    target.secrets.project = String::new();
    target.secrets.user = None;
    let pinned = ResolvedProfile {
        profile_slots: BTreeSet::from(["anthropic".into(), "codex".into()]),
        anthropic_form: "sign_in".into(),
        ..profile()
    };
    let selected =
        select_platform_authority(None, Some(authority()), false, &target, Some(&pinned))
            .unwrap()
            .unwrap();
    assert_eq!(selected.profile_slots, ["anthropic", "codex"]);
    assert_eq!(selected.anthropic_form, "sign_in");
    validate_exact_sources(&target, Some(&pinned), Some(&selected)).unwrap();
    // The pinned record and the exact profile metadata must agree on the form.
    let mut other = selected.clone();
    other.anthropic_form = "subscription_token".into();
    assert!(validate_exact_sources(&target, Some(&pinned), Some(&other)).is_err());
    // A retained profile keeps its form from the environment's record.
    let environment = v1::Environment {
        access_profile_id: PROFILE_ID.into(),
        access_profile: "user/work".into(),
        access_profile_revision: REVISION,
        platform_source_authority: Some(selected.clone()),
        ..Default::default()
    };
    assert_eq!(
        profile_from_environment(&environment)
            .unwrap()
            .anthropic_form,
        "sign_in"
    );
    // A local profile never carries a platform form.
    let local =
        select_platform_authority(None, Some(authority()), false, &spec(), Some(&pinned)).unwrap();
    assert!(local.is_none_or(|authority| authority.anthropic_form.is_empty()));
}

#[test]
fn native_create_ack_requires_exact_source_metadata() {
    let mut selected = spec();
    selected.secrets.project = format!("platform:id:{PROJECT_ID}");
    selected.credentials = Some(CredentialBinding {
        profile: format!("platform:id:{PROFILE_ID}"),
    });
    let acknowledged = environment(&selected);
    let request = v1::CreateEnvironmentRequest {
        name: acknowledged.name.clone(),
        project_spec_json: acknowledged.project_spec_json.clone(),
        project_spec_sha256: acknowledged.project_spec_sha256.clone(),
        access_profile_id: acknowledged.access_profile_id.clone(),
        access_profile_revision: acknowledged.access_profile_revision,
        access_profile_reference: acknowledged.access_profile.clone(),
        platform_source_authority: acknowledged.platform_source_authority.clone(),
        ..Default::default()
    };

    validate_created_environment(&acknowledged, &request).unwrap();
    for mutation in 0..10 {
        let mut wrong = acknowledged.clone();
        match mutation {
            0 => wrong.id = "00000000-0000-0000-0000-000000000000".into(),
            1 => wrong.name = "other".into(),
            2 => wrong.project_spec_json = b"{}".to_vec(),
            3 => wrong.project_spec_sha256 = "0".repeat(64),
            4 => wrong.access_profile_id = "44444444-4444-4444-8444-444444444444".into(),
            5 => wrong.access_profile_revision += 1,
            6 => wrong.access_profile = "user/other".into(),
            7 => wrong.platform_source_authority = None,
            8 => {
                wrong
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .organization_id = "other".into()
            }
            9 => {
                wrong
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .profile_slots = vec!["ssh".into()]
            }
            _ => unreachable!(),
        }
        assert!(
            validate_created_environment(&wrong, &request).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn platform_update_cas_carries_exact_old_and_new_origin_descriptors() {
    let mut current = spec();
    current.secrets.project = format!("platform:id:{PROJECT_ID}");
    let environment = environment(&current);
    let request =
        update_request(&environment, &current, Some(&profile()), Some(&authority())).unwrap();
    assert_eq!(
        request.expected_platform_source_authority,
        Some(authority())
    );
    assert_eq!(request.platform_source_authority, Some(authority()));
    assert!(!request.allow_restart);
}

#[test]
fn source_inspection_is_value_free_and_reports_missing_metadata_honestly() {
    let mut selected = spec();
    selected.secrets.project = format!("platform:id:{PROJECT_ID}");
    let environment = environment(&selected);
    let view = source_view(&environment).unwrap().unwrap();
    let json = serde_json::to_string(&view).unwrap();
    let text = format_source_view(Some(&view));
    for output in [&json, &text] {
        assert!(output.contains(PROJECT_ID));
        assert!(output.contains(PROFILE_ID));
        assert!(output.contains(&REVISION.to_string()));
        assert!(output.contains("platform.example.test"));
        assert!(output.contains("org_test"));
        assert!(output.contains("user_test"));
        assert!(!output.contains("VALUE_MUST_NOT_ENTER_SOURCE_PREVIEW"));
        assert!(!output.contains("npm ci"));
        assert!(!output.contains("npm start"));
    }
    assert!(source_view(&v1::Environment::default()).unwrap().is_none());
    assert!(format_source_view(None).contains("metadata unavailable"));
}

#[test]
fn source_inspection_prints_plain_values() {
    let empty = SourceView {
        secrets: SecretBindings::default(),
        credentials: None,
        platform: None,
    };
    assert_eq!(
        format_source_view(Some(&empty)),
        "Secrets:     none\nCredentials: none\n"
    );
    let selected = SourceView {
        secrets: SecretBindings {
            project: "platform:id:app".to_owned(),
            organization: true,
            user: Some(codewire_project::StoragePlacement::Local),
        },
        credentials: Some(CredentialView {
            profile: "work".to_owned(),
            reference: "local:work".to_owned(),
            revision: 3,
        }),
        platform: None,
    };
    assert_eq!(
        format_source_view(Some(&selected)),
        "Secrets:     platform:id:app\nUser secrets: local\nOrg secrets: platform organization\n\
         Credentials: work (local:work, revision 3)\n"
    );
}

#[test]
fn confirmation_is_bounded_default_no_and_eof_safe() {
    for input in ["", "\n", "no\n", "yesterday\n"] {
        assert!(!read_confirmation(input.as_bytes()).unwrap());
    }
    assert!(read_confirmation("yes\n".as_bytes()).unwrap());
    assert!(!read_confirmation(format!("yes{}", " ".repeat(100)).as_bytes()).unwrap());
}

#[test]
fn create_and_update_accept_only_the_reviewed_source_flag_names() {
    let cli = Cli::try_parse_from([
        "cw",
        "create",
        "--local",
        "--name=dev",
        "--secrets=local:development",
        "--profile=local:work",
        "--user-secrets=platform",
        "--org-secrets",
    ])
    .unwrap();
    let (_, _, EnvCommand::Create(create)) = env_operation(cli) else {
        panic!("create");
    };
    let mut selected = ProjectSpec::default();
    apply_create_source_flags(&mut selected, &create).unwrap();
    assert_eq!(selected.secrets.project, "local:development");
    assert_eq!(selected.secrets.user, Some(StoragePlacement::Platform));
    assert!(selected.secrets.organization);
    assert_eq!(selected.credentials.unwrap().profile, "local:work");
    for retired in [
        "--secrets-project=local:dev",
        "--secrets-user=local",
        "--secrets-organization",
        "--access-profile=work",
    ] {
        assert!(Cli::try_parse_from(["cw", "create", retired]).is_err());
        assert!(Cli::try_parse_from(["cw", "update", "dev", retired]).is_err());
    }
    assert!(validate_update_args(&args(&[])).is_err());
    assert!(validate_update_args(&args(&["--secrets="])).is_err());
}

/// A personal platform profile always selects GitHub, connected or not, so the
/// VM reserves GitHub's names; whether the guest is configured for GitHub is
/// decided at each start from the account's connection then. Creating the VM
/// therefore reads no credential metadata at all.
#[tokio::test]
async fn platform_metadata_resolution_is_authenticated_exact_and_material_free() {
    resolve_platform_metadata(&["codex", "github", "openai"]).await;
}

async fn resolve_platform_metadata(slots: &[&str]) {
    use buffa::Message as _;
    use codewire_client as rpc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let paths = ResolvePaths {
        platform_config_dir: directory.path().join("platform"),
        mesh_data_dir: directory.path().join("mesh"),
    };
    let env = config::MapEnv::new([
        (config::CODEWIRE_SERVER_URL_ENV, server.uri()),
        (
            config::CODEWIRE_API_KEY_ENV,
            "synthetic-oauth-source-token".to_owned(),
        ),
    ]);
    Mock::given(method("GET"))
        .and(path("/api/oauth/userinfo"))
        .and(header(
            "authorization",
            "Bearer synthetic-oauth-source-token",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"sub":"user_test"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    for (rpc_path, body) in [
        (
            "/codewire.v1.OrganizationService/ListOrganizations",
            rpc::ListOrganizationsResponse {
                organizations: vec![rpc::OrganizationMembership {
                    organization: Some(rpc::Organization {
                        id: "org_test".into(),
                        name: "Test".into(),
                        slug: "test".into(),
                        ..Default::default()
                    })
                    .into(),
                    role: rpc::OrgRole::Owner.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "/codewire.v1.SecretService/ListSecretProjects",
            rpc::ListSecretProjectsResponse {
                secret_projects: vec![rpc::SecretProject {
                    id: PROJECT_ID.into(),
                    org_id: "org_test".into(),
                    name: "development".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        (
            "/codewire.v1.AccessProfileService/ListAccessProfiles",
            rpc::ListAccessProfilesResponse {
                access_profiles: vec![rpc::AccessProfile {
                    id: PROFILE_ID.into(),
                    name: "work".into(),
                    revision: REVISION,
                    entries: vec![
                        rpc::AccessProfileEntry {
                            capability_slot: "openai".into(),
                            credential_id: "openai-credential".into(),
                            ..Default::default()
                        },
                        rpc::AccessProfileEntry {
                            capability_slot: "codex".into(),
                            credential_id: "codex-credential".into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(rpc_path))
            .and(header(
                "authorization",
                "Bearer synthetic-oauth-source-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(body),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut selected = ProjectSpec {
        secrets: SecretBindings {
            project: "platform:development".into(),
            user: Some(StoragePlacement::Platform),
            organization: true,
        },
        credentials: Some(CredentialBinding {
            profile: "platform:user/work".into(),
        }),
        ..Default::default()
    };
    let resolved = resolve_requested_sources(
        &Globals {
            server: None,
            member: None,
            placement: None,
            org: None,
        },
        &paths,
        &env,
        None,
        &mut selected,
        SourceChanges::all(),
    )
    .await
    .unwrap();
    assert_eq!(
        selected.secrets.project,
        format!("platform:id:{PROJECT_ID}")
    );
    assert_eq!(
        selected.credentials.as_ref().unwrap().profile,
        format!("platform:id:{PROFILE_ID}")
    );
    assert_eq!(
        resolved.profile,
        Some(ResolvedProfile {
            profile_slots: slots.iter().map(|slot| (*slot).to_owned()).collect(),
            ..profile()
        })
    );
    let bound = resolved.platform.unwrap();
    assert_eq!(bound.server_url, server.uri());
    assert_eq!(bound.organization_id, "org_test");
    assert_eq!(bound.user_id, "user_test");
    assert_eq!(bound.profile_slots, slots);
    // Identity, membership, and source metadata only: no credential listing.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        4,
        "only identity, membership, and source metadata reads are allowed"
    );
}

#[tokio::test]
async fn platform_api_keys_fail_before_identity_or_source_requests_without_ambient_auth() {
    let directory = tempfile::tempdir().unwrap();
    let server = wiremock::MockServer::start().await;
    let paths = ResolvePaths {
        platform_config_dir: directory.path().join("platform"),
        mesh_data_dir: directory.path().join("mesh"),
    };
    let env = config::MapEnv::new([
        (config::CODEWIRE_SERVER_URL_ENV, server.uri()),
        (
            config::CODEWIRE_API_KEY_ENV,
            "cw_synthetic_cannot_impersonate_user".to_owned(),
        ),
    ]);
    let error = platform_metadata(
        &Globals {
            server: None,
            member: None,
            placement: None,
            org: None,
        },
        &paths,
        &env,
        true,
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("cw login"));
    assert!(!error.contains("cw_synthetic"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn local_only_empty_resolution_never_reads_platform_configuration_or_authentication() {
    struct NoEnvReads;
    impl config::Env for NoEnvReads {
        fn var(&self, _: &str) -> Option<String> {
            panic!("local-only source resolution must not read platform configuration");
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let paths = ResolvePaths {
        platform_config_dir: directory.path().join("platform"),
        mesh_data_dir: directory.path().join("mesh"),
    };
    let mut selected = ProjectSpec {
        secrets: SecretBindings {
            user: Some(StoragePlacement::Local),
            ..Default::default()
        },
        ..Default::default()
    };
    let resolved = resolve_requested_sources(
        &Globals {
            server: None,
            member: None,
            placement: None,
            org: None,
        },
        &paths,
        &NoEnvReads,
        None,
        &mut selected,
        SourceChanges::all(),
    )
    .await
    .unwrap();
    assert!(resolved.profile.is_none());
    assert!(resolved.platform.is_none());
}
