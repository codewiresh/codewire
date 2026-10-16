use super::*;

fn environment(profile: bool) -> EnvironmentRecord {
    let mut environment = crate::supervisor::tests::project_environment();
    let mut project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.secrets.organization = true;
    project.secrets.user = Some(StoragePlacement::Platform);
    project.secrets.project = format!("platform:id:{}", Uuid::new_v4());
    project
        .environment
        .insert("LOG_LEVEL".into(), "debug".into());
    let slots = if profile {
        let id = AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("platform:id:{id}"),
        });
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(EnvironmentAccessBinding {
            environment_id: access_environment_id(environment.id).unwrap(),
            profile_id: id,
            profile_revision: 7,
        });
        ["codex", "github", "openai"].map(str::to_owned).into()
    } else {
        BTreeSet::new()
    };
    environment.platform_source_authority = Some(PlatformSourceAuthority {
        anthropic_form: Default::default(),
        server_url: "https://platform.invalid".into(),
        organization_id: "synthetic-org".into(),
        user_id: "synthetic-owner".into(),
        profile_slots: slots,
    });
    set_project(&mut environment, &project);
    environment
}

fn set_project(environment: &mut EnvironmentRecord, project: &ProjectSpec) {
    let json = project.canonical_json().unwrap();
    environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
    environment.project_spec_json = Some(json);
}

#[test]
fn platform_binding_uses_exact_persisted_identity_and_original_native_intent() {
    let environment = environment(true);
    let binding = broker_binding(&environment, Path::new("/synthetic/explicit-config"))
        .unwrap()
        .unwrap();
    let project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    let pin = environment.access_binding.as_ref().unwrap();
    assert_eq!(
        binding.config_directory,
        Path::new("/synthetic/explicit-config")
    );
    assert_eq!(binding.server_url, "https://platform.invalid");
    assert_eq!(binding.selection.creator, "synthetic-owner");
    assert_eq!(binding.selection.organization, "synthetic-org");
    assert!(binding.selection.organization_selected);
    assert!(binding.selection.user_selected);
    assert_eq!(
        binding.selection.profile,
        Some((pin.profile_id.to_string(), 7))
    );
    assert_eq!(
        binding.selection.project_id.as_deref(),
        project.secrets.project.strip_prefix("platform:id:")
    );
    assert_eq!(
        binding.selection.ordinary_keys,
        BTreeSet::from(["LOG_LEVEL".into()])
    );
    assert_eq!(
        binding.selection_sha256,
        Sha256::digest(environment.project_spec_json.as_ref().unwrap()).as_slice()
    );
    for key in ["CODEX_HOME", "OPENAI_BASE_URL", "GH_TOKEN"] {
        assert!(binding.selection.reserved_keys.contains(key));
    }
    assert!(!format!("{binding:?}").contains("debug"));
    let clients = managed_clients(&environment).unwrap().unwrap();
    assert!(clients.contains(codewire_access::ManagedCredentialClient::Codex));
    assert!(clients.contains(codewire_access::ManagedCredentialClient::OpenAi));
    assert!(!clients.contains(codewire_access::ManagedCredentialClient::Anthropic));
}

#[test]
fn application_only_and_empty_profile_still_have_live_platform_delivery() {
    let mut application_only = environment(false);
    let binding = broker_binding(&application_only, Path::new("/synthetic/config"))
        .unwrap()
        .unwrap();
    assert!(binding.selection.profile.is_none());
    assert_eq!(
        managed_clients(&application_only).unwrap(),
        Some(Default::default())
    );
    let mut project: ProjectSpec =
        serde_json::from_slice(application_only.project_spec_json.as_deref().unwrap()).unwrap();
    project.secrets = Default::default();
    application_only.platform_source_authority = None;
    set_project(&mut application_only, &project);
    assert!(
        broker_binding(&application_only, Path::new("/synthetic/config"))
            .unwrap()
            .is_none()
    );
    assert!(managed_clients(&application_only).unwrap().is_none());

    let mut empty_profile = environment(true);
    empty_profile
        .platform_source_authority
        .as_mut()
        .unwrap()
        .profile_slots
        .clear();
    let mut project: ProjectSpec =
        serde_json::from_slice(empty_profile.project_spec_json.as_deref().unwrap()).unwrap();
    project.secrets = Default::default();
    set_project(&mut empty_profile, &project);
    assert!(
        broker_binding(&empty_profile, Path::new("/synthetic/config"))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        managed_clients(&empty_profile).unwrap(),
        Some(Default::default())
    );
}

fn orthogonal_environment(
    profile: Option<StoragePlacement>,
    secret_project: Option<StoragePlacement>,
    user: Option<StoragePlacement>,
    organization: bool,
) -> EnvironmentRecord {
    let mut environment = environment(profile == Some(StoragePlacement::Platform));
    let mut project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.credentials = None;
    environment.access_binding = None;
    environment.access_profile = None;
    let qualifier = |placement| match placement {
        StoragePlacement::Local => "local",
        StoragePlacement::Platform => "platform",
    };
    if let Some(placement) = profile {
        let id = AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("{}:id:{id}", qualifier(placement)),
        });
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(EnvironmentAccessBinding {
            environment_id: access_environment_id(environment.id).unwrap(),
            profile_id: id,
            profile_revision: 7,
        });
    }
    project.secrets = Default::default();
    project.secrets.organization = organization;
    project.secrets.user = user;
    if let Some(placement) = secret_project {
        project.secrets.project = format!("{}:id:{}", qualifier(placement), Uuid::new_v4());
    }
    if !requires_platform_authority(&project).unwrap() {
        environment.platform_source_authority = None;
    }
    set_project(&mut environment, &project);
    environment
}

#[test]
fn all_profile_and_application_origins_are_orthogonal_and_keep_exact_authority_ids() {
    let placements = [
        None,
        Some(StoragePlacement::Local),
        Some(StoragePlacement::Platform),
    ];
    let mut cases = 0;
    for profile in placements {
        for secret_project in placements {
            for user in placements {
                for organization in [false, true] {
                    let environment =
                        orthogonal_environment(profile, secret_project, user, organization);
                    let project: ProjectSpec =
                        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap())
                            .unwrap();
                    let uses_platform = organization
                        || [profile, secret_project, user]
                            .contains(&Some(StoragePlacement::Platform));
                    assert_eq!(
                        requires_platform_authority(&project).unwrap(),
                        uses_platform
                    );
                    let platform =
                        broker_binding(&environment, Path::new("/synthetic/config")).unwrap();
                    let local = local_launch_projection(&environment).unwrap();
                    assert_eq!(platform.is_some(), uses_platform);
                    let local_apps = secret_project == Some(StoragePlacement::Local)
                        || user == Some(StoragePlacement::Local);
                    assert_eq!(
                        local.is_some(),
                        local_apps || (!uses_platform && profile == Some(StoragePlacement::Local))
                    );
                    if let Some(platform) = &platform {
                        assert_eq!(
                            platform.selection.profile.is_some(),
                            profile == Some(StoragePlacement::Platform)
                        );
                        assert_eq!(
                            platform.selection.project_id.is_some(),
                            secret_project == Some(StoragePlacement::Platform)
                        );
                        assert_eq!(
                            platform.selection.user_selected,
                            user == Some(StoragePlacement::Platform)
                        );
                        assert_eq!(platform.selection.organization_selected, organization);
                        if let Some(id) = &platform.selection.project_id {
                            assert_eq!(project.secrets.project, format!("platform:id:{id}"));
                        }
                        if let Some((id, revision)) = &platform.selection.profile {
                            assert_eq!(
                                project.credentials.as_ref().unwrap().profile,
                                format!("platform:id:{id}")
                            );
                            assert_eq!(*revision, 7);
                        }
                    }
                    if let Some(local) = &local {
                        assert_eq!(
                            local.selection.project_id.is_some(),
                            secret_project == Some(StoragePlacement::Local)
                        );
                        assert_eq!(local.selection.user, user == Some(StoragePlacement::Local));
                        if let Some(id) = local.selection.project_id {
                            assert_eq!(project.secrets.project, format!("local:id:{id}"));
                        }
                        if let Some(platform) = &platform {
                            assert_eq!(local.selection_sha256, platform.selection_sha256);
                            assert_eq!(
                                local.selection.overridden_keys,
                                platform.selection.ordinary_keys
                            );
                            assert_eq!(
                                local.selection.reserved_keys,
                                platform.selection.reserved_keys
                            );
                        }
                    }
                    assert_eq!(
                        managed_clients(&environment).unwrap().is_some(),
                        uses_platform && profile != Some(StoragePlacement::Local)
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 54);
}

#[test]
fn local_profile_with_platform_applications_requires_pinned_platform_metadata_but_not_platform_slots()
 {
    let original = orthogonal_environment(
        Some(StoragePlacement::Local),
        Some(StoragePlacement::Platform),
        None,
        false,
    );
    assert!(managed_clients(&original).unwrap().is_none());
    assert!(
        broker_binding(&original, Path::new("/synthetic/config"))
            .unwrap()
            .unwrap()
            .selection
            .profile
            .is_none()
    );
    for field in 0..5 {
        let mut invalid = original.clone();
        match field {
            0 => invalid.platform_source_authority = None,
            1 => {
                invalid
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .profile_slots
                    .insert("codex".into());
            }
            2 => invalid.access_binding.as_mut().unwrap().profile_revision = 0,
            3 => {
                invalid.access_binding.as_mut().unwrap().environment_id =
                    access_environment_id(Uuid::new_v4()).unwrap()
            }
            _ => {
                invalid
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .server_url = "https://platform.invalid/path".into()
            }
        }
        assert!(managed_clients(&invalid).is_err(), "field {field}");
        assert!(
            broker_binding(&invalid, Path::new("/synthetic/config")).is_err(),
            "field {field}"
        );
        assert!(local_launch_projection(&invalid).is_err(), "field {field}");
    }
}

#[test]
fn platform_authority_classification_rejects_unresolved_and_noncanonical_references() {
    for reference in [
        "work",
        "local:work",
        "platform:work",
        "platform:id:00000000-0000-0000-0000-000000000000",
        "local:id:NOT-A-UUID",
    ] {
        let mut project = ProjectSpec::default();
        project.secrets.project = reference.into();
        assert!(requires_platform_authority(&project).is_err());
        project.secrets.project.clear();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: reference.into(),
        });
        assert!(requires_platform_authority(&project).is_err());
    }
}

#[test]
fn stale_partial_or_forged_metadata_cannot_select_platform_delivery() {
    let original = environment(true);
    for field in 0..9 {
        let mut invalid = original.clone();
        match field {
            0 => invalid.project_spec_sha256 = Some("a".repeat(64)),
            1 => invalid.platform_source_authority = None,
            2 => invalid.access_profile = None,
            3 => invalid.access_binding = None,
            4 => invalid.access_binding.as_mut().unwrap().profile_revision = 0,
            5 => {
                invalid.access_binding.as_mut().unwrap().environment_id =
                    access_environment_id(Uuid::new_v4()).unwrap()
            }
            6 => {
                invalid.access_binding.as_mut().unwrap().profile_id =
                    AccessProfileId::parse(Uuid::new_v4().to_string()).unwrap()
            }
            7 => {
                invalid
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .profile_slots
                    .insert("unregistered".into());
            }
            _ => {
                invalid
                    .platform_source_authority
                    .as_mut()
                    .unwrap()
                    .server_url = "https://platform.invalid/api".into()
            }
        }
        assert!(
            broker_binding(&invalid, Path::new("/synthetic/config")).is_err(),
            "field {field}"
        );
        assert!(managed_clients(&invalid).is_err(), "field {field}");
    }
    assert!(broker_binding(&original, Path::new("relative/config")).is_err());
}

#[test]
fn all_platform_reserved_names_fail_locally_without_reading_application_values() {
    for key in ["CODEX_HOME", "OPENAI_API_KEY", "GH_TOKEN"] {
        let mut environment = environment(true);
        let mut project: ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project
            .environment
            .insert(key.into(), "synthetic-ordinary-value".into());
        set_project(&mut environment, &project);
        assert!(broker_binding(&environment, Path::new("/synthetic/config")).is_err());
        assert!(managed_clients(&environment).is_err());
    }
}

#[test]
fn explicit_config_aliases_bind_one_canonical_directory_without_opening_saved_login() {
    let temporary = tempfile::tempdir().unwrap();
    let configured = temporary.path().join("configured");
    fs::create_dir(&configured).unwrap();
    let alias = temporary.path().join("alias");
    std::os::unix::fs::symlink(&configured, &alias).unwrap();
    let environment = environment(false);
    for path in [&configured, &alias, &alias.join("../configured")] {
        let mut binding = broker_binding(&environment, path).unwrap().unwrap();
        resolve_config_directory(&mut binding).unwrap();
        assert_eq!(
            binding.config_directory,
            fs::canonicalize(&configured).unwrap()
        );
        // No saved OAuth fixture is necessary for metadata-only binding.
        assert_eq!(fs::read_dir(&configured).unwrap().count(), 0);
    }
    let mut binding = broker_binding(&environment, &temporary.path().join("missing"))
        .unwrap()
        .unwrap();
    assert!(resolve_config_directory(&mut binding).is_err());
}

#[tokio::test]
async fn supervisor_selects_platform_broker_and_clients_without_local_profile_or_login_reads() {
    for profile in [false, true] {
        let environment = environment(profile);
        let (_temporary, mut core) =
            crate::supervisor::tests::test_supervisor_core(environment.clone());
        fs::create_dir_all(&core.config.platform_config_dir).unwrap();
        let request = core
            .credential_broker_request_for_environment(&environment, 9)
            .unwrap();
        assert!(request.enabled);
        assert!(request.projection.is_none());
        assert_eq!(request.environment_generation, 9);
        assert_eq!(
            request.environment_id,
            access_environment_id(environment.id).unwrap()
        );
        let platform = request.platform.unwrap();
        assert_eq!(platform.selection.profile.is_some(), profile);
        assert_eq!(
            platform.config_directory,
            fs::canonicalize(&core.config.platform_config_dir).unwrap()
        );
        // With no credential authority to ask, the start keeps the pinned
        // clients but omits GitHub; it neither fails nor fabricates it.
        assert_eq!(
            core.managed_credential_clients_for_boot(&environment, 1)
                .await
                .unwrap(),
            clients_for_start(managed_clients(&environment).unwrap().unwrap(), || async {
                None
            })
            .await
        );
        core.require_environment_access(&environment.name)
            .await
            .unwrap();
        assert!(!core.config.credential_authority_root.exists());
        assert_eq!(
            fs::read_dir(&core.config.platform_config_dir)
                .unwrap()
                .count(),
            0
        );
    }
}

#[tokio::test]
async fn broker_requests_keep_both_authority_bindings_without_opening_local_credentials() {
    let local = Some(StoragePlacement::Local);
    let platform = Some(StoragePlacement::Platform);
    for (profile, secret_project, user) in [
        (local, platform, None),
        (local, platform, local),
        (platform, local, None),
        (None, platform, local),
        (None, local, platform),
        (local, None, None),
        (platform, None, None),
    ] {
        let environment = orthogonal_environment(profile, secret_project, user, false);
        let (_temporary, core) =
            crate::supervisor::tests::test_supervisor_core(environment.clone());
        fs::create_dir_all(&core.config.platform_config_dir).unwrap();
        let request = core
            .credential_broker_request_for_environment(&environment, 9)
            .unwrap();
        assert!(request.enabled);
        assert_eq!(request.environment_generation, 9);
        let expected_platform = [profile, secret_project, user].contains(&platform);
        assert_eq!(request.platform.is_some(), expected_platform);
        let expects_local_profile = profile == local;
        assert_eq!(request.local_profile.is_some(), expects_local_profile);
        if expects_local_profile {
            assert_eq!(request.local_profile, environment.access_binding);
        }
        let expected_local_apps = secret_project == local || user == local;
        assert_eq!(
            request.projection.is_some(),
            expected_local_apps || (!expected_platform && profile == local)
        );
        if let Some(binding) = request.platform {
            assert_eq!(binding.selection.profile.is_some(), profile == platform);
            assert_eq!(
                binding.selection.project_id.is_some(),
                secret_project == platform
            );
            assert_eq!(binding.selection.user_selected, user == platform);
            assert_eq!(
                binding.config_directory,
                fs::canonicalize(&core.config.platform_config_dir).unwrap()
            );
            if let Some(projection) = request.projection {
                assert_eq!(projection.selection_sha256, binding.selection_sha256);
                assert_eq!(
                    projection.selection.reserved_keys,
                    binding.selection.reserved_keys
                );
                assert_eq!(
                    projection.selection.overridden_keys,
                    binding.selection.ordinary_keys
                );
            }
        }
        assert!(!core.config.credential_authority_root.exists());
        assert_eq!(
            fs::read_dir(&core.config.platform_config_dir)
                .unwrap()
                .count(),
            0
        );
    }
}

#[tokio::test]
async fn initial_platform_repository_preparation_rejects_missing_profile_metadata_before_local_lookup()
 {
    let environment = environment(true);
    let (_temporary, mut core) =
        crate::supervisor::tests::test_supervisor_core(environment.clone());
    let mut project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
    project.repositories.push(codewire_project::RepositorySpec {
        source: "https://github.com/synthetic/repository".into(),
        destination: "/workspace/repository".into(),
        ..Default::default()
    });
    for source in [
        "https://github.com/synthetic/repository",
        "git@github.com:synthetic/repository.git",
    ] {
        project.repositories[0].source = source.into();
        let request = v1::CreateEnvironmentRequest {
            project_spec_json: serde_json::to_vec(&project).unwrap(),
            ..Default::default()
        };
        assert!(
            core.prepare_create_workspace_plan(&request, Uuid::new_v4())
                .await
                .is_err()
        );
        assert!(!core.config.credential_authority_root.exists());
    }
}

#[test]
fn initial_repository_binding_uses_eventual_create_identity_and_provider_profile_only() {
    let environment = environment(true);
    let temporary = tempfile::tempdir().unwrap();
    let profile = environment.access_binding.as_ref().unwrap();
    let project: ProjectSpec =
        serde_json::from_slice(environment.project_spec_json.as_ref().unwrap()).unwrap();
    let request = v1::CreateEnvironmentRequest {
        request_id: Uuid::new_v4().to_string(),
        project_spec_json: environment.project_spec_json.clone().unwrap(),
        project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
        access_profile_id: profile.profile_id.to_string(),
        access_profile_revision: profile.profile_revision,
        access_profile_reference: environment.access_profile.as_ref().unwrap().to_string(),
        platform_source_authority: Some(
            environment
                .platform_source_authority
                .as_ref()
                .unwrap()
                .proto(),
        ),
        ..Default::default()
    };
    let eventual_id = Uuid::new_v4();
    let selected = repository_binding(&request, &project, eventual_id, temporary.path())
        .unwrap()
        .unwrap();
    assert_eq!(selected.environment_id.as_str(), eventual_id.to_string());
    assert_ne!(selected.environment_id.as_str(), request.request_id);
    assert_eq!(selected.environment_generation, 1);
    assert_eq!(
        selected.binding.selection.profile,
        Some((profile.profile_id.to_string(), profile.profile_revision))
    );
    assert_eq!(
        selected.binding.selection_sha256,
        Sha256::digest(&request.project_spec_json).as_slice()
    );
    assert!(selected.binding.selection.project_id.is_none());
    assert!(!selected.binding.selection.organization_selected);
    assert!(!selected.binding.selection.user_selected);
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
    assert!(repository_binding(&request, &project, Uuid::nil(), temporary.path()).is_err());
    let mut changed = request.clone();
    changed.access_profile_revision += 1;
    assert_ne!(
        repository_binding(&changed, &project, eventual_id, temporary.path())
            .unwrap()
            .unwrap(),
        selected
    );
    changed.project_spec_sha256 = "0".repeat(64);
    assert!(repository_binding(&changed, &project, eventual_id, temporary.path()).is_err());
}

/// Every personal platform profile pins GitHub; a start configures the guest
/// for it only while the creator's connection is usable then, and an
/// unanswered question omits it rather than failing the start.
#[tokio::test]
async fn a_platform_start_configures_github_only_while_the_connection_is_usable() {
    let slots = |names: &[&str]| {
        ManagedCredentialClients::from_profile_slots(names.iter().copied()).unwrap()
    };
    let pinned = slots(&["codex", "anthropic", "github"]);
    assert_eq!(
        clients_for_start(pinned, || async { Some(true) }).await,
        pinned
    );
    for unusable in [Some(false), None] {
        assert_eq!(
            clients_for_start(pinned, || async move { unusable }).await,
            slots(&["codex", "anthropic"])
        );
    }
}

/// The platform is asked about GitHub only when GitHub is pinned: an
/// organization profile, or any selection without it, never makes the call
/// and never gains GitHub.
#[tokio::test]
async fn a_start_without_pinned_github_never_asks_the_platform() {
    let asked = std::cell::Cell::new(0);
    for names in [&["codex"][..], &["openai", "anthropic", "ssh"], &[]] {
        let without = ManagedCredentialClients::from_profile_slots(names.iter().copied()).unwrap();
        let clients = clients_for_start(without, || {
            asked.set(asked.get() + 1);
            async { Some(true) }
        })
        .await;
        assert_eq!(clients, without);
    }
    assert_eq!(asked.get(), 0);
}

#[test]
fn the_pinned_anthropic_form_chooses_claude_codes_form() {
    let mut environment = environment(true);
    for (form, sign_in, subscription_token) in [
        (AnthropicForm::ApiKey, false, false),
        (AnthropicForm::SubscriptionToken, false, true),
        (AnthropicForm::SignIn, true, false),
    ] {
        let authority = environment.platform_source_authority.as_mut().unwrap();
        authority.profile_slots = ["anthropic", "codex", "github"].map(str::to_owned).into();
        authority.anthropic_form = form;
        let clients = managed_clients(&environment).unwrap().unwrap();
        assert!(clients.contains(codewire_access::ManagedCredentialClient::Anthropic));
        assert_eq!(clients.anthropic_sign_in(), sign_in, "{form:?}");
        assert_eq!(
            clients.anthropic_subscription_token(),
            subscription_token,
            "{form:?}"
        );
    }
}
