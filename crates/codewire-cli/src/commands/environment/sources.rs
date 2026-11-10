//! Hosted source selection is metadata-only. Material remains behind the
//! environment operation, and every mutation uses the exact previewed inputs.
use std::io::{BufRead, Read as _};

use super::*;
use crate::environment_client::validate_source_selection;
use crate::presentation::{
    EnvironmentSourceSelection, EnvironmentSourcesUpdateOutcome, UpdateEnvironmentSourcesRequest,
};

pub(super) fn placement(value: StoragePlacementArg) -> codewire_project::StoragePlacement {
    match value {
        StoragePlacementArg::Local => codewire_project::StoragePlacement::Local,
        StoragePlacementArg::Platform => codewire_project::StoragePlacement::Platform,
    }
}

/// A codewire.yaml selected for a cloud create.
#[derive(Debug)]
pub(super) struct PlatformDocument {
    pub(super) spec: codewire_project::ProjectSpec,
    /// Settings only a local VM uses, accepted and left out.
    pub(super) unused_fields: Vec<&'static str>,
}

/// Reads the selected file. Local-only settings that would change what runs
/// (mounts, host ports, local credential or secret stores) refuse the create
/// before any request; `workspace.vm_only`, which only shapes a local VM's
/// disk, is accepted and reported as unused.
pub(super) fn load_platform_document(path: &Path) -> anyhow::Result<PlatformDocument> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut content = String::new();
    file.take((codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1) as u64)
        .read_to_string(&mut content)
        .with_context(|| format!("read {}", path.display()))?;
    let document = codewire_project::parse_project_yaml(&content)
        .with_context(|| format!("parse {}", path.display()))?;
    document.ensure_platform_compatible().with_context(|| {
        format!(
            "{} cannot configure a cloud environment; create a local VM from it, or choose another file with --file",
            path.display()
        )
    })?;
    let unused_fields = if document
        .local
        .vm_only
        .as_ref()
        .is_some_and(|patterns| !patterns.is_empty())
    {
        vec!["workspace.vm_only"]
    } else {
        Vec::new()
    };
    Ok(PlatformDocument {
        spec: document.spec,
        unused_fields,
    })
}

pub(super) fn validate_update_args(args: &EnvUpdateArgs) -> anyhow::Result<()> {
    trimmed_required(&args.environment, "environment")?;
    anyhow::ensure!(
        args.clear_secrets
            || args.clear_profile
            || args.secrets.is_some()
            || args.user_secrets.is_some()
            || args.org_secrets
            || args.profile.is_some()
            || args.policy.is_some(),
        "select a change with --secrets, --user-secrets, --org-secrets, --profile, --clear-secrets, --clear-profile, or --policy"
    );
    anyhow::ensure!(
        !(args.clear_secrets
            && (args.secrets.is_some() || args.user_secrets.is_some() || args.org_secrets)),
        "--clear-secrets conflicts with secret source selections"
    );
    anyhow::ensure!(
        !(args.clear_profile && args.profile.is_some()),
        "--clear-profile conflicts with --profile"
    );
    if let Some(project) = &args.secrets {
        codewire_project::StorageReference::project(project)?;
    }
    if let Some(profile) = &args.profile {
        codewire_project::StorageReference::profile(profile)?;
    }
    Ok(())
}

/// Preserve every omitted selector, including the pinned profile revision.
/// An explicit profile will be resolved to its current revision separately.
fn replacement_sources(
    current: &EnvironmentSourceSelection,
    args: &EnvUpdateArgs,
) -> EnvironmentSourceSelection {
    let mut replacement = current.clone();
    if args.clear_secrets {
        replacement.secrets = Default::default();
    } else {
        if let Some(project) = &args.secrets {
            replacement.secrets.project = project.clone();
        }
        if let Some(user) = args.user_secrets {
            replacement.secrets.user = Some(placement(user));
        }
        if args.org_secrets {
            replacement.secrets.organization = true;
        }
    }
    if args.clear_profile {
        replacement.credentials = None;
        replacement.profile_revision = None;
    } else if let Some(profile) = &args.profile {
        replacement.credentials = Some(codewire_project::CredentialBinding {
            profile: profile.clone(),
        });
        replacement.profile_revision = None;
    }
    replacement
}

/// Resolves the requested names to canonical references, and returns those
/// names for display.
async fn resolve_platform_sources(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org_id: &str,
    selection: &mut EnvironmentSourceSelection,
    resolve_project: bool,
    resolve_profile: bool,
) -> anyhow::Result<super::lifecycle::SourceNames> {
    let mut names = super::lifecycle::SourceNames::default();
    let spec = codewire_project::ProjectSpec {
        secrets: selection.secrets.clone(),
        credentials: selection.credentials.clone(),
        ..Default::default()
    };
    spec.ensure_platform_compatible()?;
    if resolve_project && !selection.secrets.project.is_empty() {
        let secret_client = SecretClient::new(platform)?;
        let project =
            load_secret_project_by_name(&secret_client, org_id, &selection.secrets.project).await?;
        anyhow::ensure!(
            project.org_id == org_id,
            "platform returned a secret project owned by a different organization"
        );
        selection.secrets.project = format!("platform:id:{}", project.id);
        names.project = Some(project.name);
    }
    if resolve_profile && let Some(credentials) = selection.credentials.as_mut() {
        let profile = client
            .resolve_credential_profile(&credentials.profile)
            .await?;
        credentials.profile = format!("platform:id:{}", profile.id);
        selection.profile_revision = Some(profile.revision);
        names.profile = Some(profile.name);
    }
    validate_source_selection(selection, true)?;
    Ok(names)
}

fn selection_preview(selection: &EnvironmentSourceSelection) -> String {
    let project = if selection.secrets.project.is_empty() {
        "none"
    } else {
        &selection.secrets.project
    };
    let user = match selection.secrets.user {
        None => "none",
        Some(codewire_project::StoragePlacement::Platform) => {
            "platform / current authenticated user (personal)"
        }
        Some(codewire_project::StoragePlacement::Local) => "local / current user (personal)",
    };
    let profile = match (&selection.credentials, selection.profile_revision) {
        (Some(credentials), Some(revision)) => format!(
            "{:?} revision {revision} (personal, current authenticated user)",
            credentials.profile
        ),
        _ => "none".to_owned(),
    };
    format!(
        "  Application-secret project: {project:?}\n  Organization application secrets: {}\n  Personal application secrets: {user}\n  Credential profile: {profile}\n",
        if selection.secrets.organization {
            "selected organization"
        } else {
            "none"
        }
    )
}

fn confirm_sources(assume_yes: bool, output: OutputFormat) -> anyhow::Result<()> {
    let interactive = !matches!(output, OutputFormat::Json)
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal();
    confirm_sources_with(assume_yes, interactive, || {
        eprint!("Apply this exact source selection? [y/N]: ");
        std::io::stderr()
            .flush()
            .context("flush source confirmation")?;
        read_confirmation(std::io::stdin().lock())
    })
}

fn confirm_sources_with(
    assume_yes: bool,
    interactive: bool,
    prompt: impl FnOnce() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    if assume_yes {
        return Ok(());
    }
    anyhow::ensure!(
        interactive,
        "source selection requires --yes for noninteractive or JSON commands; no source change was submitted"
    );
    anyhow::ensure!(
        prompt()?,
        "source selection canceled; no source change was submitted"
    );
    Ok(())
}

fn read_confirmation(reader: impl BufRead) -> anyhow::Result<bool> {
    let mut input = String::new();
    let count = reader
        .take(65)
        .read_line(&mut input)
        .context("read source confirmation")?;
    Ok(count > 0 && count < 65 && matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

pub(super) async fn prepare_create_sources(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org: &super::CreateOrganization<'_>,
    args: &EnvCreateArgs,
    request: &mut CreateEnvironmentRequest,
) -> anyhow::Result<super::lifecycle::SourceNames> {
    let mut selection = EnvironmentSourceSelection {
        secrets: request.project_spec.secrets.clone(),
        credentials: request.project_spec.credentials.clone(),
        profile_revision: None,
    };
    // With no profile named and no --no-profile, the user's default profile.
    let from_default = select_default_profile(client, args.no_profile, &mut selection).await?;
    if selection.secrets.is_empty() && selection.credentials.is_none() {
        return Ok(Default::default());
    }
    let org_id = org.id().await?;
    let names =
        resolve_platform_sources(platform, client, org_id, &mut selection, true, true).await?;
    if from_default && selection.secrets.is_empty() {
        // The user's own standing choice: no further confirmation.
        if matches!(args.output, OutputFormat::Text) {
            eprintln!(
                "Credential profile: {} (your default; --no-profile creates without one)",
                names.profile.as_deref().unwrap_or("default")
            );
        }
        return Ok(apply_create_selection(request, selection, names));
    }
    eprintln!(
        "Create environment {:?} on platform {:?}, organization {:?}.\n{}Application secrets are visible to the managed workload; provider credentials remain behind their supported handlers.",
        request.name.as_deref().unwrap_or("(server assigned)"),
        platform.server_url,
        org_id,
        selection_preview(&selection)
    );
    confirm_sources(args.yes, args.output)?;
    Ok(apply_create_selection(request, selection, names))
}

/// A cloud create's profile, in order: `--profile`, then codewire.yaml (both
/// already in `selection`), then the user's default; `--no-profile` selects
/// none. Returns whether the default was selected. A failure to read the
/// default fails the create; it never becomes "no profile". An organization
/// API key has no personal profiles, so it has no default.
async fn select_default_profile(
    client: &EnvironmentClient,
    no_profile: bool,
    selection: &mut EnvironmentSourceSelection,
) -> anyhow::Result<bool> {
    if no_profile || selection.credentials.is_some() || client.uses_organization_api_key().await? {
        return Ok(false);
    }
    let Some(default) = client
        .default_credential_profile()
        .await
        .context("read your default credential profile; --no-profile creates without one")?
    else {
        return Ok(false);
    };
    selection.credentials = Some(codewire_project::CredentialBinding {
        profile: format!("platform:id:{}", default.id),
    });
    Ok(true)
}

/// The exact previewed selection, with consent to exactly what it names.
fn apply_create_selection(
    request: &mut CreateEnvironmentRequest,
    selection: EnvironmentSourceSelection,
    names: super::lifecycle::SourceNames,
) -> super::lifecycle::SourceNames {
    request.confirm_personal_secrets = selection.secrets.user.is_some();
    request.confirm_personal_credentials = selection.credentials.is_some();
    request.expected_profile_revision = selection.profile_revision;
    request.project_spec.secrets = selection.secrets;
    request.project_spec.credentials = selection.credentials;
    names
}

pub(super) async fn update_platform_sources(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org_id: &str,
    args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    validate_update_args(&args)?;
    let environment = client
        .get_environment(org_id, &args.environment)
        .await
        .context("get exact environment source selection")?;
    anyhow::ensure!(
        environment.id == args.environment,
        "platform returned a different environment"
    );
    anyhow::ensure!(
        environment.operation_generation > 0,
        "platform did not return the environment operation generation; source updates are unsupported"
    );
    let expected = environment.source_selection.as_ref().context(
        "platform did not return complete source metadata; source updates are unsupported",
    )?;
    validate_source_selection(expected, true)?;
    let mut replacement = replacement_sources(expected, &args);
    resolve_platform_sources(
        platform,
        client,
        org_id,
        &mut replacement,
        args.secrets.is_some(),
        args.profile.is_some(),
    )
    .await?;
    let changed = replacement != *expected;
    anyhow::ensure!(
        matches!(environment.state.as_str(), "running" | "stopped"),
        "source updates require a running or stopped environment; wait for the current operation to finish"
    );
    let restart = changed && environment.state == "running";
    eprintln!(
        "Update environment {:?} ({:?}) on platform {:?}, organization {:?}, operation {}.\nCurrent:\n{}Replacement:\n{}{}",
        environment.name,
        environment.id,
        platform.server_url,
        org_id,
        environment.operation_generation,
        selection_preview(expected),
        selection_preview(&replacement),
        if restart {
            "This change requires a managed restart; workspace contents are preserved."
        } else if changed {
            "The stopped environment will use this selection at its next managed start."
        } else {
            "The selected sources and pinned profile revision are unchanged."
        }
    );
    confirm_sources(args.yes, args.output)?;
    let request = UpdateEnvironmentSourcesRequest {
        expected_operation_generation: environment.operation_generation,
        expected: expected.clone(),
        confirm_personal_credentials: replacement.credentials.is_some(),
        confirm_personal_secrets: replacement.secrets.user.is_some(),
        replacement,
        allow_restart: restart,
    };
    let result = client.update_environment_sources(org_id, &environment.id, &request).await
        .context("update environment sources; conflicts require a fresh preview, never an automatic retry")?;
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text => println!(
            "{}",
            match result.outcome {
                EnvironmentSourcesUpdateOutcome::Unchanged =>
                    "Environment source selection unchanged.",
                EnvironmentSourcesUpdateOutcome::Stored =>
                    "Environment source selection stored for the next managed launch.",
                EnvironmentSourcesUpdateOutcome::RestartRequired =>
                    "Environment source selection stored; managed restart requested.",
            }
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use codewire_client as rpc;
    use wiremock::matchers::{body_bytes, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DEFAULT: &str = "22222222-2222-4222-8222-222222222222";

    fn profile_client(server: &MockServer) -> EnvironmentClient {
        client_with_token(server, "synthetic-default-profile-token")
    }

    fn client_with_token(server: &MockServer, token: &str) -> EnvironmentClient {
        EnvironmentClient::for_test(
            rpc::CodewireClient::with_http(
                rpc::ClientConfig::new(server.uri()).unwrap(),
                rpc::StaticTokenProvider::new(token).unwrap(),
                reqwest::Client::new(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn an_organization_api_key_has_no_default_and_reads_none() {
        let server = MockServer::start().await;
        let mut selection = EnvironmentSourceSelection::default();
        assert!(
            !select_default_profile(
                &client_with_token(&server, "cw_synthetic_organization_key"),
                false,
                &mut selection
            )
            .await
            .unwrap()
        );
        assert!(selection.credentials.is_none());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    async fn list_page(server: &MockServer, token: &str, profiles: &[(&str, bool)], next: &str) {
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AccessProfileService/ListAccessProfiles"))
            .and(body_bytes(
                rpc::ListAccessProfilesRequest {
                    page_size: 100,
                    page_token: token.into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(
                        rpc::ListAccessProfilesResponse {
                            access_profiles: profiles
                                .iter()
                                .map(|(id, is_default)| rpc::AccessProfile {
                                    id: (*id).into(),
                                    name: "synthetic".into(),
                                    revision: 1,
                                    is_default: *is_default,
                                    ..Default::default()
                                })
                                .collect(),
                            next_page_token: next.into(),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_named_profile_or_no_profile_never_reads_the_default() {
        let server = MockServer::start().await;
        let client = profile_client(&server);
        let named = Some(codewire_project::CredentialBinding {
            profile: "platform:work".into(),
        });
        for (no_profile, credentials) in [(false, named.clone()), (true, None)] {
            let mut selection = EnvironmentSourceSelection {
                credentials: credentials.clone(),
                ..Default::default()
            };
            assert!(
                !select_default_profile(&client, no_profile, &mut selection)
                    .await
                    .unwrap()
            );
            assert_eq!(selection.credentials, credentials);
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unnamed_profile_is_the_default_from_any_page() {
        let server = MockServer::start().await;
        list_page(
            &server,
            "",
            &[("11111111-1111-4111-8111-111111111111", false)],
            "next",
        )
        .await;
        list_page(&server, "next", &[(DEFAULT, true)], "").await;
        let mut selection = EnvironmentSourceSelection::default();
        assert!(
            select_default_profile(&profile_client(&server), false, &mut selection)
                .await
                .unwrap()
        );
        assert_eq!(
            selection.credentials.unwrap().profile,
            format!("platform:id:{DEFAULT}")
        );
    }

    #[tokio::test]
    async fn no_default_selects_none_and_a_failed_read_fails_the_create() {
        let server = MockServer::start().await;
        list_page(&server, "", &[], "").await;
        let mut selection = EnvironmentSourceSelection::default();
        assert!(
            !select_default_profile(&profile_client(&server), false, &mut selection)
                .await
                .unwrap()
        );
        assert!(selection.credentials.is_none());

        let failing = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&failing)
            .await;
        assert!(
            select_default_profile(&profile_client(&failing), false, &mut selection)
                .await
                .is_err()
        );
        assert!(selection.credentials.is_none());

        let twice = MockServer::start().await;
        list_page(
            &twice,
            "",
            &[
                (DEFAULT, true),
                ("11111111-1111-4111-8111-111111111111", true),
            ],
            "",
        )
        .await;
        assert!(
            select_default_profile(&profile_client(&twice), false, &mut selection)
                .await
                .is_err()
        );
    }

    fn update_args(flags: &[&str]) -> EnvUpdateArgs {
        let mut argv = vec!["cw", "update", "exact-environment"];
        argv.extend_from_slice(flags);
        let cli = Cli::try_parse_from(argv).unwrap();
        let (_, _, EnvCommand::Update(args)) = env_operation(cli) else {
            panic!("update");
        };
        args
    }

    fn selected() -> EnvironmentSourceSelection {
        EnvironmentSourceSelection {
            secrets: codewire_project::SecretBindings {
                project: "platform:id:11111111-1111-4111-8111-111111111111".into(),
                organization: true,
                user: Some(codewire_project::StoragePlacement::Platform),
            },
            credentials: Some(codewire_project::CredentialBinding {
                profile: "platform:id:22222222-2222-4222-8222-222222222222".into(),
            }),
            profile_revision: Some(9_007_199_254_740_993),
        }
    }

    #[test]
    fn a_project_file_error_names_the_file_and_prints_once() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("codewire.yaml");
        std::fs::write(&path, "# Resources.\nversion: 1\ncpu: 8\n").unwrap();
        let error = load_platform_document(&path).unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "parse {}: cpu: invalid type: integer `8`, expected a quoted quantity such as \"8\" at line 3 column 6",
                path.display()
            )
        );
    }

    #[test]
    fn update_preserves_omitted_sources_and_exact_profile_revision() {
        let current = selected();
        let replacement =
            replacement_sources(&current, &update_args(&["--secrets=platform:other"]));
        assert_eq!(replacement.credentials, current.credentials);
        assert_eq!(replacement.profile_revision, current.profile_revision);
        assert_eq!(replacement.secrets.user, current.secrets.user);
        assert!(replacement.secrets.organization);
        assert_eq!(replacement.secrets.project, "platform:other");
        let replacement = replacement_sources(&current, &update_args(&["--profile=platform:work"]));
        assert_eq!(replacement.secrets, current.secrets);
        assert_eq!(
            replacement.profile_revision, None,
            "explicit selection must resolve a fresh exact revision"
        );
    }

    #[test]
    fn explicit_clear_clears_complete_collections_without_implicit_refresh() {
        let current = selected();
        let cleared = replacement_sources(&current, &update_args(&["--clear-secrets"]));
        assert!(cleared.secrets.is_empty());
        assert_eq!(cleared.credentials, current.credentials);
        assert_eq!(cleared.profile_revision, current.profile_revision);
        let cleared = replacement_sources(
            &current,
            &update_args(&["--clear-secrets", "--clear-profile"]),
        );
        assert_eq!(cleared, EnvironmentSourceSelection::default());
    }

    #[test]
    fn confirmation_requires_explicit_yes_and_never_prompts_noninteractive() {
        assert!(confirm_sources_with(false, false, || panic!("must not read input")).is_err());
        assert!(confirm_sources_with(true, false, || panic!("must not read input")).is_ok());
        assert!(confirm_sources_with(false, true, || Ok(false)).is_err());
        assert!(confirm_sources_with(false, true, || Ok(true)).is_ok());
        for input in ["", "\n", "no\n", "yesterday\n"] {
            assert!(!read_confirmation(input.as_bytes()).unwrap());
        }
        assert!(read_confirmation("yes\n".as_bytes()).unwrap());
        assert!(!read_confirmation(format!("yes{}", " ".repeat(100)).as_bytes()).unwrap());
    }

    #[test]
    fn source_flags_accept_equals_or_spaces_without_legacy_aliases() {
        for flags in [
            vec![
                "--secrets=platform:development",
                "--profile=platform:work",
                "--user-secrets=platform",
                "--org-secrets",
            ],
            vec![
                "--secrets",
                "platform:development",
                "--profile",
                "platform:work",
                "--user-secrets",
                "platform",
                "--org-secrets",
            ],
        ] {
            let args = update_args(&flags);
            assert_eq!(args.secrets.as_deref(), Some("platform:development"));
            assert_eq!(args.profile.as_deref(), Some("platform:work"));
            assert_eq!(args.user_secrets, Some(StoragePlacementArg::Platform));
            assert!(args.org_secrets);
            validate_update_args(&args).unwrap();
        }
        for retired in [
            "--secrets-project=work",
            "--secrets-user=platform",
            "--secrets-organization",
        ] {
            assert!(Cli::try_parse_from(["cw", "update", "app", retired]).is_err());
        }
    }

    #[test]
    fn source_update_requires_target_and_nonempty_unambiguous_change() {
        // Without ENV the update is refused before any effect.
        let crate::Command::Update(args) = Cli::try_parse_from(["cw", "update", "--clear-secrets"])
            .unwrap()
            .command
        else {
            panic!("expected update");
        };
        assert!(crate::commands::flat::update_operation(args).is_err());
        for flags in [
            vec!["--clear-secrets", "--user-secrets=platform"],
            vec!["--clear-profile", "--profile=work"],
        ] {
            let mut args = vec!["cw", "update", "exact-environment"];
            args.extend(flags);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(validate_update_args(&update_args(&[])).is_err());
        assert!(validate_update_args(&update_args(&["--secrets="])).is_err());
        assert!(validate_update_args(&update_args(&["--profile="])).is_err());
    }
}
