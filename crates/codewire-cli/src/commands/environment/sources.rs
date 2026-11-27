//! Hosted source selection is metadata-only. Material remains behind the
//! environment operation, and every mutation uses the exact previewed inputs.
use super::*;
use crate::commands::lifecycle_output::source_preview::{self, SourceRows, UpdateEffect};
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

/// `--user-secrets` for a cloud create (#4702): a cloud environment reads
/// personal secrets from the platform, never from this computer.
pub(super) fn cloud_user_secrets(
    value: StoragePlacementArg,
) -> anyhow::Result<codewire_project::StoragePlacement> {
    anyhow::ensure!(
        !matches!(value, StoragePlacementArg::Local),
        "a cloud environment can't read personal secrets stored on this computer; keep them on the platform and pass --user-secrets platform"
    );
    Ok(placement(value))
}

/// Personal secrets belong to a person, and an organization API key has
/// none: said before the create's plan, not after the server refuses it
/// (#4702).
const ORG_KEY_PERSONAL_SECRETS: &str = "personal application secrets need a personal sign-in, and an organization API key has none: run `cw login`, or pass --org-secrets for the organization's application secrets";

/// Refuses personal secrets for a client signed in with an organization API
/// key (#4702). It reads only the client's own token: no request is made.
async fn refuse_org_key_personal_secrets(
    client: &EnvironmentClient,
    selection: &EnvironmentSourceSelection,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        selection.secrets.user.is_none() || !client.uses_organization_api_key().await?,
        ORG_KEY_PERSONAL_SECRETS
    );
    Ok(())
}

/// A codewire.yaml selected for a cloud create.
#[derive(Debug)]
pub(super) struct PlatformDocument {
    pub(super) spec: codewire_project::ProjectSpec,
    /// `idle_stop`, which a create sends beside the spec.
    pub(super) idle_stop_seconds: Option<i32>,
    /// `idle_suspend`, sent beside the spec as `idle_stop` is.
    pub(super) idle_suspend_seconds: Option<i32>,
    /// `idle_hibernate`, sent beside the spec as `idle_stop` is (#6647).
    pub(super) idle_hibernate_seconds: Option<i32>,
    /// Whether the file names `working_directory`, rather than leaving it to
    /// follow its repositories.
    pub(super) working_directory_explicit: bool,
    /// Settings only a local VM uses, accepted and left out.
    pub(super) unused_fields: Vec<&'static str>,
}

/// Reads the selected file. Local-only settings that would change what runs
/// (mounts, host ports, local credential or secret stores) refuse the create
/// before any request; `workspace.vm_only`, which only shapes a local VM's
/// disk, is accepted and reported as unused.
/// The project document from `paths`, the files a cloud create reads, merged
/// in order.
pub(super) fn load_platform_document(paths: &[&Path]) -> anyhow::Result<PlatformDocument> {
    let document = project_file::read_document(paths)?;
    document.ensure_platform_compatible().with_context(|| {
        let names = paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        format!(
            "{} cannot configure a cloud environment; create a local VM from it, or choose another file with --file",
            names.join(" + ")
        )
    })?;
    let mut unused_fields = Vec::new();
    if document
        .local
        .vm_only
        .as_ref()
        .is_some_and(|patterns| !patterns.is_empty())
    {
        unused_fields.push("workspace.vm_only");
    }
    if document.local.path_mode.is_some() {
        unused_fields.push("workspace.path_mode");
    }
    Ok(PlatformDocument {
        working_directory_explicit: document.working_directory_is_explicit(),
        spec: document.spec,
        idle_stop_seconds: document.idle_stop_seconds,
        idle_suspend_seconds: document.idle_suspend_seconds,
        idle_hibernate_seconds: document.idle_hibernate_seconds,
        unused_fields,
    })
}

/// The flags given beside `--file`, which it doesn't combine with (#5949).
fn other_update_flags(args: &EnvUpdateArgs) -> Vec<&'static str> {
    [
        (args.secrets.is_some(), "--secrets"),
        (args.user_secrets.is_some(), "--user-secrets"),
        (args.org_secrets, "--org-secrets"),
        (args.clear_secrets, "--clear-secrets"),
        (args.profile.is_some(), "--profile"),
        (args.clear_profile, "--clear-profile"),
        (args.policy.is_some(), "--policy"),
        (args.idle_stop.is_some(), "--idle-stop"),
        (args.idle_suspend.is_some(), "--idle-suspend"),
        (args.idle_hibernate.is_some(), "--idle-hibernate"),
    ]
    .into_iter()
    .filter_map(|(given, flag)| given.then_some(flag))
    .collect()
}

/// Whether the update changes the environment's secret or credential sources.
pub(super) fn changes_sources(args: &EnvUpdateArgs) -> bool {
    args.clear_secrets
        || args.clear_profile
        || args.secrets.is_some()
        || args.user_secrets.is_some()
        || args.org_secrets
        || args.profile.is_some()
}

pub(super) fn validate_update_args(args: &EnvUpdateArgs) -> anyhow::Result<()> {
    trimmed_required(&args.environment, "environment")?;
    anyhow::ensure!(
        changes_sources(args)
            || args.policy.is_some()
            || args.idle_stop.is_some()
            || args.idle_suspend.is_some()
            || !args.file.is_empty(),
        "select a change with --file, --secrets, --user-secrets, --org-secrets, --profile, --clear-secrets, --clear-profile, --policy, --idle-stop, or --idle-suspend"
    );
    if !args.file.is_empty() {
        let others = other_update_flags(args);
        anyhow::ensure!(
            others.is_empty(),
            "`--file` changes only the startup script and doesn't combine with {}; run them as separate updates",
            others.join(" or ")
        );
    }
    if let Some(idle_stop) = &args.idle_stop {
        codewire_project::parse_idle_stop(idle_stop)?;
    }
    if let Some(idle_suspend) = &args.idle_suspend {
        codewire_project::parse_idle_suspend(idle_suspend)?;
    }
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

/// The preview's rows for `selection`, named by `names`.
fn preview_rows(
    selection: &EnvironmentSourceSelection,
    names: &super::lifecycle::SourceNames,
) -> SourceRows {
    SourceRows::new(
        &selection.secrets,
        names.project.as_deref(),
        selection
            .credentials
            .as_ref()
            .map(|binding| binding.profile.as_str()),
        names.profile.as_deref(),
        selection.profile_revision,
    )
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
    // First, before any name is resolved or the plan printed. It also runs
    // before the default profile: an organization key has none, so that
    // order changes nothing today; keep this check first if it moves.
    refuse_org_key_personal_secrets(client, &selection).await?;
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
    eprint!(
        "{}",
        source_preview::create_preview(
            request.name.as_deref().unwrap_or("(named by the server)"),
            VmLocation::Cloud,
            &preview_rows(&selection, &names),
        )
    );
    source_preview::confirm(args.yes, args.output)?;
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
    let resolved = resolve_platform_sources(
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
    let name = super::lifecycle::display_name(&environment);
    if !changed {
        source_preview::report_unchanged(&name, args.output);
        return Ok(());
    }
    let restart = environment.state == "running";
    let effect = if restart {
        UpdateEffect::Restart
    } else {
        UpdateEffect::NextStart
    };
    let current_names =
        super::lifecycle::resolve_source_names(platform, client, org_id, &environment).await;
    let replacement_names = super::lifecycle::SourceNames {
        profile: resolved.profile.or_else(|| {
            (replacement.credentials == expected.credentials)
                .then(|| current_names.profile.clone())
                .flatten()
        }),
        project: resolved.project.or_else(|| {
            (replacement.secrets.project == expected.secrets.project)
                .then(|| current_names.project.clone())
                .flatten()
        }),
    };
    eprint!(
        "{}",
        source_preview::update_preview(
            &name,
            VmLocation::Cloud,
            &preview_rows(expected, &current_names),
            &preview_rows(&replacement, &replacement_names),
            effect,
        )
    );
    source_preview::confirm(args.yes, args.output)?;
    let selected = replacement.clone();
    let began = Instant::now();
    let cursor = if restart {
        super::stop_start::log_cursor(client, org_id, &environment.id).await
    } else {
        Ok(None)
    };
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
    if result.outcome == EnvironmentSourcesUpdateOutcome::RestartRequired {
        // The next update is refused until this restart ends, so the update
        // ends with it, as `cw start` ends with its start.
        let caps = crate::commands::lifecycle_output::capabilities(args.output);
        let feed = super::progress::PlatformLogFeed {
            client,
            org_id,
            environment_id: &environment.id,
        };
        let view = StartProgress::new(std::io::stderr(), &caps, began, "Restarting");
        let interrupt = InterruptNotice::new(VmLocation::Cloud, "restart", &name);
        Box::pin(super::stop_start::follow_platform_start(
            &feed, cursor, false, view, &caps, &interrupt,
        ))
        .await?;
    }
    match (args.output, result.outcome) {
        (OutputFormat::Json, _) => println!("{}", serde_json::to_string_pretty(&result)?),
        (OutputFormat::Text, EnvironmentSourcesUpdateOutcome::Unchanged) => {
            source_preview::report_unchanged(&name, args.output)
        }
        (OutputFormat::Text, EnvironmentSourcesUpdateOutcome::Stored) => {
            source_preview::print_result(&name, VmLocation::Cloud, UpdateEffect::NextStart)
        }
        (OutputFormat::Text, EnvironmentSourcesUpdateOutcome::RestartRequired) => {
            source_preview::print_result(&name, VmLocation::Cloud, UpdateEffect::Restart)
        }
    }
    // The credentials its agents can't use, as a local update says them
    // (#5594).
    super::lifecycle::withheld::print_withheld(
        &super::lifecycle::withheld::withheld_credentials(platform, Some(&selected)).await,
    );
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

    /// A cloud create's personal secrets come from the platform, and only a
    /// person's sign-in has them (#4702).
    #[test]
    fn personal_secrets_for_a_cloud_create_are_refused_in_plain_words() {
        assert_eq!(
            cloud_user_secrets(StoragePlacementArg::Platform).unwrap(),
            codewire_project::StoragePlacement::Platform
        );
        let local = cloud_user_secrets(StoragePlacementArg::Local)
            .unwrap_err()
            .to_string();
        assert!(local.ends_with("pass --user-secrets platform"), "{local}");
        for message in [local.as_str(), ORG_KEY_PERSONAL_SECRETS] {
            for internal in ["secrets.user", "placement", "account-global", "scoped"] {
                assert!(!message.contains(internal), "{message}");
            }
        }
        assert!(ORG_KEY_PERSONAL_SECRETS.contains("`cw login`"));
        assert!(ORG_KEY_PERSONAL_SECRETS.contains("--org-secrets"));
    }

    /// The refusal's condition, not only its words: an organization key
    /// with personal secrets is refused before any request, and a personal
    /// sign-in, or no personal secrets, goes on (#4702).
    #[tokio::test]
    async fn an_organization_key_with_personal_secrets_is_refused_before_any_request() {
        let server = MockServer::start().await;
        let personal = EnvironmentSourceSelection {
            secrets: codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                ..Default::default()
            },
            ..Default::default()
        };
        let org_key = client_with_token(&server, "cw_synthetic-org-key");
        let refused = refuse_org_key_personal_secrets(&org_key, &personal)
            .await
            .unwrap_err();
        assert_eq!(refused.to_string(), ORG_KEY_PERSONAL_SECRETS);
        assert!(server.received_requests().await.unwrap().is_empty());

        let person = client_with_token(&server, "synthetic-personal-token");
        refuse_org_key_personal_secrets(&person, &personal)
            .await
            .unwrap();
        refuse_org_key_personal_secrets(&org_key, &EnvironmentSourceSelection::default())
            .await
            .unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
    }

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

    const SOURCE_PROJECT: &str = "platform:id:11111111-1111-4111-8111-111111111111";

    fn proto_response(message: impl buffa::Message) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/proto")
            .set_body_bytes(message.encode_to_vec())
    }

    /// The environment as GetEnvironment answers, with one secret project
    /// selected.
    fn sourced_environment(state: rpc::EnvironmentState) -> ResponseTemplate {
        let spec = codewire_project_proto::to_proto(codewire_project::ProjectSpec {
            secrets: codewire_project::SecretBindings {
                project: SOURCE_PROJECT.into(),
                ..Default::default()
            },
            ..Default::default()
        });
        proto_response(rpc::GetEnvironmentResponse {
            environment: Some(rpc::Environment {
                id: "exact-environment".into(),
                org_id: "org_demo".into(),
                name: "app".into(),
                state: state.into(),
                desired_state: rpc::DesiredState::Started.into(),
                operation_generation: 1,
                source_selection: Some(rpc::EnvironmentSourceSelection {
                    secrets: spec.secrets,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }

    /// docs/dev/CLI-PARITY.md, R8: a source update that restarts a running
    /// environment returns once the restart has finished, as `cw start`
    /// does, so the next update isn't refused for an operation in flight.
    #[tokio::test]
    async fn a_source_update_that_restarts_waits_for_the_restart() {
        const GET: &str = "/codewire.v1.EnvironmentService/GetEnvironment";
        const UPDATE: &str = "/codewire.v1.EnvironmentService/UpdateEnvironmentSources";
        const STATUS: &str = "/codewire.v1.EnvironmentService/GetEnvironmentDaemonStatus";
        let server = MockServer::start().await;
        // The plan's read, then the restart as the platform runs it.
        for state in [
            rpc::EnvironmentState::Running,
            rpc::EnvironmentState::Stopping,
            rpc::EnvironmentState::Starting,
        ] {
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(sourced_environment(state))
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path(GET))
            .respond_with(sourced_environment(rpc::EnvironmentState::Running))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(UPDATE))
            .respond_with(proto_response(rpc::UpdateEnvironmentSourcesResponse {
                environment_id: "exact-environment".into(),
                operation_generation: 1,
                selection: Some(rpc::EnvironmentSourceSelection::default()).into(),
                outcome: rpc::EnvironmentSourcesUpdateOutcome::RestartRequired.into(),
                ..Default::default()
            }))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(STATUS))
            .respond_with(proto_response(rpc::GetEnvironmentDaemonStatusResponse {
                status: Some(rpc::EnvironmentDaemonStatus {
                    state: rpc::EnvironmentDaemonState::Ready.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }))
            .mount(&server)
            .await;
        let platform = config::ResolvedPlatformConfig::static_token(
            server.uri(),
            "synthetic-source-update-token",
            true,
            None,
        );
        let client = client_with_token(&server, "synthetic-source-update-token");
        let args = update_args(&["--clear-secrets", "--yes", "--output", "json"]);
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            update_platform_sources(&platform, &client, "org_demo", args),
        )
        .await
        .expect("the update's wait is bounded")
        .unwrap();

        let paths = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .map(|request| request.url.path().to_owned())
            .collect::<Vec<_>>();
        let update = paths.iter().position(|path| path == UPDATE).unwrap();
        let gets_after = paths[update..].iter().filter(|path| *path == GET).count();
        assert!(
            gets_after >= 3,
            "followed the restart to running: {paths:?}"
        );
        assert_eq!(paths.last().map(String::as_str), Some(STATUS), "{paths:?}");
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
        let error = load_platform_document(&[&path]).unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "parse {}: cpu: invalid type: integer `8`, expected a quoted quantity such as \"8\" at line 3, column 1",
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

    /// `--idle-stop` is a change of its own, and does not touch the sources
    /// (#3384).
    #[test]
    fn idle_stop_is_an_update_without_a_source_change() {
        let args = update_args(&["--idle-stop", "30m"]);
        validate_update_args(&args).unwrap();
        assert!(!changes_sources(&args));
        validate_update_args(&update_args(&["--idle-stop", "off"])).unwrap();
        let error = validate_update_args(&update_args(&["--idle-stop", "soon"])).unwrap_err();
        assert!(error.to_string().contains("idle_stop"), "{error}");
        let both = update_args(&["--idle-stop", "1h", "--clear-profile"]);
        validate_update_args(&both).unwrap();
        assert!(changes_sources(&both));
    }

    /// `--idle-suspend` is a change of its own too, with its own range
    /// (#5529), and `--file` names it among the flags it doesn't combine with.
    #[test]
    fn idle_suspend_is_an_update_without_a_source_change() {
        let args = update_args(&["--idle-suspend", "15m"]);
        validate_update_args(&args).unwrap();
        assert!(!changes_sources(&args));
        validate_update_args(&update_args(&["--idle-suspend", "off"])).unwrap();
        validate_update_args(&update_args(&["--idle-suspend", "on"])).unwrap();
        for value in ["soon", "1m", "8d"] {
            let error = validate_update_args(&update_args(&["--idle-suspend", value])).unwrap_err();
            assert!(
                error.to_string().contains("idle_suspend"),
                "{value}: {error}"
            );
        }
        let error = validate_update_args(&update_args(&[
            "--file",
            "codewire.yaml",
            "--idle-suspend",
            "15m",
        ]))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`--file` changes only the startup script and doesn't combine with --idle-suspend; run them as separate updates"
        );
    }

    /// `--file` is a change of its own, and names the flags given beside it
    /// (#5949).
    #[test]
    fn file_is_an_update_that_takes_no_other_change() {
        let args = update_args(&["--file", "codewire.yaml", "--file", "dev.yaml"]);
        validate_update_args(&args).unwrap();
        assert_eq!(args.file.len(), 2);
        assert!(!changes_sources(&args));
        let error = validate_update_args(&update_args(&[
            "--file",
            "codewire.yaml",
            "--policy",
            "open",
        ]))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`--file` changes only the startup script and doesn't combine with --policy; run them as separate updates"
        );
        let error = validate_update_args(&update_args(&[
            "--file",
            "codewire.yaml",
            "--secrets",
            "dev",
            "--idle-stop",
            "1h",
        ]))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`--file` changes only the startup script and doesn't combine with --secrets or --idle-stop; run them as separate updates"
        );
    }
}
