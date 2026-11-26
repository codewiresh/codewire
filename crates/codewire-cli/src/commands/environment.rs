use std::path::Path;

use super::*;
use crate::commands::progress::terminal_text;

mod cp;
pub(crate) mod cpu;
mod create_request;
mod host_placement;
mod idle_stop;
mod idle_suspend;
pub(crate) mod info;
pub(crate) mod lifecycle;
mod platform_create;
mod policy_notice;
pub(crate) mod progress;
mod remove;
mod runtime;
mod server_errors;
mod shown;
mod sources;
mod stop_start;
mod transfer;
mod update;

use cp::handle_unified_environment_cp;
pub(crate) use cpu::{local_vm_vcpus, local_vm_vcpus_from_millicores, parse_resize_cpu};
pub(crate) use create_request::{
    env_create_request_from_args, parse_create_memory, prepare_platform_env_create,
};
#[cfg(test)]
pub(crate) use idle_stop::format_env_idle_stop_text;
pub(crate) use idle_stop::print_env_idle_stop_status;
#[cfg(test)]
pub(crate) use idle_suspend::format_env_idle_suspend_text;
pub(crate) use info::{env_created_label, env_state_label, format_env_info_text};
use platform_create::handle_platform_env_create;
#[cfg(test)]
pub(crate) use policy_notice::policy_selection_notice;
pub(crate) use policy_notice::{open_widening_notice, report_policy_selection};
pub(crate) use server_errors::map_env_delete_error;
use shown::display_name_for;

use progress::{FollowPolicy, StartProgress, format_environment_logs_plain};

const STOPPING_LABEL: &str = "Stopping the environment";
const REMOVING_LABEL: &str = "Removing the environment";

use super::lifecycle_output::InterruptNotice;
use crate::environment_client::{
    ResolvingCreateError, display_client_error, get_environment_error,
};
use crate::output::{Outcome, StatusLine, VmLocation};
use codewire_client::environment_setup::{self as setup, DaemonObservation, DaemonWaitError};

/// The hosted Mesh network a new cloud environment asks to join. A cloud
/// environment's resolver is pinned to its platform's hosted Mesh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CloudMeshRequest {
    pub(crate) mesh_url: String,
    /// `None` before the current organization is known.
    pub(crate) organization_id: Option<String>,
    pub(crate) network_id: String,
}

/// Refuses, before anything is requested or allocated, the `--network` a
/// cloud create can never use: `local:NAME` (a cloud environment cannot join
/// a local Mesh service) and `--network` with `--no-network`. A hosted
/// network (`cloud:NAME` or `NAME`) is checked against the hosted Mesh
/// afterwards, with the user's own sign-in.
pub(crate) fn refuse_requested_cloud_mesh(
    requested_network: Option<&str>,
    disable_network: bool,
) -> anyhow::Result<()> {
    let Some(requested) = requested_network
        .and_then(trimmed_str)
        .map(NetworkReference::parse)
        .transpose()?
    else {
        return Ok(());
    };
    anyhow::ensure!(
        !disable_network,
        "--network and --no-network cannot be used together"
    );
    if requested.mesh == Some(MeshKind::Local) {
        return Err(local_mesh_refusal(&requested.network));
    }
    Ok(())
}

fn local_mesh_refusal(network: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "a cloud environment cannot join the local Mesh service. No environment was created; use --network cloud:{network}, or create a local VM with `cw --local create --network local:{network}`"
    )
}

/// Resolves the Mesh attachment a cloud create asks for. `--network
/// local:NAME` is refused: a cloud environment cannot join a local Mesh
/// service. Without `--network`, `CODEWIRE_MESH_NETWORK` or a hosted
/// selection for this platform and organization applies, asking first
/// unless it connects automatically; a local selection does not apply.
pub(crate) fn resolve_env_create_mesh_bootstrap(
    paths: &ResolvePaths,
    env: &impl config::Env,
    platform: &config::ResolvedPlatformConfig,
    organization_id: &str,
    assume_yes: bool,
    requested_network: Option<&str>,
    disable_network: bool,
) -> anyhow::Result<Option<CloudMeshRequest>> {
    let requested = requested_network
        .and_then(trimmed_str)
        .map(NetworkReference::parse)
        .transpose()?;
    if disable_network && requested.is_some() {
        anyhow::bail!("--network and --no-network cannot be used together");
    }
    if disable_network {
        return Ok(None);
    }
    if let Some(NetworkReference {
        mesh: Some(MeshKind::Local),
        network,
    }) = &requested
    {
        return Err(local_mesh_refusal(network));
    }
    let mesh_url = mesh_commands::selection::hosted_mesh_url(platform)?;
    let organization_id = trimmed_required(organization_id, "organization ID")?.to_string();
    if let Some(requested) = requested {
        return Ok(Some(CloudMeshRequest {
            mesh_url,
            organization_id: Some(organization_id),
            network_id: requested.network,
        }));
    }
    let selection = load_network_selection(&paths.mesh_data_dir)?.filter(|selection| {
        selection.mesh == MeshKind::Cloud && selection.is_for(&mesh_url, &organization_id)
    });
    let (network_id, auto_connect) = match (
        env.var(config::CODEWIRE_MESH_NETWORK_ENV)
            .and_then(|network| trimmed_str(&network).map(str::to_owned)),
        selection,
    ) {
        (Some(network), _) => (network, false),
        (None, Some(selection)) => (selection.network_id, selection.auto_connect),
        (None, None) => {
            print_legacy_selection_notice(&paths.mesh_data_dir);
            return Ok(None);
        }
    };
    if !assume_yes && !auto_connect {
        if !stdin_is_interactive() {
            return Ok(None);
        }
        if !prompt_confirm_default_no(&env_create_mesh_prompt(
            &mesh_url,
            &organization_id,
            &network_id,
        ))? {
            return Ok(None);
        }
    }
    Ok(Some(CloudMeshRequest {
        mesh_url,
        organization_id: Some(organization_id),
        network_id,
    }))
}

pub(crate) fn env_create_mesh_prompt(
    mesh_url: &str,
    organization_id: &str,
    network_id: &str,
) -> String {
    format!(
        "Join Codewire Cloud Mesh network cloud:{network_id} at {mesh_url} (organization {organization_id}) for this cloud environment. Continue"
    )
}

/// Before a cloud create allocates anything: the hosted Mesh lists the
/// network for the signed-in user, so it exists in the organization and they
/// are a member of it. Mesh enforces this again when the environment joins;
/// this check only names the mistake before an environment is created.
async fn require_cloud_network_membership(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    request: &CloudMeshRequest,
) -> anyhow::Result<()> {
    let organization = request.organization_id.as_deref().unwrap_or_default();
    let reference = format!(
        "Codewire Cloud Mesh network cloud:{} at {} (organization {})",
        terminal_text(&request.network_id),
        terminal_text(&request.mesh_url),
        terminal_text(organization)
    );
    let mesh = mesh_commands::selection::mesh_of_kind(globals, paths, env, MeshKind::Cloud)?;
    let networks = crate::mesh::MeshClient::new(&mesh.resolved)?
        .list_networks(organization)
        .await
        .with_context(|| format!("could not check {reference}. No environment was created"))?;
    anyhow::ensure!(
        networks
            .iter()
            .any(|network| network.id == request.network_id),
        "you are not a member of {reference}, or it does not exist. No environment was created; list your networks with `cw --cloud network ls --org {}`",
        terminal_text(organization)
    );
    Ok(())
}

pub(crate) async fn handle_env_command(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: EnvCommand,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    if placement != Some(EnvironmentPlacement::Platform)
        && handle_host_environment_command(globals, placement, &command).await?
    {
        return Ok(());
    }
    match command {
        EnvCommand::Agent(args) => {
            anyhow::ensure!(
                placement != Some(EnvironmentPlacement::Local),
                "cw agent requires a cloud environment"
            );
            #[cfg(unix)]
            {
                super::sessions::agents::platform_host::handle_metadata(globals, args.command).await
            }
            #[cfg(not(unix))]
            {
                let _ = args;
                anyhow::bail!("platform managed agent commands require a Unix client")
            }
        }
        EnvCommand::Runtime(args) => runtime::handle(globals, placement, args.command).await,
        EnvCommand::Create(create) => {
            handle_unified_environment_create(globals, placement, create).await
        }
        EnvCommand::Update(update) => update::handle_unified(globals, placement, update).await,
        EnvCommand::Info(info) => handle_unified_environment_info(globals, placement, info).await,
        EnvCommand::Resize(resize) => {
            handle_unified_environment_resize(globals, placement, resize).await
        }
        EnvCommand::Start(target) => {
            handle_unified_environment_lifecycle(
                globals,
                placement,
                UnifiedEnvironmentLifecycle::Start(target),
            )
            .await
        }
        EnvCommand::Stop(target) => {
            handle_unified_environment_lifecycle(
                globals,
                placement,
                UnifiedEnvironmentLifecycle::Stop(target),
            )
            .await
        }
        EnvCommand::Restart(target) => {
            handle_unified_environment_lifecycle(
                globals,
                placement,
                UnifiedEnvironmentLifecycle::Restart(target),
            )
            .await
        }
        EnvCommand::RefreshSkills(target) => {
            handle_unified_environment_refresh_skills(globals, placement, target).await
        }
        EnvCommand::Rm(target) => {
            handle_unified_environment_lifecycle(
                globals,
                placement,
                UnifiedEnvironmentLifecycle::Remove(target),
            )
            .await
        }
        EnvCommand::Access(access) => {
            handle_unified_environment_access(globals, placement, access).await
        }
        EnvCommand::Share(share) => {
            handle_unified_environment_share(globals, placement, share).await
        }
        EnvCommand::Daemon(args) => {
            handle_unified_environment_daemon_command(globals, placement, args.command).await
        }
        EnvCommand::Cp(args) => handle_unified_environment_cp(globals, placement, args).await,
        EnvCommand::Port(args) => handle_unified_environment_port(globals, placement, args).await,
        // Locally, prune frees the images kept after their last VM (#4262).
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        EnvCommand::Prune(args) if placement == Some(EnvironmentPlacement::Local) => {
            super::local_images::prune(args).await
        }
        command => {
            // Cloud-only operations: an explicit --cloud is their placement;
            // --local is refused rather than ignored.
            if placement == Some(EnvironmentPlacement::Local) {
                anyhow::bail!(
                    "`cw {}` is available only for cloud environments",
                    platform_only_command_name(&command)
                );
            }
            handle_platform_env_command(globals, command).await
        }
    }
}

fn platform_only_command_name(command: &EnvCommand) -> &'static str {
    match command {
        EnvCommand::Report(_) => "report",
        EnvCommand::Prune(_) => "prune",
        EnvCommand::Nuke(_) => "nuke",
        EnvCommand::Protect(_) => "protect",
        EnvCommand::Unprotect(_) => "unprotect",
        EnvCommand::CancelDelete(_) => "cancel-delete",
        EnvCommand::Extend(_) => "extend",
        EnvCommand::Logs(_) => "logs --setup",
        _ => "this command",
    }
}

/// A local environment's ports live on this host's 127.0.0.1; a cloud
/// environment's are preview URLs. ENV, else the selected environment,
/// decides which when no placement is given.
async fn handle_unified_environment_port(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    mut args: EnvPortTarget,
) -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let local = match (placement, args.environment.as_deref()) {
            (Some(EnvironmentPlacement::Platform), _) => None,
            (_, Some(target)) => {
                match resolve_unified_environment_target(globals, placement, target, "ports")
                    .await?
                {
                    UnifiedEnvironmentTarget::NativeLocal(name) => Some(name),
                    UnifiedEnvironmentTarget::Platform(id) => {
                        args.environment = Some(id);
                        None
                    }
                }
            }
            (Some(EnvironmentPlacement::Local), None) => {
                Some(selected_local_environment_name().await?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "no local environment selected; pass ENV or run `cw use --local ENV`"
                    )
                })?)
            }
            (None, None) => selected_local_environment_name().await?,
        };
        if let Some(name) = local {
            return handle_native_environment_port(&name, args.operation, args.output).await;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if placement == Some(EnvironmentPlacement::Local) {
        anyhow::bail!("local environments need Linux or macOS");
    }
    handle_platform_env_command(globals, EnvCommand::Port(args)).await
}

/// The selected environment's name when it is a local VM. Only an explicit
/// `cw use` selects; a selected VM that no longer exists is an error.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn selected_local_environment_name() -> anyhow::Result<Option<String>> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    match config::current_target(&paths.mesh_data_dir) {
        Ok(target) if target.kind == "local" && target.target_ref != "local" => {
            native_environment(&target.target_ref)
                .await?
                .map(|environment| Some(environment.name))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "the selected local VM {} no longer exists; pass ENV or run `cw use`",
                        target.name
                    )
                })
        }
        _ => Ok(None),
    }
}

async fn handle_unified_environment_access(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvAccessArgs,
) -> anyhow::Result<()> {
    match placement {
        Some(EnvironmentPlacement::Local) => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                handle_native_environment_access(args).await
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = args;
                anyhow::bail!("local environments need Linux or macOS")
            }
        }
        Some(EnvironmentPlacement::Platform) | None => {
            handle_platform_env_command(globals, EnvCommand::Access(args)).await
        }
    }
}

async fn handle_unified_environment_share(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvShareArgs,
) -> anyhow::Result<()> {
    match placement {
        Some(EnvironmentPlacement::Local) => {
            anyhow::bail!("environment sharing is available only with --cloud")
        }
        Some(EnvironmentPlacement::Platform) | None => {
            handle_platform_env_command(globals, EnvCommand::Share(args)).await
        }
    }
}

/// Render the environment workspace chooser after an attach-navigation request.
/// This only observes the current placements; it never changes `cw use`.
pub(crate) async fn show_workspace_list(globals: &Globals) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let placement = resolve_platform(globals, &paths, &env)
        .is_err()
        .then_some(EnvironmentPlacement::Local);
    handle_unified_environment_list(
        globals,
        placement,
        EnvListArgs {
            environment_type: None,
            state: None,
            all: false,
            output: OutputFormat::Text,
        },
    )
    .await
}

/// A create's organization: left to the server unless something needs it
/// first, and then listed once, with the listing's own refusals (#3747).
pub(crate) struct CreateOrganization<'a> {
    platform: &'a config::ResolvedPlatformConfig,
    client: &'a OrganizationClient,
    /// `--org`, which wins over the saved default.
    requested: Option<&'a str>,
    id: tokio::sync::OnceCell<String>,
}

impl<'a> CreateOrganization<'a> {
    pub(crate) fn new(
        platform: &'a config::ResolvedPlatformConfig,
        client: &'a OrganizationClient,
        requested: Option<&'a str>,
    ) -> Self {
        let requested = requested.and_then(trimmed_str);
        Self {
            platform,
            client,
            requested,
            // An `--org` ID is used as given, as every other command does.
            id: tokio::sync::OnceCell::new_with(
                requested
                    .filter(|id| looks_like_org_id(id))
                    .map(str::to_owned),
            ),
        }
    }

    pub(crate) async fn id(&self) -> anyhow::Result<&str> {
        self.id
            .get_or_try_init(|| async {
                let orgs = self.client.list_orgs().await.context("list orgs")?;
                resolve_org_id(self.platform, &orgs, self.requested)
            })
            .await
            .map(String::as_str)
    }

    /// The guided create shows its organization, and asks for one when none
    /// is chosen.
    async fn for_setup(&self, globals: &Globals) -> anyhow::Result<&str> {
        self.id
            .get_or_try_init(|| async {
                let orgs = self.client.list_orgs().await.context("list orgs")?;
                super::launch_setup::organization_for_setup(
                    globals,
                    self.platform,
                    self.client,
                    &orgs,
                    true,
                )
                .await
            })
            .await
            .map(String::as_str)
    }
}

/// Whether this create may join a Mesh network, which is chosen per
/// organization. With no network named and none selected, it can't.
pub(crate) fn create_mesh_needs_organization(
    paths: &ResolvePaths,
    env: &impl config::Env,
    platform: &config::ResolvedPlatformConfig,
    requested_network: Option<&str>,
    disable_network: bool,
) -> anyhow::Result<bool> {
    if disable_network {
        return Ok(false);
    }
    if requested_network.and_then(trimmed_str).is_some() {
        return Ok(true);
    }
    let mesh_url = mesh_commands::selection::hosted_mesh_url(platform)?;
    let named = env
        .var(config::CODEWIRE_MESH_NETWORK_ENV)
        .is_some_and(|network| trimmed_str(&network).is_some());
    let selected = load_network_selection(&paths.mesh_data_dir)?.is_some_and(|selection| {
        selection.mesh == MeshKind::Cloud && config::same_mesh_url(&selection.mesh_url, &mesh_url)
    });
    Ok(named || selected)
}

/// Creates by ID if the organization is already known, and otherwise lets the
/// server resolve it, with the refusals the listing would have given.
pub(crate) async fn create_in_organization(
    client: &EnvironmentClient,
    org: &CreateOrganization<'_>,
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<Environment> {
    if let Some(org_id) = org.id.get() {
        return client
            .create_environment(org_id, request)
            .await
            .map_err(server_errors::create_failed);
    }
    let selector = org.requested.or_else(|| configured_org(org.platform));
    match client
        .create_environment_resolving_org(selector.unwrap_or_default(), request)
        .await
    {
        Ok(environment) => Ok(environment),
        Err(ResolvingCreateError::OlderServer) => client
            .create_environment(org.id().await?, request)
            .await
            .map_err(server_errors::create_failed),
        Err(ResolvingCreateError::NoOrganizations) => Err(no_organizations_found()),
        Err(ResolvingCreateError::NoOrganizationSelected) => Err(no_org_selected()),
        Err(ResolvingCreateError::OrganizationNotAvailable) => Err(match org.requested {
            Some(requested) => organization_not_found(requested),
            None => configured_org_unavailable(selector.unwrap_or_default()),
        }),
        Err(ResolvingCreateError::Other(error)) => Err(server_errors::create_failed(error)),
    }
}

pub(crate) async fn handle_platform_env_command(
    globals: &Globals,
    command: EnvCommand,
) -> anyhow::Result<()> {
    handle_platform_env_command_with_created(globals, command)
        .await
        .map(drop)
}

/// Keeps the exact result of a reviewed create for the first-run journey.
/// A canceled create never becomes a lookup by name of an unrelated environment.
pub(crate) async fn create_platform_environment_for_run(
    globals: &Globals,
    args: Box<EnvCreateArgs>,
) -> anyhow::Result<Environment> {
    handle_platform_env_command_with_created(globals, EnvCommand::Create(args))
        .await?
        .context("canceled; no environment created")
}

async fn handle_platform_env_command_with_created(
    globals: &Globals,
    command: EnvCommand,
) -> anyhow::Result<Option<Environment>> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    if let EnvCommand::Create(args) = command {
        return Box::pin(handle_platform_env_create(globals, &paths, *args)).await;
    }
    let platform = resolve_platform(globals, &paths, &env)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = super::launch_setup::organization_for_setup(
        globals,
        &platform,
        &organization_client,
        &orgs,
        false,
    )
    .await?;

    match command {
        EnvCommand::Agent(args) => {
            #[cfg(unix)]
            {
                super::sessions::agents::platform_host::handle_metadata(globals, args.command)
                    .await?
            }
            #[cfg(not(unix))]
            {
                let _ = args;
                anyhow::bail!("platform managed agent commands require a Unix client")
            }
        }
        EnvCommand::Runtime(_) => anyhow::bail!("cw runtime supports only native Linux VMs"),
        EnvCommand::Create(_) => unreachable!("handled before the organization listing"),
        EnvCommand::Update(args) => {
            update::platform(globals, &platform, &environment_client, &org_id, args).await?;
        }
        EnvCommand::Info(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let environment = environment_client
                .get_environment(&org_id, &environment_id)
                .await
                .context("get environment")?;
            // Managed conversations are read only while it runs and isn't suspended (#2982).
            let attention = if idle_suspend::awake(&environment) {
                Some(
                    super::sessions::agents::managed_attention(
                        globals,
                        super::sessions::agents::AttentionEnvironment::Platform {
                            id: environment_id.clone(),
                            name: environment.name.clone(),
                        },
                    )
                    .await,
                )
            } else {
                None
            };
            print_env_info(&environment, args.output, attention.as_ref())?;
        }
        EnvCommand::Report(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let report = environment_client
                .get_environment_trust_report(&org_id, &environment_id)
                .await
                .context("get environment trust report")?;
            print_env_report(&report, args.output)?;
        }
        EnvCommand::Stop(args) => stop_start::stop(&environment_client, &org_id, args).await?,
        EnvCommand::Start(args) => {
            stop_start::start(&platform, &environment_client, &org_id, args.target).await?;
        }
        EnvCommand::Restart(_) => {
            anyhow::bail!("restart is supported only for local environments");
        }
        EnvCommand::RefreshSkills(_) => {
            anyhow::bail!("refresh-skills is supported only for local environments");
        }
        EnvCommand::Rm(args) => remove::remove(&environment_client, &org_id, args).await?,
        EnvCommand::Prune(args) => {
            let environments = environment_client
                .list_environments(&org_id, false)
                .await
                .context("list environments")?;
            let states = parse_prune_states(&args.state);
            let selection = select_prune_environments(&environments, &states);
            print_env_bulk_skipped(selection.skipped_protected);

            if selection.targets.is_empty() {
                println!("No environments to prune.");
                return Ok(None);
            }

            print!("{}", format_env_prune_targets_text(&selection.targets));
            println!();

            if args.dry_run {
                println!(
                    "Would prune {} environments (dry run).",
                    selection.targets.len()
                );
                return Ok(None);
            }

            if !confirm_bulk_deletion(
                BulkDeletion::Prune,
                &format!("Delete {} environments?", selection.targets.len()),
                args.yes,
            )? {
                println!("Aborted.");
                return Ok(None);
            }

            let deleted =
                delete_environment_targets(&environment_client, &org_id, &selection.targets).await;
            println!("Pruned {deleted} environments.");
        }
        EnvCommand::Nuke(args) => {
            let environments = environment_client
                .list_environments(&org_id, false)
                .await
                .context("list environments")?;
            let selection = select_nuke_environments(&environments);
            print_env_bulk_skipped(selection.skipped_protected);

            if selection.targets.is_empty() {
                println!("No environments to nuke.");
                return Ok(None);
            }

            println!(
                "This will DELETE ALL {} environments in org {:?}.",
                selection.targets.len(),
                org_id
            );
            println!();
            print!("{}", format_env_nuke_targets_text(&selection.targets));
            println!();

            let expected = format!("nuke {} environments", selection.targets.len());
            if !confirm_bulk_deletion_typed(BulkDeletion::Nuke, &expected, args.yes)? {
                println!("Aborted.");
                return Ok(None);
            }

            let deleted =
                delete_environment_targets(&environment_client, &org_id, &selection.targets).await;
            println!("Nuked {deleted} environments.");
        }
        EnvCommand::Cp(args) => {
            handle_env_cp_command(&environment_client, &org_id, args).await?;
        }
        EnvCommand::Protect(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let response = environment_client
                .protect_environment(&org_id, &environment_id)
                .await
                .context("protect environment")?;
            print_env_status(&args.environment, &response, args.output)?;
        }
        EnvCommand::Unprotect(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let response = environment_client
                .unprotect_environment(&org_id, &environment_id)
                .await
                .context("unprotect environment")?;
            print_env_status(&args.environment, &response, args.output)?;
        }
        EnvCommand::CancelDelete(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let response = environment_client
                .cancel_environment_deletion(&org_id, &environment_id)
                .await
                .context("cancel deletion")?;
            print_env_status(&args.environment, &response, args.output)?;
        }
        EnvCommand::Extend(args) => {
            let hours = args.hours.max(1);
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let response = environment_client
                .extend_environment_ttl(
                    &org_id,
                    &environment_id,
                    &ExtendTtlRequest {
                        additional_seconds: hours.saturating_mul(3600),
                    },
                )
                .await
                .context("extend TTL")?;
            print_env_extend_status(&args.environment, &response, hours, args.output)?;
        }
        EnvCommand::Access(_) => anyhow::bail!(
            "environment credential-profile inspection is not yet available for cloud environments"
        ),
        EnvCommand::Share(args) => {
            handle_env_share_command(&environment_client, &org_id, args.command).await?;
        }
        EnvCommand::Port(args) => {
            handle_env_port_command(&environment_client, &org_id, &paths.mesh_data_dir, args)
                .await?;
        }
        EnvCommand::Logs(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            if args.follow {
                follow_environment_logs(&environment_client, &org_id, &environment_id).await?;
            } else {
                let logs = environment_client
                    .get_environment_logs(&org_id, &environment_id)
                    .await
                    .context("get environment logs")?;
                print_environment_logs_historical(&logs);
            }
        }
        EnvCommand::Resize(args) => {
            handle_platform_environment_resize(&environment_client, &org_id, args).await?;
        }
        EnvCommand::Daemon(args) => {
            handle_environment_daemon_command(&environment_client, &org_id, args.command).await?;
        }
    }
    Ok(None)
}

#[derive(Debug)]
enum UnifiedEnvironmentLifecycle {
    Start(EnvStartArgs),
    Stop(EnvTargetArgs),
    Restart(EnvTargetArgs),
    Remove(EnvDeleteArgs),
}

impl UnifiedEnvironmentLifecycle {
    fn environment(&self) -> &str {
        match self {
            Self::Start(args) => &args.environment,
            Self::Stop(args) | Self::Restart(args) => &args.environment,
            Self::Remove(args) => &args.environment,
        }
    }

    fn command_name(&self) -> &'static str {
        match self {
            Self::Start(_) => "start",
            Self::Stop(_) => "stop",
            Self::Restart(_) => "restart",
            Self::Remove(_) => "rm",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UnifiedEnvironmentTarget {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    NativeLocal(String),
    Platform(String),
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeResizeResources {
    pub(crate) vcpus: u32,
    pub(crate) memory_mib: u32,
    pub(crate) disk_bytes: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeResizePlan {
    pub(crate) current: NativeResizeResources,
    pub(crate) desired: NativeResizeResources,
    pub(crate) active_sessions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlatformResizePlan {
    pub(crate) current: EnvironmentResizeResources,
    pub(crate) desired: EnvironmentResizeResources,
    pub(crate) active_session_count: i32,
    pub(crate) execution_mode: String,
    pub(crate) reason: String,
    pub(crate) warnings: Vec<String>,
}

fn parse_resize_binary_quantity(value: &str, units: &[&str], label: &str) -> anyhow::Result<i32> {
    let value = value.trim();
    let lowercase = value.to_ascii_lowercase();
    let amount = units
        .iter()
        .find(|unit| lowercase.ends_with(**unit))
        .map(|unit| &value[..value.len() - unit.len()])
        .ok_or_else(|| {
            anyhow::anyhow!("invalid {label} quantity {value:?}; use a value such as 512MB or 8GB")
        })?;
    let amount: i32 = amount
        .parse()
        .with_context(|| format!("invalid {label} quantity {value:?}"))?;
    if amount <= 0 {
        anyhow::bail!("the {label} must be greater than zero");
    }
    Ok(amount)
}

pub(crate) fn parse_resize_memory(value: &str) -> anyhow::Result<i32> {
    let lowercase = value.trim().to_ascii_lowercase();
    if ["mib", "mi", "mb"]
        .iter()
        .any(|unit| lowercase.ends_with(unit))
    {
        return parse_resize_binary_quantity(value, &["mib", "mi", "mb"], "memory");
    }
    let gib = parse_resize_binary_quantity(value, &["gib", "gi", "gb"], "memory")?;
    gib.checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("memory quantity {value:?} is too large"))
}

pub(crate) fn parse_resize_disk(value: &str) -> anyhow::Result<i32> {
    let lowercase = value.trim().to_ascii_lowercase();
    if ["mib", "mi", "mb"]
        .iter()
        .any(|unit| lowercase.ends_with(unit))
    {
        let mib = parse_resize_binary_quantity(value, &["mib", "mi", "mb"], "disk")?;
        if mib % 1024 != 0 {
            anyhow::bail!("disk quantity must resolve to a whole GB");
        }
        return Ok(mib / 1024);
    }
    parse_resize_binary_quantity(value, &["gib", "gi", "gb"], "disk")
}

fn format_resize_cpu(millicores: i32) -> String {
    if millicores % 1000 == 0 {
        (millicores / 1000).to_string()
    } else {
        format!("{millicores}m")
    }
}

fn format_resize_memory(memory_mb: i32) -> String {
    if memory_mb % 1024 == 0 {
        format!("{} Gi", memory_mb / 1024)
    } else {
        format!("{memory_mb} Mi")
    }
}

fn format_resize_disk(disk_gb: i32) -> String {
    format!("{disk_gb} Gi")
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn resolve_native_resize_plan(
    args: &EnvResizeArgs,
    current: NativeResizeResources,
    active_sessions: Vec<String>,
) -> anyhow::Result<NativeResizePlan> {
    const GIB: u64 = 1024 * 1024 * 1024;
    let vcpus = match args.cpu.as_deref() {
        Some(value) => local_vm_vcpus(value)?,
        None => current.vcpus,
    };
    let memory_mib = match args.memory.as_deref() {
        Some(value) => u32::try_from(parse_resize_memory(value)?)
            .ok()
            .filter(|value| (128..=65_536).contains(value))
            .ok_or_else(|| anyhow::anyhow!("native memory must be from 128Mi through 64Gi"))?,
        None => current.memory_mib,
    };
    let disk_bytes = match args.disk.as_deref() {
        Some(value) => {
            let gib = u64::try_from(parse_resize_disk(value)?)
                .ok()
                .filter(|value| (1..=1024).contains(value))
                .ok_or_else(|| anyhow::anyhow!("native disk must be from 1Gi through 1024Gi"))?;
            gib.checked_mul(GIB)
                .ok_or_else(|| anyhow::anyhow!("native disk quantity is too large"))?
        }
        None => current.disk_bytes,
    };
    if disk_bytes < current.disk_bytes {
        anyhow::bail!(
            "native state disk shrink is not supported (current: {}, requested: {})",
            format_native_disk(current.disk_bytes),
            format_native_disk(disk_bytes)
        );
    }
    let desired = NativeResizeResources {
        vcpus,
        memory_mib,
        disk_bytes,
    };
    if desired == current {
        anyhow::bail!("the environment already has the requested resources");
    }
    Ok(NativeResizePlan {
        current,
        desired,
        active_sessions,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn format_native_disk(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes.is_multiple_of(GIB) {
        format!("{} Gi", bytes / GIB)
    } else {
        format!("{bytes} bytes")
    }
}

/// The local VMM a native environment runs on.
#[cfg(not(target_os = "macos"))]
pub(crate) const NATIVE_VMM_NAME: &str = "Cloud Hypervisor";
#[cfg(target_os = "macos")]
pub(crate) const NATIVE_VMM_NAME: &str = "Virtualization.framework";

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn format_native_resize_plan(name: &str, plan: &NativeResizePlan) -> String {
    let mut output = format!(
        "Environment: {name} (local · {NATIVE_VMM_NAME})\n\n              Current   Desired\nCPU       {:<9} {}\nMemory    {:<9} {}\nDisk      {:<9} {}\n\n",
        plan.current.vcpus,
        plan.desired.vcpus,
        format_resize_memory(plan.current.memory_mib as i32),
        format_resize_memory(plan.desired.memory_mib as i32),
        format_native_disk(plan.current.disk_bytes),
        format_native_disk(plan.desired.disk_bytes),
    );
    if plan.active_sessions.is_empty() {
        output.push_str("Active sessions: none\n");
    } else {
        output.push_str(&format!(
            "Active sessions ({}): {}\n",
            plan.active_sessions.len(),
            plan.active_sessions.join(", ")
        ));
        output.push_str("The required VM restart will terminate these sessions.\n");
    }
    output.push_str(
        "Codewire will stop the VM, grow the disk offline if requested, and restore its prior running state. Disk growth cannot be reversed.\n",
    );
    output
}

pub(crate) fn resolve_platform_resize_plan(
    args: &EnvResizeArgs,
    current: EnvironmentResizeResources,
) -> anyhow::Result<PlatformResizePlan> {
    let desired = EnvironmentResizeResources {
        cpu_millicores: args
            .cpu
            .as_deref()
            .map(parse_resize_cpu)
            .transpose()?
            .unwrap_or(current.cpu_millicores),
        memory_mb: args
            .memory
            .as_deref()
            .map(parse_resize_memory)
            .transpose()?
            .unwrap_or(current.memory_mb),
        disk_gb: args
            .disk
            .as_deref()
            .map(parse_resize_disk)
            .transpose()?
            .unwrap_or(current.disk_gb),
    };
    if desired.disk_gb < current.disk_gb {
        anyhow::bail!(
            "persistent disk shrink is not supported (current: {}, requested: {})",
            format_resize_disk(current.disk_gb),
            format_resize_disk(desired.disk_gb)
        );
    }
    if desired == current {
        anyhow::bail!("the environment already has the requested resources");
    }
    Ok(PlatformResizePlan {
        current,
        desired,
        active_session_count: 0,
        execution_mode: String::new(),
        reason: String::new(),
        warnings: Vec::new(),
    })
}

pub(crate) fn format_platform_resize_plan(name: &str, plan: &PlatformResizePlan) -> String {
    let mut output = format!(
        "Environment: {name} (cloud)\n\n              Current   Requested\nCPU       {:<9} {}\nMemory    {:<9} {}\nDisk      {:<9} {}\n\n",
        format_resize_cpu(plan.current.cpu_millicores),
        format_resize_cpu(plan.desired.cpu_millicores),
        format_resize_memory(plan.current.memory_mb),
        format_resize_memory(plan.desired.memory_mb),
        format_resize_disk(plan.current.disk_gb),
        format_resize_disk(plan.desired.disk_gb),
    );
    output.push_str(&format!("Execution: {}\n", plan.execution_mode));
    if !plan.reason.is_empty() {
        output.push_str(&format!("Reason: {}\n", plan.reason));
    }
    if plan.active_session_count == 0 {
        output.push_str("Active sessions: none\n");
    } else {
        output.push_str(&format!("Active sessions: {}\n", plan.active_session_count,));
    }
    for warning in &plan.warnings {
        output.push_str(&format!("Warning: {warning}\n"));
    }
    output
}

pub(crate) fn resize_requires_interactive_wizard(
    args: &EnvResizeArgs,
    stdin_is_terminal: bool,
) -> anyhow::Result<bool> {
    let has_resources = args.cpu.is_some() || args.memory.is_some() || args.disk.is_some();
    let interactive = stdin_is_terminal && matches!(args.output, OutputFormat::Text);
    if !has_resources {
        if interactive {
            return Ok(true);
        }
        anyhow::bail!(
            "non-interactive resize requires at least one of --cpu, --memory, or --disk and --yes"
        );
    }
    if !interactive && !args.yes {
        anyhow::bail!("non-interactive resize requires --yes after explicit resource validation");
    }
    Ok(false)
}

pub(crate) fn validate_platform_resize_force(
    active_session_count: i32,
    execution_mode: &str,
    force: bool,
    interactive: bool,
) -> anyhow::Result<()> {
    if !interactive && execution_mode == "restart" && active_session_count > 0 && !force {
        anyhow::bail!(
            "active sessions would be terminated; non-interactive platform resize requires --force"
        );
    }
    Ok(())
}

/// Refuse an unconsented replacement with the planner's reason, such as a VM
/// that the runtime sizes only when the Pod starts.
pub(crate) fn platform_resize_restart_consent_error(reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        return "this resize requires workspace Pod replacement; non-interactive use requires --allow-restart".into();
    }
    format!(
        "this resize requires workspace Pod replacement ({reason}); non-interactive use requires --allow-restart"
    )
}

fn prompt_resize_quantity(label: &str, current: &str) -> anyhow::Result<Option<String>> {
    eprint!("{label} [{current}]: ");
    std::io::stderr()
        .flush()
        .context("flush resize wizard prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read resize wizard input")?;
    Ok(trimmed_optional(Some(input)))
}

impl EnvDaemonCommand {
    pub(super) fn environment(&self) -> Option<&str> {
        match self {
            Self::Status(args) | Self::Repair(args) => args.environment.as_deref(),
            Self::Logs(args) => args.environment.as_deref(),
        }
    }

    fn command_name(&self) -> &'static str {
        match self {
            Self::Status(_) => "daemon status",
            Self::Logs(_) => "daemon logs",
            Self::Repair(_) => "daemon repair",
        }
    }

    fn with_environment(mut self, environment: String) -> Self {
        match &mut self {
            Self::Status(args) | Self::Repair(args) => args.environment = Some(environment),
            Self::Logs(args) => args.environment = Some(environment),
        }
        self
    }
}

/// Why and when a create the platform ended failed.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct FailedCreate {
    /// `no_capacity` or `container_start_failed`.
    pub(crate) code: String,
    pub(crate) reason: String,
    /// RFC 3339, when the platform removed it.
    pub(crate) at: String,
}

impl FailedCreate {
    pub(crate) fn of(environment: &Environment) -> Option<Self> {
        environment.failed_create().then(|| Self {
            code: environment.error_code.clone().unwrap_or_default(),
            reason: environment.error_reason.clone().unwrap_or_default(),
            at: environment.failed_create_time().to_owned(),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct UnifiedEnvironmentListEntry {
    #[serde(rename = "type")]
    pub(crate) environment_type: String,
    pub(crate) name: String,
    pub(crate) placement: String,
    pub(crate) selected: bool,
    pub(crate) state: String,
    /// Running again without anyone asking: whether, when and why (#5997).
    #[serde(flatten)]
    pub(crate) restart: info::UnplannedRestart,
    /// A create the platform ended; `state` is then `failed` (#4482).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failed: Option<FailedCreate>,
    /// Why a stopped cloud sandbox was stopped: user, credit or idle (#3384).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stop_reason: Option<String>,
    /// A running sandbox whose VM is paused; `state` stays `running` (#5529).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) suspended: bool,
    pub(crate) daemon_health: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) id: String,
}

async fn handle_unified_environment_create(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    mut args: Box<EnvCreateArgs>,
) -> anyhow::Result<()> {
    let placement = super::launch_setup::prepare_create(placement, &mut args)?;
    host_placement::refuse_local(&args, placement == Some(EnvironmentPlacement::Local))?;
    if args.environment_type == EnvironmentTypeArg::Host {
        #[cfg(unix)]
        {
            validate_host_create(&args, placement)?;
            return create_host_environment(&args).await;
        }
        #[cfg(not(unix))]
        anyhow::bail!("trusted host environments are currently qualified only on Linux");
    }
    if args.snapshot.is_some() && placement == Some(EnvironmentPlacement::Platform) {
        return Box::pin(snapshot::create_environments_from_platform_snapshot(
            globals, *args,
        ))
        .await;
    }
    if args.snapshot.is_some() || args.checkpoint.is_some() {
        // A local disk snapshot lives on this host, so its environments do too.
        if placement == Some(EnvironmentPlacement::Platform) {
            anyhow::bail!("a cloud environment cannot start from a VM checkpoint yet");
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return Box::pin(create_native_environments_from_snapshot(globals, *args)).await;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("local disk snapshots need a Linux host or a Mac");
    }
    match placement {
        Some(EnvironmentPlacement::Local) => {
            let output = args.output;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                native_create_selected(&args)?;
                let caps = super::lifecycle_output::capabilities(output);
                let Some(created) =
                    Box::pin(create_native_environment(globals, *args, &caps)).await?
                else {
                    return Ok(());
                };
                print_native_created(&created, output, &caps).await?;
                print_created_https(&created.environment.name, output).await;
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = (globals, output, args);
                anyhow::bail!("local environments need Linux or macOS")
            }
        }
        Some(EnvironmentPlacement::Platform) | None => {
            reject_local_create_options(&args)?;
            handle_platform_env_command(globals, EnvCommand::Create(args)).await
        }
    }
}

async fn handle_unified_environment_list(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvListArgs,
) -> anyhow::Result<()> {
    let inventory = inventory::environment_inventory(
        globals,
        placement,
        &inventory::InventoryOptions::listing(&args),
    )
    .await?;
    if let Some(error) = inventory.listing_failure() {
        return Err(error);
    }
    let entries: Vec<UnifiedEnvironmentListEntry> = inventory
        .entries
        .into_iter()
        .map(|entry| entry.list)
        .collect();
    print_unified_environment_list(&entries, args.output)
}

async fn handle_unified_environment_info(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvInfoArgs,
) -> anyhow::Result<()> {
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "info").await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            let environment = get_native_environment(&name).await?;
            // Managed conversations are read only while the VM runs (#2982).
            let attention = if environment.state
                == codewire_local_vmm::control::v1::EnvironmentState::Running as i32
            {
                Some(
                    super::sessions::agents::managed_attention(
                        globals,
                        super::sessions::agents::AttentionEnvironment::Native(Box::new(
                            environment.clone(),
                        )),
                    )
                    .await,
                )
            } else {
                None
            };
            super::native::print_native_environment_info(
                &environment,
                args.output,
                attention.as_ref(),
            )
        }
        UnifiedEnvironmentTarget::Platform(id) => {
            handle_platform_env_command(
                globals,
                EnvCommand::Info(EnvInfoArgs {
                    environment: id,
                    output: args.output,
                }),
            )
            .await
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn active_native_resize_sessions(
    environment: &codewire_local_vmm::control::v1::Environment,
) -> anyhow::Result<Vec<String>> {
    if environment.state != codewire_local_vmm::control::v1::EnvironmentState::Running as i32 {
        return Ok(Vec::new());
    }
    let sessions = native_environment_session_client(&environment.name)
        .await?
        .list()
        .await?;
    Ok(sessions
        .into_iter()
        .filter(|session| {
            !matches!(
                session.state.as_known(),
                Some(
                    codewire_client::EnvironmentSessionState::Stopped
                        | codewire_client::EnvironmentSessionState::Exited
                        | codewire_client::EnvironmentSessionState::Failed
                        | codewire_client::EnvironmentSessionState::Interrupted
                )
            )
        })
        .map(|session| session.session_id)
        .collect())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_native_environment_resize(
    name: String,
    mut args: EnvResizeArgs,
) -> anyhow::Result<()> {
    let environment = get_native_environment(&name).await?;
    let current = NativeResizeResources {
        vcpus: environment.vcpus,
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
    };
    let interactive = stdin_is_interactive();
    if resize_requires_interactive_wizard(&args, interactive)? {
        args.cpu = prompt_resize_quantity("CPU", &current.vcpus.to_string())?;
        args.memory =
            prompt_resize_quantity("Memory", &format_resize_memory(current.memory_mib as i32))?;
        args.disk = prompt_resize_quantity("Disk", &format_native_disk(current.disk_bytes))?;
    }
    let active_sessions = active_native_resize_sessions(&environment).await?;
    let plan = resolve_native_resize_plan(&args, current, active_sessions)?;
    if !plan.active_sessions.is_empty() && !args.force && !interactive {
        anyhow::bail!("active sessions would be terminated; pass --force to resize without asking");
    }
    if matches!(args.output, OutputFormat::Text) {
        print!("{}", format_native_resize_plan(&name, &plan));
    }
    if !args.yes && !prompt_confirm_default_no("Apply this resize")? {
        println!("Aborted.");
        return Ok(());
    }
    let resized = resize_native_environment(
        &name,
        plan.desired.vcpus,
        plan.desired.memory_mib,
        plan.desired.disk_bytes,
    )
    .await?;
    print_native_environment(&resized, args.output)
}

async fn handle_unified_environment_resize(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    mut args: EnvResizeArgs,
) -> anyhow::Result<()> {
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "resize").await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            handle_native_environment_resize(name, args).await
        }
        UnifiedEnvironmentTarget::Platform(environment_id) => {
            args.environment = environment_id;
            handle_platform_env_command(globals, EnvCommand::Resize(args)).await
        }
    }
}

async fn handle_platform_environment_resize(
    client: &EnvironmentClient,
    org_id: &str,
    mut args: EnvResizeArgs,
) -> anyhow::Result<()> {
    let environment_id = resolve_environment_id(client, org_id, &args.environment).await?;
    let environment = client
        .get_environment(org_id, &environment_id)
        .await
        .context("get environment before resize")?;
    let current = EnvironmentResizeResources {
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
    };
    if resize_requires_interactive_wizard(&args, stdin_is_interactive())? {
        args.cpu = prompt_resize_quantity("CPU", &format_resize_cpu(current.cpu_millicores))?;
        args.memory = prompt_resize_quantity("Memory", &format_resize_memory(current.memory_mb))?;
        args.disk = prompt_resize_quantity("Disk", &format_resize_disk(current.disk_gb))?;
    }
    let requested = resolve_platform_resize_plan(&args, current)?;
    let runtime_plan = client
        .plan_environment_resize(org_id, &environment_id, &requested.desired)
        .await
        .context("plan platform environment resize")?;
    let plan = PlatformResizePlan {
        current: runtime_plan.previous_resources,
        desired: runtime_plan.desired_resources,
        active_session_count: runtime_plan.active_session_count,
        execution_mode: runtime_plan.execution_mode,
        reason: runtime_plan.reason,
        warnings: runtime_plan.warnings,
    };
    let interactive = stdin_is_interactive() && matches!(args.output, OutputFormat::Text);
    if !interactive && plan.execution_mode == "restart" && !args.allow_restart {
        anyhow::bail!("{}", platform_resize_restart_consent_error(&plan.reason));
    }
    validate_platform_resize_force(
        plan.active_session_count,
        &plan.execution_mode,
        args.force,
        interactive,
    )?;
    if matches!(args.output, OutputFormat::Text) {
        print!("{}", format_platform_resize_plan(&args.environment, &plan));
    }
    if interactive
        && plan.execution_mode == "restart"
        && !args.allow_restart
        && !prompt_confirm_default_no(
            "Kubernetes cannot apply this live. Delete and replace the workspace Pod while preserving its PVC",
        )?
    {
        println!("Aborted.");
        return Ok(());
    }
    if !args.yes && !prompt_confirm_default_no("Apply this resize")? {
        println!("Aborted.");
        return Ok(());
    }

    let allow_restart = args.allow_restart || (interactive && plan.execution_mode == "restart");
    let force = args.force
        || (interactive && plan.execution_mode == "restart" && plan.active_session_count > 0);
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let (mut result, mut poll_interval) = client
        .resize_environment(
            org_id,
            &environment_id,
            &plan.desired,
            &request_id,
            force,
            allow_restart,
        )
        .await
        .context("start platform environment resize")?;
    let mut last_state = String::new();
    while matches!(
        result.operation.state.as_str(),
        "pending" | "applying" | "restarting"
    ) {
        if matches!(args.output, OutputFormat::Text) && result.operation.state != last_state {
            eprintln!("Resize: {}", result.operation.state);
            last_state.clone_from(&result.operation.state);
        }
        tokio::time::sleep(poll_interval.unwrap_or(Duration::from_secs(1))).await;
        (result, poll_interval) = client
            .get_environment_resize_operation(org_id, &environment_id, &result.operation.id)
            .await
            .context("follow platform environment resize")?;
    }

    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Text if result.operation.state == "completed" => {
            let applied = &result.operation.last_applied_resources;
            println!(
                "Resize completed: CPU {}, memory {}, disk {}.",
                format_resize_cpu(applied.cpu_millicores),
                format_resize_memory(applied.memory_mb),
                format_resize_disk(applied.disk_gb)
            );
        }
        OutputFormat::Text => {}
    }
    if result.operation.state == "failed" {
        let failure = result.operation.failure.unwrap_or_default();
        anyhow::bail!(
            "platform resize failed ({}): {}",
            failure.code,
            failure.message
        );
    }
    Ok(())
}

async fn handle_unified_environment_daemon_command(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: EnvDaemonCommand,
) -> anyhow::Result<()> {
    let target = resolve_unified_environment_daemon_target(globals, placement, &command).await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            handle_native_environment_daemon_command(&name, command).await
        }
        UnifiedEnvironmentTarget::Platform(environment_id) => {
            handle_platform_env_command(
                globals,
                EnvCommand::Daemon(EnvDaemonArgs {
                    command: command.with_environment(environment_id),
                }),
            )
            .await
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_native_environment_daemon_command(
    name: &str,
    command: EnvDaemonCommand,
) -> anyhow::Result<()> {
    let client = native_environment_diagnostic_client(name).await?;
    match command {
        EnvDaemonCommand::Status(args) => {
            let status = client
                .daemon_status()
                .await
                .context("get native environment daemon status")?;
            let status = crate::environment_client::legacy_environment_daemon_status(status);
            print_environment_daemon_status(&status, args.output)?;
        }
        EnvDaemonCommand::Logs(_) => {
            let logs = client
                .daemon_logs()
                .await
                .context("get native environment daemon logs")?;
            std::io::stdout()
                .write_all(&logs)
                .context("write native environment daemon logs")?;
        }
        EnvDaemonCommand::Repair(args) => {
            let repair = client
                .repair_daemon()
                .await
                .context("repair native environment daemon")?;
            let repair = EnvironmentDaemonRepair {
                status: crate::environment_client::legacy_environment_daemon_status(repair.status),
                replaced_pod_name: repair.replaced_pod_name,
            };
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&repair)?),
                OutputFormat::Text => {
                    println!(
                        "Environment daemon repaired: {}",
                        display_str(&repair.status.state)
                    );
                    print!("{}", format_environment_daemon_status(&repair.status));
                }
            }
        }
    }
    Ok(())
}

async fn resolve_unified_environment_daemon_target(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: &EnvDaemonCommand,
) -> anyhow::Result<UnifiedEnvironmentTarget> {
    if let Some(environment) = command.environment().and_then(trimmed_str) {
        return resolve_unified_environment_target(
            globals,
            placement,
            environment,
            command.command_name(),
        )
        .await;
    }

    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let unselected = || {
        anyhow::anyhow!(
            "no environment selected; use `cw use ENV` or pass ENV to `cw {}`",
            command.command_name()
        )
    };
    let current = config::current_target(&paths.mesh_data_dir).map_err(|_| unselected())?;
    if current == config::default_current_target() {
        return Err(unselected());
    }
    match (placement, current.kind.as_str()) {
        (Some(EnvironmentPlacement::Local), "env") => {
            anyhow::bail!("the selected environment is platform-backed; pass a local ENV")
        }
        (Some(EnvironmentPlacement::Platform), "local") => {
            anyhow::bail!("the selected environment is local; pass a platform ENV")
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (_, "local") if !current.target_ref.trim().is_empty() => {
            let environment = native_environment(&current.target_ref)
                .await?
                .ok_or_else(|| anyhow::anyhow!("selected local environment was not found"))?;
            Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name))
        }
        (_, "env") if !current.target_ref.trim().is_empty() => {
            Ok(UnifiedEnvironmentTarget::Platform(current.target_ref))
        }
        _ => Err(unselected()),
    }
}

async fn handle_unified_environment_lifecycle(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: UnifiedEnvironmentLifecycle,
) -> anyhow::Result<()> {
    let target = resolve_unified_environment_target(
        globals,
        placement,
        command.environment(),
        command.command_name(),
    )
    .await?;
    match (target, command) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (UnifiedEnvironmentTarget::NativeLocal(name), UnifiedEnvironmentLifecycle::Start(args)) => {
            Box::pin(start_native_environment(globals, &name, &args)).await
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (UnifiedEnvironmentTarget::NativeLocal(name), UnifiedEnvironmentLifecycle::Stop(args)) => {
            Box::pin(stop_native_environment(&name, args.output)).await
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (
            UnifiedEnvironmentTarget::NativeLocal(name),
            UnifiedEnvironmentLifecycle::Restart(args),
        ) => Box::pin(restart_native_environment(globals, &name, args.output)).await,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (
            UnifiedEnvironmentTarget::NativeLocal(name),
            UnifiedEnvironmentLifecycle::Remove(args),
        ) => Box::pin(remove_native_environment(&name, args.yes, args.output)).await,
        (UnifiedEnvironmentTarget::Platform(id), UnifiedEnvironmentLifecycle::Start(args)) => {
            handle_platform_env_command(globals, EnvCommand::Start(args.of(id))).await
        }
        (UnifiedEnvironmentTarget::Platform(id), UnifiedEnvironmentLifecycle::Stop(args)) => {
            handle_platform_env_command(
                globals,
                EnvCommand::Stop(EnvTargetArgs {
                    environment: id,
                    output: args.output,
                }),
            )
            .await
        }
        (UnifiedEnvironmentTarget::Platform(_), UnifiedEnvironmentLifecycle::Restart(_)) => {
            anyhow::bail!("restart is supported only for local environments")
        }
        (UnifiedEnvironmentTarget::Platform(id), UnifiedEnvironmentLifecycle::Remove(args)) => {
            handle_platform_env_command(
                globals,
                EnvCommand::Rm(EnvDeleteArgs {
                    environment: id,
                    yes: args.yes,
                    output: args.output,
                }),
            )
            .await
        }
    }
}

/// A removed local VM is no longer the current environment: clear the
/// selection when it named that VM. Nothing else becomes selected.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn reconcile_native_current_after_delete(deleted_name: &str) {
    let cleared = ResolvePaths::from_env(&OsEnv)
        .map_err(anyhow::Error::from)
        .and_then(|paths| {
            Ok(clear_removed_local_selection(
                &paths.mesh_data_dir,
                deleted_name,
            )?)
        });
    if let Err(error) = cleared {
        eprintln!("Warning: could not clear the current environment: {error:#}");
    }
}

/// Clears the selection when it is the removed local VM, matched by its
/// name: names are unique among existing VMs, and a selection by ID of a
/// VM with this name was this VM or one already gone.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn clear_removed_local_selection(
    data_dir: &std::path::Path,
    deleted_name: &str,
) -> Result<bool, config::ConfigError> {
    config::selection::clear_if(data_dir, |selection| {
        selection.location == config::selection::SelectionLocation::Local
            && (selection.name == deleted_name || selection.id == deleted_name)
    })
}

async fn handle_unified_environment_refresh_skills(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvTargetArgs,
) -> anyhow::Result<()> {
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "refresh-skills")
            .await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            let environment = refresh_native_environment_skills(&name).await?;
            print_native_environment(&environment, args.output)
        }
        UnifiedEnvironmentTarget::Platform(_) => {
            anyhow::bail!("refresh-skills is supported only for local environments")
        }
    }
}

pub(crate) async fn resolve_unified_environment_target(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    target_ref: &str,
    command: &str,
) -> anyhow::Result<UnifiedEnvironmentTarget> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let target_ref = trimmed_required(target_ref, "environment")?;
    #[cfg(unix)]
    if resolve_host_reference(globals, target_ref, placement)
        .await?
        .is_some()
    {
        anyhow::bail!("trusted host environments don't support `cw {command}`");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let native = match placement {
        Some(EnvironmentPlacement::Platform) => LocalAnswer::Absent,
        Some(EnvironmentPlacement::Local) => match native_environment(target_ref).await? {
            Some(environment) => {
                return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
            }
            None => anyhow::bail!("local environment {target_ref:?} not found"),
        },
        // Without a placement a local supervisor that cannot be asked never
        // blocks the cloud (#3560).
        None => LocalAnswer::ask(target_ref).await,
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if placement == Some(EnvironmentPlacement::Local) {
        anyhow::bail!("local environments need Linux or macOS");
    }

    let platform = match resolve_platform(globals, &paths, &env) {
        Ok(platform) => platform,
        Err(error) if placement.is_none() && command != "update" => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            match native {
                LocalAnswer::Found(environment) => {
                    return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
                }
                // Neither side could answer: the local failure is the one
                // that applies, since the cloud is not set up here.
                LocalAnswer::Unavailable(local) => return Err(local),
                LocalAnswer::Absent => {}
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let environment_client = EnvironmentClient::new(&platform)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let environments = environment_client
        .list_environments(&org_id, false)
        .await
        .context("list environments")?;
    let mut platform_match = find_environment_match(&environments, target_ref)?;
    // `cw ls` shows a create the platform ended, so the two commands that can
    // answer for one find it too. A live environment of the same name wins.
    if platform_match.is_none() && matches!(command, "info" | "rm") {
        let failed: Vec<Environment> = environment_client
            .list_environments_and_failed_creates(&org_id, false)
            .await
            .context("list environments")?
            .into_iter()
            .filter(Environment::failed_create)
            .collect();
        platform_match = find_environment_match(&failed, target_ref)?;
    }

    if placement == Some(EnvironmentPlacement::Platform) {
        let Some((id, _)) = platform_match else {
            return Err(super::lifecycle_output::no_cloud_environment(target_ref));
        };
        return Ok(UnifiedEnvironmentTarget::Platform(id));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match choose_placement(target_ref, native, platform_match, || {
        ambiguous_environment_placement_error(command, target_ref)
    })? {
        PlacementChoice::Local(environment) => {
            Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name))
        }
        PlacementChoice::Cloud {
            id,
            local_unavailable,
        } => {
            if let Some(local) = &local_unavailable {
                report_cloud_answered(target_ref, local);
            }
            Ok(UnifiedEnvironmentTarget::Platform(id))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    match platform_match {
        Some((id, _)) => Ok(UnifiedEnvironmentTarget::Platform(id)),
        None => anyhow::bail!("environment {target_ref:?} not found"),
    }
}

/// The platform answers daemon status only for a running Sandbox; every other
/// state is refused and shown as unavailable. Asking only running rows keeps
/// the output and stops `cw ls --all` from slowing down and collecting
/// errors as the history of destroyed environments grows.
pub(crate) fn environment_has_daemon(environment: &Environment) -> bool {
    environment.state == "running"
}

pub(crate) async fn platform_environment_daemon_health(
    client: &EnvironmentClient,
    org_id: &str,
    environments: Vec<Environment>,
) -> Vec<(Environment, String)> {
    let mut entries = Vec::with_capacity(environments.len());
    for environment in environments {
        let daemon_health = if environment_has_daemon(&environment) {
            client
                .get_environment_daemon_status(org_id, &environment.id)
                .await
                .map(|status| status.state)
                .unwrap_or_else(|_| "unavailable".to_string())
        } else {
            "unavailable".to_string()
        };
        entries.push((environment, daemon_health));
    }
    entries
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn ambiguous_environment_placement_error(
    command: &str,
    target_ref: &str,
) -> anyhow::Error {
    anyhow::anyhow!(
        "environment {target_ref:?} exists in both placements; use `cw --local {command} {target_ref}` or `cw --cloud {command} {target_ref}`"
    )
}

/// `cw update ENV --policy POLICY` on hosted: the selection changes in
/// place; nothing restarts (#4000).
async fn update_platform_network_policy(
    globals: &Globals,
    environment_client: &EnvironmentClient,
    org_id: &str,
    environment: &str,
    reference: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let environment_id = resolve_environment_id(environment_client, org_id, environment).await?;
    let client = super::guided_credentials::platform_client(globals)?;
    let response = client
        .update_environment_network_policy(codewire_client::UpdateEnvironmentNetworkPolicyRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.clone(),
            network_policy: reference.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(server_errors::network_policy_selection)?;
    let selected = response
        .network_policy
        .as_option()
        .map(crate::environment_client::environment_network_policy_from_proto)
        .context("the platform returned no network policy selection")?;
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&selected)?),
        OutputFormat::Text => {
            // By the time it gets here the environment is an ID; text names it.
            let shown = environment_client
                .get_environment(org_id, &environment_id)
                .await
                .map(|found| super::platform_commands::environment_display_name(&found).to_owned())
                .unwrap_or_else(|_| environment.to_owned());
            println!("Network policy for {shown}: {}", selected.summary());
            report_policy_selection(reference, &shown, Some(&selected));
        }
    }
    Ok(())
}

pub(crate) fn reject_local_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    if args.backend.is_some()
        || args.path.is_some()
        || args.path_mode.is_some()
        || args.spec.is_some()
        || args.docker_disk.is_some()
        || args.no_docker
    {
        anyhow::bail!(
            "--backend, --path, --path-mode, --spec, --docker-disk, and --no-docker require `cw create --local`"
        );
    }
    Ok(())
}

fn print_unified_environment_list(
    entries: &[UnifiedEnvironmentListEntry],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(entries)?),
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("No environments found.");
                return Ok(());
            }
            println!(
                "{:<24} {:<10} {:<10} {:<9} {:<14} DAEMON",
                "NAME", "TYPE", "PLACEMENT", "SELECTED", "STATE"
            );
            for entry in entries {
                println!(
                    "{:<24} {:<10} {:<10} {:<9} {:<14} {}",
                    entry.name,
                    entry.environment_type,
                    entry.placement,
                    if entry.selected { "yes" } else { "" },
                    display_str(&entry.state),
                    display_str(&entry.daemon_health),
                );
            }
        }
    }
    Ok(())
}

async fn wait_for_platform_environment_daemon_ready(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    setup::await_daemon_ready(client.codewire(), org_id, environment_id)
        .await
        .map_err(|error| daemon_wait_error(environment_id, error))
}

fn daemon_wait_error(environment_id: &str, error: DaemonWaitError) -> anyhow::Error {
    match error {
        DaemonWaitError::GetEnvironment(error) => {
            get_environment_error(error).context("get environment")
        }
        DaemonWaitError::PlatformEnded(facts, end) => progress::platform_end_error(&facts, end),
        DaemonWaitError::Unusable { state, message } => {
            let status = EnvironmentDaemonStatus {
                state,
                message,
                ..Default::default()
            };
            environment_daemon_readiness(&status)
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("environment daemon is not ready"))
        }
        DaemonWaitError::Left(state) => anyhow::anyhow!(
            "environment {environment_id:?} became {state} before its daemon was ready"
        ),
        DaemonWaitError::DaemonTimeout(seen) => anyhow::anyhow!(
            "timed out waiting for environment {environment_id:?} daemon to become ready: {}",
            daemon_observation(seen)
        ),
        DaemonWaitError::LifecycleTimeout(seen) => anyhow::anyhow!(
            "timed out waiting for environment {environment_id:?} to reach running state: {}",
            daemon_observation(seen)
        ),
    }
}

fn daemon_observation(seen: DaemonObservation) -> String {
    match seen {
        DaemonObservation::Starting => "daemon is still starting".to_owned(),
        DaemonObservation::StatusFailed(error) => display_client_error(error).to_string(),
        DaemonObservation::NoStatus => "GetEnvironmentDaemonStatus returned no status".to_owned(),
        DaemonObservation::Environment(state) => format!("environment is {state}"),
    }
}

pub(crate) fn environment_daemon_readiness(
    status: &EnvironmentDaemonStatus,
) -> anyhow::Result<bool> {
    match status.state.as_str() {
        "ready" => Ok(true),
        "starting" | "" => Ok(false),
        "upgrade_required" | "unsupported" => {
            anyhow::bail!("environment daemon requires an upgrade; run `cw daemon repair`")
        }
        "unhealthy" => {
            let detail = trimmed_str(&status.message).unwrap_or("no diagnostic message");
            anyhow::bail!(
                "environment daemon is unhealthy ({detail}); run `cw daemon status` or `cw daemon repair`"
            );
        }
        state => anyhow::bail!(
            "environment daemon reported unknown state {state:?}; run `cw daemon status`"
        ),
    }
}

async fn handle_environment_daemon_command(
    client: &EnvironmentClient,
    org_id: &str,
    command: EnvDaemonCommand,
) -> anyhow::Result<()> {
    match command {
        EnvDaemonCommand::Status(args) => {
            let environment = trimmed_required(
                args.environment.as_deref().unwrap_or_default(),
                "environment",
            )?;
            let environment_id = resolve_environment_id(client, org_id, environment).await?;
            let status = client
                .get_environment_daemon_status(org_id, &environment_id)
                .await
                .context("get environment daemon status")?;
            print_environment_daemon_status(&status, args.output)?;
        }
        EnvDaemonCommand::Logs(args) => {
            let environment = trimmed_required(
                args.environment.as_deref().unwrap_or_default(),
                "environment",
            )?;
            let environment_id = resolve_environment_id(client, org_id, environment).await?;
            let data = client
                .get_environment_daemon_logs(org_id, &environment_id)
                .await
                .context("get environment daemon logs")?;
            std::io::stdout()
                .write_all(&data)
                .context("write environment daemon logs")?;
        }
        EnvDaemonCommand::Repair(args) => {
            let environment = trimmed_required(
                args.environment.as_deref().unwrap_or_default(),
                "environment",
            )?;
            let environment_id = resolve_environment_id(client, org_id, environment).await?;
            let repair = client
                .repair_environment_daemon(org_id, &environment_id)
                .await
                .context("repair environment daemon")?;
            match args.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&repair)?);
                }
                OutputFormat::Text => {
                    println!(
                        "Environment daemon repaired: {} (pod {})",
                        display_str(&repair.status.state),
                        display_str(&repair.replaced_pod_name)
                    );
                    print!("{}", format_environment_daemon_status(&repair.status));
                }
            }
        }
    }
    Ok(())
}

fn print_environment_daemon_status(
    status: &EnvironmentDaemonStatus,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(status)?),
        OutputFormat::Text => print!("{}", format_environment_daemon_status(status)),
    }
    Ok(())
}

pub(crate) fn format_environment_daemon_status(status: &EnvironmentDaemonStatus) -> String {
    let mut output = format!(
        "Environment daemon: {}\n  Version: {}\n  Protocol: {} (minimum {})\n",
        display_str(&status.state),
        display_str(&status.daemon_version),
        status.protocol_version,
        status.minimum_protocol_version,
    );
    if !status.pod_name.is_empty() {
        output.push_str(&format!("  Pod: {}\n", status.pod_name));
    }
    if !status.message.is_empty() {
        output.push_str(&format!("  Message: {}\n", status.message));
    }
    if !status.capabilities.is_empty() {
        output.push_str(&format!(
            "  Capabilities: {}\n",
            status.capabilities.join(", ")
        ));
    }
    for diagnostic in &status.diagnostics {
        output.push_str(&format!(
            "  {}: {}{}\n",
            display_str(&diagnostic.name),
            if diagnostic.healthy {
                "healthy"
            } else {
                "unhealthy"
            },
            if diagnostic.message.is_empty() {
                String::new()
            } else {
                format!(" ({})", diagnostic.message)
            }
        ));
    }
    output
}

/// `--write-preset` and `cw init`: the request's project as codewire.yaml.
pub(crate) fn write_resolved_codewire_yaml(
    path: &Path,
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let data = codewire_yaml_from_request(request)?;
    fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// The request's portable project, which is all a cloud create declares.
pub(crate) fn codewire_yaml_from_request(
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<String> {
    Ok(codewire_project::ProjectDocument::new(
        request.project_spec.clone(),
        codewire_project::LocalProjectIntent::default(),
        true,
    )
    .to_yaml()?)
}

pub(crate) fn create_preset_request_from_environment(
    name: &str,
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<CreatePresetRequest> {
    let name = trimmed_required(name, "preset name")?;
    let slug = slugify_preset_name(name);
    if slug.is_empty() {
        anyhow::bail!("preset name is required");
    }
    let mut project_spec = request.project_spec.clone();
    project_spec.preset.clear();
    project_spec.validate()?;
    Ok(CreatePresetRequest {
        name: name.to_string(),
        slug,
        default_ttl_seconds: request.ttl_seconds,
        project_spec,
        ..Default::default()
    })
}

pub(crate) fn slugify_preset_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

pub(crate) fn collect_env_create_repos(
    repo_urls: &[String],
    repo_flags: &[String],
    branch: Option<&str>,
) -> anyhow::Result<Vec<codewire_project::RepositorySpec>> {
    let mut inputs = Vec::new();
    for spec in repo_urls.iter().chain(repo_flags.iter()) {
        let (url, repo_branch, mount_path) = parse_env_create_repo_spec(spec)?;
        inputs.push((url, repo_branch, mount_path));
    }
    if branch.is_some() && inputs.len() > 1 {
        anyhow::bail!("--branch can be used only with one repository");
    }
    if let (Some(branch), Some((_, repo_branch, _))) = (branch, inputs.first_mut())
        && repo_branch.is_empty()
    {
        *repo_branch = branch.to_string();
    }
    let destinations = codewire_project::validate_repository_destinations(
        inputs
            .iter()
            .map(|(source, _, destination)| (source.as_str(), destination.as_str())),
    )?;
    Ok(inputs
        .into_iter()
        .zip(destinations)
        .map(|((source, branch, _), destination)| {
            // A github.com SSH source gets GitHub's published host keys;
            // any other SSH source still needs pins from a project file,
            // and validation says so.
            let known_hosts =
                codewire_project::canonical_repository_known_hosts(&source, Vec::new())
                    .unwrap_or_default();
            codewire_project::RepositorySpec {
                source,
                branch,
                destination,
                revision: String::new(),
                known_hosts,
            }
        })
        .collect())
}

pub(crate) fn parse_env_create_repo_spec(spec: &str) -> anyhow::Result<(String, String, String)> {
    let spec = trimmed_required(spec, "repo URL")?;
    let (repo_spec, mount_path) = match spec.rsplit_once("::") {
        Some((repo_spec, mount_path)) if mount_path.starts_with('/') => {
            (repo_spec, mount_path.to_string())
        }
        _ => (spec, String::new()),
    };
    let Some(idx) = repo_spec.rfind('@') else {
        return Ok((repo_spec.to_string(), String::new(), mount_path));
    };
    let (url, branch_with_at) = repo_spec.split_at(idx);
    // The `@` of `git@host:` or of `ssh://git@host/` names the SSH user, not
    // a branch: a branch follows a repository path.
    let has_path = match url.split_once("://") {
        Some((_, authority_and_path)) => authority_and_path.contains('/'),
        None => url.contains('/'),
    };
    if !has_path {
        return Ok((repo_spec.to_string(), String::new(), mount_path));
    }
    let branch = &branch_with_at[1..];
    Ok((url.to_string(), branch.to_string(), mount_path))
}

pub(crate) async fn handle_env_share_command(
    client: &EnvironmentClient,
    org_id: &str,
    command: EnvShareCommand,
) -> anyhow::Result<()> {
    match command {
        EnvShareCommand::List(args) => {
            let environment_id = resolve_environment_id(client, org_id, &args.environment).await?;
            let grants = client
                .list_environment_access(org_id, &environment_id)
                .await
                .context("list access")?;
            print_env_access_list(&grants, args.output)?;
        }
        EnvShareCommand::Grant(args) => {
            let user_id = trimmed_str(&args.user)
                .ok_or_else(|| anyhow::anyhow!("--user is required"))?
                .to_string();
            let permission = trimmed_str(&args.permission)
                .unwrap_or("viewer")
                .to_string();
            let environment_id = resolve_environment_id(client, org_id, &args.environment).await?;
            let grant = client
                .grant_environment_access(
                    org_id,
                    &environment_id,
                    &GrantEnvironmentAccessRequest {
                        user_id: user_id.clone(),
                        permission: permission.clone(),
                    },
                )
                .await
                .context("grant access")?;
            print_env_access_grant(
                &args.environment,
                &user_id,
                &permission,
                &grant,
                args.output,
            )?;
        }
        EnvShareCommand::Revoke(args) => {
            let user_id =
                trimmed_str(&args.user).ok_or_else(|| anyhow::anyhow!("--user is required"))?;
            let environment_id = resolve_environment_id(client, org_id, &args.environment).await?;
            client
                .revoke_environment_access(org_id, &environment_id, user_id)
                .await
                .context("revoke access")?;
            print_env_access_revoke(&args.environment, user_id, args.output)?;
        }
    }
    Ok(())
}

pub(crate) async fn handle_env_cp_command(
    environment_client: &EnvironmentClient,
    org_id: &str,
    args: EnvCpArgs,
) -> anyhow::Result<()> {
    let (src_remote, dst_remote) = env_cp_remote_paths(&args.src, &args.dst)?;

    match (src_remote, dst_remote) {
        (Some(_), Some(_)) | (None, None) => unreachable!("validated copy direction"),
        (None, Some((dst_env, dst_path))) => {
            let environment_id =
                resolve_environment_id(environment_client, org_id, dst_env).await?;
            upload_cloud_file(
                environment_client,
                org_id,
                &environment_id,
                Path::new(&args.src),
                dst_path,
            )
            .await?;
            print!(
                "{}",
                format_env_cp_upload_text(&args.src, &environment_id, dst_path)
            );
        }
        (Some((src_env, src_path)), None) => {
            let environment_id =
                resolve_environment_id(environment_client, org_id, src_env).await?;
            let responses = environment_client
                .download_environment_file(org_id, &environment_id, src_path)
                .await
                .context("download")?;
            let written = transfer::download_to_file(Path::new(&args.dst), responses)
                .await
                .context("download")?;
            print!(
                "{}",
                format_env_cp_download_text(&environment_id, src_path, &args.dst, written)
            );
        }
    }

    Ok(())
}

/// A file over one part goes up in resumable parts, which pass the request
/// body cap at the platform's edge and resume when the same copy is run
/// again (#4373). A server without them gets the file in one request.
async fn upload_cloud_file(
    environment_client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    source: &Path,
    destination: &str,
) -> anyhow::Result<()> {
    let len = fs::metadata(source).context("open local file")?.len();
    if len > transfer::PART_BYTES {
        let upload_id = transfer::upload_id(source, environment_id, destination)?;
        let upload_id = upload_id.as_str();
        let uploaded = transfer::upload_resumable(source, |offset, finish, chunks| async move {
            environment_client
                .upload_environment_file_part(
                    org_id,
                    environment_id,
                    destination,
                    upload_id,
                    offset,
                    finish,
                    chunks,
                )
                .await
                .map(|held| transfer::PartHeld {
                    size: u64::try_from(held.size).unwrap_or(0),
                    finished: held.finished,
                })
                .map_err(|error| {
                    if error.code() == codewire_client::ErrorCode::Unimplemented {
                        transfer::PartError::Unsupported
                    } else {
                        transfer::PartError::Failed(
                            crate::environment_client::display_client_error(error),
                        )
                    }
                })
        })
        .await
        .context("upload")?;
        if let transfer::Resumable::Uploaded = uploaded {
            return Ok(());
        }
    }
    transfer::upload_from_file(source, |chunks| {
        environment_client.upload_environment_file(org_id, environment_id, destination, chunks)
    })
    .await
    .with_context(|| {
        if len > transfer::PART_BYTES {
            "upload; this server takes no resumable uploads, and a file this large may pass its request size limit"
        } else {
            "upload"
        }
    })?;
    Ok(())
}

pub(crate) type EnvRemotePath<'a> = (&'a str, &'a str);

pub(crate) fn env_cp_remote_paths<'a>(
    src: &'a str,
    dst: &'a str,
) -> anyhow::Result<(Option<EnvRemotePath<'a>>, Option<EnvRemotePath<'a>>)> {
    let src_remote = parse_env_remote_path(src);
    let dst_remote = parse_env_remote_path(dst);
    match (src_remote, dst_remote) {
        (Some(_), Some(_)) => anyhow::bail!("cannot copy between two remote environments"),
        (None, None) => anyhow::bail!("at least one path must be remote (<env_id>:<path>)"),
        paths => Ok(paths),
    }
}

pub(crate) fn parse_env_remote_path(input: &str) -> Option<(&str, &str)> {
    let idx = input.find(':')?;
    if idx == 0 || idx == 1 {
        return None;
    }
    Some((&input[..idx], &input[idx + 1..]))
}

pub(crate) fn format_env_cp_upload_text(
    local_path: &str,
    environment_id: &str,
    remote_path: &str,
) -> String {
    format!("Uploaded {local_path} -> {environment_id}:{remote_path}\n")
}

pub(crate) fn format_env_cp_download_text(
    environment_id: &str,
    remote_path: &str,
    local_path: &str,
    bytes: u64,
) -> String {
    format!("Downloaded {environment_id}:{remote_path} -> {local_path} ({bytes} bytes)\n")
}

pub(crate) async fn handle_env_port_command(
    environment_client: &EnvironmentClient,
    org_id: &str,
    data_dir: &Path,
    args: EnvPortTarget,
) -> anyhow::Result<()> {
    let environment_id = resolve_port_environment_id(
        environment_client,
        org_id,
        data_dir,
        args.environment.as_deref(),
    )
    .await?;
    match args.operation {
        PortOperation::List => {
            let ports = environment_client
                .list_environment_ports(org_id, &environment_id)
                .await
                .context("list ports")?;
            print_env_port_list(&ports, args.output)?;
        }
        PortOperation::Publish {
            port,
            host_port,
            label,
            access,
        } => {
            anyhow::ensure!(
                host_port.is_none(),
                "--host-port applies to local environments; a cloud port is published as a preview URL"
            );
            let labelled = label.as_deref().and_then(trimmed_str).is_some();
            let label = label
                .as_deref()
                .and_then(trimmed_str)
                .map(str::to_owned)
                .unwrap_or_else(|| default_port_label(port));
            let access = access
                .as_deref()
                .and_then(trimmed_str)
                .unwrap_or("creator")
                .to_string();
            let environment = environment_client
                .get_environment(org_id, &environment_id)
                .await
                .context("get environment")?;
            let name = environment_display_name(&environment).to_owned();
            anyhow::ensure!(
                environment.state == "running",
                "environment {name} is {}; start it with `cw start {name}`, then publish the port",
                display_str(&environment.state)
            );
            let result = environment_client
                .create_environment_port(
                    org_id,
                    &environment_id,
                    &CreateEnvironmentPortRequest {
                        port: i32::from(port),
                        label,
                        access,
                    },
                )
                .await
                .map_err(|error| server_errors::port_create_failed(&name, port, labelled, error))?;
            print_env_port_add(&result, args.output)?;
        }
        PortOperation::Unpublish {
            port,
            host_port,
            label,
        } => {
            anyhow::ensure!(
                host_port.is_none(),
                "--host-port applies to local environments; a cloud preview is selected by its port and --label"
            );
            let ports = environment_client
                .list_environment_ports(org_id, &environment_id)
                .await
                .context("list ports")?;
            let target = select_unpublished_preview(&ports, port, label.as_deref())?;
            environment_client
                .delete_environment_port(org_id, &environment_id, &target.id)
                .await
                .context("delete port")?;
            print_env_port_rm(&target, args.output)?;
        }
    }
    Ok(())
}

/// The preview label `cw ports ENV --publish PORT` uses without `--label`.
pub(crate) fn default_port_label(port: u16) -> String {
    format!("port-{port}")
}

/// The one cloud preview of a guest port; `--label` chooses among several.
pub(crate) fn select_unpublished_preview(
    ports: &[EnvironmentPort],
    port: u16,
    label: Option<&str>,
) -> anyhow::Result<EnvironmentPort> {
    let matches: Vec<&EnvironmentPort> = ports
        .iter()
        .filter(|candidate| candidate.port == i32::from(port))
        .filter(|candidate| label.is_none_or(|label| candidate.label == label))
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => anyhow::bail!("no preview publishes port {port}"),
        several => anyhow::bail!(
            "port {port} is published as {}; choose one with --label",
            several
                .iter()
                .map(|candidate| candidate.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub(crate) async fn resolve_port_environment_id(
    client: &EnvironmentClient,
    org_id: &str,
    data_dir: &Path,
    env_ref: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(env_ref) = env_ref.and_then(trimmed_str) {
        return resolve_environment_id(client, org_id, env_ref).await;
    }

    let current = config::current_target(data_dir).map_err(|_| {
        anyhow::anyhow!("no environment named and none selected; pass ENV or run `cw use ENV`")
    })?;
    if current.kind != "env" || trimmed_str(&current.target_ref).is_none() {
        anyhow::bail!("no environment named and none selected; pass ENV or run `cw use ENV`");
    }
    resolve_environment_id(client, org_id, &current.target_ref).await
}

/// `cw logs ENV --setup --follow`: renders rows until the stream's terminal row,
/// resuming after the last rendered row when the connection drops.
pub(crate) async fn follow_environment_logs(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let feed = progress::PlatformLogFeed {
        client,
        org_id,
        environment_id,
    };
    let mut view = StartProgress::for_logs(
        std::io::stderr(),
        &progress::text_progress_capabilities(),
        Instant::now(),
        "Waiting for logs",
    );
    let mut cursor = None;
    let result =
        progress::follow_start_progress(&feed, &mut view, &mut cursor, &FollowPolicy::default())
            .await;
    view.finish()?;
    // A failed stage was rendered; following it successfully is not an error.
    result.map(|_| ())
}

/// `cw create`: every setup stage through `complete`, then daemon
/// readiness. Exits non-zero when a stage fails.
async fn wait_for_platform_environment_setup(
    client: &EnvironmentClient,
    org_id: &str,
    environment: &Environment,
    began: Instant,
    caps: &crate::output::Capabilities,
) -> anyhow::Result<()> {
    let environment_id = environment.id.as_str();
    let feed = progress::PlatformLogFeed {
        client,
        org_id,
        environment_id,
    };
    let mut view = StartProgress::new(std::io::stderr(), caps, began, "Starting");
    progress::await_environment_setup(
        &feed,
        &mut view,
        &FollowPolicy::default(),
        &terminal_text(&lifecycle::display_name(environment)),
        progress::watch_setup_failure(client, org_id, environment_id),
        || async {
            wait_for_platform_environment_daemon_ready(client, org_id, environment_id)
                .await
                .context("wait for environment daemon readiness")
        },
    )
    .await
}

pub(crate) fn print_environment_logs_historical(logs: &[EnvironmentLog]) {
    if logs.is_empty() {
        println!("No logs yet.");
        return;
    }
    eprint!(
        "{}",
        format_environment_logs_plain(logs, &progress::text_progress_capabilities())
    );
}

pub(crate) fn filter_environments(
    environments: &[Environment],
    environment_type: Option<&str>,
    state: Option<&str>,
    all: bool,
    failed_creates: bool,
) -> Vec<Environment> {
    let environment_type = environment_type.and_then(trimmed_str);
    let state = state.and_then(trimmed_str);
    environments
        .iter()
        .filter(|environment| {
            environment_type.is_none_or(|wanted| environment.environment_type == wanted)
        })
        .filter(|environment| state.is_none_or(|wanted| environment.state == wanted))
        .filter(|environment| {
            all || environment.state != "destroyed"
                || (failed_creates && environment.failed_create())
        })
        .cloned()
        .collect()
}

/// `cw info` for a cloud environment and, while it runs, its managed
/// conversations that need attention (#2982). The JSON gains
/// `agents_attention` only when one does.
pub(crate) fn print_env_info(
    environment: &Environment,
    output: OutputFormat,
    attention: Option<&super::sessions::agents::ManagedAttentionReport>,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => {
            let mut value = serde_json::to_value(environment)?;
            if let Some(entries) =
                attention.and_then(super::sessions::agents::managed_attention_json)
            {
                value["agents_attention"] = entries;
            }
            println!("{}", serde_json::to_string_pretty(&value)?)
        }
        OutputFormat::Text => {
            let mut text = format_env_info_text(environment);
            for row in attention
                .map(super::sessions::agents::managed_attention_rows)
                .unwrap_or_default()
            {
                text.push_str(&format!("{:<14} {row}\n", "Attention:"));
            }
            print!("{text}")
        }
    }
    Ok(())
}

pub(crate) fn print_env_report(
    report: &EnvironmentTrustReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => print!("{}", format_env_report_text(report)),
    }
    Ok(())
}

pub(crate) fn format_env_report_text(report: &EnvironmentTrustReport) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "Environment report: {}\n",
        display_str(&report.environment.id)
    ));
    output.push_str(&format!(
        "  Trust level: {}\n",
        display_str(&report.summary.trust_level)
    ));
    output.push_str(&format!(
        "  Production verified: {}\n",
        if report.summary.production_verified {
            "yes"
        } else {
            "no"
        }
    ));
    output.push_str(&format!(
        "  Environment: {} ({})\n",
        display_str(&report.environment.environment_type),
        display_str(&report.environment.state)
    ));
    output.push_str(&format!(
        "  Isolation: {}\n",
        display_str(&report.environment.isolation_tier)
    ));
    output.push_str(&format!(
        "  Runtime: {} / RuntimeClass {} / handler {}\n",
        display_str(&report.runtime.profile),
        display_str(&report.runtime.runtime_class),
        display_str(&report.runtime.handler)
    ));
    output.push_str(&format!(
        "  Confidential: {}\n",
        if report.runtime.confidential {
            "yes"
        } else {
            "no"
        }
    ));
    output.push_str("  Placement:\n");
    output.push_str(&format!(
        "    Namespace: {}\n",
        display_opt(report.placement.namespace.as_deref())
    ));
    output.push_str(&format!(
        "    Workspace pod: {}\n",
        display_opt(report.placement.workspace_pod.as_deref())
    ));
    output.push_str(&format!(
        "    Pod IP: {}\n",
        display_opt(report.placement.pod_ip.as_deref())
    ));
    output.push_str(&format!(
        "    Node: {}\n",
        display_opt(report.placement.node.as_deref())
    ));
    output.push_str(&format!(
        "    Zone: {}\n",
        display_opt(report.placement.zone.as_deref())
    ));
    output.push_str(&format!(
        "    Region: {}\n",
        display_opt(report.placement.region.as_deref())
    ));
    output.push_str("  Images:\n");
    output.push_str(&format!(
        "    Workspace: {}\n",
        display_opt(report.images.workspace_image.as_deref())
    ));
    output.push_str(&format!(
        "    Workspace image ID: {}\n",
        display_opt(report.images.workspace_image_id.as_deref())
    ));
    output.push_str(&format!(
        "    DinD: {}\n",
        display_opt(report.images.dind_image.as_deref())
    ));
    output.push_str(&format!(
        "    DinD image ID: {}\n",
        display_opt(report.images.dind_image_id.as_deref())
    ));
    output.push_str(&format!(
        "    Daemon init: {}\n",
        display_opt(report.images.daemon_init_image.as_deref())
    ));
    output.push_str(&format!(
        "    Daemon init image ID: {}\n",
        display_opt(report.images.daemon_init_image_id.as_deref())
    ));
    output.push_str(&format!(
        "  Provenance: {}\n",
        display_str(&report.provenance.status)
    ));
    output.push_str(&format!(
        "    Guest kernel: {}\n",
        display_opt(report.provenance.guest_kernel.as_deref())
    ));
    output.push_str(&format!(
        "    Guest initrd: {}\n",
        display_opt(report.provenance.guest_initrd.as_deref())
    ));
    output.push_str(&format!(
        "    Guest image: {}\n",
        display_opt(report.provenance.guest_image.as_deref())
    ));
    output.push_str(&format!(
        "    Firmware: {}\n",
        display_opt(report.provenance.firmware.as_deref())
    ));
    output.push_str(&format!(
        "    Source: {}\n",
        display_opt(report.provenance.source.as_deref())
    ));
    if !report.provenance.notes.is_empty() {
        output.push_str("    Notes:\n");
        for note in &report.provenance.notes {
            output.push_str(&format!("      - {}\n", note));
        }
    }
    output.push_str(&format!(
        "  Attestation: {} ({})\n",
        display_str(&report.attestation.status),
        display_str(&report.attestation.tee)
    ));
    output.push_str(&format!(
        "    Report available: {}\n",
        if report.attestation.report_available {
            "yes"
        } else {
            "no"
        }
    ));
    output.push_str(&format!(
        "    Source: {}\n",
        display_opt(report.attestation.report_source.as_deref())
    ));
    for (key, value) in &report.attestation.metadata {
        output.push_str(&format!("    {}: {}\n", key, display_str(value)));
    }
    output.push_str(&format!(
        "  Trustee: {}\n",
        display_str(&report.trustee.status)
    ));
    output.push_str(&format!(
        "    Resource: {}\n",
        display_opt(report.trustee.resource_uri.as_deref())
    ));
    output.push_str(&format!(
        "    Reference values: {}\n",
        display_opt(report.trustee.reference_values.as_deref())
    ));
    output.push_str(&format!(
        "    Policy: {}\n",
        display_opt(report.trustee.policy.as_deref())
    ));
    if !report.trustee.evidence_issues.is_empty() {
        output.push_str(&format!(
            "    Evidence issues: {}\n",
            report.trustee.evidence_issues.join(", ")
        ));
    }
    if !report.summary.warnings.is_empty() {
        output.push_str("  Warnings:\n");
        for warning in &report.summary.warnings {
            output.push_str(&format!("    - {}\n", warning));
        }
    }
    output
}

pub(crate) fn display_str(value: &str) -> &str {
    trimmed_str(value).unwrap_or("--")
}

pub(crate) fn display_opt(value: Option<&str>) -> &str {
    value.and_then(trimmed_str).unwrap_or("--")
}

pub(crate) fn print_env_status(
    environment_ref: &str,
    response: &StatusResponse,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
        OutputFormat::Text => print!("{}", format_env_status_text(environment_ref, response)),
    }
    Ok(())
}

pub(crate) fn format_env_status_text(environment_ref: &str, response: &StatusResponse) -> String {
    format!(
        "Environment {}: {}.\n",
        environment_ref,
        trimmed_str(&response.status).unwrap_or("unknown")
    )
}

pub(crate) fn print_env_extend_status(
    environment_ref: &str,
    response: &StatusResponse,
    hours: i32,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
        OutputFormat::Text => print!(
            "{}",
            format_env_extend_status_text(environment_ref, response, hours)
        ),
    }
    Ok(())
}

pub(crate) fn format_env_extend_status_text(
    environment_ref: &str,
    response: &StatusResponse,
    hours: i32,
) -> String {
    format!(
        "Environment {}: {} ({} hours added).\n",
        environment_ref,
        trimmed_str(&response.status).unwrap_or("unknown"),
        hours
    )
}

pub(crate) fn print_env_access_list(
    grants: &[EnvironmentAccessGrant],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(grants)?),
        OutputFormat::Text => print!("{}", format_env_access_list_text(grants)),
    }
    Ok(())
}

pub(crate) fn format_env_access_list_text(grants: &[EnvironmentAccessGrant]) -> String {
    if grants.is_empty() {
        return "No explicit access grants (creator has implicit owner access).\n".to_string();
    }

    let mut output = String::from("USER ID\tPERMISSION\tGRANTED BY\tCREATED AT\n");
    for grant in grants {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            grant.user_id, grant.permission, grant.granted_by, grant.created_at
        ));
    }
    output
}

pub(crate) fn print_env_access_grant(
    environment_ref: &str,
    user_id: &str,
    permission: &str,
    grant: &EnvironmentAccessGrant,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(grant)?),
        OutputFormat::Text => print!(
            "{}",
            format_env_access_grant_text(environment_ref, user_id, permission)
        ),
    }
    Ok(())
}

pub(crate) fn format_env_access_grant_text(
    environment_ref: &str,
    user_id: &str,
    permission: &str,
) -> String {
    format!("Granted {permission} access to {environment_ref} for user {user_id}.\n")
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct EnvAccessRevokeResult<'a> {
    pub(crate) environment: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) revoked: bool,
}

pub(crate) fn print_env_access_revoke(
    environment_ref: &str,
    user_id: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&EnvAccessRevokeResult {
                environment: environment_ref,
                user_id,
                revoked: true,
            })?
        ),
        OutputFormat::Text => print!(
            "{}",
            format_env_access_revoke_text(environment_ref, user_id)
        ),
    }
    Ok(())
}

pub(crate) fn format_env_access_revoke_text(environment_ref: &str, user_id: &str) -> String {
    format!("Revoked access for user {user_id} on {environment_ref}.\n")
}

pub(crate) fn print_env_port_add(
    port: &EnvironmentPort,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(port)?),
        OutputFormat::Text => print!("{}", format_env_port_add_text(port)),
    }
    Ok(())
}

pub(crate) fn format_env_port_add_text(port: &EnvironmentPort) -> String {
    let mut output = format!("  * Port {} registered as {}\n", port.port, port.label);
    if !port.preview_url.is_empty() {
        output.push_str(&format!("  URL: {}\n", port.preview_url));
    }
    output.push_str(&format!("  Access: {}\n", port.access));
    output
}

pub(crate) fn print_env_port_list(
    ports: &[EnvironmentPort],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(ports)?),
        OutputFormat::Text => print!("{}", format_env_port_list_text(ports)),
    }
    Ok(())
}

pub(crate) fn format_env_port_list_text(ports: &[EnvironmentPort]) -> String {
    if ports.is_empty() {
        return "No ports registered.\n".to_string();
    }

    let mut output = String::from("PORT\tLABEL\tACCESS\tPREVIEW URL\n");
    for port in ports {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            port.port, port.label, port.access, port.preview_url
        ));
    }
    output
}

pub(crate) fn print_env_port_rm(
    port: &EnvironmentPort,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(port)?),
        OutputFormat::Text => print!("{}", format_env_port_rm_text(port)),
    }
    Ok(())
}

pub(crate) fn format_env_port_rm_text(port: &EnvironmentPort) -> String {
    format!("  * Port {} ({}) removed\n", port.port, port.label)
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct EnvDeleteResult<'a> {
    pub(crate) environment: &'a str,
    pub(crate) environment_id: &'a str,
    pub(crate) deleted: bool,
}

/// The JSON delete result. `deleted` is false only when the platform
/// scheduled the deletion behind its grace period.
pub(crate) fn print_env_delete_result(
    environment_ref: &str,
    environment_id: &str,
    deleted: bool,
) -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&EnvDeleteResult {
            environment: environment_ref,
            environment_id,
            deleted,
        })?
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnvBulkSelection {
    pub(crate) targets: Vec<Environment>,
    pub(crate) skipped_protected: usize,
}

pub(crate) fn parse_prune_states(states: &str) -> BTreeSet<String> {
    states
        .split(',')
        .filter_map(trimmed_str)
        .map(str::to_string)
        .collect()
}

pub(crate) fn select_prune_environments(
    environments: &[Environment],
    states: &BTreeSet<String>,
) -> EnvBulkSelection {
    let mut skipped_protected = 0;
    let mut targets = Vec::new();

    for environment in environments {
        if !states.contains(environment.state.as_str()) {
            continue;
        }
        if environment.protected {
            skipped_protected += 1;
            continue;
        }
        targets.push(environment.clone());
    }

    EnvBulkSelection {
        targets,
        skipped_protected,
    }
}

pub(crate) fn select_nuke_environments(environments: &[Environment]) -> EnvBulkSelection {
    let mut skipped_protected = 0;
    let mut targets = Vec::new();

    for environment in environments {
        if environment.protected {
            skipped_protected += 1;
            continue;
        }
        targets.push(environment.clone());
    }

    EnvBulkSelection {
        targets,
        skipped_protected,
    }
}

pub(crate) fn print_env_bulk_skipped(skipped_protected: usize) {
    if skipped_protected > 0 {
        eprintln!("  Skipped {skipped_protected} protected environment(s).");
    }
}

pub(crate) fn format_env_prune_targets_text(environments: &[Environment]) -> String {
    format_env_bulk_targets_text(environments, true)
}

pub(crate) fn format_env_nuke_targets_text(environments: &[Environment]) -> String {
    format_env_bulk_targets_text(environments, false)
}

pub(crate) fn format_env_bulk_targets_text(
    environments: &[Environment],
    include_age: bool,
) -> String {
    let mut output = if include_age {
        String::from("ID\tNAME\tSTATE\tAGE\n")
    } else {
        String::from("ID\tNAME\tSTATE\n")
    };
    let now = Utc::now();

    for environment in environments {
        if include_age {
            output.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                short_env_id(&environment.id),
                environment_display_name(environment),
                env_state_label(environment),
                time_ago_at(env_created_label(environment), now),
            ));
        } else {
            output.push_str(&format!(
                "{}\t{}\t{}\n",
                short_env_id(&environment.id),
                environment_display_name(environment),
                env_state_label(environment),
            ));
        }
    }

    output
}

pub(crate) async fn delete_environment_targets(
    client: &EnvironmentClient,
    org_id: &str,
    targets: &[Environment],
) -> usize {
    let mut deleted = 0;

    for environment in targets {
        if let Err(err) = client.delete_environment(org_id, &environment.id).await {
            eprintln!("Failed to delete {}: {err}", environment.id);
            continue;
        }
        println!("Deleted {}.", env_bulk_label(environment));
        deleted += 1;
    }

    deleted
}

pub(crate) fn env_bulk_label(environment: &Environment) -> String {
    match environment.name.as_deref().and_then(trimmed_str) {
        Some(name) => format!("{} ({name})", environment.id),
        None => environment.id.clone(),
    }
}
