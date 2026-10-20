use std::path::Path;

use super::*;
use crate::commands::progress::terminal_text;

pub(crate) mod progress;
mod runtime;
mod sources;

use progress::{FollowPolicy, StartProgress, format_env_ready_text, format_environment_logs_plain};

// Match the server-owned sandbox lifecycle first, then give daemon setup its
// own post-running window. Confidential guests deliberately have a longer boot
// horizon; one fixed three-minute stopwatch reports false failure while the
// accepted server operation is still progressing.
const PLATFORM_READY_TIMEOUT: Duration = Duration::from_secs(600);
const PLATFORM_CONFIDENTIAL_READY_TIMEOUT: Duration = Duration::from_secs(1800);
const PLATFORM_DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(180);

/// The hosted Mesh network a new cloud environment asks to join. A cloud
/// environment's resolver is pinned to its platform's hosted Mesh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CloudMeshRequest {
    pub(crate) mesh_url: String,
    /// `None` before the current organization is known.
    pub(crate) organization_id: Option<String>,
    pub(crate) network_id: String,
}

/// Refuses an explicit `--network` on a cloud create before anything is
/// requested or allocated: `local:NAME` can never join a cloud environment,
/// and a hosted attachment awaits credential-free runtime enrollment.
pub(crate) fn refuse_requested_cloud_mesh(
    platform: &config::ResolvedPlatformConfig,
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
    Err(cloud_mesh_attachment_refusal(&CloudMeshRequest {
        mesh_url: mesh_commands::selection::hosted_mesh_url(platform)?,
        organization_id: platform.default_org.clone(),
        network_id: requested.network,
    }))
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

/// The explicit refusal of a cloud environment's Mesh attachment, until
/// credential-free runtime enrollment exists. It is returned before any
/// source preparation or allocation.
pub(crate) fn cloud_mesh_attachment_refusal(request: &CloudMeshRequest) -> anyhow::Error {
    let organization = request
        .organization_id
        .as_deref()
        .map(|organization| format!(" (organization {})", terminal_text(organization)))
        .unwrap_or_default();
    anyhow::anyhow!(
        "a cloud environment cannot join Codewire Cloud Mesh network cloud:{} at {}{organization} yet: that needs credential-free runtime enrollment, which is not implemented. No environment was created; create it with --no-network",
        terminal_text(&request.network_id),
        terminal_text(&request.mesh_url),
    )
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
        EnvCommand::Update(update) => {
            handle_unified_environment_update(globals, placement, update).await
        }
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

async fn handle_unified_environment_cp(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvCpArgs,
) -> anyhow::Result<()> {
    let (src_remote, dst_remote) = env_cp_remote_paths(&args.src, &args.dst)?;
    let target_ref = src_remote
        .or(dst_remote)
        .map(|(environment, _)| environment)
        .expect("validated copy direction has one remote environment");
    let target = resolve_unified_environment_target(globals, placement, target_ref, "cp").await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => match (src_remote, dst_remote) {
            (None, Some((_environment, remote_path))) => {
                let data = fs::read(&args.src).context("open local file")?;
                native_environment_data_client(&name)
                    .await?
                    .upload_file(remote_path, &data)
                    .await
                    .context("upload")?;
                print!(
                    "{}",
                    format_env_cp_upload_text(&args.src, &name, remote_path)
                );
                Ok(())
            }
            (Some((_environment, remote_path)), None) => {
                let downloaded = native_environment_data_client(&name)
                    .await?
                    .download_file(remote_path)
                    .await
                    .context("download")?;
                let mut out = fs::File::create(&args.dst).context("create local file")?;
                out.write_all(&downloaded.data)
                    .context("write local file")?;
                print!(
                    "{}",
                    format_env_cp_download_text(
                        &name,
                        remote_path,
                        &args.dst,
                        downloaded.data.len(),
                    )
                );
                Ok(())
            }
            _ => unreachable!("validated copy direction"),
        },
        UnifiedEnvironmentTarget::Platform(_) => {
            let env = OsEnv;
            let paths = ResolvePaths::from_env(&env)?;
            let platform = resolve_platform(globals, &paths, &env)?;
            let orgs = organization_client(&platform)?.list_orgs().await?;
            let org_id = current_org_id(&platform, &orgs)?;
            let environment_client = EnvironmentClient::new(&platform)?;
            handle_env_cp_command(&environment_client, &org_id, args).await
        }
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
            (Some(EnvironmentPlacement::Local), None) => Some(
                native_selected_environment()
                    .await?
                    .map(|environment| environment.name)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no local environment selected; pass ENV or run `cw use --local ENV`"
                        )
                    })?,
            ),
            (None, None) => selected_local_environment_name().await?,
        };
        if let Some(name) = local {
            return handle_native_environment_port(&name, args.operation, args.output).await;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if placement == Some(EnvironmentPlacement::Local) {
        anyhow::bail!("native local environments currently require Linux or macOS");
    }
    handle_platform_env_command(globals, EnvCommand::Port(args)).await
}

/// The selected environment's name when it is a local VM.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn selected_local_environment_name() -> anyhow::Result<Option<String>> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    match config::current_target(&paths.mesh_data_dir) {
        Ok(target) if target.kind == "env" || target.kind == "host" => Ok(None),
        Ok(target) if target.kind == "local" && target.target_ref != "local" => {
            Ok(Some(target.target_ref))
        }
        _ => Ok(native_selected_environment()
            .await?
            .map(|environment| environment.name)),
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
                anyhow::bail!("native local environment access currently requires Linux or macOS")
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

pub(crate) async fn handle_platform_env_command(
    globals: &Globals,
    command: EnvCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    // An explicit network on a cloud create is refused before any request.
    if let EnvCommand::Create(args) = &command {
        refuse_requested_cloud_mesh(&platform, args.network.as_deref(), args.no_network)?;
    }
    let environment_client = EnvironmentClient::new(&platform)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;

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
        EnvCommand::Create(args) => {
            let began = Instant::now();
            let mut request = prepare_platform_env_create_request(&args)?;
            if let Some(request) = resolve_env_create_mesh_bootstrap(
                &paths,
                &env,
                &platform,
                &org_id,
                args.yes,
                args.network.as_deref(),
                args.no_network,
            )? {
                return Err(cloud_mesh_attachment_refusal(&request));
            }
            sources::prepare_create_sources(
                &platform,
                &environment_client,
                &org_id,
                &args,
                &mut request,
            )
            .await?;
            let environment = environment_client
                .create_environment(&org_id, &request)
                .await
                .context("create environment")?;
            if args.write_preset {
                write_resolved_codewire_yaml(Path::new("codewire.yaml"), &request)
                    .context("write codewire.yaml")?;
                eprintln!("Preset written: codewire.yaml");
            }
            if let Some(preset_name) = trimmed_optional(args.save_preset.clone()) {
                let preset_request =
                    create_preset_request_from_environment(&preset_name, &request)?;
                let preset = organization_client
                    .create_preset(&org_id, &preset_request)
                    .await
                    .context("save preset")?;
                eprintln!("Preset saved: {} ({}).", preset.name, preset.id);
            }
            match args.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&environment)?)
                }
                OutputFormat::Text => print!("{}", format_env_create_text(&environment)),
            }
            if matches!(args.output, OutputFormat::Text) && args.follow && !args.no_wait {
                wait_for_platform_environment_setup(
                    &environment_client,
                    &org_id,
                    &environment,
                    began,
                )
                .await?;
            }
        }
        EnvCommand::Update(args) => {
            sources::update_platform_sources(&platform, &environment_client, &org_id, args).await?;
        }
        EnvCommand::Info(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let environment = environment_client
                .get_environment(&org_id, &environment_id)
                .await
                .context("get environment")?;
            print_env_info(&environment, args.output)?;
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
        EnvCommand::Stop(args) => {
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            let response = environment_client
                .stop_environment(&org_id, &environment_id)
                .await
                .context("stop environment")?;
            print_env_status(&args.environment, &response, args.output)?;
        }
        EnvCommand::Start(args) => {
            let began = Instant::now();
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            if matches!(args.output, OutputFormat::Text) {
                start_platform_environment_with_progress(
                    &environment_client,
                    &org_id,
                    &environment_id,
                    &args.environment,
                    began,
                )
                .await?;
                return Ok(());
            }
            let response = environment_client
                .start_environment(&org_id, &environment_id)
                .await
                .context("start environment")?;
            wait_for_platform_environment_daemon_ready(
                &environment_client,
                &org_id,
                &environment_id,
            )
            .await
            .context("wait for environment daemon readiness")?;
            print_env_status(&args.environment, &response, args.output)?;
        }
        EnvCommand::Restart(_) => {
            anyhow::bail!("restart is supported only for native local environments");
        }
        EnvCommand::RefreshSkills(_) => {
            anyhow::bail!("refresh-skills is supported only for native local environments");
        }
        EnvCommand::Rm(args) => {
            let _skip_confirmation = args.yes;
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
            if let Err(err) = environment_client
                .delete_environment(&org_id, &environment_id)
                .await
            {
                return Err(map_env_delete_error(&args.environment, err));
            }
            print_env_delete_result(&args.environment, &environment_id, args.output)?;
        }
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
                return Ok(());
            }

            print!("{}", format_env_prune_targets_text(&selection.targets));
            println!();

            if args.dry_run {
                println!(
                    "Would prune {} environments (dry run).",
                    selection.targets.len()
                );
                return Ok(());
            }

            if !args.yes
                && !prompt_confirm_default_no(&format!(
                    "Delete {} environments?",
                    selection.targets.len()
                ))?
            {
                println!("Aborted.");
                return Ok(());
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
                return Ok(());
            }

            println!(
                "This will DELETE ALL {} environments in org {:?}.",
                selection.targets.len(),
                org_id
            );
            println!();
            print!("{}", format_env_nuke_targets_text(&selection.targets));
            println!();

            if !args.yes {
                let expected = format!("nuke {} environments", selection.targets.len());
                if !prompt_exact_confirmation(
                    &format!("Type {:?} to confirm: ", expected),
                    &expected,
                )? {
                    println!("Aborted.");
                    return Ok(());
                }
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
            "environment credential-profile inspection is not yet available for platform environments"
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
    Ok(())
}

#[derive(Debug)]
enum UnifiedEnvironmentLifecycle {
    Start(EnvTargetArgs),
    Stop(EnvTargetArgs),
    Restart(EnvTargetArgs),
    Remove(EnvDeleteArgs),
}

impl UnifiedEnvironmentLifecycle {
    fn environment(&self) -> &str {
        match self {
            Self::Start(args) | Self::Stop(args) | Self::Restart(args) => &args.environment,
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
enum UnifiedEnvironmentTarget {
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

pub(crate) fn parse_resize_cpu(value: &str) -> anyhow::Result<i32> {
    let value = value.trim();
    if let Some(millicores) = value.strip_suffix('m') {
        let millicores: i32 = millicores
            .parse()
            .with_context(|| format!("invalid CPU quantity {value:?}"))?;
        if millicores <= 0 {
            anyhow::bail!("CPU must be greater than zero");
        }
        return Ok(millicores);
    }

    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("invalid CPU quantity {value:?}; use values such as 500m, 0.5, or 4");
    }
    let whole: i32 = whole
        .parse()
        .with_context(|| format!("invalid CPU quantity {value:?}"))?;
    let fractional_millicores = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 3
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let scale = 10_i32.pow((3 - fraction.len()) as u32);
            let fraction: i32 = fraction
                .parse()
                .with_context(|| format!("invalid CPU quantity {value:?}"))?;
            fraction * scale
        }
        _ => anyhow::bail!(
            "invalid CPU quantity {value:?}; CPU fractions may have at most three decimal places"
        ),
    };
    let millicores = whole
        .checked_mul(1000)
        .and_then(|whole| whole.checked_add(fractional_millicores))
        .ok_or_else(|| anyhow::anyhow!("CPU quantity {value:?} is too large"))?;
    if millicores <= 0 {
        anyhow::bail!("CPU must be greater than zero");
    }
    Ok(millicores)
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
        anyhow::bail!("{label} must be greater than zero");
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
        Some(value) => {
            let millicores = parse_resize_cpu(value)?;
            if millicores % 1000 != 0 {
                anyhow::bail!(
                    "native local VMs require whole CPU cores; requested {}",
                    format_resize_cpu(millicores)
                );
            }
            u32::try_from(millicores / 1000)
                .ok()
                .filter(|value| (1..=32).contains(value))
                .ok_or_else(|| anyhow::anyhow!("native CPU must be from 1 through 32 cores"))?
        }
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
        anyhow::bail!("the requested resources already match the native local environment");
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
        anyhow::bail!("the requested resources already match the current platform environment");
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
        "Environment: {name} (platform)\n\n              Current   Requested\nCPU       {:<9} {}\nMemory    {:<9} {}\nDisk      {:<9} {}\n\n",
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

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct UnifiedEnvironmentListEntry {
    #[serde(rename = "type")]
    pub(crate) environment_type: String,
    pub(crate) name: String,
    pub(crate) placement: String,
    pub(crate) selected: bool,
    pub(crate) state: String,
    pub(crate) daemon_health: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) id: String,
}

async fn handle_unified_environment_create(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: Box<EnvCreateArgs>,
) -> anyhow::Result<()> {
    if args.environment_type == EnvironmentTypeArg::Host {
        #[cfg(unix)]
        {
            validate_host_create(&args, placement)?;
            return create_host_environment(&args).await;
        }
        #[cfg(not(unix))]
        anyhow::bail!("trusted host environments are currently qualified only on Linux");
    }
    match placement {
        Some(EnvironmentPlacement::Local) => {
            let output = args.output;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                native_create_selected(&args)?;
                let Some(environment) = create_native_environment(globals, *args).await? else {
                    return Ok(());
                };
                if matches!(output, OutputFormat::Text) {
                    eprintln!("Local environment created: {}.", environment.name);
                }
                print_native_environment(&environment, output)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = (globals, output, args);
                anyhow::bail!("native local environments currently require Linux or macOS")
            }
        }
        Some(EnvironmentPlacement::Platform) | None => {
            reject_local_create_options(&args)?;
            handle_platform_env_command(globals, EnvCommand::Create(args)).await
        }
    }
}

async fn handle_unified_environment_update(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    mut args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    sources::validate_update_args(&args)?;
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "update").await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            args.environment = name;
            handle_native_environment_update(globals, args).await
        }
        UnifiedEnvironmentTarget::Platform(id) => {
            args.environment = id;
            handle_platform_env_command(globals, EnvCommand::Update(args)).await
        }
    }
}

async fn handle_unified_environment_list(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvListArgs,
) -> anyhow::Result<()> {
    let inventory = unified_environment_inventory(globals, placement, &args).await?;
    if let Some(location) = inventory.unavailable.first() {
        anyhow::bail!(
            "{} environments could not be listed: {}",
            location.location,
            location.error
        );
    }
    print_unified_environment_list(&inventory.entries, args.output)
}

/// A location whose environments could not be listed: the local runtime or
/// the cloud. Never shown as an empty list.
#[derive(Debug)]
pub(crate) struct UnavailableLocation {
    pub(crate) location: &'static str,
    pub(crate) error: String,
}

/// The environments the placement admits, sorted by name, and the
/// locations that could not be listed.
#[derive(Debug)]
pub(crate) struct EnvironmentInventory {
    pub(crate) entries: Vec<UnifiedEnvironmentListEntry>,
    pub(crate) unavailable: Vec<UnavailableLocation>,
}

/// Every environment the placement admits, local and cloud. An unconfigured
/// cloud is skipped without a placement; a location that fails to list is
/// reported as unavailable, never as empty, and the other locations are
/// still listed.
pub(crate) async fn unified_environment_inventory(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: &EnvListArgs,
) -> anyhow::Result<EnvironmentInventory> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let mut unavailable = Vec::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let native = if placement != Some(EnvironmentPlacement::Platform)
        && args.environment_type.as_deref() != Some("host")
    {
        native_environments().await.unwrap_or_else(|error| {
            unavailable.push(UnavailableLocation {
                location: "local",
                error: format!("{error:#}"),
            });
            Vec::new()
        })
    } else {
        Vec::new()
    };

    let platform = if placement != Some(EnvironmentPlacement::Local)
        && args.environment_type.as_deref() != Some("host")
        && (placement == Some(EnvironmentPlacement::Platform)
            || resolve_platform(globals, &paths, &env).is_ok())
    {
        let listed = async {
            let platform = resolve_platform(globals, &paths, &env)?;
            let environment_client = EnvironmentClient::new(&platform)?;
            let organization_client = organization_client(&platform)?;
            let orgs = organization_client.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            let environments = environment_client
                .list_environments(&org_id, args.all)
                .await
                .context("list environments")?;
            let filtered = filter_environments(
                &environments,
                args.environment_type.as_deref(),
                args.state.as_deref(),
                args.all,
            );
            anyhow::Ok(
                platform_environment_daemon_health(&environment_client, &org_id, filtered).await,
            )
        }
        .await;
        listed.unwrap_or_else(|error| {
            unavailable.push(UnavailableLocation {
                location: "cloud",
                error: format!("{error:#}"),
            });
            Vec::new()
        })
    } else {
        Vec::new()
    };

    let current = config::current_target(&paths.mesh_data_dir)
        .ok()
        .filter(|target| !(target.kind == "local" && target.target_ref == "local"));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let current = current.filter(|target| {
        target.kind != "local"
            || native.iter().any(|environment| {
                target.target_ref == environment.name || target.target_ref == environment.id
            })
    });
    let current = current.as_ref();
    let mut entries = unified_environment_list_entries(&platform, current);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    entries.extend(
        native
            .iter()
            .map(|environment| UnifiedEnvironmentListEntry {
                environment_type: "sandbox".into(),
                name: environment.name.clone(),
                placement: "local".to_string(),
                selected: native_environment_is_selected(environment, current),
                state: native_state_label(environment.state).to_string(),
                daemon_health: if environment.state
                    == codewire_local_vmm::control::v1::EnvironmentState::Running as i32
                {
                    "ready".to_string()
                } else {
                    "unavailable".to_string()
                },
                id: environment.id.clone(),
            }),
    );
    #[cfg(unix)]
    if placement != Some(EnvironmentPlacement::Platform)
        && args.environment_type.as_deref() != Some("sandbox")
    {
        let hosts = host_environments().unwrap_or_else(|error| {
            unavailable.push(UnavailableLocation {
                location: "trusted host",
                error: format!("{error:#}"),
            });
            Vec::new()
        });
        for environment in hosts {
            let daemon_health = host_daemon_health(&environment).await;
            entries.push(UnifiedEnvironmentListEntry {
                environment_type: "host".into(),
                name: environment.name.clone(),
                placement: "local".into(),
                selected: current
                    .is_some_and(|t| t.kind == "host" && t.target_ref == environment.id),
                state: environment.state,
                id: environment.id,
                daemon_health,
            });
        }
    }
    if let Some(state) = args.state.as_deref() {
        entries.retain(|entry| entry.state.eq_ignore_ascii_case(state));
    }
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.placement.cmp(&right.placement))
    });
    Ok(EnvironmentInventory {
        entries,
        unavailable,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn native_environment_is_selected(
    environment: &codewire_local_vmm::control::v1::Environment,
    current: Option<&config::CurrentTargetConfig>,
) -> bool {
    current.is_some_and(|target| {
        target.kind == "local"
            && (target.target_ref == environment.name || target.target_ref == environment.id)
    }) || (current.is_none() && environment.selected)
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
            print_native_environment(&environment, args.output)
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
        anyhow::bail!(
            "active sessions would be terminated; non-interactive native resize requires --force"
        );
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
    let current = config::current_target(&paths.mesh_data_dir).map_err(|_| {
        anyhow::anyhow!(
            "no environment selected; use `cw use ENV` or pass ENV to `cw {}`",
            command.command_name()
        )
    })?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let default_local = current.kind == "local" && current.target_ref == "local";
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if (placement == Some(EnvironmentPlacement::Local) || (placement.is_none() && default_local))
        && let Some(environment) = native_selected_environment().await?
    {
        return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
    }
    match (placement, current.kind.as_str()) {
        (Some(EnvironmentPlacement::Local), "env") => {
            anyhow::bail!("the selected environment is platform-backed; pass a local ENV")
        }
        (Some(EnvironmentPlacement::Platform), "local") => {
            anyhow::bail!("the selected environment is local; pass a platform ENV")
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (_, "local") if !current.target_ref.trim().is_empty() && !default_local => {
            let environment = native_environment(&current.target_ref)
                .await?
                .ok_or_else(|| anyhow::anyhow!("selected local environment was not found"))?;
            Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name))
        }
        (_, "env") if !current.target_ref.trim().is_empty() => {
            Ok(UnifiedEnvironmentTarget::Platform(current.target_ref))
        }
        _ => anyhow::bail!(
            "no environment selected; use `cw use ENV` or pass ENV to `cw {}`",
            command.command_name()
        ),
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
            let environment = start_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (UnifiedEnvironmentTarget::NativeLocal(name), UnifiedEnvironmentLifecycle::Stop(args)) => {
            let environment = stop_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (
            UnifiedEnvironmentTarget::NativeLocal(name),
            UnifiedEnvironmentLifecycle::Restart(args),
        ) => {
            let environment = restart_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        (
            UnifiedEnvironmentTarget::NativeLocal(name),
            UnifiedEnvironmentLifecycle::Remove(args),
        ) => {
            let removed = delete_native_environment(&name).await?;
            reconcile_native_current_after_delete(&removed.name).await;
            match args.output {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": removed.name,
                        "removed": removed.removed,
                        "cleanup_pending": removed.cleanup_pending,
                    }))?
                ),
                OutputFormat::Text => {
                    eprintln!("Local environment removed: {}.", removed.name);
                    if removed.cleanup_pending {
                        eprintln!(
                            "An unsafe or unknown object remains quarantined for orphan inspection."
                        );
                    }
                }
            }
            Ok(())
        }
        (UnifiedEnvironmentTarget::Platform(id), UnifiedEnvironmentLifecycle::Start(args)) => {
            handle_platform_env_command(
                globals,
                EnvCommand::Start(EnvTargetArgs {
                    environment: id,
                    output: args.output,
                }),
            )
            .await
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
            anyhow::bail!("restart is supported only for native local environments")
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn reconcile_native_current_after_delete(deleted_name: &str) {
    let env = OsEnv;
    let paths = match ResolvePaths::from_env(&env) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("Warning: could not reconcile the current local target: {error}");
            return;
        }
    };
    let Ok(current) = config::current_target(&paths.mesh_data_dir) else {
        return;
    };
    if current.kind != "local"
        || (current.target_ref != deleted_name && current.name != deleted_name)
    {
        return;
    }
    let replacement = match native_selected_environment().await {
        Ok(environment) => native_current_target_after_delete(environment.map(|value| value.name)),
        Err(error) => {
            eprintln!("Warning: could not reconcile the current local target: {error}");
            return;
        }
    };
    if let Err(error) = config::save_current_target(&paths.mesh_data_dir, &replacement) {
        eprintln!("Warning: could not save the current local target: {error}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn native_current_target_after_delete(
    selected: Option<String>,
) -> config::CurrentTargetConfig {
    match selected {
        Some(name) => config::CurrentTargetConfig {
            kind: "local".to_owned(),
            target_ref: name.clone(),
            name,
        },
        None => config::default_current_target(),
    }
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
            anyhow::bail!("refresh-skills is supported only for native local environments")
        }
    }
}

async fn resolve_unified_environment_target(
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
        anyhow::bail!("{command} is not supported by trusted host environments");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let native = if placement != Some(EnvironmentPlacement::Platform) {
        native_environment(target_ref).await?
    } else {
        None
    };
    if placement == Some(EnvironmentPlacement::Local) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(environment) = native.as_ref() {
            return Ok(UnifiedEnvironmentTarget::NativeLocal(
                environment.name.clone(),
            ));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            anyhow::bail!("native local environments currently require Linux or macOS");
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            anyhow::bail!("local environment {target_ref:?} not found");
        }
    }

    let platform = match resolve_platform(globals, &paths, &env) {
        Ok(platform) => platform,
        Err(error) if placement.is_none() && command != "update" => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(environment) = native {
                return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
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
    let platform_match = find_environment_match(&environments, target_ref)?;

    if placement == Some(EnvironmentPlacement::Platform) {
        let Some((id, _)) = platform_match else {
            anyhow::bail!("platform environment {target_ref:?} not found");
        };
        return Ok(UnifiedEnvironmentTarget::Platform(id));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match (native, platform_match) {
        (_, Some((id, EnvironmentMatchKind::ExactId))) => {
            Ok(UnifiedEnvironmentTarget::Platform(id))
        }
        (Some(environment), Some((_id, EnvironmentMatchKind::ExactName)))
            if environment.name == target_ref =>
        {
            Err(ambiguous_environment_placement_error(command, target_ref))
        }
        (Some(environment), _) => Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name)),
        (None, Some((id, _))) => Ok(UnifiedEnvironmentTarget::Platform(id)),
        (None, None) => anyhow::bail!("environment {target_ref:?} not found"),
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

pub(crate) fn unified_environment_list_entries(
    platform: &[(Environment, String)],
    current: Option<&config::CurrentTargetConfig>,
) -> Vec<UnifiedEnvironmentListEntry> {
    let mut entries = platform
        .iter()
        .map(|(environment, daemon_health)| UnifiedEnvironmentListEntry {
            environment_type: "sandbox".into(),
            name: environment_display_name(environment).to_string(),
            placement: "platform".to_string(),
            selected: current
                .is_some_and(|target| target.kind == "env" && target.target_ref == environment.id),
            state: environment.state.clone(),
            daemon_health: daemon_health.clone(),
            id: environment.id.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.placement.cmp(&right.placement))
    });
    entries
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
    let lifecycle_started = Instant::now();
    let mut lifecycle_timeout = PLATFORM_READY_TIMEOUT;
    let mut daemon_started = None;

    loop {
        let (environment, poll_interval) = client
            .get_environment_with_poll_interval(org_id, environment_id)
            .await
            .context("get environment")?;
        lifecycle_timeout = lifecycle_timeout.max(platform_lifecycle_ready_timeout(
            &environment.isolation_tier,
        ));

        let observation = match environment.state.as_str() {
            "running" => {
                daemon_started.get_or_insert_with(Instant::now);
                match client
                    .get_environment_daemon_status(org_id, environment_id)
                    .await
                {
                    Ok(status) => match environment_daemon_readiness(&status)? {
                        true => return Ok(()),
                        false => "daemon is still starting".to_string(),
                    },
                    Err(error) => error.to_string(),
                }
            }
            "destroyed" | "destroying" | "failed" | "error" => {
                anyhow::bail!(
                    "environment {environment_id:?} became {} before its daemon was ready",
                    environment.state
                );
            }
            state => format!("environment is {state}"),
        };

        if daemon_started
            .as_ref()
            .is_some_and(|started| started.elapsed() >= PLATFORM_DAEMON_READY_TIMEOUT)
        {
            anyhow::bail!(
                "timed out waiting for environment {environment_id:?} daemon to become ready: {observation}"
            );
        }
        if daemon_started.is_none() && lifecycle_started.elapsed() >= lifecycle_timeout {
            anyhow::bail!(
                "timed out waiting for environment {environment_id:?} to reach running state: {observation}"
            );
        }
        tokio::time::sleep(poll_interval.unwrap_or(Duration::from_secs(2))).await;
    }
}

pub(crate) fn platform_lifecycle_ready_timeout(isolation_tier: &str) -> Duration {
    if isolation_tier == "confidential" {
        PLATFORM_CONFIDENTIAL_READY_TIMEOUT
    } else {
        PLATFORM_READY_TIMEOUT
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

pub(crate) fn env_create_request_from_args(
    args: &EnvCreateArgs,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let ttl_seconds = args
        .ttl
        .as_deref()
        .and_then(trimmed_str)
        .map(parse_go_duration_seconds)
        .transpose()
        .context("invalid --ttl duration")?;
    let preset_id = trimmed_optional(args.preset_id.clone());
    // Only the explicitly named file supplies defaults. Neither the working
    // directory nor `cw use` selects a source or a management write target.
    let mut project_spec = match args.file.as_deref() {
        Some(path) => sources::load_platform_document(path)?,
        None => codewire_project::ProjectSpec::default(),
    };
    if let Some(preset) = &args.preset_slug {
        project_spec.preset = preset.trim().to_owned();
    } else if preset_id.is_some() {
        project_spec.preset.clear();
    }
    if let Some(image) = args.image.as_deref().and_then(trimmed_str) {
        project_spec.image = if image.contains('/') {
            image.to_owned()
        } else {
            expand_image_ref(image)
        };
    }
    if !args.repo_urls.is_empty() || !args.repo_flags.is_empty() {
        project_spec.repositories = collect_env_create_repos(
            &args.repo_urls,
            &args.repo_flags,
            args.branch.as_deref().and_then(trimmed_str),
        )?;
        project_spec.working_directory = match project_spec.repositories.as_slice() {
            [repository] => repository.destination.clone(),
            _ => "/workspace".to_owned(),
        };
    } else if let Some(branch) = args.branch.as_deref().and_then(trimmed_str) {
        match project_spec.repositories.as_mut_slice() {
            [repository] => {
                repository.branch = branch.to_owned();
                repository.revision.clear();
            }
            [] if args.file.is_some() => anyhow::bail!("--branch requires a repository"),
            // `cw init --branch` detects its repository after constructing
            // this draft. Keep that existing deferred discovery intact.
            [] => {}
            _ => anyhow::bail!(
                "--branch is ambiguous with multiple YAML repositories; specify --repo"
            ),
        }
    }
    if let Some(install) = &args.install {
        project_spec.install_command = install.trim().to_owned();
    }
    if let Some(startup) = &args.startup {
        project_spec.startup_script = startup.trim().to_owned();
    }
    project_spec
        .environment
        .extend(parse_env_overrides(&args.env)?);
    if let Some(agent) = args.coding_agent.as_deref().and_then(trimmed_str) {
        project_spec.agents = codewire_project::AgentsSpec {
            install: None,
            tools: vec![config::canonical_agent_id(agent)],
        };
    }
    if args.cpu.is_some() {
        project_spec.resources.cpu_millicores =
            positive_i32(parse_platform_create_quantity(args.cpu.as_deref(), "CPU")?)
                .map(|value| value as u32);
    }
    if args.memory.is_some() {
        project_spec.resources.memory_mib =
            positive_i32(parse_create_memory(args.memory.as_deref())?).map(|value| value as u64);
    }
    if args.disk.is_some() {
        project_spec.resources.disk_gib =
            positive_i32(parse_create_disk(args.disk.as_deref())?).map(|value| value as u64);
    }
    if let Some(project) = &args.secrets {
        codewire_project::StorageReference::project(project)?;
        project_spec.secrets.project = project.clone();
    }
    if let Some(user) = args.user_secrets {
        project_spec.secrets.user = Some(sources::placement(user));
    }
    if args.org_secrets {
        project_spec.secrets.organization = true;
    }
    if let Some(profile) = &args.profile {
        codewire_project::StorageReference::profile(profile)?;
        project_spec.credentials = Some(codewire_project::CredentialBinding {
            profile: profile.clone(),
        });
    }
    project_spec.validate()?;
    Ok(CreateEnvironmentRequest {
        preset_id,
        name: trimmed_optional(args.name.clone()),
        ttl_seconds,
        isolation_tier: args.isolation.clone().unwrap_or_default(),
        project_spec,
        ..Default::default()
    })
}

fn parse_platform_create_quantity(value: Option<&str>, label: &str) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| {
            value
                .parse::<i32>()
                .with_context(|| format!("platform {label} must use the existing integer unit"))
        })
        .transpose()
}

fn parse_create_memory(value: Option<&str>) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| match value.parse::<i32>() {
            Ok(value) => Ok(value),
            Err(_) => parse_resize_memory(value)
                .context("memory must be an integer MiB value or use MB/GB units"),
        })
        .transpose()
}

fn parse_create_disk(value: Option<&str>) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| match value.parse::<i32>() {
            Ok(value) => Ok(value),
            Err(_) => parse_resize_disk(value)
                .context("disk must be an integer GiB value or use GB units"),
        })
        .transpose()
}

pub(crate) fn prepare_platform_env_create_request(
    args: &EnvCreateArgs,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let mut request = env_create_request_from_args(args)?;
    request.project_spec.ensure_platform_compatible()?;
    if request.preset_id.is_none()
        && request.project_spec.preset.is_empty()
        && request.project_spec.repositories.is_empty()
        && request.project_spec.image.is_empty()
    {
        request.project_spec.image = CANONICAL_WORKSPACE_IMAGE.to_string();
    }
    Ok(request)
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireYaml {
    pub(crate) version: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) preset: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) image: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) repositories: Vec<ResolvedCodewireRepositoryYaml>,
    pub(crate) working_directory: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) install_command: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) startup_script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secrets: Option<ResolvedCodewireSecretsYaml>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) environment: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agents: Option<ResolvedCodewireAgentsYaml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) skills: Vec<ResolvedCodewireSkillYaml>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<ResolvedCodewirePortYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credentials: Option<ResolvedCodewireCredentialsYaml>,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireRepositoryYaml {
    pub(crate) source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) revision: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) branch: String,
    pub(crate) destination: String,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewirePortYaml {
    pub(crate) port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) access: String,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireAgentsYaml {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) install: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tools: Vec<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireSecretsYaml {
    pub(crate) organization: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<codewire_project::StoragePlacement>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) project: String,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireSkillYaml {
    pub(crate) source: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) agents: Vec<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireCredentialsYaml {
    pub(crate) profile: String,
}

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
    let data = serde_yaml::to_string(&codewire_yaml_from_request(request))?;
    fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub(crate) fn codewire_yaml_from_request(
    request: &CreateEnvironmentRequest,
) -> ResolvedCodewireYaml {
    let spec = &request.project_spec;
    ResolvedCodewireYaml {
        version: spec.schema_version,
        preset: spec.preset.clone(),
        image: spec.image.clone(),
        repositories: spec
            .repositories
            .iter()
            .map(|repository| ResolvedCodewireRepositoryYaml {
                source: repository.source.clone(),
                revision: repository.revision.clone(),
                branch: repository.branch.clone(),
                destination: repository.destination.clone(),
            })
            .collect(),
        working_directory: spec.working_directory.clone(),
        install_command: spec.install_command.clone(),
        startup_script: spec.startup_script.clone(),
        secrets: (!spec.secrets.is_empty()).then(|| ResolvedCodewireSecretsYaml {
            organization: spec.secrets.organization,
            user: spec.secrets.user,
            project: spec.secrets.project.clone(),
        }),
        environment: spec.environment.clone(),
        agents: codewire_yaml_agents_from_request(request),
        skills: spec
            .skills
            .iter()
            .map(|skill| {
                let (source, path, name) = match skill.source {
                    codewire_project::SkillSource::Repository => {
                        ("repository", skill.reference.clone(), String::new())
                    }
                    codewire_project::SkillSource::User => {
                        ("user", String::new(), skill.reference.clone())
                    }
                };
                ResolvedCodewireSkillYaml {
                    source,
                    path,
                    name,
                    agents: skill.agents.clone(),
                }
            })
            .collect(),
        ports: spec
            .application_ports
            .iter()
            .map(|port| ResolvedCodewirePortYaml {
                port: port.port,
                label: port.label.clone(),
                access: port.access.clone(),
            })
            .collect(),
        cpu: spec
            .resources
            .cpu_millicores
            .map(|value| format!("{value}m")),
        memory: spec.resources.memory_mib.map(|value| format!("{value}Mi")),
        disk: spec.resources.disk_gib.map(|value| format!("{value}Gi")),
        credentials: spec
            .credentials
            .as_ref()
            .map(|credentials| ResolvedCodewireCredentialsYaml {
                profile: credentials.profile.clone(),
            }),
    }
}

pub(crate) fn codewire_yaml_agents_from_request(
    request: &CreateEnvironmentRequest,
) -> Option<ResolvedCodewireAgentsYaml> {
    let tools = request.project_spec.agents.tools.clone();
    if tools.is_empty() && request.project_spec.agents.install.is_none() {
        return None;
    }
    Some(ResolvedCodewireAgentsYaml {
        install: request.project_spec.agents.install,
        tools,
    })
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

pub(crate) fn format_env_create_text(environment: &Environment) -> String {
    let env_name = environment.name.as_deref().unwrap_or(&environment.id);
    format!(
        "Environment created: {env_name}\n  ID:        {}\n  State:     {}\n  Type:      {}\n  Isolation: {}\n  CPU:       {}m\n  Mem:       {}MB\n  Disk:      {}GB\n",
        environment.id,
        environment.state,
        environment.environment_type,
        if environment.isolation_tier.is_empty() {
            "standard"
        } else {
            &environment.isolation_tier
        },
        environment.cpu_millicores,
        environment.memory_mb,
        environment.disk_gb
    )
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
            let data = fs::read(&args.src).context("open local file")?;
            environment_client
                .upload_environment_file(org_id, &environment_id, dst_path, data)
                .await
                .context("upload")?;
            print!(
                "{}",
                format_env_cp_upload_text(&args.src, &environment_id, dst_path)
            );
        }
        (Some((src_env, src_path)), None) => {
            let environment_id =
                resolve_environment_id(environment_client, org_id, src_env).await?;
            let data = environment_client
                .download_environment_file(org_id, &environment_id, src_path)
                .await
                .context("download")?;
            let mut out = fs::File::create(&args.dst).context("create local file")?;
            out.write_all(&data).context("write local file")?;
            print!(
                "{}",
                format_env_cp_download_text(&environment_id, src_path, &args.dst, data.len())
            );
        }
    }

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
    bytes: usize,
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
                "{name} is {}; start it with `cw start {name}`, then publish the port",
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
                .context("create port")?;
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
    let mut view = StartProgress::new(
        std::io::stderr(),
        progress::live_progress_enabled(),
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
) -> anyhow::Result<()> {
    let environment_id = environment.id.as_str();
    let feed = progress::PlatformLogFeed {
        client,
        org_id,
        environment_id,
    };
    let mut view = StartProgress::new(
        std::io::stderr(),
        progress::live_progress_enabled(),
        began,
        "Starting",
    );
    progress::await_environment_setup(
        &feed,
        &mut view,
        &FollowPolicy::default(),
        environment_id,
        progress::watch_setup_failure(client, org_id, environment_id),
        || async {
            wait_for_platform_environment_daemon_ready(client, org_id, environment_id)
                .await
                .context("wait for environment daemon readiness")
        },
    )
    .await?;
    let name = environment.name.as_deref().unwrap_or(environment_id);
    print!(
        "{}",
        format_env_ready_text(name, view.total_elapsed(Instant::now()))
    );
    Ok(())
}

/// `cw start` with text output: the start's stages, then daemon
/// readiness. Exits non-zero when a stage fails.
async fn start_platform_environment_with_progress(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    environment_ref: &str,
    began: Instant,
) -> anyhow::Result<()> {
    // Rows up to now belong to earlier operations, including the terminal
    // row that would otherwise end the stream at once.
    let cursor = client
        .get_environment_logs(org_id, environment_id)
        .await
        .map(|logs| progress::last_log_id(&logs));
    client
        .start_environment(org_id, environment_id)
        .await
        .context("start environment")?;
    let mut view = StartProgress::new(
        std::io::stderr(),
        progress::live_progress_enabled(),
        began,
        "Starting",
    );
    let daemon_ready = async {
        wait_for_platform_environment_daemon_ready(client, org_id, environment_id)
            .await
            .context("wait for environment daemon readiness")
    };
    match cursor {
        Ok(cursor) => {
            let feed = progress::PlatformLogFeed {
                client,
                org_id,
                environment_id,
            };
            progress::await_environment_start(
                &feed,
                &mut view,
                &FollowPolicy::default(),
                environment_id,
                cursor,
                daemon_ready,
            )
            .await?;
        }
        Err(error) => {
            view.note(&format!("Start progress is unavailable: {error:#}"))?;
            progress::await_daemon_ready(&mut view, &FollowPolicy::default(), daemon_ready).await?;
        }
    }
    print!(
        "{}",
        format_env_ready_text(environment_ref, view.total_elapsed(Instant::now()))
    );
    Ok(())
}

pub(crate) fn print_environment_logs_historical(logs: &[EnvironmentLog]) {
    if logs.is_empty() {
        println!("No logs yet.");
        return;
    }
    eprint!("{}", format_environment_logs_plain(logs));
}

pub(crate) fn filter_environments(
    environments: &[Environment],
    environment_type: Option<&str>,
    state: Option<&str>,
    all: bool,
) -> Vec<Environment> {
    let environment_type = environment_type.and_then(trimmed_str);
    let state = state.and_then(trimmed_str);
    environments
        .iter()
        .filter(|environment| {
            environment_type.is_none_or(|wanted| environment.environment_type == wanted)
        })
        .filter(|environment| state.is_none_or(|wanted| environment.state == wanted))
        .filter(|environment| all || environment.state != "destroyed")
        .cloned()
        .collect()
}

pub(crate) fn print_env_info(
    environment: &Environment,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(environment)?),
        OutputFormat::Text => print!("{}", format_env_info_text(environment)),
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

pub(crate) fn print_env_delete_result(
    environment_ref: &str,
    environment_id: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&EnvDeleteResult {
                environment: environment_ref,
                environment_id,
                deleted: true,
            })?
        ),
        OutputFormat::Text => print!("{}", format_env_delete_text(environment_ref)),
    }
    Ok(())
}

pub(crate) fn format_env_delete_text(environment_ref: &str) -> String {
    format!("Environment {environment_ref} deleted.\n")
}

pub(crate) fn map_env_delete_error(environment_ref: &str, err: anyhow::Error) -> anyhow::Error {
    let message = err.to_string();
    if message.contains("deletion_pending") || message.contains("202") {
        return anyhow::anyhow!(
            "Environment {environment_ref} scheduled for deletion (grace period).\nUse 'cw cancel-delete {environment_ref}' to cancel."
        );
    }
    if message.contains("environment_protected") {
        return anyhow::anyhow!(
            "environment is protected. Run 'cw unprotect {environment_ref}' first"
        );
    }
    if message.contains("access_denied") {
        return anyhow::anyhow!("access denied: only the environment owner can delete it");
    }
    anyhow::anyhow!("delete environment: {message}")
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

pub(crate) fn format_env_info_text(environment: &Environment) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<14} {}\n", "ID:", environment.id));
    output.push_str(&format!(
        "{:<14} {}\n",
        "Name:",
        environment
            .name
            .as_deref()
            .and_then(trimmed_str)
            .unwrap_or("--")
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "Type:",
        env_type_label(environment)
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "State:",
        env_state_label(environment)
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "DesiredState:",
        trimmed_str(&environment.desired_state).unwrap_or("--")
    ));
    output.push_str(&format!(
        "{:<14} {}\n",
        "PresetID:",
        trimmed_str(&environment.preset_id).unwrap_or("--")
    ));
    if let Some(network) = environment.network.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("{:<14} {}\n", "Network:", network));
    }
    output.push_str(&format!("CPU:           {}m\n", environment.cpu_millicores));
    output.push_str(&format!(
        "Isolation:     {}\n",
        trimmed_str(&environment.isolation_tier).unwrap_or("standard")
    ));
    output.push_str(&format!("Memory:        {}MB\n", environment.memory_mb));
    output.push_str(&format!("Disk:          {}GB\n", environment.disk_gb));
    output.push_str(&format!(
        "CreatedBy:     {}\n",
        trimmed_str(&environment.created_by).unwrap_or("--")
    ));
    output.push_str(&format!(
        "CreatedAt:     {}\n",
        trimmed_str(&environment.created_at).unwrap_or("--")
    ));
    if let Some(started_at) = environment.started_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("StartedAt:     {started_at}\n"));
    }
    if let Some(stopped_at) = environment.stopped_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("StoppedAt:     {stopped_at}\n"));
    }
    if let Some(shutdown_at) = environment.shutdown_at.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("ShutdownAt:    {shutdown_at}\n"));
    }
    if let Some(ttl_seconds) = environment.ttl_seconds {
        output.push_str(&format!("TTL:           {ttl_seconds}s\n"));
    }
    if let Some(error_reason) = environment.error_reason.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("ErrorReason:   {error_reason}\n"));
    }
    output.push_str(&format!("Recoverable:   {}\n", environment.recoverable));
    output.push_str(&format!(
        "TotalRunning:  {}s\n",
        environment.total_running_seconds
    ));
    if environment.protected {
        output.push_str(&format!("{:<14} yes\n", "Protected:"));
    }
    if let Some(deleting_at) = environment
        .deletion_grace_until
        .as_deref()
        .and_then(trimmed_str)
    {
        output.push_str(&format!("{:<14} {}\n", "DeletingAt:", deleting_at));
    }
    output
}

pub(crate) fn env_type_label(environment: &Environment) -> &str {
    trimmed_str(&environment.environment_type).unwrap_or("--")
}

pub(crate) fn env_state_label(environment: &Environment) -> &str {
    if environment
        .deletion_grace_until
        .as_deref()
        .and_then(trimmed_str)
        .is_some()
        && !matches!(environment.state.as_str(), "destroyed" | "destroying")
    {
        return "deleting";
    }
    trimmed_str(&environment.state).unwrap_or("--")
}

pub(crate) fn env_created_label(environment: &Environment) -> &str {
    trimmed_str(&environment.created_at).unwrap_or("--")
}
