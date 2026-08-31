use std::io::Write as _;

use super::*;

// Match the server-owned sandbox lifecycle first, then give daemon setup its
// own post-running window. Confidential guests deliberately have a longer boot
// horizon; one fixed three-minute stopwatch reports false failure while the
// accepted server operation is still progressing.
const PLATFORM_READY_TIMEOUT: Duration = Duration::from_secs(600);
const PLATFORM_CONFIDENTIAL_READY_TIMEOUT: Duration = Duration::from_secs(1800);
const PLATFORM_DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) async fn handle_env_command(globals: &Globals, args: EnvArgs) -> anyhow::Result<()> {
    let placement = args.placement();
    match args.command {
        EnvCommand::Create(create) => {
            handle_unified_environment_create(globals, placement, create).await
        }
        EnvCommand::List(list) => handle_unified_environment_list(globals, placement, list).await,
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
        EnvCommand::Rm(target) => {
            handle_unified_environment_lifecycle(
                globals,
                placement,
                UnifiedEnvironmentLifecycle::Remove(target),
            )
            .await
        }
        EnvCommand::Daemon(args) => {
            handle_unified_environment_daemon_command(globals, placement, args.command).await
        }
        command => {
            if placement.is_some() {
                anyhow::bail!(
                    "--local and --platform currently support only create, list, info, start, stop, rm, and daemon diagnostics"
                );
            }
            handle_platform_env_command(globals, command).await
        }
    }
}

/// Render the environment workspace chooser after an attach-navigation request.
/// This only observes the current placements; it never changes `cw use`.
pub(crate) async fn show_workspace_list(globals: &Globals) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
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
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let secret_client = SecretClient::new(&platform)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;

    match command {
        EnvCommand::Create(args) => {
            let mut request = prepare_platform_env_create_request(&args)?;
            match resolve_env_create_mesh_bootstrap(
                &paths,
                &env,
                &platform,
                &org_id,
                args.yes,
                args.network.as_deref(),
                args.no_network,
            ) {
                Ok(Some(bootstrap)) => match create_env_mesh_invite(&bootstrap).await {
                    Ok(invite) => inject_env_create_mesh_bootstrap(
                        &mut request,
                        &bootstrap.mesh.mesh_url,
                        &bootstrap.network_id,
                        &invite.invite_code,
                    )?,
                    Err(err) => {
                        eprintln!(
                            "Warning: mesh enrollment failed ({err}), continuing without network"
                        );
                    }
                },
                Ok(None) => {}
                Err(err) => {
                    eprintln!(
                        "Warning: mesh enrollment failed ({err}), continuing without network"
                    );
                }
            }
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
                let secret_project_id = resolve_preset_secret_project_id(
                    &secret_client,
                    &org_id,
                    &preset_request.secret_project,
                )
                .await?;
                let preset = organization_client
                    .create_preset(&org_id, &preset_request, secret_project_id)
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
                follow_environment_logs(&environment_client, &org_id, &environment.id).await?;
            }
        }
        EnvCommand::List(args) => {
            let environments = environment_client
                .list_environments(&org_id)
                .await
                .context("list environments")?;
            let filtered = filter_environments(
                &environments,
                args.environment_type.as_deref(),
                args.state.as_deref(),
                args.all,
            );
            let current = config::current_target(&paths.mesh_data_dir).ok();
            print_env_list(&filtered, current.as_ref(), args.output)?;
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
            let environment_id =
                resolve_environment_id(&environment_client, &org_id, &args.environment).await?;
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
                .list_environments(&org_id)
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
                .list_environments(&org_id)
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
        EnvCommand::Access(args) => {
            handle_env_access_command(&environment_client, &org_id, args.command).await?;
        }
        EnvCommand::Port(args) => {
            handle_env_port_command(
                &environment_client,
                &org_id,
                &paths.mesh_data_dir,
                args.command,
            )
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
    Remove(EnvDeleteArgs),
}

impl UnifiedEnvironmentLifecycle {
    fn environment(&self) -> &str {
        match self {
            Self::Start(args) | Self::Stop(args) => &args.environment,
            Self::Remove(args) => &args.environment,
        }
    }

    fn command_name(&self) -> &'static str {
        match self {
            Self::Start(_) => "start",
            Self::Stop(_) => "stop",
            Self::Remove(_) => "rm",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UnifiedEnvironmentTarget {
    #[cfg(target_os = "linux")]
    NativeLocal(String),
    Local(String),
    Platform(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalResizePlan {
    pub(crate) current: LocalLimaResources,
    pub(crate) desired: LocalLimaResources,
    pub(crate) active_sessions: Vec<String>,
    pub(crate) normalized_cpu_request: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeResizeResources {
    pub(crate) vcpus: u32,
    pub(crate) memory_mib: u32,
    pub(crate) disk_bytes: u64,
}

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

fn parse_resize_binary_quantity(value: &str, unit: &str, label: &str) -> anyhow::Result<i32> {
    let value = value.trim();
    let amount = value.strip_suffix(unit).ok_or_else(|| {
        anyhow::anyhow!("invalid {label} quantity {value:?}; use a value such as 512Mi or 4Gi")
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
    if value.trim().ends_with("Mi") {
        return parse_resize_binary_quantity(value, "Mi", "memory");
    }
    let gib = parse_resize_binary_quantity(value, "Gi", "memory")?;
    gib.checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("memory quantity {value:?} is too large"))
}

pub(crate) fn parse_resize_disk(value: &str) -> anyhow::Result<i32> {
    parse_resize_binary_quantity(value, "Gi", "disk")
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

pub(crate) fn resolve_local_resize_plan(
    args: &EnvResizeArgs,
    current: LocalLimaResources,
    active_sessions: Vec<String>,
) -> anyhow::Result<LocalResizePlan> {
    let (cpu_millicores, normalized_cpu_request) = match args.cpu.as_deref() {
        Some(value) => {
            let requested = parse_resize_cpu(value)?;
            let normalized = lima_cpus_from_millicores(requested).saturating_mul(1000);
            (normalized, (requested != normalized).then_some(requested))
        }
        None => (current.cpu_millicores, None),
    };
    let memory_mb = match args.memory.as_deref() {
        Some(value) => parse_resize_memory(value)?,
        None => current.memory_mb,
    };
    let disk_gb = match args.disk.as_deref() {
        Some(value) => parse_resize_disk(value)?,
        None => current.disk_gb,
    };
    if disk_gb < current.disk_gb {
        anyhow::bail!(
            "Lima disk shrink is not supported (current: {}, requested: {})",
            format_resize_disk(current.disk_gb),
            format_resize_disk(disk_gb)
        );
    }
    let desired = LocalLimaResources {
        cpu_millicores,
        memory_mb,
        disk_gb,
    };
    if desired == current {
        anyhow::bail!("the requested resources already match the current Lima environment");
    }
    Ok(LocalResizePlan {
        current,
        desired,
        active_sessions,
        normalized_cpu_request,
    })
}

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

fn format_native_disk(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes.is_multiple_of(GIB) {
        format!("{} Gi", bytes / GIB)
    } else {
        format!("{bytes} bytes")
    }
}

pub(crate) fn format_native_resize_plan(name: &str, plan: &NativeResizePlan) -> String {
    let mut output = format!(
        "Environment: {name} (local · Cloud Hypervisor)\n\n              Current   Desired\nCPU       {:<9} {}\nMemory    {:<9} {}\nDisk      {:<9} {}\n\n",
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

pub(crate) fn format_local_resize_plan(name: &str, plan: &LocalResizePlan) -> String {
    let mut output = format!(
        "Environment: {name} (local · Lima)\n\n              Current   Desired\nCPU       {:<9} {}\nMemory    {:<9} {}\nDisk      {:<9} {}\n\n",
        format_resize_cpu(plan.current.cpu_millicores),
        format_resize_cpu(plan.desired.cpu_millicores),
        format_resize_memory(plan.current.memory_mb),
        format_resize_memory(plan.desired.memory_mb),
        format_resize_disk(plan.current.disk_gb),
        format_resize_disk(plan.desired.disk_gb),
    );
    if plan.active_sessions.is_empty() {
        output.push_str("Active sessions: none\n");
    } else {
        output.push_str(&format!(
            "Active sessions ({}): {}\n",
            plan.active_sessions.len(),
            plan.active_sessions.join(", ")
        ));
        output.push_str("The required Lima restart will terminate these sessions.\n");
    }
    if let Some(requested) = plan.normalized_cpu_request {
        output.push_str(&format!(
            "Lima uses whole CPU cores; {} is normalized to {}.\n",
            format_resize_cpu(requested),
            format_resize_cpu(plan.desired.cpu_millicores)
        ));
    }
    output.push_str(
        "Lima will stop, resize, and restart this environment. Disk growth cannot be reversed.\n",
    );
    output
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
    fn environment(&self) -> Option<&str> {
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
    match placement {
        Some(EnvironmentPlacement::Local) => {
            let output = args.output;
            #[cfg(target_os = "linux")]
            if native_create_selected(&args)? {
                let environment = create_native_environment(*args).await?;
                if matches!(output, OutputFormat::Text) {
                    eprintln!("Local environment created: {}.", environment.name);
                }
                return print_native_environment(&environment, output);
            }
            let create = local_create_args_from_environment_args(*args)?;
            handle_local_command(
                globals,
                LocalArgs {
                    output,
                    command: LocalCommand::Create(Box::new(create)),
                },
            )
            .await
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
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    if placement == Some(EnvironmentPlacement::Local)
        && (args.environment_type.is_some() || args.state.is_some() || args.all)
    {
        anyhow::bail!("--type, --state, and --all are only supported for platform environments");
    }

    #[cfg(target_os = "linux")]
    let native = if placement != Some(EnvironmentPlacement::Platform) {
        native_environments().await?
    } else {
        Vec::new()
    };

    let local = if placement != Some(EnvironmentPlacement::Platform) {
        let config = config::load_local_instances_config(&paths.mesh_data_dir)?;
        #[cfg(target_os = "linux")]
        if !native.is_empty() {
            // Native inventory must not execute a legacy runtime merely to
            // render its disjoint saved metadata. Explicit legacy-only usage
            // retains the existing live-status observation below.
            sorted_local_instance_entries(&config)
        } else {
            observed_local_environment_entries(&config)
        }
        #[cfg(not(target_os = "linux"))]
        observed_local_environment_entries(&config)
    } else {
        Vec::new()
    };

    let platform = if placement != Some(EnvironmentPlacement::Local) {
        let platform = resolve_platform(globals, &paths, &env)?;
        let environment_client = EnvironmentClient::new(&platform)?;
        let organization_client = organization_client(&platform)?;
        let orgs = organization_client.list_orgs().await.context("list orgs")?;
        let org_id = current_org_id(&platform, &orgs)?;
        let environments = environment_client
            .list_environments(&org_id)
            .await
            .context("list environments")?;
        let filtered = filter_environments(
            &environments,
            args.environment_type.as_deref(),
            args.state.as_deref(),
            args.all,
        );
        let mut entries = Vec::with_capacity(filtered.len());
        for environment in filtered {
            let daemon_health = environment_client
                .get_environment_daemon_status(&org_id, &environment.id)
                .await
                .map(|status| status.state)
                .unwrap_or_else(|_| "unavailable".to_string());
            entries.push((environment, daemon_health));
        }
        entries
    } else {
        Vec::new()
    };

    let current = config::current_target(&paths.mesh_data_dir).ok();
    #[cfg(target_os = "linux")]
    let current = (!native.iter().any(|environment| environment.selected))
        .then_some(current.as_ref())
        .flatten();
    #[cfg(not(target_os = "linux"))]
    let current = current.as_ref();
    let mut entries = unified_environment_list_entries(&local, &platform, current);
    #[cfg(target_os = "linux")]
    entries.extend(
        native
            .iter()
            .map(|environment| UnifiedEnvironmentListEntry {
                name: environment.name.clone(),
                placement: "local".to_string(),
                selected: environment.selected,
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
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.placement.cmp(&right.placement))
    });
    print_unified_environment_list(&entries, args.output)
}

fn observed_local_environment_entries(
    config: &config::LocalInstancesConfig,
) -> Vec<LocalInstanceEntry> {
    let mut entries = config
        .instances
        .iter()
        .map(|(key, instance)| {
            let state = local_environment_lifecycle_status(instance)
                .unwrap_or_else(|_| "unavailable".to_string());
            local_instance_entry(key, instance, &state)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

async fn handle_unified_environment_info(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvInfoArgs,
) -> anyhow::Result<()> {
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "info").await?;
    match target {
        #[cfg(target_os = "linux")]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            let environment = get_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        UnifiedEnvironmentTarget::Local(name) => {
            handle_local_command(
                globals,
                LocalArgs {
                    output: args.output,
                    command: LocalCommand::Info(LocalInfoArgs { name: Some(name) }),
                },
            )
            .await
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

async fn active_local_resize_sessions(
    instance: &config::LocalInstanceConfig,
    lifecycle_state: &str,
) -> anyhow::Result<Vec<String>> {
    if lifecycle_state != "running" {
        return Ok(Vec::new());
    }
    let sessions = super::sessions::local_environment_session_client(instance)
        .await?
        .list()
        .await?;
    Ok(sessions
        .into_iter()
        .filter(|session| {
            !matches!(
                codewire_daemon::client::v1::SessionLifecycleState::try_from(session.state),
                Ok(codewire_daemon::client::v1::SessionLifecycleState::Stopped
                    | codewire_daemon::client::v1::SessionLifecycleState::Exited
                    | codewire_daemon::client::v1::SessionLifecycleState::Failed
                    | codewire_daemon::client::v1::SessionLifecycleState::Interrupted)
            )
        })
        .map(|session| session.session_id)
        .collect())
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
    let name = match target {
        #[cfg(target_os = "linux")]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            return handle_native_environment_resize(name, args).await;
        }
        UnifiedEnvironmentTarget::Local(name) => name,
        UnifiedEnvironmentTarget::Platform(environment_id) => {
            args.environment = environment_id;
            return handle_platform_env_command(globals, EnvCommand::Resize(args)).await;
        }
    };

    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let config = config::load_local_instances_config(&paths.mesh_data_dir)?;
    let instance = config
        .instances
        .get(&name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("local environment {name:?} not found"))?;
    if instance.backend != "lima" {
        anyhow::bail!(
            "local resize is currently only supported for Lima-backed environments; {:?} uses {}",
            name,
            instance.backend
        );
    }

    let current = local_lima_instance_resources(local_lima_instance_name(&instance)?)?;
    if resize_requires_interactive_wizard(&args, stdin_is_interactive())? {
        args.cpu = prompt_resize_quantity("CPU", &format_resize_cpu(current.cpu_millicores))?;
        args.memory = prompt_resize_quantity("Memory", &format_resize_memory(current.memory_mb))?;
        args.disk = prompt_resize_quantity("Disk", &format_resize_disk(current.disk_gb))?;
    }
    let lifecycle_state = local_environment_lifecycle_status(&instance)?;
    let active_sessions = active_local_resize_sessions(&instance, &lifecycle_state).await?;
    let plan = resolve_local_resize_plan(&args, current, active_sessions)?;

    if matches!(args.output, OutputFormat::Text) {
        print!("{}", format_local_resize_plan(&name, &plan));
    }
    if !args.yes && !prompt_confirm_default_no("Apply this resize")? {
        println!("Aborted.");
        return Ok(());
    }

    handle_local_command(
        globals,
        LocalArgs {
            output: args.output,
            command: LocalCommand::Resize(LocalResizeArgs {
                name: Some(name),
                cpu: if plan.desired.cpu_millicores != plan.current.cpu_millicores {
                    plan.desired.cpu_millicores
                } else {
                    0
                },
                memory: if plan.desired.memory_mb != plan.current.memory_mb {
                    plan.desired.memory_mb
                } else {
                    0
                },
                disk: if plan.desired.disk_gb != plan.current.disk_gb {
                    plan.desired.disk_gb
                } else {
                    0
                },
                restart: true,
            }),
        },
    )
    .await
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
        anyhow::bail!(
            "this resize requires workspace Pod replacement; non-interactive use requires --allow-restart"
        );
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
        #[cfg(target_os = "linux")]
        UnifiedEnvironmentTarget::NativeLocal(_) => anyhow::bail!(
            "native environment daemon diagnostics are not exposed in this preview; use cw shell or cw run"
        ),
        UnifiedEnvironmentTarget::Local(name) => {
            let env = OsEnv;
            let paths = ResolvePaths::from_env(&env);
            let config = config::load_local_instances_config(&paths.mesh_data_dir)?;
            let instance = config
                .instances
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("local environment {name:?} not found"))?;
            handle_local_environment_daemon_command(instance, command).await
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
    let paths = ResolvePaths::from_env(&env);
    #[cfg(target_os = "linux")]
    if placement != Some(EnvironmentPlacement::Platform)
        && let Some(environment) = native_selected_environment().await?
    {
        return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
    }
    let current = config::current_target(&paths.mesh_data_dir).map_err(|_| {
        anyhow::anyhow!(
            "no environment selected; use `cw use ENV` or pass ENV to `cw env {}`",
            command.command_name()
        )
    })?;
    match (placement, current.kind.as_str()) {
        (Some(EnvironmentPlacement::Local), "env") => {
            anyhow::bail!("the selected environment is platform-backed; pass a local ENV")
        }
        (Some(EnvironmentPlacement::Platform), "local") => {
            anyhow::bail!("the selected environment is local; pass a platform ENV")
        }
        (_, "local") if !current.target_ref.trim().is_empty() && current.target_ref != "local" => {
            Ok(UnifiedEnvironmentTarget::Local(current.target_ref))
        }
        (_, "env") if !current.target_ref.trim().is_empty() => {
            Ok(UnifiedEnvironmentTarget::Platform(current.target_ref))
        }
        _ => anyhow::bail!(
            "no environment selected; use `cw use ENV` or pass ENV to `cw env {}`",
            command.command_name()
        ),
    }
}

async fn handle_local_environment_daemon_command(
    instance: &config::LocalInstanceConfig,
    command: EnvDaemonCommand,
) -> anyhow::Result<()> {
    match command {
        EnvDaemonCommand::Status(args) => {
            let status = wait_for_local_environment_daemon_ready(instance).await?;
            print_environment_daemon_status(&status, args.output)?;
        }
        EnvDaemonCommand::Logs(_) => {
            let logs = read_local_daemon_logs(instance)?;
            std::io::stdout()
                .write_all(logs.as_bytes())
                .context("write local environment daemon logs")?;
        }
        EnvDaemonCommand::Repair(args) => {
            repair_local_daemon(instance)?;
            let status = wait_for_local_environment_daemon_ready(instance).await?;
            let repair = EnvironmentDaemonRepair {
                status,
                replaced_pod_name: String::new(),
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

async fn local_environment_daemon_status(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<EnvironmentDaemonStatus> {
    let client = local_environment_daemon_client(instance).await?;
    let capabilities = client.get_capabilities(&[]).await?;
    let health = client.get_health().await?;
    let capabilities_state = codewire_daemon::client::v1::DaemonState::try_from(capabilities.state)
        .unwrap_or(codewire_daemon::client::v1::DaemonState::Unspecified);
    let health_state = codewire_daemon::client::v1::DaemonState::try_from(health.state)
        .unwrap_or(codewire_daemon::client::v1::DaemonState::Unspecified);
    let state = if capabilities_state == codewire_daemon::client::v1::DaemonState::Ready {
        health_state
    } else {
        capabilities_state
    };
    let message = if capabilities_state == codewire_daemon::client::v1::DaemonState::Ready {
        health.message
    } else {
        capabilities.message
    };
    Ok(EnvironmentDaemonStatus {
        state: local_daemon_state_name(state).to_string(),
        protocol_version: capabilities.protocol_version,
        minimum_protocol_version: capabilities.minimum_protocol_version,
        daemon_version: capabilities.daemon_version,
        capabilities: capabilities.capabilities,
        message,
        diagnostics: health
            .diagnostics
            .into_iter()
            .map(|diagnostic| EnvironmentDaemonDiagnostic {
                name: diagnostic.name,
                healthy: diagnostic.healthy,
                message: diagnostic.message,
            })
            .collect(),
        pod_name: String::new(),
    })
}

pub(crate) fn local_daemon_state_name(
    state: codewire_daemon::client::v1::DaemonState,
) -> &'static str {
    match state {
        codewire_daemon::client::v1::DaemonState::Unspecified => "unspecified",
        codewire_daemon::client::v1::DaemonState::Unsupported => "unsupported",
        codewire_daemon::client::v1::DaemonState::Starting => "starting",
        codewire_daemon::client::v1::DaemonState::Ready => "ready",
        codewire_daemon::client::v1::DaemonState::Unhealthy => "unhealthy",
        codewire_daemon::client::v1::DaemonState::UpgradeRequired => "upgrade_required",
    }
}

pub(super) async fn wait_for_local_environment_daemon_ready(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<EnvironmentDaemonStatus> {
    let mut last_error = None;
    for attempt in 0..LOCAL_DAEMON_READY_ATTEMPTS {
        match local_environment_daemon_status(instance).await {
            Ok(status) if status.state == "ready" => return Ok(status),
            Ok(status) if status.state == "starting" => {
                last_error = Some(anyhow::anyhow!("daemon is still starting"));
            }
            Ok(status) => {
                anyhow::bail!(
                    "local environment daemon returned state {:?}: {}",
                    status.state,
                    display_str(&status.message)
                );
            }
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < LOCAL_DAEMON_READY_ATTEMPTS {
            tokio::time::sleep(LOCAL_DAEMON_READY_RETRY_INTERVAL).await;
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("local environment daemon did not become ready")))
    .context("wait for local environment daemon readiness")
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
        #[cfg(target_os = "linux")]
        (UnifiedEnvironmentTarget::NativeLocal(name), UnifiedEnvironmentLifecycle::Start(args)) => {
            let environment = start_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        #[cfg(target_os = "linux")]
        (UnifiedEnvironmentTarget::NativeLocal(name), UnifiedEnvironmentLifecycle::Stop(args)) => {
            let environment = stop_native_environment(&name).await?;
            print_native_environment(&environment, args.output)
        }
        #[cfg(target_os = "linux")]
        (
            UnifiedEnvironmentTarget::NativeLocal(name),
            UnifiedEnvironmentLifecycle::Remove(args),
        ) => {
            let removed = delete_native_environment(&name).await?;
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
        (UnifiedEnvironmentTarget::Local(name), UnifiedEnvironmentLifecycle::Start(args)) => {
            handle_local_command(
                globals,
                LocalArgs {
                    output: args.output,
                    command: LocalCommand::Start(LocalInfoArgs { name: Some(name) }),
                },
            )
            .await
        }
        (UnifiedEnvironmentTarget::Local(name), UnifiedEnvironmentLifecycle::Stop(args)) => {
            handle_local_command(
                globals,
                LocalArgs {
                    output: args.output,
                    command: LocalCommand::Stop(LocalInfoArgs { name: Some(name) }),
                },
            )
            .await
        }
        (UnifiedEnvironmentTarget::Local(name), UnifiedEnvironmentLifecycle::Remove(args)) => {
            handle_local_command(
                globals,
                LocalArgs {
                    output: args.output,
                    command: LocalCommand::Rm(LocalInfoArgs { name: Some(name) }),
                },
            )
            .await
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

async fn resolve_unified_environment_target(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    target_ref: &str,
    command: &str,
) -> anyhow::Result<UnifiedEnvironmentTarget> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let target_ref = trimmed_required(target_ref, "environment")?;
    #[cfg(target_os = "linux")]
    let native = if placement != Some(EnvironmentPlacement::Platform) {
        native_environment(target_ref).await?
    } else {
        None
    };
    let local = resolve_local_instance_target(&paths.mesh_data_dir, target_ref);
    if placement == Some(EnvironmentPlacement::Local) {
        #[cfg(target_os = "linux")]
        if let Some(environment) = native.as_ref() {
            return Ok(UnifiedEnvironmentTarget::NativeLocal(
                environment.name.clone(),
            ));
        }
        let Some((key, _)) = local else {
            anyhow::bail!("local environment {target_ref:?} not found");
        };
        return Ok(UnifiedEnvironmentTarget::Local(key));
    }

    #[cfg(target_os = "linux")]
    if let Some(environment) = native {
        return Ok(UnifiedEnvironmentTarget::NativeLocal(environment.name));
    }

    let platform = match resolve_platform(globals, &paths, &env) {
        Ok(platform) => platform,
        Err(error) if placement.is_none() => {
            if let Some((key, _)) = local {
                return Ok(UnifiedEnvironmentTarget::Local(key));
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
        .list_environments(&org_id)
        .await
        .context("list environments")?;
    let platform_match = find_environment_match(&environments, target_ref)?;

    if placement == Some(EnvironmentPlacement::Platform) {
        let Some((id, _)) = platform_match else {
            anyhow::bail!("platform environment {target_ref:?} not found");
        };
        return Ok(UnifiedEnvironmentTarget::Platform(id));
    }

    match (local, platform_match) {
        (_, Some((id, EnvironmentMatchKind::ExactId))) => {
            Ok(UnifiedEnvironmentTarget::Platform(id))
        }
        (Some((_key, _)), Some((_id, EnvironmentMatchKind::ExactName))) => {
            Err(ambiguous_environment_placement_error(command, target_ref))
        }
        (Some((key, _)), Some((_id, EnvironmentMatchKind::IdPrefix))) => {
            Ok(UnifiedEnvironmentTarget::Local(key))
        }
        (Some((key, _)), None) => Ok(UnifiedEnvironmentTarget::Local(key)),
        (None, Some((id, _))) => Ok(UnifiedEnvironmentTarget::Platform(id)),
        (None, None) => anyhow::bail!("environment {target_ref:?} not found"),
    }
}

pub(crate) fn ambiguous_environment_placement_error(
    command: &str,
    target_ref: &str,
) -> anyhow::Error {
    anyhow::anyhow!(
        "environment {target_ref:?} exists in both placements; use `cw env {command} --local {target_ref}` or `cw env {command} --platform {target_ref}`"
    )
}

pub(crate) fn local_create_args_from_environment_args(
    args: EnvCreateArgs,
) -> anyhow::Result<LocalCreateArgs> {
    if !args.repo_urls.is_empty() || !args.repo_flags.is_empty() {
        anyhow::bail!(
            "repository arguments are only supported for --platform environment creation"
        );
    }
    if args.preset_id.is_some()
        || args.ttl.is_some()
        || !args.follow
        || args.no_wait
        || args.write_preset
        || args.save_preset.is_some()
    {
        anyhow::bail!("the selected create option is only supported for --platform environments");
    }
    let backend = args.backend.ok_or_else(|| {
        anyhow::anyhow!("legacy local creation requires --backend docker or --backend lima")
    })?;
    let cpu = parse_legacy_create_quantity(args.cpu.as_deref(), "CPU")?;
    let memory = parse_legacy_create_quantity(args.memory.as_deref(), "memory")?;
    let disk = parse_legacy_create_quantity(args.disk.as_deref(), "disk")?;
    Ok(LocalCreateArgs {
        backend,
        name: args.name,
        path: args.path.unwrap_or_else(|| PathBuf::from(".")),
        file: args.file.unwrap_or_else(|| PathBuf::from("codewire.yaml")),
        spec: args.spec,
        preset: args.preset_slug,
        image: args.image,
        install: args.install,
        startup: args.startup,
        agent: args.coding_agent,
        secrets: args.secret_project,
        env: args.env,
        cpu,
        memory,
        disk,
        no_org_secrets: args.no_org_secrets,
        no_user_secrets: args.no_user_secrets,
        network: args.network,
        no_network: args.no_network,
        yes: args.yes,
    })
}

fn parse_legacy_create_quantity(value: Option<&str>, label: &str) -> anyhow::Result<i32> {
    let Some(value) = value else {
        return Ok(0);
    };
    value
        .parse::<i32>()
        .with_context(|| format!("legacy local {label} must use the existing integer unit"))
}

pub(crate) fn reject_local_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    if args.backend.is_some() || args.path.is_some() || args.file.is_some() || args.spec.is_some() {
        anyhow::bail!("--backend, --path, --file, and --spec require `cw env create --local`");
    }
    Ok(())
}

pub(crate) fn unified_environment_list_entries(
    local: &[LocalInstanceEntry],
    platform: &[(Environment, String)],
    current: Option<&config::CurrentTargetConfig>,
) -> Vec<UnifiedEnvironmentListEntry> {
    let mut entries =
        local
            .iter()
            .map(|entry| UnifiedEnvironmentListEntry {
                name: entry.name.clone(),
                placement: "local".to_string(),
                selected: current.is_some_and(|target| {
                    target.kind == "local"
                        && (target.target_ref == entry.name || target.name == entry.name)
                }),
                state: entry.status.clone(),
                daemon_health: "unknown".to_string(),
                id: entry.runtime_name.clone(),
            })
            .chain(platform.iter().map(|(environment, daemon_health)| {
                UnifiedEnvironmentListEntry {
                    name: environment_display_name(environment).to_string(),
                    placement: "platform".to_string(),
                    selected: current.is_some_and(|target| {
                        target.kind == "env" && target.target_ref == environment.id
                    }),
                    state: environment.state.clone(),
                    daemon_health: daemon_health.clone(),
                    id: environment.id.clone(),
                }
            }))
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
                "{:<24} {:<10} {:<9} {:<14} DAEMON",
                "NAME", "PLACEMENT", "SELECTED", "STATE"
            );
            for entry in entries {
                println!(
                    "{:<24} {:<10} {:<9} {:<14} {}",
                    entry.name,
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
            anyhow::bail!("environment daemon requires an upgrade; run `cw env daemon repair`")
        }
        "unhealthy" => {
            let detail = trimmed_str(&status.message).unwrap_or("no diagnostic message");
            anyhow::bail!(
                "environment daemon is unhealthy ({detail}); run `cw env daemon status` or `cw env daemon repair`"
            );
        }
        state => anyhow::bail!(
            "environment daemon reported unknown state {state:?}; run `cw env daemon status`"
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
    let (repo_url, branch, repos) = collect_env_create_repos(
        &args.repo_urls,
        &args.repo_flags,
        args.branch.as_deref().and_then(trimmed_str),
    )?;
    let preset_id = trimmed_optional(args.preset_id.clone());
    let preset_slug = trimmed_optional(args.preset_slug.clone()).unwrap_or_default();
    let image = args
        .image
        .as_deref()
        .and_then(trimmed_str)
        .map(|image| {
            if image.contains('/') {
                image.to_string()
            } else {
                expand_image_ref(image)
            }
        })
        .unwrap_or_default();
    let agent = trimmed_optional(args.coding_agent.clone())
        .map(|agent| config::canonical_agent_id(&agent))
        .unwrap_or_default();
    let agents = if agent.is_empty() {
        Vec::new()
    } else {
        vec![SetupAgent {
            agent_type: agent.clone(),
        }]
    };

    let mut request = CreateEnvironmentRequest {
        preset_id,
        name: trimmed_optional(args.name.clone()),
        cpu_millicores: positive_i32(parse_platform_create_quantity(args.cpu.as_deref(), "CPU")?),
        memory_mb: positive_i32(parse_platform_create_quantity(
            args.memory.as_deref(),
            "memory",
        )?),
        disk_gb: positive_i32(parse_platform_create_quantity(
            args.disk.as_deref(),
            "disk",
        )?),
        ttl_seconds,
        preset_slug,
        repo_url,
        branch,
        repos,
        image,
        install_command: trimmed_optional(args.install.clone()).unwrap_or_default(),
        startup_script: trimmed_optional(args.startup.clone()).unwrap_or_default(),
        env_vars: parse_env_overrides(&args.env)?,
        agents,
        install_agents: None,
        agent,
        agent_env: BTreeMap::new(),
        secret_project: trimmed_optional(args.secret_project.clone()).unwrap_or_default(),
        app_ports: Vec::new(),
        include_org_secrets: args.no_org_secrets.then_some(false),
        include_user_secrets: args.no_user_secrets.then_some(false),
        isolation_tier: args.isolation.clone().unwrap_or_default(),
        project_spec: None,
    };
    request.project_spec = Some(project_spec_from_create_request(&request)?);
    Ok(request)
}

fn project_spec_from_create_request(
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<codewire_project::ProjectSpec> {
    let destinations = codewire_project::validate_repository_destinations(
        request
            .repos
            .iter()
            .map(|repository| (repository.url.as_str(), repository.mount_path.as_str())),
    )?;
    let repositories = request
        .repos
        .iter()
        .zip(destinations.iter())
        .map(
            |(repository, destination)| codewire_project::RepositorySpec {
                source: repository.url.clone(),
                revision: repository.revision.clone(),
                branch: repository.branch.clone(),
                destination: destination.clone(),
            },
        )
        .collect::<Vec<_>>();
    let working_directory = match repositories.as_slice() {
        [repository] => repository.destination.clone(),
        _ => "/workspace".to_string(),
    };
    let application_ports = request
        .app_ports
        .iter()
        .map(|port| {
            Ok(codewire_project::ApplicationPort {
                port: u16::try_from(port.port)
                    .map_err(|_| anyhow::anyhow!("application port is outside 1 through 65535"))?,
                label: port.label.clone(),
                access: port.access.clone(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let spec = codewire_project::ProjectSpec {
        schema_version: codewire_project::PROJECT_SCHEMA_VERSION,
        preset: request.preset_slug.clone(),
        image: request.image.clone(),
        repositories,
        working_directory,
        install_command: request.install_command.clone(),
        startup_script: request.startup_script.clone(),
        environment: request.env_vars.clone(),
        agents: codewire_project::AgentsSpec {
            install: request.install_agents,
            tools: request
                .agents
                .iter()
                .map(|agent| agent.agent_type.clone())
                .collect(),
        },
        agent_environment: request.agent_env.clone(),
        application_ports,
        resources: codewire_project::ResourceSpec {
            cpu_millicores: request.cpu_millicores.map(|value| value as u32),
            memory_mib: request.memory_mb.map(|value| value as u64),
            disk_gib: request.disk_gb.map(|value| value as u64),
        },
        secrets: codewire_project::SecretBindings {
            project: request.secret_project.clone(),
            include_org: request.include_org_secrets,
            include_user: request.include_user_secrets,
        },
        ..codewire_project::ProjectSpec::default()
    };
    spec.validate()?;
    Ok(spec)
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

pub(crate) fn prepare_platform_env_create_request(
    args: &EnvCreateArgs,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let mut request = env_create_request_from_args(args)?;
    if request.preset_id.is_none()
        && request.preset_slug.is_empty()
        && request.repo_url.is_empty()
        && request.repos.is_empty()
        && request.image.is_empty()
    {
        request.image = CANONICAL_WORKSPACE_IMAGE.to_string();
        request.project_spec = Some(project_spec_from_create_request(&request)?);
    }
    if !args.no_network {
        validate_env_create_mesh_bootstrap_env(&request)?;
    }
    Ok(request)
}

pub(crate) fn validate_env_create_mesh_bootstrap_env(
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    for key in [
        config::CODEWIRE_MESH_URL_ENV,
        config::CODEWIRE_MESH_NETWORK_ENV,
        config::CODEWIRE_MESH_INVITE_CODE_ENV,
    ] {
        if request.env_vars.contains_key(key) {
            anyhow::bail!("{key} is reserved for mesh bootstrap");
        }
    }
    Ok(())
}

pub(crate) fn inject_env_create_mesh_bootstrap(
    request: &mut CreateEnvironmentRequest,
    mesh_url: &str,
    network_id: &str,
    invite_code: &str,
) -> anyhow::Result<()> {
    validate_env_create_mesh_bootstrap_env(request)?;
    for (key, value) in [
        (config::CODEWIRE_MESH_URL_ENV, mesh_url),
        (config::CODEWIRE_MESH_NETWORK_ENV, network_id),
        (config::CODEWIRE_MESH_INVITE_CODE_ENV, invite_code),
    ] {
        request.env_vars.insert(key.to_string(), value.to_string());
    }
    Ok(())
}

pub(crate) async fn create_env_mesh_invite(
    bootstrap: &LocalMeshBootstrap,
) -> anyhow::Result<Invite> {
    MeshClient::new(&bootstrap.mesh)?
        .create_invite(&bootstrap.organization_id, &bootstrap.network_id, "24h")
        .await
        .context("create mesh invite for environment")
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewireYaml {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) image: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) install: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) startup: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secrets: Option<ResolvedCodewireSecretsYaml>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<ResolvedCodewirePortYaml>,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) cpu: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) memory: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) disk: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agents: Option<ResolvedCodewireAgentsYaml>,
}

#[derive(serde::Serialize)]
pub(crate) struct ResolvedCodewirePortYaml {
    pub(crate) port: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
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
    pub(crate) org: bool,
    pub(crate) user: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) project: String,
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
    ResolvedCodewireYaml {
        image: request.image.clone(),
        install: request.install_command.clone(),
        startup: request.startup_script.clone(),
        secrets: Some(ResolvedCodewireSecretsYaml {
            org: request.include_org_secrets.unwrap_or(true),
            user: request.include_user_secrets.unwrap_or(true),
            project: request.secret_project.clone(),
        }),
        env: request.env_vars.clone(),
        ports: request
            .app_ports
            .iter()
            .map(|port| ResolvedCodewirePortYaml {
                port: port.port,
                label: port.label.clone(),
            })
            .collect(),
        cpu: request.cpu_millicores.unwrap_or_default(),
        memory: request.memory_mb.unwrap_or_default(),
        disk: request.disk_gb.unwrap_or_default(),
        agents: codewire_yaml_agents_from_request(request),
    }
}

pub(crate) fn codewire_yaml_agents_from_request(
    request: &CreateEnvironmentRequest,
) -> Option<ResolvedCodewireAgentsYaml> {
    let mut tools = request
        .agents
        .iter()
        .filter_map(|agent| {
            let tool = config::display_agent_id(&agent.agent_type);
            (!tool.is_empty()).then_some(tool)
        })
        .collect::<Vec<_>>();
    if tools.is_empty()
        && let Some(agent) = trimmed_str(&request.agent)
    {
        let tool = config::display_agent_id(agent);
        if !tool.is_empty() {
            tools.push(tool);
        }
    }
    if tools.is_empty() && request.install_agents.is_none() {
        return None;
    }
    Some(ResolvedCodewireAgentsYaml {
        install: request.install_agents,
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
    Ok(CreatePresetRequest {
        name: name.to_string(),
        slug,
        default_cpu_millicores: request.cpu_millicores,
        default_memory_mb: request.memory_mb,
        default_disk_gb: request.disk_gb,
        default_ttl_seconds: request.ttl_seconds,
        image: request.image.clone(),
        install_command: request.install_command.clone(),
        startup_script: request.startup_script.clone(),
        env_vars: request.env_vars.clone(),
        agents: request
            .agents
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
        install_agents: request.install_agents,
        agent: request.agent.clone(),
        agent_env: request.agent_env.clone(),
        app_ports: request
            .app_ports
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
        include_org_secrets: request.include_org_secrets,
        include_user_secrets: request.include_user_secrets,
        secret_project: request.secret_project.clone(),
        ..CreatePresetRequest::default()
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
) -> anyhow::Result<(String, String, Vec<RepoEntry>)> {
    let mut repos = Vec::new();
    for spec in repo_urls.iter().chain(repo_flags.iter()) {
        let (url, repo_branch, mount_path) = parse_env_create_repo_spec(spec)?;
        repos.push(RepoEntry {
            url,
            branch: repo_branch,
            mount_path,
            revision: String::new(),
        });
    }

    let mut repo_url = String::new();
    let mut branch = branch.unwrap_or("").to_string();
    if let Some(first) = repos.first() {
        repo_url = first.url.clone();
        if repos.len() == 1 && branch.is_empty() {
            branch = first.branch.clone();
        }
    }

    Ok((repo_url, branch, repos))
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
    if !url.contains('/') {
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

pub(crate) async fn handle_env_access_command(
    client: &EnvironmentClient,
    org_id: &str,
    command: EnvAccessCommand,
) -> anyhow::Result<()> {
    match command {
        EnvAccessCommand::List(args) => {
            let environment_id = resolve_environment_id(client, org_id, &args.environment).await?;
            let grants = client
                .list_environment_access(org_id, &environment_id)
                .await
                .context("list access")?;
            print_env_access_list(&grants, args.output)?;
        }
        EnvAccessCommand::Grant(args) => {
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
        EnvAccessCommand::Revoke(args) => {
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
    command: EnvPortCommand,
) -> anyhow::Result<()> {
    match command {
        EnvPortCommand::Add(args) => {
            let port = parse_env_port_number(&args.port)?;
            let label = trimmed_str(&args.label)
                .ok_or_else(|| anyhow::anyhow!("--label is required"))?
                .to_string();
            let access = trimmed_str(&args.access).unwrap_or("creator").to_string();
            let environment_id = resolve_port_environment_id(
                environment_client,
                org_id,
                data_dir,
                args.env.as_deref(),
            )
            .await?;
            let result = environment_client
                .create_environment_port(
                    org_id,
                    &environment_id,
                    &CreateEnvironmentPortRequest {
                        port,
                        label,
                        access,
                    },
                )
                .await
                .context("create port")?;
            print_env_port_add(&result, args.output)?;
        }
        EnvPortCommand::List(args) => {
            let environment_id = resolve_port_environment_id(
                environment_client,
                org_id,
                data_dir,
                args.env.as_deref(),
            )
            .await?;
            let ports = environment_client
                .list_environment_ports(org_id, &environment_id)
                .await
                .context("list ports")?;
            print_env_port_list(&ports, args.output)?;
        }
        EnvPortCommand::Rm(args) => {
            let environment_id = resolve_port_environment_id(
                environment_client,
                org_id,
                data_dir,
                args.env.as_deref(),
            )
            .await?;
            let ports = environment_client
                .list_environment_ports(org_id, &environment_id)
                .await
                .context("list ports")?;
            let target = resolve_environment_port(&ports, &args.port)?;
            environment_client
                .delete_environment_port(org_id, &environment_id, &target.id)
                .await
                .context("delete port")?;
            print_env_port_rm(&target, args.output)?;
        }
    }
    Ok(())
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
        anyhow::anyhow!(
            "no environment specified and no current target set (use --env or `cw use`)"
        )
    })?;
    if current.kind != "env" || trimmed_str(&current.target_ref).is_none() {
        anyhow::bail!("no environment specified and no current target set (use --env or `cw use`)");
    }
    resolve_environment_id(client, org_id, &current.target_ref).await
}

pub(crate) fn parse_env_port_number(value: &str) -> anyhow::Result<i32> {
    let Ok(port) = value.parse::<i32>() else {
        anyhow::bail!("invalid port number: {value}");
    };
    if !(1..=65535).contains(&port) {
        anyhow::bail!("invalid port number: {value}");
    }
    Ok(port)
}

pub(crate) fn resolve_environment_port(
    ports: &[EnvironmentPort],
    port_ref: &str,
) -> anyhow::Result<EnvironmentPort> {
    let port_ref = trimmed_str(port_ref).unwrap_or(port_ref);
    for port in ports {
        if port.label == port_ref || port.id == port_ref || port.port.to_string() == port_ref {
            return Ok(port.clone());
        }
    }
    anyhow::bail!("port {port_ref:?} not found")
}

pub(crate) async fn follow_environment_logs(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let mut phases = HashMap::new();
    client
        .stream_environment_logs(org_id, environment_id, |event| {
            eprint!(
                "{}",
                format_environment_log_event(&event, &mut phases, None)
            );
            !is_terminal_environment_log(&event)
        })
        .await
        .context("connect to log stream")
}

pub(crate) fn print_environment_logs_historical(logs: &[EnvironmentLog]) {
    if logs.is_empty() {
        println!("No logs yet.");
        return;
    }

    let mut phases = HashMap::new();
    for event in logs {
        eprint!(
            "{}",
            format_environment_log_event_historical(event, &mut phases)
        );
    }
}

pub(crate) fn format_environment_log_event_historical(
    event: &EnvironmentLog,
    phases: &mut HashMap<String, DateTime<Utc>>,
) -> String {
    let created_at = parse_environment_log_time(&event.created_at);
    format_environment_log_event(event, phases, created_at)
}

pub(crate) fn format_environment_log_event(
    event: &EnvironmentLog,
    phases: &mut HashMap<String, DateTime<Utc>>,
    event_time: Option<DateTime<Utc>>,
) -> String {
    match event.status.as_str() {
        "started" => {
            let start = event_time.unwrap_or_else(Utc::now);
            phases.insert(event.phase.clone(), start);
            format!("  ◌ {}...\n", event.message)
        }
        "completed" => {
            let elapsed = phases.get(&event.phase).and_then(|start| {
                event_time.map(|end| format!("  {}", format_elapsed_seconds(end - *start)))
            });
            format!(
                "  ✓ {}{}\n",
                event.message,
                elapsed.as_deref().unwrap_or("")
            )
        }
        "warning" => format!("  ! {}\n", event.message),
        "failed" => format!("  ✗ {}\n", event.message),
        _ => format!("  · {}\n", event.message),
    }
}

pub(crate) fn parse_environment_log_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

pub(crate) fn format_elapsed_seconds(duration: ChronoDuration) -> String {
    let seconds = duration.num_seconds().max(0);
    format!("{seconds}s")
}

pub(crate) fn is_terminal_environment_log(event: &EnvironmentLog) -> bool {
    event.phase == "complete" || event.status == "failed"
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

pub(crate) fn print_env_list(
    environments: &[Environment],
    current: Option<&config::CurrentTargetConfig>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(environments)?),
        OutputFormat::Text => print!("{}", format_env_list_text(environments, current)),
    }
    Ok(())
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
        "    Gateway: {}\n",
        display_opt(report.images.gateway_image.as_deref())
    ));
    output.push_str(&format!(
        "    Gateway image ID: {}\n",
        display_opt(report.images.gateway_image_id.as_deref())
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
            "Environment {environment_ref} scheduled for deletion (grace period).\nUse 'cw env cancel-delete {environment_ref}' to cancel."
        );
    }
    if message.contains("environment_protected") {
        return anyhow::anyhow!(
            "environment is protected. Run 'cw env unprotect {environment_ref}' first"
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

pub(crate) fn format_env_list_text(
    environments: &[Environment],
    current: Option<&config::CurrentTargetConfig>,
) -> String {
    if environments.is_empty() {
        return "No environments found.\n".to_string();
    }

    let current_ref = current
        .filter(|target| target.kind == "env")
        .and_then(|target| trimmed_str(&target.target_ref));
    let mut output = String::new();
    for (index, environment) in environments.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&format_env_card_text(environment, current_ref));
    }
    output
}

pub(crate) fn format_env_card_text(environment: &Environment, current_ref: Option<&str>) -> String {
    let marker = if current_ref.is_some_and(|current| current == environment.id) {
        " (current)"
    } else {
        ""
    };
    let protected = if environment.protected {
        " [protected]"
    } else {
        ""
    };

    let mut output = format!(
        "{} [{}]  {}  {}{}{}\n",
        environment_display_name(environment),
        short_env_id(&environment.id),
        env_state_label(environment),
        env_created_label(environment),
        marker,
        protected
    );
    output.push_str(&format!(
        "  {}  {}m/{}MB  ttl {}\n",
        env_type_label(environment),
        environment.cpu_millicores,
        environment.memory_mb,
        env_ttl_label(environment)
    ));
    if let Some(network) = environment.network.as_deref().and_then(trimmed_str) {
        output.push_str(&format!("  network: {network}\n"));
    }
    if let Some(deleting_at) = environment
        .deletion_grace_until
        .as_deref()
        .and_then(trimmed_str)
    {
        output.push_str(&format!("  deleting at: {deleting_at}\n"));
    }
    output.push_str(&format!("  connect: {}\n", env_connect_hint(environment)));
    output
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

pub(crate) fn env_ttl_label(environment: &Environment) -> String {
    if let Some(ttl_seconds) = environment.ttl_seconds {
        return format!("{ttl_seconds}s");
    }
    if environment
        .shutdown_at
        .as_deref()
        .and_then(trimmed_str)
        .is_some()
    {
        return "set".to_string();
    }
    "--".to_string()
}

pub(crate) fn env_connect_hint(environment: &Environment) -> String {
    if env_type_label(environment) == "sandbox" && environment.state == "running" {
        return format!("cw shell {}", short_env_id(&environment.id));
    }
    "--".to_string()
}
