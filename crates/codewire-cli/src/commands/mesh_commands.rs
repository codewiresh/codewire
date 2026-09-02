use super::*;

pub(crate) async fn handle_network_command(
    globals: &Globals,
    command: NetworkCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);

    match command {
        NetworkCommand::List(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, None)?;
            let networks = MeshClient::new(&mesh)?.list_networks(org_id).await?;
            print_networks(&networks, mesh.selected_network.as_deref(), args.output)?;
        }
        NetworkCommand::Create(args) => {
            let network_id = trimmed_required(&args.name, "network name")?;
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, None)?;
            MeshClient::new(&mesh)?
                .create_network(org_id, network_id)
                .await?;
            if args.no_use {
                eprintln!("Network {network_id:?} created");
            } else {
                config::save_selected_mesh_network(&paths.mesh_data_dir, network_id)?;
                update_local_mesh_owner_selection(
                    &paths.mesh_data_dir,
                    Some(&mesh.mesh_url),
                    Some(network_id),
                    false,
                )?;
                eprintln!("Network {network_id:?} created and selected");
            }
        }
        NetworkCommand::Current => match config::selected_mesh_network(&paths, &env) {
            Some(network_id) => println!("{network_id}"),
            None => println!("none"),
        },
        NetworkCommand::Use(args) => {
            let network_id = trimmed_required(&args.name, "network name")?;
            config::save_selected_mesh_network_preference(
                &paths.mesh_data_dir,
                network_id,
                args.auto_connect,
            )?;
            update_local_mesh_owner_selection(
                &paths.mesh_data_dir,
                None,
                Some(network_id),
                args.auto_connect,
            )?;
            eprintln!(
                "Selected network {network_id:?} ({})",
                if args.auto_connect {
                    "new environments connect automatically"
                } else {
                    "new environments ask before connecting"
                }
            );
        }
        NetworkCommand::Clear => {
            config::clear_selected_mesh_network(&paths.mesh_data_dir)?;
            update_local_mesh_owner_selection(&paths.mesh_data_dir, None, None, false)?;
            eprintln!("Cleared selected network");
        }
        NetworkCommand::Nodes(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            if args.all
                && args
                    .network
                    .as_ref()
                    .is_some_and(|network| !network.trim().is_empty())
            {
                anyhow::bail!("--all and --network cannot be used together");
            }
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, args.network)?;
            let network_id = if args.all {
                None
            } else {
                Some(
                    mesh.selected_network
                        .as_deref()
                        .and_then(|network| {
                            let network = network.trim();
                            (!network.is_empty()).then_some(network)
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "network not selected (run 'cw network use <name>' or pass --network)"
                            )
                        })?,
                )
            };
            let nodes = MeshClient::new(&mesh)?
                .list_nodes(org_id, network_id)
                .await?;
            print_nodes(&nodes, args.all, args.output)?;
        }
        NetworkCommand::Invite(args) => {
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, args.network)?;
            let network_id = selected_network_or_error(&mesh)?;
            let ttl = trimmed_required(&args.ttl, "ttl")?;
            let invite = MeshClient::new(&mesh)?
                .create_invite(org_id, network_id, ttl)
                .await?;
            print_invite(&invite, &mesh.mesh_url, args.output)?;
        }
        NetworkCommand::Join(args) => {
            let invite_code = trimmed_required(&args.invite_code, "invitation code")?;
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, None)?;
            let joined = MeshClient::new(&mesh)?.join_network(invite_code).await?;
            config::save_joined_network(&paths.mesh_data_dir, &mesh.mesh_url, &joined.network_id)?;
            update_local_mesh_owner_selection(
                &paths.mesh_data_dir,
                Some(&mesh.mesh_url),
                Some(&joined.network_id),
                false,
            )?;
            eprintln!("Joined network {:?}", joined.network_id);
            eprintln!("Selected network is ready for Mesh commands.");
        }
        NetworkCommand::Revoke(args) => {
            let node_name = trimmed_required(&args.node_name, "node name")?;
            let org_id = trimmed_required(&args.org, "organization ID")?;
            let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, args.network)?;
            let network_id = selected_network_or_error(&mesh)?;
            MeshClient::new(&mesh)?
                .revoke_node(org_id, network_id, node_name)
                .await?;
            eprintln!("Node {node_name:?} revoked");
        }
        NetworkCommand::Enroll { command } => match command {
            NetworkEnrollCommand::Create(args) => {
                let org_id = trimmed_required(&args.org, "organization ID")?;
                let mesh = resolve_mesh(globals, &paths, &env, args.mesh_url, args.network)?;
                let network_id = selected_network_or_error(&mesh)?;
                let node_name = args.node_name.as_deref().map(str::trim).unwrap_or("");
                let ttl = trimmed_required(&args.ttl, "ttl")?;
                let enrollment = MeshClient::new(&mesh)?
                    .create_node_enrollment(org_id, network_id, node_name, ttl)
                    .await?;
                print_node_enrollment(&enrollment, args.output)?;
            }
            NetworkEnrollCommand::Redeem(args) => {
                let code = trimmed_required(&args.enrollment_code, "enrollment code")?;
                let node_name = args.node_name.as_deref().map(str::trim).unwrap_or("");
                let mesh_url = config::resolve_mesh_base_url(
                    config::MeshResolveOptions {
                        mesh_url: args.mesh_url,
                        platform_server_url: globals.server.clone(),
                        ..config::MeshResolveOptions::default()
                    },
                    &paths,
                    &env,
                )?;
                let redeemed = MeshClient::unauthenticated(&mesh_url)?
                    .redeem_node_enrollment(code, node_name)
                    .await?;
                save_redeemed_node_enrollment(&paths.mesh_data_dir, &mesh_url, &redeemed)?;
                eprintln!("Node {:?} enrolled", redeemed.node_name);
            }
        },
    }

    Ok(())
}

pub(crate) async fn handle_mesh_command(
    globals: &Globals,
    command: MeshCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    match command {
        MeshCommand::Up(args) => {
            let output = args.output;
            let report = handle_mesh_up(&paths, args).await?;
            print_mesh_up_report(&report, output)
        }
        MeshCommand::Status(args) => {
            let report = mesh_status_report(globals, &paths, &env);
            print_mesh_status_report(&report, args.output)
        }
        MeshCommand::Down(args) => {
            let report = handle_mesh_down(&paths).await?;
            print_mesh_down_report(&report, args.output)
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshStatusReport {
    pub(crate) mesh_data_dir: String,
    pub(crate) configured: bool,
    pub(crate) mesh_url: Option<String>,
    pub(crate) selected_network: Option<String>,
    pub(crate) auto_connect: bool,
    pub(crate) auth_configured: bool,
    pub(crate) auth_source: Option<config::MeshAuthSource>,
    pub(crate) local: LocalMeshStatus,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalMeshStatus {
    pub(crate) state: String,
    pub(crate) pid: Option<u32>,
    pub(crate) base_url: Option<String>,
    pub(crate) listen_addr: Option<String>,
    pub(crate) binary: Option<String>,
    pub(crate) log_path: Option<String>,
    pub(crate) derp: Option<LocalDerpStatus>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalDerpStatus {
    pub(crate) state: String,
    pub(crate) pid: Option<u32>,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct LocalMeshRuntime {
    pub(crate) pid: u32,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
    pub(crate) started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) derp: Option<LocalDerpRuntime>,
}

/// Credential-free projection consumed by native environment creation. It is
/// intentionally separate from both process state and the protected Mesh
/// config so the ordinary `cw env` process never deserializes a bearer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalMeshOwnerContext {
    pub(crate) schema_version: u32,
    pub(crate) auth_source: LocalMeshOwnerAuthSource,
    pub(crate) mesh_url: String,
    pub(crate) organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_network: Option<String>,
    #[serde(default)]
    pub(crate) auto_connect: bool,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalMeshOwnerAuthSource {
    StandaloneLocal,
    HostedCurrent,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct LocalDerpRuntime {
    pub(crate) pid: u32,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalMeshStartSpec {
    pub(crate) binary: PathBuf,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) auth_token: String,
    pub(crate) local_identity: config::LocalMeshIdentity,
    pub(crate) log_path: PathBuf,
    pub(crate) derp: Option<LocalDerpStartSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalDerpStartSpec {
    pub(crate) binary: PathBuf,
    pub(crate) url: String,
    pub(crate) listen_addr: String,
    pub(crate) log_path: PathBuf,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshUpReport {
    pub(crate) started: bool,
    pub(crate) pid: u32,
    pub(crate) base_url: String,
    pub(crate) listen_addr: String,
    pub(crate) binary: String,
    pub(crate) log_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) derp: Option<LocalDerpRuntime>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct MeshDownReport {
    pub(crate) stopped: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) state: String,
}

pub(crate) fn mesh_status_report(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> MeshStatusReport {
    let opts = config::MeshResolveOptions {
        mesh_url: None,
        auth_token: globals.token.clone(),
        network_id: None,
        platform_server_url: globals.server.clone(),
    };
    let mesh_url = config::resolve_mesh_base_url(opts.clone(), paths, env).ok();
    let resolved = config::resolve_mesh(opts, paths, env).ok();
    let selected_network = resolved
        .as_ref()
        .and_then(|mesh| mesh.selected_network.clone())
        .or_else(|| config::selected_mesh_network(paths, env));
    let auth_configured = resolved
        .as_ref()
        .map(config::ResolvedMeshConfig::auth_configured)
        .unwrap_or(false);
    let auth_source = resolved.as_ref().map(|mesh| mesh.auth_source);
    let auto_connect = config::load_mesh_config(&paths.mesh_data_dir)
        .ok()
        .is_some_and(|mesh| {
            mesh.mesh_auto_connect.unwrap_or(false)
                && mesh.mesh_selected_network.as_deref().and_then(trimmed_str)
                    == selected_network.as_deref().and_then(trimmed_str)
        });

    MeshStatusReport {
        mesh_data_dir: paths.mesh_data_dir.display().to_string(),
        configured: mesh_url.is_some(),
        mesh_url,
        selected_network,
        auto_connect,
        auth_configured,
        auth_source,
        local: local_mesh_status(&paths.mesh_data_dir),
    }
}

pub(crate) fn print_mesh_status_report(
    report: &MeshStatusReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        OutputFormat::Text => {
            print!("{}", format_mesh_status_report(report));
        }
    }
    Ok(())
}

pub(crate) fn format_mesh_status_report(report: &MeshStatusReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Mesh:        {}\n",
        if report.configured {
            "configured"
        } else {
            "unconfigured"
        }
    ));
    out.push_str(&format!(
        "URL:         {}\n",
        report.mesh_url.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "Network:     {}\n",
        report.selected_network.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "Auto-connect: {}\n",
        if report.auto_connect { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "Auth:        {}\n",
        if report.auth_configured {
            "configured"
        } else {
            "unconfigured"
        }
    ));
    out.push_str(&format!(
        "Auth source: {}\n",
        report
            .auth_source
            .map(mesh_auth_source_label)
            .unwrap_or("-")
    ));
    out.push_str(&format!(
        "Local:       {}{}\n",
        report.local.state,
        report
            .local
            .pid
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default()
    ));
    if let Some(base_url) = report.local.base_url.as_deref() {
        out.push_str(&format!("Local URL:   {base_url}\n"));
    }
    if let Some(listen_addr) = report.local.listen_addr.as_deref() {
        out.push_str(&format!("Listen:      {listen_addr}\n"));
    }
    if let Some(log_path) = report.local.log_path.as_deref() {
        out.push_str(&format!("Log:         {log_path}\n"));
    }
    if let Some(derp) = report.local.derp.as_ref() {
        out.push_str(&format!(
            "DERP:        {}{}\n",
            derp.state,
            derp.pid
                .map(|pid| format!(" (pid {pid})"))
                .unwrap_or_default()
        ));
        out.push_str(&format!("DERP URL:    {}\n", derp.url));
        out.push_str(&format!("DERP listen: {}\n", derp.listen_addr));
        out.push_str(&format!("DERP log:    {}\n", derp.log_path));
    }
    out.push_str(&format!("Data dir:    {}\n", report.mesh_data_dir));
    out
}

pub(crate) fn mesh_auth_source_label(source: config::MeshAuthSource) -> &'static str {
    match source {
        config::MeshAuthSource::Explicit => "explicit",
        config::MeshAuthSource::MeshEnv => "mesh_env",
        config::MeshAuthSource::MeshConfig => "mesh_config",
        config::MeshAuthSource::ApiKeyEnv => "api_key_env",
        config::MeshAuthSource::PlatformConfig => "platform_config",
    }
}

pub(crate) async fn handle_mesh_up(
    paths: &ResolvePaths,
    args: MeshUpArgs,
) -> anyhow::Result<MeshUpReport> {
    let local_identity = config::ensure_local_mesh_identity(&paths.mesh_data_dir)
        .context("initialize standalone Mesh identity")?;
    let mesh_config = config::load_mesh_config(&paths.mesh_data_dir)?;
    let selected_network = mesh_config
        .mesh_selected_network
        .and_then(|network| trimmed_str(&network).map(str::to_owned));
    let auto_connect = selected_network.is_some() && mesh_config.mesh_auto_connect.unwrap_or(false);
    if let Some(runtime) = load_local_mesh_runtime(&paths.mesh_data_dir)?
        && local_process_is_running(runtime.pid)
    {
        if local_mesh_runtime_matches_args(&runtime, &args) {
            save_local_mesh_owner_context(
                &paths.mesh_data_dir,
                &LocalMeshOwnerContext {
                    schema_version: 1,
                    auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                    mesh_url: runtime.base_url.clone(),
                    organization_id: local_identity.organization_id,
                    selected_network,
                    auto_connect,
                },
            )?;
            return Ok(mesh_up_report(false, &runtime));
        }
        stop_local_process(runtime.pid, "local Codewire Mesh").await?;
        if let Some(derp) = runtime.derp.as_ref()
            && local_process_is_running(derp.pid)
        {
            stop_local_process(derp.pid, "local Codewire DERP").await?;
        }
        remove_local_mesh_runtime(&paths.mesh_data_dir)?;
    }
    remove_local_mesh_owner_context(&paths.mesh_data_dir)?;

    let organization_id = local_identity.organization_id.clone();
    let spec = local_mesh_start_spec(paths, &args, local_identity)?;
    let derp = match spec.derp.as_ref() {
        Some(derp_spec) => Some(start_local_derp_process(derp_spec)?),
        None => None,
    };
    let pid = match start_local_mesh_process(&spec) {
        Ok(pid) => pid,
        Err(err) => {
            if let Some(derp) = derp.as_ref() {
                let _ = stop_local_process(derp.pid, "local Codewire DERP").await;
            }
            return Err(err);
        }
    };
    if let Err(error) = wait_for_standalone_mesh_catalog(
        paths,
        &spec,
        &organization_id,
        selected_network.as_deref(),
    )
    .await
    {
        let _ = stop_local_process(pid, "local Codewire Mesh").await;
        if let Some(derp) = derp.as_ref() {
            let _ = stop_local_process(derp.pid, "local Codewire DERP").await;
        }
        return Err(error);
    }
    let runtime = LocalMeshRuntime {
        pid,
        base_url: spec.base_url.clone(),
        listen_addr: spec.listen_addr.clone(),
        binary: spec.binary.display().to_string(),
        log_path: spec.log_path.display().to_string(),
        started_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        derp,
    };
    let persist = (|| -> anyhow::Result<()> {
        config::save_mesh_connection(&paths.mesh_data_dir, &spec.base_url, &spec.auth_token)
            .context("save local mesh config")?;
        save_local_mesh_runtime(&paths.mesh_data_dir, &runtime)?;
        save_local_mesh_owner_context(
            &paths.mesh_data_dir,
            &LocalMeshOwnerContext {
                schema_version: 1,
                auth_source: LocalMeshOwnerAuthSource::StandaloneLocal,
                mesh_url: runtime.base_url.clone(),
                organization_id,
                selected_network,
                auto_connect,
            },
        )
    })();
    if let Err(error) = persist {
        let mesh_stop = stop_local_process(runtime.pid, "local Codewire Mesh").await;
        let derp_stop = match runtime.derp.as_ref() {
            Some(derp) => stop_local_process(derp.pid, "local Codewire DERP").await,
            None => Ok(()),
        };
        if let Err(cleanup) = mesh_stop.and(derp_stop) {
            return Err(error.context(format!(
                "started local Mesh state could not be persisted and process cleanup failed: {cleanup}"
            )));
        }
        let _ = remove_local_mesh_runtime(&paths.mesh_data_dir);
        let _ = remove_mesh_owner_context_for_auth_source(
            &paths.mesh_data_dir,
            LocalMeshOwnerAuthSource::StandaloneLocal,
        );
        return Err(error);
    }
    Ok(mesh_up_report(true, &runtime))
}

async fn wait_for_standalone_mesh_catalog(
    paths: &ResolvePaths,
    spec: &LocalMeshStartSpec,
    organization_id: &str,
    selected_network: Option<&str>,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let resolved = config::resolve_mesh(
        config::MeshResolveOptions {
            mesh_url: Some(spec.base_url.clone()),
            auth_token: Some(spec.auth_token.clone()),
            ..config::MeshResolveOptions::default()
        },
        paths,
        &env,
    )?;
    let client = MeshClient::new(&resolved)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let result = match selected_network {
            Some(network_id) => client.create_network(organization_id, network_id).await,
            None => client.list_networks(organization_id).await.map(|_| ()),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(error);
            }
            Err(error) => {
                return Err(error).context("initialize standalone Mesh catalog");
            }
        }
    }
}

pub(crate) fn local_mesh_runtime_matches_args(
    runtime: &LocalMeshRuntime,
    args: &MeshUpArgs,
) -> bool {
    runtime.base_url == args.base_url
        && runtime.listen_addr == args.listen
        && match (runtime.derp.as_ref(), args.no_derp) {
            (None, true) => true,
            (Some(derp), false) => {
                derp.url == args.derp_url && derp.listen_addr == args.derp_listen
            }
            _ => false,
        }
}

pub(crate) fn print_mesh_up_report(
    report: &MeshUpReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => {
            println!(
                "{} local Codewire Mesh at {} (pid {}).",
                if report.started {
                    "Started"
                } else {
                    "Using existing"
                },
                report.base_url,
                report.pid
            );
            println!("HTTP listen: {}", report.listen_addr);
            if let Some(derp) = report.derp.as_ref() {
                println!("DERP:        {} (pid {})", derp.url, derp.pid);
                println!("DERP listen: {}", derp.listen_addr);
                println!("DERP log:    {}", derp.log_path);
            }
            println!("Log:         {}", report.log_path);
        }
    }
    Ok(())
}

pub(crate) async fn handle_mesh_down(paths: &ResolvePaths) -> anyhow::Result<MeshDownReport> {
    let Some(runtime) = load_local_mesh_runtime(&paths.mesh_data_dir)? else {
        remove_mesh_owner_context_for_auth_source(
            &paths.mesh_data_dir,
            LocalMeshOwnerAuthSource::StandaloneLocal,
        )?;
        return Ok(MeshDownReport {
            stopped: false,
            pid: None,
            state: "not_running".to_string(),
        });
    };

    let mut stopped = false;
    let mesh_running = local_process_is_running(runtime.pid);
    if mesh_running {
        stop_local_process(runtime.pid, "local Codewire Mesh").await?;
        stopped = true;
    }
    if let Some(derp) = runtime.derp.as_ref()
        && local_process_is_running(derp.pid)
    {
        stop_local_process(derp.pid, "local Codewire DERP").await?;
        stopped = true;
    }
    remove_local_mesh_runtime(&paths.mesh_data_dir)?;
    remove_mesh_owner_context_for_auth_source(
        &paths.mesh_data_dir,
        LocalMeshOwnerAuthSource::StandaloneLocal,
    )?;
    Ok(MeshDownReport {
        stopped,
        pid: Some(runtime.pid),
        state: if stopped { "stopped" } else { "stale" }.to_string(),
    })
}

pub(crate) fn print_mesh_down_report(
    report: &MeshDownReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => {
            if let Some(pid) = report.pid {
                match report.state.as_str() {
                    "stopped" => println!("Stopped local Codewire Mesh (pid {pid})."),
                    "stale" => println!("Removed stale local Codewire Mesh state (pid {pid})."),
                    _ => println!("Local Codewire Mesh state: {}", report.state),
                }
            } else {
                println!("Local Codewire Mesh is not running.");
            }
        }
    }
    Ok(())
}

pub(crate) fn local_mesh_start_spec(
    paths: &ResolvePaths,
    args: &MeshUpArgs,
    local_identity: config::LocalMeshIdentity,
) -> anyhow::Result<LocalMeshStartSpec> {
    let base_url = trimmed_required(&args.base_url, "base URL")?.to_string();
    let listen_addr = trimmed_required(&args.listen, "listen address")?.to_string();
    let binary = locate_codewire_mesh_binary(args.binary.as_ref());
    let derp = if args.no_derp {
        None
    } else {
        Some(LocalDerpStartSpec {
            binary: locate_codewire_derp_binary(args.derp_binary.as_ref()),
            url: trimmed_required(&args.derp_url, "DERP URL")?.to_string(),
            listen_addr: trimmed_required(&args.derp_listen, "DERP listen address")?.to_string(),
            log_path: paths.mesh_data_dir.join(LOCAL_DERP_LOG_FILE),
        })
    };
    Ok(LocalMeshStartSpec {
        binary,
        base_url,
        listen_addr,
        auth_token: local_identity.api_key.clone(),
        local_identity,
        log_path: paths.mesh_data_dir.join(LOCAL_MESH_LOG_FILE),
        derp,
    })
}

pub(crate) fn locate_codewire_mesh_binary(override_path: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = override_path {
        return path.clone();
    }
    if let Ok(current) = env::current_exe()
        && let Some(dir) = current.parent()
    {
        let sibling = dir.join("codewire-mesh");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("codewire-mesh")
}

pub(crate) fn locate_codewire_derp_binary(override_path: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = override_path {
        return path.clone();
    }
    if let Ok(current) = env::current_exe()
        && let Some(dir) = current.parent()
    {
        let sibling = dir.join("codewire-derp");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("codewire-derp")
}

pub(crate) fn start_local_mesh_process(spec: &LocalMeshStartSpec) -> anyhow::Result<u32> {
    if let Some(parent) = spec.log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .with_context(|| format!("open {}", spec.log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("clone {}", spec.log_path.display()))?;
    let mut command = ProcessCommand::new(&spec.binary);
    command
        .arg("--base-url")
        .arg(&spec.base_url)
        .arg("--listen")
        .arg(&spec.listen_addr)
        // The local API key remains a standard cw_ credential. Keep it out
        // of argv; only hash-only verification material reaches the Mesh
        // process besides its normal local environment. The client retains
        // the credential; Mesh itself no longer accepts a separate server
        // auth-token mode.
        .env(
            "CODEWIRE_MESH_LOCAL_ORGANIZATION_ID",
            &spec.local_identity.organization_id,
        )
        .env(
            "CODEWIRE_MESH_LOCAL_API_KEY_HASH",
            spec.local_identity.api_key_hash(),
        )
        .env(
            "CODEWIRE_MESH_LOCAL_ENVIRONMENT_ID",
            &spec.local_identity.environment_id,
        )
        .env(
            "CODEWIRE_MESH_LOCAL_ENVIRONMENT_TOKEN_HASH",
            spec.local_identity.environment_token_hash(),
        )
        .stdin(Stdio::null());
    if let Some(derp) = spec.derp.as_ref() {
        command.arg("--derp-url").arg(&derp.url);
    }
    let mut child = command
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| {
            format!(
                "start codewire-mesh via {} (install codewire-mesh or pass --binary)",
                spec.binary.display()
            )
        })?;

    std::thread::sleep(Duration::from_millis(150));
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("check codewire-mesh pid {}", child.id()))?
    {
        anyhow::bail!(
            "codewire-mesh exited immediately with {status}; see {}",
            spec.log_path.display()
        );
    }
    Ok(child.id())
}

pub(crate) fn start_local_derp_process(
    spec: &LocalDerpStartSpec,
) -> anyhow::Result<LocalDerpRuntime> {
    if let Some(parent) = spec.log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spec.log_path)
        .with_context(|| format!("open {}", spec.log_path.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("clone {}", spec.log_path.display()))?;
    let mut child = ProcessCommand::new(&spec.binary);
    child
        // Standalone Mesh advertises its loopback DERP URL with the
        // InsecureForTests marker so the transport can admit this one
        // self-signed endpoint. The relay itself still runs encrypted TLS;
        // never turn the managed local process into a plaintext DERP server.
        .env_remove("LISTEN_ADDR")
        .env("PORT", "-1")
        .env("TLS_LISTEN_ADDR", &spec.listen_addr)
        .env("STUN_LISTEN_ADDR", "-1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));

    let mut child = child.spawn().with_context(|| {
        format!(
            "start codewire-derp via {} (install codewire-derp, pass --derp-binary, or use --no-derp)",
            spec.binary.display()
        )
    })?;

    std::thread::sleep(Duration::from_millis(150));
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("check codewire-derp pid {}", child.id()))?
    {
        anyhow::bail!(
            "codewire-derp exited immediately with {status}; see {}",
            spec.log_path.display()
        );
    }

    Ok(LocalDerpRuntime {
        pid: child.id(),
        url: spec.url.clone(),
        listen_addr: spec.listen_addr.clone(),
        binary: spec.binary.display().to_string(),
        log_path: spec.log_path.display().to_string(),
    })
}

pub(crate) async fn stop_local_process(pid: u32, label: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let status = ProcessCommand::new("kill")
            .arg(pid.to_string())
            .status()
            .with_context(|| format!("stop {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to stop {label} pid {pid}: {status}");
        }
        if wait_for_local_process_exit(pid, Duration::from_secs(2)).await {
            return Ok(());
        }
        let status = ProcessCommand::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status()
            .with_context(|| format!("kill unresponsive {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to kill unresponsive {label} pid {pid}: {status}");
        }
        if !wait_for_local_process_exit(pid, Duration::from_secs(2)).await {
            anyhow::bail!("{label} pid {pid} did not exit after SIGKILL");
        }
    }
    #[cfg(windows)]
    {
        let status = ProcessCommand::new("taskkill")
            .arg("/PID")
            .arg(pid.to_string())
            .arg("/T")
            .status()
            .with_context(|| format!("stop {label} pid {pid}"))?;
        if !status.success() && local_process_is_running(pid) {
            anyhow::bail!("failed to stop {label} pid {pid}: {status}");
        }
    }
    Ok(())
}

async fn wait_for_local_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if !local_process_is_running(pid) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) fn local_mesh_status(data_dir: &Path) -> LocalMeshStatus {
    let runtime = load_local_mesh_runtime(data_dir).ok().flatten();
    let Some(runtime) = runtime else {
        return LocalMeshStatus {
            state: "not_running".to_string(),
            pid: None,
            base_url: None,
            listen_addr: None,
            binary: None,
            log_path: None,
            derp: None,
        };
    };
    let running = local_process_is_running(runtime.pid);
    let derp = runtime.derp.map(|derp| LocalDerpStatus {
        state: if local_process_is_running(derp.pid) {
            "running".to_string()
        } else {
            "stale".to_string()
        },
        pid: Some(derp.pid),
        url: derp.url,
        listen_addr: derp.listen_addr,
        binary: derp.binary,
        log_path: derp.log_path,
    });
    LocalMeshStatus {
        state: if running { "running" } else { "stale" }.to_string(),
        pid: Some(runtime.pid),
        base_url: Some(runtime.base_url),
        listen_addr: Some(runtime.listen_addr),
        binary: Some(runtime.binary),
        log_path: Some(runtime.log_path),
        derp,
    }
}

pub(crate) fn load_local_mesh_runtime(data_dir: &Path) -> anyhow::Result<Option<LocalMeshRuntime>> {
    let path = local_mesh_runtime_path(data_dir);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    serde_json::from_str(&data)
        .map(Some)
        .with_context(|| format!("parse {}", path.display()))
}

pub(crate) fn save_local_mesh_runtime(
    data_dir: &Path,
    runtime: &LocalMeshRuntime,
) -> anyhow::Result<()> {
    let path = local_mesh_runtime_path(data_dir);
    let data = serde_json::to_vec_pretty(runtime)?;
    write_owner_only_mesh_file(data_dir, &path, &data)
}

/// Keep the credential-free owner projection aligned with network selection.
/// An expected URL prevents a hosted join from rewriting a different active
/// standalone runtime in the same user data directory.
pub(crate) fn update_local_mesh_owner_selection(
    data_dir: &Path,
    expected_mesh_url: Option<&str>,
    selected_network: Option<&str>,
    auto_connect: bool,
) -> anyhow::Result<()> {
    let Some(mut context) = load_local_mesh_owner_context(data_dir)? else {
        return Ok(());
    };
    if expected_mesh_url.is_some_and(|expected| !config::same_mesh_url(expected, &context.mesh_url))
    {
        return Ok(());
    }
    context.selected_network = selected_network.and_then(trimmed_str).map(str::to_owned);
    context.auto_connect = context.selected_network.is_some() && auto_connect;
    save_local_mesh_owner_context(data_dir, &context)
}

pub(crate) fn refresh_hosted_mesh_owner_context(
    paths: &ResolvePaths,
    platform_server_url: &str,
    organization_id: Option<&str>,
) -> anyhow::Result<()> {
    let organization_id = organization_id.and_then(trimmed_str);
    let mesh_url = config::derive_hosted_mesh_url_for_server(platform_server_url);
    let existing = load_local_mesh_owner_context(&paths.mesh_data_dir)?;
    if existing
        .as_ref()
        .is_some_and(|context| context.auth_source == LocalMeshOwnerAuthSource::StandaloneLocal)
    {
        return Ok(());
    }
    let (Some(mesh_url), Some(organization_id)) = (mesh_url, organization_id) else {
        if existing
            .as_ref()
            .is_some_and(|context| context.auth_source == LocalMeshOwnerAuthSource::HostedCurrent)
        {
            remove_local_mesh_owner_context(&paths.mesh_data_dir)?;
        }
        return Ok(());
    };
    let (selected_network, auto_connect) = existing
        .filter(|context| {
            context.auth_source == LocalMeshOwnerAuthSource::HostedCurrent
                && config::same_mesh_url(&context.mesh_url, &mesh_url)
                && context.organization_id == organization_id
        })
        .map(|context| (context.selected_network, context.auto_connect))
        .unwrap_or((None, false));
    save_local_mesh_owner_context(
        &paths.mesh_data_dir,
        &LocalMeshOwnerContext {
            schema_version: 1,
            auth_source: LocalMeshOwnerAuthSource::HostedCurrent,
            mesh_url,
            organization_id: organization_id.to_owned(),
            selected_network,
            auto_connect,
        },
    )
}

pub(crate) fn remove_hosted_mesh_owner_context(data_dir: &Path) -> anyhow::Result<()> {
    remove_mesh_owner_context_for_auth_source(data_dir, LocalMeshOwnerAuthSource::HostedCurrent)
}

fn remove_mesh_owner_context_for_auth_source(
    data_dir: &Path,
    auth_source: LocalMeshOwnerAuthSource,
) -> anyhow::Result<()> {
    if load_local_mesh_owner_context(data_dir)?
        .is_some_and(|context| context.auth_source == auth_source)
    {
        remove_local_mesh_owner_context(data_dir)?;
    }
    Ok(())
}

pub(crate) fn load_local_mesh_owner_context(
    data_dir: &Path,
) -> anyhow::Result<Option<LocalMeshOwnerContext>> {
    let path = local_mesh_owner_context_path(data_dir);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let context: LocalMeshOwnerContext =
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    if context.schema_version != 1 {
        anyhow::bail!(
            "unsupported local Mesh owner context schema {}",
            context.schema_version
        );
    }
    Ok(Some(context))
}

pub(crate) fn save_local_mesh_owner_context(
    data_dir: &Path,
    context: &LocalMeshOwnerContext,
) -> anyhow::Result<()> {
    if context.schema_version != 1 {
        anyhow::bail!("local Mesh owner context schema must be 1");
    }
    let path = local_mesh_owner_context_path(data_dir);
    let data = serde_json::to_vec_pretty(context)?;
    write_owner_only_mesh_file(data_dir, &path, &data)
}

fn write_owner_only_mesh_file(data_dir: &Path, path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    fs::create_dir_all(data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", data_dir.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protect {}", path.display()))?;
    }
    file.write_all(data)
        .with_context(|| format!("write {}", path.display()))
}

pub(crate) fn remove_local_mesh_owner_context(data_dir: &Path) -> anyhow::Result<()> {
    let path = local_mesh_owner_context_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub(crate) fn local_mesh_owner_context_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCAL_MESH_OWNER_CONTEXT_FILE)
}

pub(crate) fn remove_local_mesh_runtime(data_dir: &Path) -> anyhow::Result<()> {
    let path = local_mesh_runtime_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub(crate) fn local_mesh_runtime_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOCAL_MESH_RUNTIME_FILE)
}

pub(crate) fn mesh_up_report(started: bool, runtime: &LocalMeshRuntime) -> MeshUpReport {
    MeshUpReport {
        started,
        pid: runtime.pid,
        base_url: runtime.base_url.clone(),
        listen_addr: runtime.listen_addr.clone(),
        binary: runtime.binary.clone(),
        log_path: runtime.log_path.clone(),
        derp: runtime.derp.clone(),
    }
}

pub(crate) fn local_process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat
                .rsplit_once(") ")
                .and_then(|(_, suffix)| suffix.as_bytes().first())
                .copied();
            !matches!(state, Some(b'Z' | b'X') | None)
        } else {
            false
        }
        #[cfg(not(target_os = "linux"))]
        ProcessCommand::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        ProcessCommand::new("tasklist")
            .arg("/FI")
            .arg(format!("PID eq {pid}"))
            .output()
            .map(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
