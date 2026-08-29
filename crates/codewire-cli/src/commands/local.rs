use super::*;
use codewire_daemon::config::{DAEMON_AUTH_TOKEN_ENV, SHIM_ADDR_ENV};

mod backend;
mod execution;
mod files;
mod lifecycle;
mod ports;
mod presentation;
mod runtime;
mod state;

pub(crate) use backend::*;
pub(crate) use execution::*;
pub(crate) use files::*;
pub(crate) use lifecycle::*;
pub(crate) use ports::*;
pub(crate) use presentation::*;
pub(crate) use runtime::*;
pub(crate) use state::*;

const LOCAL_DAEMON_RUNTIME_PORT: u16 = 7777;

pub(crate) async fn handle_local_command(globals: &Globals, args: LocalArgs) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    match args.command {
        LocalCommand::Create(create) => {
            let mesh_bootstrap = match resolve_local_mesh_bootstrap(
                globals,
                &paths,
                &env,
                create.yes,
                create.network.as_deref(),
                create.no_network,
            ) {
                Ok(bootstrap) => bootstrap,
                Err(err) => {
                    eprintln!(
                        "Warning: mesh enrollment failed ({err}), continuing without network"
                    );
                    None
                }
            };
            let mut config = config::load_local_instances_config(&paths.mesh_data_dir)?;
            let instance = prepare_local_instance(&create)?;
            #[cfg(target_os = "linux")]
            if native_environment(&instance.name).await?.is_some() {
                anyhow::bail!(
                    "local environment {:?} already exists in native state; choose a different name or remove it explicitly",
                    instance.name
                );
            }
            if config.instances.contains_key(&instance.name) {
                anyhow::bail!("local instance {:?} already exists", instance.name);
            }
            create_local_runtime(&instance, &paths.mesh_data_dir)?;
            config
                .instances
                .insert(instance.name.clone(), instance.clone());
            config::save_local_instances_config(&paths.mesh_data_dir, &config)
                .context("save local instance state")?;
            let mut enrolled_mesh_network = None;
            if let Some(bootstrap) = mesh_bootstrap.as_ref() {
                match create_local_mesh_node_enrollment(bootstrap, &instance.name).await {
                    Ok(enrollment) => {
                        if let Err(err) = redeem_mesh_enrollment_in_local_runtime(
                            &instance,
                            &bootstrap.mesh.mesh_url,
                            &enrollment,
                        ) {
                            let code = enrollment.enrollment_code.trim();
                            eprintln!(
                                "Warning: mesh enrollment redemption failed ({err}); the runtime is up but not visible on the mesh. Redeem manually with: cw run {} -- cw network enroll redeem {} --node-name {} --mesh-url {}",
                                instance.name, code, instance.name, bootstrap.mesh.mesh_url
                            );
                        } else {
                            enrolled_mesh_network = Some(bootstrap.network_id.clone());
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Warning: mesh enrollment failed ({err}), continuing without network"
                        );
                    }
                }
            }
            let entry = local_instance_entry(&instance.name, &instance, "running");
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                OutputFormat::Text => {
                    eprintln!("Local instance created: {}.", entry.name);
                    println!("{:<10} {}", "Backend:", entry.backend);
                    println!("{:<10} {}", "Runtime:", entry.runtime_name);
                    println!("{:<10} {}", "Image:", entry.image);
                    println!("{:<10} {}", "Repo:", entry.repo_path);
                    println!("{:<10} {}", "Mount:", entry.workdir);
                    if let Some(network) = enrolled_mesh_network.as_deref() {
                        println!("{:<10} {} (node: {})", "Network:", network, entry.name);
                    }
                }
            }
        }
        LocalCommand::List => {
            let config = config::load_local_instances_config(&paths.mesh_data_dir)?;
            let entries = sorted_local_instance_entries(&config);
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
                OutputFormat::Text => print!("{}", format_local_instance_list_text(&entries)),
            }
        }
        LocalCommand::Info(info) => {
            let current_dir = env::current_dir().context("current directory")?;
            let entry = resolve_local_instance_entry(
                &paths.mesh_data_dir,
                info.name.as_deref(),
                &current_dir,
            )?;
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                OutputFormat::Text => print!("{}", format_local_instance_info_text(&entry)),
            }
        }
        LocalCommand::Start(info) => {
            let current_dir = env::current_dir().context("current directory")?;
            let (key, instance) = resolve_local_instance_config(
                &paths.mesh_data_dir,
                info.name.as_deref(),
                &current_dir,
            )?;
            run_local_lifecycle_command(&instance, LocalLifecycleAction::Start)?;
            super::environment::wait_for_local_environment_daemon_ready(&instance).await?;
            let entry = local_instance_entry(&key, &instance, "running");
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                OutputFormat::Text => eprintln!("Local instance started: {}.", entry.name),
            }
        }
        LocalCommand::Stop(info) => {
            let current_dir = env::current_dir().context("current directory")?;
            let (key, instance) = resolve_local_instance_config(
                &paths.mesh_data_dir,
                info.name.as_deref(),
                &current_dir,
            )?;
            run_local_lifecycle_command(&instance, LocalLifecycleAction::Stop)?;
            let entry = local_instance_entry(&key, &instance, "stopped");
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                OutputFormat::Text => eprintln!("Local instance stopped: {}.", entry.name),
            }
        }
        LocalCommand::Rm(info) => {
            let current_dir = env::current_dir().context("current directory")?;
            let mut config = config::load_local_instances_config(&paths.mesh_data_dir)?;
            let (key, instance) = resolve_local_instance_config_from_state(
                &config,
                info.name.as_deref(),
                &current_dir,
            )?;
            run_local_lifecycle_command(&instance, LocalLifecycleAction::Remove)?;
            config.instances.remove(&key);
            config::save_local_instances_config(&paths.mesh_data_dir, &config)
                .context("save local instance state")?;
            let entry = local_instance_entry(&key, &instance, "removed");
            match args.output {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "name": entry.name, "removed": true })
                    )?
                ),
                OutputFormat::Text => eprintln!("Local instance removed: {}.", entry.name),
            }
        }
        LocalCommand::Resize(resize) => {
            validate_local_resize_args(&resize)?;
            let current_dir = env::current_dir().context("current directory")?;
            let mut config = config::load_local_instances_config(&paths.mesh_data_dir)?;
            let (key, mut instance) = resolve_local_instance_config_from_state(
                &config,
                resize.name.as_deref(),
                &current_dir,
            )?;
            let result = resize_local_runtime(&mut instance, &resize)?;
            let mut status = result.status_after_resize;
            config.instances.insert(key.clone(), instance.clone());
            config::save_local_instances_config(&paths.mesh_data_dir, &config)
                .context("save local instance state")?;
            if result.restart_after_resize {
                run_local_lifecycle_command(&instance, LocalLifecycleAction::Start)?;
                status = "running".to_string();
            }
            let entry = local_instance_entry(&key, &instance, &status);
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                OutputFormat::Text => {
                    eprintln!("Local instance resized: {}.", entry.name);
                    print!("{}", format_local_resize_text(&entry));
                }
            }
        }
        LocalCommand::Ports(ports) => {
            let current_dir = env::current_dir().context("current directory")?;
            if ports.publish.is_empty() {
                let entry = resolve_local_instance_entry(
                    &paths.mesh_data_dir,
                    ports.name.as_deref(),
                    &current_dir,
                )?;
                match args.output {
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&entry.ports)?)
                    }
                    OutputFormat::Text => print!("{}", format_local_ports_text(&entry)),
                }
            } else {
                let mut config = config::load_local_instances_config(&paths.mesh_data_dir)?;
                let (key, mut instance) = resolve_local_instance_config_from_state(
                    &config,
                    ports.name.as_deref(),
                    &current_dir,
                )?;
                let published = publish_local_ports(&mut instance, &ports.publish)?;
                config.instances.insert(key.clone(), instance.clone());
                config::save_local_instances_config(&paths.mesh_data_dir, &config)
                    .context("save local instance state")?;
                let entry = local_instance_entry(&key, &instance, "unknown");
                match args.output {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entry)?),
                    OutputFormat::Text => {
                        if published.added == 0 {
                            println!("No new ports were added.");
                        } else {
                            println!("Updated Lima port forwards for {}.", entry.name);
                        }
                        print!("{}", format_local_ports_text(&entry));
                    }
                }
            }
        }
        LocalCommand::Files(files) => {
            handle_local_files_command(&paths.mesh_data_dir, files, args.output)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct LocalMeshBootstrap {
    pub(crate) mesh: config::ResolvedMeshConfig,
    pub(crate) organization_id: String,
    pub(crate) network_id: String,
}

pub(crate) fn resolve_env_create_mesh_bootstrap(
    paths: &ResolvePaths,
    env: &impl config::Env,
    platform: &config::ResolvedPlatformConfig,
    organization_id: &str,
    assume_yes: bool,
    requested_network: Option<&str>,
    disable_network: bool,
) -> anyhow::Result<Option<LocalMeshBootstrap>> {
    if disable_network {
        return Ok(None);
    }

    let requested_network = requested_network.and_then(trimmed_str);
    let explicit_network = requested_network.is_some();
    let Some(mesh_url) = config::derive_hosted_mesh_url_for_server(&platform.server_url) else {
        if explicit_network {
            anyhow::bail!(
                "selected platform {} does not provide a hosted Mesh service",
                platform.server_url
            );
        }
        return Ok(None);
    };

    let organization_id = trimmed_required(organization_id, "organization ID")?.to_string();
    let mesh = match config::resolve_mesh_with_token_provider(
        config::MeshResolveOptions {
            mesh_url: Some(mesh_url),
            auth_token: None,
            network_id: requested_network.map(str::to_string),
            platform_server_url: Some(platform.server_url.clone()),
        },
        paths,
        env,
        platform.token_provider()?,
        config::MeshAuthSource::PlatformConfig,
    ) {
        Ok(mesh) => mesh,
        Err(err) if !explicit_network => {
            let _ = err;
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };
    let Some(network_id) = mesh
        .selected_network
        .as_deref()
        .and_then(trimmed_str)
        .map(str::to_string)
    else {
        return Ok(None);
    };

    if !explicit_network && !assume_yes {
        if !stdin_is_interactive() {
            return Ok(None);
        }
        if !prompt_confirm_default_no(&env_create_mesh_prompt(&mesh.mesh_url, &network_id))? {
            return Ok(None);
        }
    }

    Ok(Some(LocalMeshBootstrap {
        mesh,
        organization_id,
        network_id,
    }))
}

pub(crate) fn env_create_mesh_prompt(mesh_url: &str, network_id: &str) -> String {
    format!(
        "Join hosted Mesh network {network_id:?} at {mesh_url} for this platform environment. Continue"
    )
}

pub(crate) fn resolve_local_mesh_bootstrap(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    assume_yes: bool,
    requested_network: Option<&str>,
    disable_network: bool,
) -> anyhow::Result<Option<LocalMeshBootstrap>> {
    resolve_mesh_bootstrap_for_network(
        globals,
        paths,
        env,
        assume_yes,
        requested_network,
        disable_network,
        "New local runtimes will auto-join your private Mesh network",
    )
}

pub(crate) fn resolve_mesh_bootstrap_for_network(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    assume_yes: bool,
    requested_network: Option<&str>,
    disable_network: bool,
    prompt_prefix: &str,
) -> anyhow::Result<Option<LocalMeshBootstrap>> {
    if disable_network {
        return Ok(None);
    }

    let requested_network = requested_network.and_then(trimmed_str);
    let explicit_network = requested_network.is_some();
    let network_id = requested_network
        .map(str::to_string)
        .or_else(|| config::selected_mesh_network(paths, env));
    let Some(network_id) = network_id.and_then(|network| trimmed_str(&network).map(str::to_string))
    else {
        return Ok(None);
    };

    if !explicit_network && !assume_yes {
        if !stdin_is_interactive() {
            return Ok(None);
        }
        if !prompt_confirm_default_no(&format!(
            "{prompt_prefix} {network_id:?} for remote access. Continue"
        ))? {
            return Ok(None);
        }
    }

    let organization_id = config::load_mesh_config(&paths.mesh_data_dir)?
        .local_identity
        .and_then(|identity| trimmed_str(&identity.organization_id).map(str::to_string));
    let Some(organization_id) = organization_id else {
        if explicit_network {
            anyhow::bail!(
                "local Mesh organization not configured (run 'cw mesh up' before selecting a network)"
            );
        }
        return Ok(None);
    };

    match resolve_mesh(globals, paths, env, None, Some(network_id.clone())) {
        Ok(mesh) => Ok(Some(LocalMeshBootstrap {
            mesh,
            organization_id,
            network_id,
        })),
        Err(err) if !explicit_network => {
            let _ = err;
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

pub(crate) async fn create_local_mesh_node_enrollment(
    bootstrap: &LocalMeshBootstrap,
    node_name: &str,
) -> anyhow::Result<NodeEnrollment> {
    let node_name = trimmed_required(node_name, "node name")?;
    MeshClient::new(&bootstrap.mesh)?
        .create_node_enrollment(
            &bootstrap.organization_id,
            &bootstrap.network_id,
            node_name,
            "10m",
        )
        .await
        .context("create mesh node enrollment for local runtime")
}

pub(crate) fn mesh_enrollment_redeem_command(
    instance: &config::LocalInstanceConfig,
    mesh_url: &str,
    enrollment: &NodeEnrollment,
) -> Option<Vec<String>> {
    let code = trimmed_str(&enrollment.enrollment_code)?;
    let node_name = trimmed_str(&instance.name)?;
    let mut command = vec![
        "cw".to_string(),
        "network".to_string(),
        "enroll".to_string(),
        "redeem".to_string(),
        code.to_string(),
        "--node-name".to_string(),
        node_name.to_string(),
    ];
    if let Some(mesh_url) = trimmed_str(mesh_url) {
        command.push("--mesh-url".to_string());
        command.push(mesh_url.to_string());
    }
    Some(command)
}

pub(crate) fn redeem_mesh_enrollment_in_local_runtime(
    instance: &config::LocalInstanceConfig,
    mesh_url: &str,
    enrollment: &NodeEnrollment,
) -> anyhow::Result<()> {
    let runtime_mesh_url = local_runtime_mesh_url(instance, mesh_url);
    let Some(command) = mesh_enrollment_redeem_command(instance, &runtime_mesh_url, enrollment)
    else {
        return Ok(());
    };
    let spec = local_runtime_command_spec(instance, None, &command, &BTreeMap::new())?;
    run_local_command_combined(&spec).context("redeem mesh enrollment in local runtime")?;
    Ok(())
}

pub(crate) fn local_runtime_mesh_url(
    instance: &config::LocalInstanceConfig,
    mesh_url: &str,
) -> String {
    let Some(host) = local_runtime_host_gateway(instance) else {
        return mesh_url.to_string();
    };
    mesh_url_with_reachable_host(mesh_url, host).unwrap_or_else(|| mesh_url.to_string())
}

pub(crate) fn local_runtime_host_gateway(
    instance: &config::LocalInstanceConfig,
) -> Option<&'static str> {
    match trimmed_str(&instance.backend) {
        Some("docker") => Some("host.docker.internal"),
        Some("lima") => Some("host.lima.internal"),
        _ => None,
    }
}

pub(crate) fn mesh_url_with_reachable_host(mesh_url: &str, host: &str) -> Option<String> {
    let mut url = url::Url::parse(mesh_url.trim()).ok()?;
    let current_host = url.host_str()?;
    let loopback = current_host.eq_ignore_ascii_case("localhost")
        || current_host == "127.0.0.1"
        || current_host == "::1"
        || current_host.starts_with("127.");
    if !loopback {
        return None;
    }
    url.set_host(Some(host)).ok()?;
    Some(url.to_string())
}

pub(crate) fn prepare_local_instance(
    args: &LocalCreateArgs,
) -> anyhow::Result<config::LocalInstanceConfig> {
    let backend = trimmed_required(&args.backend, "local backend")?.to_string();
    if !matches!(backend.as_str(), "docker" | "lima") {
        anyhow::bail!("unsupported local backend {backend:?}");
    }

    let project_dir = args
        .path
        .canonicalize()
        .with_context(|| format!("read project path {}", args.path.display()))?;
    if !project_dir.is_dir() {
        anyhow::bail!("project path must be a directory");
    }

    let mut cfg = if let Some(spec) = args.spec.as_deref().and_then(trimmed_str) {
        load_local_spec_config(spec)?
    } else {
        let config_path = if args.file.is_absolute() {
            args.file.clone()
        } else {
            project_dir.join(&args.file)
        };
        match config::load_codewire_config(&config_path) {
            Ok(config) => config,
            Err(config::ConfigError::ReadConfig { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                config::CodewireConfig {
                    image: "workspace".to_string(),
                    ..config::CodewireConfig::default()
                }
            }
            Err(err) => return Err(err.into()),
        }
    };

    let parsed_env = parse_env_overrides(&args.env)?;
    cfg.env.extend(parsed_env);

    if let Some(preset) = args.preset.as_deref().and_then(trimmed_str) {
        cfg.preset = preset.to_string();
    }
    if let Some(image) = args.image.as_deref().and_then(trimmed_str) {
        cfg.image = expand_image_ref(image);
    }
    if let Some(install) = args.install.as_deref().and_then(trimmed_str) {
        cfg.install = install.to_string();
    }
    if let Some(startup) = args.startup.as_deref().and_then(trimmed_str) {
        cfg.startup = startup.to_string();
    }
    if let Some(agent) = args.agent.as_deref().and_then(trimmed_str) {
        cfg.agents = Some(config::CodewireAgentsConfig {
            install: cfg.install_agents,
            tools: vec![config::display_agent_id(agent)],
        });
        cfg.agent.clear();
    }
    if let Some(secrets) = args.secrets.as_deref().and_then(trimmed_str) {
        cfg.secrets
            .get_or_insert_with(config::CodewireSecretsConfig::default)
            .project = secrets.to_string();
    }
    if args.cpu > 0 {
        cfg.cpu = args.cpu;
    }
    if args.memory > 0 {
        cfg.memory = args.memory;
    }
    if args.disk > 0 {
        cfg.disk = args.disk;
    }
    if args.no_org_secrets {
        cfg.secrets
            .get_or_insert_with(config::CodewireSecretsConfig::default)
            .org = Some(false);
    }
    if args.no_user_secrets {
        cfg.secrets
            .get_or_insert_with(config::CodewireSecretsConfig::default)
            .user = Some(false);
    }
    if cfg.image.trim().is_empty() && !cfg.preset.trim().is_empty() {
        cfg.image = expand_image_ref(&cfg.preset);
    }
    if cfg.image.trim().is_empty() {
        anyhow::bail!("local create requires an image; set image in codewire.yaml or pass --image");
    }

    let name = args
        .name
        .as_deref()
        .and_then(trimmed_str)
        .map(sanitize_local_name)
        .unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|name| name.to_str())
                .map(sanitize_local_name)
                .unwrap_or_default()
        });
    if name.is_empty() {
        anyhow::bail!("could not derive a valid local instance name");
    }

    let secrets = local_secret_project(&cfg);
    if cfg
        .ports
        .iter()
        .any(|port| port.effective_guest_port() == i32::from(LOCAL_DAEMON_RUNTIME_PORT))
    {
        anyhow::bail!(
            "guest port {LOCAL_DAEMON_RUNTIME_PORT} is reserved for the managed environment daemon"
        );
    }
    let mounts = resolve_local_mounts(&project_dir, &cfg.mounts)?;
    let agent = local_primary_agent(&cfg);
    let include_org_secrets = local_include_org_secrets(&cfg);
    let include_user_secrets = local_include_user_secrets(&cfg);
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let runtime_name = format!("cw-{name}");
    let (workdir, lima_instance_name, lima_vm_type, lima_mount_type) = if backend == "lima" {
        let vm_type = default_lima_vm_type().to_string();
        (
            project_dir.display().to_string(),
            runtime_name.clone(),
            vm_type.clone(),
            default_lima_mount_type(&vm_type).to_string(),
        )
    } else {
        (
            LOCAL_WORKSPACE_PATH.to_string(),
            String::new(),
            String::new(),
            String::new(),
        )
    };

    Ok(config::LocalInstanceConfig {
        name: name.clone(),
        backend,
        runtime_name,
        lima_instance_name,
        repo_path: project_dir.display().to_string(),
        workdir,
        preset: cfg.preset,
        image: expand_image_ref(&cfg.image),
        install: cfg.install,
        startup: cfg.startup,
        secrets,
        env: cfg.env,
        ports: cfg.ports,
        mounts,
        cpu: cfg.cpu,
        memory: cfg.memory,
        disk: cfg.disk,
        agent,
        include_org_secrets,
        include_user_secrets,
        lima_mount_type,
        lima_vm_type,
        daemon_host_port: reserve_local_daemon_port()?,
        daemon_auth_token: generate_local_daemon_token(),
        created_at: now.clone(),
        last_used_at: now,
    })
}

pub(crate) fn reserve_local_daemon_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("reserve local daemon loopback port")?;
    listener
        .local_addr()
        .context("read reserved local daemon loopback port")
        .map(|address| address.port())
}

pub(crate) fn generate_local_daemon_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn local_daemon_host_port(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<u16> {
    if instance.daemon_host_port == 0 {
        anyhow::bail!(
            "local environment daemon endpoint is missing; recreate the local environment"
        );
    }
    Ok(instance.daemon_host_port)
}

pub(crate) fn local_daemon_auth_token(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<&str> {
    trimmed_str(&instance.daemon_auth_token).ok_or_else(|| {
        anyhow::anyhow!(
            "local environment daemon credential is missing; recreate the local environment"
        )
    })
}

pub(crate) fn load_local_spec_config(source: &str) -> anyhow::Result<config::CodewireConfig> {
    let mut data = Vec::new();
    if source == "-" {
        std::io::stdin()
            .read_to_end(&mut data)
            .context("read spec from stdin")?;
    } else {
        data = fs::read(source).with_context(|| format!("read spec {source}"))?;
    }
    config::parse_local_spec_json(&data).map_err(Into::into)
}

pub(crate) fn resolve_local_mounts(
    project_dir: &Path,
    mounts: &[config::LocalMountConfig],
) -> anyhow::Result<Vec<config::LocalMountConfig>> {
    let mut resolved = Vec::new();
    for mount in mounts {
        let source = trimmed_required(&mount.source, "mount source")?;
        let source = if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            project_dir.join(source)
        };
        let source = source
            .canonicalize()
            .with_context(|| format!("read mount source {}", source.display()))?;
        let target = match trimmed_str(&mount.target) {
            Some(target) => {
                let target = PathBuf::from(target);
                if !target.is_absolute() {
                    anyhow::bail!("mount target must be absolute: {}", target.display());
                }
                normalized_path(&target)
            }
            None => source.clone(),
        };
        resolved.push(config::LocalMountConfig {
            source: source.display().to_string(),
            target: target.display().to_string(),
            readonly: mount.readonly,
        });
    }
    Ok(resolved)
}

pub(crate) fn local_primary_agent(cfg: &config::CodewireConfig) -> String {
    cfg.agents
        .as_ref()
        .and_then(|agents| agents.tools.first())
        .map(|agent| config::canonical_agent_id(agent))
        .unwrap_or_else(|| config::canonical_agent_id(&cfg.agent))
}

pub(crate) fn local_secret_project(cfg: &config::CodewireConfig) -> String {
    cfg.secrets
        .as_ref()
        .map(|secrets| secrets.project.trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn local_include_org_secrets(cfg: &config::CodewireConfig) -> Option<bool> {
    cfg.secrets
        .as_ref()
        .and_then(|secrets| secrets.org)
        .or(cfg.include_org_secrets)
}

pub(crate) fn local_include_user_secrets(cfg: &config::CodewireConfig) -> Option<bool> {
    cfg.secrets
        .as_ref()
        .and_then(|secrets| secrets.user)
        .or(cfg.include_user_secrets)
}

pub(crate) const LOCAL_SSH_AUTH_SOCK_PATH: &str = "/tmp/codewire-ssh-agent.sock";

pub(crate) fn push_volume(args: &mut Vec<String>, source: Option<&PathBuf>, target: &str) {
    if let Some(source) = source {
        args.push("--volume".to_string());
        args.push(format!("{}:{target}", source.display()));
    }
}

pub(crate) fn lima_workspace_container_status(name: &str) -> anyhow::Result<String> {
    let output = ProcessCommand::new("limactl")
        .args([
            "shell",
            "--workdir",
            "/",
            name,
            "sudo",
            "docker",
            "inspect",
            "--format",
            "{{.State.Status}}",
            LIMA_CONTAINER_NAME,
        ])
        .output()
        .context("inspect Lima workspace container")?;
    let combined = combined_output(&output.stdout, &output.stderr);
    if !output.status.success() {
        let lower = combined.to_lowercase();
        if lower.contains("no such object")
            || lower.contains("no such container")
            || lower.contains("not found")
        {
            return Ok("missing".to_string());
        }
        anyhow::bail!(
            "docker inspect {LIMA_CONTAINER_NAME}: exit code {}\n{}",
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    Ok(combined.trim().to_ascii_lowercase())
}

pub(crate) fn lima_docker_socket_gid(name: &str) -> anyhow::Result<String> {
    let output = run_local_command_combined(&LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            name.to_string(),
            "sudo".to_string(),
            "stat".to_string(),
            "-c".to_string(),
            "%g".to_string(),
            LIMA_DOCKER_SOCK_PATH.to_string(),
        ],
    })
    .context("stat docker socket gid")?;
    Ok(output.trim().to_string())
}

pub(crate) fn ensure_lima_docker_socket_group(name: &str, gid: &str) -> anyhow::Result<()> {
    let Some(gid) = trimmed_str(gid) else {
        return Ok(());
    };
    let script = format!(
        "gid={gid:?}; if getent group \"$gid\" >/dev/null 2>&1; then exit 0; fi; groupadd -g \"$gid\" codewire-docker >/dev/null 2>&1 || groupadd -g \"$gid\" docker >/dev/null 2>&1 || true"
    );
    run_local_command_combined(&LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            name.to_string(),
            "sudo".to_string(),
            "docker".to_string(),
            "exec".to_string(),
            "-u".to_string(),
            "0".to_string(),
            LIMA_CONTAINER_NAME.to_string(),
            "sh".to_string(),
            "-lc".to_string(),
            script,
        ],
    })
    .with_context(|| format!("ensure docker socket group in {LIMA_CONTAINER_NAME}"))?;
    Ok(())
}

pub(crate) fn bootstrap_lima_claude_json(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<()> {
    let name = local_lima_instance_name(instance)?;
    let workdir = trimmed_str(&instance.workdir)
        .or_else(|| trimmed_str(&instance.repo_path))
        .unwrap_or(LOCAL_WORKSPACE_PATH);
    let workdir_json = serde_json::to_string(workdir)?;
    let container_home_json = serde_json::to_string("/home/codewire")?;
    let script = format!(
        r#"set -eu
trust='{{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true}}'
mkdir -p /home/codewire/.claude
cat > /home/codewire/.claude.json <<CWEOF
{{
  "autoUpdaterStatus": "disabled",
  "bypassPermissionsModeAccepted": true,
  "hasAcknowledgedCostThreshold": true,
  "hasCompletedOnboarding": true,
  "projects": {{
    {workdir_json}:  $trust,
    {container_home_json}:  $trust,
    "/workspace": $trust
  }}
}}
CWEOF
chown codewire:codewire /home/codewire/.claude.json
chmod 600 /home/codewire/.claude.json
mkdir -p /etc/profile.d
cat > /etc/profile.d/cw-claude-token-shadow.sh <<'CWEOF2'
{}
CWEOF2
chmod 644 /etc/profile.d/cw-claude-token-shadow.sh
"#,
        claude_token_shadow_script()
    );
    run_local_command_combined(&LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            name.to_string(),
            "sudo".to_string(),
            "docker".to_string(),
            "exec".to_string(),
            "-u".to_string(),
            "0".to_string(),
            LIMA_CONTAINER_NAME.to_string(),
            "bash".to_string(),
            "-c".to_string(),
            script,
        ],
    })
    .context("bootstrap claude.json")?;
    Ok(())
}

pub(crate) fn claude_token_shadow_script() -> &'static str {
    r#"# Auto-generated by cw env create --local. Do not edit by hand.
# Unsets CLAUDE_CODE_OAUTH_TOKEN when ~/.claude/.credentials.json exists,
# so freshly-minted full-scope creds from `claude auth login` win
# over the long-lived inference-only token forwarded by cli.
if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -f "${HOME}/.claude/.credentials.json" ]; then
    unset CLAUDE_CODE_OAUTH_TOKEN
fi"#
}

pub(crate) fn detect_local_github_token() -> Option<String> {
    if let Some(token) = env::var("GH_TOKEN").ok().and_then(non_empty_string) {
        return Some(token);
    }
    if let Some(token) = env::var("GITHUB_TOKEN").ok().and_then(non_empty_string) {
        return Some(token);
    }
    let output = ProcessCommand::new("gh")
        .args(["auth", "token"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .and_then(non_empty_string)
}

pub(crate) fn detect_local_git_config_path() -> Option<PathBuf> {
    let path = env::var_os("HOME").map(PathBuf::from)?.join(".gitconfig");
    if !path.exists() {
        return None;
    }
    fs::canonicalize(&path).ok().or(Some(path))
}

pub(crate) fn detect_local_ssh_auth_sock() -> Option<PathBuf> {
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        let one_password = home.join(".1password").join("agent.sock");
        if one_password.exists() {
            return Some(one_password);
        }
    }
    env::var("SSH_AUTH_SOCK")
        .ok()
        .and_then(non_empty_string)
        .map(PathBuf::from)
        .filter(|path| path.exists())
}

pub(crate) fn detect_local_claude_oauth_token() -> Option<String> {
    if let Some(token) = env::var("CLAUDE_CODE_OAUTH_TOKEN")
        .ok()
        .and_then(non_empty_string)
    {
        return Some(token);
    }
    let path = env::var_os("HOME")
        .map(PathBuf::from)?
        .join(".claude")
        .join(".credentials.json");
    let data = fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    json.get("claudeAiOauth")
        .and_then(|oauth| oauth.get("accessToken"))
        .and_then(|token| token.as_str())
        .map(str::to_string)
        .and_then(non_empty_string)
}

pub(crate) fn non_empty_string(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn format_docker_cpus(millicores: i32) -> String {
    let whole = millicores / 1000;
    let frac = millicores % 1000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:03}")
    }
}

pub(crate) fn default_lima_vm_type() -> &'static str {
    if cfg!(target_os = "macos") {
        "vz"
    } else {
        "qemu"
    }
}

pub(crate) fn default_lima_mount_type(vm_type: &str) -> &'static str {
    if vm_type == "vz" || command_exists("virtiofsd") {
        "virtiofs"
    } else {
        "9p"
    }
}

pub(crate) fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file()
        })
    })
}

pub(crate) fn sanitize_local_name(raw: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for ch in raw.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}

fn install_local_docker_daemon_before_start(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<()> {
    let current_exe = env::current_exe().context("resolve current Codewire CLI path")?;
    let runtime = local_runtime_name(instance)?;
    let copy = LocalRuntimeCommand {
        program: "docker".to_string(),
        args: vec![
            "cp".to_string(),
            current_exe.display().to_string(),
            format!("{runtime}:{LOCAL_RUNTIME_CLI_PATH}"),
        ],
    };
    run_local_command_combined(&copy)
        .with_context(|| format!("install environment daemon in Docker runtime {runtime}"))?;
    Ok(())
}

fn stage_lima_runtime_cli(lima_name: &str) -> anyhow::Result<()> {
    let current_exe = env::current_exe().context("resolve current Codewire CLI path")?;
    for command in lima_runtime_cli_stage_commands(lima_name, &current_exe) {
        run_local_command_combined(&command)
            .with_context(|| format!("stage environment daemon in Lima runtime {lima_name}"))?;
    }
    Ok(())
}

pub(crate) fn lima_runtime_cli_stage_commands(
    lima_name: &str,
    current_exe: &Path,
) -> Vec<LocalRuntimeCommand> {
    vec![
        LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "copy".to_string(),
                "--backend=scp".to_string(),
                current_exe.display().to_string(),
                format!("{lima_name}:{LIMA_RUNTIME_CLI_COPY_PATH}"),
            ],
        },
        LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
                "sudo".to_string(),
                "install".to_string(),
                "-d".to_string(),
                "-m".to_string(),
                "0755".to_string(),
                LIMA_RUNTIME_CLI_STAGE_DIR.to_string(),
            ],
        },
        LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
                "sudo".to_string(),
                "install".to_string(),
                "-m".to_string(),
                "0755".to_string(),
                LIMA_RUNTIME_CLI_COPY_PATH.to_string(),
                LIMA_RUNTIME_CLI_STAGE_PATH.to_string(),
            ],
        },
        LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
                "rm".to_string(),
                LIMA_RUNTIME_CLI_COPY_PATH.to_string(),
            ],
        },
    ]
}

pub(crate) fn normalized_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn path_contains(root: &Path, candidate: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}
