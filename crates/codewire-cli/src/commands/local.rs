use super::*;
use codewire_daemon::config::{DAEMON_AUTH_TOKEN_ENV, SHIM_ADDR_ENV};

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

pub(crate) fn create_local_runtime(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> anyhow::Result<()> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => create_local_docker_instance(instance),
        "lima" => create_local_lima_instance(instance, data_dir),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn create_local_docker_instance(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<()> {
    let context = LocalDockerHostContext::detect();
    let create = local_docker_create_command_spec(instance, &context)?;
    run_local_command_combined(&create)
        .with_context(|| format!("docker {}", display_local_runtime_args(&create.args)))?;

    if let Err(err) = install_local_docker_daemon_before_start(instance) {
        let cleanup = LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "rm".to_string(),
                "-f".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        };
        let _ = run_local_command_combined(&cleanup);
        return Err(err);
    }

    let start = LocalRuntimeCommand {
        program: "docker".to_string(),
        args: vec![
            "start".to_string(),
            local_runtime_name(instance)?.to_string(),
        ],
    };
    if let Err(err) = run_local_command_combined(&start)
        .with_context(|| format!("docker {}", start.args.join(" ")))
    {
        let cleanup = LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "rm".to_string(),
                "-f".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        };
        let _ = run_local_command_combined(&cleanup);
        return Err(err);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LocalDockerHostContext {
    pub(crate) claude_dir: Option<PathBuf>,
    pub(crate) claude_json: Option<PathBuf>,
    pub(crate) gh_config_dir: Option<PathBuf>,
    pub(crate) git_config_path: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
    pub(crate) ssh_dir: Option<PathBuf>,
    pub(crate) codex_dir: Option<PathBuf>,
    pub(crate) github_token: Option<String>,
    pub(crate) claude_oauth_token: Option<String>,
    pub(crate) anthropic_api_key: Option<String>,
}

impl LocalDockerHostContext {
    pub(crate) fn detect() -> Self {
        let home = env::var_os("HOME").map(PathBuf::from);
        let path_if_exists = |path: PathBuf| path.exists().then_some(path);
        Self {
            claude_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".claude"))),
            claude_json: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".claude.json"))),
            gh_config_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".config").join("gh"))),
            git_config_path: detect_local_git_config_path(),
            ssh_auth_sock: detect_local_ssh_auth_sock(),
            ssh_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".ssh"))),
            codex_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".codex"))),
            github_token: detect_local_github_token(),
            claude_oauth_token: detect_local_claude_oauth_token(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY")
                .ok()
                .and_then(non_empty_string),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LimaVmMount {
    pub(crate) location: String,
    #[serde(rename = "mountPoint")]
    pub(crate) mount_point: String,
    pub(crate) writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LimaContainerMount {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) read_only: bool,
}

pub(crate) fn create_local_lima_instance(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let context = LocalDockerHostContext::detect();
    ensure_lima_git_config(instance, data_dir, &context)?;

    let name = local_lima_instance_name(instance)?;
    let mut cleanup_vm = false;
    let result = (|| -> anyhow::Result<()> {
        match local_lima_instance_status(name)? {
            status if status == "missing" => {
                cleanup_vm = true;
                let create = local_lima_create_command_spec(instance, data_dir, &context)?;
                eprintln!("  Creating Lima VM {name:?}...");
                run_local_command_combined(&create)
                    .with_context(|| format!("limactl {}", create.args.join(" ")))?;
            }
            status if status != "running" => {
                let start = LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "start".to_string(),
                        "--tty=false".to_string(),
                        name.to_string(),
                    ],
                };
                eprintln!("  Starting Lima VM {name:?}...");
                run_local_command_combined(&start)
                    .with_context(|| format!("limactl {}", start.args.join(" ")))?;
            }
            _ => {
                eprintln!("  Reusing existing Lima VM {name:?}...");
            }
        }

        let _ = run_local_command_combined(&LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "systemctl".to_string(),
                "start".to_string(),
                "docker".to_string(),
            ],
        });

        eprintln!("  Waiting for Docker inside VM...");
        let docker_info = LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "info".to_string(),
            ],
        };
        run_local_command_combined(&docker_info).context("docker not ready inside Lima VM")?;

        if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
            let _ = run_local_command_with_stdin(
                &LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "shell".to_string(),
                        "--workdir".to_string(),
                        "/".to_string(),
                        name.to_string(),
                        "sudo".to_string(),
                        "docker".to_string(),
                        "login".to_string(),
                        "ghcr.io".to_string(),
                        "-u".to_string(),
                        "oauth2".to_string(),
                        "--password-stdin".to_string(),
                    ],
                },
                token,
            );
        }

        let image = trimmed_required(&instance.image, "local image")?;
        eprintln!("  Pulling {image}...");
        let pull = LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "pull".to_string(),
                image.to_string(),
            ],
        };
        run_local_command_combined(&pull).with_context(|| format!("docker pull {image}"))?;

        let status = lima_workspace_container_status(name)?;
        let docker_sock_gid = lima_docker_socket_gid(name)?;
        stage_lima_runtime_cli(name)?;
        eprintln!("  Starting workspace container...");
        match status.as_str() {
            "missing" => {
                let run = local_lima_workspace_run_command_spec(
                    instance,
                    data_dir,
                    &context,
                    &docker_sock_gid,
                )?;
                run_local_command_combined(&run).context("docker run")?;
            }
            "running" => {}
            _ => {
                let start = LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "shell".to_string(),
                        "--workdir".to_string(),
                        "/".to_string(),
                        name.to_string(),
                        "sudo".to_string(),
                        "docker".to_string(),
                        "start".to_string(),
                        LIMA_CONTAINER_NAME.to_string(),
                    ],
                };
                run_local_command_combined(&start)
                    .with_context(|| format!("docker start {LIMA_CONTAINER_NAME}"))?;
            }
        }

        ensure_lima_docker_socket_group(name, &docker_sock_gid)?;
        bootstrap_lima_claude_json(instance)?;
        cleanup_vm = false;
        Ok(())
    })();

    if result.is_err() && cleanup_vm {
        let _ = run_local_command_combined(&LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "delete".to_string(),
                "--force".to_string(),
                name.to_string(),
            ],
        });
    }
    result
}

pub(crate) fn ensure_lima_git_config(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<()> {
    let Some(source) = context.git_config_path.as_ref() else {
        return Ok(());
    };
    let target_dir = local_lima_git_state_dir(instance, data_dir);
    fs::create_dir_all(&target_dir).context("create Lima git state dir")?;
    let target = target_dir.join(".gitconfig");
    if target.exists() {
        return Ok(());
    }
    fs::copy(source, &target).context("seed Lima git config")?;
    Ok(())
}

pub(crate) fn local_lima_state_dir(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> PathBuf {
    let name = trimmed_str(&instance.lima_instance_name)
        .or_else(|| trimmed_str(&instance.runtime_name))
        .or_else(|| trimmed_str(&instance.name))
        .unwrap_or("default");
    data_dir.join("lima").join(name)
}

pub(crate) fn local_lima_git_state_dir(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> PathBuf {
    local_lima_state_dir(instance, data_dir).join("git")
}

pub(crate) fn local_lima_create_command_spec(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<LocalRuntimeCommand> {
    let vm_type = trimmed_str(&instance.lima_vm_type)
        .unwrap_or(default_lima_vm_type())
        .to_string();
    let mount_type = trimmed_str(&instance.lima_mount_type)
        .map(str::to_string)
        .unwrap_or_else(|| default_lima_mount_type(&vm_type).to_string());
    let mounts = serde_json::to_string(&lima_vm_mounts(instance, data_dir, context)?)?;
    let mut args = vec![
        "start".to_string(),
        "--tty=false".to_string(),
        "--name".to_string(),
        local_lima_instance_name(instance)?.to_string(),
        "--vm-type".to_string(),
        vm_type,
        "--mount-type".to_string(),
        mount_type,
        "--mount-none".to_string(),
        "--set".to_string(),
        format!(".mounts={mounts}"),
    ];
    if let Some(set_expr) = lima_ssh_agent_forward_set_expr(context)? {
        args.push("--set".to_string());
        args.push(set_expr);
    }
    args.push("--set".to_string());
    args.push(lima_daemon_forward_set_expr(instance)?);
    if instance.cpu > 0 {
        args.push("--cpus".to_string());
        args.push(lima_cpus_from_millicores(instance.cpu).to_string());
    }
    if instance.memory > 0 {
        args.push("--memory".to_string());
        args.push(lima_memory_gib_from_mb(instance.memory).to_string());
    }
    if instance.disk > 0 {
        args.push("--disk".to_string());
        args.push(instance.disk.to_string());
    }
    for port in &instance.ports {
        let host_port = port.effective_host_port();
        let guest_port = port.effective_guest_port();
        if host_port > 0 && guest_port > 0 {
            args.push("--port-forward".to_string());
            args.push(format!("{host_port}:{guest_port},static=true"));
        }
    }
    args.push("template:docker".to_string());

    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args,
    })
}

pub(crate) fn lima_daemon_forward_set_expr(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    #[derive(serde::Serialize)]
    struct DaemonForward {
        #[serde(rename = "guestPort")]
        guest_port: u16,
        #[serde(rename = "hostPort")]
        host_port: u16,
        #[serde(rename = "guestIP")]
        guest_ip: &'static str,
        #[serde(rename = "hostIP")]
        host_ip: &'static str,
        proto: &'static str,
        r#static: bool,
    }

    let payload = serde_json::to_string(&[DaemonForward {
        guest_port: LOCAL_DAEMON_RUNTIME_PORT,
        host_port: local_daemon_host_port(instance)?,
        guest_ip: "127.0.0.1",
        host_ip: "127.0.0.1",
        proto: "tcp",
        r#static: true,
    }])?;
    Ok(format!(
        ".portForwards = ((.portForwards // []) | map(select(.guestPort != {LOCAL_DAEMON_RUNTIME_PORT})) + {payload})"
    ))
}

pub(crate) fn local_lima_workspace_run_command_spec(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
    docker_sock_gid: &str,
) -> anyhow::Result<LocalRuntimeCommand> {
    let name = local_lima_instance_name(instance)?;
    let repo_mount = lima_repo_mount_path(instance)?;
    let daemon_auth_token = local_daemon_auth_token(instance)?;
    let mut docker_args = vec![
        "sudo".to_string(),
        "docker".to_string(),
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        LIMA_CONTAINER_NAME.to_string(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--network".to_string(),
        "host".to_string(),
    ];
    if let Some(gid) = trimmed_str(docker_sock_gid) {
        docker_args.push("--group-add".to_string());
        docker_args.push(gid.to_string());
    }
    docker_args.extend([
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        "-e".to_string(),
        format!("DOCKER_HOST={LIMA_DOCKER_HOST_VALUE}"),
        "-v".to_string(),
        format!("{LIMA_DOCKER_SOCK_PATH}:{LIMA_DOCKER_SOCK_PATH}"),
        "-v".to_string(),
        format!("{repo_mount}:{repo_mount}"),
        "-v".to_string(),
        format!("{LIMA_RUNTIME_CLI_STAGE_PATH}:{LOCAL_RUNTIME_CLI_PATH}:ro"),
        "-e".to_string(),
        format!("{SHIM_ADDR_ENV}=127.0.0.1:{LOCAL_DAEMON_RUNTIME_PORT}"),
        "-e".to_string(),
        format!("{DAEMON_AUTH_TOKEN_ENV}={daemon_auth_token}"),
    ]);
    if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("GH_TOKEN={token}"));
    }
    if context.ssh_auth_sock.is_some() {
        docker_args.push("-e".to_string());
        docker_args.push(format!("SSH_AUTH_SOCK={LOCAL_SSH_AUTH_SOCK_PATH}"));
    }
    if let Some(api_key) = context.anthropic_api_key.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("ANTHROPIC_API_KEY={api_key}"));
    }
    if let Some(token) = context.claude_oauth_token.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("CLAUDE_CODE_OAUTH_TOKEN={token}"));
    }
    for mount in lima_container_mounts(instance, data_dir, context)? {
        docker_args.push("-v".to_string());
        let mut spec = format!("{}:{}", mount.source, mount.target);
        if mount.read_only {
            spec.push_str(":ro");
        }
        docker_args.push(spec);
    }
    docker_args.extend([
        "--workdir".to_string(),
        repo_mount,
        trimmed_required(&instance.image, "local image")?.to_string(),
        "-lc".to_string(),
        format!("exec {LOCAL_RUNTIME_CLI_PATH} daemon"),
    ]);

    let mut args = vec![
        "shell".to_string(),
        "--workdir".to_string(),
        "/".to_string(),
        name.to_string(),
    ];
    args.extend(docker_args);
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args,
    })
}

pub(crate) fn lima_vm_mounts(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<Vec<LimaVmMount>> {
    let mut mounts = vec![LimaVmMount {
        location: lima_repo_mount_path(instance)?,
        mount_point: lima_repo_mount_path(instance)?,
        writable: true,
    }];
    if let Some(path) = &context.gh_config_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.config/gh".to_string(),
            writable: true,
        });
    }
    let git_dir = local_lima_git_state_dir(instance, data_dir);
    if git_dir.join(".gitconfig").exists() {
        mounts.push(LimaVmMount {
            location: git_dir.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.codewire-git".to_string(),
            writable: false,
        });
    }
    if let Some(path) = &context.ssh_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/mnt/host-ssh".to_string(),
            writable: false,
        });
    }
    if let Some(path) = &context.codex_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.codex".to_string(),
            writable: true,
        });
    }
    for mount in &instance.mounts {
        if let Some(source) = trimmed_str(&mount.source) {
            mounts.push(LimaVmMount {
                location: source.to_string(),
                mount_point: local_mount_target(mount).to_string(),
                writable: !mount.readonly.unwrap_or(false),
            });
        }
    }
    Ok(mounts)
}

pub(crate) fn lima_container_mounts(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<Vec<LimaContainerMount>> {
    let vm_user = env::var("USER").unwrap_or_default();
    let vm_home = format!("/home/{vm_user}.guest");
    let mut mounts = Vec::new();
    if context.ssh_auth_sock.is_some() {
        mounts.push(LimaContainerMount {
            source: LOCAL_SSH_AUTH_SOCK_PATH.to_string(),
            target: LOCAL_SSH_AUTH_SOCK_PATH.to_string(),
            read_only: false,
        });
    }
    if local_lima_git_state_dir(instance, data_dir)
        .join(".gitconfig")
        .exists()
    {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.codewire-git/.gitconfig"),
            target: "/home/codewire/.gitconfig".to_string(),
            read_only: true,
        });
    }
    if context.gh_config_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.config/gh"),
            target: "/home/codewire/.config/gh".to_string(),
            read_only: false,
        });
    }
    if context.ssh_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: "/mnt/host-ssh".to_string(),
            target: "/home/codewire/.ssh".to_string(),
            read_only: true,
        });
    }
    if context.codex_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.codex"),
            target: "/home/codewire/.codex".to_string(),
            read_only: false,
        });
    }
    for mount in &instance.mounts {
        if let Some(source) = trimmed_str(&mount.source) {
            mounts.push(LimaContainerMount {
                source: source.to_string(),
                target: local_mount_target(mount).to_string(),
                read_only: mount.readonly.unwrap_or(false),
            });
        }
    }
    Ok(mounts)
}

pub(crate) fn local_mount_target(mount: &config::LocalMountConfig) -> &str {
    trimmed_str(&mount.target).unwrap_or_else(|| mount.source.trim())
}

pub(crate) fn lima_repo_mount_path(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    trimmed_str(&instance.repo_path)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("repo path is empty"))
}

pub(crate) fn lima_ssh_agent_forward_set_expr(
    context: &LocalDockerHostContext,
) -> anyhow::Result<Option<String>> {
    let Some(host_socket) = context.ssh_auth_sock.as_ref() else {
        return Ok(None);
    };
    #[derive(serde::Serialize)]
    struct Forward<'a> {
        #[serde(rename = "guestSocket")]
        guest_socket: &'a str,
        #[serde(rename = "hostSocket")]
        host_socket: String,
    }
    let payload = serde_json::to_string(&[Forward {
        guest_socket: LOCAL_SSH_AUTH_SOCK_PATH,
        host_socket: host_socket.display().to_string(),
    }])?;
    Ok(Some(format!(
        ".portForwards = ((.portForwards // []) | map(select(.guestSocket != {:?})) + {payload})",
        LOCAL_SSH_AUTH_SOCK_PATH
    )))
}

pub(crate) fn local_docker_create_command_spec(
    instance: &config::LocalInstanceConfig,
    context: &LocalDockerHostContext,
) -> anyhow::Result<LocalRuntimeCommand> {
    let runtime = local_runtime_name(instance)?;
    let daemon_host_port = local_daemon_host_port(instance)?;
    let daemon_auth_token = local_daemon_auth_token(instance)?;
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        runtime.to_string(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--hostname".to_string(),
        runtime.to_string(),
        "--add-host".to_string(),
        "host.docker.internal:host-gateway".to_string(),
        "--publish".to_string(),
        format!("127.0.0.1:{daemon_host_port}:{LOCAL_DAEMON_RUNTIME_PORT}/tcp"),
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        "--workdir".to_string(),
        LOCAL_WORKSPACE_PATH.to_string(),
        "--volume".to_string(),
        format!(
            "{}:{LOCAL_WORKSPACE_PATH}",
            trimmed_required(&instance.repo_path, "repo path")?
        ),
    ];

    push_volume(
        &mut args,
        context.claude_dir.as_ref(),
        "/home/codewire/.claude",
    );
    push_volume(
        &mut args,
        context.claude_json.as_ref(),
        "/home/codewire/.claude.json",
    );
    push_volume(
        &mut args,
        context.gh_config_dir.as_ref(),
        "/home/codewire/.config/gh",
    );
    push_volume(
        &mut args,
        context.git_config_path.as_ref(),
        "/home/codewire/.gitconfig:ro",
    );
    push_volume(
        &mut args,
        context.ssh_auth_sock.as_ref(),
        LOCAL_SSH_AUTH_SOCK_PATH,
    );
    push_volume(
        &mut args,
        context.ssh_dir.as_ref(),
        "/home/codewire/.ssh:ro",
    );
    push_volume(
        &mut args,
        context.codex_dir.as_ref(),
        "/home/codewire/.codex",
    );

    if instance.cpu > 0 {
        args.push("--cpus".to_string());
        args.push(format_docker_cpus(instance.cpu));
    }
    if instance.memory > 0 {
        args.push("--memory".to_string());
        args.push(format!("{}m", instance.memory));
    }
    if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("GH_TOKEN={token}"));
    }
    if context.ssh_auth_sock.is_some() {
        args.push("--env".to_string());
        args.push(format!("SSH_AUTH_SOCK={LOCAL_SSH_AUTH_SOCK_PATH}"));
    }
    if let Some(token) = context.claude_oauth_token.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("CLAUDE_CODE_OAUTH_TOKEN={token}"));
    }
    if let Some(api_key) = context.anthropic_api_key.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("ANTHROPIC_API_KEY={api_key}"));
    }
    args.push("--env".to_string());
    args.push(format!(
        "{SHIM_ADDR_ENV}=0.0.0.0:{LOCAL_DAEMON_RUNTIME_PORT}"
    ));
    args.push("--env".to_string());
    args.push(format!("{DAEMON_AUTH_TOKEN_ENV}={daemon_auth_token}"));
    for (key, value) in &instance.env {
        args.push("--env".to_string());
        args.push(format!("{key}={value}"));
    }
    args.push(trimmed_required(&instance.image, "local image")?.to_string());
    args.push("-lc".to_string());
    args.push(format!("exec {LOCAL_RUNTIME_CLI_PATH} daemon"));

    Ok(LocalRuntimeCommand {
        program: "docker".to_string(),
        args,
    })
}

pub(crate) const LOCAL_SSH_AUTH_SOCK_PATH: &str = "/tmp/codewire-ssh-agent.sock";

pub(crate) fn push_volume(args: &mut Vec<String>, source: Option<&PathBuf>, target: &str) {
    if let Some(source) = source {
        args.push("--volume".to_string());
        args.push(format!("{}:{target}", source.display()));
    }
}

pub(crate) fn run_local_command_combined(spec: &LocalRuntimeCommand) -> anyhow::Result<String> {
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .with_context(|| format!("run {}", spec.program))?;
    if !output.status.success() {
        let combined = combined_output(&output.stdout, &output.stderr);
        anyhow::bail!(
            "{} {} failed with exit code {}\n{}",
            spec.program,
            display_local_runtime_args(&spec.args),
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    Ok(combined_output(&output.stdout, &output.stderr))
}

pub(crate) fn run_local_command_with_stdin(
    spec: &LocalRuntimeCommand,
    stdin: &str,
) -> anyhow::Result<String> {
    let mut child = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {}", spec.program))?;
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin
            .write_all(stdin.as_bytes())
            .with_context(|| format!("write stdin for {}", spec.program))?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("wait for {}", spec.program))?;
    if !output.status.success() {
        let combined = combined_output(&output.stdout, &output.stderr);
        anyhow::bail!(
            "{} {} failed with exit code {}\n{}",
            spec.program,
            display_local_runtime_args(&spec.args),
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    Ok(combined_output(&output.stdout, &output.stderr))
}

pub(crate) fn display_local_runtime_args(args: &[String]) -> String {
    let mut redact_environment_value = false;
    args.iter()
        .map(|arg| {
            let rendered = if redact_environment_value {
                arg.split_once('=')
                    .map(|(key, _)| format!("{key}=<redacted>"))
                    .unwrap_or_else(|| arg.clone())
            } else {
                arg.strip_prefix(&format!("{DAEMON_AUTH_TOKEN_ENV}="))
                    .map(|_| format!("{DAEMON_AUTH_TOKEN_ENV}=<redacted>"))
                    .unwrap_or_else(|| arg.clone())
            };
            redact_environment_value = matches!(arg.as_str(), "--env" | "-e");
            rendered
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn combined_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(stdout));
    combined.push_str(&String::from_utf8_lossy(stderr));
    combined
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
    r#"# Auto-generated by cw env --local create. Do not edit by hand.
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

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalInstanceEntry {
    pub(crate) name: String,
    pub(crate) backend: String,
    pub(crate) status: String,
    pub(crate) runtime_name: String,
    pub(crate) repo_path: String,
    pub(crate) workdir: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) image: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) preset: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) install: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) startup: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) secrets: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) agent: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ports: Vec<LocalPortEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) mounts: Vec<LocalMountEntry>,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) cpu: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) memory: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub(crate) disk: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) last_used_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lima: Option<LocalLimaEntry>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalPortEntry {
    pub(crate) host_port: i32,
    pub(crate) guest_port: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) label: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalMountEntry {
    pub(crate) source: String,
    pub(crate) target: String,
    #[serde(skip_serializing_if = "is_false")]
    pub(crate) readonly: bool,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalLimaEntry {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) instance_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mount_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) vm_type: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LocalFileEntry {
    pub(crate) name: String,
    pub(crate) size: i64,
    pub(crate) is_dir: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) mtime: String,
}

pub(crate) fn sorted_local_instance_entries(
    config: &config::LocalInstancesConfig,
) -> Vec<LocalInstanceEntry> {
    let mut entries = config
        .instances
        .iter()
        .map(|(key, instance)| local_instance_entry(key, instance, "unknown"))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

pub(crate) fn resolve_local_instance_entry(
    data_dir: &Path,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<LocalInstanceEntry> {
    let (key, instance) = resolve_local_instance_config(data_dir, name, current_dir)?;
    Ok(local_instance_entry(&key, &instance, "unknown"))
}

pub(crate) fn resolve_local_instance_config(
    data_dir: &Path,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<(String, config::LocalInstanceConfig)> {
    let config = config::load_local_instances_config(data_dir)?;
    resolve_local_instance_config_from_state(&config, name, current_dir)
}

pub(crate) fn resolve_local_instance_config_from_state(
    config: &config::LocalInstancesConfig,
    name: Option<&str>,
    current_dir: &Path,
) -> anyhow::Result<(String, config::LocalInstanceConfig)> {
    if config.instances.is_empty() {
        anyhow::bail!("no local instances found");
    }

    if let Some(name) = name.and_then(trimmed_str) {
        if let Some(instance) = config.instances.get(name) {
            return Ok((name.to_string(), instance.clone()));
        }
        for (key, instance) in &config.instances {
            if trimmed_str(&instance.runtime_name) == Some(name) {
                return Ok((key.clone(), instance.clone()));
            }
        }
        anyhow::bail!("local instance not found: {name}");
    }

    let current_dir = normalized_path(current_dir);
    let mut matches = config
        .instances
        .iter()
        .filter(|(_, instance)| {
            trimmed_str(&instance.repo_path)
                .map(|repo_path| {
                    path_contains(&normalized_path(Path::new(repo_path)), &current_dir)
                })
                .unwrap_or(false)
        })
        .map(|(key, instance)| (key.as_str(), instance))
        .collect::<Vec<_>>();
    matches.sort_by_key(|(key, _)| *key);

    match matches.as_slice() {
        [(key, instance)] => Ok(((*key).to_string(), (*instance).clone())),
        [] => anyhow::bail!(
            "no local environment associated with this directory; pass a name explicitly or run 'cw env --local create'"
        ),
        _ => {
            let names = matches
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("multiple local instances match this repo: {names}");
        }
    }
}

pub(crate) fn local_instance_entry(
    key: &str,
    instance: &config::LocalInstanceConfig,
    status: &str,
) -> LocalInstanceEntry {
    let ports = instance
        .ports
        .iter()
        .filter_map(local_port_entry)
        .collect::<Vec<_>>();
    let mounts = instance
        .mounts
        .iter()
        .filter_map(local_mount_entry)
        .collect::<Vec<_>>();
    let lima = if instance.backend == "lima" {
        let lima = LocalLimaEntry {
            instance_name: instance.lima_instance_name.clone(),
            mount_type: instance.lima_mount_type.clone(),
            vm_type: instance.lima_vm_type.clone(),
        };
        if lima.instance_name.is_empty() && lima.mount_type.is_empty() && lima.vm_type.is_empty() {
            None
        } else {
            Some(lima)
        }
    } else {
        None
    };

    LocalInstanceEntry {
        name: local_instance_display_name(key, instance).to_string(),
        backend: instance.backend.clone(),
        status: status.to_string(),
        runtime_name: instance.runtime_name.clone(),
        repo_path: instance.repo_path.clone(),
        workdir: instance.workdir.clone(),
        image: instance.image.clone(),
        preset: instance.preset.clone(),
        install: instance.install.clone(),
        startup: instance.startup.clone(),
        secrets: instance.secrets.clone(),
        agent: instance.agent.clone(),
        env: instance.env.clone(),
        ports,
        mounts,
        cpu: instance.cpu,
        memory: instance.memory,
        disk: instance.disk,
        created_at: instance.created_at.clone(),
        last_used_at: instance.last_used_at.clone(),
        lima,
    }
}

pub(crate) fn local_port_entry(port: &config::LocalPortConfig) -> Option<LocalPortEntry> {
    let host_port = port.effective_host_port();
    let guest_port = port.effective_guest_port();
    if host_port <= 0 || guest_port <= 0 {
        return None;
    }
    Some(LocalPortEntry {
        host_port,
        guest_port,
        label: port.label.clone(),
    })
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LimaPortForwardEdit {
    #[serde(rename = "guestPort")]
    pub(crate) guest_port: i32,
    #[serde(rename = "hostPort")]
    pub(crate) host_port: i32,
    pub(crate) proto: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalPortPublishResult {
    pub(crate) added: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LimaPortForwardPlan {
    pub(crate) updated_ports: Vec<config::LocalPortConfig>,
    pub(crate) forwards: Vec<LimaPortForwardEdit>,
    pub(crate) added: usize,
}

pub(crate) fn publish_local_ports(
    instance: &mut config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LocalPortPublishResult> {
    match trimmed_required(&instance.backend, "local backend")? {
        "lima" => {
            let result = add_lima_port_forwards(instance, publish)?;
            instance.ports = result.updated_ports;
            Ok(LocalPortPublishResult {
                added: result.added,
            })
        }
        _ => anyhow::bail!(
            "interactive 'cw env --local ports' forwarding is only available for Lima; use backend-native port mapping for docker"
        ),
    }
}

pub(crate) fn add_lima_port_forwards(
    instance: &config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LimaPortForwardPlan> {
    let plan = plan_lima_port_forwards(instance, publish)?;
    if !plan.forwards.is_empty() {
        lima_add_port_forwards(instance, &plan.forwards)?;
    }
    Ok(plan)
}

pub(crate) fn plan_lima_port_forwards(
    instance: &config::LocalInstanceConfig,
    publish: &[String],
) -> anyhow::Result<LimaPortForwardPlan> {
    let mut existing_by_host: HashMap<i32, config::LocalPortConfig> =
        HashMap::with_capacity(instance.ports.len());
    let mut updated_ports = Vec::with_capacity(instance.ports.len() + publish.len());
    for port in &instance.ports {
        let canonical = canonical_local_port(port);
        let host_port = canonical.effective_host_port();
        let guest_port = canonical.effective_guest_port();
        if host_port <= 0 || guest_port <= 0 {
            continue;
        }
        if let Some(existing) = existing_by_host.get(&host_port)
            && existing.effective_guest_port() != guest_port
        {
            anyhow::bail!(
                "Lima instance {:?} has conflicting host port {} mapped to guest ports {} and {}",
                instance.name,
                host_port,
                existing.effective_guest_port(),
                guest_port
            );
        }
        existing_by_host.insert(host_port, canonical.clone());
        updated_ports.push(canonical);
    }

    let mut forwards = Vec::with_capacity(publish.len());
    let mut added = 0;
    for spec in publish {
        let port = parse_published_port_spec(spec)?;
        let host_port = port.effective_host_port();
        let guest_port = port.effective_guest_port();
        if let Some(existing) = existing_by_host.get(&host_port) {
            if existing.effective_guest_port() != guest_port {
                anyhow::bail!(
                    "host port {} is already forwarded to guest port {}",
                    host_port,
                    existing.effective_guest_port()
                );
            }
            continue;
        }
        existing_by_host.insert(host_port, port.clone());
        updated_ports.push(port);
        forwards.push(LimaPortForwardEdit {
            guest_port,
            host_port,
            proto: "tcp".to_string(),
        });
        added += 1;
    }

    Ok(LimaPortForwardPlan {
        updated_ports,
        forwards,
        added,
    })
}

pub(crate) fn parse_published_port_spec(spec: &str) -> anyhow::Result<config::LocalPortConfig> {
    let spec = spec.trim();
    let Some((host, guest)) = spec.split_once(':') else {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    };
    if guest.contains(':') {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    }
    let host_port = host.trim().parse::<i32>().ok().filter(|port| *port > 0);
    let guest_port = guest.trim().parse::<i32>().ok().filter(|port| *port > 0);
    let (Some(host_port), Some(guest_port)) = (host_port, guest_port) else {
        anyhow::bail!(
            "invalid port spec {:?} (use host:guest format, e.g. 8080:3000)",
            spec
        );
    };
    if guest_port == i32::from(LOCAL_DAEMON_RUNTIME_PORT) {
        anyhow::bail!(
            "guest port {LOCAL_DAEMON_RUNTIME_PORT} is reserved for the managed environment daemon"
        );
    }
    Ok(canonical_local_port(&config::LocalPortConfig {
        host_port,
        guest_port,
        ..config::LocalPortConfig::default()
    }))
}

pub(crate) fn canonical_local_port(port: &config::LocalPortConfig) -> config::LocalPortConfig {
    let host_port = port.effective_host_port();
    let guest_port = port.effective_guest_port();
    let mut out = config::LocalPortConfig {
        label: port.label.clone(),
        ..config::LocalPortConfig::default()
    };
    if host_port <= 0 || guest_port <= 0 {
        return out;
    }
    if host_port == guest_port {
        out.port = guest_port;
    } else {
        out.host_port = host_port;
        out.guest_port = guest_port;
    }
    out
}

pub(crate) fn lima_add_port_forwards(
    instance: &config::LocalInstanceConfig,
    forwards: &[LimaPortForwardEdit],
) -> anyhow::Result<()> {
    if forwards.is_empty() {
        return Ok(());
    }
    let spec = lima_add_port_forwards_command_spec(instance, forwards)?;
    run_local_command_combined(&spec).map(|_| ())
}

pub(crate) fn lima_add_port_forwards_command_spec(
    instance: &config::LocalInstanceConfig,
    forwards: &[LimaPortForwardEdit],
) -> anyhow::Result<LocalRuntimeCommand> {
    let name = local_lima_instance_name(instance)?;
    if forwards.is_empty() {
        anyhow::bail!("no Lima port forwards specified");
    }
    let payload = serde_json::to_string(forwards).context("marshal Lima port forwards")?;
    let set_expr = format!(".portForwards = (.portForwards // []) + {payload}");
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "edit".to_string(),
            "--tty=false".to_string(),
            name.to_string(),
            "--set".to_string(),
            set_expr,
        ],
    })
}

pub(crate) fn local_mount_entry(mount: &config::LocalMountConfig) -> Option<LocalMountEntry> {
    if mount.source.trim().is_empty() {
        return None;
    }
    Some(LocalMountEntry {
        source: mount.source.clone(),
        target: mount.target.clone(),
        readonly: mount.readonly.unwrap_or(false),
    })
}

pub(crate) fn format_local_instance_list_text(entries: &[LocalInstanceEntry]) -> String {
    if entries.is_empty() {
        return "No local instances found.\n".to_string();
    }
    let mut output = format!(
        "{:<20} {:<10} {:<10} {:<18} {:<20} {}\n",
        "NAME", "BACKEND", "STATE", "PORTS", "IMAGE", "REPO"
    );
    for entry in entries {
        output.push_str(&format!(
            "{:<20} {:<10} {:<10} {:<18} {:<20} {}\n",
            entry.name,
            entry.backend,
            entry.status,
            local_port_summary(entry),
            entry.image,
            entry.repo_path
        ));
    }
    output
}

pub(crate) fn format_local_instance_info_text(entry: &LocalInstanceEntry) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<10} {}\n", "Name:", entry.name));
    output.push_str(&format!("{:<10} {}\n", "Backend:", entry.backend));
    output.push_str(&format!("{:<10} {}\n", "State:", entry.status));
    output.push_str(&format!("{:<10} {}\n", "Runtime:", entry.runtime_name));
    output.push_str(&format!("{:<10} {}\n", "Image:", entry.image));
    output.push_str(&format!("{:<10} {}\n", "Repo:", entry.repo_path));
    output.push_str(&format!("{:<10} {}\n", "Workdir:", entry.workdir));
    let ports = local_port_summary(entry);
    if !ports.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Ports:", ports));
    }
    if let Some(lima) = &entry.lima {
        if !lima.vm_type.is_empty() {
            output.push_str(&format!("{:<10} {}\n", "VMType:", lima.vm_type));
        }
        if !lima.mount_type.is_empty() {
            output.push_str(&format!("{:<10} {}\n", "MountType:", lima.mount_type));
        }
    }
    if !entry.preset.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Preset:", entry.preset));
    }
    if !entry.install.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Install:", entry.install));
    }
    if !entry.startup.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Startup:", entry.startup));
    }
    if !entry.created_at.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Created:", entry.created_at));
    }
    output
}

pub(crate) fn format_local_resize_text(entry: &LocalInstanceEntry) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<10} {}\n", "State:", entry.status));
    if entry.cpu > 0 {
        output.push_str(&format!("{:<10} {}m\n", "CPU:", entry.cpu));
    }
    if entry.memory > 0 {
        output.push_str(&format!(
            "{:<10} {}\n",
            "Memory:",
            local_runtime_memory_label(entry.memory)
        ));
    }
    if entry.disk > 0 {
        output.push_str(&format!("{:<10} {}GiB\n", "Disk:", entry.disk));
    }
    output
}

pub(crate) fn local_runtime_memory_label(memory_mb: i32) -> String {
    if memory_mb > 0 && memory_mb % 1024 == 0 {
        format!("{}GiB", memory_mb / 1024)
    } else {
        format!("{memory_mb}MB")
    }
}

pub(crate) fn local_port_summary(entry: &LocalInstanceEntry) -> String {
    entry
        .ports
        .iter()
        .filter_map(|port| local_port_display(entry, port))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn format_local_ports_text(entry: &LocalInstanceEntry) -> String {
    let mut lines = entry
        .ports
        .iter()
        .filter_map(|port| local_port_display(entry, port))
        .map(|display| format!("  {display}\n"))
        .collect::<String>();
    if lines.is_empty() {
        lines.push_str("No ports configured.\n");
    }
    lines
}

pub(crate) fn format_local_files_text(entries: &[LocalFileEntry]) -> String {
    entries
        .iter()
        .map(|entry| {
            let kind = if entry.is_dir { "dir" } else { "file" };
            format!("{kind}\t{}\t{}\t{}\n", entry.mode, entry.size, entry.name)
        })
        .collect()
}

pub(crate) fn local_port_display(
    entry: &LocalInstanceEntry,
    port: &LocalPortEntry,
) -> Option<String> {
    if port.host_port <= 0 || port.guest_port <= 0 {
        return None;
    }
    let mut display = if port.host_port != port.guest_port || entry.backend == "lima" {
        format!("{} -> {}", port.host_port, port.guest_port)
    } else {
        port.guest_port.to_string()
    };
    if let Some(label) = trimmed_str(&port.label) {
        display.push_str(" (");
        display.push_str(label);
        display.push(')');
    }
    Some(display)
}

pub(crate) fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalLifecycleAction {
    Start,
    Stop,
    Remove,
}

impl LocalLifecycleAction {
    pub(crate) fn docker_subcommand(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "rm",
        }
    }

    pub(crate) fn lima_subcommand(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "delete",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "remove",
        }
    }
}

pub(crate) fn local_lifecycle_command_spec(
    instance: &config::LocalInstanceConfig,
    action: LocalLifecycleAction,
) -> anyhow::Result<LocalRuntimeCommand> {
    let backend = trimmed_required(&instance.backend, "local backend")?;
    match backend {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let args = match action {
                LocalLifecycleAction::Start | LocalLifecycleAction::Stop => {
                    vec![action.docker_subcommand().to_string(), runtime.to_string()]
                }
                LocalLifecycleAction::Remove => vec![
                    action.docker_subcommand().to_string(),
                    "-f".to_string(),
                    runtime.to_string(),
                ],
            };
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let args = match action {
                LocalLifecycleAction::Start | LocalLifecycleAction::Stop => {
                    vec![action.lima_subcommand().to_string(), lima_name.to_string()]
                }
                LocalLifecycleAction::Remove => vec![
                    action.lima_subcommand().to_string(),
                    "--force".to_string(),
                    lima_name.to_string(),
                ],
            };
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn run_local_lifecycle_command(
    instance: &config::LocalInstanceConfig,
    action: LocalLifecycleAction,
) -> anyhow::Result<()> {
    let backend = trimmed_required(&instance.backend, "local backend")?;
    let spec = local_lifecycle_command_spec(instance, action)?;
    let status = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .status()
        .with_context(|| format!("{} local runtime command", action.label()))?;
    if !status.success() {
        anyhow::bail!(
            "local runtime {} failed with exit code {}",
            action.label(),
            status.code().unwrap_or(1)
        );
    }
    if backend == "lima" && action == LocalLifecycleAction::Start {
        run_local_command_combined(&local_lima_docker_service_start_command_spec(instance)?)
            .context("start Docker inside Lima environment")?;
        run_local_command_combined(&local_lima_workspace_start_command_spec(instance)?)
            .context("start managed workspace inside Lima environment")?;
    }
    Ok(())
}

pub(crate) fn local_lima_docker_service_start_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            local_lima_instance_name(instance)?.to_string(),
            "sudo".to_string(),
            "systemctl".to_string(),
            "start".to_string(),
            "docker".to_string(),
        ],
    })
}

pub(crate) fn local_lima_workspace_start_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: vec![
            "shell".to_string(),
            "--workdir".to_string(),
            "/".to_string(),
            local_lima_instance_name(instance)?.to_string(),
            "sudo".to_string(),
            "docker".to_string(),
            "start".to_string(),
            LIMA_CONTAINER_NAME.to_string(),
        ],
    })
}

pub(crate) fn local_daemon_logs_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => Ok(LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "logs".to_string(),
                "--tail".to_string(),
                "200".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        }),
        "lima" => Ok(LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                local_lima_instance_name(instance)?.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "logs".to_string(),
                "--tail".to_string(),
                "200".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ],
        }),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_daemon_repair_command_spec(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<LocalRuntimeCommand> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => Ok(LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "restart".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        }),
        "lima" => Ok(LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                local_lima_instance_name(instance)?.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "restart".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ],
        }),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn read_local_daemon_logs(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    run_local_command_combined(&local_daemon_logs_command_spec(instance)?)
        .context("read local environment daemon logs")
}

pub(crate) fn repair_local_daemon(instance: &config::LocalInstanceConfig) -> anyhow::Result<()> {
    run_local_command_combined(&local_daemon_repair_command_spec(instance)?)
        .context("restart local environment daemon")?;
    Ok(())
}

pub(crate) fn local_environment_lifecycle_status(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => docker_workspace_container_status(local_runtime_name(instance)?),
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let vm_status = local_lima_instance_status(lima_name)?;
            if vm_status == "running" {
                lima_workspace_container_status(lima_name)
            } else {
                Ok(vm_status)
            }
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn docker_workspace_container_status(runtime_name: &str) -> anyhow::Result<String> {
    let output = ProcessCommand::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", runtime_name])
        .output()
        .context("inspect local workspace container")?;
    parse_docker_workspace_container_status(
        output.status.success(),
        output.status.code().unwrap_or(1),
        &output.stdout,
        &output.stderr,
    )
    .with_context(|| format!("docker inspect {runtime_name}"))
}

pub(crate) fn parse_docker_workspace_container_status(
    success: bool,
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Result<String> {
    let combined = combined_output(stdout, stderr);
    if !success {
        let lower = combined.to_ascii_lowercase();
        if lower.contains("no such object")
            || lower.contains("no such container")
            || lower.contains("not found")
        {
            return Ok("missing".to_string());
        }
        anyhow::bail!("exit code {exit_code}\\n{}", combined.trim());
    }
    Ok(combined.trim().to_ascii_lowercase())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalResizeResult {
    pub(crate) restart_after_resize: bool,
    pub(crate) status_after_resize: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct LimaListEntry {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) status: String,
}

pub(crate) fn validate_local_resize_args(args: &LocalResizeArgs) -> anyhow::Result<()> {
    if args.cpu == 0 && args.memory == 0 && args.disk == 0 {
        anyhow::bail!("at least one of --cpu, --memory, or --disk is required");
    }
    if args.cpu < 0 {
        anyhow::bail!("--cpu must be positive");
    }
    if args.memory < 0 {
        anyhow::bail!("--memory must be positive");
    }
    if args.disk < 0 {
        anyhow::bail!("--disk must be positive");
    }
    Ok(())
}

pub(crate) fn resize_local_runtime(
    instance: &mut config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalResizeResult> {
    match trimmed_required(&instance.backend, "local backend")? {
        "lima" => resize_local_lima_instance(instance, args),
        _ => anyhow::bail!("local resize is currently only supported for Lima-backed instances"),
    }
}

pub(crate) fn resize_local_lima_instance(
    instance: &mut config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalResizeResult> {
    let name = local_lima_instance_name(instance)?;
    let status = local_lima_instance_status(name)?;
    if status == "missing" {
        anyhow::bail!(
            "Lima instance {:?} is missing; recreate it with 'cw env --local create --backend lima'",
            instance.name
        );
    }

    let mut restart_after_resize = false;
    if status == "running" {
        if !args.restart {
            anyhow::bail!(
                "Lima instance {:?} is running; pass --restart to stop, resize, and start it again",
                instance.name
            );
        }
        run_local_lifecycle_command(instance, LocalLifecycleAction::Stop)?;
        restart_after_resize = true;
    }

    let spec = local_resize_command_spec(instance, args)?;
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .context("resize local runtime command")?;
    if !output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let trimmed = combined.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "limactl edit {name}: exit code {}",
                output.status.code().unwrap_or(1)
            );
        }
        anyhow::bail!(
            "limactl edit {name}: exit code {}\n{trimmed}",
            output.status.code().unwrap_or(1)
        );
    }

    if args.cpu > 0 {
        instance.cpu = args.cpu;
    }
    if args.memory > 0 {
        instance.memory = args.memory;
    }
    if args.disk > 0 {
        instance.disk = args.disk;
    }

    Ok(LocalResizeResult {
        restart_after_resize,
        status_after_resize: if restart_after_resize {
            "running".to_string()
        } else {
            status
        },
    })
}

pub(crate) fn local_resize_command_spec(
    instance: &config::LocalInstanceConfig,
    args: &LocalResizeArgs,
) -> anyhow::Result<LocalRuntimeCommand> {
    if trimmed_required(&instance.backend, "local backend")? != "lima" {
        anyhow::bail!("local resize is currently only supported for Lima-backed instances");
    }
    let name = local_lima_instance_name(instance)?;
    let mut command_args = vec![
        "edit".to_string(),
        "--tty=false".to_string(),
        name.to_string(),
    ];
    if args.cpu > 0 {
        command_args.push("--cpus".to_string());
        command_args.push(lima_cpus_from_millicores(args.cpu).to_string());
    }
    if args.memory > 0 {
        command_args.push("--memory".to_string());
        command_args.push(lima_memory_gib_from_mb(args.memory).to_string());
    }
    if args.disk > 0 {
        command_args.push("--disk".to_string());
        command_args.push(args.disk.to_string());
    }
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args: command_args,
    })
}

pub(crate) fn local_lima_instance_status(name: &str) -> anyhow::Result<String> {
    let output = ProcessCommand::new("limactl")
        .args(["list", "--format", "json"])
        .output()
        .context("limactl list --format json")?;
    if !output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lower = combined.to_lowercase();
        if lower.contains("not found")
            || lower.contains("no such")
            || lower.contains("no instance matching")
            || lower.contains("unmatched instances")
        {
            return Ok("missing".to_string());
        }
        anyhow::bail!(
            "limactl list --format json: exit code {}\n{}",
            output.status.code().unwrap_or(1),
            combined.trim()
        );
    }
    parse_lima_instance_status(name, &output.stdout)
}

pub(crate) fn parse_lima_instance_status(name: &str, data: &[u8]) -> anyhow::Result<String> {
    let data = trim_ascii_bytes(data);
    if data.is_empty() {
        return Ok("missing".to_string());
    }

    let entries = if data[0] == b'[' {
        serde_json::from_slice::<Vec<LimaListEntry>>(data).context("parse limactl list output")?
    } else {
        let mut entries = Vec::new();
        for line in data.split(|byte| *byte == b'\n') {
            let line = trim_ascii_bytes(line);
            if line.first() != Some(&b'{') {
                continue;
            }
            entries.push(
                serde_json::from_slice::<LimaListEntry>(line)
                    .context("parse limactl list output")?,
            );
        }
        entries
    };

    for entry in entries {
        if entry.name.trim() == name {
            let status = entry.status.trim().to_lowercase();
            return Ok(if status.is_empty() {
                "unknown".to_string()
            } else {
                status
            });
        }
    }
    Ok("missing".to_string())
}

pub(crate) fn trim_ascii_bytes(mut data: &[u8]) -> &[u8] {
    while data.first().is_some_and(u8::is_ascii_whitespace) {
        data = &data[1..];
    }
    while data.last().is_some_and(u8::is_ascii_whitespace) {
        data = &data[..data.len() - 1];
    }
    data
}

pub(crate) fn lima_cpus_from_millicores(millicores: i32) -> i32 {
    ((millicores + 999) / 1000).max(1)
}

pub(crate) fn lima_memory_gib_from_mb(memory_mb: i32) -> i32 {
    ((memory_mb + 1023) / 1024).max(1)
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalRuntimeCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

pub(crate) fn local_runtime_command_spec(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
    command: &[String],
    env_overrides: &BTreeMap<String, String>,
) -> anyhow::Result<LocalRuntimeCommand> {
    local_runtime_command_spec_with_tty(instance, workdir, command, env_overrides, false)
}

pub(crate) fn local_runtime_command_spec_with_tty(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
    command: &[String],
    env_overrides: &BTreeMap<String, String>,
    allocate_tty: bool,
) -> anyhow::Result<LocalRuntimeCommand> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }
    let backend = trimmed_required(&instance.backend, "local backend")?;
    let workdir = local_runtime_workdir(instance, workdir);
    let mut env_args = Vec::new();
    for (key, value) in env_overrides {
        env_args.push("-e".to_string());
        env_args.push(format!("{key}={value}"));
    }

    match backend {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let mut args = vec!["exec".to_string(), "-i".to_string()];
            if allocate_tty {
                args.push("-t".to_string());
            }
            if !workdir.is_empty() {
                args.push("-w".to_string());
                args.push(workdir);
            }
            args.extend(env_args);
            args.push(runtime.to_string());
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let mut docker_args = vec![
                "sudo".to_string(),
                "docker".to_string(),
                "exec".to_string(),
                "-i".to_string(),
            ];
            if allocate_tty {
                docker_args.push("-t".to_string());
            }
            if !workdir.is_empty() {
                docker_args.push("-w".to_string());
                docker_args.push(workdir);
            }
            docker_args.extend(env_args);
            docker_args.push(LIMA_CONTAINER_NAME.to_string());
            docker_args.extend(command.iter().cloned());

            let mut args = vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
            ];
            args.extend(docker_args);
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_runtime_workdir(
    instance: &config::LocalInstanceConfig,
    workdir: Option<&str>,
) -> String {
    workdir
        .and_then(trimmed_str)
        .or_else(|| trimmed_str(&instance.workdir))
        .unwrap_or(LOCAL_WORKSPACE_PATH)
        .to_string()
}

pub(crate) fn local_runtime_name(instance: &config::LocalInstanceConfig) -> anyhow::Result<&str> {
    trimmed_str(&instance.runtime_name)
        .or_else(|| trimmed_str(&instance.name))
        .ok_or_else(|| anyhow::anyhow!("local runtime name is empty"))
}

pub(crate) fn local_lima_instance_name(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<&str> {
    trimmed_str(&instance.lima_instance_name)
        .or_else(|| trimmed_str(&instance.runtime_name))
        .or_else(|| trimmed_str(&instance.name))
        .ok_or_else(|| anyhow::anyhow!("Lima instance name is empty"))
}

pub(crate) fn handle_local_files_command(
    data_dir: &Path,
    args: LocalFilesArgs,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let current_dir = env::current_dir().context("current directory")?;
    match args.command {
        LocalFilesCommand::Upload(upload) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&upload.name), &current_dir)?;
            local_files_upload(&instance, &upload.remote_path)?;
            if matches!(output, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": instance.name,
                        "remote_path": upload.remote_path,
                        "uploaded": true,
                    }))?
                );
            }
        }
        LocalFilesCommand::Download(download) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&download.name), &current_dir)?;
            local_files_download(&instance, &download.remote_path)?;
        }
        LocalFilesCommand::List(list) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&list.name), &current_dir)?;
            let entries = local_files_list(
                &instance,
                list.remote_path
                    .as_deref()
                    .and_then(trimmed_str)
                    .unwrap_or("/"),
            )?;
            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
                OutputFormat::Text => print!("{}", format_local_files_text(&entries)),
            }
        }
    }
    Ok(())
}

pub(crate) fn local_files_command_spec(
    instance: &config::LocalInstanceConfig,
    command: &[String],
) -> anyhow::Result<LocalRuntimeCommand> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let mut args = vec!["exec".to_string(), "-i".to_string(), runtime.to_string()];
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let mut args = vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "exec".to_string(),
                "-i".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ];
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_files_upload(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<()> {
    let remote_path = trimmed_required(remote_path, "remote path")?;
    let script = format!(
        "mkdir -p {} && cat > {}",
        shell_quote(&parent_dir(remote_path)),
        shell_quote(remote_path)
    );
    let spec = local_files_command_spec(instance, &["sh".to_string(), "-c".to_string(), script])?;
    let mut child = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("start upload")?;
    let mut child_stdin = child.stdin.take().context("stdin pipe")?;
    let mut stdin = std::io::stdin().lock();
    let copy_result = std::io::copy(&mut stdin, &mut child_stdin).context("upload");
    drop(child_stdin);
    let status = child.wait().context("upload")?;
    copy_result?;
    if !status.success() {
        anyhow::bail!(
            "upload failed with exit code {}",
            status.code().unwrap_or(1)
        );
    }
    Ok(())
}

pub(crate) fn local_files_download(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<()> {
    let remote_path = trimmed_required(remote_path, "remote path")?;
    let spec = local_files_command_spec(instance, &["cat".to_string(), remote_path.to_string()])?;
    let status = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("download")?;
    if !status.success() {
        anyhow::bail!(
            "download failed with exit code {}",
            status.code().unwrap_or(1)
        );
    }
    Ok(())
}

pub(crate) fn local_files_list(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<Vec<LocalFileEntry>> {
    let remote_path = trimmed_str(remote_path).unwrap_or("/");
    let spec = local_files_command_spec(
        instance,
        &[
            "ls".to_string(),
            "-la".to_string(),
            "--time-style=full-iso".to_string(),
            remote_path.to_string(),
        ],
    )?;
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .context("list")?;
    if !output.status.success() {
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        anyhow::bail!(
            "list failed with exit code {}",
            output.status.code().unwrap_or(1)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ls_output(&stdout))
}

pub(crate) fn parse_ls_output(output: &str) -> Vec<LocalFileEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        if line.starts_with("total ") || line.trim().is_empty() {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 9 {
            continue;
        }
        let mode = parts[0];
        let size = parts[4].parse::<i64>().unwrap_or_default();
        let mtime = format!("{} {} {}", parts[5], parts[6], parts[7]);
        let mut name = extract_ls_name(line, &parts[..8]);
        if name == "." || name == ".." {
            continue;
        }
        if let Some((link_name, _)) = name.split_once(" -> ") {
            name = link_name.to_string();
        }
        entries.push(LocalFileEntry {
            name,
            size,
            is_dir: mode.starts_with('d'),
            mode: mode.to_string(),
            mtime,
        });
    }
    entries
}

pub(crate) fn extract_ls_name(line: &str, prefix: &[&str]) -> String {
    let mut rest = line;
    for field in prefix {
        if let Some(index) = rest.find(field) {
            rest = &rest[index + field.len()..];
        } else {
            return rest.to_string();
        }
    }
    rest.trim_start_matches([' ', '\t']).to_string()
}

pub(crate) fn parent_dir(remote_path: &str) -> String {
    match remote_path.rfind('/') {
        Some(index) if index > 0 => remote_path[..index].to_string(),
        _ => "/".to_string(),
    }
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
