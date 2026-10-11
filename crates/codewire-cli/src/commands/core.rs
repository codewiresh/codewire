use std::path::Path;

use super::*;

pub(crate) async fn handle_logout_command(globals: &Globals) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    if let Ok(platform) = resolve_platform(globals, &paths, &env) {
        if let Some(path) = &platform.oauth_credentials_path {
            let store = codewire_client::FileCredentialStore::at(path);
            if let Ok(Some(credentials)) = codewire_client::CredentialStore::load(&store)
                && let Ok(client) =
                    codewire_client::OAuthClient::for_server_url(&platform.server_url)
            {
                let _ = client.revoke_credentials(&credentials).await;
            }
            let _ = codewire_client::CredentialStore::delete(&store);
        } else if let Ok(client) = codewire_client(&platform) {
            let _ = client.auth().logout().await;
        }
    }
    let _ = config::delete_platform_config(&paths.platform_config_dir);
    remove_hosted_mesh_owner_context(&paths.mesh_data_dir)?;
    eprintln!("Logged out.");
    Ok(())
}

pub(crate) async fn handle_whoami_command(
    globals: &Globals,
    args: WhoamiArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let token = platform.token_provider()?.token().await?;
    let response = codewire_client::OAuthClient::for_server_url(&platform.server_url)?
        .userinfo(&token)
        .await
        .context("OAuth user info failed")?;
    let user = PlatformUser {
        id: response.sub,
        email: response.email.unwrap_or_default(),
        email_verified: response.email_verified.unwrap_or(false),
        name: response.name.unwrap_or_default(),
        image: response.picture.unwrap_or_default(),
        ..PlatformUser::default()
    };
    print_platform_user(&user, &platform, args.output)
}

pub(crate) async fn handle_use_command(
    globals: &Globals,
    args: UseTargetArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let placement = if args.local {
        Some(EnvironmentPlacement::Local)
    } else if args.platform {
        Some(EnvironmentPlacement::Platform)
    } else {
        None
    };
    #[cfg(unix)]
    let host = if placement != Some(EnvironmentPlacement::Platform) {
        resolve_host_reference(globals, &args.target, placement).await?
    } else {
        None
    };
    #[cfg(unix)]
    let target = if let Some(host) = host {
        host.current_target()
    } else {
        resolve_named_execution_target(globals, &paths, &env, &args.target, placement).await?
    };
    #[cfg(not(unix))]
    let target =
        resolve_named_execution_target(globals, &paths, &env, &args.target, placement).await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if target.kind == "local" && target.target_ref != "local" {
        select_native_environment(&target.target_ref).await?;
    }
    config::save_current_target(&paths.mesh_data_dir, &target).context("save current target")?;

    match target.kind.as_str() {
        "local" if target.target_ref == "local" => eprintln!("Current target set to local."),
        "local" => eprintln!(
            "Current target set to {}.",
            target_display_name(&target, None)
        ),
        "env" => eprintln!(
            "Current target set to {} ({}).",
            target_display_name(&target, None),
            short_env_id(&target.target_ref)
        ),
        _ => eprintln!(
            "Current target set to {}.",
            target_display_name(&target, None)
        ),
    }
    Ok(())
}

pub(crate) async fn handle_current_command(
    globals: &Globals,
    args: CurrentTargetArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let target = config::current_target(&paths.mesh_data_dir)?;
    let network = config::selected_mesh_network(&paths, &env);
    let environment = lookup_environment_for_target(globals, &paths, &env, &target).await;
    print!(
        "{}",
        format_current_target_text(
            &target,
            environment.as_ref(),
            network.as_deref(),
            args.verbose
        )
    );
    Ok(())
}

pub(crate) async fn handle_init_command(globals: &Globals, args: InitArgs) -> anyhow::Result<()> {
    if !args.force
        && args
            .file
            .try_exists()
            .with_context(|| format!("stat {}", args.file.display()))?
    {
        anyhow::bail!(
            "{} already exists (use --force to overwrite)",
            args.file.display()
        );
    }

    let mut platform_context = None;
    let request = if init_needs_platform_resolution(&args) {
        let prepare = init_prepare_request_from_args(&args)?;
        let (org_id, organization_client, environment_client) =
            resolve_platform_context(globals).await?;
        let response = environment_client
            .prepare_environment_create(&org_id, &prepare)
            .await
            .context("prepare launch")?;
        platform_context = Some((org_id, organization_client));
        response.draft
    } else {
        init_request_from_args(&args)?
    };

    write_resolved_codewire_yaml(&args.file, &request).context("write codewire.yaml")?;
    eprintln!("codewire.yaml written: {}", args.file.display());
    if let Some(preset_name) = trimmed_optional(args.save_preset.clone()) {
        let (org_id, organization_client) = match platform_context {
            Some(context) => context,
            None => {
                let (org_id, organization_client, _) = resolve_platform_context(globals).await?;
                (org_id, organization_client)
            }
        };
        let preset_request = create_preset_request_from_environment(&preset_name, &request)?;
        let preset = organization_client
            .create_preset(&org_id, &preset_request)
            .await
            .context("save preset")?;
        eprintln!("Preset saved: {} ({}).", preset.name, preset.id);
    }
    eprintln!("Next:");
    eprintln!("  cw env create --local --name <environment>");
    eprintln!("  cw run <environment> -- <command>");
    eprintln!("  cw env create");
    Ok(())
}

pub(crate) async fn resolve_platform_context(
    globals: &Globals,
) -> anyhow::Result<(String, OrganizationClient, EnvironmentClient)> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let organization_client = organization_client(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    Ok((
        org_id,
        organization_client,
        EnvironmentClient::new(&platform)?,
    ))
}

pub(crate) async fn handle_vscode_command(
    globals: &Globals,
    args: VscodeArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let org_id = resolve_org_id(&platform, &orgs, args.org.as_deref())?;
    let environment = args.environment.as_deref().and_then(vscode_environment_ref);
    let environment_id = resolve_port_environment_id(
        &environment_client,
        &org_id,
        &paths.mesh_data_dir,
        environment,
    )
    .await?;

    handle_config_ssh_command(ConfigSshArgs {
        ssh_config_file: None,
        dry_run: false,
        ssh_options: Vec::new(),
    })
    .context("update ssh config")?;

    let uri = vscode_remote_uri(&environment_id, &args.folder);
    println!("Opening VS Code for environment {environment_id}...");
    open_browser(&uri)
}

pub(crate) async fn handle_shell_stdio(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<()> {
    if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
        init_tailnet_debug_log();
    }
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = codewire_client(&platform)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list organizations")?;
    let org_id = resolve_org_id(&platform, &orgs, None)?;
    let target = environment.and_then(vscode_environment_ref);
    let environment_id =
        resolve_port_environment_id(&environment_client, &org_id, &paths.mesh_data_dir, target)
            .await?;
    let mode = tailnet_ssh::SshTransportMode::from_env()?;
    tailnet_ssh::pipe_shell_stdio(&client, &org_id, &environment_id, mode).await
}

/// `CW_DEBUG_TAILNET` timeline on stderr: tailnet and client debug events,
/// timestamped from process start. `RUST_LOG` narrows or widens it.
fn init_tailnet_debug_log() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("codewire_tailnet=debug,codewire_client=debug"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_env_filter(filter)
        .try_init();
}

pub(crate) fn vscode_environment_ref(value: &str) -> Option<&str> {
    let value = trimmed_str(value)?;
    Some(value.strip_prefix("cw-").unwrap_or(value))
}

pub(crate) fn vscode_remote_uri(environment_id: &str, folder: &str) -> String {
    format!("vscode://vscode-remote/ssh-remote+cw-{environment_id}/{folder}")
}

pub(crate) fn init_request_from_args(args: &InitArgs) -> anyhow::Result<CreateEnvironmentRequest> {
    if args.preset_slug.as_deref().and_then(trimmed_str).is_some()
        || args.preset_id.as_deref().and_then(trimmed_str).is_some()
    {
        anyhow::bail!("cw init --preset and --preset-id require platform resolution");
    }
    if !args.repo_urls.is_empty()
        || !args.repo_flags.is_empty()
        || args.branch.as_deref().and_then(trimmed_str).is_some()
    {
        anyhow::bail!("cw init repo inputs require platform resolution");
    }
    env_create_request_from_init_args(args)
}

pub(crate) fn init_prepare_request_from_args(
    args: &InitArgs,
) -> anyhow::Result<PrepareEnvironmentRequest> {
    init_prepare_request_from_args_with_repo_detector(args, || detect_local_repo(Path::new(".")))
}

pub(crate) fn init_prepare_request_from_args_with_repo_detector(
    args: &InitArgs,
    detect_repo: impl FnOnce() -> anyhow::Result<(String, String)>,
) -> anyhow::Result<PrepareEnvironmentRequest> {
    let mut draft = env_create_request_from_init_args(args)?;
    if draft.project_spec.repositories.is_empty()
        && draft.preset_id.is_none()
        && draft.project_spec.preset.is_empty()
        && draft.project_spec.image.is_empty()
    {
        let (repo_url, detected_branch) =
            detect_repo().context("provide a repo URL, --image, or --preset")?;
        if repo_url.trim().is_empty() {
            anyhow::bail!("provide a repo URL, --image, or --preset");
        }
        let destination =
            codewire_project::validate_repository_destinations([(repo_url.as_str(), "")])?
                .into_iter()
                .next()
                .expect("one repository produces one destination");
        draft.project_spec.working_directory = destination.clone();
        let branch = args
            .branch
            .as_deref()
            .and_then(trimmed_str)
            .unwrap_or(&detected_branch)
            .to_string();
        draft
            .project_spec
            .repositories
            .push(codewire_project::RepositorySpec {
                source: repo_url,
                branch,
                destination,
                ..Default::default()
            });
        draft.project_spec.validate()?;
    }
    Ok(PrepareEnvironmentRequest { draft })
}

pub(crate) fn init_needs_platform_resolution(args: &InitArgs) -> bool {
    args.preset_slug.as_deref().and_then(trimmed_str).is_some()
        || args.preset_id.as_deref().and_then(trimmed_str).is_some()
        || !args.repo_urls.is_empty()
        || !args.repo_flags.is_empty()
        || args.branch.as_deref().and_then(trimmed_str).is_some()
        || !init_has_direct_yaml_inputs(args)
}

pub(crate) fn init_has_direct_yaml_inputs(args: &InitArgs) -> bool {
    args.cpu.is_some()
        || args.memory.is_some()
        || args.disk.is_some()
        || args.image.as_deref().and_then(trimmed_str).is_some()
        || args.install.as_deref().and_then(trimmed_str).is_some()
        || args.startup.as_deref().and_then(trimmed_str).is_some()
        || args.coding_agent.as_deref().and_then(trimmed_str).is_some()
        || !args.env.is_empty()
}

pub(crate) fn env_create_request_from_init_args(
    args: &InitArgs,
) -> anyhow::Result<CreateEnvironmentRequest> {
    if args.branch.as_deref().and_then(trimmed_str).is_some()
        && args.repo_urls.is_empty()
        && args.repo_flags.is_empty()
        && (args.preset_slug.as_deref().and_then(trimmed_str).is_some()
            || args.preset_id.as_deref().and_then(trimmed_str).is_some()
            || init_has_direct_yaml_inputs(args))
    {
        anyhow::bail!("--branch requires a repo URL");
    }
    let env_args = EnvCreateArgs {
        environment_type: EnvironmentTypeArg::Sandbox,
        repo_urls: args.repo_urls.clone(),
        preset_slug: args.preset_slug.clone(),
        preset_id: args.preset_id.clone(),
        name: args.name.clone(),
        backend: None,
        path: None,
        path_mode: None,
        file: None,
        spec: None,
        ttl: args.ttl.clone(),
        cpu: args.cpu.map(|value| value.to_string()),
        memory: args.memory.map(|value| value.to_string()),
        disk: args.disk.map(|value| value.to_string()),
        docker_disk: None,
        no_docker: false,
        isolation: args.isolation.clone(),
        repo_flags: args.repo_flags.clone(),
        branch: args.branch.clone(),
        image: args.image.clone(),
        install: args.install.clone(),
        startup: args.startup.clone(),
        coding_agent: args.coding_agent.clone(),
        env: args.env.clone(),
        profile: None,
        secrets: None,
        user_secrets: None,
        org_secrets: false,
        network: None,
        no_network: false,
        follow: true,
        no_wait: false,
        yes: args.yes,
        output: OutputFormat::Text,
        write_preset: false,
        save_preset: None,
    };
    env_create_request_from_args(&env_args)
}

pub(crate) fn detect_local_repo(dir: &Path) -> anyhow::Result<(String, String)> {
    let remote = ProcessCommand::new("git")
        .arg("-C")
        .arg(dir)
        .arg("remote")
        .arg("get-url")
        .arg("origin")
        .output()
        .context("detect git origin")?;
    if !remote.status.success() {
        anyhow::bail!("not a git repository or no origin remote");
    }
    let repo_url = normalize_git_url(String::from_utf8(remote.stdout)?.trim());
    // Reject ambient URL credentials at the discovery boundary. In
    // particular, never return the untrusted remote to a caller that might
    // display or log it before canonical request validation.
    codewire_project::validate_repository_destinations([(repo_url.as_str(), "")])?;
    let branch = ProcessCommand::new("git")
        .arg("-C")
        .arg(dir)
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|branch| {
            let branch = branch.trim();
            (!branch.is_empty() && branch != "HEAD").then(|| branch.to_string())
        })
        .unwrap_or_default();
    Ok((repo_url, branch))
}

pub(crate) fn normalize_git_url(raw_url: &str) -> String {
    let mut url = raw_url.trim().trim_end_matches(".git").to_string();
    if let Some(rest) = url.strip_prefix("git@") {
        return format!("https://{}", rest.replacen(':', "/", 1));
    }
    if let Some(rest) = url.strip_prefix("ssh://") {
        url = rest.trim_start_matches("git@").to_string();
        return format!("https://{url}");
    }
    url
}
