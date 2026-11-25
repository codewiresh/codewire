use std::path::Path;

use crate::commands::progress::terminal_text;

use super::*;

pub(crate) mod refusal;

pub(crate) async fn handle_logout_command(globals: &Globals) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env).ok();
    let outcome = log_out(
        &paths.platform_config_dir,
        platform
            .as_ref()
            .map(|platform| platform.server_url.as_str()),
        platform
            .as_ref()
            .and_then(config::ResolvedPlatformConfig::deployment_ca),
    )
    .await?;
    if config::Env::var(&env, config::CODEWIRE_API_KEY_ENV)
        .is_some_and(|key| !key.trim().is_empty())
    {
        eprintln!(
            "CODEWIRE_API_KEY is set: cw logout does not end API keys. Delete the key with `cw api-keys delete KEY_ID`."
        );
    }
    logout_result(outcome)
}

/// What `cw logout` could confirm about the sign-in saved on this machine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LogoutOutcome {
    /// No sign-in was saved. `cleared_settings` is whether a saved server,
    /// organization, account or pinned CA existed and was removed.
    NoSignIn { cleared_settings: bool },
    /// The server revoked the sign-in's refresh and access tokens.
    Revoked,
    /// The sign-in was removed from this machine, but the server did not
    /// confirm it ended (#4016).
    NotConfirmed {
        reason: String,
        access_token_expires_at_unix: Option<u64>,
    },
}

/// Revoke the saved sign-in, then remove it and the saved configuration
/// whatever the server answered: a sign-out that cannot reach the server
/// still leaves nothing usable on this machine.
pub(crate) async fn log_out(
    config_dir: &Path,
    server_url: Option<&str>,
    deployment_ca: Option<&codewire_client::DeploymentCa>,
) -> anyhow::Result<LogoutOutcome> {
    let store =
        codewire_client::FileCredentialStore::at(config::oauth_credentials_path(config_dir));
    let saved_settings = [
        "config.json",
        config::ACCOUNT_FILE,
        config::DEPLOYMENT_CA_FILE,
    ]
    .iter()
    .any(|file| config_dir.join(file).exists());
    let outcome = match codewire_client::CredentialStore::load(&store) {
        Ok(None) => LogoutOutcome::NoSignIn {
            cleared_settings: saved_settings,
        },
        Ok(Some(credentials)) => {
            match revoke_saved_sign_in(&credentials, server_url, deployment_ca).await {
                Ok(()) => LogoutOutcome::Revoked,
                Err(reason) => LogoutOutcome::NotConfirmed {
                    reason,
                    access_token_expires_at_unix: Some(credentials.expires_at_unix()),
                },
            }
        }
        Err(_) => LogoutOutcome::NotConfirmed {
            reason: "the saved sign-in could not be read".to_owned(),
            access_token_expires_at_unix: None,
        },
    };
    crate::completion::forget_cached_names(config_dir);
    codewire_client::CredentialStore::delete(&store).context("remove the saved sign-in")?;
    config::delete_platform_config(config_dir).context("remove the saved configuration")?;
    config::delete_deployment_ca(config_dir).context("remove the pinned CA")?;
    config::delete_account(config_dir).context("remove the saved account")?;
    Ok(outcome)
}

async fn revoke_saved_sign_in(
    credentials: &codewire_client::OAuthCredentials,
    server_url: Option<&str>,
    deployment_ca: Option<&codewire_client::DeploymentCa>,
) -> Result<(), String> {
    let server_url = server_url.ok_or("no Codewire server is configured")?;
    let client = config::ResolvedPlatformConfig::static_token(server_url, "", false, None)
        .with_deployment_ca(deployment_ca.cloned())
        .oauth_client()
        .map_err(|error| format!("the server address is invalid ({error})"))?;
    client
        .revoke_credentials(credentials)
        .await
        .map_err(|error| match error {
            codewire_client::AuthClientError::Request(error)
                if error.is_connect() || error.is_timeout() =>
            {
                "the server could not be reached".to_owned()
            }
            error => error.to_string(),
        })
}

pub(super) fn not_signed_in_text(cleared_settings: bool, style: crate::output::Style) -> String {
    let what = if cleared_settings {
        "removed the saved settings"
    } else {
        "there is nothing to remove"
    };
    format!(
        "Not signed in; {what}.\n{} cw login\n",
        style.status(crate::output::Status::Next)
    )
}

/// "Logged out" only when the server confirmed it; otherwise an error, so
/// the command exits non-zero and scripts notice.
pub(crate) fn logout_result(outcome: LogoutOutcome) -> anyhow::Result<()> {
    match outcome {
        LogoutOutcome::NoSignIn { cleared_settings } => {
            let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
                .stderr_style();
            eprint!("{}", not_signed_in_text(cleared_settings, style));
            Ok(())
        }
        LogoutOutcome::Revoked => {
            eprintln!("Logged out; the server ended this sign-in.");
            Ok(())
        }
        LogoutOutcome::NotConfirmed {
            reason,
            access_token_expires_at_unix,
        } => {
            let until = access_token_expires_at_unix
                .and_then(|seconds| i64::try_from(seconds).ok())
                .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
                .map(|expiry| format!(" until {}", expiry.format("%Y-%m-%d %H:%M UTC")))
                .unwrap_or_default();
            anyhow::bail!(
                "Removed the sign-in from this machine, but the server did not confirm it ended: {reason}. \
                 Its access token stays valid{until}, and its refresh token until it expires on the server."
            )
        }
    }
}

pub(crate) async fn handle_whoami_command(
    globals: &Globals,
    args: WhoamiArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let user =
        current_platform_user(&codewire_client(&platform)?, &platform.oauth_client()?).await?;
    print_platform_user(&user, &platform, args.output)
}

pub(crate) async fn handle_init_command(
    globals: &Globals,
    mut args: InitArgs,
) -> anyhow::Result<()> {
    if !args.force
        && args
            .file
            .try_exists()
            .with_context(|| format!("stat {}", args.file.display()))?
    {
        anyhow::bail!(
            "the file {} already exists (use --force to overwrite)",
            args.file.display()
        );
    }

    let guided = super::launch_setup::prepare_init(globals, &mut args)
        .await
        .context("codewire.yaml was not written")?;
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

    if guided {
        eprintln!(
            "{}",
            super::launch_setup::configuration_summary("Write codewire.yaml", &request)
        );
        eprintln!(
            "  File          {}",
            terminal_text(&args.file.display().to_string())
        );
        if !super::guided::confirm("Write this configuration?")? {
            anyhow::bail!("canceled; no configuration written");
        }
    }
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
    eprintln!("  cw create --local --name <environment>");
    eprintln!("  cw shell <environment>");
    eprintln!("  cw create");
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
    let environment =
        super::flat::select_environment("vscode", args.environment, args.in_environment, &[])?;
    let alias = environment.as_deref().and_then(SshAlias::parse);
    if let Some(alias) = alias {
        alias.check_placement(globals.placement)?;
    }
    let local = alias.map_or(
        globals.placement == Some(EnvironmentPlacement::Local),
        |alias| alias.is_local(globals.placement),
    );
    // The editor connects through the placement-qualified alias, by ID.
    let (host, shown) = if local {
        let environment = match alias {
            Some(alias) => local_ssh_target(alias).await?,
            None => super::native::native_ssh_target(None).await?,
        };
        // Refused here, not as an opaque Remote-SSH failure in the editor.
        super::native::ensure_native_running(&environment)?;
        super::native::ensure_native_ssh().await?;
        (
            format!("{LOCAL_ALIAS_PREFIX}{}", environment.id),
            environment.name,
        )
    } else {
        let env = OsEnv;
        let paths = ResolvePaths::from_env(&env)?;
        let platform = resolve_platform(globals, &paths, &env)?;
        let environment_client = EnvironmentClient::new(&platform)?;
        let orgs = organization_client(&platform)?
            .list_orgs()
            .await
            .context("list orgs")?;
        let org_id = resolve_org_id(&platform, &orgs, args.org.as_deref())?;
        let environment_id =
            resolve_alias_or_selected(&environment_client, &org_id, &paths.mesh_data_dir, alias)
                .await?;
        let shown = alias.map_or_else(
            || environment_id.clone(),
            |alias| alias.environment_ref.to_owned(),
        );
        // Refused here, not as an opaque Remote-SSH failure in the editor.
        let environment = environment_client
            .get_environment(&org_id, &environment_id)
            .await
            .context("look up the environment")?;
        ensure_cloud_connectable(&environment, &shown)?;
        (format!("{CLOUD_ALIAS_PREFIX}{environment_id}"), shown)
    };

    // Keeps the managed SSH section current, silently: the link below
    // connects through it.
    install_default_managed_ssh_config().context("update ssh config")?;

    let uri = vscode_remote_uri(&host, &args.folder);
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprintln!(
        "{} Opening VS Code for {}{}",
        style.status(crate::output::Status::Next),
        terminal_text(&shown),
        style.paint(
            crate::output::Role::Dim,
            &format!("{}{}", style.separator(), terminal_text(&args.folder))
        )
    );
    open_browser(&uri)
}

pub(crate) async fn handle_shell_stdio(
    globals: &Globals,
    environment: Option<&str>,
) -> anyhow::Result<()> {
    let alias = environment.and_then(SshAlias::parse);
    if let Some(alias) = alias {
        alias.check_placement(globals.placement)?;
    }
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
    let environment_id =
        resolve_alias_or_selected(&environment_client, &org_id, &paths.mesh_data_dir, alias)
            .await?;
    let mode = tailnet_ssh::SshTransportMode::from_env()?;
    let pipe = tailnet_ssh::pipe_shell_stdio(&client, &org_id, &environment_id, mode);
    let piped = until_ssh_hangs_up(pipe).await.unwrap_or(Ok(()));
    // When a stop ended the connection, such as the Sandbox stopping itself
    // for being idle, say why, as `cw shell` does: ssh shows only the broken
    // stream the environment's SSH server reports, then ends the connection
    // itself, so the end looks the same here whoever made it. Asked once
    // per connection, within a bound; ssh doesn't wait for this process.
    let looked_up = tokio::time::timeout(
        STOP_LOOKUP_LIMIT,
        environment_client.get_environment(&org_id, &environment_id),
    )
    .await;
    let shown = alias.map_or(environment_id.as_str(), |alias| alias.environment_ref);
    if let Ok(Ok(environment)) = looked_up
        && let Some(stopped) = ended_by_stop(&environment, shown)
    {
        return Err(stopped);
    }
    if let Some(lost) = lost_connection(codewire_client::stdio_silent_for(), shown) {
        return Err(lost);
    }
    piped
}

/// The server silence after which `cw shell --stdio` calls its connection
/// lost (#6101): the workspace SSH server's own wait before it drops a client
/// that doesn't answer. While the connection is up, the server sends a
/// keepalive whenever it has heard nothing for one interval, and a clean end
/// ends with the server's closing packets, so neither is ever this silent.
pub(crate) const LOST_AFTER: std::time::Duration = std::time::Duration::from_secs(45);

/// When the connection ended after [`LOST_AFTER`] with nothing from the
/// server, a lost connection, which ended the SSH session and its processes
/// with it (`docs/dev/DERP-STUN.md`; `editor-reconnect`), and what keeps work
/// running through one. `None` for any other end, or a connection that never
/// heard from the server.
pub(crate) fn lost_connection(
    silent_for: Option<std::time::Duration>,
    shown: &str,
) -> Option<anyhow::Error> {
    if silent_for? < LOST_AFTER {
        return None;
    }
    Some(crate::error_report::with_next_step(
        anyhow::anyhow!(
            "lost the connection to {shown}: SSH sessions end after about a minute offline, \
             and their processes stop"
        ),
        format!(
            "for work that must keep running, use cw shell --durable {shown} or cw run --detach"
        ),
    ))
}

/// How long `cw shell --stdio` asks why its connection ended.
const STOP_LOOKUP_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// `pipe`'s result, or `None` when ssh hangs up first: OpenSSH sends its
/// ProxyCommand SIGHUP as it exits. Holding SIGHUP from here on keeps this
/// process alive to say why the connection ended.
async fn until_ssh_hangs_up<T>(pipe: impl std::future::Future<Output = T>) -> Option<T> {
    #[cfg(unix)]
    if let Ok(mut hangup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        return tokio::select! {
            piped = pipe => Some(piped),
            _ = hangup.recv() => None,
        };
    }
    Some(pipe.await)
}

/// Why an ssh connection to a cloud environment ended, when a stop ended
/// it: the stop is under way (`desired_state` stopped) or done. In
/// [`refusal::state_error`]'s words for a stopped environment, the idle
/// timeout included, so it reads as plain `cw shell` says it. `None` while
/// the environment is meant to run.
pub(crate) fn ended_by_stop(environment: &Environment, shown: &str) -> Option<anyhow::Error> {
    let stopping = environment.desired_state == "stopped"
        || matches!(environment.state.as_str(), "stopping" | "stopped");
    if !stopping {
        return None;
    }
    let idle_stop = (environment.stop_reason.as_deref() == Some("idle"))
        .then_some(environment.idle_stop_seconds);
    refusal::state_error(
        platform_address(environment),
        &terminal_text(shown),
        Some(codewire_client::EnvironmentState::Stopped),
        idle_stop,
    )
}

/// `error`, or, when the server refused it because the cloud environment
/// isn't running, what state it is in and what to do (#4689). The state is
/// asked only then, so a command that works makes no extra call.
pub(crate) async fn explain_not_running(
    globals: &Globals,
    environment: Option<&str>,
    error: anyhow::Error,
) -> anyhow::Error {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if refusal::is_local_refusal(&error) {
        return explain_local_not_running(environment, error).await;
    }
    if !refusal::is_refusal(&error) {
        return error;
    }
    let found = async {
        let env = OsEnv;
        let paths = ResolvePaths::from_env(&env)?;
        let platform = resolve_platform(globals, &paths, &env)?;
        let orgs = organization_client(&platform)?.list_orgs().await?;
        let org_id = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
        let alias = environment.and_then(SshAlias::parse);
        let environment_id = resolve_alias_or_selected(
            &EnvironmentClient::new(&platform)?,
            &org_id,
            &paths.mesh_data_dir,
            alias,
        )
        .await?;
        anyhow::Ok((codewire_client(&platform)?, org_id, environment_id))
    }
    .await;
    match found {
        Ok((client, org_id, environment_id)) => {
            explain_by_state(&client, &org_id, &environment_id, environment, error).await
        }
        Err(_) => match environment {
            Some(name) => refusal::explain(error, name, None),
            None => error,
        },
    }
}

/// A local VM's refusal of a session explained by its state, read once:
/// `environment` as given, else the selected one.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn explain_local_not_running(
    environment: Option<&str>,
    error: anyhow::Error,
) -> anyhow::Error {
    let name = match environment {
        Some(name) => name.to_owned(),
        None => match ResolvePaths::from_env(&OsEnv)
            .ok()
            .and_then(|paths| config::current_target(&paths.mesh_data_dir).ok())
        {
            Some(target) if !target.name.is_empty() => target.name,
            _ => return error,
        },
    };
    let state = native_environment(&name)
        .await
        .ok()
        .flatten()
        .and_then(|environment| refusal::local_state(environment.state));
    refusal::explain_local(error, &terminal_text(&name), state)
}

/// `error` from reaching a cloud environment, or, when the environment is
/// not running, what its state means and what to do, in the one wording
/// [`refusal::state_error`] gives. A running environment, or one whose
/// state can't be read, keeps `error`, unless the server had refused it as
/// not running. `given` is the name the user typed, else the environment's.
pub(crate) async fn explain_by_state(
    client: &codewire_client::CodewireClient,
    org_id: &str,
    environment_id: &str,
    given: Option<&str>,
    error: anyhow::Error,
) -> anyhow::Error {
    let answer =
        codewire_client::hosted_shell::restart::ask_environment(client, org_id, environment_id)
            .await;
    let found = answer.as_ref().ok().map(|(environment, _)| {
        (
            given.unwrap_or(&environment.name),
            environment.state.as_known(),
            (environment.stop_reason == "idle").then_some(environment.idle_stop_seconds),
            environment.host.as_option().map(|host| host.name.as_str()),
        )
    });
    refusal::explain(error, given.unwrap_or(environment_id), found)
}

/// How a next step names `environment`: on its host with no placement flag.
fn platform_address(environment: &Environment) -> crate::commands::lifecycle_output::Address {
    crate::commands::lifecycle_output::Address::platform(
        environment.host.as_ref().map(|host| host.name.as_str()),
    )
}

/// Refuses a cloud environment that is stopped, naming the command that
/// starts it. Any other state is left to the connection.
pub(crate) fn ensure_cloud_connectable(
    environment: &Environment,
    shown: &str,
) -> anyhow::Result<()> {
    let state = match environment.state.as_str() {
        "stopped" => codewire_client::EnvironmentState::Stopped,
        "stopping" => codewire_client::EnvironmentState::Stopping,
        _ => return Ok(()),
    };
    let idle_stop = (environment.stop_reason.as_deref() == Some("idle"))
        .then_some(environment.idle_stop_seconds);
    refusal::state_error(
        platform_address(environment),
        &terminal_text(shown),
        Some(state),
        idle_stop,
    )
    .map_or(Ok(()), Err)
}

/// `CW_DEBUG_TAILNET` timeline on stderr for `cw shell`: tailnet and client
/// debug events, timestamped from process start. `RUST_LOG` narrows or widens it.
pub(crate) fn init_tailnet_debug_log() {
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

/// The cloud environment an alias or reference names, or with none the
/// selected one.
async fn resolve_alias_or_selected(
    client: &EnvironmentClient,
    org_id: &str,
    data_dir: &Path,
    alias: Option<SshAlias<'_>>,
) -> anyhow::Result<String> {
    match alias {
        Some(alias) => resolve_cloud_alias(client, org_id, alias).await,
        None => resolve_port_environment_id(client, org_id, data_dir, None).await,
    }
}

/// The editor link for `host`, a placement-qualified alias. `cw vscode`
/// writes the managed SSH section first, so the alias is always configured.
pub(crate) fn vscode_remote_uri(host: &str, folder: &str) -> String {
    format!("vscode://vscode-remote/ssh-remote+{host}/{folder}")
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
    args.profile.is_some()
        || args.no_profile
        || args.secrets.is_some()
        || args.cpu.is_some()
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
    // Refused in `cw init`'s words; the create request below parses them.
    parse_env_settings(&args.env, "cw init")?;
    let env_args = EnvCreateArgs {
        guided: false,
        policy: None,
        environment_type: EnvironmentTypeArg::Sandbox,
        repo_urls: args.repo_urls.clone(),
        preset_slug: args.preset_slug.clone(),
        preset_id: args.preset_id.clone(),
        name: args.name.clone(),
        backend: None,
        path: None,
        path_mode: None,
        file: Vec::new(),
        no_file: false,
        no_local_file: false,
        spec: None,
        ttl: args.ttl.clone(),
        idle_stop: None,
        cpu: args.cpu.clone(),
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
        profile: args.profile.clone(),
        no_profile: args.no_profile,
        secrets: args.secrets.clone(),
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
        snapshot: None,
        checkpoint: None,
        start_with_uncleared_disk: false,
        count: 1,
        name_prefix: None,
        share_mounts: false,
        on: None,
    };
    env_create_request_from_args(&env_args)
}

pub(crate) fn detect_local_repo(dir: &Path) -> anyhow::Result<(String, String)> {
    let remote = crate::process::command("git", &[])
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
    let branch = crate::process::command("git", &[])
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
