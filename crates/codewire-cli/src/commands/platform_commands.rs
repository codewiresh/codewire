use std::path::Path;

use super::*;
use codewire_client::{ClientError, CodewireClient, DeleteApiKeyRequest, ListApiKeysRequest};

pub(crate) fn codewire_client(
    platform: &config::ResolvedPlatformConfig,
) -> anyhow::Result<CodewireClient> {
    crate::environment_client::connect_client(platform)
}

pub(crate) fn organization_client(
    platform: &config::ResolvedPlatformConfig,
) -> anyhow::Result<OrganizationClient> {
    OrganizationClient::new(platform)
}

pub(crate) fn display_client_error(error: ClientError) -> anyhow::Error {
    crate::environment_client::display_client_error(error)
}

pub(crate) async fn handle_cost_command(globals: &Globals, args: CostArgs) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = ConsoleClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let reports = collect_cost_reports(&client, &orgs, args.org.as_deref()).await;
    print_cost_reports(&reports, args.output)
}

pub(crate) async fn resolve_named_execution_target(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    target_ref: &str,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<config::CurrentTargetConfig> {
    let target_ref = trimmed_required(target_ref, "target")?;
    #[cfg(target_os = "linux")]
    let local = if placement != Some(EnvironmentPlacement::Platform) {
        native_environment(target_ref).await?
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let local: Option<()> = None;
    if placement == Some(EnvironmentPlacement::Local) {
        #[cfg(target_os = "linux")]
        if let Some(environment) = local.as_ref() {
            return Ok(config::CurrentTargetConfig {
                kind: "local".to_string(),
                target_ref: environment.name.clone(),
                name: environment.name.clone(),
            });
        }
        #[cfg(not(target_os = "linux"))]
        let _ = local;
        {
            anyhow::bail!("local environment {target_ref:?} not found");
        }
    }

    let platform = match resolve_platform(globals, paths, env) {
        Ok(platform) => platform,
        Err(error) if placement.is_none() => {
            #[cfg(target_os = "linux")]
            if let Some(environment) = local.as_ref() {
                return Ok(config::CurrentTargetConfig {
                    kind: "local".to_string(),
                    target_ref: environment.name.clone(),
                    name: environment.name.clone(),
                });
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let organization_client = organization_client(&platform)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let environments = environment_client
        .list_environments(&org_id, false)
        .await
        .context("list environments")?;
    let platform_match = find_environment_match(&environments, target_ref)?;

    if placement == Some(EnvironmentPlacement::Platform) {
        let Some((environment_id, _)) = platform_match else {
            anyhow::bail!("platform environment {target_ref:?} not found");
        };
        let environment = environment_client
            .get_environment(&org_id, &environment_id)
            .await
            .context("get environment")?;
        return Ok(current_target_from_environment(&environment));
    }

    #[cfg(target_os = "linux")]
    match (local, platform_match) {
        (_, Some((environment_id, EnvironmentMatchKind::ExactId))) => {
            let environment = environment_client
                .get_environment(&org_id, &environment_id)
                .await
                .context("get environment")?;
            Ok(current_target_from_environment(&environment))
        }
        (Some(environment), Some((_environment_id, EnvironmentMatchKind::ExactName)))
            if environment.name == target_ref =>
        {
            anyhow::bail!(
                "environment {target_ref:?} exists in both placements; use `cw use --local {target_ref}` or `cw use --platform {target_ref}`"
            )
        }
        (Some(environment), _) => Ok(config::CurrentTargetConfig {
            kind: "local".to_string(),
            target_ref: environment.name.clone(),
            name: environment.name,
        }),
        (None, Some((environment_id, _))) => {
            let environment = environment_client
                .get_environment(&org_id, &environment_id)
                .await
                .context("get environment")?;
            Ok(current_target_from_environment(&environment))
        }
        (None, None) => anyhow::bail!("environment {target_ref:?} not found"),
    }
    #[cfg(not(target_os = "linux"))]
    match platform_match {
        Some((environment_id, _)) => {
            let environment = environment_client
                .get_environment(&org_id, &environment_id)
                .await
                .context("get environment")?;
            Ok(current_target_from_environment(&environment))
        }
        None => anyhow::bail!("environment {target_ref:?} not found"),
    }
}

fn current_target_from_environment(environment: &Environment) -> config::CurrentTargetConfig {
    config::CurrentTargetConfig {
        kind: "env".to_string(),
        target_ref: environment.id.clone(),
        name: environment_display_name(environment).to_string(),
    }
}

pub(crate) async fn lookup_environment_for_target(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    target: &config::CurrentTargetConfig,
) -> Option<Environment> {
    if target.kind != "env" || target.target_ref.trim().is_empty() {
        return None;
    }
    let platform = resolve_platform(globals, paths, env).ok()?;
    let organization_client = organization_client(&platform).ok()?;
    let environment_client = EnvironmentClient::new(&platform).ok()?;
    let orgs = organization_client.list_orgs().await.ok()?;
    let org_id = current_org_id(&platform, &orgs).ok()?;
    environment_client
        .get_environment(&org_id, &target.target_ref)
        .await
        .ok()
}

pub(crate) async fn resolve_environment_id(
    client: &EnvironmentClient,
    org_id: &str,
    target_ref: &str,
) -> anyhow::Result<String> {
    let target_ref = trimmed_required(target_ref, "environment reference")?;
    if target_ref.len() >= 36
        && target_ref.contains('-')
        && client.get_environment(org_id, target_ref).await.is_ok()
    {
        return Ok(target_ref.to_string());
    }

    let environments = client
        .list_environments(org_id, false)
        .await
        .context("list environments")?;
    resolve_environment_id_from_list(&environments, target_ref)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvironmentMatchKind {
    ExactId,
    ExactName,
    IdPrefix,
}

pub(crate) fn find_environment_match(
    environments: &[Environment],
    target_ref: &str,
) -> anyhow::Result<Option<(String, EnvironmentMatchKind)>> {
    let target_ref = trimmed_required(target_ref, "environment reference")?;
    let mut exact_name_matches = Vec::new();
    let mut prefix_matches = Vec::new();

    for environment in environments {
        if environment.id == target_ref {
            return Ok(Some((
                environment.id.clone(),
                EnvironmentMatchKind::ExactId,
            )));
        }
        if environment
            .name
            .as_deref()
            .is_some_and(|name| name == target_ref)
        {
            exact_name_matches.push(environment);
        }
        if environment.id.starts_with(target_ref) {
            prefix_matches.push(environment);
        }
    }

    match exact_name_matches.as_slice() {
        [environment] => {
            return Ok(Some((
                environment.id.clone(),
                EnvironmentMatchKind::ExactName,
            )));
        }
        [] => {}
        matches => {
            let ids = matches
                .iter()
                .map(|environment| environment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("multiple environments named {target_ref:?}, use ID: {ids}");
        }
    }

    match prefix_matches.as_slice() {
        [environment] => Ok(Some((
            environment.id.clone(),
            EnvironmentMatchKind::IdPrefix,
        ))),
        [] => Ok(None),
        matches => {
            let ids = matches
                .iter()
                .map(|environment| environment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "environment {target_ref:?} matched multiple IDs, use a longer prefix or full ID: {ids}"
            );
        }
    }
}

pub(crate) fn resolve_environment_id_from_list(
    environments: &[Environment],
    target_ref: &str,
) -> anyhow::Result<String> {
    let target_ref = trimmed_required(target_ref, "environment reference")?;
    find_environment_match(environments, target_ref)?
        .map(|(id, _)| id)
        .ok_or_else(|| anyhow::anyhow!("environment {target_ref:?} not found"))
}

pub(crate) fn format_current_target_text(
    target: &config::CurrentTargetConfig,
    environment: Option<&Environment>,
    network: Option<&str>,
    verbose: bool,
) -> String {
    let network = network.and_then(trimmed_str);
    if !verbose {
        let mut summary = target_summary_line(target, environment);
        if let Some(network) = network {
            summary.push_str("  network: ");
            summary.push_str(network);
        }
        summary.push('\n');
        return summary;
    }

    let mut output = String::new();
    output.push_str(&format!("{:<10} {}\n", "Kind:", target.kind));
    if let Some(network) = network {
        output.push_str(&format!("{:<10} {}\n", "Network:", network));
    }
    match target.kind.as_str() {
        "local" if target.target_ref == "local" => {
            output.push_str(&format!("{:<10} {}\n", "Target:", "local"));
        }
        "local" => {
            output.push_str(&format!(
                "{:<10} {}\n",
                "Target:",
                target_display_name(target, None)
            ));
        }
        "env" => {
            output.push_str(&format!(
                "{:<10} {}\n",
                "Target:",
                target_display_name(target, environment)
            ));
            output.push_str(&format!("{:<10} {}\n", "ID:", target.target_ref));
            output.push_str(&format!(
                "{:<10} {}\n",
                "ShortID:",
                short_env_id(&target.target_ref)
            ));
            if let Some(environment) = environment {
                if let Some(name) = environment.name.as_deref().and_then(trimmed_str) {
                    output.push_str(&format!("{:<10} {}\n", "Name:", name));
                }
                if let Some(state) = trimmed_str(&environment.state) {
                    output.push_str(&format!("{:<10} {}\n", "State:", state));
                }
                if let Some(joined) = environment.network.as_deref().and_then(trimmed_str)
                    && Some(joined) != network
                {
                    output.push_str(&format!("{:<10} {}\n", "Joined:", joined));
                }
            }
        }
        _ => {
            output.push_str(&format!(
                "{:<10} {}\n",
                "Target:",
                target_display_name(target, environment)
            ));
        }
    }
    output
}

pub(crate) fn target_summary_line(
    target: &config::CurrentTargetConfig,
    environment: Option<&Environment>,
) -> String {
    if target.kind == "local" && target.target_ref == "local" {
        return "local".to_string();
    }
    if target.kind == "local" {
        return target_display_name(target, None).to_string();
    }
    if target.kind == "env" {
        let mut summary = format!(
            "{} [{}]",
            target_display_name(target, environment),
            short_env_id(&target.target_ref)
        );
        if let Some(environment) = environment
            && let Some(state) = trimmed_str(&environment.state)
        {
            summary.push(' ');
            summary.push_str(state);
        }
        return summary;
    }
    target_display_name(target, environment).to_string()
}

pub(crate) fn target_display_name<'a>(
    target: &'a config::CurrentTargetConfig,
    environment: Option<&'a Environment>,
) -> &'a str {
    if target.kind == "local" {
        return trimmed_str(&target.name)
            .or_else(|| trimmed_str(&target.target_ref))
            .unwrap_or("local");
    }
    environment
        .map(environment_display_name)
        .or_else(|| trimmed_str(&target.name))
        .or_else(|| trimmed_str(&target.target_ref))
        .unwrap_or("local")
}

pub(crate) fn environment_display_name(environment: &Environment) -> &str {
    environment
        .name
        .as_deref()
        .and_then(trimmed_str)
        .unwrap_or(&environment.id)
}

pub(crate) fn short_env_id(id: &str) -> &str {
    if let Some((prefix, _)) = id.split_once('-')
        && !prefix.is_empty()
    {
        return prefix;
    }
    id.get(..8).unwrap_or(id)
}

pub(crate) async fn handle_login_command(globals: &Globals, args: LoginArgs) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let server_url = resolve_login_server_url(globals, &paths, &env)?;
    let configured_org = saved_login_default_org(&paths, &server_url);
    let client = OAuthClient::discover(&server_url)
        .await
        .context("discover OAuth device flow")?;

    let (credentials, user) = login_with_device(&client).await?;
    let bearer = credentials
        .bearer_token()
        .context("validate OAuth access token")?;
    let login_platform = config::ResolvedPlatformConfig::static_token(
        server_url.clone(),
        bearer.expose_secret(),
        false,
        None,
    );
    let orgs = organization_client(&login_platform)?
        .list_orgs()
        .await
        .context("list organizations after login")?;
    let org_resolution = resolve_login_org(&orgs, configured_org.as_deref(), args.org.as_deref())?;
    let org_resolution = match org_resolution {
        LoginOrgResolution::SelectionRequired if stdin_is_interactive() => {
            LoginOrgResolution::Selected(prompt_select_org(&orgs)?.clone())
        }
        resolution => resolution,
    };
    let default_org = match &org_resolution {
        LoginOrgResolution::Selected(org) => Some(org.id.as_str()),
        LoginOrgResolution::NoOrganizations | LoginOrgResolution::SelectionRequired => None,
    };

    save_login_platform_config(&paths, &server_url, &credentials, default_org)?;
    eprintln!("Logged in as {}.", oauth_user_display_name(&user));
    match org_resolution {
        LoginOrgResolution::Selected(org) => {
            eprintln!("Default org: {} ({}).", org.name, org.slug);
            Ok(())
        }
        LoginOrgResolution::NoOrganizations => {
            anyhow::bail!(
                "logged in, but no organizations found; run 'cw org create <name>' or join an organization"
            )
        }
        LoginOrgResolution::SelectionRequired => {
            anyhow::bail!(
                "logged in, but no default organization is selected; run 'cw org set <id-or-slug>' or rerun 'cw login --org <id-or-slug>'"
            )
        }
    }
}

pub(crate) async fn handle_setup_command(globals: &Globals, args: SetupArgs) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let server_url = resolve_setup_server_url(globals, &paths, &env);
    let login_client = OAuthClient::discover(&server_url)
        .await
        .context("discover OAuth device flow")?;

    eprintln!("Welcome to Codewire.");
    eprintln!("Server: {server_url}");

    let (credentials, user) = login_with_device(&login_client).await?;
    eprintln!("Logged in as {}.", oauth_user_display_name(&user));

    save_login_platform_config(&paths, &server_url, &credentials, None)?;

    let authed_platform = config::ResolvedPlatformConfig::oauth_credentials(
        server_url.clone(),
        config::oauth_credentials_path(&paths.platform_config_dir),
        None,
    );
    let organization_client = organization_client(&authed_platform)?;
    let selected_org = setup_select_org(&organization_client, &args).await?;

    config::save_platform_config(
        &paths.platform_config_dir,
        &config::PlatformConfig {
            server_url: server_url.clone(),
            default_org: selected_org
                .as_ref()
                .map(|org| org.id.clone())
                .unwrap_or_default(),
        },
    )
    .context("save config")?;
    refresh_hosted_mesh_owner_context(
        &paths,
        &server_url,
        selected_org.as_ref().map(|org| org.id.as_str()),
    )?;

    if let Some(org) = &selected_org {
        eprintln!("Default org: {} ({}).", org.name, org.slug);
    } else {
        eprintln!("No default org selected.");
    }

    if !args.skip_ssh {
        if let Err(err) = handle_config_ssh_command(ConfigSshArgs {
            ssh_config_file: None,
            ssh_options: Vec::new(),
            dry_run: false,
        }) {
            eprintln!("Warning: SSH config update failed: {err}");
            eprintln!("You can retry later with: cw config-ssh");
        } else {
            eprintln!("Updated OpenSSH config.");
        }
    }

    eprintln!("Setup complete.");
    Ok(())
}

pub(crate) fn resolve_setup_server_url(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> String {
    resolve_login_server_url(globals, paths, env)
        .unwrap_or_else(|_| "https://codewire.sh".to_string())
}

pub(crate) async fn setup_select_org(
    client: &OrganizationClient,
    args: &SetupArgs,
) -> anyhow::Result<Option<OrgWithRole>> {
    if args.org.as_deref().and_then(trimmed_str).is_some() && args.create_org.is_some() {
        anyhow::bail!("--org and --create-org are mutually exclusive");
    }

    if let Some(name) = args.create_org.as_deref().and_then(trimmed_str) {
        let slug = args
            .org_slug
            .as_deref()
            .and_then(trimmed_str)
            .map(str::to_string)
            .unwrap_or_else(|| slugify(name));
        let org = client
            .create_org(&CreateOrgRequest {
                name: name.to_string(),
                slug,
            })
            .await
            .context("create org")?;
        return Ok(Some(OrgWithRole {
            id: org.id,
            name: org.name,
            slug: org.slug,
            role: "owner".to_string(),
            ..OrgWithRole::default()
        }));
    }

    let orgs = client.list_orgs().await.context("list orgs")?;
    if let Some(org_ref) = args.org.as_deref().and_then(trimmed_str) {
        return Ok(Some(select_org(&orgs, Some(org_ref))?.clone()));
    }

    match orgs.as_slice() {
        [] if stdin_is_interactive() => {
            if !prompt_confirm_default_yes("No organizations found. Create one?")? {
                return Ok(None);
            }
            let name = trimmed_required(&prompt_text("Organization name: ")?, "organization name")?
                .to_string();
            let default_slug = slugify(&name);
            let slug = prompt_default("Organization slug", &default_slug)?;
            let org = client
                .create_org(&CreateOrgRequest { name, slug })
                .await
                .context("create org")?;
            Ok(Some(OrgWithRole {
                id: org.id,
                name: org.name,
                slug: org.slug,
                role: "owner".to_string(),
                ..OrgWithRole::default()
            }))
        }
        [] => anyhow::bail!("no organizations found; pass --create-org <name>"),
        [org] => Ok(Some(org.clone())),
        _ if stdin_is_interactive() => Ok(Some(prompt_select_org(&orgs)?.clone())),
        _ => anyhow::bail!("multiple organizations found; pass --org <id-or-slug>"),
    }
}

pub(crate) fn resolve_login_server_url(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<String> {
    if let Some(server_url) = normalize_login_server_url(globals.server.as_deref()) {
        return Ok(server_url);
    }
    if let Some(server_url) =
        normalize_login_server_url(env.var(config::CODEWIRE_SERVER_URL_ENV).as_deref())
    {
        return Ok(server_url);
    }
    if let Ok(config) = config::load_platform_config(&paths.platform_config_dir)
        && let Some(server_url) = normalize_login_server_url(Some(&config.server_url))
    {
        return Ok(server_url);
    }
    anyhow::bail!("no server configured (run 'cw setup' first, or pass --server)")
}

pub(crate) fn normalize_login_server_url(value: Option<&str>) -> Option<String> {
    let value = value?.trim().trim_end_matches('/').to_string();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn saved_login_default_org(paths: &ResolvePaths, server_url: &str) -> Option<String> {
    config::load_platform_config(&paths.platform_config_dir)
        .ok()
        .filter(|saved| config::same_server_url(&saved.server_url, server_url))
        .and_then(|saved| {
            let default_org = saved.default_org.trim().to_string();
            (!default_org.is_empty()).then_some(default_org)
        })
}

#[derive(Clone, Debug)]
pub(crate) enum LoginOrgResolution {
    Selected(OrgWithRole),
    NoOrganizations,
    SelectionRequired,
}

pub(crate) fn resolve_login_org(
    orgs: &[OrgWithRole],
    configured_org: Option<&str>,
    requested_org: Option<&str>,
) -> anyhow::Result<LoginOrgResolution> {
    if let Some(requested_org) = requested_org.and_then(trimmed_str) {
        return Ok(LoginOrgResolution::Selected(
            select_org(orgs, Some(requested_org))?.clone(),
        ));
    }
    if let Some(configured_org) = configured_org.and_then(trimmed_str)
        && let Some(org) = orgs
            .iter()
            .find(|org| org.id == configured_org || org.slug == configured_org)
    {
        return Ok(LoginOrgResolution::Selected(org.clone()));
    }
    Ok(match orgs {
        [] => LoginOrgResolution::NoOrganizations,
        [org] => LoginOrgResolution::Selected(org.clone()),
        _ => LoginOrgResolution::SelectionRequired,
    })
}

pub(crate) async fn login_with_device(
    client: &OAuthClient,
) -> anyhow::Result<(OAuthCredentials, OAuthUserInfo)> {
    let auth = client
        .authorize_device()
        .await
        .context("device auth failed")?;

    println!("Opening browser to authorize...");
    println!("If browser doesn't open, visit: {}", auth.verification_uri);
    println!("Your code: {}", auth.user_code);
    let _ = open_browser(&auth.verification_uri);

    let mut interval = Duration::from_secs(auth.interval.max(5));
    let deadline = Instant::now() + Duration::from_secs(auth.expires_in.max(1));

    eprintln!("Waiting for authorization...");
    loop {
        if Instant::now() > deadline {
            anyhow::bail!("timed out waiting for authorization");
        }
        tokio::time::sleep(interval).await;

        let poll = match client.exchange_device_code(&auth.device_code).await {
            Ok(poll) => poll,
            // Each HTTP poll has its own bounded request budget; this loop's
            // device-code expiry remains the overall authorization deadline.
            Err(error) if error.oauth_code() == Some("authorization_pending") => continue,
            Err(error) if error.oauth_code() == Some("slow_down") => {
                interval = interval.saturating_add(Duration::from_secs(5));
                continue;
            }
            Err(error) if error.oauth_code() == Some("access_denied") => {
                anyhow::bail!("authorization denied")
            }
            Err(error) if error.oauth_code() == Some("expired_token") => {
                anyhow::bail!("device code expired")
            }
            Err(error) => return Err(error).context("device authorization poll"),
        };
        let credentials = client
            .credentials_from_device_token(poll)
            .context("validate OAuth device token")?;
        let user = client
            .userinfo(&credentials.bearer_token()?)
            .await
            .context("read OAuth user info")?;
        return Ok((credentials, user));
    }
}

pub(crate) fn save_login_platform_config(
    paths: &ResolvePaths,
    server_url: &str,
    credentials: &OAuthCredentials,
    default_org: Option<&str>,
) -> anyhow::Result<()> {
    config::save_platform_config(
        &paths.platform_config_dir,
        &config::PlatformConfig {
            server_url: server_url.to_string(),
            default_org: default_org.unwrap_or_default().to_string(),
        },
    )
    .context("save config")?;
    codewire_client::CredentialStore::save(
        &codewire_client::FileCredentialStore::new(&paths.platform_config_dir),
        credentials,
    )
    .context("save OAuth credentials")?;
    refresh_hosted_mesh_owner_context(paths, server_url, default_org)
}

pub(crate) fn oauth_user_display_name(user: &OAuthUserInfo) -> String {
    user.name
        .as_deref()
        .and_then(trimmed_str)
        .map(str::to_string)
        .or_else(|| {
            user.email
                .as_deref()
                .and_then(trimmed_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "(unknown)".to_string())
}

pub(crate) fn open_browser(url: &str) -> anyhow::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = ProcessCommand::new("open");
        command.arg(url);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = ProcessCommand::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    } else {
        let mut command = ProcessCommand::new("xdg-open");
        command.arg(url);
        command
    };
    command.spawn().context("open browser")?;
    Ok(())
}

pub(crate) async fn handle_org_command(
    globals: &Globals,
    command: Option<OrgCommand>,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = organization_client(&platform)?;

    match command.unwrap_or(OrgCommand::Set(OrgSetArgs { id_or_slug: None })) {
        OrgCommand::List(args) => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            print_orgs(&orgs, platform.default_org.as_deref(), args.output)?;
        }
        OrgCommand::Current => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            let org = orgs
                .iter()
                .find(|org| org.id == org_id)
                .ok_or_else(|| anyhow::anyhow!("current organization {org_id:?} not found"))?;
            print_org_current(org);
        }
        OrgCommand::Set(args) => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            let selected = select_org(&orgs, args.id_or_slug.as_deref())?;
            let mut saved = config::load_platform_config(&paths.platform_config_dir)?;
            if !config::same_server_url(&saved.server_url, &platform.server_url) {
                anyhow::bail!(
                    "cannot save current org for {}; saved config is for {}",
                    platform.server_url,
                    config::normalize_server_url(&saved.server_url)
                );
            }
            saved.default_org = selected.id.clone();
            config::save_platform_config(&paths.platform_config_dir, &saved)
                .context("save config")?;
            refresh_hosted_mesh_owner_context(&paths, &saved.server_url, Some(&saved.default_org))?;
            eprintln!("Current org set to {} ({}).", selected.name, selected.slug);
        }
        OrgCommand::Create(args) => {
            let name = trimmed_required(&args.name, "organization name")?;
            let slug = args
                .slug
                .as_deref()
                .and_then(trimmed_str)
                .map(str::to_string)
                .unwrap_or_else(|| slugify(name));
            let org = client
                .create_org(&CreateOrgRequest {
                    name: name.to_string(),
                    slug,
                })
                .await
                .context("create org")?;
            eprintln!("Created organization {:?} (slug: {}).", org.name, org.slug);
        }
        OrgCommand::Delete(args) => {
            let id_or_slug = trimmed_required(&args.id_or_slug, "organization id or slug")?;
            let orgs = client.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, Some(id_or_slug))?;
            let org_name = orgs
                .iter()
                .find(|org| org.id == org_id)
                .map(|org| org.name.as_str())
                .unwrap_or(id_or_slug);
            if !args.yes {
                confirm_delete("organization", org_name)?;
            }
            match client.delete_org(&org_id).await.context("delete org")? {
                OrganizationDeletionStart::Accepted(operation) => {
                    eprintln!(
                        "{}",
                        organization_deletion_started_message(&operation.operation_id)
                    );
                    match client
                        .wait_for_org_deletion(&org_id, &operation.operation_id)
                        .await
                        .context("observe organization deletion")?
                    {
                        OrganizationDeletionOutcome::Completed => {
                            eprintln!("Organization deleted.");
                        }
                        OrganizationDeletionOutcome::Failed {
                            operation_id,
                            failure_code,
                        } => {
                            anyhow::bail!(
                                "organization deletion {operation_id} failed ({failure_code}); the organization is retained for retry"
                            );
                        }
                        OrganizationDeletionOutcome::PollingStopped { operation_id } => {
                            eprintln!(
                                "{}",
                                organization_deletion_polling_stopped_message(&operation_id)
                            );
                        }
                    }
                }
            }
        }
        OrgCommand::Invite(args) => {
            let email = trimmed_required(&args.email, "email")?;
            let role = trimmed_required(&args.role, "role")?;
            let orgs = client.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, args.org.as_deref())?;
            let created = client
                .create_invitation(
                    &org_id,
                    &CreateInvitationRequest {
                        email: email.to_string(),
                        role: role.to_string(),
                    },
                )
                .await
                .context("invite")?;
            eprintln!(
                "Created an invitation for {} as {}. Share this URL; it will not be shown again.",
                created.invitation.email, created.invitation.role
            );
            println!("{}", created.url);
        }
    }

    Ok(())
}

pub(crate) async fn handle_api_keys_command(
    globals: &Globals,
    command: ApiKeyCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let client = codewire_client(&platform)?;

    match command {
        ApiKeyCommand::Create(args) => {
            let name = trimmed_required(&args.name, "api key name")?;
            let response = client
                .create_api_key(CreateApiKeyRequest {
                    org_id,
                    name: name.to_string(),
                    scopes: Vec::new(),
                    expires_in_days: (args.expires > 0).then_some(args.expires),
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)
                .context("create api key")?;
            println!("{}", response.key);
        }
        ApiKeyCommand::List => {
            let keys = client
                .list_api_keys(ListApiKeysRequest {
                    org_id,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)
                .context("list api keys")?;
            print!("{}", format_api_key_list_text(&keys.api_keys));
        }
        ApiKeyCommand::Delete(args) => {
            let key_id = trimmed_required(&args.key_id, "api key id")?;
            client
                .delete_api_key(DeleteApiKeyRequest {
                    org_id,
                    key_id: key_id.to_string(),
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)
                .context("delete api key")?;
            eprintln!("API key deleted.");
        }
    }

    Ok(())
}

pub(crate) async fn handle_preset_command(
    globals: &Globals,
    command: PresetCommand,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = organization_client(&platform)?;
    let orgs = client.list_orgs().await.context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;

    match command {
        PresetCommand::List => {
            let presets = client.list_presets(&org_id).await.context("list presets")?;
            print!("{}", format_preset_list_text(&presets));
        }
        PresetCommand::Create(args) => {
            let slug = trimmed_required(&args.slug, "preset slug")?;
            let image = trimmed_required(&args.image, "image")?;
            let image = if image.contains('/') {
                image.to_string()
            } else {
                expand_image_ref(image)
            };
            let ttl_seconds = args
                .ttl
                .as_deref()
                .and_then(trimmed_str)
                .map(parse_go_duration_seconds)
                .transpose()
                .context("invalid --ttl duration")?;
            let name = args
                .name
                .as_deref()
                .and_then(trimmed_str)
                .unwrap_or(slug)
                .to_string();
            let request = CreatePresetRequest {
                name,
                slug: slug.to_string(),
                description: trimmed_optional(args.description).unwrap_or_default(),
                default_ttl_seconds: ttl_seconds,
                project_spec: codewire_project::ProjectSpec {
                    image,
                    install_command: trimmed_optional(args.install).unwrap_or_default(),
                    startup_script: trimmed_optional(args.startup).unwrap_or_default(),
                    resources: codewire_project::ResourceSpec {
                        cpu_millicores: positive_i32(args.cpu).map(|value| value as u32),
                        memory_mib: positive_i32(args.memory).map(|value| value as u64),
                        disk_gib: positive_i32(args.disk).map(|value| value as u64),
                    },
                    ..Default::default()
                },
            };
            request.project_spec.validate()?;
            let preset = client
                .create_preset(&org_id, &request)
                .await
                .context("create preset")?;
            eprintln!("Preset created: {}.", preset.name);
            println!("  ID:    {}", preset.id);
        }
        PresetCommand::Info(args) => {
            let selector = trimmed_required(&args.selector, "preset selector")?;
            let presets = client.list_presets(&org_id).await.context("list presets")?;
            let preset = find_preset(&presets, &org_id, selector)?
                .ok_or_else(|| anyhow::anyhow!("preset not found: {selector}"))?;
            print!("{}", format_preset_info_text(preset));
        }
        PresetCommand::Rm(args) => {
            let id = trimmed_required(&args.id, "preset id")?;
            client
                .delete_preset(&org_id, id)
                .await
                .context("delete preset")?;
            eprintln!("Preset {id} deleted.");
        }
    }

    Ok(())
}

pub(crate) async fn handle_platform_secrets_command(
    globals: &Globals,
    command: SecretOperation,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = SecretClient::new(&platform)?;
    let organizations = organization_client(&platform)?;

    match command {
        SecretOperation::User(command) => {
            handle_user_secret_command(&client, command).await?;
        }
        SecretOperation::Organization(command) => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            handle_org_secret_command(&client, &org_id, command).await?;
        }
        SecretOperation::Preview(args) => {
            let intent = load_secret_preview_intent(&args.file)?;
            validate_secret_preview_placement(
                &intent,
                super::storage_placement::StoragePlacement::Platform,
            )?;
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            let secret_project_id = if let Some(project_name) = intent.project.as_deref() {
                Some(
                    load_secret_project_by_name(&client, &org_id, project_name)
                        .await?
                        .id,
                )
            } else {
                None
            };
            let secrets = client
                .preview_workload_secret_resolution(
                    &org_id,
                    intent.organization,
                    secret_project_id.as_deref(),
                    intent.user.is_some(),
                    intent.explicit_environment_keys,
                )
                .await
                .context("preview platform workload-secret resolution")?;
            print_secret_resolution("platform", &secrets, args.output)?;
        }
        SecretOperation::Project { name, command } => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            handle_project_secret_command(&client, &org_id, &name, command).await?;
        }
        SecretOperation::Projects(command) => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            match command {
                SecretProjectCommand::Create(args) => {
                    let name = trimmed_required(&args.name, "secret project name")?;
                    let project = client
                        .create_secret_project(
                            &org_id,
                            &CreateSecretProjectRequest {
                                name: name.to_string(),
                            },
                        )
                        .await
                        .context("create secret project")?;
                    eprintln!(
                        "Secret project {:?} created. (id: {})",
                        project.name, project.id
                    );
                }
                SecretProjectCommand::List(args) => {
                    let projects = client
                        .list_secret_projects(&org_id)
                        .await
                        .context("list secret projects")?;
                    print_secret_project_list(&projects, args.output)?;
                }
                SecretProjectCommand::Delete(args) => {
                    let project_name = trimmed_required(&args.name, "secret project")?;
                    let project =
                        load_secret_project_by_name(&client, &org_id, project_name).await?;
                    let target = format!(
                        "platform secret project {:?} ({}) in organization {}",
                        project.name, project.id, org_id
                    );
                    if !confirm_secret_project_delete(&target, args.yes)? {
                        eprintln!("Canceled.");
                        return Ok(());
                    }
                    client
                        .delete_secret_project(&org_id, &project.id)
                        .await
                        .context("delete secret project")?;
                    eprintln!("Secret project {project_name:?} deleted.");
                }
            }
        }
    }

    Ok(())
}

async fn handle_project_secret_command(
    client: &SecretClient,
    org_id: &str,
    project_name: &str,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    let project = load_secret_project_by_name(client, org_id, project_name).await?;
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_project_secrets(org_id, &project.id)
                .await
                .context("list project secrets")?;
            print_secret_metadata_list(
                &secrets,
                &format!("No secrets in project {project_name:?}."),
                args.output,
            )?;
        }
        ScopedSecretCommand::Set(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let value = prompt_platform_workload_secret_value()?;
            client
                .set_project_secret(org_id, &project.id, key, &value)
                .await
                .context("set secret")?;
            eprintln!("Secret {key} set in project {project_name:?}.");
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            client
                .delete_project_secret(org_id, &project.id, key)
                .await
                .context("delete secret")?;
            eprintln!("Secret {key} deleted from project {project_name:?}.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            client
                .rename_project_secret(org_id, &project.id, old_key, new_key)
                .await
                .context("rename secret")?;
            eprintln!("Secret {old_key} renamed to {new_key} in project {project_name:?}.");
        }
    }
    Ok(())
}

pub(crate) async fn handle_user_secret_command(
    client: &SecretClient,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_user_secrets()
                .await
                .context("list user secrets")?;
            print_secret_metadata_list(&secrets, "No user secrets found.", args.output)?;
        }
        ScopedSecretCommand::Set(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let value = prompt_platform_workload_secret_value()?;
            client
                .set_user_secret(key, &value)
                .await
                .context("set user secret")?;
            eprintln!("Secret {key} set.");
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            client
                .delete_user_secret(key)
                .await
                .context("delete user secret")?;
            eprintln!("Secret {key} deleted.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            client
                .rename_user_secret(old_key, new_key)
                .await
                .context("rename user secret")?;
            eprintln!("Secret {old_key} renamed to {new_key}.");
        }
    }

    Ok(())
}

pub(crate) async fn handle_org_secret_command(
    client: &SecretClient,
    org_id: &str,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_org_secrets(org_id)
                .await
                .context("list org secrets")?;
            print_secret_metadata_list(&secrets, "No organization secrets found.", args.output)?;
        }
        ScopedSecretCommand::Set(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let value = prompt_platform_workload_secret_value()?;
            client
                .set_org_secret(org_id, key, &value)
                .await
                .context("set org secret")?;
            eprintln!("Secret {key} set.");
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            client
                .delete_org_secret(org_id, key)
                .await
                .context("delete org secret")?;
            eprintln!("Secret {key} deleted.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            client
                .rename_org_secret(org_id, old_key, new_key)
                .await
                .context("rename org secret")?;
            eprintln!("Secret {old_key} renamed to {new_key}.");
        }
    }

    Ok(())
}

pub(crate) async fn load_secret_project_by_name(
    client: &SecretClient,
    org_id: &str,
    project_name: &str,
) -> anyhow::Result<SecretProject> {
    let projects = client
        .list_secret_projects(org_id)
        .await
        .context("list secret projects")?;
    resolve_platform_secret_project(&projects, project_name).cloned()
}

fn resolve_platform_secret_project<'a>(
    projects: &'a [SecretProject],
    selector: &str,
) -> anyhow::Result<&'a SecretProject> {
    let selector = project_selector_for_placement(
        selector,
        super::storage_placement::StoragePlacement::Platform,
    )?;
    let mut matches = projects
        .iter()
        .filter(|project| match selector.strip_prefix("id:") {
            Some(id) => project.id == id,
            None => project.name.eq_ignore_ascii_case(selector),
        });
    let project = matches
        .next()
        .context("platform secret project was not found in the selected organization")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "platform secret project name is ambiguous; select an exact id"
    );
    Ok(project)
}

pub(crate) fn inspect_config(output: OutputFormat) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform =
        config::resolve_platform(config::PlatformResolveOptions::default(), &paths, &env);
    let mesh = config::resolve_mesh(config::MeshResolveOptions::default(), &paths, &env);
    let report = config::ConfigReport::from_results(&paths, platform, mesh);

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
            println!("platform_config_dir={}", report.platform_config_dir);
            println!("mesh_data_dir={}", report.mesh_data_dir);
            match &report.platform {
                Some(platform) => {
                    println!("platform_server_url={}", platform.server_url);
                    println!(
                        "platform_token_source={}",
                        if platform.used_config_token {
                            "config"
                        } else {
                            "override"
                        }
                    );
                }
                None => println!("platform=unconfigured"),
            }
            match &report.mesh {
                Some(mesh) => {
                    println!("mesh_url={}", mesh.mesh_url);
                    if let Some(network) = &mesh.selected_network {
                        println!("mesh_selected_network={network}");
                    }
                    println!("mesh_auth_configured={}", mesh.auth_configured);
                }
                None => println!("mesh=unconfigured"),
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct DoctorReport {
    pub(crate) platform_config_dir: String,
    pub(crate) mesh_data_dir: String,
    pub(crate) checks: Vec<DoctorCheck>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct TailnetDoctorReport {
    pub(crate) environment_id: String,
    pub(crate) server_url: String,
    pub(crate) expect: String,
    pub(crate) direct: tailnet_ssh::EnvironmentTailnetDiagnostic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) forced_derp: Option<tailnet_ssh::EnvironmentTailnetDiagnostic>,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct DoctorCheck {
    pub(crate) name: String,
    pub(crate) status: DoctorStatus,
    pub(crate) detail: String,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

pub(crate) async fn handle_doctor_command(
    globals: &Globals,
    args: DoctorArgs,
) -> anyhow::Result<()> {
    if let Some(command) = args.command {
        return match command {
            #[cfg(target_os = "linux")]
            DoctorCommand::Local(args) => {
                let report = native_orphan_report()?;
                print_native_orphan_report(&report, args.output)
            }
            DoctorCommand::Tailnet(args) => handle_doctor_tailnet_command(globals, args).await,
        };
    }

    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let report = collect_doctor_report(globals, &paths, &env).await;
    print_doctor_report(&report, args.output)
}

pub(crate) async fn collect_doctor_report(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> DoctorReport {
    let checks = vec![
        doctor_platform_check(globals, paths, env).await,
        doctor_org_check(globals, paths, env).await,
        doctor_completion_check(),
        doctor_ssh_config_check(),
    ];

    DoctorReport {
        platform_config_dir: paths.platform_config_dir.display().to_string(),
        mesh_data_dir: paths.mesh_data_dir.display().to_string(),
        checks,
    }
}

pub(crate) fn print_doctor_report(
    report: &DoctorReport,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Text => print!("{}", format_doctor_text(report)),
    }
    Ok(())
}

pub(crate) async fn handle_doctor_tailnet_command(
    globals: &Globals,
    args: DoctorTailnetArgs,
) -> anyhow::Result<()> {
    let direct_wait = parse_tailnet_doctor_duration("direct-wait", &args.direct_wait, true)?;
    let peer_timeout = parse_tailnet_doctor_duration("peer-timeout", &args.peer_timeout, false)?;
    let expected_transport = tailnet_ssh::ExpectedTransport::parse(&args.expect)?;
    let direct_expected = match expected_transport {
        tailnet_ssh::ExpectedTransport::DerpRelay => tailnet_ssh::ExpectedTransport::Any,
        other => other,
    };

    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env);
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = codewire_client(&platform)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let environment_id =
        resolve_environment_id(&environment_client, &org_id, &args.environment).await?;

    let direct_probe = tailnet_ssh::diagnose_environment_tailnet(
        &client,
        &org_id,
        &environment_id,
        tailnet_ssh::TailnetDiagnosticOptions {
            peer_timeout,
            direct_wait,
            force_derp: false,
            expected_transport: direct_expected,
        },
    );

    let (direct, forced_derp) = if args.skip_forced_derp {
        (direct_probe.await, None)
    } else {
        let forced_derp_probe = tailnet_ssh::diagnose_environment_tailnet(
            &client,
            &org_id,
            &environment_id,
            tailnet_ssh::TailnetDiagnosticOptions {
                peer_timeout,
                direct_wait: Duration::ZERO,
                force_derp: true,
                expected_transport: tailnet_ssh::ExpectedTransport::Any,
            },
        );
        // These are independent read-only sessions with distinct ephemeral
        // identities. Running them together keeps the command horizon to one
        // probe instead of adding two complete peer/session wait budgets.
        let (direct, forced_derp) = tokio::join!(direct_probe, forced_derp_probe);
        (direct, Some(forced_derp))
    };

    let report = TailnetDoctorReport {
        environment_id,
        server_url: client.server_url().to_string(),
        expect: expected_transport.as_str().to_string(),
        direct,
        forced_derp,
    };

    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => print!("{}", format_tailnet_doctor_text(&report)),
    }

    validate_tailnet_doctor_report(&report)
}

pub(crate) fn parse_tailnet_doctor_duration(
    flag_name: &str,
    raw: &str,
    allow_zero: bool,
) -> anyhow::Result<Duration> {
    let duration = tailnet_ssh::parse_duration(raw)
        .with_context(|| format!("--{flag_name} must be a duration such as 250ms, 15s, or 1m"))?;
    if !allow_zero && duration.is_zero() {
        anyhow::bail!("--{flag_name} must be positive");
    }
    Ok(duration)
}

pub(crate) fn validate_tailnet_doctor_report(report: &TailnetDoctorReport) -> anyhow::Result<()> {
    if let Some(detail) = tailnet_diagnostic_failure_detail(&report.direct) {
        anyhow::bail!("tailnet direct probe failed: {detail}");
    }
    if let Some(forced_derp) = report.forced_derp.as_ref()
        && let Some(detail) = tailnet_diagnostic_failure_detail(forced_derp)
    {
        anyhow::bail!("tailnet forced DERP probe failed: {detail}");
    }

    match report.expect.as_str() {
        "any" => Ok(()),
        "direct_udp" => {
            if tailnet_diagnostic_has_transport(&report.direct, "direct_udp") {
                return Ok(());
            }
            anyhow::bail!(
                "expected direct_udp transport but probe did not verify a direct UDP path"
            )
        }
        "udp_relay" => {
            if tailnet_diagnostic_has_transport(&report.direct, "udp_relay") {
                return Ok(());
            }
            anyhow::bail!("expected udp_relay transport but probe did not verify a UDP relay path")
        }
        "derp" | "derp_relay" => {
            if report
                .forced_derp
                .as_ref()
                .is_some_and(|diag| tailnet_diagnostic_has_transport(diag, "derp"))
                || tailnet_diagnostic_has_transport(&report.direct, "derp")
            {
                return Ok(());
            }
            anyhow::bail!("expected derp transport but probe did not verify a DERP path")
        }
        value => anyhow::bail!("unsupported tailnet expectation {value:?}"),
    }
}

pub(crate) fn tailnet_diagnostic_failure_detail(
    diagnostic: &tailnet_ssh::EnvironmentTailnetDiagnostic,
) -> Option<String> {
    diagnostic
        .stages
        .iter()
        .find(|stage| stage.status == "fail")
        .map(|stage| {
            if stage.detail.is_empty() {
                stage.name.clone()
            } else {
                format!("{}: {}", stage.name, stage.detail)
            }
        })
}

pub(crate) fn tailnet_diagnostic_has_transport(
    diagnostic: &tailnet_ssh::EnvironmentTailnetDiagnostic,
    transport: &str,
) -> bool {
    diagnostic
        .direct_path
        .as_ref()
        .is_some_and(|path| tailnet_path_has_transport(path, transport))
        || diagnostic
            .final_path
            .as_ref()
            .is_some_and(|path| tailnet_path_has_transport(path, transport))
}

pub(crate) fn tailnet_path_has_transport(
    path: &tailnet_ssh::TailnetPathDiagnostic,
    transport: &str,
) -> bool {
    transport_matches(&path.transport, transport)
        && (path.ready || transport_matches(transport, "derp"))
}

pub(crate) fn transport_matches(actual: &str, expected: &str) -> bool {
    actual == expected
        || matches!(
            (actual, expected),
            ("derp_relay", "derp") | ("derp", "derp_relay")
        )
}

pub(crate) fn format_doctor_text(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{:<12} {}\n",
        "Config:", report.platform_config_dir
    ));
    output.push_str(&format!("{:<12} {}\n", "Mesh data:", report.mesh_data_dir));
    output.push('\n');
    for check in &report.checks {
        output.push_str(&format!(
            "{:<12} {:<6} {}\n",
            check.name,
            check.status.as_str(),
            check.detail
        ));
    }
    output
}

pub(crate) fn format_tailnet_doctor_text(report: &TailnetDoctorReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("Environment: {}\n", report.environment_id));
    if !report.server_url.trim().is_empty() {
        output.push_str(&format!("Server:      {}\n", report.server_url));
    }
    output.push_str(&format!("Expect:      {}\n\n", report.expect));
    append_tailnet_diagnostic_text(&mut output, "direct", &report.direct);
    if let Some(forced_derp) = report.forced_derp.as_ref() {
        output.push('\n');
        append_tailnet_diagnostic_text(&mut output, "forced derp", forced_derp);
    }
    output
}

pub(crate) fn append_tailnet_diagnostic_text(
    output: &mut String,
    label: &str,
    diagnostic: &tailnet_ssh::EnvironmentTailnetDiagnostic,
) {
    output.push_str(&format!("Probe:       {label}\n"));
    if let Some(derp_map) = diagnostic.derp_map.as_ref() {
        output.push_str(&format!(
            "  {:<18} regions={} derp_nodes={} stun_nodes={}\n",
            "derp map", derp_map.regions, derp_map.derp_nodes, derp_map.stun_nodes
        ));
    }
    if let Some(peer) = diagnostic.peer.as_ref() {
        output.push_str(&format!(
            "  {:<18} derp={} endpoints={} addresses={}\n",
            "peer",
            peer.preferred_derp,
            peer.endpoints.len(),
            peer.addresses.len()
        ));
    }
    if let Some(path) = diagnostic.direct_path.as_ref() {
        output.push_str(&format!(
            "  {:<18} {}\n",
            "direct path",
            tailnet_path_summary(path)
        ));
    }
    if let Some(path) = diagnostic.final_path.as_ref() {
        output.push_str(&format!(
            "  {:<18} {}\n",
            "final path",
            tailnet_path_summary(path)
        ));
    }
    for stage in &diagnostic.stages {
        let mut detail = stage.detail.clone();
        if let Some(duration_ms) = stage.duration_ms {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!("({duration_ms}ms)"));
        }
        output.push_str(&format!(
            "  {:<18} {:<6} {}\n",
            stage.name, stage.status, detail
        ));
    }
}

pub(crate) fn tailnet_path_summary(path: &tailnet_ssh::TailnetPathDiagnostic) -> String {
    let mut parts = Vec::new();
    parts.push(if path.ready { "ready" } else { "not-ready" }.to_string());
    if !path.transport.is_empty() {
        parts.push(format!("transport={}", path.transport));
    }
    if !path.endpoint.is_empty() {
        parts.push(format!("endpoint={}", path.endpoint));
    }
    if let Some(region_id) = path.derp_region_id {
        parts.push(format!("derp_region={region_id}"));
    }
    if !path.error.is_empty() {
        parts.push(format!("error={}", path.error));
    }
    parts.join(" ")
}

pub(crate) async fn doctor_platform_check(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> DoctorCheck {
    let platform = match resolve_platform(globals, paths, env) {
        Ok(platform) => platform,
        Err(err) => return doctor_check("platform", DoctorStatus::Fail, err.to_string()),
    };
    let client = match doctor_platform_client(&platform) {
        Ok(client) => client,
        Err(err) => return doctor_check("platform", DoctorStatus::Fail, err.to_string()),
    };
    let token = match client.bearer_token().await {
        Ok(token) => token,
        Err(err) => {
            return doctor_check(
                "platform",
                DoctorStatus::Fail,
                format!("OAuth token failed: {err}"),
            );
        }
    };
    match OAuthClient::for_server_url(&platform.server_url) {
        Ok(oauth) => match oauth.userinfo(&token).await {
            Ok(user) => doctor_check(
                "platform",
                DoctorStatus::Ok,
                format!(
                    "{} on {}",
                    oauth_user_display_name(&user),
                    platform.server_url
                ),
            ),
            Err(err) => doctor_check(
                "platform",
                DoctorStatus::Fail,
                format!("OAuth user info failed: {err}"),
            ),
        },
        Err(err) => doctor_check(
            "platform",
            DoctorStatus::Fail,
            format!("OAuth client failed: {err}"),
        ),
    }
}

pub(crate) async fn doctor_org_check(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> DoctorCheck {
    let platform = match resolve_platform(globals, paths, env) {
        Ok(platform) => platform,
        Err(err) => return doctor_check("org", DoctorStatus::Warn, err.to_string()),
    };
    let client = match organization_client(&platform) {
        Ok(client) => client,
        Err(err) => return doctor_check("org", DoctorStatus::Warn, err.to_string()),
    };
    let orgs = match client.list_orgs().await {
        Ok(orgs) => orgs,
        Err(err) => return doctor_check("org", DoctorStatus::Warn, format!("list orgs: {err}")),
    };
    doctor_org_selection_check(&platform, &orgs)
}

pub(crate) fn doctor_org_selection_check(
    platform: &config::ResolvedPlatformConfig,
    orgs: &[OrgWithRole],
) -> DoctorCheck {
    let org_id = match current_org_id(platform, orgs) {
        Ok(org_id) => org_id,
        Err(err) => return doctor_check("org", DoctorStatus::Warn, err.to_string()),
    };
    let Some(org) = orgs.iter().find(|org| org.id == org_id) else {
        return doctor_check(
            "org",
            DoctorStatus::Warn,
            format!("selected organization {org_id:?} was not returned by the server"),
        );
    };
    let detail = trimmed_str(&org.name)
        .or_else(|| trimmed_str(&org.slug))
        .unwrap_or(&org.id)
        .to_string();
    doctor_check("org", DoctorStatus::Ok, detail)
}

pub(crate) fn doctor_completion_check() -> DoctorCheck {
    let shell_path = env::var("SHELL").ok();
    let Some(shell) = detect_completion_shell(shell_path.as_deref()) else {
        return doctor_check("completion", DoctorStatus::Warn, "unknown shell");
    };
    let Some(path) = detect_installed_completion_path(shell) else {
        return doctor_check(
            "completion",
            DoctorStatus::Warn,
            format!("{} completion not installed", shell.name()),
        );
    };
    doctor_check(
        "completion",
        DoctorStatus::Ok,
        format!("{} at {}", shell.name(), path.display()),
    )
}

pub(crate) fn doctor_platform_client(
    platform: &config::ResolvedPlatformConfig,
) -> anyhow::Result<CodewireClient> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build doctor HTTP client")?;
    let config = codewire_client::ClientConfig::new(&platform.server_url)?
        .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
    CodewireClient::with_http_token_provider(config, platform.token_provider()?, http)
        .map_err(Into::into)
}

pub(crate) fn detect_installed_completion_path(shell: CompletionShell) -> Option<PathBuf> {
    completion_install_paths(shell)
        .into_iter()
        .find(|path| path.is_file())
}

pub(crate) fn completion_install_paths(shell: CompletionShell) -> Vec<PathBuf> {
    match shell {
        CompletionShell::Zsh => zsh_completion_install_candidates()
            .into_iter()
            .map(|candidate| candidate.dir.join("_cw"))
            .collect(),
        CompletionShell::Bash => {
            let mut paths = Vec::new();
            if let Some(prefix) = brew_prefix() {
                paths.push(prefix.join("etc/bash_completion.d/cw"));
            }
            if let Some(home) = home_dir() {
                paths.push(home.join(".bash_completion.d/cw"));
            }
            paths
        }
        CompletionShell::Fish => home_dir()
            .map(|home| vec![home.join(".config/fish/completions/cw.fish")])
            .unwrap_or_default(),
        CompletionShell::Powershell => Vec::new(),
    }
}

pub(crate) fn doctor_ssh_config_check() -> DoctorCheck {
    let cw_command = match current_cw_executable().and_then(|path| ssh_cw_command(&path)) {
        Ok(cw_command) => cw_command,
        Err(err) => return doctor_check("ssh config", DoctorStatus::Warn, format!("{err:#}")),
    };
    doctor_ssh_config_check_at(&default_ssh_config_path(), &cw_command)
}

pub(crate) fn doctor_ssh_config_check_at(config_path: &Path, cw_command: &str) -> DoctorCheck {
    let content = match fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return doctor_check(
                "ssh config",
                DoctorStatus::Warn,
                format!("missing {}", config_path.display()),
            );
        }
        Err(err) => return doctor_check("ssh config", DoctorStatus::Warn, err.to_string()),
    };
    if !content.contains(SSH_CONFIG_MARKER_START) || !content.contains(SSH_CONFIG_MARKER_END) {
        return doctor_check(
            "ssh config",
            DoctorStatus::Warn,
            format!("Codewire section missing in {}", config_path.display()),
        );
    }
    if !managed_ssh_section_is_current(&content, cw_command) {
        return doctor_check(
            "ssh config",
            DoctorStatus::Warn,
            format!(
                "Codewire section in {} is outdated or not first; run `cw config-ssh`",
                config_path.display()
            ),
        );
    }
    doctor_check(
        "ssh config",
        DoctorStatus::Ok,
        config_path.display().to_string(),
    )
}

pub(crate) fn doctor_check(
    name: impl Into<String>,
    status: DoctorStatus,
    detail: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

pub(crate) fn handle_completion_command(args: CompletionArgs) -> anyhow::Result<()> {
    if args.install {
        return install_completion_for_current_shell();
    }

    let shell = args.shell.unwrap_or(CompletionShell::Zsh);
    let mut stdout = std::io::stdout();
    stdout.write_all(&completion_script(shell))?;
    Ok(())
}

pub(crate) fn completion_script(shell: CompletionShell) -> Vec<u8> {
    let mut cmd = Cli::command();
    let mut out = Vec::new();
    generate(shell.clap_shell(), &mut cmd, "cw", &mut out);
    out
}

pub(crate) const SSH_CONFIG_MARKER_START: &str = "# ---- START CODEWIRE ----";
pub(crate) const SSH_CONFIG_MARKER_END: &str = "# ---- END CODEWIRE ----";

/// Stands for the `cw` executable in [`MANAGED_SSH_DIRECTIVES`]; see
/// [`ssh_cw_command`].
const SSH_CW_PLACEHOLDER: &str = "{cw}";

/// What every Codewire host gets, in order. The SSH server runs inside the
/// environment's sandbox, so nothing here may expose the user's agent, X11,
/// Kerberos credentials or a password prompt to it, and host keys are trusted
/// only through `KnownHostsCommand`: the environment's recorded key, fetched
/// through the authenticated API (`cw ssh known-hosts`), failing closed with
/// no first-use trust and no known_hosts file. The recorded key is always
/// Ed25519, and naming that one algorithm also stops OpenSSH from running
/// `KnownHostsCommand` a second time, before key exchange, only to order the
/// host key algorithms. OpenSSH keeps the first value it obtains, so the block
/// is written before the user's own entries.
pub(crate) const MANAGED_SSH_DIRECTIVES: &[(&str, &str)] = &[
    ("ProxyCommand", "{cw} shell --stdio %n"),
    ("User", "codewire"),
    ("StrictHostKeyChecking", "yes"),
    ("UserKnownHostsFile", "/dev/null"),
    ("GlobalKnownHostsFile", "/dev/null"),
    ("KnownHostsCommand", "{cw} ssh known-hosts %H"),
    ("HostKeyAlgorithms", "ssh-ed25519"),
    ("UpdateHostKeys", "no"),
    ("ForwardAgent", "no"),
    ("ForwardX11", "no"),
    ("PasswordAuthentication", "no"),
    ("KbdInteractiveAuthentication", "no"),
    ("PubkeyAuthentication", "no"),
    ("GSSAPIAuthentication", "no"),
    ("GSSAPIDelegateCredentials", "no"),
];

/// Keywords `--ssh-option` may not set: the managed directives (which would be
/// silently ignored after them), and those that would change the block's
/// scope, which host key is checked, or which hop is trusted.
const RESERVED_SSH_OPTION_KEYWORDS: &[&str] = &[
    "Host",
    "Match",
    "Include",
    "HostKeyAlias",
    "ProxyJump",
    "ForwardX11Trusted",
    "HostbasedAuthentication",
];

#[derive(Clone, Debug)]
pub(crate) struct SshConfigOptions {
    /// `cw` as the managed directives run it, from [`ssh_cw_command`].
    pub(crate) cw_command: String,
    pub(crate) ssh_options: Vec<String>,
}

/// The managed directives with `cw_command` in place of the executable.
fn managed_ssh_directives(cw_command: &str) -> impl Iterator<Item = (&'static str, String)> + '_ {
    MANAGED_SSH_DIRECTIVES
        .iter()
        .map(move |(keyword, value)| (*keyword, value.replace(SSH_CW_PLACEHOLDER, cw_command)))
}

/// The `cw` the managed block runs: the first `cw` on `PATH` when it is this
/// very executable, so a package manager's stable link survives upgrades, and
/// otherwise this executable itself.
pub(crate) fn current_cw_executable() -> anyhow::Result<PathBuf> {
    let current = env::current_exe().context("locate the running cw executable")?;
    let resolved_current = fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
    let name = format!("cw{}", env::consts::EXE_SUFFIX);
    let on_path = env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(&name))
            .find(|candidate| candidate.is_absolute() && candidate.is_file())
    });
    Ok(match on_path {
        Some(on_path)
            if fs::canonicalize(&on_path).is_ok_and(|resolved| resolved == resolved_current) =>
        {
            on_path
        }
        _ => current,
    })
}

/// `path` as OpenSSH runs it from `ProxyCommand` (through the user's shell)
/// and `KnownHostsCommand` (which OpenSSH runs only from an absolute path).
/// `%` is doubled because both expand `%` tokens, and a path with whitespace
/// is double-quoted. A path neither form can carry verbatim is refused.
pub(crate) fn ssh_cw_command(path: &Path) -> anyhow::Result<String> {
    anyhow::ensure!(
        path.is_absolute(),
        "the cw executable path {} is not absolute",
        path.display()
    );
    let path = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("the cw executable path {} is not UTF-8", path.display()))?;
    anyhow::ensure!(
        !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\' | '$' | '`')),
        "the cw executable path {path:?} cannot be written into an SSH config; \
         install cw at a path without quotes, backslashes, `$` or backticks"
    );
    let escaped = path.replace('%', "%%");
    Ok(if escaped.chars().any(char::is_whitespace) {
        format!("\"{escaped}\"")
    } else {
        escaped
    })
}

pub(crate) fn handle_config_ssh_command(args: ConfigSshArgs) -> anyhow::Result<()> {
    let config_path =
        expand_home_path(args.ssh_config_file.unwrap_or_else(default_ssh_config_path))?;
    let (content, changed) = render_managed_ssh_config(
        &config_path,
        &SshConfigOptions {
            cw_command: ssh_cw_command(&current_cw_executable()?)?,
            ssh_options: args.ssh_options,
        },
    )?;

    if args.dry_run {
        std::io::stdout().write_all(content.as_bytes())?;
        return Ok(());
    }

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create ssh config dir {parent:?}"))?;
    }
    write_ssh_config_file(&config_path, content.as_bytes())?;

    if changed {
        println!("Updated {}", config_path.display());
    } else {
        println!("No changes to {}", config_path.display());
    }
    Ok(())
}

pub(crate) fn default_ssh_config_path() -> PathBuf {
    home_path_or_tilde(".ssh/config")
}

pub(crate) fn home_path_or_tilde(relative: &str) -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"))
        .join(relative)
}

pub(crate) fn expand_home_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("get home dir"))?;
        return Ok(PathBuf::from(home).join(rest));
    }
    Ok(path)
}

pub(crate) fn render_managed_ssh_config(
    config_path: &Path,
    options: &SshConfigOptions,
) -> anyhow::Result<(String, bool)> {
    let existing = match fs::read(config_path) {
        Ok(existing) => existing,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).with_context(|| format!("read ssh config {config_path:?}")),
    };
    let existing_text = String::from_utf8_lossy(&existing);
    let rendered = place_managed_ssh_section(&existing_text, &ssh_config_block(options)?)?;
    let changed = existing != rendered.as_bytes();
    Ok((rendered, changed))
}

pub(crate) fn ssh_config_block(options: &SshConfigOptions) -> anyhow::Result<String> {
    let mut output = String::new();
    output.push_str(SSH_CONFIG_MARKER_START);
    output.push('\n');
    output
        .push_str("# This section is managed by Codewire. Re-run `cw config-ssh` to update it.\n");
    output.push_str(
        "# It stays first in this file: OpenSSH uses the first value it finds for an option.\n",
    );
    output.push_str("Host cw-*\n");
    for (keyword, value) in managed_ssh_directives(&options.cw_command) {
        output.push_str(&format!("    {keyword} {value}\n"));
    }
    for option in &options.ssh_options {
        let option = option.trim();
        if option.is_empty() {
            continue;
        }
        anyhow::ensure!(
            !option.contains(['\n', '\r']),
            "SSH option must be a single line: {option:?}"
        );
        let keyword = ssh_option_keyword(option);
        anyhow::ensure!(
            !MANAGED_SSH_DIRECTIVES
                .iter()
                .map(|(managed, _)| *managed)
                .chain(RESERVED_SSH_OPTION_KEYWORDS.iter().copied())
                .any(|reserved| reserved.eq_ignore_ascii_case(keyword)),
            "SSH option {keyword} is fixed by the managed Codewire block and cannot be overridden"
        );
        output.push_str("    ");
        output.push_str(option);
        output.push('\n');
    }
    // Restore the global scope so the user's entries after this block keep
    // their meaning for every host.
    output.push_str("Host *\n");
    output.push_str(SSH_CONFIG_MARKER_END);
    Ok(output)
}

fn ssh_option_keyword(option: &str) -> &str {
    option
        .split(|c: char| c.is_whitespace() || c == '=')
        .next()
        .unwrap_or_default()
}

/// Whether `content` starts with a Codewire section that carries every current
/// managed directive, running `cw_command`.
pub(crate) fn managed_ssh_section_is_current(content: &str, cw_command: &str) -> bool {
    let content = content.trim_start_matches(['\n', '\r']);
    let Some(rest) = content.strip_prefix(SSH_CONFIG_MARKER_START) else {
        return false;
    };
    let Some(end) = rest.find(SSH_CONFIG_MARKER_END) else {
        return false;
    };
    let section = &rest[..end];
    managed_ssh_directives(cw_command)
        .all(|(keyword, value)| section.contains(&format!("\n    {keyword} {value}\n")))
        && section.contains("\nHost cw-*\n")
        && section.ends_with("\nHost *\n")
}

/// Puts `managed` first in the file, replacing any earlier Codewire section
/// wherever it was. Everything else is kept as it was.
pub(crate) fn place_managed_ssh_section(existing: &str, managed: &str) -> anyhow::Result<String> {
    let rest = remove_managed_ssh_section(existing)?;
    let rest = rest.trim_start_matches(['\n', '\r']);
    let mut output = String::with_capacity(managed.len() + rest.len() + 3);
    output.push_str(managed);
    output.push('\n');
    if !rest.is_empty() {
        output.push('\n');
        output.push_str(rest);
        if !rest.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

pub(crate) fn remove_managed_ssh_section(existing: &str) -> anyhow::Result<String> {
    let start = existing.find(SSH_CONFIG_MARKER_START);
    let end = existing.find(SSH_CONFIG_MARKER_END);

    match (start, end) {
        (None, None) => Ok(existing.to_string()),
        (Some(start), Some(end)) if end >= start => {
            let mut end = end + SSH_CONFIG_MARKER_END.len();
            if existing.as_bytes().get(end) == Some(&b'\n') {
                end += 1;
            }
            Ok(format!("{}{}", &existing[..start], &existing[end..]))
        }
        _ => anyhow::bail!("malformed ssh config: Codewire markers are incomplete"),
    }
}

pub(crate) fn write_ssh_config_file(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write ssh config {path:?}"))?;
    file.write_all(content)
        .with_context(|| format!("write ssh config {path:?}"))
}

pub(crate) fn install_completion_for_current_shell() -> anyhow::Result<()> {
    match detect_completion_shell(env::var("SHELL").ok().as_deref()) {
        Some(CompletionShell::Zsh) => install_zsh_completion(),
        Some(CompletionShell::Bash) => install_bash_completion(),
        Some(CompletionShell::Fish) => install_fish_completion(),
        Some(CompletionShell::Powershell) | None => {
            anyhow::bail!(
                "unsupported shell {:?}; run 'cw completion zsh|bash|fish|powershell' and follow shell-specific instructions",
                env::var("SHELL").unwrap_or_default()
            )
        }
    }
}

pub(crate) fn detect_completion_shell(shell_path: Option<&str>) -> Option<CompletionShell> {
    let shell = Path::new(shell_path.unwrap_or_default())
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase();
    match shell.as_str() {
        "bash" => Some(CompletionShell::Bash),
        "zsh" => Some(CompletionShell::Zsh),
        "fish" => Some(CompletionShell::Fish),
        "powershell" | "pwsh" => Some(CompletionShell::Powershell),
        _ => None,
    }
}

pub(crate) fn install_zsh_completion() -> anyhow::Result<()> {
    for candidate in zsh_completion_install_candidates() {
        let dest = candidate.dir.join("_cw");
        if write_completion_file(&dest, CompletionShell::Zsh).is_err() {
            continue;
        }
        eprintln!("zsh completion installed: {}", dest.display());
        if !candidate.autoload {
            eprintln!("\n{}", candidate.hint);
            eprintln!("\nThen start a new shell or run: source ~/.zshrc");
        } else {
            eprintln!("Start a new shell to activate, or run: source ~/.zshrc");
        }
        return Ok(());
    }

    eprintln!("Could not find a writable zsh completion directory.");
    eprintln!("Add this to ~/.zshrc:\n  source <(cw completion zsh)");
    Ok(())
}

pub(crate) struct ZshCompletionCandidate {
    pub(crate) dir: PathBuf,
    pub(crate) autoload: bool,
    pub(crate) hint: String,
}

pub(crate) fn zsh_completion_install_candidates() -> Vec<ZshCompletionCandidate> {
    let mut candidates = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut add = |dir: PathBuf, autoload: bool, hint: String| {
        if dir.as_os_str().is_empty() || !seen.insert(dir.clone()) {
            return;
        }
        candidates.push(ZshCompletionCandidate {
            dir,
            autoload,
            hint,
        });
    };

    if let Some(prefix) = brew_prefix() {
        add(prefix.join("share/zsh/site-functions"), true, String::new());
    }
    add(
        PathBuf::from("/usr/local/share/zsh/site-functions"),
        true,
        String::new(),
    );
    add(
        PathBuf::from("/usr/share/zsh/site-functions"),
        true,
        String::new(),
    );
    if let Some(zsh_dir) = env::var_os("ZSH") {
        add(
            PathBuf::from(zsh_dir).join("completions"),
            true,
            String::new(),
        );
    }
    if let Some(home) = home_dir() {
        add(
            home.join(".zfunc"),
            false,
            "Add these lines to ~/.zshrc (before compinit):\n  fpath=(~/.zfunc $fpath)\n  autoload -Uz compinit && compinit".to_string(),
        );
    }

    candidates
}

pub(crate) fn install_bash_completion() -> anyhow::Result<()> {
    let mut candidates = Vec::new();
    if let Some(prefix) = brew_prefix() {
        candidates.push((prefix.join("etc/bash_completion.d"), true, String::new()));
    }
    if let Some(home) = home_dir() {
        candidates.push((
            home.join(".bash_completion.d"),
            false,
            "Add to ~/.bashrc:\n  source ~/.bash_completion.d/cw".to_string(),
        ));
    }

    for (dir, autoload, hint) in candidates {
        let dest = dir.join("cw");
        if write_completion_file(&dest, CompletionShell::Bash).is_err() {
            continue;
        }
        eprintln!("bash completion installed: {}", dest.display());
        if !autoload {
            eprintln!("\n{hint}");
            eprintln!("\nThen start a new shell or run: source ~/.bashrc");
        } else {
            eprintln!("Start a new shell to activate.");
        }
        return Ok(());
    }

    eprintln!("Could not find a writable bash completion directory.");
    eprintln!("Add to ~/.bashrc:\n  source <(cw completion bash)");
    Ok(())
}

pub(crate) fn install_fish_completion() -> anyhow::Result<()> {
    let home = home_dir().context("$HOME is required to install fish completion")?;
    let dest = home.join(".config/fish/completions/cw.fish");
    write_completion_file(&dest, CompletionShell::Fish)
        .with_context(|| format!("installing fish completion to {}", dest.display()))?;
    eprintln!("fish completion installed: {}", dest.display());
    eprintln!("Start a new shell to activate (fish auto-loads completions).");
    Ok(())
}

pub(crate) fn write_completion_file(path: &Path, shell: CompletionShell) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("completion path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    fs::write(path, completion_script(shell))?;
    Ok(())
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

pub(crate) fn brew_prefix() -> Option<PathBuf> {
    let output = std::process::Command::new("brew")
        .arg("--prefix")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8(output.stdout).ok()?;
    let prefix = prefix.trim();
    if prefix.is_empty() {
        None
    } else {
        Some(PathBuf::from(prefix))
    }
}

impl CompletionShell {
    pub(crate) fn name(self) -> &'static str {
        match self {
            CompletionShell::Bash => "bash",
            CompletionShell::Zsh => "zsh",
            CompletionShell::Fish => "fish",
            CompletionShell::Powershell => "powershell",
        }
    }

    pub(crate) fn clap_shell(self) -> Shell {
        match self {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
        }
    }
}
