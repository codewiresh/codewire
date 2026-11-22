//! `cw setup`: the cloud sign-in and organization, or with `--local` the
//! local VM runtime.

use super::*;

pub(crate) async fn handle_setup_command(globals: &Globals, args: SetupArgs) -> anyhow::Result<()> {
    match args.command {
        Some(SetupCommand::Ssh(ssh)) => return handle_config_ssh_command(ssh),
        Some(SetupCommand::Rex(rex)) => return handle_setup_rex_command(rex),
        None => {}
    }
    validate_setup_placement(&args, globals.placement)?;
    if globals.placement == Some(EnvironmentPlacement::Local) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return super::native::setup_local_runtime(args.from, args.replace).await;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("local VMs are not available on this platform");
    }
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let (server_url, sandbox) = resolve_login_server(globals, &paths, &env);
    if sandbox {
        eprintln!("Server: {server_url} (this sandbox's server)");
        eprintln!("{SANDBOX_SIGN_IN_WARNING}");
    }
    if api_key_in_use(&env) {
        anyhow::ensure!(
            args.org.is_none() && args.create_org.is_none() && args.org_slug.is_none(),
            "with CODEWIRE_API_KEY set there is no sign-in to save an organization for, so --org, --create-org and --org-slug don't apply; set CODEWIRE_ORG instead"
        );
        eprintln!("Welcome to Codewire.");
        if !sandbox {
            eprintln!("Server: {server_url}");
        }
        eprintln!("{API_KEY_IN_USE}");
        return finish_setup(args.skip_ssh);
    }
    let login_client = OAuthClient::discover(&server_url)
        .await
        .context("discover OAuth device flow")?;

    eprintln!("Welcome to Codewire.");
    if !sandbox {
        eprintln!("Server: {server_url}");
    }

    let (credentials, user) = login_with_device(&login_client).await?;
    eprintln!("Logged in as {}.", oauth_user_display_name(&user));

    save_login(&paths, &server_url, &credentials, None, &user, None)?;

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
            deployment_ca: None,
        },
    )
    .context("save config")?;

    if let Some(org) = &selected_org {
        eprintln!("Default org: {} ({}).", org.name, org.slug);
    } else {
        eprintln!("No default org selected.");
    }
    finish_setup(args.skip_ssh)
}

/// What `cw setup --cloud` says instead of a sign-in when `CODEWIRE_API_KEY`
/// is set: every command already uses that key, so a saved sign-in would
/// change nothing.
const API_KEY_IN_USE: &str =
    "Using the API key in CODEWIRE_API_KEY, so there is nothing to sign in to.";

fn api_key_in_use(env: &impl config::Env) -> bool {
    env.var(config::CODEWIRE_API_KEY_ENV)
        .is_some_and(|key| !key.trim().is_empty())
}

/// The managed SSH section, unless `--skip-ssh`, then the last line.
fn finish_setup(skip_ssh: bool) -> anyhow::Result<()> {
    if !skip_ssh {
        // Setup's own lines go to stderr, so the SSH result does too, once.
        let style = crate::output::Capabilities::from_process(crate::output::OutputMode::Text)
            .stderr_style();
        eprintln!();
        match install_default_managed_ssh_config() {
            Ok(outcome) => eprint!("{}", outcome.render(style)),
            Err(err) => eprint!("{}", render_ssh_setup_failure(&err, style)),
        }
        eprintln!();
    }

    eprintln!("Setup complete.");
    Ok(())
}

/// `cw setup --local` installs the local VM runtime; sign-in flags belong to
/// the cloud setup and the runtime flags to the local one. Checked before any
/// effect, since clap cannot relate a subcommand flag to the global
/// `--local`.
pub(crate) fn validate_setup_placement(
    args: &SetupArgs,
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<()> {
    if placement == Some(EnvironmentPlacement::Local) {
        anyhow::ensure!(
            args.org.is_none()
                && args.create_org.is_none()
                && args.org_slug.is_none()
                && !args.skip_ssh,
            "--org, --create-org, --org-slug and --skip-ssh apply to sign-in, not to `cw setup --local`"
        );
        return Ok(());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    anyhow::ensure!(
        args.from.is_none() && !args.replace,
        "--from and --replace install the local VM runtime; use `cw setup --local`"
    );
    Ok(())
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
            if !super::guided::confirm("No organizations found. Create one?")? {
                return Ok(None);
            }
            let name = super::guided::text("Organization name", None, super::guided::required)?;
            let default_slug = slugify(&name);
            let slug = super::guided::text(
                "Organization slug",
                Some(&default_slug),
                super::additions::valid_slug,
            )?;
            eprintln!("  Name          {}", progress::terminal_text(&name));
            eprintln!("  Slug          {}", progress::terminal_text(&slug));
            if !super::guided::confirm("Create organization?")? {
                return Ok(None);
            }
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
