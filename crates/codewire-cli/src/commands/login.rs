//! `cw login`: sign in to a Codewire server with the device flow, then save
//! the sign-in and the default organization.

use super::*;

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    #[arg(long, value_name = "ID_OR_SLUG", help = "Default organization to save")]
    pub(crate) org: Option<String>,
    /// The CA that signs this server's HTTPS certificate, for a self-hosted
    /// server with a private certificate. It is copied into cw's config and
    /// trusted for this server's host alone, never the public CAs as well.
    #[arg(long, value_name = "PEM_FILE")]
    pub(crate) ca_file: Option<std::path::PathBuf>,
}

pub(crate) async fn handle_login_command(globals: &Globals, args: LoginArgs) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let server_url = resolve_login_server_url(globals, &paths, &env);
    let configured_org = saved_login_default_org(&paths, &server_url);
    let ca = args
        .ca_file
        .as_deref()
        .map(config::read_ca_file)
        .transpose()?;
    let previous_pin = config::load_platform_config(&paths.platform_config_dir)
        .ok()
        .filter(|saved| config::same_server_url(&saved.server_url, &server_url))
        .and_then(|saved| saved.deployment_ca);
    let pinned_platform =
        config::ResolvedPlatformConfig::static_token(&server_url, "", false, None)
            .with_deployment_ca(ca.as_ref().map(|(ca, _)| ca.clone()));
    let http = pinned_platform
        .client_config()?
        .http_client_builder()?
        .build()
        .context("build the HTTP client")?;
    let client = OAuthClient::discover_with_http(&server_url, http)
        .await
        .map_err(|error| login_tls_hint(error, ca.is_some()))
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
    )
    .with_deployment_ca(pinned_platform.deployment_ca().cloned());
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

    let pin = ca
        .map(|(ca, pem)| config::save_deployment_ca(&paths.platform_config_dir, &ca, &pem))
        .transpose()?;
    save_login(
        &paths,
        &server_url,
        &credentials,
        default_org,
        &user,
        pin.as_ref(),
    )?;
    if pin.is_none() {
        config::delete_deployment_ca(&paths.platform_config_dir)?;
    }
    eprintln!("Logged in as {}.", oauth_user_display_name(&user));
    report_pin(&server_url, previous_pin.as_ref(), pin.as_ref());
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

/// Say which CA this login pinned, and what it replaced.
fn report_pin(
    server_url: &str,
    previous: Option<&config::PinnedCa>,
    pin: Option<&config::PinnedCa>,
) {
    match (previous, pin) {
        (_, Some(pin)) if previous == Some(pin) => {
            eprintln!("CA for {server_url}: unchanged.");
        }
        (_, Some(pin)) => {
            if let Some(previous) = previous {
                eprintln!("CA for {server_url} replaced. Was:");
                for fingerprint in &previous.fingerprints {
                    eprintln!("  SHA-256 {fingerprint}");
                }
                eprintln!("Now:");
            } else {
                eprintln!("CA pinned for {server_url}:");
            }
            for fingerprint in &pin.fingerprints {
                eprintln!("  SHA-256 {fingerprint}");
            }
        }
        (Some(previous), None) => {
            eprintln!("CA for {server_url} removed; the public CAs verify it now. Was:");
            for fingerprint in &previous.fingerprints {
                eprintln!("  SHA-256 {fingerprint}");
            }
        }
        (None, None) => {}
    }
}

/// A certificate the server's host could not be verified with: say which
/// option fixes it.
fn login_tls_hint(error: codewire_client::AuthClientError, pinned: bool) -> anyhow::Error {
    let certificate = matches!(&error, codewire_client::AuthClientError::Request(request)
        if codewire_client::DeploymentCa::refused_certificate(request));
    match (certificate, pinned) {
        (true, false) => anyhow::Error::new(error).context(
            "the server's certificate is not from a public CA; if it is a self-hosted server with its own CA, pass that CA with `cw login --ca-file`",
        ),
        (true, true) => anyhow::Error::new(error)
            .context("the server's certificate is not signed by the CA given with --ca-file"),
        (false, _) => anyhow::Error::new(error),
    }
}
