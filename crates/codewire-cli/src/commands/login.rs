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
    let (server_url, sandbox) = resolve_login_server(globals, &paths, &env);
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
    // Say where before waiting, and wait a bounded time (#4598).
    let host = server_host(&server_url);
    if sandbox {
        eprintln!("Connecting to {host} (this sandbox's server)…");
        eprintln!("{SANDBOX_SIGN_IN_WARNING}");
    } else {
        eprintln!("Connecting to {host}…");
    }
    let client = match tokio::time::timeout(
        LOGIN_REACH_TIMEOUT,
        OAuthClient::discover_with_http(&server_url, http),
    )
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => return Err(login_reach_error(error, &host, ca.is_some())),
        Err(_) => {
            return Err(unreachable(
                &host,
                &format!("no answer within {} s", LOGIN_REACH_TIMEOUT.as_secs()),
            ));
        }
    };

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
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprintln!("{}", login_outcome(&org_resolution, &orgs, style));
    Ok(())
}

/// What `cw login` says once the sign-in is saved. The sign-in has
/// succeeded by then, so nothing here is an error: an account in no
/// organization yet is a new invitee's normal state (#4530), and one in
/// several with no terminal to ask at gets the command that picks one
/// (#5873; journey `login-default-org`).
pub(super) fn login_outcome(
    resolution: &LoginOrgResolution,
    orgs: &[OrgWithRole],
    style: crate::output::Style,
) -> String {
    match resolution {
        LoginOrgResolution::Selected(org) => format!("Default org: {} ({}).", org.name, org.slug),
        // The same words as `cw ls`, `cw org list` and a cloud create (#4592).
        LoginOrgResolution::NoOrganizations => {
            format!("{}.", super::sentence(&super::NoOrganization.to_string()))
        }
        LoginOrgResolution::SelectionRequired => format!(
            "You're in {} organizations and none is your default yet.\n{} cw org set {}",
            orgs.len(),
            style.status(crate::output::Status::Next),
            orgs.first().map_or("SLUG", |org| org.slug.as_str()),
        ),
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
/// How long `cw login` waits for the server's first answer.
const LOGIN_REACH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// The host a server URL names, as messages say it.
fn server_host(server_url: &str) -> String {
    url::Url::parse(server_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| server_url.to_owned())
}

/// The server could not be reached: one sentence, and what to do (#4598).
fn unreachable(host: &str, cause: &str) -> anyhow::Error {
    crate::error_report::with_next_step(
        anyhow::anyhow!("couldn't reach {host} ({cause})"),
        "check your network, or name another server with `cw login --server URL`",
    )
}

/// Why discovery failed, in the user's terms: a certificate it refused, a
/// server it could not reach, or the server's own answer.
fn login_reach_error(
    error: codewire_client::AuthClientError,
    host: &str,
    pinned: bool,
) -> anyhow::Error {
    if let codewire_client::AuthClientError::Request(request) = &error
        && !codewire_client::DeploymentCa::refused_certificate(request)
        // Only a connection that never opened. A server that answered
        // and then failed the request was reached (#4658 review).
        && (request.is_connect() || request.is_timeout())
    {
        let cause = if request.is_timeout() {
            "it didn't answer in time".to_owned()
        } else {
            let mut cause: &dyn std::error::Error = request;
            while let Some(source) = cause.source() {
                cause = source;
            }
            cause.to_string()
        };
        return unreachable(host, &cause);
    }
    login_tls_hint(error, pinned).context(format!("no Codewire server answered at {host}"))
}

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

#[cfg(test)]
mod reach_tests {
    use super::*;

    #[test]
    fn an_unreachable_server_is_one_sentence_with_what_to_do() {
        // #4598: named before the wait, then one sentence and a next step.
        assert_eq!(
            server_host("https://codewire.example:8443/x"),
            "codewire.example"
        );
        assert_eq!(server_host("not a url"), "not a url");
        let error = unreachable("10.255.255.1", "no answer within 20 s");
        assert_eq!(
            format!("{error:#}"),
            "check your network, or name another server with `cw login --server URL`: \
             couldn't reach 10.255.255.1 (no answer within 20 s)"
        );
        assert_eq!(
            error.to_string(),
            "check your network, or name another server with `cw login --server URL`",
            "the next step is the outer layer the printer lifts out"
        );
        assert_eq!(LOGIN_REACH_TIMEOUT.as_secs(), 20);
    }

    /// A refused port is unreachable; a server that accepts the connection
    /// and then closes it was reached, so it is not called unreachable.
    #[tokio::test]
    async fn only_a_connection_that_never_opened_is_unreachable() {
        let get = |port: u16| async move {
            let error = reqwest::Client::new()
                .get(format!("http://127.0.0.1:{port}/"))
                .send()
                .await
                .unwrap_err();
            login_reach_error(error.into(), "127.0.0.1", false).to_string()
        };
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(
            get(refused_port).await.starts_with("check your network"),
            "a refused port is unreachable"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hang_up = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let answered = get(port).await;
        hang_up.await.unwrap();
        assert_eq!(answered, "no Codewire server answered at 127.0.0.1");
    }
}
