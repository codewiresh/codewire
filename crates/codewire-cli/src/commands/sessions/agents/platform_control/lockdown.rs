//! The managed-only login lockdown of a hosted managed Codex agent.
//!
//! A managed agent runs in the Sandbox session environment its driver was
//! started with. The shared `codewire-access` projection gives it the Git
//! route, the SSH signer socket and the provider variables exactly as an
//! interactive session has them, and Codex's provider configuration is that
//! crate's too, so this module names no route, URL or credential variable.
//!
//! Claude needs no lockdown and has none: the session's provider variables
//! outrank a login saved in the Sandbox, so a managed Claude agent runs as
//! `claude` does for the user there, with their settings.
//!
//! Codex has no such precedence. `~/.codex` may hold the user's own login or
//! the delivered one, so a managed Codex agent gets its own private Codex home
//! with exact configuration and fixed arguments, and never opens `~/.codex` or
//! `auth.json`.
use super::*;
use codewire_access::{CodexProviderProjection, ManagedCredentialClient};

/// Codex's sign-in lockdown, as `(key, TOML value)`: only the configured
/// provider, never a ChatGPT login, and no operating-system credential store.
const CODEX_LOGIN_LOCKDOWN: [(&str, &str); 2] = [
    ("forced_login_method", "\"api\""),
    ("cli_auth_credentials_store", "\"file\""),
];
/// The shared provider configuration a Codex `route` names, the same one a
/// local VM's native Codex home holds for that client
/// ([`CodexProviderProjection::for_managed_client`]). The Codex slot's names
/// no key, so Codex sends no credential and the broker adds the owner's
/// ChatGPT sign-in, or the API key held in that slot.
fn codex_provider(route: Route) -> Option<CodexProviderProjection> {
    CodexProviderProjection::for_managed_client(match route {
        Route::Codex => ManagedCredentialClient::Codex,
        Route::OpenAi => ManagedCredentialClient::OpenAi,
        Route::Anthropic => return None,
    })
}
/// The private Codex configuration: the login lockdown, then the shared
/// provider configuration byte for byte.
fn codex_config(provider: &CodexProviderProjection) -> String {
    let mut config: String = CODEX_LOGIN_LOCKDOWN
        .iter()
        .map(|(key, value)| format!("{key} = {value}\n"))
        .collect();
    config.push_str(provider.config_toml());
    config
}
fn write_config(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::File::open(path.parent().context("proxy config parent")?)?.sync_all()?;
    Ok(())
}
/// Codex's private home below its driver directory, and the exact
/// configuration file in it.
const CODEX_HOME: &str = "codex";
const CODEX_CONFIG_FILE: &str = "config.toml";
/// Write Codex's private home for `route`, which the home then records: its
/// exact configuration names the route for the driver's lifetime. Claude has
/// one route and nothing is written for it.
pub(super) fn prepare(stage: &Path, config: &AgentConfig, route: Route) -> anyhow::Result<()> {
    match (config.agent, codex_provider(route)) {
        (AgentKind::Codex, Some(provider)) => {
            make_directory(&stage.join(CODEX_HOME))?;
            write_config(
                &stage.join(CODEX_HOME).join(CODEX_CONFIG_FILE),
                codex_config(&provider).as_bytes(),
            )
        }
        (AgentKind::Claude, None) => Ok(()),
        _ => anyhow::bail!("platform route serves another agent"),
    }
}
/// The route an exact private Codex configuration names, if any.
fn codex_route(bytes: &[u8], working_dir: &str) -> anyhow::Result<Option<Route>> {
    ensure!(
        !working_dir.is_empty()
            && working_dir.len() <= 4096
            && Path::new(working_dir).is_absolute()
            && !working_dir.chars().any(char::is_control),
        "invalid private proxy working directory"
    );
    // Codex adds this one project-trust entry to its own private home. Admit
    // only the authenticated launch directory; provider/features stay exact.
    let quoted = serde_json::to_string(working_dir)?;
    for route in [Route::OpenAi, Route::Codex] {
        let exact = codex_config(&codex_provider(route).context("Codex route")?);
        let trusted = format!("{exact}\n[projects.{quoted}]\ntrust_level = \"trusted\"\n");
        if bytes == exact.as_bytes() || bytes == trusted.as_bytes() {
            return Ok(Some(route));
        }
    }
    Ok(None)
}
/// The driver's route. For Codex, admit the private home and return the route
/// its exact configuration names; Claude's one route needs no record.
pub(super) fn check(dir: &Path, config: &AgentConfig) -> anyhow::Result<Route> {
    if config.agent == AgentKind::Claude {
        return Ok(Route::Anthropic);
    }
    DirectoryPin::open(&dir.join(CODEX_HOME))?.check()?;
    let path = dir.join(CODEX_HOME).join(CODEX_CONFIG_FILE);
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == euid()
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() <= 8192,
        "private proxy configuration differs"
    );
    let mut bytes = Vec::new();
    (&mut f).take(8193).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "private proxy configuration differs");
    let route =
        codex_route(&bytes, &config.working_dir)?.context("private proxy configuration differs")?;
    ensure!(
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ) == (
            f.metadata()?.dev(),
            f.metadata()?.ino(),
            f.metadata()?.mode(),
            f.metadata()?.len(),
            f.metadata()?.mtime(),
            f.metadata()?.mtime_nsec(),
            f.metadata()?.ctime(),
            f.metadata()?.ctime_nsec()
        ),
        "private proxy configuration changed"
    );
    let named = fs::symlink_metadata(path)?;
    ensure!(
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ) == (
            named.dev(),
            named.ino(),
            named.mode(),
            named.len(),
            named.mtime(),
            named.mtime_nsec(),
            named.ctime(),
            named.ctime_nsec()
        ),
        "private proxy configuration changed"
    );
    Ok(route)
}
/// The lockdown variables for `route`, which the private home must name. They
/// are set over the session environment the provider inherits and are the
/// only variables this path adds to it: Codex's own private home, so that it
/// never reads a login saved in the user's. Claude gets none.
pub(super) fn environment(
    dir: &Path,
    config: &AgentConfig,
    route: Route,
) -> anyhow::Result<Vec<(String, String)>> {
    ensure!(check(dir, config)? == route, "private proxy route differs");
    Ok(match config.agent {
        AgentKind::Codex => vec![(
            "CODEX_HOME".into(),
            dir.join(CODEX_HOME).to_string_lossy().into_owned(),
        )],
        AgentKind::Claude => Vec::new(),
        AgentKind::Noel => anyhow::bail!("{NOEL_HOST_ONLY}"),
    })
}
/// The fixed arguments before the driver's own. Codex gets its login lockdown
/// and the shared provider configuration again as overrides, so the provider
/// holds whatever its configuration file later contains. Claude gets none.
pub(super) fn arguments(route: Route) -> Vec<String> {
    match codex_provider(route) {
        Some(provider) => CODEX_LOGIN_LOCKDOWN
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .chain(provider.overrides().iter().cloned())
            .flat_map(|setting| ["-c".to_owned(), setting])
            .collect(),
        None => Vec::new(),
    }
}
