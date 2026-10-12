//! The managed-only login lockdown of a hosted managed agent.
//!
//! The agent runs in the Sandbox session environment its driver was started
//! with. The shared `codewire-access` projection gives it the Git route, the
//! SSH signer socket and the provider variables exactly as an interactive
//! session has them, and Codex's provider configuration is that crate's too,
//! so this module names no route, URL or credential variable. It holds only
//! what keeps the agent on the selected broker route instead of a login saved
//! in the Sandbox: its own private Codex or Claude home with exact
//! configuration, and fixed arguments. It never opens `~/.codex`, `~/.claude`,
//! `auth.json` or the user's agent settings.
use super::*;
use codewire_access::{CodexProviderProjection, MANAGED_HTTP_PORT};

/// Codex's sign-in lockdown, as `(key, TOML value)`: only the configured
/// provider, never a ChatGPT login, and no operating-system credential store.
const CODEX_LOGIN_LOCKDOWN: [(&str, &str); 2] = [
    ("forced_login_method", "\"api\""),
    ("cli_auth_credentials_store", "\"file\""),
];
/// The shared provider configuration a Codex `route` names. The Codex slot's
/// names no key, so Codex sends no credential and the broker adds the owner's
/// ChatGPT sign-in, or the API key held in that slot.
fn codex_provider(route: Route) -> Option<CodexProviderProjection> {
    let provider = match route {
        Route::Codex => CodexProviderProjection::for_loopback_port(MANAGED_HTTP_PORT),
        Route::OpenAi => CodexProviderProjection::for_openai_api_loopback_port(MANAGED_HTTP_PORT),
        Route::Anthropic => return None,
    };
    Some(provider.expect("fixed managed HTTP port is unprivileged"))
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
/// The agent's private home below its driver directory, and the exact
/// configuration file in it.
fn private_home(agent: AgentKind) -> (&'static str, &'static str) {
    match agent {
        AgentKind::Codex => ("codex", "config.toml"),
        AgentKind::Claude => ("claude", "settings.json"),
    }
}
/// Write the private home for `route`, which the home then records: its exact
/// configuration names the route for the driver's lifetime.
pub(super) fn prepare(stage: &Path, config: &AgentConfig, route: Route) -> anyhow::Result<()> {
    let bytes = match (config.agent, codex_provider(route)) {
        (AgentKind::Codex, Some(provider)) => codex_config(&provider).into_bytes(),
        (AgentKind::Claude, None) => b"{}\n".to_vec(),
        _ => anyhow::bail!("platform route serves another agent"),
    };
    let (home, file) = private_home(config.agent);
    make_directory(&stage.join(home))?;
    write_config(&stage.join(home).join(file), &bytes)
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
/// Admit the private home and return the route its exact configuration names.
pub(super) fn check(dir: &Path, config: &AgentConfig) -> anyhow::Result<Route> {
    let (home, file) = private_home(config.agent);
    DirectoryPin::open(&dir.join(home))?.check()?;
    let path = dir.join(home).join(file);
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
    let route = match config.agent {
        AgentKind::Codex => codex_route(&bytes, &config.working_dir)?,
        AgentKind::Claude => (bytes == b"{}\n").then_some(Route::Anthropic),
    }
    .context("private proxy configuration differs")?;
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
/// are set over the session environment the provider inherits, and are the
/// only variables this path adds to it: the agent's own private home, so that
/// it never reads a login or settings saved in the user's, and Claude's
/// nonessential-traffic switch.
pub(super) fn environment(
    dir: &Path,
    config: &AgentConfig,
    route: Route,
) -> anyhow::Result<Vec<(String, String)>> {
    ensure!(check(dir, config)? == route, "private proxy route differs");
    let home = dir
        .join(private_home(config.agent).0)
        .to_string_lossy()
        .into_owned();
    Ok(match config.agent {
        AgentKind::Codex => vec![("CODEX_HOME".into(), home)],
        AgentKind::Claude => vec![
            ("CLAUDE_CONFIG_DIR".into(), home),
            (
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(),
                "1".into(),
            ),
        ],
    })
}
/// The fixed arguments before the driver's own. Codex gets its login lockdown
/// and the shared provider configuration again as overrides, so the provider
/// holds whatever its configuration file later contains.
pub(super) fn arguments(route: Route) -> Vec<String> {
    match codex_provider(route) {
        Some(provider) => CODEX_LOGIN_LOCKDOWN
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .chain(provider.overrides().iter().cloned())
            .flat_map(|setting| ["-c".to_owned(), setting])
            .collect(),
        None => [
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            "{\"mcpServers\":{}}",
            "--disable-slash-commands",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
}
