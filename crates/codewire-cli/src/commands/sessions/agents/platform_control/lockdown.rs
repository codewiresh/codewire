//! The managed-only login lockdown of a hosted managed agent.
//!
//! The agent runs in the Sandbox session environment its driver was started
//! with. The shared `codewire-access` projection gives it the Git route, the
//! SSH signer socket and the provider variables exactly as an interactive
//! session has them, so this module sets none of them. It holds only what
//! keeps the agent on the selected broker route instead of a login saved in
//! the Sandbox: its own private Codex or Claude home with exact configuration,
//! and fixed arguments. It never opens `~/.codex`, `~/.claude`, `auth.json` or
//! the user's agent settings.
use super::*;
const CODEX_CONFIG: &str = concat!(
    "model_provider = \"codewire_platform_api\"\n",
    "forced_login_method = \"api\"\n",
    "cli_auth_credentials_store = \"file\"\n",
    "[model_providers.codewire_platform_api]\n",
    "name = \"Codewire Platform API\"\n",
    "base_url = \"http://127.0.0.1:38081/_codewire/openai/v1\"\n",
    "env_key = \"OPENAI_API_KEY\"\n",
    "wire_api = \"responses\"\n",
    "requires_openai_auth = false\n",
    "supports_websockets = false\n",
    "[features]\n",
    "enable_request_compression = false\n"
);
/// The Codex slot's route. It names no key, so Codex sends no credential; the
/// broker adds the owner's ChatGPT sign-in, or the API key held in that slot.
const CODEX_SLOT_CONFIG: &str = concat!(
    "model_provider = \"codewire_platform_codex\"\n",
    "forced_login_method = \"api\"\n",
    "cli_auth_credentials_store = \"file\"\n",
    "[model_providers.codewire_platform_codex]\n",
    "name = \"Codewire Platform Codex\"\n",
    "base_url = \"http://127.0.0.1:38081/v1\"\n",
    "wire_api = \"responses\"\n",
    "requires_openai_auth = false\n",
    "supports_websockets = false\n",
    "[features]\n",
    "enable_request_compression = false\n"
);
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
    let bytes = match (config.agent, route) {
        (AgentKind::Codex, Route::OpenAi) => CODEX_CONFIG.as_bytes(),
        (AgentKind::Codex, Route::Codex) => CODEX_SLOT_CONFIG.as_bytes(),
        (AgentKind::Claude, Route::Anthropic) => b"{}\n".as_slice(),
        _ => anyhow::bail!("platform route serves another agent"),
    };
    let (home, file) = private_home(config.agent);
    make_directory(&stage.join(home))?;
    write_config(&stage.join(home).join(file), bytes)
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
    for (route, exact) in [
        (Route::OpenAi, CODEX_CONFIG),
        (Route::Codex, CODEX_SLOT_CONFIG),
    ] {
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
pub(super) fn arguments(route: Route) -> Vec<String> {
    match route {
        Route::Codex=>["-c","model_provider=\"codewire_platform_codex\"","-c","forced_login_method=\"api\"","-c","cli_auth_credentials_store=\"file\"","-c",
            "model_providers.codewire_platform_codex={name=\"Codewire Platform Codex\",base_url=\"http://127.0.0.1:38081/v1\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}",
            "-c","features.enable_request_compression=false"].into_iter().map(str::to_owned).collect(),
        Route::OpenAi=>["-c","model_provider=\"codewire_platform_api\"","-c","forced_login_method=\"api\"","-c","cli_auth_credentials_store=\"file\"","-c",
            "model_providers.codewire_platform_api={name=\"Codewire Platform API\",base_url=\"http://127.0.0.1:38081/_codewire/openai/v1\",env_key=\"OPENAI_API_KEY\",wire_api=\"responses\",requires_openai_auth=false,supports_websockets=false}",
            "-c","features.enable_request_compression=false"].into_iter().map(str::to_owned).collect(),
        Route::Anthropic=>["--setting-sources","","--strict-mcp-config","--mcp-config","{\"mcpServers\":{}}","--disable-slash-commands"].into_iter().map(str::to_owned).collect(),
    }
}
