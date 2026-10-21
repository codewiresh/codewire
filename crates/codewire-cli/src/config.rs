use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use codewire_client::{
    FileCredentialStore, OAuthClient, RefreshingTokenProvider, StaticTokenProvider, TokenProvider,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub mod selection;

pub const CW_CONFIG_DIR_ENV: &str = "CW_CONFIG_DIR";
pub const CW_MESH_DATA_DIR_ENV: &str = "CW_MESH_DATA_DIR";
pub const CODEWIRE_SERVER_URL_ENV: &str = "CODEWIRE_SERVER_URL";
pub const CODEWIRE_API_KEY_ENV: &str = "CODEWIRE_API_KEY";
pub const CODEWIRE_MESH_URL_ENV: &str = "CODEWIRE_MESH_URL";
pub const CODEWIRE_MESH_AUTH_TOKEN_ENV: &str = "CODEWIRE_MESH_AUTH_TOKEN";
pub const CODEWIRE_MESH_NETWORK_ENV: &str = "CODEWIRE_MESH_NETWORK";
pub const CODEWIRE_MESH_INVITE_CODE_ENV: &str = "CODEWIRE_MESH_INVITE_CODE";
pub const CODEWIRE_NODE_NAME_ENV: &str = "CODEWIRE_NODE_NAME";

pub trait Env {
    fn var(&self, key: &str) -> Option<String>;

    fn checked_var(&self, key: &str) -> Result<Option<String>, std::env::VarError> {
        Ok(self.var(key))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OsEnv;

impl Env for OsEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn checked_var(&self, key: &str) -> Result<Option<String>, std::env::VarError> {
        match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MapEnv {
    vars: HashMap<String, String>,
}

impl MapEnv {
    pub fn new(vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        Self {
            vars: vars
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }
}

impl Env for MapEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvePaths {
    pub platform_config_dir: PathBuf,
    pub mesh_data_dir: PathBuf,
}

impl ResolvePaths {
    pub fn from_env(env: &impl Env) -> Result<Self, ConfigError> {
        Self::from_home_and_env(home_dir(env), env)
    }

    pub fn from_home_and_env(home: PathBuf, env: &impl Env) -> Result<Self, ConfigError> {
        let mesh_data_dir = match env
            .checked_var(CW_MESH_DATA_DIR_ENV)
            .map_err(|_| ConfigError::InvalidMeshDataDirectory)?
        {
            None => home.join(".codewire"),
            Some(value) => {
                let path = PathBuf::from(&value);
                // Check raw components before Path normalizes away '.'. Resolving
                // paths has no filesystem effects and never repairs ownership.
                if value.is_empty()
                    || value.len() > 4096
                    || value.chars().any(char::is_control)
                    || value.split('/').any(|part| matches!(part, "." | ".."))
                    || !path.is_absolute()
                    || path.parent().is_none()
                {
                    return Err(ConfigError::InvalidMeshDataDirectory);
                }
                path
            }
        };
        let platform_config_dir = env
            .var(CW_CONFIG_DIR_ENV)
            .and_then(non_empty)
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config").join("cw"));
        Ok(Self {
            platform_config_dir,
            mesh_data_dir,
        })
    }
}

fn home_dir(env: &impl Env) -> PathBuf {
    env.var("HOME")
        .and_then(non_empty)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/.codewire-home"))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlatformConfig {
    pub server_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_org: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformResolveOptions {
    pub server_url: Option<String>,
}

#[derive(Clone)]
pub struct ResolvedPlatformConfig {
    pub server_url: String,
    pub session_token: String,
    pub used_config_token: bool,
    pub oauth_credentials_path: Option<PathBuf>,
    pub default_org: Option<String>,
    token_provider_cache: Arc<std::sync::OnceLock<Result<Arc<dyn TokenProvider>, String>>>,
}

impl ResolvedPlatformConfig {
    fn new(
        server_url: String,
        session_token: String,
        used_config_token: bool,
        oauth_credentials_path: Option<PathBuf>,
        default_org: Option<String>,
    ) -> Self {
        Self {
            server_url,
            session_token,
            used_config_token,
            oauth_credentials_path,
            default_org,
            token_provider_cache: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn static_token(
        server_url: impl Into<String>,
        session_token: impl Into<String>,
        used_config_token: bool,
        default_org: Option<String>,
    ) -> Self {
        Self::new(
            server_url.into(),
            session_token.into(),
            used_config_token,
            None,
            default_org,
        )
    }

    pub fn oauth_credentials(
        server_url: impl Into<String>,
        credentials_path: PathBuf,
        default_org: Option<String>,
    ) -> Self {
        Self::new(
            server_url.into(),
            String::new(),
            true,
            Some(credentials_path),
            default_org,
        )
    }

    /// Build the one shared bearer provider for every generated Connect
    /// facade. Explicit tokens/API keys stay static; saved native OAuth
    /// credentials refresh and persist atomically through codewire-client.
    pub fn token_provider(&self) -> anyhow::Result<Arc<dyn TokenProvider>> {
        self.token_provider_cache
            .get_or_init(|| {
                if let Some(path) = &self.oauth_credentials_path {
                    let client = OAuthClient::for_server_url(&self.server_url)
                        .map_err(|error| error.to_string())?;
                    let provider =
                        RefreshingTokenProvider::from_store(client, FileCredentialStore::at(path))
                            .map_err(|error| error.to_string())?;
                    return Ok(Arc::new(provider));
                }
                StaticTokenProvider::new(self.session_token.clone())
                    .map(|provider| Arc::new(provider) as Arc<dyn TokenProvider>)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map(Arc::clone)
            .map_err(|error| anyhow::anyhow!(error.to_owned()))
    }
}

impl std::fmt::Debug for ResolvedPlatformConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedPlatformConfig")
            .field("server_url", &self.server_url)
            .field("session_token", &"[REDACTED]")
            .field("used_config_token", &self.used_config_token)
            .field("oauth_credentials_path", &self.oauth_credentials_path)
            .field("default_org", &self.default_org)
            .finish()
    }
}

impl PartialEq for ResolvedPlatformConfig {
    fn eq(&self, other: &Self) -> bool {
        self.server_url == other.server_url
            && self.session_token == other.session_token
            && self.used_config_token == other.used_config_token
            && self.oauth_credentials_path == other.oauth_credentials_path
            && self.default_org == other.default_org
    }
}

impl Eq for ResolvedPlatformConfig {}

/// Why the saved platform config could not be used, named once beside "no
/// server" or "not logged in". No config file at all is the ordinary state
/// before `cw login`, so it adds nothing to the message.
fn config_note(cause: Option<&ConfigError>) -> String {
    match cause {
        None => String::new(),
        Some(ConfigError::ReadConfig { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            String::new()
        }
        Some(error) => format!(": {error}"),
    }
}

pub fn oauth_credentials_path(config_dir: &Path) -> PathBuf {
    config_dir.join("credentials.json")
}

pub fn resolve_platform(
    opts: PlatformResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<ResolvedPlatformConfig, ConfigError> {
    let config_result = load_platform_config(&paths.platform_config_dir);
    let explicit_server = trim_opt(opts.server_url);
    let env_server = trim_opt(env.var(CODEWIRE_SERVER_URL_ENV));
    let server_from_override = explicit_server.is_some() || env_server.is_some();

    let mut server_url = explicit_server.or(env_server);
    if server_url.is_none()
        && let Ok(config) = &config_result
    {
        server_url = non_empty(normalize_server_url(&config.server_url));
    }
    let server_url = match server_url {
        Some(server_url) => server_url,
        None => {
            return Err(ConfigError::NoPlatformServer {
                cause: config_result.err().map(Box::new),
            });
        }
    };

    let token = trim_opt(env.var(CODEWIRE_API_KEY_ENV));
    let mut used_config_token = false;
    let mut oauth_credential_file = None;
    if token.is_none()
        && let Ok(config) = &config_result
        && (!server_from_override || same_server_url(&config.server_url, &server_url))
    {
        let credentials_path = oauth_credentials_path(&paths.platform_config_dir);
        if credentials_path.is_file() {
            oauth_credential_file = Some(credentials_path);
            used_config_token = true;
        }
    }

    let token = match (token, oauth_credential_file.is_some()) {
        (Some(token), _) => token,
        (None, true) => String::new(),
        (None, false) => {
            if server_from_override
                && let Ok(config) = &config_result
                && !same_server_url(&config.server_url, &server_url)
            {
                return Err(ConfigError::PlatformServerMismatch {
                    requested: server_url,
                    saved: normalize_server_url(&config.server_url),
                });
            }
            return Err(ConfigError::NoPlatformToken {
                cause: config_result.err().map(Box::new),
            });
        }
    };

    let default_org = config_result
        .ok()
        .and_then(|config| non_empty(config.default_org.trim().to_string()));

    Ok(ResolvedPlatformConfig::new(
        server_url,
        token,
        used_config_token,
        oauth_credential_file,
        default_org,
    ))
}

/// The selected platform server without requiring a sign-in: `--server`,
/// then `CODEWIRE_SERVER_URL`, then the saved login's server.
pub fn resolve_platform_server_url(
    explicit: Option<String>,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Option<String> {
    trim_opt(explicit)
        .or_else(|| trim_opt(env.var(CODEWIRE_SERVER_URL_ENV)))
        .or_else(|| {
            load_platform_config(&paths.platform_config_dir)
                .ok()
                .and_then(|config| non_empty(normalize_server_url(&config.server_url)))
        })
}

pub fn load_platform_config(config_dir: &Path) -> Result<PlatformConfig, ConfigError> {
    let path = config_dir.join("config.json");
    let data = fs::read(&path).map_err(|source| ConfigError::ReadConfig {
        path: path.clone(),
        source,
    })?;
    let config: PlatformConfig =
        serde_json::from_slice(&data).map_err(|source| ConfigError::ParsePlatform {
            path: path.clone(),
            source,
        })?;
    if config.server_url.trim().is_empty() {
        return Err(ConfigError::IncompletePlatformConfig { path });
    }
    Ok(config)
}

pub fn save_platform_config(config_dir: &Path, config: &PlatformConfig) -> Result<(), ConfigError> {
    let path = config_dir.join("config.json");
    if config.server_url.trim().is_empty() {
        return Err(ConfigError::IncompletePlatformConfig { path });
    }

    fs::create_dir_all(config_dir).map_err(|source| ConfigError::CreateConfigDir {
        path: config_dir.to_path_buf(),
        source,
    })?;
    harden_dir(config_dir)?;

    let mut data =
        serde_json::to_vec_pretty(config).map_err(|source| ConfigError::SerializePlatform {
            path: path.clone(),
            source,
        })?;
    data.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|source| ConfigError::WriteConfig {
            path: path.clone(),
            source,
        })?;
    harden_file(&path)?;
    file.write_all(&data)
        .map_err(|source| ConfigError::WriteConfig { path, source })
}

pub fn delete_platform_config(config_dir: &Path) -> Result<(), ConfigError> {
    let path = config_dir.join("config.json");
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::WriteConfig { path, source }),
    }
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_auth_token: Option<String>,
    /// Parse-only: an older cw saved the network selection here, without
    /// its Mesh. The selection now lives in `network_selection.json`; the
    /// next write of this file drops the key.
    #[serde(default, skip_serializing)]
    pub mesh_selected_network: Option<String>,
    /// Parse-only, with [`MeshConfig::mesh_selected_network`].
    #[serde(default, skip_serializing)]
    pub mesh_auto_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_node_network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_target: Option<CurrentTargetConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<MeshNodeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_identity: Option<LocalMeshIdentity>,
    /// Where `--local` secrets and credentials are stored: "keychain"
    /// (default) or "file" on macOS, "secret-service" on Linux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_credential_store: Option<String>,
}

impl std::fmt::Debug for MeshConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshConfig")
            .field("mesh_url", &self.mesh_url)
            .field(
                "mesh_auth_token",
                &self.mesh_auth_token.as_ref().map(|_| "[redacted]"),
            )
            .field("mesh_selected_network", &self.mesh_selected_network)
            .field("mesh_auto_connect", &self.mesh_auto_connect)
            .field("mesh_node_network", &self.mesh_node_network)
            .field("current_target", &self.current_target)
            .field("node", &self.node)
            .field("local_identity", &self.local_identity)
            .field("local_credential_store", &self.local_credential_store)
            .finish()
    }
}

/// Durable standalone-Mesh identity. The file containing this record is
/// created mode 0600; Debug intentionally never displays the raw credential.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalMeshIdentity {
    pub organization_id: String,
    pub api_key: String,
}

impl std::fmt::Debug for LocalMeshIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalMeshIdentity")
            .field("organization_id", &self.organization_id)
            .field("api_key", &"[redacted]")
            .finish()
    }
}

impl LocalMeshIdentity {
    pub fn api_key_hash(&self) -> String {
        sha256_hex(&self.api_key)
    }

    pub(crate) fn is_complete(&self) -> bool {
        [self.organization_id.as_str(), self.api_key.as_str()]
            .iter()
            .all(|value| !value.trim().is_empty())
            && self.api_key.starts_with("cw_")
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshNodeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentTargetConfig {
    pub kind: String,
    #[serde(rename = "ref")]
    pub target_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

pub fn canonical_agent_id(raw: &str) -> String {
    codewire_project::canonical_agent_id(raw)
        .ok()
        .flatten()
        .unwrap_or_else(|| raw.trim())
        .to_string()
}

pub fn display_agent_id(raw: &str) -> String {
    codewire_project::display_agent_id(raw)
        .ok()
        .flatten()
        .unwrap_or_else(|| raw.trim())
        .to_string()
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct MeshResolveOptions {
    pub mesh_url: Option<String>,
    pub auth_token: Option<String>,
    pub network_id: Option<String>,
    pub platform_server_url: Option<String>,
}

impl std::fmt::Debug for MeshResolveOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshResolveOptions")
            .field("mesh_url", &self.mesh_url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[redacted]"),
            )
            .field("network_id", &self.network_id)
            .field("platform_server_url", &self.platform_server_url)
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct ResolvedMeshConfig {
    pub mesh_url: String,
    pub selected_network: Option<String>,
    pub auth_source: MeshAuthSource,
    #[serde(skip)]
    token_provider: Arc<dyn TokenProvider>,
}

impl ResolvedMeshConfig {
    #[cfg(target_os = "linux")]
    pub(crate) fn static_token(mesh_url: String, token: &str) -> Result<Self, ConfigError> {
        Self::static_token_from(mesh_url, token, MeshAuthSource::Explicit)
    }

    /// One endpoint with one fixed bearer, recorded with where it came from.
    pub(crate) fn static_token_from(
        mesh_url: String,
        token: &str,
        auth_source: MeshAuthSource,
    ) -> Result<Self, ConfigError> {
        let token_provider = StaticTokenProvider::new(token).map_err(|_| {
            ConfigError::InvalidMeshAuth("invalid standalone credential".to_owned())
        })?;
        Ok(Self {
            mesh_url,
            selected_network: None,
            auth_source,
            token_provider: Arc::new(token_provider),
        })
    }

    pub fn auth_configured(&self) -> bool {
        true
    }

    pub fn token_provider(&self) -> Arc<dyn TokenProvider> {
        Arc::clone(&self.token_provider)
    }
}

impl std::fmt::Debug for ResolvedMeshConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedMeshConfig")
            .field("mesh_url", &self.mesh_url)
            .field("selected_network", &self.selected_network)
            .field("auth_source", &self.auth_source)
            .field("token_provider", &"[redacted]")
            .finish()
    }
}

impl PartialEq for ResolvedMeshConfig {
    fn eq(&self, other: &Self) -> bool {
        self.mesh_url == other.mesh_url
            && self.selected_network == other.selected_network
            && self.auth_source == other.auth_source
    }
}

impl Eq for ResolvedMeshConfig {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshAuthSource {
    Explicit,
    MeshEnv,
    MeshConfig,
    ApiKeyEnv,
    PlatformConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshUrlSource {
    Explicit,
    MeshEnv,
    Hosted,
}

type ResolvedMeshAuth = (Arc<dyn TokenProvider>, MeshAuthSource);

pub fn resolve_mesh(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<ResolvedMeshConfig, ConfigError> {
    let mesh_config = load_mesh_config(&paths.mesh_data_dir)?;
    let (mesh_url, mesh_url_source) = resolve_mesh_base_url_with_source(opts.clone(), paths, env)?;
    let selected_network = resolve_mesh_network(&opts, env);
    let config_auth_token = saved_mesh_value_for_selected_url(
        &mesh_url,
        mesh_url_source,
        mesh_config.mesh_url.as_deref(),
        mesh_config.mesh_auth_token.as_deref(),
    );

    let (token_provider, auth_source) = resolve_mesh_user_auth_provider(
        &mesh_url,
        opts.platform_server_url.as_deref().unwrap_or(""),
        trim_opt(opts.auth_token),
        config_auth_token,
        paths,
        env,
    )?
    .ok_or(ConfigError::NoMeshAuth)?;

    Ok(ResolvedMeshConfig {
        mesh_url,
        selected_network,
        auth_source,
        token_provider,
    })
}

pub fn resolve_mesh_with_token_provider(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
    token_provider: Arc<dyn TokenProvider>,
    auth_source: MeshAuthSource,
) -> Result<ResolvedMeshConfig, ConfigError> {
    let (mesh_url, _source) = resolve_mesh_base_url_with_source(opts.clone(), paths, env)?;
    let selected_network = resolve_mesh_network(&opts, env);
    Ok(ResolvedMeshConfig {
        mesh_url,
        selected_network,
        auth_source,
        token_provider,
    })
}

/// The network a request names: `--network`, else `CODEWIRE_MESH_NETWORK`.
/// The saved selection is scoped to one Mesh and organization, so callers
/// apply it themselves (`commands::mesh_commands::selection`).
fn resolve_mesh_network(opts: &MeshResolveOptions, env: &impl Env) -> Option<String> {
    trim_opt(opts.network_id.clone()).or_else(|| trim_opt(env.var(CODEWIRE_MESH_NETWORK_ENV)))
}

pub fn resolve_mesh_base_url(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<String, ConfigError> {
    resolve_mesh_base_url_with_source(opts, paths, env).map(|(url, _source)| url)
}

/// `--mesh-url`, then `CODEWIRE_MESH_URL`, then the selected platform's
/// hosted Mesh. The local service's saved `mesh_url` is never a default: a
/// running or stale local Mesh cannot redirect a hosted operation.
fn resolve_mesh_base_url_with_source(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<(String, MeshUrlSource), ConfigError> {
    let explicit_mesh = trim_opt(opts.mesh_url);
    let env_mesh = trim_opt(env.var(CODEWIRE_MESH_URL_ENV));
    let hosted_mesh =
        derive_hosted_mesh_url(opts.platform_server_url.as_deref().unwrap_or(""), paths);

    if let Some(mesh_url) = explicit_mesh {
        return Ok((mesh_url, MeshUrlSource::Explicit));
    }
    if let Some(mesh_url) = env_mesh {
        return Ok((mesh_url, MeshUrlSource::MeshEnv));
    }
    if let Some(mesh_url) = hosted_mesh {
        return Ok((mesh_url, MeshUrlSource::Hosted));
    }

    Err(ConfigError::NoMeshUrl)
}

fn saved_mesh_value_for_selected_url(
    mesh_url: &str,
    mesh_url_source: MeshUrlSource,
    saved_mesh_url: Option<&str>,
    saved_value: Option<&str>,
) -> Option<String> {
    let saved_value = saved_value.and_then(|value| non_empty(value.trim().to_string()))?;
    let Some(saved_mesh_url) = saved_mesh_url.and_then(|url| non_empty(url.trim().to_string()))
    else {
        return (mesh_url_source == MeshUrlSource::Hosted).then_some(saved_value);
    };
    same_mesh_url(mesh_url, &saved_mesh_url).then_some(saved_value)
}

pub fn load_mesh_config(data_dir: &Path) -> Result<MeshConfig, ConfigError> {
    let path = data_dir.join("config.toml");
    #[cfg(target_os = "linux")]
    let data = {
        let read_error = |error: anyhow::Error| ConfigError::ReadConfig {
            path: path.clone(),
            source: std::io::Error::other(error),
        };
        let Some(directory) =
            crate::commands::MeshStateDir::open(data_dir, false).map_err(read_error)?
        else {
            return Ok(MeshConfig::default());
        };
        let Some(bytes) = directory.read("config.toml").map_err(read_error)? else {
            return Ok(MeshConfig::default());
        };
        String::from_utf8(bytes).map_err(|error| ConfigError::ReadConfig {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?
    };
    #[cfg(not(target_os = "linux"))]
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(MeshConfig::default()),
        Err(source) => return Err(ConfigError::ReadConfig { path, source }),
    };
    let value: toml::Value = toml::from_str(&data).map_err(|source| ConfigError::ParseMesh {
        path: path.clone(),
        source,
    })?;
    if !matches!(value, toml::Value::Table(_)) {
        return Err(ConfigError::InvalidMeshConfigRoot { path });
    }
    value
        .try_into()
        .map_err(|source| ConfigError::ParseMesh { path, source })
}

/// Creates the one standalone-local organization and its approved machine
/// credential once, then persists them in the hardened local config. It never
/// derives identity from a network name or a hosted default.
pub fn ensure_local_mesh_identity(data_dir: &Path) -> Result<LocalMeshIdentity, ConfigError> {
    let mut config = load_mesh_config(data_dir)?;
    if let Some(identity) = config.local_identity.as_ref()
        && identity.is_complete()
    {
        return Ok(identity.clone());
    }

    let identity = new_local_mesh_identity();
    config.local_identity = Some(identity.clone());
    write_mesh_config(data_dir, &config)?;
    Ok(identity)
}

pub(crate) fn new_local_mesh_identity() -> LocalMeshIdentity {
    let mut api_key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut api_key_bytes);
    LocalMeshIdentity {
        organization_id: format!("local-org-{}", uuid::Uuid::new_v4().simple()),
        api_key: format!("cw_{}", hex_lower(&api_key_bytes)),
    }
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The network new environments join: `CODEWIRE_MESH_NETWORK`, else the
/// saved selection's name. The selection's Mesh and organization are in
/// `commands::NetworkSelection`.
pub fn selected_mesh_network(paths: &ResolvePaths, env: &impl Env) -> Option<String> {
    trim_opt(env.var(CODEWIRE_MESH_NETWORK_ENV)).or_else(|| {
        crate::commands::load_network_selection(&paths.mesh_data_dir)
            .ok()
            .flatten()
            .map(|selection| selection.network_id)
    })
}

/// Forget the local Mesh service's endpoint and key after `cw mesh down`,
/// only while they are still that service's: the durable local identity
/// stays, and an unrelated endpoint is never removed.
pub fn clear_local_mesh_connection(data_dir: &Path, base_url: &str) -> Result<(), ConfigError> {
    let config = load_mesh_config(data_dir)?;
    if !config
        .mesh_url
        .as_deref()
        .is_some_and(|saved| same_mesh_url(saved, base_url))
    {
        return Ok(());
    }
    update_mesh_config(data_dir, |config| {
        config.mesh_url = None;
        config.mesh_auth_token = None;
    })
}

pub fn save_mesh_connection(
    data_dir: &Path,
    mesh_url: &str,
    auth_token: &str,
) -> Result<(), ConfigError> {
    let mesh_url = mesh_url.trim();
    if mesh_url.is_empty() {
        return Err(ConfigError::NoMeshUrl);
    }
    let auth_token = auth_token.trim();
    if auth_token.is_empty() {
        return Err(ConfigError::NoMeshAuth);
    }
    update_mesh_config(data_dir, |config| {
        config.mesh_url = Some(mesh_url.to_string());
        config.mesh_auth_token = Some(auth_token.to_string());
    })
}

pub fn default_current_target() -> CurrentTargetConfig {
    CurrentTargetConfig {
        kind: "local".to_string(),
        target_ref: "local".to_string(),
        name: "local".to_string(),
    }
}

/// The target the current selection names, or the unset default
/// ([`default_current_target`]) when nothing is selected. See [`selection`].
pub fn current_target(data_dir: &Path) -> Result<CurrentTargetConfig, ConfigError> {
    Ok(selection::load(data_dir)?
        .map(|selected| selected.target())
        .unwrap_or_else(default_current_target))
}

pub fn load_project_document(
    path: &Path,
) -> Result<codewire_project::ProjectDocument, ConfigError> {
    let data = fs::read_to_string(path).map_err(|source| ConfigError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    codewire_project::parse_project_yaml(&data).map_err(|source| ConfigError::ParseCodewireConfig {
        path: path.to_path_buf(),
        source,
    })
}

/// Records the node this machine enrolled as. The Mesh endpoint is not
/// saved: `mesh_url` names only the local Mesh service's endpoint.
pub fn save_node_registration(
    data_dir: &Path,
    network_id: &str,
    node_name: &str,
) -> Result<(), ConfigError> {
    let network_id = network_id.trim();
    let node_name = node_name.trim();

    update_mesh_config(data_dir, |config| {
        if !network_id.is_empty() {
            config.mesh_node_network = Some(network_id.to_string());
        }
        if !node_name.is_empty() {
            config.node = Some(MeshNodeConfig {
                name: Some(node_name.to_string()),
            });
        }
    })
}

fn update_mesh_config(
    data_dir: &Path,
    update: impl FnOnce(&mut MeshConfig),
) -> Result<(), ConfigError> {
    let mut config = load_mesh_config(data_dir)?;
    update(&mut config);
    write_mesh_config(data_dir, &config)
}

fn write_mesh_config(data_dir: &Path, config: &MeshConfig) -> Result<(), ConfigError> {
    let path = data_dir.join("config.toml");
    let data = toml::to_string_pretty(config).map_err(|source| ConfigError::SerializeMesh {
        path: path.clone(),
        source,
    })?;
    #[cfg(target_os = "linux")]
    {
        let write_error = |error: anyhow::Error| ConfigError::WriteConfig {
            path: path.clone(),
            source: std::io::Error::other(error),
        };
        let directory = crate::commands::MeshStateDir::open(data_dir, true)
            .map_err(write_error)?
            .ok_or_else(|| ConfigError::WriteConfig {
                path: path.clone(),
                source: std::io::Error::other("local Mesh directory is absent"),
            })?;
        directory
            .write("config.toml", data.as_bytes())
            .map_err(write_error)
    }
    #[cfg(not(target_os = "linux"))]
    {
        fs::create_dir_all(data_dir).map_err(|source| ConfigError::CreateConfigDir {
            path: data_dir.to_path_buf(),
            source,
        })?;
        harden_dir(data_dir)?;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|source| ConfigError::WriteConfig {
                path: path.clone(),
                source,
            })?;
        harden_file(&path)?;
        file.write_all(data.as_bytes())
            .map_err(|source| ConfigError::WriteConfig { path, source })
    }
}

#[cfg(unix)]
fn harden_dir(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ConfigError::WriteConfig {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn harden_dir(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(unix)]
fn harden_file(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ConfigError::WriteConfig {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn harden_file(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

fn resolve_mesh_user_auth_provider(
    mesh_url: &str,
    platform_server_url: &str,
    explicit_token: Option<String>,
    config_token: Option<String>,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<Option<ResolvedMeshAuth>, ConfigError> {
    if let Some(token) = explicit_token {
        return static_mesh_provider(token, MeshAuthSource::Explicit).map(Some);
    }
    if let Some(token) = trim_opt(env.var(CODEWIRE_MESH_AUTH_TOKEN_ENV)) {
        return static_mesh_provider(token, MeshAuthSource::MeshEnv).map(Some);
    }

    let hosted_url = derive_hosted_mesh_url(platform_server_url, paths);
    let Some(hosted_url) = hosted_url else {
        return match config_token {
            Some(token) => static_mesh_provider(token, MeshAuthSource::MeshConfig).map(Some),
            None => Ok(None),
        };
    };
    if !same_mesh_url(mesh_url, &hosted_url) {
        return match config_token {
            Some(token) => static_mesh_provider(token, MeshAuthSource::MeshConfig).map(Some),
            None => Ok(None),
        };
    }

    if let Some(token) = trim_opt(env.var(CODEWIRE_API_KEY_ENV)) {
        return static_mesh_provider(token, MeshAuthSource::ApiKeyEnv).map(Some);
    }

    let Ok(config) = load_platform_config(&paths.platform_config_dir) else {
        return Ok(None);
    };
    if !platform_server_url.trim().is_empty()
        && !same_server_url(&config.server_url, platform_server_url)
    {
        return Ok(None);
    }
    let credentials_path = oauth_credentials_path(&paths.platform_config_dir);
    if !credentials_path.is_file() {
        return Ok(None);
    }
    let client = OAuthClient::for_server_url(&config.server_url)
        .map_err(|error| ConfigError::InvalidMeshAuth(error.to_string()))?;
    let provider =
        RefreshingTokenProvider::from_store(client, FileCredentialStore::at(credentials_path))
            .map_err(|error| ConfigError::InvalidMeshAuth(error.to_string()))?;
    Ok(Some((
        Arc::new(provider) as Arc<dyn TokenProvider>,
        MeshAuthSource::PlatformConfig,
    )))
}

fn static_mesh_provider(
    token: String,
    source: MeshAuthSource,
) -> Result<ResolvedMeshAuth, ConfigError> {
    StaticTokenProvider::new(token)
        .map(|provider| (Arc::new(provider) as Arc<dyn TokenProvider>, source))
        .map_err(|error| ConfigError::InvalidMeshAuth(error.to_string()))
}

/// The hosted Mesh of a platform server. Codewire's own servers publish it
/// at `mesh.` of their domain; any other server, such as a local Kind
/// cluster, serves the Mesh services on its own origin, where its edge
/// routes them by path (the Kind ingress and the Caddyfile).
pub fn derive_hosted_mesh_url_for_server(raw_server_url: &str) -> Option<String> {
    let server = Url::parse(raw_server_url.trim()).ok()?;
    if !matches!(server.scheme(), "http" | "https") {
        return None;
    }
    let host = match server.host_str()? {
        "codewire.sh" | "www.codewire.sh" | "app.codewire.sh" | "api.codewire.sh" => {
            "mesh.codewire.sh"
        }
        "codewire-dev.sh"
        | "www.codewire-dev.sh"
        | "app.codewire-dev.sh"
        | "api.codewire-dev.sh" => "mesh.codewire-dev.sh",
        _ => return non_empty(normalize_server_url(raw_server_url)),
    };
    Some(format!("{}://{host}", server.scheme()))
}

fn derive_hosted_mesh_url(platform_server_url: &str, paths: &ResolvePaths) -> Option<String> {
    derive_hosted_mesh_url_for_server(platform_server_url).or_else(|| {
        load_platform_config(&paths.platform_config_dir)
            .ok()
            .and_then(|config| derive_hosted_mesh_url_for_server(&config.server_url))
    })
}

pub fn normalize_server_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

pub fn same_server_url(a: &str, b: &str) -> bool {
    let left = normalize_server_url(a);
    let right = normalize_server_url(b);
    !left.is_empty() && left == right
}

pub fn same_mesh_url(a: &str, b: &str) -> bool {
    let normalize = |raw: &str| -> String {
        let raw = raw.trim();
        if raw.is_empty() {
            return String::new();
        }
        match Url::parse(raw) {
            Ok(mut url) => {
                let path = url.path().trim_end_matches('/').to_string();
                url.set_path(&path);
                url.set_query(None);
                url.set_fragment(None);
                url.to_string().trim_end_matches('/').to_string()
            }
            Err(_) => raw.trim_end_matches('/').to_string(),
        }
    };
    let left = normalize(a);
    let right = normalize(b);
    !left.is_empty() && left == right
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigReport {
    pub platform_config_dir: String,
    pub mesh_data_dir: String,
    pub platform: Option<PlatformReport>,
    pub mesh: Option<MeshReport>,
    /// The effective local protected-storage backend, or `None` when the
    /// configured value is invalid on this platform.
    pub local_credential_store: Option<String>,
}

impl ConfigReport {
    pub fn from_results(
        paths: &ResolvePaths,
        platform: Result<ResolvedPlatformConfig, ConfigError>,
        mesh: Result<ResolvedMeshConfig, ConfigError>,
        local_credential_store: Option<String>,
    ) -> Self {
        Self {
            platform_config_dir: paths.platform_config_dir.display().to_string(),
            mesh_data_dir: paths.mesh_data_dir.display().to_string(),
            platform: platform.ok().map(PlatformReport::from),
            mesh: mesh.ok().map(MeshReport::from),
            local_credential_store,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlatformReport {
    pub server_url: String,
    pub used_config_token: bool,
    pub default_org: Option<String>,
}

impl From<ResolvedPlatformConfig> for PlatformReport {
    fn from(value: ResolvedPlatformConfig) -> Self {
        Self {
            server_url: value.server_url,
            used_config_token: value.used_config_token,
            default_org: value.default_org,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshReport {
    pub mesh_url: String,
    pub selected_network: Option<String>,
    pub auth_configured: bool,
    pub auth_source: MeshAuthSource,
}

impl From<ResolvedMeshConfig> for MeshReport {
    fn from(value: ResolvedMeshConfig) -> Self {
        let auth_configured = value.auth_configured();
        Self {
            mesh_url: value.mesh_url,
            selected_network: value.selected_network,
            auth_configured,
            auth_source: value.auth_source,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "CW_MESH_DATA_DIR must be a bounded absolute non-root Unicode path without control or dot components"
    )]
    InvalidMeshDataDirectory,
    #[error("read config {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("create config dir {path}: {source}")]
    CreateConfigDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("write config {path}: {source}")]
    WriteConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse platform config {path}: {source}")]
    ParsePlatform {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("serialize platform config {path}: {source}")]
    SerializePlatform {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("parse mesh config {path}: {source}")]
    ParseMesh {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("parse codewire config {path}: {source}")]
    ParseCodewireConfig {
        path: PathBuf,
        #[source]
        source: codewire_project::ProjectError,
    },
    #[error("serialize mesh config {path}: {source}")]
    SerializeMesh {
        path: PathBuf,
        #[source]
        source: toml::ser::Error,
    },
    #[error("invalid mesh config {path}: top-level TOML value must be a table")]
    InvalidMeshConfigRoot { path: PathBuf },
    #[error("network name must be non-empty")]
    InvalidMeshSelection,
    #[error("the current environment needs a canonical ID and a name")]
    InvalidCurrentTarget,
    #[error("incomplete platform config {path}: missing server_url")]
    IncompletePlatformConfig { path: PathBuf },
    // `cause` is printed at most once, here; as a `source` the error chain
    // would print it again.
    #[error("no server configured (set --server, CODEWIRE_SERVER_URL, run 'cw setup', or run 'cw login'){}", config_note(cause.as_deref()))]
    NoPlatformServer { cause: Option<Box<ConfigError>> },
    #[error("not logged in (set CODEWIRE_API_KEY, run 'cw setup', or run 'cw login'){}", config_note(cause.as_deref()))]
    NoPlatformToken { cause: Option<Box<ConfigError>> },
    #[error(
        "not logged in for {requested} (saved config is for {saved}; set CODEWIRE_API_KEY or log in to that server)"
    )]
    PlatformServerMismatch { requested: String, saved: String },
    #[error("mesh not configured (set CODEWIRE_MESH_URL or log in to hosted Codewire)")]
    NoMeshUrl,
    #[error(
        "mesh user authentication not configured (set CODEWIRE_MESH_AUTH_TOKEN, or use 'cw login'/CODEWIRE_API_KEY for hosted Codewire)"
    )]
    NoMeshAuth,
    #[error("invalid Mesh authentication configuration: {0}")]
    InvalidMeshAuth(String),
}

fn trim_opt(value: Option<String>) -> Option<String> {
    value.and_then(|value| non_empty(value.trim().to_string()))
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(home: &Path, env: &impl Env) -> ResolvePaths {
        ResolvePaths::from_home_and_env(home.to_path_buf(), env).unwrap()
    }

    #[test]
    fn mesh_data_directory_default_preserves_home_and_platform_resolution() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([("HOME", home.path().to_str().unwrap())]);
        let paths = ResolvePaths::from_env(&env).unwrap();
        assert_eq!(paths.mesh_data_dir, home.path().join(".codewire"));
        assert_eq!(paths.platform_config_dir, home.path().join(".config/cw"));
        assert_eq!(env.var("HOME").unwrap(), home.path().to_str().unwrap());
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn mesh_data_directory_override_is_independent_and_has_no_filesystem_effects() {
        let home = tempfile::tempdir().unwrap();
        let mesh = home.path().join("isolated-mesh");
        let platform = home.path().join("isolated-platform");
        let env = MapEnv::new([
            ("HOME", home.path().to_str().unwrap()),
            (CW_CONFIG_DIR_ENV, platform.to_str().unwrap()),
            (CW_MESH_DATA_DIR_ENV, mesh.to_str().unwrap()),
        ]);
        let paths = ResolvePaths::from_env(&env).unwrap();
        assert_eq!(paths.mesh_data_dir, mesh);
        assert_eq!(paths.platform_config_dir, platform);
        assert_eq!(env.var("HOME").unwrap(), home.path().to_str().unwrap());
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn invalid_present_mesh_data_directory_never_falls_back_or_changes_state() {
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join("sentinel"), b"preserve").unwrap();
        for value in [
            "".to_owned(),
            "relative".to_owned(),
            "/".to_owned(),
            "///".to_owned(),
            "/safe/./child".to_owned(),
            "/safe/../child".to_owned(),
            "/safe/child/.".to_owned(),
            "/safe/\0child".to_owned(),
            "/safe/\nchild".to_owned(),
            "/safe/\u{7f}child".to_owned(),
            format!("/{}", "a".repeat(4096)),
        ] {
            let env = MapEnv::new([
                ("HOME", home.path().to_str().unwrap()),
                (CW_MESH_DATA_DIR_ENV, value.as_str()),
            ]);
            assert!(matches!(
                ResolvePaths::from_env(&env),
                Err(ConfigError::InvalidMeshDataDirectory)
            ));
            assert_eq!(fs::read(home.path().join("sentinel")).unwrap(), b"preserve");
            assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn mesh_data_directory_os_lookup_refuses_present_invalid_unicode() {
        use std::os::unix::ffi::OsStringExt;
        const SENTINEL: &str = "CODEWIRE_TEST_INVALID_MESH_DIRECTORY";
        if std::env::var_os(SENTINEL).is_none() {
            let name = std::thread::current().name().unwrap().to_owned();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name])
                .env(SENTINEL, "1")
                .env(
                    CW_MESH_DATA_DIR_ENV,
                    std::ffi::OsString::from_vec(vec![b'/', 0xff]),
                )
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let home = std::env::var_os("HOME");
        assert!(matches!(
            ResolvePaths::from_env(&OsEnv),
            Err(ConfigError::InvalidMeshDataDirectory)
        ));
        assert_eq!(home, std::env::var_os("HOME"));
    }

    fn write_platform_config(dir: &Path, server_url: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("config.json"),
            serde_json::json!({
                "server_url": server_url,
                "default_org": "org-default",
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_mesh_config(dir: &Path, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.toml"), body).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(dir.join("config.toml"), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }

    #[test]
    fn platform_uses_api_key_env_with_config_server() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_API_KEY_ENV, "cw_env_override"),
            (CODEWIRE_SERVER_URL_ENV, ""),
        ]);
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://example.invalid");

        let resolved = resolve_platform(PlatformResolveOptions::default(), &paths, &env).unwrap();

        assert_eq!(resolved.server_url, "https://example.invalid");
        assert_eq!(resolved.session_token, "cw_env_override");
        assert!(!resolved.used_config_token);
    }

    #[test]
    fn platform_uses_env_without_config() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_API_KEY_ENV, "cw_env_only"),
            (CODEWIRE_SERVER_URL_ENV, "https://api.codewire.test"),
        ]);
        let paths = paths(home.path(), &env);

        let resolved = resolve_platform(PlatformResolveOptions::default(), &paths, &env).unwrap();

        assert_eq!(resolved.server_url, "https://api.codewire.test");
        assert_eq!(resolved.session_token, "cw_env_only");
        assert!(!format!("{resolved:?}").contains("cw_env_only"));
    }

    #[tokio::test]
    async fn platform_uses_saved_oauth_credentials_after_process_restart() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://api.codewire.test");
        let credentials = codewire_client::OAuthCredentials::new(
            "https://api.codewire.test",
            codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "saved-access",
            "saved-refresh",
            u64::MAX,
            codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .unwrap();
        codewire_client::CredentialStore::save(
            &FileCredentialStore::new(&paths.platform_config_dir),
            &credentials,
        )
        .unwrap();

        let resolved = resolve_platform(PlatformResolveOptions::default(), &paths, &env).unwrap();

        assert!(resolved.used_config_token);
        assert_eq!(
            resolved.oauth_credentials_path.as_deref(),
            Some(oauth_credentials_path(&paths.platform_config_dir).as_path())
        );
        assert_eq!(
            resolved
                .token_provider()
                .unwrap()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "saved-access"
        );
        let first = resolved.token_provider().unwrap();
        let second = resolved.token_provider().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "one config owns one provider");
    }

    #[test]
    fn platform_rejects_mismatched_saved_config() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://codewire.sh");

        let err = resolve_platform(
            PlatformResolveOptions {
                server_url: Some("https://codewire-dev.sh".to_string()),
            },
            &paths,
            &env,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("not logged in for https://codewire-dev.sh")
        );
    }

    #[test]
    fn delete_platform_config_removes_config_and_allows_missing_file() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://codewire.sh");

        delete_platform_config(&paths.platform_config_dir).unwrap();
        assert!(!paths.platform_config_dir.join("config.json").exists());

        delete_platform_config(&paths.platform_config_dir).unwrap();
    }

    #[test]
    fn save_platform_config_writes_go_compatible_secure_json() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        save_platform_config(
            &paths.platform_config_dir,
            &PlatformConfig {
                server_url: "https://codewire.sh".to_string(),
                default_org: "org_123".to_string(),
            },
        )
        .unwrap();

        let data = fs::read_to_string(paths.platform_config_dir.join("config.json")).unwrap();
        assert!(data.ends_with('\n'));
        assert!(data.contains("\"server_url\": \"https://codewire.sh\""));
        assert!(!data.contains("session_token"));
        assert!(data.contains("\"default_org\": \"org_123\""));

        let config = load_platform_config(&paths.platform_config_dir).unwrap();
        assert_eq!(config.default_org, "org_123");
    }

    #[test]
    fn derives_hosted_mesh_url_for_platform_server() {
        assert_eq!(
            derive_hosted_mesh_url_for_server("https://api.codewire.sh/").as_deref(),
            Some("https://mesh.codewire.sh")
        );
        assert_eq!(
            derive_hosted_mesh_url_for_server("https://app.codewire-dev.sh/").as_deref(),
            Some("https://mesh.codewire-dev.sh")
        );
        assert_eq!(
            derive_hosted_mesh_url_for_server(" http://localhost:8090/ ").as_deref(),
            Some("http://localhost:8090")
        );
        assert_eq!(
            derive_hosted_mesh_url_for_server("https://example.com/base/").as_deref(),
            Some("https://example.com/base")
        );
        assert_eq!(derive_hosted_mesh_url_for_server("file:///tmp/mesh"), None);
        assert_eq!(derive_hosted_mesh_url_for_server(""), None);
    }

    #[test]
    fn standalone_local_identity_persists_only_the_api_key_identity() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        let first = ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap();
        assert!(first.organization_id.starts_with("local-org-"));
        assert!(first.api_key.starts_with("cw_"));
        assert_eq!(
            ensure_local_mesh_identity(&paths.mesh_data_dir).unwrap(),
            first
        );

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("[local_identity]"));
        assert!(data.contains("organization_id = \"local-org-"));
        assert!(data.contains("api_key = \"cw_"));
        assert!(!data.contains("environment_id"));
        assert!(!data.contains("environment_token"));
    }

    #[test]
    fn retired_local_environment_identity_fields_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
[local_identity]
organization_id = "local-org"
api_key = "cw_local"
environment_id = "retired-environment"
environment_token = "retired-bearer"
"#,
        );

        assert!(matches!(
            load_mesh_config(&paths.mesh_data_dir),
            Err(ConfigError::ParseMesh { .. })
        ));
    }

    #[tokio::test]
    async fn the_saved_local_mesh_endpoint_authenticates_only_its_own_url() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "http://127.0.0.1:18090"
mesh_auth_token = "mesh-token"
"#,
        );

        // The local service's saved endpoint is never a default Mesh.
        assert!(matches!(
            resolve_mesh(MeshResolveOptions::default(), &paths, &env),
            Err(ConfigError::NoMeshUrl)
        ));
        let resolved = resolve_mesh(
            MeshResolveOptions {
                mesh_url: Some("http://127.0.0.1:18090/".to_owned()),
                ..MeshResolveOptions::default()
            },
            &paths,
            &env,
        )
        .unwrap();

        assert_eq!(resolved.mesh_url, "http://127.0.0.1:18090/");
        assert_eq!(
            resolved
                .token_provider()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "mesh-token"
        );
        assert_eq!(resolved.auth_source, MeshAuthSource::MeshConfig);
    }

    #[tokio::test]
    async fn mesh_env_url_and_token_override_saved_mesh_config() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_MESH_URL_ENV, "http://127.0.0.1:19090"),
            (CODEWIRE_MESH_AUTH_TOKEN_ENV, "env-token"),
            (CODEWIRE_MESH_NETWORK_ENV, "env-network"),
        ]);
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com"
mesh_auth_token = "saved-token"
mesh_selected_network = "saved-network"
"#,
        );

        let resolved = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap();

        assert_eq!(resolved.mesh_url, "http://127.0.0.1:19090");
        assert_eq!(
            resolved
                .token_provider()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "env-token"
        );
        assert_eq!(resolved.selected_network.as_deref(), Some("env-network"));
        assert_eq!(resolved.auth_source, MeshAuthSource::MeshEnv);
    }

    #[test]
    fn mesh_env_url_does_not_reuse_different_saved_mesh_token_or_network() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([(CODEWIRE_MESH_URL_ENV, "http://127.0.0.1:19090")]);
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com"
mesh_auth_token = "saved-token"
mesh_selected_network = "saved-network"
"#,
        );

        let err = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap_err();

        assert!(matches!(err, ConfigError::NoMeshAuth));
    }

    #[test]
    fn mesh_env_url_does_not_reuse_unpaired_saved_mesh_token() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([(CODEWIRE_MESH_URL_ENV, "http://127.0.0.1:19090")]);
        let paths = paths(home.path(), &env);
        write_mesh_config(&paths.mesh_data_dir, r#"mesh_auth_token = "saved-token""#);

        let err = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap_err();

        assert!(matches!(err, ConfigError::NoMeshAuth));
    }

    #[tokio::test]
    async fn mesh_env_url_can_reuse_matching_saved_mesh_token() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_MESH_URL_ENV, "https://mesh.example.com/base/"),
            (CODEWIRE_MESH_NETWORK_ENV, "env-network"),
        ]);
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com/base"
mesh_auth_token = "saved-token"
mesh_selected_network = "saved-network"
"#,
        );

        let resolved = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap();

        assert_eq!(resolved.mesh_url, "https://mesh.example.com/base/");
        assert_eq!(
            resolved
                .token_provider()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "saved-token"
        );
        assert_eq!(resolved.selected_network.as_deref(), Some("env-network"));
        assert_eq!(resolved.auth_source, MeshAuthSource::MeshConfig);
    }

    #[test]
    fn explicit_mesh_url_does_not_reuse_different_saved_mesh_token() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com"
mesh_auth_token = "saved-token"
"#,
        );

        let err = resolve_mesh(
            MeshResolveOptions {
                mesh_url: Some("http://127.0.0.1:19090".to_string()),
                ..MeshResolveOptions::default()
            },
            &paths,
            &env,
        )
        .unwrap_err();

        assert!(matches!(err, ConfigError::NoMeshAuth));
    }

    #[test]
    fn save_mesh_connection_writes_mesh_keys_and_drops_the_legacy_selection() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_selected_network = "project-alpha"
"#,
        );

        save_mesh_connection(&paths.mesh_data_dir, " http://127.0.0.1:18090 ", " token ").unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"http://127.0.0.1:18090\""));
        assert!(data.contains("mesh_auth_token = \"token\""));
        assert!(!data.contains("mesh_selected_network"));
    }

    #[test]
    fn clearing_the_local_connection_keeps_identity_and_unrelated_endpoints() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "http://127.0.0.1:18090"
mesh_auth_token = "cw_local"

[local_identity]
organization_id = "local-org-1"
api_key = "cw_local"
"#,
        );

        clear_local_mesh_connection(&paths.mesh_data_dir, "http://127.0.0.1:19090").unwrap();
        let kept = load_mesh_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(kept.mesh_url.as_deref(), Some("http://127.0.0.1:18090"));

        clear_local_mesh_connection(&paths.mesh_data_dir, "http://127.0.0.1:18090/").unwrap();
        let cleared = load_mesh_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(cleared.mesh_url, None);
        assert_eq!(cleared.mesh_auth_token, None);
        assert_eq!(
            cleared.local_identity.unwrap().organization_id,
            "local-org-1"
        );
    }

    #[test]
    fn retired_saved_platform_token_field_fails_closed_without_exposing_its_value() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        const MARKER: &str = "synthetic-retired-platform-bearer-canary";
        fs::create_dir_all(&paths.platform_config_dir).unwrap();
        fs::write(
            paths.platform_config_dir.join("config.json"),
            serde_json::json!({
                "server_url": "https://codewire.sh",
                "session_token": MARKER,
                "default_org": "org-default",
            })
            .to_string(),
        )
        .unwrap();

        let error = load_platform_config(&paths.platform_config_dir).unwrap_err();
        assert!(matches!(error, ConfigError::ParsePlatform { .. }));
        assert!(error.to_string().contains("session_token"));
        assert!(!error.to_string().contains(MARKER));
    }

    #[tokio::test]
    async fn hosted_mesh_uses_the_saved_oauth_token_provider() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://codewire.sh");
        let credentials = codewire_client::OAuthCredentials::new(
            "https://codewire.sh",
            codewire_client::CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "saved-oauth-access",
            "saved-oauth-refresh",
            u64::MAX,
            codewire_client::CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .unwrap();
        codewire_client::CredentialStore::save(
            &FileCredentialStore::new(&paths.platform_config_dir),
            &credentials,
        )
        .unwrap();

        let resolved = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap();
        assert_eq!(resolved.mesh_url, "https://mesh.codewire.sh");
        assert_eq!(resolved.auth_source, MeshAuthSource::PlatformConfig);
        assert_eq!(
            resolved
                .token_provider()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "saved-oauth-access"
        );
    }

    #[tokio::test]
    async fn mesh_auth_uses_explicit_platform_server_for_hosted_dev_mesh() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([(CODEWIRE_API_KEY_ENV, "cw_dev_exact_org")]);
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://codewire.sh");
        write_mesh_config(&paths.mesh_data_dir, r#"mesh_selected_network = "default""#);

        let resolved = resolve_mesh(
            MeshResolveOptions {
                platform_server_url: Some("https://codewire-dev.sh".to_string()),
                ..MeshResolveOptions::default()
            },
            &paths,
            &env,
        )
        .unwrap();

        assert_eq!(resolved.mesh_url, "https://mesh.codewire-dev.sh");
        assert_eq!(
            resolved
                .token_provider()
                .token()
                .await
                .unwrap()
                .expose_secret(),
            "cw_dev_exact_org"
        );
        // An older cw's unscoped selection is never applied.
        assert_eq!(resolved.selected_network, None);
        assert_eq!(resolved.auth_source, MeshAuthSource::ApiKeyEnv);
    }

    #[test]
    fn mesh_auth_does_not_use_api_key_for_standalone_mesh() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_MESH_URL_ENV, "http://127.0.0.1:8080"),
            (CODEWIRE_API_KEY_ENV, "hosted-api-key"),
        ]);
        let paths = paths(home.path(), &env);

        let err = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap_err();

        assert!(matches!(err, ConfigError::NoMeshAuth));
    }

    #[test]
    fn same_mesh_url_ignores_trailing_path_slash_query_and_fragment() {
        assert!(same_mesh_url(
            "https://mesh.codewire.sh/api/?x=1#frag",
            "https://mesh.codewire.sh/api"
        ));
    }

    #[test]
    fn mesh_network_env_is_used_when_no_mesh_network_is_saved() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([(CODEWIRE_MESH_NETWORK_ENV, "mesh-env-network")]);
        let paths = paths(home.path(), &env);

        assert_eq!(
            selected_mesh_network(&paths, &env).as_deref(),
            Some("mesh-env-network")
        );
    }

    #[test]
    fn selected_mesh_network_prefers_mesh_env_over_saved_mesh_config() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([(CODEWIRE_MESH_NETWORK_ENV, "env-network")]);
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"mesh_selected_network = "saved-network""#,
        );

        assert_eq!(
            selected_mesh_network(&paths, &env).as_deref(),
            Some("env-network")
        );
        // Without the environment, the legacy key is not a selection.
        assert_eq!(selected_mesh_network(&paths, &MapEnv::default()), None);
    }

    #[test]
    fn retired_mesh_node_token_fails_closed_for_load_and_mutations() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_node_token = "legacy-node-token"
"#,
        );

        assert!(matches!(
            load_mesh_config(&paths.mesh_data_dir),
            Err(ConfigError::ParseMesh { .. })
        ));
        assert!(save_node_registration(&paths.mesh_data_dir, "project-alpha", "builder").is_err());
        assert!(
            clear_local_mesh_connection(&paths.mesh_data_dir, "http://127.0.0.1:18090").is_err()
        );
        assert!(
            fs::read_to_string(paths.mesh_data_dir.join("config.toml"))
                .unwrap()
                .contains("legacy-node-token")
        );
    }

    #[test]
    fn mesh_bearer_debug_output_is_redacted() {
        const MARKER: &str = "synthetic-mesh-bearer-debug-canary";
        let config = MeshConfig {
            mesh_auth_token: Some(MARKER.to_owned()),
            local_identity: Some(LocalMeshIdentity {
                organization_id: "local-org".to_owned(),
                api_key: MARKER.to_owned(),
            }),
            ..MeshConfig::default()
        };
        let options = MeshResolveOptions {
            auth_token: Some(MARKER.to_owned()),
            ..MeshResolveOptions::default()
        };

        assert!(!format!("{config:?}").contains(MARKER));
        assert!(!format!("{options:?}").contains(MARKER));
    }
}
