use std::collections::{BTreeMap, HashMap};
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

pub const CW_CONFIG_DIR_ENV: &str = "CW_CONFIG_DIR";
pub const CODEWIRE_SERVER_URL_ENV: &str = "CODEWIRE_SERVER_URL";
pub const CODEWIRE_API_KEY_ENV: &str = "CODEWIRE_API_KEY";
pub const CODEWIRE_MESH_URL_ENV: &str = "CODEWIRE_MESH_URL";
pub const CODEWIRE_MESH_AUTH_TOKEN_ENV: &str = "CODEWIRE_MESH_AUTH_TOKEN";
pub const CODEWIRE_MESH_NETWORK_ENV: &str = "CODEWIRE_MESH_NETWORK";
pub const CODEWIRE_MESH_INVITE_CODE_ENV: &str = "CODEWIRE_MESH_INVITE_CODE";
pub const CODEWIRE_NODE_NAME_ENV: &str = "CODEWIRE_NODE_NAME";

pub trait Env {
    fn var(&self, key: &str) -> Option<String>;
}

#[derive(Clone, Copy, Debug)]
pub struct OsEnv;

impl Env for OsEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
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
    pub fn from_env(env: &impl Env) -> Self {
        Self::from_home_and_env(home_dir(env), env)
    }

    pub fn from_home_and_env(home: PathBuf, env: &impl Env) -> Self {
        let platform_config_dir = env
            .var(CW_CONFIG_DIR_ENV)
            .and_then(non_empty)
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config").join("cw"));
        Self {
            platform_config_dir,
            mesh_data_dir: home.join(".codewire"),
        }
    }
}

fn home_dir(env: &impl Env) -> PathBuf {
    env.var("HOME")
        .and_then(non_empty)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/.codewire-home"))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformConfig {
    pub server_url: String,
    pub session_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_org: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformResolveOptions {
    pub server_url: Option<String>,
    pub token: Option<String>,
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
                source: config_result.err().map(Box::new),
            });
        }
    };

    let mut token = trim_opt(opts.token).or_else(|| trim_opt(env.var(CODEWIRE_API_KEY_ENV)));
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
        } else {
            token = non_empty(config.session_token.trim().to_string());
            used_config_token = token.is_some();
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
                source: config_result.err().map(Box::new),
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

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MeshConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_selected_network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_auto_connect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_node_network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_target: Option<CurrentTargetConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<MeshNodeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_identity: Option<LocalMeshIdentity>,
}

/// Durable standalone-Mesh identity. The file containing this record is
/// created mode 0600; Debug intentionally never displays the raw credentials.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalMeshIdentity {
    pub organization_id: String,
    pub api_key: String,
    pub environment_id: String,
    pub environment_token: String,
}

impl std::fmt::Debug for LocalMeshIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalMeshIdentity")
            .field("organization_id", &self.organization_id)
            .field("api_key", &"[redacted]")
            .field("environment_id", &self.environment_id)
            .field("environment_token", &"[redacted]")
            .finish()
    }
}

impl LocalMeshIdentity {
    pub fn api_key_hash(&self) -> String {
        sha256_hex(&self.api_key)
    }

    pub fn environment_token_hash(&self) -> String {
        sha256_hex(&self.environment_token)
    }

    fn is_complete(&self) -> bool {
        [
            self.organization_id.as_str(),
            self.api_key.as_str(),
            self.environment_id.as_str(),
            self.environment_token.as_str(),
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
            && self.api_key.starts_with("cw_")
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MeshNodeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CurrentTargetConfig {
    pub kind: String,
    #[serde(rename = "ref")]
    pub target_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalInstancesConfig {
    #[serde(default)]
    pub instances: HashMap<String, LocalInstanceConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalInstanceConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub runtime_name: String,
    #[serde(default)]
    pub lima_instance_name: String,
    #[serde(default)]
    pub repo_path: String,
    #[serde(default)]
    pub workdir: String,
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub install: String,
    #[serde(default)]
    pub startup: String,
    #[serde(default)]
    pub secrets: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<LocalPortConfig>,
    #[serde(default)]
    pub mounts: Vec<LocalMountConfig>,
    #[serde(default)]
    pub cpu: i32,
    #[serde(default)]
    pub memory: i32,
    #[serde(default)]
    pub disk: i32,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
    #[serde(default)]
    pub lima_mount_type: String,
    #[serde(default)]
    pub lima_vm_type: String,
    #[serde(default)]
    pub daemon_host_port: u16,
    #[serde(default)]
    pub daemon_auth_token: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalPortConfig {
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub host_port: i32,
    #[serde(default)]
    pub guest_port: i32,
    #[serde(default)]
    pub label: String,
}

impl LocalPortConfig {
    pub fn effective_guest_port(&self) -> i32 {
        if self.guest_port > 0 {
            self.guest_port
        } else {
            self.port
        }
    }

    pub fn effective_host_port(&self) -> i32 {
        if self.host_port > 0 {
            self.host_port
        } else {
            self.effective_guest_port()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalMountConfig {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub readonly: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CodewireConfig {
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub install: String,
    #[serde(default)]
    pub startup: String,
    #[serde(default)]
    pub secrets: Option<CodewireSecretsConfig>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<LocalPortConfig>,
    #[serde(default)]
    pub mounts: Vec<LocalMountConfig>,
    #[serde(default)]
    pub cpu: i32,
    #[serde(default)]
    pub memory: i32,
    #[serde(default)]
    pub disk: i32,
    #[serde(default)]
    pub agents: Option<CodewireAgentsConfig>,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub install_agents: Option<bool>,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CodewireAgentsConfig {
    #[serde(default)]
    pub install: Option<bool>,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CodewireSecretsConfig {
    #[serde(default)]
    pub org: Option<bool>,
    #[serde(default)]
    pub user: Option<bool>,
    #[serde(default)]
    pub project: String,
}

fn legacy_codewire_config(
    document: codewire_project::ProjectDocument,
) -> Result<CodewireConfig, codewire_project::ProjectError> {
    let spec = document.spec;
    if !spec.repositories.is_empty() {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "repositories",
            detail: "the legacy Docker/Lima backend does not support multiple repositories"
                .to_string(),
        });
    }
    if spec.working_directory != "/workspace" {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "working_directory",
            detail: "the legacy Docker/Lima backend does not support an explicit workdir"
                .to_string(),
        });
    }
    if !spec.skills.is_empty() {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "skills",
            detail: "skill snapshots require the native workspace runtime".to_string(),
        });
    }
    if !spec.credentials.is_empty() {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "credentials",
            detail: "credential grants require the native workspace runtime".to_string(),
        });
    }
    if document
        .local
        .mounts
        .iter()
        .any(|mount| mount.mode == codewire_project::LocalMountMode::Copy)
    {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "mounts.mode",
            detail: "copy mounts require the native workspace runtime".to_string(),
        });
    }
    if !spec.agent_environment.is_empty() {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "agent_env",
            detail:
                "agent-specific environment values are not supported by the legacy local backend"
                    .to_string(),
        });
    }
    if spec
        .application_ports
        .iter()
        .any(|port| !port.access.is_empty())
    {
        return Err(codewire_project::ProjectError::InvalidField {
            field: "ports.access",
            detail: "port access policy is not supported by the legacy local backend".to_string(),
        });
    }

    let host_ports = document
        .local
        .host_ports
        .into_iter()
        .map(|binding| (binding.guest_port, binding.host_port))
        .collect::<BTreeMap<_, _>>();
    let ports = spec
        .application_ports
        .into_iter()
        .map(|port| match host_ports.get(&port.port).copied() {
            Some(host_port) if host_port != port.port => LocalPortConfig {
                host_port: i32::from(host_port),
                guest_port: i32::from(port.port),
                label: port.label,
                ..LocalPortConfig::default()
            },
            _ => LocalPortConfig {
                port: i32::from(port.port),
                label: port.label,
                ..LocalPortConfig::default()
            },
        })
        .collect();
    let agents = (!spec.agents.is_empty()).then_some(CodewireAgentsConfig {
        install: spec.agents.install,
        tools: spec.agents.tools,
    });
    let secrets = (!spec.secrets.is_empty()).then_some(CodewireSecretsConfig {
        org: spec.secrets.include_org,
        user: spec.secrets.include_user,
        project: spec.secrets.project,
    });

    Ok(CodewireConfig {
        preset: spec.preset,
        image: spec.image,
        install: spec.install_command,
        startup: spec.startup_script,
        secrets,
        env: spec.environment,
        ports,
        mounts: document
            .local
            .mounts
            .into_iter()
            .map(|mount| LocalMountConfig {
                source: mount.source,
                target: mount.destination,
                readonly: mount.read_only,
            })
            .collect(),
        cpu: spec.resources.cpu_millicores.unwrap_or_default() as i32,
        memory: spec.resources.memory_mib.unwrap_or_default() as i32,
        disk: spec.resources.disk_gib.unwrap_or_default() as i32,
        agents,
        agent: String::new(),
        install_agents: spec.agents.install,
        include_org_secrets: None,
        include_user_secrets: None,
    })
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct LocalSpec {
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub install: String,
    #[serde(default)]
    pub startup: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<LocalSpecPort>,
    #[serde(default)]
    pub mounts: Vec<LocalSpecMount>,
    #[serde(default)]
    pub cpu: i32,
    #[serde(default)]
    pub memory: i32,
    #[serde(default)]
    pub disk: i32,
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub secret_project: String,
    #[serde(default)]
    pub include_org_secrets: Option<bool>,
    #[serde(default)]
    pub include_user_secrets: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct LocalSpecPort {
    #[serde(default)]
    pub host_port: i32,
    #[serde(default)]
    pub guest_port: i32,
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub label: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct LocalSpecMount {
    pub source: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub readonly: bool,
}

impl From<LocalSpec> for CodewireConfig {
    fn from(spec: LocalSpec) -> Self {
        let secrets = if spec.secret_project.trim().is_empty() {
            None
        } else {
            Some(CodewireSecretsConfig {
                project: spec.secret_project,
                ..CodewireSecretsConfig::default()
            })
        };
        Self {
            preset: spec.preset,
            image: spec.image,
            install: spec.install,
            startup: spec.startup,
            secrets,
            env: spec.env,
            ports: spec
                .ports
                .into_iter()
                .map(|port| {
                    canonical_local_spec_port(LocalPortConfig {
                        port: port.port,
                        host_port: port.host_port,
                        guest_port: port.guest_port,
                        label: port.label,
                    })
                })
                .collect(),
            mounts: spec
                .mounts
                .into_iter()
                .map(|mount| LocalMountConfig {
                    source: mount.source,
                    target: mount.target,
                    readonly: Some(mount.readonly),
                })
                .collect(),
            cpu: spec.cpu,
            memory: spec.memory,
            disk: spec.disk,
            agent: spec.agent,
            include_org_secrets: spec.include_org_secrets,
            include_user_secrets: spec.include_user_secrets,
            ..CodewireConfig::default()
        }
    }
}

fn canonical_local_spec_port(port: LocalPortConfig) -> LocalPortConfig {
    let host = port.effective_host_port();
    let guest = port.effective_guest_port();
    let label = port.label;
    if host <= 0 || guest <= 0 {
        return LocalPortConfig {
            label,
            ..LocalPortConfig::default()
        };
    }
    if host == guest {
        return LocalPortConfig {
            port: guest,
            label,
            ..LocalPortConfig::default()
        };
    }
    LocalPortConfig {
        host_port: host,
        guest_port: guest,
        label,
        ..LocalPortConfig::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshResolveOptions {
    pub mesh_url: Option<String>,
    pub auth_token: Option<String>,
    pub network_id: Option<String>,
    pub platform_server_url: Option<String>,
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
    MeshConfig,
    Hosted,
}

type ResolvedMeshAuth = (Arc<dyn TokenProvider>, MeshAuthSource);

pub fn resolve_mesh(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<ResolvedMeshConfig, ConfigError> {
    let mesh_config = load_mesh_config(&paths.mesh_data_dir)?;
    let (mesh_url, mesh_url_source) =
        resolve_mesh_base_url_with_source(opts.clone(), &mesh_config, paths, env)?;
    let selected_network =
        resolve_mesh_network(&mesh_url, mesh_url_source, &opts, &mesh_config, env);
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
    let mesh_config = load_mesh_config(&paths.mesh_data_dir)?;
    let (mesh_url, mesh_url_source) =
        resolve_mesh_base_url_with_source(opts.clone(), &mesh_config, paths, env)?;
    let selected_network =
        resolve_mesh_network(&mesh_url, mesh_url_source, &opts, &mesh_config, env);
    Ok(ResolvedMeshConfig {
        mesh_url,
        selected_network,
        auth_source,
        token_provider,
    })
}

fn resolve_mesh_network(
    mesh_url: &str,
    mesh_url_source: MeshUrlSource,
    opts: &MeshResolveOptions,
    mesh_config: &MeshConfig,
    env: &impl Env,
) -> Option<String> {
    trim_opt(opts.network_id.clone())
        .or_else(|| trim_opt(env.var(CODEWIRE_MESH_NETWORK_ENV)))
        .or_else(|| {
            saved_mesh_value_for_selected_url(
                mesh_url,
                mesh_url_source,
                mesh_config.mesh_url.as_deref(),
                mesh_config.mesh_selected_network.as_deref(),
            )
        })
}

pub fn resolve_mesh_base_url(
    opts: MeshResolveOptions,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<String, ConfigError> {
    let mesh_config = load_mesh_config(&paths.mesh_data_dir)?;
    resolve_mesh_base_url_with_source(opts, &mesh_config, paths, env).map(|(url, _source)| url)
}

fn resolve_mesh_base_url_with_source(
    opts: MeshResolveOptions,
    mesh_config: &MeshConfig,
    paths: &ResolvePaths,
    env: &impl Env,
) -> Result<(String, MeshUrlSource), ConfigError> {
    let explicit_mesh = trim_opt(opts.mesh_url);
    let env_mesh = trim_opt(env.var(CODEWIRE_MESH_URL_ENV));
    let config_mesh = trim_opt(mesh_config.mesh_url.clone());
    let hosted_mesh =
        derive_hosted_mesh_url(opts.platform_server_url.as_deref().unwrap_or(""), paths);

    if let Some(mesh_url) = explicit_mesh {
        return Ok((mesh_url, MeshUrlSource::Explicit));
    }
    if let Some(mesh_url) = env_mesh {
        return Ok((mesh_url, MeshUrlSource::MeshEnv));
    }
    if let Some(mesh_url) = config_mesh {
        return Ok((mesh_url, MeshUrlSource::MeshConfig));
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
    if mesh_url_source == MeshUrlSource::MeshConfig {
        return Some(saved_value);
    }
    let Some(saved_mesh_url) = saved_mesh_url.and_then(|url| non_empty(url.trim().to_string()))
    else {
        return (mesh_url_source == MeshUrlSource::Hosted).then_some(saved_value);
    };
    same_mesh_url(mesh_url, &saved_mesh_url).then_some(saved_value)
}

pub fn load_mesh_config(data_dir: &Path) -> Result<MeshConfig, ConfigError> {
    let path = data_dir.join("config.toml");
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

/// Creates the one standalone-local organization and its approved machine and
/// environment credentials once, then persists them in the hardened local
/// config. It never derives identity from a network name or a hosted default.
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

fn new_local_mesh_identity() -> LocalMeshIdentity {
    let mut api_key_bytes = [0u8; 32];
    let mut environment_token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut api_key_bytes);
    rand::rngs::OsRng.fill_bytes(&mut environment_token_bytes);
    LocalMeshIdentity {
        organization_id: format!("local-org-{}", uuid::Uuid::new_v4().simple()),
        api_key: format!("cw_{}", hex_lower(&api_key_bytes)),
        environment_id: format!("local-env-{}", uuid::Uuid::new_v4().simple()),
        environment_token: hex_lower(&environment_token_bytes),
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

pub fn selected_mesh_network(paths: &ResolvePaths, env: &impl Env) -> Option<String> {
    let config = load_mesh_config(&paths.mesh_data_dir).ok();
    trim_opt(env.var(CODEWIRE_MESH_NETWORK_ENV)).or_else(|| {
        config
            .as_ref()
            .and_then(|config| trim_opt(config.mesh_selected_network.clone()))
    })
}

pub fn save_selected_mesh_network(data_dir: &Path, network_id: &str) -> Result<(), ConfigError> {
    save_selected_mesh_network_preference(data_dir, network_id, false)
}

pub fn save_selected_mesh_network_preference(
    data_dir: &Path,
    network_id: &str,
    auto_connect: bool,
) -> Result<(), ConfigError> {
    let network_id = network_id.trim();
    if network_id.is_empty() {
        return Err(ConfigError::InvalidMeshSelection);
    }
    update_mesh_config(data_dir, |config| {
        config.mesh_selected_network = Some(network_id.to_string());
        config.mesh_auto_connect = Some(auto_connect);
    })
}

pub fn clear_selected_mesh_network(data_dir: &Path) -> Result<(), ConfigError> {
    update_mesh_config(data_dir, |config| {
        config.mesh_selected_network = None;
        config.mesh_auto_connect = None;
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

pub fn current_target_from_config(config: &MeshConfig) -> CurrentTargetConfig {
    match config.current_target.as_ref() {
        Some(target) if !target.kind.trim().is_empty() => CurrentTargetConfig {
            kind: target.kind.trim().to_string(),
            target_ref: target.target_ref.trim().to_string(),
            name: target.name.trim().to_string(),
        },
        _ => default_current_target(),
    }
}

pub fn current_target(data_dir: &Path) -> Result<CurrentTargetConfig, ConfigError> {
    Ok(current_target_from_config(&load_mesh_config(data_dir)?))
}

pub fn load_codewire_config(path: &Path) -> Result<CodewireConfig, ConfigError> {
    let document = load_project_document(path)?;
    legacy_codewire_config(document).map_err(|source| ConfigError::ParseCodewireConfig {
        path: path.to_path_buf(),
        source,
    })
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

pub fn parse_codewire_config(data: &str) -> Result<CodewireConfig, codewire_project::ProjectError> {
    legacy_codewire_config(codewire_project::parse_project_yaml(data)?)
}

pub fn parse_local_spec_json(data: &[u8]) -> Result<CodewireConfig, ConfigError> {
    let spec: LocalSpec =
        serde_json::from_slice(data).map_err(|source| ConfigError::ParseLocalSpec { source })?;
    Ok(spec.into())
}

pub fn load_local_instances_config(data_dir: &Path) -> Result<LocalInstancesConfig, ConfigError> {
    let path = data_dir.join("local_instances.toml");
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalInstancesConfig::default());
        }
        Err(source) => return Err(ConfigError::ReadConfig { path, source }),
    };
    toml::from_str(&data).map_err(|source| ConfigError::ParseLocalInstances { path, source })
}

pub fn save_local_instances_config(
    data_dir: &Path,
    config: &LocalInstancesConfig,
) -> Result<(), ConfigError> {
    fs::create_dir_all(data_dir).map_err(|source| ConfigError::CreateConfigDir {
        path: data_dir.to_path_buf(),
        source,
    })?;
    harden_dir(data_dir)?;

    let path = data_dir.join("local_instances.toml");
    let data =
        toml::to_string_pretty(config).map_err(|source| ConfigError::SerializeLocalInstances {
            path: path.clone(),
            source,
        })?;
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

pub fn save_current_target(
    data_dir: &Path,
    target: &CurrentTargetConfig,
) -> Result<(), ConfigError> {
    let kind = target.kind.trim();
    let target_ref = target.target_ref.trim();
    if kind.is_empty() || target_ref.is_empty() {
        return Err(ConfigError::InvalidCurrentTarget);
    }
    let name = target.name.trim();
    update_mesh_config(data_dir, |config| {
        config.current_target = Some(CurrentTargetConfig {
            kind: kind.to_string(),
            target_ref: target_ref.to_string(),
            name: name.to_string(),
        });
    })
}

pub fn save_node_registration(
    data_dir: &Path,
    mesh_url: &str,
    network_id: &str,
    node_name: &str,
) -> Result<(), ConfigError> {
    let mesh_url = mesh_url.trim();
    let network_id = network_id.trim();
    let node_name = node_name.trim();

    update_mesh_config(data_dir, |config| {
        if !mesh_url.is_empty() {
            config.mesh_url = Some(mesh_url.to_string());
        }
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

pub fn save_joined_network(
    data_dir: &Path,
    mesh_url: &str,
    network_id: &str,
) -> Result<(), ConfigError> {
    let mesh_url = mesh_url.trim();
    let network_id = network_id.trim();
    if network_id.is_empty() {
        return Err(ConfigError::InvalidMeshSelection);
    }
    update_mesh_config(data_dir, |config| {
        if !mesh_url.is_empty() {
            config.mesh_url = Some(mesh_url.to_string());
        }
        config.mesh_selected_network = Some(network_id.to_string());
        config.mesh_auto_connect = Some(false);
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
    fs::create_dir_all(data_dir).map_err(|source| ConfigError::CreateConfigDir {
        path: data_dir.to_path_buf(),
        source,
    })?;
    harden_dir(data_dir)?;

    let path = data_dir.join("config.toml");
    let data = toml::to_string_pretty(config).map_err(|source| ConfigError::SerializeMesh {
        path: path.clone(),
        source,
    })?;
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

pub fn derive_hosted_mesh_url_for_server(raw_server_url: &str) -> Option<String> {
    let server = Url::parse(raw_server_url.trim()).ok()?;
    let host = match server.host_str()? {
        "codewire.sh" | "www.codewire.sh" | "app.codewire.sh" | "api.codewire.sh" => {
            "mesh.codewire.sh"
        }
        "codewire-dev.sh"
        | "www.codewire-dev.sh"
        | "app.codewire-dev.sh"
        | "api.codewire-dev.sh" => "mesh.codewire-dev.sh",
        _ => return None,
    };
    let scheme = if server.scheme().is_empty() {
        "https"
    } else {
        server.scheme()
    };
    Some(format!("{scheme}://{host}"))
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
}

impl ConfigReport {
    pub fn from_results(
        paths: &ResolvePaths,
        platform: Result<ResolvedPlatformConfig, ConfigError>,
        mesh: Result<ResolvedMeshConfig, ConfigError>,
    ) -> Self {
        Self {
            platform_config_dir: paths.platform_config_dir.display().to_string(),
            mesh_data_dir: paths.mesh_data_dir.display().to_string(),
            platform: platform.ok().map(PlatformReport::from),
            mesh: mesh.ok().map(MeshReport::from),
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
    #[error("parse local instances config {path}: {source}")]
    ParseLocalInstances {
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
    #[error("parse local spec json: {source}")]
    ParseLocalSpec {
        #[source]
        source: serde_json::Error,
    },
    #[error("serialize local instances config {path}: {source}")]
    SerializeLocalInstances {
        path: PathBuf,
        #[source]
        source: toml::ser::Error,
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
    #[error("current target kind and ref must be non-empty")]
    InvalidCurrentTarget,
    #[error("incomplete platform config {path}: missing server_url")]
    IncompletePlatformConfig { path: PathBuf },
    #[error("no server configured (set --server, CODEWIRE_SERVER_URL, run 'cw setup', or run 'cw login'){suffix}", suffix = source.as_ref().map(|e| format!(": {e}")).unwrap_or_default())]
    NoPlatformServer { source: Option<Box<ConfigError>> },
    #[error("not logged in (pass --token, set CODEWIRE_API_KEY, run 'cw setup', or run 'cw login'){suffix}", suffix = source.as_ref().map(|e| format!(": {e}")).unwrap_or_default())]
    NoPlatformToken { source: Option<Box<ConfigError>> },
    #[error(
        "not logged in for {requested} (saved config is for {saved}; pass --token or set CODEWIRE_API_KEY)"
    )]
    PlatformServerMismatch { requested: String, saved: String },
    #[error("mesh not configured (set CODEWIRE_MESH_URL or log in to hosted Codewire)")]
    NoMeshUrl,
    #[error(
        "mesh user authentication not configured (pass --token, set CODEWIRE_MESH_AUTH_TOKEN, or use 'cw login'/CODEWIRE_API_KEY for hosted Codewire)"
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
        ResolvePaths::from_home_and_env(home.to_path_buf(), env)
    }

    fn write_platform_config(dir: &Path, server_url: &str, token: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("config.json"),
            serde_json::json!({
                "server_url": server_url,
                "session_token": token,
                "default_org": "org-default",
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_mesh_config(dir: &Path, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.toml"), body).unwrap();
    }

    #[test]
    fn load_codewire_config_parses_compose_style_ports() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(
            &path,
            r#"
ports:
  - 3000
  - "18080:8080"
  - port: 4000
    label: web
  - published: 15432
    target: 5432
    label: postgres
"#,
        )
        .unwrap();

        let config = load_codewire_config(&path).unwrap();

        assert_eq!(
            config.ports,
            vec![
                LocalPortConfig {
                    port: 3000,
                    ..LocalPortConfig::default()
                },
                LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    ..LocalPortConfig::default()
                },
                LocalPortConfig {
                    port: 4000,
                    label: "web".to_string(),
                    ..LocalPortConfig::default()
                },
                LocalPortConfig {
                    host_port: 15432,
                    guest_port: 5432,
                    label: "postgres".to_string(),
                    ..LocalPortConfig::default()
                },
            ]
        );
    }

    #[test]
    fn load_codewire_config_rejects_partial_port_mappings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(
            &path,
            r#"
ports:
  - host_port: 18080
"#,
        )
        .unwrap();

        let err = load_codewire_config(&path).unwrap_err();

        assert!(
            err.to_string()
                .contains("host_port and guest_port must both be greater than zero"),
            "{err}"
        );
    }

    #[test]
    fn load_codewire_config_parses_mounts_agents_and_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(
            &path,
            r#"
preset: full
image: ghcr.io/codewire/dev:latest
install: npm install
startup: npm test
secrets:
  org: false
  user: true
  project: dev
agents:
  install: true
  tools:
    - claude
    - gemini
mounts:
  - source: ../agentic
    target: /workspace/agentic
    mode: direct
    readonly: true
  - source: /srv/shared
    target: /workspace/shared
    mode: direct
    readonly: false
"#,
        )
        .unwrap();

        let config = load_codewire_config(&path).unwrap();

        assert_eq!(config.preset, "full");
        assert_eq!(config.image, "ghcr.io/codewire/dev:latest");
        assert_eq!(
            config.mounts,
            vec![
                LocalMountConfig {
                    source: "../agentic".to_string(),
                    target: "/workspace/agentic".to_string(),
                    readonly: Some(true),
                },
                LocalMountConfig {
                    source: "/srv/shared".to_string(),
                    target: "/workspace/shared".to_string(),
                    readonly: Some(false),
                },
            ]
        );
        assert_eq!(
            config.secrets,
            Some(CodewireSecretsConfig {
                org: Some(false),
                user: Some(true),
                project: "dev".to_string(),
            })
        );
        assert_eq!(
            config.agents,
            Some(CodewireAgentsConfig {
                install: Some(true),
                tools: vec!["claude-code".to_string(), "gemini-cli".to_string()],
            })
        );
        assert_eq!(canonical_agent_id("gemini"), "gemini-cli");
        assert_eq!(canonical_agent_id("kimi"), "kimi-code");
        assert_eq!(canonical_agent_id("pi-coding-agent"), "pi");
        assert_eq!(display_agent_id("claude-code"), "claude");
        assert_eq!(display_agent_id("kimi-code"), "kimi");
    }

    #[test]
    fn load_codewire_config_parses_scalar_agents_and_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(
            &path,
            r#"
agents: codex
secrets: project-dev
"#,
        )
        .unwrap();

        let config = load_codewire_config(&path).unwrap();

        assert_eq!(
            config.agents,
            Some(CodewireAgentsConfig {
                install: None,
                tools: vec!["codex".to_string()],
            })
        );
        assert_eq!(
            config.secrets,
            Some(CodewireSecretsConfig {
                project: "project-dev".to_string(),
                ..CodewireSecretsConfig::default()
            })
        );
    }

    #[test]
    fn parse_local_spec_json_matches_go_conversion_shape() {
        let config = parse_local_spec_json(
            br#"
{
  "preset": "full",
  "image": "ubuntu:24.04",
  "install": "npm install",
  "startup": "npm test",
  "env": {"FOO": "bar"},
  "ports": [
    {"port": 3000, "label": "web"},
    {"host_port": 18080, "guest_port": 8080}
  ],
  "mounts": [
    {"source": "/tmp/data", "target": "/data", "readonly": true}
  ],
  "cpu": 2000,
  "memory": 4096,
  "disk": 20,
  "agent": "claude",
  "secret_project": "dev",
  "include_org_secrets": false,
  "include_user_secrets": true
}
"#,
        )
        .unwrap();

        assert_eq!(config.preset, "full");
        assert_eq!(config.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(
            config.ports,
            vec![
                LocalPortConfig {
                    port: 3000,
                    label: "web".to_string(),
                    ..LocalPortConfig::default()
                },
                LocalPortConfig {
                    host_port: 18080,
                    guest_port: 8080,
                    ..LocalPortConfig::default()
                },
            ]
        );
        assert_eq!(
            config.mounts,
            vec![LocalMountConfig {
                source: "/tmp/data".to_string(),
                target: "/data".to_string(),
                readonly: Some(true),
            }]
        );
        assert_eq!(
            config.secrets,
            Some(CodewireSecretsConfig {
                project: "dev".to_string(),
                ..CodewireSecretsConfig::default()
            })
        );
        assert_eq!(config.include_org_secrets, Some(false));
        assert_eq!(config.include_user_secrets, Some(true));
    }

    #[test]
    fn platform_uses_api_key_env_with_config_server() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::new([
            (CODEWIRE_API_KEY_ENV, "cw_env_override"),
            (CODEWIRE_SERVER_URL_ENV, ""),
        ]);
        let paths = paths(home.path(), &env);
        write_platform_config(
            &paths.platform_config_dir,
            "https://example.invalid",
            "session-token",
        );

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
    }

    #[tokio::test]
    async fn platform_uses_saved_oauth_credentials_after_process_restart() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://api.codewire.test", "");
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
        write_platform_config(
            &paths.platform_config_dir,
            "https://codewire.sh",
            "prod-token",
        );

        let err = resolve_platform(
            PlatformResolveOptions {
                server_url: Some("https://codewire-dev.sh".to_string()),
                token: None,
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
        write_platform_config(
            &paths.platform_config_dir,
            "https://codewire.sh",
            "session-token",
        );

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
                session_token: "session-token".to_string(),
                default_org: "org_123".to_string(),
            },
        )
        .unwrap();

        let data = fs::read_to_string(paths.platform_config_dir.join("config.json")).unwrap();
        assert!(data.ends_with('\n'));
        assert!(data.contains("\"server_url\": \"https://codewire.sh\""));
        assert!(data.contains("\"session_token\": \"session-token\""));
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
            derive_hosted_mesh_url_for_server("https://example.com"),
            None
        );
    }

    #[test]
    fn current_target_defaults_to_local_when_missing_or_blank() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        assert_eq!(
            current_target(&paths.mesh_data_dir).unwrap(),
            default_current_target()
        );

        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
[current_target]
kind = " "
ref = "env_123"
name = "builder"
"#,
        );

        assert_eq!(
            current_target(&paths.mesh_data_dir).unwrap(),
            default_current_target()
        );
    }

    #[test]
    fn save_current_target_writes_go_compatible_toml_and_preserves_mesh_settings() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.codewire.sh"
mesh_auth_token = "mesh-token"
mesh_selected_network = "project-alpha"
"#,
        );

        save_current_target(
            &paths.mesh_data_dir,
            &CurrentTargetConfig {
                kind: " env ".to_string(),
                target_ref: " 12345678-abcd-4000-9000-000000000001 ".to_string(),
                name: " builder ".to_string(),
            },
        )
        .unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"https://mesh.codewire.sh\""));
        assert!(data.contains("mesh_auth_token = \"mesh-token\""));
        assert!(data.contains("mesh_selected_network = \"project-alpha\""));
        assert!(data.contains("[current_target]"));
        assert!(data.contains("kind = \"env\""));
        assert!(data.contains("ref = \"12345678-abcd-4000-9000-000000000001\""));
        assert!(data.contains("name = \"builder\""));

        assert_eq!(
            current_target(&paths.mesh_data_dir).unwrap(),
            CurrentTargetConfig {
                kind: "env".to_string(),
                target_ref: "12345678-abcd-4000-9000-000000000001".to_string(),
                name: "builder".to_string(),
            }
        );
    }

    #[test]
    fn save_current_target_rejects_blank_kind_or_ref() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        assert!(matches!(
            save_current_target(
                &paths.mesh_data_dir,
                &CurrentTargetConfig {
                    kind: String::new(),
                    target_ref: "local".to_string(),
                    name: "local".to_string(),
                }
            )
            .unwrap_err(),
            ConfigError::InvalidCurrentTarget
        ));

        assert!(matches!(
            save_current_target(
                &paths.mesh_data_dir,
                &CurrentTargetConfig {
                    kind: "env".to_string(),
                    target_ref: " ".to_string(),
                    name: String::new(),
                }
            )
            .unwrap_err(),
            ConfigError::InvalidCurrentTarget
        ));
    }

    #[test]
    fn load_local_instances_reads_go_compatible_state() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        assert_eq!(
            load_local_instances_config(&paths.mesh_data_dir).unwrap(),
            LocalInstancesConfig::default()
        );

        fs::create_dir_all(&paths.mesh_data_dir).unwrap();
        fs::write(
            paths.mesh_data_dir.join("local_instances.toml"),
            r#"
[instances.repo]
name = "repo"
backend = "lima"
runtime_name = "cw-repo"
repo_path = "/home/user/src/repo"
workdir = "/workspace"
image = "ubuntu:24.04"
preset = "full"
install = "npm install"
startup = "npm test"
secrets = "dev"
agent = "claude"
cpu = 2000
memory = 4096
disk = 20
lima_instance_name = "cw-repo-vm"
lima_mount_type = "virtiofs"
lima_vm_type = "vz"
created_at = "2026-07-05T01:00:00Z"
last_used_at = "2026-07-05T01:05:00Z"

[instances.repo.env]
FOO = "bar"

[[instances.repo.ports]]
host_port = 18080
guest_port = 8080
label = "web"

[[instances.repo.mounts]]
source = "/tmp/data"
target = "/data"
readonly = true
"#,
        )
        .unwrap();

        let loaded = load_local_instances_config(&paths.mesh_data_dir).unwrap();
        let instance = loaded.instances.get("repo").unwrap();
        assert_eq!(instance.name, "repo");
        assert_eq!(instance.backend, "lima");
        assert_eq!(instance.runtime_name, "cw-repo");
        assert_eq!(instance.lima_instance_name, "cw-repo-vm");
        assert_eq!(instance.repo_path, "/home/user/src/repo");
        assert_eq!(instance.workdir, "/workspace");
        assert_eq!(instance.image, "ubuntu:24.04");
        assert_eq!(instance.preset, "full");
        assert_eq!(instance.install, "npm install");
        assert_eq!(instance.startup, "npm test");
        assert_eq!(instance.secrets, "dev");
        assert_eq!(instance.agent, "claude");
        assert_eq!(instance.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(instance.ports[0].host_port, 18080);
        assert_eq!(instance.ports[0].guest_port, 8080);
        assert_eq!(instance.ports[0].label, "web");
        assert_eq!(instance.mounts[0].source, "/tmp/data");
        assert_eq!(instance.mounts[0].target, "/data");
        assert_eq!(instance.mounts[0].readonly, Some(true));
        assert_eq!(instance.cpu, 2000);
        assert_eq!(instance.memory, 4096);
        assert_eq!(instance.disk, 20);
        assert_eq!(instance.lima_mount_type, "virtiofs");
        assert_eq!(instance.lima_vm_type, "vz");
        assert_eq!(instance.created_at, "2026-07-05T01:00:00Z");
        assert_eq!(instance.last_used_at, "2026-07-05T01:05:00Z");
    }

    #[test]
    fn save_local_instances_writes_go_compatible_state() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        let mut config = LocalInstancesConfig::default();
        config.instances.insert(
            "repo".to_string(),
            LocalInstanceConfig {
                name: "repo".to_string(),
                backend: "docker".to_string(),
                runtime_name: "cw-repo".to_string(),
                repo_path: "/home/user/src/repo".to_string(),
                workdir: "/workspace".to_string(),
                image: "ubuntu:24.04".to_string(),
                ..LocalInstanceConfig::default()
            },
        );

        save_local_instances_config(&paths.mesh_data_dir, &config).unwrap();

        let loaded = load_local_instances_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(loaded, config);
        let data = fs::read_to_string(paths.mesh_data_dir.join("local_instances.toml")).unwrap();
        assert!(data.contains("[instances.repo]"));
        assert!(data.contains("runtime_name = \"cw-repo\""));
    }

    #[tokio::test]
    async fn mesh_auth_uses_saved_mesh_config_token() {
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

        let resolved = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap();

        assert_eq!(resolved.mesh_url, "http://127.0.0.1:18090");
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
    fn save_mesh_connection_writes_mesh_keys_and_preserves_selected_network() {
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
        assert!(data.contains("mesh_selected_network = \"project-alpha\""));
    }

    #[test]
    fn hosted_mesh_rejects_the_old_saved_platform_token_fallback() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(
            &paths.platform_config_dir,
            "https://codewire.sh",
            "platform-token",
        );

        let error = resolve_mesh(MeshResolveOptions::default(), &paths, &env).unwrap_err();
        assert!(matches!(error, ConfigError::NoMeshAuth));
    }

    #[tokio::test]
    async fn hosted_mesh_uses_the_saved_oauth_token_provider() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_platform_config(&paths.platform_config_dir, "https://codewire.sh", "");
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
        write_platform_config(
            &paths.platform_config_dir,
            "https://codewire.sh",
            "prod-token",
        );
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
        assert_eq!(resolved.selected_network.as_deref(), Some("default"));
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
    }

    #[test]
    fn save_selected_mesh_network_preserves_existing_mesh_config_keys() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com"
mesh_node_token = "node-token"

[node]
name = "builder"
"#,
        );

        save_selected_mesh_network(&paths.mesh_data_dir, "project-alpha").unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"https://mesh.example.com\""));
        assert!(!data.contains("mesh_node_token"));
        assert!(data.contains("mesh_selected_network = \"project-alpha\""));
        assert!(data.contains("mesh_auto_connect = false"));
        assert!(data.contains("[node]"));
        assert!(data.contains("name = \"builder\""));
    }

    #[test]
    fn selected_mesh_network_auto_connect_is_an_explicit_scoped_preference() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);

        save_selected_mesh_network_preference(&paths.mesh_data_dir, "project-alpha", true).unwrap();
        let selected = load_mesh_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(
            selected.mesh_selected_network.as_deref(),
            Some("project-alpha")
        );
        assert_eq!(selected.mesh_auto_connect, Some(true));

        save_selected_mesh_network(&paths.mesh_data_dir, "project-beta").unwrap();
        let selected = load_mesh_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(
            selected.mesh_selected_network.as_deref(),
            Some("project-beta")
        );
        assert_eq!(selected.mesh_auto_connect, Some(false));
    }

    #[test]
    fn clear_selected_mesh_network_preserves_other_mesh_config_keys() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_url = "https://mesh.example.com"
mesh_selected_network = "project-alpha"
mesh_node_token = "node-token"
"#,
        );

        clear_selected_mesh_network(&paths.mesh_data_dir).unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"https://mesh.example.com\""));
        assert!(!data.contains("mesh_node_token"));
        assert!(!data.contains("mesh_selected_network"));
        assert!(!data.contains("mesh_auto_connect"));
    }

    #[test]
    fn save_node_registration_preserves_existing_config_and_scrubs_legacy_token() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_node_token = "legacy-node-token"

[node]
name = "old-builder"
"#,
        );

        save_node_registration(
            &paths.mesh_data_dir,
            "https://mesh.example.com/",
            "project-alpha",
            "builder",
        )
        .unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"https://mesh.example.com/\""));
        assert!(!data.contains("mesh_node_token"));
        assert!(data.contains("mesh_node_network = \"project-alpha\""));
        assert!(data.contains("[node]"));
        assert!(data.contains("name = \"builder\""));

        let config = load_mesh_config(&paths.mesh_data_dir).unwrap();
        assert_eq!(
            config.node.and_then(|node| node.name).as_deref(),
            Some("builder")
        );
    }

    #[test]
    fn save_joined_network_writes_selected_network() {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default();
        let paths = paths(home.path(), &env);
        write_mesh_config(
            &paths.mesh_data_dir,
            r#"
mesh_node_token = "mesh-node-token"
"#,
        );

        save_joined_network(
            &paths.mesh_data_dir,
            "https://mesh.example.com",
            "project-alpha",
        )
        .unwrap();

        let data = fs::read_to_string(paths.mesh_data_dir.join("config.toml")).unwrap();
        assert!(data.contains("mesh_url = \"https://mesh.example.com\""));
        assert!(data.contains("mesh_selected_network = \"project-alpha\""));
        assert!(!data.contains("mesh_node_token"));
    }
}
