use crate::docker_proxy::DockerProxySettings;
use codewire_gateway_proto::DaemonAuthToken;
use codewire_tls::{ClientTlsEndpoint, ServerTlsFiles};
use std::{env, fmt, net::SocketAddr, path::PathBuf, time::Duration};
use thiserror::Error;
use uuid::Uuid;

pub const SHIM_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const DAEMON_CONNECT_TIMEOUT_SECONDS_ENV: &str = "CODEWIRE_DAEMON_CONNECT_TIMEOUT_SECONDS";
pub const DEFAULT_SHIM_ADDR: &str = "127.0.0.1:7777";
pub const DEFAULT_DAEMON_CONNECT_TIMEOUT_SECONDS: u64 = 60;
pub const MAX_DAEMON_CONNECT_TIMEOUT_SECONDS: u64 = 3_600;
pub const DEFAULT_SSH_LISTEN_ADDR: &str = "0.0.0.0:2222";
pub const DEFAULT_READYZ_LISTEN_ADDR: &str = "0.0.0.0:2223";
pub const DEFAULT_DOCKER_UPSTREAM_SOCK: &str = "/var/run/docker/docker.sock";
pub const DEFAULT_HOST_KEY_PATH: &str = "/codewire/gateway/ssh/host_ed25519";
pub const DEFAULT_TAILNET_UDP_LISTEN_ADDR: &str = "0.0.0.0:31000";

pub const SSH_LISTEN_ADDR_ENV: &str = "CODEWIRE_SSH_LISTEN_ADDR";
pub const READYZ_LISTEN_ADDR_ENV: &str = "CODEWIRE_READYZ_LISTEN_ADDR";
pub const SSH_PORT_ENV: &str = "CODEWIRE_SSH_PORT";
pub const SSH_HOST_KEY_PATH_ENV: &str = "CODEWIRE_SSH_HOST_KEY_PATH";
pub const GATEWAY_LISTENER_SELF_CHECK_INTERVAL_ENV: &str =
    "CODEWIRE_GATEWAY_LISTENER_SELF_CHECK_INTERVAL";

pub const ENVIRONMENT_ID_ENV: &str = "CODEWIRE_ENVIRONMENT_ID";
pub const GATEWAY_TOKEN_ENV: &str = "CODEWIRE_GATEWAY_TOKEN";
pub const API_URL_ENV: &str = "CODEWIRE_API_URL";
pub const BINDING_URL_ENV: &str = "CODEWIRE_BINDING_URL";
pub const COORDINATOR_URL_ENV: &str = "CODEWIRE_COORDINATOR_URL";
pub const DERP_URL_ENV: &str = "CODEWIRE_DERP_URL";
pub const STUN_HOST_ENV: &str = "CODEWIRE_STUN_HOST";
pub const STUN_PORT_ENV: &str = "CODEWIRE_STUN_PORT";
pub const STUN_SERVERS_ENV: &str = "CODEWIRE_STUN_SERVERS";
pub const TAILNET_UDP_LISTEN_ADDR_ENV: &str = "CODEWIRE_TAILNET_UDP_LISTEN_ADDR";
pub const TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV: &str =
    "CODEWIRE_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS";
pub const UDP_RELAY_ALLOCATOR_URL_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_URL";
pub const UDP_RELAY_ALLOCATOR_TOKEN_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN";
pub const UDP_RELAY_BIND_ADDRS_ENV: &str = "CODEWIRE_UDP_RELAY_BIND_ADDRS";
pub const DEBUG_TAILNET_ENV: &str = "CODEWIRE_DEBUG_TAILNET";

pub const DOCKER_PROXY_SOCK_ENV: &str = "CODEWIRE_DOCKER_PROXY_SOCK";
pub const DOCKER_UPSTREAM_SOCK_ENV: &str = "CODEWIRE_DOCKER_UPSTREAM_SOCK";

pub const ENVIRONMENT_OPERATION_GENERATION_ENV: &str = "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION";
pub use codewire_daemon::config::HOSTED_PROJECTION_SHA256_ENV;
pub const CREDENTIAL_HTTPS_AUTHORITY_ENV: &str = "CODEWIRE_CREDENTIAL_HTTPS_AUTHORITY";
pub const CREDENTIAL_HTTPS_LISTEN_ADDR_ENV: &str = "CODEWIRE_CREDENTIAL_HTTPS_LISTEN_ADDR";
pub const CREDENTIAL_GATEWAY_TOKEN_FILE_ENV: &str = "CODEWIRE_CREDENTIAL_GATEWAY_TOKEN_FILE";
pub const CREDENTIAL_TLS_CERT_FILE_ENV: &str = "CODEWIRE_CREDENTIAL_TLS_CERT_FILE";
pub const CREDENTIAL_TLS_KEY_FILE_ENV: &str = "CODEWIRE_CREDENTIAL_TLS_KEY_FILE";
pub const CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV: &str = "CODEWIRE_CREDENTIAL_BROKER_HTTPS_ORIGIN";
pub const CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV: &str = "CODEWIRE_CREDENTIAL_BROKER_TLS_ROOTS_FILE";
pub const CREDENTIAL_HTTPS_PORT: u16 = 8443;

const CREDENTIAL_ENV_GROUP: [&str; 8] = [
    ENVIRONMENT_OPERATION_GENERATION_ENV,
    CREDENTIAL_HTTPS_AUTHORITY_ENV,
    CREDENTIAL_HTTPS_LISTEN_ADDR_ENV,
    CREDENTIAL_GATEWAY_TOKEN_FILE_ENV,
    CREDENTIAL_TLS_CERT_FILE_ENV,
    CREDENTIAL_TLS_KEY_FILE_ENV,
    CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV,
    CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV,
];

/// All-or-none material-free credential transport configuration. No runtime
/// authority is inferred from these coordinates: the broker authenticates
/// the original projected identities on each private call.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRuntimeConfig {
    environment_id: Uuid,
    operation_generation: u64,
    https_authority: String,
    pub(crate) listen_addr: SocketAddr,
    gateway_token_file: PathBuf,
    tls_cert_file: PathBuf,
    tls_key_file: PathBuf,
    broker_https_origin: String,
    broker_tls_roots_file: PathBuf,
    hosted_projection_sha256: Option<[u8; 32]>,
}

impl fmt::Debug for CredentialRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRuntimeConfig")
            .finish_non_exhaustive()
    }
}

impl CredentialRuntimeConfig {
    pub(crate) fn hosted_bridge(
        &self,
    ) -> Result<Option<crate::hosted_bridge::HostedBridgeConfig>, ConfigError> {
        if self.hosted_projection_sha256.is_none() {
            return Ok(None);
        }
        Ok(Some(crate::hosted_bridge::HostedBridgeConfig::new(
            self.environment_id,
            self.operation_generation,
            self.gateway_token_file.clone(),
            self.broker_endpoint()?,
        )))
    }

    pub(crate) fn server_tls(&self) -> Result<ServerTlsFiles, ConfigError> {
        ServerTlsFiles::new(self.tls_cert_file.clone(), self.tls_key_file.clone())
            .map_err(|_| ConfigError::InvalidCredentialRuntime)
    }

    pub(crate) fn broker_endpoint(&self) -> Result<ClientTlsEndpoint, ConfigError> {
        ClientTlsEndpoint::new(
            self.broker_https_origin.clone(),
            self.broker_tls_roots_file.clone(),
        )
        .map_err(|_| ConfigError::InvalidCredentialRuntime)
    }

    pub(crate) fn ingress(
        &self,
    ) -> Result<crate::credentials::CredentialIngressConfig, ConfigError> {
        crate::credentials::CredentialIngressConfig::new(
            self.environment_id,
            self.operation_generation,
            &self.https_authority,
            self.gateway_token_file.clone(),
            self.broker_endpoint()?,
        )
        .map_err(|_| ConfigError::InvalidCredentialRuntime)
    }

    fn from_getenv<F: Fn(&str) -> Option<String>>(getenv: &F) -> Result<Option<Self>, ConfigError> {
        let hosted_projection_sha256 = getenv(HOSTED_PROJECTION_SHA256_ENV)
            .map(|digest| {
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ConfigError::InvalidCredentialRuntime);
                }
                let mut bytes = [0; 32];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
                        .map_err(|_| ConfigError::InvalidCredentialRuntime)?;
                }
                if bytes == [0; 32] {
                    return Err(ConfigError::InvalidCredentialRuntime);
                }
                Ok(bytes)
            })
            .transpose()?;
        // ENVIRONMENT_ID is also used by SSH/Mesh. Its presence alone must not
        // activate credential delivery or require any credential transport.
        if CREDENTIAL_ENV_GROUP
            .iter()
            .all(|name| getenv(name).is_none())
        {
            return if hosted_projection_sha256.is_none() {
                Ok(None)
            } else {
                Err(ConfigError::InvalidCredentialRuntime)
            };
        }
        let required = |name| -> Result<String, ConfigError> {
            let value = getenv(name).ok_or(ConfigError::InvalidCredentialRuntime)?;
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(ConfigError::InvalidCredentialRuntime);
            }
            Ok(value)
        };
        let raw_id = required(ENVIRONMENT_ID_ENV)?;
        let environment_id =
            Uuid::parse_str(&raw_id).map_err(|_| ConfigError::InvalidCredentialRuntime)?;
        if environment_id.is_nil() || environment_id.to_string() != raw_id {
            return Err(ConfigError::InvalidCredentialRuntime);
        }
        let raw_generation = required(ENVIRONMENT_OPERATION_GENERATION_ENV)?;
        let operation_generation: u64 = raw_generation
            .parse()
            .map_err(|_| ConfigError::InvalidCredentialRuntime)?;
        if operation_generation == 0
            || operation_generation > i64::MAX as u64
            || operation_generation.to_string() != raw_generation
        {
            return Err(ConfigError::InvalidCredentialRuntime);
        }
        let listen_addr: SocketAddr = required(CREDENTIAL_HTTPS_LISTEN_ADDR_ENV)?
            .parse()
            .map_err(|_| ConfigError::InvalidCredentialRuntime)?;
        if listen_addr.port() != CREDENTIAL_HTTPS_PORT {
            return Err(ConfigError::InvalidCredentialRuntime);
        }
        let path = |name| -> Result<PathBuf, ConfigError> {
            let path = PathBuf::from(required(name)?);
            if !path.is_absolute() || path.file_name().is_none() {
                return Err(ConfigError::InvalidCredentialRuntime);
            }
            Ok(path)
        };
        let config = Self {
            hosted_projection_sha256,
            environment_id,
            operation_generation,
            https_authority: required(CREDENTIAL_HTTPS_AUTHORITY_ENV)?,
            listen_addr,
            gateway_token_file: path(CREDENTIAL_GATEWAY_TOKEN_FILE_ENV)?,
            tls_cert_file: path(CREDENTIAL_TLS_CERT_FILE_ENV)?,
            tls_key_file: path(CREDENTIAL_TLS_KEY_FILE_ENV)?,
            broker_https_origin: required(CREDENTIAL_BROKER_HTTPS_ORIGIN_ENV)?,
            broker_tls_roots_file: path(CREDENTIAL_BROKER_TLS_ROOTS_FILE_ENV)?,
        };
        config.server_tls()?;
        config.ingress()?;
        Ok(Some(config))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub shim_addr: String,
    pub daemon_auth_token: DaemonAuthToken,
    pub daemon_connect_timeout: Duration,
    pub ssh_listen_addr: String,
    pub readyz_listen_addr: String,
    pub host_key_path: String,
    pub listener_self_check_interval: Option<String>,
    pub api_url: Option<String>,
    pub binding_url: Option<String>,
    pub coordinator_url: Option<String>,
    pub derp_url: Option<String>,
    pub stun: Option<StunConfig>,
    pub stun_servers: Vec<StunConfig>,
    pub tailnet_udp_listen_addr: Option<SocketAddr>,
    pub tailnet_direct_udp_advertise_endpoints: Vec<SocketAddr>,
    pub udp_relay_allocator_url: Option<String>,
    pub udp_relay_allocator_token: Option<String>,
    pub udp_relay_bind_addrs: Vec<String>,
    pub tailnet: Option<TailnetConfig>,
    pub docker_proxy: Option<DockerProxyConfig>,
    pub debug_tailnet: bool,
    pub credentials: Option<CredentialRuntimeConfig>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TailnetConfig {
    pub environment_id: Uuid,
    pub gateway_token: String,
    pub coordinator_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerProxyConfig {
    pub listen_sock: String,
    pub upstream_sock: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{DAEMON_AUTH_TOKEN_ENV} is required")]
    MissingDaemonAuthToken,
    #[error("{DAEMON_AUTH_TOKEN_ENV} must be nonblank canonical ASCII metadata")]
    InvalidDaemonAuthToken,
    #[error("credential runtime configuration is incomplete or invalid")]
    InvalidCredentialRuntime,
    #[error("{name} must be a UDP port from 1 to 65535")]
    InvalidPort { name: &'static str },
    #[error("{name} contains invalid STUN server {value:?}; expected host[:port]")]
    InvalidStunServer { name: &'static str, value: String },
    #[error("{name} must be an IP socket address, got {value:?}: {message}")]
    InvalidSocketAddr {
        name: &'static str,
        value: String,
        message: String,
    },
    #[error("parse CODEWIRE_ENVIRONMENT_ID: {0}")]
    InvalidEnvironmentId(String),
    #[error("invalid Docker proxy config: {0}")]
    InvalidDockerProxy(String),
    #[error("{name} must be whole seconds from 1 to {max}, got {value:?}")]
    InvalidDurationSeconds {
        name: &'static str,
        value: String,
        max: u64,
    },
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        for name in CREDENTIAL_ENV_GROUP {
            if matches!(env::var(name), Err(env::VarError::NotUnicode(_))) {
                return Err(ConfigError::InvalidCredentialRuntime);
            }
        }
        let daemon_auth_token = match env::var(DAEMON_AUTH_TOKEN_ENV) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Err(ConfigError::MissingDaemonAuthToken),
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidDaemonAuthToken),
        };
        Self::from_getenv(|key| {
            if key == DAEMON_AUTH_TOKEN_ENV {
                Some(daemon_auth_token.clone())
            } else {
                env::var(key).ok()
            }
        })
    }

    pub fn from_getenv<F>(getenv: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let credentials = CredentialRuntimeConfig::from_getenv(&getenv)?;
        let shim_addr = env_or(&getenv, SHIM_ADDR_ENV, DEFAULT_SHIM_ADDR);
        let daemon_auth_token = getenv(DAEMON_AUTH_TOKEN_ENV)
            .ok_or(ConfigError::MissingDaemonAuthToken)
            .and_then(|value| {
                DaemonAuthToken::new(value).map_err(|_| ConfigError::InvalidDaemonAuthToken)
            })?;
        let daemon_connect_timeout = parse_duration_seconds_env(
            &getenv,
            DAEMON_CONNECT_TIMEOUT_SECONDS_ENV,
            DEFAULT_DAEMON_CONNECT_TIMEOUT_SECONDS,
            MAX_DAEMON_CONNECT_TIMEOUT_SECONDS,
        )?;
        let ssh_listen_addr = resolve_ssh_listen_addr(&getenv);
        let readyz_listen_addr =
            env_or(&getenv, READYZ_LISTEN_ADDR_ENV, DEFAULT_READYZ_LISTEN_ADDR);
        let host_key_path = env_or(&getenv, SSH_HOST_KEY_PATH_ENV, DEFAULT_HOST_KEY_PATH);
        let listener_self_check_interval =
            trim_env(&getenv, GATEWAY_LISTENER_SELF_CHECK_INTERVAL_ENV);
        let api_url = trim_env(&getenv, API_URL_ENV);
        let binding_url = trim_env(&getenv, BINDING_URL_ENV);
        let coordinator_url = resolve_coordinator_url(&getenv);
        let derp_url = trim_env(&getenv, DERP_URL_ENV);
        let (stun, stun_servers) = resolve_stun(&getenv)?;
        let tailnet_direct_udp_advertise_endpoints =
            parse_socket_addr_csv_env(&getenv, TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV)?;
        let tailnet_udp_listen_addr = resolve_tailnet_udp_listen_addr(
            &getenv,
            stun.is_some()
                || !stun_servers.is_empty()
                || !tailnet_direct_udp_advertise_endpoints.is_empty(),
        )?;
        let udp_relay_allocator_url = trim_env(&getenv, UDP_RELAY_ALLOCATOR_URL_ENV);
        let udp_relay_allocator_token = trim_env(&getenv, UDP_RELAY_ALLOCATOR_TOKEN_ENV);
        let udp_relay_bind_addrs = parse_csv_env(&getenv, UDP_RELAY_BIND_ADDRS_ENV);
        let tailnet = resolve_tailnet(&getenv, coordinator_url.as_deref())?;
        let docker_proxy = resolve_docker_proxy(&getenv)?;

        Ok(Self {
            shim_addr,
            daemon_auth_token,
            daemon_connect_timeout,
            ssh_listen_addr,
            readyz_listen_addr,
            host_key_path,
            listener_self_check_interval,
            api_url,
            binding_url,
            coordinator_url,
            derp_url,
            stun,
            stun_servers,
            tailnet_udp_listen_addr,
            tailnet_direct_udp_advertise_endpoints,
            udp_relay_allocator_url,
            udp_relay_allocator_token,
            udp_relay_bind_addrs,
            tailnet,
            docker_proxy,
            debug_tailnet: trim_env(&getenv, DEBUG_TAILNET_ENV).is_some(),
            credentials,
        })
    }
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayConfig")
            .field("shim_addr", &self.shim_addr)
            .field("daemon_auth_token", &self.daemon_auth_token)
            .field("daemon_connect_timeout", &self.daemon_connect_timeout)
            .field("ssh_listen_addr", &self.ssh_listen_addr)
            .field("readyz_listen_addr", &self.readyz_listen_addr)
            .field("host_key_path", &self.host_key_path)
            .field(
                "listener_self_check_interval",
                &self.listener_self_check_interval,
            )
            .field("api_url", &self.api_url)
            .field("binding_url", &self.binding_url)
            .field("coordinator_url", &self.coordinator_url)
            .field("derp_url", &self.derp_url)
            .field("stun", &self.stun)
            .field("stun_servers", &self.stun_servers)
            .field("tailnet_udp_listen_addr", &self.tailnet_udp_listen_addr)
            .field(
                "tailnet_direct_udp_advertise_endpoints",
                &self.tailnet_direct_udp_advertise_endpoints,
            )
            .field("udp_relay_allocator_url", &self.udp_relay_allocator_url)
            .field("udp_relay_allocator_token", &"[REDACTED]")
            .field("udp_relay_bind_addrs", &self.udp_relay_bind_addrs)
            .field("tailnet", &self.tailnet)
            .field("docker_proxy", &self.docker_proxy)
            .field("debug_tailnet", &self.debug_tailnet)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl fmt::Debug for TailnetConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TailnetConfig")
            .field("environment_id", &self.environment_id)
            .field("gateway_token", &"[REDACTED]")
            .field("coordinator_url", &self.coordinator_url)
            .finish()
    }
}

pub fn resolve_coordinator_url<F>(getenv: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(value) = trim_env(getenv, COORDINATOR_URL_ENV) {
        return Some(value);
    }
    trim_env(getenv, API_URL_ENV)
}

fn resolve_ssh_listen_addr<F>(getenv: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(addr) = trim_env(getenv, SSH_LISTEN_ADDR_ENV) {
        return addr;
    }
    if let Some(port) = trim_env(getenv, SSH_PORT_ENV) {
        return format!("0.0.0.0:{port}");
    }
    DEFAULT_SSH_LISTEN_ADDR.into()
}

fn resolve_stun<F>(getenv: &F) -> Result<(Option<StunConfig>, Vec<StunConfig>), ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let primary_port = match trim_env(getenv, STUN_PORT_ENV) {
        Some(value) => parse_u16_env(STUN_PORT_ENV, &value)?,
        None => 3478,
    };
    let primary = trim_env(getenv, STUN_HOST_ENV).map(|host| StunConfig {
        host,
        port: primary_port,
    });
    let mut servers = Vec::new();
    if let Some(primary) = primary.clone() {
        push_stun_server(&mut servers, primary);
    }
    if let Some(raw) = trim_env(getenv, STUN_SERVERS_ENV) {
        for entry in raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let server = parse_stun_server_entry(STUN_SERVERS_ENV, entry, 3478)?;
            push_stun_server(&mut servers, server);
        }
    }
    Ok((primary, servers))
}

fn push_stun_server(servers: &mut Vec<StunConfig>, server: StunConfig) {
    if !servers
        .iter()
        .any(|existing| existing.host == server.host && existing.port == server.port)
    {
        servers.push(server);
    }
}

fn parse_stun_server_entry(
    name: &'static str,
    value: &str,
    default_port: u16,
) -> Result<StunConfig, ConfigError> {
    let value = value
        .strip_prefix("stun://")
        .or_else(|| value.strip_prefix("stun:"))
        .unwrap_or(value)
        .trim();
    if value.is_empty() {
        return Err(ConfigError::InvalidStunServer {
            name,
            value: value.into(),
        });
    }

    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, rest)) = rest.split_once(']') else {
            return Err(ConfigError::InvalidStunServer {
                name,
                value: value.into(),
            });
        };
        let port = match rest.strip_prefix(':') {
            Some(port) => parse_u16_env(name, port)?,
            None if rest.is_empty() => default_port,
            _ => {
                return Err(ConfigError::InvalidStunServer {
                    name,
                    value: value.into(),
                });
            }
        };
        return Ok(StunConfig {
            host: host.into(),
            port,
        });
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, parse_u16_env(name, port)?)
        }
        _ => (value, default_port),
    };
    if host.is_empty() {
        return Err(ConfigError::InvalidStunServer {
            name,
            value: value.into(),
        });
    }
    Ok(StunConfig {
        host: host.into(),
        port,
    })
}

fn resolve_tailnet_udp_listen_addr<F>(
    getenv: &F,
    direct_udp_enabled: bool,
) -> Result<Option<SocketAddr>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match trim_env(getenv, TAILNET_UDP_LISTEN_ADDR_ENV) {
        Some(value) => parse_socket_addr_env(TAILNET_UDP_LISTEN_ADDR_ENV, &value).map(Some),
        None if direct_udp_enabled => {
            parse_socket_addr_env(TAILNET_UDP_LISTEN_ADDR_ENV, DEFAULT_TAILNET_UDP_LISTEN_ADDR)
                .map(Some)
        }
        None => Ok(None),
    }
}

fn resolve_tailnet<F>(
    getenv: &F,
    coordinator_url: Option<&str>,
) -> Result<Option<TailnetConfig>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(coordinator_url) = coordinator_url else {
        return Ok(None);
    };
    let Some(environment_id) = trim_env(getenv, ENVIRONMENT_ID_ENV) else {
        return Ok(None);
    };
    let Some(gateway_token) = trim_env(getenv, GATEWAY_TOKEN_ENV) else {
        return Ok(None);
    };

    let environment_id = Uuid::parse_str(&environment_id)
        .map_err(|err| ConfigError::InvalidEnvironmentId(err.to_string()))?;
    Ok(Some(TailnetConfig {
        environment_id,
        gateway_token,
        coordinator_url: coordinator_url.to_string(),
    }))
}

fn resolve_docker_proxy<F>(getenv: &F) -> Result<Option<DockerProxyConfig>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(listen_sock) = trim_env(getenv, DOCKER_PROXY_SOCK_ENV) else {
        return Ok(None);
    };
    let upstream_sock = trim_env(getenv, DOCKER_UPSTREAM_SOCK_ENV)
        .unwrap_or_else(|| DEFAULT_DOCKER_UPSTREAM_SOCK.into());
    DockerProxySettings::new(listen_sock.clone(), upstream_sock.clone())
        .map_err(|err| ConfigError::InvalidDockerProxy(err.to_string()))?;
    Ok(Some(DockerProxyConfig {
        listen_sock,
        upstream_sock,
    }))
}

fn parse_u16_env(name: &'static str, value: &str) -> Result<u16, ConfigError> {
    match value.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(ConfigError::InvalidPort { name }),
    }
}

fn parse_duration_seconds_env<F>(
    getenv: &F,
    name: &'static str,
    default_seconds: u64,
    max_seconds: u64,
) -> Result<Duration, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = trim_env(getenv, name) else {
        return Ok(Duration::from_secs(default_seconds));
    };
    match value.parse::<u64>() {
        Ok(seconds) if (1..=max_seconds).contains(&seconds) => Ok(Duration::from_secs(seconds)),
        _ => Err(ConfigError::InvalidDurationSeconds {
            name,
            value,
            max: max_seconds,
        }),
    }
}

fn parse_socket_addr_env(name: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value
        .parse::<SocketAddr>()
        .map_err(|err| ConfigError::InvalidSocketAddr {
            name,
            value: value.into(),
            message: err.to_string(),
        })
}

fn parse_socket_addr_csv_env<F>(
    getenv: &F,
    name: &'static str,
) -> Result<Vec<SocketAddr>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = trim_env(getenv, name) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_socket_addr_env(name, entry))
        .collect()
}

fn env_or<F>(getenv: &F, name: &str, default: &str) -> String
where
    F: Fn(&str) -> Option<String>,
{
    trim_env(getenv, name).unwrap_or_else(|| default.into())
}

fn trim_env<F>(getenv: &F, name: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    getenv(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_csv_env<F>(getenv: &F, name: &str) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    trim_env(getenv, name)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "config/credential_tests.rs"]
mod credential_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<GatewayConfig, ConfigError> {
        let mut vars: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect();
        vars.entry(DAEMON_AUTH_TOKEN_ENV.into())
            .or_insert_with(|| "gateway-daemon-test-token".into());
        GatewayConfig::from_getenv(|key| vars.get(key).cloned())
    }

    #[test]
    fn defaults_match_gateway_contract() {
        let cfg = config(&[]).unwrap();
        assert_eq!(cfg.shim_addr, DEFAULT_SHIM_ADDR);
        assert_eq!(
            cfg.daemon_connect_timeout,
            Duration::from_secs(DEFAULT_DAEMON_CONNECT_TIMEOUT_SECONDS)
        );
        assert_eq!(cfg.ssh_listen_addr, DEFAULT_SSH_LISTEN_ADDR);
        assert_eq!(cfg.readyz_listen_addr, DEFAULT_READYZ_LISTEN_ADDR);
        assert_eq!(cfg.host_key_path, "/codewire/gateway/ssh/host_ed25519");
        assert!(cfg.tailnet.is_none());
        assert!(cfg.stun.is_none());
        assert!(cfg.stun_servers.is_empty());
        assert_eq!(cfg.tailnet_udp_listen_addr, None);
        assert!(cfg.tailnet_direct_udp_advertise_endpoints.is_empty());
        assert_eq!(cfg.udp_relay_allocator_url, None);
        assert_eq!(cfg.udp_relay_allocator_token, None);
        assert!(cfg.udp_relay_bind_addrs.is_empty());
        assert!(cfg.docker_proxy.is_none());
    }

    #[test]
    fn daemon_auth_token_is_required_and_not_canonicalized() {
        assert_eq!(
            GatewayConfig::from_getenv(|_| None),
            Err(ConfigError::MissingDaemonAuthToken)
        );
        for invalid in ["", " ", " token", "token ", "line\nbreak"] {
            assert_eq!(
                GatewayConfig::from_getenv(|key| {
                    (key == DAEMON_AUTH_TOKEN_ENV).then(|| invalid.to_string())
                }),
                Err(ConfigError::InvalidDaemonAuthToken)
            );
        }
    }

    #[test]
    fn credential_debug_fields_are_redacted() {
        let daemon_marker = "daemon-debug-marker";
        let relay_marker = "relay-debug-marker";
        let gateway_marker = "gateway-debug-marker";
        let env_id = Uuid::new_v4().to_string();
        let config = config(&[
            (DAEMON_AUTH_TOKEN_ENV, daemon_marker),
            (UDP_RELAY_ALLOCATOR_TOKEN_ENV, relay_marker),
            (API_URL_ENV, "https://codewire.example"),
            (ENVIRONMENT_ID_ENV, &env_id),
            (GATEWAY_TOKEN_ENV, gateway_marker),
        ])
        .unwrap();

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        for marker in [daemon_marker, relay_marker, gateway_marker] {
            assert!(!debug.contains(marker), "debug exposed {marker}");
        }
    }

    #[test]
    fn daemon_connect_timeout_is_bounded_and_explicit() {
        let cfg = config(&[(DAEMON_CONNECT_TIMEOUT_SECONDS_ENV, "1500")]).unwrap();
        assert_eq!(cfg.daemon_connect_timeout, Duration::from_secs(1_500));

        for value in ["0", "3601", "not-seconds"] {
            assert_eq!(
                config(&[(DAEMON_CONNECT_TIMEOUT_SECONDS_ENV, value)]),
                Err(ConfigError::InvalidDurationSeconds {
                    name: DAEMON_CONNECT_TIMEOUT_SECONDS_ENV,
                    value: value.into(),
                    max: MAX_DAEMON_CONNECT_TIMEOUT_SECONDS,
                })
            );
        }
    }

    #[test]
    fn ssh_listen_addr_precedence_matches_gateway_contract() {
        let cfg = config(&[
            (SSH_LISTEN_ADDR_ENV, "127.0.0.1:2200"),
            (SSH_PORT_ENV, "2201"),
            ("SSH_PORT", "2202"),
        ])
        .unwrap();
        assert_eq!(cfg.ssh_listen_addr, "127.0.0.1:2200");

        let cfg = config(&[(SSH_PORT_ENV, "2201"), ("SSH_PORT", "2202")]).unwrap();
        assert_eq!(cfg.ssh_listen_addr, "0.0.0.0:2201");

        let cfg = config(&[("SSH_PORT", "2202")]).unwrap();
        assert_eq!(cfg.ssh_listen_addr, DEFAULT_SSH_LISTEN_ADDR);
    }

    #[test]
    fn coordinator_url_derives_from_api_url() {
        let cfg = config(&[(API_URL_ENV, "https://codewire.example/")]).unwrap();
        assert_eq!(
            cfg.coordinator_url.as_deref(),
            Some("https://codewire.example/")
        );
    }

    #[test]
    fn binding_url_is_explicit_config() {
        let cfg = config(&[
            (API_URL_ENV, "https://codewire.example/"),
            (
                BINDING_URL_ENV,
                "http://codewire-orchestration.dev.svc.cluster.local:8085",
            ),
        ])
        .unwrap();
        assert_eq!(
            cfg.binding_url.as_deref(),
            Some("http://codewire-orchestration.dev.svc.cluster.local:8085")
        );
        assert_eq!(
            cfg.coordinator_url.as_deref(),
            Some("https://codewire.example/")
        );
    }

    #[test]
    fn tailnet_requires_binding_credentials() {
        let cfg = config(&[(API_URL_ENV, "https://codewire.example")]).unwrap();
        assert!(cfg.coordinator_url.is_some());
        assert!(cfg.tailnet.is_none());
    }

    #[test]
    fn tailnet_parses_binding_credentials() {
        let env_id = Uuid::new_v4().to_string();
        let cfg = config(&[
            (API_URL_ENV, "https://codewire.example"),
            (ENVIRONMENT_ID_ENV, &env_id),
            (GATEWAY_TOKEN_ENV, "token"),
        ])
        .unwrap();
        let tailnet = cfg.tailnet.unwrap();
        assert_eq!(tailnet.environment_id, Uuid::parse_str(&env_id).unwrap());
        assert_eq!(tailnet.gateway_token, "token");
        assert_eq!(tailnet.coordinator_url, "https://codewire.example");
    }

    #[test]
    fn stun_servers_include_primary_and_extra_candidates() {
        let cfg = config(&[
            (STUN_HOST_ENV, "stun.codewire-dev.sh"),
            (STUN_PORT_ENV, "3478"),
            (
                STUN_SERVERS_ENV,
                "stun.codewire-dev.sh:3478, stun.l.google.com:19302, stun.cloudflare.com",
            ),
        ])
        .unwrap();
        assert_eq!(
            cfg.stun,
            Some(StunConfig {
                host: "stun.codewire-dev.sh".into(),
                port: 3478,
            })
        );
        assert_eq!(
            cfg.stun_servers,
            vec![
                StunConfig {
                    host: "stun.codewire-dev.sh".into(),
                    port: 3478,
                },
                StunConfig {
                    host: "stun.l.google.com".into(),
                    port: 19302,
                },
                StunConfig {
                    host: "stun.cloudflare.com".into(),
                    port: 3478,
                },
            ]
        );
        assert_eq!(
            cfg.tailnet_udp_listen_addr.unwrap().to_string(),
            DEFAULT_TAILNET_UDP_LISTEN_ADDR
        );
    }

    #[test]
    fn tailnet_udp_listen_addr_overrides_default_when_direct_udp_is_enabled() {
        let cfg = config(&[
            (STUN_HOST_ENV, "stun.codewire-dev.sh"),
            (TAILNET_UDP_LISTEN_ADDR_ENV, "127.0.0.1:32000"),
        ])
        .unwrap();
        assert_eq!(
            cfg.tailnet_udp_listen_addr.unwrap().to_string(),
            "127.0.0.1:32000"
        );
    }

    #[test]
    fn explicit_direct_udp_advertise_endpoints_enable_listener() {
        let cfg = config(&[(
            TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV,
            "192.0.2.36:33017, [2001:db8::1]:33017",
        )])
        .unwrap();
        assert_eq!(
            cfg.tailnet_udp_listen_addr.unwrap().to_string(),
            DEFAULT_TAILNET_UDP_LISTEN_ADDR
        );
        assert_eq!(
            cfg.tailnet_direct_udp_advertise_endpoints,
            vec![
                "192.0.2.36:33017".parse().unwrap(),
                "[2001:db8::1]:33017".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn udp_relay_allocator_config_is_explicit() {
        let cfg = config(&[
            (
                UDP_RELAY_ALLOCATOR_URL_ENV,
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
            ),
            (UDP_RELAY_ALLOCATOR_TOKEN_ENV, "allocator-token"),
            (
                UDP_RELAY_BIND_ADDRS_ENV,
                " codewire-udp-relay.dev.svc.cluster.local:41641, 127.0.0.1:41641 ",
            ),
        ])
        .unwrap();
        assert_eq!(
            cfg.udp_relay_allocator_url.as_deref(),
            Some(
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
            )
        );
        assert_eq!(
            cfg.udp_relay_allocator_token.as_deref(),
            Some("allocator-token")
        );
        assert_eq!(
            cfg.udp_relay_bind_addrs,
            vec![
                "codewire-udp-relay.dev.svc.cluster.local:41641",
                "127.0.0.1:41641",
            ]
        );
    }

    #[test]
    fn docker_proxy_defaults_upstream_socket() {
        let cfg = config(&[(DOCKER_PROXY_SOCK_ENV, "/codewire/run/docker.sock")]).unwrap();
        assert_eq!(
            cfg.docker_proxy,
            Some(DockerProxyConfig {
                listen_sock: "/codewire/run/docker.sock".into(),
                upstream_sock: DEFAULT_DOCKER_UPSTREAM_SOCK.into(),
            })
        );
    }

    #[test]
    fn docker_proxy_rejects_host_socket_upstream() {
        let err = config(&[
            (DOCKER_PROXY_SOCK_ENV, "/codewire/run/docker.sock"),
            (DOCKER_UPSTREAM_SOCK_ENV, "/var/run/docker.sock"),
        ])
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDockerProxy(_)));
        assert!(err.to_string().contains("forbidden host socket"));
    }
}
