use thiserror::Error;
use uuid::Uuid;

use crate::docker_proxy::DockerProxySettings;
use std::net::SocketAddr;

pub const SHIM_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const DEFAULT_SHIM_ADDR: &str = "127.0.0.1:7777";
pub const DEFAULT_SSH_LISTEN_ADDR: &str = "0.0.0.0:2222";
pub const DEFAULT_READYZ_LISTEN_ADDR: &str = "0.0.0.0:2223";
pub const DEFAULT_DOCKER_UPSTREAM_SOCK: &str = "/var/run/docker/docker.sock";
pub const DEFAULT_HOST_KEY_PATH: &str = "/codewire/workspace/.codewire/ssh/sidecar_host_ed25519";
pub const DEFAULT_TAILNET_UDP_LISTEN_ADDR: &str = "0.0.0.0:31000";

pub const SSH_LISTEN_ADDR_ENV: &str = "CODEWIRE_SSH_LISTEN_ADDR";
pub const READYZ_LISTEN_ADDR_ENV: &str = "CODEWIRE_READYZ_LISTEN_ADDR";
pub const SSH_PORT_ENV: &str = "CODEWIRE_SSH_PORT";
pub const LEGACY_SSH_PORT_ENV: &str = "SSH_PORT";
pub const SSH_HOST_KEY_PATH_ENV: &str = "CODEWIRE_SSH_HOST_KEY_PATH";
pub const GATEWAY_LISTENER_SELF_CHECK_INTERVAL_ENV: &str =
    "CODEWIRE_GATEWAY_LISTENER_SELF_CHECK_INTERVAL";

pub const ENVIRONMENT_ID_ENV: &str = "CODEWIRE_ENVIRONMENT_ID";
pub const GATEWAY_TOKEN_ENV: &str = "CODEWIRE_GATEWAY_TOKEN";
pub const API_URL_ENV: &str = "CODEWIRE_API_URL";
pub const BINDING_URL_ENV: &str = "CODEWIRE_BINDING_URL";
pub const COORDINATOR_URL_ENV: &str = "CODEWIRE_COORDINATOR_URL";
pub const COORDINATE_TRANSPORT_ENV: &str = "CODEWIRE_COORDINATE_TRANSPORT";
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

const COORDINATOR_PATH: &str = "/api/v1/internal/gateway/coordinate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub shim_addr: String,
    pub daemon_auth_token: Option<String>,
    pub ssh_listen_addr: String,
    pub readyz_listen_addr: String,
    pub host_key_path: String,
    pub listener_self_check_interval: Option<String>,
    pub api_url: Option<String>,
    pub binding_url: Option<String>,
    pub coordinator_url: Option<String>,
    pub coordinate_transport: CoordinateTransport,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailnetConfig {
    pub environment_id: Uuid,
    pub gateway_token: String,
    pub coordinator_url: String,
    pub coordinate_transport: CoordinateTransport,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CoordinateTransport {
    Ws,
    Connect,
    #[default]
    Auto,
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
    #[error("CODEWIRE_COORDINATE_TRANSPORT must be exactly ws, connect, or auto; got {0:?}")]
    InvalidCoordinateTransport(String),
    #[error("invalid Docker proxy config: {0}")]
    InvalidDockerProxy(String),
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_getenv(|key| std::env::var(key).ok())
    }

    pub fn from_getenv<F>(getenv: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let shim_addr = env_or(&getenv, SHIM_ADDR_ENV, DEFAULT_SHIM_ADDR);
        let daemon_auth_token = trim_env(&getenv, DAEMON_AUTH_TOKEN_ENV);
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
        let coordinate_transport = resolve_coordinate_transport(&getenv)?;
        let tailnet = resolve_tailnet(&getenv, coordinator_url.as_deref(), coordinate_transport)?;
        let docker_proxy = resolve_docker_proxy(&getenv)?;

        Ok(Self {
            shim_addr,
            daemon_auth_token,
            ssh_listen_addr,
            readyz_listen_addr,
            host_key_path,
            listener_self_check_interval,
            api_url,
            binding_url,
            coordinator_url,
            coordinate_transport,
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
        })
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
        .map(|api_url| format!("{}{}", api_url.trim_end_matches('/'), COORDINATOR_PATH))
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
    if let Some(port) = trim_env(getenv, LEGACY_SSH_PORT_ENV) {
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
    coordinate_transport: CoordinateTransport,
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
        coordinate_transport,
    }))
}

fn resolve_coordinate_transport<F>(getenv: &F) -> Result<CoordinateTransport, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match getenv(COORDINATE_TRANSPORT_ENV)
        .filter(|value| !value.is_empty())
        .as_deref()
    {
        None | Some("auto") => Ok(CoordinateTransport::Auto),
        Some("ws") => Ok(CoordinateTransport::Ws),
        Some("connect") => Ok(CoordinateTransport::Connect),
        Some(value) => Err(ConfigError::InvalidCoordinateTransport(value.into())),
    }
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
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<GatewayConfig, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect();
        GatewayConfig::from_getenv(|key| vars.get(key).cloned())
    }

    #[test]
    fn defaults_match_go_gateway() {
        let cfg = config(&[]).unwrap();
        assert_eq!(cfg.shim_addr, DEFAULT_SHIM_ADDR);
        assert_eq!(cfg.ssh_listen_addr, DEFAULT_SSH_LISTEN_ADDR);
        assert_eq!(cfg.readyz_listen_addr, DEFAULT_READYZ_LISTEN_ADDR);
        assert_eq!(cfg.host_key_path, DEFAULT_HOST_KEY_PATH);
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
    fn ssh_listen_addr_precedence_matches_go_gateway() {
        let cfg = config(&[
            (SSH_LISTEN_ADDR_ENV, "127.0.0.1:2200"),
            (SSH_PORT_ENV, "2201"),
            (LEGACY_SSH_PORT_ENV, "2202"),
        ])
        .unwrap();
        assert_eq!(cfg.ssh_listen_addr, "127.0.0.1:2200");

        let cfg = config(&[(SSH_PORT_ENV, "2201"), (LEGACY_SSH_PORT_ENV, "2202")]).unwrap();
        assert_eq!(cfg.ssh_listen_addr, "0.0.0.0:2201");

        let cfg = config(&[(LEGACY_SSH_PORT_ENV, "2202")]).unwrap();
        assert_eq!(cfg.ssh_listen_addr, "0.0.0.0:2202");
    }

    #[test]
    fn coordinator_url_derives_from_api_url() {
        let cfg = config(&[(API_URL_ENV, "https://codewire.example/")]).unwrap();
        assert_eq!(
            cfg.coordinator_url.as_deref(),
            Some("https://codewire.example/api/v1/internal/gateway/coordinate")
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
            Some("https://codewire.example/api/v1/internal/gateway/coordinate")
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
        assert_eq!(tailnet.coordinate_transport, CoordinateTransport::Auto);
    }

    #[test]
    fn coordinate_transport_accepts_only_exact_values_and_defaults_to_auto() {
        for (raw, expected) in [
            (None, CoordinateTransport::Auto),
            (Some("ws"), CoordinateTransport::Ws),
            (Some("connect"), CoordinateTransport::Connect),
            (Some("auto"), CoordinateTransport::Auto),
        ] {
            assert_eq!(
                resolve_coordinate_transport(&|key| {
                    (key == COORDINATE_TRANSPORT_ENV).then(|| raw.unwrap_or_default().to_string())
                })
                .unwrap(),
                expected
            );
        }

        for raw in ["WS", "Connect", "automatic", "ws,connect", " ws", "auto "] {
            assert_eq!(
                config(&[(COORDINATE_TRANSPORT_ENV, raw)]).unwrap_err(),
                ConfigError::InvalidCoordinateTransport(raw.into())
            );
        }
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
