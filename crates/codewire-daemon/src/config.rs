use std::env;
use std::path::{Path, PathBuf};

use codewire_gateway_proto::DaemonAuthToken;
use uuid::Uuid;

use crate::execution::ProcessExecution;

pub const SHIM_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";
pub const WORKSPACE_ROOT_ENV: &str = "CODEWIRE_WORKSPACE_ROOT";
pub const HOME_ROOT_ENV: &str = "CODEWIRE_HOME_ROOT";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:7777";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
pub const DEFAULT_HOME_ROOT: &str = "/home/codewire";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen_addr: String,
    pub workspace_root: PathBuf,
    pub home_root: PathBuf,
    pub auth_token: DaemonAuthToken,
    pub process_execution: ProcessExecution,
    /// Local/platform placement-specific guest endpoint for material-free
    /// credential requests. Protected values never enter this configuration.
    pub credential_bridge: Option<CredentialBridgeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBridgeConfig {
    pub environment_id: Uuid,
    pub environment_generation: u64,
    pub ingress_socket: PathBuf,
    pub ingress_uid: u32,
    pub ingress_gid: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let auth_token = match env::var(DAEMON_AUTH_TOKEN_ENV) {
            Ok(value) => {
                DaemonAuthToken::new(value).map_err(|_| ConfigError::InvalidDaemonAuthToken)?
            }
            Err(env::VarError::NotPresent) => return Err(ConfigError::MissingDaemonAuthToken),
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidDaemonAuthToken),
        };
        Ok(Self {
            listen_addr: env_value(SHIM_ADDR_ENV).unwrap_or_else(|| DEFAULT_LISTEN_ADDR.into()),
            workspace_root: env_path(WORKSPACE_ROOT_ENV, DEFAULT_WORKSPACE_ROOT),
            home_root: env_path(HOME_ROOT_ENV, DEFAULT_HOME_ROOT),
            auth_token,
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{DAEMON_AUTH_TOKEN_ENV} is required")]
    MissingDaemonAuthToken,
    #[error("{DAEMON_AUTH_TOKEN_ENV} must be nonblank canonical ASCII metadata")]
    InvalidDaemonAuthToken,
}

fn env_value(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_path(key: &str, default: &str) -> PathBuf {
    env_value(key)
        .map(|value| clean_path(Path::new(&value)))
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| clean_path(Path::new(default)))
}

pub fn clean_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    let absolute = raw.starts_with('/');
    let mut parts = Vec::<&str>::new();

    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last().copied() {
                Some("..") if !absolute => parts.push(".."),
                Some(_) => {
                    parts.pop();
                }
                None if !absolute => parts.push(".."),
                None => {}
            },
            part => parts.push(part),
        }
    }

    if absolute {
        if parts.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(format!("/{}", parts.join("/")))
        }
    } else if parts.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_collapses_dot_and_parent_components() {
        assert_eq!(
            clean_path(Path::new("/workspace/./a/../b")),
            PathBuf::from("/workspace/b")
        );
        assert_eq!(clean_path(Path::new("a/./b/../c")), PathBuf::from("a/c"));
        assert_eq!(clean_path(Path::new("../../x")), PathBuf::from("../../x"));
    }

    #[test]
    fn config_debug_redacts_daemon_credential() {
        let marker = "daemon-config-secret-marker";
        let config = Config {
            listen_addr: DEFAULT_LISTEN_ADDR.into(),
            workspace_root: DEFAULT_WORKSPACE_ROOT.into(),
            home_root: DEFAULT_HOME_ROOT.into(),
            auth_token: DaemonAuthToken::new(marker).unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
        };

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
    }
}
