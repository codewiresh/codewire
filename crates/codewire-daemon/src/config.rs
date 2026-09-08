use std::env;
use std::path::{Path, PathBuf};

use codewire_access::ManagedCredentialClients;
use codewire_gateway_proto::DaemonAuthToken;
use uuid::Uuid;

use crate::execution::ProcessExecution;

pub const SHIM_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";
pub const WORKSPACE_ROOT_ENV: &str = "CODEWIRE_WORKSPACE_ROOT";
pub const HOME_ROOT_ENV: &str = "CODEWIRE_HOME_ROOT";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const HOSTED_PROJECTION_SHA256_ENV: &str = "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256";
pub const MANAGED_CREDENTIAL_CLIENTS_ENV: &str = "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS";
pub const ENVIRONMENT_ID_ENV: &str = "CODEWIRE_ENVIRONMENT_ID";
pub const ENVIRONMENT_GENERATION_ENV: &str = "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION";
pub const HOSTED_PROCESS_DIRECTORY: &str = "/codewire/run/processes";
pub const HOSTED_CREDENTIAL_SOCKET: &str = "/codewire/run/credentials.sock";

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
    /// Exact stock-client selection captured from the bound profile revision.
    /// This contains no credential, endpoint supplied by a user, or grant.
    pub managed_credential_clients: ManagedCredentialClients,
    /// Exact source selection for one-launch application values, never values.
    pub launch_projection: Option<LaunchProjectionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchProjectionConfig {
    pub selection_sha256: [u8; 32],
    /// Required for Native; runc uses its sealed /init and process directory.
    pub native: Option<NativeLaunchProjectionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLaunchProjectionConfig {
    /// The installed normal cw executable, with its early hidden entry point.
    pub helper_path: PathBuf,
    /// An existing owner-private (0700) runtime directory, outside the child.
    pub process_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBridgeConfig {
    pub transport: CredentialBridgeTransport,
    pub environment_id: Uuid,
    pub environment_generation: u64,
    pub ingress_socket: PathBuf,
    pub ingress_uid: u32,
    pub ingress_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBridgeTransport {
    Local,
    /// Existing capability-authenticated, plaintext intra-cluster daemon leg.
    /// Its gateway separately authenticates both Pod tokens to the TLS broker.
    Hosted,
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
        let mut config = Self {
            listen_addr: env_value(SHIM_ADDR_ENV).unwrap_or_else(|| DEFAULT_LISTEN_ADDR.into()),
            workspace_root: env_path(WORKSPACE_ROOT_ENV, DEFAULT_WORKSPACE_ROOT),
            home_root: env_path(HOME_ROOT_ENV, DEFAULT_HOME_ROOT),
            auth_token,
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: ManagedCredentialClients::default(),
            launch_projection: None,
        };
        config.configure_hosted_projection(|name| env::var_os(name))?;
        Ok(config)
    }

    fn configure_hosted_projection(
        &mut self,
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<(), ConfigError> {
        // ID is also used without credential delivery. Only the admitted
        // selection digest activates this all-or-none hosted configuration.
        let digest = lookup(HOSTED_PROJECTION_SHA256_ENV);
        let managed_credential_clients = lookup(MANAGED_CREDENTIAL_CLIENTS_ENV);
        let (digest, managed_credential_clients) = match (digest, managed_credential_clients) {
            (None, None) => return Ok(()),
            (Some(digest), Some(managed_credential_clients)) => {
                (digest, managed_credential_clients)
            }
            _ => return Err(ConfigError::InvalidHostedProjection),
        };
        let invalid = || ConfigError::InvalidHostedProjection;
        let digest = digest.to_str().ok_or_else(invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        let mut selection_sha256 = [0; 32];
        for (index, byte) in selection_sha256.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
        }
        if selection_sha256 == [0; 32] {
            return Err(invalid());
        }
        let managed_credential_clients = managed_credential_clients.to_str().ok_or_else(invalid)?;
        let managed_credential_clients =
            ManagedCredentialClients::decode(managed_credential_clients).map_err(|_| invalid())?;
        let id = lookup(ENVIRONMENT_ID_ENV).ok_or_else(invalid)?;
        let id = id.to_str().ok_or_else(invalid)?;
        let environment_id = Uuid::parse_str(id).map_err(|_| invalid())?;
        let generation = lookup(ENVIRONMENT_GENERATION_ENV).ok_or_else(invalid)?;
        let generation = generation.to_str().ok_or_else(invalid)?;
        let environment_generation: u64 = generation.parse().map_err(|_| invalid())?;
        if environment_id.is_nil()
            || environment_id.to_string() != id
            || environment_generation == 0
            || environment_generation > i64::MAX as u64
            || environment_generation.to_string() != generation
        {
            return Err(invalid());
        }
        self.credential_bridge = Some(CredentialBridgeConfig {
            transport: CredentialBridgeTransport::Hosted,
            environment_id,
            environment_generation,
            ingress_socket: HOSTED_CREDENTIAL_SOCKET.into(),
            ingress_uid: 1000,
            ingress_gid: 1000,
        });
        self.managed_credential_clients = managed_credential_clients;
        self.launch_projection = Some(LaunchProjectionConfig {
            selection_sha256,
            native: Some(NativeLaunchProjectionConfig {
                helper_path: "/codewire/bin/cw".into(),
                process_directory: HOSTED_PROCESS_DIRECTORY.into(),
            }),
        });
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{DAEMON_AUTH_TOKEN_ENV} is required")]
    MissingDaemonAuthToken,
    #[error("{DAEMON_AUTH_TOKEN_ENV} must be nonblank canonical ASCII metadata")]
    InvalidDaemonAuthToken,
    #[error("hosted environment projection configuration is invalid")]
    InvalidHostedProjection,
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

    fn fixture() -> Config {
        Config {
            listen_addr: DEFAULT_LISTEN_ADDR.into(),
            workspace_root: DEFAULT_WORKSPACE_ROOT.into(),
            home_root: DEFAULT_HOME_ROOT.into(),
            auth_token: DaemonAuthToken::new("synthetic").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: ManagedCredentialClients::default(),
            launch_projection: None,
        }
    }

    #[test]
    fn hosted_selection_configuration_is_explicit_canonical_and_metadata_only() {
        let id = Uuid::new_v4().to_string();
        let mut config = fixture();
        config
            .configure_hosted_projection(|name| {
                (name == ENVIRONMENT_ID_ENV).then(|| id.clone().into())
            })
            .unwrap();
        assert!(config.credential_bridge.is_none());
        let values = [
            (HOSTED_PROJECTION_SHA256_ENV, "ab".repeat(32)),
            (
                MANAGED_CREDENTIAL_CLIENTS_ENV,
                "v1:codex,anthropic,ssh".into(),
            ),
            (ENVIRONMENT_ID_ENV, id),
            (ENVIRONMENT_GENERATION_ENV, "7".into()),
        ];
        config
            .configure_hosted_projection(|name| {
                values
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone().into())
            })
            .unwrap();
        assert_eq!(
            config.credential_bridge.as_ref().unwrap().transport,
            CredentialBridgeTransport::Hosted
        );
        assert_eq!(
            config
                .credential_bridge
                .as_ref()
                .unwrap()
                .environment_generation,
            7
        );
        assert_eq!(
            config.managed_credential_clients.encode(),
            "v1:codex,anthropic,ssh"
        );
        let projection = config.launch_projection.as_ref().unwrap();
        assert_eq!(projection.selection_sha256, [0xab; 32]);
        assert_eq!(
            projection.native.as_ref().unwrap().process_directory,
            Path::new(HOSTED_PROCESS_DIRECTORY)
        );
        assert_eq!(
            projection.native.as_ref().unwrap().helper_path,
            Path::new("/codewire/bin/cw")
        );
        for (field, invalid) in [
            (HOSTED_PROJECTION_SHA256_ENV, "00".repeat(32)),
            (HOSTED_PROJECTION_SHA256_ENV, "AB".repeat(32)),
            (ENVIRONMENT_GENERATION_ENV, "0".into()),
            (ENVIRONMENT_GENERATION_ENV, "07".into()),
            (ENVIRONMENT_GENERATION_ENV, u64::MAX.to_string()),
            (ENVIRONMENT_ID_ENV, Uuid::nil().to_string()),
        ] {
            assert_eq!(
                fixture().configure_hosted_projection(|name| if name == field {
                    Some(invalid.clone().into())
                } else {
                    values
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone().into())
                }),
                Err(ConfigError::InvalidHostedProjection)
            );
        }
        for missing in [
            MANAGED_CREDENTIAL_CLIENTS_ENV,
            ENVIRONMENT_ID_ENV,
            ENVIRONMENT_GENERATION_ENV,
        ] {
            assert!(
                fixture()
                    .configure_hosted_projection(|name| if name == missing {
                        None
                    } else {
                        values
                            .iter()
                            .find(|(key, _)| *key == name)
                            .map(|(_, value)| value.clone().into())
                    })
                    .is_err()
            );
        }
        for (present, value) in [
            (MANAGED_CREDENTIAL_CLIENTS_ENV, "v1:codex"),
            (HOSTED_PROJECTION_SHA256_ENV, "ab"),
        ] {
            assert_eq!(
                fixture().configure_hosted_projection(|name| {
                    (name == present).then(|| value.into())
                }),
                Err(ConfigError::InvalidHostedProjection)
            );
        }
        for invalid in ["", "none", "v1:", "v1:openai,codex", "v1:github"] {
            assert_eq!(
                fixture().configure_hosted_projection(|name| {
                    values
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| {
                            if name == MANAGED_CREDENTIAL_CLIENTS_ENV {
                                invalid.into()
                            } else {
                                value.clone().into()
                            }
                        })
                }),
                Err(ConfigError::InvalidHostedProjection)
            );
        }

        let mut app_only = fixture();
        app_only
            .configure_hosted_projection(|name| {
                values
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| {
                        if name == MANAGED_CREDENTIAL_CLIENTS_ENV {
                            "v1:none".into()
                        } else {
                            value.clone().into()
                        }
                    })
            })
            .unwrap();
        assert_eq!(
            app_only.managed_credential_clients,
            ManagedCredentialClients::default()
        );
        assert!(app_only.launch_projection.is_some());
    }

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
            managed_credential_clients: ManagedCredentialClients::default(),
            launch_projection: None,
        };

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
    }
}
