use std::path::PathBuf;

use codewire_access::EnvironmentId;
use thiserror::Error;

/// Material-free launch description for one environment generation. Provider
/// values and protected-store references are structurally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalBrokerProcessConfig {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub environment_name: String,
    pub supervisor_socket: PathBuf,
}

impl LocalBrokerProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalBrokerSpawnError> {
        if self.environment_generation == 0
            || !valid_environment_name(&self.environment_name)
            || !self.supervisor_socket.is_absolute()
            || self
                .supervisor_socket
                .file_name()
                .and_then(|name| name.to_str())
                != Some("supervisor.sock")
        {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Exact broker generation currently owned by the local authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentBrokerRuntime {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub running: bool,
}

/// Stable launch failures that carry no process environment or command line.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalBrokerSpawnError {
    #[error("local credential broker launch configuration is invalid")]
    InvalidConfiguration,
    #[error("spawn local credential broker failed")]
    Spawn,
}

/// Authority-owned broker launcher. The stream peer is transferred directly
/// into the isolated child and must become its only lease-authority channel.
pub trait LocalBrokerProcessSpawner: Send + Sync + 'static {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(name: &str) -> LocalBrokerProcessConfig {
        LocalBrokerProcessConfig {
            environment_id: EnvironmentId::parse("environment-id").unwrap(),
            environment_generation: 1,
            environment_name: name.to_owned(),
            supervisor_socket: PathBuf::from("/run/user/1000/codewire/supervisor.sock"),
        }
    }

    #[test]
    fn launch_name_matches_the_supervisor_grammar() {
        for admitted in ["a", "project.one", "project_two", "project-three"] {
            assert!(config(admitted).validate().is_ok(), "{admitted}");
        }
        for denied in [
            "",
            "-project",
            " project",
            "project/path",
            "project:one",
            &"a".repeat(64),
        ] {
            assert_eq!(
                config(denied).validate(),
                Err(LocalBrokerSpawnError::InvalidConfiguration),
                "{denied}"
            );
        }
    }
}
