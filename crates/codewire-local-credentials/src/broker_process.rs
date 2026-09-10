use std::collections::BTreeSet;
use std::path::PathBuf;

use codewire_access::{EnvironmentId, HttpProvider};
use thiserror::Error;

/// Exact owner-selected sources for one environment broker. Absence of a
/// local profile explicitly selects none; it never discovers an ambient one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentBrokerSelection {
    pub local_profile: Option<codewire_access::EnvironmentAccessBinding>,
    pub projection: Option<crate::LocalEnvironmentProjectionBinding>,
    pub platform: Option<crate::PlatformCredentialBinding>,
}

/// Material-free launch description for one environment generation. Provider
/// values and protected-store references are structurally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalBrokerProcessConfig {
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub environment_name: String,
    pub runner_socket: PathBuf,
    pub http_providers: BTreeSet<HttpProvider>,
    /// The child is a material-free platform relay, not a local store reader.
    pub platform_delegated: bool,
}

impl LocalBrokerProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalBrokerSpawnError> {
        if self.environment_generation == 0
            || (self.platform_delegated && !self.http_providers.is_empty())
            || !valid_environment_name(&self.environment_name)
            || !self.runner_socket.is_absolute()
            || self
                .runner_socket
                .file_name()
                .and_then(|name| name.to_str())
                != Some(format!("{}.sock", self.environment_id).as_str())
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
            runner_socket: PathBuf::from("/run/user/1000/codewire/runners/environment-id.sock"),
            http_providers: BTreeSet::from([HttpProvider::OpenAiApiKey]),
            platform_delegated: false,
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

    #[test]
    fn launch_accepts_application_only_and_exact_supported_provider_sets() {
        let mut config = config("project");
        config.http_providers.clear();
        config.validate().unwrap();
        for provider in [
            HttpProvider::OpenAiApiKey,
            HttpProvider::CodexOAuth,
            HttpProvider::AnthropicApiKey,
            HttpProvider::GitHubOAuth,
        ] {
            assert_eq!(HttpProvider::parse(provider.as_str()), Some(provider));
            config.http_providers.insert(provider);
            config.validate().unwrap();
        }
        assert!(HttpProvider::parse("https://arbitrary-provider.invalid").is_none());
    }
}
