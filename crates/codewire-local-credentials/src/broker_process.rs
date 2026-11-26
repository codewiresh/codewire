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
    /// Whether the environment's network policy allows GitHub's hosts by
    /// rule (#4926). The default is no: a caller of this client that does
    /// not say is refused the managed GitHub credential.
    pub network_policy_allows_github: bool,
    /// The bound hosts the environment's network policy allows by rule on
    /// 443, lowercase (#5555). A caller that does not say gets none, and its
    /// broker forwards no front-door request carrying no placeholder.
    pub network_policy_allowed_hosts: BTreeSet<String>,
    /// An intercepting boot's secrets, for each broker it starts (#3999).
    pub boot_secrets: crate::BrokerBootSecrets,
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
    /// Whether the child serves the managed GitHub credential: the
    /// environment's network policy allows GitHub's hosts by rule (#4926).
    pub network_policy_allows_github: bool,
    /// Where the child may forward a front-door request carrying no
    /// placeholder untouched (#5555).
    pub network_policy_allowed_hosts: BTreeSet<String>,
}

impl LocalBrokerProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalBrokerSpawnError> {
        if self.environment_generation == 0
            || (self.platform_delegated && !self.http_providers.is_empty())
            || !valid_environment_name(&self.environment_name)
            || self.network_policy_allowed_hosts.len() > MAX_ALLOWED_HOSTS
            || !self
                .network_policy_allowed_hosts
                .iter()
                .all(|host| valid_allowed_host(host))
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

/// What a broker child is told about provider hosts that do not resolve at
/// its start (#5286; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "A provider that
/// can't be looked up when a local VM starts").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderLookup {
    /// No child serves this generation: start whatever resolves.
    Available,
    /// A replacement for a serving child that left exactly these hosts
    /// unresolved. It starts only if every other host resolves, so it never
    /// takes over serving fewer providers than the child it replaces.
    NoFewerThan(BTreeSet<String>),
    /// An early replacement for a serving child that left exactly these
    /// hosts unresolved, started to get one back. It starts only if every
    /// other host resolves and at least one of these does: otherwise it
    /// would replace a working child for nothing.
    FewerThan(BTreeSet<String>),
}

impl ProviderLookup {
    /// The rule's name on a `broker_spawned` line of the broker log. A child
    /// started as `early` that never becomes ready got no host back, which
    /// is not a fault.
    pub(crate) fn log_name(&self) -> &'static str {
        match self {
            Self::Available => "first",
            Self::NoFewerThan(_) => "regular",
            Self::FewerThan(_) => "early",
        }
    }

    /// The broker command's arguments that carry this rule.
    pub fn arguments(&self) -> Vec<String> {
        fn may_not_resolve(unresolved: &BTreeSet<String>) -> impl Iterator<Item = String> + '_ {
            unresolved
                .iter()
                .map(|host| format!("--may-not-resolve={host}"))
        }
        match self {
            Self::Available => vec!["--start-whatever-resolves".to_owned()],
            Self::NoFewerThan(unresolved) => may_not_resolve(unresolved).collect(),
            Self::FewerThan(unresolved) => may_not_resolve(unresolved)
                .chain(["--must-resolve-more".to_owned()])
                .collect(),
        }
    }
}

/// More than any route table binds; the answer names only bound hosts.
const MAX_ALLOWED_HOSTS: usize = 16;

/// A lowercase DNS name of letters, digits, hyphens and dots, or `*.` and a
/// routed suffix: each becomes a broker argument, so it never starts with
/// `-`.
fn valid_allowed_host(host: &str) -> bool {
    if let Some(suffix) = host.strip_prefix("*.") {
        return codewire_access::ROUTED_SUFFIXES.contains(&suffix);
    }
    host.len() <= 253
        && !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
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
    /// The runner protocol the brokers this spawner starts accept. The
    /// authority reports it, so a cw whose runner speaks another protocol
    /// knows these brokers cannot serve its VMs (#5238).
    fn runner_protocol(&self) -> u32;

    /// Start one broker child. A boot's `boot_secrets`, when it has any,
    /// reach the child only on an inherited descriptor (#3999).
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        lookup: &ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        boot_secrets: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError>;
}

/// What this crate's test spawners report as their brokers' runner protocol.
#[cfg(test)]
pub(crate) const TEST_RUNNER_PROTOCOL: u32 = 7;

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
            network_policy_allows_github: true,
            network_policy_allowed_hosts: Default::default(),
        }
    }

    /// #5555: each allowed host becomes a broker argument, so only a bounded
    /// set of lowercase DNS names is launched.
    #[test]
    fn only_lowercase_dns_names_are_launched_as_allowed_hosts() {
        let with = |hosts: &[&str]| LocalBrokerProcessConfig {
            network_policy_allowed_hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            ..config("project")
        };
        assert!(
            with(&["api.anthropic.com", "chatgpt.com", "*.chatgpt.com"])
                .validate()
                .is_ok()
        );
        for denied in [
            "",
            "-x",
            "--network-policy-allows-github",
            "API.anthropic.com",
            "api.anthropic.com.",
            "a..b",
            "-a.com",
            "api.anthropic.com:443",
            "*.example.com",
            "*.a.chatgpt.com",
            "*.",
        ] {
            assert_eq!(
                with(&[denied]).validate(),
                Err(LocalBrokerSpawnError::InvalidConfiguration),
                "{denied}"
            );
        }
        let many: Vec<String> = (0..=MAX_ALLOWED_HOSTS)
            .map(|index| format!("h{index}.com"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            with(&many).validate(),
            Err(LocalBrokerSpawnError::InvalidConfiguration)
        );
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
            HttpProvider::GeminiApiKey,
            HttpProvider::GitHubOAuth,
        ] {
            assert_eq!(HttpProvider::parse(provider.as_str()), Some(provider));
            config.http_providers.insert(provider);
            config.validate().unwrap();
        }
        assert!(HttpProvider::parse("https://arbitrary-provider.invalid").is_none());
    }
}
