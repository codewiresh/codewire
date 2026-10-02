use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

const CODEX_PROVIDER_ID: &str = "codewire_openai";
const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Relative path for the generated credential-free Codex provider config.
pub const CODEX_CONFIG_FILE_NAME: &str = "config.toml";

/// Projected, purpose-bound workspace capability, never provider material.
pub const CODEX_PLATFORM_TOKEN_FILE: &str = "/run/codewire-credentials/workspace/token";
/// Public gateway CA bundle mounted only as trust, not a private identity.
pub const CODEX_PLATFORM_ROOTS_FILE: &str = "/run/codewire-credentials/gateway-roots/ca.crt";
/// Writable per-Pod Codex state, separate from the persisted user workspace.
pub const CODEX_PLATFORM_HOME: &str = "/run/codewire-codex/home";
/// Native Codex state mounted at the existing isolated guest path.
pub const CODEX_NATIVE_HOME: &str = "/run/codewire-agent/codex";
/// Native workspace path for the distinct selected-key OpenSSH agent ingress.
pub const SSH_NATIVE_AUTH_SOCK: &str = "/run/codewire-host/ssh-agent.sock";
/// Hosted workspace path for the distinct selected-key OpenSSH agent ingress.
pub const SSH_PLATFORM_AUTH_SOCK: &str = "/codewire/run/ssh-agent.sock";
/// Fixed per-environment HTTP ingress; callers own listener authentication and readiness.
pub const MANAGED_HTTP_PORT: u16 = 38_081;
/// Workspace environment variable carrying the managed clients orchestration
/// rendered for one Pod, in [`ManagedCredentialClients::encode`] form.
pub const MANAGED_CREDENTIAL_CLIENTS_ENV: &str = "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS";
/// Base-URL path for the distinct OpenAI API-key profile slot. Only POST
/// responses is admitted; ordinary Codex configuration retains its own route.
pub const MANAGED_OPENAI_API_PREFIX: &str = "/_codewire/openai/v1";
/// Smart Git prefix on the existing managed HTTP ingress. Only the selected
/// GitHub adapter may resolve this route to an upstream provider.
pub const MANAGED_GITHUB_GIT_PREFIX: &str = "/_codewire/github/";

/// Stock clients configured by selected profile slots, not credential auth kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedCredentialClient {
    Codex,
    OpenAi,
    Anthropic,
    Ssh,
    GitHub,
}

impl ManagedCredentialClient {
    const fn bit(self) -> u8 {
        match self {
            Self::Codex => 1,
            Self::OpenAi => 2,
            Self::Anthropic => 4,
            Self::Ssh => 8,
            Self::GitHub => 16,
        }
    }

    fn environment_keys(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["CODEX_HOME"],
            Self::OpenAi => &["OPENAI_BASE_URL", "OPENAI_API_KEY"],
            Self::Anthropic => &[
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "CLAUDE_CODE_OAUTH_TOKEN",
            ],
            Self::Ssh => &["SSH_AUTH_SOCK"],
            // Checkout owns an exact command-scoped URL rewrite, never a
            // provider token or an ambient/global Git configuration.
            Self::GitHub => &[],
        }
    }
}

/// Closed layouts for the existing native and hosted client bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedCredentialClientPlacement {
    Native,
    Platform,
}

const MANAGED_CLIENT_ENCODINGS: [&str; 32] = [
    "v1:none",
    "v1:codex",
    "v1:openai",
    "v1:codex,openai",
    "v1:anthropic",
    "v1:codex,anthropic",
    "v1:openai,anthropic",
    "v1:codex,openai,anthropic",
    "v1:ssh",
    "v1:codex,ssh",
    "v1:openai,ssh",
    "v1:codex,openai,ssh",
    "v1:anthropic,ssh",
    "v1:codex,anthropic,ssh",
    "v1:openai,anthropic,ssh",
    "v1:codex,openai,anthropic,ssh",
    // Preserve every existing v1 byte. GitHub combinations use a finite v2
    // hexadecimal bitset so every encoding still fits the native seed's
    // existing 32-byte, NUL-terminated field without changing its ABI.
    "v2:10",
    "v2:11",
    "v2:12",
    "v2:13",
    "v2:14",
    "v2:15",
    "v2:16",
    "v2:17",
    "v2:18",
    "v2:19",
    "v2:1a",
    "v2:1b",
    "v2:1c",
    "v2:1d",
    "v2:1e",
    "v2:1f",
];

/// Material-free stock-client selection. This is not a grant, a credential,
/// or an upstream transport selection. The caller supplies an authenticated,
/// exact bound profile revision; neither names nor this encoding prove authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedCredentialClients(u8);

impl ManagedCredentialClients {
    /// Validate exact closed profile slot names, including duplicates.
    /// Processing fails by the sixth item at the latest; no unbounded collection
    /// of caller strings or credential metadata is retained.
    pub fn from_profile_slots<'a>(
        slots: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ProjectionError> {
        let mut seen = 0_u8;
        let mut clients = 0_u8;
        for slot in slots {
            let bit = match slot {
                "codex" => 1,
                "openai" => 2,
                "anthropic" => 4,
                "ssh" => 8,
                "github" => 16,
                _ => return Err(ProjectionError::InvalidManagedClientSelection),
            };
            if seen & bit != 0 {
                return Err(ProjectionError::InvalidManagedClientSelection);
            }
            seen |= bit;
            clients |= bit;
        }
        Ok(Self(clients))
    }

    /// One of 32 canonical tokens for private bootstrap metadata. Empty
    /// selection is explicit; unversioned or reordered forms are not aliases.
    pub fn encode(self) -> &'static str {
        MANAGED_CLIENT_ENCODINGS[usize::from(self.0)]
    }

    /// Accept only the current exact private encoding, without legacy fallback.
    pub fn decode(value: &str) -> Result<Self, ProjectionError> {
        MANAGED_CLIENT_ENCODINGS
            .iter()
            .position(|candidate| *candidate == value)
            .map(|bits| Self(bits as u8))
            .ok_or(ProjectionError::InvalidManagedClientSelection)
    }

    pub fn contains(self, client: ManagedCredentialClient) -> bool {
        self.0 & client.bit() != 0
    }

    /// Provider names owned only while their client is selected. Generic
    /// runtime and GitHub names remain their adapters' responsibility.
    pub fn reserved_environment_keys(self) -> BTreeSet<&'static str> {
        [
            ManagedCredentialClient::Codex,
            ManagedCredentialClient::OpenAi,
            ManagedCredentialClient::Anthropic,
            ManagedCredentialClient::Ssh,
            ManagedCredentialClient::GitHub,
        ]
        .into_iter()
        .filter(|client| self.contains(*client))
        .flat_map(|client| client.environment_keys().iter().copied())
        .collect()
    }

    /// Reject collisions using names alone, before accepting values or spawning
    /// a child. Callers retain ordinary environment syntax and size validation.
    pub fn check_collisions<'a>(
        self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ProjectionError> {
        let reserved = self.reserved_environment_keys();
        if names.into_iter().any(|name| reserved.contains(name)) {
            return Err(ProjectionError::ManagedEnvironmentCollision);
        }
        Ok(())
    }

    /// Generate only fixed public routing inputs for the selected clients.
    /// Placeholder strings are not authentication: the admitted local or hosted
    /// ingress and broker grants remain responsible for authority. Both layouts
    /// use the existing loopback ingress; no caller URL, token or path is accepted.
    pub fn for_placement(
        self,
        placement: ManagedCredentialClientPlacement,
    ) -> ManagedCredentialClientProjection {
        let mut environment = BTreeMap::new();
        let origin = format!("http://127.0.0.1:{MANAGED_HTTP_PORT}");
        let codex = self.contains(ManagedCredentialClient::Codex).then(|| {
            let home = match placement {
                ManagedCredentialClientPlacement::Native => CODEX_NATIVE_HOME,
                ManagedCredentialClientPlacement::Platform => CODEX_PLATFORM_HOME,
            };
            environment.insert("CODEX_HOME".into(), home.into());
            CodexProviderProjection::for_loopback_port(MANAGED_HTTP_PORT)
                .expect("fixed managed HTTP port is unprivileged")
        });
        if self.contains(ManagedCredentialClient::OpenAi) {
            environment.insert(
                "OPENAI_BASE_URL".into(),
                format!("{origin}{MANAGED_OPENAI_API_PREFIX}"),
            );
            environment.insert("OPENAI_API_KEY".into(), "codewire-managed".into());
        }
        if self.contains(ManagedCredentialClient::Anthropic) {
            environment.insert("ANTHROPIC_BASE_URL".into(), origin);
            environment.insert("ANTHROPIC_AUTH_TOKEN".into(), "codewire-managed".into());
            // Clear competing inherited auth inputs; do not import or read a
            // saved login. The stock client's exact precedence needs its own
            // pinned-client proof, not a claim from this pure renderer.
            environment.insert("ANTHROPIC_API_KEY".into(), String::new());
            environment.insert("CLAUDE_CODE_OAUTH_TOKEN".into(), String::new());
        }
        if self.contains(ManagedCredentialClient::Ssh) {
            let socket = match placement {
                ManagedCredentialClientPlacement::Native => SSH_NATIVE_AUTH_SOCK,
                ManagedCredentialClientPlacement::Platform => SSH_PLATFORM_AUTH_SOCK,
            };
            environment.insert("SSH_AUTH_SOCK".into(), socket.into());
        }
        ManagedCredentialClientProjection { environment, codex }
    }
}

/// Nonsecret generated values only. Publishing these does not prove delivery,
/// listener readiness, or immunity to a workload changing its own client config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCredentialClientProjection {
    pub environment: BTreeMap<String, String>,
    pub codex: Option<CodexProviderProjection>,
}

/// Deterministic machine-owned Codex configuration for a protected provider
/// route.
///
/// The projection contains no provider credential or environment-key lookup.
/// Local delivery uses its guest loopback listener. Platform delivery uses a
/// fixed command to read a short-lived, purpose-bound Pod capability; it never
/// reads provider credentials. Both keep material in their broker boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexProviderProjection {
    config_toml: String,
}

impl CodexProviderProjection {
    /// Project an exact per-environment Kubernetes gateway on HTTPS port443.
    /// Codex 0.157.0's supported command-backed bearer mechanism re-reads the
    /// dedicated projected Pod capability on demand and after one401 retry.
    /// The caller also mounts public roots and sets CODEX_CA_CERTIFICATE to
    /// [`CODEX_PLATFORM_ROOTS_FILE`]. This is environment-level capability
    /// access, not a promise to hide the Pod token from its own workload.
    pub fn for_platform_gateway(dns_name: &str) -> Result<Self, ProjectionError> {
        if dns_name.len() > 253
            || !dns_name.ends_with(".svc.cluster.local")
            || dns_name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(ProjectionError::InvalidGuestEndpoint);
        }
        Ok(Self {
            config_toml: format!(
                concat!(
                    "model_provider = \"{provider}\"\n",
                    "\n",
                    "[model_providers.{provider}]\n",
                    "name = \"Codewire OpenAI\"\n",
                    "base_url = \"https://{dns_name}/v1\"\n",
                    "wire_api = \"responses\"\n",
                    "requires_openai_auth = false\n",
                    "supports_websockets = false\n",
                    "\n",
                    "[model_providers.{provider}.auth]\n",
                    "command = \"/bin/cat\"\n",
                    "args = [\"{token}\"]\n",
                    "cwd = \"/\"\n",
                    "timeout_ms = 2000\n",
                    "refresh_interval_ms = 30000\n",
                    "\n",
                    "[features]\n",
                    "enable_request_compression = false\n",
                ),
                provider = CODEX_PROVIDER_ID,
                token = CODEX_PLATFORM_TOKEN_FILE,
                dns_name = dns_name,
            ),
        })
    }

    /// Create a Responses-only provider projection for one unprivileged IPv4
    /// loopback port owned by the guest-side Codewire listener.
    pub fn for_loopback_port(port: u16) -> Result<Self, ProjectionError> {
        if port < MIN_UNPRIVILEGED_PORT {
            return Err(ProjectionError::InvalidGuestEndpoint);
        }
        Ok(Self {
            config_toml: format!(
                concat!(
                    "model_provider = \"{provider}\"\n",
                    "\n",
                    "[model_providers.{provider}]\n",
                    "name = \"Codewire OpenAI\"\n",
                    "base_url = \"http://127.0.0.1:{port}/v1\"\n",
                    "wire_api = \"responses\"\n",
                    "requires_openai_auth = false\n",
                    "supports_websockets = false\n",
                    "\n",
                    "[features]\n",
                    "enable_request_compression = false\n",
                ),
                provider = CODEX_PROVIDER_ID,
                port = port,
            ),
        })
    }

    /// Return the complete UTF-8 contents to install as
    /// [`CODEX_CONFIG_FILE_NAME`] inside an isolated guest `CODEX_HOME`.
    pub fn config_toml(&self) -> &str {
        &self.config_toml
    }

    /// Consume the projection and return its complete UTF-8 contents.
    pub fn into_config_toml(self) -> String {
        self.config_toml
    }
}

/// Stable material-free projection validation errors.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProjectionError {
    #[error("credential broker guest endpoint is invalid")]
    InvalidGuestEndpoint,
    #[error("managed credential client selection is invalid")]
    InvalidManagedClientSelection,
    #[error("environment configuration collides with selected managed client routing")]
    ManagedEnvironmentCollision,
}

#[cfg(test)]
#[path = "projection/managed_tests.rs"]
mod managed_tests;

#[cfg(test)]
mod tests {
    use toml::Value;

    use super::*;

    #[test]
    fn platform_projection_reads_only_fixed_pod_capability_over_exact_https() {
        let host = "cw-gateway-svc-123.dev-sandboxes.svc.cluster.local";
        let projection = CodexProviderProjection::for_platform_gateway(host).unwrap();
        let parsed: Value = toml::from_str(projection.config_toml()).unwrap();
        let provider = &parsed["model_providers"][CODEX_PROVIDER_ID];
        assert_eq!(
            provider["base_url"].as_str(),
            Some(format!("https://{host}/v1").as_str())
        );
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(false));
        assert_eq!(provider["supports_websockets"].as_bool(), Some(false));
        let auth = &provider["auth"];
        assert_eq!(auth["command"].as_str(), Some("/bin/cat"));
        assert_eq!(
            auth["args"].as_array().unwrap(),
            &[Value::String(CODEX_PLATFORM_TOKEN_FILE.to_owned())]
        );
        assert_eq!(auth["cwd"].as_str(), Some("/"));
        assert_eq!(auth["timeout_ms"].as_integer(), Some(2000));
        assert_eq!(auth["refresh_interval_ms"].as_integer(), Some(30000));
        for forbidden in [
            "env_key",
            "experimental_bearer_token",
            "OPENAI_API_KEY",
            "auth.json",
            "sh -c",
            "Bearer ",
        ] {
            assert!(!projection.config_toml().contains(forbidden));
        }
    }

    #[test]
    fn platform_projection_rejects_authority_or_toml_injection() {
        for host in [
            "",
            "localhost",
            "127.0.0.1",
            "https://gateway.dev.svc.cluster.local",
            "gateway.dev.svc.cluster.local:8443",
            "gateway.dev.svc.cluster.local/elsewhere",
            "gateway.dev.svc.cluster.local\"\n",
            "Gateway.dev.svc.cluster.local",
            "gateway..svc.cluster.local",
            "-gateway.dev.svc.cluster.local",
            "gateway-.dev.svc.cluster.local",
            "gateway.dev.svc.cluster.local.",
        ] {
            assert_eq!(
                CodexProviderProjection::for_platform_gateway(host),
                Err(ProjectionError::InvalidGuestEndpoint)
            );
        }
    }

    #[test]
    fn projects_one_credential_free_responses_provider() {
        let projection =
            CodexProviderProjection::for_loopback_port(38_081).expect("Codex projection");
        let config = projection.config_toml();
        assert_eq!(
            config,
            concat!(
                "model_provider = \"codewire_openai\"\n",
                "\n",
                "[model_providers.codewire_openai]\n",
                "name = \"Codewire OpenAI\"\n",
                "base_url = \"http://127.0.0.1:38081/v1\"\n",
                "wire_api = \"responses\"\n",
                "requires_openai_auth = false\n",
                "supports_websockets = false\n",
                "\n",
                "[features]\n",
                "enable_request_compression = false\n",
            )
        );
        let parsed = toml::from_str::<Value>(config).expect("valid TOML projection");

        assert_eq!(
            parsed.get("model_provider").and_then(Value::as_str),
            Some(CODEX_PROVIDER_ID)
        );
        let provider = parsed
            .get("model_providers")
            .and_then(Value::as_table)
            .and_then(|providers| providers.get(CODEX_PROVIDER_ID))
            .and_then(Value::as_table)
            .expect("Codewire provider");
        assert_eq!(provider.len(), 5);
        assert_eq!(
            provider.get("name").and_then(Value::as_str),
            Some("Codewire OpenAI")
        );
        assert_eq!(
            provider.get("base_url").and_then(Value::as_str),
            Some("http://127.0.0.1:38081/v1")
        );
        assert_eq!(
            provider.get("wire_api").and_then(Value::as_str),
            Some("responses")
        );
        assert_eq!(
            provider
                .get("requires_openai_auth")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            provider.get("supports_websockets").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parsed
                .get("features")
                .and_then(Value::as_table)
                .and_then(|features| features.get("enable_request_compression"))
                .and_then(Value::as_bool),
            Some(false)
        );
        for forbidden in [
            "env_key",
            "experimental_bearer_token",
            "auth.command",
            "OPENAI_API_KEY",
            "Bearer ",
        ] {
            assert!(!config.contains(forbidden));
        }
        assert_eq!(CODEX_CONFIG_FILE_NAME, "config.toml");
        assert_eq!(projection.clone().into_config_toml(), config);
    }

    #[test]
    fn rejects_privileged_or_missing_loopback_ports() {
        for port in [0, 1, MIN_UNPRIVILEGED_PORT - 1] {
            assert_eq!(
                CodexProviderProjection::for_loopback_port(port),
                Err(ProjectionError::InvalidGuestEndpoint)
            );
        }
        for port in [MIN_UNPRIVILEGED_PORT, u16::MAX] {
            assert!(CodexProviderProjection::for_loopback_port(port).is_ok());
        }
    }
}
