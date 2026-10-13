use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

const CODEX_PROVIDER_ID: &str = "codewire_openai";
const CODEX_OPENAI_API_PROVIDER_ID: &str = "codewire_openai_api";
const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Relative path for the generated credential-free Codex provider config.
pub const CODEX_CONFIG_FILE_NAME: &str = "config.toml";

/// Projected, purpose-bound workspace capability, never provider material.
pub const CODEX_PLATFORM_TOKEN_FILE: &str = "/run/codewire-credentials/workspace/token";
/// Codex's own default home (`~/.codex`) for the hosted workspace user, on the
/// persistent home volume, so sessions and history survive Stop/Start.
pub const CODEX_PLATFORM_HOME: &str = "/home/codewire/.codex";
/// First line of the `config.toml` the hosted daemon keeps in
/// [`CODEX_PLATFORM_HOME`]. The daemon replaces or removes that file only
/// while this is still its first line; deleting the line hands the file to
/// the user.
pub const CODEX_MANAGED_CONFIG_HEADER: &str =
    "# Managed by Codewire. Delete this line to manage this file yourself.";
/// Native Codex state mounted at the existing isolated guest path.
pub const CODEX_NATIVE_HOME: &str = "/run/codewire-agent/codex";
/// Native workspace path for the distinct selected-key OpenSSH agent ingress.
pub const SSH_NATIVE_AUTH_SOCK: &str = "/run/codewire-host/ssh-agent.sock";
/// Hosted workspace path for the distinct selected-key OpenSSH agent ingress.
pub const SSH_PLATFORM_AUTH_SOCK: &str = "/codewire/run/ssh-agent.sock";
/// Fixed per-environment HTTP ingress; callers own listener authentication and readiness.
pub const MANAGED_HTTP_PORT: u16 = 38_081;
/// Hosted workspace path of the same ingress as a Unix socket. Stock `gh`
/// reaches the GitHub API route through it.
pub const MANAGED_HTTP_PLATFORM_SOCKET: &str = "/codewire/run/credentials.sock";
/// Native workspace path of the same ingress as a Unix socket.
pub const MANAGED_HTTP_NATIVE_SOCKET: &str = "/run/codewire-host/credential.sock";
/// Hosted workspace directory holding Codewire's `gh` configuration. It is
/// written and owned by the workspace daemon, never the user's `~/.config/gh`.
pub const GH_PLATFORM_CONFIG_DIR: &str = "/codewire/run/gh";
/// Native workspace directory holding Codewire's `gh` configuration, on the
/// guest's read-only control mount.
pub const GH_NATIVE_CONFIG_DIR: &str = "/run/codewire-host/gh";
/// Relative path of the generated `gh` configuration in that directory.
pub const GH_CONFIG_FILE_NAME: &str = "config.yml";
/// Public placeholder that makes stock `gh` send requests at all. It is not a
/// credential: the broker drops the guest's authorization and adds the
/// owner's GitHub login outside the workspace.
pub const GH_TOKEN_PLACEHOLDER: &str = "codewire-managed";
/// Workspace environment variable carrying the managed clients orchestration
/// rendered for one Pod, in [`ManagedCredentialClients::encode`] form.
pub const MANAGED_CREDENTIAL_CLIENTS_ENV: &str = "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS";
/// Base-URL path for the distinct OpenAI API-key profile slot. Every request
/// under it reaches the OpenAI API unchanged except for its credential;
/// ordinary Codex configuration retains its own route.
pub const MANAGED_OPENAI_API_PREFIX: &str = "/_codewire/openai/v1";
/// Base-URL path for the Anthropic profile slot. Every request under it
/// reaches the Anthropic API unchanged except for its credential.
pub const MANAGED_ANTHROPIC_API_PREFIX: &str = "/_codewire/anthropic";
/// Smart Git prefix on the existing managed HTTP ingress. Only the selected
/// GitHub adapter may resolve this route to an upstream provider.
pub const MANAGED_GITHUB_GIT_PREFIX: &str = "/_codewire/github/";
/// Destinations a workspace process must reach directly, whatever proxy it is
/// told to use: every managed HTTP route is the workspace's own loopback
/// ingress, and a request to it carries prompts and repository content.
pub const MANAGED_NO_PROXY: [&str; 3] = ["127.0.0.1", "localhost", "::1"];
/// Both spellings of the proxy exemption list that HTTP clients read.
pub const NO_PROXY_NAMES: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// Stock clients configured by selected profile slots, not credential auth
/// kinds. The Anthropic client alone has two forms: see
/// [`ManagedCredentialClients::with_anthropic_subscription_token`].
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
            // Git's environment configuration routes github.com through the
            // managed GitHub route; never a provider token or a written file.
            // This replaces the former checkout-only rewrite, so git in the
            // workspace keeps working after checkout. A declared variable of
            // these names is refused, never merged or overwritten.
            //
            // The `gh` names the client also projects are deliberately not
            // listed. This set is bound into every environment's projection
            // selection digest, so adding a name would refuse the launches
            // of running environments until they restart. `GH_TOKEN` is
            // already refused with the GitHub provider's own names
            // (`HttpProvider::reserved_environment_keys`); a declared
            // `GH_CONFIG_DIR` is the user's own choice of `gh` configuration.
            Self::GitHub => &["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"],
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

/// The Anthropic client's subscription-token form, valid only with the
/// Anthropic client itself. It is never set from slot names alone.
const ANTHROPIC_SUBSCRIPTION_TOKEN_BIT: u8 = 32;
/// Every bit a selection may set.
const ALL_CLIENT_BITS: u8 = 63;

/// The 16 selections with the Anthropic client in its subscription-token form,
/// in the same finite v2 hexadecimal bitset. Every earlier encoding keeps its
/// exact bytes; each of these fits the native seed's 32-byte field.
const ANTHROPIC_SUBSCRIPTION_ENCODINGS: [&str; 16] = [
    "v2:24", "v2:25", "v2:26", "v2:27", "v2:2c", "v2:2d", "v2:2e", "v2:2f", "v2:34", "v2:35",
    "v2:36", "v2:37", "v2:3c", "v2:3d", "v2:3e", "v2:3f",
];

/// Index into [`ANTHROPIC_SUBSCRIPTION_ENCODINGS`] of a selection with both
/// the Anthropic and subscription-token bits: the four other client bits.
const fn anthropic_subscription_index(bits: u8) -> usize {
    ((bits & 0b0000_0011) | ((bits & 0b0001_1000) >> 1)) as usize
}

/// Inverse of [`anthropic_subscription_index`].
const fn anthropic_subscription_bits(index: usize) -> u8 {
    let index = index as u8;
    ManagedCredentialClient::Anthropic.bit()
        | ANTHROPIC_SUBSCRIPTION_TOKEN_BIT
        | (index & 0b0011)
        | ((index & 0b1100) << 1)
}

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

    /// The same selection with its Anthropic client in the subscription-token
    /// form: the bound profile revision's Anthropic slot holds a Claude
    /// subscription token (the provider's OAuth kind) rather than an API key.
    /// The caller derives this from the exact bound revision's credential,
    /// whose kind never changes; it is client configuration, not authority.
    /// Selections without the Anthropic client are rejected.
    pub fn with_anthropic_subscription_token(self) -> Result<Self, ProjectionError> {
        if !self.contains(ManagedCredentialClient::Anthropic) {
            return Err(ProjectionError::InvalidManagedClientSelection);
        }
        Ok(Self(self.0 | ANTHROPIC_SUBSCRIPTION_TOKEN_BIT))
    }

    /// Whether the Anthropic client uses its subscription-token form.
    pub fn anthropic_subscription_token(self) -> bool {
        self.0 & ANTHROPIC_SUBSCRIPTION_TOKEN_BIT != 0
    }

    /// One of 48 canonical tokens for private bootstrap metadata. Empty
    /// selection is explicit; unversioned or reordered forms are not aliases.
    pub fn encode(self) -> &'static str {
        debug_assert!(
            self.0 & !ALL_CLIENT_BITS == 0
                && (!self.anthropic_subscription_token()
                    || self.contains(ManagedCredentialClient::Anthropic))
        );
        if self.anthropic_subscription_token() {
            ANTHROPIC_SUBSCRIPTION_ENCODINGS[anthropic_subscription_index(self.0)]
        } else {
            MANAGED_CLIENT_ENCODINGS[usize::from(self.0)]
        }
    }

    /// Accept only the current exact private encoding, without legacy fallback.
    pub fn decode(value: &str) -> Result<Self, ProjectionError> {
        if let Some(bits) = MANAGED_CLIENT_ENCODINGS
            .iter()
            .position(|candidate| *candidate == value)
        {
            return Ok(Self(bits as u8));
        }
        ANTHROPIC_SUBSCRIPTION_ENCODINGS
            .iter()
            .position(|candidate| *candidate == value)
            .map(|index| Self(anthropic_subscription_bits(index)))
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

    /// Whether a selected client reaches its route over the loopback HTTP
    /// ingress: every client but SSH, whose signer is a Unix socket.
    pub fn uses_loopback_http(self) -> bool {
        [
            ManagedCredentialClient::Codex,
            ManagedCredentialClient::OpenAi,
            ManagedCredentialClient::Anthropic,
            ManagedCredentialClient::GitHub,
        ]
        .into_iter()
        .any(|client| self.contains(client))
    }

    /// The value of [`NO_PROXY_NAMES`] for a process of this selection, given
    /// the value `current` it would otherwise have. While an HTTP client is
    /// selected, [`MANAGED_NO_PROXY`] is appended to it, so a declared
    /// `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` never receives a managed
    /// route's loopback request. The declared entries stay as written and in
    /// order, and an entry already listed is not repeated. Without an HTTP
    /// client the value is the caller's, unchanged.
    ///
    /// The names are deliberately not reserved: a declared list is extended,
    /// never refused, and the reserved set is bound into every environment's
    /// projection selection digest.
    pub fn no_proxy(self, current: Option<&str>) -> Option<String> {
        if !self.uses_loopback_http() {
            return current.map(str::to_owned);
        }
        let mut value = current.unwrap_or_default().to_owned();
        for destination in MANAGED_NO_PROXY {
            if value
                .split(',')
                .any(|entry| entry.trim().eq_ignore_ascii_case(destination))
            {
                continue;
            }
            if !value.is_empty() && !value.ends_with(',') {
                value.push(',');
            }
            value.push_str(destination);
        }
        Some(value)
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
            let projection = CodexProviderProjection::for_loopback_port(MANAGED_HTTP_PORT)
                .expect("fixed managed HTTP port is unprivileged");
            // The native home is Codewire's own directory. The hosted home is
            // the user's `~/.codex`, so its file carries the ownership header.
            let (home, projection) = match placement {
                ManagedCredentialClientPlacement::Native => (CODEX_NATIVE_HOME, projection),
                ManagedCredentialClientPlacement::Platform => {
                    (CODEX_PLATFORM_HOME, projection.with_managed_header())
                }
            };
            environment.insert("CODEX_HOME".into(), home.into());
            projection
        });
        if self.contains(ManagedCredentialClient::OpenAi) {
            environment.insert(
                "OPENAI_BASE_URL".into(),
                format!("{origin}{MANAGED_OPENAI_API_PREFIX}"),
            );
            environment.insert("OPENAI_API_KEY".into(), "codewire-managed".into());
        }
        if self.contains(ManagedCredentialClient::Anthropic) {
            environment.insert(
                "ANTHROPIC_BASE_URL".into(),
                format!("{origin}{MANAGED_ANTHROPIC_API_PREFIX}"),
            );
            // Only the selected form's variable is projected. The other
            // Anthropic names are reserved while the client is selected, so
            // every placement removes an inherited value of them instead of
            // projecting it as an empty string, which a newer Claude Code
            // could read as set.
            if self.anthropic_subscription_token() {
                // Claude Code's subscription mode: the placeholder makes it
                // send its own OAuth form (bearer plus the OAuth beta) to
                // the managed route, where the broker replaces it with the
                // owner's Claude subscription token. The token itself never
                // enters the Sandbox.
                environment.insert("CLAUDE_CODE_OAUTH_TOKEN".into(), "codewire-managed".into());
            } else {
                // The API-key form: a bearer the broker replaces with the
                // selected API key.
                environment.insert("ANTHROPIC_AUTH_TOKEN".into(), "codewire-managed".into());
            }
        }
        if self.contains(ManagedCredentialClient::GitHub) {
            // Git 2.31+ reads configuration from the environment: every
            // https://github.com/ remote goes to the managed GitHub route,
            // where the broker adds the owner's GitHub login outside the
            // workspace, so fetch, pull and push work with no login step.
            // Only this endpoint is projected: no token, helper or file.
            environment.insert("GIT_CONFIG_COUNT".into(), "1".into());
            environment.insert(
                "GIT_CONFIG_KEY_0".into(),
                format!("url.{origin}{MANAGED_GITHUB_GIT_PREFIX}.insteadOf"),
            );
            environment.insert("GIT_CONFIG_VALUE_0".into(), "https://github.com/".into());
        }
        let gh = self.contains(ManagedCredentialClient::GitHub).then(|| {
            // Stock `gh` speaks HTTPS to api.github.com unless its own
            // configuration names a Unix socket. Its directory is Codewire's,
            // so the user's `~/.config/gh` is neither read nor written while
            // GitHub is selected. The placeholder only makes `gh` send; the
            // route, its grants and its closed operations are the broker's.
            let (directory, socket) = match placement {
                ManagedCredentialClientPlacement::Native => {
                    (GH_NATIVE_CONFIG_DIR, MANAGED_HTTP_NATIVE_SOCKET)
                }
                ManagedCredentialClientPlacement::Platform => {
                    (GH_PLATFORM_CONFIG_DIR, MANAGED_HTTP_PLATFORM_SOCKET)
                }
            };
            environment.insert("GH_TOKEN".into(), GH_TOKEN_PLACEHOLDER.into());
            environment.insert("GH_CONFIG_DIR".into(), directory.into());
            GhConfigProjection::for_socket(socket)
        });
        if self.contains(ManagedCredentialClient::Ssh) {
            let socket = match placement {
                ManagedCredentialClientPlacement::Native => SSH_NATIVE_AUTH_SOCK,
                ManagedCredentialClientPlacement::Platform => SSH_PLATFORM_AUTH_SOCK,
            };
            environment.insert("SSH_AUTH_SOCK".into(), socket.into());
        }
        ManagedCredentialClientProjection {
            environment,
            codex,
            gh,
        }
    }
}

/// Nonsecret generated values only. Publishing these does not prove delivery,
/// listener readiness, or immunity to a workload changing its own client config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedCredentialClientProjection {
    pub environment: BTreeMap<String, String>,
    pub codex: Option<CodexProviderProjection>,
    /// The file the placement writes as [`GH_CONFIG_FILE_NAME`] in the
    /// projected `GH_CONFIG_DIR`, while the GitHub client is selected.
    pub gh: Option<GhConfigProjection>,
}

/// Deterministic machine-owned `gh` configuration: where the managed ingress
/// listens, and nothing else. It names no host, account, token or helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhConfigProjection {
    config_yml: String,
}

impl GhConfigProjection {
    /// `socket` is one of this crate's fixed ingress paths, which need no
    /// YAML quoting. The version line is `gh`'s current schema, so the pinned
    /// client reads the file without migrating or rewriting it.
    fn for_socket(socket: &str) -> Self {
        Self {
            config_yml: format!("version: 1\nhttp_unix_socket: {socket}\n"),
        }
    }

    /// Return the complete UTF-8 contents to install as
    /// [`GH_CONFIG_FILE_NAME`].
    pub fn config_yml(&self) -> &str {
        &self.config_yml
    }
}

/// Deterministic machine-owned Codex configuration for a protected provider
/// route.
///
/// The projection contains no provider credential. Every placement uses the
/// guest loopback listener and keeps material in its broker boundary. The
/// Codex slot's provider names no environment key; the OpenAI API-key slot's
/// names only the session's public `OPENAI_API_KEY` placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexProviderProjection {
    config_toml: String,
    overrides: [String; 3],
}

impl CodexProviderProjection {
    /// Create a Responses-only provider projection for one unprivileged IPv4
    /// loopback port owned by the guest-side Codewire listener. This is the
    /// Codex slot's route: the broker adds the ChatGPT sign-in, or the API key
    /// held in that slot.
    pub fn for_loopback_port(port: u16) -> Result<Self, ProjectionError> {
        Self::provider(port, CODEX_PROVIDER_ID, "Codewire OpenAI", "/v1", None)
    }

    /// The same for Codex through the distinct OpenAI API-key slot: that
    /// slot's managed base path, with Codex sending the session's
    /// `OPENAI_API_KEY` placeholder, which the broker replaces. A managed
    /// agent uses it when its profile has no Codex slot.
    pub fn for_openai_api_loopback_port(port: u16) -> Result<Self, ProjectionError> {
        Self::provider(
            port,
            CODEX_OPENAI_API_PROVIDER_ID,
            "Codewire OpenAI API",
            MANAGED_OPENAI_API_PREFIX,
            Some("OPENAI_API_KEY"),
        )
    }

    /// One provider as a configuration file and as the equivalent overrides,
    /// rendered from the same settings. Every value is a fixed ASCII token
    /// that needs no TOML escaping.
    fn provider(
        port: u16,
        id: &str,
        name: &str,
        base_path: &str,
        env_key: Option<&str>,
    ) -> Result<Self, ProjectionError> {
        if port < MIN_UNPRIVILEGED_PORT {
            return Err(ProjectionError::InvalidGuestEndpoint);
        }
        let mut settings = vec![
            ("name", format!("\"{name}\"")),
            (
                "base_url",
                format!("\"http://127.0.0.1:{port}{base_path}\""),
            ),
        ];
        if let Some(env_key) = env_key {
            settings.push(("env_key", format!("\"{env_key}\"")));
        }
        settings.extend([
            ("wire_api", "\"responses\"".to_owned()),
            ("requires_openai_auth", "false".to_owned()),
            ("supports_websockets", "false".to_owned()),
        ]);
        let lines: String = settings
            .iter()
            .map(|(key, value)| format!("{key} = {value}\n"))
            .collect();
        let inline = settings
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self {
            config_toml: format!(
                concat!(
                    "model_provider = \"{id}\"\n",
                    "\n",
                    "[model_providers.{id}]\n",
                    "{lines}",
                    "\n",
                    "[features]\n",
                    "enable_request_compression = false\n",
                ),
                id = id,
                lines = lines,
            ),
            overrides: [
                format!("model_provider=\"{id}\""),
                format!("model_providers.{id}={{{inline}}}"),
                "features.enable_request_compression=false".to_owned(),
            ],
        })
    }

    /// The same configuration with [`CODEX_MANAGED_CONFIG_HEADER`] as its
    /// first line, for a home the user also owns.
    fn with_managed_header(self) -> Self {
        Self {
            config_toml: format!("{CODEX_MANAGED_CONFIG_HEADER}\n{}", self.config_toml),
            ..self
        }
    }

    /// Return the complete UTF-8 contents to install as
    /// [`CODEX_CONFIG_FILE_NAME`] inside the selected `CODEX_HOME`.
    pub fn config_toml(&self) -> &str {
        &self.config_toml
    }

    /// Consume the projection and return its complete UTF-8 contents.
    pub fn into_config_toml(self) -> String {
        self.config_toml
    }

    /// The same settings as Codex `-c` override values, each one `key=value`
    /// whose value is TOML. A launch that must keep this provider whatever
    /// its configuration file later holds passes every one after `-c`.
    pub fn overrides(&self) -> &[String] {
        &self.overrides
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

    /// The `-c` override values merged into one table, as Codex applies them.
    fn overrides_table(projection: &CodexProviderProjection) -> toml::Table {
        fn merge(into: &mut toml::Table, from: toml::Table) {
            for (key, value) in from {
                match (into.get_mut(&key), value) {
                    (Some(Value::Table(existing)), Value::Table(table)) => merge(existing, table),
                    (_, value) => {
                        into.insert(key, value);
                    }
                }
            }
        }
        let mut table = toml::Table::new();
        for value in projection.overrides() {
            merge(
                &mut table,
                toml::from_str(value).expect("valid TOML override"),
            );
        }
        table
    }

    #[test]
    fn overrides_are_the_configuration_file_as_codex_command_line_values() {
        let codex = CodexProviderProjection::for_loopback_port(38_081).unwrap();
        assert_eq!(
            codex.overrides(),
            [
                "model_provider=\"codewire_openai\"",
                concat!(
                    "model_providers.codewire_openai={name=\"Codewire OpenAI\",",
                    "base_url=\"http://127.0.0.1:38081/v1\",wire_api=\"responses\",",
                    "requires_openai_auth=false,supports_websockets=false}"
                ),
                "features.enable_request_compression=false",
            ]
        );
        for projection in [
            codex,
            CodexProviderProjection::for_openai_api_loopback_port(38_081).unwrap(),
        ] {
            assert_eq!(
                overrides_table(&projection),
                toml::from_str::<toml::Table>(projection.config_toml()).unwrap()
            );
            // The ownership header changes the file only.
            assert_eq!(
                projection.clone().with_managed_header().overrides(),
                projection.overrides()
            );
        }
    }

    #[test]
    fn openai_api_slot_provider_names_its_managed_base_and_the_public_placeholder() {
        let projection = CodexProviderProjection::for_openai_api_loopback_port(38_081).unwrap();
        assert_eq!(
            projection.config_toml(),
            concat!(
                "model_provider = \"codewire_openai_api\"\n",
                "\n",
                "[model_providers.codewire_openai_api]\n",
                "name = \"Codewire OpenAI API\"\n",
                "base_url = \"http://127.0.0.1:38081/_codewire/openai/v1\"\n",
                "env_key = \"OPENAI_API_KEY\"\n",
                "wire_api = \"responses\"\n",
                "requires_openai_auth = false\n",
                "supports_websockets = false\n",
                "\n",
                "[features]\n",
                "enable_request_compression = false\n",
            )
        );
        // The base and the key name are the OpenAI client's own projection:
        // Codex reads the placeholder the session already has.
        let environment = ManagedCredentialClients::from_profile_slots(["openai"])
            .unwrap()
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .environment;
        assert!(projection.config_toml().contains(&format!(
            "base_url = \"{}\"\n",
            environment["OPENAI_BASE_URL"]
        )));
        assert!(environment.contains_key("OPENAI_API_KEY"));
        for forbidden in ["experimental_bearer_token", "auth.command", "Bearer "] {
            assert!(!projection.config_toml().contains(forbidden));
        }
        assert_eq!(
            CodexProviderProjection::for_openai_api_loopback_port(MIN_UNPRIVILEGED_PORT - 1),
            Err(ProjectionError::InvalidGuestEndpoint)
        );
    }

    #[test]
    fn hosted_projection_marks_the_users_home_file_as_codewire_managed() {
        let clients = ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
        let hosted = clients
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .codex
            .unwrap();
        assert_eq!(
            hosted.config_toml(),
            concat!(
                "# Managed by Codewire. Delete this line to manage this file yourself.\n",
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
        assert_eq!(
            hosted.config_toml().lines().next(),
            Some(CODEX_MANAGED_CONFIG_HEADER)
        );
        // The header is a TOML comment; the configuration is unchanged.
        assert_eq!(
            toml::from_str::<Value>(hosted.config_toml()).unwrap(),
            toml::from_str::<Value>(
                CodexProviderProjection::for_loopback_port(38_081)
                    .unwrap()
                    .config_toml()
            )
            .unwrap()
        );
        // The local VM's Codex home is Codewire's own directory: no header.
        let native = clients
            .for_placement(ManagedCredentialClientPlacement::Native)
            .codex
            .unwrap();
        assert!(!native.config_toml().contains(CODEX_MANAGED_CONFIG_HEADER));
        assert_eq!(CODEX_PLATFORM_HOME, "/home/codewire/.codex");
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
