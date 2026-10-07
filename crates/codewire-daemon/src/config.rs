use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use codewire_access::ManagedCredentialClients;
use codewire_gateway_proto::DaemonAuthToken;
pub use codewire_gateway_proto::{
    HOSTED_DAEMON_ACCESS_READY_FILE, HOSTED_DAEMON_CREDENTIAL_FILE, HOSTED_DAEMON_READY_FILE,
    HOSTED_DAEMON_STATE_DIRECTORY, WORKSPACE_BINDING_TLS_ROOTS_FILE, WORKSPACE_BINDING_TOKEN_PATH,
    WORKSPACE_BINDING_URL_ENV, WORKSPACE_BINDING_WAIT_SECONDS, WORKSPACE_POD_UID_ENV,
};
use uuid::Uuid;

use crate::execution::ProcessExecution;

pub const SHIM_ADDR_ENV: &str = "CODEWIRE_WORKSPACE_SHIM_ADDR";
pub const WORKSPACE_ROOT_ENV: &str = "CODEWIRE_WORKSPACE_ROOT";
pub const HOME_ROOT_ENV: &str = "CODEWIRE_HOME_ROOT";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const HOSTED_PROJECTION_SHA256_ENV: &str = "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256";
pub use codewire_access::MANAGED_CREDENTIAL_CLIENTS_ENV;
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
    /// Explicit trusted-host placement. Guest defaults always leave this None.
    pub host: Option<HostConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Dedicated state for one host environment. Session records live under
    /// `state_root/sessions`, saved environment under `state_root/environment.json`.
    /// This is independent of home_root, which remains the child's real HOME.
    pub state_root: PathBuf,
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
    /// The credential relay separately authenticates both Pod tokens to the
    /// TLS broker.
    Hosted,
}

impl Config {
    pub fn validate_host(&self) -> Result<(), ConfigError> {
        let Some(host) = &self.host else {
            return Ok(());
        };
        if !cfg!(target_os = "linux") {
            // A process-group-only fallback cannot truthfully clean ordinary
            // PTY job-control groups. Admit no host placement until that
            // platform has an equivalent owned-identity implementation.
            return Err(ConfigError::HostUnsupportedPlatform);
        }
        let root = clean_path(&host.state_root);
        if !host.state_root.is_absolute()
            || root != host.state_root
            || root == Path::new("/")
            || root == clean_path(&self.home_root)
            || root.starts_with(clean_path(&self.home_root).join(".codewire"))
            || self.process_execution != ProcessExecution::Native
            || self.credential_bridge.is_some()
            || self.launch_projection.is_some()
            || self.managed_credential_clients != Default::default()
        {
            return Err(ConfigError::InvalidHost);
        }
        // Trusted host state must not resolve through links into HOME state.
        for path in root.ancestors() {
            if let Ok(metadata) = std::fs::symlink_metadata(path)
                && metadata.file_type().is_symlink()
            {
                return Err(ConfigError::InvalidHost);
            }
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| env::var_os(name))
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let auth_token = match lookup(DAEMON_AUTH_TOKEN_ENV) {
            Some(value) => value
                .into_string()
                .ok()
                .and_then(|value| DaemonAuthToken::new(value).ok())
                .ok_or(ConfigError::InvalidDaemonAuthToken)?,
            None => return Err(ConfigError::MissingDaemonAuthToken),
        };
        let mut config = HostedPlacement::from_lookup(&lookup).into_config(auth_token);
        config.configure_hosted_projection(lookup)?;
        Ok(config)
    }

    /// Create the hosted native launch directory before serving. Its parent is
    /// the Pod's `/codewire/run`; no init container prepares it. Every launch
    /// still checks that it is an owner-private (0700) directory.
    pub fn prepare_native_launch_directory(&self) -> std::io::Result<()> {
        match self
            .launch_projection
            .as_ref()
            .and_then(|projection| projection.native.as_ref())
        {
            Some(native) => crate::execution::ensure_process_directory(&native.process_directory),
            None => Ok(()),
        }
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
        self.apply_hosted_projection(
            environment_id,
            environment_generation,
            selection_sha256,
            managed_credential_clients,
        );
        Ok(())
    }

    /// The one hosted projection shape, from the rendered environment of a
    /// legacy Pod or from a validated bind response.
    fn apply_hosted_projection(
        &mut self,
        environment_id: Uuid,
        environment_generation: u64,
        selection_sha256: [u8; 32],
        managed_credential_clients: ManagedCredentialClients,
    ) {
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
    }
}

/// Placement fields shared by both hosted modes. They carry no credential and
/// no environment identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedPlacement {
    listen_addr: String,
    workspace_root: PathBuf,
    home_root: PathBuf,
}

impl HostedPlacement {
    fn from_lookup(lookup: &impl Fn(&str) -> Option<OsString>) -> Self {
        Self {
            listen_addr: lookup_value(lookup, SHIM_ADDR_ENV)
                .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.into()),
            workspace_root: lookup_path(lookup, WORKSPACE_ROOT_ENV, DEFAULT_WORKSPACE_ROOT),
            home_root: lookup_path(lookup, HOME_ROOT_ENV, DEFAULT_HOME_ROOT),
        }
    }

    fn into_config(self, auth_token: DaemonAuthToken) -> Config {
        Config {
            listen_addr: self.listen_addr,
            workspace_root: self.workspace_root,
            home_root: self.home_root,
            auth_token,
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: ManagedCredentialClients::default(),
            launch_projection: None,
            host: None,
        }
    }
}

/// Container variables that carry environment identity. A binding-mode Pod
/// must carry none of them: its identity comes only from the bind response.
pub const BINDING_MODE_FORBIDDEN_ENV: [&str; 5] = [
    DAEMON_AUTH_TOKEN_ENV,
    ENVIRONMENT_ID_ENV,
    ENVIRONMENT_GENERATION_ENV,
    HOSTED_PROJECTION_SHA256_ENV,
    MANAGED_CREDENTIAL_CLIENTS_ENV,
];

/// How the hosted daemon entrypoint learns its identity (design §8).
#[derive(Debug)]
pub enum HostedDaemonMode {
    /// A legacy or local Pod rendered with the environment-wide daemon token.
    EnvironmentToken(Box<Config>),
    /// An identity-free Pod that must bind before it listens.
    Binding(WorkspaceBindingConfig),
}

impl HostedDaemonMode {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| env::var_os(name))
    }

    /// `CODEWIRE_WORKSPACE_BINDING_URL` selects binding mode, which refuses
    /// every rendered identity variable. Without it the environment token is
    /// required, as before; neither is a configuration error.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let Some(binding_url) = lookup(WORKSPACE_BINDING_URL_ENV) else {
            return Config::from_lookup(lookup)
                .map(|config| Self::EnvironmentToken(Box::new(config)));
        };
        if BINDING_MODE_FORBIDDEN_ENV
            .iter()
            .any(|name| lookup(name).is_some())
        {
            return Err(ConfigError::BindingModeIdentity);
        }
        let binding_url = binding_url
            .into_string()
            .ok()
            .filter(|url| valid_binding_url(url))
            .ok_or(ConfigError::InvalidWorkspaceBinding)?;
        let pod_uid = lookup(WORKSPACE_POD_UID_ENV)
            .and_then(|value| value.into_string().ok())
            .filter(|value| canonical_uid(value))
            .ok_or(ConfigError::InvalidWorkspaceBinding)?;
        Ok(Self::Binding(WorkspaceBindingConfig {
            binding_url,
            pod_uid,
            token_path: WORKSPACE_BINDING_TOKEN_PATH.into(),
            // The listener serves TLS (#2460), verified only against the
            // mounted internal roots; without them the daemon never binds.
            tls_roots_file: WORKSPACE_BINDING_TLS_ROOTS_FILE.into(),
            placement: HostedPlacement::from_lookup(&lookup),
        }))
    }
}

/// Static configuration of an unbound hosted daemon. It holds no credential
/// and no environment identity.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceBindingConfig {
    binding_url: String,
    pod_uid: String,
    token_path: PathBuf,
    tls_roots_file: PathBuf,
    placement: HostedPlacement,
}

impl fmt::Debug for WorkspaceBindingConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceBindingConfig")
            .field("binding_url", &self.binding_url)
            .field("pod_uid", &self.pod_uid)
            .field("token_path", &self.token_path)
            .field("tls_roots_file", &self.tls_roots_file)
            .finish_non_exhaustive()
    }
}

/// The raw fields of one `BindWorkspace` response, before validation.
pub struct BindResponseFields<'a> {
    pub environment_id: &'a str,
    pub pod_uid: &'a str,
    pub operation_generation: i64,
    pub daemon_credential: &'a str,
    pub projection_selection_sha256: &'a str,
    pub managed_credential_clients: &'a str,
}

/// A bind response the daemon accepted. Its credential never appears in
/// `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceBinding {
    environment_id: Uuid,
    operation_generation: u64,
    daemon_credential: DaemonAuthToken,
    projection_selection_sha256: Option<[u8; 32]>,
    managed_credential_clients: ManagedCredentialClients,
}

impl fmt::Debug for WorkspaceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceBinding")
            .field("environment_id", &self.environment_id)
            .field("operation_generation", &self.operation_generation)
            .field("daemon_credential", &self.daemon_credential)
            .field(
                "projection_selected",
                &self.projection_selection_sha256.is_some(),
            )
            .field(
                "managed_credential_clients",
                &self.managed_credential_clients.encode(),
            )
            .finish()
    }
}

impl WorkspaceBinding {
    pub fn environment_id(&self) -> Uuid {
        self.environment_id
    }

    pub fn operation_generation(&self) -> u64 {
        self.operation_generation
    }

    pub fn daemon_credential(&self) -> &DaemonAuthToken {
        &self.daemon_credential
    }
}

/// A bind response the daemon refused. It is value-blind; the daemon backs
/// off and never listens on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("workspace binding response is invalid")]
pub struct InvalidWorkspaceBinding;

impl WorkspaceBindingConfig {
    pub fn binding_url(&self) -> &str {
        &self.binding_url
    }

    pub fn pod_uid(&self) -> &str {
        &self.pod_uid
    }

    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// The public roots the binding listener's certificate must chain to.
    pub fn tls_roots_file(&self) -> &Path {
        &self.tls_roots_file
    }

    /// Redirect the projected token, for tests of the binding loop.
    pub fn with_token_path(mut self, token_path: impl Into<PathBuf>) -> Self {
        self.token_path = token_path.into();
        self
    }

    /// Redirect the listener's roots, for tests of the binding loop.
    pub fn with_tls_roots_file(mut self, tls_roots_file: impl Into<PathBuf>) -> Self {
        self.tls_roots_file = tls_roots_file.into();
        self
    }

    pub fn listen_addr(&self) -> &str {
        &self.placement.listen_addr
    }

    /// Validate one response (design §8.3). The reviewed Pod UID must equal
    /// this Pod's downward-API UID, so another Pod's binding is never used.
    pub fn validate(
        &self,
        response: &BindResponseFields<'_>,
    ) -> Result<WorkspaceBinding, InvalidWorkspaceBinding> {
        let invalid = InvalidWorkspaceBinding;
        if response.pod_uid != self.pod_uid {
            return Err(invalid);
        }
        let environment_id = Uuid::parse_str(response.environment_id)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == response.environment_id)
            .ok_or(invalid)?;
        let operation_generation = u64::try_from(response.operation_generation)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or(invalid)?;
        let projection_selection_sha256 = match response.projection_selection_sha256 {
            "" => None,
            digest => Some(parse_selection_digest(digest).ok_or(invalid)?),
        };
        let managed_credential_clients =
            ManagedCredentialClients::decode(response.managed_credential_clients)
                .map_err(|_| invalid)?;
        // Managed clients have launch authority only with a selected projection.
        if projection_selection_sha256.is_none()
            && managed_credential_clients != ManagedCredentialClients::default()
        {
            return Err(invalid);
        }
        let daemon_credential =
            DaemonAuthToken::new(response.daemon_credential).map_err(|_| invalid)?;
        Ok(WorkspaceBinding {
            environment_id,
            operation_generation,
            daemon_credential,
            projection_selection_sha256,
            managed_credential_clients,
        })
    }

    /// The served configuration, built exactly as the rendered-environment
    /// path builds it, from the accepted binding alone.
    pub fn into_config(self, binding: &WorkspaceBinding) -> Config {
        let mut config = self
            .placement
            .into_config(binding.daemon_credential.clone());
        if let Some(selection_sha256) = binding.projection_selection_sha256 {
            config.apply_hosted_projection(
                binding.environment_id,
                binding.operation_generation,
                selection_sha256,
                binding.managed_credential_clients,
            );
        }
        config
    }
}

fn parse_selection_digest(digest: &str) -> Option<[u8; 32]> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut selection_sha256 = [0; 32];
    for (index, byte) in selection_sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).ok()?;
    }
    (selection_sha256 != [0; 32]).then_some(selection_sha256)
}

/// A canonical, lowercase, non-nil UUID such as a Kubernetes UID.
fn canonical_uid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uid| !uid.is_nil() && uid.to_string() == value)
}

/// An in-cluster `https://host[:port]` origin, with no credentials, path,
/// query or fragment. Plaintext is refused (#2460).
fn valid_binding_url(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    !authority.is_empty()
        && authority.len() <= 253 + 6
        && authority.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b':')
        })
        && !authority.starts_with(['.', '-', ':'])
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("trusted host session ownership currently requires Linux")]
    HostUnsupportedPlatform,
    #[error(
        "host requires a dedicated absolute state root, Native execution and no managed credential or projection configuration"
    )]
    InvalidHost,
    #[error("{DAEMON_AUTH_TOKEN_ENV} is required")]
    MissingDaemonAuthToken,
    #[error("{DAEMON_AUTH_TOKEN_ENV} must be nonblank canonical ASCII metadata")]
    InvalidDaemonAuthToken,
    #[error("hosted environment projection configuration is invalid")]
    InvalidHostedProjection,
    #[error("a workspace-binding daemon must not carry rendered environment identity")]
    BindingModeIdentity,
    #[error("workspace binding configuration is invalid")]
    InvalidWorkspaceBinding,
}

fn lookup_value(lookup: &impl Fn(&str) -> Option<OsString>, key: &str) -> Option<String> {
    lookup(key)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn lookup_path(lookup: &impl Fn(&str) -> Option<OsString>, key: &str, default: &str) -> PathBuf {
    lookup_value(lookup, key)
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
            host: None,
            launch_projection: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_configuration_requires_dedicated_state_and_excludes_guest_authority() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = fixture();
        config.home_root = temp.path().join("home");
        config.host = Some(HostConfig {
            state_root: temp.path().join("state"),
        });
        config.validate_host().unwrap();
        for root in [
            PathBuf::from("relative"),
            PathBuf::from("/"),
            config.home_root.clone(),
            config.home_root.join(".codewire/state"),
        ] {
            let mut invalid = config.clone();
            invalid.host.as_mut().unwrap().state_root = root;
            assert_eq!(invalid.validate_host(), Err(ConfigError::InvalidHost));
        }
        let mut invalid = config.clone();
        invalid.managed_credential_clients =
            ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
        assert_eq!(invalid.validate_host(), Err(ConfigError::InvalidHost));
        let mut invalid = config.clone();
        invalid.launch_projection = Some(LaunchProjectionConfig {
            selection_sha256: [1; 32],
            native: None,
        });
        assert_eq!(invalid.validate_host(), Err(ConfigError::InvalidHost));
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(temp.path(), &link).unwrap();
        config.host.as_mut().unwrap().state_root = link.join("state");
        assert_eq!(config.validate_host(), Err(ConfigError::InvalidHost));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_host_ownership_is_rejected_before_effects_without_affecting_guests() {
        let mut config = fixture();
        config.validate_host().unwrap();
        config.host = Some(HostConfig {
            state_root: "/dedicated-host-state".into(),
        });
        assert_eq!(
            config.validate_host(),
            Err(ConfigError::HostUnsupportedPlatform)
        );
    }

    #[test]
    fn hosted_daemon_creates_only_its_configured_native_process_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let process_directory = parent.path().join("processes");
        let mut config = fixture();
        config.prepare_native_launch_directory().unwrap();
        config.launch_projection = Some(LaunchProjectionConfig {
            selection_sha256: [0xab; 32],
            native: None,
        });
        config.prepare_native_launch_directory().unwrap();
        assert!(!process_directory.exists());
        config.launch_projection = Some(LaunchProjectionConfig {
            selection_sha256: [0xab; 32],
            native: Some(NativeLaunchProjectionConfig {
                helper_path: "/codewire/bin/cw".into(),
                process_directory: process_directory.clone(),
            }),
        });
        for _restart in 0..2 {
            config.prepare_native_launch_directory().unwrap();
            let metadata = std::fs::symlink_metadata(&process_directory).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn hosted_github_bootstrap_keeps_the_exact_selected_client() {
        for token in ["v2:10", "v2:1f"] {
            let values = [
                (HOSTED_PROJECTION_SHA256_ENV, "ab".repeat(32)),
                (MANAGED_CREDENTIAL_CLIENTS_ENV, token.to_owned()),
                (ENVIRONMENT_ID_ENV, Uuid::new_v4().to_string()),
                (ENVIRONMENT_GENERATION_ENV, "7".into()),
            ];
            let mut config = fixture();
            config
                .configure_hosted_projection(|name| {
                    values
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone().into())
                })
                .unwrap();
            assert_eq!(config.managed_credential_clients.encode(), token);
            assert!(
                config
                    .managed_credential_clients
                    .contains(codewire_access::ManagedCredentialClient::GitHub)
            );
            assert!(config.credential_bridge.is_some());
            assert!(config.launch_projection.is_some());
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

    const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
    const OTHER_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
    const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const BINDING_URL: &str =
        "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";
    const SYNTHETIC_CREDENTIAL: &str = "synthetic-workspace-daemon-credential";

    fn lookup_from(values: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        let values = values.to_vec();
        move |name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(*value))
        }
    }

    fn binding_mode(
        values: &[(&'static str, &'static str)],
    ) -> Result<HostedDaemonMode, ConfigError> {
        HostedDaemonMode::from_lookup(lookup_from(values))
    }

    fn binding_config() -> WorkspaceBindingConfig {
        match binding_mode(&[
            (WORKSPACE_BINDING_URL_ENV, BINDING_URL),
            (WORKSPACE_POD_UID_ENV, POD),
        ])
        .unwrap()
        {
            HostedDaemonMode::Binding(config) => config,
            HostedDaemonMode::EnvironmentToken(_) => panic!("binding mode expected"),
        }
    }

    fn response<'a>() -> BindResponseFields<'a> {
        BindResponseFields {
            environment_id: ENVIRONMENT,
            pod_uid: POD,
            operation_generation: 7,
            daemon_credential: SYNTHETIC_CREDENTIAL,
            projection_selection_sha256: "",
            managed_credential_clients: "v1:none",
        }
    }

    #[test]
    fn hosted_mode_is_selected_by_the_binding_url_alone() {
        // Legacy: the environment token without a binding URL, unchanged.
        let legacy =
            binding_mode(&[(DAEMON_AUTH_TOKEN_ENV, "synthetic-environment-token")]).unwrap();
        let HostedDaemonMode::EnvironmentToken(config) = legacy else {
            panic!("legacy mode expected");
        };
        assert_eq!(
            config.auth_token.expose_secret(),
            "synthetic-environment-token"
        );
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR);
        assert!(config.credential_bridge.is_none());

        // Neither is an error, exactly as before.
        assert_eq!(
            binding_mode(&[]).unwrap_err(),
            ConfigError::MissingDaemonAuthToken
        );

        // Binding: the URL and the downward-API Pod UID, and nothing else.
        let config = binding_config();
        assert_eq!(config.binding_url(), BINDING_URL);
        assert_eq!(config.pod_uid(), POD);
        assert_eq!(config.token_path(), Path::new(WORKSPACE_BINDING_TOKEN_PATH));
        assert_eq!(
            config.tls_roots_file(),
            Path::new(WORKSPACE_BINDING_TLS_ROOTS_FILE)
        );
        assert_eq!(config.listen_addr(), DEFAULT_LISTEN_ADDR);
        let shimmed = binding_mode(&[
            (WORKSPACE_BINDING_URL_ENV, BINDING_URL),
            (WORKSPACE_POD_UID_ENV, POD),
            (SHIM_ADDR_ENV, "0.0.0.0:7777"),
        ])
        .unwrap();
        let HostedDaemonMode::Binding(shimmed) = shimmed else {
            panic!("binding mode expected");
        };
        assert_eq!(shimmed.listen_addr(), "0.0.0.0:7777");
    }

    #[test]
    fn binding_mode_refuses_every_rendered_identity_variable() {
        for forbidden in BINDING_MODE_FORBIDDEN_ENV {
            for value in ["", "synthetic-value"] {
                let values = [
                    (WORKSPACE_BINDING_URL_ENV, BINDING_URL),
                    (WORKSPACE_POD_UID_ENV, POD),
                    (forbidden, value),
                ];
                assert_eq!(
                    binding_mode(&values).unwrap_err(),
                    ConfigError::BindingModeIdentity,
                    "{forbidden}"
                );
            }
        }
        assert_eq!(
            BINDING_MODE_FORBIDDEN_ENV,
            [
                "CODEWIRE_DAEMON_AUTH_TOKEN",
                "CODEWIRE_ENVIRONMENT_ID",
                "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
                "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256",
                "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
            ]
        );
    }

    #[test]
    fn binding_mode_requires_a_canonical_pod_uid_and_tls_url() {
        for pod_uid in [
            "",
            "not-a-uid",
            "00000000-0000-0000-0000-000000000000",
            "7E7B20F6-0BD2-4F11-8B16-9C239851EB52",
            "7e7b20f60bd24f118b169c239851eb52",
            " 7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
        ] {
            assert_eq!(
                binding_mode(&[
                    (WORKSPACE_BINDING_URL_ENV, BINDING_URL),
                    (WORKSPACE_POD_UID_ENV, pod_uid),
                ])
                .unwrap_err(),
                ConfigError::InvalidWorkspaceBinding,
                "{pod_uid:?}"
            );
        }
        assert_eq!(
            binding_mode(&[(WORKSPACE_BINDING_URL_ENV, BINDING_URL)]).unwrap_err(),
            ConfigError::InvalidWorkspaceBinding
        );
        for url in [
            "",
            // Plaintext is refused: the listener serves TLS only.
            "http://binding.test:8087",
            "https://",
            "https://user:secret@binding.test:8087",
            "https://binding.test:8087/path",
            "https://binding.test:8087?query",
            "https://Binding.test:8087",
            "binding.test:8087",
            "https://binding.test:8087 ",
        ] {
            assert_eq!(
                binding_mode(&[
                    (WORKSPACE_BINDING_URL_ENV, url),
                    (WORKSPACE_POD_UID_ENV, POD),
                ])
                .unwrap_err(),
                ConfigError::InvalidWorkspaceBinding,
                "{url:?}"
            );
        }
        for url in [
            "https://binding.test:8087",
            "https://binding.test:8087/",
            "https://10.0.0.1:8087",
        ] {
            assert!(
                binding_mode(&[
                    (WORKSPACE_BINDING_URL_ENV, url),
                    (WORKSPACE_POD_UID_ENV, POD),
                ])
                .is_ok(),
                "{url:?}"
            );
        }
        // The roots are always the mounted internal CA, never configurable.
        assert_eq!(
            binding_config().tls_roots_file(),
            Path::new(WORKSPACE_BINDING_TLS_ROOTS_FILE)
        );
    }

    #[test]
    fn bind_response_without_projection_serves_only_the_credential() {
        let config = binding_config();
        let binding = config.validate(&response()).unwrap();
        assert_eq!(binding.environment_id().to_string(), ENVIRONMENT);
        assert_eq!(binding.operation_generation(), 7);
        assert_eq!(
            binding.daemon_credential().expose_secret(),
            SYNTHETIC_CREDENTIAL
        );
        let served = config.into_config(&binding);
        assert_eq!(served.auth_token.expose_secret(), SYNTHETIC_CREDENTIAL);
        assert!(served.credential_bridge.is_none());
        assert!(served.launch_projection.is_none());
        assert_eq!(
            served.managed_credential_clients,
            ManagedCredentialClients::default()
        );
        assert_eq!(served.process_execution, ProcessExecution::Native);
    }

    #[test]
    fn bind_response_with_projection_matches_the_rendered_environment_path() {
        let digest = "ab".repeat(32);
        let config = binding_config();
        let binding = config
            .validate(&BindResponseFields {
                projection_selection_sha256: &digest,
                managed_credential_clients: "v1:codex,anthropic,ssh",
                ..response()
            })
            .unwrap();
        let served = config.into_config(&binding);
        // Codex's home is prepared from these served clients in both modes.
        assert!(
            served
                .managed_credential_clients
                .contains(codewire_access::ManagedCredentialClient::Codex)
        );

        // The same configuration the legacy rendered environment produces.
        let values = [
            (HOSTED_PROJECTION_SHA256_ENV, digest.clone()),
            (
                MANAGED_CREDENTIAL_CLIENTS_ENV,
                "v1:codex,anthropic,ssh".to_owned(),
            ),
            (ENVIRONMENT_ID_ENV, ENVIRONMENT.to_owned()),
            (ENVIRONMENT_GENERATION_ENV, "7".to_owned()),
        ];
        let mut rendered = fixture();
        rendered.auth_token = DaemonAuthToken::new(SYNTHETIC_CREDENTIAL).unwrap();
        rendered
            .configure_hosted_projection(|name| {
                values
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone().into())
            })
            .unwrap();
        assert_eq!(served, rendered);
    }

    #[test]
    fn bind_responses_with_any_invalid_field_are_refused() {
        let config = binding_config();
        let digest = "ab".repeat(32);
        let long_generation_digest = "AB".repeat(32);
        let zero_digest = "00".repeat(32);
        let cases: Vec<BindResponseFields<'_>> = vec![
            // Response confusion: another Pod's binding.
            BindResponseFields {
                pod_uid: OTHER_POD,
                ..response()
            },
            BindResponseFields {
                pod_uid: "",
                ..response()
            },
            BindResponseFields {
                environment_id: "",
                ..response()
            },
            BindResponseFields {
                environment_id: "not-a-uuid",
                ..response()
            },
            BindResponseFields {
                environment_id: "00000000-0000-0000-0000-000000000000",
                ..response()
            },
            BindResponseFields {
                environment_id: "550E8400-E29B-41D4-A716-446655440000",
                ..response()
            },
            BindResponseFields {
                operation_generation: 0,
                ..response()
            },
            BindResponseFields {
                operation_generation: -1,
                ..response()
            },
            BindResponseFields {
                projection_selection_sha256: "ab",
                ..response()
            },
            BindResponseFields {
                projection_selection_sha256: &long_generation_digest,
                ..response()
            },
            BindResponseFields {
                projection_selection_sha256: &zero_digest,
                ..response()
            },
            BindResponseFields {
                managed_credential_clients: "",
                ..response()
            },
            BindResponseFields {
                managed_credential_clients: "codex",
                ..response()
            },
            // Managed clients without a selected projection have no authority.
            BindResponseFields {
                managed_credential_clients: "v1:codex",
                ..response()
            },
            BindResponseFields {
                daemon_credential: "",
                ..response()
            },
            BindResponseFields {
                daemon_credential: " padded",
                ..response()
            },
            BindResponseFields {
                daemon_credential: "line\nbreak",
                ..response()
            },
        ];
        for case in &cases {
            assert_eq!(config.validate(case).unwrap_err(), InvalidWorkspaceBinding);
        }
        assert!(
            config
                .validate(&BindResponseFields {
                    operation_generation: i64::MAX,
                    projection_selection_sha256: &digest,
                    managed_credential_clients: "v1:codex",
                    ..response()
                })
                .is_ok()
        );
    }

    #[test]
    fn binding_debug_output_never_carries_the_credential() {
        let config = binding_config();
        let binding = config.validate(&response()).unwrap();
        for debug in [
            format!("{binding:?}"),
            format!("{:?}", config.clone().into_config(&binding)),
            format!("{config:?}"),
            format!("{:?}", HostedDaemonMode::Binding(config.clone())),
        ] {
            assert!(!debug.contains(SYNTHETIC_CREDENTIAL), "{debug}");
        }
        assert!(format!("{binding:?}").contains("[REDACTED]"));
        assert!(InvalidWorkspaceBinding.to_string().contains("invalid"));
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
            host: None,
            launch_projection: None,
        };

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(marker));
    }
}
