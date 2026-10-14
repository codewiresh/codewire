//! Versioned, placement-neutral Codewire project intent.
//!
//! This crate deliberately performs no filesystem, network, credential-store,
//! registry, VMM, or orchestration I/O. Callers supply document bytes and keep
//! placement-specific resolution in their own adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use codewire_access::AccessProfileReference;

mod normalize;
mod platform_projection;
mod repository;
mod selection;

#[cfg(test)]
mod selection_tests;

pub use platform_projection::{
    PlatformProjectionSelection, PlatformProjectionSelectionError,
    platform_projection_reserved_keys,
};
pub use repository::{
    GITHUB_SSH_KNOWN_HOSTS, GitHubSourceForm, GitHubSshSource, RepositorySshHost,
    canonical_repository_known_hosts, github_known_hosts_additions, github_repository_path,
    github_ssh_source, parse_repository_ssh_host,
};
pub use selection::{StoragePlacement, StorageReference};

pub const PROJECT_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROJECT_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_REPOSITORIES: usize = 64;
pub const MAX_REPOSITORY_KNOWN_HOSTS: usize = 32;
pub const MAX_REPOSITORY_KNOWN_HOST_LINE_BYTES: usize = 8 * 1024;
pub const MAX_REPOSITORY_KNOWN_HOSTS_BYTES: usize = 64 * 1024;
pub const MAX_ENVIRONMENT_VALUES: usize = 256;
pub const MAX_APPLICATION_PORTS: usize = 128;
pub const MAX_AGENTS: usize = 32;
pub const MAX_SKILLS: usize = 256;
pub const MAX_LOCAL_MOUNTS: usize = 64;
/// Environment names reserved for Codewire-owned runtime control channels.
pub const RESERVED_RUNTIME_ENVIRONMENT_KEYS: [&str; 5] = [
    "CODEWIRE_MESH_URL",
    "CODEWIRE_MESH_AUTH_TOKEN",
    "CODEWIRE_MESH_NETWORK",
    "CODEWIRE_MESH_INVITE_CODE",
    "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS",
];
/// Maximum key size accepted by canonical project and guest workload boundaries.
pub const MAX_ENVIRONMENT_KEY_BYTES: usize =
    codewire_workload_secrets::MAX_WORKLOAD_SECRET_KEY_BYTES;

/// Returns whether a name is valid across project, guest, and secret-resolution boundaries.
pub fn is_valid_environment_key(key: &str) -> bool {
    codewire_workload_secrets::validate_workload_secret_key(key).is_ok()
}

const WORKSPACE_ROOT: &str = "/workspace";
const MAX_SHORT_VALUE_BYTES: usize = 1024;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("codewire project document is {actual} bytes; maximum is {maximum}")]
    DocumentTooLarge { actual: usize, maximum: usize },
    #[error("parse codewire project document: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported codewire project schema version {0}")]
    UnsupportedSchema(u32),
    #[error("{field} exceeds the maximum of {maximum} entries")]
    TooManyEntries { field: &'static str, maximum: usize },
    #[error("invalid {field}: {detail}")]
    InvalidField { field: &'static str, detail: String },
    #[error("{field} is local-only and is not supported by platform placement")]
    PlatformUnsupported { field: &'static str },
    #[error("serialize canonical codewire project: {0}")]
    CanonicalJson(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectDocument {
    pub spec: ProjectSpec,
    pub local: LocalProjectIntent,
    working_directory_explicit: bool,
}

impl ProjectDocument {
    pub fn working_directory_is_explicit(&self) -> bool {
        self.working_directory_explicit
    }

    pub fn ensure_platform_compatible(&self) -> Result<(), ProjectError> {
        if !self.local.mounts.is_empty() {
            return Err(ProjectError::PlatformUnsupported { field: "mounts" });
        }
        if !self.local.host_ports.is_empty() {
            return Err(ProjectError::PlatformUnsupported {
                field: "ports.host_port",
            });
        }
        self.spec.ensure_platform_compatible()?;
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ProjectError> {
        self.spec.canonical_json()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectSpec {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preset: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<RepositorySpec>,
    pub working_directory: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_command: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub startup_script: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "AgentsSpec::is_empty")]
    pub agents: AgentsSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillSelection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ports: Vec<ApplicationPort>,
    #[serde(default, skip_serializing_if = "ResourceSpec::is_empty")]
    pub resources: ResourceSpec,
    #[serde(default, skip_serializing_if = "SecretBindings::is_empty")]
    pub secrets: SecretBindings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialBinding>,
}

impl Default for ProjectSpec {
    fn default() -> Self {
        Self {
            schema_version: PROJECT_SCHEMA_VERSION,
            preset: String::new(),
            image: String::new(),
            repositories: Vec::new(),
            working_directory: WORKSPACE_ROOT.to_string(),
            install_command: String::new(),
            startup_script: String::new(),
            environment: BTreeMap::new(),
            agents: AgentsSpec::default(),
            skills: Vec::new(),
            application_ports: Vec::new(),
            resources: ResourceSpec::default(),
            secrets: SecretBindings::default(),
            credentials: None,
        }
    }
}

impl ProjectSpec {
    /// Reject explicitly local selections before a platform adapter performs I/O.
    /// Bare names still require exact resolution in the adapter's authority.
    pub fn ensure_platform_compatible(&self) -> Result<(), ProjectError> {
        self.validate()?;
        if self.secrets.user == Some(StoragePlacement::Local) {
            return Err(ProjectError::PlatformUnsupported {
                field: "secrets.user",
            });
        }
        if !self.secrets.project.is_empty()
            && self.secrets.project_reference()?.placement == Some(StoragePlacement::Local)
        {
            return Err(ProjectError::PlatformUnsupported {
                field: "secrets.project",
            });
        }
        if let Some(credentials) = &self.credentials
            && credentials.reference()?.placement == Some(StoragePlacement::Local)
        {
            return Err(ProjectError::PlatformUnsupported {
                field: "credentials.profile",
            });
        }
        Ok(())
    }

    /// Validate that a typed or persisted spec is already in canonical form.
    /// Parser callers receive this guarantee automatically; protobuf and
    /// stored-row adapters use it to reject malformed typed input.
    pub fn validate(&self) -> Result<(), ProjectError> {
        normalize::validate_project_spec(self)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ProjectError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositorySpec {
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    pub destination: String,
    /// Canonical, direct OpenSSH host-key lines for this exact SSH source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_hosts: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentsSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
}

impl AgentsSpec {
    pub fn is_empty(&self) -> bool {
        self.install.is_none() && self.tools.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SkillSource {
    #[default]
    Repository,
    User,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct SkillSelection {
    pub source: SkillSource,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationPort {
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millicores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gib: Option<u64>,
}

impl ResourceSpec {
    pub fn is_empty(&self) -> bool {
        self.cpu_millicores.is_none() && self.memory_mib.is_none() && self.disk_gib.is_none()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretBindings {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub organization: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<StoragePlacement>,
}

impl SecretBindings {
    pub fn is_empty(&self) -> bool {
        self.project.is_empty() && !self.organization && self.user.is_none()
    }

    /// Parse origin without choosing an account, owner or fallback store.
    pub fn project_reference(&self) -> Result<StorageReference<'_>, ProjectError> {
        StorageReference::project(&self.project)
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    pub profile: String,
}

impl CredentialBinding {
    /// Parse the requested profile without resolving or granting it.
    pub fn reference(&self) -> Result<StorageReference<'_>, ProjectError> {
        StorageReference::profile(&self.profile)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalProjectIntent {
    pub mounts: Vec<LocalMountIntent>,
    pub host_ports: Vec<HostPortBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalMountIntent {
    pub source: String,
    pub destination: String,
    pub mode: LocalMountMode,
    pub read_only: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalMountMode {
    Copy,
    Direct,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostPortBinding {
    pub host_port: u16,
    pub guest_port: u16,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProject {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    preset: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    repositories: Vec<RawRepository>,
    #[serde(default)]
    working_directory: String,
    #[serde(default)]
    install_command: String,
    #[serde(default)]
    startup_script: String,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    agents: Option<RawAgentsBlock>,
    #[serde(default)]
    skills: Vec<RawSkillBlock>,
    #[serde(default)]
    ports: Vec<RawPortBlock>,
    #[serde(default)]
    cpu: Option<RawQuantity>,
    #[serde(default)]
    memory: Option<RawQuantity>,
    #[serde(default)]
    disk: Option<RawQuantity>,
    #[serde(default)]
    secrets: Option<RawSecretsBlock>,
    #[serde(default)]
    credentials: Option<CredentialBinding>,
    #[serde(default)]
    mounts: Vec<RawMountBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepository {
    #[serde(default)]
    source: String,
    #[serde(default)]
    revision: String,
    #[serde(default)]
    branch: String,
    #[serde(default)]
    destination: String,
    #[serde(default)]
    known_hosts: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentsBlock {
    #[serde(default)]
    install: Option<bool>,
    #[serde(default)]
    tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkillBlock {
    source: SkillSource,
    #[serde(default)]
    path: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    agents: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPortBlock {
    #[serde(default)]
    port: i64,
    #[serde(default)]
    host_port: i64,
    #[serde(default)]
    guest_port: i64,
    #[serde(default)]
    label: String,
    #[serde(default)]
    access: String,
}

#[derive(Debug, Clone)]
struct RawQuantity(String);

impl<'de> Deserialize<'de> for RawQuantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match serde_yaml::Value::deserialize(deserializer)? {
            serde_yaml::Value::String(value) => Ok(Self(value)),
            _ => Err(serde::de::Error::custom(
                "resource quantity must be a unit-bearing string",
            )),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretsBlock {
    #[serde(default)]
    organization: bool,
    #[serde(default)]
    user: Option<StoragePlacement>,
    #[serde(default)]
    project: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMountBlock {
    #[serde(default)]
    source: String,
    #[serde(default)]
    destination: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    read_only: Option<bool>,
}

pub fn parse_project_yaml(content: &str) -> Result<ProjectDocument, ProjectError> {
    if content.len() > MAX_PROJECT_DOCUMENT_BYTES {
        return Err(ProjectError::DocumentTooLarge {
            actual: content.len(),
            maximum: MAX_PROJECT_DOCUMENT_BYTES,
        });
    }
    let raw: RawProject = serde_yaml::from_str(content)?;
    normalize::normalize_raw_project(raw)
}

pub use normalize::{
    canonical_agent_id, display_agent_id, repository_name, validate_repository_destinations,
};

#[cfg(test)]
mod tests;
