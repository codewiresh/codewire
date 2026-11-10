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
mod overrides;
mod platform_projection;
mod repository;
mod selection;
mod vm_only;
mod yaml;

#[cfg(test)]
mod overrides_tests;
#[cfg(test)]
mod selection_tests;
#[cfg(test)]
mod yaml_tests;

pub use overrides::{ProjectYamlFile, merge_project_files};
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
pub use vm_only::{
    MAX_VM_ONLY_DEPTH, MAX_VM_ONLY_MATCH_STEPS, MAX_VM_ONLY_MATCHES, MAX_VM_ONLY_PATH_BYTES,
    MAX_VM_ONLY_PATTERNS, MAX_VM_ONLY_WALK_DIRECTORIES, MAX_VM_ONLY_WALK_ENTRIES, VmOnlyCursor,
    VmOnlyExpansion, VmOnlyMatch, VmOnlyPatternError, VmOnlyPatterns, VmOnlyTree, expand_vm_only,
    normalize_vm_only_pattern, valid_vm_only_patterns,
};

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
/// The codewire.yaml setting whose patterns name project folders kept on the
/// VM's own disk instead of the host share or copy. Its YAML key is the one
/// serde attribute on `RawWorkspaceBlock`.
pub const VM_ONLY_FIELD: &str = "workspace.vm_only";
/// Kept on the VM's own disk when codewire.yaml does not set `workspace.vm_only`:
/// top-level folders only.
pub const DEFAULT_VM_ONLY_PATTERNS: [&str; 3] = ["node_modules", "target", ".venv"];
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
    /// Not YAML, or not this schema. The parser's message is the whole text:
    /// the key path, what it expected, and that value's line and column.
    /// It is not also the error's source, so a caller that prints the error
    /// chain (`{:#}`) prints it once.
    #[error("{0}")]
    Yaml(serde_yaml::Error),
    #[error("unsupported codewire project schema version {0}")]
    UnsupportedSchema(u32),
    #[error("{field} exceeds the maximum of {maximum} entries")]
    TooManyEntries { field: &'static str, maximum: usize },
    #[error("invalid {field}: {detail}")]
    InvalidField { field: &'static str, detail: String },
    #[error("{field} is local-only and is not supported by platform placement")]
    PlatformUnsupported { field: &'static str },
    #[error("serialize canonical codewire project: {0}")]
    CanonicalJson(serde_json::Error),
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
        serde_json::to_vec(self).map_err(ProjectError::CanonicalJson)
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
    /// `workspace.vm_only` patterns as written (canonical): `None` when
    /// absent, so the default list applies; `Some([])` turns it off.
    pub vm_only: Option<Vec<String>>,
    /// `workspace.path_mode`: how a local create turns the project folder
    /// into the workspace when `--path-mode` does not say.
    pub path_mode: Option<WorkspacePathMode>,
}

/// How a local create turns the project folder into the workspace, as
/// `--path-mode` and `workspace.path_mode` name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspacePathMode {
    Mount,
    Copy,
    Clone,
    Empty,
}

impl WorkspacePathMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Copy => "copy",
            Self::Clone => "clone",
            Self::Empty => "empty",
        }
    }
}

impl LocalProjectIntent {
    /// The patterns kept on the VM's own disk: the declared list, or the
    /// default list when codewire.yaml does not set one.
    pub fn effective_vm_only(&self) -> Vec<String> {
        effective_vm_only(self.vm_only.as_deref())
    }
}

/// The patterns kept on the VM's own disk for a `workspace.vm_only` as
/// written: the default list when absent.
pub fn effective_vm_only(declared: Option<&[String]>) -> Vec<String> {
    match declared {
        Some(patterns) => patterns.to_vec(),
        None => DEFAULT_VM_ONLY_PATTERNS.map(str::to_owned).to_vec(),
    }
}

/// The create review's line for the effective `workspace.vm_only` patterns.
pub fn vm_only_summary(patterns: &[String]) -> String {
    if patterns.is_empty() {
        "Kept in the VM: none".to_owned()
    } else {
        format!("Kept in the VM: {}", patterns.join(", "))
    }
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
    #[serde(default, deserialize_with = "raw_cpu")]
    cpu: Option<RawQuantity>,
    #[serde(default, deserialize_with = "raw_memory")]
    memory: Option<RawQuantity>,
    #[serde(default, deserialize_with = "raw_disk")]
    disk: Option<RawQuantity>,
    #[serde(default)]
    secrets: Option<RawSecretsBlock>,
    #[serde(default)]
    credentials: Option<CredentialBinding>,
    #[serde(default)]
    mounts: Vec<RawMountBlock>,
    #[serde(default)]
    workspace: Option<RawWorkspaceBlock>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkspaceBlock {
    #[serde(default, rename = "vm_only")]
    vm_only: Option<Vec<String>>,
    #[serde(default)]
    path_mode: Option<String>,
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

/// A resource quantity as written: a YAML string such as `"8"` or `"16Gi"`.
#[derive(Debug, Clone)]
struct RawQuantity(String);

/// Accepts only a string, and refuses anything else inside the value's own
/// deserializer, so the parser reports that key's path and position (not the
/// document's) with the quoted form expected. `null` leaves it unset.
struct QuantityVisitor {
    example: &'static str,
}

impl serde::de::Visitor<'_> for QuantityVisitor {
    type Value = Option<RawQuantity>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a quoted quantity such as {}", self.example)
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Some(RawQuantity(value.to_owned())))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
}

fn raw_quantity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    example: &'static str,
) -> Result<Option<RawQuantity>, D::Error> {
    deserializer.deserialize_any(QuantityVisitor { example })
}

fn raw_cpu<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RawQuantity>, D::Error> {
    raw_quantity(deserializer, "\"8\"")
}

fn raw_memory<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RawQuantity>, D::Error> {
    raw_quantity(deserializer, "\"16Gi\"")
}

fn raw_disk<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RawQuantity>, D::Error> {
    raw_quantity(deserializer, "\"100Gi\"")
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
    let raw: RawProject = serde_yaml::from_str(content).map_err(ProjectError::Yaml)?;
    normalize::normalize_raw_project(raw)
}

pub use normalize::{
    canonical_agent_id, destination_depths, destination_parents, display_agent_id, repository_name,
    validate_repository_destinations,
};

#[cfg(test)]
mod tests;
