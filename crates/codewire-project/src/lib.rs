//! Versioned, placement-neutral Codewire project intent.
//!
//! This crate deliberately performs no filesystem, network, credential-store,
//! registry, VMM, or orchestration I/O. Callers supply document bytes and keep
//! placement-specific resolution in their own adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod normalize;

pub const PROJECT_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROJECT_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_REPOSITORIES: usize = 64;
pub const MAX_ENVIRONMENT_VALUES: usize = 256;
pub const MAX_APPLICATION_PORTS: usize = 128;
pub const MAX_AGENTS: usize = 32;
pub const MAX_SKILLS: usize = 256;
pub const MAX_CREDENTIALS: usize = 128;
pub const MAX_LOCAL_MOUNTS: usize = 64;

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
    #[error("conflicting codewire project schema versions {version} and {schema_version}")]
    ConflictingSchemaVersion { version: u32, schema_version: u32 },
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
}

impl ProjectDocument {
    pub fn ensure_platform_compatible(&self) -> Result<(), ProjectError> {
        if self.spec.workspace_mode == WorkspaceMode::Direct {
            return Err(ProjectError::PlatformUnsupported {
                field: "workspace.mode",
            });
        }
        if self.local.direct_source.is_some() {
            return Err(ProjectError::PlatformUnsupported {
                field: "workspace.source",
            });
        }
        if !self.local.mounts.is_empty() {
            return Err(ProjectError::PlatformUnsupported { field: "mounts" });
        }
        if !self.local.host_ports.is_empty() {
            return Err(ProjectError::PlatformUnsupported {
                field: "ports.host_port",
            });
        }
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agent_environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillSelection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ports: Vec<ApplicationPort>,
    #[serde(default, skip_serializing_if = "ResourceSpec::is_empty")]
    pub resources: ResourceSpec,
    #[serde(default, skip_serializing_if = "SecretBindings::is_empty")]
    pub secrets: SecretBindings,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialReference>,
    #[serde(default, skip_serializing_if = "WorkspaceMode::is_auto")]
    pub workspace_mode: WorkspaceMode,
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
            agent_environment: BTreeMap::new(),
            skills: Vec::new(),
            application_ports: Vec::new(),
            resources: ResourceSpec::default(),
            secrets: SecretBindings::default(),
            credentials: BTreeMap::new(),
            workspace_mode: WorkspaceMode::Auto,
        }
    }
}

impl ProjectSpec {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_org: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_user: Option<bool>,
}

impl SecretBindings {
    pub fn is_empty(&self) -> bool {
        self.project.is_empty() && self.include_org.is_none() && self.include_user.is_none()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialReference {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider: String,
    pub account: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    #[default]
    Auto,
    Clone,
    Direct,
}

impl WorkspaceMode {
    fn is_auto(value: &Self) -> bool {
        *value == Self::Auto
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalProjectIntent {
    pub direct_source: Option<String>,
    pub direct_read_only: bool,
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
    schema_version: Option<u32>,
    #[serde(default)]
    preset: String,
    #[serde(default)]
    image: String,
    #[serde(default, alias = "repos")]
    repositories: Vec<RawRepository>,
    #[serde(default, alias = "workdir")]
    working_directory: String,
    #[serde(default, alias = "install")]
    install_command: String,
    #[serde(default, alias = "startup")]
    startup_script: String,
    #[serde(default, alias = "env")]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    agents: Option<RawAgents>,
    #[serde(default)]
    agent: String,
    #[serde(default)]
    install_agents: Option<bool>,
    #[serde(default)]
    agent_env: BTreeMap<String, String>,
    #[serde(default)]
    skills: Vec<RawSkill>,
    #[serde(default, alias = "app_ports")]
    ports: Vec<RawPort>,
    #[serde(default)]
    cpu: Option<RawQuantity>,
    #[serde(default)]
    memory: Option<RawQuantity>,
    #[serde(default)]
    disk: Option<RawQuantity>,
    #[serde(default)]
    secrets: Option<RawSecrets>,
    #[serde(default)]
    secret_project: String,
    #[serde(default)]
    include_org_secrets: Option<bool>,
    #[serde(default)]
    include_user_secrets: Option<bool>,
    #[serde(default)]
    credentials: BTreeMap<String, RawCredential>,
    #[serde(default)]
    workspace: Option<RawWorkspace>,
    #[serde(default)]
    mounts: Vec<RawMountBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepository {
    #[serde(default, alias = "url")]
    source: String,
    #[serde(default)]
    revision: String,
    #[serde(default)]
    branch: String,
    #[serde(default, alias = "mount_path")]
    destination: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawAgents {
    String(String),
    List(Vec<String>),
    Mapping(RawAgentsBlock),
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
#[serde(untagged)]
enum RawSkill {
    String(String),
    Mapping(RawSkillBlock),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkillBlock {
    #[serde(default)]
    path: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    agents: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawPort {
    Int(i64),
    String(String),
    Mapping(RawPortBlock),
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
    published: i64,
    #[serde(default)]
    target: i64,
    #[serde(default)]
    label: String,
    #[serde(default)]
    access: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawQuantity {
    Int(i64),
    String(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSecrets {
    String(String),
    Mapping(RawSecretsBlock),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretsBlock {
    #[serde(default)]
    org: Option<bool>,
    #[serde(default)]
    user: Option<bool>,
    #[serde(default)]
    project: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawCredential {
    String(String),
    Mapping(RawCredentialBlock),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialBlock {
    #[serde(default)]
    provider: String,
    #[serde(default, alias = "account_ref")]
    account: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawWorkspace {
    String(String),
    Mapping(RawWorkspaceBlock),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkspaceBlock {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    source: String,
    #[serde(default, alias = "readonly")]
    read_only: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMountBlock {
    #[serde(default)]
    source: String,
    #[serde(default, alias = "target")]
    destination: String,
    #[serde(default)]
    mode: String,
    #[serde(default, alias = "readonly")]
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
