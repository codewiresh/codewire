//! Complete credential-free supervisor state codec shared by platform stores.
//!
//! Decoding these records grants no process, socket, filesystem, registry, or
//! credential authority. Each platform store separately admits the represented
//! stopped state before exposing it through the supervisor protocol.

pub(crate) mod direct_share;
pub(crate) mod legacy;
pub(crate) mod oci;
pub(crate) mod workspace;
pub(crate) mod workspace_plan;

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::{
    AccessProfileId, AccessProfileReference, AccessProfileScope, EnvironmentAccessBinding,
    EnvironmentId,
};
use codewire_project::{ProjectSpec, StoragePlacement, StorageReference};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::control::v1;
use crate::host_port::{HostPortBinding, validate_canonical_host_port_bindings};
use crate::mesh_ingress::{
    MeshAttachment, MeshEnrollmentAuthSource, canonical_mesh_ingress_ports,
    validate_canonical_mesh_ingress_ports,
};
use crate::workspace_generation::{WorkspaceGenerationError, WorkspaceGenerationRecord};

use self::legacy::{
    MINIMUM_DOCKER_DISK_BYTES, MINIMUM_STATE_DISK_BYTES, ProcessIdentity, SocketIdentity,
    valid_root_disk_bytes,
};
use self::workspace_plan::{WorkspacePlan, WorkspacePlanError};

pub(crate) const SUPERVISOR_STATE_SCHEMA: u32 = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredEnvironmentState {
    Stopped,
    Starting,
    Running,
    Error,
    Orphaned,
}

impl StoredEnvironmentState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Error => "error",
            Self::Orphaned => "orphaned",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "stopped" => Some(Self::Stopped),
            "starting" => Some(Self::Starting),
            "running" => Some(Self::Running),
            "error" => Some(Self::Error),
            "orphaned" => Some(Self::Orphaned),
            _ => None,
        }
    }

    pub(crate) fn proto(self) -> v1::EnvironmentState {
        match self {
            Self::Stopped => v1::EnvironmentState::Stopped,
            Self::Starting => v1::EnvironmentState::Starting,
            Self::Running => v1::EnvironmentState::Running,
            Self::Error => v1::EnvironmentState::Error,
            Self::Orphaned => v1::EnvironmentState::Orphaned,
        }
    }

    pub(crate) fn from_proto(value: i32) -> Result<Self, SupervisorMetadataError> {
        match v1::EnvironmentState::try_from(value) {
            Ok(v1::EnvironmentState::Stopped) => Ok(Self::Stopped),
            Ok(v1::EnvironmentState::Starting) => Ok(Self::Starting),
            Ok(v1::EnvironmentState::Running) => Ok(Self::Running),
            Ok(v1::EnvironmentState::Error) => Ok(Self::Error),
            Ok(v1::EnvironmentState::Orphaned) => Ok(Self::Orphaned),
            _ => Err(SupervisorMetadataError::InvalidRunnerResponse),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunnerRecord {
    pub(crate) process: ProcessIdentity,
    pub(crate) socket: SocketIdentity,
    pub(crate) artifact_generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cw_runtime_catalog_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
}

/// Independent runtime custody; these generations never identify a boot or workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CwRuntimeBinding {
    pub(crate) schema_version: u32,
    pub(crate) active_catalog_generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) staging_catalog_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rollback_catalog_generation: Option<String>,
}

impl CwRuntimeBinding {
    pub(crate) fn validate(&self) -> Result<(), SupervisorMetadataError> {
        if self.schema_version != 1
            || !valid_sha256(&self.active_catalog_generation)
            || self
                .staging_catalog_generation
                .as_deref()
                .is_some_and(|generation| !valid_sha256(generation))
            || self
                .rollback_catalog_generation
                .as_deref()
                .is_some_and(|generation| !valid_sha256(generation))
        {
            return Err(SupervisorMetadataError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) state: StoredEnvironmentState,
    pub(crate) vcpus: u8,
    pub(crate) memory_mib: u32,
    pub(crate) disk_bytes: u64,
    #[serde(default)]
    pub(crate) docker_disk_bytes: u64,
    pub(crate) generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) host_ports: Vec<HostPortBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mesh: Option<MeshAttachment>,
    pub(crate) workspace_plan: WorkspacePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_json: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_profile: Option<AccessProfileReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_binding: Option<EnvironmentAccessBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) platform_source_authority: Option<PlatformSourceAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cw_runtime: Option<CwRuntimeBinding>,
    pub(crate) runner: Option<RunnerRecord>,
    #[serde(default)]
    pub(crate) active_artifact_generation: Option<String>,
    #[serde(default)]
    pub(crate) staging_artifact_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_workspace_generation: Option<WorkspaceGenerationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) staging_workspace_generation: Option<WorkspaceGenerationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rollback_workspace_generation: Option<WorkspaceGenerationRecord>,
}

impl EnvironmentRecord {
    pub(crate) fn proto(&self, selected: bool) -> v1::Environment {
        let project = self
            .project_spec_json
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<ProjectSpec>(bytes).ok());
        let skill_snapshot = self
            .active_workspace_generation
            .as_ref()
            .and_then(|generation| generation.skill_snapshot.as_ref());
        v1::Environment {
            id: self.id.to_string(),
            name: self.name.clone(),
            state: self.state.proto() as i32,
            vcpus: u32::from(self.vcpus),
            memory_mib: self.memory_mib,
            disk_bytes: self.disk_bytes,
            docker_disk_bytes: self.docker_disk_bytes,
            generation: self.generation,
            selected,
            project_spec_sha256: self.project_spec_sha256.clone().unwrap_or_default(),
            project_spec_json: self.project_spec_json.clone().unwrap_or_default(),
            access_profile_id: self
                .access_binding
                .as_ref()
                .map(|binding| binding.profile_id.to_string())
                .unwrap_or_default(),
            platform_source_authority: self
                .platform_source_authority
                .as_ref()
                .map(PlatformSourceAuthority::proto),
            workspace_plan_sha256: self.workspace_plan.sha256().unwrap_or_default(),
            workspace_input_count: u32::try_from(self.workspace_plan.inputs.len())
                .unwrap_or_default(),
            working_directory: project
                .as_ref()
                .map(|project| project.working_directory.clone())
                .unwrap_or_default(),
            access_profile: self
                .access_profile
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            access_profile_revision: self
                .access_binding
                .as_ref()
                .map(|binding| binding.profile_revision)
                .unwrap_or_default(),
            skill_snapshot_sha256: skill_snapshot
                .and_then(|snapshot| snapshot.sha256().ok())
                .unwrap_or_default(),
            skill_snapshot_generation: skill_snapshot
                .map(codewire_vmm_guest_probe::SkillSnapshotPlan::plan_generation)
                .unwrap_or_default(),
            skill_snapshot_count: skill_snapshot
                .and_then(|snapshot| u32::try_from(snapshot.skills().len()).ok())
                .unwrap_or_default(),
            requires_credential_authority: self.access_profile.is_some()
                || project
                    .as_ref()
                    .is_some_and(|project| !project.secrets.is_empty()),
            host_ports: host_ports_to_proto(&self.host_ports),
            mesh: mesh_attachment_to_proto(self.mesh.as_ref()),
            error_code: self
                .runner
                .as_ref()
                .and_then(|runner| runner.error_code.clone())
                .filter(|_| self.state == StoredEnvironmentState::Error)
                .unwrap_or_default(),
        }
    }

    pub(crate) fn validate(&self, key: &str) -> Result<(), SupervisorMetadataError> {
        if self
            .cw_runtime
            .as_ref()
            .is_some_and(|binding| binding.validate().is_err())
            || self.runner.as_ref().is_some_and(|runner| {
                runner
                    .cw_runtime_catalog_generation
                    .as_deref()
                    .is_some_and(|generation| !valid_sha256(generation))
            })
        {
            return Err(SupervisorMetadataError::InvalidState);
        }
        let invalid_workspace_generation = match (
            self.project_spec_json.as_deref(),
            self.project_spec_sha256.as_deref(),
        ) {
            (Some(project_json), Some(project_sha256)) => {
                self.active_workspace_generation
                    .as_ref()
                    .is_some_and(|generation| {
                        generation
                            .validate_for_project_intent(project_json, project_sha256)
                            .is_err()
                    })
                    || self
                        .staging_workspace_generation
                        .as_ref()
                        .is_some_and(|generation| {
                            if self.active_workspace_generation.is_some() {
                                generation.validate().is_err()
                            } else {
                                generation
                                    .validate_for_project_intent(project_json, project_sha256)
                                    .is_err()
                            }
                        })
                    || self
                        .rollback_workspace_generation
                        .as_ref()
                        .is_some_and(|generation| generation.validate().is_err())
            }
            (None, None) => true,
            _ => true,
        };
        let active_artifact = self.active_artifact_generation.as_deref();
        let staging_artifact = self
            .staging_artifact_generation
            .as_deref()
            .or(active_artifact);
        let active_storage = self
            .active_workspace_generation
            .as_ref()
            .map(|generation| {
                let artifact = active_artifact.ok_or(SupervisorMetadataError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorMetadataError::InvalidState);
                }
                workspace_storage_generation(generation)
            })
            .transpose()?;
        let staging_storage = self
            .staging_workspace_generation
            .as_ref()
            .map(|generation| {
                let artifact = staging_artifact.ok_or(SupervisorMetadataError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorMetadataError::InvalidState);
                }
                workspace_storage_generation(generation)
            })
            .transpose()?;
        let rollback_storage = self
            .rollback_workspace_generation
            .as_ref()
            .map(workspace_storage_generation)
            .transpose()?;
        let duplicate_workspace_generation =
            |left: Option<&String>, right: Option<&String>| left.is_some() && left == right;
        if self.id.is_nil()
            || self.name != key
            || !valid_environment_name(&self.name)
            || self.vcpus == 0
            || self.vcpus > 32
            || !(128..=65_536).contains(&self.memory_mib)
            || self.disk_bytes < MINIMUM_STATE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(1024 * 1024)
            || (self.docker_disk_bytes != 0
                && (self.docker_disk_bytes < MINIMUM_DOCKER_DISK_BYTES
                    || !self.docker_disk_bytes.is_multiple_of(1024 * 1024)))
            || self.workspace_plan.validate().is_err()
            || validate_canonical_host_port_bindings(&self.host_ports).is_err()
            || self.mesh.as_ref().is_some_and(|mesh| {
                mesh.validate().is_err()
                    || mesh.node_name != self.name
                    || self
                        .project_spec_json
                        .as_deref()
                        .and_then(|bytes| serde_json::from_slice(bytes).ok())
                        .is_none_or(|project: ProjectSpec| {
                            validate_mesh_for_project(mesh, &project).is_err()
                        })
            })
            || match (&self.project_spec_json, &self.project_spec_sha256) {
                (None, None) => true,
                (Some(bytes), Some(digest)) => {
                    validate_project_intent(bytes, digest, None).is_err()
                        || serde_json::from_slice::<ProjectSpec>(bytes).map_or(true, |project| {
                            self.workspace_plan.validate_for_project(&project).is_err()
                        })
                }
                _ => true,
            }
            || !environment_access_metadata_valid(self)
            || self
                .active_artifact_generation
                .as_ref()
                .is_none_or(|generation| !valid_sha256(generation))
            || self
                .staging_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || self.runner.as_ref().is_some_and(|runner| {
                runner
                    .error_code
                    .as_deref()
                    .is_some_and(|error_code| !runner_event_error_code_valid(error_code))
            })
            || invalid_workspace_generation
            || (self.rollback_workspace_generation.is_some()
                && self.active_workspace_generation.is_none())
            || duplicate_workspace_generation(active_storage.as_ref(), rollback_storage.as_ref())
            || duplicate_workspace_generation(staging_storage.as_ref(), rollback_storage.as_ref())
        {
            return Err(SupervisorMetadataError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorState {
    pub(crate) schema_version: u32,
    pub(crate) current: Option<String>,
    pub(crate) environments: BTreeMap<String, EnvironmentRecord>,
}

impl Default for SupervisorState {
    fn default() -> Self {
        Self {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: None,
            environments: BTreeMap::new(),
        }
    }
}

impl SupervisorState {
    pub(crate) fn validate(&self) -> Result<(), SupervisorMetadataError> {
        if self.schema_version != SUPERVISOR_STATE_SCHEMA
            || self
                .current
                .as_ref()
                .is_some_and(|name| !self.environments.contains_key(name))
        {
            return Err(SupervisorMetadataError::InvalidState);
        }
        for (name, environment) in &self.environments {
            environment.validate(name)?;
        }
        let value =
            serde_json::to_value(self).map_err(|_| SupervisorMetadataError::InvalidState)?;
        if contains_forbidden_state_key(&value) {
            return Err(SupervisorMetadataError::SecretInState);
        }
        Ok(())
    }
}

/// Pinned platform authority, not a cached credential or delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlatformSourceAuthority {
    pub(crate) server_url: String,
    pub(crate) organization_id: String,
    pub(crate) user_id: String,
    #[serde(with = "canonical_profile_slots")]
    pub(crate) profile_slots: BTreeSet<String>,
}

impl PlatformSourceAuthority {
    pub(crate) fn from_proto(
        value: &v1::PlatformSourceAuthority,
    ) -> Result<Self, SupervisorMetadataError> {
        let profile_slots = value.profile_slots.iter().cloned().collect::<BTreeSet<_>>();
        if profile_slots.len() != value.profile_slots.len()
            || value
                .profile_slots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(SupervisorMetadataError::InvalidRequest);
        }
        let result = Self {
            server_url: value.server_url.clone(),
            organization_id: value.organization_id.clone(),
            user_id: value.user_id.clone(),
            profile_slots,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn validate(&self) -> Result<(), SupervisorMetadataError> {
        let server = url::Url::parse(&self.server_url)
            .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
        if self.server_url.len() > 2048
            || !matches!(server.scheme(), "https" | "http")
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.password().is_some()
            || server.query().is_some()
            || server.fragment().is_some()
            || !matches!(server.path(), "" | "/")
            || !valid_identity(&self.organization_id)
            || !valid_identity(&self.user_id)
            || codewire_access::ManagedCredentialClients::from_profile_slots(
                self.profile_slots.iter().map(String::as_str),
            )
            .is_err()
        {
            return Err(SupervisorMetadataError::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) fn proto(&self) -> v1::PlatformSourceAuthority {
        v1::PlatformSourceAuthority {
            server_url: self.server_url.clone(),
            organization_id: self.organization_id.clone(),
            user_id: self.user_id.clone(),
            profile_slots: self.profile_slots.iter().cloned().collect(),
        }
    }
}

/// The rule every local environment name follows.
pub fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn runner_event_error_code_valid(error_code: &str) -> bool {
    !error_code.is_empty()
        && error_code.len() <= 64
        && error_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

pub(crate) fn host_ports_to_proto(bindings: &[HostPortBinding]) -> Vec<v1::HostPortBinding> {
    bindings
        .iter()
        .map(|binding| v1::HostPortBinding {
            host_port: u32::from(binding.host_port),
            guest_port: u32::from(binding.guest_port),
        })
        .collect()
}

pub(crate) fn mesh_attachment_to_proto(
    attachment: Option<&MeshAttachment>,
) -> Option<v1::MeshAttachment> {
    attachment.map(|attachment| v1::MeshAttachment {
        mesh_url: attachment.mesh_url.clone(),
        organization_id: attachment.organization_id.clone(),
        network_id: attachment.network_id.clone(),
        node_name: attachment.node_name.clone(),
        guest_ports: attachment
            .guest_ports
            .iter()
            .map(|port| u32::from(*port))
            .collect(),
        auth_source: mesh_auth_source_to_proto(attachment.auth_source) as i32,
    })
}

fn mesh_auth_source_to_proto(source: MeshEnrollmentAuthSource) -> v1::MeshEnrollmentAuthSource {
    match source {
        MeshEnrollmentAuthSource::StandaloneLocal => v1::MeshEnrollmentAuthSource::StandaloneLocal,
        MeshEnrollmentAuthSource::HostedCurrent => v1::MeshEnrollmentAuthSource::HostedCurrent,
    }
}

pub(crate) fn validate_host_ports_for_project(
    bindings: &[HostPortBinding],
    project: &ProjectSpec,
) -> Result<(), SupervisorMetadataError> {
    validate_canonical_host_port_bindings(bindings)
        .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
    let application_ports = project
        .application_ports
        .iter()
        .map(|port| port.port)
        .collect::<BTreeSet<_>>();
    if bindings
        .iter()
        .any(|binding| !application_ports.contains(&binding.guest_port))
    {
        return Err(SupervisorMetadataError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn validate_mesh_for_project(
    attachment: &MeshAttachment,
    project: &ProjectSpec,
) -> Result<(), SupervisorMetadataError> {
    attachment
        .validate()
        .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
    let guest_ports =
        canonical_mesh_ingress_ports(project.application_ports.iter().map(|port| port.port))
            .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
    if attachment.guest_ports != guest_ports {
        return Err(SupervisorMetadataError::InvalidRequest);
    }
    validate_canonical_mesh_ingress_ports(&attachment.guest_ports)
        .map_err(|_| SupervisorMetadataError::InvalidRequest)
}

pub(crate) fn validate_project_intent(
    canonical_json: &[u8],
    expected_sha256: &str,
    expected_resources: Option<(u32, u32, u64)>,
) -> Result<(), ()> {
    const GIB: u64 = 1024 * 1024 * 1024;
    if canonical_json.is_empty()
        || canonical_json.len() > codewire_project::MAX_PROJECT_DOCUMENT_BYTES
        || !valid_sha256(expected_sha256)
    {
        return Err(());
    }
    let spec: ProjectSpec = serde_json::from_slice(canonical_json).map_err(|_| ())?;
    spec.validate().map_err(|_| ())?;
    if spec.canonical_json().map_err(|_| ())? != canonical_json
        || format!("{:x}", Sha256::digest(canonical_json)) != expected_sha256
        || spec.image.is_empty()
        || !spec.preset.is_empty()
        || spec.agents.install == Some(true)
    {
        return Err(());
    }
    if let Some((vcpus, memory_mib, disk_bytes)) = expected_resources
        && (!disk_bytes.is_multiple_of(GIB)
            || spec.resources.cpu_millicores != vcpus.checked_mul(1_000)
            || spec.resources.memory_mib != Some(u64::from(memory_mib))
            || spec.resources.disk_gib != Some(disk_bytes / GIB))
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn environment_access_metadata_valid(environment: &EnvironmentRecord) -> bool {
    let Some(json) = environment.project_spec_json.as_deref() else {
        return false;
    };
    let Some(sha256) = environment.project_spec_sha256.as_deref() else {
        return false;
    };
    if validate_project_intent(json, sha256, None).is_err() {
        return false;
    }
    let Ok(project) = serde_json::from_slice::<ProjectSpec>(json) else {
        return false;
    };
    let (profile_id, revision, reference) = match (
        environment.access_profile.as_ref(),
        environment.access_binding.as_ref(),
    ) {
        (None, None) => (String::new(), 0, String::new()),
        (Some(reference), Some(binding)) => {
            if binding.validate().is_err()
                || !access_environment_id(environment.id).is_ok_and(|environment_id| {
                    environment_id.as_str() == binding.environment_id.as_str()
                })
            {
                return false;
            }
            (
                binding.profile_id.to_string(),
                binding.profile_revision,
                reference.to_string(),
            )
        }
        _ => return false,
    };
    let authority = environment
        .platform_source_authority
        .as_ref()
        .map(PlatformSourceAuthority::proto);
    validate_source_metadata(
        &project,
        &profile_id,
        revision,
        &reference,
        authority.as_ref(),
    )
    .is_ok()
}

pub(crate) fn validate_source_metadata(
    project: &ProjectSpec,
    profile_id: &str,
    revision: u64,
    profile_reference: &str,
    authority: Option<&v1::PlatformSourceAuthority>,
) -> Result<Option<(AccessProfileId, u64, AccessProfileReference)>, SupervisorMetadataError> {
    let mut uses_platform =
        project.secrets.organization || project.secrets.user == Some(StoragePlacement::Platform);
    if !project.secrets.project.is_empty() {
        uses_platform |= exact_reference(
            StorageReference::project(&project.secrets.project)
                .map_err(|_| SupervisorMetadataError::InvalidRequest)?,
        )? == StoragePlacement::Platform;
    }
    let mut platform_profile = false;
    let binding = match &project.credentials {
        Some(credentials) => {
            let selected = StorageReference::profile(&credentials.profile)
                .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
            let placement = exact_reference(selected)?;
            if selected.selector.strip_prefix("id:") != Some(profile_id) || revision == 0 {
                return Err(SupervisorMetadataError::InvalidRequest);
            }
            let reference = profile_reference
                .parse::<AccessProfileReference>()
                .map_err(|_| SupervisorMetadataError::InvalidRequest)?;
            if placement == StoragePlacement::Local && reference.scope() != AccessProfileScope::User
            {
                return Err(SupervisorMetadataError::InvalidRequest);
            }
            platform_profile = placement == StoragePlacement::Platform;
            uses_platform |= placement == StoragePlacement::Platform;
            Some((
                AccessProfileId::parse(profile_id)
                    .map_err(|_| SupervisorMetadataError::InvalidRequest)?,
                revision,
                reference,
            ))
        }
        None if profile_id.is_empty() && revision == 0 && profile_reference.is_empty() => None,
        None => return Err(SupervisorMetadataError::InvalidRequest),
    };
    if uses_platform != authority.is_some() {
        return Err(SupervisorMetadataError::InvalidRequest);
    }
    if let Some(authority) = authority {
        let authority = PlatformSourceAuthority::from_proto(authority)?;
        if !platform_profile && !authority.profile_slots.is_empty() {
            return Err(SupervisorMetadataError::InvalidRequest);
        }
    }
    Ok(binding)
}

fn exact_reference(
    reference: StorageReference<'_>,
) -> Result<StoragePlacement, SupervisorMetadataError> {
    let placement = reference
        .placement
        .ok_or(SupervisorMetadataError::InvalidRequest)?;
    let id = reference
        .selector
        .strip_prefix("id:")
        .ok_or(SupervisorMetadataError::InvalidRequest)?;
    if !Uuid::parse_str(id).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == id) {
        return Err(SupervisorMetadataError::InvalidRequest);
    }
    Ok(placement)
}

fn access_environment_id(environment_id: Uuid) -> Result<EnvironmentId, SupervisorMetadataError> {
    EnvironmentId::parse(environment_id.to_string())
        .map_err(|_| SupervisorMetadataError::InvalidState)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn workspace_storage_generation(
    generation: &WorkspaceGenerationRecord,
) -> Result<String, SupervisorMetadataError> {
    let oci = oci_storage_generation(
        &generation.root_generation,
        generation.artifact_generation()?,
        generation.root_disk_bytes,
    )?;
    let Some(snapshot) = generation.skill_snapshot()? else {
        return Ok(oci);
    };
    let snapshot_sha256 = snapshot
        .sha256()
        .map_err(|_| SupervisorMetadataError::WorkspaceGeneration)?;
    let mut digest = Sha256::new();
    digest.update(b"codewire-root-generation-with-skills-v1\0");
    digest.update(oci.as_bytes());
    digest.update(snapshot_sha256.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn oci_storage_generation(
    oci_generation: &str,
    artifact_generation: &str,
    root_disk_bytes: u64,
) -> Result<String, SupervisorMetadataError> {
    if !valid_sha256(oci_generation)
        || !valid_sha256(artifact_generation)
        || !valid_root_disk_bytes(root_disk_bytes)
    {
        return Err(SupervisorMetadataError::InvalidState);
    }
    let mut digest = Sha256::new();
    digest.update(b"codewire-root-generation-oci-storage-v1\0");
    digest.update(oci_generation.as_bytes());
    digest.update(artifact_generation.as_bytes());
    digest.update(root_disk_bytes.to_le_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn contains_forbidden_state_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(name, value)| {
            let name = name.to_ascii_lowercase();
            name.contains("capability")
                || name.contains("credential")
                || name.contains("token")
                || contains_forbidden_state_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_forbidden_state_key),
        _ => false,
    }
}

mod canonical_profile_slots {
    use std::collections::BTreeSet;

    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    pub(super) fn serialize<S>(slots: &BTreeSet<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        slots.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(D::Error::custom(
                "platform profile slots must be unique and sorted",
            ));
        }
        Ok(values.into_iter().collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SupervisorMetadataError {
    #[error("native environment request is invalid")]
    InvalidRequest,
    #[error("native supervisor state is invalid")]
    InvalidState,
    #[error("native supervisor state must never contain a secret")]
    SecretInState,
    #[error("native environment runner returned invalid state")]
    InvalidRunnerResponse,
    #[error("workspace generation identity is invalid")]
    WorkspaceGeneration,
}

impl From<WorkspaceGenerationError> for SupervisorMetadataError {
    fn from(_: WorkspaceGenerationError) -> Self {
        Self::WorkspaceGeneration
    }
}

impl From<WorkspacePlanError> for SupervisorMetadataError {
    fn from(_: WorkspacePlanError) -> Self {
        Self::InvalidState
    }
}
