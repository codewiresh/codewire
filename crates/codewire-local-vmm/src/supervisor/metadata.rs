//! Supervisor-owned durable metadata and its exact in-memory transitions.

use std::collections::BTreeMap;

use codewire_access::{AccessProfileReference, EnvironmentAccessBinding};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::v1;
use crate::host_port::{HostPortBinding, validate_canonical_host_port_bindings};
use crate::linux::path::SocketIdentity;
use crate::mesh_ingress::MeshAttachment;
use crate::workspace_generation::WorkspaceGenerationRecord;
use crate::workspace_plan::WorkspacePlan;

use super::{
    PlatformSourceAuthority, ProcessIdentity, SUPERVISOR_STATE_SCHEMA, SupervisorError,
    contains_forbidden_state_key, environment_access_metadata_valid, host_ports_to_proto,
    mesh_attachment_to_proto, runner_event_error_code_valid, valid_environment_name, valid_sha256,
    validate_host_ports_for_project, validate_mesh_for_project, validate_project_intent,
    workspace_storage_generation,
};

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

    pub(super) fn proto(self) -> v1::EnvironmentState {
        match self {
            Self::Stopped => v1::EnvironmentState::Stopped,
            Self::Starting => v1::EnvironmentState::Starting,
            Self::Running => v1::EnvironmentState::Running,
            Self::Error => v1::EnvironmentState::Error,
            Self::Orphaned => v1::EnvironmentState::Orphaned,
        }
    }

    pub(super) fn from_proto(value: i32) -> Result<Self, SupervisorError> {
        match v1::EnvironmentState::try_from(value) {
            Ok(v1::EnvironmentState::Stopped) => Ok(Self::Stopped),
            Ok(v1::EnvironmentState::Starting) => Ok(Self::Starting),
            Ok(v1::EnvironmentState::Running) => Ok(Self::Running),
            Ok(v1::EnvironmentState::Error) => Ok(Self::Error),
            Ok(v1::EnvironmentState::Orphaned) => Ok(Self::Orphaned),
            _ => Err(SupervisorError::InvalidRunnerResponse),
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
    pub(crate) error_code: Option<String>,
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
    pub(super) fn proto(&self, selected: bool) -> v1::Environment {
        let project = self
            .project_spec_json
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<codewire_project::ProjectSpec>(bytes).ok());
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

    pub(super) fn promote_staging_workspace_generation(
        &mut self,
    ) -> Result<Option<WorkspaceGenerationRecord>, SupervisorError> {
        let Some(staging) = self.staging_workspace_generation.as_ref() else {
            return Ok(None);
        };
        let current_project_json = self
            .project_spec_json
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_project_sha256 = self
            .project_spec_sha256
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_artifact_generation = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let next_rollback = self.active_workspace_generation.clone();
        if let Some(active) = next_rollback.as_ref() {
            active.validate_for_project_intent(current_project_json, current_project_sha256)?;
            if active.artifact_generation()? != current_artifact_generation {
                return Err(SupervisorError::InvalidState);
            }
        }
        let (next_project_json, next_project_sha256) = staging
            .project_intent_with_current_sources(current_project_json, current_project_sha256)?;
        let staging_artifact_fallback = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(current_artifact_generation);
        let next_artifact_generation = staging.artifact_generation()?.to_owned();
        if next_artifact_generation != staging_artifact_fallback {
            return Err(SupervisorError::InvalidState);
        }
        if self
            .staging_artifact_generation
            .as_deref()
            .is_some_and(|artifact| artifact != next_artifact_generation)
        {
            return Err(SupervisorError::InvalidState);
        }

        let displaced = self.rollback_workspace_generation.take();
        self.rollback_workspace_generation = next_rollback;
        self.active_workspace_generation = self.staging_workspace_generation.take();
        self.project_spec_json = Some(next_project_json);
        self.project_spec_sha256 = Some(next_project_sha256);
        self.active_artifact_generation = Some(next_artifact_generation);
        self.staging_artifact_generation = None;
        Ok(displaced)
    }

    pub(super) fn finish_staging_workspace_update_without_boot(
        &mut self,
    ) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let staging_artifact_fallback = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(active_artifact);
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let staging = self
            .staging_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != workspace_storage_generation(staging)? {
            return Err(SupervisorError::InvalidState);
        }
        let current_project_json = self
            .project_spec_json
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_project_sha256 = self
            .project_spec_sha256
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        active.validate_for_project_intent(current_project_json, current_project_sha256)?;
        let (next_project_json, next_project_sha256) = staging
            .project_intent_with_current_sources(current_project_json, current_project_sha256)?;
        let next_artifact_generation = staging.artifact_generation()?.to_owned();
        if next_artifact_generation != staging_artifact_fallback {
            return Err(SupervisorError::InvalidState);
        }

        self.active_workspace_generation = self.staging_workspace_generation.take();
        self.project_spec_json = Some(next_project_json);
        self.project_spec_sha256 = Some(next_project_sha256);
        self.active_artifact_generation = Some(next_artifact_generation);
        self.staging_artifact_generation = None;
        Ok(())
    }

    pub(super) fn stage_rollback_workspace_generation(
        &mut self,
        expected_active_storage: &str,
        expected_rollback_storage: &str,
    ) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != expected_active_storage {
            return Err(SupervisorError::InvalidState);
        }
        if let Some(staging) = self.staging_workspace_generation.as_ref() {
            let staging_artifact = self
                .staging_artifact_generation
                .as_deref()
                .unwrap_or(active_artifact);
            if workspace_storage_generation(staging)? == expected_rollback_storage
                && self.rollback_workspace_generation.is_none()
            {
                if staging.artifact_generation()? != staging_artifact {
                    return Err(SupervisorError::InvalidState);
                }
                return Ok(());
            }
            return Err(SupervisorError::InvalidState);
        }
        let rollback = self
            .rollback_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(rollback)? != expected_rollback_storage {
            return Err(SupervisorError::InvalidState);
        }
        let rollback = self
            .rollback_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let rollback_artifact = rollback.artifact_generation()?.to_owned();
        self.staging_artifact_generation = Some(rollback_artifact);
        self.staging_workspace_generation = self.rollback_workspace_generation.take();
        Ok(())
    }

    pub(super) fn restore_staged_rollback_workspace_generation(
        &mut self,
        expected_active_storage: &str,
        expected_rollback_storage: &str,
    ) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != expected_active_storage
            || self.rollback_workspace_generation.is_some()
        {
            return Err(SupervisorError::InvalidState);
        }
        let staging_artifact = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(active_artifact);
        let staging = self
            .staging_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if staging.artifact_generation()? != staging_artifact
            || workspace_storage_generation(staging)? != expected_rollback_storage
        {
            return Err(SupervisorError::InvalidState);
        }
        self.rollback_workspace_generation = self.staging_workspace_generation.take();
        self.staging_artifact_generation = None;
        Ok(())
    }

    pub(super) fn validate(&self, key: &str) -> Result<(), SupervisorError> {
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
                let artifact = active_artifact.ok_or(SupervisorError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorError::InvalidState);
                }
                workspace_storage_generation(generation)
            })
            .transpose()?;
        let staging_storage = self
            .staging_workspace_generation
            .as_ref()
            .map(|generation| {
                let artifact = staging_artifact.ok_or(SupervisorError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorError::InvalidState);
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
            || self.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(1024 * 1024)
            || (self.docker_disk_bytes != 0
                && (self.docker_disk_bytes < crate::linux::state::MINIMUM_DOCKER_DISK_BYTES
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
                        .is_none_or(|project: codewire_project::ProjectSpec| {
                            validate_mesh_for_project(mesh, &project).is_err()
                        })
            })
            || match (&self.project_spec_json, &self.project_spec_sha256) {
                (None, None) => true,
                (Some(bytes), Some(digest)) => {
                    validate_project_intent(bytes, digest, None).is_err()
                        || serde_json::from_slice::<codewire_project::ProjectSpec>(bytes)
                            .map_or(true, |project| {
                                self.workspace_plan.validate_for_project(&project).is_err()
                            })
                }
                _ => true,
            }
            || !environment_access_metadata_valid(self)
            || self
                .project_spec_json
                .as_deref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .is_none_or(|project: codewire_project::ProjectSpec| {
                    validate_host_ports_for_project(&self.host_ports, &project).is_err()
                })
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
            return Err(SupervisorError::InvalidState);
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
    pub(crate) fn validate(&self) -> Result<(), SupervisorError> {
        if self.schema_version != SUPERVISOR_STATE_SCHEMA
            || self
                .current
                .as_ref()
                .is_some_and(|name| !self.environments.contains_key(name))
        {
            return Err(SupervisorError::InvalidState);
        }
        for (name, environment) in &self.environments {
            environment.validate(name)?;
        }
        let value = serde_json::to_value(self).map_err(|_| SupervisorError::InvalidState)?;
        if contains_forbidden_state_key(&value) {
            return Err(SupervisorError::SecretInState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
