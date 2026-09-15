//! Linux lifecycle transitions for the shared supervisor metadata records.

#[cfg(test)]
use crate::supervisor_metadata::legacy::{ProcessIdentity, SocketIdentity};
use crate::supervisor_metadata::{
    EnvironmentRecord, SupervisorMetadataError, workspace_storage_generation,
};
#[cfg(test)]
use crate::supervisor_metadata::{
    PlatformSourceAuthority, RunnerRecord, SUPERVISOR_STATE_SCHEMA, StoredEnvironmentState,
    SupervisorState,
};
use crate::workspace_generation::WorkspaceGenerationRecord;

use super::SupervisorError;

impl EnvironmentRecord {
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
        if workspace_storage_generation(active).map_err(SupervisorError::from)?
            != workspace_storage_generation(staging).map_err(SupervisorError::from)?
        {
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
        if workspace_storage_generation(active).map_err(SupervisorError::from)?
            != expected_active_storage
        {
            return Err(SupervisorError::InvalidState);
        }
        if let Some(staging) = self.staging_workspace_generation.as_ref() {
            let staging_artifact = self
                .staging_artifact_generation
                .as_deref()
                .unwrap_or(active_artifact);
            if workspace_storage_generation(staging).map_err(SupervisorError::from)?
                == expected_rollback_storage
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
        if workspace_storage_generation(rollback).map_err(SupervisorError::from)?
            != expected_rollback_storage
        {
            return Err(SupervisorError::InvalidState);
        }
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
        if workspace_storage_generation(active).map_err(SupervisorError::from)?
            != expected_active_storage
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
            || workspace_storage_generation(staging).map_err(SupervisorError::from)?
                != expected_rollback_storage
        {
            return Err(SupervisorError::InvalidState);
        }
        self.rollback_workspace_generation = self.staging_workspace_generation.take();
        self.staging_artifact_generation = None;
        Ok(())
    }
}

impl From<SupervisorMetadataError> for SupervisorError {
    fn from(error: SupervisorMetadataError) -> Self {
        match error {
            SupervisorMetadataError::InvalidRequest => Self::InvalidRequest,
            SupervisorMetadataError::InvalidState => Self::InvalidState,
            SupervisorMetadataError::SecretInState => Self::SecretInState,
            SupervisorMetadataError::InvalidRunnerResponse => Self::InvalidRunnerResponse,
            SupervisorMetadataError::WorkspaceGeneration => Self::WorkspaceGeneration,
        }
    }
}

#[cfg(test)]
mod tests;
