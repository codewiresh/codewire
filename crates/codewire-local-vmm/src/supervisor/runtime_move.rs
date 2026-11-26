//! The guest runtime ABI of an environment's boot assets: what a start or a
//! restart admits, and the move of a stopped environment whose assets speak
//! an earlier ABI onto the installed runtime (#4980;
//! `docs/dev/CLI-ORCHESTRATION.md`, the paragraph on retained boot assets).

use super::*;

impl Supervisor {
    pub(super) async fn require_environment_guest_seed_abi(
        &self,
        name: &str,
        staging: bool,
    ) -> Result<(), SupervisorError> {
        let generation =
            artifact_generation_for_boot(&self.environment(name)?, staging)?.to_owned();
        self.require_guest_seed_abi_for_generation(&generation)
            .await
    }

    pub(super) async fn require_guest_seed_abi_for_generation(
        &self,
        generation: &str,
    ) -> Result<(), SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(generation)
            .await
            .map_err(artifact_store_error)?
            .require_current_guest_seed_abi()?;
        Ok(())
    }

    pub(super) async fn admit_start_boot_inputs(&self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let staging = environment.staging_workspace_generation.is_some();
        let generation = if !staging
            && environment.active_workspace_generation.is_none()
            && environment.staging_workspace_generation.is_none()
            && environment.staging_artifact_generation.is_none()
        {
            // A first Start has retained boot assets before its workspace is
            // staged. Admit those exact assets, never a new installed default.
            environment
                .active_artifact_generation
                .as_deref()
                .filter(|generation| valid_sha256(generation))
                .ok_or(SupervisorError::InvalidState)?
        } else {
            artifact_generation_for_boot(&environment, staging)?
        }
        .to_owned();
        self.require_guest_seed_abi_for_generation(&generation)
            .await?;
        let workspace_plan = self.environment(name)?.workspace_plan.clone();
        self.require_vm_only_guest_for_plan(&generation, &workspace_plan)
            .await?;
        if self.environment(name)?.cw_runtime.is_some() {
            let engine = PrivateRoot::open(&self.config.engine_root())?;
            RuntimeArtifactStore::create(&engine)
                .map_err(artifact_store_error)?
                .open_generation(&generation)
                .await
                .map_err(artifact_store_error)?
                .require_live_cw_runtime_publisher()?;
        }
        self.admit_environment_cw_runtime(name).await?;
        Ok(())
    }

    /// What a runtime's guest init declares, such as
    /// `seed=13;cw_catalog=1;net=2`.
    pub(super) async fn guest_abi_for_generation(
        &self,
        generation: &str,
    ) -> Result<String, SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        Ok(RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(generation)
            .await
            .map_err(artifact_store_error)?
            .guest_runtime_abi()?)
    }

    /// The guest ABI `name` moves from: when its active boot assets speak an
    /// ABI the installed runner cannot start and nothing else is staged for
    /// it, or when a move it staged has not finished yet. A start moves only
    /// an environment that is not running; a restart moves a running one
    /// before it stops it.
    pub(super) async fn runtime_move_from(
        &self,
        name: &str,
    ) -> Result<Option<String>, SupervisorError> {
        let environment = self.environment(name)?;
        let staged_move = staged_runtime_move(&environment);
        if !staged_move
            && (environment.staging_workspace_generation.is_some()
                || environment.staging_artifact_generation.is_some())
        {
            return Ok(None);
        }
        let Some(current) = environment.active_artifact_generation.clone() else {
            return Ok(None);
        };
        match self.require_guest_seed_abi_for_generation(&current).await {
            Ok(()) => Ok(None),
            Err(SupervisorError::Artifact(
                crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_),
            )) => {
                // An init older than the marker declares nothing; it still
                // moves, and is named for what it is.
                let declared = self.guest_abi_for_generation(&current).await;
                Ok(Some(
                    declared.unwrap_or_else(|_| "an unmarked guest".to_owned()),
                ))
            }
            Err(error) => Err(error),
        }
    }

    /// The guest ABI a start of `name` moves it from: as
    /// [`Self::runtime_move_from`], for an environment that is not running.
    pub(super) async fn start_moves_from(
        &self,
        name: &str,
    ) -> Result<Option<String>, SupervisorError> {
        if self.environment(name)?.state == StoredEnvironmentState::Running {
            return Ok(None);
        }
        self.runtime_move_from(name).await
    }

    /// A start's boot admission: [`Self::admit_start_boot_inputs`], except
    /// that assets the installed runner cannot start pass when the start
    /// moves the environment off them, once the installed runtime is shown
    /// usable. A start that cannot move so refuses here, before any of its
    /// effects. Its `StageWorkspaceGeneration` then stages the installed
    /// assets, which the runner admits again as it boots.
    pub(super) async fn admit_start_or_move(&self, name: &str) -> Result<(), SupervisorError> {
        // A staged move boots its staged assets, which are admitted as such.
        if !staged_runtime_move(&self.environment(name)?)
            && self.start_moves_from(name).await?.is_some()
        {
            let installed = self.admit_current_artifact_generation().await?;
            self.require_guest_seed_abi_for_generation(&installed)
                .await?;
            self.admit_environment_cw_runtime(name).await?;
            return Ok(());
        }
        self.admit_start_boot_inputs(name).await
    }

    /// A fork's snapshot assets: a VM checkpoint's must speak the installed
    /// guest ABI, since its memory cannot move; a disk snapshot's may speak
    /// an earlier one, and the fork moves onto the installed runtime at its
    /// first boot.
    pub(super) async fn require_forkable_guest(
        &self,
        generation: &str,
        checkpoint: bool,
    ) -> Result<(), SupervisorError> {
        match self.require_guest_seed_abi_for_generation(generation).await {
            Err(SupervisorError::Artifact(
                crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_),
            )) if !checkpoint => Ok(()),
            checked => checked,
        }
    }

    /// The boot assets `name` would boot next pass the guest ABI check: the
    /// staged ones when a move is staged, else the active ones.
    pub(super) async fn require_boot_guest_seed_abi(
        &self,
        name: &str,
    ) -> Result<(), SupervisorError> {
        let staging = self
            .environment(name)?
            .staging_workspace_generation
            .is_some();
        self.require_environment_guest_seed_abi(name, staging).await
    }

    /// `name`'s workspace on the installed runtime, when it moves: the same
    /// project, image, root disk size and skill snapshot, on the installed
    /// boot assets. The workspace disk is kept; the root disk is built
    /// again from the image for the new assets. None when no move is due,
    /// or when one is staged already.
    async fn installed_runtime_generation(
        &self,
        name: &str,
    ) -> Result<Option<InstalledRuntime>, SupervisorError> {
        if staged_runtime_move(&self.environment(name)?)
            || self.runtime_move_from(name).await?.is_none()
        {
            return Ok(None);
        }
        let artifact_generation = self.admit_current_artifact_generation().await?;
        self.require_guest_seed_abi_for_generation(&artifact_generation)
            .await?;
        let environment = self.environment(name)?;
        // The guest cw is part of the runtime: a bound environment's catalog
        // moves with its boot assets, since the earlier guest cw cannot speak
        // the installed runner's protocols.
        let catalog_generation = match environment.cw_runtime {
            Some(_) => Some(
                self.admit_installed_cw_runtime()
                    .await?
                    .ok_or(CwRuntimeError::InvalidAsset)?,
            ),
            None => None,
        };
        let generation = environment
            .active_workspace_generation
            .as_ref()
            .map(|active| moved_generation(active, &artifact_generation))
            .transpose()?;
        Ok(Some(InstalledRuntime {
            artifact_generation,
            catalog_generation,
            generation,
        }))
    }

    /// What a start's `StageWorkspaceGeneration` stages: the move onto the
    /// installed runtime when one is due, else the first boot's generation.
    /// An environment never booted has no workspace to keep, so it takes the
    /// installed assets and catalog as its own and stages its first
    /// generation on them.
    pub(super) async fn stage_start_generation(
        &self,
        name: &str,
    ) -> Result<StagedStart, SupervisorError> {
        let Some(installed) = self.installed_runtime_generation(name).await? else {
            return Ok(StagedStart::Generation(
                self.stage_workspace_generation(name).await?,
            ));
        };
        let InstalledRuntime {
            artifact_generation,
            catalog_generation,
            generation,
        } = installed;
        if let Some(generation) = generation {
            return Ok(StagedStart::Moved {
                artifact_generation,
                catalog_generation,
                generation,
            });
        }
        self.update_environment(name, |environment| {
            environment.active_artifact_generation = Some(artifact_generation);
            if let (Some(binding), Some(catalog)) =
                (environment.cw_runtime.as_mut(), catalog_generation)
            {
                binding.active_catalog_generation = catalog;
            }
            Ok(())
        })?;
        Ok(StagedStart::Generation(
            self.stage_workspace_generation(name).await?,
        ))
    }

    /// A restart of a running `name` whose assets speak an earlier ABI
    /// stages the move before anything is stopped, so the restart boots the
    /// installed runtime and promotes it as an update would. A move that
    /// cannot be staged fails here, with the VM still running.
    pub(super) async fn stage_restart_move(&self, name: &str) -> Result<(), SupervisorError> {
        let Some(installed) = self.installed_runtime_generation(name).await? else {
            return Ok(());
        };
        let generation = installed.generation.ok_or(SupervisorError::InvalidState)?;
        self.update_environment(name, |environment| {
            StagedStart::Moved {
                artifact_generation: installed.artifact_generation,
                catalog_generation: installed.catalog_generation,
                generation,
            }
            .record_in(environment)
        })
    }

    /// The catalog this boot moves `environment` off, for its seed, logged
    /// as the move it is; empty for every other boot.
    pub(super) fn cw_runtime_moved_from(&self, environment: &EnvironmentRecord) -> String {
        let Some((from, to)) = moved_catalogs(environment) else {
            return String::new();
        };
        diagnostic_log::record(
            self.log.as_deref(),
            "cw_runtime_move",
            &[
                ("environment", LogField::Id(environment.id)),
                ("from", LogField::Digest(from)),
                ("to", LogField::Digest(to)),
            ],
        );
        from.to_owned()
    }

    /// The `runtime_move` a start's result carries when it moved `name`
    /// from `from`: both ABIs, and how many of its VM checkpoints the move
    /// leaves unrestorable.
    pub(super) async fn runtime_move_result(
        &self,
        name: &str,
        from: String,
    ) -> Result<serde_json::Value, SupervisorError> {
        let environment = self.environment(name)?;
        let to = self
            .guest_abi_for_generation(
                environment
                    .active_artifact_generation
                    .as_deref()
                    .ok_or(SupervisorError::InvalidState)?,
            )
            .await?;
        let unrestorable = {
            let (config, id) = (self.config.clone(), environment.id);
            tokio::task::spawn_blocking(move || {
                checkpoints::local::unrestorable_after_move(&config, id)
            })
            .await
            .map_err(|_| SupervisorError::InvalidState)?
            .map_err(|_| SupervisorError::InvalidState)?
        };
        Ok(serde_json::json!({
            "from_guest_abi": from,
            "to_guest_abi": to,
            "unrestorable_checkpoints": unrestorable,
        }))
    }
}

impl SupervisorCore {
    /// Fail a restart its preflight refused, with the VM still running, and
    /// drop the move its RPC staged, so nothing staged outlives it.
    pub(super) fn fail_restart_preflight(
        &mut self,
        pending: &OperationRecord,
        name: &str,
    ) -> Result<(), SupervisorError> {
        let current = self
            .store
            .operation_by_request(pending.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        let mut next_state = self.state.clone();
        next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
            .discard_staged_runtime_move();
        self.store.replace_state_and_advance_operation(
            &next_state,
            current.operation_id,
            current.checkpoint,
            OperationPhase::Failed,
            None,
            Some("restart_preflight"),
        )?;
        self.state = next_state;
        Ok(())
    }
}

/// The catalogs a boot with a staged catalog moves between: only a staged
/// move stages one.
pub(super) fn moved_catalogs(environment: &EnvironmentRecord) -> Option<(&str, &str)> {
    let binding = environment.cw_runtime.as_ref()?;
    let staged = binding.staging_catalog_generation.as_deref()?;
    Some((binding.active_catalog_generation.as_str(), staged))
}

/// `active` on other boot assets: the same project, image, root disk size
/// and skill snapshot.
pub(super) fn moved_generation(
    active: &WorkspaceGenerationRecord,
    artifact_generation: &str,
) -> Result<WorkspaceGenerationRecord, SupervisorError> {
    Ok(WorkspaceGenerationRecord::new_with_skill_snapshot(
        active.project_spec_json.as_bytes(),
        active.project_sha256.clone(),
        artifact_generation.to_owned(),
        active.image.clone(),
        active.root_disk_bytes,
        active.skill_snapshot.clone(),
    )?)
}

/// Whether `environment` holds a move that a start or restart staged and
/// has not finished: a staged generation that is its active workspace on
/// the staged boot assets, and nothing else. It stays staged after a failed
/// boot, as a first boot's generation does, so the runner's pin on the root
/// disk it booted holds, and the next start or restart boots it.
pub(super) fn staged_runtime_move(environment: &EnvironmentRecord) -> bool {
    let (Some(active), Some(staged), Some(artifact)) = (
        environment.active_workspace_generation.as_ref(),
        environment.staging_workspace_generation.as_ref(),
        environment.staging_artifact_generation.as_deref(),
    ) else {
        return false;
    };
    moved_generation(active, artifact).is_ok_and(|moved| &moved == staged)
}

/// The installed runtime a move stages: its boot assets, its cw catalog for
/// an environment bound to one, and the workspace generation on them (None
/// for an environment never booted).
struct InstalledRuntime {
    artifact_generation: String,
    catalog_generation: Option<String>,
    generation: Option<WorkspaceGenerationRecord>,
}

/// What a start stages before it boots.
pub(super) enum StagedStart {
    /// The first boot's generation; None when one is staged already.
    Generation(Option<WorkspaceGenerationRecord>),
    /// The environment's workspace on the installed runtime.
    Moved {
        artifact_generation: String,
        catalog_generation: Option<String>,
        generation: WorkspaceGenerationRecord,
    },
}

impl StagedStart {
    pub(super) fn record(
        self,
        state: &mut SupervisorState,
        name: &str,
    ) -> Result<(), SupervisorError> {
        match self {
            Self::Generation(generation) => {
                record_staged_workspace_generation(state, name, generation)
            }
            moved @ Self::Moved { .. } => moved.record_in(
                state
                    .environments
                    .get_mut(name)
                    .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?,
            ),
        }
    }

    /// Stage a move's assets, catalog and generation, promoted together when
    /// the boot that follows succeeds.
    fn record_in(self, environment: &mut EnvironmentRecord) -> Result<(), SupervisorError> {
        let Self::Moved {
            artifact_generation,
            catalog_generation,
            generation,
        } = self
        else {
            return Err(SupervisorError::InvalidState);
        };
        if environment.staging_workspace_generation.is_some()
            || environment.staging_artifact_generation.is_some()
            || environment
                .cw_runtime
                .as_ref()
                .is_some_and(|binding| binding.staging_catalog_generation.is_some())
        {
            return Err(SupervisorError::InvalidState);
        }
        match (environment.cw_runtime.as_mut(), catalog_generation) {
            (Some(binding), Some(catalog)) if catalog != binding.active_catalog_generation => {
                binding.staging_catalog_generation = Some(catalog);
            }
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err(SupervisorError::InvalidState),
        }
        environment.staging_artifact_generation = Some(artifact_generation);
        environment.staging_workspace_generation = Some(generation);
        Ok(())
    }
}

/// A start result's recorded `runtime_move`, for the operation it completed.
pub(super) fn runtime_move_proto(value: &serde_json::Value) -> Result<v1::RuntimeMove, Status> {
    let invalid = || Status::internal("local lifecycle runtime move result is invalid");
    let fields = value
        .as_object()
        .filter(|fields| fields.len() == 3)
        .ok_or_else(invalid)?;
    let text = |key| {
        fields
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(v1::RuntimeMove {
        from_guest_abi: text("from_guest_abi")?,
        to_guest_abi: text("to_guest_abi")?,
        unrestorable_checkpoints: fields
            .get("unrestorable_checkpoints")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(invalid)?,
    })
}
