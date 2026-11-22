//! A VM checkpoint as the supervisor describes it.

use super::*;

pub(in crate::supervisor) fn checkpoint_proto(
    engine_root: &Path,
    row: &crate::snapshot_store::SnapshotRow,
    manifest: &Manifest,
    measure_sharing: bool,
) -> Result<v1::Checkpoint, SupervisorError> {
    let checkpoint = manifest
        .checkpoint
        .as_ref()
        .ok_or(SupervisorError::InvalidState)?;
    let snapshot = snapshot_proto(engine_root, row, manifest, measure_sharing)?;
    let described = snapshot.clone();
    let memory = snapshots_root(engine_root)?
        .path()
        .join(row.id.to_string())
        .join("vmm")
        .join(super::host::MEMORY_FILE);
    let memory_allocated_bytes = fs::File::open(&memory)
        .and_then(|file| crate::fs_clone::allocated_bytes(&file))
        .unwrap_or(0);
    let unrestorable_reason = super::host::other_host(&checkpoint.host)
        .or_else(|| earlier_runtime(engine_root, manifest))
        .unwrap_or_default();
    let mut warnings = vec![
        "a VM checkpoint holds everything the VM's memory held, delivered sign-ins included, until they expire; it stays on this host and is never exported".to_owned(),
    ];
    warnings.extend(super::host::host_warning(&checkpoint.host));
    Ok(v1::Checkpoint {
        id: snapshot.id,
        name: snapshot.name,
        created_unix_ms: snapshot.created_unix_ms,
        source_environment_id: snapshot.source_environment_id,
        source_name: snapshot.source_name,
        consistency: snapshot.consistency,
        locations: snapshot.locations,
        architecture: snapshot.architecture,
        vcpus: snapshot.vcpus,
        memory_mib: snapshot.memory_mib,
        disk_bytes: snapshot.disk_bytes,
        docker_disk_bytes: snapshot.docker_disk_bytes,
        image: snapshot.image,
        disks: snapshot.disks,
        memory_bytes: checkpoint.memory_bytes,
        memory_allocated_bytes,
        vmm_version: checkpoint.vmm.version.clone(),
        vmm_sha256: checkpoint.vmm.sha256.clone(),
        guest_checkpoint_abi: checkpoint.guest_checkpoint_abi,
        timings: Some(checkpoint.timings.proto()),
        unrestorable_reason,
        warnings,
        account: snapshot.account,
        source_generation: checkpoint.source_generation,
        snapshot: Some(described),
    })
}

/// Why a VM checkpoint the installed runtime cannot restore is so: it was
/// taken under boot assets whose guest speaks an earlier runtime ABI
/// (#4980). Those assets are kept while the checkpoint is, so the reason is
/// read from them; None when they declare the installed ABI or cannot be
/// read, which a restore's own admission then refuses with its reason.
pub(in crate::supervisor) fn earlier_runtime(
    engine_root: &Path,
    manifest: &Manifest,
) -> Option<String> {
    let generation = manifest.root_generation.artifact_generation().ok()?;
    let engine = PrivateRoot::open(engine_root).ok()?;
    let declared = match RuntimeArtifactStore::create(&engine)
        .ok()?
        .guest_runtime_abi(generation)
    {
        Ok(declared) => declared,
        Err(crate::artifact_store::RuntimeArtifactStoreError::Artifact(
            crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_),
        )) => "none declared".to_owned(),
        Err(_) => return None,
    };
    (declared != crate::artifact::current_guest_abi()).then(|| {
        format!(
            "it was taken under an earlier runtime (guest ABI {declared}), which this cw cannot restore"
        )
    })
}

/// How many of `environment_id`'s VM checkpoints the installed runtime
/// cannot restore because they were taken under an earlier runtime: what a
/// start that moved the environment reports.
pub(in crate::supervisor) fn unrestorable_after_move(
    config: &NativeRuntimeConfig,
    environment_id: Uuid,
) -> Result<u32, Status> {
    let engine_root = config.engine_root();
    let count = list_ready(config, true)?
        .iter()
        .filter(|(_, manifest)| manifest.source.environment_id == environment_id)
        .filter(|(_, manifest)| earlier_runtime(&engine_root, manifest).is_some())
        .count();
    u32::try_from(count).map_err(|_| Status::internal("too many VM checkpoints to count"))
}
