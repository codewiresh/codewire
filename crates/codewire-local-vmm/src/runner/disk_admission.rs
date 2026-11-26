//! Persisted disk admission and revalidation for [`super::CloudHypervisorRunner`].
//!
//! Local VMs live on one host filesystem whose device number (`st_dev`) never
//! changes across boots, so local revalidation keeps full [`FileIdentity`]
//! equality. Hosted `standard` Pods mount a CSI `PersistentVolumeClaim` whose
//! kernel device number (`st_dev`) changes legitimately across node moves,
//! DRBD minor reassignments, and `VolumeSnapshot` restores (#5602); hosted
//! revalidation therefore checks every on-volume attribute (`inode`, `size`,
//! `uid`, `mode`, `links`) plus the disk's cryptographic SHA-256 or ext4
//! superblock UUID, and returns the freshly captured identity so same-Pod
//! checks still enforce full `st_dev` + `InodePin` equality.

use std::path::{Path, PathBuf};

use super::{CreateVmRequest, RunnerError, root_disk_path};
use crate::cw_runtime::{AdmittedCwRuntimeDisk, CwRuntimeError, CwRuntimeStore};
use crate::host::path::PrivateRoot;
use crate::state::{PersistedVmState, StateDiskIdentity, StateError, VmPaths};

pub(super) fn revalidate_persisted_cw_runtime_disk(
    state_root: &PrivateRoot,
    persisted: Option<&PersistedVmState>,
    request: &CreateVmRequest,
    next_catalog: Option<&AdmittedCwRuntimeDisk>,
    hosted: bool,
) -> Result<(), RunnerError> {
    let Some(disk) = persisted.and_then(|state| state.cw_runtime_disk.as_ref()) else {
        return Ok(());
    };
    if hosted && request.checkpoint.is_none() && next_catalog.is_some() {
        // Hosted non-checkpoint boots attach the newly verified read-only
        // catalog from the signed `pod-runtime` image; the prior Pod's
        // catalog may have lived in an older container image or pre-baked
        // rollout and is never attached to this boot (#5602).
        disk.validate_metadata()?;
        return Ok(());
    }
    revalidate_persisted_cw_runtime_attachment(state_root, disk, hosted)
}

fn revalidate_persisted_cw_runtime_attachment(
    state_root: &PrivateRoot,
    disk: &AdmittedCwRuntimeDisk,
    hosted: bool,
) -> Result<(), RunnerError> {
    let store = CwRuntimeStore::create(state_root)?;
    if !hosted {
        store.revalidate_attachment(disk)?;
        return Ok(());
    }
    disk.validate_metadata()?;
    let admitted = store.open_catalog(&disk.generation)?;
    if admitted.path != disk.path {
        return Err(CwRuntimeError::InvalidManifest.into());
    }
    if admitted.generation != disk.generation
        || admitted.manifest != disk.manifest
        || !admitted.identity.same_file_across_mount(&disk.identity)
    {
        return Err(CwRuntimeError::DiskChanged.into());
    }
    Ok(())
}

pub(super) fn admit_state_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
    persisted: Option<&PersistedVmState>,
    hosted: bool,
) -> Result<StateDiskIdentity, RunnerError> {
    if !paths.state_disk.exists() {
        return Err(RunnerError::MissingPreformattedStateDisk);
    }
    let state_disk = if let Some(state) = persisted {
        if request.generation <= state.generation {
            return Err(RunnerError::GenerationNotAdvanced {
                previous: state.generation,
                requested: request.generation,
            });
        }
        revalidate_state_disk(&state.state_disk, &paths.state_disk, hosted)?
    } else {
        StateDiskIdentity::capture(&paths.state_disk)?
    };
    if state_disk.file.size != request.state_disk_bytes {
        return Err(RunnerError::StateDiskSizeMismatch {
            current: state_disk.file.size,
            requested: request.state_disk_bytes,
        });
    }
    Ok(state_disk)
}

pub(super) fn admit_docker_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
    persisted: Option<&PersistedVmState>,
    hosted: bool,
) -> Result<Option<StateDiskIdentity>, RunnerError> {
    let Some(requested_bytes) = request.docker_disk_bytes else {
        if persisted
            .and_then(|state| state.docker_disk.as_ref())
            .is_some()
            || paths.docker_disk.exists()
        {
            return Err(RunnerError::UnexpectedDockerDisk);
        }
        return Ok(None);
    };
    if !paths.docker_disk.exists() {
        return Err(RunnerError::MissingPreformattedDockerDisk);
    }
    let identity = match persisted.and_then(|state| state.docker_disk.as_ref()) {
        Some(expected) => revalidate_state_disk(expected, &paths.docker_disk, hosted)?,
        None => StateDiskIdentity::capture(&paths.docker_disk)?,
    };
    if identity.file.size != requested_bytes {
        return Err(RunnerError::DockerDiskSizeMismatch {
            current: identity.file.size,
            requested: requested_bytes,
        });
    }
    Ok(Some(identity))
}

pub(super) fn admit_root_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
    persisted: Option<&PersistedVmState>,
    hosted: bool,
) -> Result<(PathBuf, StateDiskIdentity), RunnerError> {
    let path = root_disk_path(paths, &request.root_generation)?;
    if !path.exists() {
        return Err(RunnerError::MissingPreformattedRootDisk);
    }
    let root_disk = match persisted {
        Some(state) if state.root_generation.as_deref() == Some(&request.root_generation) => {
            let expected = state
                .root_disk
                .as_ref()
                .ok_or(RunnerError::PersistedRootGenerationMismatch)?;
            revalidate_state_disk(expected, &path, hosted)?
        }
        _ => StateDiskIdentity::capture(&path)?,
    };
    if root_disk.file.size != request.root_disk_bytes {
        return Err(RunnerError::RootDiskSizeMismatch {
            current: root_disk.file.size,
            requested: request.root_disk_bytes,
        });
    }
    Ok((path, root_disk))
}

fn revalidate_state_disk(
    expected: &StateDiskIdentity,
    path: &Path,
    hosted: bool,
) -> Result<StateDiskIdentity, StateError> {
    if !hosted {
        expected.revalidate(path)?;
        return Ok(expected.clone());
    }
    let current = StateDiskIdentity::capture(path)?;
    if current.filesystem_uuid != expected.filesystem_uuid
        || !current.file.same_file_across_mount(&expected.file)
    {
        return Err(StateError::StateDiskIdentityChanged(path.to_owned()));
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::cw_runtime::{CwRuntimeAssetLock, CwRuntimeFileSpec};
    use crate::host::process::ProcessIdentity;
    use crate::state::{
        MINIMUM_DOCKER_DISK_BYTES, MINIMUM_ROOT_DISK_BYTES, MINIMUM_STATE_DISK_BYTES,
        PERSISTED_STATE_SCHEMA_VERSION, RootGenerationPaths, VmPhase,
    };
    use codewire_vmm_guest_probe::cw_runtime::{
        CW_RUNTIME_ELF_MACHINE, CW_RUNTIME_TARGET, CwImageDescriptor, CwImagePayload,
        CwRuntimeProvenance,
    };

    fn write_test_ext4(path: &Path, uuid: Uuid, bytes: u64) {
        let mut file = fs::File::create(path).unwrap();
        file.set_len(bytes).unwrap();
        let mut superblock = [0_u8; 1024];
        superblock[0x38..0x3a].copy_from_slice(&0xEF53_u16.to_le_bytes());
        superblock[0x68..0x78].copy_from_slice(uuid.as_bytes());
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(1024)).unwrap();
        file.write_all(&superblock).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn sha_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn fixture_cw_runtime_lock(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut cw = vec![0_u8; 136];
        cw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        cw[16..18].copy_from_slice(&2_u16.to_le_bytes());
        cw[18..20].copy_from_slice(&CW_RUNTIME_ELF_MACHINE.to_le_bytes());
        cw[32..40].copy_from_slice(&64_u64.to_le_bytes());
        cw[54..56].copy_from_slice(&56_u16.to_le_bytes());
        cw[56..58].copy_from_slice(&1_u16.to_le_bytes());
        cw[64..68].copy_from_slice(&1_u32.to_le_bytes());
        let descriptor = CwImageDescriptor {
            sha256: "a".repeat(64),
            size: 10_240,
        };
        let provenance = CwRuntimeProvenance {
            schema_version: 1,
            image_index_sha256: "b".repeat(64),
            image_manifest: descriptor.clone(),
            image_config: descriptor.clone(),
            image_layer: descriptor,
            layer_diff_id: "a".repeat(64),
            payload: CwImagePayload {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: "0.1.0".into(),
                target: CW_RUNTIME_TARGET.into(),
                source_revision: format!("{:040x}", 1_u8),
                source_tree_sha256: "c".repeat(64),
                rustc: "rustc 1.93.0 (synthetic fixture)".into(),
                sha256: sha_hex(&cw),
                size: cw.len() as u64,
            },
        };
        let provenance = serde_json::to_vec(&provenance).unwrap();
        let mut pack = b"CWRPACK1".to_vec();
        pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
        pack.extend_from_slice(&(cw.len() as u64).to_le_bytes());
        pack.extend_from_slice(&provenance);
        pack.extend_from_slice(&cw);
        let lock = CwRuntimeAssetLock {
            schema_version: 1,
            image_index_sha256: "b".repeat(64),
            pack: CwRuntimeFileSpec {
                path: "runtime.pack".into(),
                size: pack.len() as u64,
                sha256: sha_hex(&pack),
            },
        };
        let pack_path = dir.join("runtime.pack");
        fs::write(&pack_path, &pack).unwrap();
        fs::set_permissions(&pack_path, fs::Permissions::from_mode(0o400)).unwrap();
        let lock_path = dir.join("cw-runtime.lock.json");
        fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o400)).unwrap();
        lock_path
    }

    fn test_request(
        vm_id: Uuid,
        root_generation: String,
        docker_bytes: Option<u64>,
    ) -> CreateVmRequest {
        let mut request = super::super::tests::request(2, 16_384);
        request.vm_id = vm_id;
        request.generation = 2;
        request.root_generation = root_generation;
        request.docker_disk_bytes = docker_bytes;
        request
    }

    #[test]
    fn hosted_revalidation_accepts_csi_remount_device_change_and_rejects_replacement() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&temp.path().join("engine")).unwrap();

        let store = CwRuntimeStore::create(&engine).unwrap();
        let lock_path = fixture_cw_runtime_lock(&temp.path().join("source"));
        let source = store.admit_source(&lock_path).unwrap().provenance;
        let current_catalog = store.prepare_catalog(&source, &BTreeMap::new()).unwrap();

        let mut remounted_catalog = current_catalog.clone();
        remounted_catalog.identity.device = remounted_catalog.identity.device.wrapping_add(1);

        // Local VMs still reject st_dev drift; hosted standard Pods accept it.
        assert!(matches!(
            revalidate_persisted_cw_runtime_attachment(&engine, &remounted_catalog, false),
            Err(RunnerError::CwRuntime(CwRuntimeError::DiskChanged))
        ));
        revalidate_persisted_cw_runtime_attachment(&engine, &remounted_catalog, true).unwrap();

        // Any on-volume attribute change or hash drift still fails closed in hosted mode.
        let mut wrong_inode = remounted_catalog.clone();
        wrong_inode.identity.inode = wrong_inode.identity.inode.wrapping_add(1);
        assert!(matches!(
            revalidate_persisted_cw_runtime_attachment(&engine, &wrong_inode, true),
            Err(RunnerError::CwRuntime(CwRuntimeError::DiskChanged))
        ));

        let mut wrong_sha = remounted_catalog;
        wrong_sha.manifest.disk.sha256 = "f".repeat(64);
        assert!(matches!(
            revalidate_persisted_cw_runtime_attachment(&engine, &wrong_sha, true),
            Err(RunnerError::CwRuntime(CwRuntimeError::DiskChanged))
        ));
    }

    #[test]
    fn hosted_non_checkpoint_boot_accepts_retired_prior_catalog_when_replacing_with_baked_catalog()
    {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&temp.path().join("engine")).unwrap();
        let old_image = PrivateRoot::create(&temp.path().join("old-image")).unwrap();
        let new_image = PrivateRoot::create(&temp.path().join("new-image")).unwrap();

        let lock_path = fixture_cw_runtime_lock(&temp.path().join("source"));
        let old_store = CwRuntimeStore::create(&old_image).unwrap();
        let old_source = old_store.admit_source(&lock_path).unwrap().provenance;
        let prior_catalog = old_store
            .prepare_catalog(&old_source, &BTreeMap::new())
            .unwrap();
        let new_store = CwRuntimeStore::create(&new_image).unwrap();
        let new_source = new_store.admit_source(&lock_path).unwrap().provenance;
        let next_catalog = new_store
            .prepare_catalog(&new_source, &BTreeMap::new())
            .unwrap();

        // Remove the old container image's catalog directory, as happens on pod-runtime upgrade.
        fs::remove_dir_all(old_image.path()).unwrap();

        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine, vm_id).unwrap();
        write_test_ext4(&paths.state_disk, Uuid::new_v4(), MINIMUM_STATE_DISK_BYTES);
        let persisted = PersistedVmState {
            intercept: false,
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Running,
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            state_disk: StateDiskIdentity::capture(&paths.state_disk).unwrap(),
            docker_disk: None,
            root_generation: None,
            root_disk: None,
            cw_runtime_disk: Some(prior_catalog),
            api_socket: None,
            vsock_socket: None,
        };
        let request = test_request(vm_id, "a".repeat(64), None);

        // Hosted non-checkpoint boot with a verified next_catalog succeeds across image upgrade.
        revalidate_persisted_cw_runtime_disk(
            &engine,
            Some(&persisted),
            &request,
            Some(&next_catalog),
            true,
        )
        .unwrap();

        // Local VMs still require the retained prior catalog to exist in state_root.
        assert!(
            revalidate_persisted_cw_runtime_disk(
                &engine,
                Some(&persisted),
                &request,
                Some(&next_catalog),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn hosted_disk_admission_accepts_csi_remount_device_change_and_refreshes_device() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&temp.path().join("engine")).unwrap();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine, vm_id).unwrap();
        let root_generation = "a".repeat(64);
        let root_paths = RootGenerationPaths::create(&paths, &root_generation).unwrap();

        write_test_ext4(&paths.state_disk, Uuid::new_v4(), MINIMUM_STATE_DISK_BYTES);
        write_test_ext4(
            &paths.docker_disk,
            Uuid::new_v4(),
            MINIMUM_DOCKER_DISK_BYTES,
        );
        write_test_ext4(
            &root_paths.root_disk,
            Uuid::new_v4(),
            MINIMUM_ROOT_DISK_BYTES,
        );

        let actual_state = StateDiskIdentity::capture(&paths.state_disk).unwrap();
        let actual_docker = StateDiskIdentity::capture(&paths.docker_disk).unwrap();
        let actual_root = StateDiskIdentity::capture(&root_paths.root_disk).unwrap();

        let mut old_state = actual_state.clone();
        old_state.file.device = old_state.file.device.wrapping_add(1);
        let mut old_docker = actual_docker.clone();
        old_docker.file.device = old_docker.file.device.wrapping_add(1);
        let mut old_root = actual_root.clone();
        old_root.file.device = old_root.file.device.wrapping_add(1);

        let persisted = PersistedVmState {
            intercept: false,
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Running,
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            state_disk: old_state,
            docker_disk: Some(old_docker),
            root_generation: Some(root_generation.clone()),
            root_disk: Some(old_root),
            cw_runtime_disk: None,
            api_socket: None,
            vsock_socket: None,
        };

        let request = test_request(vm_id, root_generation, Some(MINIMUM_DOCKER_DISK_BYTES));

        // Local VMs still reject st_dev change on every persisted disk.
        assert!(matches!(
            admit_state_disk(&paths, &request, Some(&persisted), false),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(_)))
        ));
        assert!(matches!(
            admit_docker_disk(&paths, &request, Some(&persisted), false),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(_)))
        ));
        assert!(matches!(
            admit_root_disk(&paths, &request, Some(&persisted), false),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(_)))
        ));

        // Hosted standard Pods accept st_dev change and return the refreshed identity
        // so start()'s strict revalidate() succeeds on the new mount.
        let admitted_state = admit_state_disk(&paths, &request, Some(&persisted), true).unwrap();
        let admitted_docker = admit_docker_disk(&paths, &request, Some(&persisted), true)
            .unwrap()
            .unwrap();
        let (_, admitted_root) = admit_root_disk(&paths, &request, Some(&persisted), true).unwrap();

        assert_eq!(admitted_state, actual_state);
        assert_eq!(admitted_docker, actual_docker);
        assert_eq!(admitted_root, actual_root);
        admitted_state.revalidate(&paths.state_disk).unwrap();
        admitted_docker.revalidate(&paths.docker_disk).unwrap();
        admitted_root.revalidate(&root_paths.root_disk).unwrap();

        // Changing inode or filesystem UUID still fails closed in hosted mode.
        let mut wrong_uuid = persisted.clone();
        wrong_uuid.state_disk.filesystem_uuid = Uuid::new_v4();
        assert!(matches!(
            admit_state_disk(&paths, &request, Some(&wrong_uuid), true),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(_)))
        ));

        let mut wrong_inode = persisted;
        wrong_inode.state_disk.file.inode = wrong_inode.state_disk.file.inode.wrapping_add(1);
        assert!(matches!(
            admit_state_disk(&paths, &request, Some(&wrong_inode), true),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(_)))
        ));
    }
}
