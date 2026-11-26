//! Image-baked read-only `cw-runtime` catalog for `standard` Pods (#5602).
//!
//! Building the `cw-runtime` ext4 disk on the sandbox's CSI PVC at every cold
//! create copies and hashes ~100 MiB and runs `mkfs.ext4` + `debugfs` +
//! multiple `fsync` calls on network-replicated storage (~5.5 s). Because the
//! catalog is 100% read-only and identical for every Pod of a `pod-runtime`
//! image, `images/pod-runtime/Dockerfile` pre-bakes it once under
//! `/opt/codewire/runtime/cw-runtimes/` with a small `baked-catalog.json`
//! bound to `cw-runtime.lock.json`. At Pod boot, `resolve_cw_runtime` verifies
//! that binding and opens the sealed `0400` catalog read-only from the node's
//! page cache, falling back to `engine_root` when no pre-baked catalog exists.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{PodPaths, PodRuntimeError};
use crate::cw_runtime::{CwRuntimeAssetLock, CwRuntimeError, CwRuntimeStore};
use crate::host::path::PrivateRoot;

const BAKED_MANIFEST_NAME: &str = "baked-catalog.json";
const MAX_LOCK_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BakedCatalogManifest {
    schema_version: u32,
    generation: String,
    image_index_sha256: String,
    pack_sha256: String,
}

/// Pre-bake the sealed `cw-runtime` ext4 catalog beside `paths.cw_runtime_lock`
/// during `images/pod-runtime/Dockerfile` build so cold Pod starts never copy
/// `runtime.pack` or run `mkfs.ext4`/`debugfs` on the sandbox's PVC.
pub fn prepare_baked_catalog(paths: &PodPaths) -> Result<String, PodRuntimeError> {
    let runtime_dir = paths
        .cw_runtime_lock
        .parent()
        .ok_or(CwRuntimeError::InvalidAsset)?;
    let lock = read_asset_lock(&paths.cw_runtime_lock)?;
    let runtime_root = PrivateRoot::open(runtime_dir)?;
    let store = CwRuntimeStore::create(&runtime_root)?;
    let asset = store.admit_source(&paths.cw_runtime_lock)?;
    let disk = store.prepare_catalog(&asset.provenance, &BTreeMap::new())?;
    let baked = BakedCatalogManifest {
        schema_version: 1,
        generation: disk.generation.clone(),
        image_index_sha256: lock.image_index_sha256,
        pack_sha256: lock.pack.sha256,
    };
    let bytes = serde_json::to_vec(&baked).map_err(|_| CwRuntimeError::InvalidManifest)?;
    let manifest_path = runtime_dir.join("cw-runtimes").join(BAKED_MANIFEST_NAME);
    write_readonly(&manifest_path, &bytes)?;
    // `runtime.pack` already lives beside `cw-runtime.lock.json`; drop the
    // duplicate copy ingested into `cw-runtimes/assets/` so the image layer
    // doesn't carry two copies of the ~50 MiB payload.
    let asset_copy = runtime_dir
        .join("cw-runtimes")
        .join("assets")
        .join(format!("{}.pack", asset.provenance.payload.sha256));
    if asset_copy.exists() {
        fs::remove_file(&asset_copy)?;
    }
    Ok(disk.generation)
}

/// Resolve the read-only `cw-runtime` store root and catalog generation for a
/// Pod boot. Uses the pre-baked catalog beside `lock` when present (failing
/// closed if its binding to `lock` does not match), otherwise installs into
/// `engine_root` as before.
pub(super) fn resolve_cw_runtime(
    engine_root: &Path,
    lock_path: &Path,
) -> Result<(PathBuf, String), PodRuntimeError> {
    if let Some(runtime_dir) = lock_path.parent() {
        let baked_path = runtime_dir.join("cw-runtimes").join(BAKED_MANIFEST_NAME);
        match fs::symlink_metadata(&baked_path) {
            Ok(_) => {
                let lock = read_asset_lock(lock_path)?;
                let baked = read_baked_manifest(&baked_path)?;
                if baked.schema_version != 1
                    || baked.image_index_sha256 != lock.image_index_sha256
                    || baked.pack_sha256 != lock.pack.sha256
                {
                    return Err(CwRuntimeError::InvalidManifest.into());
                }
                let runtime_root = PrivateRoot::open(runtime_dir)?;
                let store = CwRuntimeStore::create(&runtime_root)?;
                let admitted = store.open_catalog(&baked.generation)?;
                let active = admitted
                    .manifest
                    .catalog
                    .active()
                    .map_err(CwRuntimeError::InvalidCatalog)?;
                if active.image_index_sha256 != lock.image_index_sha256 {
                    return Err(CwRuntimeError::InvalidManifest.into());
                }
                return Ok((runtime_dir.to_owned(), admitted.generation));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let store = CwRuntimeStore::create(&PrivateRoot::open(engine_root)?)?;
    let asset = store.admit_source(lock_path)?;
    let generation = store
        .prepare_catalog(&asset.provenance, &BTreeMap::new())?
        .generation;
    Ok((engine_root.to_owned(), generation))
}

fn read_asset_lock(path: &Path) -> Result<CwRuntimeAssetLock, PodRuntimeError> {
    let bytes = read_private_file(path, MAX_LOCK_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| CwRuntimeError::InvalidAsset.into())
}

fn read_baked_manifest(path: &Path) -> Result<BakedCatalogManifest, PodRuntimeError> {
    let bytes = read_private_file(path, MAX_LOCK_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| CwRuntimeError::InvalidManifest.into())
}

fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PodRuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(CwRuntimeError::InvalidManifest.into());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(CwRuntimeError::InvalidManifest.into());
    }
    Ok(bytes)
}

fn write_readonly(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::cw_runtime::CwRuntimeFileSpec;
    use codewire_vmm_guest_probe::cw_runtime::{
        CW_RUNTIME_ELF_MACHINE, CW_RUNTIME_TARGET, CwImageDescriptor, CwImagePayload,
        CwRuntimeProvenance,
    };

    fn sha_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn fixture_runtime_dir(root: &Path) -> PodPaths {
        fs::create_dir_all(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
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
        let pack_path = root.join("runtime.pack");
        fs::write(&pack_path, &pack).unwrap();
        fs::set_permissions(&pack_path, fs::Permissions::from_mode(0o400)).unwrap();
        let lock_path = root.join("cw-runtime.lock.json");
        fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o400)).unwrap();
        PodPaths {
            cw_runtime_lock: lock_path,
            ..PodPaths::default()
        }
    }

    #[test]
    fn baked_catalog_resolves_read_only_without_touching_engine_root() {
        let scratch = tempfile::tempdir().unwrap();
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_dir = scratch.path().join("runtime");
        let engine_root = scratch.path().join("state-runtime");
        fs::create_dir(&engine_root).unwrap();
        fs::set_permissions(&engine_root, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = fixture_runtime_dir(&runtime_dir);

        let baked_gen = prepare_baked_catalog(&paths).unwrap();
        assert_eq!(
            fs::read_dir(runtime_dir.join("cw-runtimes/assets"))
                .unwrap()
                .count(),
            0,
            "duplicate pack copy should be removed after baking"
        );

        let (resolved_root, resolved_gen) =
            resolve_cw_runtime(&engine_root, &paths.cw_runtime_lock).unwrap();
        assert_eq!(resolved_root, runtime_dir);
        assert_eq!(resolved_gen, baked_gen);
        assert!(
            !engine_root.join("cw-runtimes").exists(),
            "engine_root on the PVC must remain untouched when a baked catalog exists"
        );
    }

    #[test]
    fn baked_catalog_fails_closed_when_lock_binding_differs() {
        let scratch = tempfile::tempdir().unwrap();
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_dir = scratch.path().join("runtime");
        let engine_root = scratch.path().join("state-runtime");
        fs::create_dir(&engine_root).unwrap();
        fs::set_permissions(&engine_root, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = fixture_runtime_dir(&runtime_dir);

        prepare_baked_catalog(&paths).unwrap();

        let mut lock = read_asset_lock(&paths.cw_runtime_lock).unwrap();
        lock.pack.sha256 = "f".repeat(64);
        fs::set_permissions(&paths.cw_runtime_lock, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&paths.cw_runtime_lock, serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::set_permissions(&paths.cw_runtime_lock, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(matches!(
            resolve_cw_runtime(&engine_root, &paths.cw_runtime_lock),
            Err(PodRuntimeError::CwRuntime(CwRuntimeError::InvalidManifest))
        ));
    }

    #[test]
    fn missing_baked_catalog_falls_back_to_engine_root() {
        let scratch = tempfile::tempdir().unwrap();
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime_dir = scratch.path().join("runtime");
        let engine_root = scratch.path().join("state-runtime");
        fs::create_dir(&engine_root).unwrap();
        fs::set_permissions(&engine_root, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = fixture_runtime_dir(&runtime_dir);

        let (resolved_root, _gen) =
            resolve_cw_runtime(&engine_root, &paths.cw_runtime_lock).unwrap();
        assert_eq!(resolved_root, engine_root);
        assert!(engine_root.join("cw-runtimes/catalogs").exists());
    }
}
