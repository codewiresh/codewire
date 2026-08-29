//! Read-only inventory for local runtime objects that cannot be proven live.
//!
//! Inventory never adopts, repairs, moves, or removes an object. Byte counts
//! are conservative allocated-byte estimates and become zero when traversal
//! cannot be completed safely within the fixed entry bound.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::artifact_store::runtime_artifact_diagnostics;
use crate::linux::path::{PrivateRoot, SocketIdentity, current_uid};
use crate::linux::state::{StateDiskIdentity, validate_owned_vm_tree};

const MAX_ACCOUNTING_ENTRIES: usize = 10_000;
const MAX_CONTENT_OBJECTS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanEntry {
    pub(crate) kind: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) reason: &'static str,
    pub(crate) reclaimable_bytes: u64,
}

pub(crate) fn inventory(
    runtime_root: &PrivateRoot,
    environments: &BTreeMap<Uuid, u64>,
    runners: &BTreeMap<String, SocketIdentity>,
    deletion_trash_names: &BTreeSet<String>,
    content_blobs: &BTreeMap<String, u64>,
    artifact_generations: &BTreeSet<String>,
) -> Vec<OrphanEntry> {
    let mut orphans = Vec::new();
    inventory_vms(runtime_root, environments, &mut orphans);
    inventory_trash(runtime_root, deletion_trash_names, &mut orphans);
    inventory_runners(runtime_root, runners, &mut orphans);
    inventory_content(runtime_root, content_blobs, &mut orphans);
    inventory_runtime_artifacts(runtime_root, artifact_generations, &mut orphans);
    orphans.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(right.kind))
    });
    orphans
}

fn inventory_runtime_artifacts(
    runtime_root: &PrivateRoot,
    retained: &BTreeSet<String>,
    orphans: &mut Vec<OrphanEntry>,
) {
    orphans.extend(
        runtime_artifact_diagnostics(&runtime_root.path().join("engine"), retained)
            .into_iter()
            .map(|diagnostic| OrphanEntry {
                reclaimable_bytes: if diagnostic.reclaimable {
                    allocated_bytes(&diagnostic.path).unwrap_or(0)
                } else {
                    0
                },
                kind: diagnostic.kind,
                path: diagnostic.path,
                reason: diagnostic.reason,
            }),
    );
}

fn inventory_content(
    runtime_root: &PrivateRoot,
    retained: &BTreeMap<String, u64>,
    orphans: &mut Vec<OrphanEntry>,
) {
    let content = runtime_root.path().join("engine/content");
    let blobs = content.join("blobs");
    let Ok(content_metadata) = fs::symlink_metadata(&content) else {
        return;
    };
    if !private_directory(&content_metadata) {
        push(
            orphan("oci_content", content, "unsafe_content_directory"),
            orphans,
        );
        return;
    }
    let Ok(entries) = fs::read_dir(&content) else {
        push(
            orphan("oci_content", content, "unreadable_content_directory"),
            orphans,
        );
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() != "blobs" {
            push(
                orphan("oci_content", entry.path(), "unexpected_content_object"),
                orphans,
            );
        }
    }
    let Ok(blobs_metadata) = fs::symlink_metadata(&blobs) else {
        return;
    };
    if !private_directory(&blobs_metadata) {
        push(
            orphan("oci_content", blobs, "unsafe_blob_directory"),
            orphans,
        );
        return;
    }
    let Ok(entries) = fs::read_dir(&blobs) else {
        push(
            orphan("oci_content", blobs, "unreadable_blob_directory"),
            orphans,
        );
        return;
    };
    for (index, entry) in entries.flatten().enumerate() {
        if index == MAX_CONTENT_OBJECTS {
            push(
                OrphanEntry {
                    kind: "oci_content",
                    path: blobs.clone(),
                    reason: "content_object_bound_exceeded",
                    reclaimable_bytes: 0,
                },
                orphans,
            );
            break;
        }
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            push(
                orphan("oci_content", path, "unknown_content_object"),
                orphans,
            );
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if valid_blob_name(&name) {
            let safe = private_regular(&metadata, 0o400);
            match retained.get(&name) {
                Some(size) if safe && metadata.len() == *size => {}
                Some(_) => push(
                    orphan("oci_blob", path, "unsafe_referenced_content_blob"),
                    orphans,
                ),
                None if safe => push(
                    orphan("oci_blob", path, "unreferenced_content_blob"),
                    orphans,
                ),
                None => push(
                    orphan("oci_blob", path, "unsafe_unreferenced_content_blob"),
                    orphans,
                ),
            }
        } else if valid_ingest_name(&name) {
            let safe = private_regular(&metadata, 0o600) || private_regular(&metadata, 0o400);
            push(
                orphan(
                    "oci_ingest",
                    path,
                    if safe {
                        "interrupted_content_ingest"
                    } else {
                        "unsafe_content_ingest"
                    },
                ),
                orphans,
            );
        } else {
            push(
                orphan("oci_content", path, "unknown_content_object"),
                orphans,
            );
        }
    }
}

fn private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && metadata.uid() == current_uid() && metadata.mode() & 0o777 == 0o700
}

fn private_regular(metadata: &fs::Metadata, permissions: u32) -> bool {
    metadata.is_file()
        && metadata.uid() == current_uid()
        && metadata.nlink() == 1
        && metadata.mode() & 0o777 == permissions
}

fn valid_blob_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_ingest_name(name: &str) -> bool {
    name.strip_prefix(".ingest-")
        .and_then(|value| Uuid::parse_str(value).ok().map(|uuid| (value, uuid)))
        .is_some_and(|(value, uuid)| value == uuid.to_string())
}

fn inventory_vms(
    runtime_root: &PrivateRoot,
    environments: &BTreeMap<Uuid, u64>,
    orphans: &mut Vec<OrphanEntry>,
) {
    let path = runtime_root.path().join("engine/vms");
    let mut found = BTreeSet::new();
    let Ok(entries) = fs::read_dir(&path) else {
        for id in environments.keys() {
            push(orphaned_missing_vm(&path, *id), orphans);
        }
        return;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let id = entry
            .file_name()
            .to_str()
            .and_then(|name| Uuid::parse_str(name).ok());
        let Some(id) = id else {
            push(
                orphan("vm_tree", entry_path, "untracked_environment_tree"),
                orphans,
            );
            continue;
        };
        let Some(expected_bytes) = environments.get(&id) else {
            push(
                orphan("vm_tree", entry_path, "untracked_environment_tree"),
                orphans,
            );
            continue;
        };
        found.insert(id);
        let vm = match PrivateRoot::open(&entry_path) {
            Ok(vm) => vm,
            Err(_) => {
                push(
                    orphan("vm_tree", entry_path, "unsafe_environment_tree"),
                    orphans,
                );
                continue;
            }
        };
        if validate_owned_vm_tree(&vm).is_err() {
            push(
                orphan("vm_tree", entry_path, "unexpected_environment_object"),
                orphans,
            );
            continue;
        }
        let disk = entry_path.join("disks/state.raw");
        match StateDiskIdentity::capture(&disk) {
            Ok(identity) if identity.file.size == *expected_bytes => {}
            Ok(_) => push(
                orphan("state_disk", disk, "state_disk_size_mismatch"),
                orphans,
            ),
            Err(_) => push(
                orphan("state_disk", disk, "missing_or_unsafe_state_disk"),
                orphans,
            ),
        }
    }
    for id in environments.keys().filter(|id| !found.contains(id)) {
        push(orphaned_missing_vm(&path, *id), orphans);
    }
}

fn orphaned_missing_vm(vms: &Path, id: Uuid) -> OrphanEntry {
    OrphanEntry {
        kind: "vm_tree",
        path: vms.join(id.to_string()),
        reason: "recorded_environment_tree_missing",
        reclaimable_bytes: 0,
    }
}

fn inventory_trash(
    runtime_root: &PrivateRoot,
    known: &BTreeSet<String>,
    orphans: &mut Vec<OrphanEntry>,
) {
    let path = runtime_root.path().join("engine/trash");
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let reason = if name.to_str().is_some_and(|name| known.contains(name)) {
            "delete_cleanup_pending"
        } else {
            "untracked_trash_object"
        };
        push(orphan("trash", entry.path(), reason), orphans);
    }
}

fn inventory_runners(
    runtime_root: &PrivateRoot,
    runners: &BTreeMap<String, SocketIdentity>,
    orphans: &mut Vec<OrphanEntry>,
) {
    let path = runtime_root.path().join("runners");
    let mut found = BTreeSet::new();
    let Ok(entries) = fs::read_dir(&path) else {
        for name in runners.keys() {
            push(
                OrphanEntry {
                    kind: "runner_socket",
                    path: path.join(name),
                    reason: "recorded_runner_socket_missing",
                    reclaimable_bytes: 0,
                },
                orphans,
            );
        }
        return;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            push(
                orphan("runner_socket", entry_path, "untracked_runner_object"),
                orphans,
            );
            continue;
        };
        let Some(identity) = runners.get(&name) else {
            push(
                orphan("runner_socket", entry_path, "untracked_runner_object"),
                orphans,
            );
            continue;
        };
        found.insert(name);
        if identity.revalidate(&entry_path).is_err() {
            push(
                orphan("runner_socket", entry_path, "runner_socket_mismatch"),
                orphans,
            );
        }
    }
    for name in runners.keys().filter(|name| !found.contains(*name)) {
        push(
            OrphanEntry {
                kind: "runner_socket",
                path: path.join(name),
                reason: "recorded_runner_socket_missing",
                reclaimable_bytes: 0,
            },
            orphans,
        );
    }
}

fn orphan(kind: &'static str, path: PathBuf, reason: &'static str) -> OrphanEntry {
    let reclaimable_bytes = allocated_bytes(&path).unwrap_or(0);
    OrphanEntry {
        kind,
        path,
        reason,
        reclaimable_bytes,
    }
}

fn push(orphan: OrphanEntry, orphans: &mut Vec<OrphanEntry>) {
    orphans.push(orphan);
}

fn allocated_bytes(path: &Path) -> io::Result<u64> {
    let root = fs::symlink_metadata(path)?;
    let device = root.dev();
    let mut remaining = MAX_ACCOUNTING_ENTRIES;
    allocated_bytes_bounded(path, device, &mut remaining)
}

fn allocated_bytes_bounded(path: &Path, device: u64, remaining: &mut usize) -> io::Result<u64> {
    if *remaining == 0 {
        return Err(io::Error::other("orphan accounting entry bound exceeded"));
    }
    *remaining -= 1;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.dev() != device || metadata.uid() != current_uid() {
        return Ok(0);
    }
    let mut bytes = metadata.blocks().saturating_mul(512);
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            bytes =
                bytes.saturating_add(allocated_bytes_bounded(&entry?.path(), device, remaining)?);
        }
    } else if metadata.nlink() != 1 {
        return Ok(0);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt as _;

    fn runtime_root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for path in ["engine", "engine/vms", "engine/trash", "runners"] {
            fs::create_dir(root.join(path)).unwrap();
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = PrivateRoot::open(&root).unwrap();
        (parent, root)
    }

    #[test]
    fn inventory_reports_untracked_and_missing_objects_without_mutation() {
        let (_parent, root) = runtime_root();
        let expected_id = Uuid::new_v4();
        let unknown_id = Uuid::new_v4();
        let unknown = root.path().join("engine/vms").join(unknown_id.to_string());
        fs::create_dir(&unknown).unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(unknown.join("data"), b"orphan").unwrap();
        let trash_name = format!("delete-{}-{}", Uuid::new_v4(), Uuid::new_v4());
        let trash = root.path().join("engine/trash").join(&trash_name);
        fs::create_dir(&trash).unwrap();
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();

        let entries = inventory(
            &root,
            &BTreeMap::from([(expected_id, 1024)]),
            &BTreeMap::new(),
            &BTreeSet::from([trash_name]),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(entries.iter().any(|entry| {
            entry.path == unknown && entry.reason == "untracked_environment_tree"
        }));
        assert!(entries.iter().any(|entry| {
            entry.path.ends_with(expected_id.to_string())
                && entry.reason == "recorded_environment_tree_missing"
        }));
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == trash && entry.reason == "delete_cleanup_pending")
        );
        assert!(unknown.join("data").exists());
        assert!(trash.exists());
        assert!(!root.path().join("engine/runtime-artifacts").exists());
    }

    #[test]
    fn inventory_reports_only_unreferenced_or_unsafe_content_objects() {
        let (_parent, root) = runtime_root();
        let content = root.path().join("engine/content");
        let blobs = content.join("blobs");
        for path in [&content, &blobs] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let retained = "a".repeat(64);
        let stale = "b".repeat(64);
        let unsafe_retained = "c".repeat(64);
        let wrong_size = "d".repeat(64);
        for (name, mode) in [
            (&retained, 0o400),
            (&stale, 0o400),
            (&unsafe_retained, 0o600),
            (&wrong_size, 0o400),
        ] {
            fs::write(blobs.join(name), b"content").unwrap();
            fs::set_permissions(blobs.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        let ingest = format!(".ingest-{}", Uuid::new_v4());
        fs::write(blobs.join(&ingest), b"partial").unwrap();
        fs::set_permissions(blobs.join(&ingest), fs::Permissions::from_mode(0o600)).unwrap();
        let unknown = blobs.join("unknown");
        fs::write(&unknown, b"unknown").unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o400)).unwrap();

        let entries = inventory(
            &root,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeMap::from([
                (retained.clone(), b"content".len() as u64),
                (unsafe_retained.clone(), b"content".len() as u64),
                (wrong_size.clone(), b"content".len() as u64 + 1),
            ]),
            &BTreeSet::new(),
        );

        assert!(
            !entries
                .iter()
                .any(|entry| entry.path == blobs.join(&retained))
        );
        assert!(entries.iter().any(|entry| {
            entry.path == blobs.join(&stale) && entry.reason == "unreferenced_content_blob"
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == blobs.join(&unsafe_retained)
                && entry.reason == "unsafe_referenced_content_blob"
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == blobs.join(&wrong_size)
                && entry.reason == "unsafe_referenced_content_blob"
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == blobs.join(&ingest) && entry.reason == "interrupted_content_ingest"
        }));
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == unknown && entry.reason == "unknown_content_object")
        );
    }

    #[test]
    fn inventory_reports_runtime_artifacts_without_overstating_reclaimability() {
        let (_parent, root) = runtime_root();
        let store = root.path().join("engine/runtime-artifacts");
        let blobs = store.join("blobs");
        let generations = store.join("generations");
        for path in [&store, &blobs, &generations] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let blob_bytes = b"possibly-live-runtime-blob";
        let blob_name = format!("r-{:x}", Sha256::digest(blob_bytes));
        let blob = blobs.join(&blob_name);
        fs::write(&blob, blob_bytes).unwrap();
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o400)).unwrap();
        let ingest_name = format!(".ingest-r-{}", Uuid::new_v4());
        let ingest = blobs.join(&ingest_name);
        fs::write(&ingest, b"partial").unwrap();
        fs::set_permissions(&ingest, fs::Permissions::from_mode(0o400)).unwrap();
        let missing = "f".repeat(64);

        let entries = inventory(
            &root,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::from([missing.clone()]),
        );

        assert!(entries.iter().any(|entry| {
            entry.path == generations.join(format!("{missing}.json"))
                && entry.reason == "recorded_runtime_artifact_generation_missing"
                && entry.reclaimable_bytes == 0
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == blob
                && entry.reason == "runtime_artifact_blob_reachability_unknown"
                && entry.reclaimable_bytes == 0
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == ingest
                && entry.reason == "interrupted_runtime_artifact_ingest"
                && entry.reclaimable_bytes > 0
        }));
        assert_eq!(fs::read(blob).unwrap(), blob_bytes);
        assert_eq!(fs::read(ingest).unwrap(), b"partial");
    }
}
