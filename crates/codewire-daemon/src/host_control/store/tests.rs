use super::*;
use crate::host_control::tests::{config, grant, launch, scope};
use std::os::unix::fs::{PermissionsExt, symlink};

fn admitted(root: &Path) -> Store {
    let config = config(root);
    let mut store = Store::open(&config.host.unwrap().state_root, &scope().environment_id).unwrap();
    store.put_grant(grant(&scope(), 0)).unwrap();
    store
}

#[test]
fn host_control_store_recovery_never_upgrades_pending_or_issued_to_permission_to_replay() {
    for issued in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = admitted(temp.path());
        let request = launch(3, &scope(), "printf must-not-execute");
        store.register(&request).unwrap();
        if issued {
            store.issue(&request).unwrap();
        }
        let book_generation = store.book.generation;
        drop(store);
        let mut recovered =
            Store::open(&temp.path().join("state"), &scope().environment_id).unwrap();
        let receipt = recovered.find(&request.request_id).unwrap().unwrap();
        assert_eq!(receipt.phase, v1::HostControlRequestPhase::Unknown as i32);
        assert_eq!(receipt.reason, "recovered_unknown");
        assert!(!receipt.input_acknowledged);
        assert!(matches!(recovered.issue(&request), Err(Error::Conflict)));
        assert_eq!(recovered.book.generation, book_generation + 1);
        assert!(!temp.path().join("state/sessions").exists());
    }
}

#[test]
fn host_control_store_revoke_is_durable_cas_and_retains_original_receipt_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = admitted(temp.path());
    let request = launch(3, &scope(), "exit 0");
    store.register(&request).unwrap();
    let revoke = v1::HostControlRevokeGrantRequest {
        expected_book_revision: 1,
        grant_id: scope().grant_id,
        expected_grant_revision: 1,
    };
    store.revoke_grant(revoke.clone()).unwrap();
    assert!(matches!(store.issue(&request), Err(Error::Denied)));
    assert!(matches!(store.revoke_grant(revoke), Err(Error::Conflict)));
    store.finish(&request, Err(Error::Denied)).unwrap();
    drop(store);
    let mut recovered = Store::open(&temp.path().join("state"), &scope().environment_id).unwrap();
    assert!(recovered.grants().unwrap().grants[0].revoked);
    let receipt = recovered.find(&request.request_id).unwrap().unwrap();
    assert_eq!(receipt.origin, request.origin());
    assert_eq!(receipt.phase, v1::HostControlRequestPhase::Rejected as i32);
    assert!(matches!(
        recovered.put_grant(grant(&scope(), 2)),
        Err(Error::Conflict)
    ));
}

#[test]
fn host_control_store_snapshot_replacement_and_hardlinks_refuse_without_overwrite() {
    for hardlink in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = admitted(temp.path());
        let name = store.snapshots.last().unwrap().name.clone();
        let path = temp.path().join("state/host-control").join(name);
        let saved = std::fs::read(&path).unwrap();
        if hardlink {
            std::fs::hard_link(&path, temp.path().join("external-alias")).unwrap();
        } else {
            std::fs::rename(&path, temp.path().join("retained-original")).unwrap();
            std::fs::write(&path, &saved).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let directory = temp.path().join("state/host-control");
        let before = std::fs::read_dir(&directory).unwrap().count();
        let mut other = scope();
        other.grant_id = Uuid::from_u128(8).to_string();
        assert!(matches!(
            store.put_grant(grant(&other, 1)),
            Err(Error::Storage)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), before);
    }
}

#[test]
fn host_control_store_ancestry_modes_symlinks_and_unknown_entries_refuse_preserving_bytes() {
    for kind in [
        "writable-parent",
        "state-link",
        "book-link",
        "unknown",
        "fifo",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = admitted(temp.path());
        let directory = temp.path().join("state/host-control");
        let latest = directory.join(&store.snapshots.last().unwrap().name);
        drop(store);
        let payload = b"preserve-unknown";
        match kind {
            "writable-parent" => {
                std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o722))
                    .unwrap()
            }
            "state-link" => {
                std::fs::rename(temp.path().join("state"), temp.path().join("real-state")).unwrap();
                symlink(temp.path().join("real-state"), temp.path().join("state")).unwrap();
            }
            "book-link" => {
                std::fs::rename(&latest, temp.path().join("real-book")).unwrap();
                symlink(temp.path().join("real-book"), &latest).unwrap();
            }
            "unknown" => std::fs::write(directory.join("do-not-remove"), payload).unwrap(),
            "fifo" => {
                std::fs::remove_file(&latest).unwrap();
                let raw = std::ffi::CString::new(latest.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: fixed private path owned by this fixture.
                assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            Store::open(&temp.path().join("state"), &scope().environment_id),
            Err(Error::Storage)
        ));
        if kind == "unknown" {
            assert_eq!(
                std::fs::read(directory.join("do-not-remove")).unwrap(),
                payload
            );
        }
        // Restore only our intentionally widened private parent for TempDir's
        // ordinary owned cleanup; no production path is repaired on refusal.
        if kind == "writable-parent" {
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}

#[test]
fn host_control_store_capacity_preserves_request_and_grant_tombstones() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = admitted(temp.path());
    let mut next = store.book.clone();
    for id in 10..10 + MAX_REQUESTS as u128 {
        let request = launch(id, &scope(), "exit 0");
        let mut receipt = Receipt::pending(&request);
        receipt.phase = v1::HostControlRequestPhase::Rejected as i32;
        receipt.reason = "generation_or_process_unavailable".into();
        next.requests.insert(request.request_id, receipt);
    }
    store.publish(next).unwrap();
    let before = store.book.generation;
    assert!(matches!(
        store.register(&launch(5000, &scope(), "exit 0")),
        Err(Error::Capacity)
    ));
    assert_eq!(store.book.generation, before);
    assert_eq!(store.book.requests.len(), MAX_REQUESTS);
    let mut next = store.book.clone();
    for id in 100..100 + (MAX_GRANTS - 1) as u128 {
        let mut principal = scope();
        principal.grant_id = Uuid::from_u128(id).to_string();
        next.grants.insert(
            principal.grant_id.clone(),
            Grant {
                scope: principal,
                verbs: vec![1],
                revoked: true,
            },
        );
    }
    store.publish(next).unwrap();
    let mut other = scope();
    other.grant_id = Uuid::from_u128(999).to_string();
    assert!(matches!(
        store.put_grant(grant(&other, 1)),
        Err(Error::Capacity)
    ));
    assert_eq!(store.book.grants.len(), MAX_GRANTS);
    drop(store);
    let recovered = Store::open(&temp.path().join("state"), &scope().environment_id).unwrap();
    assert_eq!(recovered.book.requests.len(), MAX_REQUESTS);
    assert_eq!(recovered.book.grants.len(), MAX_GRANTS);
}

#[test]
fn host_control_store_issued_publication_failure_leaves_pending_no_effect_authority() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = admitted(temp.path());
    let request = launch(3, &scope(), "exit 0");
    store.register(&request).unwrap();
    let before = store.book.generation;
    store.fail_next_publication = true;
    assert!(matches!(store.issue(&request), Err(Error::Storage)));
    assert_eq!(store.book.generation, before);
    assert_eq!(
        store.find(&request.request_id).unwrap().unwrap().phase,
        v1::HostControlRequestPhase::Pending as i32
    );
    assert!(!temp.path().join("state/sessions").exists());
}

#[test]
fn host_control_store_three_complete_snapshots_after_crash_are_admitted_and_pruned_by_inode() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = admitted(temp.path());
    let oldest = store.snapshots[0].name.clone();
    let saved = std::fs::read(temp.path().join("state/host-control").join(&oldest)).unwrap();
    store.register(&launch(3, &scope(), "exit 0")).unwrap();
    // Reconstruct only the third known immutable predecessor, which a crash
    // before pruning could retain. Its byte/hash chain is the actual producer.
    let restored = temp.path().join("state/host-control").join(oldest);
    std::fs::write(&restored, saved).unwrap();
    std::fs::set_permissions(&restored, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    let recovered = Store::open(&temp.path().join("state"), &scope().environment_id).unwrap();
    assert_eq!(recovered.snapshots.len(), 2);
    assert!(!restored.exists());
}

#[test]
fn host_control_store_reload_refuses_false_completed_or_acknowledged_shapes() {
    for field in [
        "phase",
        "input_acknowledged",
        "foreign_origin",
        "duplicate_key",
        "unknown_field",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = admitted(temp.path());
        let request = launch(3, &scope(), "exit 0");
        store.register(&request).unwrap();
        let path = temp
            .path()
            .join("state/host-control")
            .join(&store.snapshots.last().unwrap().name);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let receipt = &mut value["requests"][&request.request_id];
        match field {
            "phase" => {
                receipt["phase"] = serde_json::json!(v1::HostControlRequestPhase::Completed as i32)
            }
            "input_acknowledged" => receipt["input_acknowledged"] = serde_json::json!(true),
            "foreign_origin" => {
                receipt["origin"]["scope"]["environment_id"] =
                    serde_json::json!(Uuid::from_u128(90).to_string())
            }
            "unknown_field" => receipt["future"] = serde_json::json!(true),
            "duplicate_key" => {}
            _ => unreachable!(),
        }
        let duplicate = receipt.to_string();
        let bytes = if field == "duplicate_key" {
            let rendered = serde_json::to_string(&value).unwrap();
            rendered
                .replacen(
                    "\"requests\":{",
                    &format!("\"requests\":{{\"{}\":{},", request.request_id, duplicate),
                    1,
                )
                .into_bytes()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        drop(store);
        std::fs::write(&path, bytes).unwrap();
        assert!(
            matches!(
                Store::open(&temp.path().join("state"), &scope().environment_id),
                Err(Error::Storage)
            ),
            "{field}"
        );
    }
}
