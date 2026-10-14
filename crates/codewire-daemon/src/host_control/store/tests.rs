use super::*;
use crate::host_control::tests::{config, grant, launch, scope};
use std::os::unix::fs::{PermissionsExt, symlink};

fn admitted(root: &Path) -> Store {
    let config = config(root);
    let mut store = Store::open(&config.host.unwrap().state_root, &scope().environment_id).unwrap();
    store.put_grant(grant(&scope(), 0)).unwrap();
    store
}

fn managed_admitted(root: &Path) -> Store {
    let config = config(root);
    let mut store = Store::open(&config.host.unwrap().state_root, &scope().environment_id).unwrap();
    let mut request = grant(&scope(), 0);
    request.grant.as_mut().unwrap().verbs = (1..=11).collect();
    store.put_grant(request).unwrap();
    store
}
/// Reopen the store under `state_root` after its previous owner was dropped.
/// A child that a concurrent test forks while that owner's `owner.lock`
/// descriptor is open holds a copy of it, and so the lock, until the child
/// execs. The reopen waits that out, bounded, and only while another process
/// really holds the lock: any other refusal still fails at once.
fn reopen(state_root: &Path) -> Store {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match Store::open(state_root, &scope().environment_id) {
            Ok(store) => return store,
            Err(Error::Storage)
                if std::time::Instant::now() < deadline
                    && lock_held_elsewhere(&state_root.join(DIRECTORY).join("owner.lock")) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => panic!("reopening the store failed: {error:?}"),
        }
    }
}

/// Whether another open description holds the store's lock right now.
fn lock_held_elsewhere(lock: &Path) -> bool {
    let Ok(file) = std::fs::File::open(lock) else {
        return false;
    };
    // SAFETY: flock operates on this owned descriptor only; closing it
    // releases this probe's own lock.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

fn managed_launch(id: u128) -> Mutation {
    Mutation::from_wire(v1::HostControlMutationRequest {
        request_id: Uuid::from_u128(id).to_string(),
        scope: Some(scope().to_wire()),
        operation: Some(v1::host_control_mutation_request::Operation::ManagedLaunch(
            v1::HostControlManagedLaunch {
                agent: 1,
                model: "synthetic".into(),
                effort: Some("max".into()),
                prompt: Some("hello".into()),
                ..Default::default()
            },
        )),
    })
    .unwrap()
}
#[test]
fn member_managed_store_preserves_reserved_ids_and_never_reissues_pending_or_issued_after_reload() {
    for issued in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = managed_admitted(temp.path());
        let request = managed_launch(3);
        let pending = store.register(&request).unwrap();
        assert_eq!(pending.driver_id, request.request_id);
        assert_eq!(pending.message_id, request.request_id);
        if issued {
            store.issue(&request).unwrap();
        }
        drop(store);
        let mut recovered = reopen(&temp.path().join("state"));
        let observed = recovered.find(&request.request_id).unwrap().unwrap();
        assert_eq!(observed.phase, v1::HostControlRequestPhase::Unknown as i32);
        assert_eq!(observed.driver_id, request.request_id);
        assert_eq!(observed.message_id, request.request_id);
        assert!(matches!(recovered.issue(&request), Err(Error::Conflict)));
        assert!(!temp.path().join("state/sessions").exists());
        recovered
            .revoke_grant(v1::HostControlRevokeGrantRequest {
                expected_book_revision: 1,
                grant_id: scope().grant_id,
                expected_grant_revision: 1,
            })
            .unwrap();
        assert_eq!(
            recovered
                .find(&request.request_id)
                .unwrap()
                .unwrap()
                .to_wire(),
            observed.to_wire()
        );
    }
}
#[test]
fn member_managed_store_refuses_rebound_message_driver_and_false_restart_generation() {
    for field in ["message", "driver", "requested-zero", "launch-generation"] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = managed_admitted(temp.path());
        let request = managed_launch(3);
        store.register(&request).unwrap();
        let path = temp
            .path()
            .join("state/host-control")
            .join(&store.snapshots.last().unwrap().name);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let receipt = &mut value["requests"][&request.request_id];
        match field {
            "message" => receipt["message_id"] = serde_json::json!(Uuid::from_u128(8).to_string()),
            "driver" => receipt["driver_id"] = serde_json::json!(Uuid::from_u128(9).to_string()),
            "requested-zero" => receipt["requested_generation"] = serde_json::json!(0),
            "launch-generation" => receipt["requested_generation"] = serde_json::json!(2),
            _ => unreachable!(),
        };
        drop(store);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            matches!(
                Store::open(&temp.path().join("state"), &scope().environment_id),
                Err(Error::Storage)
            ),
            "{field}"
        );
    }
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
        let mut recovered = reopen(&temp.path().join("state"));
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
    let mut recovered = reopen(&temp.path().join("state"));
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
    let recovered = reopen(&temp.path().join("state"));
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
    let recovered = reopen(&temp.path().join("state"));
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

#[tokio::test]
async fn host_control_store_owner_regrant_current_cas_preserves_observe_and_no_reissue() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = managed_admitted(temp.path());
    let request = managed_launch(3);
    store.register(&request).unwrap();
    store.issue(&request).unwrap();
    let original = store.finish(&request, Err(Error::Unavailable)).unwrap();
    assert_eq!(original.phase, v1::HostControlRequestPhase::Unknown as i32);
    let original_bytes = serde_json::to_vec(&original).unwrap();
    store
        .revoke_grant(v1::HostControlRevokeGrantRequest {
            expected_book_revision: 1,
            grant_id: scope().grant_id,
            expected_grant_revision: 1,
        })
        .unwrap();
    let mut put = grant(&scope(), 2);
    let value = put.grant.as_mut().unwrap();
    value.revision = 2;
    value.verbs = (1..=11).collect();
    let result = store.put_grant(put).unwrap();
    assert_eq!(result.book_revision, 3);
    assert_eq!(result.grants[0].revision, 3);
    assert!(!result.grants[0].revoked);
    let mut current = scope();
    current.grant_revision = 3;
    store
        .authorize(&current, v1::HostControlVerb::ManagedRead)
        .unwrap();
    for revision in [1, 2] {
        let mut stale = scope();
        stale.grant_revision = revision;
        assert!(matches!(
            store.authorize(&stale, v1::HostControlVerb::ManagedRead),
            Err(Error::Denied)
        ));
    }
    assert_eq!(
        serde_json::to_vec(&store.find(&request.request_id).unwrap().unwrap()).unwrap(),
        original_bytes
    );
    drop(store);
    let mut recovered = reopen(&temp.path().join("state"));
    let grants = recovered.grants().unwrap();
    assert_eq!(grants.book_revision, 3);
    assert_eq!(grants.grants[0].revision, 3);
    assert!(!grants.grants[0].revoked);
    recovered
        .authorize(&current, v1::HostControlVerb::ManagedRead)
        .unwrap();
    for revision in [1, 2] {
        let mut stale = scope();
        stale.grant_revision = revision;
        assert!(matches!(
            recovered.authorize(&stale, v1::HostControlVerb::ManagedRead),
            Err(Error::Denied)
        ));
    }
    assert_eq!(
        serde_json::to_vec(&recovered.find(&request.request_id).unwrap().unwrap()).unwrap(),
        original_bytes
    );
    let mut rebound = managed_launch(3);
    rebound.scope = current.clone();
    assert!(matches!(recovered.register(&rebound), Err(Error::Conflict)));
    assert!(matches!(recovered.issue(&rebound), Err(Error::Conflict)));
    drop(recovered);

    // Observe and duplicate admission use the retained owning row. Neither an
    // old alias nor the newly granted revision can turn Unknown into a spawn.
    let config = config(temp.path());
    let engine = crate::durable_session::SessionEngine::new(
        &config,
        crate::credential_bridge::CredentialBridge::new(None),
    );
    let owner = crate::host_control::Owner::new(
        &config,
        crate::host_control::HostControlBinding::new(scope().environment_id)
            .unwrap()
            .with_managed_agents(),
        engine.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_vec(
            &owner
                .observe(&request.request_id, &request.scope)
                .await
                .unwrap()
        )
        .unwrap(),
        original_bytes
    );
    assert!(matches!(
        owner.observe(&request.request_id, &current).await,
        Err(Error::Denied)
    ));
    assert_eq!(
        serde_json::to_vec(&owner.mutate(request).await.unwrap()).unwrap(),
        original_bytes
    );
    assert!(matches!(owner.mutate(rebound).await, Err(Error::Conflict)));
    assert!(
        std::fs::read_dir(temp.path().join("state/sessions"))
            .unwrap()
            .next()
            .is_none()
    );
    owner.drain().await.unwrap();
    engine.shutdown().await.unwrap();
}

#[test]
fn host_control_store_regrant_refusals_preserve_exact_book_and_receipt_bytes() {
    for kind in [
        "stale-book",
        "future-book",
        "stale-grant",
        "zero-grant",
        "future-grant",
        "environment",
        "org",
        "network",
        "caller",
        "target",
        "grant-id",
        "revoked",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = admitted(temp.path());
        let request = launch(3, &scope(), "must-not-execute");
        store.register(&request).unwrap();
        store.issue(&request).unwrap();
        store.finish(&request, Err(Error::Unavailable)).unwrap();
        store
            .revoke_grant(v1::HostControlRevokeGrantRequest {
                expected_book_revision: 1,
                grant_id: scope().grant_id,
                expected_grant_revision: 1,
            })
            .unwrap();
        let before_book = serde_json::to_vec(&store.book).unwrap();
        let before_receipt =
            serde_json::to_vec(&store.find(&request.request_id).unwrap().unwrap()).unwrap();
        let before_name = store.snapshots.last().unwrap().name.clone();
        let before_path = temp.path().join("state/host-control").join(&before_name);
        let before_disk = std::fs::read(&before_path).unwrap();
        assert_eq!(before_disk, before_book);
        let mut put = grant(&scope(), 2);
        let value = put.grant.as_mut().unwrap();
        value.revision = 2;
        match kind {
            "stale-book" => put.expected_book_revision = 1,
            "future-book" => put.expected_book_revision = 3,
            "stale-grant" => value.revision = 1,
            "zero-grant" => value.revision = 0,
            "future-grant" => value.revision = 3,
            "environment" => value.environment_id = Uuid::from_u128(9).to_string(),
            "org" => value.org_id = "different-org".into(),
            "network" => value.network_id = "different-network".into(),
            "caller" => value.caller_key = vec![3; 32],
            "target" => value.target_key = vec![4; 32],
            "grant-id" => value.grant_id = Uuid::from_u128(9).to_string(),
            "revoked" => value.revoked = true,
            _ => unreachable!(),
        }
        let error = store.put_grant(put).unwrap_err();
        match kind {
            "environment" => assert!(matches!(error, Error::Denied)),
            "revoked" => assert!(matches!(error, Error::Invalid)),
            _ => assert!(matches!(error, Error::Conflict), "{kind}"),
        }
        assert_eq!(
            serde_json::to_vec(&store.book).unwrap(),
            before_book,
            "{kind}"
        );
        assert_eq!(
            serde_json::to_vec(&store.find(&request.request_id).unwrap().unwrap()).unwrap(),
            before_receipt,
            "{kind}"
        );
        assert_eq!(store.snapshots.last().unwrap().name, before_name, "{kind}");
        assert_eq!(std::fs::read(&before_path).unwrap(), before_disk, "{kind}");
        assert!(matches!(
            store.authorize(&scope(), v1::HostControlVerb::Launch),
            Err(Error::Denied)
        ));
        assert!(!temp.path().join("state/sessions").exists());
    }
}
