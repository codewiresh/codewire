use super::*;
use codewire_tailnet::derp::NodePrivate;
use prost::Message;
use std::os::unix::fs::PermissionsExt;

fn private() -> (tempfile::TempDir, store::Directory) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = store::Directory::open(&temp.path().join("members"), true).unwrap();
    (temp, directory)
}
fn binding() -> wire::Binding {
    wire::Binding {
        environment_id: uuid::Uuid::new_v4().to_string(),
        org: "test-org".into(),
        network: "test-network".into(),
        target_wg: *NodePrivate::from_raw([33; 32]).public().as_bytes(),
        caller: *NodePrivate::from_raw([11; 32]).public().as_bytes(),
        target: *NodePrivate::from_raw([22; 32]).public().as_bytes(),
        grant_id: uuid::Uuid::new_v4().to_string(),
        grant_revision: 1,
    }
}
fn launch(binding: &wire::Binding) -> v1::HostControlMutationRequest {
    v1::HostControlMutationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        scope: Some(binding.scope()),
        operation: Some(v1::host_control_mutation_request::Operation::Launch(
            v1::HostControlLaunch {
                command: vec!["/bin/true".into()],
                ..Default::default()
            },
        )),
    }
}

#[tokio::test]
async fn member_wire_mutual_proof_binds_scope_and_typed_terminal_payload() {
    let binding = binding();
    let (a, b) = tokio::io::duplex(8192);
    let (caller, target) = tokio::join!(
        wire::Channel::caller(a, NodePrivate::from_raw([11; 32]), binding.clone()),
        wire::Channel::target(b, NodePrivate::from_raw([22; 32]), &binding)
    );
    let mut caller = caller.unwrap();
    let mut target = target.unwrap();
    let request = launch(&binding);
    caller.send(2, &request.encode_to_vec()).await.unwrap();
    let (action, payload) = target.receive().await.unwrap();
    assert_eq!(action, 2);
    assert_eq!(
        wire::decode::<v1::HostControlMutationRequest>(&payload).unwrap(),
        request
    );
    assert_eq!(target.binding, binding);
}

#[tokio::test]
async fn member_wire_refuses_wrong_org_network_target_and_noncontributory_key() {
    for field in 0..3 {
        let expected = binding();
        let mut incoming = expected.clone();
        match field {
            0 => incoming.org.push('x'),
            1 => incoming.network.push('x'),
            _ => incoming.target_wg[0] ^= 1,
        };
        let (a, b) = tokio::io::duplex(8192);
        let (caller, target) = tokio::join!(
            wire::Channel::caller(a, NodePrivate::from_raw([11; 32]), incoming),
            wire::Channel::target(b, NodePrivate::from_raw([22; 32]), &expected)
        );
        assert!(caller.is_err());
        assert!(target.is_err());
    }
    let mut bad = binding();
    bad.target = [0; 32];
    bad.target[0] = 1;
    let (a, _b) = tokio::io::duplex(8192);
    assert!(
        wire::Channel::caller(a, NodePrivate::from_raw([11; 32]), bad)
            .await
            .is_err()
    );
}

#[test]
fn member_wire_refuses_unknown_noncanonical_and_oversized_payloads() {
    assert!(wire::decode::<v1::HostControlInfoRequest>(&[8, 1]).is_err());
    assert!(wire::decode::<v1::HostControlInfoRequest>(&vec![0; wire::MAX_PAYLOAD + 1]).is_err());
    let mut request = launch(&binding()).encode_to_vec();
    request.extend([0x08, 0x01]);
    assert!(wire::decode::<v1::HostControlMutationRequest>(&request).is_err());
    assert!(wire::result::<v1::HostControlInfoResponse>(&[0]).is_err());
}

#[tokio::test]
async fn member_caller_intent_survives_drop_and_duplicate_is_observe_only() {
    let (_temp, directory) = private();
    let binding = binding();
    let request = launch(&binding);
    let (mut first, duplicate) =
        store::RequestRecord::prepare(&directory, binding.clone(), &request)
            .await
            .unwrap();
    assert!(!duplicate);
    first.begin(&directory).await.unwrap();
    drop(first);
    let (mut duplicate, is_duplicate) =
        store::RequestRecord::prepare(&directory, binding.clone(), &request)
            .await
            .unwrap();
    assert!(is_duplicate && duplicate.attempted);
    assert!(duplicate.begin(&directory).await.is_err());
    let mut changed = request.clone();
    if let Some(v1::host_control_mutation_request::Operation::Launch(x)) = &mut changed.operation {
        x.command = vec!["/bin/false".into()];
    }
    assert!(
        store::RequestRecord::prepare(&directory, binding, &changed)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn member_caller_refuses_cross_scope_stale_generation_and_changed_receipt() {
    let (_temp, directory) = private();
    let binding = binding();
    let request = launch(&binding);
    let (mut record, _) = store::RequestRecord::prepare(&directory, binding.clone(), &request)
        .await
        .unwrap();
    record.begin(&directory).await.unwrap();
    let receipt = v1::HostControlReceipt {
        request_id: request.request_id.clone(),
        scope: Some(binding.scope()),
        fingerprint_sha256: "ab".repeat(32),
        verb: 2,
        phase: 3,
        session_id: record.session_id.clone(),
        launch_generation: 1,
        session_state: 2,
        ..Default::default()
    };
    record.finish(&directory, receipt.clone()).await.unwrap();
    let mut bad = receipt.clone();
    bad.scope.as_mut().unwrap().network_id.push('x');
    assert!(record.validate_receipt(&bad).is_err());
    bad = receipt.clone();
    bad.launch_generation = 2;
    assert!(record.validate_receipt(&bad).is_err());
    bad = receipt;
    bad.fingerprint_sha256 = "cd".repeat(32);
    assert!(record.validate_receipt(&bad).is_err());
    let zero = v1::HostControlMutationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        scope: Some(binding.scope()),
        operation: Some(v1::host_control_mutation_request::Operation::Stop(
            v1::HostControlStop {
                session_id: record.session_id,
                expected_launch_generation: 0,
            },
        )),
    };
    assert!(
        store::RequestRecord::prepare(&directory, binding, &zero)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn member_alias_full_keys_are_immutable_and_identity_is_explicit() {
    let (_temp, directory) = private();
    assert!(store::Identity::load(&directory, false).await.is_err());
    let identity = store::Identity::load(&directory, true).await.unwrap();
    assert_eq!(
        identity.secret().public(),
        store::Identity::load(&directory, false)
            .await
            .unwrap()
            .secret()
            .public()
    );
    let alias = store::Alias {
        schema: 1,
        name: "target".into(),
        origin: "http://127.0.0.1:9080/".into(),
        route_name: "host-target".into(),
        binding: binding(),
        derp_only: true,
        required_transport: None,
    };
    alias.save(&directory).await.unwrap();
    let mut changed = alias;
    changed.binding.target[0] ^= 1;
    assert!(changed.save(&directory).await.is_err());
    assert_ne!(
        store::Alias::load(&directory, "target").unwrap().binding,
        changed.binding
    );
}

#[test]
fn member_saved_transport_requirement_is_closed_and_conflicts_are_refused() {
    let original = store::Alias {
        schema: 1,
        name: "target".into(),
        origin: "http://127.0.0.1:9080/".into(),
        route_name: "target".into(),
        binding: binding(),
        derp_only: false,
        required_transport: None,
    };
    let mut encoded = serde_json::to_value(&original).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .remove("required_transport");
    let legacy: store::Alias = serde_json::from_value(encoded.clone()).unwrap();
    legacy.validate().unwrap();
    assert!(legacy.required_transport.is_none());
    encoded["required_transport"] = "derp".into();
    let conflict: store::Alias = serde_json::from_value(encoded.clone()).unwrap();
    assert!(conflict.validate().is_err());
    encoded["derp_only"] = true.into();
    let relay: store::Alias = serde_json::from_value(encoded.clone()).unwrap();
    relay.validate().unwrap();
    encoded["required_transport"] = "direct_udp".into();
    let conflict: store::Alias = serde_json::from_value(encoded.clone()).unwrap();
    assert!(conflict.validate().is_err());
    encoded["derp_only"] = false.into();
    let direct: store::Alias = serde_json::from_value(encoded.clone()).unwrap();
    direct.validate().unwrap();
    encoded["required_transport"] = "plaintext_relay".into();
    assert!(serde_json::from_value::<store::Alias>(encoded).is_err());
}

fn input_request(binding: &wire::Binding) -> v1::HostControlMutationRequest {
    v1::HostControlMutationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        scope: Some(binding.scope()),
        operation: Some(v1::host_control_mutation_request::Operation::Input(
            v1::HostControlInput {
                session_id: format!("session-{}", uuid::Uuid::new_v4()),
                expected_launch_generation: 7,
                data: b"synthetic terminal input".to_vec(),
            },
        )),
    }
}
fn input_receipt(record: &store::RequestRecord) -> v1::HostControlReceipt {
    v1::HostControlReceipt {
        request_id: record.id.clone(),
        scope: Some(record.binding.scope()),
        fingerprint_sha256: "ab".repeat(32),
        verb: 3,
        phase: v1::HostControlRequestPhase::Completed as i32,
        session_id: record.session_id.clone(),
        launch_generation: record.generation,
        session_state: 3,
        input_acknowledged: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn member_route_refusal_preserves_authenticated_ack_and_duplicate_is_observe_only() {
    let (_temp, directory) = private();
    let binding = binding();
    let request = input_request(&binding);
    let (mut record, _) = store::RequestRecord::prepare(&directory, binding.clone(), &request)
        .await
        .unwrap();
    record.begin(&directory).await.unwrap();
    let receipt = input_receipt(&record);
    let id = record.id.clone();
    let qualification = async {
        // The production helper must save the received ACK before the route
        // qualifier's first poll; this also protects cancellation in that wait.
        let saved = store::RequestRecord::load(&directory, &id).unwrap();
        let observed: v1::HostControlReceipt =
            wire::decode(saved.receipt.as_ref().unwrap()).unwrap();
        assert!(saved.attempted && observed.input_acknowledged);
        anyhow::bail!("synthetic path changed after acknowledged input")
    };
    assert!(
        transport::retain_receipt(&directory, &mut record, receipt.clone(), qualification)
            .await
            .is_err()
    );
    let saved = store::RequestRecord::load(&directory, &id).unwrap();
    assert!(saved.attempted);
    assert_eq!(
        wire::decode::<v1::HostControlReceipt>(saved.receipt.as_ref().unwrap()).unwrap(),
        receipt
    );
    let (mut duplicate, existing) = store::RequestRecord::prepare(&directory, binding, &request)
        .await
        .unwrap();
    assert!(existing && duplicate.attempted && duplicate.receipt.is_some());
    assert!(duplicate.begin(&directory).await.is_err());
}

#[tokio::test]
async fn member_cancelled_route_qualification_keeps_ack_and_malformed_receipt_never_qualifies() {
    let (_temp, directory) = private();
    let binding = binding();
    let request = input_request(&binding);
    let (mut record, _) = store::RequestRecord::prepare(&directory, binding, &request)
        .await
        .unwrap();
    record.begin(&directory).await.unwrap();
    let receipt = input_receipt(&record);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            transport::retain_receipt(
                &directory,
                &mut record,
                receipt.clone(),
                std::future::pending()
            )
        )
        .await
        .is_err()
    );
    let saved = store::RequestRecord::load(&directory, &record.id).unwrap();
    assert!(saved.attempted);
    assert_eq!(
        wire::decode::<v1::HostControlReceipt>(saved.receipt.as_ref().unwrap()).unwrap(),
        receipt
    );
    let polled = std::sync::atomic::AtomicBool::new(false);
    let mut bad = receipt.clone();
    bad.launch_generation += 1;
    assert!(
        transport::retain_receipt(&directory, &mut record, bad, async {
            polled.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
        .await
        .is_err()
    );
    assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
    let saved = store::RequestRecord::load(&directory, &record.id).unwrap();
    assert_eq!(
        wire::decode::<v1::HostControlReceipt>(saved.receipt.as_ref().unwrap()).unwrap(),
        receipt
    );
}

#[test]
fn member_store_refuses_symlink_hardlink_and_replaced_directory_without_cleanup() {
    let (temp, directory) = private();
    directory
        .write("plain.json", &serde_json::json!({"safe":true}))
        .unwrap();
    std::fs::hard_link(
        directory.path.join("plain.json"),
        directory.path.join("alias.json"),
    )
    .unwrap();
    assert!(directory.read::<serde_json::Value>("plain.json").is_err());
    std::os::unix::fs::symlink(
        directory.path.join("plain.json"),
        directory.path.join("linked.json"),
    )
    .unwrap();
    assert!(directory.read::<serde_json::Value>("linked.json").is_err());
    fs::rename(&directory.path, temp.path().join("retained")).unwrap();
    fs::create_dir(&directory.path).unwrap();
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(directory.write("new.json", &true).is_err());
    assert!(!directory.path.join("new.json").exists());
    assert!(temp.path().join("retained/plain.json").exists());
}

#[test]
fn member_store_refuses_unsafe_ancestor_before_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let path = temp.path().join("member");
    assert!(store::Directory::open(&path, true).is_err());
    assert!(!path.exists());
}

#[test]
fn member_held_cleanup_refuses_record_and_directory_replacement_without_unlink() {
    let (temp, directory) = private();
    directory
        .write(
            "member-ready.json",
            &serde_json::json!({"nonce":"original"}),
        )
        .unwrap();
    directory
        .write("member-runtime.json", &serde_json::json!({"pid":123}))
        .unwrap();
    let (_, ready) = directory
        .read_held::<serde_json::Value>("member-ready.json")
        .unwrap()
        .unwrap();
    let (_, runtime) = directory
        .read_held::<serde_json::Value>("member-runtime.json")
        .unwrap()
        .unwrap();
    directory
        .write(
            "member-ready.json",
            &serde_json::json!({"nonce":"original"}),
        )
        .unwrap();
    assert!(directory.validate_held(&ready).is_err());
    assert!(directory.remove_held(&ready).is_err());
    directory.validate_held(&runtime).unwrap();
    assert!(directory.path.join("member-runtime.json").exists());
    fs::rename(&directory.path, temp.path().join("original-members")).unwrap();
    store::create_chain(&directory.path).unwrap();
    assert!(directory.remove_held(&runtime).is_err());
    assert!(
        temp.path()
            .join("original-members/member-runtime.json")
            .exists()
    );
}

#[tokio::test]
async fn member_caller_capacity_preserves_retained_requests_and_unknown_entries() {
    let (_temp, directory) = private();
    let binding = binding();
    directory.write("unknown.json", &"preserve").unwrap();
    for _ in 0..256 {
        let request = launch(&binding);
        store::RequestRecord::prepare(&directory, binding.clone(), &request)
            .await
            .unwrap();
    }
    let request = launch(&binding);
    assert!(
        store::RequestRecord::prepare(&directory, binding, &request)
            .await
            .is_err()
    );
    assert_eq!(
        directory.read::<String>("unknown.json").unwrap().as_deref(),
        Some("preserve")
    );
    assert_eq!(
        fs::read_dir(&directory.path)
            .unwrap()
            .filter(|x| x
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("request-"))
            .count(),
        256
    );
}

#[tokio::test]
async fn member_missing_owner_does_not_start_daemon() {
    let (temp, _directory) = private();
    let root = temp.path().join("host");
    store::create_chain(&root).unwrap();
    let env = HostEnvironment {
        id: uuid::Uuid::new_v4().to_string(),
        name: "test".into(),
        path: temp.path().to_owned(),
        created_at: String::new(),
        state: "running".into(),
        runtime_root: Some(root.clone()),
    };
    assert!(custody::OwnerPin::admit(&env).await.is_err());
    assert!(!root.join("daemon.sock").exists());
    assert!(!root.join("daemon.log").exists());
    assert!(!root.join("daemon.lock").exists());
}

#[test]
fn member_exact_host_uuid_never_rebinds_to_uuid_shaped_name() {
    let id = uuid::Uuid::new_v4().to_string();
    let host = |saved_id: String, name: String| HostEnvironment {
        id: saved_id,
        name,
        path: PathBuf::from("/not-opened-by-selector"),
        created_at: String::new(),
        state: "running".into(),
        runtime_root: None,
    };
    let decoy = host(uuid::Uuid::new_v4().to_string(), id.clone());
    let expected = host(id.clone(), "target".into());
    let selected = select_host_from(vec![decoy.clone(), expected], &id).unwrap();
    assert_eq!(selected.id, id);
    // Deletion/name reuse is a refusal, including noncanonical UUID syntax;
    // the selector does not open either owner's path or start a replacement.
    assert!(select_host_from(vec![decoy.clone()], &id).is_err());
    assert!(select_host_from(vec![decoy], &id.to_uppercase()).is_err());
}
