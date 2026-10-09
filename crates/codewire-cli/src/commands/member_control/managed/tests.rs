use super::*;
use prost::Message;
use std::os::unix::fs::PermissionsExt;

fn binding() -> wire::Binding {
    wire::Binding {
        environment_id: uuid::Uuid::new_v4().to_string(),
        org: "test-org".into(),
        network: "test-network".into(),
        target_wg: [3; 32],
        caller: [1; 32],
        target: [2; 32],
        grant_id: uuid::Uuid::new_v4().to_string(),
        grant_revision: 1,
    }
}
fn session(generation: u64) -> v1::SessionRecord {
    let id = uuid::Uuid::new_v4().to_string();
    v1::SessionRecord {
        session_id: format!("session-{id}"),
        launch_generation: generation,
        command: vec![
            "/retained/cw".into(),
            "_agent-driver".into(),
            "--environment".into(),
            uuid::Uuid::new_v4().to_string(),
            "--driver-id".into(),
            id,
            "--registry-root".into(),
            "/private/hosts".into(),
        ],
        ..Default::default()
    }
}
fn record(session: &v1::SessionRecord, id: &str, original: u64, state: &str) -> Value {
    json!({"record":{"version":1,"id":id,"target_session_id":session.session_id,
        "driver_id":session.command[5],"member_launch_generation":original,"state":state}})
}
#[test]
fn member_managed_history_requires_exact_terminal_original_generation_and_identity() {
    let current = session(2);
    let id = uuid::Uuid::new_v4().to_string();
    for state in ["completed", "error", "interrupted", "unknown"] {
        assert!(checked_record(record(&current, &id, 1, state), &current, &id).is_ok());
    }
    for state in [
        "requested",
        "pipe_written",
        "undelivered",
        "accepted",
        "running",
    ] {
        assert!(checked_record(record(&current, &id, 1, state), &current, &id).is_err());
        assert!(checked_record(record(&current, &id, 2, state), &current, &id).is_ok());
    }
    for generation in [0, 3] {
        assert!(
            checked_record(
                record(&current, &id, generation, "completed"),
                &current,
                &id
            )
            .is_err()
        );
    }
    let mut missing = record(&current, &id, 1, "completed");
    missing["record"]
        .as_object_mut()
        .unwrap()
        .remove("member_launch_generation");
    assert!(checked_record(missing, &current, &id).is_err());
    let mut wrong = record(&current, &id, 1, "completed");
    wrong["record"]["driver_id"] = json!(uuid::Uuid::new_v4().to_string());
    assert!(checked_record(wrong, &current, &id).is_err());
}
#[test]
fn member_managed_retained_binding_accepts_fresh_revision_but_never_new_principal_or_key() {
    let saved = binding();
    let mut current = saved.clone();
    current.grant_revision = 2;
    assert!(same_member(&saved, &current));
    assert!(!same_member(&current, &saved));
    for field in ["env", "org", "network", "caller", "target", "wg", "grant"] {
        let mut wrong = current.clone();
        match field {
            "env" => wrong.environment_id = uuid::Uuid::new_v4().to_string(),
            "org" => wrong.org.push('x'),
            "network" => wrong.network.push('x'),
            "caller" => wrong.caller[0] ^= 1,
            "target" => wrong.target[0] ^= 1,
            "wg" => wrong.target_wg[0] ^= 1,
            "grant" => wrong.grant_id = uuid::Uuid::new_v4().to_string(),
            _ => unreachable!(),
        };
        assert!(!same_member(&saved, &wrong), "{field}");
    }
}
#[tokio::test]
async fn member_managed_caller_reserves_ids_and_lost_reply_is_observe_only() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = store::Directory::open(&temp.path().join("members"), true).unwrap();
    let binding = binding();
    let id = uuid::Uuid::new_v4().to_string();
    let request = v1::HostControlMutationRequest {
        request_id: id.clone(),
        scope: Some(binding.scope()),
        operation: Some(v1::host_control_mutation_request::Operation::ManagedLaunch(
            v1::HostControlManagedLaunch {
                agent: 1,
                model: "synthetic".into(),
                effort: Some("max".into()),
                prompt: Some("hello".into()),
                ..Default::default()
            },
        )),
    };
    let (mut intent, duplicate) = store::RequestRecord::prepare(&dir, binding.clone(), &request)
        .await
        .unwrap();
    assert!(!duplicate);
    assert_eq!((&intent.driver_id, &intent.message_id), (&id, &id));
    intent.begin(&dir).await.unwrap();
    drop(intent);
    let (mut recovered, duplicate) = store::RequestRecord::prepare(&dir, binding.clone(), &request)
        .await
        .unwrap();
    assert!(duplicate && recovered.attempted);
    assert!(recovered.begin(&dir).await.is_err());
    let mut altered = request.clone();
    if let Some(v1::host_control_mutation_request::Operation::ManagedLaunch(x)) =
        &mut altered.operation
    {
        x.prompt = Some("changed".into());
    }
    assert!(
        store::RequestRecord::prepare(&dir, binding, &altered)
            .await
            .is_err()
    );
    assert_eq!(
        store::RequestRecord::load(&dir, &id).unwrap().message_id,
        id
    );
}
#[tokio::test]
async fn member_managed_wire_transfers_large_record_in_separately_authenticated_bounded_frames() {
    use codewire_tailnet::derp::NodePrivate;
    use sha2::{Digest, Sha256};
    let mut binding = binding();
    binding.caller = *NodePrivate::from_raw([11; 32]).public().as_bytes();
    binding.target = *NodePrivate::from_raw([22; 32]).public().as_bytes();
    let (a, b) = tokio::io::duplex(8192);
    let (caller, target) = tokio::join!(
        wire::Channel::caller(a, NodePrivate::from_raw([11; 32]), binding.clone()),
        wire::Channel::target(b, NodePrivate::from_raw([22; 32]), &binding)
    );
    let mut caller = caller.unwrap();
    let mut target = target.unwrap();
    let current = session(1);
    let id = uuid::Uuid::new_v4().to_string();
    let request = v1::HostControlManagedReadRequest {
        scope: Some(binding.scope()),
        session_id: current.session_id.clone(),
        driver_id: current.command[5].clone(),
        expected_launch_generation: 1,
        message_id: id,
        limit: 20,
    };
    let bytes = vec![b'x'; 512 * 1024];
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let chunks: Vec<_> = bytes
        .chunks(240 * 1024)
        .enumerate()
        .map(|(i, data)| v1::HostControlManagedRecordChunk {
            session_id: request.session_id.clone(),
            driver_id: request.driver_id.clone(),
            message_id: request.message_id.clone(),
            launch_generation: 1,
            offset: (i * 240 * 1024) as u64,
            total_bytes: bytes.len() as u64,
            payload_sha256: hash.clone(),
            data: data.to_vec(),
        })
        .collect();
    let send = async {
        for chunk in &chunks {
            let frame = wire::response(Ok(chunk.clone())).unwrap();
            assert!(frame.len() <= 256 * 1024);
            target.send(7, &frame).await.unwrap();
        }
    };
    let receive = async {
        let mut received = Vec::new();
        for _ in &chunks {
            let (action, frame) = caller.receive().await.unwrap();
            assert_eq!(action, 7);
            received.push(wire::result::<v1::HostControlManagedRecordChunk>(&frame).unwrap());
        }
        received
    };
    let (_, received) = tokio::join!(send, receive);
    assert_eq!(
        codewire_daemon::client::validate_host_managed_chunks(&request, &received).unwrap(),
        bytes
    );
    assert!(received.iter().all(|c| c.encoded_len() < 256 * 1024));
}
