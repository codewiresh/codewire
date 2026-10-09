//! Synthetic record/transport fixtures. No incoming CW executable is run.
use super::{
    model::{CapturedBindingFacts, RuntimeAction, RuntimeMutation, RuntimePhase},
    owner::RuntimeRequest,
    wire,
};
use chrono::{DateTime, Utc};
use codewire_cw_release::{build_record::BuildRecord, identity::CwPayloadIdentity};
use codewire_proto::codewire::v1 as proto;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub(super) fn identity(tag: char) -> CwPayloadIdentity {
    CwPayloadIdentity {
        schema_version: 2,
        protocol_version: 1,
        record_version: 1,
        package_version: "v1.2.3".into(),
        target: "x86_64-unknown-linux-musl".into(),
        source_revision: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        rustc: "rustc 1.93.0 (synthetic-fixture)".into(),
        sha256: tag.to_string().repeat(64),
        size: 1024,
    }
}

pub(super) fn payload(extra: &[u8]) -> (CwPayloadIdentity, Vec<u8>) {
    let mut identity = identity('c');
    let record = BuildRecord {
        package_version: identity.package_version.clone(),
        target: identity.target.clone(),
        rustc: identity.rustc.clone(),
        source_revision: Some(identity.source_revision.clone()),
        source_tree_sha256: Some(identity.source_tree_sha256.clone()),
    };
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64] = 1;
    bytes.extend(record.frame(super::intake::BUILD_MARKER).unwrap());
    bytes.extend_from_slice(extra);
    identity.sha256 = format!("{:x}", Sha256::digest(&bytes));
    identity.size = bytes.len() as u64;
    (identity, bytes)
}

pub(super) fn binding() -> CapturedBindingFacts {
    let bound = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let org = "runtime-service-org";
    let env = "550e8400-e29b-41d4-a716-446655440000";
    let ns = "runtime-sandboxes";
    let name = format!("sandbox-{env}");
    let pod = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
    let claim = "c0ffee00-e29b-41d4-a716-446655440000";
    let pvc = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
    CapturedBindingFacts {
        organization_id: org.into(),
        organization_deletion_state: "active".into(),
        organization_deletion_generation: 0,
        environment_id: env.into(),
        environment_state: "running".into(),
        desired_state: "started".into(),
        environment_type: "sandbox".into(),
        isolation_tier: "standard".into(),
        environment_generation: 9,
        deletion_requested_at: None,
        backend_namespace: ns.into(),
        backend_pod_name: name.clone(),
        backend_pod_ip: "10.12.3.4".into(),
        backend_pod_uid: pod.into(),
        backend_claim_uid: Some(claim.into()),
        backend_pvc_uid: Some(pvc.into()),
        backend_bound_at: bound,
        setup_complete: true,
        setup_owner_status: None,
        pod_uid: pod.into(),
        namespace: ns.into(),
        pod_name: name,
        claim_uid: claim.into(),
        sandbox_uid: "5a4db0c5-e29b-41d4-a716-446655440000".into(),
        workspace_pvc_uid: Some(pvc.into()),
        binding_generation: 3,
        projection_selection_sha256: Some("a".repeat(64)),
        managed_credential_clients: codewire_access::ManagedCredentialClients::default()
            .encode()
            .into(),
        credential_scope: "pod".into(),
        binding_bound_at: bound,
    }
}

pub(super) fn request(action: RuntimeAction, generation: u64) -> RuntimeRequest {
    RuntimeRequest {
        mutation: RuntimeMutation {
            request_id: Uuid::new_v4(),
            action,
            expected_store_generation: generation,
            expected_current_sha256: (generation > 0).then(|| identity('a').sha256),
            expected_previous_sha256: (generation > 1).then(|| identity('b').sha256),
            bootstrap_identity: (generation == 0).then(|| identity('a')),
            target_identity: identity('c'),
        },
        binding: binding(),
        actor_user_id: "runtime-service-actor".into(),
        phase: RuntimePhase::Admitted,
        checkpoint: 0,
        effect: None,
        acknowledgements: vec![],
        error_code: None,
        admitted_at: Utc::now(),
        issued_at: None,
        terminal_at: None,
    }
}

pub(super) fn header(generation: u64) -> proto::UpdateEnvironmentCwRuntimeHeader {
    let request = request(RuntimeAction::Update, generation);
    proto::UpdateEnvironmentCwRuntimeHeader {
        org_id: request.binding.organization_id.clone(),
        environment_id: request.binding.environment_id.clone(),
        request_id: request.mutation.request_id.to_string(),
        expected_incarnation: Some(
            wire::proto_incarnation(&request.binding.incarnation()).unwrap(),
        )
        .into(),
        expected_selection: Some(proto::EnvironmentCwRuntimeExpectation {
            generation,
            current_sha256: request.mutation.expected_current_sha256.clone(),
            previous_sha256: request.mutation.expected_previous_sha256.clone(),
            ..Default::default()
        })
        .into(),
        identity: Some(wire::proto_identity(&request.mutation.target_identity)).into(),
        bootstrap_identity: request
            .mutation
            .bootstrap_identity
            .as_ref()
            .map(wire::proto_identity)
            .into(),
        ..Default::default()
    }
}
