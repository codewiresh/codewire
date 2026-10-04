use k8s_openapi::api::core::v1::PersistentVolumeClaimStatus;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{OwnerReference, Time};
use serde_json::json;

use super::*;

const NAMESPACE: &str = "sandboxes";
const CLAIM_NAME: &str = "sandbox-550e8400-e29b-41d4-a716-446655440000";
const CLAIM_UID: &str = "c0ffee00-1d2e-4f3a-8b4c-5d6e7f8a9b0c";
const SANDBOX_NAME: &str = "sandbox-550e8400-e29b-41d4-a716-446655440000";
const SANDBOX_UID: &str = "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11";
const PVC_UID: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const OTHER_UID: &str = "a1560db3-8899-40c9-b521-500f223b04fb";

fn pvc_name() -> String {
    format!("workspace-{SANDBOX_NAME}")
}

fn claim() -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
        "kind": "SandboxClaim",
        "metadata": { "name": CLAIM_NAME, "namespace": NAMESPACE, "uid": CLAIM_UID },
        "status": { "sandbox": { "name": SANDBOX_NAME } },
    }))
    .unwrap()
}

fn sandbox(with_workspace: bool) -> DynamicObject {
    let templates = if with_workspace {
        json!([{ "metadata": { "name": "workspace" } }])
    } else {
        json!([])
    };
    serde_json::from_value(json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": {
            "name": SANDBOX_NAME,
            "namespace": NAMESPACE,
            "uid": SANDBOX_UID,
            "ownerReferences": [{
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                "kind": "SandboxClaim",
                "name": CLAIM_NAME,
                "uid": CLAIM_UID,
                "controller": true,
            }],
        },
        "spec": { "volumeClaimTemplates": templates },
    }))
    .unwrap()
}

fn pvc() -> PersistentVolumeClaim {
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(pvc_name()),
            namespace: Some(NAMESPACE.into()),
            uid: Some(PVC_UID.into()),
            owner_references: Some(vec![OwnerReference {
                api_version: "agents.x-k8s.io/v1beta1".into(),
                kind: "Sandbox".into(),
                name: SANDBOX_NAME.into(),
                uid: SANDBOX_UID.into(),
                controller: Some(true),
                ..Default::default()
            }]),
            ..Default::default()
        },
        status: Some(PersistentVolumeClaimStatus {
            phase: Some("Bound".into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn identity(pvc: &PersistentVolumeClaim, recorded: Option<&str>) -> anyhow::Result<WorkspacePvc> {
    workspace_pvc_identity(
        pvc,
        NAMESPACE,
        &pvc_name(),
        SANDBOX_NAME,
        SANDBOX_UID,
        recorded,
    )
}

#[test]
fn the_recorded_claim_names_its_sandbox() {
    assert_eq!(
        workspace_claim_sandbox(&claim(), NAMESPACE, CLAIM_NAME, CLAIM_UID).unwrap(),
        SANDBOX_NAME
    );
    // A replaced Claim under the same name, a missing recorded UID, a
    // terminating Claim and an unbound Claim never resolve.
    assert!(workspace_claim_sandbox(&claim(), NAMESPACE, CLAIM_NAME, OTHER_UID).is_err());
    assert!(workspace_claim_sandbox(&claim(), NAMESPACE, CLAIM_NAME, "").is_err());
    let mut terminating = claim();
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(workspace_claim_sandbox(&terminating, NAMESPACE, CLAIM_NAME, CLAIM_UID).is_err());
    let mut unbound = claim();
    unbound.data = json!({ "status": {} });
    assert!(workspace_claim_sandbox(&unbound, NAMESPACE, CLAIM_NAME, CLAIM_UID).is_err());
    let mut wrong_namespace = claim();
    wrong_namespace.metadata.namespace = Some("other".into());
    assert!(workspace_claim_sandbox(&wrong_namespace, NAMESPACE, CLAIM_NAME, CLAIM_UID).is_err());
}

#[test]
fn the_sandbox_template_names_the_pvc_and_only_its_claim_controls_it() {
    assert_eq!(
        workspace_pvc_name(&sandbox(true), NAMESPACE, CLAIM_NAME, CLAIM_UID).unwrap(),
        Some(pvc_name())
    );
    // disk_gb = 0 renders no workspace claim template.
    assert_eq!(
        workspace_pvc_name(&sandbox(false), NAMESPACE, CLAIM_NAME, CLAIM_UID).unwrap(),
        None
    );
    // Adoption rewrites Sandbox ownership: another Claim never resolves.
    assert!(workspace_pvc_name(&sandbox(true), NAMESPACE, CLAIM_NAME, OTHER_UID).is_err());
    let mut terminating = sandbox(true);
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(workspace_pvc_name(&terminating, NAMESPACE, CLAIM_NAME, CLAIM_UID).is_err());
    let mut orphaned = sandbox(true);
    orphaned.metadata.owner_references = None;
    assert!(workspace_pvc_name(&orphaned, NAMESPACE, CLAIM_NAME, CLAIM_UID).is_err());
}

#[test]
fn first_resolution_requires_the_sandbox_controller_and_records_the_uid() {
    assert_eq!(
        identity(&pvc(), None).unwrap(),
        WorkspacePvc::Claim {
            name: pvc_name(),
            uid: PVC_UID.into(),
            bound: true,
        }
    );
    // An unowned same-name PVC, even one carrying a tracking label, is not
    // accepted on first resolution, nor afterwards unless the label is this
    // Sandbox's own name hash (the restore adoption window below).
    let mut unowned = pvc();
    unowned.metadata.owner_references = None;
    unowned.metadata.labels = Some(BTreeMap::from([(
        "agents.x-k8s.io/sandbox-name-hash".into(),
        "0123abcd".into(),
    )]));
    assert!(identity(&unowned, None).is_err());
    assert!(identity(&unowned, Some(PVC_UID)).is_err());
    let mut other_sandbox = pvc();
    other_sandbox.metadata.owner_references.as_mut().unwrap()[0].uid = OTHER_UID.into();
    assert!(identity(&other_sandbox, None).is_err());
    let mut terminating = pvc();
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(identity(&terminating, None).is_err());
}

#[test]
fn a_recorded_uid_decides_and_a_same_name_substitute_fails() {
    assert!(identity(&pvc(), Some(PVC_UID)).is_ok());
    let mut substitute = pvc();
    substitute.metadata.uid = Some(OTHER_UID.into());
    assert!(identity(&substitute, Some(PVC_UID)).is_err());
    let mut pending = pvc();
    pending.status.as_mut().unwrap().phase = Some("Pending".into());
    assert!(matches!(
        identity(&pending, Some(PVC_UID)).unwrap(),
        WorkspacePvc::Claim { bound: false, .. }
    ));
}

/// The exact PVC the pinned agent-sandbox fork (aacf9ba1,
/// `controllers/sandbox_controller.go` `reconcilePVCs`) creates from the
/// `workspace` volume claim template: named `workspace-<sandbox>`, labelled
/// with the Sandbox name hash, and owned through
/// `ctrl.SetControllerReference`, which sets `controller` and
/// `blockOwnerDeletion`.
#[test]
fn the_pvc_shape_the_pinned_fork_creates_resolves_on_first_resolution() {
    let fork_created: PersistentVolumeClaim = serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": pvc_name(),
            "namespace": NAMESPACE,
            "uid": PVC_UID,
            "labels": { "agents.x-k8s.io/sandbox-name-hash": "1a2b3c4d" },
            "ownerReferences": [{
                "apiVersion": "agents.x-k8s.io/v1beta1",
                "kind": "Sandbox",
                "name": SANDBOX_NAME,
                "uid": SANDBOX_UID,
                "controller": true,
                "blockOwnerDeletion": true,
            }],
        },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "linstor-local" },
        "status": { "phase": "Bound" },
    }))
    .unwrap();
    assert_eq!(
        identity(&fork_created, None).unwrap(),
        WorkspacePvc::Claim {
            name: pvc_name(),
            uid: PVC_UID.into(),
            bound: true,
        }
    );
    // The fork's adoption path patches the same controller reference onto an
    // unowned PVC, so an adopted PVC also resolves, by its recorded UID.
    assert!(identity(&fork_created, Some(PVC_UID)).is_ok());
}

#[test]
fn the_name_hash_matches_the_fork() {
    // Independently computed with Go's hash/fnv New32a, which the fork's
    // NameHash wraps.
    assert_eq!(sandbox_name_hash(SANDBOX_NAME), "d0258436");
    assert_eq!(sandbox_name_hash("my-warm-pool"), "034dafb4");
    assert_eq!(sandbox_name_hash(""), "811c9dc5");
}

fn restored(labels: Option<&str>) -> PersistentVolumeClaim {
    let mut restored = pvc();
    restored.metadata.uid = Some(OTHER_UID.into());
    restored.metadata.owner_references = None;
    restored.metadata.labels =
        labels.map(|hash| BTreeMap::from([(SANDBOX_NAME_HASH_LABEL.to_owned(), hash.to_owned())]));
    restored
}

/// Design §12: between `adopt_restored_workspace_pvc` and the fork's adoption,
/// an unowned restore-born PVC resolves only with the recorded UID and this
/// Sandbox's tracking label. Every other unowned same-name PVC fails.
#[test]
fn a_restore_born_pvc_resolves_only_by_its_adopted_uid_and_tracking_label() {
    let hash = sandbox_name_hash(SANDBOX_NAME);
    assert_eq!(
        identity(&restored(Some(&hash)), Some(OTHER_UID)).unwrap(),
        WorkspacePvc::Claim {
            name: pvc_name(),
            uid: OTHER_UID.into(),
            bound: true,
        }
    );
    // Not adopted: the recorded UID is still the old PVC's.
    assert!(identity(&restored(Some(&hash)), Some(PVC_UID)).is_err());
    // First resolution never accepts an unowned PVC.
    assert!(identity(&restored(Some(&hash)), None).is_err());
    // Another Sandbox's tracking label, or none at all.
    assert!(identity(&restored(Some("0123abcd")), Some(OTHER_UID)).is_err());
    assert!(identity(&restored(None), Some(OTHER_UID)).is_err());
    // Controlled by something else: never the adoption window.
    let mut foreign = restored(Some(&hash));
    foreign.metadata.owner_references = Some(vec![OwnerReference {
        api_version: "apps/v1".into(),
        kind: "StatefulSet".into(),
        name: "other".into(),
        uid: PVC_UID.into(),
        controller: Some(true),
        ..Default::default()
    }]);
    assert!(identity(&foreign, Some(OTHER_UID)).is_err());
    // Once the fork adopts it, the controller reference and the UID decide.
    let mut adopted = restored(Some(&hash));
    adopted.metadata.owner_references = pvc().metadata.owner_references;
    assert!(identity(&adopted, Some(OTHER_UID)).is_ok());
    let mut terminating = restored(Some(&hash));
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert!(identity(&terminating, Some(OTHER_UID)).is_err());
}
