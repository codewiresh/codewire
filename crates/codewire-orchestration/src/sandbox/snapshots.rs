//! Names and rendered objects of a hosted disk snapshot (#3046 H1).
//!
//! Every Kubernetes name derives from the snapshot's id, never a user string.
//! The clearing Sandbox has no environment label, so an environment's destroy
//! and residue proof never see it, and no binding, network, credential or
//! service-account token, so it can do nothing but clear its own volume.

use serde_json::{Value, json};

use super::template::{SANDBOX_SERVICE_ACCOUNT, render_sandbox_shadow_pool};
use super::{EXTENSIONS_API_VERSION, LABEL_TYPE, shadow_warm_pool_name};

pub const VOLUME_SNAPSHOT_API_VERSION: &str = "snapshot.storage.k8s.io/v1";
pub const LABEL_SNAPSHOT_ID: &str = "codewire.sh/snapshot-id";
const NAME_PREFIX: &str = "cw-snap-";
/// The role a clearing object carries in `codewire.sh/type`.
const CLEARING_TYPE: &str = "snapshot-clearing";
/// Where the clearing container mounts the volume.
pub const CLEARING_MOUNT_PATH: &str = "/workspace";
/// The hidden `cw` command clearing runs (`codewire-cli-bin`).
pub const CLEARING_COMMAND: &str = "__snapshot-clear";
/// `cw` in the support image, as `DAEMON_INIT_CONTAINER` copies it.
const SUPPORT_IMAGE_CW: &str = "/usr/local/bin/cw";

/// The kept snapshot.
pub fn kept_snapshot_name(snapshot_id: &str) -> String {
    format!("{NAME_PREFIX}{snapshot_id}")
}

/// The uncleared copy of the source's disk. It holds delivered sign-ins whole
/// and never outlives its capture.
pub fn raw_snapshot_name(snapshot_id: &str) -> String {
    format!("{NAME_PREFIX}{snapshot_id}-raw")
}

/// The clearing template and claim, and so its Sandbox and Pod.
pub fn clearing_name(snapshot_id: &str) -> String {
    format!("{NAME_PREFIX}{snapshot_id}-clear")
}

/// The volume the controller creates from the clearing template.
pub fn clearing_volume_name(snapshot_id: &str) -> String {
    format!("workspace-{}", clearing_name(snapshot_id))
}

/// Whether a Sandbox is a clearing Sandbox, which no environment owns and no
/// bill covers. An environment's Sandbox is named `sandbox-<id>`, a pool
/// member's `cw-pool-*`.
pub fn is_clearing_sandbox(name: &str) -> bool {
    name.starts_with(NAME_PREFIX)
}

pub fn render_volume_snapshot(
    namespace: &str,
    name: &str,
    snapshot_id: &str,
    source_pvc: &str,
    snapshot_class: &str,
) -> Value {
    json!({
        "apiVersion": VOLUME_SNAPSHOT_API_VERSION,
        "kind": "VolumeSnapshot",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": { LABEL_SNAPSHOT_ID: snapshot_id },
        },
        "spec": {
            "volumeSnapshotClassName": snapshot_class,
            "source": { "persistentVolumeClaimName": source_pvc },
        },
    })
}

/// What a clearing Sandbox needs from the deployment and the raw snapshot.
pub struct ClearingOpts<'a> {
    pub namespace: &'a str,
    pub snapshot_id: &'a str,
    pub support_image: &'a str,
    pub runtime_class: &'a str,
    pub storage_class: &'a str,
    /// The raw snapshot's `status.restoreSize`.
    pub restore_size: &'a str,
}

/// The template of a clearing Sandbox: one container that clears a restore of
/// the raw snapshot and exits.
pub fn render_clearing_template(opts: &ClearingOpts<'_>) -> Value {
    let name = clearing_name(opts.snapshot_id);
    let mut pod_spec = json!({
        "restartPolicy": "Never",
        "serviceAccountName": SANDBOX_SERVICE_ACCOUNT,
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        // Root, because a tenant's files may have any mode, with only the two
        // capabilities that needs. No fsGroup: the kubelet changes nothing on
        // the volume.
        "securityContext": { "runAsUser": 0, "runAsGroup": 0 },
        "containers": [{
            "name": "clear",
            "image": opts.support_image,
            "command": [SUPPORT_IMAGE_CW, CLEARING_COMMAND, CLEARING_MOUNT_PATH],
            "resources": {
                "requests": { "cpu": "250m", "memory": "256Mi" },
                "limits": { "cpu": "1", "memory": "512Mi" },
            },
            "securityContext": {
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "capabilities": { "drop": ["ALL"], "add": ["DAC_OVERRIDE", "FOWNER"] },
                "seccompProfile": { "type": "RuntimeDefault" },
            },
            "volumeMounts": [{ "name": "workspace", "mountPath": CLEARING_MOUNT_PATH }],
        }],
    });
    if !opts.runtime_class.is_empty() {
        pod_spec["runtimeClassName"] = opts.runtime_class.into();
    }
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxTemplate",
        "metadata": {
            "name": name,
            "namespace": opts.namespace,
            "labels": {
                LABEL_TYPE: CLEARING_TYPE,
                LABEL_SNAPSHOT_ID: opts.snapshot_id,
            },
        },
        "spec": {
            "podTemplate": {
                "metadata": {
                    "labels": {
                        LABEL_TYPE: CLEARING_TYPE,
                        LABEL_SNAPSHOT_ID: opts.snapshot_id,
                    },
                },
                "spec": pod_spec,
            },
            "volumeClaimTemplates": [{
                "metadata": { "name": "workspace" },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": opts.storage_class,
                    "resources": { "requests": { "storage": opts.restore_size } },
                    "dataSource": {
                        "apiGroup": "snapshot.storage.k8s.io",
                        "kind": "VolumeSnapshot",
                        "name": raw_snapshot_name(opts.snapshot_id),
                    },
                },
            }],
            // No ingress and no egress: the controller manages a policy that
            // admits nothing either way.
            "networkPolicy": { "ingress": [], "egress": [] },
        },
    })
}

/// The zero-replica shadow pool a claim needs. It holds no members, so nothing
/// can adopt from it. The pool's identity label names the snapshot, which no
/// environment's selector ever matches.
pub fn render_clearing_pool(namespace: &str, snapshot_id: &str) -> Value {
    let template = clearing_name(snapshot_id);
    let mut pool = render_sandbox_shadow_pool(
        namespace,
        &shadow_warm_pool_name(&template),
        &template,
        snapshot_id,
    );
    pool["metadata"]["labels"][LABEL_TYPE] = CLEARING_TYPE.into();
    pool["metadata"]["labels"][LABEL_SNAPSHOT_ID] = snapshot_id.into();
    pool
}

pub fn render_clearing_claim(namespace: &str, snapshot_id: &str) -> Value {
    let template = clearing_name(snapshot_id);
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxClaim",
        "metadata": {
            "name": template,
            "namespace": namespace,
            "labels": {
                LABEL_TYPE: CLEARING_TYPE,
                LABEL_SNAPSHOT_ID: snapshot_id,
            },
        },
        "spec": { "warmPoolRef": { "name": shadow_warm_pool_name(&template) } },
    })
}

/// A Kubernetes quantity in bytes, for the binary and plain forms a volume's
/// size takes.
pub fn quantity_bytes(quantity: &str) -> Option<i64> {
    let quantity = quantity.trim();
    let (digits, unit) = match quantity.find(|c: char| !c.is_ascii_digit()) {
        Some(split) => quantity.split_at(split),
        None => (quantity, ""),
    };
    let scale: i64 = match unit {
        "" => 1,
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        "Gi" => 1 << 30,
        "Ti" => 1 << 40,
        _ => return None,
    };
    digits.parse::<i64>().ok()?.checked_mul(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn opts() -> ClearingOpts<'static> {
        ClearingOpts {
            namespace: "dev-sandboxes",
            snapshot_id: ID,
            support_image: "registry.example/daemon@sha256:abc",
            runtime_class: "commodity",
            storage_class: "linstor-local",
            restore_size: "80Gi",
        }
    }

    #[test]
    fn names_fit_kubernetes_and_derive_only_from_the_id() {
        for name in [
            kept_snapshot_name(ID),
            raw_snapshot_name(ID),
            clearing_name(ID),
            clearing_volume_name(ID),
            shadow_warm_pool_name(&clearing_name(ID)),
        ] {
            assert!(name.len() <= 63, "{name}");
            assert!(name.contains(&ID[..8]), "{name}");
        }
        assert_eq!(
            clearing_volume_name(ID),
            format!("workspace-{}", clearing_name(ID)),
            "the controller names a claim template's PVC <template>-<sandbox>"
        );
    }

    #[test]
    fn a_clearing_sandbox_is_told_apart_from_every_other_sandbox() {
        assert!(is_clearing_sandbox(&clearing_name(ID)));
        assert!(!is_clearing_sandbox(&super::super::claim_name(ID)));
        assert!(!is_clearing_sandbox("cw-pool-1000m-4096mi-80gi-add3f0f3-x"));
    }

    #[test]
    fn the_clearing_template_restores_the_raw_snapshot_and_holds_no_authority() {
        let template = render_clearing_template(&opts());
        let claim = &template["spec"]["volumeClaimTemplates"][0]["spec"];
        assert_eq!(claim["dataSource"]["name"], raw_snapshot_name(ID));
        assert_eq!(claim["dataSource"]["kind"], "VolumeSnapshot");
        assert_eq!(claim["storageClassName"], "linstor-local");
        assert_eq!(claim["resources"]["requests"]["storage"], "80Gi");

        assert_eq!(template["spec"]["networkPolicy"]["ingress"], json!([]));
        assert_eq!(template["spec"]["networkPolicy"]["egress"], json!([]));
        let pod = &template["spec"]["podTemplate"]["spec"];
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(pod["runtimeClassName"], "commodity");
        assert_eq!(pod["restartPolicy"], "Never");
        assert!(pod["securityContext"].get("fsGroup").is_none());
        let containers = pod["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        let container = &containers[0];
        assert!(container.get("env").is_none());
        assert!(container.get("envFrom").is_none());
        assert_eq!(
            container["command"],
            json!(["/usr/local/bin/cw", "__snapshot-clear", "/workspace"])
        );
        assert_eq!(
            container["securityContext"]["capabilities"]["add"],
            json!(["DAC_OVERRIDE", "FOWNER"])
        );
        assert_eq!(pod["volumes"], Value::Null);
    }

    #[test]
    fn no_clearing_object_carries_an_environment_or_organization_label_of_the_source() {
        let template = render_clearing_template(&opts());
        let claim = render_clearing_claim("dev-sandboxes", ID);
        for object in [
            &template["metadata"]["labels"],
            &template["spec"]["podTemplate"]["metadata"]["labels"],
            &claim["metadata"]["labels"],
        ] {
            assert!(object.get(super::super::LABEL_ENV_ID).is_none());
            assert!(object.get(super::super::LABEL_ORG_ID).is_none());
            assert_eq!(object[LABEL_SNAPSHOT_ID], ID);
        }
    }

    #[test]
    fn the_shadow_pool_holds_no_member_and_names_only_its_template() {
        let pool = render_clearing_pool("dev-sandboxes", ID);
        assert_eq!(pool["spec"]["replicas"], 0);
        assert_eq!(
            pool["spec"]["sandboxTemplateRef"]["name"],
            clearing_name(ID)
        );
        assert_eq!(
            pool["metadata"]["name"],
            shadow_warm_pool_name(&clearing_name(ID))
        );
        let claim = render_clearing_claim("dev-sandboxes", ID);
        assert_eq!(
            claim["spec"]["warmPoolRef"]["name"],
            pool["metadata"]["name"]
        );
        assert!(claim["spec"].get("env").is_none());
    }

    #[test]
    fn quantities_read_as_bytes() {
        assert_eq!(quantity_bytes("80Gi"), Some(85_899_345_920));
        assert_eq!(quantity_bytes("85899345920"), Some(85_899_345_920));
        assert_eq!(quantity_bytes("512Mi"), Some(536_870_912));
        assert_eq!(quantity_bytes("1G"), None);
        assert_eq!(quantity_bytes(""), None);
    }
}
