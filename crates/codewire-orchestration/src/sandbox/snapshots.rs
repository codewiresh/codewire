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
/// The raw snapshot's record of its source's volume mode, which decides how
/// its restore is cleared. A raw snapshot without it is a Filesystem one: a
/// release before this label took no other.
pub const LABEL_SOURCE_VOLUME_MODE: &str = "codewire.sh/source-volume-mode";
const NAME_PREFIX: &str = "cw-snap-";
/// The role a clearing object carries in `codewire.sh/type`.
const CLEARING_TYPE: &str = "snapshot-clearing";
/// Where the clearing container mounts the volume.
pub const CLEARING_MOUNT_PATH: &str = "/workspace";
/// The hidden `cw` command clearing runs (`codewire-cli-bin`).
pub const CLEARING_COMMAND: &str = "__snapshot-clear";
/// Where a Block restore appears in the clearing container.
pub const CLEARING_DEVICE_PATH: &str = "/dev/codewire-clearing";
/// Where a Block clearing writes its report line, which Kubernetes keeps as the
/// container's termination message for the worker to log.
pub const CLEARING_REPORT_PATH: &str = "/dev/termination-log";
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

/// A source volume's mode, as its PVC states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeMode {
    /// A volume the node formats and the guest reaches over virtio-fs, so a
    /// guest never reads its free blocks. Clearing zeroes the current token
    /// files only (option A). Removed with the virtio-fs workspace path at
    /// the Block cutover (#3718), together with every branch on it.
    Filesystem,
    /// A volume the guest formats and reads block by block, so clearing also
    /// wipes every block its guest cannot read through the filesystem.
    Block,
}

impl VolumeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "Filesystem",
            Self::Block => "Block",
        }
    }

    /// The mode a raw snapshot's label records; an absent label is
    /// Filesystem, and anything else is refused.
    pub fn from_label(label: Option<&str>) -> Option<Self> {
        match label {
            None | Some("Filesystem") => Some(Self::Filesystem),
            Some("Block") => Some(Self::Block),
            Some(_) => None,
        }
    }
}

/// A VolumeSnapshot of `source_pvc`. A raw snapshot records its source's
/// volume mode; the kept snapshot passes `None`.
pub fn render_volume_snapshot(
    namespace: &str,
    name: &str,
    snapshot_id: &str,
    source_pvc: &str,
    snapshot_class: &str,
    source_mode: Option<VolumeMode>,
) -> Value {
    let mut labels = json!({ LABEL_SNAPSHOT_ID: snapshot_id });
    if let Some(mode) = source_mode {
        labels[LABEL_SOURCE_VOLUME_MODE] = mode.as_str().into();
    }
    json!({
        "apiVersion": VOLUME_SNAPSHOT_API_VERSION,
        "kind": "VolumeSnapshot",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "volumeSnapshotClassName": snapshot_class,
            "source": { "persistentVolumeClaimName": source_pvc },
        },
    })
}

/// What a clearing Sandbox needs from the deployment and the raw snapshot.
pub struct ClearingOpts<'a> {
    pub snapshot_id: &'a str,
    pub support_image: &'a str,
    pub runtime_class: &'a str,
    pub storage_class: &'a str,
    /// The raw snapshot's `status.restoreSize`.
    pub restore_size: &'a str,
    /// The raw snapshot's source volume mode, which its restore keeps.
    pub volume_mode: VolumeMode,
}

/// The template of a clearing Sandbox: one container that clears a restore of
/// the raw snapshot and exits.
///
/// A Block restore reaches the container as a device. The container clears its
/// files through debugfs without mounting it, and wipes every block its guest
/// cannot read (`cw __snapshot-clear --block`), all inside the clearing VM, so
/// the host never parses the guest's filesystem. Nothing mounts it, so the
/// container holds no `SYS_ADMIN` (#4013).
pub fn render_clearing_template(namespace: &str, opts: &ClearingOpts<'_>) -> Value {
    let name = clearing_name(opts.snapshot_id);
    let (command, storage) = match opts.volume_mode {
        VolumeMode::Filesystem => (
            json!([SUPPORT_IMAGE_CW, CLEARING_COMMAND, CLEARING_MOUNT_PATH]),
            json!({
                "volumeMounts": [{ "name": "workspace", "mountPath": CLEARING_MOUNT_PATH }],
            }),
        ),
        VolumeMode::Block => (
            json!([
                SUPPORT_IMAGE_CW,
                CLEARING_COMMAND,
                "--block",
                CLEARING_DEVICE_PATH,
                "--report",
                CLEARING_REPORT_PATH
            ]),
            json!({
                "volumeDevices": [{ "name": "workspace", "devicePath": CLEARING_DEVICE_PATH }],
                "terminationMessagePath": CLEARING_REPORT_PATH,
            }),
        ),
    };
    let mut container = json!({
        "name": "clear",
        "image": opts.support_image,
        "command": command,
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
    });
    for (key, value) in storage.as_object().expect("an object") {
        container[key] = value.clone();
    }
    let mut pod_spec = json!({
        "restartPolicy": "Never",
        "serviceAccountName": SANDBOX_SERVICE_ACCOUNT,
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        // Root, because a tenant's files may have any mode, with only the
        // capabilities that needs. No fsGroup: the kubelet changes nothing on
        // the volume.
        "securityContext": { "runAsUser": 0, "runAsGroup": 0 },
        "containers": [container],
    });
    if !opts.runtime_class.is_empty() {
        pod_spec["runtimeClassName"] = opts.runtime_class.into();
    }
    let mut claim_spec = json!({
        "accessModes": ["ReadWriteOnce"],
        "storageClassName": opts.storage_class,
        "resources": { "requests": { "storage": opts.restore_size } },
        "dataSource": {
            "apiGroup": "snapshot.storage.k8s.io",
            "kind": "VolumeSnapshot",
            "name": raw_snapshot_name(opts.snapshot_id),
        },
    });
    if opts.volume_mode == VolumeMode::Block {
        claim_spec["volumeMode"] = "Block".into();
    }
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxTemplate",
        "metadata": {
            "name": name,
            "namespace": namespace,
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
                "spec": claim_spec,
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
            snapshot_id: ID,
            support_image: "registry.example/daemon@sha256:abc",
            runtime_class: "commodity",
            storage_class: "linstor-local",
            restore_size: "80Gi",
            volume_mode: VolumeMode::Filesystem,
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
        let template = render_clearing_template("dev-sandboxes", &opts());
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
        let template = render_clearing_template("dev-sandboxes", &opts());
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
    fn a_filesystem_restore_is_mounted_by_the_node_and_gets_no_sys_admin() {
        let template = render_clearing_template("dev-sandboxes", &opts());
        let claim = &template["spec"]["volumeClaimTemplates"][0]["spec"];
        assert!(claim.get("volumeMode").is_none());
        let pod = &template["spec"]["podTemplate"]["spec"];
        let container = &pod["containers"][0];
        assert!(container.get("volumeDevices").is_none());
        assert_eq!(
            container["volumeMounts"],
            json!([{ "name": "workspace", "mountPath": "/workspace" }])
        );
        assert!(pod.get("volumes").is_none());
    }

    #[test]
    fn a_block_restore_is_a_device_the_clearing_vm_mounts_and_wipes() {
        let template = render_clearing_template(
            "dev-sandboxes",
            &ClearingOpts {
                volume_mode: VolumeMode::Block,
                ..opts()
            },
        );
        let claim = &template["spec"]["volumeClaimTemplates"][0]["spec"];
        assert_eq!(claim["volumeMode"], "Block");
        assert_eq!(claim["dataSource"]["name"], raw_snapshot_name(ID));
        assert_eq!(claim["resources"]["requests"]["storage"], "80Gi");

        assert_eq!(template["spec"]["networkPolicy"]["ingress"], json!([]));
        assert_eq!(template["spec"]["networkPolicy"]["egress"], json!([]));
        let pod = &template["spec"]["podTemplate"]["spec"];
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(pod["runtimeClassName"], "commodity");
        let containers = pod["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        let container = &containers[0];
        assert!(container.get("env").is_none());
        assert_eq!(
            container["command"],
            json!([
                "/usr/local/bin/cw",
                "__snapshot-clear",
                "--block",
                "/dev/codewire-clearing",
                "--report",
                "/dev/termination-log"
            ])
        );
        assert_eq!(container["terminationMessagePath"], "/dev/termination-log");
        assert_eq!(
            container["volumeDevices"],
            json!([{ "name": "workspace", "devicePath": "/dev/codewire-clearing" }])
        );
        // Nothing mounts the volume, the node or the container, so the
        // container holds no SYS_ADMIN (#4013).
        assert!(container.get("volumeMounts").is_none());
        assert!(pod.get("volumes").is_none());
        let security = &container["securityContext"];
        assert_eq!(
            security["capabilities"],
            json!({ "drop": ["ALL"], "add": ["DAC_OVERRIDE", "FOWNER"] })
        );
        assert_eq!(security["allowPrivilegeEscalation"], false);
        assert_eq!(security["readOnlyRootFilesystem"], true);
        assert!(security.get("privileged").is_none());
    }

    #[test]
    fn only_a_raw_snapshot_records_its_source_mode_and_an_unknown_one_is_refused() {
        let raw = render_volume_snapshot(
            "dev-sandboxes",
            &raw_snapshot_name(ID),
            ID,
            "workspace-sandbox-x",
            "linstor-local",
            Some(VolumeMode::Block),
        );
        assert_eq!(raw["metadata"]["labels"][LABEL_SOURCE_VOLUME_MODE], "Block");
        assert_eq!(raw["metadata"]["labels"][LABEL_SNAPSHOT_ID], ID);
        let kept = render_volume_snapshot(
            "dev-sandboxes",
            &kept_snapshot_name(ID),
            ID,
            &clearing_volume_name(ID),
            "linstor-local",
            None,
        );
        assert!(
            kept["metadata"]["labels"]
                .get(LABEL_SOURCE_VOLUME_MODE)
                .is_none()
        );

        assert_eq!(
            VolumeMode::from_label(Some("Block")),
            Some(VolumeMode::Block)
        );
        assert_eq!(
            VolumeMode::from_label(Some("Filesystem")),
            Some(VolumeMode::Filesystem)
        );
        // A raw snapshot from a release before the label.
        assert_eq!(VolumeMode::from_label(None), Some(VolumeMode::Filesystem));
        assert_eq!(VolumeMode::from_label(Some("block")), None);
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
