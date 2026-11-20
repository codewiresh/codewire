//! The workspace Pod's parts for hosted egress (#4000), rendered only when it
//! is on. The interface is cw-learn's, posted on #4000: the daemon reads the
//! egress token and the two addresses; the TUN init container runs `cw
//! __hosted-egress-tun`; the netstack answers DNS.
//! Nothing here resolves a name: the infra#1822 fence denies cluster DNS to a
//! broker-mode Pod from its first packet.

use serde_json::{Map, Value, json};

use codewire_daemon_proto::{
    EGRESS_TOKEN_AUDIENCE, EGRESS_TOKEN_EXPIRATION_SECONDS, EGRESS_TOKEN_MOUNT_PATH,
};

use super::HostedEgressTemplate;

/// The fence revision the Pod was created under (infra#1822), read back by
/// admission and status.
pub(crate) const FENCE_REVISION_ANNOTATION: &str = "codewire.sh/egress-fence-revision";
/// The workspace's egress token volume, the second Pod-bound token beside the
/// binding's.
pub(crate) const EGRESS_TOKEN_VOLUME: &str = "workspace-egress-identity";
pub(crate) const TUN_INIT_CONTAINER: &str = "hosted-egress-tun";
/// The TUN device's volume. A Kata container has no `/dev/net/tun`, so the
/// TUN init makes the node here and the daemon opens it. Memory-backed only:
/// a disk-backed emptyDir is the node's filesystem shared into the VM, and a
/// device node must never be written there. Mounted at exactly
/// [`DEVNET_MOUNT_PATH`] by the TUN init and the workspace container only
/// (`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`, "Hosted Egress Setup").
pub(crate) const DEVNET_VOLUME: &str = "egress-devnet";
pub(crate) const DEVNET_MOUNT_PATH: &str = "/dev/net";
pub(crate) const DEVNET_SIZE_LIMIT: &str = "1Mi";
/// The netstack's resolver: the TUN's gateway address.
pub(crate) const NETSTACK_RESOLVER: &str = "192.0.2.1";
/// The TUN init container's whole command, the workspace user owning the
/// TUN. It runs the support image's own `cw`, never the copy in the daemon
/// volume: in emptyDir mode the workspace can write that copy, and a re-run
/// privileged init would execute it. Admission holds a pool member to this
/// command (`pool_member_isolated`).
pub(crate) const TUN_INIT_COMMAND: [&str; 4] = [
    "/usr/local/bin/cw",
    "__hosted-egress-tun",
    "--owner-uid",
    "1000",
];

/// The token, mounted into the workspace container only, the TUN device's
/// volume, and the addresses the daemon dials instead of names.
pub(super) fn mount_workspace(
    ws: &mut Value,
    volumes: &mut Vec<Value>,
    egress: &HostedEgressTemplate,
) {
    volumes.push(devnet_volume());
    volumes.push(json!({
        "name": EGRESS_TOKEN_VOLUME,
        "projected": {
            "defaultMode": 0o440,
            "sources": [{
                "serviceAccountToken": {
                    "audience": EGRESS_TOKEN_AUDIENCE,
                    "expirationSeconds": EGRESS_TOKEN_EXPIRATION_SECONDS,
                    "path": "token",
                },
            }],
        },
    }));
    ws["volumeMounts"]
        .as_array_mut()
        .expect("workspace mounts")
        .extend([
            json!({
                "name": EGRESS_TOKEN_VOLUME,
                "mountPath": EGRESS_TOKEN_MOUNT_PATH,
                "readOnly": true,
            }),
            devnet_mount(),
        ]);
    let env = ws["env"].as_array_mut().expect("workspace env");
    env.push(json!({ "name": "CODEWIRE_EGRESS_STREAM_ADDR", "value": egress.stream_addr }));
    env.push(json!({ "name": "CODEWIRE_WORKSPACE_BINDING_ADDR", "value": egress.binding_addr }));
    // The daemon's platform path (#5039): every platform connection by
    // address, none by name.
    env.push(json!({ "name": "CODEWIRE_API_ADDR", "value": egress.gateway_addr }));
    env.push(json!({ "name": "CODEWIRE_MESH_ADDR", "value": egress.gateway_addr }));
    env.push(json!({ "name": "CODEWIRE_DERP_ADDR", "value": egress.derp_addr }));
    env.push(json!({ "name": "CODEWIRE_CLUSTER_DNS_IP", "value": egress.cluster_dns_ip }));
}

/// The netstack as the only resolver: no cluster DNS, no search list.
pub(super) fn resolver(spec: &mut Map<String, Value>) {
    spec.insert("dnsPolicy".into(), "None".into());
    spec.insert(
        "dnsConfig".into(),
        json!({ "nameservers": [NETSTACK_RESOLVER], "searches": [] }),
    );
}

/// Creates the TUN, its addresses, the default route and the rule that sends
/// the tailnet socket's replies out of eth0. Privileged inside the guest
/// only, so it renders only on a VM runtime
/// ([`super::TemplateOpts::validate_hosted_egress`]). Its one mount is the
/// TUN device's volume, where it makes the device node.
pub(super) fn tun_init_container(support_image: &str) -> Value {
    json!({
        "name": TUN_INIT_CONTAINER,
        "image": support_image,
        "command": TUN_INIT_COMMAND,
        "securityContext": { "privileged": true, "runAsUser": 0, "runAsGroup": 0 },
        "volumeMounts": [devnet_mount()],
    })
}

/// The TUN device's volume and its one mount, exactly as rendered; the bind's
/// isolation check compares a pool member's against these whole.
pub(crate) fn devnet_volume() -> Value {
    json!({
        "name": DEVNET_VOLUME,
        "emptyDir": { "medium": "Memory", "sizeLimit": DEVNET_SIZE_LIMIT },
    })
}

pub(crate) fn devnet_mount() -> Value {
    json!({ "name": DEVNET_VOLUME, "mountPath": DEVNET_MOUNT_PATH })
}
