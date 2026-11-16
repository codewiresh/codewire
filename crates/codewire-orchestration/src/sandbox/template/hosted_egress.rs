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

/// The token, mounted into the workspace container only, and the two
/// addresses the daemon dials instead of names.
pub(super) fn mount_workspace(
    ws: &mut Value,
    volumes: &mut Vec<Value>,
    egress: &HostedEgressTemplate,
) {
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
        .push(json!({
            "name": EGRESS_TOKEN_VOLUME,
            "mountPath": EGRESS_TOKEN_MOUNT_PATH,
            "readOnly": true,
        }));
    let env = ws["env"].as_array_mut().expect("workspace env");
    env.push(json!({ "name": "CODEWIRE_EGRESS_STREAM_ADDR", "value": egress.stream_addr }));
    env.push(json!({ "name": "CODEWIRE_WORKSPACE_BINDING_ADDR", "value": egress.binding_addr }));
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
/// ([`super::TemplateOpts::validate_hosted_egress`]), and it mounts nothing.
pub(super) fn tun_init_container(support_image: &str) -> Value {
    json!({
        "name": TUN_INIT_CONTAINER,
        "image": support_image,
        "command": TUN_INIT_COMMAND,
        "securityContext": { "privileged": true, "runAsUser": 0, "runAsGroup": 0 },
    })
}
