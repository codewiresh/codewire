//! The workspace container's tokens and public roots: mounted into it only,
//! never DinD or an init container, on every runtime profile.

use serde_json::{Value, json};

use codewire_daemon_proto::{
    WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH, WORKSPACE_BINDING_TOKEN_AUDIENCE,
    WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS, WORKSPACE_BINDING_TOKEN_MOUNT_PATH,
};
// The binding recorder recognizes a Pod-scope Pod by this exact volume.
use crate::worker::workspace_binding::WORKSPACE_BINDING_VOLUME;

use super::credentials;
use super::runtime_policy::RUNTIME_PROFILE_CONFIDENTIAL;
use super::{HostedEgressTemplate, ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP, TemplateOpts};

/// The workspace container's tokens and public roots, with their volumes;
/// `mount_egress` places hosted egress's part.
pub(super) fn mount_identity(
    opts: &TemplateOpts,
    ws: &mut Value,
    volumes: &mut Vec<Value>,
    mount_egress: fn(&mut Value, &mut Vec<Value>, &HostedEgressTemplate),
) {
    if opts.credential_runtime.is_some() {
        volumes.extend(credentials::workspace_volumes(opts));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .extend(credentials::workspace_mounts());
        // The bound daemon expands its managed clients into child
        // environments from the bind response; nothing is rendered here.
    }
    if let Some(egress) = &opts.hosted_egress {
        mount_egress(ws, volumes, egress);
    }
    // Workspace container only; never DinD or an init container.
    volumes.push(workspace_binding_token_volume());
    ws["volumeMounts"]
        .as_array_mut()
        .expect("workspace mounts")
        .push(json!({
            "name": WORKSPACE_BINDING_VOLUME,
            "mountPath": WORKSPACE_BINDING_TOKEN_MOUNT_PATH,
            "readOnly": true,
        }));
    // The public roots that verify the binding listener's TLS identity. A
    // confidential workspace mounts none: the host supplies every file there,
    // so its daemon trusts only its measured roots (B2c).
    let confidential = opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL;
    if !confidential {
        volumes.push(workspace_binding_roots_volume());
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .push(json!({
                "name": WORKSPACE_BINDING_ROOTS_VOLUME,
                "mountPath": WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH,
                "readOnly": true,
            }));
    }
    // A local cluster's coordinator is not WebPKI-signed: only there does
    // orchestration mount the public bundle the daemon trusts beside the
    // WebPKI roots for its coordinator. Dev and Production never do, and a
    // confidential daemon never trusts one.
    if opts.coordinator_extra_roots && !confidential {
        volumes.push(coordinator_extra_roots_volume());
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .push(json!({
                "name": COORDINATOR_EXTRA_ROOTS_VOLUME,
                "mountPath": codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_MOUNT_PATH,
                "readOnly": true,
            }));
    }
}

/// The Pod-bound projected token the daemon presents to `BindWorkspace`
/// (design §3.4). Same mode and lifetime as the gateway's binding token.
fn workspace_binding_token_volume() -> Value {
    json!({
        "name": WORKSPACE_BINDING_VOLUME,
        "projected": {
            "defaultMode": 0o440,
            "sources": [{
                "serviceAccountToken": {
                    "audience": WORKSPACE_BINDING_TOKEN_AUDIENCE,
                    "expirationSeconds": WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS,
                    "path": "token",
                },
            }],
        },
    })
}

/// The volume of the binding listener's public roots.
pub(crate) const WORKSPACE_BINDING_ROOTS_VOLUME: &str = "orchestration-internal-roots";

/// Only the `ca.crt` key of orchestration's published internal roots: public
/// trust material, never a credential (daemon-hosted access §6).
fn workspace_binding_roots_volume() -> Value {
    json!({
        "name": WORKSPACE_BINDING_ROOTS_VOLUME,
        "configMap": {
            "name": ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP,
            "items": [{ "key": "ca.crt", "path": "ca.crt" }],
            "defaultMode": 0o444,
        },
    })
}

/// The volume of the coordinator's extra public roots (local clusters only).
pub(crate) const COORDINATOR_EXTRA_ROOTS_VOLUME: &str = "coordinator-extra-roots";

/// Only the `ca.crt` key of the coordinator's extra public roots: public trust
/// material, never a credential.
fn coordinator_extra_roots_volume() -> Value {
    json!({
        "name": COORDINATOR_EXTRA_ROOTS_VOLUME,
        "configMap": {
            "name": codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_CONFIGMAP,
            "items": [{ "key": "ca.crt", "path": "ca.crt" }],
            "defaultMode": 0o444,
        },
    })
}
