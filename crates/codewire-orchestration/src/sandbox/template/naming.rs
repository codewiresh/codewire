//! DNS-safe object names, labels, and selectors.

use serde_json::{Value, json};

use super::{TemplateOpts, WORKSPACE_DAEMON_PORT};

pub fn workspace_daemon_service_name(env_id: &str) -> String {
    dns_name("cw-daemon", env_id)
}

/// `cw-tailnet-udp-<env>`: the environment's direct-UDP LoadBalancer.
pub fn direct_udp_service_name(env_id: &str) -> String {
    dns_name("cw-tailnet-udp", env_id)
}

pub fn workspace_daemon_network_policy_name(env_id: &str) -> String {
    dns_name("cw-daemon-net", env_id)
}

/// The Pod label the agent-sandbox fork stamps at birth with the owning
/// Sandbox's UID and re-enforces like `sandbox-name-hash` (#2434). Unlike the
/// 32-bit name hash, a UID is never shared by two Sandboxes.
pub const SANDBOX_UID_LABEL: &str = "agents.x-k8s.io/sandbox-uid";

/// `cw-daemon-warm-<env>`: the adopted warm member's half of the bridge.
pub fn warm_member_daemon_bridge_name(env_id: &str) -> String {
    dns_name("cw-daemon-warm", env_id)
}

fn dns_name(prefix: &str, suffix: &str) -> String {
    let suffix = suffix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let mut name = format!("{prefix}-{suffix}");
    if name.len() > 63 {
        name.truncate(63);
    }
    while name.ends_with('-') {
        name.pop();
    }
    if name.is_empty() {
        prefix.to_string()
    } else {
        name
    }
}

pub fn workspace_daemon_service_addr(env_id: &str) -> String {
    format!(
        "{}:{}",
        workspace_daemon_service_name(env_id),
        WORKSPACE_DAEMON_PORT
    )
}

pub(super) fn workspace_selector(opts: &TemplateOpts) -> Value {
    json!({
        "codewire.sh/environment-id": opts.environment_id,
        "codewire.sh/type": "workspace",
    })
}

/// Exactly one adopted warm-pool member: the Sandbox UID its committed
/// binding recorded, and the workspace type. No other label, so neither the
/// claim-time relabel nor a name-hash collision changes what it selects.
pub(super) fn warm_member_selector(sandbox_uid: &str) -> Value {
    json!({
        SANDBOX_UID_LABEL: sandbox_uid,
        "codewire.sh/type": "workspace",
    })
}

pub(super) fn workspace_template_labels() -> Value {
    json!({
        "codewire.sh/type": "workspace",
    })
}
