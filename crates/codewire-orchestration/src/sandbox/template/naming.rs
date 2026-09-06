//! DNS-safe object names, labels, and selectors.

use serde_json::{Value, json};

use super::{RUNTIME_PROFILE_CONFIDENTIAL, TemplateOpts, WORKSPACE_DAEMON_PORT};

pub fn gateway_workload_name(env_id: &str) -> String {
    dns_name("cw-gateway", env_id)
}

pub fn workspace_daemon_service_name(env_id: &str) -> String {
    dns_name("cw-daemon", env_id)
}

pub fn gateway_service_name(env_id: &str) -> String {
    dns_name("cw-gateway-svc", env_id)
}

pub fn gateway_direct_udp_service_name(env_id: &str) -> String {
    dns_name("cw-gateway-udp", env_id)
}

pub fn gateway_network_policy_name(env_id: &str) -> String {
    dns_name("cw-gw-net", env_id)
}

pub fn gateway_host_key_secret_name(env_id: &str) -> String {
    dns_name("cw-gateway-host-key", env_id)
}

pub fn workspace_daemon_network_policy_name(env_id: &str) -> String {
    dns_name("cw-daemon-net", env_id)
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

pub(super) fn workspace_template_labels() -> Value {
    json!({
        "codewire.sh/type": "workspace",
    })
}

pub(super) fn gateway_selector(opts: &TemplateOpts) -> Value {
    json!({
        "codewire.sh/environment-id": opts.environment_id,
        "codewire.sh/type": "gateway",
    })
}

pub(super) fn gateway_labels(opts: &TemplateOpts) -> Value {
    let mut labels = gateway_selector(opts);
    let object = labels.as_object_mut().expect("labels object");
    object.insert(
        "codewire.sh/org-id".into(),
        opts.organization_id.clone().into(),
    );
    object.insert(
        super::super::LABEL_OPERATION_GENERATION.into(),
        opts.operation_generation.to_string().into(),
    );
    object.insert("app.kubernetes.io/name".into(), "codewire-gateway".into());
    object.insert("app.kubernetes.io/component".into(), "gateway".into());
    object.insert("app.kubernetes.io/managed-by".into(), "codewire".into());
    if opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL {
        object.insert("codewire.sh/isolation-tier".into(), "confidential".into());
    }
    labels
}
