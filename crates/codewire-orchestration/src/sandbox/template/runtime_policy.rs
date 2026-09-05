//! Pure sandbox runtime-profile and resource policy.

use super::{
    CONFIDENTIAL_WORKSPACE_STORAGE_CLASS, DEFAULT_DIND_IMAGE, DEFAULT_WORKSPACE_STORAGE_CLASS,
    TemplateOpts,
};

pub const RUNTIME_CLASS_RUNC: &str = "runc";
pub const RUNTIME_CLASS_COMMODITY: &str = "commodity";
pub const RUNTIME_CLASS_CONFIDENTIAL: &str = "confidential";
pub const RUNTIME_PROFILE_NONE: &str = "none";
pub const RUNTIME_PROFILE_RUNC: &str = "runc";
pub const RUNTIME_PROFILE_COMMODITY: &str = "commodity";
pub const RUNTIME_PROFILE_CONFIDENTIAL: &str = "confidential";
pub const DOCKER_MODE_PROFILE_DEFAULT: &str = "profile-default";
pub const DOCKER_MODE_NONE: &str = "none";
pub const DOCKER_MODE_LOCAL_DIND_DIRECT: &str = "local-dind-direct";
pub const DOCKER_MODE_GUEST_DIND: &str = "guest-dind";
pub const KATA_COCO_IMAGE_RESOURCE_TIMEOUT_SECS: u32 = 300;
const KATA_AGENT_LOG_VPORT: u16 = 1025;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RuntimeProfileSpec {
    pub profile: String,
    pub runtime_class_name: String,
    pub docker_mode: String,
}

pub fn runtime_profile_spec(
    profile: &str,
    docker_mode: &str,
    dind_enabled: bool,
) -> RuntimeProfileSpec {
    let profile = profile.trim().to_string();

    RuntimeProfileSpec {
        runtime_class_name: runtime_class_for_profile(&profile),
        docker_mode: resolve_docker_mode(&profile, docker_mode, dind_enabled),
        profile,
    }
}

pub fn validate_managed_runtime_profile(
    spec: &RuntimeProfileSpec,
    allow_diagnostic: bool,
) -> Result<(), String> {
    match spec.profile.as_str() {
        RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL => Ok(()),
        RUNTIME_PROFILE_RUNC | RUNTIME_PROFILE_NONE => {
            if allow_diagnostic {
                Ok(())
            } else {
                Err(format!(
                    "managed sandboxes require an approved runtime profile; {:?} is diagnostic-only",
                    spec.profile
                ))
            }
        }
        "" => Err("managed sandboxes require SANDBOX_RUNTIME_PROFILE".to_string()),
        other => Err(format!(
            "unsupported managed sandbox runtime profile {other:?}"
        )),
    }?;
    match spec.docker_mode.as_str() {
        DOCKER_MODE_NONE | DOCKER_MODE_LOCAL_DIND_DIRECT | DOCKER_MODE_GUEST_DIND => Ok(()),
        other => Err(format!("unsupported managed sandbox Docker mode {other:?}")),
    }
}

fn runtime_class_for_profile(profile: &str) -> String {
    match profile {
        RUNTIME_PROFILE_NONE => String::new(),
        RUNTIME_PROFILE_RUNC => RUNTIME_CLASS_RUNC.to_string(),
        RUNTIME_PROFILE_COMMODITY => RUNTIME_CLASS_COMMODITY.to_string(),
        RUNTIME_PROFILE_CONFIDENTIAL => RUNTIME_CLASS_CONFIDENTIAL.to_string(),
        _ => profile.to_string(),
    }
}

fn resolve_docker_mode(profile: &str, docker_mode: &str, dind_enabled: bool) -> String {
    let docker_mode = docker_mode.trim();
    if !docker_mode.is_empty() && docker_mode != DOCKER_MODE_PROFILE_DEFAULT {
        return docker_mode.to_string();
    }
    if dind_enabled {
        return DOCKER_MODE_LOCAL_DIND_DIRECT.to_string();
    }
    match profile {
        RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL => {
            DOCKER_MODE_GUEST_DIND.to_string()
        }
        _ => DOCKER_MODE_NONE.to_string(),
    }
}

pub(super) fn uses_kata_policy_init_data(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
) -> bool {
    let profile = runtime_spec.profile.as_str();
    (opts.kata_agent_policy_enabled
        && matches!(
            profile,
            RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL
        ))
        || (opts.kata_coco_init_data_enabled && matches!(profile, RUNTIME_PROFILE_CONFIDENTIAL))
}

pub(super) fn kata_coco_kernel_params_annotation(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
) -> Option<String> {
    if runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL || !opts.kata_coco_init_data_enabled {
        return None;
    }
    let kbs_url = kernel_param_value(&opts.kata_coco_kbs_url)?;
    let mut params = Vec::new();
    let auth_uri = opts.kata_coco_image_registry_auth_uri.trim();
    if !auth_uri.is_empty() {
        let auth_uri = kernel_param_value(auth_uri)?;
        params.push(format!("agent.image_registry_auth={auth_uri}"));
    }
    params.push(format!(
        "agent.image_resource_timeout_secs={KATA_COCO_IMAGE_RESOURCE_TIMEOUT_SECS}"
    ));
    // The Pod shares the guest network namespace. Starting api-server-rest
    // would therefore expose its unauthenticated resource and attestation
    // routes to workload containers. The Agent needs AA and CDH only.
    params.push("agent.guest_components_procs=confidential-data-hub".to_string());
    params.push(format!("agent.aa_kbc_params=cc_kbc::{kbs_url}"));
    // runtime-rs already forwards the guest agent's bounded INFO+ log stream
    // from this vsock port. Without the guest listener, CDH failures collapse
    // to a generic ttRPC status before they reach the node's CRI log.
    params.push(format!("agent.log_vport={KATA_AGENT_LOG_VPORT}"));
    Some(params.join(" "))
}

fn kernel_param_value(raw: &str) -> Option<&str> {
    let value = raw.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        None
    } else {
        Some(value)
    }
}

pub(super) fn workspace_storage_class(opts: &TemplateOpts) -> &str {
    if opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL {
        return CONFIDENTIAL_WORKSPACE_STORAGE_CLASS;
    }
    let storage_class = opts.workspace_storage_class.trim();
    if storage_class.is_empty() {
        DEFAULT_WORKSPACE_STORAGE_CLASS
    } else {
        storage_class
    }
}

pub(super) fn docker_data_size_gib(disk_gib: i64) -> i64 {
    if disk_gib <= 0 {
        return 8;
    }
    if disk_gib <= 4 {
        return 2;
    }
    disk_gib - 2
}

pub(super) fn dind_memory_limit_gib(memory_mib: i64) -> i64 {
    if memory_mib >= 8192 { 4 } else { 2 }
}

pub(super) fn dind_image(opts: &TemplateOpts) -> &str {
    let image = opts.dind_image.trim();
    if image.is_empty() {
        DEFAULT_DIND_IMAGE
    } else {
        image
    }
}
