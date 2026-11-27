//! An environment from its wire form. Moved out of `environment_client.rs`
//! unchanged (#3384).

use super::*;

pub(super) fn environment_from_proto(value: rpc::Environment) -> anyhow::Result<Environment> {
    let state = setup::environment_state_token(&value.state);
    let desired_state = setup::desired_state_token(&value.desired_state);
    let (egress_enforcement, egress_failure) = match value.network_policy.as_option() {
        Some(policy) => (
            egress_enforcement(policy.enforcement),
            empty_to_none(policy.failure_code.clone()),
        ),
        None => (None, None),
    };
    Ok(Environment {
        network_policy: value
            .network_policy
            .as_option()
            .map(environment_network_policy_from_proto),
        operation_generation: value.operation_generation,
        source_selection: value
            .source_selection
            .into_option()
            .map(source_selection_from_proto)
            .transpose()?,
        id: value.id,
        org_id: value.org_id,
        created_by: value.created_by,
        preset_id: value.preset_id,
        environment_type: value.r#type,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                "standard".into()
            }
        },
        name: empty_to_none(value.name),
        state: state.to_string(),
        desired_state: desired_state.to_string(),
        error_reason: empty_to_none(value.error_reason),
        error_code: empty_to_none(value.error_code),
        stop_reason: empty_to_none(value.stop_reason),
        idle_stop_seconds: value.idle_stop_seconds,
        idle_stop_enforced: value.idle_stop_enforced,
        idle_suspend_seconds: value.idle_suspend_seconds,
        suspended_at: value.suspended_at.into_option().map(timestamp_to_rfc3339),
        idle_hibernate_seconds: value.idle_hibernate_seconds,
        hibernated_at: value.hibernated_at.into_option().map(timestamp_to_rfc3339),
        hibernate_reason: empty_to_none(value.hibernate_reason),
        hibernate_fallback_reason: empty_to_none(value.hibernate_fallback_reason),
        restarted_at: value.restarted_at.into_option().map(timestamp_to_rfc3339),
        restart_cause: empty_to_none(value.restart_cause),
        host: value
            .host
            .into_option()
            .map(|host| crate::presentation::EnvironmentHost {
                id: host.id,
                name: host.name,
            }),
        recoverable: value.recoverable,
        state_changed_at: value
            .state_changed_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        retry_count: value.retry_count,
        setup_phase: value.setup_phase,
        setup_complete: value.setup_complete,
        setup_error: empty_to_none(value.setup_error),
        ttl_seconds: value.ttl_seconds,
        shutdown_at: value.shutdown_at.into_option().map(timestamp_to_rfc3339),
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
        total_running_seconds: value.total_running_seconds,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        started_at: value.started_at.into_option().map(timestamp_to_rfc3339),
        stopped_at: value.stopped_at.into_option().map(timestamp_to_rfc3339),
        destroyed_at: value.destroyed_at.into_option().map(timestamp_to_rfc3339),
        protected: value.protected,
        deletion_requested_at: value
            .deletion_requested_at
            .into_option()
            .map(timestamp_to_rfc3339),
        deletion_grace_until: value
            .deletion_grace_until
            .into_option()
            .map(timestamp_to_rfc3339),
        network_state: network_state(value.network_state),
        network_failure: network_failure(value.network_failure),
        network: empty_to_none(value.network),
        egress_enforcement,
        egress_failure,
    })
}
