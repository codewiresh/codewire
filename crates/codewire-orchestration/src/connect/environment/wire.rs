//! An environment as the wire carries it. Moved out of `environment.rs`
//! unchanged (#3384).

use super::*;

pub(super) fn proto_environment(
    environment: Environment,
    network_policies: NetworkPolicyFlags,
    idle_stop: crate::worker::idle_stop::IdleStop,
) -> AppResult<proto::Environment> {
    // Unset while the deployment's platform network policies are off (#4000).
    let network_policy = environment
        .network_policy
        .filter(|_| network_policies.enabled)
        .map(super::super::network_policies::proto_environment_policy);
    Ok(proto::Environment {
        id: environment.id,
        org_id: environment.org_id,
        created_by: environment.created_by,
        preset_id: environment.preset_id.unwrap_or_default(),
        r#type: environment.env_type,
        name: environment.name.unwrap_or_default(),
        state: proto_environment_state(&environment.state)?.into(),
        desired_state: proto_desired_state(&environment.desired_state)?.into(),
        error_reason: environment.error_reason.unwrap_or_default(),
        error_code: environment.error_code.unwrap_or_default(),
        stop_reason: environment.stop_reason.unwrap_or_default(),
        idle_stop_seconds: environment.idle_stop_seconds,
        idle_stop_enforced: Some(idle_stop.is_on()),
        recoverable: environment.recoverable,
        state_changed_at: Some(proto_timestamp(&environment.state_changed_at)?).into(),
        retry_count: environment.retry_count,
        setup_phase: environment.setup_phase,
        setup_complete: environment.setup_complete,
        operation_generation: environment.operation_generation,
        source_selection: environment
            .source_selection
            .map(proto_source_selection)
            .into(),
        setup_error: environment.setup_error.unwrap_or_default(),
        ttl_seconds: environment.ttl_seconds,
        shutdown_at: optional_timestamp(environment.shutdown_at)?,
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
        total_running_seconds: environment.total_running_seconds,
        created_at: Some(proto_timestamp(&environment.created_at)?).into(),
        started_at: optional_timestamp(environment.started_at)?,
        stopped_at: optional_timestamp(environment.stopped_at)?,
        destroyed_at: optional_timestamp(environment.destroyed_at)?,
        protected: environment.protected,
        deletion_requested_at: optional_timestamp(environment.deletion_requested_at)?,
        deletion_grace_until: optional_timestamp(environment.deletion_grace_until)?,
        preset_name: environment.preset_name.unwrap_or_default(),
        network_state: proto_network_state(environment.network_state.as_deref())?.into(),
        network_failure: proto_network_failure(environment.network_failure.as_deref())?.into(),
        network: environment.network.unwrap_or_default(),
        network_policy: network_policy.into(),
        ports: environment
            .ports
            .into_iter()
            .map(proto_port)
            .collect::<AppResult<Vec<_>>>()?,
        isolation_tier: match environment.isolation_tier.as_str() {
            "standard" => proto::IsolationTier::Standard.into(),
            "confidential" => proto::IsolationTier::Confidential.into(),
            unexpected => return invalid_stored_value("environment isolation tier", unexpected),
        },
        ..Default::default()
    })
}
