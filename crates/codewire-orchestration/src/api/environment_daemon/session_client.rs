//! The daemon client every session call starts from: the environment's
//! target, in a sandbox or on a host, a channel to its daemon, and a prompt
//! readiness check.

use super::*;

pub(super) async fn session_client_for_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    required_capabilities: &[&str],
    budget: DaemonRequestBudget,
) -> AppResult<(
    v1::daemon_service_client::DaemonServiceClient<Channel>,
    String,
)> {
    let target = super::super::proxy::resolve_running_target(state, user, org_id, environment_id)
        .await
        .map_err(|(status, message)| huma_error(status, message))?;
    let (channel, token) = daemon_channel(state, target, budget).await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    // Even a launch-budget channel must prove readiness promptly. Do not let
    // this pre-dispatch probe inherit the longer process-start deadline.
    tokio::time::timeout(
        DAEMON_CONTROL_TIMEOUT,
        require_ready_daemon(&mut client, &token, required_capabilities),
    )
    .await
    .map_err(|_| AppError::Upstream("environment daemon is unavailable".into()))??;
    Ok((client, token))
}

/// A channel to a running environment's daemon, wherever it runs: in a
/// sandbox, or on a host through its session's tunnel (#3609).
pub(super) async fn daemon_channel(
    state: &ApiState,
    target: super::super::proxy::RunningTarget,
    budget: DaemonRequestBudget,
) -> AppResult<(Channel, String)> {
    Ok(match target {
        super::super::proxy::RunningTarget::Host(target) => {
            super::host_daemon::host_daemon_channel(state.host_tunnels.clone(), target, budget)
                .await?
        }
        super::super::proxy::RunningTarget::Sandbox(target) => {
            if state.runtime.is_none() {
                return Err(AppError::ServiceUnavailable(
                    "sandbox client not configured".into(),
                ));
            }
            daemon_channel_for_endpoint(
                &state.pool,
                state.runtime.as_deref(),
                &state.session_secret,
                &target.environment_id,
                state
                    .environment_daemon_endpoints
                    .endpoint(&target.namespace, &target.environment_id),
                budget,
            )
            .await?
        }
    })
}
