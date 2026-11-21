//! The daemon of an environment whose caller asks for its desktop
//! (`docs/dev/SANDBOX-DESKTOP.md`, "Starting and stopping"). The caller is
//! authorized as for a terminal: operator access to a running, current and
//! claimed Sandbox. The daemon is reached with the bound Pod's credential,
//! and what it answers is vetted by the shared desktop bridge.

use codewire_daemon_bridge::client::DaemonClient;
use codewire_daemon_bridge::desktop::DesktopCall;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};

use super::{DaemonRequestBudget, daemon_channel_for_endpoint, resolve_target};
use crate::api::ApiState;

/// A start answers only once the desktop accepts a viewer, within the
/// daemon's own ten seconds, so it gets the launch budget.
pub(crate) async fn environment_desktop_daemon_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    call: DesktopCall,
) -> AppResult<DaemonClient> {
    let budget = match call {
        DesktopCall::Start => DaemonRequestBudget::Launch,
        DesktopCall::Read | DesktopCall::Stop => DaemonRequestBudget::Control,
    };
    let target = resolve_target(state, user, org_id, environment_id).await?;
    let (channel, token) = daemon_channel_for_endpoint(
        &state.pool,
        state.runtime.as_deref(),
        &state.session_secret,
        &target.environment_id,
        state
            .environment_daemon_endpoints
            .endpoint(&target.namespace, &target.environment_id),
        budget,
    )
    .await?;
    DaemonClient::from_channel(channel, token)
        .map_err(|_| AppError::InternalMsg("failed to authorize environment daemon".into()))
}
