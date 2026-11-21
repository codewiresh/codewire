//! What a Sandbox's daemon says about its activity, for idle stop (#3384).

use codewire_daemon_proto::daemon::v1;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use super::{authorize, daemon_channel_for_runtime};
use crate::runtime::RuntimeDriver;

/// What the daemon answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonActivity {
    /// Unix seconds of the last minute it saw in use, if any since it started.
    LastActive(Option<i64>),
    /// A daemon older than `GetActivity`. It cannot say, so its Sandbox
    /// counts as in use until a start gives it a daemon that can.
    Unsupported,
}

/// Worker-only: when the Sandbox was last in use as its daemon saw it. Read
/// by the idle check, which it can only hold off; it changes nothing. With
/// `include_guest_cpu`, a busy minute of the whole guest counts too.
pub(crate) async fn environment_daemon_activity_for_worker(
    pool: &PgPool,
    runtime: Option<&dyn RuntimeDriver>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
    include_guest_cpu: bool,
) -> AppResult<DaemonActivity> {
    let (channel, token) =
        daemon_channel_for_runtime(pool, runtime, session_secret, namespace, environment_id)
            .await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    let request = v1::GetActivityRequest { include_guest_cpu };
    match client.get_activity(authorize(request, &token)?).await {
        Ok(response) => Ok(DaemonActivity::LastActive(
            response
                .into_inner()
                .last_active_at
                .map(|timestamp| timestamp.seconds),
        )),
        Err(status) if status.code() == tonic::Code::Unimplemented => {
            Ok(DaemonActivity::Unsupported)
        }
        Err(status) => Err(AppError::InternalMsg(
            format!("daemon activity: {}", status.message()).into(),
        )),
    }
}
