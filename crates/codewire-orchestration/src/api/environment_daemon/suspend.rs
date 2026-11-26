//! Asking a `standard` Sandbox's daemon to suspend (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"), for the worker's idle suspend.

use codewire_daemon_proto::daemon::v1;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use super::{authorize, daemon_channel_for_runtime};
use crate::runtime::RuntimeDriver;

/// What the daemon answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonSuspend {
    /// It holds its platform connections and asks for the pause.
    Accepted,
    /// A suspend is already under way.
    NotAccepted,
    /// It can't suspend: a daemon or runtime from before suspend, or one
    /// outside the workload a pause freezes.
    CantSuspend,
}

/// Worker-only: asks the daemon to suspend, under the daemon credential the
/// activity check uses.
pub(crate) async fn environment_daemon_suspend_for_worker(
    pool: &PgPool,
    runtime: Option<&dyn RuntimeDriver>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
) -> AppResult<DaemonSuspend> {
    let (channel, token) =
        daemon_channel_for_runtime(pool, runtime, session_secret, namespace, environment_id)
            .await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    match client
        .suspend(authorize(v1::SuspendRequest {}, &token)?)
        .await
    {
        Ok(response) if response.get_ref().accepted => Ok(DaemonSuspend::Accepted),
        Ok(_) => Ok(DaemonSuspend::NotAccepted),
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Unimplemented | tonic::Code::FailedPrecondition
            ) =>
        {
            Ok(DaemonSuspend::CantSuspend)
        }
        Err(status) => Err(AppError::InternalMsg(
            format!("daemon suspend: {}", status.message()).into(),
        )),
    }
}
