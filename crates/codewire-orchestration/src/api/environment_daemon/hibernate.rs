//! Asking a `standard` Sandbox's daemon to hibernate (#6647,
//! `docs/dev/SANDBOX-SLEEP.md`, "Hibernating a Sandbox").

use codewire_daemon_proto::daemon::v1;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use super::{authorize, daemon_channel_for_runtime};
use crate::runtime::RuntimeDriver;

/// What the daemon answered to a hibernate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonHibernate {
    /// The daemon wiped its credential, closed platform connections, and
    /// armed `cw __pod-runtime` to hibernate the VM.
    Accepted,
    /// A hibernate is already in progress.
    NotAccepted,
    /// This Sandbox's daemon or runtime cannot hibernate (older daemon,
    /// non-standard profile, or running outside the hibernate-capable guest).
    CantHibernate,
}

/// Worker-only: asks the daemon to hibernate, under the bound Pod's daemon
/// credential. If the VM is currently suspended in its Pod, connecting to port
/// `7777` wakes it first so the hibernate handoff runs uniformly.
pub(crate) async fn environment_daemon_hibernate_for_worker(
    pool: &PgPool,
    runtime: Option<&dyn RuntimeDriver>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
) -> AppResult<DaemonHibernate> {
    let (channel, token) =
        daemon_channel_for_runtime(pool, runtime, session_secret, namespace, environment_id)
            .await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    match client
        .hibernate(authorize(v1::HibernateRequest {}, &token)?)
        .await
    {
        Ok(response) if response.get_ref().accepted => Ok(DaemonHibernate::Accepted),
        Ok(_) => Ok(DaemonHibernate::NotAccepted),
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Unimplemented | tonic::Code::FailedPrecondition
            ) =>
        {
            tracing::info!(
                environment_id,
                code = ?status.code(),
                reason = status.message(),
                "daemon can't hibernate"
            );
            Ok(DaemonHibernate::CantHibernate)
        }
        Err(status) => Err(AppError::InternalMsg(
            format!("daemon hibernate: {}", status.message()).into(),
        )),
    }
}
