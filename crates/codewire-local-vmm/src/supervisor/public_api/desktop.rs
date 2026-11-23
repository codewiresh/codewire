//! Local ownership for the shared public `EnvironmentDesktopService` daemon
//! bridge (`docs/dev/SANDBOX-DESKTOP.md`, "Starting and stopping"): the VM's
//! owner, over the owner-only socket, reaches the guest daemon through the
//! supervisor and never holds its credential. The bridge vets what the
//! daemon answers, as it does for a hosted Sandbox.

use async_trait::async_trait;
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::desktop::{DesktopBackend, DesktopCall, DesktopRefusal};
use codewire_daemon_proto::daemon::v1::DaemonState;
use connectrpc::RequestContext;

use super::{SupervisorRpc, enforce_connect_only};

const PUBLIC_DESKTOP_ROUTE: &str = "/codewire.v1.EnvironmentDesktopService/{*method}";

/// A stop and a start move a VM onto the installed runtime.
const RUNTIME_PREDATES_THE_DESKTOP: &str =
    "this local VM's runtime predates the desktop; stop and start it to use it";

pub(super) fn router(supervisor: SupervisorRpc) -> axum::Router {
    let desktop = connectrpc::ConnectRpcService::new(codewire_daemon_bridge::desktop::router(
        LocalDesktopBackend { supervisor },
    ));
    axum::Router::new()
        .route_service(PUBLIC_DESKTOP_ROUTE, desktop)
        .layer(axum::middleware::from_fn(enforce_connect_only))
}

#[derive(Clone)]
struct LocalDesktopBackend {
    supervisor: SupervisorRpc,
}

#[async_trait]
impl DesktopBackend for LocalDesktopBackend {
    /// The socket admits its owner alone, and that check is the whole
    /// authorization: this admits every caller that reaches it. The router
    /// must therefore be mounted on the owner-only socket and nowhere else.
    fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        Ok(())
    }

    async fn daemon(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        _call: DesktopCall,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        self.supervisor
            .public_bridge_daemon_client(org_id, environment_id)
            .await
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_desktop_daemon_error(error)
    }

    fn refusal(
        &self,
        refusal: DesktopRefusal,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_desktop_refusal(refusal)
    }
}

/// A guest daemon that is not ready for a desktop call. The variants' own
/// text is the guest's and is not read.
fn local_desktop_daemon_error(error: DaemonClientError) -> connectrpc::ConnectError {
    match error {
        DaemonClientError::NotReady {
            state: DaemonState::Starting,
            ..
        } => connectrpc::ConnectError::unavailable("local environment daemon is still starting"),
        DaemonClientError::NotReady {
            state: DaemonState::Unsupported | DaemonState::UpgradeRequired,
            ..
        }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            connectrpc::ConnectError::failed_precondition(RUNTIME_PREDATES_THE_DESKTOP)
        }
        DaemonClientError::NotReady { .. } => connectrpc::ConnectError::failed_precondition(
            "local environment daemon is not ready for the desktop",
        ),
        DaemonClientError::InvalidEndpoint | DaemonClientError::InvalidCredential => {
            connectrpc::ConnectError::internal("local environment desktop request failed")
        }
        _ => connectrpc::ConnectError::unavailable(DesktopRefusal::TransportLost.sentence()),
    }
}

fn local_desktop_refusal(refusal: DesktopRefusal) -> connectrpc::ConnectError {
    match refusal {
        DesktopRefusal::NoDesktopInImage | DesktopRefusal::DidNotStart => {
            connectrpc::ConnectError::failed_precondition(refusal.sentence())
        }
        DesktopRefusal::DaemonTooOld => {
            connectrpc::ConnectError::failed_precondition(RUNTIME_PREDATES_THE_DESKTOP)
        }
        DesktopRefusal::LaunchDenied
        | DesktopRefusal::NotReadyInTime
        | DesktopRefusal::TransportLost
        | DesktopRefusal::InvalidAnswer => {
            connectrpc::ConnectError::unavailable(refusal.sentence())
        }
        DesktopRefusal::Failed => connectrpc::ConnectError::internal(refusal.sentence()),
    }
}

#[cfg(test)]
mod tests {
    use connectrpc::ErrorCode;

    use super::*;

    /// What a guest might put wherever it can write text.
    const GUEST_TEXT: &str = "guest-chosen-text-not-for-the-owner";

    #[test]
    fn an_older_runtime_is_told_how_to_move_onto_the_installed_one() {
        for error in [
            DaemonClientError::MissingCapability {
                capability: GUEST_TEXT.into(),
            },
            DaemonClientError::NotReady {
                state: DaemonState::UpgradeRequired,
                message: GUEST_TEXT.into(),
            },
        ] {
            let refused = local_desktop_daemon_error(error);
            assert_eq!(refused.code, ErrorCode::FailedPrecondition);
            assert_eq!(
                refused.message.as_deref(),
                Some(RUNTIME_PREDATES_THE_DESKTOP)
            );
        }
        let old = local_desktop_refusal(DesktopRefusal::DaemonTooOld);
        assert_eq!(old.message.as_deref(), Some(RUNTIME_PREDATES_THE_DESKTOP));
    }

    #[test]
    fn no_refusal_carries_the_guests_text_and_each_has_its_code() {
        for (error, code) in [
            (
                DaemonClientError::NotReady {
                    state: DaemonState::Starting,
                    message: GUEST_TEXT.into(),
                },
                ErrorCode::Unavailable,
            ),
            (
                DaemonClientError::NotReady {
                    state: DaemonState::Unhealthy,
                    message: GUEST_TEXT.into(),
                },
                ErrorCode::FailedPrecondition,
            ),
            (
                DaemonClientError::Status(tonic::Status::internal(GUEST_TEXT)),
                ErrorCode::Unavailable,
            ),
            (DaemonClientError::Connect, ErrorCode::Unavailable),
        ] {
            let refused = local_desktop_daemon_error(error);
            assert_eq!(refused.code, code, "{refused:?}");
            assert!(
                !format!("{refused:?}").contains("guest-chosen"),
                "{refused:?}"
            );
        }
        for (refusal, code) in [
            (
                DesktopRefusal::NoDesktopInImage,
                ErrorCode::FailedPrecondition,
            ),
            (DesktopRefusal::DidNotStart, ErrorCode::FailedPrecondition),
            (DesktopRefusal::LaunchDenied, ErrorCode::Unavailable),
            (DesktopRefusal::NotReadyInTime, ErrorCode::Unavailable),
            (DesktopRefusal::TransportLost, ErrorCode::Unavailable),
            (DesktopRefusal::InvalidAnswer, ErrorCode::Unavailable),
            (DesktopRefusal::Failed, ErrorCode::Internal),
        ] {
            let refused = local_desktop_refusal(refusal);
            assert_eq!(refused.code, code, "{refusal:?}");
            assert_eq!(refused.message.as_deref(), Some(refusal.sentence()));
        }
    }
}
