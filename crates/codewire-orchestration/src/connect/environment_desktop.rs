//! Platform ownership for the shared public `EnvironmentDesktopService`
//! daemon bridge (`docs/dev/SANDBOX-DESKTOP.md`, "Starting and stopping"):
//! who may call it, which daemon answers, and how a refusal is worded. The
//! bridge vets what the daemon answers; the viewer password a running
//! desktop carries passes through to the authorized caller, under the
//! no-store policy every authenticated Connect response gets.

use async_trait::async_trait;
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::desktop::{DesktopBackend, DesktopCall, DesktopRefusal};
use codewire_server_core::AppError;
use codewire_server_core::connect::{auth_user, wire_error};
use connectrpc::RequestContext;

use crate::api::ApiState;
use crate::api::environment_daemon::environment_desktop_daemon_core;
use crate::connect::rendered_workspace_error;

const DAEMON_UPGRADE_REQUIRED: &str =
    "environment daemon upgrade is required; run `cw daemon repair`";

pub fn router(state: ApiState) -> connectrpc::Router {
    codewire_daemon_bridge::desktop::router(PlatformDesktopBackend { state })
}

#[derive(Clone)]
struct PlatformDesktopBackend {
    state: ApiState,
}

#[async_trait]
impl DesktopBackend for PlatformDesktopBackend {
    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        auth_user(ctx).map(|_| ())
    }

    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        call: DesktopCall,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        let user = auth_user(ctx)?.clone();
        environment_desktop_daemon_core(&self.state, &user, org_id, environment_id, call)
            .await
            .map_err(|error| render(&error, request_id(ctx)))
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        render(&daemon_error(error), request_id)
    }

    fn refusal(
        &self,
        refusal: DesktopRefusal,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        // The refusal's name alone: nothing of the daemon's own text exists
        // by this point.
        tracing::warn!(?refusal, "environment desktop call refused");
        render(&refusal_error(refusal), request_id)
    }
}

/// A daemon that is not ready for a desktop call. The variants' own text is
/// the daemon's and is not read.
fn daemon_error(error: DaemonClientError) -> AppError {
    use codewire_daemon_proto::daemon::v1::DaemonState;

    match error {
        // Transient: nothing has run, so clients wait it out (#4311).
        DaemonClientError::NotReady {
            state: DaemonState::Starting,
            ..
        } => AppError::ServiceUnavailable("environment daemon is still starting".into()),
        DaemonClientError::NotReady {
            state: DaemonState::Unsupported | DaemonState::UpgradeRequired,
            ..
        }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            AppError::Precondition(DAEMON_UPGRADE_REQUIRED.into())
        }
        DaemonClientError::NotReady { .. } => {
            AppError::Precondition("environment daemon is not ready; run `cw daemon status`".into())
        }
        DaemonClientError::InvalidEndpoint | DaemonClientError::InvalidCredential => {
            AppError::InternalMsg("failed to authorize environment daemon".into())
        }
        _ => AppError::Upstream(DesktopRefusal::TransportLost.sentence().into()),
    }
}

fn refusal_error(refusal: DesktopRefusal) -> AppError {
    match refusal {
        DesktopRefusal::NoDesktopInImage | DesktopRefusal::DidNotStart => {
            AppError::Precondition(refusal.sentence().into())
        }
        DesktopRefusal::DaemonTooOld => AppError::Precondition(DAEMON_UPGRADE_REQUIRED.into()),
        DesktopRefusal::LaunchDenied
        | DesktopRefusal::NotReadyInTime
        | DesktopRefusal::TransportLost
        | DesktopRefusal::InvalidAnswer => AppError::Upstream(refusal.sentence().into()),
        DesktopRefusal::Failed => AppError::InternalMsg(refusal.sentence().into()),
    }
}

fn render(error: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    wire_error(&rendered_workspace_error(error, request_id))
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use codewire_daemon_proto::daemon::v1::DaemonState;

    use super::*;

    /// What a replaced daemon might put wherever it can write text.
    const WORKLOAD_TEXT: &str = "workload-chosen-text-not-for-callers";

    #[test]
    fn each_refusal_has_its_kind_of_error_and_an_old_daemon_gets_the_repair() {
        for refusal in [
            DesktopRefusal::NoDesktopInImage,
            DesktopRefusal::DidNotStart,
        ] {
            let error = refusal_error(refusal);
            assert!(
                matches!(&error, AppError::Precondition(reason) if reason == refusal.sentence()),
                "{refusal:?}: {error:?}"
            );
        }
        for refusal in [
            DesktopRefusal::LaunchDenied,
            DesktopRefusal::NotReadyInTime,
            DesktopRefusal::TransportLost,
            DesktopRefusal::InvalidAnswer,
        ] {
            let error = refusal_error(refusal);
            assert!(
                matches!(&error, AppError::Upstream(reason) if reason == refusal.sentence()),
                "{refusal:?}: {error:?}"
            );
        }
        let old = refusal_error(DesktopRefusal::DaemonTooOld);
        assert!(
            matches!(&old, AppError::Precondition(reason) if reason.contains("cw daemon repair")),
            "{old:?}"
        );
        assert!(matches!(
            refusal_error(DesktopRefusal::Failed),
            AppError::InternalMsg(_)
        ));
    }

    #[test]
    fn a_daemon_that_is_not_ready_is_told_without_its_own_text() {
        let not_ready = |state| DaemonClientError::NotReady {
            state,
            message: WORKLOAD_TEXT.into(),
        };
        let cases = [
            (not_ready(DaemonState::Starting), "still starting"),
            (not_ready(DaemonState::UpgradeRequired), "cw daemon repair"),
            (not_ready(DaemonState::Unsupported), "cw daemon repair"),
            (not_ready(DaemonState::Unhealthy), "cw daemon status"),
            (
                DaemonClientError::MissingCapability {
                    capability: WORKLOAD_TEXT.into(),
                },
                "cw daemon repair",
            ),
            (
                DaemonClientError::Status(tonic::Status::unavailable(WORKLOAD_TEXT)),
                "transport was lost",
            ),
            (DaemonClientError::Connect, "transport was lost"),
        ];
        for (error, expected) in cases {
            let rendered = daemon_error(error);
            let text = format!("{rendered:?} {rendered}");
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("workload-chosen"), "{text}");
        }
    }
}
