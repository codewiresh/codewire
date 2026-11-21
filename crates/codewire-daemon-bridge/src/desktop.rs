//! Shared public `EnvironmentDesktopService` adapter for the private guest
//! daemon (`docs/dev/SANDBOX-DESKTOP.md`, "Starting and stopping").
//!
//! Platform and local backends own coordinate authorization, daemon
//! discovery and the wording of an error. This module owns the daemon calls
//! and what may come back from them. A Sandbox's daemon can be replaced from
//! inside the Sandbox, so everything it answers is the workload's own text:
//! a refusal's message is never read, only its code, and an answer is passed
//! on only in the one shape the real daemon gives it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use buffa_types::Timestamp;
use codewire_daemon_proto::daemon::v1 as daemon;
use codewire_daemon_proto::{DAEMON_CAPABILITY_DESKTOP_VNC, vetted_desktop};
use codewire_proto::codewire::v1 as proto;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::client::{DaemonClient, DaemonClientError};

/// What an unavailable desktop says of itself, in place of the daemon's
/// reason.
pub const NO_DESKTOP_IN_IMAGE: &str =
    "this environment's image has no desktop; create the environment again on the current image";

/// How long the daemon may take to say it is ready and has the capability,
/// whatever deadline the call itself was given.
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Which call a daemon is wanted for. A start answers only once the desktop
/// accepts a viewer, so a backend gives it its longer deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopCall {
    Start,
    Read,
    Stop,
}

/// Why a desktop call was refused. A backend words each in its own error
/// shape; [`DesktopRefusal::sentence`] is what there is to say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopRefusal {
    NoDesktopInImage,
    /// A held display or port, or a session in the way.
    DidNotStart,
    NotReadyInTime,
    /// The daemon does not know the desktop calls. A backend names its own
    /// repair.
    DaemonTooOld,
    TransportLost,
    /// An answer that is not the real daemon's.
    InvalidAnswer,
    Failed,
}

impl DesktopRefusal {
    pub fn sentence(self) -> &'static str {
        match self {
            Self::NoDesktopInImage => NO_DESKTOP_IN_IMAGE,
            Self::DidNotStart => {
                "the desktop did not start: another process in the environment may hold display \
                 :1 or port 5901, or a session named codewire-desktop is in the way; the \
                 codewire-desktop session's output says which"
            }
            Self::NotReadyInTime => {
                "the desktop was not ready in time; start it again, and read the \
                 codewire-desktop session's output if it repeats"
            }
            Self::DaemonTooOld => "the environment's daemon is too old for the desktop",
            Self::TransportLost => "environment desktop transport was lost",
            Self::InvalidAnswer => "environment daemon returned an invalid desktop",
            Self::Failed => "environment desktop request failed",
        }
    }
}

#[async_trait]
pub trait DesktopBackend: Clone + Send + Sync + 'static {
    fn authorize(&self, ctx: &RequestContext) -> Result<(), connectrpc::ConnectError>;

    /// The environment's daemon, for a caller who may open a terminal there.
    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        call: DesktopCall,
    ) -> Result<DaemonClient, connectrpc::ConnectError>;

    /// A daemon that is not ready, lacks the capability or cannot be
    /// reached, before any desktop call was made.
    fn daemon_error(
        &self,
        error: DaemonClientError,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;

    fn refusal(
        &self,
        refusal: DesktopRefusal,
        request_id: Option<&str>,
    ) -> connectrpc::ConnectError;
}

#[derive(Clone)]
pub struct DesktopBridge<B> {
    backend: B,
}

pub fn router<B>(backend: B) -> connectrpc::Router
where
    B: DesktopBackend,
{
    connectrpc::Router::new().add_service(Arc::new(DesktopBridge { backend }))
}

impl<B: DesktopBackend> DesktopBridge<B> {
    /// A daemon that has said it is ready and has the capability.
    async fn daemon(
        &self,
        ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        call: DesktopCall,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        self.backend.authorize(ctx)?;
        let daemon = self
            .backend
            .daemon(ctx, org_id, environment_id, call)
            .await?;
        let ready = daemon.require_ready(&[DAEMON_CAPABILITY_DESKTOP_VNC]);
        match tokio::time::timeout(READINESS_TIMEOUT, ready).await {
            Ok(Ok(_)) => Ok(daemon),
            Ok(Err(error)) => Err(self.backend.daemon_error(error, request_id(ctx))),
            Err(_) => Err(self.refused(ctx, DesktopRefusal::TransportLost)),
        }
    }

    fn refused(&self, ctx: &RequestContext, refusal: DesktopRefusal) -> connectrpc::ConnectError {
        self.backend.refusal(refusal, request_id(ctx))
    }

    fn answered(
        &self,
        ctx: &RequestContext,
        answer: Result<Option<daemon::Desktop>, tonic::Status>,
    ) -> Result<proto::EnvironmentDesktop, connectrpc::ConnectError> {
        let answer = answer.map_err(|refusal| self.refused(ctx, status_refusal(&refusal)))?;
        vetted_desktop(answer, NO_DESKTOP_IN_IMAGE)
            .map(proto_desktop)
            .ok_or_else(|| self.refused(ctx, DesktopRefusal::InvalidAnswer))
    }
}

#[allow(refining_impl_trait)]
impl<B> proto::EnvironmentDesktopService for DesktopBridge<B>
where
    B: DesktopBackend,
{
    async fn start_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StartDesktopRequest>,
    ) -> ServiceResult<proto::StartDesktopResponse> {
        let request = request.view();
        let daemon = self
            .daemon(
                &ctx,
                request.org_id,
                request.environment_id,
                DesktopCall::Start,
            )
            .await?;
        let desktop = match daemon.start_desktop().await {
            // The daemon's sentence says which refusal this is, and is not
            // read. Its state does: an image with no desktop reads
            // unavailable, and anything else left the desktop unstarted.
            Err(refusal) if refusal.code() == tonic::Code::FailedPrecondition => {
                let read = daemon.get_desktop().await;
                return Err(self.refused(&ctx, start_refusal(read)));
            }
            answer => self.answered(&ctx, answer)?,
        };
        connectrpc::Response::ok(proto::StartDesktopResponse {
            desktop: Some(desktop).into(),
            ..Default::default()
        })
    }

    async fn get_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetDesktopRequest>,
    ) -> ServiceResult<proto::GetDesktopResponse> {
        let request = request.view();
        let daemon = self
            .daemon(
                &ctx,
                request.org_id,
                request.environment_id,
                DesktopCall::Read,
            )
            .await?;
        let desktop = self.answered(&ctx, daemon.get_desktop().await)?;
        connectrpc::Response::ok(proto::GetDesktopResponse {
            desktop: Some(desktop).into(),
            ..Default::default()
        })
    }

    async fn stop_desktop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopDesktopRequest>,
    ) -> ServiceResult<proto::StopDesktopResponse> {
        let request = request.view();
        let daemon = self
            .daemon(
                &ctx,
                request.org_id,
                request.environment_id,
                DesktopCall::Stop,
            )
            .await?;
        let desktop = self.answered(&ctx, daemon.stop_desktop().await)?;
        connectrpc::Response::ok(proto::StopDesktopResponse {
            desktop: Some(desktop).into(),
            ..Default::default()
        })
    }
}

/// The refusal a daemon's status stands for. Its message is the workload's
/// text and is not read.
fn status_refusal(refusal: &tonic::Status) -> DesktopRefusal {
    match refusal.code() {
        tonic::Code::FailedPrecondition => DesktopRefusal::DidNotStart,
        tonic::Code::Unimplemented => DesktopRefusal::DaemonTooOld,
        tonic::Code::DeadlineExceeded => DesktopRefusal::NotReadyInTime,
        tonic::Code::Unavailable | tonic::Code::Cancelled => DesktopRefusal::TransportLost,
        _ => DesktopRefusal::Failed,
    }
}

/// Why a start was refused, from the state read after it.
fn start_refusal(read: Result<Option<daemon::Desktop>, tonic::Status>) -> DesktopRefusal {
    let state = read
        .ok()
        .and_then(|answer| vetted_desktop(answer, NO_DESKTOP_IN_IMAGE))
        .map(|desktop| desktop.state);
    if state == Some(daemon::DesktopState::Unavailable as i32) {
        DesktopRefusal::NoDesktopInImage
    } else {
        DesktopRefusal::DidNotStart
    }
}

/// A vetted answer in the public contract's words.
fn proto_desktop(desktop: daemon::Desktop) -> proto::EnvironmentDesktop {
    let state = match daemon::DesktopState::try_from(desktop.state) {
        Ok(daemon::DesktopState::Unavailable) => proto::EnvironmentDesktopState::Unavailable,
        Ok(daemon::DesktopState::Stopped) => proto::EnvironmentDesktopState::Stopped,
        Ok(daemon::DesktopState::Starting) => proto::EnvironmentDesktopState::Starting,
        Ok(daemon::DesktopState::Running) => proto::EnvironmentDesktopState::Running,
        Ok(daemon::DesktopState::Unspecified) | Err(_) => {
            proto::EnvironmentDesktopState::Unspecified
        }
    };
    proto::EnvironmentDesktop {
        state: state.into(),
        unavailable_reason: desktop.unavailable_reason,
        running: desktop
            .running
            .map(|running| proto::EnvironmentDesktopRunning {
                display: running.display,
                // The vetted answer names the desktop's one port, which fits.
                port: i32::try_from(running.port).unwrap_or_default(),
                started_at: running
                    .started_at
                    .map(|at| Timestamp::from_unix(at.seconds, at.nanos))
                    .into(),
                viewer_password: running.viewer_password,
                ..Default::default()
            })
            .into(),
        ..Default::default()
    }
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests;
