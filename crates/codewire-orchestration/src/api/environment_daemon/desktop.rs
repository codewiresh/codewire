//! The environment's desktop through its daemon (`desktop.vnc.v1`;
//! `docs/dev/SANDBOX-DESKTOP.md`, "Starting and stopping"). The caller is
//! authorized as for a terminal: operator access to a running, current and
//! claimed Sandbox. The daemon is called with the bound Pod's credential.
//!
//! A hosted Sandbox's daemon can be replaced by whoever has a shell in it,
//! so everything it answers is the workload's own text. None of that text
//! reaches a caller or a log: a refusal becomes one of the sentences here,
//! and an answer is passed on only once every field has the one shape the
//! real daemon gives it. The viewer password a running desktop carries goes
//! to the caller and nowhere else.

use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{
    DAEMON_CAPABILITY_DESKTOP_VNC, DESKTOP_DISPLAY, DESKTOP_VNC_PORT, is_desktop_viewer_password,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use tonic::transport::Channel;

use super::{DaemonRequestBudget, authorize, session_client_for_target};
use crate::api::ApiState;

type DaemonClient = v1::daemon_service_client::DaemonServiceClient<Channel>;

/// What an unavailable desktop says, and what a start of one is refused with.
pub const NO_DESKTOP_IN_IMAGE: &str =
    "this environment's image has no desktop; create the environment again on the current image";
const DID_NOT_START: &str = "the desktop did not start: another process in the environment may hold display :1 or \
     port 5901, or a session named codewire-desktop is in the way; the codewire-desktop \
     session's output says which";
const NOT_READY_IN_TIME: &str = "the desktop was not ready in time; start it again, and read the codewire-desktop \
     session's output if it repeats";
const INVALID_ANSWER: &str = "environment daemon returned an invalid desktop";

/// The latest second a start time may name: the last of the year 9999, which
/// every client's timestamp formatting accepts.
const LATEST_START_SECONDS: i64 = 253_402_300_799;

/// A start answers only once the desktop accepts a viewer, within the
/// daemon's own ten seconds, so it gets the launch budget.
pub async fn start_environment_desktop_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<v1::Desktop> {
    let (mut client, token) = desktop_client(
        state,
        user,
        org_id,
        environment_id,
        DaemonRequestBudget::Launch,
    )
    .await?;
    let request = authorize(v1::StartDesktopRequest {}, &token)?;
    match client.start_desktop(request).await {
        Ok(response) => vetted(response.into_inner().desktop),
        Err(refusal) if refusal.code() == tonic::Code::FailedPrecondition => {
            log_refusal(&refusal);
            // The daemon's sentence says which refusal this is, and is not
            // read. Its state does: an image with no desktop reads
            // unavailable, and anything else left the desktop unstarted.
            let request = authorize(v1::GetDesktopRequest {}, &token)?;
            let read = client
                .get_desktop(request)
                .await
                .map(|response| response.into_inner().desktop);
            Err(AppError::Precondition(start_refusal(read).into()))
        }
        Err(refusal) => Err(daemon_desktop_error(&refusal)),
    }
}

pub async fn get_environment_desktop_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<v1::Desktop> {
    let (mut client, token) = desktop_client(
        state,
        user,
        org_id,
        environment_id,
        DaemonRequestBudget::Control,
    )
    .await?;
    let request = authorize(v1::GetDesktopRequest {}, &token)?;
    answered(
        client
            .get_desktop(request)
            .await
            .map(|response| response.into_inner().desktop),
    )
}

pub async fn stop_environment_desktop_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<v1::Desktop> {
    let (mut client, token) = desktop_client(
        state,
        user,
        org_id,
        environment_id,
        DaemonRequestBudget::Control,
    )
    .await?;
    let request = authorize(v1::StopDesktopRequest {}, &token)?;
    answered(
        client
            .stop_desktop(request)
            .await
            .map(|response| response.into_inner().desktop),
    )
}

/// A daemon without the capability is refused here, with the repair, before
/// any desktop call is made.
async fn desktop_client(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    budget: DaemonRequestBudget,
) -> AppResult<(DaemonClient, String)> {
    session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_DESKTOP_VNC],
        budget,
    )
    .await
}

fn answered(answer: Result<Option<v1::Desktop>, tonic::Status>) -> AppResult<v1::Desktop> {
    vetted(answer.map_err(|refusal| daemon_desktop_error(&refusal))?)
}

/// Why a start was refused, from the state read after it.
fn start_refusal(read: Result<Option<v1::Desktop>, tonic::Status>) -> &'static str {
    match read.ok().and_then(|desktop| vetted(desktop).ok()) {
        Some(desktop) if desktop.state == v1::DesktopState::Unavailable as i32 => {
            NO_DESKTOP_IN_IMAGE
        }
        _ => DID_NOT_START,
    }
}

/// The daemon's answer with nothing in it but what the real daemon answers:
/// a known state; when unavailable, this module's sentence in place of the
/// daemon's reason; when running, the one display and port a desktop has, a
/// password of the shape the daemon makes, and a start time a client can
/// format. Anything else is an upstream error, and no part of it is kept.
fn vetted(answer: Option<v1::Desktop>) -> AppResult<v1::Desktop> {
    let invalid = || AppError::Upstream(INVALID_ANSWER.into());
    let desktop = answer.ok_or_else(invalid)?;
    let state = v1::DesktopState::try_from(desktop.state).map_err(|_| invalid())?;
    let (unavailable_reason, running) = match (state, desktop.running) {
        (v1::DesktopState::Unavailable, None) => (NO_DESKTOP_IN_IMAGE.to_owned(), None),
        (v1::DesktopState::Stopped | v1::DesktopState::Starting, None) => (String::new(), None),
        (v1::DesktopState::Running, Some(running))
            if running.display == DESKTOP_DISPLAY
                && running.port == u32::from(DESKTOP_VNC_PORT)
                && is_desktop_viewer_password(&running.viewer_password) =>
        {
            let started_at = running.started_at.filter(|at| {
                (0..=LATEST_START_SECONDS).contains(&at.seconds)
                    && (0..1_000_000_000).contains(&at.nanos)
            });
            (
                String::new(),
                Some(v1::DesktopRunning {
                    started_at,
                    ..running
                }),
            )
        }
        _ => return Err(invalid()),
    };
    Ok(v1::Desktop {
        state: state as i32,
        unavailable_reason,
        running,
    })
}

/// The code alone: the message is the workload's text.
fn log_refusal(refusal: &tonic::Status) {
    tracing::warn!(code = ?refusal.code(), "environment daemon desktop RPC failed");
}

fn daemon_desktop_error(refusal: &tonic::Status) -> AppError {
    log_refusal(refusal);
    match refusal.code() {
        tonic::Code::FailedPrecondition => AppError::Precondition(DID_NOT_START.into()),
        tonic::Code::Unimplemented => AppError::Precondition(
            "environment daemon upgrade is required; run `cw daemon repair`".into(),
        ),
        tonic::Code::DeadlineExceeded => AppError::Upstream(NOT_READY_IN_TIME.into()),
        tonic::Code::Unavailable | tonic::Code::Cancelled => {
            AppError::Upstream("environment desktop transport was lost".into())
        }
        _ => AppError::InternalMsg("environment desktop request failed".into()),
    }
}

#[cfg(test)]
mod tests;
