//! The dashboard viewer's way to a hosted Sandbox's desktop
//! (`docs/dev/SANDBOX-DESKTOP.md`, "The desktop stream"):
//! `codewire.desktop-stream.v1` carries the VNC (RFB) bytes unchanged in
//! binary frames, through the daemon's `ForwardTcp` to the workload's
//! `127.0.0.1:5901`, made with the bound Pod's credential. Orchestration
//! never connects to the Pod's address.
//!
//! Admission is the durable terminal's, in the same order and inside the
//! same budget, and a request that fails it is refused before the upgrade
//! with nothing dialed. What can fail after the upgrade (the viewer limit,
//! a desktop that is not running) closes with a reason the page shows.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use codewire_daemon::client::SessionClientError;
use codewire_daemon_bridge::drain::Restart;
use codewire_daemon_proto::DESKTOP_VNC_PORT;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;
use tonic::Code;

use super::durable::{
    browser_cookie, require_account, require_two_factor_eligible, valid_account_id,
};
use super::{ApiState, require_sandbox_claim_ready, terminal_error};
use crate::api::environment_daemon::streaming_daemon_client;
use crate::api::proxy::resolve_running_sandbox_target;
use crate::api::socket_fence::{SocketAdmission, access_revoked_close, site};
use crate::runtime::Placement;

const PROTOCOL: &str = "codewire.desktop-stream.v1";
/// The largest WebSocket message either way; a larger one ends the stream.
const FRAME_BYTES: usize = 64 * 1024;
/// The most desktop bytes in one message towards the browser.
const CHUNK_BYTES: usize = 32 * 1024;
/// How long a write may make no progress, either way, before the stream ends.
const STALL: Duration = Duration::from_secs(5);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Streams into one environment's desktop that one orchestration process
/// carries at once.
const VIEWERS_PER_ENVIRONMENT: usize = 4;

/// `GET /api/v1/organizations/{org_id}/environments/{env_id}/desktop-stream`
pub(crate) async fn desktop_stream_websocket(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let Ok(account_id) = requested_account(request.headers(), request.uri().query()) else {
        return terminal_error(StatusCode::BAD_REQUEST, "desktop stream request is invalid");
    };
    let cookie = match browser_cookie(request.headers(), &state.frontend_url) {
        Ok(cookie) => cookie.to_owned(),
        Err(()) => {
            return terminal_error(
                StatusCode::FORBIDDEN,
                "browser desktop authentication required",
            );
        }
    };
    // `browser_cookie` admitted only the one canonical cookie, so these
    // headers authenticate exactly as it did.
    let headers = request.headers().clone();
    let (mut parts, _) = request.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(error) => return error.into_response(),
    };
    let admitted = timeout(ADMISSION_TIMEOUT, async {
        let admission = SocketAdmission::headers(&state.auth, &headers)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        require_account(&account_id, &admission.user.user_id)?;
        require_two_factor_eligible(&state.pool, &admission.user.user_id, &cookie).await?;
        let target = resolve_running_sandbox_target(&state, &admission.user, &org_id, &env_id)
            .await
            .map_err(|(status, _)| status)?;
        let (_, revoked) = admission
            .fence(
                &state.auth,
                &state.pool,
                &state.revocation,
                site("desktop", &target.environment_id),
            )
            .await?;
        let runtime = state
            .runtime
            .as_deref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        require_sandbox_claim_ready(
            runtime,
            &Placement::new(&target.namespace),
            &target.environment_id,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok::<_, StatusCode>((target, revoked))
    })
    .await;
    let (target, revoked) = match admitted {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(status)) => return terminal_error(status, "desktop is unavailable"),
        Err(_) => {
            return terminal_error(StatusCode::SERVICE_UNAVAILABLE, "desktop is unavailable");
        }
    };
    let drain = state.drain.clone();
    ws.protocols([PROTOCOL])
        .max_frame_size(FRAME_BYTES)
        .max_message_size(FRAME_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let restart = drain.signal(Restart::Deadline);
            let (mut browser_output, mut browser_input) = socket.split();
            let end = match Viewer::admit(&target.environment_id) {
                None => End::TooManyViewers,
                Some(_viewer) => {
                    let opened = async {
                        let client = streaming_daemon_client(
                            &state.pool,
                            state.runtime.as_deref(),
                            &state.session_secret,
                            &state.environment_daemon_endpoints,
                            &target.namespace,
                            &target.environment_id,
                        )
                        .await
                        .map_err(|_| End::DaemonUnreachable)?;
                        client
                            .forward_tcp(desktop_address())
                            .await
                            .map_err(|error| refused(&error))
                    };
                    tokio::select! {
                        end = async {
                            match opened.await {
                                Ok(desktop) => {
                                    relay(&mut browser_output, &mut browser_input, desktop, STALL)
                                        .await
                                }
                                Err(end) => end,
                            }
                        } => end,
                        () = restart => End::Restarting,
                        () = revoked.into_future() => End::Revoked,
                    }
                }
            };
            if !matches!(end, End::ViewerLeft | End::Restarting | End::Revoked) {
                tracing::info!(
                    environment_id = %target.environment_id,
                    reason = end.as_str(),
                    "browser desktop stream ended"
                );
            }
            // The browser may already be gone; the viewer has ended either way.
            let _ = timeout(STALL, browser_output.send(close_for(end))).await;
        })
}

/// The account the page asks for, from the only query parameter, and the one
/// subprotocol. A cookie can change account between the page's load and the
/// upgrade; the stream is refused then, as the durable terminal's is.
fn requested_account(headers: &HeaderMap, query: Option<&str>) -> Result<String, ()> {
    let query = query.unwrap_or_default();
    let protocols = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .collect::<Vec<_>>();
    if query.len() > 256 || protocols.len() != 1 || protocols[0].to_str().ok() != Some(PROTOCOL) {
        return Err(());
    }
    let mut account_id = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "account_id" if account_id.is_none() && valid_account_id(&value) => {
                account_id = Some(value.into_owned());
            }
            _ => return Err(()),
        }
    }
    account_id.ok_or(())
}

/// The desktop's VNC listener on the workload's loopback.
fn desktop_address() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, DESKTOP_VNC_PORT))
}

/// How a forward the daemon would not open ends the stream.
fn refused(error: &SessionClientError) -> End {
    match error {
        SessionClientError::Status(status) if status.code() == Code::Unimplemented => {
            End::DaemonTooOld
        }
        // Nothing accepted the connection: the desktop is not running.
        SessionClientError::Status(status) if status.code() == Code::Unavailable => End::NotRunning,
        _ => End::DaemonUnreachable,
    }
}

/// One stream's place in its environment's viewer count, given back when the
/// stream ends.
struct Viewer(String);

static VIEWERS: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(Mutex::default);

impl Viewer {
    fn admit(environment_id: &str) -> Option<Self> {
        let mut viewers = VIEWERS.lock().unwrap_or_else(PoisonError::into_inner);
        let count = viewers.entry(environment_id.to_owned()).or_default();
        if *count >= VIEWERS_PER_ENVIRONMENT {
            return None;
        }
        *count += 1;
        Some(Self(environment_id.to_owned()))
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        let mut viewers = VIEWERS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = viewers.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                viewers.remove(&self.0);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// The browser closed the stream, or went.
    ViewerLeft,
    /// The browser sent a text frame or a message over the bound.
    Invalid,
    /// A write made no progress within the stall bound, either way.
    Stalled,
    /// The desktop's connection ended: the desktop or the Sandbox stopped.
    DesktopEnded,
    /// Nothing listened on the desktop's port.
    NotRunning,
    /// The Sandbox's daemon has no `ForwardTcp`.
    DaemonTooOld,
    DaemonUnreachable,
    TooManyViewers,
    /// This replica reached its drain deadline; the viewer connects again.
    Restarting,
    /// The credential that admitted the browser was lost.
    Revoked,
}

impl End {
    fn as_str(self) -> &'static str {
        match self {
            Self::ViewerLeft => "viewer_left",
            Self::Invalid => "invalid",
            Self::Stalled => "stalled",
            Self::DesktopEnded => "desktop_ended",
            Self::NotRunning => "not_running",
            Self::DaemonTooOld => "daemon_too_old",
            Self::DaemonUnreachable => "daemon_unreachable",
            Self::TooManyViewers => "too_many_viewers",
            Self::Restarting => "restarting",
            Self::Revoked => "revoked",
        }
    }
}

/// The close the browser gets: 1000 when the viewer left, 1012 on a drain,
/// 1008 otherwise, with a reason the page shows.
fn close_for(end: End) -> Message {
    let (code, reason) = match end {
        End::ViewerLeft => (1000, "viewer left"),
        End::Restarting => (1012, "server restarting; connect again"),
        End::Revoked => return access_revoked_close(),
        End::Invalid => (1008, "the viewer sent something other than desktop bytes"),
        End::Stalled => (1008, "the connection stalled"),
        End::DesktopEnded => (1008, "the desktop ended"),
        End::NotRunning => (1008, "the desktop is not running"),
        End::DaemonTooOld => (1008, "this Sandbox predates the desktop stream"),
        End::DaemonUnreachable => (1008, "the Sandbox could not be reached"),
        End::TooManyViewers => (
            1008,
            "4 viewers already watch this desktop, the most it takes",
        ),
    };
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// Copy desktop bytes both ways until either side ends. Each direction holds
/// one message at a time, so a side that stops taking bytes stops the other
/// from reading: nothing grows.
async fn relay<Tx, Rx, E, D>(
    browser_output: &mut Tx,
    browser_input: &mut Rx,
    desktop: D,
    stall: Duration,
) -> End
where
    Tx: Sink<Message> + Unpin,
    Rx: Stream<Item = Result<Message, E>> + Unpin,
    D: AsyncRead + AsyncWrite,
{
    let (mut from_desktop, mut to_desktop) = tokio::io::split(desktop);
    let to_desktop = async {
        loop {
            let bytes = match browser_input.next().await {
                Some(Ok(Message::Binary(bytes))) if bytes.len() <= FRAME_BYTES => bytes,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_)) | Err(_)) | None => return End::ViewerLeft,
                Some(Ok(_)) => return End::Invalid,
            };
            match timeout(stall, to_desktop.write_all(&bytes)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return End::DesktopEnded,
                Err(_) => return End::Stalled,
            }
        }
    };
    let to_browser = async {
        let mut buffer = vec![0; CHUNK_BYTES];
        loop {
            let read = match from_desktop.read(&mut buffer).await {
                Ok(0) | Err(_) => return End::DesktopEnded,
                Ok(read) => read,
            };
            let message = Message::Binary(buffer[..read].to_vec().into());
            match timeout(stall, browser_output.send(message)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return End::ViewerLeft,
                Err(_) => return End::Stalled,
            }
        }
    };
    tokio::select! {
        end = to_desktop => end,
        end = to_browser => end,
    }
}

#[cfg(test)]
mod tests;
