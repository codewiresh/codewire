//! cw-egress's side of `EgressService.FrontDoorSession` (#4001;
//! `docs/dev/SECRETS-AND-CREDENTIALS.md`, "The client"): one session for
//! each Pod whose front door runs, from the front door's start until the
//! Pod's egress pair ends, reopened whenever it ends.
//!
//! Each session is handed to the front door as one end of a fresh socket
//! pair, which this side tags itself before the hand-off. The relay then
//! writes each frame orchestration sends unchanged, and cuts the front
//! door's bytes into whole frames, each one message. It holds at most one
//! frame each way, parses nothing else and logs only fixed reasons.

use std::future::Future;
use std::hash::{BuildHasher as _, Hasher as _};
use std::pin::Pin;
use std::time::Duration;

use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_egress_front_door_bridge::FRONT_DOOR_SESSION_ROLE_TAG;
use codewire_egress_front_door_bridge::control::ControlChannel;
use codewire_egress_policy::handoff::stream_pair;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::launch::{HandError, hand_session};

/// How long the front door may take to answer a hand-off.
const HAND_TIMEOUT: Duration = Duration::from_secs(15);
/// A session that stayed attached this long resets the backoff.
const HEALTHY_FOR: Duration = Duration::from_secs(60);
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);
/// How soon a healthy session's clean end, as at the token's expiry, opens
/// the next.
const REOPEN_WITHIN: Duration = Duration::from_secs(2);
const REFUSED_WAIT: Duration = Duration::from_secs(60);
const UNIMPLEMENTED_WAIT: Duration = Duration::from_secs(300);
const LENGTH_BYTES: usize = 4;

/// One attached session: each frame orchestration sends, and a way to send
/// it whole frames. Each holds at most one frame.
pub struct Attached {
    pub to_orchestration: mpsc::Sender<Vec<u8>>,
    pub from_orchestration: mpsc::Receiver<Result<Vec<u8>, SessionEnd>>,
}

/// How a session ended, or why it never attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// Orchestration ended it, as at the token's expiry.
    Clean,
    /// `UNAVAILABLE`, `ALREADY_EXISTS` or a transport error: try again soon.
    Unavailable,
    /// `PERMISSION_DENIED`, `FAILED_PRECONDITION` or `INVALID_ARGUMENT`.
    Refused,
    /// Hosted interception is off at orchestration.
    Unimplemented,
}

impl SessionEnd {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Unavailable => "unavailable",
            Self::Refused => "refused",
            Self::Unimplemented => "unimplemented",
        }
    }
}

/// Opens one front-door session for a Pod.
pub trait SessionOpener: std::fmt::Debug + Send + Sync + 'static {
    fn open<'a>(
        &'a self,
        pod_uid: &'a str,
        pod_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Attached, SessionEnd>> + Send + 'a>>;
}

/// Why a Pod's session task ended the pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionTaskError {
    #[error("the front door did not take its session: {0}")]
    Hand(HandError),
    #[error("no socket pair for a session")]
    Socket,
}

/// Keeps the Pod's front door supplied with a session until the pair ends,
/// which drops this. It returns only when the front door won't take one,
/// which ends the pair.
pub async fn run(
    opener: &dyn SessionOpener,
    pod_uid: &str,
    pod_name: &str,
    sessions: &mut ControlChannel,
) -> SessionTaskError {
    let mut backoff = Backoff::default();
    loop {
        let (end, attached_for) = match opener.open(pod_uid, pod_name).await {
            Err(end) => (end, None),
            Ok(attached) => {
                let started = Instant::now();
                let end = match handed(sessions).await {
                    Ok(ours) => relay(attached, ours).await,
                    Err(error) => return error,
                };
                (end, Some(started.elapsed()))
            }
        };
        if end != SessionEnd::Clean {
            tracing::info!(pod_uid, outcome = end.code(), "a front-door session ended");
        }
        tokio::time::sleep(backoff.after(end, attached_for)).await;
    }
}

/// A fresh socket pair whose far end the front door took, and our end,
/// already tagged.
async fn handed(sessions: &mut ControlChannel) -> Result<UnixStream, SessionTaskError> {
    let (ours, theirs) = stream_pair().map_err(|_| SessionTaskError::Socket)?;
    let ours = std::os::unix::net::UnixStream::from(ours);
    ours.set_nonblocking(true)
        .map_err(|_| SessionTaskError::Socket)?;
    let mut ours = UnixStream::from_std(ours).map_err(|_| SessionTaskError::Socket)?;
    ours.write_all(&[FRONT_DOOR_SESSION_ROLE_TAG])
        .await
        .map_err(|_| SessionTaskError::Socket)?;
    // One relay runs at a time, so a busy front door is a fault too.
    hand_session(sessions, theirs, HAND_TIMEOUT)
        .await
        .map_err(SessionTaskError::Hand)?;
    Ok(ours)
}

/// Relays one session until either side ends, then ends the other.
pub(crate) async fn relay(attached: Attached, socket: UnixStream) -> SessionEnd {
    let Attached {
        to_orchestration,
        mut from_orchestration,
    } = attached;
    let (mut reading, mut writing) = socket.into_split();
    let to_front_door = async {
        loop {
            match from_orchestration.recv().await {
                Some(Ok(frame)) => {
                    if writing.write_all(&frame).await.is_err() {
                        return SessionEnd::Unavailable;
                    }
                }
                Some(Err(end)) => return end,
                None => return SessionEnd::Clean,
            }
        }
    };
    let from_front_door = async {
        loop {
            let Some(frame) = read_frame(&mut reading).await else {
                return SessionEnd::Unavailable;
            };
            if to_orchestration.send(frame).await.is_err() {
                return SessionEnd::Unavailable;
            }
        }
    };
    // Whichever ends first drops the other, closing our end of the socket
    // and the session's stream together.
    tokio::select! {
        end = to_front_door => end,
        end = from_front_door => end,
    }
}

/// One whole frame, its length included, or `None` at its end or on a
/// length of zero or over the bridge's maximum.
async fn read_frame(reading: &mut tokio::net::unix::OwnedReadHalf) -> Option<Vec<u8>> {
    let mut length = [0_u8; LENGTH_BYTES];
    reading.read_exact(&mut length).await.ok()?;
    let body = usize::try_from(u32::from_be_bytes(length)).ok()?;
    if body == 0 || body > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
        return None;
    }
    let mut frame = vec![0_u8; LENGTH_BYTES + body];
    frame[..LENGTH_BYTES].copy_from_slice(&length);
    reading.read_exact(&mut frame[LENGTH_BYTES..]).await.ok()?;
    Some(frame)
}

/// The wait before the next open. A Sandbox can end its own session by what
/// it sends, so only a session that stayed attached [`HEALTHY_FOR`] resets
/// the backoff, and every wait is drawn from the upper half of its interval.
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: BACKOFF_FLOOR,
        }
    }
}

impl Backoff {
    fn after(&mut self, end: SessionEnd, attached_for: Option<Duration>) -> Duration {
        let healthy = attached_for.is_some_and(|attached| attached >= HEALTHY_FOR);
        if healthy {
            self.next = BACKOFF_FLOOR;
        }
        match end {
            SessionEnd::Clean if healthy => random_below(REOPEN_WITHIN),
            SessionEnd::Clean | SessionEnd::Unavailable => {
                let wait = upper_half(self.next);
                self.next = (self.next * 2).min(BACKOFF_CAP);
                wait
            }
            SessionEnd::Refused => upper_half(REFUSED_WAIT),
            SessionEnd::Unimplemented => upper_half(UNIMPLEMENTED_WAIT),
        }
    }
}

/// A random point in the upper half of `interval`.
fn upper_half(interval: Duration) -> Duration {
    interval / 2 + random_below(interval / 2)
}

/// A random point in `[0, limit)`, for spreading reopens. Not secret.
fn random_below(limit: Duration) -> Duration {
    let nanos = u64::try_from(limit.as_nanos()).unwrap_or(u64::MAX).max(1);
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    Duration::from_nanos(random % nanos)
}

#[cfg(test)]
mod tests;
