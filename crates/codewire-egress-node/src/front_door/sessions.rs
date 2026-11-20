//! The front door's sessions socket ([`super::protocol::FRONT_DOOR_SESSIONS_FD`]):
//! each credential session the supervisor hands over is admitted only as a
//! connected Unix stream socket whose first byte, already written by the
//! supervisor, is the session role tag. Anything else is dropped, closed and
//! answered with a fixed code. The supervisor wrote the tag itself before
//! the hand-off, so nothing from the network decides how long this waits.

use std::os::fd::OwnedFd;
use std::time::Duration;

use codewire_egress_front_door_bridge::FRONT_DOOR_SESSION_ROLE_TAG;
use codewire_egress_front_door_bridge::control::ControlChannel;
use codewire_egress_front_door_bridge::handoff::connected_unix_stream;
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::protocol::{
    CREDENTIALS, MAX_CONTROL_MESSAGE, SESSION_SERVING, SessionRefusal, session_dropped_message,
};

/// How long a handed-over session's tag may take to be readable.
const SESSION_TAG_TIMEOUT: Duration = Duration::from_secs(2);

/// Admits each credential session and answers it, until the sessions socket
/// closes or carries anything else.
pub(super) async fn follow_sessions(
    sessions: &mut ControlChannel,
    successors: mpsc::Sender<UnixStream>,
) {
    while let Ok((frame, descriptors)) = sessions.receive(MAX_CONTROL_MESSAGE, 1).await {
        let Ok([socket]) = <[OwnedFd; 1]>::try_from(descriptors) else {
            return;
        };
        if frame != CREDENTIALS {
            return;
        }
        let answer = match admitted(socket).await {
            Ok(session) => match successors.try_send(session) {
                Ok(()) => SESSION_SERVING.to_vec(),
                Err(_) => session_dropped_message(SessionRefusal::Busy),
            },
            Err(why) => session_dropped_message(why),
        };
        if sessions.send(&answer, &[]).await.is_err() {
            return;
        }
    }
}

/// `socket` as a session, or why not. A refused socket is closed here.
async fn admitted(socket: OwnedFd) -> Result<UnixStream, SessionRefusal> {
    if !connected_unix_stream(&socket) {
        return Err(SessionRefusal::Kind);
    }
    let socket = std::os::unix::net::UnixStream::from(socket);
    socket
        .set_nonblocking(true)
        .map_err(|_| SessionRefusal::Kind)?;
    let mut session = UnixStream::from_std(socket).map_err(|_| SessionRefusal::Kind)?;
    let mut tag = [0_u8; 1];
    match tokio::time::timeout(SESSION_TAG_TIMEOUT, session.read_exact(&mut tag)).await {
        Ok(Ok(_)) if tag[0] == FRONT_DOOR_SESSION_ROLE_TAG => Ok(session),
        _ => Err(SessionRefusal::Tag),
    }
}
