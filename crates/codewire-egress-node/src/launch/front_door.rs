//! One Pod's front door, as a process (#4001). The protocol on its control
//! socket is `crate::front_door::protocol`.

use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

use codewire_confinement::spawn::{OwnImage, duplicate_inherited_descriptor};
use codewire_egress_front_door_bridge::control::ControlChannel;
use codewire_egress_policy::handoff::stream_pair;
use tokio::time::Instant;
use uuid::Uuid;

use super::StartError;
use super::spawner::{Process, Spawner};
use crate::children::{FRONT_DOOR_WORD, POD_UID_FLAG};
use crate::front_door::protocol::{
    Bindings, CONFINE, CREDENTIALS, FRONT_DOOR_CONTROL_FD, FRONT_DOOR_SESSIONS_FD, HANDOFF,
    INSTALLED, MAX_CONTROL_MESSAGE, PREPARED, READY, SERVING, SESSION_SERVING, SessionRefusal,
    decode_failed, decode_refused, decode_session_dropped, encode_bindings, encode_leaves,
};
use crate::interception::FrontDoorSpec;

/// How long a front door has to answer a leaves frame.
const INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A confined front door holding its key. Dropping it kills it.
pub(super) struct FrontDoor {
    process: Process,
    control: ControlChannel,
    /// Taken once, by whatever hands the front door its credential sessions.
    sessions: Option<ControlChannel>,
    spki: Vec<u8>,
}

/// Why a credential session was not handed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandError {
    #[error("the front door dropped the session: {}", .0.code())]
    Dropped(SessionRefusal),
    #[error("the front door's sessions socket closed, misbehaved or did not answer")]
    Control,
}

/// Hands the front door one credential session, `socket`, already tagged,
/// and waits for its answer within `timeout`.
pub async fn hand_session(
    sessions: &mut ControlChannel,
    socket: OwnedFd,
    timeout: std::time::Duration,
) -> Result<(), HandError> {
    let deadline = Instant::now() + timeout;
    tokio::time::timeout_at(deadline, sessions.send(CREDENTIALS, &[socket.as_fd()]))
        .await
        .map_err(|_| HandError::Control)?
        .map_err(|_| HandError::Control)?;
    drop(socket);
    let (answer, _) = tokio::time::timeout_at(deadline, sessions.receive(MAX_CONTROL_MESSAGE, 0))
        .await
        .map_err(|_| HandError::Control)?
        .map_err(|_| HandError::Control)?;
    if answer == SESSION_SERVING {
        return Ok(());
    }
    Err(decode_session_dropped(&answer).map_or(HandError::Control, HandError::Dropped))
}

/// Starts a front door for `pod_uid` from `image` and waits until it is
/// confined and holds its key.
pub(super) async fn start(
    image: &OwnImage,
    spawner: &Spawner,
    pod_uid: Uuid,
    spec: &FrontDoorSpec,
    deadline: Instant,
) -> Result<FrontDoor, StartError> {
    let (parent, child) = stream_pair().map_err(|_| StartError::Spawn)?;
    let (sessions_parent, sessions_child) = stream_pair().map_err(|_| StartError::Spawn)?;
    let inherited =
        duplicate_inherited_descriptor(child.as_raw_fd()).map_err(|_| StartError::Spawn)?;
    let inherited_sessions = duplicate_inherited_descriptor(sessions_child.as_raw_fd())
        .map_err(|_| StartError::Spawn)?;
    let pod = pod_uid.to_string();
    let command = image
        .command(
            &["cw-egress", FRONT_DOOR_WORD, POD_UID_FLAG, &pod],
            vec![
                (inherited.as_raw_fd(), FRONT_DOOR_CONTROL_FD),
                (inherited_sessions.as_raw_fd(), FRONT_DOOR_SESSIONS_FD),
            ],
        )
        .map_err(|_| StartError::Spawn)?;
    let process = spawner.spawn(command).await?;
    // The child holds its own copies of its ends.
    drop((inherited, inherited_sessions));
    drop((child, sessions_child));

    let mut control = ControlChannel::new(parent).map_err(|_| StartError::Spawn)?;
    let sessions = ControlChannel::new(sessions_parent).map_err(|_| StartError::Spawn)?;
    let spki = prepare(&mut control, spec, deadline, || {
        super::require_image(image, &process)
    })
    .await?;
    Ok(FrontDoor {
        process,
        control,
        sessions: Some(sessions),
        spki,
    })
}

/// The supervisor's half of a start: the bindings, then `check` while the
/// child waits unconfined, then confinement. Returns the front door's public
/// key. A failed `check` tells the child nothing more: it never confines,
/// never makes a key, and ends when its process is killed.
pub(super) async fn prepare(
    control: &mut ControlChannel,
    spec: &FrontDoorSpec,
    deadline: Instant,
    check: impl FnOnce() -> Result<(), StartError>,
) -> Result<Vec<u8>, StartError> {
    let bindings = encode_bindings(&Bindings {
        environment_id: spec.environment_id,
        generation: spec.generation,
        intercepts: spec.intercepts.clone(),
    })
    .map_err(|_| StartError::Bootstrap)?;
    send(control, &bindings, None, deadline).await?;
    expect(control, PREPARED, deadline).await?;
    check()?;
    send(control, CONFINE, None, deadline).await?;
    let ready = receive(control, deadline).await?;
    match ready.strip_prefix(READY) {
        Some(spki) if !spki.is_empty() => Ok(spki.to_vec()),
        _ => Err(refusal(&ready)),
    }
}

/// Gives the front door its end of the broker's hand-off socket and waits
/// until it serves it.
pub(super) async fn take_handoff(
    control: &mut ControlChannel,
    handoff: OwnedFd,
    deadline: Instant,
) -> Result<(), StartError> {
    send(control, HANDOFF, Some(handoff.as_fd()), deadline).await?;
    // The front door holds its own copy now.
    drop(handoff);
    expect(control, SERVING, deadline).await
}

/// Has the front door serve `leaves` from now on, all or none. A refusal
/// leaves it with the leaves it had.
pub(super) async fn install<C: AsRef<[u8]>>(
    control: &mut ControlChannel,
    leaves: &[C],
) -> Result<(), StartError> {
    let frame = encode_leaves(leaves).ok_or(StartError::Bootstrap)?;
    let deadline = Instant::now() + INSTALL_TIMEOUT;
    send(control, &frame, None, deadline).await?;
    let answer = receive(control, deadline).await?;
    if answer == INSTALLED {
        return Ok(());
    }
    Err(decode_refused(&answer).map_or(StartError::Bootstrap, StartError::Leaves))
}

impl FrontDoor {
    pub(super) fn public_key_spki(&self) -> &[u8] {
        &self.spki
    }

    /// The front door's sessions socket, once.
    pub(super) fn take_sessions(&mut self) -> Option<ControlChannel> {
        self.sessions.take()
    }

    pub(super) async fn take_handoff(
        &mut self,
        handoff: OwnedFd,
        deadline: Instant,
    ) -> Result<(), StartError> {
        take_handoff(&mut self.control, handoff, deadline).await
    }

    pub(super) async fn install<C: AsRef<[u8]>>(&mut self, leaves: &[C]) -> Result<(), StartError> {
        install(&mut self.control, leaves).await
    }

    /// Resolves when the front door is gone. Outside an install it sends
    /// nothing, so anything it sends, or its socket closing, is its end.
    /// Cancel-safe: the channel keeps a frame it has partly read.
    pub(super) async fn exited(&mut self) {
        // A frame, an error and the end all mean the same here.
        let _ = self.control.receive(MAX_CONTROL_MESSAGE, 0).await;
    }

    /// Kills the process and returns once it is reaped.
    pub(super) async fn end(self) {
        self.process.end().await;
    }
}

async fn send(
    control: &mut ControlChannel,
    message: &[u8],
    descriptor: Option<std::os::fd::BorrowedFd<'_>>,
    deadline: Instant,
) -> Result<(), StartError> {
    let descriptors: Vec<_> = descriptor.into_iter().collect();
    tokio::time::timeout_at(deadline, control.send(message, &descriptors))
        .await
        .map_err(|_| StartError::Timeout)?
        .map_err(|_| StartError::Bootstrap)
}

async fn receive(control: &mut ControlChannel, deadline: Instant) -> Result<Vec<u8>, StartError> {
    tokio::time::timeout_at(deadline, control.receive(MAX_CONTROL_MESSAGE, 0))
        .await
        .map_err(|_| StartError::Timeout)?
        .map(|(message, _)| message)
        .map_err(|_| StartError::Bootstrap)
}

/// Reads the front door's next message and requires it to be `expected`.
async fn expect(
    control: &mut ControlChannel,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), StartError> {
    let message = receive(control, deadline).await?;
    if message == expected {
        Ok(())
    } else {
        Err(refusal(&message))
    }
}

fn refusal(message: &[u8]) -> StartError {
    decode_failed(message).map_or(StartError::Bootstrap, StartError::FrontDoor)
}

#[cfg(test)]
mod tests;
