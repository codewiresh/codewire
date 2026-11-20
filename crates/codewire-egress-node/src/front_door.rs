//! The front door cw-egress runs for each Pod whose assignment intercepts
//! its agent hosts (#4001; `SPEC.md`, cw-egress's front door): a child of
//! the supervisor, from the same image as the Pod's broker and worker.
//!
//! It confines itself as the local VM's front door does (no new privileges,
//! no filesystem, no new sockets or processes), and only then makes its own
//! P-256 key, so the key only ever exists confined. Only the public key
//! leaves it. It serves a bound host only while a leaf the credential
//! service's signer issued for that key covers it; otherwise the host's
//! handshake fails closed. Its control socket's protocol is [`protocol`].

pub mod protocol;
mod sessions;

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use codewire_confinement::linux::require_single_threaded_process;
use codewire_egress_front_door::{CaError, SignedLeaves};
use codewire_egress_front_door_bridge::control::ControlChannel;
use codewire_egress_front_door_bridge::handoff::{connected_unix_stream, expect_broker_role_tag};
use codewire_egress_front_door_bridge::{Ended, EnvironmentFrontDoor};
use codewire_egress_worker::worker::inherited_std_unix_stream;
use uuid::Uuid;

use protocol::{
    CONFINE, FRONT_DOOR_CONTROL_FD, FRONT_DOOR_SESSIONS_FD, FrontDoorStage, HANDOFF, INSTALLED,
    LeafRefusal, MAX_CONTROL_MESSAGE, PREPARED, SERVING, decode_bindings, decode_leaves,
    failed_message, ready_message, refused_message,
};

/// How long each step of the supervisor's start may take: its whole start
/// is bounded by `launch::START_TIMEOUT`, and this outlasts it.
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the broker's role tag may take once its end is here: the broker
/// wrote it before it said it was ready.
const ROLE_TAG_TIMEOUT: Duration = Duration::from_secs(2);

/// Why the front door stopped.
#[derive(Debug, thiserror::Error)]
pub enum FrontDoorProcessError {
    #[error("the front door did not start: {}", .0.code())]
    Startup(FrontDoorStage),
    #[error("the front door's control socket closed or misbehaved")]
    Control,
    #[error("the front door stopped: {0}")]
    Ended(#[source] Ended),
}

impl FrontDoorProcessError {
    /// The process's exit status: one per way it ends.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Startup(stage) => match stage {
                FrontDoorStage::Control => 80,
                FrontDoorStage::Bindings => 81,
                FrontDoorStage::Admission => 82,
                FrontDoorStage::Confinement => 83,
                FrontDoorStage::Start => 84,
                FrontDoorStage::Handoff => 85,
                FrontDoorStage::Sessions => 88,
            },
            Self::Control => 86,
            Self::Ended(_) => 87,
        }
    }
}

/// The `__egress-front-door` child: its inherited control and sessions
/// sockets, then [`run`] with the real confinement.
pub async fn run_inherited_front_door(pod_uid: Uuid) -> Result<(), FrontDoorProcessError> {
    let control = inherited_channel(FRONT_DOOR_CONTROL_FD)
        .map_err(|()| FrontDoorProcessError::Startup(FrontDoorStage::Control))?;
    let sessions = inherited_channel(FRONT_DOOR_SESSIONS_FD)
        .map_err(|()| FrontDoorProcessError::Startup(FrontDoorStage::Sessions))?;
    run(control, sessions, pod_uid, confine).await
}

/// An inherited descriptor, admitted only as a connected Unix stream and
/// made close-on-exec, before anything is confined.
fn inherited_channel(descriptor: std::os::fd::RawFd) -> Result<ControlChannel, ()> {
    let socket = inherited_std_unix_stream(descriptor)
        .map(OwnedFd::from)
        .map_err(|_| ())?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC).map_err(|_| ())?;
    ControlChannel::new(socket).map_err(|_| ())
}

/// No other thread may exist: the syscall filter binds only the calling
/// thread and those it starts.
fn confine() -> io::Result<()> {
    require_single_threaded_process()?;
    codewire_egress_front_door_bridge::confine::confine_front_door()
}

/// The front door's life on `control`, until it ends. `confine` is
/// [`confine`] in the process; a test runs it in its own process without.
pub(crate) async fn run(
    mut control: ControlChannel,
    mut sessions: ControlChannel,
    pod_uid: Uuid,
    confine: impl FnOnce() -> io::Result<()>,
) -> Result<(), FrontDoorProcessError> {
    let result = start_and_serve(&mut control, &mut sessions, pod_uid, confine).await;
    if let Err(FrontDoorProcessError::Startup(stage)) = &result {
        // The supervisor may already be gone; the exit status says the same.
        let _ = control.send(&failed_message(*stage), &[]).await;
    }
    result
}

async fn start_and_serve(
    control: &mut ControlChannel,
    sessions: &mut ControlChannel,
    pod_uid: Uuid,
    confine: impl FnOnce() -> io::Result<()>,
) -> Result<(), FrontDoorProcessError> {
    let startup = FrontDoorProcessError::Startup;
    let (frame, _) = receive(control, 0)
        .await
        .map_err(|()| startup(FrontDoorStage::Bindings))?;
    let bindings = decode_bindings(&frame)
        .await
        .ok_or(startup(FrontDoorStage::Bindings))?;
    send(control, PREPARED).await?;
    match receive(control, 0).await {
        Ok((admission, _)) if admission == CONFINE => {}
        _ => return Err(startup(FrontDoorStage::Admission)),
    }
    confine().map_err(|_| startup(FrontDoorStage::Confinement))?;

    let leaves = Arc::new(SignedLeaves::generate().map_err(|_| startup(FrontDoorStage::Start))?);
    let door = EnvironmentFrontDoor::with_leaves(
        bindings.environment_id,
        bindings.generation,
        bindings.intercepts,
        Arc::clone(&leaves),
    )
    .map_err(|_| startup(FrontDoorStage::Start))?
    .handed_off_as(pod_uid);
    send(control, &ready_message(leaves.public_key_spki())).await?;

    let handoff = receive_handoff(control).await?;
    send(control, SERVING).await?;

    // Credential sessions come from cw-egress's front-door session, on
    // their own socket: until one is admitted, each request fails closed at
    // the bridge. Either socket ending ends the front door, so a pair whose
    // sessions are gone restarts rather than serving on with none.
    let (successors, later) = tokio::sync::mpsc::channel::<tokio::net::UnixStream>(1);
    let serve = door.serve(handoff, None, later);
    tokio::pin!(serve);
    let follow = async {
        tokio::select! {
            () = follow_leaves(control, &leaves) => {}
            () = sessions::follow_sessions(sessions, successors) => {}
        }
    };
    let ended = tokio::select! {
        ended = &mut serve => ended,
        () = follow => serve.await,
    };
    Err(FrontDoorProcessError::Ended(ended))
}

/// The broker's hand-off end: one connected Unix stream that opens with the
/// broker's role tag.
async fn receive_handoff(control: &mut ControlChannel) -> Result<OwnedFd, FrontDoorProcessError> {
    let failed = FrontDoorProcessError::Startup(FrontDoorStage::Handoff);
    let (message, descriptors) = receive(control, 1).await.map_err(|()| failed)?;
    let Ok([handoff]) = <[OwnedFd; 1]>::try_from(descriptors) else {
        return Err(FrontDoorProcessError::Startup(FrontDoorStage::Handoff));
    };
    if message != HANDOFF || !connected_unix_stream(&handoff) {
        return Err(FrontDoorProcessError::Startup(FrontDoorStage::Handoff));
    }
    expect_broker_role_tag(&handoff, ROLE_TAG_TIMEOUT)
        .map_err(|_| FrontDoorProcessError::Startup(FrontDoorStage::Handoff))?;
    Ok(handoff)
}

/// Installs each leaves frame and answers it, until the control socket
/// closes or carries anything else.
async fn follow_leaves(control: &mut ControlChannel, leaves: &SignedLeaves) {
    while let Ok((frame, _)) = control.receive(MAX_CONTROL_MESSAGE, 0).await {
        let Some(certificates) = decode_leaves(&frame) else {
            return;
        };
        let answer = match leaves.install(certificates) {
            Ok(()) => INSTALLED.to_vec(),
            Err(CaError::Expired) => refused_message(LeafRefusal::Expired),
            Err(_) => refused_message(LeafRefusal::Invalid),
        };
        if control.send(&answer, &[]).await.is_err() {
            return;
        }
    }
}

/// One frame of at most `descriptors` descriptors, within [`STEP_TIMEOUT`].
async fn receive(
    control: &mut ControlChannel,
    descriptors: usize,
) -> Result<(Vec<u8>, Vec<OwnedFd>), ()> {
    tokio::time::timeout(
        STEP_TIMEOUT,
        control.receive(MAX_CONTROL_MESSAGE, descriptors),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn send(control: &mut ControlChannel, message: &[u8]) -> Result<(), FrontDoorProcessError> {
    tokio::time::timeout(STEP_TIMEOUT, control.send(message, &[]))
        .await
        .map_err(|_| FrontDoorProcessError::Control)?
        .map_err(|_| FrontDoorProcessError::Control)
}
