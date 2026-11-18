//! Confined host process for one local environment's TLS front door (#3999).
//!
//! The runner starts it early in `prepare()`, before the guest seed is
//! written, with one inherited control socket: a connected Unix stream,
//! framed as the hand-off is ([`control::ControlChannel`]), in order:
//!
//! 1. runner: the environment's interception bindings
//!    (`broker_control::encode_intercept_frame`);
//! 2. front door: [`FRONT_DOOR_READY_MESSAGE`] followed by the CA certificate
//!    in DER, which the runner puts in the seed, or a failure line;
//! 3. runner: [`FRONT_DOOR_SOCKETS_MESSAGE`] carrying exactly two
//!    descriptors: the egress broker's hand-off end, then the credential
//!    broker's front-door session;
//! 4. runner, for each later credential broker of the generation: the
//!    credential authority replaces the broker every few minutes, and each
//!    successor pairs again. [`FRONT_DOOR_CREDENTIALS_MESSAGE`] carries
//!    exactly one descriptor, its session, which takes all new work while the
//!    one it replaces drains (`EnvironmentFrontDoor::serve`);
//! 5. front door, after each of those frames: its serving word
//!    ([`front_door_serving_message`]) once it has checked the frame's
//!    sockets and their role tags and takes them, so the runner records a
//!    pairing on the front door's own word. The word carries the frame's
//!    number in the generation, counted from 1 over every frame of steps 3
//!    and 4, so a word that arrives late is never taken for a later
//!    pairing's. It says nothing for a later broker's socket it drops, whose
//!    number is then never said, and a failure line if the first pairing's
//!    sockets fail.
//!
//! Each of those sockets first carries a role tag from its peer, which
//! the front door checks before it serves anything, so a swapped pair is
//! refused at once rather than detected later:
//!
//! - the hand-off end: the egress broker's first frame, body exactly
//!   [`HANDOFF_ROLE_TAG`] and no descriptors, sent right after it takes its
//!   end and before any intercepted stream;
//! - the credential end: one raw byte, [`FRONT_DOOR_CREDENTIAL_TAG`], written
//!   by the credential broker before its bridge Open.
//!
//! Each is read within [`ROLE_TAG_TIMEOUT`]; both peers are up by then.
//!
//! It confines itself before generating the CA, so the CA key only ever
//! exists inside the confined process. It then serves until the hand-off
//! ends or the control channel closes, and exits; the runner treats that exit
//! as the front door dying, which fails closed. A credential session ending
//! ends nothing: the next broker to pair serves. A later frame that is not
//! a well-formed credentials frame ends the front door; a socket in one that
//! fails its checks is dropped and the next pairing awaited. Linux only until
//! its macOS confinement lands.

use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::time::Duration;

use codewire_egress_front_door_bridge::{Ended, EnvironmentFrontDoor};
use codewire_egress_policy::handoff::HandoffReceiver;
use codewire_egress_policy::intercept::InterceptSet;
use rustix::net::SocketType;
use uuid::Uuid;

use crate::broker_control::{ControlFrame, read_control_frame};
pub(crate) use control::ControlChannel;
mod control;

use crate::linux::confinement::{
    install_denied_syscalls, install_deny_all_filesystem_domain, lock_process_privileges,
};
use crate::linux::syscall_floor::DENIED_SYSCALL_FLOOR;

/// The control socket's descriptor in the front-door process.
pub const FRONT_DOOR_CONTROL_FD: RawFd = 4;
pub const FRONT_DOOR_READY_MESSAGE: &[u8] = b"CWFD1 ready\n";
pub const FRONT_DOOR_SOCKETS_MESSAGE: &[u8] = b"CWFD1 sockets\n";
/// A later credential broker's session, for its renewal.
pub const FRONT_DOOR_CREDENTIALS_MESSAGE: &[u8] = b"CWFD1 credentials\n";
/// The front door's word that it checked a pairing's sockets and serves
/// them: this prefix, the pairing's number in decimal, and a line feed.
pub const FRONT_DOOR_SERVING_PREFIX: &[u8] = b"CWFD1 serving ";

/// The serving word for the generation's `pairing`th pairing frame.
pub fn front_door_serving_message(pairing: u64) -> Vec<u8> {
    let mut message = FRONT_DOOR_SERVING_PREFIX.to_vec();
    message.extend_from_slice(pairing.to_string().as_bytes());
    message.push(b'\n');
    message
}

/// The pairing a serving word names. None for anything but the prefix, a
/// decimal number from 1 that fits a `u64`, with no sign and no leading
/// zero, and one line feed: a word is matched to its pairing, never guessed.
pub fn front_door_serving_pairing(message: &[u8]) -> Option<u64> {
    let digits = message
        .strip_prefix(FRONT_DOOR_SERVING_PREFIX)?
        .strip_suffix(b"\n")?;
    if digits.first().is_none_or(|first| *first == b'0')
        || digits.len() > 20
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}
/// The egress broker's first frame on the hand-off socket (#3999).
pub use codewire_egress_policy::handoff::HANDOFF_ROLE_TAG;
/// The credential broker's first byte on the front-door session socket.
pub const FRONT_DOOR_CREDENTIAL_TAG: u8 =
    codewire_egress_front_door_bridge::FRONT_DOOR_SESSION_ROLE_TAG;
/// How long each peer's role tag may take to arrive.
pub const ROLE_TAG_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const FRONT_DOOR_FAILED_PREFIX: &[u8] = b"CWFD1 failed ";
/// The largest message the runner sends: an interception frame of 32
/// bindings, each at most 255 bytes of name.
const MAX_CONTROL_MESSAGE: usize = 6 + 32 * (1 + 255 + 2);
/// How long the runner has to send the bindings.
const BINDINGS_TIMEOUT: Duration = Duration::from_secs(5);

/// What a local front door refuses after it starts, beyond the shared
/// floor. The process makes no connection, opens no file and starts nothing.
const FRONT_DOOR_DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_connect,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_name_to_handle_at,
    libc::SYS_capset,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
];
#[cfg(target_arch = "x86_64")]
const FRONT_DOOR_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[libc::SYS_fork, libc::SYS_vfork];
#[cfg(target_arch = "aarch64")]
const FRONT_DOOR_ARCH_DENIED_SYSCALLS: &[libc::c_long] = &[];

/// The shared floor and the front door's own denials.
fn front_door_denied_syscalls() -> Vec<libc::c_long> {
    [DENIED_SYSCALL_FLOOR, FRONT_DOOR_DENIED_SYSCALLS].concat()
}

/// Why the front-door process stopped. Each names a fixed stage, so it can
/// be written to the runner and logged.
#[derive(Debug, thiserror::Error)]
pub enum FrontDoorProcessError {
    #[error("front door control socket is unusable")]
    Control,
    #[error("front door environment id is not canonical")]
    Identity,
    #[error("front door bindings are missing or invalid")]
    Bindings,
    #[error("front door could not confine itself")]
    Confinement,
    #[error("front door could not start")]
    Start,
    #[error("front door sockets are missing or invalid")]
    Sockets,
    #[error("front door stopped: {0}")]
    Ended(#[source] Ended),
}

impl FrontDoorProcessError {
    fn stage(&self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Identity => "identity",
            Self::Bindings => "bindings",
            Self::Confinement => "confinement",
            Self::Start => "start",
            Self::Sockets => "sockets",
            Self::Ended(_) => "ended",
        }
    }
}

/// Entrypoint used only by the hidden `cw` front-door command.
pub async fn run_inherited_front_door(
    environment_id: &str,
    generation: u64,
) -> Result<(), FrontDoorProcessError> {
    let control = inherited_control(FRONT_DOOR_CONTROL_FD)?;
    let mut control = ControlChannel::new(control).map_err(|_| FrontDoorProcessError::Control)?;
    let result = match canonical_environment_id(environment_id) {
        Ok(environment_id) => start_and_serve(&mut control, environment_id, generation).await,
        Err(error) => Err(error),
    };
    if let Err(error) = &result
        && !matches!(error, FrontDoorProcessError::Ended(_))
    {
        let mut line = FRONT_DOOR_FAILED_PREFIX.to_vec();
        line.extend_from_slice(error.stage().as_bytes());
        line.push(b'\n');
        // The runner may already be gone; the exit status says the same.
        let _ = control.send(&line, &[]).await;
    }
    result
}

async fn start_and_serve(
    control: &mut ControlChannel,
    environment_id: Uuid,
    generation: u64,
) -> Result<(), FrontDoorProcessError> {
    let intercepts = receive_bindings(control).await?;
    lock_process_privileges()
        .and_then(|()| install_deny_all_filesystem_domain())
        .and_then(|()| {
            install_denied_syscalls(
                &front_door_denied_syscalls(),
                FRONT_DOOR_ARCH_DENIED_SYSCALLS,
            )
        })
        .map_err(|_| FrontDoorProcessError::Confinement)?;
    let door = EnvironmentFrontDoor::start(environment_id, generation, intercepts)
        .map_err(|_| FrontDoorProcessError::Start)?;
    let mut ready = FRONT_DOOR_READY_MESSAGE.to_vec();
    ready.extend_from_slice(door.ca_certificate_der());
    control
        .send(&ready, &[])
        .await
        .map_err(|_| FrontDoorProcessError::Control)?;
    let (handoff, credentials) = receive_sockets(control).await?;
    control
        .send(&front_door_serving_message(1), &[])
        .await
        .map_err(|_| FrontDoorProcessError::Control)?;
    let (successors, later) = tokio::sync::mpsc::channel(1);
    let serve = door.serve(handoff, credentials, later);
    tokio::pin!(serve);
    // Once the control channel closes or misbehaves, no successor can pair:
    // dropping the sender lets the front door end.
    let feed = async move {
        // The sockets frame was the generation's first pairing frame.
        let mut pairing = 1_u64;
        while let Some(credentials) = receive_credentials(control, &mut pairing).await {
            if successors.send(credentials).await.is_err() {
                break;
            }
        }
    };
    let ended = tokio::select! {
        ended = &mut serve => ended,
        () = feed => serve.await,
    };
    Err(FrontDoorProcessError::Ended(ended))
}

/// The next later credential broker's admitted session; none once the
/// control channel closes or carries anything but a credentials frame.
/// `pairing` counts the generation's pairing frames, each credentials frame
/// received among them.
async fn receive_credentials(
    control: &mut ControlChannel,
    pairing: &mut u64,
) -> Option<tokio::net::UnixStream> {
    loop {
        let (message, descriptors) = control.receive(MAX_CONTROL_MESSAGE, 1).await.ok()?;
        let Ok([credentials]) = <[OwnedFd; 1]>::try_from(descriptors) else {
            return None;
        };
        if message != FRONT_DOOR_CREDENTIALS_MESSAGE {
            return None;
        }
        *pairing = pairing.checked_add(1)?;
        // One broker's failed checks drop only its socket, without a word;
        // the runner records that pairing as unacknowledged, and the next
        // broker pairs.
        if let Some(credentials) = admitted_credentials(credentials).await {
            control
                .send(&front_door_serving_message(*pairing), &[])
                .await
                .ok()?;
            return Some(credentials);
        }
    }
}

async fn receive_bindings(
    control: &mut ControlChannel,
) -> Result<InterceptSet, FrontDoorProcessError> {
    // A frame with a descriptor is refused by the channel itself.
    let (message, _) =
        tokio::time::timeout(BINDINGS_TIMEOUT, control.receive(MAX_CONTROL_MESSAGE, 0))
            .await
            .map_err(|_| FrontDoorProcessError::Bindings)?
            .map_err(|_| FrontDoorProcessError::Bindings)?;
    match read_control_frame(&mut message.as_slice()).await {
        Ok(ControlFrame::ReplaceIntercepts(intercepts)) if !intercepts.is_empty() => Ok(intercepts),
        _ => Err(FrontDoorProcessError::Bindings),
    }
}

/// The hand-off end and the credential session, both connected Unix
/// streams, in that order, in one frame.
async fn receive_sockets(
    control: &mut ControlChannel,
) -> Result<(OwnedFd, tokio::net::UnixStream), FrontDoorProcessError> {
    let (message, descriptors) = control
        .receive(MAX_CONTROL_MESSAGE, 2)
        .await
        .map_err(|_| FrontDoorProcessError::Sockets)?;
    let Ok([handoff, credentials]) = <[OwnedFd; 2]>::try_from(descriptors) else {
        return Err(FrontDoorProcessError::Sockets);
    };
    if message != FRONT_DOOR_SOCKETS_MESSAGE
        || !admitted_socket(&handoff, SocketType::STREAM)
        || !handoff_role_tagged(&handoff)
    {
        return Err(FrontDoorProcessError::Sockets);
    }
    let credentials = admitted_credentials(credentials)
        .await
        .ok_or(FrontDoorProcessError::Sockets)?;
    Ok((handoff, credentials))
}

/// A credential broker's session, when it is a connected Unix stream that
/// closes on exec and its first byte is the broker's role tag.
async fn admitted_credentials(credentials: OwnedFd) -> Option<tokio::net::UnixStream> {
    if !admitted_socket(&credentials, SocketType::STREAM) {
        return None;
    }
    let credentials = std::os::unix::net::UnixStream::from(credentials);
    credentials.set_nonblocking(true).ok()?;
    let mut credentials = tokio::net::UnixStream::from_std(credentials).ok()?;
    let deadline = tokio::time::Instant::now() + ROLE_TAG_TIMEOUT;
    credential_role_tagged(&mut credentials, deadline)
        .await
        .then_some(credentials)
}

/// Whether the hand-off end's first frame is the egress broker's role tag.
/// Read blocking, within [`ROLE_TAG_TIMEOUT`], before anything is served.
fn handoff_role_tagged(handoff: &OwnedFd) -> bool {
    // The receiver that reads the tag is dropped after it; the front door's
    // own receiver starts at the first intercepted stream.
    rustix::io::fcntl_dupfd_cloexec(handoff, 0)
        .ok()
        .and_then(|duplicate| HandoffReceiver::new(duplicate).ok())
        .is_some_and(|mut receiver| receiver.expect_role_tag(ROLE_TAG_TIMEOUT).is_ok())
}

/// Whether the credential end's first byte is the credential broker's role
/// tag, read by `deadline` before the bridge Open. It waits without blocking
/// the process: a successor broker pairs while earlier sessions serve, and a
/// late tag must stall none of them.
async fn credential_role_tagged(
    credentials: &mut tokio::net::UnixStream,
    deadline: tokio::time::Instant,
) -> bool {
    use tokio::io::AsyncReadExt as _;
    let mut tag = [0_u8; 1];
    matches!(
        tokio::time::timeout_at(deadline, credentials.read_exact(&mut tag)).await,
        Ok(Ok(_))
    ) && tag[0] == FRONT_DOOR_CREDENTIAL_TAG
}

/// The inherited control descriptor, admitted only as a connected Unix
/// stream and made close-on-exec.
fn inherited_control(descriptor: RawFd) -> Result<OwnedFd, FrontDoorProcessError> {
    // SAFETY: the runner places the control socket at this fixed descriptor
    // before exec and nothing else in this process opens or owns it; taking
    // ownership here happens once, before any other code runs.
    let control = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let admitted = rustix::io::fcntl_setfd(&control, rustix::io::FdFlags::CLOEXEC).is_ok()
        && admitted_socket(&control, SocketType::STREAM);
    if !admitted {
        return Err(FrontDoorProcessError::Control);
    }
    Ok(control)
}

/// Whether `descriptor` is a connected Unix socket of the `expected` type
/// that closes on exec: the checks the egress broker runs on its own
/// inherited ends. The peer is only required to exist, never read.
fn admitted_socket(descriptor: &OwnedFd, expected: SocketType) -> bool {
    rustix::net::sockopt::socket_domain(descriptor) == Ok(rustix::net::AddressFamily::UNIX)
        && rustix::net::sockopt::socket_type(descriptor) == Ok(expected)
        && rustix::io::fcntl_getfd(descriptor)
            .is_ok_and(|flags| flags.contains(rustix::io::FdFlags::CLOEXEC))
        && rustix::net::getpeername(descriptor).is_ok()
}

/// The environment id exactly as `Uuid` writes it: lowercase, hyphenated,
/// not nil. The hand-off header must carry the same string.
fn canonical_environment_id(environment_id: &str) -> Result<Uuid, FrontDoorProcessError> {
    Uuid::parse_str(environment_id)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == environment_id)
        .ok_or(FrontDoorProcessError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tag that comes late is still read by the deadline, without
    /// blocking anything else; silence or another byte is refused.
    #[tokio::test]
    async fn the_credential_tag_is_read_to_its_deadline_without_blocking() {
        use tokio::io::AsyncWriteExt as _;
        let (mut front_door, mut broker) = tokio::net::UnixStream::pair().unwrap();
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            broker
                .write_all(&[FRONT_DOOR_CREDENTIAL_TAG])
                .await
                .unwrap();
            broker
        });
        let deadline = tokio::time::Instant::now() + ROLE_TAG_TIMEOUT;
        assert!(credential_role_tagged(&mut front_door, deadline).await);
        drop(late.await.unwrap());

        let (mut front_door, mut broker) = tokio::net::UnixStream::pair().unwrap();
        broker.write_all(b"H").await.unwrap();
        let deadline = tokio::time::Instant::now() + ROLE_TAG_TIMEOUT;
        assert!(!credential_role_tagged(&mut front_door, deadline).await);

        // Silence until a deadline already past: refused at once.
        let (mut front_door, _broker) = tokio::net::UnixStream::pair().unwrap();
        assert!(!credential_role_tagged(&mut front_door, tokio::time::Instant::now()).await);
    }

    #[test]
    fn the_front_door_denies_the_shared_floor_and_its_own_calls() {
        let denied = front_door_denied_syscalls();
        for call in DENIED_SYSCALL_FLOOR.iter().chain([
            &libc::SYS_socket,
            &libc::SYS_connect,
            &libc::SYS_clone,
            &libc::SYS_clone3,
        ]) {
            assert!(denied.contains(call), "{call}");
        }
    }
}
