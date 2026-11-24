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
//!    pairing's. For a later broker's socket it does not take it says
//!    [`front_door_dropped_message`] instead, with the same number and why,
//!    and goes on to the next pairing; if the first pairing's sockets fail it
//!    ends with a failure line. A socket that reads end of file before any
//!    byte is named `received_dead` in both, apart from one whose role tag
//!    is wrong or late: on macOS a socket can die in flight (#4916), and the
//!    name is what tells that from a peer that misbehaved.
//!
//! 6. front door, once it serves: its refusal reports ([`refusals`], #5058),
//!    at most one a second, which the runner reads as untrusted.
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
//! exists inside the confined process: on Linux with no new privileges,
//! Landlock and a syscall filter, on macOS with Seatbelt's deny-all profile
//! ([`confine`]). It then serves until the hand-off ends or the control
//! channel closes, and exits; the runner treats that exit as the front door
//! dying, which fails closed. A credential session ending ends nothing: the
//! next broker to pair serves. A later frame that is not a well-formed
//! credentials frame ends the front door; a socket in one that fails its
//! checks is dropped and the next pairing awaited.

use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::time::Duration;

use codewire_egress_front_door_bridge::{Ended, EnvironmentFrontDoor};
use codewire_egress_policy::handoff::HandoffError;
use codewire_egress_policy::intercept::InterceptSet;
use rustix::net::SocketType;
use uuid::Uuid;

use crate::broker_control::{ControlFrame, read_control_frame};

pub mod refusals;
pub(crate) use codewire_egress_front_door_bridge::control::ControlChannel;

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
/// pairing number and one line feed: a word is matched to its pairing, never
/// guessed.
pub fn front_door_serving_pairing(message: &[u8]) -> Option<u64> {
    pairing_number(
        message
            .strip_prefix(FRONT_DOOR_SERVING_PREFIX)?
            .strip_suffix(b"\n")?,
    )
}

/// A pairing number as the front door writes it: decimal, from 1, fitting a
/// `u64`, with no sign and no leading zero.
fn pairing_number(digits: &[u8]) -> Option<u64> {
    if digits.first().is_none_or(|first| *first == b'0')
        || digits.len() > 20
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The front door's word that it did not take a later pairing's socket: this
/// prefix, the pairing's number, a space, why, and a line feed. It goes on to
/// the next pairing.
pub const FRONT_DOOR_DROPPED_PREFIX: &[u8] = b"CWFD1 dropped ";

/// Why the front door did not take a socket it received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DroppedSocket {
    /// It read end of file before any byte: it arrived dead.
    ReceivedDead,
    /// Anything else: it is not a connected Unix stream, or its role tag was
    /// wrong or late.
    RoleTag,
}

impl DroppedSocket {
    pub fn stage(self) -> &'static str {
        match self {
            Self::ReceivedDead => "received_dead",
            Self::RoleTag => "role_tag",
        }
    }
}

/// The dropped word for the generation's `pairing`th pairing frame.
pub fn front_door_dropped_message(pairing: u64, why: DroppedSocket) -> Vec<u8> {
    let mut message = FRONT_DOOR_DROPPED_PREFIX.to_vec();
    message.extend_from_slice(pairing.to_string().as_bytes());
    message.push(b' ');
    message.extend_from_slice(why.stage().as_bytes());
    message.push(b'\n');
    message
}

/// The pairing a dropped word names, and why. None for anything but the
/// prefix, a pairing number, one space, a known stage and one line feed.
pub fn front_door_dropped_pairing(message: &[u8]) -> Option<(u64, DroppedSocket)> {
    let word = message
        .strip_prefix(FRONT_DOOR_DROPPED_PREFIX)?
        .strip_suffix(b"\n")?;
    let space = word.iter().position(|byte| *byte == b' ')?;
    let why = [DroppedSocket::ReceivedDead, DroppedSocket::RoleTag]
        .into_iter()
        .find(|why| why.stage().as_bytes() == &word[space + 1..])?;
    Some((pairing_number(&word[..space])?, why))
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
    #[error("a front door socket arrived dead")]
    ReceivedDead,
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
            Self::ReceivedDead => DroppedSocket::ReceivedDead.stage(),
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
    confine().map_err(|_| FrontDoorProcessError::Confinement)?;
    let reported = refusals::FrontDoorRefusals::new();
    let door = EnvironmentFrontDoor::start_reporting(
        environment_id,
        generation,
        intercepts,
        Some(reported.clone()),
    )
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
    let serve = door.serve(handoff, Some(credentials), later);
    tokio::pin!(serve);
    let (words, mut reports) = tokio::sync::mpsc::channel(1);
    // It ends once the control channel can't take a word.
    let reporter = tokio::spawn(async move {
        codewire_egress_broker::refusals::report_folded(reported.fold(), |batch| {
            let word = refusals::encode_report(&batch);
            let words = words.clone();
            async move { words.send(word).await }
        })
        .await
    });
    // Once the control channel closes or misbehaves, no successor can pair:
    // dropping the sender lets the front door end.
    let feed = async move {
        // The sockets frame was the generation's first pairing frame.
        let mut pairing = 1_u64;
        loop {
            tokio::select! {
                received = control.receive(MAX_CONTROL_MESSAGE, 1) => {
                    match receive_credentials(control, received, &mut pairing).await {
                        Some(Some(credentials)) => {
                            if successors.send(credentials).await.is_err() {
                                break;
                            }
                        }
                        Some(None) => {}
                        None => break,
                    }
                }
                Some(word) = reports.recv() => {
                    if control.send(&word, &[]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let ended = tokio::select! {
        ended = &mut serve => ended,
        () = feed => serve.await,
    };
    reporter.abort();
    Err(FrontDoorProcessError::Ended(ended))
}

/// A later credential broker's admitted session from the frame `received`:
/// `Some(None)` when the front door dropped its socket and said why, and
/// `None` once the control channel fails or carries anything but a
/// credentials frame. `pairing` counts the generation's pairing frames, each
/// credentials frame received among them.
async fn receive_credentials(
    control: &mut ControlChannel,
    received: std::io::Result<(Vec<u8>, Vec<OwnedFd>)>,
    pairing: &mut u64,
) -> Option<Option<tokio::net::UnixStream>> {
    let (message, descriptors) = received.ok()?;
    let Ok([credentials]) = <[OwnedFd; 1]>::try_from(descriptors) else {
        return None;
    };
    if message != FRONT_DOOR_CREDENTIALS_MESSAGE {
        return None;
    }
    *pairing = pairing.checked_add(1)?;
    // One broker's failed checks drop only its socket. The front door says
    // which pairing and why, and the next broker pairs.
    match admitted_credentials(credentials).await {
        Ok(credentials) => {
            control
                .send(&front_door_serving_message(*pairing), &[])
                .await
                .ok()?;
            Some(Some(credentials))
        }
        Err(why) => {
            control
                .send(&front_door_dropped_message(*pairing, why), &[])
                .await
                .ok()?;
            Some(None)
        }
    }
}

/// Confine the process for good as every front door does on Linux: no new
/// privileges, no filesystem, and a syscall filter that refuses new sockets,
/// connections, processes and signals.
#[cfg(target_os = "linux")]
fn confine() -> std::io::Result<()> {
    codewire_egress_front_door_bridge::confine::confine_front_door()
}

/// Confine the process for good with Seatbelt's deny-all profile: no file,
/// no named or network endpoint, no process, signal or Mach service, so it
/// works only with the descriptors it already holds and those passed to it.
/// Darwin has no no-new-privileges switch; nothing can execute once the
/// profile refuses process creation.
#[cfg(target_os = "macos")]
fn confine() -> std::io::Result<()> {
    crate::host::sandbox::confine_front_door()
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
    if message != FRONT_DOOR_SOCKETS_MESSAGE || !admitted_socket(&handoff, SocketType::STREAM) {
        return Err(FrontDoorProcessError::Sockets);
    }
    let first_pairing = |why| match why {
        DroppedSocket::ReceivedDead => FrontDoorProcessError::ReceivedDead,
        DroppedSocket::RoleTag => FrontDoorProcessError::Sockets,
    };
    handoff_role_tagged(&handoff).map_err(first_pairing)?;
    let credentials = admitted_credentials(credentials)
        .await
        .map_err(first_pairing)?;
    Ok((handoff, credentials))
}

/// A credential broker's session, when it is a connected Unix stream that
/// closes on exec and its first byte is the broker's role tag.
async fn admitted_credentials(
    credentials: OwnedFd,
) -> Result<tokio::net::UnixStream, DroppedSocket> {
    if !admitted_socket(&credentials, SocketType::STREAM) {
        return Err(DroppedSocket::RoleTag);
    }
    let credentials = std::os::unix::net::UnixStream::from(credentials);
    credentials
        .set_nonblocking(true)
        .map_err(|_| DroppedSocket::RoleTag)?;
    let mut credentials =
        tokio::net::UnixStream::from_std(credentials).map_err(|_| DroppedSocket::RoleTag)?;
    let deadline = tokio::time::Instant::now() + ROLE_TAG_TIMEOUT;
    credential_role_tagged(&mut credentials, deadline).await?;
    Ok(credentials)
}

/// Checks that the hand-off end's first frame is the egress broker's role
/// tag. Read blocking, within [`ROLE_TAG_TIMEOUT`], before anything is
/// served.
fn handoff_role_tagged(handoff: &OwnedFd) -> Result<(), DroppedSocket> {
    codewire_egress_front_door_bridge::handoff::expect_broker_role_tag(handoff, ROLE_TAG_TIMEOUT)
        .map_err(|error| match error {
            HandoffError::Closed => DroppedSocket::ReceivedDead,
            _ => DroppedSocket::RoleTag,
        })
}

/// Checks that the credential end's first byte is the credential broker's
/// role tag, read by `deadline` before the bridge Open. It waits without
/// blocking the process: a successor broker pairs while earlier sessions
/// serve, and a late tag must stall none of them.
async fn credential_role_tagged(
    credentials: &mut tokio::net::UnixStream,
    deadline: tokio::time::Instant,
) -> Result<(), DroppedSocket> {
    use tokio::io::AsyncReadExt as _;
    let mut tag = [0_u8; 1];
    match tokio::time::timeout_at(deadline, credentials.read_exact(&mut tag)).await {
        Ok(Ok(_)) if tag[0] == FRONT_DOOR_CREDENTIAL_TAG => Ok(()),
        // One byte is asked for, so an early end of file is before any byte.
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(DroppedSocket::ReceivedDead)
        }
        _ => Err(DroppedSocket::RoleTag),
    }
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
/// inherited ends. The peer is only required to exist, never read. The
/// family comes from the socket's own address, as
/// `codewire_egress_policy::handoff` reads it: macOS has no `SO_DOMAIN`.
fn admitted_socket(descriptor: &OwnedFd, expected: SocketType) -> bool {
    rustix::net::getsockname(descriptor)
        .is_ok_and(|address| address.address_family() == rustix::net::AddressFamily::UNIX)
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

#[cfg(all(test, target_os = "linux"))]
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
        assert_eq!(
            credential_role_tagged(&mut front_door, deadline).await,
            Ok(())
        );
        drop(late.await.unwrap());

        let (mut front_door, mut broker) = tokio::net::UnixStream::pair().unwrap();
        broker.write_all(b"H").await.unwrap();
        let deadline = tokio::time::Instant::now() + ROLE_TAG_TIMEOUT;
        assert_eq!(
            credential_role_tagged(&mut front_door, deadline).await,
            Err(DroppedSocket::RoleTag)
        );

        // Silence until a deadline already past: refused at once.
        let (mut front_door, _broker) = tokio::net::UnixStream::pair().unwrap();
        assert_eq!(
            credential_role_tagged(&mut front_door, tokio::time::Instant::now()).await,
            Err(DroppedSocket::RoleTag)
        );
    }

    /// A socket whose peer is gone before it wrote anything reads end of
    /// file before any byte: it arrived dead, which is not a peer with the
    /// wrong tag. Both of a pairing's sockets say which.
    #[tokio::test]
    async fn a_socket_at_end_of_file_before_any_byte_arrived_dead() {
        let (front_door, broker) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(broker);
        assert_eq!(
            admitted_credentials(OwnedFd::from(front_door))
                .await
                .map(|_| ()),
            Err(DroppedSocket::ReceivedDead)
        );

        let (front_door, egress_broker) = codewire_egress_policy::handoff::stream_pair().unwrap();
        drop(egress_broker);
        assert_eq!(
            handoff_role_tagged(&front_door),
            Err(DroppedSocket::ReceivedDead)
        );
    }

    #[test]
    fn a_dropped_word_is_read_strictly() {
        for why in [DroppedSocket::ReceivedDead, DroppedSocket::RoleTag] {
            assert_eq!(
                front_door_dropped_pairing(&front_door_dropped_message(7, why)),
                Some((7, why))
            );
        }
        assert_eq!(
            front_door_dropped_message(2, DroppedSocket::ReceivedDead),
            b"CWFD1 dropped 2 received_dead\n"
        );
        for malformed in [
            &b"CWFD1 dropped 2\n"[..],
            b"CWFD1 dropped 2 \n",
            b"CWFD1 dropped  received_dead\n",
            b"CWFD1 dropped 0 received_dead\n",
            b"CWFD1 dropped 02 received_dead\n",
            b"CWFD1 dropped 2 sockets\n",
            b"CWFD1 dropped 2 received_dead",
            b"CWFD1 dropped 2 received_dead \n",
            b"CWFD1 dropped 2  received_dead\n",
            b"CWFD1 serving 2\n",
        ] {
            assert_eq!(front_door_dropped_pairing(malformed), None, "{malformed:?}");
        }
        assert_eq!(
            front_door_serving_pairing(b"CWFD1 dropped 2 role_tag\n"),
            None
        );
    }
}
