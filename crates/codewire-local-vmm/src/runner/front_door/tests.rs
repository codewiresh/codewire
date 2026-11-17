use codewire_egress_policy::handoff::{HandoffReceiver, HandoffSender};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

/// Generous, so a loaded CI host fails only a missing frame.
const WAIT: Duration = Duration::from_secs(30);

/// The test's side of a front door's control socket: blocking, with a
/// receive deadline so a missing frame fails the test instead of hanging it.
struct FakeFrontDoor {
    receiver: HandoffReceiver,
    sender: HandoffSender,
}

impl FakeFrontDoor {
    fn new(socket: OwnedFd) -> Self {
        rustix::net::sockopt::set_socket_timeout(
            &socket,
            rustix::net::sockopt::Timeout::Recv,
            Some(WAIT),
        )
        .unwrap();
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&socket, 0).unwrap();
        Self {
            receiver: HandoffReceiver::new(socket).unwrap(),
            sender: HandoffSender::new(duplicate).unwrap(),
        }
    }

    /// The next frame the runner sent, and its descriptors.
    fn received(&mut self) -> (Vec<u8>, Vec<OwnedFd>) {
        tokio::task::block_in_place(|| self.receiver.recv_frame(MAX_READY_MESSAGE, 2)).unwrap()
    }

    fn reply(&mut self, body: &[u8]) {
        self.sender.send_frame(body, &[]).unwrap();
    }
}

/// A front-door process stand-in: a child that only waits, and the test's
/// end of its control socket, where passed sockets arrive.
fn stand_in() -> (FrontDoorProcess, FakeFrontDoor) {
    let (runner_end, front_door_end) = stream_pair().unwrap();
    let child = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let process = FrontDoorProcess {
        child,
        control: Some(ControlChannel::new(runner_end).unwrap()),
        ca_der: Vec::new(),
    };
    (process, FakeFrontDoor::new(front_door_end))
}

async fn connect_presenting(socket: &Path, capability: &[u8]) -> tokio::net::UnixStream {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream
        .write_u16(u16::try_from(capability.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(capability).await.unwrap();
    stream
}

/// The connection is refused: the runner closes it without a byte.
async fn refused(mut stream: tokio::net::UnixStream) {
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(WAIT, stream.read(&mut byte)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))));
}

struct Pairing {
    _directory: tempfile::TempDir,
    socket: std::path::PathBuf,
    /// The boot's pairing secret, as its credential brokers receive it.
    capability: Vec<u8>,
    front_door: FakeFrontDoor,
    /// The egress broker's end of the hand-off pair.
    handoff: OwnedFd,
    /// The front door's end, until [`Self::hand_off`] passes it.
    front_door_handoff: Option<OwnedFd>,
    running: RunningFrontDoor,
}

impl Pairing {
    fn hand_off(&mut self) -> Result<(), RunnerError> {
        self.running
            .hand_off(self.front_door_handoff.take().unwrap())
    }
}

/// A bound pairing whose egress broker is not up yet.
fn listening() -> Pairing {
    // The socket's directory must be private to its owner.
    let directory = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let socket = directory.path().join("credentials.sock");
    let (process, front_door) = stand_in();
    let (handoff, front_door_handoff) = stream_pair().unwrap();
    let secrets = BootSecrets::mint();
    let capability = secrets.pairing().to_vec();
    let running = RunningFrontDoor::listen(process, &socket, secrets).unwrap();
    Pairing {
        _directory: directory,
        socket,
        capability,
        front_door,
        handoff,
        front_door_handoff: Some(front_door_handoff),
        running,
    }
}

/// A bound pairing with the egress broker's hand-off end.
fn pairing() -> Pairing {
    let mut pairing = listening();
    pairing.hand_off().unwrap();
    pairing
}

/// The socket exists from the moment the front door does, before the
/// generation's access names it: a credential broker that connects before
/// the egress broker is up waits, and is paired once the hand-off end
/// arrives.
#[tokio::test(flavor = "multi_thread")]
async fn a_broker_that_connects_before_the_handoff_is_paired_once_it_arrives() {
    let mut pairing = listening();
    assert_eq!(pairing.running.socket(), pairing.socket);
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.hand_off().unwrap();
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    assert_eq!(descriptors.len(), 2);
}

/// The hand-off end is given once; a front door already gone refuses it,
/// failing the boot, and the end closes rather than staying with the runner.
#[tokio::test(flavor = "multi_thread")]
async fn the_handoff_end_is_given_once_and_refused_by_a_front_door_already_gone() {
    let mut pairing = pairing();
    let (_, spare) = stream_pair().unwrap();
    assert!(matches!(
        pairing.running.hand_off(spare),
        Err(RunnerError::FrontDoor(FrontDoorFailure::Sockets))
    ));

    let Pairing {
        _directory,
        socket,
        front_door,
        handoff,
        front_door_handoff,
        mut running,
        ..
    } = listening();
    drop(front_door);
    let deadline = tokio::time::Instant::now() + WAIT;
    while socket.exists() {
        assert!(tokio::time::Instant::now() < deadline, "the socket stays");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(matches!(
        running.hand_off(front_door_handoff.unwrap()),
        Err(RunnerError::FrontDoor(FrontDoorFailure::Sockets))
    ));
    let mut byte = [0_u8; 1];
    let read = tokio::task::block_in_place(|| rustix::io::read(&handoff, &mut byte));
    assert_eq!(read, Ok(0), "the egress broker's end sees the close");
}

/// The credential broker that presents this generation's capability is
/// handed to the front door with the hand-off end, and bytes then cross.
#[tokio::test(flavor = "multi_thread")]
async fn the_broker_with_this_generations_capability_is_paired_with_the_front_door() {
    let mut pairing = pairing();
    let mut broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    let [handoff, credentials] = <[OwnedFd; 2]>::try_from(descriptors).unwrap();

    broker.write_all(b"open").await.unwrap();
    let mut received = [0_u8; 4];
    rustix::io::read(&credentials, &mut received).unwrap();
    assert_eq!(&received, b"open");
    rustix::io::write(&pairing.handoff, b"h").unwrap();
    let mut byte = [0_u8; 1];
    rustix::io::read(&handoff, &mut byte).unwrap();
    assert_eq!(&byte, b"h");
}

/// A stale or wrong capability is refused, and the generation's own broker
/// still pairs after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_capability_is_refused_and_the_right_one_still_pairs() {
    let mut pairing = pairing();
    for presented in [
        b"a-previous-generation-capability".as_slice(),
        b"this-generation-capabilitX",
        b"",
    ] {
        refused(connect_presenting(&pairing.socket, presented).await).await;
    }
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    assert_eq!(descriptors.len(), 2);
}

/// Only the boot's own pairing secret pairs. The daemon token, which the
/// guest knows and the seed carried, is refused, as is any other value
/// (#3999).
#[tokio::test(flavor = "multi_thread")]
async fn only_the_boots_pairing_secret_pairs_never_the_daemon_token() {
    let mut pairing = pairing();
    let daemon_token = "0f".repeat(32);
    refused(connect_presenting(&pairing.socket, daemon_token.as_bytes()).await).await;
    refused(connect_presenting(&pairing.socket, BootSecrets::mint().pairing()).await).await;
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    assert_eq!(descriptors.len(), 2);
}

/// The credential authority replaces a generation's broker every few
/// minutes, and each successor pairs again (#3999): the socket stays, each
/// later broker's session reaches the front door alone, and a stale
/// capability is still refused between them.
#[tokio::test(flavor = "multi_thread")]
async fn each_renewed_broker_pairs_again_with_its_own_session() {
    let mut pairing = pairing();
    let _first = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    assert_eq!(descriptors.len(), 2);

    refused(connect_presenting(&pairing.socket, b"a-previous-generation-capability").await).await;
    for _renewal in 0..2 {
        let mut successor = connect_presenting(&pairing.socket, &pairing.capability).await;
        let (message, descriptors) = pairing.front_door.received();
        assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
        let [credentials] = <[OwnedFd; 1]>::try_from(descriptors).unwrap();
        successor.write_all(b"open").await.unwrap();
        let mut received = [0_u8; 4];
        rustix::io::read(&credentials, &mut received).unwrap();
        assert_eq!(&received, b"open");
    }
    assert!(pairing.socket.exists());
}

#[test]
fn capabilities_compare_by_every_byte_and_their_length() {
    assert!(constant_time_equal(b"same", b"same"));
    assert!(!constant_time_equal(b"same", b"samf"));
    assert!(!constant_time_equal(b"same", b"sam"));
    assert!(constant_time_equal(b"", b""));
}

fn bindings() -> InterceptSet {
    InterceptSet::new([codewire_egress_policy::intercept::InterceptBinding::new(
        "api.anthropic.com",
        443,
    )
    .unwrap()])
    .unwrap()
}

/// The runner sends the bindings as one interception frame and takes the
/// CA certificate from the ready message that answers it.
#[tokio::test(flavor = "multi_thread")]
async fn start_sends_the_bindings_and_returns_the_reported_certificate() {
    let (mut process, mut front_door) = stand_in();
    let starting = tokio::spawn(async move { process.start(&bindings()).await });
    let (received, descriptors) = front_door.received();
    assert!(descriptors.is_empty());
    assert_eq!(received, encode_intercept_frame(&bindings()).unwrap());
    let mut ready = FRONT_DOOR_READY_MESSAGE.to_vec();
    ready.extend_from_slice(b"certificate-der");
    front_door.reply(&ready);
    assert_eq!(starting.await.unwrap().unwrap(), b"certificate-der");
}

/// A failure line, or a ready message without a certificate, fails the boot.
#[tokio::test(flavor = "multi_thread")]
async fn a_front_door_that_reports_failure_fails_the_boot() {
    for reply in [
        b"CWFD1 failed confinement\n".as_slice(),
        FRONT_DOOR_READY_MESSAGE,
    ] {
        let (mut process, mut front_door) = stand_in();
        let starting = tokio::spawn(async move { process.start(&bindings()).await });
        front_door.received();
        front_door.reply(reply);
        assert!(matches!(
            starting.await.unwrap(),
            Err(RunnerError::FrontDoor(FrontDoorFailure::Startup))
        ));
    }
}

/// A front door that never answers fails the boot at its deadline.
#[tokio::test(start_paused = true)]
async fn a_front_door_that_never_answers_fails_the_boot_at_its_deadline() {
    let (mut process, _front_door) = stand_in();
    assert!(matches!(
        process.start(&bindings()).await,
        Err(RunnerError::FrontDoor(FrontDoorFailure::StartTimeout))
    ));
}

/// A front door that dies before its broker pairs takes its hand-off end
/// with it: the runner keeps no copy, so the egress broker's end sees the
/// close, and the pairing socket goes away.
#[tokio::test(flavor = "multi_thread")]
async fn a_front_door_that_dies_before_pairing_closes_its_handoff_end() {
    let pairing = pairing();
    drop(pairing.front_door);
    let mut byte = [0_u8; 1];
    rustix::net::sockopt::set_socket_timeout(
        &pairing.handoff,
        rustix::net::sockopt::Timeout::Recv,
        Some(WAIT),
    )
    .unwrap();
    let read = tokio::task::block_in_place(|| rustix::io::read(&pairing.handoff, &mut byte));
    assert_eq!(read, Ok(0), "the egress broker's end sees the close");
    let deadline = tokio::time::Instant::now() + WAIT;
    while pairing.socket.exists() {
        assert!(tokio::time::Instant::now() < deadline, "the socket stays");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
