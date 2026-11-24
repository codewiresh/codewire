use codewire_egress_policy::handoff::{HandoffReceiver, HandoffSender};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::front_door::{front_door_dropped_message, front_door_serving_message};

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
    let child = crate::test_tokio_command("sleep")
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
    let (mut pairing, log) = recording_pairing();
    let _first = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    assert_eq!(descriptors.len(), 2);
    pairing.front_door.reply(&front_door_serving_message(1));

    refused(connect_presenting(&pairing.socket, b"a-previous-generation-capability").await).await;
    for renewal in 2..=3 {
        let mut successor = connect_presenting(&pairing.socket, &pairing.capability).await;
        let (message, descriptors) = pairing.front_door.received();
        assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
        let [credentials] = <[OwnedFd; 1]>::try_from(descriptors).unwrap();
        successor.write_all(b"open").await.unwrap();
        let mut received = [0_u8; 4];
        rustix::io::read(&credentials, &mut received).unwrap();
        assert_eq!(&received, b"open");
        // Each pairing is recorded on the front door's word for it.
        pairing
            .front_door
            .reply(&front_door_serving_message(renewal));
        let paired = format!("outcome=paired pairing={renewal}");
        let lines = recorded(&log, "front_door_pairing", &paired).await;
        assert_eq!(
            lines.iter().filter(|line| line.ends_with(&paired)).count(),
            1
        );
    }
    assert!(pairing.socket.exists());
}

/// The runner keeps its copy of each end it sends until the front door says
/// it serves them, and none after: a socket whose only reference is in flight
/// can arrive dead on macOS once its sender has closed its last copy (#4916).
/// Here the front door closes what it received, so each peer sees the end of
/// its stream exactly when the runner lets go.
#[tokio::test(flavor = "multi_thread")]
async fn the_runner_holds_the_ends_it_sent_until_the_front_door_answers() {
    let mut pairing = pairing();
    let mut broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);
    drop(descriptors);

    let mut byte = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), broker.read(&mut byte))
            .await
            .is_err(),
        "the runner still holds the credential end"
    );
    rustix::net::sockopt::set_socket_timeout(
        &pairing.handoff,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_millis(300)),
    )
    .unwrap();
    assert_eq!(
        tokio::task::block_in_place(|| rustix::io::read(&pairing.handoff, &mut byte)),
        Err(rustix::io::Errno::AGAIN),
        "the runner still holds the hand-off end"
    );

    // Set before the end is released: macOS refuses socket options on a
    // socket whose peer has gone (EINVAL).
    rustix::net::sockopt::set_socket_timeout(
        &pairing.handoff,
        rustix::net::sockopt::Timeout::Recv,
        Some(WAIT),
    )
    .unwrap();

    pairing.front_door.reply(&front_door_serving_message(1));
    assert_eq!(
        tokio::time::timeout(WAIT, broker.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "the runner released the credential end"
    );
    assert_eq!(
        tokio::task::block_in_place(|| rustix::io::read(&pairing.handoff, &mut byte)),
        Ok(0),
        "the runner released the hand-off end"
    );
}

/// A front door that says nothing about a later pairing leaves it recorded
/// as unacknowledged at the limit, never as paired; its word, when it comes
/// late, is recorded then; and the next broker still pairs.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_pairing_the_front_door_says_nothing_about_is_unacknowledged() {
    let (mut pairing, log) = recording_pairing();
    let _first = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    pairing.front_door.reply(&front_door_serving_message(1));

    let mut second = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
    // The front door drops this socket; the runner's copy goes at the limit.
    drop(descriptors);
    let lines = recorded(
        &log,
        "front_door_pairing",
        "outcome=unacknowledged pairing=2",
    )
    .await;
    assert_eq!(
        tokio::time::timeout(WAIT, second.read(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "the runner released its copy of the dropped broker's end"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.ends_with("outcome=paired pairing=2")),
        "{lines:?}"
    );

    pairing.front_door.reply(&front_door_serving_message(2));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=2").await;

    let _third = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, _descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
    pairing.front_door.reply(&front_door_serving_message(3));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=3").await;
}

/// The front door's word names its pairing, so one that arrives late is
/// never taken for the next pairing's. Here pairing 2 goes unanswered, and
/// its word comes while the runner waits for pairing 3: it is recorded for
/// pairing 2, and the runner still holds pairing 3's end, whose copy at the
/// front door is already closed, until pairing 3's own word. A word said
/// twice changes nothing, and a number not yet sent is not this protocol.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_word_is_recorded_for_its_own_pairing_and_releases_no_other() {
    let (mut pairing, log) = recording_pairing();
    let _first = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    pairing.front_door.reply(&front_door_serving_message(1));

    let _second = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (_message, _slow) = pairing.front_door.received();
    recorded(
        &log,
        "front_door_pairing",
        "outcome=unacknowledged pairing=2",
    )
    .await;

    let mut third = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
    drop(descriptors);
    pairing.front_door.reply(&front_door_serving_message(2));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=2").await;
    // Read from the socket itself: the runtime's own readiness can lag it.
    assert_eq!(
        rustix::io::read(&third, &mut [0_u8; 1]),
        Err(rustix::io::Errno::AGAIN),
        "the runner still holds pairing 3's end after pairing 2's late word"
    );
    assert!(
        events(&log, "front_door_pairing")
            .iter()
            .all(|line| !line.ends_with("pairing=3"))
    );

    pairing.front_door.reply(&front_door_serving_message(3));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=3").await;
    assert_eq!(
        tokio::time::timeout(WAIT, third.read(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "the runner released pairing 3's end on its own word"
    );

    pairing.front_door.reply(&front_door_serving_message(2));
    recorded(
        &log,
        "front_door_pairing",
        "outcome=unexpected_serving pairing=2",
    )
    .await;
    pairing.front_door.reply(&front_door_serving_message(9));
    let lines = recorded(
        &log,
        "front_door_pairing",
        "outcome=front_door_refused stage=invalid",
    )
    .await;
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("outcome=paired"))
            .count(),
        3,
        "{lines:?}"
    );
}

/// For a later broker's socket it does not take, the front door says which
/// pairing and why. The runner records that at once, with the stage, lets go
/// of its copy without waiting out the limit, and the next broker pairs. A
/// dropped word said twice changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_socket_the_front_door_drops_is_recorded_with_its_stage() {
    let (mut pairing, log) = recording_pairing();
    let _first = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    pairing.front_door.reply(&front_door_serving_message(1));

    let asked = std::time::Instant::now();
    let mut second = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
    drop(descriptors);
    pairing
        .front_door
        .reply(&front_door_dropped_message(2, DroppedSocket::ReceivedDead));
    let lines = recorded(
        &log,
        "front_door_pairing",
        "outcome=front_door_dropped stage=received_dead pairing=2",
    )
    .await;
    assert_eq!(
        tokio::time::timeout(WAIT, second.read(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "the runner released its copy of the dropped broker's end"
    );
    assert!(asked.elapsed() < SERVING_TIMEOUT, "released on the word");
    assert!(
        !lines.iter().any(|line| line.contains("unacknowledged")),
        "{lines:?}"
    );

    let _third = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, _descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_CREDENTIALS_MESSAGE);
    pairing.front_door.reply(&front_door_serving_message(3));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=3").await;

    pairing
        .front_door
        .reply(&front_door_dropped_message(2, DroppedSocket::RoleTag));
    recorded(
        &log,
        "front_door_pairing",
        "outcome=unexpected_dropped pairing=2",
    )
    .await;
}

#[test]
fn a_serving_word_is_read_strictly() {
    assert_eq!(front_door_serving_pairing(b"CWFD1 serving 1\n"), Some(1));
    assert_eq!(
        front_door_serving_pairing(&front_door_serving_message(u64::MAX)),
        Some(u64::MAX)
    );
    for malformed in [
        &b"CWFD1 serving\n"[..],
        b"CWFD1 serving \n",
        b"CWFD1 serving 0\n",
        b"CWFD1 serving 01\n",
        b"CWFD1 serving +1\n",
        b"CWFD1 serving 1",
        b"CWFD1 serving 1\n\n",
        b"CWFD1 serving 1 \n",
        b"CWFD1 serving 18446744073709551616\n",
        b"CWFD1 serving 111111111111111111111\n",
        b"CWFD1 failed sockets\n",
    ] {
        assert_eq!(front_door_serving_pairing(malformed), None, "{malformed:?}");
    }
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

/// A private log the runner records in, and where to read it back.
fn recording() -> (std::sync::Arc<DiagnosticLog>, tempfile::NamedTempFile) {
    let file = tempfile::NamedTempFile::new().unwrap();
    let log = DiagnosticLog::adopt(file.reopen().unwrap()).unwrap();
    (std::sync::Arc::new(log), file)
}

/// The log's lines for `event`, once one holding `needle` is there.
async fn recorded(log: &tempfile::NamedTempFile, event: &str, needle: &str) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let lines = events(log, event);
        if lines.iter().any(|line| line.contains(needle)) {
            return lines;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no {event} line with {needle}: {lines:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn events(log: &tempfile::NamedTempFile, event: &str) -> Vec<String> {
    std::fs::read_to_string(log.path())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains(&format!(" event={event} ")) || line.ends_with(&format!(" event={event}"))
        })
        .map(str::to_owned)
        .collect()
}

/// A pairing, with the egress broker's hand-off end, that records in a log
/// the test reads.
fn recording_pairing() -> (Pairing, tempfile::NamedTempFile) {
    let directory = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let socket = directory.path().join("credentials.sock");
    let (process, front_door) = stand_in();
    let (handoff, front_door_handoff) = stream_pair().unwrap();
    let (log, file) = recording();
    let secrets = BootSecrets::mint();
    let capability = secrets.pairing().to_vec();
    let running = RunningFrontDoor::listen_recording(process, &socket, secrets, Some(log)).unwrap();
    let mut pairing = Pairing {
        _directory: directory,
        socket,
        capability,
        front_door,
        handoff,
        front_door_handoff: Some(front_door_handoff),
        running,
    };
    pairing.hand_off().unwrap();
    (pairing, file)
}

/// The pairing is recorded, once, when the front door says it serves. That
/// it is not recorded on the send alone is what the two tests below show: a
/// front door that refuses or goes is never recorded as paired.
#[tokio::test(flavor = "multi_thread")]
async fn a_pairing_is_recorded_once_the_front_door_says_it_serves() {
    let (mut pairing, log) = recording_pairing();
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    let (message, _descriptors) = pairing.front_door.received();
    assert_eq!(message, FRONT_DOOR_SOCKETS_MESSAGE);

    pairing.front_door.reply(&front_door_serving_message(1));
    let lines = recorded(&log, "front_door_pairing", "outcome=paired").await;
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// A front door that refuses the sockets it was sent is recorded as refusing
/// them, with the stage it named, and never as paired.
#[tokio::test(flavor = "multi_thread")]
async fn a_front_door_that_refuses_its_sockets_is_recorded_with_its_stage() {
    let (mut pairing, log) = recording_pairing();
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    pairing.front_door.reply(b"CWFD1 failed sockets\n");
    let lines = recorded(&log, "front_door_pairing", "outcome=front_door_refused").await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].ends_with("outcome=front_door_refused stage=sockets pairing=1"),
        "{lines:?}"
    );
    assert_eq!(pairing.running.stopped(), Some(FrontDoorStop::Sockets));
}

/// A start that fails after the front door stopped is told where it stopped.
/// What the front door said of itself is kept over the closed channel or the
/// exit that follows it; a front door that only goes is `gone`; and one that
/// serves has not stopped.
#[tokio::test(flavor = "multi_thread")]
async fn where_the_front_door_stopped_is_kept_for_the_start() {
    let (mut pairing, log) = recording_pairing();
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    assert_eq!(pairing.running.stopped(), None);
    pairing.front_door.reply(b"CWFD1 failed received_dead\n");
    recorded(
        &log,
        "front_door_pairing",
        "outcome=front_door_refused stage=received_dead pairing=1",
    )
    .await;
    assert_eq!(pairing.running.stopped(), Some(FrontDoorStop::ReceivedDead));

    let record = StopRecord::default();
    record.note(FrontDoorStop::Exited);
    record.note(FrontDoorStop::Gone);
    assert_eq!(record.get(), Some(FrontDoorStop::Exited));
    record.note(FrontDoorStop::ReceivedDead);
    record.note(FrontDoorStop::Sockets);
    record.note(FrontDoorStop::Exited);
    assert_eq!(record.get(), Some(FrontDoorStop::ReceivedDead));

    let (mut pairing, log) = recording_pairing();
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    pairing.front_door.reply(&front_door_serving_message(1));
    recorded(&log, "front_door_pairing", "outcome=paired pairing=1").await;
    assert_eq!(pairing.running.stopped(), None);
    drop(pairing.front_door);
    recorded(&log, "front_door_pairing", "outcome=front_door_gone").await;
    assert_eq!(pairing.running.stopped(), Some(FrontDoorStop::Gone));
}

/// A front door that takes the sockets and goes without a word is recorded
/// as gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_front_door_that_goes_after_taking_its_sockets_is_recorded_as_gone() {
    let (mut pairing, log) = recording_pairing();
    let _broker = connect_presenting(&pairing.socket, &pairing.capability).await;
    pairing.front_door.received();
    drop(pairing.front_door);
    let lines = recorded(&log, "front_door_pairing", "outcome=front_door_gone").await;
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// A front door that takes the sockets, stays and says nothing is not
/// waited for past the limit, and is never read as serving.
#[tokio::test(start_paused = true)]
async fn a_front_door_that_says_nothing_is_unacknowledged_at_the_limit() {
    let (runner_end, _front_door_end) = stream_pair().unwrap();
    let mut control = ControlChannel::new(runner_end).unwrap();
    let asked = tokio::time::Instant::now();
    assert!(matches!(
        acknowledgement(&mut control, None, 1, &mut Unanswered::default()).await,
        Acknowledgement::Silent
    ));
    assert_eq!(asked.elapsed(), SERVING_TIMEOUT);
}

/// A front-door process that exits by itself, with `status`.
fn exiting(status: &str) -> FrontDoorProcess {
    let child = crate::test_tokio_command("sh")
        .args(["-c", status])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    FrontDoorProcess {
        child,
        control: None,
        ca_der: Vec::new(),
    }
}

/// An exit nobody asked for is recorded with how the process ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_front_door_that_exits_is_recorded_with_its_status() {
    let (log, file) = recording();
    let stopped = StopRecord::default();
    let _watch = FrontDoorWatch::start(exiting("exit 3"), Some(log.clone()), stopped.clone());
    let lines = recorded(&file, "front_door_exited", "exit_code=3").await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(stopped.get(), Some(FrontDoorStop::Exited));

    let (log, file) = recording();
    let _watch = FrontDoorWatch::start(exiting("kill -TERM $$"), Some(log), stopped);
    let lines = recorded(&file, "front_door_exited", "signal=15").await;
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// Stopping kills the front door and reaps it, and records no exit: it was
/// asked for. Stopping again, or after the process went by itself, is fine.
#[tokio::test(flavor = "multi_thread")]
async fn stopping_reaps_the_front_door_and_records_no_exit() {
    let (log, file) = recording();
    let (process, _front_door) = stand_in();
    let stopped = StopRecord::default();
    let mut watch = FrontDoorWatch::start(process, Some(log.clone()), stopped.clone());
    let pid = rustix::process::Pid::from_raw(i32::try_from(watch.pid.unwrap()).unwrap()).unwrap();
    assert!(rustix::process::test_kill_process(pid).is_ok(), "it runs");

    watch.stop().await.unwrap();
    assert!(
        rustix::process::test_kill_process(pid).is_err(),
        "it was reaped"
    );
    assert_eq!(events(&file, "front_door_exited"), Vec::<String>::new());
    assert_eq!(stopped.get(), None, "a stop that was asked for is no cause");
    watch.stop().await.unwrap();

    let mut gone = FrontDoorWatch::start(exiting("exit 0"), Some(log), stopped);
    recorded(&file, "front_door_exited", "exit_code=0").await;
    gone.stop().await.unwrap();
}
