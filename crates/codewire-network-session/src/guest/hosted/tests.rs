use std::collections::VecDeque;
use std::os::unix::net::UnixDatagram;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt as _, DuplexStream};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::*;
use crate::guest::{authenticate_guest, read_frame};
use crate::{
    NETWORK_GUEST_ACK_LEN, NetworkFrame, NetworkGuestAck, NetworkHostHello, NetworkHostReady,
    NetworkKey, NetworkRole, NetworkSession,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const VM: Uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
const GENERATION: u64 = 1;
const WAIT: Duration = Duration::from_secs(10);

fn key() -> NetworkKey {
    NetworkKey::derive(TOKEN, VM, GENERATION).unwrap()
}

fn config() -> HostedEgressConfig {
    HostedEgressConfig {
        mtu: 1_500,
        self_check_bound: Duration::from_millis(200),
        first_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(40),
        steady_after: Duration::from_millis(100),
        unhealed_backoff: Duration::from_millis(20),
        unhealed_max_backoff: Duration::from_millis(40),
    }
}

/// What one dial meets: a refusal, or a host that runs the handshake, sends
/// `trust`, reads the guest's first frame and then either holds the stream
/// open for `hold` or closes it.
enum Host {
    Refuse,
    /// cw-egress answers the hello with the versions it accepts.
    RefuseVersion,
    Serve {
        trust: EgressTrust,
        hold: Duration,
    },
}

/// What a host saw of the guest's side.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    FirstFrame(SelfCheck),
    NoFrame,
    /// A packet frame arrived while the host held the stream.
    Packet,
}

struct FakeEgress {
    hosts: Mutex<VecDeque<Host>>,
    seen: mpsc::UnboundedSender<Seen>,
    dials: AtomicUsize,
}

impl EgressConnector for FakeEgress {
    type Stream = DuplexStream;
    type Error = std::io::Error;

    fn connect(
        &self,
    ) -> impl Future<Output = Result<GuestSession<DuplexStream>, std::io::Error>> + Send {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let host = self
            .hosts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Host::Refuse);
        let seen = self.seen.clone();
        async move {
            let (trust, hold) = match host {
                Host::Refuse => return Err(std::io::Error::other("refused")),
                Host::RefuseVersion => return Err(std::io::ErrorKind::Unsupported.into()),
                Host::Serve { trust, hold } => (trust, hold),
            };
            let (guest, host) = tokio::io::duplex(1 << 20);
            tokio::spawn(serve(host, trust, hold, seen));
            authenticate_guest(guest, &key(), VM, GENERATION)
                .await
                .map_err(std::io::Error::other)
        }
    }

    fn version_refused(error: &std::io::Error) -> Option<VersionRefused> {
        (error.kind() == std::io::ErrorKind::Unsupported).then_some(REFUSED)
    }
}

const REFUSED: VersionRefused = VersionRefused {
    lowest: 3,
    highest: 4,
    spoken: 2,
};

/// The host's side, as cw-egress's worker runs it.
async fn serve(
    mut stream: DuplexStream,
    trust: EgressTrust,
    hold: Duration,
    seen: mpsc::UnboundedSender<Seen>,
) {
    let bound = SessionLimits::HOSTED.packet_bound();
    let nonce = [9_u8; 32];
    let key = key();
    let hello = NetworkHostHello::new(VM, GENERATION, nonce, bound).unwrap();
    stream.write_all(&hello.encode(&key)).await.unwrap();
    let mut ack = [0_u8; NETWORK_GUEST_ACK_LEN];
    stream.read_exact(&mut ack).await.unwrap();
    NetworkGuestAck::decode(&ack, &key, &nonce, bound).unwrap();
    stream
        .write_all(&NetworkHostReady::new(nonce).unwrap().encode(&key))
        .await
        .unwrap();
    let mut session = NetworkSession::new(&key, &nonce, NetworkRole::Host, bound).unwrap();
    stream
        .write_all(&session.encode_egress_trust(&trust).unwrap())
        .await
        .unwrap();
    let Ok(frame) = read_frame(&mut stream, bound).await else {
        let _ = seen.send(Seen::NoFrame);
        return;
    };
    match session.decode_frame(&frame) {
        Ok(NetworkFrame::SelfCheck(result)) => {
            let _ = seen.send(Seen::FirstFrame(result));
        }
        other => panic!(
            "the guest's first frame was not its self-check: {:?}",
            other.is_ok()
        ),
    }
    let _ = tokio::time::timeout(hold, async {
        while let Ok(frame) = read_frame(&mut stream, bound).await {
            if matches!(session.decode_frame(&frame), Ok(NetworkFrame::Packet(_))) {
                let _ = seen.send(Seen::Packet);
            }
        }
    })
    .await;
}

/// What the loop reported.
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Trust(bool),
    Ready,
    Ended(String),
}

/// Each event with the instant the loop reported it, so a pacing test measures
/// the loop's own gaps, not when the test got round to reading them.
struct Recorder(mpsc::UnboundedSender<(Event, Instant)>);

impl Recorder {
    fn send(&self, event: Event) {
        let _ = self.0.send((event, Instant::now()));
    }
}

impl EgressEvents for Recorder {
    fn egress_trust(&mut self, trust: &EgressTrust) {
        self.send(Event::Trust(matches!(trust, EgressTrust::Ca(_))));
    }
    fn ready(&mut self) {
        self.send(Event::Ready);
    }
    fn round_ended(&mut self, end: &RoundEnd) {
        let name = match end {
            RoundEnd::Connect(_) => "connect".to_owned(),
            RoundEnd::SelfCheckTimedOut => "timed-out".to_owned(),
            RoundEnd::SelfCheckFailed(reason) => format!("failed-{reason:?}"),
            RoundEnd::SendSelfCheck => "send".to_owned(),
            RoundEnd::Bridge(_) => "bridge".to_owned(),
            RoundEnd::TrustChanged => "trust-changed".to_owned(),
            RoundEnd::VersionRefused(refused) => {
                assert_eq!(*refused, REFUSED);
                "version-refused".to_owned()
            }
        };
        self.send(Event::Ended(name));
    }
}

/// A datagram socket pair stands in for the TUN, one packet per datagram.
fn tun_pair() -> (Arc<AsyncFd<OwnedFd>>, UnixDatagram) {
    let (guest, peer) = UnixDatagram::pair().unwrap();
    guest.set_nonblocking(true).unwrap();
    #[allow(deprecated)]
    // RUSTSEC-2026-0386: an owned `OwnedFd` is outside `AsyncFd::new`'s unsound case, as for the guest's TUN.
    let registered = AsyncFd::new(OwnedFd::from(guest)).unwrap();
    (Arc::new(registered), peer)
}

fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet
}

struct Walk {
    events: mpsc::UnboundedReceiver<(Event, Instant)>,
    /// When the loop reported the last event [`Walk::event`] returned.
    at: Instant,
    seen: mpsc::UnboundedReceiver<Seen>,
    egress: Arc<FakeEgress>,
    peer: UnixDatagram,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Walk {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start the loop against `hosts`, with `check` as its self-check.
fn start<F, Fut>(hosts: Vec<Host>, check: F) -> Walk
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = SelfCheck> + Send,
{
    start_with(config(), hosts, check)
}

fn start_with<F, Fut>(config: HostedEgressConfig, hosts: Vec<Host>, check: F) -> Walk
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = SelfCheck> + Send,
{
    let (seen_tx, seen) = mpsc::unbounded_channel();
    let (events_tx, events) = mpsc::unbounded_channel();
    let egress = Arc::new(FakeEgress {
        hosts: Mutex::new(hosts.into()),
        seen: seen_tx,
        dials: AtomicUsize::new(0),
    });
    let (tun, peer) = tun_pair();
    let loop_egress = Arc::clone(&egress);
    let task = tokio::spawn(async move {
        let mut recorder = Recorder(events_tx);
        run(&config, &*loop_egress, check, tun, &mut recorder).await;
    });
    Walk {
        events,
        at: Instant::now(),
        seen,
        egress,
        peer,
        task,
    }
}

impl Walk {
    async fn event(&mut self) -> Event {
        let (event, at) = tokio::time::timeout(WAIT, self.events.recv())
            .await
            .unwrap()
            .unwrap();
        self.at = at;
        event
    }
    async fn seen(&mut self) -> Seen {
        tokio::time::timeout(WAIT, self.seen.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn a_passed_check_is_the_first_frame_and_reports_ready_once() {
    let hosts = vec![
        Host::Serve {
            trust: EgressTrust::Ca(vec![0x30; 40]),
            hold: Duration::ZERO,
        },
        Host::Serve {
            trust: EgressTrust::Ca(vec![0x30; 40]),
            hold: WAIT,
        },
    ];
    let mut walk = start(hosts, || async { SelfCheck::Passed });
    // The trust comes before the check, the check's result is the host's
    // first frame, and only then is the daemon ready.
    assert_eq!(walk.event().await, Event::Trust(true));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    assert_eq!(walk.event().await, Event::Ready);
    // The host closes at once, so the loop backs off and redials, and a
    // second pass does not report ready again.
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert_eq!(walk.event().await, Event::Trust(true));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    // Packets cross once the second stream is up.
    walk.peer.send(&ipv4_packet(60)).unwrap();
    assert_eq!(walk.seen().await, Seen::Packet);
    assert!(
        walk.events.try_recv().is_err(),
        "nothing else, and no second ready"
    );
    assert_eq!(walk.egress.dials.load(Ordering::SeqCst), 2);
}

// The daemon installed the first ready session's trust before it served, and
// the workload's NODE_EXTRA_CA_CERTS is fixed from then. A redial whose host
// sends a different trust is ended before its self-check and never bridged
// or reported; the loop redials, and a session with the pinned trust is
// bridged again (#5006).
#[tokio::test]
async fn a_redial_with_a_changed_trust_is_dropped_and_never_bridged() {
    let pinned = EgressTrust::Ca(vec![0x30; 40]);
    let hosts = vec![
        Host::Serve {
            trust: pinned.clone(),
            hold: Duration::ZERO,
        },
        Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        },
        Host::Serve {
            trust: pinned,
            hold: WAIT,
        },
    ];
    let mut walk = start(hosts, || async { SelfCheck::Passed });
    assert_eq!(walk.event().await, Event::Trust(true));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    // The changed trust: no trust event, no self-check frame, no bridge.
    assert_eq!(walk.event().await, Event::Ended("trust-changed".to_owned()));
    assert_eq!(walk.seen().await, Seen::NoFrame);
    // The pinned trust again: bridged, and packets cross.
    assert_eq!(walk.event().await, Event::Trust(true));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    walk.peer.send(&ipv4_packet(60)).unwrap();
    assert_eq!(walk.seen().await, Seen::Packet);
    assert!(
        walk.events.try_recv().is_err(),
        "nothing else, and no second ready"
    );
    assert_eq!(walk.egress.dials.load(Ordering::SeqCst), 3);
}

// A changed trust is paced apart and slower than the loop's own backoff:
// redialling cannot heal it, so each further session waits at least the
// trust wait, doubling to its cap (#5006). Lower bounds only.
#[tokio::test]
async fn changed_trust_redials_wait_the_trust_pacing_and_double() {
    let pinned = EgressTrust::Ca(vec![0x30; 40]);
    let mut hosts = vec![Host::Serve {
        trust: pinned,
        hold: Duration::ZERO,
    }];
    for _ in 0..3 {
        hosts.push(Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        });
    }
    // Far above the loop's own backoff (20 ms) and far below `WAIT`, which
    // bounds each event the walk waits for.
    let trust_wait = Duration::from_millis(300);
    let mut walk = start_with(
        HostedEgressConfig {
            unhealed_backoff: trust_wait,
            unhealed_max_backoff: trust_wait * 2,
            ..config()
        },
        hosts,
        || async { SelfCheck::Passed },
    );
    assert_eq!(walk.event().await, Event::Trust(true));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert_eq!(walk.event().await, Event::Ended("trust-changed".to_owned()));
    let first = walk.at;
    assert_eq!(walk.event().await, Event::Ended("trust-changed".to_owned()));
    let second = walk.at;
    assert!(
        second - first >= trust_wait,
        "the trust wait, not the loop's"
    );
    assert_eq!(walk.event().await, Event::Ended("trust-changed".to_owned()));
    assert!(walk.at - second >= trust_wait * 2, "doubled to its cap");
}

/// A version refusal is not healed by redialling either, before or after the
/// daemon is ready: it waits the slow pacing, doubling, and a stream
/// cw-egress then admits starts the pacing over.
#[tokio::test]
async fn version_refusals_wait_the_slow_pacing_and_an_admitted_stream_starts_it_over() {
    let hosts = vec![
        Host::RefuseVersion,
        Host::RefuseVersion,
        Host::RefuseVersion,
        Host::Serve {
            trust: EgressTrust::None,
            hold: Duration::ZERO,
        },
        Host::RefuseVersion,
        Host::RefuseVersion,
    ];
    // Far above the loop's own backoff (20 ms) and far below `WAIT`. The cap
    // is high enough that a pacing that did not start over would wait eight
    // times the first wait, well apart from the bound asserted below.
    let slow = Duration::from_millis(200);
    let mut walk = start_with(
        HostedEgressConfig {
            unhealed_backoff: slow,
            unhealed_max_backoff: slow * 16,
            ..config()
        },
        hosts,
        || async { SelfCheck::Passed },
    );
    let refused = Event::Ended("version-refused".to_owned());
    assert_eq!(walk.event().await, refused);
    let first = walk.at;
    assert_eq!(walk.event().await, refused);
    let second = walk.at;
    assert!(second - first >= slow, "the slow wait, not the loop's");
    assert_eq!(walk.event().await, refused);
    assert!(walk.at - second >= slow * 2, "doubled");
    // No refused round reported a trust or readiness.
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert_eq!(walk.event().await, refused);
    let restarted = walk.at;
    assert_eq!(walk.event().await, refused);
    let waited = walk.at - restarted;
    assert!(
        waited >= slow && waited < slow * 5,
        "the first slow wait again, not eight times it: {waited:?}"
    );
}

#[tokio::test]
async fn a_failed_check_is_sent_and_the_daemon_never_reports_ready() {
    let hosts = vec![
        Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        },
        Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        },
    ];
    let mut walk = start(hosts, || async { SelfCheck::Failed(SelfCheckFailure::Dns) });
    for _ in 0..2 {
        assert_eq!(walk.event().await, Event::Trust(false));
        assert_eq!(
            walk.seen().await,
            Seen::FirstFrame(SelfCheck::Failed(SelfCheckFailure::Dns))
        );
        assert_eq!(walk.event().await, Event::Ended("failed-Dns".to_owned()));
    }
    assert!(
        !walk
            .events
            .try_recv()
            .is_ok_and(|(event, _)| event == Event::Ready)
    );
}

#[tokio::test]
async fn a_check_that_outlasts_its_bound_sends_nothing() {
    let hosts = vec![Host::Serve {
        trust: EgressTrust::None,
        hold: WAIT,
    }];
    let mut walk = start(hosts, std::future::pending::<SelfCheck>);
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.event().await, Event::Ended("timed-out".to_owned()));
    // The stream is dropped with no frame on it.
    assert_eq!(walk.seen().await, Seen::NoFrame);
    // Readiness is never reported, so the daemon never serves and the
    // workload never starts: the loop only goes on refusing and backing off.
    for _ in 0..3 {
        assert_eq!(walk.event().await, Event::Ended("connect".to_owned()));
    }
}

#[tokio::test]
async fn refused_dials_back_off_and_drain_the_tun_until_a_stream_is_up() {
    let hosts = vec![
        Host::Refuse,
        Host::Refuse,
        Host::Serve {
            trust: EgressTrust::None,
            hold: Duration::from_millis(300),
        },
    ];
    let mut walk = start(hosts, || async { SelfCheck::Passed });
    assert_eq!(walk.event().await, Event::Ended("connect".to_owned()));
    // Sent while no stream is up: drained, never delivered later.
    walk.peer.send(&ipv4_packet(60)).unwrap();
    assert_eq!(walk.event().await, Event::Ended("connect".to_owned()));
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert!(
        walk.seen.try_recv().is_err(),
        "the drained packet never reached a host"
    );
}

#[tokio::test]
async fn only_a_steady_stream_redials_at_once_and_one_dropped_at_once_backs_off() {
    // A backoff far longer than the test, so a redial that comes is one that
    // went at once.
    let config = HostedEgressConfig {
        first_backoff: WAIT * 6,
        max_backoff: WAIT * 6,
        ..config()
    };
    let hosts = vec![
        Host::Serve {
            trust: EgressTrust::None,
            hold: config.steady_after * 2,
        },
        Host::Serve {
            trust: EgressTrust::None,
            hold: Duration::ZERO,
        },
        Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        },
    ];
    let mut walk = start_with(config, hosts, || async { SelfCheck::Passed });
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    // The first stream carried packets past `steady_after`: at once.
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    // The second was dropped at once: it backs off, and no third dial comes.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), walk.events.recv())
            .await
            .is_err()
    );
    assert_eq!(walk.egress.dials.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_later_stream_whose_check_fails_ends_its_round_and_is_never_bridged() {
    let hosts = vec![
        Host::Serve {
            trust: EgressTrust::None,
            hold: Duration::ZERO,
        },
        Host::Serve {
            trust: EgressTrust::None,
            hold: WAIT,
        },
    ];
    let checks = Arc::new(AtomicUsize::new(0));
    let mut walk = start(hosts, move || {
        let checks = Arc::clone(&checks);
        async move {
            if checks.fetch_add(1, Ordering::SeqCst) == 0 {
                SelfCheck::Passed
            } else {
                SelfCheck::Failed(SelfCheckFailure::DirectDial)
            }
        }
    });
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert_eq!(walk.event().await, Event::Trust(false));
    assert_eq!(
        walk.seen().await,
        Seen::FirstFrame(SelfCheck::Failed(SelfCheckFailure::DirectDial))
    );
    assert_eq!(
        walk.event().await,
        Event::Ended("failed-DirectDial".to_owned())
    );
    // Nothing crosses after the failed check.
    walk.peer.send(&ipv4_packet(60)).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), walk.seen.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn packets_sent_during_the_check_are_drained_never_delivered() {
    let hosts = vec![Host::Serve {
        trust: EgressTrust::None,
        hold: Duration::from_millis(300),
    }];
    let mut walk = start(hosts, || async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        SelfCheck::Passed
    });
    assert_eq!(walk.event().await, Event::Trust(false));
    // Sent while the check runs, before any stream carries the TUN.
    walk.peer.send(&ipv4_packet(60)).unwrap();
    assert_eq!(walk.seen().await, Seen::FirstFrame(SelfCheck::Passed));
    assert_eq!(walk.event().await, Event::Ready);
    assert_eq!(walk.event().await, Event::Ended("bridge".to_owned()));
    assert!(
        walk.seen.try_recv().is_err(),
        "the packet sent during the check never reached the host"
    );
}
