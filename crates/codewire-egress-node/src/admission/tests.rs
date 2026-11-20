use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_network_session::NETWORK_PROTOCOL_VERSION;
use codewire_network_session::hosted::hello::{
    ACCEPTED_VERSIONS, ANSWER_MAGIC_LEN, Answer, VERSION_ANSWER, answer_tail_len, decode_answer,
};
use zeroize::Zeroizing;

use super::*;
use crate::reporter::Reports;

const POD: Uuid = Uuid::from_u128(0x0b8f_6a52_0f6c_4a59_9f43_1b1f_0c3a_9e01);
const TOKEN: &str = "guest-egress-token-0123456789abcdef";

/// Orchestration as the tests need it: admits or refuses every stream, and
/// answers each watch from a script.
struct Fake {
    refuse: bool,
    admits: AtomicUsize,
    watches: AtomicUsize,
    /// How each watch call ends, in order; past the end it never does.
    watch_ends: Mutex<Vec<Result<(), CallError>>>,
}

impl Fake {
    fn admitting() -> Arc<Self> {
        Arc::new(Self {
            refuse: false,
            admits: AtomicUsize::new(0),
            watches: AtomicUsize::new(0),
            watch_ends: Mutex::new(Vec::new()),
        })
    }
}

impl Admits for Fake {
    fn admit(
        &self,
        guest_token: &str,
        _peer: IpAddr,
    ) -> impl Future<Output = Result<Admitted, CallError>> + Send {
        self.admits.fetch_add(1, Ordering::SeqCst);
        let answer = if self.refuse || guest_token != TOKEN {
            Err(CallError::Refused)
        } else {
            Ok(Admitted {
                trust: codewire_network_session::EgressTrust::None,
                pod_uid: POD.to_string(),
                pod_name: "workspace".into(),
                assignment: Ok(Assignment::Unbound {
                    platform: Vec::new(),
                }),
            })
        };
        std::future::ready(answer)
    }

    fn watch(
        &self,
        _pod_uid: &str,
        _pod_name: &str,
        mut on_change: impl FnMut(Result<Assignment, AssignmentError>) + Send,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        self.watches.fetch_add(1, Ordering::SeqCst);
        let end = {
            let mut ends = self.watch_ends.lock().unwrap();
            (!ends.is_empty()).then(|| ends.remove(0))
        };
        on_change(Err(AssignmentError::Missing));
        async move {
            match end {
                Some(end) => end,
                None => std::future::pending().await,
            }
        }
    }
}

struct Silent;

impl Reports for Silent {
    fn enforcement(
        &self,
        _pod_uid: &str,
        _pod_name: &str,
        _enforcement: &crate::orchestration::Enforcement,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        std::future::ready(Ok(()))
    }

    fn records(
        &self,
        _pod_uid: &str,
        _pod_name: &str,
        _records: Vec<codewire_proto::codewire::internal::v1::EgressRecord>,
    ) -> impl Future<Output = Result<(), CallError>> + Send {
        std::future::ready(Ok(()))
    }
}

struct Running {
    address: SocketAddr,
    admitted: mpsc::Receiver<AdmittedStream>,
    stop: CancellationToken,
    serving: tokio::task::JoinHandle<()>,
}

async fn running(fake: &Arc<Fake>) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (reporter, _task) = Reporter::start(Arc::new(Silent));
    let (sender, admitted) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let serving = tokio::spawn(serve(
        listener,
        Arc::clone(fake),
        reporter,
        sender,
        stop.clone(),
    ));
    Running {
        address,
        admitted,
        stop,
        serving,
    }
}

/// The stream ended with no answer: closed, or reset because cw-egress
/// closed it with the guest's bytes still unread.
async fn closed_without_answer(guest: &mut TcpStream) -> bool {
    let mut byte = [0_u8; 1];
    match guest.read(&mut byte).await {
        Ok(read) => read == 0,
        Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
    }
}

fn guest_hello(token: &str) -> Vec<u8> {
    GuestHello {
        version: NETWORK_PROTOCOL_VERSION,
        token: Zeroizing::new(token.to_owned()),
        nonce: [7; NONCE_LEN],
    }
    .encode()
    .unwrap()
}

#[tokio::test]
async fn an_admitted_stream_reaches_the_supervisor_keyed_as_the_guest_keys_it() {
    let fake = Fake::admitting();
    let mut running = running(&fake).await;
    let mut guest = TcpStream::connect(running.address).await.unwrap();
    guest.write_all(&guest_hello(TOKEN)).await.unwrap();
    let Answer::Admitted { nonce: node_nonce } = read_answer(&mut guest).await else {
        panic!("the stream was not admitted");
    };
    let guest_key = stream_key(&StreamKeyInput {
        token: TOKEN,
        guest_nonce: &[7; NONCE_LEN],
        node_nonce: &node_nonce,
        pod_uid: POD,
    })
    .unwrap();
    let stream = running.admitted.recv().await.unwrap();
    assert_eq!(stream.pod_uid, POD);
    assert_eq!(stream.pod_name, "workspace");
    assert_eq!(stream.peer.ip(), guest.local_addr().unwrap().ip());
    assert!(matches!(stream.assignment, Assignment::Unbound { .. }));
    stream
        .key
        .with_bytes(|host| guest_key.with_bytes(|guest| assert_eq!(host, guest)));
    running.stop.cancel();
}

#[tokio::test]
async fn a_refused_stream_is_closed_with_no_answer() {
    let fake = Arc::new(Fake {
        refuse: true,
        ..Arc::try_unwrap(Fake::admitting()).ok().unwrap()
    });
    let mut running = running(&fake).await;
    let mut guest = TcpStream::connect(running.address).await.unwrap();
    guest.write_all(&guest_hello(TOKEN)).await.unwrap();
    assert!(closed_without_answer(&mut guest).await);
    assert_eq!(fake.admits.load(Ordering::SeqCst), 1);
    assert!(running.admitted.try_recv().is_err());
    running.stop.cancel();
}

async fn read_answer(guest: &mut TcpStream) -> Answer {
    let mut magic = [0_u8; ANSWER_MAGIC_LEN];
    guest.read_exact(&mut magic).await.unwrap();
    let mut tail = vec![0_u8; answer_tail_len(&magic).unwrap()];
    guest.read_exact(&mut tail).await.unwrap();
    decode_answer(&magic, &tail).unwrap()
}

/// A hello for `version`, its token and nonce replaced by bytes that are no
/// hello at all.
fn version_then_garbage(version: u16) -> Vec<u8> {
    let mut bytes = b"CWEGRS01".to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&[0xff; 64]);
    bytes
}

#[tokio::test]
async fn an_unaccepted_session_version_gets_exactly_the_version_answer_whatever_follows() {
    let fake = Fake::admitting();
    let running = running(&fake).await;
    let above = ACCEPTED_VERSIONS.end() + 1;
    let below = ACCEPTED_VERSIONS.start() - 1;
    for version in [above, below, u16::MAX] {
        let mut guest = TcpStream::connect(running.address).await.unwrap();
        guest
            .write_all(&version_then_garbage(version))
            .await
            .unwrap();
        let mut answer = Vec::new();
        // The answer, then the close.
        let _ = guest.read_to_end(&mut answer).await;
        assert_eq!(answer, VERSION_ANSWER, "version {version}");
    }
    assert_eq!(fake.admits.load(Ordering::SeqCst), 0);
    running.stop.cancel();
}

#[tokio::test]
async fn an_accepted_version_with_a_bad_token_gets_the_same_silent_close_as_any_refusal() {
    let fake = Fake::admitting();
    let running = running(&fake).await;
    let mut wrong_token = TcpStream::connect(running.address).await.unwrap();
    wrong_token
        .write_all(&guest_hello("not-the-token-0123456789"))
        .await
        .unwrap();
    assert!(closed_without_answer(&mut wrong_token).await);
    let mut garbage = TcpStream::connect(running.address).await.unwrap();
    garbage
        .write_all(&version_then_garbage(NETWORK_PROTOCOL_VERSION))
        .await
        .unwrap();
    assert!(closed_without_answer(&mut garbage).await);
    running.stop.cancel();
}

#[tokio::test]
async fn a_stream_that_is_not_an_egress_hello_never_reaches_orchestration() {
    let fake = Fake::admitting();
    let running = running(&fake).await;
    let mut guest = TcpStream::connect(running.address).await.unwrap();
    guest.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert!(closed_without_answer(&mut guest).await);
    assert_eq!(fake.admits.load(Ordering::SeqCst), 0);
    running.stop.cancel();
}

#[tokio::test]
async fn starts_past_the_limit_are_refused_before_orchestration_is_asked() {
    let fake = Fake::admitting();
    let running = running(&fake).await;
    let mut guests = Vec::new();
    for _ in 0..crate::replacement::STARTS_PER_WINDOW + 3 {
        let mut guest = TcpStream::connect(running.address).await.unwrap();
        // A wrong token is refused by orchestration, so only the limit
        // decides whether orchestration was asked.
        guest
            .write_all(&guest_hello("not-the-token-0123456789"))
            .await
            .unwrap();
        guests.push(guest);
    }
    for guest in &mut guests {
        assert!(closed_without_answer(guest).await);
    }
    assert_eq!(
        fake.admits.load(Ordering::SeqCst),
        crate::replacement::STARTS_PER_WINDOW
    );
    running.stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn a_lost_watch_is_opened_again_and_a_watch_orchestration_ends_closes_the_channel() {
    let fake = Fake::admitting();
    *fake.watch_ends.lock().unwrap() = vec![Err(CallError::Unavailable("down".into())), Ok(())];
    let (changes, mut receiver) = watch::channel(Ok(Assignment::Unbound {
        platform: Vec::new(),
    }));
    let following = tokio::spawn(follow_assignment(
        Arc::clone(&fake),
        POD.to_string(),
        "workspace".into(),
        changes,
    ));
    following.await.unwrap();
    // Opened once, lost, opened again after the backoff, then ended.
    assert_eq!(fake.watches.load(Ordering::SeqCst), 2);
    // The watch's last change arrived, and the ended Pod closed the channel.
    assert!(receiver.borrow_and_update().is_err());
    assert!(receiver.changed().await.is_err());
}

#[tokio::test]
async fn stopping_admission_closes_the_supervisors_channel() {
    let fake = Fake::admitting();
    let mut running = running(&fake).await;
    running.stop.cancel();
    running.serving.await.unwrap();
    assert!(running.admitted.recv().await.is_none());
}
