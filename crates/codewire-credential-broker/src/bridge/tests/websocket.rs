//! A front-door session's WebSocket sockets in the runner (#3999).

use std::time::Duration;

use codewire_daemon_proto::CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use v1::credential_bridge_guest_message::Payload as Guest;
use v1::credential_bridge_host_message::Payload as Host;

use super::*;
use crate::bridge::websocket::{MAX_OPEN_SOCKETS, RELEASE_EVERY, RELEASE_WITHIN};
use crate::runtime::upgrade::{BrokerUpgradeOutcome, SocketGrant};

/// A hang guard, not a product bound.
const GUARD: Duration = Duration::from_secs(30);
const WINDOW: u32 = CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;

/// A front-door executor whose provider is the far end of a pipe per socket.
struct SocketExecutor {
    serves: bool,
    grant_holds: Arc<AtomicBool>,
    /// The authority never answers a re-lease.
    grant_hangs: Arc<AtomicBool>,
    /// Handshakes the executor was asked to serve.
    handshakes: Arc<AtomicUsize>,
    providers: mpsc::UnboundedSender<DuplexStream>,
}

#[async_trait]
impl BrokerRequestExecutor for SocketExecutor {
    async fn execute_request(
        &self,
        _request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        Ok(BrokerHttpResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Box::pin(stream::iter([Ok(Bytes::from_static(b"ok"))])),
        ))
    }

    fn serves_upgrades(&self) -> bool {
        self.serves
    }

    async fn execute_upgrade(
        &self,
        upgrade: v1::CredentialBridgeUpgrade,
    ) -> Result<BrokerUpgradeOutcome, BrokerRequestError> {
        self.handshakes.fetch_add(1, Ordering::SeqCst);
        if upgrade.path == "/hold" {
            std::future::pending::<()>().await;
        }
        if upgrade.path == "/refuse" {
            return Ok(BrokerUpgradeOutcome::Response(BrokerHttpResponse::new(
                StatusCode::UNAUTHORIZED,
                HeaderMap::new(),
                Box::pin(stream::iter([Ok(Bytes::from_static(b"no"))])),
            )));
        }
        let (broker_end, provider_end) = tokio::io::duplex(8 * 1024);
        self.providers.send(provider_end).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-accept", HeaderValue::from_static("accept"));
        Ok(BrokerUpgradeOutcome::Switched {
            headers,
            stream: Box::new(broker_end),
            grant: Some(SocketGrant::for_tests()),
        })
    }

    async fn socket_grant_holds(&self, _grant: &SocketGrant) -> bool {
        if self.grant_hangs.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.grant_holds.load(Ordering::SeqCst)
    }
}

struct Session {
    input: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    output: mpsc::Receiver<Host>,
    providers: mpsc::UnboundedReceiver<DuplexStream>,
    grant_holds: Arc<AtomicBool>,
    grant_hangs: Arc<AtomicBool>,
    handshakes: Arc<AtomicUsize>,
    run: tokio::task::JoinHandle<Result<(), BrokerBridgeError>>,
}

fn session(serves: bool) -> Session {
    let (input, input_rx) = mpsc::channel(64);
    let (output_tx, output) = mpsc::channel(64);
    let (providers_tx, providers) = mpsc::unbounded_channel();
    let grant_holds = Arc::new(AtomicBool::new(true));
    let grant_hangs = Arc::new(AtomicBool::new(false));
    let handshakes = Arc::new(AtomicUsize::new(0));
    let executor = SocketExecutor {
        serves,
        grant_holds: grant_holds.clone(),
        grant_hangs: grant_hangs.clone(),
        handshakes: handshakes.clone(),
        providers: providers_tx,
    };
    let bridge = FakeBridge {
        input: input_rx,
        output: output_tx,
    };
    let run = tokio::spawn(run_admitted_bridge(Arc::new(executor), bridge));
    Session {
        input,
        output,
        providers,
        grant_holds,
        grant_hangs,
        handshakes,
        run,
    }
}

impl Session {
    async fn send(&self, payload: Guest) {
        self.input
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }

    async fn upgrade(&self, path: &str) -> String {
        let request_id = Uuid::new_v4().to_string();
        self.send(Guest::Upgrade(v1::CredentialBridgeUpgrade {
            request_id: request_id.clone(),
            method: "GET".to_owned(),
            path: path.to_owned(),
            initial_credit_bytes: WINDOW,
            ..Default::default()
        }))
        .await;
        request_id
    }

    async fn next(&mut self) -> Host {
        tokio::time::timeout(GUARD, self.output.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// Open a socket and return its id and the provider's end.
    async fn open(&mut self) -> (String, DuplexStream) {
        let request_id = self.upgrade("/switch").await;
        let Host::UpgradeAccepted(accepted) = self.next().await else {
            panic!("a switched handshake is accepted");
        };
        assert_eq!(accepted.request_id, request_id);
        assert!(
            accepted
                .headers
                .iter()
                .any(|header| header.name == "sec-websocket-accept")
        );
        let Host::StreamCredit(credit) = self.next().await else {
            panic!("a window of credit follows the acceptance");
        };
        assert_eq!(credit.credit_bytes, WINDOW);
        let provider = self.providers.recv().await.unwrap();
        (request_id, provider)
    }
}

fn data(request_id: &str, bytes: &[u8]) -> Guest {
    Guest::StreamData(v1::CredentialBridgeStreamData {
        request_id: request_id.to_owned(),
        data: bytes.to_vec(),
    })
}

#[tokio::test]
async fn a_switched_socket_carries_bytes_both_ways() {
    let mut session = session(true);
    let (socket, mut provider) = session.open().await;
    session.send(data(&socket, b"hello")).await;
    let mut got = [0_u8; 5];
    tokio::time::timeout(GUARD, provider.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"hello");
    provider.write_all(b"world").await.unwrap();
    let Host::StreamData(reply) = session.next().await else {
        panic!("the provider's bytes reach the guest");
    };
    assert_eq!(
        (reply.request_id.as_str(), &reply.data[..]),
        (socket.as_str(), &b"world"[..])
    );
}

#[tokio::test]
async fn a_refused_handshake_is_answered_as_a_reply() {
    let mut session = session(true);
    let request_id = session.upgrade("/refuse").await;
    let Host::ResponseStart(start) = session.next().await else {
        panic!("a refusal is a reply");
    };
    assert_eq!(
        (start.request_id.as_str(), start.status_code),
        (request_id.as_str(), 401)
    );
}

#[tokio::test]
async fn a_session_that_serves_no_upgrades_ends_on_one() {
    let session = session(false);
    session.upgrade("/switch").await;
    assert!(matches!(
        tokio::time::timeout(GUARD, session.run)
            .await
            .unwrap()
            .unwrap(),
        Err(BrokerBridgeError::InvalidProtocol)
    ));
}

#[tokio::test]
async fn a_session_carries_at_most_its_socket_limit() {
    let mut session = session(true);
    let mut providers = Vec::new();
    for _ in 0..MAX_OPEN_SOCKETS {
        providers.push(session.open().await);
    }
    let refused = session.upgrade("/switch").await;
    let Host::ResponseFailure(failure) = session.next().await else {
        panic!("a socket past the limit is refused");
    };
    assert_eq!(failure.request_id, refused);
    assert_eq!(
        failure.reason,
        v1::CredentialBridgeFailureReason::Unavailable as i32
    );
}

#[tokio::test(start_paused = true)]
async fn a_socket_whose_credential_no_longer_leases_is_reset_at_both_ends() {
    let mut session = session(true);
    let (socket, mut provider) = session.open().await;
    session.grant_holds.store(false, Ordering::SeqCst);
    tokio::time::sleep(RELEASE_EVERY).await;
    let Host::StreamClose(close) = session.next().await else {
        panic!("the guest is told the socket is reset");
    };
    assert_eq!(close.request_id, socket);
    assert_eq!(
        close.kind,
        v1::CredentialBridgeStreamCloseKind::Reset as i32
    );
    let mut byte = [0_u8; 1];
    assert!(matches!(provider.read(&mut byte).await, Ok(0) | Err(_)));
}

#[tokio::test]
async fn a_socket_whose_guest_stops_reading_never_delays_a_request() {
    let mut session = session(true);
    let (_socket, mut provider) = session.open().await;
    // The provider keeps sending; the guest grants nothing back.
    let flood = tokio::spawn(async move {
        let _ = provider.write_all(&vec![7_u8; 4 * 1024 * 1024]).await;
        provider
    });
    let request_id = Uuid::new_v4().to_string();
    session
        .send(Guest::Request(v1::CredentialBridgeRequest {
            request_id: request_id.clone(),
            method: "GET".to_owned(),
            path: "/plain".to_owned(),
            ..Default::default()
        }))
        .await;
    let mut stream_bytes = 0_usize;
    loop {
        match session.next().await {
            Host::StreamData(data) => stream_bytes += data.data.len(),
            Host::ResponseEnd(end) if end.request_id == request_id => break,
            _ => {}
        }
    }
    assert!(
        stream_bytes <= WINDOW as usize,
        "{stream_bytes} past the window"
    );
    assert!(!flood.is_finished());
    flood.abort();
}

#[tokio::test]
async fn the_sessions_end_closes_its_sockets() {
    let mut session = session(true);
    let (_socket, mut provider) = session.open().await;
    drop(session.input);
    let _ = tokio::time::timeout(GUARD, session.run).await.unwrap();
    let mut byte = [0_u8; 1];
    assert!(matches!(
        tokio::time::timeout(GUARD, provider.read(&mut byte))
            .await
            .unwrap(),
        Ok(0) | Err(_)
    ));
}

#[tokio::test]
async fn a_frame_for_a_socket_this_session_never_opened_ends_it() {
    let session = session(true);
    session
        .send(data(&Uuid::new_v4().to_string(), b"stray"))
        .await;
    assert!(matches!(
        tokio::time::timeout(GUARD, session.run)
            .await
            .unwrap()
            .unwrap(),
        Err(BrokerBridgeError::InvalidProtocol)
    ));
}

#[tokio::test(start_paused = true)]
async fn an_authority_that_never_answers_the_release_resets_the_socket() {
    let mut session = session(true);
    let (socket, _provider) = session.open().await;
    session.grant_hangs.store(true, Ordering::SeqCst);
    tokio::time::sleep(RELEASE_EVERY + RELEASE_WITHIN).await;
    let Host::StreamClose(close) = session.next().await else {
        panic!("a re-lease with no answer is a refusal");
    };
    assert_eq!(close.request_id, socket);
    assert_eq!(
        close.kind,
        v1::CredentialBridgeStreamCloseKind::Reset as i32
    );
}

/// Handshakes still in flight count against the socket limit, so the one
/// past it is refused before the executor, and so any lease, sees it. An
/// ordinary request still has room: the in-flight limit is apart.
#[tokio::test]
async fn handshakes_in_flight_count_against_the_socket_limit() {
    let mut session = session(true);
    let half = MAX_OPEN_SOCKETS / 2;
    let mut providers = Vec::new();
    for _ in 0..half {
        providers.push(session.open().await);
    }
    for _ in 0..half {
        session.upgrade("/hold").await;
    }
    // Every held handshake has reached the executor.
    tokio::time::timeout(GUARD, async {
        while session.handshakes.load(Ordering::SeqCst) < MAX_OPEN_SOCKETS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let started = session.handshakes.load(Ordering::SeqCst);
    let refused = session.upgrade("/switch").await;
    let Host::ResponseFailure(failure) = session.next().await else {
        panic!("a handshake past the socket limit is refused");
    };
    assert_eq!(failure.request_id, refused);
    assert_eq!(session.handshakes.load(Ordering::SeqCst), started);
    let request_id = Uuid::new_v4().to_string();
    session
        .send(Guest::Request(v1::CredentialBridgeRequest {
            request_id: request_id.clone(),
            method: "GET".to_owned(),
            path: "/plain".to_owned(),
            ..Default::default()
        }))
        .await;
    loop {
        if let Host::ResponseEnd(end) = session.next().await
            && end.request_id == request_id
        {
            break;
        }
    }
}

/// A guest frame racing a socket's end is dropped, and the session serves on.
#[tokio::test(start_paused = true)]
async fn a_frame_for_a_socket_that_just_ended_is_dropped() {
    let mut session = session(true);
    let (socket, provider) = session.open().await;
    // The provider leaves: the next bytes for it fail, and the socket ends.
    drop(provider);
    session.send(data(&socket, b"to a gone provider")).await;
    loop {
        if let Host::StreamClose(close) = session.next().await
            && close.request_id == socket
            && close.kind == v1::CredentialBridgeStreamCloseKind::Reset as i32
        {
            break;
        }
    }
    // Let the runner retire the ended socket.
    tokio::time::sleep(Duration::from_millis(1)).await;
    session.send(data(&socket, b"late")).await;
    let request_id = Uuid::new_v4().to_string();
    session
        .send(Guest::Request(v1::CredentialBridgeRequest {
            request_id: request_id.clone(),
            method: "GET".to_owned(),
            path: "/plain".to_owned(),
            ..Default::default()
        }))
        .await;
    loop {
        if let Host::ResponseEnd(end) = session.next().await
            && end.request_id == request_id
        {
            break;
        }
    }
    assert!(!session.run.is_finished(), "the session serves on");
}
