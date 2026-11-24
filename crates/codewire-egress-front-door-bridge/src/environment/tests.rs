use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsFd as _;
use std::time::Duration;

use bytes::Bytes;
use codewire_credential_bridge::{BridgeIdentity, FrontDoorHostSession};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_egress_policy::handoff::{HandoffSender, stream_pair};
use codewire_egress_policy::intercept::InterceptBinding;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

use super::*;

const WAIT: Duration = Duration::from_secs(30);
const GENERATION: u64 = 4;
const BOUND: &str = "api.openai.com";

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("bounded test step")
}

fn intercepts(hosts: &[&str], port: u16) -> InterceptSet {
    InterceptSet::new(
        hosts
            .iter()
            .map(|host| InterceptBinding::new(host, port).unwrap()),
    )
    .unwrap()
}

/// A front door serving one environment, the broker ends of its two sockets,
/// and the CA certificate it reported.
struct Running {
    environment_id: Uuid,
    ca: Vec<u8>,
    handoff: HandoffSender,
    /// The credential broker's side of the live session, once one paired.
    host: Option<FrontDoorHostSession>,
    door: tokio::task::JoinHandle<Ended>,
    /// Where a successor broker's session reaches the front door.
    successors: tokio::sync::mpsc::Sender<tokio::net::UnixStream>,
    next_stream: u64,
}

impl Running {
    async fn start(hosts: &[&str]) -> Self {
        Self::start_with(hosts, |_| {}).await
    }

    /// [`Self::start`], with `configure` applied to the front door's end of
    /// the hand-off socket before it serves.
    async fn start_with(hosts: &[&str], configure: impl FnOnce(&OwnedFd)) -> Self {
        Self::serving(intercepts(hosts, 443), configure, true).await
    }

    /// A front door for exactly `bound`, with `configure` applied as
    /// [`Self::start_with`] does.
    async fn start_binding(bound: InterceptSet, configure: impl FnOnce(&OwnedFd)) -> Self {
        Self::serving(bound, configure, true).await
    }

    /// A front door serving `bound`, with a first credential session when
    /// `paired`, as a local one always has.
    async fn serving(bound: InterceptSet, configure: impl FnOnce(&OwnedFd), paired: bool) -> Self {
        let environment_id = Uuid::new_v4();
        let door = EnvironmentFrontDoor::start(environment_id, GENERATION, bound).unwrap();
        let ca = door.ca_certificate_der().to_vec();
        let (door_handoff, handoff) = stream_pair().unwrap();
        configure(&door_handoff);
        let handoff = HandoffSender::new(handoff).unwrap();
        let (door_credentials, credentials) = tokio::net::UnixStream::pair().unwrap();
        let (successors, later) = tokio::sync::mpsc::channel(4);
        let first = paired.then_some(door_credentials);
        let door = tokio::spawn(door.serve(door_handoff, first, later));
        let host = if paired {
            Some(open_host(credentials, environment_id).await)
        } else {
            None
        };
        Self {
            environment_id,
            ca,
            handoff,
            host,
            door,
            successors,
            next_stream: 1,
        }
    }

    /// Hand the front door a stream as the broker does; the guest's end.
    fn hand_over(
        &mut self,
        hostname: &str,
        port: u16,
        environment_id: &str,
    ) -> tokio::net::UnixStream {
        self.hand_over_named(hostname, &[], port, environment_id)
    }

    /// [`Self::hand_over`] for an address `aliases` also hold.
    fn hand_over_named(
        &mut self,
        hostname: &str,
        aliases: &[&str],
        port: u16,
        environment_id: &str,
    ) -> tokio::net::UnixStream {
        let (guest, handed) = std::os::unix::net::UnixStream::pair().unwrap();
        let header = InterceptedStreamHeader {
            version: codewire_egress_policy::handoff::HANDOFF_VERSION,
            hostname: hostname.to_owned(),
            port,
            destination_ip: Ipv4Addr::new(192, 0, 2, 1),
            stream_id: self.next_stream,
            environment_id: environment_id.to_owned(),
            aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
        };
        self.next_stream += 1;
        self.handoff
            .send_intercepted_stream(&header, handed.as_fd())
            .unwrap();
        guest.set_nonblocking(true).unwrap();
        tokio::net::UnixStream::from_std(guest).unwrap()
    }

    fn own_stream(&mut self, hostname: &str) -> tokio::net::UnixStream {
        let environment_id = self.environment_id.to_string();
        self.hand_over(hostname, INTERCEPT_PORT, &environment_id)
    }

    /// A TLS client on `stream` that trusts only the reported CA.
    async fn tls(
        &self,
        stream: tokio::net::UnixStream,
        server_name: &'static str,
    ) -> io::Result<TlsStream<tokio::net::UnixStream>> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.ca.clone())).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        bounded(
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(server_name).unwrap(), stream),
        )
        .await
    }

    /// Start one request through a fresh handed-over stream. The task ends
    /// with the status and body the guest read, once a broker answers.
    async fn start_request(&mut self) -> tokio::task::JoinHandle<(StatusCode, Bytes)> {
        let stream = self.own_stream(BOUND);
        self.start_request_through(stream, BOUND, "/v1/responses")
            .await
    }

    /// [`Self::start_request`] for `server_name` and `path` through `stream`.
    async fn start_request_through(
        &mut self,
        stream: tokio::net::UnixStream,
        server_name: &'static str,
        path: &'static str,
    ) -> tokio::task::JoinHandle<(StatusCode, Bytes)> {
        let tls = self.tls(stream, server_name).await.expect("handshake");
        let (mut sender, connection) =
            bounded(hyper::client::conn::http1::handshake(TokioIo::new(tls)))
                .await
                .unwrap();
        tokio::spawn(connection);
        tokio::spawn(async move {
            let response = sender
                .send_request(
                    Request::post(path)
                        .header("host", server_name)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from_static(b"{}")))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        })
    }

    /// One request for `server_name` and `path` through `stream`: what
    /// reached the credential broker, and the response the guest read.
    async fn request_through(
        &mut self,
        stream: tokio::net::UnixStream,
        server_name: &'static str,
        path: &'static str,
    ) -> (v1::CredentialBridgeRequest, StatusCode, Bytes) {
        let response = self.start_request_through(stream, server_name, path).await;
        let seen = received(self.host()).await;
        answer(self.host(), &seen.request_id).await;
        let (status, body) = bounded(response).await.unwrap();
        (seen, status, body)
    }

    /// One request through a fresh handed-over stream: what reached the
    /// credential broker, and the response the guest read.
    async fn request(&mut self) -> (v1::CredentialBridgeRequest, StatusCode, Bytes) {
        let stream = self.own_stream(BOUND);
        self.request_through(stream, BOUND, "/v1/responses").await
    }

    fn host(&mut self) -> &mut FrontDoorHostSession {
        self.host.as_mut().expect("a paired credential session")
    }

    /// A successor broker pairs: its session reaches the front door, which
    /// answers its Open.
    async fn successor(&self) -> FrontDoorHostSession {
        let (door_credentials, credentials) = tokio::net::UnixStream::pair().unwrap();
        self.successors.try_send(door_credentials).unwrap();
        open_host(credentials, self.environment_id).await
    }
}

async fn open_host(
    credentials: tokio::net::UnixStream,
    environment_id: Uuid,
) -> FrontDoorHostSession {
    let identity = BridgeIdentity {
        environment_id,
        environment_generation: GENERATION,
    };
    let mut host = bounded(FrontDoorHostSession::open(
        credentials,
        identity,
        &codewire_credential_bridge::front_door_capabilities(true),
    ))
    .await
    .unwrap();
    let ready = bounded(host.receive()).await.unwrap().unwrap();
    assert!(matches!(ready.payload, Some(GuestPayload::Ready(_))));
    host
}

/// The next request the front door sent to `host`.
async fn received(host: &mut FrontDoorHostSession) -> v1::CredentialBridgeRequest {
    let Some(GuestPayload::Request(seen)) = bounded(host.receive()).await.unwrap().unwrap().payload
    else {
        panic!("expected a request at the credential broker");
    };
    seen
}

/// Answer `request_id` on `host` with 200 and `answered`.
async fn answer(host: &FrontDoorHostSession, request_id: &str) {
    let sender = host.sender();
    for payload in [
        HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
            request_id: request_id.to_owned(),
            status_code: 200,
            headers: Vec::new(),
        }),
        HostPayload::ResponseBody(v1::CredentialBridgeResponseBody {
            request_id: request_id.to_owned(),
            data: b"answered".to_vec(),
        }),
        HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: request_id.to_owned(),
        }),
    ] {
        sender
            .send(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_handed_over_stream_reaches_the_credential_broker_naming_its_bound_host() {
    let mut running = Running::start(&[BOUND]).await;
    let (seen, status, body) = running.request().await;
    assert_eq!(seen.intercepted_host, BOUND);
    assert_eq!(
        (seen.capability_slot.as_str(), seen.route.as_str()),
        ("openai", "openai-api")
    );
    assert_eq!(seen.path, "/responses");
    assert_eq!(seen.body, b"{}");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "answered");
}

/// The broker is trusted for neither the environment nor the binding: a
/// stream for another environment, or for a name or port this front door
/// does not bind, is closed before its handshake, and the next good stream
/// is served.
#[tokio::test]
async fn a_stream_for_another_environment_or_an_unbound_host_is_closed() {
    let mut running = Running::start(&[BOUND]).await;
    let own = running.environment_id.to_string();
    let other = Uuid::new_v4().to_string();
    for stream in [
        running.hand_over(BOUND, INTERCEPT_PORT, &other),
        running.hand_over(BOUND, 8443, &own),
        running.hand_over("api.anthropic.com", INTERCEPT_PORT, &own),
    ] {
        // The guest offers the bound name; only the header is wrong.
        assert!(running.tls(stream, BOUND).await.is_err());
    }

    let (seen, status, _) = running.request().await;
    assert_eq!(seen.intercepted_host, BOUND);
    assert_eq!(status, StatusCode::OK);
}

/// No hand-back: the guest dialled a bound address, so a ClientHello naming
/// any other server is refused and the stream closed.
/// A stream the broker attributed to chatgpt.com, whose address a routed
/// name under its suffix also holds, is served for the name the client asks
/// for (#3999): the credential broker sees that name and the admitted
/// address. An alias this front door does not bind is never served.
#[tokio::test]
async fn a_shared_address_is_served_for_the_bound_name_the_client_asks_for() {
    let bound = RouteTable::defaults().intercepts().unwrap();
    let mut running = Running::start_binding(bound, |_| {}).await;
    let environment_id = running.environment_id.to_string();
    let stream = running.hand_over_named(
        "chatgpt.com",
        &["routed.chatgpt.com"],
        INTERCEPT_PORT,
        &environment_id,
    );
    let (seen, status, _) = running
        .request_through(stream, "routed.chatgpt.com", "/backend-api/codex/responses")
        .await;
    assert_eq!(seen.intercepted_host, "routed.chatgpt.com");
    assert_eq!(seen.destination_ip, "192.0.2.1");
    assert_eq!(seen.path, "/backend-api/codex/responses");
    assert_eq!(status, StatusCode::OK);

    let stream = running.hand_over_named(
        "chatgpt.com",
        &["unbound.example.com"],
        INTERCEPT_PORT,
        &environment_id,
    );
    assert!(running.tls(stream, "unbound.example.com").await.is_err());
}

#[tokio::test]
async fn a_client_hello_for_another_name_is_closed() {
    let mut running = Running::start(&[BOUND, "api.anthropic.com"]).await;
    let stream = running.own_stream(BOUND);
    assert!(running.tls(stream, "api.anthropic.com").await.is_err());
    assert!(!running.door.is_finished());
}

#[tokio::test]
async fn the_front_door_stops_when_the_broker_closes_the_handoff_socket() {
    let running = Running::start(&[BOUND]).await;
    drop(running.handoff);
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Ended::HandoffClosed
    ));
}

/// The credential authority replaces a generation's broker every few
/// minutes (#3999). Its successor's session takes every new request while
/// the first finishes the one already sent on it, and once the first is gone
/// requests are still served: the renewal keeps interception, with the same
/// front door, CA and bindings.
#[tokio::test]
async fn a_renewed_broker_keeps_interception_and_the_first_finishes_its_request() {
    let mut running = Running::start(&[BOUND]).await;
    let in_flight = running.start_request().await;
    let first_seen = received(running.host()).await;

    let mut successor = running.successor().await;
    let next = running.start_request().await;
    let next_seen = received(&mut successor).await;
    answer(running.host(), &first_seen.request_id).await;
    assert_eq!(bounded(in_flight).await.unwrap().0, StatusCode::OK);
    answer(&successor, &next_seen.request_id).await;
    assert_eq!(bounded(next).await.unwrap().0, StatusCode::OK);

    drop(running.host.replace(successor));
    let after = running.start_request().await;
    let after_seen = received(running.host()).await;
    answer(running.host(), &after_seen.request_id).await;
    assert_eq!(
        bounded(after).await.unwrap(),
        (StatusCode::OK, Bytes::from("answered"))
    );
    assert!(!running.door.is_finished());
}

/// A session that ends with no successor stops nothing: the front door keeps
/// the hand-off socket, so no dial falls back to a direct path, and the next
/// broker to pair serves again.
#[tokio::test]
async fn a_broker_gone_without_a_successor_leaves_the_front_door_for_the_next() {
    let mut running = Running::start(&[BOUND]).await;
    drop(running.host);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!running.door.is_finished());
    let (door_credentials, credentials) = tokio::net::UnixStream::pair().unwrap();
    running.successors.try_send(door_credentials).unwrap();
    running.host = Some(open_host(credentials, running.environment_id).await);
    let (_, status, body) = running.request().await;
    assert_eq!((status, body), (StatusCode::OK, Bytes::from("answered")));
}

/// At most two sessions are live, a predecessor draining and its successor:
/// a third pairing ends the oldest, so a broker that keeps pairing cannot
/// pile sessions up in the confined process.
#[tokio::test]
async fn a_third_session_ends_the_oldest() {
    let mut running = Running::start(&[BOUND]).await;
    let _second = running.successor().await;
    let mut third = running.successor().await;
    assert!(matches!(
        bounded(running.host().receive()).await,
        Ok(None) | Err(_)
    ));
    let response = running.start_request().await;
    let seen = received(&mut third).await;
    answer(&third, &seen.request_id).await;
    assert_eq!(bounded(response).await.unwrap().0, StatusCode::OK);
}

/// The front door stops once no further session can arrive: the runner that
/// pairs brokers is gone.
#[tokio::test]
async fn the_front_door_stops_when_no_further_session_can_arrive() {
    let running = Running::start(&[BOUND]).await;
    drop(running.successors);
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Ended::SessionsClosed
    ));
    let mut byte = [0_u8; 1];
    assert_eq!(rustix::io::read(&running.handoff, &mut byte).unwrap(), 0);
}

#[test]
fn a_front_door_needs_bindings_and_serves_only_port_443() {
    let environment_id = Uuid::new_v4();
    assert!(matches!(
        EnvironmentFrontDoor::start(environment_id, GENERATION, InterceptSet::default()),
        Err(StartError::NoBindings)
    ));
    assert!(matches!(
        EnvironmentFrontDoor::start(environment_id, GENERATION, intercepts(&[BOUND], 80)),
        Err(StartError::Port)
    ));
    assert!(matches!(
        EnvironmentFrontDoor::start(Uuid::nil(), GENERATION, intercepts(&[BOUND], 443)),
        Err(StartError::Identity)
    ));
}

/// A frame the trusted broker should never send is a protocol error: the
/// front door closes its hand-off socket and stops, failing closed.
#[tokio::test]
async fn a_protocol_error_on_the_hand_off_stops_the_front_door() {
    let mut running = Running::start(&[BOUND]).await;
    let (_peer, datagram) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let header = InterceptedStreamHeader {
        version: codewire_egress_policy::handoff::HANDOFF_VERSION,
        hostname: BOUND.to_owned(),
        port: INTERCEPT_PORT,
        destination_ip: Ipv4Addr::new(192, 0, 2, 1),
        stream_id: 1,
        environment_id: running.environment_id.to_string(),
        aliases: Vec::new(),
    };
    running
        .handoff
        .send_intercepted_stream(&header, datagram.as_fd())
        .unwrap();
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Ended::Handoff(_)
    ));
}

/// Every stream the front door receives is acknowledged before its checks,
/// whether it is served or refused, so the broker drops its copy either way.
#[tokio::test(flavor = "multi_thread")]
async fn every_received_stream_is_acknowledged_served_or_refused() {
    let mut running = Running::start(&[BOUND]).await;
    let duplicate = rustix::io::fcntl_dupfd_cloexec(&running.handoff, 0).unwrap();
    rustix::net::sockopt::set_socket_timeout(
        &duplicate,
        rustix::net::sockopt::Timeout::Recv,
        Some(WAIT),
    )
    .unwrap();
    let mut acknowledged =
        codewire_egress_policy::handoff::HandoffReceiver::new(duplicate).unwrap();
    let other = Uuid::new_v4().to_string();
    let _refused = running.hand_over(BOUND, INTERCEPT_PORT, &other);
    let _served = running.own_stream(BOUND);
    for stream_id in [1_u64, 2] {
        let (body, _) = tokio::task::block_in_place(|| acknowledged.recv_frame(8, 0)).unwrap();
        assert_eq!(body, stream_id.to_le_bytes());
    }
}

/// A broker that stops reading acknowledgements fails the front door closed
/// within the acknowledgement bound, instead of hanging it. Small buffers
/// fill after a few unread acknowledgements.
#[tokio::test]
async fn a_broker_that_stops_reading_acknowledgements_stops_the_front_door() {
    let mut running = Running::start_with(&[BOUND], |end| {
        rustix::net::sockopt::set_socket_send_buffer_size(end, 1).unwrap();
    })
    .await;
    rustix::net::sockopt::set_socket_recv_buffer_size(&running.handoff, 1).unwrap();
    let mut guests = Vec::new();
    let started = tokio::time::Instant::now();
    while !running.door.is_finished() {
        assert!(started.elapsed() < WAIT, "the front door never stopped");
        guests.push(running.own_stream(BOUND));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(matches!(running.door.await.unwrap(), Ended::Handoff(_)));
}

/// A hosted front door starts with no credential session (#4001): a request
/// fails closed at the bridge rather than waiting, the front door carries
/// on, and once a session pairs requests are served.
#[tokio::test]
async fn without_a_credential_session_a_request_fails_closed_until_one_pairs() {
    let mut running = Running::serving(intercepts(&[BOUND], 443), |_| {}, false).await;
    let (status, _) = bounded(running.start_request().await).await.unwrap();
    assert_ne!(status, StatusCode::OK);
    assert!(!running.door.is_finished());

    running.host = Some(running.successor().await);
    let (_, status, body) = running.request().await;
    assert_eq!((status, body), (StatusCode::OK, Bytes::from("answered")));
}

/// The Codex slot's bindings as cw-egress takes them: `chatgpt.com`, exactly
/// and as its suffix (#6195).
fn codex_binding() -> InterceptSet {
    use codewire_egress_policy::intercept::InterceptSuffix;
    InterceptSet::with_suffixes(
        [InterceptBinding::new("chatgpt.com", 443).unwrap()],
        [InterceptSuffix::new("chatgpt.com", 443).unwrap()],
    )
    .unwrap()
}

/// A Codex model call on a fresh stream the broker handed over for `handed`,
/// naming `server_name` and sending `host` as Host, with a placeholder and the
/// account the agent names: the status and refusal the guest read.
async fn codex_call(
    running: &mut Running,
    handed: &str,
    server_name: &'static str,
    host: &'static str,
) -> tokio::task::JoinHandle<(StatusCode, Option<String>)> {
    let stream = running.own_stream(handed);
    let tls = running.tls(stream, server_name).await.expect("handshake");
    let (mut sender, connection) =
        bounded(hyper::client::conn::http1::handshake(TokioIo::new(tls)))
            .await
            .unwrap();
    tokio::spawn(connection);
    tokio::spawn(async move {
        let request = Request::post("/backend-api/codex/responses")
            .header("host", host)
            .header("authorization", "Bearer cwp1_agent-placeholder")
            .header("chatgpt-account-id", "agent-named-account")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let refusal = response
            .headers()
            .get("codewire-refusal")
            .map(|value| value.to_str().unwrap().to_owned());
        (response.status(), refusal)
    })
}

/// Codex's routed origin, one label under `chatgpt.com` and matched by the
/// suffix the Codex slot binds, reaches the credential broker naming that
/// origin and the admitted address, carrying the placeholder and the account
/// the agent sent as received: the swap, and the account header's
/// replacement, are the credential broker's alone, exactly as for
/// `chatgpt.com` (#6195). Mixed case in SNI or Host is normalised and then
/// matched; a Host with a trailing dot is misdirected, and a deeper name is
/// refused, both before the credential broker hears of them.
#[tokio::test]
async fn a_routed_origin_reaches_the_credential_broker_as_the_agent_sent_it() {
    let mut running = Running::start_binding(codex_binding(), |_| {}).await;
    for (server_name, host) in [
        ("routed.chatgpt.com", "routed.chatgpt.com"),
        ("Routed.ChatGPT.com", "ROUTED.chatgpt.COM"),
    ] {
        let call = codex_call(&mut running, "routed.chatgpt.com", server_name, host).await;
        let seen = received(running.host()).await;
        assert_eq!(
            (
                seen.intercepted_host.as_str(),
                seen.destination_ip.as_str(),
                seen.capability_slot.as_str(),
                seen.route.as_str(),
                seen.path.as_str(),
            ),
            (
                "routed.chatgpt.com",
                "192.0.2.1",
                "codex",
                "openai-api",
                "/backend-api/codex/responses",
            ),
            "{server_name} {host}"
        );
        let sent = |name: &str| -> Vec<&[u8]> {
            seen.headers
                .iter()
                .filter(|header| header.name == name)
                .map(|header| header.value.as_slice())
                .collect()
        };
        assert_eq!(
            sent("authorization"),
            [&b"Bearer cwp1_agent-placeholder"[..]]
        );
        assert_eq!(sent("chatgpt-account-id"), [&b"agent-named-account"[..]]);
        answer(running.host(), &seen.request_id).await;
        assert_eq!(bounded(call).await.unwrap().0, StatusCode::OK);
    }

    for (name, host, refused) in [
        (
            "routed.chatgpt.com",
            "routed.chatgpt.com.",
            (StatusCode::MISDIRECTED_REQUEST, "request_not_forwarded"),
        ),
        (
            "a.b.chatgpt.com",
            "a.b.chatgpt.com",
            (StatusCode::NOT_FOUND, "path_not_served"),
        ),
    ] {
        let call = codex_call(&mut running, name, name, host).await;
        let (status, refusal) = bounded(call).await.unwrap();
        assert_eq!(
            (status, refusal.as_deref()),
            (refused.0, Some(refused.1)),
            "{name} {host}"
        );
    }
    // Nothing reached the credential broker for either: its next request is
    // the next served one.
    let call = codex_call(
        &mut running,
        "x.chatgpt.com",
        "x.chatgpt.com",
        "x.chatgpt.com",
    )
    .await;
    let seen = received(running.host()).await;
    assert_eq!(seen.intercepted_host, "x.chatgpt.com");
    answer(running.host(), &seen.request_id).await;
    assert_eq!(bounded(call).await.unwrap().0, StatusCode::OK);
}
