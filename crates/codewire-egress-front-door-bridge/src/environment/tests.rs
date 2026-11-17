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
    host: FrontDoorHostSession,
    door: tokio::task::JoinHandle<Ended>,
    next_stream: u64,
}

impl Running {
    async fn start(hosts: &[&str]) -> Self {
        Self::start_with(hosts, |_| {}).await
    }

    /// [`Self::start`], with `configure` applied to the front door's end of
    /// the hand-off socket before it serves.
    async fn start_with(hosts: &[&str], configure: impl FnOnce(&OwnedFd)) -> Self {
        let environment_id = Uuid::new_v4();
        let door = EnvironmentFrontDoor::start(environment_id, GENERATION, intercepts(hosts, 443))
            .unwrap();
        let ca = door.ca_certificate_der().to_vec();
        let (door_handoff, handoff) = stream_pair().unwrap();
        configure(&door_handoff);
        let handoff = HandoffSender::new(handoff).unwrap();
        let (door_credentials, credentials) = tokio::net::UnixStream::pair().unwrap();
        let door = tokio::spawn(door.serve(door_handoff, door_credentials));
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
        Self {
            environment_id,
            ca,
            handoff,
            host,
            door,
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
        let (guest, handed) = std::os::unix::net::UnixStream::pair().unwrap();
        let header = InterceptedStreamHeader {
            version: codewire_egress_policy::handoff::HANDOFF_VERSION,
            hostname: hostname.to_owned(),
            port,
            destination_ip: Ipv4Addr::new(192, 0, 2, 1),
            stream_id: self.next_stream,
            environment_id: environment_id.to_owned(),
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

    /// One request through a fresh handed-over stream: what reached the
    /// credential broker, and the response the guest read.
    async fn request(&mut self) -> (v1::CredentialBridgeRequest, StatusCode, Bytes) {
        let stream = self.own_stream(BOUND);
        let tls = self.tls(stream, BOUND).await.expect("handshake");
        let (mut sender, connection) =
            bounded(hyper::client::conn::http1::handshake(TokioIo::new(tls)))
                .await
                .unwrap();
        tokio::spawn(connection);
        let response = tokio::spawn(
            sender.send_request(
                Request::post("/v1/responses")
                    .header("host", BOUND)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from_static(b"{}")))
                    .unwrap(),
            ),
        );
        let Some(GuestPayload::Request(seen)) =
            bounded(self.host.receive()).await.unwrap().unwrap().payload
        else {
            panic!("expected a request at the credential broker");
        };
        let sender = self.host.sender();
        for payload in [
            HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
                request_id: seen.request_id.clone(),
                status_code: 200,
                headers: Vec::new(),
            }),
            HostPayload::ResponseBody(v1::CredentialBridgeResponseBody {
                request_id: seen.request_id.clone(),
                data: b"answered".to_vec(),
            }),
            HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
                request_id: seen.request_id.clone(),
            }),
        ] {
            sender
                .send(v1::CredentialBridgeHostMessage {
                    payload: Some(payload),
                })
                .await
                .unwrap();
        }
        let response = bounded(response).await.unwrap().unwrap();
        let status = response.status();
        let body = bounded(response.into_body().collect())
            .await
            .unwrap()
            .to_bytes();
        (seen, status, body)
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

/// Killing the credential side fails closed: the front door stops, and with
/// it the hand-off socket, so the broker's next hand-off finds no one.
#[tokio::test]
async fn the_front_door_stops_when_its_credential_session_ends() {
    let running = Running::start(&[BOUND]).await;
    drop(running.host);
    assert!(matches!(
        bounded(running.door).await.unwrap(),
        Ended::Session(None)
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
