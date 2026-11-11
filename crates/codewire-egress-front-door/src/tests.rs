use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::upgrade::Upgraded;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::hello::{self, Hello};
use crate::serve::{Route, route};
use crate::{
    Accepted, Backend, BoxError, CaError, EnvironmentCa, FrontDoor, FrontDoorConfig,
    FrontDoorError, HandBackReason, MAX_CLIENT_HELLO_BYTES, ResponseBody, Served, UpgradeOutcome,
};

const BOUND: &str = "api.example.com";
const SECOND: &str = "api.example.net";
const OTHER: &str = "other.example.com";
/// A failure guard, longer than every bound under test.
const WAIT: Duration = Duration::from_secs(60);

/// What the fake back end received.
#[derive(Clone, Debug)]
struct Seen {
    host: String,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<Seen>>,
    /// The test's ends of spliced upstream streams.
    upstreams: Mutex<Vec<DuplexStream>>,
    refuse_upgrades: AtomicBool,
}

impl Fake {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn upstream(&self) -> DuplexStream {
        self.upstreams
            .lock()
            .unwrap()
            .pop()
            .expect("a spliced upstream")
    }

    fn record(&self, host: &str, parts: http::request::Parts, body: Bytes) {
        self.seen.lock().unwrap().push(Seen {
            host: host.to_owned(),
            method: parts.method,
            uri: parts.uri,
            version: parts.version,
            headers: parts.headers,
            body,
        });
    }
}

fn full(bytes: &'static [u8]) -> ResponseBody {
    Full::new(Bytes::from_static(bytes))
        .map_err(|never| match never {})
        .boxed()
}

impl Backend for Arc<Fake> {
    async fn respond(&self, host: &str, request: Request<Incoming>) -> Response<ResponseBody> {
        let (parts, body) = request.into_parts();
        let body = body.collect().await.expect("request body").to_bytes();
        self.record(host, parts, body);
        let chunks = futures::stream::iter(
            ["hello, ", "world"]
                .map(|chunk| Ok::<_, BoxError>(Frame::data(Bytes::from_static(chunk.as_bytes())))),
        );
        Response::new(StreamBody::new(chunks).boxed())
    }

    async fn upgrade(&self, host: &str, request: Request<()>) -> UpgradeOutcome {
        let (parts, ()) = request.into_parts();
        self.record(host, parts, Bytes::new());
        if self.refuse_upgrades.load(Ordering::Relaxed) {
            let mut refused = Response::new(full(b"refused"));
            *refused.status_mut() = StatusCode::FORBIDDEN;
            return Err(refused);
        }
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        self.upstreams.lock().unwrap().push(ours);
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("sec-websocket-accept", "test-accept")
            .body(())
            .unwrap();
        Ok((response, Box::new(theirs)))
    }
}

type Door = Arc<FrontDoor<Arc<Fake>>>;
type Outcome = JoinHandle<Result<Accepted<DuplexStream>, FrontDoorError>>;

fn door_with(config: FrontDoorConfig) -> (Door, Arc<Fake>) {
    let backend = Arc::new(Fake::default());
    let ca = EnvironmentCa::generate([BOUND, SECOND]).unwrap();
    (
        Arc::new(FrontDoor::new(ca, backend.clone(), config)),
        backend,
    )
}

fn door() -> (Door, Arc<Fake>) {
    door_with(FrontDoorConfig::default())
}

/// Accepts one end of an in-memory connection; returns the peer's end.
fn start(door: &Door) -> (DuplexStream, Outcome) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let door = door.clone();
    (
        client,
        tokio::spawn(async move { door.accept(server, BOUND).await }),
    )
}

/// A client that trusts only `ca`.
fn client_config(ca: &EnvironmentCa, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der().clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn tls(door: &Door, alpn: &[&[u8]]) -> (TlsStream<DuplexStream>, Outcome) {
    let (client, outcome) = start(door);
    let tls = TlsConnector::from(client_config(door.ca(), alpn))
        .connect(ServerName::try_from(BOUND).unwrap(), client)
        .await
        .expect("handshake");
    (tls, outcome)
}

/// The exact first flight a real client sends for `server_name`.
fn client_hello(ca: &EnvironmentCa, server_name: ServerName<'static>) -> Vec<u8> {
    let config = client_config(ca, &[b"h2", b"http/1.1"]);
    let mut connection = rustls::ClientConnection::new(config, server_name).unwrap();
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).unwrap();
    hello
}

fn named(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).unwrap()
}

fn address() -> ServerName<'static> {
    ServerName::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).into())
}

async fn served(outcome: Outcome) -> Served {
    match tokio::time::timeout(WAIT, outcome)
        .await
        .expect("accept ends")
    {
        Ok(Ok(Accepted::Served(served))) => served,
        other => panic!("not served: {other:?}"),
    }
}

async fn failed(outcome: Outcome) -> FrontDoorError {
    match tokio::time::timeout(WAIT, outcome)
        .await
        .expect("accept ends")
    {
        Ok(Err(error)) => error,
        other => panic!("not an error: {other:?}"),
    }
}

async fn handed_back(outcome: Outcome) -> (DuplexStream, Bytes, HandBackReason) {
    match tokio::time::timeout(WAIT, outcome)
        .await
        .expect("accept ends")
    {
        Ok(Ok(Accepted::HandBack {
            stream,
            read,
            reason,
        })) => (stream, read, reason),
        other => panic!("not handed back: {other:?}"),
    }
}

/// The peer reads end of stream, or a failure, and never any bytes.
async fn assert_closed_silently<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut rest))
        .await
        .expect("stream closes");
    assert!(rest.is_empty(), "peer received {} bytes", rest.len());
}

type Http1 = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

async fn http1(tls: TlsStream<DuplexStream>) -> Http1 {
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    sender
}

fn get(uri: &str) -> http::request::Builder {
    Request::get(uri).header(HOST, BOUND)
}

/// The front door never reads the WebSocket handshake nonce. Sixteen zero
/// bytes: a random-looking value here reads as a credential to the secret
/// scan.
const HANDSHAKE_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

fn websocket_request() -> Request<Full<Bytes>> {
    get("/v1/realtime?model=m")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-key", HANDSHAKE_NONCE)
        .header("sec-websocket-version", "13")
        .body(Full::default())
        .unwrap()
}

/// A spliced WebSocket: the client's upgraded stream and the fake upstream.
async fn websocket(door: &Door, backend: &Fake) -> (TokioIo<Upgraded>, DuplexStream, Outcome) {
    let (tls, outcome) = tls(door, &[b"http/1.1"]).await;
    let mut sender = http1(tls).await;
    let response = sender.send_request(websocket_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.headers()["sec-websocket-accept"], "test-accept");
    assert_eq!(response.headers()[UPGRADE], "websocket");
    let client = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
    (client, backend.upstream(), outcome)
}

/// Sends one raw HTTP/1.1 request on its own connection; the status code.
async fn raw_status(door: &Door, request: &str) -> u16 {
    let (mut tls, _outcome) = tls(door, &[b"http/1.1"]).await;
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    std::str::from_utf8(&head[9..12]).unwrap().parse().unwrap()
}

// ---------------------------------------------------------------------------
// The CA

#[test]
fn bound_hosts_must_be_exact_canonical_names() {
    let invalid: Vec<Vec<String>> = vec![
        vec![],
        vec!["API.example.com".into()],
        vec!["api.example.com.".into()],
        vec!["*.example.com".into()],
        vec!["192.0.2.1".into()],
        vec!["com".into()],
        vec!["bad_name.example.com".into()],
        vec![" api.example.com".into()],
        vec![BOUND.into(), BOUND.into()],
        (0..33)
            .map(|index| format!("h{index}.example.com"))
            .collect(),
    ];
    for hosts in invalid {
        assert_eq!(
            EnvironmentCa::generate(&hosts).err(),
            Some(CaError::InvalidBoundHosts),
            "accepted {hosts:?}"
        );
    }
    let most: Vec<String> = (0..32)
        .map(|index| format!("h{index}.example.com"))
        .collect();
    assert_eq!(EnvironmentCa::generate(&most).unwrap().bound_hosts(), most);
}

#[test]
fn the_ca_debug_output_names_only_its_hosts() {
    let ca = EnvironmentCa::generate([BOUND]).unwrap();
    assert_eq!(
        format!("{ca:?}"),
        r#"EnvironmentCa { hosts: ["api.example.com"], .. }"#
    );
    assert!(
        ca.certificate_pem()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
}

#[test]
fn the_ca_is_name_constrained_to_exactly_the_bound_hosts() {
    let ca = EnvironmentCa::generate([BOUND, SECOND]).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (_, cert) = X509Certificate::from_der(ca.certificate_der()).unwrap();
    cert.verify_signature(None).unwrap();
    assert_eq!(cert.subject(), cert.issuer());
    let common_name = cert.subject().iter_common_name().next().unwrap();
    assert_eq!(
        common_name.as_str().unwrap(),
        "Codewire environment egress CA"
    );
    assert_eq!(
        cert.subject().iter().count(),
        1,
        "nothing else in the subject"
    );

    let basic = cert.basic_constraints().unwrap().unwrap();
    assert!(basic.critical);
    assert!(basic.value.ca);
    assert_eq!(basic.value.path_len_constraint, Some(0));
    let usage = cert.key_usage().unwrap().unwrap();
    assert!(usage.critical);
    assert!(usage.value.key_cert_sign() && usage.value.crl_sign());
    assert!(!usage.value.digital_signature());

    let constraints = cert.name_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    let permitted: Vec<_> = constraints
        .value
        .permitted_subtrees
        .as_ref()
        .unwrap()
        .iter()
        .map(|subtree| match subtree.base {
            GeneralName::DNSName(name) => name,
            ref other => panic!("permitted a non-DNS name: {other:?}"),
        })
        .collect();
    assert_eq!(permitted, [BOUND, SECOND]);
    let excluded: Vec<_> = constraints
        .value
        .excluded_subtrees
        .as_ref()
        .unwrap()
        .iter()
        .map(|subtree| match subtree.base {
            GeneralName::IPAddress(range) => range.to_vec(),
            ref other => panic!("excluded a non-address name: {other:?}"),
        })
        .collect();
    assert_eq!(excluded, [vec![0; 8], vec![0; 32]]);

    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    assert!(
        (now - 5 * 60 - not_before).abs() <= 5,
        "backdated 5 minutes"
    );
    assert!(
        (not_after - (now + 30 * 24 * 60 * 60)).abs() <= 5,
        "30 days"
    );
}

#[test]
fn leaves_chain_to_the_ca_name_only_their_host_and_are_cached() {
    let ca = EnvironmentCa::generate([BOUND, SECOND]).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (_, authority) = X509Certificate::from_der(ca.certificate_der()).unwrap();
    let (host, key) = ca.leaf("API.example.COM").unwrap();
    assert_eq!(host, BOUND);
    assert_eq!(
        key.cert.len(),
        1,
        "the leaf alone; the CA is the trust anchor"
    );
    let (_, leaf) = X509Certificate::from_der(&key.cert[0]).unwrap();
    leaf.verify_signature(Some(authority.public_key())).unwrap();
    assert_eq!(leaf.issuer(), authority.subject());

    let names = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(names.value.general_names, [GeneralName::DNSName(BOUND)]);
    let purposes = leaf.extended_key_usage().unwrap().unwrap().value;
    assert!(purposes.server_auth);
    assert!(!purposes.any && !purposes.client_auth && !purposes.code_signing);
    assert!(purposes.other.is_empty());
    assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    let validity = leaf.validity();
    assert!((now - 5 * 60 - validity.not_before.timestamp()).abs() <= 5);
    assert!((validity.not_after.timestamp() - (now + 24 * 60 * 60)).abs() <= 5);

    let (_, again) = ca.leaf(BOUND).unwrap();
    assert!(Arc::ptr_eq(&key, &again), "cached per host");
    let (_, second) = ca.leaf(SECOND).unwrap();
    let (_, second) = X509Certificate::from_der(&second.cert[0]).unwrap();
    let names = second.subject_alternative_name().unwrap().unwrap();
    assert_eq!(names.value.general_names, [GeneralName::DNSName(SECOND)]);
    assert_eq!(ca.leaf(OTHER).err(), Some(CaError::UnboundHost));
}

/// Signs a leaf for `san` with the CA's key, outside what it would mint, and
/// connects a client that trusts only the CA.
async fn connect_to_leaf(
    ca: &EnvironmentCa,
    san: SanType,
    server_name: ServerName<'static>,
) -> Result<(), String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "test");
    params.subject_alt_names = vec![san];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = ca.sign_for_test(params, &key);
    let server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
    let (client, server_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(TlsAcceptor::from(Arc::new(server)).accept(server_io));
    let result = TlsConnector::from(client_config(ca, &[]))
        .connect(server_name, client)
        .await;
    server_task.abort();
    result.map(drop).map_err(|error| format!("{error:?}"))
}

#[tokio::test]
async fn a_client_trusting_the_ca_enforces_its_name_constraint() {
    let ca = EnvironmentCa::generate([BOUND]).unwrap();
    let dns = |name: &str| SanType::DnsName(name.try_into().unwrap());
    // The seam itself produces certificates a client accepts...
    assert_eq!(connect_to_leaf(&ca, dns(BOUND), named(BOUND)).await, Ok(()));
    // ...so these refusals are the constraint's.
    let outside = connect_to_leaf(&ca, dns("evil.example.org"), named("evil.example.org")).await;
    assert!(
        outside
            .as_ref()
            .is_err_and(|error| error.contains("NameConstraintViolation")),
        "{outside:?}"
    );
    let address_san = SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let address = connect_to_leaf(&ca, address_san, address()).await;
    assert!(
        address
            .as_ref()
            .is_err_and(|error| error.contains("NameConstraintViolation")),
        "{address:?}"
    );
    // A DNS name constraint is a subtree (RFC 5280, name constraints): names
    // below a bound host pass it too. Only minting keeps leaves to exact hosts.
    let below = format!("deep.{BOUND}");
    assert_eq!(
        connect_to_leaf(&ca, dns(&below), named(&below)).await,
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Accepting

#[tokio::test]
async fn a_get_reaches_the_back_end_over_http1_with_bodies_streamed() {
    let (door, backend) = door();
    let (tls, outcome) = tls(&door, &[b"http/1.1"]).await;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    let mut sender = http1(tls).await;
    let request = get("/v1/models?limit=2")
        .body(Full::new(Bytes::from_static(b"ping")))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "hello, world");
    drop(sender);
    assert_eq!(
        served(outcome).await,
        Served {
            requests: 1,
            upgraded: 0
        }
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].host, BOUND);
    assert_eq!(seen[0].method, Method::GET);
    assert_eq!(seen[0].uri, "/v1/models?limit=2");
    assert_eq!(seen[0].version, Version::HTTP_11);
    assert_eq!(seen[0].headers[HOST], BOUND);
    assert_eq!(seen[0].body, "ping");
}

#[tokio::test]
async fn a_get_reaches_the_back_end_over_http2_in_origin_form() {
    let (door, backend) = door();
    let (tls, outcome) = tls(&door, &[b"h2", b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    let request = Request::get(format!("https://{BOUND}/v1/models?limit=2"))
        .body(Full::new(Bytes::from_static(b"ping")))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "hello, world");

    let misdirected = Request::get(format!("https://{OTHER}/"))
        .body(Full::default())
        .unwrap();
    let response = sender.send_request(misdirected).await.unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    // A live response keeps the client's connection open.
    drop((response, sender));
    assert_eq!(
        served(outcome).await,
        Served {
            requests: 2,
            upgraded: 0
        }
    );

    let seen = backend.seen();
    assert_eq!(seen.len(), 1, "the misdirected request stops here");
    assert_eq!(seen[0].uri, "/v1/models?limit=2");
    assert_eq!(seen[0].uri.authority(), None);
    assert_eq!(seen[0].version, Version::HTTP_2);
    assert_eq!(seen[0].body, "ping");
}

#[tokio::test]
async fn another_server_name_is_handed_back_untouched() {
    let (door, backend) = door();
    for (server_name, reason) in [
        (named(OTHER), HandBackReason::OtherServerName),
        // The CA binds this host, but the dial was attributed to BOUND.
        (named(SECOND), HandBackReason::OtherServerName),
        // Clients send no server name when connecting to an address.
        (address(), HandBackReason::NoServerName),
    ] {
        let hello = client_hello(door.ca(), server_name);
        let (mut client, outcome) = start(&door);
        client.write_all(&hello).await.unwrap();
        let (stream, read, why) = handed_back(outcome).await;
        assert_eq!(why, reason);
        assert_eq!(read, hello, "every byte read, and no more");
        drop(stream);
        assert_closed_silently(&mut client).await;
    }
    assert!(backend.seen().is_empty());
}

#[tokio::test]
async fn bytes_that_are_not_tls_are_handed_back_after_one_byte() {
    let (door, backend) = door();
    let sent = format!("GET / HTTP/1.1\r\nHost: {BOUND}\r\n\r\n");
    let (mut client, outcome) = start(&door);
    client.write_all(sent.as_bytes()).await.unwrap();
    let (mut stream, read, reason) = handed_back(outcome).await;
    assert_eq!(reason, HandBackReason::NotClientHello);
    assert_eq!(read, "G");
    let mut rest = vec![0; sent.len() - 1];
    stream.read_exact(&mut rest).await.unwrap();
    assert_eq!([&read[..], &rest].concat(), sent.as_bytes());
    // The caller now owns the stream in both directions.
    stream.write_all(b"from the caller").await.unwrap();
    let mut reply = [0; 15];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"from the caller");
    assert!(backend.seen().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_slow_client_hello_hits_the_time_bound() {
    let (door, _backend) = door();
    let hello = client_hello(door.ca(), named(BOUND));
    let (mut client, outcome) = start(&door);
    client.write_all(&hello[..20]).await.unwrap();
    assert_eq!(failed(outcome).await, FrontDoorError::HelloTimeout);
    assert_closed_silently(&mut client).await;
}

#[tokio::test]
async fn an_oversized_client_hello_hits_the_size_bound() {
    let (door, _backend) = door();
    // A ClientHello declaring a length beyond the bound.
    let (mut client, outcome) = start(&door);
    client
        .write_all(&[22, 3, 1, 0, 6, 1, 0, 0x40, 0, 3, 3])
        .await
        .unwrap();
    assert_eq!(failed(outcome).await, FrontDoorError::HelloTooLarge);
    assert_closed_silently(&mut client).await;

    // One that fits by itself but not split into many small records.
    let body = 16_000;
    let mut message = vec![1, 0, (body >> 8) as u8, body as u8];
    message.resize(4 + body, 0);
    let mut records = Vec::new();
    for fragment in message.chunks(100) {
        records.extend_from_slice(&[22, 3, 1, 0, fragment.len() as u8]);
        records.extend_from_slice(fragment);
    }
    let (mut client, outcome) = start(&door);
    client.write_all(&records).await.unwrap();
    assert_eq!(failed(outcome).await, FrontDoorError::HelloTooLarge);
    assert_closed_silently(&mut client).await;
}

#[tokio::test]
async fn misdirected_absolute_and_tunnel_requests_never_reach_the_back_end() {
    let (door, backend) = door();
    for (request, status) in [
        (format!("GET / HTTP/1.1\r\nHost: {OTHER}\r\n\r\n"), 421),
        (format!("GET / HTTP/1.1\r\nHost: {BOUND}:8443\r\n\r\n"), 421),
        ("GET / HTTP/1.1\r\n\r\n".to_owned(), 421),
        (
            format!("GET http://{BOUND}/ HTTP/1.1\r\nHost: {BOUND}\r\n\r\n"),
            400,
        ),
        (format!("OPTIONS * HTTP/1.1\r\nHost: {BOUND}\r\n\r\n"), 400),
        (
            format!("CONNECT {BOUND}:443 HTTP/1.1\r\nHost: {BOUND}:443\r\n\r\n"),
            403,
        ),
    ] {
        assert_eq!(raw_status(&door, &request).await, status, "{request:?}");
    }
    assert!(backend.seen().is_empty());
}

#[test]
fn requests_are_routed_before_the_back_end() {
    let h1 = |uri: &str| Request::get(uri).header(HOST, BOUND);
    let websocket = || {
        h1("/socket")
            .header(CONNECTION, "keep-alive, Upgrade")
            .header(UPGRADE, "WebSocket")
    };
    let h2 = |uri: &str| Request::get(uri).version(Version::HTTP_2);
    let cases: Vec<(http::request::Builder, Result<Route, StatusCode>)> = vec![
        (h1("/x?y=1"), Ok(Route::Ordinary)),
        (
            Request::get("/x").header(HOST, "API.Example.com:443"),
            Ok(Route::Ordinary),
        ),
        (
            Request::get("/x").header(HOST, format!("{BOUND}.")),
            Err(StatusCode::MISDIRECTED_REQUEST),
        ),
        (
            h1("/x").header(HOST, BOUND),
            Err(StatusCode::MISDIRECTED_REQUEST),
        ),
        (
            Request::get("/x").header(HOST, format!("user@{BOUND}")),
            Err(StatusCode::MISDIRECTED_REQUEST),
        ),
        (
            h1("https://api.example.com/x"),
            Err(StatusCode::BAD_REQUEST),
        ),
        (
            Request::connect(format!("{BOUND}:443")).header(HOST, BOUND),
            Err(StatusCode::FORBIDDEN),
        ),
        (websocket(), Ok(Route::WebSocket)),
        (
            websocket().version(Version::HTTP_10),
            Err(StatusCode::FORBIDDEN),
        ),
        (websocket().method(Method::POST), Err(StatusCode::FORBIDDEN)),
        (
            websocket().header("content-length", "5"),
            Err(StatusCode::FORBIDDEN),
        ),
        (
            websocket().header("transfer-encoding", "chunked"),
            Err(StatusCode::FORBIDDEN),
        ),
        (
            h1("/").header(CONNECTION, "upgrade").header(UPGRADE, "h2c"),
            Err(StatusCode::FORBIDDEN),
        ),
        (
            h1("/")
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket, h2c"),
            Err(StatusCode::FORBIDDEN),
        ),
        (
            websocket().header(UPGRADE, "websocket"),
            Err(StatusCode::FORBIDDEN),
        ),
        (
            h1("/").header(UPGRADE, "websocket"),
            Err(StatusCode::FORBIDDEN),
        ),
        (h2("https://api.example.com/x?y=1"), Ok(Route::Ordinary)),
        (
            h2("https://api.example.com:443/x").header(HOST, "api.example.com:443"),
            Ok(Route::Ordinary),
        ),
        (h2("/x").header(HOST, BOUND), Ok(Route::Ordinary)),
        (
            h2("https://other.example.com/x"),
            Err(StatusCode::MISDIRECTED_REQUEST),
        ),
        (
            h2("https://api.example.com/x").header(HOST, OTHER),
            Err(StatusCode::BAD_REQUEST),
        ),
        (h2("http://api.example.com/x"), Err(StatusCode::BAD_REQUEST)),
        (
            h2("https://api.example.com/x")
                .header(CONNECTION, "upgrade")
                .header(UPGRADE, "websocket"),
            Err(StatusCode::FORBIDDEN),
        ),
    ];
    for (builder, expected) in cases {
        let mut request = builder.body(()).unwrap();
        let before = format!(
            "{} {} {:?}",
            request.method(),
            request.uri(),
            request.headers()
        );
        assert_eq!(route(&mut request, BOUND), expected, "{before}");
        if expected.is_ok() {
            assert!(request.uri().authority().is_none(), "{before}");
            assert!(request.uri().path().starts_with("/x") || request.uri() == "/socket");
        }
    }
}

// ---------------------------------------------------------------------------
// WebSockets

#[tokio::test]
async fn a_websocket_is_spliced_both_ways_until_the_client_closes() {
    let (door, backend) = door();
    let (mut client, mut upstream, outcome) = websocket(&door, &backend).await;
    let seen = backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].uri, "/v1/realtime?model=m");
    assert_eq!(seen[0].headers["sec-websocket-key"], HANDSHAKE_NONCE);
    assert_eq!(seen[0].headers[UPGRADE], "websocket");

    client.write_all(b"\x81\x05hello").await.unwrap();
    let mut frame = [0; 7];
    upstream.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"\x81\x05hello");
    upstream.write_all(b"\x81\x05world").await.unwrap();
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"\x81\x05world");

    client.shutdown().await.unwrap();
    assert_closed_silently(&mut upstream).await;
    assert_eq!(
        served(outcome).await,
        Served {
            requests: 1,
            upgraded: 1
        }
    );
}

#[tokio::test]
async fn a_websocket_closes_at_the_client_when_the_upstream_closes() {
    let (door, backend) = door();
    let (mut client, upstream, outcome) = websocket(&door, &backend).await;
    drop(upstream);
    assert_closed_silently(&mut client).await;
    assert_eq!(served(outcome).await.upgraded, 1);
}

#[tokio::test]
async fn an_idle_websocket_is_closed_at_both_ends() {
    let (door, backend) = door_with(FrontDoorConfig {
        websocket_idle_timeout: Duration::from_millis(200),
        ..FrontDoorConfig::default()
    });
    let (mut client, mut upstream, outcome) = websocket(&door, &backend).await;
    client.write_all(b"one").await.unwrap();
    let mut three = [0; 3];
    upstream.read_exact(&mut three).await.unwrap();
    assert_closed_silently(&mut client).await;
    assert_closed_silently(&mut upstream).await;
    assert_eq!(served(outcome).await.upgraded, 1);
}

#[tokio::test]
async fn other_upgrades_are_forbidden() {
    let (door, backend) = door();
    for request in [
        format!(
            "GET / HTTP/1.1\r\nHost: {BOUND}\r\nConnection: Upgrade, HTTP2-Settings\r\n\
             Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: {BOUND}\r\nConnection: Upgrade\r\nUpgrade: websocket, h2c\r\n\r\n"
        ),
        format!("GET / HTTP/1.1\r\nHost: {BOUND}\r\nUpgrade: websocket\r\n\r\n"),
    ] {
        assert_eq!(raw_status(&door, &request).await, 403, "{request:?}");
    }
    assert!(backend.seen().is_empty());
}

#[tokio::test]
async fn a_refused_upgrade_answers_and_keeps_the_connection_usable() {
    let (door, backend) = door();
    backend.refuse_upgrades.store(true, Ordering::Relaxed);
    let (tls, outcome) = tls(&door, &[b"http/1.1"]).await;
    let mut sender = http1(tls).await;
    let response = sender.send_request(websocket_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "refused");

    let response = sender
        .send_request(get("/after").body(Full::default()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "hello, world");
    drop(sender);
    assert_eq!(
        served(outcome).await,
        Served {
            requests: 2,
            upgraded: 0
        }
    );
    let uris: Vec<_> = backend.seen().into_iter().map(|seen| seen.uri).collect();
    assert_eq!(uris, ["/v1/realtime?model=m", "/after"]);
}

// ---------------------------------------------------------------------------
// Limits and shutdown

#[tokio::test]
async fn connections_over_the_cap_are_closed_before_the_handshake() {
    let (door, _backend) = door_with(FrontDoorConfig {
        max_connections: 1,
        ..FrontDoorConfig::default()
    });
    let (first, first_outcome) = tls(&door, &[b"http/1.1"]).await;
    let (mut second, second_outcome) = start(&door);
    assert_eq!(failed(second_outcome).await, FrontDoorError::AtCapacity);
    assert_closed_silently(&mut second).await;

    drop(first);
    assert_eq!(served(first_outcome).await, Served::default());
    let (third, third_outcome) = tls(&door, &[b"http/1.1"]).await;
    drop(third);
    assert_eq!(served(third_outcome).await, Served::default());
}

#[tokio::test]
async fn close_ends_a_spliced_websocket_and_refuses_new_connections() {
    let (door, backend) = door();
    let (mut client, mut upstream, outcome) = websocket(&door, &backend).await;
    door.close();
    assert_eq!(served(outcome).await.upgraded, 1);
    assert_closed_silently(&mut client).await;
    assert_closed_silently(&mut upstream).await;

    let (mut late, late_outcome) = start(&door);
    assert_eq!(failed(late_outcome).await, FrontDoorError::Closed);
    assert_closed_silently(&mut late).await;
}

// ---------------------------------------------------------------------------
// Arbitrary input

/// A small deterministic generator: the same cases on every run.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }
}

/// Inputs around real ClientHellos: random bytes, truncations, corruptions,
/// refragmentations, wild record lengths and trailing data.
fn arbitrary_input(random: &mut Xorshift, seeds: &[Vec<u8>]) -> Vec<u8> {
    let seed = &seeds[random.below(seeds.len())];
    match random.below(6) {
        0 => {
            let length = if random.below(8) == 0 {
                MAX_CLIENT_HELLO_BYTES + random.below(4096)
            } else {
                random.below(600)
            };
            random.bytes(length)
        }
        1 => seed[..random.below(seed.len() + 1)].to_vec(),
        2 => {
            let mut input = seed.clone();
            for _ in 0..1 + random.below(8) {
                let at = random.below(input.len());
                input[at] = random.next() as u8;
            }
            input
        }
        3 => {
            let message = &seed[5..];
            let mut input = Vec::new();
            let mut at = 0;
            while at < message.len() {
                let length = (1 + random.below(300)).min(message.len() - at);
                input.extend_from_slice(&[22, 3, 1, (length >> 8) as u8, length as u8]);
                input.extend_from_slice(&message[at..at + length]);
                at += length;
            }
            input
        }
        4 => {
            let mut input = Vec::new();
            for _ in 0..1 + random.below(4) {
                let length = random.below(1 << 16);
                input.extend_from_slice(&[22, 3, random.below(5) as u8]);
                input.extend_from_slice(&(length as u16).to_be_bytes());
                let body = length.min(random.below(2048));
                input.extend(random.bytes(body));
            }
            input
        }
        _ => {
            let mut input = seed.clone();
            let trailing = 1 + random.below(64);
            input.extend(random.bytes(trailing));
            input
        }
    }
}

fn seeds(ca: &EnvironmentCa) -> Vec<Vec<u8>> {
    vec![
        client_hello(ca, named(BOUND)),
        client_hello(ca, named(OTHER)),
        client_hello(ca, address()),
    ]
}

#[tokio::test]
async fn the_hello_reader_takes_only_what_it_needs_from_any_input() {
    let ca = EnvironmentCa::generate([BOUND]).unwrap();
    let seeds = seeds(&ca);
    let mut random = Xorshift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..4000 {
        let input = arbitrary_input(&mut random, &seeds);
        let mut reader = input.as_slice();
        let mut read = BytesMut::new();
        let outcome = hello::read_client_hello(&mut reader, &mut read).await;
        assert!(read.len() <= MAX_CLIENT_HELLO_BYTES);
        assert_eq!(
            read.len() + reader.len(),
            input.len(),
            "read is what was taken"
        );
        assert_eq!(read[..], input[..read.len()]);
        if seeds.iter().any(|seed| input.starts_with(seed)) {
            assert!(matches!(outcome, Ok(Hello::ClientHello { .. })));
            assert!(
                seeds.iter().any(|seed| read[..] == seed[..]),
                "stops at its end"
            );
        }
    }
}

/// Reads `input` then end of stream; records anything written.
struct Scripted {
    input: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Scripted {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.input).poll_read(cx, buf)
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.written.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn every_hand_back_returns_exactly_the_bytes_consumed() {
    let backend = Arc::new(Fake::default());
    let door = FrontDoor::new(
        EnvironmentCa::generate([BOUND]).unwrap(),
        backend.clone(),
        FrontDoorConfig::default(),
    );
    let seeds = seeds(door.ca());
    let mut random = Xorshift(0x2545_f491_4f6c_dd1d);
    let mut handed_back = 0;
    for _ in 0..1000 {
        let input = arbitrary_input(&mut random, &seeds);
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = Scripted {
            input: Cursor::new(input.clone()),
            written: written.clone(),
        };
        if let Ok(Accepted::HandBack {
            mut stream, read, ..
        }) = door.accept(stream, BOUND).await
        {
            handed_back += 1;
            assert!(written.lock().unwrap().is_empty(), "nothing written");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert_eq!([&read[..], &rest].concat(), input);
        }
    }
    assert!(handed_back > 300, "only {handed_back} cases handed back");
    assert!(backend.seen().is_empty());
}
