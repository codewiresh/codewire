//! The WebSocket upgrade client (#3999) against a raw-socket provider
//! stand-in: what reaches the wire, and what comes back.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use base64::Engine as _;

use super::*;

/// A provider that reads one request head, sends it to the test, and
/// answers with `reply`. After a `101` it echoes five bytes, then says
/// "world".
async fn provider(reply: &'static [u8]) -> (SocketAddr, oneshot::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (head_tx, head_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut head = Vec::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                break;
            }
            head.push(line.trim_end().to_owned());
        }
        let _ = head_tx.send(head);
        stream.get_mut().write_all(reply).await.unwrap();
        if reply.starts_with(b"HTTP/1.1 101") {
            let mut echo = [0_u8; 5];
            stream.read_exact(&mut echo).await.unwrap();
            stream.get_mut().write_all(&echo).await.unwrap();
            stream.get_mut().write_all(b"world").await.unwrap();
        }
    });
    (address, head_rx)
}

/// The production upgrade client; only what a plain loopback stand-in needs
/// differs: http, and the host pinned to it.
fn client(address: SocketAddr) -> reqwest::Client {
    upgrade_client_builder()
        .https_only(false)
        .resolve(OPENAI_HOST, address)
        .build()
        .unwrap()
}

/// RFC 6455's sample handshake nonce, encoded as a client sends it.
fn sample_nonce() -> String {
    base64::engine::general_purpose::STANDARD.encode(b"the sample nonce")
}

fn opening_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("authorization", "Bearer swapped"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert(
        "sec-websocket-key",
        HeaderValue::from_str(&sample_nonce()).unwrap(),
    );
    headers
}

fn header<'a>(head: &'a [String], name: &str) -> Vec<&'a str> {
    head.iter()
        .filter_map(|line| line.split_once(':'))
        .filter(|(line_name, _)| line_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

#[tokio::test]
async fn an_opening_request_reaches_the_wire_whole_and_101_yields_the_socket() {
    let (address, head) = provider(
        b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\
          sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    )
    .await;
    let target = url::Url::parse(&format!(
        "http://{OPENAI_HOST}:{}/v1/realtime?model=m",
        address.port()
    ))
    .unwrap();
    let response = send_upgrade(&client(address), &target, opening_headers())
        .await
        .unwrap();
    let upgraded = switched_or_response(response).await.unwrap();

    let head = head.await.unwrap();
    assert_eq!(head[0], "GET /v1/realtime?model=m HTTP/1.1");
    assert!(
        header(&head, "connection")
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("upgrade")),
        "{head:?}"
    );
    assert_eq!(header(&head, "upgrade"), ["websocket"]);
    assert_eq!(header(&head, "sec-websocket-key"), [sample_nonce()]);
    assert_eq!(header(&head, "sec-websocket-version"), ["13"]);
    assert_eq!(header(&head, "authorization"), ["Bearer swapped"]);
    assert_eq!(
        header(&head, "host"),
        [format!("{OPENAI_HOST}:{}", address.port())]
    );

    let BrokerUpstreamUpgrade::Switched {
        headers,
        mut stream,
    } = upgraded
    else {
        panic!("a 101 is a switched connection");
    };
    assert_eq!(headers["upgrade"], "websocket");
    stream.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 10];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"helloworld");
}

#[tokio::test]
async fn any_other_status_is_an_ordinary_response() {
    let (address, _head) =
        provider(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 4\r\n\r\nnope").await;
    let target = url::Url::parse(&format!(
        "http://{OPENAI_HOST}:{}/v1/realtime",
        address.port()
    ))
    .unwrap();
    let response = send_upgrade(&client(address), &target, opening_headers())
        .await
        .unwrap();
    let BrokerUpstreamUpgrade::Response(response) = switched_or_response(response).await.unwrap()
    else {
        panic!("a 401 is not a switched connection");
    };
    let (status, _, mut body) = response.into_parts();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(bytes, b"nope");
}

#[tokio::test]
async fn an_upgrade_is_refused_before_any_connection_unless_a_get_to_a_selected_route() {
    let transport = ProviderHttpsTransport {
        client: client_builder(ConnectionReuse::PerRequest).build().unwrap(),
        upgrade_client: upgrade_client_builder().build().unwrap(),
        selected: BTreeSet::from([HttpProvider::OpenAiApiKey]),
        unresolved: BTreeSet::new(),
        log_hosts: BTreeSet::new(),
        resolved_address_count: 1,
        reuse: ConnectionReuse::PerRequest,
    };
    for (method, target, body, refused) in [
        (
            Method::POST,
            "https://api.openai.com/v1/realtime",
            Vec::new(),
            BrokerUpstreamError::DestinationDenied,
        ),
        (
            Method::GET,
            "https://chatgpt.com/backend-api/codex/responses",
            Vec::new(),
            BrokerUpstreamError::DestinationDenied,
        ),
        (
            Method::GET,
            "https://api.openai.com/v2/realtime",
            Vec::new(),
            BrokerUpstreamError::DestinationDenied,
        ),
        (
            Method::GET,
            "http://api.openai.com/v1/realtime",
            Vec::new(),
            BrokerUpstreamError::DestinationDenied,
        ),
        (
            Method::GET,
            "https://api.openai.com/v1/realtime",
            b"body".to_vec(),
            BrokerUpstreamError::Protocol,
        ),
    ] {
        let request = BrokerUpstreamRequest::new(
            method.clone(),
            url::Url::parse(target).unwrap(),
            opening_headers(),
            body,
        );
        assert_eq!(
            transport.upgrade(request).await.err(),
            Some(refused),
            "{method} {target}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_provider_that_never_answers_the_opening_request_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Accepts, then holds the connection without a response head.
    let _silent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop(stream);
    });
    let target = url::Url::parse(&format!(
        "http://{OPENAI_HOST}:{}/v1/realtime",
        address.port()
    ))
    .unwrap();
    let started = tokio::time::Instant::now();
    let result = send_upgrade(&client(address), &target, opening_headers()).await;
    assert!(matches!(result, Err(BrokerUpstreamError::Connect)));
    assert_eq!(started.elapsed(), UPGRADE_RESPONSE_TIMEOUT);
}

/// A transport whose upgrade client is `upgrade_client`, and whose buffered
/// client is never used.
fn transport_with(upgrade_client: reqwest::Client) -> ProviderHttpsTransport {
    ProviderHttpsTransport {
        client: upgrade_client_builder().build().unwrap(),
        upgrade_client,
        selected: BTreeSet::from([HttpProvider::OpenAiApiKey]),
        unresolved: BTreeSet::new(),
        log_hosts: BTreeSet::new(),
        resolved_address_count: 1,
        reuse: ConnectionReuse::PerRequest,
    }
}

fn opening_request(headers: HeaderMap) -> BrokerUpstreamRequest {
    BrokerUpstreamRequest::new(
        Method::GET,
        url::Url::parse(&format!("https://{OPENAI_HOST}/v1/realtime")).unwrap(),
        headers,
        Vec::new(),
    )
}

/// A TLS provider for `OPENAI_HOST` that answers a WebSocket opening request
/// with `101`, then echoes five bytes. The PKI must outlive the test.
async fn tls_websocket_provider() -> (codewire_tls::test_support::SyntheticPki, reqwest::Client) {
    use axum::extract::Request;
    use axum::response::Response;
    use hyper_util::rt::TokioIo;

    let pki = codewire_tls::test_support::SyntheticPki::new(OPENAI_HOST);
    let app = axum::Router::new().route(
        "/v1/realtime",
        axum::routing::get(|mut request: Request| async move {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let mut io = TokioIo::new(upgrade.await.unwrap());
                let mut echo = [0_u8; 5];
                io.read_exact(&mut echo).await.unwrap();
                io.write_all(&echo).await.unwrap();
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                .body(axum::body::Body::empty())
                .unwrap()
        }),
    );
    let address = pki.serve(app).await;
    let roots = std::fs::read(&pki.roots).unwrap();
    let client = upgrade_client_builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&roots).unwrap())
        .resolve(OPENAI_HOST, address)
        .build()
        .unwrap();
    (pki, client)
}

#[tokio::test]
async fn the_transport_upgrades_end_to_end_over_tls_to_the_pinned_address() {
    let (_pki, client) = tls_websocket_provider().await;
    let transport = transport_with(client);
    let BrokerUpstreamUpgrade::Switched {
        headers,
        mut stream,
    } = transport
        .upgrade(opening_request(opening_headers()))
        .await
        .unwrap()
    else {
        panic!("a 101 is a switched connection");
    };
    assert_eq!(
        headers["sec-websocket-accept"],
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
    stream.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 5];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");
}

#[tokio::test]
async fn an_opening_request_that_is_not_a_websocket_or_frames_itself_is_refused_before_connecting()
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let transport = transport_with(client(address));
    let mut h2c = opening_headers();
    h2c.insert("upgrade", HeaderValue::from_static("h2c"));
    let mut no_connection = opening_headers();
    no_connection.remove("connection");
    let mut twice = opening_headers();
    twice.append("upgrade", HeaderValue::from_static("websocket"));
    let mut refused = vec![h2c, no_connection, twice];
    for (name, value) in [
        ("host", "other.example"),
        ("content-length", "0"),
        ("transfer-encoding", "chunked"),
    ] {
        let mut headers = opening_headers();
        headers.insert(name, HeaderValue::from_static(value));
        refused.push(headers);
    }
    for headers in refused {
        assert_eq!(
            transport.upgrade(opening_request(headers)).await.err(),
            Some(BrokerUpstreamError::Protocol)
        );
    }
    let streamed =
        opening_request(opening_headers()).with_body_stream(Box::pin(futures::stream::empty()));
    assert_eq!(
        transport.upgrade(streamed).await.err(),
        Some(BrokerUpstreamError::Protocol)
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "nothing may connect"
    );
}

/// `reply` through the helpers, as `upgrade` sends them.
async fn answered(reply: &'static [u8]) -> Result<BrokerUpstreamUpgrade, BrokerUpstreamError> {
    let (address, _head) = provider(reply).await;
    let target = url::Url::parse(&format!(
        "http://{OPENAI_HOST}:{}/v1/realtime",
        address.port()
    ))
    .unwrap();
    let response = send_upgrade(&client(address), &target, opening_headers()).await?;
    switched_or_response(response).await
}

#[tokio::test]
async fn only_a_websocket_101_becomes_a_socket() {
    for reply in [
        &b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\n\r\n"[..],
        b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: h2c\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\r\n",
    ] {
        let reply: &'static [u8] = reply;
        assert!(matches!(
            answered(reply).await,
            Err(BrokerUpstreamError::Protocol)
        ));
    }
}

#[tokio::test]
async fn a_redirect_is_returned_not_followed() {
    let Ok(BrokerUpstreamUpgrade::Response(response)) = answered(
        b"HTTP/1.1 302 Found\r\nlocation: https://elsewhere.example/\r\ncontent-length: 0\r\n\r\n",
    )
    .await
    else {
        panic!("a redirect is an ordinary response");
    };
    assert_eq!(response.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn an_oversized_101_head_is_refused() {
    let filler = "a".repeat(16 * 1024);
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\
         x-a: {filler}\r\nx-b: {filler}\r\nx-c: {filler}\r\nx-d: {filler}\r\nx-e: {filler}\r\n\r\n"
    );
    let reply: &'static [u8] = Box::leak(reply.into_bytes().into_boxed_slice());
    assert!(matches!(
        answered(reply).await,
        Err(BrokerUpstreamError::ResourceLimit)
    ));
}

/// A transport that implements only `execute`.
struct RequestsOnly;

#[async_trait::async_trait]
impl BrokerUpstreamTransport for RequestsOnly {
    async fn execute(
        &self,
        _request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        Err(BrokerUpstreamError::Connect)
    }
}

#[tokio::test]
async fn a_transport_without_upgrades_and_a_missing_transport_refuse() {
    assert_eq!(
        RequestsOnly
            .upgrade(opening_request(opening_headers()))
            .await
            .err(),
        Some(BrokerUpstreamError::DestinationDenied)
    );
    assert_eq!(
        None::<RequestsOnly>
            .upgrade(opening_request(opening_headers()))
            .await
            .err(),
        Some(BrokerUpstreamError::DestinationDenied)
    );
}
