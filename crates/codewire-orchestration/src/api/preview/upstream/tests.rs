use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_daemon::execution::ProcessExecution;
use codewire_daemon::local_transport::{local_transport, with_local_connections};
use codewire_daemon::{Config, DaemonAuthToken, serve_grpc_with_incoming};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::Endpoint;

use super::*;

const TOKEN: &str = "synthetic-preview-upstream-daemon-token";
const NAMESPACE: &str = "sandboxes";
const ENVIRONMENT: &str = "0e3c1f2a-preview";

/// A real daemon over its in-process transport. Its workload loopback is
/// this host's, as a hosted daemon's is its Pod's.
async fn in_process_daemon(temp: &Path) -> SessionClient {
    let workspace_root = temp.join("workspace");
    let home_root = temp.join("home");
    std::fs::create_dir_all(&workspace_root).unwrap();
    std::fs::create_dir_all(&home_root).unwrap();
    let config = Config {
        listen_addr: "in-process".into(),
        workspace_root,
        home_root,
        mount_roots: Vec::new(),
        auth_token: DaemonAuthToken::new(TOKEN).unwrap(),
        process_execution: ProcessExecution::Native,
        credential_bridge: None,
        host: None,
        launch_projection: None,
        managed_credential_clients: Default::default(),
        session_working_dir: None,
    };
    let (connector, local) = local_transport();
    let network = tokio_stream::empty::<std::io::Result<TcpStream>>();
    tokio::spawn(async move {
        let _ = serve_grpc_with_incoming(
            config,
            with_local_connections(network, local),
            std::future::pending(),
        )
        .await;
    });
    let channel = Endpoint::from_static("http://codewire-daemon.local")
        .connect_with_connector(tower::service_fn(move |_| {
            let connector = connector.clone();
            async move { connector.connect().await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    SessionClient::from_channel(channel, TOKEN).unwrap()
}

/// An HTTP/1.1 server on `address` that answers every request with its
/// Host, X-Forwarded-Proto and path, and counts the connections it accepts.
async fn app(address: &str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(address).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                    let line = |name: &str| {
                        head.lines()
                            .find_map(|line| line.strip_prefix(name))
                            .unwrap_or("")
                            .trim()
                            .to_owned()
                    };
                    let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                    let body = format!("{path}|{}|{}", line("host:"), line("x-forwarded-proto:"));
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, connections)
}

async fn get(upstream: &PreviewUpstream, port: u16, path: &str) -> Result<String, UpstreamError> {
    let request = Request::get(PreviewUpstream::uri(NAMESPACE, ENVIRONMENT, port, path).unwrap())
        .header("host", "web-0e3c1-acme.preview.test")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let response = upstream.send(request).await?;
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Ok(String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn a_server_bound_only_to_loopback_answers_and_the_connection_is_reused() {
    let temp = tempfile::tempdir().unwrap();
    let upstream = PreviewUpstream::fixed(in_process_daemon(temp.path()).await);
    let (port, connections) = app("127.0.0.1:0").await;

    assert_eq!(
        get(&upstream, port, "/page?q=1").await.unwrap(),
        "/page?q=1|web-0e3c1-acme.preview.test|https"
    );
    assert_eq!(
        get(&upstream, port, "/asset.js").await.unwrap(),
        "/asset.js|web-0e3c1-acme.preview.test|https"
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the second request reused the pooled forward"
    );
}

#[tokio::test]
async fn a_server_on_every_address_still_answers() {
    let temp = tempfile::tempdir().unwrap();
    let upstream = PreviewUpstream::fixed(in_process_daemon(temp.path()).await);
    let (port, _) = app("0.0.0.0:0").await;
    assert!(get(&upstream, port, "/").await.unwrap().starts_with("/|"));
}

#[tokio::test]
async fn nothing_listening_is_named() {
    let temp = tempfile::tempdir().unwrap();
    let upstream = PreviewUpstream::fixed(in_process_daemon(temp.path()).await);
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    assert!(matches!(
        get(&upstream, port, "/").await,
        Err(UpstreamError::NothingListens(named)) if named == port
    ));
}

#[tokio::test]
async fn a_platform_listener_is_refused_with_the_daemons_reason() {
    let temp = tempfile::tempdir().unwrap();
    let upstream = PreviewUpstream::fixed(in_process_daemon(temp.path()).await);
    match get(&upstream, 2222, "/").await {
        Err(UpstreamError::Refused(reason)) => assert!(reason.contains("2222"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_daemon_that_forwards_is_recognised() {
    let temp = tempfile::tempdir().unwrap();
    let upstream = PreviewUpstream::fixed(in_process_daemon(temp.path()).await);
    assert!(upstream.forwards(NAMESPACE, ENVIRONMENT).await);
}

#[test]
fn upstream_uris_name_the_environment_namespace_and_port() {
    let uri = PreviewUpstream::uri(NAMESPACE, ENVIRONMENT, 3000, "/a?b=c").unwrap();
    assert_eq!(
        upstream_target(&uri).unwrap(),
        (ENVIRONMENT, NAMESPACE, 3000)
    );
    for invalid in [
        "http://example.com:3000/",
        "http://env.ns.extra.preview-upstream.invalid:3000/",
        "http://env.preview-upstream.invalid:3000/",
        "http://env.ns.preview-upstream.invalid/",
    ] {
        assert!(
            upstream_target(&invalid.parse().unwrap()).is_err(),
            "{invalid}"
        );
    }
}
