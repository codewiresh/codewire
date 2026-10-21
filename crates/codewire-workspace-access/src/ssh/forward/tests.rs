use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use russh::client;
use tokio::io::ReadBuf;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::super::{
    DaemonSessionStart, SshChannelOutput, SshSession, SshSessionRunner, SshSessionRunnerError,
    WorkspaceSshHandler, workspace_ssh_server_config,
};
use super::*;

const BOUND: Duration = Duration::from_secs(10);

/// Process sessions are not under test.
struct NoSessions;

#[async_trait]
impl SshSessionRunner for NoSessions {
    async fn start_session(
        &self,
        _key: SshSessionKey,
        _start: DaemonSessionStart,
        _output: SshChannelOutput,
    ) -> Result<Box<dyn SshSession>, SshSessionRunnerError> {
        Err(SshSessionRunnerError("no process sessions here".into()))
    }
}

struct AcceptAllKeys;

impl client::Handler for AcceptAllKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A workspace SSH server whose connections each get `forwarding()`.
async fn gateway(
    forwarding: impl Fn() -> Option<Forwarding> + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = workspace_ssh_server_config();
    config.keys.push(crate::host_key::generate_ed25519_key());
    let config = Arc::new(config);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            // As the daemon's listener does.
            stream.set_nodelay(true).unwrap();
            let handler = WorkspaceSshHandler::new(Arc::new(NoSessions));
            let handler = match forwarding() {
                Some(forwarding) => handler.with_forwarding(forwarding),
                None => handler,
            };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    (addr, task)
}

/// Forwarding through `dialer`, with no platform listeners: the test's own
/// ephemeral ports could be any port.
fn dialing(dialer: Arc<dyn ForwardDialer>) -> impl Fn() -> Option<Forwarding> + Send + 'static {
    dialing_except(dialer, PlatformListeners::new())
}

/// Forwarding through `dialer` that never reaches the `platform` listeners.
fn dialing_except(
    dialer: Arc<dyn ForwardDialer>,
    platform: PlatformListeners,
) -> impl Fn() -> Option<Forwarding> + Send + 'static {
    let platform = Arc::new(platform);
    move || Some(Forwarding::new(dialer.clone(), platform.clone()))
}

async fn connect(addr: SocketAddr) -> client::Handle<AcceptAllKeys> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).unwrap();
    let mut handle =
        client::connect_stream(Arc::new(client::Config::default()), stream, AcceptAllKeys)
            .await
            .unwrap();
    let auth = handle.authenticate_none("codewire").await.unwrap();
    assert!(matches!(auth, client::AuthResult::Success));
    handle
}

async fn open(
    client: &client::Handle<AcceptAllKeys>,
    host: &str,
    port: u16,
) -> Result<Channel<client::Msg>, russh::Error> {
    timeout(
        BOUND,
        client.channel_open_direct_tcpip(host, port.into(), "127.0.0.1", 40000),
    )
    .await
    .expect("the forward was answered")
}

fn open_failure_code(result: Result<Channel<client::Msg>, russh::Error>) -> u32 {
    match result {
        Err(russh::Error::ChannelOpenFailure(failure)) => failure.code(),
        Err(other) => panic!("expected an open failure, got {other}"),
        Ok(_) => panic!("expected an open failure, the channel opened"),
    }
}

/// Echoes each connection until its end of stream, then closes it.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    addr
}

/// The channel's data until its EOF.
async fn read_to_eof(read: &mut russh::ChannelReadHalf) -> Vec<u8> {
    let mut received = Vec::new();
    timeout(BOUND, async {
        loop {
            match read.wait().await {
                Some(ChannelMsg::Data { data }) => received.extend_from_slice(&data),
                Some(ChannelMsg::Eof) => return,
                Some(ChannelMsg::Close) | None => panic!("closed before EOF"),
                Some(_) => {}
            }
        }
    })
    .await
    .expect("the target's end of stream reached the client");
    received
}

/// Wait until the server closes the channel. (A russh client that closes
/// first drops the server's reply, so this is only for a server's close.)
async fn closed_by_server(read: &mut russh::ChannelReadHalf) {
    timeout(BOUND, async {
        loop {
            match read.wait().await {
                Some(ChannelMsg::Close) | None => return,
                Some(_) => {}
            }
        }
    })
    .await
    .expect("the server closed the channel");
}

async fn eventually(what: &str, done: impl Fn() -> bool) {
    timeout(BOUND, async {
        while !done() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// The real loopback dialer, counting its dials and the connections still
/// held: each forward's one descriptor.
#[derive(Default)]
struct CountingDialer {
    dials: AtomicUsize,
    live: Arc<AtomicUsize>,
}

struct Counted {
    stream: Box<dyn ForwardIo>,
    live: Arc<AtomicUsize>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[async_trait]
impl ForwardDialer for CountingDialer {
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let stream = WorkloadLoopbackDialer.dial(target).await?;
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Counted {
            stream,
            live: self.live.clone(),
        }))
    }
}

/// Records every target it is asked to dial and dials none.
#[derive(Default)]
struct RecordingDialer {
    targets: Mutex<Vec<ForwardTarget>>,
}

#[async_trait]
impl ForwardDialer for RecordingDialer {
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        self.targets.lock().unwrap().push(target.clone());
        Err(ForwardDialError::ConnectFailed("recorded only".into()))
    }
}

/// Hosts a forward must never reach: the node and other Pods (private and
/// link-local ranges, Service names), metadata services, and spellings that
/// only look like loopback.
const OUTSIDE: &[&str] = &[
    "10.0.0.1",
    "10.96.0.1",
    "172.17.0.1",
    "192.168.1.1",
    "100.64.0.1",
    "169.254.169.254",
    "fd00:ec2::254",
    "fe80::1",
    "8.8.8.8",
    "::ffff:169.254.169.254",
    "::ffff:127.0.0.1",
    "metadata.google.internal",
    "kubernetes.default.svc",
    "codewire.dev",
    "localhost.",
    "localhost.codewire.dev",
    "127.0.0.1.nip.io",
    "2130706433",
    "0x7f000001",
    "127.1",
    "[::1]",
    "127.0.0.1:22",
];

#[test]
fn forward_targets_are_only_the_workloads_own_loopback() {
    let v4 = |port| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let v6 = |port| SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);
    for (host, addrs) in [
        ("localhost", vec![v4(8080), v6(8080)]),
        ("LocalHost", vec![v4(8080), v6(8080)]),
        ("", vec![v4(8080), v6(8080)]),
        ("127.0.0.1", vec![v4(8080)]),
        (
            "127.3.2.1",
            vec![SocketAddr::new(Ipv4Addr::new(127, 3, 2, 1).into(), 8080)],
        ),
        ("0.0.0.0", vec![v4(8080)]),
        ("::1", vec![v6(8080)]),
        ("::", vec![v6(8080)]),
    ] {
        let target = ForwardTarget::local(host, 8080, &PlatformListeners::new())
            .unwrap_or_else(|refusal| panic!("{host:?} refused: {refusal}"));
        assert_eq!(target.addrs(), addrs, "{host:?}");
        assert!(target.addrs().iter().all(|addr| addr.ip().is_loopback()));
    }
    assert_eq!(
        ForwardTarget::local("::1", 22, &PlatformListeners::new())
            .unwrap()
            .to_string(),
        "[::1]:22"
    );

    for host in OUTSIDE {
        let refusal = ForwardTarget::local(host, 8080, &PlatformListeners::new()).unwrap_err();
        assert!(
            refusal.0.contains("only this environment's own loopback"),
            "{host:?}: {refusal}"
        );
    }
    for port in [0, 65536, u32::MAX] {
        let refusal =
            ForwardTarget::local("127.0.0.1", port, &PlatformListeners::new()).unwrap_err();
        assert_eq!(refusal.0, format!("{port} is not a TCP port"));
    }
}

#[test]
fn platform_listeners_are_refused_however_loopback_is_spelled() {
    // The listeners the hosted daemon refuses: the credential bridge, its SSH
    // server and its own gRPC port (#3068).
    let platform = codewire_daemon_proto::platform_listeners(Some(7777));
    assert!(platform.contains_key(&codewire_daemon_proto::CREDENTIAL_BRIDGE_LOOPBACK_PORT));
    for (port, listener) in &platform {
        for host in [
            "localhost",
            "",
            "127.0.0.1",
            "127.3.2.1",
            "0.0.0.0",
            "::1",
            "::",
        ] {
            let refusal = ForwardTarget::local(host, (*port).into(), &platform).unwrap_err();
            assert_eq!(
                refusal.0,
                format!(
                    "port {port} is {listener}, which belongs to the platform; port forwarding \
                     cannot reach it"
                ),
                "{host:?}"
            );
        }
    }
    // A user's own server on loopback still forwards.
    assert!(ForwardTarget::local("localhost", 8080, &platform).is_ok());
}

#[tokio::test]
async fn a_platform_listener_is_refused_and_user_ports_still_forward() {
    // A live listener standing in for the credential bridge.
    let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_port = bridge.local_addr().unwrap().port();
    let echo = echo_server().await;
    let platform = PlatformListeners::from([(bridge_port, "the credential bridge")]);
    let (addr, _gateway) =
        gateway(dialing_except(Arc::new(WorkloadLoopbackDialer), platform)).await;
    let client = connect(addr).await;
    for host in ["127.0.0.1", "localhost", "0.0.0.0", "::1"] {
        assert_eq!(
            open_failure_code(open(&client, host, bridge_port).await),
            1,
            "{host}"
        );
    }
    assert!(
        timeout(Duration::from_millis(300), bridge.accept())
            .await
            .is_err(),
        "a forward reached the platform listener"
    );
    let (mut read, write) = open(&client, "localhost", echo.port())
        .await
        .unwrap()
        .split();
    write.data_bytes(b"user port".to_vec()).await.unwrap();
    write.eof().await.unwrap();
    assert_eq!(read_to_eof(&mut read).await, b"user port");
}

#[tokio::test]
async fn an_accepted_forward_carries_bytes_both_ways() {
    let echo = echo_server().await;
    let dialer = Arc::new(CountingDialer::default());
    let (addr, _gateway) = gateway(dialing(dialer.clone())).await;
    let client = connect(addr).await;

    for host in ["127.0.0.1", "localhost"] {
        let (mut read, write) = open(&client, host, echo.port()).await.unwrap().split();
        // More than one window each way, written while the echo comes back.
        let sent: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let writer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                for chunk in sent.chunks(64 * 1024) {
                    write.data_bytes(chunk.to_vec()).await.unwrap();
                }
                // The target sees the end of stream, echoes the rest and closes.
                write.eof().await.unwrap();
                write
            })
        };
        let received = read_to_eof(&mut read).await;
        assert!(
            received == sent,
            "{host}: the echo differs from what was sent"
        );
        let write = writer.await.unwrap();
        // Both sides are done; the client closes, as OpenSSH does, and the
        // forward ends.
        write.close().await.unwrap();
        eventually("the forward released its connection", || {
            dialer.live.load(Ordering::SeqCst) == 0
        })
        .await;
    }
}

#[tokio::test]
async fn refused_forwards_get_an_open_failure_naming_the_reason() {
    let recording = Arc::new(RecordingDialer::default());
    let (addr, _gateway) = gateway(dialing(recording.clone())).await;
    let client = connect(addr).await;
    // A target outside the workload: refused before any dial.
    assert_eq!(open_failure_code(open(&client, "10.0.0.1", 80).await), 1);
    // A dial that fails: connect failed.
    assert_eq!(open_failure_code(open(&client, "127.0.0.1", 80).await), 2);
    assert_eq!(recording.targets.lock().unwrap().len(), 1);

    // Nothing listening, through the real dialer.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let (addr, _gateway) = gateway(dialing(Arc::new(WorkloadLoopbackDialer))).await;
    let client = connect(addr).await;
    assert_eq!(
        open_failure_code(open(&client, "127.0.0.1", closed_port).await),
        2
    );
    let error = WorkloadLoopbackDialer
        .dial(
            &ForwardTarget::local("127.0.0.1", closed_port.into(), &PlatformListeners::new())
                .unwrap(),
        )
        .await
        .err()
        .expect("nothing listens");
    assert!(
        error.to_string().starts_with(&format!(
            "nothing in the environment accepted a connection to 127.0.0.1:{closed_port}"
        )),
        "{error}"
    );

    // A server without a dialer refuses every forward.
    let (addr, _gateway) = gateway(|| None).await;
    let client = connect(addr).await;
    assert_eq!(open_failure_code(open(&client, "127.0.0.1", 80).await), 1);
}

/// No forward reaches past the workload's loopback: not a listener on this
/// host's other addresses, not the metadata service, not a Service name.
#[tokio::test]
async fn forwards_never_leave_the_workloads_network_namespace() {
    let recording = Arc::new(RecordingDialer::default());
    let (addr, _gateway) = gateway(dialing(recording.clone())).await;
    let client = connect(addr).await;
    for host in OUTSIDE {
        assert_eq!(
            open_failure_code(open(&client, host, 8080).await),
            1,
            "{host:?}"
        );
    }
    assert!(recording.targets.lock().unwrap().is_empty());

    // A listener on every address of this host, reached through one of its
    // non-loopback addresses (the node, as a Pod sees it): refused, and
    // never connected, even through the real dialer.
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let outside_ip = probe
        .connect("192.0.2.1:9")
        .ok()
        .and_then(|()| probe.local_addr().ok())
        .map(|addr| addr.ip())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified());
    let (addr, _gateway) = gateway(dialing(Arc::new(WorkloadLoopbackDialer))).await;
    let client = connect(addr).await;
    if let Some(ip) = outside_ip {
        assert_eq!(
            open_failure_code(open(&client, &ip.to_string(), port).await),
            1,
            "{ip}"
        );
    }
    assert!(
        timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "a forward connected outside the loopback"
    );
    // The same listener through loopback is the workload's own.
    let channel = open(&client, "127.0.0.1", port).await.unwrap();
    timeout(BOUND, listener.accept())
        .await
        .expect("the loopback forward connected")
        .unwrap();
    drop(channel);
}

#[tokio::test]
async fn the_target_closing_ends_the_channel() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let dialer = Arc::new(CountingDialer::default());
    let (addr, _gateway) = gateway(dialing(dialer.clone())).await;
    let client = connect(addr).await;

    let (mut read, write) = open(&client, "127.0.0.1", port).await.unwrap().split();
    let (mut accepted, _) = target.accept().await.unwrap();
    accepted.write_all(b"goodbye").await.unwrap();
    drop(accepted);
    assert_eq!(read_to_eof(&mut read).await, b"goodbye");
    // The client finishes too and closes the channel.
    write.eof().await.unwrap();
    write.close().await.unwrap();
    eventually("the forward released its connection", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;
}

#[tokio::test]
async fn a_finished_forward_the_client_leaves_open_is_closed_by_the_server() {
    let echo = echo_server().await;
    let (addr, _gateway) = gateway(|| {
        Some(
            Forwarding::new(Arc::new(WorkloadLoopbackDialer), Arc::default())
                .with_close_grace(Duration::from_millis(100)),
        )
    })
    .await;
    let client = connect(addr).await;
    let (mut read, write) = open(&client, "127.0.0.1", echo.port())
        .await
        .unwrap()
        .split();
    write.data_bytes(b"ping".to_vec()).await.unwrap();
    write.eof().await.unwrap();
    assert_eq!(read_to_eof(&mut read).await, b"ping");
    // The client never closes; the server does.
    closed_by_server(&mut read).await;
}

#[tokio::test]
async fn the_client_closing_ends_the_forward() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let dialer = Arc::new(CountingDialer::default());
    let (addr, _gateway) = gateway(dialing(dialer.clone())).await;
    let client = connect(addr).await;

    // Half-close: the client's EOF reaches the target, which can still
    // answer.
    let (mut read, write) = open(&client, "127.0.0.1", port).await.unwrap().split();
    let (mut accepted, _) = target.accept().await.unwrap();
    write.data_bytes(b"request".to_vec()).await.unwrap();
    write.eof().await.unwrap();
    let mut request = Vec::new();
    timeout(BOUND, accepted.read_to_end(&mut request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request, b"request");
    accepted.write_all(b"answer").await.unwrap();
    accepted.shutdown().await.unwrap();
    assert_eq!(read_to_eof(&mut read).await, b"answer");
    write.close().await.unwrap();
    eventually("the answered forward released its connection", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;

    // A client that closes without EOF, while the target is silent: the
    // target sees the end of stream and the forward ends.
    let channel = open(&client, "127.0.0.1", port).await.unwrap();
    let (mut accepted, _) = target.accept().await.unwrap();
    channel.close().await.unwrap();
    let mut rest = Vec::new();
    timeout(BOUND, accepted.read_to_end(&mut rest))
        .await
        .expect("the target saw the forward end")
        .unwrap();
    eventually("the forward released its connection", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;
}

/// Dials loopback with the smallest socket buffers, so a target that does
/// not read blocks the forward's writes almost at once.
struct TinyBufferDialer {
    live: Arc<AtomicUsize>,
}

#[async_trait]
impl ForwardDialer for TinyBufferDialer {
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        let stream = socket
            .connect(target.addrs()[0])
            .await
            .map_err(|error| ForwardDialError::ConnectFailed(error.to_string()))?;
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Counted {
            stream: Box::new(stream),
            live: self.live.clone(),
        }))
    }
}

#[tokio::test]
async fn closing_a_channel_whose_target_is_not_reading_ends_the_forward() {
    let target = tokio::net::TcpSocket::new_v4().unwrap();
    target.set_recv_buffer_size(4096).unwrap();
    target.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let target = target.listen(1).unwrap();
    let port = target.local_addr().unwrap().port();
    let live = Arc::new(AtomicUsize::new(0));
    let dialer = Arc::new(TinyBufferDialer { live: live.clone() });
    let (addr, _gateway) = gateway(dialing(dialer)).await;
    let client = connect(addr).await;

    let channel = open(&client, "127.0.0.1", port).await.unwrap();
    let (_accepted, _) = target.accept().await.unwrap();
    // Far more than the sockets hold, and fewer messages than russh queues
    // per channel, so the close still reaches the server.
    channel.data_bytes(vec![7u8; 1024 * 1024]).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    channel.close().await.unwrap();
    eventually("the blocked forward ended", || {
        live.load(Ordering::SeqCst) == 0
    })
    .await;

    // The connection still serves forwards.
    let echo = echo_server().await;
    let (mut read, write) = open(&client, "127.0.0.1", echo.port())
        .await
        .unwrap()
        .split();
    write.data_bytes(b"still served".to_vec()).await.unwrap();
    write.eof().await.unwrap();
    assert_eq!(read_to_eof(&mut read).await, b"still served");
}

#[tokio::test]
async fn the_connection_ending_ends_its_forwards() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let dialer = Arc::new(CountingDialer::default());
    let (addr, _gateway) = gateway(dialing(dialer.clone())).await;
    let client = connect(addr).await;
    let _channel = open(&client, "127.0.0.1", port).await.unwrap();
    let (mut accepted, _) = target.accept().await.unwrap();
    client
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    let mut rest = Vec::new();
    timeout(BOUND, accepted.read_to_end(&mut rest))
        .await
        .expect("the target saw the forward end")
        .unwrap();
    eventually("the forward released its connection", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;
}

#[tokio::test]
async fn forwards_beyond_the_connection_limit_are_refused_until_one_ends() {
    let echo = echo_server().await;
    let (addr, _gateway) = gateway(|| {
        let mut forwarding = Forwarding::new(Arc::new(WorkloadLoopbackDialer), Arc::default());
        forwarding.slots = Arc::new(Semaphore::new(2));
        Some(forwarding)
    })
    .await;
    let client = connect(addr).await;
    let first = open(&client, "127.0.0.1", echo.port()).await.unwrap();
    let _second = open(&client, "127.0.0.1", echo.port()).await.unwrap();
    assert_eq!(
        open_failure_code(open(&client, "127.0.0.1", echo.port()).await),
        4
    );
    first.close().await.unwrap();
    timeout(BOUND, async {
        loop {
            if open(&client, "127.0.0.1", echo.port()).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a slot came back when a forward ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_sequential_forwards_leave_no_tasks_or_connections() {
    let echo = echo_server().await;
    let dialer = Arc::new(CountingDialer::default());
    let (addr, _gateway) = gateway(dialing(dialer.clone())).await;
    let client = connect(addr).await;
    let metrics = tokio::runtime::Handle::current().metrics();

    let round_trip = |round: usize| {
        let client = &client;
        async move {
            let (mut read, write) = open(client, "localhost", echo.port())
                .await
                .unwrap()
                .split();
            let message = format!("round {round}").into_bytes();
            write.data_bytes(message.clone()).await.unwrap();
            write.eof().await.unwrap();
            assert_eq!(read_to_eof(&mut read).await, message);
            write.close().await.unwrap();
        }
    };
    round_trip(0).await;
    eventually("the first forward ended", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;
    let tasks = metrics.num_alive_tasks();

    for round in 1..=300 {
        round_trip(round).await;
    }
    assert_eq!(dialer.dials.load(Ordering::SeqCst), 301);
    eventually("every forward released its connection", || {
        dialer.live.load(Ordering::SeqCst) == 0
    })
    .await;
    eventually("every forward's task ended", || {
        metrics.num_alive_tasks() <= tasks
    })
    .await;
}

/// The host's OpenSSH client, as `cw setup ssh`'s users and VS Code run it.
#[cfg(target_os = "linux")]
fn openssh(gateway: SocketAddr) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("/usr/bin/ssh");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", std::env::temp_dir())
        .args(["-F", "/dev/null", "-o", "BatchMode=yes"])
        .args(["-o", "PreferredAuthentications=none"])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .arg("-p")
        .arg(gateway.port().to_string())
        .kill_on_drop(true);
    command
}

#[cfg(target_os = "linux")]
async fn openssh_stdio_forward(
    gateway: SocketAddr,
    target: &str,
    input: &[u8],
) -> std::process::Output {
    let mut child = openssh(gateway)
        .arg("-W")
        .arg(target)
        .arg("codewire@127.0.0.1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn OpenSSH");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    drop(stdin);
    timeout(BOUND, child.wait_with_output())
        .await
        .expect("OpenSSH finished")
        .unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn openssh_stdio_forwards_and_prints_the_refusal_reason() {
    let echo = echo_server().await;
    let (addr, _gateway) = gateway(dialing(Arc::new(WorkloadLoopbackDialer))).await;

    let output =
        openssh_stdio_forward(addr, &format!("127.0.0.1:{}", echo.port()), b"over -W\n").await;
    assert!(
        output.status.success(),
        "ssh -W failed: {:?}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"over -W\n");

    let output = openssh_stdio_forward(addr, "169.254.169.254:80", b"").await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("administratively prohibited: port forwarding reaches only this environment's own loopback"),
        "{stderr}"
    );

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let output = openssh_stdio_forward(addr, &format!("127.0.0.1:{closed_port}"), b"").await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("connect failed: nothing in the environment accepted a connection"),
        "{stderr}"
    );
}

/// A SOCKS5 CONNECT to `host:port` through OpenSSH's dynamic forward at
/// `proxy`, naming the host as VS Code does: the open stream, or `None` when
/// the proxy ends the connection instead of answering success (OpenSSH
/// answers once its channel opens).
#[cfg(target_os = "linux")]
async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> Option<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "no-authentication SOCKS5");
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    // VER REP RSV ATYP (IPv4) ADDR PORT.
    let mut reply = [0u8; 10];
    match timeout(BOUND, stream.read_exact(&mut reply))
        .await
        .expect("the SOCKS5 CONNECT was answered")
    {
        Ok(_) if reply[..2] == [5, 0] => Some(stream),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn openssh_dynamic_forward_refuses_platform_listeners_and_reaches_user_ports() {
    let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_port = bridge.local_addr().unwrap().port();
    let echo = echo_server().await;
    let platform = PlatformListeners::from([(bridge_port, "the credential bridge")]);
    let (addr, _gateway) =
        gateway(dialing_except(Arc::new(WorkloadLoopbackDialer), platform)).await;
    let socks = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let ssh = openssh(addr)
        .args(["-N", "-D"])
        .arg(socks.to_string())
        .arg("codewire@127.0.0.1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn OpenSSH");
    timeout(BOUND, async {
        while tokio::net::TcpStream::connect(socks).await.is_err() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("ssh -D listens");

    // A user's server, named localhost as VS Code names its server.
    let mut user = socks5_connect(socks, "localhost", echo.port())
        .await
        .expect("SOCKS reaches the user's server");
    user.write_all(b"through socks").await.unwrap();
    user.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    timeout(BOUND, user.read_to_end(&mut echoed))
        .await
        .expect("the echo ended")
        .unwrap();
    assert_eq!(echoed, b"through socks");

    // The platform listener: SOCKS ends the connection without success.
    assert!(
        socks5_connect(socks, "localhost", bridge_port)
            .await
            .is_none()
    );
    assert!(
        timeout(Duration::from_millis(300), bridge.accept())
            .await
            .is_err(),
        "a forward reached the platform listener"
    );

    let mut ssh = ssh;
    ssh.start_kill().unwrap();
    let output = timeout(BOUND, ssh.wait_with_output())
        .await
        .expect("OpenSSH ended")
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "administratively prohibited: port {bridge_port} is the credential bridge, which \
             belongs to the platform"
        )),
        "{stderr}"
    );
}
