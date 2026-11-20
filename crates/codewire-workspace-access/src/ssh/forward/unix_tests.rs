//! Unix-socket forwards (`direct-streamlocal@openssh.com`, #5608) through
//! the SSH handler, from russh's client and from OpenSSH.

use std::path::PathBuf;

use russh::client;
use tokio::net::UnixListener;

use super::tests::{HANG_GUARD, connect, gateway, open, open_failure_code, openssh};
use super::*;

/// Echoes each connection on a socket in `directory` until its end of
/// stream, then closes it.
fn unix_echo_server(directory: &Path) -> PathBuf {
    let path = directory.join("echo.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    path
}

async fn open_unix(
    client: &client::Handle<super::tests::AcceptAllKeys>,
    path: &str,
) -> Result<Channel<client::Msg>, russh::Error> {
    tokio::time::timeout(HANG_GUARD, client.channel_open_direct_streamlocal(path))
        .await
        .expect("the forward was answered")
}

fn forwarding(dialer: Arc<dyn ForwardDialer>) -> impl Fn() -> Option<Forwarding> + Send + 'static {
    move || Some(Forwarding::new(dialer.clone(), Arc::default()))
}

/// A dialer that forwards TCP only, as a local VM's supervisor does with a
/// runtime that predates `ForwardUnix`.
struct TcpOnly;

#[async_trait]
impl ForwardDialer for TcpOnly {
    async fn dial(&self, _target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        Err(ForwardDialError::ConnectFailed("not under test".to_owned()))
    }
}

#[tokio::test]
async fn relative_abstract_and_long_targets_are_refused_before_any_dial() {
    let (addr, _gateway) = gateway(forwarding(Arc::new(TcpOnly))).await;
    let client = connect(addr).await;
    let long = format!("/{}", "x".repeat(200));
    for target in ["echo.sock", "./echo.sock", "@abstract", "", long.as_str()] {
        let refused = open_unix(&client, target).await;
        // Administratively prohibited, from the shape check, not the dialer.
        assert_eq!(open_failure_code(refused), 1, "{target:?}");
    }
}

#[tokio::test]
async fn a_runtime_without_unix_forwarding_refuses_with_a_reason() {
    let (addr, _gateway) = gateway(forwarding(Arc::new(TcpOnly))).await;
    let client = connect(addr).await;
    match open_unix(&client, "/home/codewire/rex.sock").await {
        Err(russh::Error::ChannelOpenFailure(failure)) => assert_eq!(failure.code(), 1),
        other => panic!("expected a refusal, got {:?}", other.map(|_| "a channel")),
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tcp_and_unix_forwards_share_the_connection_limit() {
    let directory = tempfile::tempdir().unwrap();
    let echo = unix_echo_server(directory.path());
    let tcp = super::tests::echo_server().await;
    let (addr, _gateway) = gateway(|| {
        let mut forwarding = Forwarding::new(Arc::new(WorkloadLoopbackDialer), Arc::default());
        forwarding.slots = Arc::new(Semaphore::new(2));
        Some(forwarding)
    })
    .await;
    let client = connect(addr).await;
    let _unix = open_unix(&client, echo.to_str().unwrap()).await.unwrap();
    let _tcp = open(&client, "127.0.0.1", tcp.port()).await.unwrap();
    // The third, of either kind, is refused for resource shortage.
    assert_eq!(
        open_failure_code(open_unix(&client, echo.to_str().unwrap()).await),
        4
    );
    assert_eq!(
        open_failure_code(open(&client, "127.0.0.1", tcp.port()).await),
        4
    );
}

#[cfg(target_os = "linux")]
async fn openssh_socket_forward(
    gateway: SocketAddr,
    target: &Path,
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
    tokio::time::timeout(HANG_GUARD, child.wait_with_output())
        .await
        .expect("OpenSSH finished")
        .unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn openssh_reaches_a_users_socket_and_prints_each_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let echo = unix_echo_server(directory.path());
    let (addr, _gateway) = gateway(forwarding(Arc::new(WorkloadLoopbackDialer))).await;

    let output = openssh_socket_forward(addr, &echo, b"over a socket\n").await;
    assert!(
        output.status.success(),
        "ssh -W failed: {:?}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"over a socket\n");

    // A platform socket, by its own name and by a hard link to it.
    let platform = directory.path().join("platform.sock");
    let (_listener, _record) =
        codewire_daemon::platform_sockets::bind(&platform, "the test's platform socket").unwrap();
    let hard = directory.path().join("hard.sock");
    std::fs::hard_link(&platform, &hard).unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"").unwrap();
    for (target, reason) in [
        (&platform, "administratively prohibited: \""),
        (&hard, "administratively prohibited: \""),
        (&file, "administratively prohibited: \""),
        (
            &directory.path().join("missing.sock"),
            "connect failed: nothing in the environment is at",
        ),
    ] {
        let output = openssh_socket_forward(addr, target, b"").await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{target:?} opened");
        assert!(stderr.contains(reason), "{target:?}: {stderr}");
    }
    let output = openssh_socket_forward(addr, &hard, b"").await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is the test's platform socket, which belongs to the platform"),
        "{stderr}"
    );
}
