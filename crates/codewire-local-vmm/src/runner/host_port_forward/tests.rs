use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;
use crate::guest_loopback::tests::in_process_daemon;

/// A forward that should end; a regression fails here instead of hanging.
const HANG_GUARD: Duration = Duration::from_secs(10);

/// The two ends of one accepted host connection: what the runner forwards and
/// what the host's client holds.
async fn host_connection() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    (accepted, client)
}

#[tokio::test]
async fn a_host_connection_is_carried_to_a_loopback_only_server_and_ends_with_it() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let guest_port = server.local_addr().unwrap().port();
    let (accepted, mut host) = host_connection().await;
    let forward = tokio::spawn(async move { carry(&client, accepted, guest_port).await });
    let (mut served, _) = server.accept().await.unwrap();
    host.write_all(b"ping").await.unwrap();
    let mut buffer = [0_u8; 4];
    served.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"ping");
    served.write_all(b"pong").await.unwrap();
    host.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"pong");
    // A forward ends once both sides have closed, as the TCP connection does.
    drop(host);
    drop(served);
    let ended = tokio::time::timeout(HANG_GUARD, forward)
        .await
        .expect("the forward did not end after both sides closed");
    assert_eq!(ended.unwrap(), Ok(()));
}

#[tokio::test]
async fn a_host_connection_with_nothing_listening_is_closed() {
    let temp = tempfile::tempdir().unwrap();
    let forwarder = HostPortForwarder::connected(in_process_daemon(temp.path()).await);
    let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let guest_port = unused.local_addr().unwrap().port();
    drop(unused);
    let (accepted, mut host) = host_connection().await;
    let mut tasks = JoinSet::new();
    forwarder.forward(
        AcceptedHostPort {
            binding: crate::host_port::HostPortBinding::new(18_080, guest_port).unwrap(),
            stream: accepted,
        },
        &mut tasks,
    );
    tokio::time::timeout(HANG_GUARD, tasks.join_next())
        .await
        .expect("the refused forward did not end")
        .unwrap()
        .unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(host.read(&mut byte).await.unwrap(), 0);
}
