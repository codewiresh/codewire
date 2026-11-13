use std::path::Path;

use codewire_daemon::execution::ProcessExecution;
use codewire_daemon::local_transport::{local_transport, with_local_connections};
use codewire_daemon::{Config, serve_grpc_with_incoming};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tonic::Status;

use super::*;

const TOKEN: &str = "synthetic-guest-loopback-daemon-token";

/// A real daemon, reached only over its in-process transport, as a local VM's
/// daemon is reached over hybrid vsock. Its workload loopback is this host's.
pub(crate) async fn in_process_daemon(temp: &Path) -> DaemonSessionClient {
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
    DaemonSessionClient::connect_local(connector, DaemonAuthToken::new(TOKEN).unwrap())
        .await
        .unwrap()
}

/// Opens `guest_port` and checks one echoed exchange with `server`.
async fn reaches(client: &DaemonSessionClient, server: TcpListener) {
    let guest_port = server.local_addr().unwrap().port();
    let served = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.unwrap();
        stream.write_all(&buffer).await.unwrap();
    });
    let mut stream = open_guest_loopback(client, guest_port).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    served.await.unwrap();
}

#[tokio::test]
async fn a_server_bound_only_to_loopback_is_reached() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    reaches(&client, server).await;
}

#[tokio::test]
async fn a_server_on_every_address_is_reached_on_loopback() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    let server = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    reaches(&client, server).await;
}

#[tokio::test]
async fn a_server_bound_only_to_ipv6_loopback_is_reached() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    let Ok(server) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await else {
        return; // This host has no IPv6 loopback.
    };
    reaches(&client, server).await;
}

#[tokio::test]
async fn a_port_nothing_listens_on_is_named_as_such() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let guest_port = unused.local_addr().unwrap().port();
    drop(unused);
    let error = open_guest_loopback(&client, guest_port).await.unwrap_err();
    assert_eq!(error, GuestLoopbackError::NothingListens(guest_port));
    assert_eq!(
        error.to_string(),
        format!(
            "nothing in the environment listens on 127.0.0.1:{guest_port} or [::1]:{guest_port}"
        )
    );
}

#[tokio::test]
async fn a_platform_listener_is_refused_with_the_daemons_reason() {
    let temp = tempfile::tempdir().unwrap();
    let client = in_process_daemon(temp.path()).await;
    for (port, _) in codewire_daemon_proto::platform_listeners(None) {
        match open_guest_loopback(&client, port).await {
            Err(GuestLoopbackError::Refused(reason)) => assert!(!reason.is_empty(), "{port}"),
            other => panic!("{port}: {other:?}"),
        }
    }
}

#[test]
fn a_daemon_without_forwarding_is_refused_rather_than_read_as_nothing_listening() {
    assert_eq!(
        failure(
            DaemonClientError::Status(Status::unimplemented("unknown method")),
            3_000
        ),
        GuestLoopbackError::Refused(
            "this local VM's runtime predates port forwarding; stop and start it to use it".into()
        )
    );
    assert_eq!(
        failure(
            DaemonClientError::Status(Status::permission_denied("a platform listener")),
            3_000
        ),
        GuestLoopbackError::Refused("a platform listener".into())
    );
    assert_eq!(
        failure(
            DaemonClientError::Status(Status::unavailable("connection refused")),
            3_000
        ),
        GuestLoopbackError::NothingListens(3_000)
    );
}
