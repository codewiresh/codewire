use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::ssh::{SshOperation, agent};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::credential_bridge::ingress_tests::LOOPBACK_TEST;
use crate::credential_bridge::{
    CredentialBridgeOutput, HostedIngressDrain, serve_ingress_listeners,
};
use crate::{Config, CredentialBridgeTransport};

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(3), future)
        .await
        .expect("bounded synthetic SSH ingress")
}

fn config(path: PathBuf, transport: CredentialBridgeTransport) -> CredentialBridgeConfig {
    CredentialBridgeConfig {
        transport,
        environment_id: uuid::Uuid::new_v4(),
        environment_generation: 7,
        ingress_socket: path,
        ingress_uid: unsafe { libc::geteuid() },
        ingress_gid: unsafe { libc::getegid() },
    }
}

fn daemon_config(root: &Path) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".into(),
        workspace_root: root.into(),
        home_root: root.into(),
        mount_roots: Vec::new(),
        auth_token: codewire_daemon_proto::DaemonAuthToken::new("synthetic-ssh-daemon-token")
            .unwrap(),
        process_execution: crate::execution::ProcessExecution::Native,
        credential_bridge: Some(config(
            root.join("credential.sock"),
            CredentialBridgeTransport::Local,
        )),
        managed_credential_clients: codewire_access::ManagedCredentialClients::from_profile_slots(
            ["ssh"],
        )
        .unwrap(),
        host: None,
        launch_projection: Some(crate::LaunchProjectionConfig {
            selection_sha256: [1; 32],
            native: None,
        }),
        session_working_dir: None,
    }
}

struct Harness {
    root: tempfile::TempDir,
    bridge: CredentialBridge,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    permits: Arc<Semaphore>,
}

impl Harness {
    fn new(transport: CredentialBridgeTransport, wrong_uid: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path().join("credential.sock"), transport);
        let bridge = CredentialBridge::new(Some(config));
        let mut ingress = bridge.prepare_ingress(true).unwrap().unwrap();
        let ssh = ingress.ssh.as_mut().unwrap();
        if wrong_uid {
            ssh.uid = ssh.uid.wrapping_add(1);
        }
        let permits = ssh.permits.clone();
        let stop = CancellationToken::new();
        let task = tokio::spawn(ingress.serve(stop.clone().cancelled_owned()));
        Self {
            root,
            bridge,
            stop,
            task: Some(task),
            permits,
        }
    }

    fn ssh_path(&self) -> PathBuf {
        self.root.path().join(SOCKET_NAME)
    }
    fn http_path(&self) -> &Path {
        &self.bridge.config.as_ref().unwrap().ingress_socket
    }

    async fn connect(&self) -> UnixStream {
        UnixStream::connect(self.ssh_path()).await.unwrap()
    }

    async fn host(
        &self,
    ) -> (
        mpsc::Sender<Result<v1::CredentialBridgeHostMessage, tonic::Status>>,
        CredentialBridgeOutput,
    ) {
        let config = self.bridge.config.as_ref().unwrap();
        let (sender, receiver) = mpsc::channel(16);
        let token = self.root.path().join("synthetic-workspace-token");
        std::fs::write(&token, "synthetic.ssh.ingress").unwrap();
        sender
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(v1::credential_bridge_host_message::Payload::Open(
                    v1::CredentialBridgeOpen {
                        protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: config.environment_id.to_string(),
                        environment_generation: config.environment_generation,
                        capabilities: Vec::new(),
                    },
                )),
            }))
            .await
            .unwrap();
        let mut connection = self
            .bridge
            .connect_with_token_file(ReceiverStream::new(receiver), &token)
            .await
            .unwrap();
        assert!(matches!(
            connection.output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        self.bridge
            .wait_for_initial_host(&codewire_workload_secrets::ProjectionContext {
                environment_id: *config.environment_id.as_bytes(),
                operation_generation: config.environment_generation,
                selection_sha256: [1; 32],
                deadline_unix_ms: codewire_workload_secrets::launcher::now_unix_ms().unwrap()
                    + 3_000,
            })
            .await
            .unwrap();
        (sender, connection.output)
    }

    async fn wait_permits(&self, count: usize) {
        bounded(async {
            while self.permits.available_permits() != count {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    async fn stopped(&self) {
        bounded(self.bridge.shutdown()).await;
        assert!(self.bridge.owner.tasks.is_empty());
        assert!(self.bridge.owner.tasks.is_closed());
        assert_eq!(self.permits.available_permits(), MAX_CONNECTIONS);
        assert!(!self.ssh_path().exists());
        assert!(!self.http_path().exists());
        assert!(UnixStream::connect(self.ssh_path()).await.is_err());
    }

    async fn finish(mut self) {
        self.stop.cancel();
        bounded(self.task.take().unwrap()).await.unwrap().unwrap();
        self.stopped().await;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn send(stream: &mut UnixStream, operation: &v1::credential_ssh_request::Operation) {
    let payload = agent::encode_request(operation).unwrap();
    bounded(async {
        stream.write_u32(payload.len() as u32).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    })
    .await;
}

async fn receive(
    stream: &mut UnixStream,
    operation: SshOperation,
) -> v1::credential_ssh_response::Result {
    bounded(async {
        let count = stream.read_u32().await.unwrap() as usize;
        assert!(count <= agent::MAX_PAYLOAD_BYTES);
        let mut payload = vec![0; count];
        stream.read_exact(&mut payload).await.unwrap();
        agent::decode_response(&payload, operation).unwrap()
    })
    .await
}

fn identities() -> v1::credential_ssh_request::Operation {
    v1::credential_ssh_request::Operation::Identities(v1::CredentialSshIdentitiesRequest {})
}

fn sign() -> v1::credential_ssh_request::Operation {
    v1::credential_ssh_request::Operation::Sign(v1::CredentialSshSignRequest {
        public_key_blob: b"synthetic-public-key".to_vec(),
        data: b"synthetic-sign-input".to_vec(),
        flags: 4,
    })
}

async fn request(output: &mut CredentialBridgeOutput) -> v1::CredentialSshRequest {
    let message = bounded(output.next()).await.unwrap().unwrap();
    let Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) = message.payload else {
        panic!("expected SSH request");
    };
    request
}

/// The signer binds beside the HTTP ingress (asserted below). In a hosted
/// Sandbox that is the path the shared projection gives every session, a
/// managed agent's included, as `SSH_AUTH_SOCK`.
#[test]
fn hosted_signer_socket_is_the_projected_ssh_auth_sock() {
    assert_eq!(
        Path::new(crate::config::HOSTED_CREDENTIAL_SOCKET).with_file_name(SOCKET_NAME),
        Path::new(codewire_access::SSH_PLATFORM_AUTH_SOCK)
    );
}

#[tokio::test]
async fn selected_socket_permissions_and_unselected_no_socket_are_exact() {
    let root = tempfile::tempdir().unwrap();
    let config = config(
        root.path().join("credential.sock"),
        CredentialBridgeTransport::Local,
    );
    let bridge = CredentialBridge::new(Some(config.clone()));
    let ingress = bridge.prepare_ingress(false).unwrap().unwrap();
    assert!(ingress.ssh.is_none());
    assert!(!root.path().join(SOCKET_NAME).exists());
    drop(ingress);
    let ingress = bridge.prepare_ingress(true).unwrap().unwrap();
    let ssh = ingress.ssh.as_ref().unwrap();
    let metadata = std::fs::symlink_metadata(&ssh.socket.path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        (metadata.uid(), metadata.gid()),
        (config.ingress_uid, config.ingress_gid)
    );
    assert_eq!(ssh.socket.path, root.path().join(SOCKET_NAME));
    drop(ingress);
    assert!(!root.path().join(SOCKET_NAME).exists());
    assert!(CredentialBridge::new(None).prepare_ingress(true).is_err());
}

#[tokio::test]
async fn occupied_ssh_objects_never_unlink_ssh_or_the_existing_http_owner() {
    let _lock = LOOPBACK_TEST.lock().await;
    for transport in [
        CredentialBridgeTransport::Local,
        CredentialBridgeTransport::Hosted,
    ] {
        for object in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join(SOCKET_NAME);
            let http = root.path().join("credential.sock");
            let _http_listener = UnixListener::bind(&http).unwrap();
            let mut socket = None;
            match object {
                0 => std::fs::write(&path, b"synthetic occupied object").unwrap(),
                1 => std::os::unix::fs::symlink("synthetic-absent-target", &path).unwrap(),
                2 | 3 => {
                    socket = Some(UnixListener::bind(&path).unwrap());
                    if object == 3 {
                        drop(socket.take());
                    }
                }
                _ => unreachable!(),
            }
            let before = std::fs::symlink_metadata(&path).unwrap();
            let http_before = std::fs::symlink_metadata(&http).unwrap();
            let bridge = CredentialBridge::new(Some(config(http.clone(), transport)));
            let result = bridge.prepare_ingress(true);
            assert!(
                matches!(&result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists),
                "transport={transport:?}, object={object}: unexpected ingress result: {:?}",
                result.as_ref().err()
            );
            let after = std::fs::symlink_metadata(&path).unwrap();
            let http_after = std::fs::symlink_metadata(&http).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(
                (http_before.dev(), http_before.ino()),
                (http_after.dev(), http_after.ino())
            );
            drop(socket);
        }
    }
}

#[tokio::test]
async fn socket_cleanup_preserves_a_replacement_inode() {
    let root = tempfile::tempdir().unwrap();
    let bridge = CredentialBridge::new(Some(config(
        root.path().join("credential.sock"),
        CredentialBridgeTransport::Local,
    )));
    let ingress = bridge.prepare_ingress(true).unwrap().unwrap();
    let path = root.path().join(SOCKET_NAME);
    std::fs::rename(&path, root.path().join("original-owned.sock")).unwrap();
    let replacement = UnixListener::bind(&path).unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    drop(ingress);
    let after = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!((metadata.dev(), metadata.ino()), (after.dev(), after.ino()));
    let client = UnixStream::connect(&path).await.unwrap();
    drop(bounded(replacement.accept()).await.unwrap());
    drop(client);
}

#[tokio::test]
async fn selected_without_bridge_or_projection_rejects_before_any_path_mutation() {
    for bridge_present in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credential.sock");
        std::fs::write(&path, b"synthetic existing object").unwrap();
        let mut config = daemon_config(root.path());
        // Independently discriminate both missing prerequisites.
        if bridge_present {
            config.launch_projection = None;
        } else {
            config.credential_bridge = None;
        }
        let incoming = tokio_stream::pending::<io::Result<UnixStream>>();
        let result = bounded(crate::serve_grpc_with_incoming(
            config,
            incoming,
            std::future::pending(),
        ))
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic existing object");
        assert!(!root.path().join(SOCKET_NAME).exists());
    }
}

#[tokio::test]
async fn shutdown_closes_admission_while_an_accepted_stream_waits_for_the_owner_lock() {
    let mut harness = Harness::new(CredentialBridgeTransport::Local, false);
    let gate = harness.bridge.owner.accepting.lock().await;
    let mut stream = harness.connect().await;
    // Permit acquisition precedes the locked registration: this is the exact
    // accepted-but-not-tracked phase, not a timing-based approximation.
    harness.wait_permits(MAX_CONNECTIONS - 1).await;
    assert_eq!(harness.bridge.owner.tasks.len(), 0);
    harness.stop.cancel();
    bounded(harness.bridge.owner.shutdown.cancelled()).await;
    drop(gate);
    bounded(harness.task.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    harness.stopped().await;
    let mut byte = [0];
    assert_eq!(bounded(stream.read(&mut byte)).await.unwrap(), 0);
}

#[tokio::test]
async fn dropping_the_whole_daemon_future_stops_ssh_and_aborts_its_shutdown_observer() {
    struct ObservedDrop(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for ObservedDrop {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let observer_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = ObservedDrop(observer_dropped.clone());
    let task = tokio::spawn(crate::serve_grpc_with_incoming(
        config,
        tokio_stream::pending::<io::Result<UnixStream>>(),
        async move {
            let _observed = observed;
            std::future::pending::<()>().await;
        },
    ));
    let path = root.path().join(SOCKET_NAME);
    let mut stream = bounded(async {
        loop {
            if let Ok(stream) = UnixStream::connect(&path).await {
                break stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    send(&mut stream, &identities()).await;
    assert!(matches!(
        receive(&mut stream, SshOperation::Identities).await,
        v1::credential_ssh_response::Result::Failure(_)
    ));
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(bounded(stream.read(&mut byte)).await.unwrap(), 0);
    bounded(async {
        while path.exists() || !observer_dropped.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(!root.path().join("credential.sock").exists());
}

#[tokio::test]
async fn peer_uid_and_eight_connections_are_enforced_before_dispatch() {
    let harness = Harness::new(CredentialBridgeTransport::Local, true);
    let mut rejected = harness.connect().await;
    let mut byte = [0];
    assert_eq!(bounded(rejected.read(&mut byte)).await.unwrap(), 0);
    assert_eq!(harness.bridge.owner.tasks.len(), 0);
    harness.finish().await;

    let harness = Harness::new(CredentialBridgeTransport::Local, false);
    let mut streams = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        streams.push(harness.connect().await);
    }
    harness.wait_permits(0).await;
    assert_eq!(harness.bridge.owner.tasks.len(), MAX_CONNECTIONS);
    let mut rejected = harness.connect().await;
    assert_eq!(bounded(rejected.read(&mut byte)).await.unwrap(), 0);
    drop(streams.pop());
    harness.wait_permits(1).await;
    let mut replacement = harness.connect().await;
    send(&mut replacement, &identities()).await;
    assert!(matches!(
        receive(&mut replacement, SshOperation::Identities).await,
        v1::credential_ssh_response::Result::Failure(_)
    ));
    // Readiness did not wait for a host epoch, and a socket request did not
    // create one. Only the bounded stream workers exist in the shared owner.
    assert_eq!(harness.bridge.owner.tasks.len(), MAX_CONNECTIONS);
    drop(streams);
    drop(replacement);
    harness.finish().await;
}

#[tokio::test]
async fn local_and_hosted_selected_socket_use_the_admitted_shared_epoch() {
    let _lock = LOOPBACK_TEST.lock().await;
    for transport in [
        CredentialBridgeTransport::Local,
        CredentialBridgeTransport::Hosted,
    ] {
        let harness = Harness::new(transport, false);
        let (sender, mut output) = harness.host().await;
        let mut stream = harness.connect().await;
        for (operation, kind, result) in [
            (
                identities(),
                SshOperation::Identities,
                v1::credential_ssh_response::Result::Identity(v1::CredentialSshIdentity {
                    public_key_blob: b"synthetic-public-key".to_vec(),
                }),
            ),
            (
                sign(),
                SshOperation::Sign,
                v1::credential_ssh_response::Result::Signature(v1::CredentialSshSignature {
                    signature_blob: b"synthetic-signature".to_vec(),
                }),
            ),
        ] {
            send(&mut stream, &operation).await;
            let request = request(&mut output).await;
            assert_eq!(request.operation.as_ref(), Some(&operation));
            sender
                .send(Ok(v1::CredentialBridgeHostMessage {
                    payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                        v1::CredentialSshResponse {
                            request_id: request.request_id,
                            result: Some(result.clone()),
                        },
                    )),
                }))
                .await
                .unwrap();
            assert_eq!(receive(&mut stream, kind).await, result);
        }
        drop(stream);
        harness.finish().await;
        while bounded(output.next()).await.is_some() {}
    }
}

#[tokio::test]
async fn selected_shutdown_and_future_drop_cancel_pending_ssh_and_partial_http_before_drain() {
    let _lock = LOOPBACK_TEST.lock().await;
    for transport in [
        CredentialBridgeTransport::Local,
        CredentialBridgeTransport::Hosted,
    ] {
        for abort in [false, true] {
            let mut harness = Harness::new(transport, false);
            let (_sender, mut output) = harness.host().await;
            let mut ssh = harness.connect().await;
            send(&mut ssh, &sign()).await;
            let _admitted = request(&mut output).await;
            let mut http = UnixStream::connect(harness.http_path()).await.unwrap();
            http.write_all(b"POST /v1/responses HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
            let mut continued = [0; 25];
            bounded(http.read_exact(&mut continued)).await.unwrap();
            assert_eq!(&continued, b"HTTP/1.1 100 Continue\r\n\r\n");
            if abort {
                harness.task.as_ref().unwrap().abort();
                assert!(
                    bounded(harness.task.take().unwrap())
                        .await
                        .unwrap_err()
                        .is_cancelled()
                );
                // Prove cancellation was caused by future-drop, before the
                // explicit final wait used only to observe completion here.
                assert!(harness.bridge.owner.shutdown.is_cancelled());
                harness.stopped().await;
            } else {
                harness.stop.cancel();
                bounded(harness.task.take().unwrap())
                    .await
                    .unwrap()
                    .unwrap();
                harness.stopped().await;
            }
            let mut byte = [0];
            assert_eq!(bounded(ssh.read(&mut byte)).await.unwrap(), 0);
            assert!(matches!(
                bounded(http.read(&mut byte)).await,
                Ok(0) | Err(_)
            ));
            while bounded(output.next()).await.is_some() {}
        }
    }
}

#[tokio::test]
async fn ssh_listener_failure_cancels_siblings_and_waits_the_existing_owner() {
    let owner = CredentialBridge::new(None);
    let drain = HostedIngressDrain {
        stop: CancellationToken::new(),
        transports: crate::server::TransportShutdown::new(),
        owner: owner.clone(),
    };
    let (unix_done, tcp_done) = (
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let sibling = |done: Arc<std::sync::atomic::AtomicBool>| {
        let stop = drain.stop.clone();
        async move {
            stop.cancelled().await;
            done.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }
    };
    let result = bounded(serve_ingress_listeners(
        sibling(unix_done.clone()),
        sibling(tcp_done.clone()),
        async { Err(io::Error::other("synthetic accept failure")) },
        std::future::pending(),
        CancellationToken::new(),
        drain,
    ))
    .await;
    assert!(result.is_err());
    assert!(unix_done.load(std::sync::atomic::Ordering::Acquire));
    assert!(tcp_done.load(std::sync::atomic::Ordering::Acquire));
    assert!(owner.owner.shutdown.is_cancelled());
    assert!(owner.owner.tasks.is_empty());
    assert!(owner.owner.tasks.is_closed());
}
