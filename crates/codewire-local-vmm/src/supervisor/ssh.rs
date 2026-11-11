//! SSH to a local environment (#3025). The supervisor terminates SSH for one
//! stream on its owner-only socket and runs the stream's sessions through the
//! environment's own daemon, so nothing listens for SSH anywhere and the guest
//! supplies no trust material. Each environment has one host key, kept with
//! the supervisor's state; `GetEnvironmentHostKey` serves its public half.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use codewire_daemon_proto::platform_listeners;
use codewire_workspace_access::daemon::{DaemonForwardDialer, DaemonSessionClient};
use codewire_workspace_access::daemon_access::{
    HostKeyStore, daemon_ssh_server_config, public_key_line,
};
use codewire_workspace_access::scp::DaemonScpRunner;
use codewire_workspace_access::sftp::DaemonSftpRunner;
use codewire_workspace_access::ssh::{
    DaemonBackedSshRunner, ForwardDialError, ForwardDialer, ForwardIo, ForwardTarget,
    WorkspaceSshHandler,
};
use futures::{Stream, StreamExt as _};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::ssh_stream_frame::Frame;
use crate::hybrid_vsock::HybridVsockTarget;
use crate::supervisor_store::{OperationKind, OperationRecord};

/// Under the supervisor root: one owner-only directory per environment.
const HOST_KEY_DIRECTORY: &str = "ssh-host-keys";
/// Open SSH streams, per environment and for every environment together.
const MAX_STREAMS_PER_ENVIRONMENT: usize = 8;
const MAX_STREAMS: usize = 64;
/// The largest SSH frame sent to the client, and the in-memory pipe and frame
/// queue behind it: a stream's memory stays bounded whatever its peer does.
const FRAME_BYTES: usize = 32 * 1024;
const PIPE_BYTES: usize = 64 * 1024;
const QUEUED_FRAMES: usize = 8;
/// How long a disconnect has to reach the client once the VM stops.
const DISCONNECT_FLUSH: std::time::Duration = std::time::Duration::from_secs(2);
/// Exec requests run `<shell> -c <command>`, as sshd runs them through the
/// login shell: the workspace's own shell, or `/bin/sh` from a daemon older
/// than its report.
const FALLBACK_EXEC_SHELL: &str = "/bin/sh";

pub(super) type SshFrames =
    Pin<Box<dyn Stream<Item = Result<v1::SshStreamFrame, Status>> + Send + 'static>>;

/// Every environment's host key. Generated on first use and kept owner-only
/// with the supervisor's state, it stays the same for every boot until the
/// environment is deleted; a recreated environment has a new UUID and so a
/// new key. One lock serializes generation, so the stream and
/// `GetEnvironmentHostKey`, which an SSH client asks at the same moment, never
/// make two keys.
pub(super) struct HostKeys {
    root: PathBuf,
    lock: Mutex<()>,
}

impl HostKeys {
    pub(super) fn new(supervisor_root: &Path) -> Self {
        Self {
            root: supervisor_root.join(HOST_KEY_DIRECTORY),
            lock: Mutex::new(()),
        }
    }

    pub(super) fn private(&self, environment_id: Uuid) -> io::Result<PrivateKey> {
        let _generation = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        HostKeyStore::new(self.directory(environment_id)).for_generation(1)
    }

    /// The public key line `KnownHostsCommand` prints: `ssh-ed25519 <base64>`.
    pub(super) fn public_line(&self, environment_id: Uuid) -> io::Result<String> {
        self.private(environment_id)
            .map(|key| public_key_line(&key))
    }

    fn directory(&self, environment_id: Uuid) -> PathBuf {
        host_key_directory(&self.root, environment_id)
    }
}

/// Forget a deleted environment's host key; best effort.
pub(super) fn remove_host_key(supervisor_root: &Path, environment_id: Uuid) {
    let _ = std::fs::remove_dir_all(host_key_directory(
        &supervisor_root.join(HOST_KEY_DIRECTORY),
        environment_id,
    ));
}

fn host_key_directory(keys: &Path, environment_id: Uuid) -> PathBuf {
    keys.join(environment_id.to_string())
}

/// Open streams, bounded per environment and in total, so no peer can
/// exhaust the supervisor every environment shares.
#[derive(Default)]
pub(super) struct SshStreams {
    open: Mutex<HashMap<Uuid, usize>>,
}

impl SshStreams {
    pub(super) fn admit(self: &Arc<Self>, environment_id: Uuid) -> Result<SshStreamPermit, Status> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let total: usize = open.values().sum();
        let here = open.get(&environment_id).copied().unwrap_or(0);
        if total >= MAX_STREAMS || here >= MAX_STREAMS_PER_ENVIRONMENT {
            return Err(Status::resource_exhausted(
                "too many SSH connections to local environments are open; close one and retry",
            ));
        }
        *open.entry(environment_id).or_default() += 1;
        Ok(SshStreamPermit {
            streams: Arc::clone(self),
            environment_id,
        })
    }
}

/// One admitted stream; dropping it frees its place.
pub(super) struct SshStreamPermit {
    streams: Arc<SshStreams>,
    environment_id: Uuid,
}

impl Drop for SshStreamPermit {
    fn drop(&mut self) {
        let mut open = self
            .streams
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.environment_id) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.environment_id);
            }
        }
    }
}

/// The environment from a stream's first frame, which must open it.
pub(super) async fn opened_environment(
    inbound: &mut Streaming<v1::SshStreamFrame>,
) -> Result<Uuid, Status> {
    match inbound.message().await? {
        Some(v1::SshStreamFrame {
            frame: Some(Frame::Open(open)),
        }) => Uuid::parse_str(&open.environment_id)
            .map_err(|_| Status::invalid_argument("the SSH stream names an invalid environment")),
        _ => Err(Status::invalid_argument(
            "an SSH stream opens with its environment",
        )),
    }
}

/// A daemon client over the environment's admitted daemon access.
pub(super) async fn daemon_client(access: v1::DaemonAccess) -> Result<DaemonSessionClient, Status> {
    let capability = zeroize::Zeroizing::new(access.generation_capability);
    let unavailable = || Status::unavailable("local environment daemon is unavailable");
    let target = HybridVsockTarget::new(PathBuf::from(access.hybrid_socket), access.guest_port)
        .map_err(|_| unavailable())?;
    let channel = target.connect_channel().await.map_err(|_| unavailable())?;
    let credential = codewire_daemon::DaemonAuthToken::new(capability.as_str())
        .map_err(|_| Status::internal("local supervisor request failed"))?;
    Ok(DaemonSessionClient::from_channel(channel, credential))
}

/// What the environment's daemon offers the SSH server.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DaemonFeatures {
    exec_shell: String,
    /// SFTP and SCP only where file operations act as the workload user, so
    /// a transfer never leaves root-owned files in the workspace.
    file_transfer: bool,
    /// Port forwarding only where the daemon connects inside the workload's
    /// network namespace; a dial from here would reach the host.
    forwarding: bool,
}

impl DaemonFeatures {
    pub(super) async fn read(daemon: &DaemonSessionClient) -> Self {
        daemon
            .capabilities()
            .await
            .map(Self::from_capabilities)
            .unwrap_or_else(|_| Self::from_capabilities(Default::default()))
    }

    fn from_capabilities(
        response: codewire_daemon_proto::daemon::v1::GetCapabilitiesResponse,
    ) -> Self {
        Self {
            exec_shell: Some(response.default_shell)
                .filter(|shell| shell.starts_with('/'))
                .unwrap_or_else(|| FALLBACK_EXEC_SHELL.to_owned()),
            file_transfer: response.capabilities.iter().any(|capability| {
                capability == codewire_daemon_proto::DAEMON_CAPABILITY_WORKLOAD_FILES
            }),
            forwarding: response.capabilities.iter().any(|capability| {
                capability == codewire_daemon_proto::DAEMON_CAPABILITY_FORWARD_TCP
            }),
        }
    }
}

/// Refuses every forward from a VM whose runtime predates `ForwardTcp`.
struct OlderRuntime;

#[async_trait::async_trait]
impl ForwardDialer for OlderRuntime {
    async fn dial(&self, _target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        Err(ForwardDialError::Prohibited(
            "this local VM's runtime predates port forwarding; a local VM created with \
             this cw has it"
                .into(),
        ))
    }
}

/// Whether `operation` stops or replaces the environment's VM, which ends the
/// environment's SSH streams.
fn replaces_vm(operation: &OperationRecord, environment_id: Uuid) -> bool {
    operation.environment_id == Some(environment_id)
        && matches!(
            operation.kind,
            OperationKind::Stop
                | OperationKind::Restart
                | OperationKind::UpdateWorkspace
                | OperationKind::RollbackWorkspace
                | OperationKind::UpdateEnvironmentSources
                | OperationKind::GrowDisk
                | OperationKind::Delete
        )
}

/// Serve SSH over `inbound` and the returned frames until the client or the
/// server ends the connection, or an operation stops or replaces the VM. SFTP
/// and SCP are offered only by a daemon whose file operations act as the
/// workload user, and port forwarding only by one that connects inside the
/// workload's network namespace.
pub(super) fn serve(
    daemon: DaemonSessionClient,
    features: DaemonFeatures,
    host_key: PrivateKey,
    mut inbound: impl Stream<Item = Result<v1::SshStreamFrame, Status>> + Send + Unpin + 'static,
    mut operations: broadcast::Receiver<OperationRecord>,
    environment_id: Uuid,
    permit: SshStreamPermit,
) -> SshFrames {
    let (outbound, frames) = mpsc::channel(QUEUED_FRAMES);
    let (server_side, client_side) = tokio::io::duplex(PIPE_BYTES);
    let (mut from_server, mut to_server) = tokio::io::split(client_side);
    let config = Arc::new(daemon_ssh_server_config(host_key));
    let runner = Arc::new(DaemonBackedSshRunner::new(daemon.clone()));
    let dialer: Arc<dyn ForwardDialer> = if features.forwarding {
        Arc::new(DaemonForwardDialer::new(daemon.clone()))
    } else {
        Arc::new(OlderRuntime)
    };
    let handler = if features.file_transfer {
        WorkspaceSshHandler::with_file_protocols(
            runner,
            Some(Arc::new(DaemonSftpRunner::new(daemon.clone()))),
            Some(Arc::new(DaemonScpRunner::new(daemon))),
        )
    } else {
        WorkspaceSshHandler::new(runner)
    }
    .with_exec_shell(features.exec_shell)
    // The guest daemon serves its API on vsock, so no workload port is its.
    .with_port_forwarding(dialer, Arc::new(platform_listeners(None)));
    tokio::spawn(async move {
        let _permit = permit;
        let (handle_tx, mut handle_rx) = tokio::sync::oneshot::channel();
        let session = async move {
            if let Ok(session) = russh::server::run_stream(config, server_side, handler).await {
                let _ = handle_tx.send(session.handle());
                let _ = session.await;
            }
        };
        // Everything the server writes reaches the client before the stream
        // ends: the server side closes when its session ends.
        let egress = async move {
            let mut buffer = vec![0; FRAME_BYTES];
            loop {
                match from_server.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let frame = v1::SshStreamFrame {
                            frame: Some(Frame::Data(buffer[..read].to_vec())),
                        };
                        if outbound.send(Ok(frame)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        let ingress = async move {
            while let Some(Ok(frame)) = inbound.next().await {
                // Only data follows the opening frame.
                let Some(Frame::Data(bytes)) = frame.frame else {
                    break;
                };
                if to_server.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = to_server.shutdown().await;
        };
        let replaced = async move {
            loop {
                match operations.recv().await {
                    Ok(operation) if replaces_vm(&operation, environment_id) => break,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
                }
            }
        };
        let mut transport = std::pin::pin!(async { tokio::join!(session, egress) });
        tokio::select! {
            _ = &mut transport => return,
            _ = ingress => return,
            _ = replaced => {}
        }
        // The VM is stopping or being replaced: tell the client why, so it
        // ends the connection instead of waiting on a session that is gone.
        if let Ok(handle) = handle_rx.try_recv() {
            let _ = handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "the local environment stopped".to_owned(),
                    String::new(),
                )
                .await;
        }
        let _ = tokio::time::timeout(DISCONNECT_FLUSH, transport).await;
    });
    Box::pin(ReceiverStream::new(frames))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use codewire_daemon::execution::ProcessExecution;
    use codewire_daemon::local_transport::{local_transport, with_local_connections};
    use codewire_daemon::{Config, DaemonAuthToken, serve_grpc_with_incoming};
    use russh::{ChannelMsg, client};
    use tokio::time::timeout;

    use super::*;

    const TOKEN: &str = "synthetic-ssh-stream-daemon-token";

    fn test_operation(kind: OperationKind, environment_id: Uuid) -> OperationRecord {
        OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(environment_id),
            kind,
            phase: crate::supervisor_store::OperationPhase::Intent,
            checkpoint: 0,
            payload: serde_json::json!({}),
            result: None,
            error_code: None,
            created_unix_ms: 0,
            updated_unix_ms: 0,
        }
    }

    /// A real daemon, reached only over its in-process transport, as a local
    /// VM's daemon is reached over hybrid vsock.
    async fn in_process_daemon(temp: &Path) -> DaemonSessionClient {
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
        let network = tokio_stream::empty::<io::Result<tokio::net::TcpStream>>();
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

    /// Checks the server presents exactly the environment's stored key.
    struct ExpectKey(ssh_key::PublicKey);

    impl client::Handler for ExpectKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(matches!(
                key,
                russh::keys::PublicKeyOrCertificate::PublicKey { key, .. }
                    if key.key_data() == self.0.key_data()
            ))
        }
    }

    /// An SSH client connected to [`serve`] over the frames the RPC carries.
    /// Like `cw` as a ProxyCommand, the bridge keeps the client's input open
    /// after the stream ends: only an SSH disconnect closes the client.
    struct Connected {
        client: client::Handle<ExpectKey>,
        stream_ended: tokio::sync::oneshot::Receiver<()>,
    }

    async fn connect(
        daemon: DaemonSessionClient,
        host_key: PrivateKey,
        operations: broadcast::Receiver<OperationRecord>,
        environment: Uuid,
        permit: SshStreamPermit,
    ) -> Connected {
        let expected = host_key.public_key().clone();
        let (inbound_tx, inbound_rx) = mpsc::channel(8);
        let features = DaemonFeatures::read(&daemon).await;
        let mut frames = serve(
            daemon,
            features,
            host_key,
            ReceiverStream::new(inbound_rx),
            operations,
            environment,
            permit,
        );
        let (client_io, bridge) = tokio::io::duplex(PIPE_BYTES);
        let (mut from_client, mut to_client) = tokio::io::split(bridge);
        let (ended, stream_ended) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let upstream = async move {
                let mut buffer = vec![0; FRAME_BYTES];
                while let Ok(read @ 1..) = from_client.read(&mut buffer).await {
                    let frame = v1::SshStreamFrame {
                        frame: Some(Frame::Data(buffer[..read].to_vec())),
                    };
                    if inbound_tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
            };
            let downstream = async move {
                while let Some(Ok(frame)) = frames.next().await {
                    if let Some(Frame::Data(bytes)) = frame.frame
                        && to_client.write_all(&bytes).await.is_err()
                    {
                        break;
                    }
                }
                let _ = ended.send(());
                std::future::pending::<()>().await;
                drop(to_client);
            };
            tokio::join!(upstream, downstream);
        });
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            client_io,
            ExpectKey(expected),
        )
        .await
        .expect("SSH handshake with the environment's host key");
        assert!(matches!(
            client.authenticate_none("codewire").await.unwrap(),
            client::AuthResult::Success
        ));
        Connected {
            client,
            stream_ended,
        }
    }

    async fn exec(client: &client::Handle<ExpectKey>, command: &str) -> (Vec<u8>, Option<u32>) {
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .unwrap();
        let mut stdout = Vec::new();
        let mut exit = None;
        timeout(Duration::from_secs(20), async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("exec finishes");
        (stdout, exit)
    }

    #[tokio::test]
    async fn an_ssh_stream_runs_commands_through_the_daemon_with_the_environments_key() {
        let temp = tempfile::tempdir().unwrap();
        let daemon = in_process_daemon(temp.path()).await;
        let keys = HostKeys::new(temp.path());
        let environment = Uuid::new_v4();
        let streams = Arc::new(SshStreams::default());
        let (operations, _) = broadcast::channel(16);
        let connected = connect(
            daemon,
            keys.private(environment).unwrap(),
            operations.subscribe(),
            environment,
            streams.admit(environment).unwrap(),
        )
        .await;

        // A PTY session's output is the program's own.
        let mut pty = connected.client.channel_open_session().await.unwrap();
        pty.request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        pty.exec(true, b"printf ready".to_vec()).await.unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(20), async {
            while let Some(message) = pty.wait().await {
                match message {
                    ChannelMsg::Data { data } => output.extend_from_slice(&data),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("the PTY session finishes");
        assert_eq!(
            String::from_utf8_lossy(&output).trim_end(),
            "ready",
            "{output:?}"
        );

        // A command line runs through the shell: pipes and variables work.
        let (stdout, exit) = exec(&connected.client, "printf '%s' \"$((6 * 7))\" | tr 4 x").await;
        assert_eq!((stdout.as_slice(), exit), (&b"x2"[..], Some(0)));

        // This daemon's file operations act as the workload user, so SFTP is
        // offered.
        let mut sftp = connected.client.channel_open_session().await.unwrap();
        sftp.request_subsystem(true, "sftp").await.unwrap();
        assert!(matches!(sftp.wait().await, Some(ChannelMsg::Success)));

        // A forward reaches a loopback service through the daemon, which
        // makes the connection; both directions half-close as TCP does.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(&received).await.unwrap();
        });
        let mut forward = connected
            .client
            .channel_open_direct_tcpip("127.0.0.1", echo_port.into(), "127.0.0.1", 40_000)
            .await
            .expect("the forward opens");
        forward.data(&b"through the daemon"[..]).await.unwrap();
        forward.eof().await.unwrap();
        let mut echoed = Vec::new();
        timeout(Duration::from_secs(20), async {
            while let Some(message) = forward.wait().await {
                match message {
                    ChannelMsg::Data { data } => echoed.extend_from_slice(&data),
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("the forward finishes");
        assert_eq!(echoed, b"through the daemon");
        // A platform listener, such as the credential bridge, is refused.
        let bridge = connected
            .client
            .channel_open_direct_tcpip(
                "127.0.0.1",
                codewire_daemon_proto::CREDENTIAL_BRIDGE_LOOPBACK_PORT.into(),
                "127.0.0.1",
                40_001,
            )
            .await;
        assert!(
            matches!(bridge, Err(russh::Error::ChannelOpenFailure(_))),
            "the credential bridge port is refused"
        );

        // Another operation on the VM, such as a host-port change, leaves the
        // stream open; a stop ends it and frees its place.
        let mut ports = test_operation(OperationKind::UpdateHostPorts, environment);
        operations.send(ports.clone()).unwrap();
        ports.kind = OperationKind::Stop;
        let (stdout, _) = exec(&connected.client, "echo still").await;
        assert_eq!(stdout, b"still\n");
        operations.send(ports).unwrap();
        timeout(Duration::from_secs(10), connected.stream_ended)
            .await
            .expect("a stop ends the stream")
            .unwrap();
        // The client was told: its connection is closed, not left waiting on
        // input that stays open.
        timeout(Duration::from_secs(10), async {
            while !connected.client.is_closed() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the client learns the environment stopped");
        timeout(Duration::from_secs(10), async {
            while !streams.open.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the stream's place is freed");
    }

    #[tokio::test]
    async fn an_older_runtime_refuses_forwards_with_a_reason() {
        let target = ForwardTarget::local("localhost", 8080, &platform_listeners(None)).unwrap();
        let Err(ForwardDialError::Prohibited(reason)) = OlderRuntime.dial(&target).await else {
            panic!("an older runtime refuses");
        };
        assert!(reason.contains("predates port forwarding"), "{reason}");
    }

    #[test]
    fn an_older_daemon_offers_no_file_transfer_or_forwarding_and_runs_lines_through_sh() {
        use codewire_daemon_proto::daemon::v1::GetCapabilitiesResponse;
        assert_eq!(
            DaemonFeatures::from_capabilities(GetCapabilitiesResponse {
                capabilities: vec!["files.v1".into(), "exec.v1".into()],
                ..Default::default()
            }),
            DaemonFeatures {
                exec_shell: "/bin/sh".into(),
                file_transfer: false,
                forwarding: false,
            }
        );
        assert_eq!(
            DaemonFeatures::from_capabilities(GetCapabilitiesResponse {
                capabilities: vec![
                    codewire_daemon_proto::DAEMON_CAPABILITY_WORKLOAD_FILES.into(),
                    codewire_daemon_proto::DAEMON_CAPABILITY_FORWARD_TCP.into(),
                ],
                default_shell: "/usr/bin/zsh".into(),
                ..Default::default()
            }),
            DaemonFeatures {
                exec_shell: "/usr/bin/zsh".into(),
                file_transfer: true,
                forwarding: true,
            }
        );
        // Only an absolute shell is used.
        assert_eq!(
            DaemonFeatures::from_capabilities(GetCapabilitiesResponse {
                default_shell: "zsh".into(),
                ..Default::default()
            })
            .exec_shell,
            "/bin/sh"
        );
    }

    #[test]
    fn an_environment_keeps_one_host_key_until_it_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let keys = HostKeys::new(root.path());
        let environment = Uuid::new_v4();
        let first = keys.public_line(environment).unwrap();
        assert!(first.starts_with("ssh-ed25519 "), "{first}");
        assert_eq!(keys.public_line(environment).unwrap(), first);
        assert_eq!(
            public_key_line(&keys.private(environment).unwrap()),
            first,
            "the stream serves the key KnownHostsCommand prints"
        );
        assert_ne!(keys.public_line(Uuid::new_v4()).unwrap(), first);
        remove_host_key(root.path(), environment);
        assert_ne!(keys.public_line(environment).unwrap(), first);
    }

    #[test]
    fn concurrent_first_uses_make_one_key() {
        let root = tempfile::tempdir().unwrap();
        let keys = Arc::new(HostKeys::new(root.path()));
        let environment = Uuid::new_v4();
        let lines = (0..8)
            .map(|_| {
                let keys = Arc::clone(&keys);
                std::thread::spawn(move || keys.public_line(environment).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(lines.len(), 1, "{lines:?}");
    }

    #[test]
    fn streams_are_bounded_per_environment_and_in_total() {
        let streams = Arc::new(SshStreams::default());
        let environment = Uuid::new_v4();
        let mut held = (0..MAX_STREAMS_PER_ENVIRONMENT)
            .map(|_| streams.admit(environment).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            streams.admit(environment).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        held.pop();
        held.push(streams.admit(environment).unwrap());
        while held.len() < MAX_STREAMS {
            held.push(streams.admit(Uuid::new_v4()).unwrap());
        }
        assert_eq!(
            streams.admit(Uuid::new_v4()).err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        held.clear();
        assert!(streams.open.lock().unwrap().is_empty());
    }

    #[test]
    fn only_operations_that_stop_or_replace_the_vm_end_its_streams() {
        let environment = Uuid::new_v4();
        let operation = |kind, environment_id: Option<Uuid>| {
            let mut operation = test_operation(kind, environment_id.unwrap_or_default());
            operation.environment_id = environment_id;
            operation
        };
        for kind in [
            OperationKind::Stop,
            OperationKind::Restart,
            OperationKind::UpdateWorkspace,
            OperationKind::RollbackWorkspace,
            OperationKind::UpdateEnvironmentSources,
            OperationKind::GrowDisk,
            OperationKind::Delete,
        ] {
            assert!(replaces_vm(
                &operation(kind, Some(environment)),
                environment
            ));
            assert!(!replaces_vm(
                &operation(kind, Some(Uuid::new_v4())),
                environment
            ));
        }
        for kind in [
            OperationKind::Reconcile,
            OperationKind::UpdateHostPorts,
            OperationKind::UpdateCwRuntime,
            OperationKind::Start,
        ] {
            assert!(!replaces_vm(
                &operation(kind, Some(environment)),
                environment
            ));
        }
    }
}
