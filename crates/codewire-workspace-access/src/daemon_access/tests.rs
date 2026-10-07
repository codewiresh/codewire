use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_daemon::execution::ProcessExecution;
use codewire_daemon::local_transport::{local_transport, with_local_connections};
use codewire_daemon::{Config, DaemonAuthToken, serve_grpc_with_incoming};
use russh::{ChannelMsg, client};
use tokio::time::timeout;

use super::*;

const TEST_DAEMON_TOKEN: &str = "synthetic-local-daemon-token";

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_generation_keeps_its_key_and_a_new_generation_rotates_it() {
    let root = tempfile::tempdir().unwrap();
    let store = HostKeyStore::new(root.path().join("daemon"));
    let first = store.for_generation(4).unwrap();
    assert_eq!(mode(&root.path().join("daemon")), 0o700);
    let path = root.path().join("daemon/ssh_host_ed25519_g4");
    assert_eq!(mode(&path), 0o400);
    // A daemon restarted in the same Pod reloads the same key.
    let again = store.for_generation(4).unwrap();
    assert_eq!(public_key_line(&first), public_key_line(&again));
    // A new generation gets a new key, and the old one is removed.
    let rotated = store.for_generation(5).unwrap();
    assert_ne!(public_key_line(&first), public_key_line(&rotated));
    assert!(!path.exists());
    assert!(root.path().join("daemon/ssh_host_ed25519_g5").exists());
}

#[test]
fn an_unreadable_or_foreign_key_is_refused_not_replaced() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("daemon");
    let store = HostKeyStore::new(&directory);
    store.for_generation(4).unwrap();
    let path = directory.join("ssh_host_ed25519_g4");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"not a key").unwrap();
    assert_eq!(
        store.for_generation(4).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn the_recorded_line_is_a_bare_ed25519_public_key() {
    let key = generate_ed25519_key();
    let line = public_key_line(&key);
    let fields: Vec<_> = line.split(' ').collect();
    assert_eq!(fields.len(), 2, "{line}");
    assert_eq!(fields[0], "ssh-ed25519");
    assert!(!line.contains('\n'));
}

#[derive(Default)]
struct ScriptedPlane {
    answers: Mutex<Vec<Result<(), ControlPlaneError>>>,
    calls: AtomicUsize,
    recorded: Mutex<Vec<String>>,
}

#[async_trait]
impl AccessControlPlane for ScriptedPlane {
    async fn record_host_key(&self, public_key_openssh: &str) -> Result<(), ControlPlaneError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.recorded
            .lock()
            .unwrap()
            .push(public_key_openssh.to_owned());
        let mut answers = self.answers.lock().unwrap();
        if answers.is_empty() {
            Ok(())
        } else {
            answers.remove(0)
        }
    }

    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError> {
        Err(ControlPlaneError::Retryable)
    }

    async fn allocate_peer_relay(
        &self,
        _disco_keys: [String; 2],
        _relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError> {
        Err(ControlPlaneError::Retryable)
    }
}

#[tokio::test]
async fn recording_retries_while_unavailable_and_stops_on_a_refusal() {
    let plane = ScriptedPlane {
        answers: Mutex::new(vec![
            Err(ControlPlaneError::Retryable),
            Err(ControlPlaneError::Retryable),
        ]),
        ..Default::default()
    };
    record_host_key_until_accepted(
        &plane,
        "ssh-ed25519 AAAA",
        Duration::from_millis(1),
        Duration::from_millis(2),
    )
    .await
    .unwrap();
    assert_eq!(plane.calls.load(Ordering::SeqCst), 3);
    assert!(
        plane
            .recorded
            .lock()
            .unwrap()
            .iter()
            .all(|key| key == "ssh-ed25519 AAAA")
    );

    let refused = ScriptedPlane {
        answers: Mutex::new(vec![Err(ControlPlaneError::Refused)]),
        ..Default::default()
    };
    assert_eq!(
        record_host_key_until_accepted(
            &refused,
            "ssh-ed25519 AAAA",
            Duration::from_millis(1),
            Duration::from_millis(2),
        )
        .await,
        Err(ControlPlaneError::Refused)
    );
    assert_eq!(refused.calls.load(Ordering::SeqCst), 1);
}

/// A real daemon reached only over its in-process transport, and the SSH
/// server serving it on a loopback listener.
struct DaemonSsh {
    _temp: tempfile::TempDir,
    workspace_root: PathBuf,
    ssh: SocketAddr,
    shutdown: watch::Sender<bool>,
    access_ready: watch::Sender<bool>,
}

async fn spawn_daemon_ssh() -> DaemonSsh {
    spawn_daemon_ssh_with_access(true).await
}

async fn spawn_daemon_ssh_with_access(ready: bool) -> DaemonSsh {
    let temp = tempfile::tempdir().unwrap();
    let workspace_root = temp.path().join("workspace");
    let home_root = temp.path().join("home");
    fs::create_dir_all(&workspace_root).unwrap();
    fs::create_dir_all(&home_root).unwrap();
    let config = Config {
        listen_addr: "in-process".into(),
        workspace_root: workspace_root.clone(),
        home_root,
        auth_token: DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
        process_execution: ProcessExecution::Native,
        credential_bridge: None,
        launch_projection: None,
        managed_credential_clients: Default::default(),
    };
    let (connector, local) = local_transport();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let mut daemon_shutdown = shutdown_rx.clone();
    // No network listener at all: only in-process connections.
    let network = tokio_stream::empty::<io::Result<tokio::net::TcpStream>>();
    tokio::spawn(async move {
        serve_grpc_with_incoming(config, with_local_connections(network, local), async move {
            let _ = daemon_shutdown.changed().await;
        })
        .await
        .expect("serve in-process daemon");
    });
    let daemon = DaemonSessionClient::connect_local(
        connector,
        DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
    )
    .await
    .unwrap();
    let store = HostKeyStore::new(temp.path().join("state"));
    let config = Arc::new(daemon_ssh_server_config(store.for_generation(1).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh = listener.local_addr().unwrap();
    let (access_ready_tx, access_ready) = watch::channel(ready);
    tokio::spawn(serve_ssh_listener(
        listener,
        config,
        DaemonSshRunners::new(daemon, access_ready, "/bin/sh".into()),
        shutdown_rx,
    ));
    DaemonSsh {
        _temp: temp,
        workspace_root,
        ssh,
        shutdown,
        access_ready: access_ready_tx,
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

async fn connect(addr: SocketAddr) -> client::Handle<AcceptAllKeys> {
    let mut handle = client::connect(Arc::new(client::Config::default()), addr, AcceptAllKeys)
        .await
        .unwrap();
    // The transport authenticated the user before the connection arrived.
    let authenticated = handle
        .authenticate_none("codewire")
        .await
        .map(|result| matches!(result, client::AuthResult::Success))
        .unwrap();
    assert!(authenticated, "none auth must be accepted");
    handle
}

#[tokio::test]
async fn an_exec_session_runs_through_the_in_process_daemon() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, br#"printf 'hello from the daemon'"#.to_vec())
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
    .expect("exec session finished");
    assert_eq!(String::from_utf8_lossy(&stdout), "hello from the daemon");
    assert_eq!(exit, Some(0));
    let _ = daemon.shutdown.send(true);
}

/// Run `command` on a new session channel: its stdout, stderr and exit
/// status, within `limit`.
async fn exec_within(
    client: &client::Handle<AcceptAllKeys>,
    command: &str,
    limit: Duration,
) -> (String, String, Option<u32>) {
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, command.as_bytes().to_vec())
        .await
        .unwrap();
    let (mut stdout, mut stderr, mut exit) = (Vec::new(), Vec::new(), None);
    timeout(limit, async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("the session ended within its limit");
    (
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        exit,
    )
}

#[tokio::test]
async fn an_exec_command_line_runs_through_the_workspace_shell() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    // sshd semantics: the whole line goes to `<shell> -c`, so operators,
    // pipes, quoting and expansions work as they do over OpenSSH.
    let (stdout, stderr, exit) = exec_within(
        &client,
        r#"printf a && printf b | tr b B; printf ' %s' "$((1 + 2))"; exit 3"#,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(stdout, "aB 3", "stderr: {stderr}");
    assert_eq!(exit, Some(3));
    let _ = daemon.shutdown.send(true);
}

#[tokio::test]
async fn an_sftp_channel_reports_exit_status_zero_when_the_client_is_done() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    // OpenSSH's scp and sftp send EOF when finished and report the
    // subsystem's exit status as their own.
    channel.eof().await.unwrap();
    let exit = timeout(Duration::from_secs(10), async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = message {
                return Some(exit_status);
            }
        }
        None
    })
    .await
    .expect("the SFTP channel ended");
    assert_eq!(exit, Some(0));
    let _ = daemon.shutdown.send(true);
}

#[tokio::test]
async fn a_session_before_access_is_ready_is_refused_at_once() {
    let daemon = spawn_daemon_ssh_with_access(false).await;
    let client = connect(daemon.ssh).await;
    // Refused promptly with the reason and a failing exit status, never left
    // waiting on a launch the platform cannot admit yet.
    let (stdout, stderr, exit) =
        exec_within(&client, "printf never-run", Duration::from_secs(5)).await;
    assert_eq!(stdout, "");
    assert_eq!(stderr.trim_end(), ACCESS_NOT_READY);
    assert_eq!(exit, Some(1));
    // Once access is ready the same connection runs sessions.
    daemon.access_ready.send_replace(true);
    let (stdout, _, exit) = exec_within(&client, "printf SSH-OK", Duration::from_secs(20)).await;
    assert_eq!(stdout, "SSH-OK");
    assert_eq!(exit, Some(0));
    let _ = daemon.shutdown.send(true);
}

#[tokio::test]
async fn sftp_reaches_the_workspace_through_the_in_process_daemon() {
    let daemon = spawn_daemon_ssh().await;
    fs::write(daemon.workspace_root.join("note.txt"), b"synthetic").unwrap();
    let client = connect(daemon.ssh).await;
    let channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .unwrap();
    let contents = timeout(
        Duration::from_secs(20),
        sftp.read(daemon.workspace_root.join("note.txt").to_string_lossy()),
    )
    .await
    .expect("sftp read finished")
    .unwrap();
    assert_eq!(contents, b"synthetic");
    let _ = daemon.shutdown.send(true);
}

/// No acknowledgement of `request` arrives on `channel` within a short
/// window: the forwarding it asked for is never granted.
async fn never_granted(channel: &mut russh::Channel<client::Msg>, request: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(message) = tokio::time::timeout_at(deadline, channel.wait()).await {
        match message {
            Some(ChannelMsg::Success) => panic!("{request} must not be granted"),
            None => break,
            Some(_) => {}
        }
    }
}

#[tokio::test]
async fn agent_x11_and_reverse_forwarding_are_refused() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel.agent_forward(true).await.unwrap();
    never_granted(&mut channel, "agent forwarding").await;
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
        .await
        .unwrap();
    never_granted(&mut channel, "X11 forwarding").await;
    // Reverse (remote) port forwarding is refused for the whole connection.
    let reverse = timeout(Duration::from_secs(5), client.tcpip_forward("127.0.0.1", 0))
        .await
        .expect("reverse forwarding answered");
    assert!(reverse.is_err(), "reverse forwarding must be refused");
    let _ = daemon.shutdown.send(true);
}
