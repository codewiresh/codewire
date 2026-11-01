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
    /// The daemon's own session client, to launch and inspect sessions.
    sessions: codewire_daemon::client::SessionClient,
}

/// The environment the fixture's SSH server attaches sessions for.
const ENVIRONMENT_ID: &str = "11111111-2222-4333-8444-555555555555";

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
        host: None,
        launch_projection: None,
        managed_credential_clients: Default::default(),
        session_working_dir: None,
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
    let sessions = daemon.credential_client();
    tokio::spawn(serve_ssh_listener(
        listener,
        config,
        DaemonSshRunners::new(daemon, access_ready, "/bin/sh".into())
            .with_session_attach(sessions.clone(), ENVIRONMENT_ID),
        shutdown_rx,
    ));
    DaemonSsh {
        _temp: temp,
        workspace_root,
        ssh,
        shutdown,
        access_ready: access_ready_tx,
        sessions,
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

/// A deterministic payload, different for each seed.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Run `command` on a new channel, sending `input` and then EOF while its
/// stdout is read: its stdout and exit status, within `limit`.
async fn exec_with_input(
    client: &client::Handle<AcceptAllKeys>,
    command: &str,
    input: Vec<u8>,
    limit: Duration,
) -> (Vec<u8>, Option<u32>) {
    let channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, command.as_bytes().to_vec())
        .await
        .unwrap();
    let (mut reader, writer) = channel.split();
    let send = async move {
        writer.data(&input[..]).await.unwrap();
        writer.eof().await.unwrap();
        writer
    };
    let receive = async {
        let (mut stdout, mut exit) = (Vec::new(), None);
        while let Some(message) = reader.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        (stdout, exit)
    };
    let (_writer, received) = timeout(limit, async { tokio::join!(send, receive) })
        .await
        .expect("the session finished within its limit");
    received
}

/// More than russh queues for a channel (100 messages of 32 KiB) reaches
/// the command, intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_upload_reaches_the_command_in_full() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let path = daemon.workspace_root.join("upload.bin");
    let upload = payload(24 * 1024 * 1024, 1);
    let (_, exit) = exec_with_input(
        &client,
        &format!("cat > '{}'", path.display()),
        upload.clone(),
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(exit, Some(0));
    assert!(
        fs::read(&path).unwrap() == upload,
        "the upload arrived changed"
    );
    let _ = daemon.shutdown.send(true);
}

/// Bulk input and output at once: `cat` echoes a stream larger than every
/// buffer between the client and the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bulk_stream_echoes_through_the_command() {
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let stream = payload(16 * 1024 * 1024, 2);
    let (stdout, exit) =
        exec_with_input(&client, "cat", stream.clone(), Duration::from_secs(60)).await;
    assert_eq!(exit, Some(0));
    assert!(stdout == stream, "the echo came back changed");
    let _ = daemon.shutdown.send(true);
}

/// Two connections upload at the same time, each through its own channel 2,
/// and each command writes exactly its own bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_connections_each_upload_their_own_bytes() {
    let daemon = spawn_daemon_ssh().await;
    let first = connect(daemon.ssh).await;
    let second = connect(daemon.ssh).await;
    let (a_path, b_path) = (
        daemon.workspace_root.join("a.bin"),
        daemon.workspace_root.join("b.bin"),
    );
    let (a, b) = (payload(6 * 1024 * 1024, 3), payload(6 * 1024 * 1024, 4));
    let a_command = format!("cat > '{}'", a_path.display());
    let b_command = format!("cat > '{}'", b_path.display());
    let ((_, a_exit), (_, b_exit)) = tokio::join!(
        exec_with_input(&first, &a_command, a.clone(), Duration::from_secs(60)),
        exec_with_input(&second, &b_command, b.clone(), Duration::from_secs(60)),
    );
    assert_eq!((a_exit, b_exit), (Some(0), Some(0)));
    assert!(
        fs::read(&a_path).unwrap() == a,
        "the first upload is not its own"
    );
    assert!(
        fs::read(&b_path).unwrap() == b,
        "the second upload is not its own"
    );
    let _ = daemon.shutdown.send(true);
}

/// An interactive terminal keeps answering past russh's channel queue: each
/// line is typed as one message, as OpenSSH sends keystrokes, once the
/// shell's prompt is up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interactive_shell_answers_hundreds_of_lines() {
    const LINES: u32 = 250;
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 120, 40, 0, 0, &[])
        .await
        .unwrap();
    // A plain interactive shell on the terminal, independent of the test
    // host's login shell and its start-up files.
    channel
        .exec(true, b"exec /bin/sh -i".to_vec())
        .await
        .unwrap();
    let (mut reader, writer) = channel.split();
    let (prompted, prompt) = tokio::sync::oneshot::channel::<()>();
    let typing = async move {
        // Typed-ahead input before the launch completes is bounded by the
        // daemon; type at the prompt, as a person does.
        let _ = prompt.await;
        for line in 1..=LINES {
            writer
                .data_bytes(format!("echo R$((100000+{line}))\n").into_bytes())
                .await
                .unwrap();
        }
        writer.data_bytes(b"exit\n".to_vec()).await.unwrap();
        writer
    };
    let screen = async {
        let mut prompted = Some(prompted);
        let mut screen = Vec::new();
        while let Some(message) = reader.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    screen.extend_from_slice(&data);
                    if let Some(prompted) = prompted.take() {
                        let _ = prompted.send(());
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        String::from_utf8_lossy(&screen).into_owned()
    };
    let (_writer, screen) = timeout(Duration::from_secs(60), async {
        tokio::join!(typing, screen)
    })
    .await
    .expect("the shell answered every line and exited");
    let missing: Vec<u32> = (1..=LINES)
        .filter(|line| !screen.contains(&format!("R{}", 100_000 + line)))
        .collect();
    assert!(missing.is_empty(), "no answers for lines {missing:?}");
    let _ = daemon.shutdown.send(true);
}

/// Every answer `R<100000 + line>` on `screen`, in the order they appear.
fn answers(screen: &str) -> Vec<u32> {
    screen
        .match_indices('R')
        .filter_map(|(at, _)| screen.get(at + 1..at + 7)?.parse::<u32>().ok())
        .filter(|value| (100_001..200_000).contains(value))
        .map(|value| value - 100_000)
        .collect()
}

/// Type `lines` one message each into an interactive shell, as a fast paste
/// or `ssh -tt host < file` does, and read the screen until the shell exits.
/// `before` is typed first, at once, without waiting for the prompt when
/// `at_prompt` is false.
async fn type_burst(
    client: &client::Handle<AcceptAllKeys>,
    before: &str,
    lines: u32,
    at_prompt: bool,
) -> String {
    let channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 120, 40, 0, 0, &[])
        .await
        .unwrap();
    channel
        .exec(true, b"exec /bin/sh -i".to_vec())
        .await
        .unwrap();
    let (mut reader, writer) = channel.split();
    let (prompted, prompt) = tokio::sync::oneshot::channel::<()>();
    let typing = async move {
        if at_prompt {
            let _ = prompt.await;
        }
        if !before.is_empty() {
            writer.data_bytes(before.as_bytes().to_vec()).await.unwrap();
        }
        for line in 1..=lines {
            writer
                .data_bytes(format!("echo R$((100000+{line}))\n").into_bytes())
                .await
                .unwrap();
        }
        writer.data_bytes(b"exit\n".to_vec()).await.unwrap();
        writer
    };
    let screen = async {
        let mut prompted = Some(prompted);
        let mut screen = Vec::new();
        while let Some(message) = reader.wait().await {
            match message {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    screen.extend_from_slice(&data);
                    if let Some(prompted) = prompted.take() {
                        let _ = prompted.send(());
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        String::from_utf8_lossy(&screen).into_owned()
    };
    let (_writer, screen) = timeout(Duration::from_secs(90), async {
        tokio::join!(typing, screen)
    })
    .await
    .expect("the shell answered every line and exited");
    screen
}

/// A burst of more than a thousand small input messages, typed while the
/// shell is busy and not reading its terminal, keeps the session: every
/// line is answered once, in order (#2822).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_typed_while_the_shell_is_busy_is_answered_in_order() {
    const LINES: u32 = 1200;
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let screen = type_burst(&client, "sleep 2\n", LINES, true).await;
    assert!(
        !screen.contains("workspace session failed"),
        "the session failed: {}",
        &screen[screen.len().saturating_sub(400)..]
    );
    assert_eq!(answers(&screen), (1..=LINES).collect::<Vec<_>>());
    let _ = daemon.shutdown.send(true);
}

/// Lines typed before the shell has started, as `ssh -tt host < file`
/// sends them at connect, wait for the shell instead of cancelling its
/// launch (#2830).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lines_typed_before_the_shell_starts_are_answered_in_order() {
    const LINES: u32 = 250;
    let daemon = spawn_daemon_ssh().await;
    let client = connect(daemon.ssh).await;
    let screen = type_burst(&client, "", LINES, false).await;
    assert!(
        !screen.contains("environment launch denied or expired")
            && !screen.contains("workspace session failed"),
        "the session failed: {}",
        &screen[screen.len().saturating_sub(400)..]
    );
    assert_eq!(answers(&screen), (1..=LINES).collect::<Vec<_>>());
    let _ = daemon.shutdown.send(true);
}

#[cfg(target_os = "linux")]
mod process_lifetime {
    use super::*;

    /// A TCP relay in front of `target` for one connection; aborting it
    /// closes both sides, as a killed client does.
    async fn relay(target: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut server = tokio::net::TcpStream::connect(target).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        });
        (addr, task)
    }

    /// Running and not a zombie.
    fn alive(pid: i32) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let state = stat.rsplit_once(") ")?.1.chars().next()?;
                Some(state != 'Z' && state != 'X')
            })
            .unwrap_or(false)
    }

    async fn read_pid(path: &Path) -> i32 {
        timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(text) = fs::read_to_string(path)
                    && let Ok(pid) = text.trim().parse()
                {
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{} was not written", path.display()))
    }

    async fn gone_within(pid: i32, limit: Duration) -> bool {
        timeout(limit, async {
            while alive(pid) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok()
    }

    fn kill(pid: i32) {
        // SAFETY: kill takes no pointers; a stale pid only fails with ESRCH.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }

    /// The command line: the shell itself, a job in its process group, and
    /// a job that left the group with `setsid`; each writes its pid.
    fn three_processes(dir: &Path) -> String {
        let dir = dir.display();
        format!(
            "echo $$ > '{dir}/leader.pid'; \
             sleep 600 & echo $! > '{dir}/member.pid'; \
             setsid sh -c 'echo $$ > \"$1\"; exec sleep 600' sh '{dir}/detached.pid' \
               </dev/null >/dev/null 2>&1 & \
             wait"
        )
    }

    /// Killing the client ends the command and everything in its process
    /// group within seconds, but not what deliberately left the group.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vanished_client_ends_its_command_and_process_group() {
        let daemon = spawn_daemon_ssh().await;
        let (relay, relay_task) = relay(daemon.ssh).await;
        let client = connect(relay).await;
        let channel = client.channel_open_session().await.unwrap();
        let dir = daemon.workspace_root.clone();
        channel
            .exec(true, three_processes(&dir).into_bytes())
            .await
            .unwrap();
        channel.data_bytes(b"unread input".to_vec()).await.unwrap();
        let leader = read_pid(&dir.join("leader.pid")).await;
        let member = read_pid(&dir.join("member.pid")).await;
        let detached = read_pid(&dir.join("detached.pid")).await;
        assert!(alive(leader) && alive(member) && alive(detached));

        relay_task.abort();
        let ended = gone_within(leader, Duration::from_secs(10)).await
            && gone_within(member, Duration::from_secs(10)).await;
        let survived = alive(detached);
        kill(detached);
        kill(member);
        kill(leader);
        assert!(
            ended,
            "the command or its process group outlived the client"
        );
        assert!(
            survived,
            "a process that left the group with setsid was ended"
        );
        let _ = daemon.shutdown.send(true);
    }

    /// A client that sent EOF and then closed its channel ends a command that
    /// ignores stdin, and the connection keeps serving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_the_channel_after_eof_ends_the_command() {
        let daemon = spawn_daemon_ssh().await;
        let client = connect(daemon.ssh).await;
        let channel = client.channel_open_session().await.unwrap();
        let pid_file = daemon.workspace_root.join("sleeper.pid");
        channel
            .exec(
                true,
                format!("echo $$ > '{}'; exec sleep 600", pid_file.display()).into_bytes(),
            )
            .await
            .unwrap();
        channel.eof().await.unwrap();
        let sleeper = read_pid(&pid_file).await;
        channel.close().await.unwrap();
        let ended = gone_within(sleeper, Duration::from_secs(10)).await;
        kill(sleeper);
        assert!(ended, "the command outlived its closed channel");

        let (stdout, _, exit) =
            exec_within(&client, "printf still-serving", Duration::from_secs(20)).await;
        assert_eq!((stdout.as_str(), exit), ("still-serving", Some(0)));
        let _ = daemon.shutdown.send(true);
    }
}

// #3827: `session@codewire.sh` attaches to a durable daemon session over the
// environment's own SSH server, with the API's public attach messages.
mod session_attach {
    use codewire_client::session_wire::{FrameDecoder, SESSION_SUBSYSTEM, encode_frame};
    use codewire_client::{
        AttachSessionOpen, AttachSessionRequest, AttachSessionResponse, attach_session_request,
        attach_session_response,
    };
    use codewire_daemon_proto::daemon::v1;
    use russh::{ChannelMsg, client};
    use tokio::time::timeout;

    use super::*;

    /// A shell session that prints `hello` and then echoes its input raw.
    async fn launch_echo(daemon: &DaemonSsh) -> String {
        daemon
            .sessions
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "stty raw -echo; printf hello; exec cat".into(),
                ],
                pty: true,
                term: "xterm-256color".into(),
                width: 80,
                height: 24,
                ..Default::default()
            })
            .await
            .unwrap()
            .session_id
    }

    struct Attached {
        // Kept so the connection outlives the attachment.
        _client: client::Handle<AcceptAllKeys>,
        channel: russh::Channel<client::Msg>,
        frames: FrameDecoder,
        output: Vec<u8>,
        first_offset: Option<u64>,
        next_offset: u64,
    }

    enum Ended {
        Exit { status: u32, stderr: String },
    }

    async fn attach(
        daemon: &DaemonSsh,
        environment_id: &str,
        session_id: &str,
        offset: u64,
    ) -> Attached {
        let client = connect(daemon.ssh).await;
        let channel = client.channel_open_session().await.unwrap();
        channel
            .request_subsystem(true, SESSION_SUBSYSTEM)
            .await
            .unwrap();
        let open = AttachSessionRequest {
            input: Some(attach_session_request::Input::Open(Box::new(
                AttachSessionOpen {
                    org_id: "org-synthetic".into(),
                    environment_id: environment_id.into(),
                    session_id: session_id.into(),
                    output_offset: offset,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        };
        channel
            .data(&encode_frame(&open).unwrap()[..])
            .await
            .unwrap();
        Attached {
            _client: client,
            channel,
            frames: FrameDecoder::default(),
            output: Vec::new(),
            first_offset: None,
            next_offset: offset,
        }
    }

    impl Attached {
        async fn send(&self, input: attach_session_request::Input) {
            let request = AttachSessionRequest {
                input: Some(input),
                ..Default::default()
            };
            self.channel
                .data(&encode_frame(&request).unwrap()[..])
                .await
                .unwrap();
        }

        /// Read until the output so far contains `needle`.
        async fn read_until(&mut self, needle: &[u8]) {
            timeout(Duration::from_secs(20), async {
                while !self.output.windows(needle.len()).any(|w| w == needle) {
                    if let Some(response) =
                        self.frames.next_message::<AttachSessionResponse>().unwrap()
                    {
                        if let Some(attach_session_response::Event::Output(chunk)) = response.event
                        {
                            self.first_offset.get_or_insert(chunk.offset);
                            assert_eq!(chunk.offset, self.next_offset, "output is contiguous");
                            self.next_offset = chunk.next_offset;
                            self.output.extend_from_slice(&chunk.data);
                        }
                        continue;
                    }
                    match self.channel.wait().await {
                        Some(ChannelMsg::Data { data }) => self.frames.push(&data),
                        Some(
                            ended @ (ChannelMsg::Eof
                            | ChannelMsg::Close
                            | ChannelMsg::ExitStatus { .. }
                            | ChannelMsg::ExtendedData { .. }
                            | ChannelMsg::Failure),
                        ) => panic!("attachment ended early: {ended:?}"),
                        // The subsystem request's reply and flow control.
                        Some(_) => {}
                        None => panic!("attachment closed early"),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{:?} never arrived; output so far {:?}",
                    String::from_utf8_lossy(needle),
                    String::from_utf8_lossy(&self.output)
                )
            });
        }

        async fn ended(mut self) -> Ended {
            let mut stderr = Vec::new();
            let mut status = None;
            timeout(Duration::from_secs(20), async {
                while let Some(message) = self.channel.wait().await {
                    match message {
                        ChannelMsg::ExtendedData { data, ext: 1 } => {
                            stderr.extend_from_slice(&data)
                        }
                        ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                        ChannelMsg::Close => break,
                        _ => {}
                    }
                }
            })
            .await
            .expect("the attachment ended");
            Ended::Exit {
                status: status.expect("an exit status"),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            }
        }
    }

    async fn assert_running(daemon: &DaemonSsh, session_id: &str) {
        let record = daemon.sessions.get(session_id).await.unwrap();
        assert_eq!(
            v1::SessionLifecycleState::try_from(record.state),
            Ok(v1::SessionLifecycleState::Running),
            "{record:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_attachment_carries_output_and_input_and_closing_it_leaves_the_session_running() {
        let daemon = spawn_daemon_ssh().await;
        let session = launch_echo(&daemon).await;
        let mut attached = attach(&daemon, ENVIRONMENT_ID, &session, 0).await;
        attached.read_until(b"hello").await;
        assert_eq!(attached.first_offset, Some(0));
        attached
            .send(attach_session_request::Input::Stdin(b"ping".to_vec()))
            .await;
        attached.read_until(b"ping").await;
        attached.channel.close().await.unwrap();
        drop(attached);
        assert_running(&daemon, &session).await;
        let _ = daemon.shutdown.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reattachment_from_an_offset_gets_only_what_it_missed() {
        let daemon = spawn_daemon_ssh().await;
        let session = launch_echo(&daemon).await;
        let mut first = attach(&daemon, ENVIRONMENT_ID, &session, 0).await;
        first.read_until(b"hello").await;
        let resume_at = first.next_offset;
        first.channel.close().await.unwrap();
        drop(first);

        // Output produced while nobody is attached.
        daemon
            .sessions
            .send_input(&session, b"while-away".to_vec())
            .await
            .unwrap();
        let mut again = attach(&daemon, ENVIRONMENT_ID, &session, resume_at).await;
        again.read_until(b"while-away").await;
        assert_eq!(again.first_offset, Some(resume_at));
        assert!(
            !again.output.windows(5).any(|w| w == b"hello"),
            "a reattachment replays only what it missed"
        );
        let _ = daemon.shutdown.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_attachments_see_the_same_session() {
        let daemon = spawn_daemon_ssh().await;
        let session = launch_echo(&daemon).await;
        let mut laptop = attach(&daemon, ENVIRONMENT_ID, &session, 0).await;
        let mut phone = attach(&daemon, ENVIRONMENT_ID, &session, 0).await;
        laptop.read_until(b"hello").await;
        phone.read_until(b"hello").await;
        phone
            .send(attach_session_request::Input::Stdin(
                b"from-the-phone".to_vec(),
            ))
            .await;
        laptop.read_until(b"from-the-phone").await;
        phone.read_until(b"from-the-phone").await;
        let _ = daemon.shutdown.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_environment_or_an_unknown_session_is_refused_with_a_reason() {
        let daemon = spawn_daemon_ssh().await;
        let session = launch_echo(&daemon).await;

        let elsewhere = attach(&daemon, "99999999-2222-4333-8444-555555555555", &session, 0).await;
        let Ended::Exit { status, stderr } = elsewhere.ended().await;
        assert_eq!(status, 1);
        assert!(stderr.contains("serves environment"), "{stderr}");

        let unknown = attach(
            &daemon,
            ENVIRONMENT_ID,
            "session-00000000-0000-4000-8000-000000000000",
            0,
        )
        .await;
        let Ended::Exit { status, stderr } = unknown.ended().await;
        assert_eq!(status, 1);
        assert!(!stderr.trim().is_empty(), "the refusal says why");
        assert_running(&daemon, &session).await;
        let _ = daemon.shutdown.send(true);
    }
}
