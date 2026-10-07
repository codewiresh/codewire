//! Linux component proof, NOT Local/Hosted placement or initial-checkout proof.
//! All keys are newly generated; every stock child has a closed environment and
//! explicit config, trust and agent paths. Default scp exercises SFTP, not -O.

use std::collections::HashMap;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_credential_bridge::{CredentialBridge, serve_ssh_agent};
use codewire_credential_broker::ssh_agent::{SelectedSshAgent, SshAgentConfig, SshAgentOwner};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::ssh::{SshOperation, agent, remaining_deadline, validate_request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;
use zeroize::Zeroizing;

#[path = "stock_credentials/server.rs"]
mod server;

const LIMIT: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

async fn complete<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(COMMAND_TIMEOUT, future)
        .await
        .expect("bounded synthetic stock-client operation")
}

fn fresh_key() -> ssh_key::PrivateKey {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
        &signing.to_bytes(),
    ))
}

fn clean_command(program: &str, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("TMPDIR", home)
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    command
}

// Reserve the exact process group until kill has been issued, then reap. This
// also covers scp/Git's SSH descendants; inherited output EOF is drained below.
struct OwnedChild {
    child: Child,
    group: Option<i32>,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> Self {
        let child = command.spawn().expect("fixed stock executable");
        let group = Some(i32::try_from(child.id().unwrap()).unwrap());
        Self { child, group }
    }

    async fn exited(&self) {
        loop {
            let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: valid writable siginfo; this unreaped direct child is
            // owned here. WNOWAIT retains its PID/group against numeric reuse.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.group.unwrap() as libc::id_t,
                    status.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            assert_eq!(result, 0, "observe exact stock child exit");
            // SAFETY: successful waitid initialized status (zero PID if live).
            if unsafe { status.assume_init().si_pid() } != 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn kill_group(&self) {
        if let Some(group) = self.group {
            // SAFETY: spawn created this private group; its leader is unreaped.
            let result = unsafe { libc::kill(-group, libc::SIGKILL) };
            assert!(
                result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            );
        }
    }

    async fn finish(&mut self) -> ExitStatus {
        self.kill_group();
        let result = complete(self.child.wait()).await.unwrap();
        self.group = None;
        result
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Best-effort panic/timeout guard; normal proof requires finish + EOF.
        if let Some(group) = self.group {
            // SAFETY: the owned, unreaped leader still reserves this group.
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
    }
}

async fn limited(reader: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > LIMIT {
        return Err(std::io::Error::other("synthetic output limit"));
    }
    Ok(bytes)
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run(mut command: Command, input: &[u8]) -> Output {
    let mut owned = OwnedChild::spawn(&mut command);
    let mut stdin = owned.child.stdin.take().unwrap();
    let stdout = tokio::spawn(limited(owned.child.stdout.take().unwrap()));
    let stderr = tokio::spawn(limited(owned.child.stderr.take().unwrap()));
    let result = tokio::time::timeout(COMMAND_TIMEOUT, async {
        stdin.write_all(input).await?;
        stdin.shutdown().await?;
        drop(stdin);
        owned.exited().await;
        Ok::<_, std::io::Error>(())
    })
    .await;
    let status = owned.finish().await;
    // Attempt both exact pipe drains before asserting either result.
    let stdout = tokio::time::timeout(COMMAND_TIMEOUT, stdout).await;
    let stderr = tokio::time::timeout(COMMAND_TIMEOUT, stderr).await;
    let stdout = stdout.unwrap().unwrap().unwrap();
    let stderr = stderr.unwrap().unwrap().unwrap();
    assert!(
        matches!(result, Ok(Ok(()))),
        "stock command input/deadline, synthetic stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    Output {
        status,
        stdout,
        stderr,
    }
}

fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "stock command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

// TaskTracker retains lifetime; this guard additionally makes worker panic an
// observed test failure instead of silently treating task completion as success.
struct WorkerGuard(Arc<AtomicBool>, bool);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if !self.1 {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}
fn tracked(
    tasks: &TaskTracker,
    failed: Arc<AtomicBool>,
    future: impl Future<Output = ()> + Send + 'static,
) {
    tasks.spawn(async move {
        let mut guard = WorkerGuard(failed, false);
        future.await;
        guard.1 = true;
    });
}

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    runtime: PathBuf,
    socket: PathBuf,
    pins: PathBuf,
    repository: PathBuf,
    address: std::net::SocketAddr,
    owner: SshAgentOwner,
    selected: Arc<SelectedSshAgent>,
    bridge: CredentialBridge,
    stop: CancellationToken,
    disconnect: CancellationToken,
    disconnected: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    workers: TaskTracker,
    failed: Arc<AtomicBool>,
    expected: Arc<Mutex<ssh_key::PublicKey>>,
    authenticated: Arc<AtomicUsize>,
    signatures: Arc<AtomicUsize>,
    revoked: Arc<AtomicBool>,
    files: server::Files,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("cw-stock-")
            .tempdir_in("/dev/shm")
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.path().join("home");
        let runtime = root.path().join("runtime");
        let repository = root.path().join("repository");
        for path in [&home, &runtime, &repository] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../codewire-credential-broker/src/ssh_agent/askpass.sh")
            .canonicalize()
            .unwrap();
        let key = fresh_key();
        let expected = Arc::new(Mutex::new(key.public_key().clone()));
        let owner = SshAgentOwner::new(
            SshAgentConfig::new(
                runtime.clone(),
                "/usr/bin/ssh-agent".into(),
                "/usr/bin/ssh-add".into(),
                helper,
            )
            .unwrap(),
        );
        let pending = owner
            .start(
                Zeroizing::new(
                    key.to_openssh(ssh_key::LineEnding::LF)
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                ),
                None,
                tokio::time::Instant::now() + Duration::from_secs(180),
            )
            .unwrap();
        let drain = pending.drain_handle();
        let ready = complete(pending.ready()).await;
        if ready.is_err() {
            drain.cancel_and_drain().await.unwrap();
            owner.shutdown().await.unwrap();
        }
        let selected = Arc::new(ready.unwrap());
        assert_eq!(
            selected.public_identity().key_blob(),
            key.public_key().to_bytes().unwrap()
        );
        drop(key);

        let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
        let stop = CancellationToken::new();
        let disconnect = CancellationToken::new();
        let disconnected = CancellationToken::new();
        let workers = TaskTracker::new();
        let failed = Arc::new(AtomicBool::new(false));
        let authenticated = Arc::new(AtomicUsize::new(0));
        let signatures = Arc::new(AtomicUsize::new(0));
        let revoked = Arc::new(AtomicBool::new(false));
        let files = server::Files::default();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        let (input, receiver) = mpsc::channel(4);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        let done = disconnected.clone();
        let disconnected_signal = disconnect.clone();
        let driver = tokio::spawn(async move {
            connection
                .run_until(disconnected_signal.cancelled_owned())
                .await;
            done.cancel();
        });
        let signing = selected.clone();
        let revoked_state = revoked.clone();
        let count = signatures.clone();
        let host_stop = stop.clone();
        let host = tokio::spawn(async move {
            loop {
                let frame = tokio::select! {
                    biased;
                    () = host_stop.cancelled() => break,
                    frame = output.next() => match frame { Some(Ok(frame)) => frame, None => break, _ => panic!("synthetic bridge frame") },
                };
                let request = match frame.payload {
                    Some(v1::credential_bridge_guest_message::Payload::Ssh(request)) => request,
                    Some(v1::credential_bridge_guest_message::Payload::Cancel(_)) => continue,
                    _ => panic!("unexpected synthetic bridge operation"),
                };
                let kind = validate_request(&request).unwrap();
                let denied = v1::credential_ssh_response::Result::Failure(
                    v1::CredentialBridgeFailureReason::Denied as i32,
                );
                let mut result = denied.clone();
                if !revoked_state.load(Ordering::SeqCst) {
                    let wire = agent::encode_request(request.operation.as_ref().unwrap()).unwrap();
                    // Retain and finish the actual owner request even if its
                    // bridge waiter is cancelled; no remote-drain claim here.
                    if let Ok(response) = signing.request(&wire).await {
                        result = agent::decode_response(&response, kind).unwrap();
                        if kind == SshOperation::Sign {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                if revoked_state.load(Ordering::SeqCst)
                    || remaining_deadline(request.deadline_unix_ms).is_err()
                {
                    result = denied;
                }
                if input
                    .send(Ok(v1::CredentialBridgeHostMessage {
                        payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                            v1::CredentialSshResponse {
                                request_id: request.request_id,
                                result: Some(result),
                            },
                        )),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let socket = root.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let relay = bridge.clone();
        let relay_stop = stop.clone();
        let agent_task = tokio::spawn(async move {
            loop {
                let (stream, _) = tokio::select! {
                    biased;
                    () = relay_stop.cancelled() => break,
                    stream = listener.accept() => stream.unwrap(),
                };
                let _ = serve_ssh_agent(&relay, stream, relay_stop.cancelled()).await;
            }
        });
        let host_key = fresh_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pins = root.path().join("known_hosts");
        std::fs::write(
            &pins,
            format!(
                "[127.0.0.1]:{} {}\n",
                address.port(),
                host_key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(COMMAND_TIMEOUT),
            ..Default::default()
        });
        let peer_stop = stop.clone();
        let peer_expected = expected.clone();
        let peer_authenticated = authenticated.clone();
        let peer_files = files.clone();
        let peer_repository = repository.clone();
        let peer_home = home.clone();
        let peer_workers = workers.clone();
        let peer_failed = failed.clone();
        let server = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = peer_stop.cancelled() => break,
                    result = sessions.join_next(), if !sessions.is_empty() => { result.unwrap().unwrap(); },
                    stream = listener.accept() => {
                        let (stream, _) = stream.unwrap();
                        let handler = server::Peer { expected: peer_expected.clone(), authenticated: peer_authenticated.clone(), files: peer_files.clone(), repository: peer_repository.clone(), home: peer_home.clone(), stop: peer_stop.clone(), tasks: peer_workers.clone(), failed: peer_failed.clone(), channels: HashMap::new() };
                        let config = config.clone();
                        let stop = peer_stop.clone();
                        sessions.spawn(async move {
                            let connected = tokio::time::timeout(COMMAND_TIMEOUT, russh::server::run_stream(config, stream, handler)).await;
                            // Host-key rejection deliberately terminates KEX.
                            let Ok(Ok(mut session)) = connected else { return; };
                            tokio::select! {
                                biased;
                                () = stop.cancelled() => {
                                    let _ = session.handle().disconnect(russh::Disconnect::ByApplication, "synthetic shutdown".into(), "en".into()).await;
                                    let _ = complete(session).await;
                                },
                                _ = &mut session => {},
                            }
                        });
                    },
                }
            }
            while let Some(result) = complete(sessions.join_next()).await {
                result.unwrap();
            }
        });
        Self {
            _root: root,
            home,
            runtime,
            socket,
            pins,
            repository,
            address,
            owner,
            selected,
            bridge,
            stop,
            disconnect,
            disconnected,
            tasks: vec![driver, host, agent_task, server],
            workers,
            failed,
            expected,
            authenticated,
            signatures,
            revoked,
            files,
        }
    }

    fn ssh_options(&self, pins: &Path) -> Vec<String> {
        let options = [
            format!("Port={}", self.address.port()),
            format!("HostKeyAlias=[127.0.0.1]:{}", self.address.port()),
            format!("IdentityAgent={}", self.socket.display()),
            format!("UserKnownHostsFile={}", pins.display()),
            "GlobalKnownHostsFile=/dev/null".into(),
            "IdentityFile=none".into(),
            "IdentitiesOnly=no".into(),
            "StrictHostKeyChecking=yes".into(),
            "BatchMode=yes".into(),
            "PreferredAuthentications=publickey".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "GSSAPIAuthentication=no".into(),
            "HostbasedAuthentication=no".into(),
            "ForwardAgent=no".into(),
            "ClearAllForwardings=yes".into(),
            "ControlMaster=no".into(),
            "ControlPath=none".into(),
            "ControlPersist=no".into(),
            "ForkAfterAuthentication=no".into(),
            "ProxyCommand=none".into(),
            "ProxyJump=none".into(),
            "RequestTTY=no".into(),
            "PubkeyAcceptedAlgorithms=ssh-ed25519".into(),
        ];
        let mut args = vec!["-F".into(), "/dev/null".into()];
        for option in options {
            args.extend(["-o".into(), option]);
        }
        args
    }

    fn stock(&self, program: &str, pins: &Path) -> Command {
        let mut command = clean_command(program, &self.home);
        command.args(self.ssh_options(pins));
        command
    }

    async fn denied(&self, pins: &Path) {
        let signed = self.signatures.load(Ordering::SeqCst);
        let authenticated = self.authenticated.load(Ordering::SeqCst);
        let mut command = self.stock("/usr/bin/ssh", pins);
        command.args(["synthetic@127.0.0.1", "synthetic-exec"]);
        assert!(!run(command, b"").await.status.success());
        assert_eq!(self.signatures.load(Ordering::SeqCst), signed);
        assert_eq!(self.authenticated.load(Ordering::SeqCst), authenticated);
    }

    async fn finish(mut self, preserve_after_panic: bool) {
        self.stop.cancel();
        self.disconnect.cancel();
        let deadline = tokio::time::Instant::now() + COMMAND_TIMEOUT;
        let mut tasks_drained = true;
        for mut task in self.tasks.drain(..) {
            // An abnormal task must not skip the remaining tasks or actual
            // selected-agent cleanup. A timeout keeps its staging intact.
            tasks_drained &= matches!(
                tokio::time::timeout_at(deadline, &mut task).await,
                Ok(Ok(()))
            );
        }
        self.workers.close();
        let workers_drained = tokio::time::timeout_at(deadline, self.workers.wait())
            .await
            .is_ok();
        let drain = self.selected.drain_handle();
        let selected_drained = matches!(
            tokio::time::timeout(COMMAND_TIMEOUT, drain.cancel_and_drain()).await,
            Ok(Ok(()))
        );
        let owner_drained = matches!(
            tokio::time::timeout(COMMAND_TIMEOUT, self.owner.shutdown()).await,
            Ok(Ok(()))
        );
        let workers_clean = !self.failed.load(Ordering::SeqCst);
        let runtime_empty =
            std::fs::read_dir(&self.runtime).is_ok_and(|mut entries| entries.next().is_none());
        let drained = tasks_drained
            && workers_drained
            && selected_drained
            && owner_drained
            && workers_clean
            && runtime_empty;
        let socket_removed = drained && std::fs::remove_file(&self.socket).is_ok();
        // A command/worker panic may have interrupted its own drain proof.
        // Preserve only this exact synthetic root, never delete under a writer.
        let retained = if preserve_after_panic || !socket_removed {
            Some(self._root.keep())
        } else {
            None
        };
        assert!(
            socket_removed,
            "synthetic cleanup unproven: tasks={tasks_drained} workers={workers_drained} selected={selected_drained} owner={owner_drained} clean={workers_clean} empty={runtime_empty}; retained={retained:?}"
        );
    }
}

async fn journey(fixture: &Fixture) {
    let mut init = clean_command("/usr/bin/git", &fixture.home);
    init.args(["init", "--initial-branch=main"])
        .arg(&fixture.repository);
    success(run(init, b"").await);
    let content = b"fresh selected-agent repository tree\n";
    std::fs::write(fixture.repository.join("proof.txt"), content).unwrap();
    for args in [
        vec!["add", "proof.txt"],
        vec![
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "-m",
            "synthetic",
        ],
    ] {
        let mut command = clean_command("/usr/bin/git", &fixture.home);
        command.arg("-C").arg(&fixture.repository).args(args);
        success(run(command, b"").await);
    }
    let mut revision = clean_command("/usr/bin/git", &fixture.home);
    revision
        .arg("-C")
        .arg(&fixture.repository)
        .args(["rev-parse", "HEAD"]);
    let expected_revision = success(run(revision, b"").await);

    let mut command = fixture.stock("/usr/bin/ssh", &fixture.pins);
    command.args(["synthetic@127.0.0.1", "synthetic-exec"]);
    let output = run(command, b"").await;
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"selected-agent-exec\n");

    let bytes = b"\0synthetic\xfffile\nwith\0binary";
    let upload = fixture.home.join("upload.bin");
    let download = fixture.home.join("download.bin");
    std::fs::write(&upload, bytes).unwrap();
    let mut scp = fixture.stock("/usr/bin/scp", &fixture.pins);
    scp.arg(&upload).arg("synthetic@127.0.0.1:/scp.bin");
    success(run(scp, b"").await);
    assert_eq!(fixture.files.bytes("/scp.bin"), bytes);
    let mut scp = fixture.stock("/usr/bin/scp", &fixture.pins);
    scp.arg("synthetic@127.0.0.1:/scp.bin").arg(&download);
    success(run(scp, b"").await);
    assert_eq!(std::fs::read(&download).unwrap(), bytes);
    let sftp_download = fixture.home.join("sftp-download.bin");
    let mut sftp = fixture.stock("/usr/bin/sftp", &fixture.pins);
    sftp.args(["-b", "-", "synthetic@127.0.0.1"]);
    success(
        run(
            sftp,
            format!(
                "put {} /sftp.bin\nget /sftp.bin {}\n",
                upload.display(),
                sftp_download.display()
            )
            .as_bytes(),
        )
        .await,
    );
    assert_eq!(fixture.files.bytes("/sftp.bin"), bytes);
    assert_eq!(std::fs::read(sftp_download).unwrap(), bytes);

    let clone = fixture.home.join("clone");
    let ssh_command = std::iter::once("/usr/bin/ssh".to_owned())
        .chain(fixture.ssh_options(&fixture.pins))
        .collect::<Vec<_>>()
        .join(" ");
    // All words are fixed ASCII options or freshly generated safe tmpfs paths.
    assert!(
        !ssh_command
            .bytes()
            .any(|byte| matches!(byte, b'\'' | b'"' | b'`' | b'$' | b';' | b'\n'))
    );
    let mut git = clean_command("/usr/bin/git", &fixture.home);
    git.env("GIT_SSH_VARIANT", "ssh")
        .args(["-c", &format!("core.sshCommand={ssh_command}"), "clone"])
        .arg(format!(
            "ssh://synthetic@127.0.0.1:{}{}",
            fixture.address.port(),
            fixture.repository.display()
        ))
        .arg(&clone);
    success(run(git, b"").await);
    let mut revision = clean_command("/usr/bin/git", &fixture.home);
    revision.arg("-C").arg(&clone).args(["rev-parse", "HEAD"]);
    assert_eq!(success(run(revision, b"").await), expected_revision);
    assert_eq!(std::fs::read(clone.join("proof.txt")).unwrap(), content);
    assert_eq!(fixture.authenticated.load(Ordering::SeqCst), 5);
    assert_eq!(fixture.signatures.load(Ordering::SeqCst), 5);

    let empty_pins = fixture.home.join("unknown-host");
    std::fs::write(&empty_pins, b"").unwrap();
    fixture.denied(&empty_pins).await;
    let wrong_key = fresh_key();
    let bad_pins = fixture.home.join("bad-host");
    std::fs::write(
        &bad_pins,
        format!(
            "[127.0.0.1]:{} {}\n",
            fixture.address.port(),
            wrong_key.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    fixture.denied(&bad_pins).await;
    let selected_key = fixture.expected.lock().unwrap().clone();
    *fixture.expected.lock().unwrap() = wrong_key.public_key().clone();
    fixture.denied(&fixture.pins).await;
    *fixture.expected.lock().unwrap() = selected_key;
    // A direct request naming another public key must also fail at the real
    // selected-agent guard, not merely because the SSH server rejects it.
    let operation = v1::credential_ssh_request::Operation::Sign(v1::CredentialSshSignRequest {
        public_key_blob: wrong_key.public_key().to_bytes().unwrap(),
        data: b"synthetic".to_vec(),
        flags: 0,
    });
    let request = v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string(),
        deadline_unix_ms: (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            + Duration::from_secs(5))
        .as_millis()
        .try_into()
        .unwrap(),
        operation: Some(operation),
    };
    let response = complete(fixture.bridge.relay_ssh(request)).await.unwrap();
    assert_eq!(
        response.result,
        Some(v1::credential_ssh_response::Result::Failure(
            v1::CredentialBridgeFailureReason::Denied as i32
        ))
    );

    fixture.revoked.store(true, Ordering::SeqCst);
    fixture.denied(&fixture.pins).await;
    fixture.revoked.store(false, Ordering::SeqCst);
    fixture.disconnect.cancel();
    complete(fixture.disconnected.cancelled()).await;
    fixture.denied(&fixture.pins).await;
}

#[tokio::test]
async fn stock_credentials_selected_agent_ssh_scp_sftp_git_and_fresh_denials() {
    let fixture = Arc::new(Fixture::new().await);
    let run_fixture = fixture.clone();
    let result = tokio::spawn(async move { journey(&run_fixture).await }).await;
    // Retain the fixture outside the assertion task: all owned workers/agent
    // drain even when an individual stock-client assertion panics.
    Arc::try_unwrap(fixture)
        .ok()
        .unwrap()
        .finish(result.is_err())
        .await;
    if let Err(error) = result {
        std::panic::resume_unwind(error.into_panic());
    }
}
