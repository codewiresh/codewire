//! Owner-operated host-loopback target for initial private checkout acceptance.
//! This example is never installed as a product executable. It receives only a
//! public client key; its freshly generated synthetic host key stays in memory.
//! No caller can choose a listener address, Git command, or repository content.

use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::future::Future;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::{Channel, ChannelId, server};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

type Result<T> = std::result::Result<T, &'static str>;
const CONTENT: &str = "initial-private-checkout-synthetic-v1";
const IO_LIMIT: u64 = 1024 * 1024;
const CHILD_LIMIT: Duration = Duration::from_secs(20);
const DRAIN_LIMIT: Duration = Duration::from_secs(10);

struct Options {
    public_key: PathBuf,
    output: PathBuf,
    lifetime: Duration,
}

impl Options {
    fn parse(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let mut public_key = None;
        let mut output = None;
        let mut lifetime = None;
        while let Some(argument) = arguments.next() {
            let value = arguments.next().ok_or("option requires a value")?;
            match argument.to_str() {
                Some("--public-key-file") if public_key.is_none() => {
                    public_key = Some(value.into())
                }
                Some("--output-dir") if output.is_none() => output = Some(value.into()),
                Some("--timeout-seconds") if lifetime.is_none() => {
                    let seconds = value
                        .to_str()
                        .and_then(|value| value.parse::<u64>().ok())
                        .filter(|value| (1..=1800).contains(value))
                        .ok_or("timeout must be between 1 and 1800 seconds")?;
                    lifetime = Some(Duration::from_secs(seconds));
                }
                _ => return Err("unsupported or repeated fixture option"),
            }
        }
        Ok(Self {
            public_key: public_key.ok_or("--public-key-file is required")?,
            output: output.ok_or("--output-dir is required")?,
            lifetime: lifetime.unwrap_or(Duration::from_secs(300)),
        })
    }
}

#[derive(Default, Serialize)]
struct Counts {
    version: u8,
    authenticated: u64,
    denied: u64,
    unsupported_commands: u64,
}

struct Evidence {
    directory: PathBuf,
    counts: Mutex<Counts>,
}

impl Evidence {
    fn update(&self, update: impl FnOnce(&mut Counts)) -> Result<()> {
        let mut counts = self.counts.lock().map_err(|_| "counter owner failed")?;
        update(&mut counts);
        self.publish("counter.json", &*counts)
    }

    fn publish(&self, name: &str, value: &impl Serialize) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| "cannot create public evidence file")?;
        serde_json::to_writer(file.as_file_mut(), value)
            .map_err(|_| "cannot write public evidence")?;
        file.as_file_mut()
            .write_all(b"\n")
            .map_err(|_| "cannot finish public evidence")?;
        file.as_file()
            .sync_all()
            .map_err(|_| "cannot sync public evidence")?;
        file.persist(self.directory.join(name))
            .map_err(|_| "cannot publish public evidence")?;
        Ok(())
    }
}

fn read_selected_public_key(path: &Path) -> Result<ssh_key::PublicKey> {
    if !path.is_absolute() || fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err("public key path must be absolute and canonical");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot open selected public key")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect selected public key")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("selected public key must be a bounded regular file");
    }
    let mut text = String::new();
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read selected public key")?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    if line.contains(['\n', '\r']) || line.split_whitespace().count() != 2 {
        return Err("selected public key must contain exactly one uncommented OpenSSH key");
    }
    let key =
        ssh_key::PublicKey::from_openssh(line).map_err(|_| "selected public key is invalid")?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("fixture requires the generated Ed25519 public key");
    }
    Ok(key)
}

fn create_output(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or("fixture output requires an owned parent")?;
    if !path.is_absolute()
        || fs::canonicalize(parent).ok().as_deref() != Some(parent)
        || path.file_name().is_none()
    {
        return Err("fixture output must have an absolute canonical parent");
    }
    let metadata = fs::metadata(parent).map_err(|_| "cannot inspect fixture output parent")?;
    // SAFETY: geteuid has no arguments and does not change process state.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("fixture output parent must be owner-only and owned");
    }
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "fixture output must be a new directory")
}

fn git_command(directory: &Path) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "maintenance.autoDetach=false",
            "-c",
            "gc.autoDetach=false",
        ])
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    command
}

// Keep the group leader unreaped until the whole group has been killed. Git's
// pack subprocesses cannot outlive either cancellation or a completed request.
struct OwnedChild {
    child: Child,
    group: Option<i32>,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> Result<Self> {
        let child = command
            .spawn()
            .map_err(|_| "cannot spawn fixed Git process")?;
        let group = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or("cannot identify fixed Git process")?;
        Ok(Self {
            child,
            group: Some(group),
        })
    }

    async fn exited(&self) -> Result<()> {
        loop {
            let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: status is writable, and this unreaped direct child is owned.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.group.ok_or("Git group already reaped")? as u32,
                    status.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                return Err("cannot observe fixed Git process");
            }
            // SAFETY: successful waitid initialized status, with zero PID if live.
            if unsafe { status.assume_init().si_pid() } != 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn kill_group(&self) -> Result<()> {
        if let Some(group) = self.group {
            // SAFETY: the unreaped owned leader reserves this private group ID.
            if unsafe { libc::kill(-group, libc::SIGKILL) } != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err("cannot stop owned Git process group");
            }
        }
        Ok(())
    }

    async fn finish(&mut self) -> Result<ExitStatus> {
        self.kill_group()?;
        let status = tokio::time::timeout(DRAIN_LIMIT, self.child.wait())
            .await
            .map_err(|_| "owned Git process did not drain")?
            .map_err(|_| "cannot reap owned Git process")?;
        self.group = None;
        Ok(status)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.kill_group();
    }
}

async fn bounded_bytes(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(IO_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "cannot drain fixed Git output")?;
    if bytes.len() as u64 > IO_LIMIT {
        return Err("fixed Git output exceeded limit");
    }
    Ok(bytes)
}

async fn run_git(
    directory: &Path,
    arguments: &[&str],
    stop: &CancellationToken,
) -> Result<Vec<u8>> {
    if stop.is_cancelled() {
        return Err("repository preparation cancelled");
    }
    let mut command = git_command(directory);
    command.args(arguments);
    let mut child = OwnedChild::spawn(&mut command)?;
    drop(child.child.stdin.take());
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or("missing fixed Git stdout")?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or("missing fixed Git stderr")?;
    let mut output = tokio::spawn(bounded_bytes(stdout));
    let mut errors = tokio::spawn(bounded_bytes(stderr));
    let observed = tokio::select! {
        biased;
        () = stop.cancelled() => None,
        result = tokio::time::timeout(CHILD_LIMIT, child.exited()) => Some(result),
    };
    let status = child.finish().await?;
    let (output, errors) = tokio::join!(
        tokio::time::timeout(DRAIN_LIMIT, &mut output),
        tokio::time::timeout(DRAIN_LIMIT, &mut errors)
    );
    errors
        .map_err(|_| "fixed Git stderr drain timed out")?
        .map_err(|_| "fixed Git stderr drain task failed")??;
    let output = output
        .map_err(|_| "fixed Git stdout drain timed out")?
        .map_err(|_| "fixed Git stdout drain task failed")??;
    if stop.is_cancelled() {
        return Err("repository preparation cancelled");
    }
    if !matches!(observed, Some(Ok(Ok(())))) || !status.success() {
        return Err("fixed Git repository preparation failed");
    }
    Ok(output)
}

async fn prepare_repository(directory: &Path, stop: &CancellationToken) -> Result<String> {
    run_git(
        directory,
        &["init", "--quiet", "--initial-branch=main", "source"],
        stop,
    )
    .await?;
    fs::write(directory.join("source/proof.txt"), format!("{CONTENT}\n"))
        .map_err(|_| "cannot write synthetic repository content")?;
    run_git(directory, &["-C", "source", "add", "proof.txt"], stop).await?;
    run_git(
        directory,
        &[
            "-C",
            "source",
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "synthetic",
        ],
        stop,
    )
    .await?;
    run_git(
        directory,
        &["clone", "--quiet", "--bare", "source", "repository.git"],
        stop,
    )
    .await?;
    let revision = run_git(
        directory,
        &["--git-dir=repository.git", "rev-parse", "HEAD"],
        stop,
    )
    .await?;
    let revision =
        String::from_utf8(revision).map_err(|_| "invalid synthetic repository revision")?;
    let revision = revision.trim();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid synthetic repository revision");
    }
    Ok(revision.to_owned())
}

// Cancellation reaches the actual transport owned by Russh's internal task.
// Dropping a RunningSession handle alone does not prove that task has stopped.
struct StopStream<S> {
    stream: S,
    stopped: Pin<Box<dyn Future<Output = ()> + Send>>,
    received: u64,
    sent: u64,
}

impl<S: AsyncRead + Unpin> AsyncRead for StopStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stopped.as_mut().poll(context).is_ready() {
            return Poll::Ready(Ok(()));
        }
        if self.received >= IO_LIMIT * 4 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        self.received += (buffer.filled().len() - before) as u64;
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StopStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stopped.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.sent >= IO_LIMIT * 4 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        let result = Pin::new(&mut self.stream).poll_write(context, bytes);
        if let Poll::Ready(Ok(written)) = result {
            self.sent += written as u64;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct Peer {
    expected: Arc<ssh_key::PublicKey>,
    evidence: Arc<Evidence>,
    repository_root: PathBuf,
    stop: CancellationToken,
    failed: CancellationToken,
    workers: TaskTracker,
    failures: Arc<Mutex<Vec<&'static str>>>,
    channels: HashMap<ChannelId, Channel<server::Msg>>,
    admitted: bool,
}

struct WorkerCompletion {
    failed: CancellationToken,
    failures: Arc<Mutex<Vec<&'static str>>>,
    complete: bool,
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        if !self.complete {
            if let Ok(mut failures) = self.failures.lock() {
                failures.push("upload-pack worker did not finish");
            }
            self.failed.cancel();
        }
    }
}

impl Peer {
    fn count(&self, update: impl FnOnce(&mut Counts)) -> std::result::Result<(), russh::Error> {
        self.evidence.update(update).map_err(|message| {
            self.failed.cancel();
            io::Error::other(message).into()
        })
    }
}

impl server::Handler for Peer {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> std::result::Result<server::Auth, Self::Error> {
        if user == "synthetic" && offer.public_key == self.expected.as_ref() {
            Ok(server::Auth::Accept)
        } else {
            self.count(|count| count.denied += 1)?;
            Ok(server::Auth::reject())
        }
    }

    // Russh invokes this only after checking the client signature.
    async fn auth_publickey(
        &mut self,
        user: &str,
        verified: server::VerifiedPublicKey<'_>,
    ) -> std::result::Result<server::Auth, Self::Error> {
        if user == "synthetic" && verified.public_key == self.expected.as_ref() {
            self.count(|count| count.authenticated += 1)?;
            Ok(server::Auth::Accept)
        } else {
            self.count(|count| count.denied += 1)?;
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.admitted || !self.channels.is_empty() {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.admitted || command != b"git-upload-pack '/repository.git'" {
            self.count(|count| count.unsupported_commands += 1)?;
            session.channel_failure(id)?;
            return Ok(());
        }
        self.admitted = true;
        let Some(channel) = self.channels.remove(&id) else {
            return Ok(());
        };
        session.channel_success(id)?;
        let root = self.repository_root.clone();
        let stop = self.stop.clone();
        let failures = self.failures.clone();
        let failed = self.failed.clone();
        self.workers.spawn(async move {
            let mut completion = WorkerCompletion {
                failed: failed.clone(),
                failures: failures.clone(),
                complete: false,
            };
            if let Err(message) = upload_pack(channel, &root, &stop).await {
                if let Ok(mut failures) = failures.lock() {
                    failures.push(message);
                }
                failed.cancel();
            }
            completion.complete = true;
        });
        Ok(())
    }
}

async fn upload_pack(
    channel: Channel<server::Msg>,
    root: &Path,
    stop: &CancellationToken,
) -> Result<()> {
    let mut command = git_command(root);
    command.args(["upload-pack", "--strict", "repository.git"]);
    let mut child = OwnedChild::spawn(&mut command)?;
    let mut input = child
        .child
        .stdin
        .take()
        .ok_or("missing upload-pack stdin")?;
    let mut output = child
        .child
        .stdout
        .take()
        .ok_or("missing upload-pack stdout")?
        .take(IO_LIMIT + 1);
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or("missing upload-pack stderr")?;
    let mut errors = tokio::spawn(bounded_bytes(stderr));
    let (mut read, write) = channel.split();
    let mut reader = read.make_reader().take(IO_LIMIT + 1);
    let mut writer = write.make_writer();
    let transfer = {
        let to_git = async {
            let count = tokio::io::copy(&mut reader, &mut input)
                .await
                .map_err(|_| "upload-pack input transport failed")?;
            if count > IO_LIMIT {
                return Err("upload-pack input limit exceeded");
            }
            input
                .shutdown()
                .await
                .map_err(|_| "cannot close upload-pack input")
        };
        let from_git = async {
            let count = tokio::io::copy(&mut output, &mut writer)
                .await
                .map_err(|_| "upload-pack output transport failed")?;
            if count > IO_LIMIT {
                return Err("upload-pack output limit exceeded");
            }
            child.exited().await
        };
        tokio::pin!(to_git, from_git);
        let exchange = async {
            tokio::select! {
                result = &mut from_git => result,
                result = &mut to_git => { result?; from_git.await },
            }
        };
        tokio::select! {
            biased;
            () = stop.cancelled() => None,
            result = tokio::time::timeout(CHILD_LIMIT, exchange) => Some(result),
        }
    };
    drop(input);
    let status = child.finish().await?;
    tokio::time::timeout(DRAIN_LIMIT, &mut errors)
        .await
        .map_err(|_| "upload-pack stderr drain timed out")?
        .map_err(|_| "upload-pack stderr task failed")??;
    drop(writer);
    if stop.is_cancelled() {
        return Ok(());
    }
    if !matches!(transfer, Some(Ok(Ok(())))) || !status.success() {
        return Err("fixed upload-pack request failed or exceeded its deadline");
    }
    write
        .exit_status(0)
        .await
        .map_err(|_| "cannot publish upload-pack status")?;
    write
        .eof()
        .await
        .map_err(|_| "cannot finish upload-pack output")?;
    write
        .close()
        .await
        .map_err(|_| "cannot close upload-pack channel")?;
    Ok(())
}

async fn serve(options: Options) -> Result<()> {
    let started = tokio::time::Instant::now();
    let expected = Arc::new(read_selected_public_key(&options.public_key)?);
    create_output(&options.output)?;
    let evidence = Arc::new(Evidence {
        directory: options.output.clone(),
        counts: Mutex::new(Counts {
            version: 1,
            ..Counts::default()
        }),
    });
    let repository = tempfile::Builder::new()
        .prefix("repository-state-")
        .tempdir_in(&options.output)
        .map_err(|_| "cannot create owned synthetic repository state")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "cannot register fixture termination")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "cannot register fixture interruption")?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|_| "cannot register fixture hangup")?;
    let stop = CancellationToken::new();
    let deadline = tokio::time::sleep_until(started + options.lifetime);
    tokio::pin!(deadline);
    let mut early_signal = false;
    let mut early_deadline = false;
    let prepared = {
        let preparation = prepare_repository(repository.path(), &stop);
        tokio::pin!(preparation);
        tokio::select! {
            result = &mut preparation => result,
            _ = terminate.recv() => { early_signal = true; stop.cancel(); preparation.await },
            _ = interrupt.recv() => { early_signal = true; stop.cancel(); preparation.await },
            _ = hangup.recv() => { early_signal = true; stop.cancel(); preparation.await },
            () = &mut deadline => { early_deadline = true; stop.cancel(); preparation.await },
        }
    };
    if early_signal || early_deadline {
        if let Err(message) = prepared
            && message != "repository preparation cancelled"
        {
            return Err(message);
        }
        repository
            .close()
            .map_err(|_| "cannot remove cancelled repository preparation")?;
        evidence.update(|_| {})?;
        evidence.publish("finish.json", &serde_json::json!({
            "version": 1, "drained": true, "authenticated": 0, "denied": 0, "unsupported_commands": 0,
        }))?;
        return if early_signal {
            Ok(())
        } else {
            Err("fixture lifetime expired")
        };
    }
    let revision = prepared?;
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let host_key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
        &signing.to_bytes(),
    ));
    let public_host = host_key
        .public_key()
        .to_openssh()
        .map_err(|_| "cannot encode public host trust")?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "cannot bind host loopback fixture")?;
    let address = listener
        .local_addr()
        .map_err(|_| "cannot inspect bound fixture address")?;
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(CHILD_LIMIT),
        max_auth_attempts: 3,
        maximum_packet_size: 32768,
        window_size: 65536,
        ..Default::default()
    });
    evidence.update(|_| {})?;
    evidence.publish("ready.json", &serde_json::json!({
        "version": 1, "url": format!("ssh://synthetic@127.0.0.1:{}/repository.git", address.port()),
        "known_hosts": [format!("[127.0.0.1]:{} {public_host}", address.port())],
        "revision": revision, "content_path": "proof.txt", "content": CONTENT,
    }))?;
    let workers = TaskTracker::new();
    let failures = Arc::new(Mutex::new(Vec::new()));
    let mut connections = JoinSet::new();
    let mut accepted = 0;
    let outcome = loop {
        tokio::select! {
            biased;
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = hangup.recv() => break Ok(()),
            () = stop.cancelled() => break Err("fixture upload-pack worker failed"),
            () = &mut deadline => break Err("fixture lifetime expired"),
            result = connections.join_next(), if !connections.is_empty() => {
                if result.is_some_and(|result| result.is_err()) { break Err("SSH connection task failed"); }
            },
            stream = listener.accept() => {
                let (stream, _) = match stream { Ok(stream) => stream, Err(_) => break Err("fixture listener failed") };
                accepted += 1;
                if accepted > 64 { break Err("fixture total connection limit exceeded"); }
                if connections.len() >= 4 { drop(stream); continue; }
                let peer_stop = stop.child_token();
                let handler = Peer {
                    expected: expected.clone(), evidence: evidence.clone(), repository_root: repository.path().to_owned(),
                    stop: peer_stop.clone(), workers: workers.clone(), failures: failures.clone(),
                    failed: stop.clone(),
                    channels: HashMap::new(), admitted: false,
                };
                let config = config.clone();
                connections.spawn(async move {
                    let stream = StopStream { stream, stopped: Box::pin(peer_stop.clone().cancelled_owned()), received: 0, sent: 0 };
                    // The wrapped transport makes both handshake and established-session
                    // shutdown observable through their actual awaited task handles.
                    let connected = tokio::time::timeout(CHILD_LIMIT, server::run_stream(config, stream, handler)).await;
                    if let Ok(Ok(mut session)) = connected {
                        tokio::select! {
                            _ = &mut session => {},
                            () = tokio::time::sleep(CHILD_LIMIT) => {
                                peer_stop.cancel();
                                let _ = session.await;
                            },
                        }
                    }
                    peer_stop.cancel();
                });
            },
        }
    };
    drop(listener);
    stop.cancel();
    let drain = async {
        while let Some(result) = connections.join_next().await {
            result.map_err(|_| "SSH connection failed during drain")?;
        }
        workers.close();
        workers.wait().await;
        Ok::<(), &'static str>(())
    };
    tokio::time::timeout(DRAIN_LIMIT + CHILD_LIMIT, drain)
        .await
        .map_err(|_| "fixture shutdown did not drain")??;
    repository
        .close()
        .map_err(|_| "cannot remove owned synthetic repository state")?;
    let counts = evidence.counts.lock().map_err(|_| "counter owner failed")?;
    evidence.publish(
        "finish.json",
        &serde_json::json!({
            "version": 1, "drained": true, "authenticated": counts.authenticated,
            "denied": counts.denied, "unsupported_commands": counts.unsupported_commands,
        }),
    )?;
    let failures = failures
        .lock()
        .map_err(|_| "worker evidence owner failed")?;
    if let Some(message) = failures.first() {
        return Err(message);
    }
    outcome
}

#[tokio::main]
pub(super) async fn main() {
    // Synthetic host-key material must not appear in a core dump.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid immutable rlimit, applying a stricter limit to this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        eprintln!("initial-private-checkout fixture: cannot disable core dumps");
        std::process::exit(1);
    }
    let result = match Options::parse(std::env::args_os().skip(1)) {
        Ok(options) => serve(options).await,
        Err(message) => Err(message),
    };
    if let Err(message) = result {
        // Only fixed stage diagnostics: never print SSH payloads, Git output,
        // key bytes, inherited environment, or third-party error objects.
        eprintln!("initial-private-checkout fixture: {message}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
