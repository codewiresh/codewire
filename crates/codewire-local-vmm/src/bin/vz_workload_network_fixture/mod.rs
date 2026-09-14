//! Fixed production-workspace session proof over admitted progress/daemon FDs.
//! Packet bytes never enter this process. Service facts arrive only from the
//! parent after it authenticates the separate service VM's status protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use codewire_daemon::client::SessionClient;
use codewire_vmm_guest_probe::{NetworkKey, Seed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use uuid::Uuid;
use zeroize::Zeroizing;

#[path = "../vz_production_fixture/common.rs"]
mod common;
#[path = "../vz_production_fixture/session.rs"]
mod session;
#[cfg(test)]
mod tests;
mod workload;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(210);
const WORKLOAD_DEADLINE: Duration = Duration::from_secs(30);
const POWEROFF_DEADLINE: Duration = Duration::from_secs(20);

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

fn options(
    arguments: impl IntoIterator<Item = String>,
) -> Result<(String, BTreeMap<String, String>)> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or_else(invalid)?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        let value = arguments.next().ok_or_else(invalid)?;
        if options.insert(key, value).is_some() {
            return Err(invalid().into());
        }
    }
    Ok((command, options))
}

pub(super) fn entry() -> Result<()> {
    let (command, options) = options(std::env::args().skip(1))?;
    match command.as_str() {
        "seed" => make_seed(options),
        "verify" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async { tokio::time::timeout(DEADLINE, verify(options)).await? }),
        _ => Err(invalid().into()),
    }
}

fn descriptors(options: &BTreeMap<String, String>, keys: &[&str]) -> Result<Vec<RawFd>> {
    let numbers = keys
        .iter()
        .map(|key| {
            let number = common::descriptor(options, key)?;
            if options[*key] != number.to_string() {
                return Err(invalid().into());
            }
            Ok(number)
        })
        .collect::<Result<Vec<_>>>()?;
    if numbers.iter().copied().collect::<BTreeSet<_>>().len() != numbers.len() {
        return Err(invalid().into());
    }
    Ok(numbers)
}

fn strict_file(number: RawFd, writable: bool) -> Result<File> {
    let file = common::private_file(number, writable)?;
    let mode = file.metadata()?.mode() & 0o7777;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if (writable && mode != 0o600)
        || (!writable && !matches!(mode, 0o400 | 0o600))
        || flags < 0
        || flags & (libc::O_APPEND | libc::O_NONBLOCK) != 0
    {
        return Err(invalid().into());
    }
    Ok(file)
}

fn strict_stream(number: RawFd) -> Result<UnixStream> {
    let flags = unsafe { libc::fcntl(number, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR || flags & libc::O_APPEND != 0 {
        return Err(invalid().into());
    }
    common::private_stream(number)
}

fn make_seed(options: BTreeMap<String, String>) -> Result<()> {
    common::exact_keys(
        &options,
        &[
            "--setup-fd",
            "--output-fd",
            "--network-key-fd",
            "--vm-id",
            "--generation",
        ],
    )?;
    let numbers = descriptors(&options, &["--setup-fd", "--output-fd", "--network-key-fd"])?;
    let vm_id = Uuid::parse_str(&options["--vm-id"])?;
    let generation = options["--generation"].parse::<u64>()?;
    if vm_id.is_nil()
        || vm_id.hyphenated().to_string() != options["--vm-id"]
        || generation == 0
        || generation.to_string() != options["--generation"]
    {
        return Err(invalid().into());
    }
    let mut setup = strict_file(numbers[0], false)?;
    let mut output = strict_file(numbers[1], true)?;
    let mut key_output = strict_file(numbers[2], true)?;
    let mut identities = BTreeSet::new();
    for file in [&setup, &output, &key_output] {
        let metadata = file.metadata()?;
        if !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(invalid().into());
        }
    }
    if output.metadata()?.len() != 0 || key_output.metadata()?.len() != 0 {
        return Err(invalid().into());
    }
    let seed = common::seed_from_setup(&mut setup, &options)?;
    let key = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation())?;
    let encoded = Zeroizing::new(seed.encode());
    output.write_all(encoded.as_ref())?;
    key.with_bytes(|bytes| key_output.write_all(bytes))?;
    output.sync_all()?;
    key_output.sync_all()?;
    // No seed, key, token, derived hash or identity is printed.
    Ok(())
}

async fn verify(options: BTreeMap<String, String>) -> Result<()> {
    let keys = ["--progress-fd", "--daemon-fd", "--control-fd", "--seed-fd"];
    common::exact_keys(&options, &keys)?;
    let numbers = descriptors(&options, &keys)?;
    let seed = Arc::new(common::fixture_seed(strict_file(numbers[3], false)?)?);
    verify_session(
        seed,
        strict_stream(numbers[0])?,
        strict_stream(numbers[1])?,
        strict_stream(numbers[2])?,
    )
    .await
}

#[derive(Clone, Default)]
struct Facts {
    progress_started: bool,
    daemon_started: bool,
    service_ready: bool,
    endpoint_completed: bool,
    progress_ready: bool,
    daemon_ready: bool,
    ready_sent: bool,
    session_stopped: bool,
    workload_sent: bool,
    poweroff_requested: bool,
    poweroff_accepted: bool,
    acceptance_sent: bool,
    poweroff_ended: bool,
    parent_finished: bool,
}

impl Facts {
    fn input(&mut self, byte: u8) -> Result<()> {
        match byte {
            b'P' if !self.progress_started => self.progress_started = true,
            b'D' if !self.daemon_started => self.daemon_started = true,
            b'S' if !self.service_ready => self.service_ready = true,
            b'E' if self.service_ready && !self.endpoint_completed => {
                self.endpoint_completed = true
            }
            b'Q' if self.workload_sent && !self.poweroff_requested => {
                self.poweroff_requested = true
            }
            b'F' if self.acceptance_sent && !self.parent_finished => self.parent_finished = true,
            _ => return Err(invalid().into()),
        }
        Ok(())
    }

    fn batch(&mut self, bytes: &[u8]) -> Result<()> {
        // Validate the whole coalesced batch before launching any RPC. For
        // example QF cannot smuggle completion before poweroff acceptance.
        let mut next = self.clone();
        for byte in bytes {
            next.input(*byte)?;
        }
        *self = next;
        Ok(())
    }

    fn pending(&self) -> Option<u8> {
        if self.service_ready && self.progress_ready && self.daemon_ready && !self.ready_sent {
            Some(b'R')
        } else if self.ready_sent
            && self.session_stopped
            && self.endpoint_completed
            && !self.workload_sent
        {
            Some(b'W')
        } else if self.poweroff_accepted && !self.acceptance_sent {
            Some(b'A')
        } else if self.parent_finished && self.poweroff_ended {
            Some(b'C')
        } else {
            None
        }
    }
}

enum Finished {
    Progress(UnixStream),
    Daemon(SessionClient),
    Workload,
    Poweroff,
}

fn retain_daemon_receive_endpoint(stream: &UnixStream) -> io::Result<OwnedFd> {
    // Hyper may perform real SHUT_WR and drop its transport during graceful
    // daemon shutdown. Retain the exact socket's receive endpoint, not a second
    // reader or a replacement transport. Native forwarding remains bounded by
    // its buffers/deadline and must still observe genuine guest EOF. This does
    // not claim trailing bytes were parsed by the application.
    stream.as_fd().try_clone_to_owned()
}

async fn verify_session(
    seed: Arc<Seed>,
    progress: UnixStream,
    daemon: UnixStream,
    control: UnixStream,
) -> Result<()> {
    verify_with_operations(
        seed,
        progress,
        daemon,
        control,
        |client| async move { workload::prove(&client).await },
        |client, seed, sender| async move { workload::poweroff(&client, &seed, sender).await },
    )
    .await
}

async fn verify_with_operations<W, F, P, PF>(
    seed: Arc<Seed>,
    progress: UnixStream,
    daemon: UnixStream,
    control: UnixStream,
    workload: W,
    poweroff: P,
) -> Result<()>
where
    W: FnOnce(SessionClient) -> F + Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
    P: FnOnce(SessionClient, Arc<Seed>, oneshot::Sender<()>) -> PF + Send + 'static,
    PF: Future<Output = Result<()>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let result = run(
        seed, progress, daemon, control, workload, poweroff, &mut tasks,
    )
    .await;
    // Failed control/readiness/RPC never waits for a blocked workload to finish.
    // Only the parent can prove owned VM/process teardown after this failure.
    tokio::time::timeout(Duration::from_secs(1), tasks.shutdown()).await?;
    result
}

async fn run<W, F, P, PF>(
    seed: Arc<Seed>,
    progress: UnixStream,
    daemon: UnixStream,
    control: UnixStream,
    workload: W,
    poweroff: P,
    tasks: &mut JoinSet<Result<Finished>>,
) -> Result<()>
where
    W: FnOnce(SessionClient) -> F + Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
    P: FnOnce(SessionClient, Arc<Seed>, oneshot::Sender<()>) -> PF + Send + 'static,
    PF: Future<Output = Result<()>> + Send + 'static,
{
    let retained_daemon_endpoint = retain_daemon_receive_endpoint(&daemon)?;
    let (mut control_read, mut control_write) = control.into_split();
    let mut facts = Facts::default();
    let mut progress = Some(progress);
    let mut daemon = Some(daemon);
    let mut retained_progress = None;
    let mut retained_daemon: Option<SessionClient> = None;
    let mut workload = Some(workload);
    let mut poweroff = Some(poweroff);
    let mut acceptance: Option<oneshot::Receiver<()>> = None;
    loop {
        let pending = facts.pending();
        let mut bytes = [0; 16];
        tokio::select! {
            biased;
            count = control_read.read(&mut bytes) => {
                let count = count?;
                if count == 0 { return Err(invalid().into()); }
                facts.batch(&bytes[..count])?;
                for byte in &bytes[..count] {
                    match byte {
                        b'P' => {
                            let stream = progress.take().ok_or_else(invalid)?;
                            let seed = seed.clone();
                            tasks.spawn(async move { common::prove_progress(stream, &seed).await.map(Finished::Progress) });
                        }
                        b'D' => {
                            let stream = daemon.take().ok_or_else(invalid)?;
                            let seed = seed.clone();
                            tasks.spawn(async move { common::prove_daemon(stream, &seed).await.map(Finished::Daemon) });
                        }
                        b'Q' => {
                            let client = retained_daemon.as_ref().ok_or_else(invalid)?.clone();
                            let seed = seed.clone();
                            let (sender, receiver) = oneshot::channel();
                            acceptance = Some(receiver);
                            let poweroff = poweroff.take().ok_or_else(invalid)?;
                            tasks.spawn(async move {
                                tokio::time::timeout(POWEROFF_DEADLINE, poweroff(client, seed, sender)).await??;
                                Ok(Finished::Poweroff)
                            });
                        }
                        _ => {}
                    }
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result.ok_or_else(invalid)??? {
                    Finished::Progress(stream) => { retained_progress = Some(stream); facts.progress_ready = true; }
                    Finished::Daemon(client) => { retained_daemon = Some(client); facts.daemon_ready = true; }
                    Finished::Workload => { facts.session_stopped = true; }
                    Finished::Poweroff => { facts.poweroff_ended = true; }
                }
            }
            result = async { acceptance.as_mut().ok_or_else(invalid)?.await.map_err(Into::into) }, if acceptance.is_some() => {
                let result: Result<()> = result;
                result?;
                acceptance = None;
                facts.poweroff_accepted = true;
            }
            result = async { control_write.write_all(&[pending.ok_or_else(invalid)?]).await }, if pending.is_some() => {
                result?;
                match pending.ok_or_else(invalid)? {
                    b'R' => {
                        facts.ready_sent = true;
                        let client = retained_daemon.as_ref().ok_or_else(invalid)?.clone();
                        let workload = workload.take().ok_or_else(invalid)?;
                        tasks.spawn(async move {
                            tokio::time::timeout(WORKLOAD_DEADLINE, workload(client)).await??;
                            Ok(Finished::Workload)
                        });
                    }
                    b'W' => facts.workload_sent = true,
                    b'A' => facts.acceptance_sent = true,
                    b'C' => {
                        drop(retained_progress);
                        drop(retained_daemon);
                        // F independently attests actual VM stops and native
                        // EOF/drain/reap; only now release the receiving end.
                        drop(retained_daemon_endpoint);
                        return Ok(());
                    }
                    _ => return Err(invalid().into()),
                }
            }
        }
    }
}
