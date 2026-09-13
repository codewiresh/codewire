use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_daemon::client::SessionClient;
use codewire_local_vmm::network_session::{DenyBroker, NetworkSessionError, run_network_session};
use codewire_vmm_guest_probe::{
    GuestBootStage, NetworkKey, PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN, ProgressFrame,
    ProgressRequest, SEED_LEN, SETUP_HEADER_LEN, Seed, SetupArchitecture, SetupBinding,
    SetupHeader,
};
use hyper_util::rt::TokioIo;
use rand::{RngCore, rngs::OsRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod prepare;
#[cfg(test)]
mod tests;
mod workload;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(210);
const MAX_PROGRESS_FRAMES: usize = 64;
const WORKLOAD_DEADLINE: Duration = Duration::from_secs(30);

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

pub(super) fn entry() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or_else(invalid)?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        let value = arguments.next().ok_or_else(invalid)?;
        if options.insert(key, value).is_some() {
            return Err(invalid().into());
        }
    }
    match command.as_str() {
        "seed" => make_seed(options),
        "verify" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async { tokio::time::timeout(DEADLINE, verify(options)).await? })
        }
        #[cfg(target_os = "linux")]
        "prepare" => prepare::run(options),
        _ => Err(invalid().into()),
    }
}

fn exact_keys(options: &BTreeMap<String, String>, keys: &[&str]) -> Result<()> {
    if options.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys.iter().copied().collect()
    {
        return Err(invalid().into());
    }
    Ok(())
}

fn descriptor(options: &BTreeMap<String, String>, key: &str) -> Result<RawFd> {
    let descriptor: RawFd = options.get(key).ok_or_else(invalid)?.parse()?;
    if descriptor < 3 {
        return Err(invalid().into());
    }
    Ok(descriptor)
}

fn private_file(fd: RawFd, writable: bool) -> Result<File> {
    // Each command validates distinct inherited numbers before taking ownership.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut file = File::from(owned);
    let metadata = file.metadata()?;
    let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || access < 0
        || access & libc::O_ACCMODE
            != if writable {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            }
    {
        return Err(invalid().into());
    }
    // Descriptor commands consume an exact artifact from byte zero. In
    // particular an empty output with a pre-positioned offset must not create
    // a sparse prefix and still report successful seed/setup preparation.
    if file.stream_position()? != 0 {
        return Err(invalid().into());
    }
    Ok(file)
}

fn private_stream(fd: RawFd) -> Result<UnixStream> {
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = File::from(owned);
    if !file.metadata()?.file_type().is_socket() {
        return Err(invalid().into());
    }
    let mut socket_type = 0_i32;
    let mut length = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::from_mut(&mut socket_type).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&socket_type)
        || socket_type != libc::SOCK_STREAM
    {
        return Err(invalid().into());
    }
    let mut peer_address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of_val(&peer_address) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            std::ptr::from_mut(&mut peer_address).cast(),
            &mut address_len,
        )
    } != 0
        || i32::from(peer_address.ss_family) != libc::AF_UNIX
    {
        return Err(invalid().into());
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = !0;
        let mut gid = !0;
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0
            || uid != unsafe { libc::geteuid() }
        {
            return Err(invalid().into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut peer).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&peer)
            || peer.uid != unsafe { libc::geteuid() }
        {
            return Err(invalid().into());
        }
    }
    let stream = StdUnixStream::from(OwnedFd::from(file));
    // These calls also require a connected Unix socket, not an IP socket with
    // a convenient file descriptor number. No address is used for dialing.
    stream.local_addr()?;
    stream.peer_addr()?;
    stream.set_nonblocking(true)?;
    Ok(UnixStream::from_std(stream)?)
}

fn make_seed(options: BTreeMap<String, String>) -> Result<()> {
    exact_keys(
        &options,
        &["--setup-fd", "--output-fd", "--vm-id", "--generation"],
    )?;
    let setup_fd = descriptor(&options, "--setup-fd")?;
    let output_fd = descriptor(&options, "--output-fd")?;
    if setup_fd == output_fd {
        return Err(invalid().into());
    }
    let mut setup = private_file(setup_fd, false)?;
    let mut output = private_file(output_fd, true)?;
    if output.metadata()?.len() != 0 {
        return Err(invalid().into());
    }
    let mut header = vec![0; SETUP_HEADER_LEN];
    setup.read_exact(&mut header)?;
    let header = SetupHeader::decode(&header)?;
    if header.architecture != SetupArchitecture::Arm64
        || setup.metadata()?.len() != header.total_bytes
    {
        return Err(invalid().into());
    }
    let vm_id = Uuid::parse_str(&options["--vm-id"])?;
    let generation = options["--generation"].parse()?;
    let mut random = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(random.as_mut());
    let token = Zeroizing::new(
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let binding = SetupBinding::new(
        header.total_bytes,
        header.root_generation,
        header.encoded_sha256()?,
    )?;
    let seed = Seed::new_with_setup(vm_id, generation, 7777, token.as_str(), binding)?;
    let encoded = Zeroizing::new(seed.encode());
    output.write_all(encoded.as_ref())?;
    output.sync_all()?;
    Ok(())
}

fn fixture_seed(mut file: File) -> Result<Seed> {
    if file.metadata()?.len() != SEED_LEN as u64 {
        return Err(invalid().into());
    }
    let mut bytes = Zeroizing::new([0; SEED_LEN]);
    file.read_exact(bytes.as_mut())?;
    let seed = Seed::decode(bytes.as_ref())?;
    if seed.daemon_vsock_port() != 7777
        || seed.setup().is_none()
        || seed.docker_data_disk()
        || seed.direct_shares_sha256().is_some()
        || seed.skill_snapshot_sha256().is_some()
        || seed.environment_projection_sha256().is_some()
        || seed.managed_credential_clients() != Default::default()
    {
        return Err(invalid().into());
    }
    Ok(seed)
}

enum Finished {
    Network,
    Progress(UnixStream),
    Daemon(SessionClient),
    Workload,
}

async fn verify(options: BTreeMap<String, String>) -> Result<()> {
    let keys = [
        "--network-fd",
        "--progress-fd",
        "--daemon-fd",
        "--control-fd",
        "--seed-fd",
    ];
    exact_keys(&options, &keys)?;
    let numbers = keys
        .iter()
        .map(|key| descriptor(&options, key))
        .collect::<Result<Vec<_>>>()?;
    // Numeric uniqueness prevents taking ownership twice. The Python parent
    // constructs separate socketpairs; Swift independently proves its endpoint
    // identities. This check alone does not claim duplicate-open-file detection.
    if numbers.iter().copied().collect::<BTreeSet<_>>().len() != numbers.len() {
        return Err(invalid().into());
    }
    let seed = Arc::new(fixture_seed(private_file(numbers[4], false)?)?);
    verify_session(
        seed,
        private_stream(numbers[0])?,
        private_stream(numbers[1])?,
        private_stream(numbers[2])?,
        private_stream(numbers[3])?,
    )
    .await
}

async fn verify_session(
    seed: Arc<Seed>,
    network: UnixStream,
    progress: UnixStream,
    daemon: UnixStream,
    control: UnixStream,
) -> Result<()> {
    verify_session_with_workload(
        seed,
        network,
        progress,
        daemon,
        control,
        |client| async move { workload::prove(&client).await },
    )
    .await
}

async fn verify_session_with_workload<W, F>(
    seed: Arc<Seed>,
    network: UnixStream,
    progress: UnixStream,
    daemon: UnixStream,
    mut control: UnixStream,
    workload: W,
) -> Result<()>
where
    W: FnOnce(SessionClient) -> F + Send + 'static,
    F: Future<Output = Result<()>> + Send + 'static,
{
    let mut network = Some(network);
    let mut progress = Some(progress);
    let mut daemon = Some(daemon);
    let (network_ready_tx, mut network_ready_rx) = oneshot::channel();
    let mut network_ready_tx = Some(network_ready_tx);
    let mut network_ready = false;
    let mut tasks: JoinSet<Result<Finished>> = JoinSet::new();
    let mut retained_progress = None;
    let mut retained_daemon = None;
    let mut workload = Some(workload);
    let mut ready = false;
    let mut workload_complete = false;
    let mut armed = false;
    loop {
        // Completed task failures win over a simultaneous control command.
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => match result.ok_or_else(invalid)??? {
                Finished::Network => {
                    if !armed { return Err(invalid().into()); }
                    // The parent's armed SIGKILL must close the owned network
                    // stream. The parent separately proves actual helper death,
                    // control EOF, process-group absence and private cleanup.
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    drop(retained_daemon);
                    drop(retained_progress);
                    control.write_all(b"C").await?;
                    return Ok(());
                }
                Finished::Progress(stream) => retained_progress = Some(stream),
                Finished::Daemon(client) => retained_daemon = Some(client),
                Finished::Workload => {
                    if !ready || workload_complete {
                        return Err(invalid().into());
                    }
                    workload_complete = true;
                    control.write_all(b"W").await?;
                }
            },
            result = &mut network_ready_rx, if network.is_none() && !network_ready => {
                result?;
                network_ready = true;
            },
            marker = control.read_u8() => match marker? {
                b'N' => {
                    let stream = network.take().ok_or_else(invalid)?;
                    let key = NetworkKey::derive(seed.auth_token(), seed.vm_id(), seed.generation())?;
                    let ready_sender = network_ready_tx.take().ok_or_else(invalid)?;
                    let (vm_id, generation) = (seed.vm_id(), seed.generation());
                    tasks.spawn(async move {
                        let result = run_network_session(stream, key, vm_id, generation, Arc::new(DenyBroker), move || {
                            ready_sender.send(()).map_err(|_| invalid())
                        }).await;
                        // Any termination before the armed ownership check is
                        // rejected, including an otherwise normal peer EOF.
                        match result {
                            Err(NetworkSessionError::FrameIo) => Ok(Finished::Network),
                            _ => Err(invalid().into()),
                        }
                    });
                }
                b'P' => {
                    let stream = progress.take().ok_or_else(invalid)?;
                    let seed = seed.clone();
                    tasks.spawn(async move { prove_progress(stream, &seed).await.map(Finished::Progress) });
                }
                b'D' => {
                    let stream = daemon.take().ok_or_else(invalid)?;
                    let seed = seed.clone();
                    tasks.spawn(async move { prove_daemon(stream, &seed).await.map(Finished::Daemon) });
                }
                b'K' if ready && workload_complete && !armed => {
                    armed = true;
                    control.write_all(b"A").await?;
                }
                _ => return Err(invalid().into()),
            }
        }
        if !ready
            && complete_readiness(
                network_ready,
                retained_progress.is_some(),
                retained_daemon.is_some(),
            )
        {
            ready = true;
            control.write_all(b"R").await?;
            let client = retained_daemon.as_ref().ok_or_else(invalid)?.clone();
            let workload = workload.take().ok_or_else(invalid)?;
            tasks.spawn(async move {
                tokio::time::timeout(WORKLOAD_DEADLINE, workload(client))
                    .await
                    .map_err(|_| invalid())??;
                Ok(Finished::Workload)
            });
        }
    }
}

fn complete_readiness(network: bool, progress: bool, daemon: bool) -> bool {
    network && progress && daemon
}

async fn prove_progress(mut stream: UnixStream, seed: &Seed) -> Result<UnixStream> {
    let mut challenge = [0; PROGRESS_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut challenge);
    let request = ProgressRequest {
        vm_id: seed.vm_id(),
        generation: seed.generation(),
        challenge,
    };
    stream.write_all(&request.encode()).await?;
    let mut last = 0;
    let mut last_stage = None;
    for _ in 0..MAX_PROGRESS_FRAMES {
        let mut bytes = [0; PROGRESS_FRAME_LEN];
        stream.read_exact(&mut bytes).await?;
        let frame = ProgressFrame::decode(
            &bytes,
            &challenge,
            seed.auth_token(),
            seed.vm_id(),
            seed.generation(),
        )?;
        if frame.sequence <= last
            || last_stage.is_some_and(|stage| frame.stage <= stage)
            || frame.stage.is_failure()
        {
            return Err(invalid().into());
        }
        last = frame.sequence;
        last_stage = Some(frame.stage);
        if frame.stage == GuestBootStage::DaemonStarted {
            let mut trailing = [0];
            if stream.read(&mut trailing).await? != 0 {
                return Err(invalid().into());
            }
            return Ok(stream);
        }
        if frame.stage.is_terminal() {
            return Err(invalid().into());
        }
    }
    Err(invalid().into())
}

async fn prove_daemon(stream: UnixStream, seed: &Seed) -> Result<SessionClient> {
    // A single already-admitted stream; reconnection cannot dial any address or
    // substitute another VM. The URI is only tonic's HTTP/2 authority label.
    let stream = Arc::new(Mutex::new(Some(stream)));
    let channel = tonic::transport::Endpoint::from_static("http://codewire-fixture-daemon")
        .timeout(Duration::from_secs(5))
        .connect_with_connector(tower::service_fn(move |_| {
            let stream = stream.clone();
            async move {
                stream
                    .lock()
                    .map_err(|_| invalid())?
                    .take()
                    .map(TokioIo::new)
                    .ok_or_else(invalid)
            }
        }))
        .await?;
    let client = SessionClient::from_channel(channel, seed.auth_token())?;
    client.require_ready().await?;
    Ok(client)
}
