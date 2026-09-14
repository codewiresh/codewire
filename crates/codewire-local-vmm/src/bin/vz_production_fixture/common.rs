//! Shared private artifacts and authenticated progress/daemon verification.
//! This module has no network session engine or packet descriptor.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Result, invalid};
use codewire_daemon::client::SessionClient;
use codewire_vmm_guest_probe::{
    GuestBootStage, PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN, ProgressFrame, ProgressRequest,
    SEED_LEN, SETUP_HEADER_LEN, Seed, SetupArchitecture, SetupBinding, SetupHeader,
};
use hyper_util::rt::TokioIo;
use rand::{RngCore, rngs::OsRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_PROGRESS_FRAMES: usize = 64;

pub(super) fn exact_keys(options: &BTreeMap<String, String>, keys: &[&str]) -> Result<()> {
    if options.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys.iter().copied().collect()
    {
        return Err(invalid().into());
    }
    Ok(())
}

pub(super) fn descriptor(options: &BTreeMap<String, String>, key: &str) -> Result<RawFd> {
    let descriptor: RawFd = options.get(key).ok_or_else(invalid)?.parse()?;
    if descriptor < 3 {
        return Err(invalid().into());
    }
    Ok(descriptor)
}

pub(super) fn private_file(fd: RawFd, writable: bool) -> Result<File> {
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

pub(super) fn private_stream(fd: RawFd) -> Result<UnixStream> {
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

pub(super) fn seed_from_setup(
    setup: &mut File,
    options: &BTreeMap<String, String>,
) -> Result<Seed> {
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
    Ok(Seed::new_with_setup(
        vm_id,
        generation,
        7777,
        token.as_str(),
        binding,
    )?)
}

pub(super) fn fixture_seed(mut file: File) -> Result<Seed> {
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

pub(super) async fn prove_progress(mut stream: UnixStream, seed: &Seed) -> Result<UnixStream> {
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

pub(super) async fn prove_daemon(stream: UnixStream, seed: &Seed) -> Result<SessionClient> {
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
