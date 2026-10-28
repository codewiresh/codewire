//! Guest PID 1's VM checkpoint hook (#3046 R4), a child of `guest`.
//!
//! PID 1 is never frozen. It answers the runner's `Freeze`, `Thaw` and
//! `Resume` (see `checkpoint_protocol`) on its own thread, one connection at a
//! time, so a freeze, a resume and a thaw never interleave.
//!
//! `Resume` arrives in a VM restored from a VM checkpoint while its workload
//! is still frozen. PID 1 rereads the seed the runner wrote for the restored
//! boot straight from the seed disk (`O_DIRECT`: the page cache holds the
//! captured boot's copy), checks the request against it, mixes the host's
//! entropy into the kernel CRNG and reseeds it, steps the wall clock if it is
//! two seconds or more off, and moves this boot's identity: the progress
//! server's key, the machine-id on a fork, and through `SIGUSR1` the daemon's
//! token and credential bridge identity and the network agent's key. Each of
//! those processes acknowledges by writing the identity it moved to. The
//! workload thaws only on a later authenticated `Thaw`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::checkpoint_protocol::{
    CHECKPOINT_CHALLENGE_LEN, CHECKPOINT_REQUEST_LEN, CheckpointAction, CheckpointHello,
    CheckpointKey, CheckpointReply, CheckpointRequest, CheckpointStatus, GUEST_CHECKPOINT_ABI,
    GUEST_CHECKPOINT_VSOCK_PORT, ResumeReport, resume_transition_allowed,
};
use crate::workload_cgroup::{FREEZE_TIMEOUT, THAW_TIMEOUT, WorkloadCgroup};
use crate::{SEED_DISK_SERIAL, SEED_LEN, Seed};

/// Where the daemon and the network agent acknowledge a re-key.
const ACK_DIRECTORY: &str = "/run/codewire/checkpoint";
const DAEMON_ACK: &str = "daemon";
const NETWORK_ACK: &str = "network";
/// How long each re-keyed process may take to acknowledge.
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one connection may take, request to reply.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// A wall clock this far from the host's is stepped on `Resume`.
const MAX_SKEW: Duration = Duration::from_secs(2);
const HOST_ENTROPY_BITS: i32 = 512;
const VMGENID_DRIVERS: [&str; 2] = [
    "/sys/bus/acpi/drivers/vmgenid",
    "/sys/bus/platform/drivers/vmgenid",
];

/// This boot's identity: what the progress server and the hook authenticate
/// with. `Resume` replaces it.
pub(super) struct BootIdentity {
    pub(super) vm_id: Uuid,
    pub(super) generation: u64,
    pub(super) token: Zeroizing<String>,
}

static IDENTITY: OnceLock<Mutex<BootIdentity>> = OnceLock::new();
/// The daemon's and the network agent's PIDs, once both run.
static REKEY_TARGETS: OnceLock<(u32, u32)> = OnceLock::new();

/// Installs this boot's identity. The progress server and the hook read it.
pub(super) fn install_identity(seed: &Seed) -> Result<()> {
    IDENTITY
        .set(Mutex::new(BootIdentity {
            vm_id: seed.vm_id(),
            generation: seed.generation(),
            token: Zeroizing::new(seed.auth_token().to_owned()),
        }))
        .map_err(|_| anyhow::anyhow!("the boot identity is already installed"))
}

/// Runs `read` on the current boot identity.
pub(super) fn with_identity<T>(read: impl FnOnce(&BootIdentity) -> T) -> Result<T> {
    let identity = IDENTITY
        .get()
        .context("the boot identity is not installed")?
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(read(&identity))
}

/// Records the processes `Resume` re-keys.
pub(super) fn set_rekey_targets(daemon: u32, network: u32) -> Result<()> {
    REKEY_TARGETS
        .set((daemon, network))
        .map_err(|_| anyhow::anyhow!("checkpoint re-key targets are already set"))
}

/// Starts the hook server on its own thread and waits until it listens.
pub(super) fn start() -> Result<()> {
    // PID 1 starts the hook before it lays out the rest of /run/codewire.
    super::create_dir(Path::new("/run/codewire"), 0o700)?;
    super::create_dir(Path::new(ACK_DIRECTORY), 0o700)?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    thread::Builder::new()
        .name("codewire-checkpoint".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match VsockListener::bind(VsockAddr::new(
                    VMADDR_CID_ANY,
                    GUEST_CHECKPOINT_VSOCK_PORT,
                )) {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        continue;
                    };
                    if !super::is_host_cid(peer.cid()) {
                        continue;
                    }
                    // One exchange at a time: the next connection waits.
                    if let Ok(Err(error)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, serve(stream)).await
                    {
                        eprintln!("codewire guest: checkpoint hook: {error:#}");
                    }
                }
            });
        })
        .context("spawn the checkpoint hook")?;
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .context("wait for the checkpoint hook listener")??;
    Ok(())
}

async fn serve(mut stream: VsockStream) -> Result<()> {
    let mut challenge = [0_u8; CHECKPOINT_CHALLENGE_LEN];
    fill_random(&mut challenge)?;
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        &CheckpointHello {
            challenge,
            abi: GUEST_CHECKPOINT_ABI,
        }
        .encode(),
    )
    .await
    .context("write the checkpoint hello")?;
    let mut bytes = [0_u8; CHECKPOINT_REQUEST_LEN];
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes),
    )
    .await
    .context("the checkpoint request timed out")?
    .context("read the checkpoint request")?;
    let (action, vm_id, generation) =
        CheckpointRequest::peek_identity(&bytes).context("decode the checkpoint request")?;
    let (key, request) = match action {
        CheckpointAction::Freeze | CheckpointAction::Thaw => {
            let key = with_identity(|current| {
                ensure!(
                    current.vm_id == vm_id && current.generation == generation,
                    "the checkpoint request names another boot"
                );
                CheckpointKey::derive(&current.token, vm_id, generation)
                    .context("derive this boot's checkpoint key")
            })??;
            let request = CheckpointRequest::decode(&bytes, &key, &challenge)
                .context("authenticate the checkpoint request")?;
            (key, request)
        }
        CheckpointAction::Resume => {
            let seed = tokio::task::spawn_blocking(read_seed_direct)
                .await
                .context("reread the seed")??;
            ensure!(
                seed.vm_id() == vm_id && seed.generation() == generation,
                "the resume request does not name the identity in the seed"
            );
            let key = CheckpointKey::derive(seed.auth_token(), vm_id, generation)
                .context("derive the restored boot's checkpoint key")?;
            let request = CheckpointRequest::decode(&bytes, &key, &challenge)
                .context("authenticate the resume request")?;
            (key, request)
        }
    };
    let reply = tokio::task::spawn_blocking(move || act(request))
        .await
        .context("run the checkpoint action")?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &reply.encode(&key, &challenge))
        .await
        .context("write the checkpoint reply")?;
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .context("flush the checkpoint reply")
}

fn act(request: CheckpointRequest) -> CheckpointReply {
    let started = Instant::now();
    let mut reply = CheckpointReply {
        action: request.action,
        status: CheckpointStatus::Done,
        operation_id: request.operation_id,
        vm_id: request.vm_id,
        generation: request.generation,
        elapsed_us: 0,
        clock_skew_ms: 0,
        resume: ResumeReport::default(),
    };
    let workload = WorkloadCgroup::at(Path::new(super::CGROUP_HIERARCHY_PATH));
    let result = match request.action {
        CheckpointAction::Freeze => workload.freeze(FREEZE_TIMEOUT).map(drop),
        CheckpointAction::Thaw => workload.thaw(THAW_TIMEOUT),
        CheckpointAction::Resume => match resume(&request) {
            Ok(Some((report, skew_ms))) => {
                reply.resume = report;
                reply.clock_skew_ms = skew_ms;
                Ok(())
            }
            Ok(None) => {
                reply.status = CheckpointStatus::Refused;
                Ok(())
            }
            Err(error) => Err(error),
        },
    };
    if let Err(error) = result {
        eprintln!(
            "codewire guest: checkpoint {:?} failed: {error:#}",
            request.action
        );
        reply.status = CheckpointStatus::Failed;
    }
    reply.elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    reply
}

/// Moves this guest to the restored boot's identity, with the workload still
/// frozen. `None` refuses a transition that is neither a fork nor a newer
/// generation; nothing changes then.
fn resume(request: &CheckpointRequest) -> Result<Option<(ResumeReport, i64)>> {
    let current = with_identity(|current| (current.vm_id, current.generation))?;
    if !resume_transition_allowed(current.0, current.1, request.vm_id, request.generation) {
        return Ok(None);
    }
    let (daemon, network) = *REKEY_TARGETS
        .get()
        .context("the guest daemon and network agent are not running yet")?;
    // The seed was authenticated by the request's MAC; read it again for the
    // token now that the transition is allowed.
    let seed = read_seed_direct()?;
    ensure!(
        seed.vm_id() == request.vm_id && seed.generation() == request.generation,
        "the seed changed during resume"
    );

    reseed(&request.host_entropy)?;
    let skew_ms = step_clock(request.host_time_ns)?;

    let fork = request.vm_id != current.0;
    {
        let mut identity = IDENTITY
            .get()
            .context("the boot identity is not installed")?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        identity.vm_id = request.vm_id;
        identity.generation = request.generation;
        identity.token = Zeroizing::new(seed.auth_token().to_owned());
    }
    drop(seed);
    if fork {
        rewrite_container_identity(request.vm_id, request.generation)?;
    }
    let mut removed_logins = false;
    for (name, pid) in [(DAEMON_ACK, daemon), (NETWORK_ACK, network)] {
        removed_logins |= rekey(name, pid, request.vm_id, request.generation)?;
    }
    Ok(Some((
        ResumeReport {
            reseeded: true,
            vmgenid_driver: VMGENID_DRIVERS.iter().any(|path| Path::new(path).exists()),
            removed_logins,
        },
        skew_ms,
    )))
}

/// Mixes the host's entropy into the input pool, credited in full, and
/// reseeds the CRNG from it, so every later draw differs between forks.
fn reseed(entropy: &[u8]) -> Result<()> {
    // struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
    let mut request = Vec::with_capacity(8 + entropy.len());
    request.extend_from_slice(&HOST_ENTROPY_BITS.to_ne_bytes());
    request.extend_from_slice(&(entropy.len() as i32).to_ne_bytes());
    request.extend_from_slice(entropy);
    let random = File::open("/dev/urandom").context("open the guest RNG")?;
    use std::os::fd::AsRawFd as _;
    // RNDADDENTROPY = _IOW('R', 0x03, int[2]); RNDRESEEDCRNG = _IO('R', 0x07).
    const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;
    const RNDRESEEDCRNG: libc::c_ulong = 0x5207;
    // SAFETY: the buffer is a valid rand_pool_info of exactly buf_size bytes.
    if unsafe { libc::ioctl(random.as_raw_fd(), RNDADDENTROPY as _, request.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("add host entropy to the guest RNG");
    }
    zeroize::Zeroize::zeroize(&mut request);
    // SAFETY: an argument-free ioctl on the RNG device.
    if unsafe { libc::ioctl(random.as_raw_fd(), RNDRESEEDCRNG as _) } != 0 {
        return Err(io::Error::last_os_error()).context("reseed the guest CRNG");
    }
    Ok(())
}

/// Steps the wall clock to the host's when they differ by [`MAX_SKEW`] or
/// more; returns the skew in milliseconds before any step.
fn step_clock(host_time_ns: u64) -> Result<i64> {
    let guest_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read the guest wall clock")?
        .as_nanos();
    let skew_ns = i128::try_from(guest_ns).unwrap_or(i128::MAX) - i128::from(host_time_ns);
    let skew_ms = i64::try_from(skew_ns / 1_000_000).unwrap_or(i64::MAX);
    if skew_ns.unsigned_abs() >= MAX_SKEW.as_nanos() {
        let time = libc::timespec {
            tv_sec: (host_time_ns / 1_000_000_000) as _,
            tv_nsec: (host_time_ns % 1_000_000_000) as _,
        };
        // SAFETY: a valid timespec; guest init runs as root.
        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
            return Err(io::Error::last_os_error()).context("step the guest wall clock");
        }
    }
    Ok(skew_ms)
}

/// Rewrites the machine-id and the container's identity record in place:
/// the workspace sees each through a read-only bind of that same inode.
fn rewrite_container_identity(vm_id: Uuid, generation: u64) -> Result<()> {
    let identity = super::GuestIdentity { vm_id, generation };
    identity.validate()?;
    overwrite_in_place(
        Path::new(super::CONTAINER_MACHINE_ID_PATH),
        identity.machine_id().as_bytes(),
    )
    .context("rewrite the machine-id")?;
    overwrite_in_place(
        Path::new(super::CONTAINER_IDENTITY_PATH),
        &serde_json::to_vec(&identity).context("encode the guest identity record")?,
    )
    .context("rewrite the guest identity record")
}

fn overwrite_in_place(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Signals one re-keyed process and waits for its acknowledgement of
/// `(vm_id, generation)`. Returns whether it removed delivered sign-ins.
fn rekey(name: &str, pid: u32, vm_id: Uuid, generation: u64) -> Result<bool> {
    let path = Path::new(ACK_DIRECTORY).join(name);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("clear a stale re-key acknowledgement"),
    }
    let pid = libc::pid_t::try_from(pid).context("re-key target pid")?;
    // SAFETY: signalling a child PID 1 started and still supervises.
    if unsafe { libc::kill(pid, libc::SIGUSR1) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("signal the {name}"));
    }
    let deadline = Instant::now() + REKEY_TIMEOUT;
    loop {
        if let Some(acknowledged) = read_acknowledgement(&path)? {
            ensure!(
                acknowledged.0 == vm_id && acknowledged.1 == generation,
                "the {name} acknowledged another identity"
            );
            return Ok(acknowledged.2);
        }
        if Instant::now() >= deadline {
            bail!("the {name} did not acknowledge its re-key");
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn read_acknowledgement(path: &Path) -> Result<Option<(Uuid, u64, bool)>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read a re-key acknowledgement"),
    };
    parse_acknowledgement(&text).map(Some)
}

fn parse_acknowledgement(text: &str) -> Result<(Uuid, u64, bool)> {
    let mut fields = text.trim_end_matches('\n').split(' ');
    let (Some(vm_id), Some(generation), Some(removed), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        bail!("a re-key acknowledgement is malformed");
    };
    Ok((
        Uuid::parse_str(vm_id).context("re-key acknowledgement environment")?,
        generation
            .parse()
            .context("re-key acknowledgement generation")?,
        match removed {
            "0" => false,
            "1" => true,
            _ => bail!("a re-key acknowledgement is malformed"),
        },
    ))
}

/// The daemon or the network agent records that it moved to `seed`'s
/// identity.
pub(super) fn acknowledge_rekey(name: &str, seed: &Seed, removed_logins: bool) -> Result<()> {
    let text = format!(
        "{} {} {}\n",
        seed.vm_id().hyphenated(),
        seed.generation(),
        u8::from(removed_logins)
    );
    super::write_durable(&Path::new(ACK_DIRECTORY).join(name), text.as_bytes(), 0o600)
}

pub(super) const DAEMON_REKEY: &str = DAEMON_ACK;
pub(super) const NETWORK_REKEY: &str = NETWORK_ACK;

/// Reads the seed disk past the page cache. A restored VM's cache still holds
/// the captured boot's seed; the runner has since written a new one.
pub(super) fn read_seed_direct() -> Result<Seed> {
    let device = super::wait_for_disk_by_serial(
        Path::new(super::SYS_BLOCK_PATH),
        Path::new(super::DEV_PATH),
        SEED_DISK_SERIAL,
        super::DISK_DISCOVERY_TIMEOUT,
    )?;
    super::validate_block_device(&device)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&device)
        .with_context(|| format!("open the seed disk {} directly", device.display()))?;
    let mut buffer = AlignedSeed::new();
    file.read_exact(buffer.as_mut())
        .context("read the seed disk directly")?;
    Seed::decode(buffer.as_mut()).context("decode the reread seed")
}

/// One seed-sized buffer aligned for `O_DIRECT`, zeroed when dropped.
struct AlignedSeed(Box<Aligned>);

#[repr(C, align(4096))]
struct Aligned([u8; SEED_LEN]);

impl AlignedSeed {
    fn new() -> Self {
        Self(Box::new(Aligned([0; SEED_LEN])))
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0.0
    }
}

impl Drop for AlignedSeed {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0.0);
    }
}

fn fill_random(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        // SAFETY: writes at most the remaining bytes of `buffer`.
        let read = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr().cast(),
                buffer.len() - filled,
                0,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("draw a checkpoint challenge");
        }
        filled += read as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgements_parse_exactly() {
        let vm_id = Uuid::new_v4();
        assert_eq!(
            parse_acknowledgement(&format!("{vm_id} 3 1\n")).unwrap(),
            (vm_id, 3, true)
        );
        assert_eq!(
            parse_acknowledgement(&format!("{vm_id} 3 0")).unwrap(),
            (vm_id, 3, false)
        );
        for malformed in [
            String::new(),
            format!("{vm_id} 3"),
            format!("{vm_id} 3 2"),
            format!("{vm_id} x 1"),
            format!("{vm_id} 3 1 extra"),
            "not-a-uuid 3 1".to_owned(),
        ] {
            assert!(parse_acknowledgement(&malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn the_seed_buffer_is_aligned_for_direct_reads() {
        let mut buffer = AlignedSeed::new();
        let slice = buffer.as_mut();
        assert_eq!(slice.len(), SEED_LEN);
        assert_eq!(slice.as_ptr() as usize % 4096, 0);
    }

    #[test]
    fn small_skews_are_left_alone() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        // Within the bound nothing is stepped, so this needs no privilege.
        let skew = step_clock(now).unwrap();
        assert!(skew.abs() < 1_000, "{skew}");
    }
}
