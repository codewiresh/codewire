use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::Stream;
use tokio_vsock::{
    Incoming, VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener, VsockStream,
};
use zeroize::Zeroizing;

use crate::{SEED_DISK_SERIAL, SEED_LEN, STATE_DISK_SERIAL, Seed};

pub const INIT_PATH: &str = "/init";
pub const STATE_MOUNT_PATH: &str = "/state";
pub const WORKSPACE_PATH: &str = "/workspace";
pub const HOME_PATH: &str = "/home/codewire";
pub const CONTROL_PATH: &str = "/state/codewire";
pub const NONCE_PATH: &str = "/state/codewire/nonce";
pub const POWEROFF_MARKER_PATH: &str = "/state/codewire/poweroff.accepted";
pub const IDENTITY_MARKER: &str = "CWIDENTITY1";
pub const NONCE_MARKER: &str = "CWNONCE1";
pub const NETWORK_MARKER: &str = "CWNETWORK1 loopback-only";
pub const POWEROFF_MARKER: &str = "CWPOWEROFF1 accepted";

const SYS_BLOCK_PATH: &str = "/sys/class/block";
const DEV_PATH: &str = "/dev";
const DISK_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_ONLY_REJECTION_BUDGET: usize = 32;
const NONCE_MAX_LEN: usize = 256;
const READ_LIMIT: usize = 4097;
const PERSISTENT_WORKSPACE_PATH: &str = "/state/workspace";
const PERSISTENT_HOME_PATH: &str = "/state/home";

static POWEROFF_REQUESTED: AtomicBool = AtomicBool::new(false);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn run_init() -> Result<()> {
    ensure!(
        unsafe { libc::getpid() } == 1,
        "guest init must run as PID 1"
    );
    POWEROFF_REQUESTED.store(false, Ordering::Release);

    mount_minimal_filesystems()?;
    install_poweroff_handlers()?;

    let state_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        STATE_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    let seed_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        SEED_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    ensure!(
        state_device != seed_device,
        "state and seed disks resolve to one device"
    );
    validate_block_device(&state_device)?;
    validate_block_device(&seed_device)?;
    mount_state(&state_device)?;
    create_state_layout()?;
    expose_persistent_layout()?;

    // Validate the complete seed before starting anything that accepts guest
    // control traffic. The child deliberately rereads it from the immutable
    // disk rather than inheriting the token through argv or environment.
    let _ = read_seed_file(&seed_device)?;

    let daemon_pid = spawn_daemon()?;
    supervise_daemon(daemon_pid)
}

pub async fn run_daemon() -> Result<()> {
    ensure!(
        std::env::vars_os().next().is_none(),
        "guest daemon refuses an ambient environment"
    );
    let seed = read_seed_from_discovered_disk()?;
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, seed.daemon_vsock_port()))
        .with_context(|| {
            format!(
                "bind guest daemon AF_VSOCK port {}",
                seed.daemon_vsock_port()
            )
        })?;

    let config = codewire_daemon::Config {
        // The injected transport owns the listener; this value is never used
        // to bind TCP and intentionally contains no host address.
        listen_addr: format!("vsock:any:{}", seed.daemon_vsock_port()),
        workspace_root: PathBuf::from(WORKSPACE_PATH),
        home_root: PathBuf::from(HOME_PATH),
        auth_token: Some(seed.auth_token().to_owned()),
    };

    codewire_daemon::serve_grpc_with_incoming(
        config,
        HostOnlyIncoming::new(listener.incoming()),
        shutdown_signal(),
    )
    .await
    .context("serve authenticated guest daemon over AF_VSOCK")
}

struct HostOnlyIncoming {
    incoming: Incoming,
}

impl HostOnlyIncoming {
    fn new(incoming: Incoming) -> Self {
        Self { incoming }
    }
}

fn is_host_cid(cid: u32) -> bool {
    cid == VMADDR_CID_HOST
}

impl Stream for HostOnlyIncoming {
    type Item = io::Result<VsockStream>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut rejected = 0;
        loop {
            match Pin::new(&mut self.incoming).poll_next(context) {
                Poll::Ready(Some(Ok(stream))) => match stream.peer_addr() {
                    Ok(peer) if is_host_cid(peer.cid()) => {
                        return Poll::Ready(Some(Ok(stream)));
                    }
                    Ok(_) | Err(_) => {
                        // Guest-local processes are hostile. Drop their
                        // transport without surfacing an error that would stop
                        // the authenticated host listener.
                        if rejected_connection_requires_yield(&mut rejected, context) {
                            return Poll::Pending;
                        }
                    }
                },
                other => return other,
            }
        }
    }
}

fn rejected_connection_requires_yield(rejected: &mut usize, context: &mut TaskContext<'_>) -> bool {
    *rejected += 1;
    if *rejected < HOST_ONLY_REJECTION_BUDGET {
        return false;
    }

    // A guest-local connect flood must not monopolize the Tokio worker that
    // also carries authenticated host control. The listener remains readable,
    // so arrange another poll after yielding to peer tasks.
    context.waker().wake_by_ref();
    true
}

pub fn run_identity() -> Result<()> {
    let seed = read_seed_from_discovered_disk()?;
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{IDENTITY_MARKER} vm_id={} generation={}",
        seed.vm_id(),
        seed.generation()
    )?;
    stdout.flush()?;
    Ok(())
}

pub fn run_write_nonce(nonce: &OsStr) -> Result<()> {
    let _ = read_seed_from_discovered_disk()?;
    let nonce = validate_nonce(nonce)?;
    write_durable(Path::new(NONCE_PATH), nonce.as_bytes(), 0o600).context("persist guest nonce")?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NONCE_MARKER} written")?;
    stdout.flush()?;
    Ok(())
}

pub fn run_read_nonce() -> Result<()> {
    let _ = read_seed_from_discovered_disk()?;
    let nonce = read_nonce(Path::new(NONCE_PATH))?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NONCE_MARKER} {nonce}")?;
    stdout.flush()?;
    Ok(())
}

pub fn run_network_check() -> Result<()> {
    let _ = read_seed_from_discovered_disk()?;
    verify_loopback_only(
        Path::new("/sys/class/net"),
        Path::new("/proc/net/route"),
        Path::new("/proc/net/ipv6_route"),
    )?;
    verify_no_ip_egress_canaries()?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{NETWORK_MARKER}")?;
    stdout.flush()?;
    Ok(())
}

pub fn run_poweroff() -> Result<()> {
    let seed = read_seed_from_discovered_disk()?;
    ensure_init_is_expected()?;
    let marker = format!(
        "{POWEROFF_MARKER} vm_id={} generation={}\n",
        seed.vm_id(),
        seed.generation()
    );
    let mut operations = RealPoweroffOperations { marker };
    request_poweroff(&mut operations)
}

pub fn find_disk_by_serial(
    sys_block_path: &Path,
    dev_path: &Path,
    expected_serial: &str,
) -> Result<PathBuf> {
    ensure!(!expected_serial.is_empty(), "disk serial must not be empty");
    let mut matches = Vec::new();
    for entry in fs::read_dir(sys_block_path)
        .with_context(|| format!("read block-device class {}", sys_block_path.display()))?
    {
        let entry = entry.context("read block-device class entry")?;
        let name = entry.file_name();
        if !valid_virtio_block_name(&name) {
            continue;
        }
        let serial_path = entry.path().join("serial");
        let Ok(serial) = read_bounded(&serial_path, 64) else {
            continue;
        };
        let Ok(serial) = std::str::from_utf8(&serial) else {
            continue;
        };
        if serial.trim_end_matches(['\r', '\n']) == expected_serial {
            matches.push(dev_path.join(name));
        }
    }

    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("virtio block disk with required serial is absent"),
        _ => bail!("multiple virtio block disks use the required serial"),
    }
}

fn wait_for_disk_by_serial(
    sys_block_path: &Path,
    dev_path: &Path,
    serial: &str,
    timeout: Duration,
) -> Result<PathBuf> {
    let deadline = Instant::now() + timeout;
    loop {
        match find_disk_by_serial(sys_block_path, dev_path, serial) {
            Ok(path) => return Ok(path),
            Err(error) if error.to_string().starts_with("multiple ") => return Err(error),
            Err(error) if Instant::now() >= deadline => {
                return Err(error).with_context(|| format!("discover required {serial} disk"));
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn valid_virtio_block_name(name: &OsStr) -> bool {
    let name = name.as_bytes();
    name.len() >= 3 && name.starts_with(b"vd") && name[2..].iter().all(u8::is_ascii_lowercase)
}

fn validate_block_device(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect guest block device {}", path.display()))?;
    ensure!(
        metadata.file_type().is_block_device(),
        "guest disk path is not a block device"
    );
    Ok(())
}

fn read_seed_from_discovered_disk() -> Result<Seed> {
    let seed_device = wait_for_disk_by_serial(
        Path::new(SYS_BLOCK_PATH),
        Path::new(DEV_PATH),
        SEED_DISK_SERIAL,
        DISK_DISCOVERY_TIMEOUT,
    )?;
    validate_block_device(&seed_device)?;
    read_seed_file(&seed_device)
}

fn read_seed_file(path: &Path) -> Result<Seed> {
    // This limits one avoidable plaintext copy. The daemon's live Config must
    // retain its token to authenticate RPCs, so guest memory is not claimed as
    // a token-secrecy boundary.
    let bytes = Zeroizing::new(
        read_bounded(path, READ_LIMIT)
            .with_context(|| format!("read guest seed disk {}", path.display()))?,
    );
    ensure!(
        bytes.len() == SEED_LEN,
        "guest seed disk has invalid length"
    );
    Seed::decode(&bytes).context("decode guest seed")
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(4096));
    Read::by_ref(&mut file)
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn mount_minimal_filesystems() -> Result<()> {
    create_dir(Path::new("/dev"), 0o755)?;
    mount_fs(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    create_dir(Path::new("/proc"), 0o555)?;
    mount_fs(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    create_dir(Path::new("/sys"), 0o555)?;
    mount_fs(
        "sysfs",
        "/sys",
        "sysfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    create_dir(Path::new("/dev/pts"), 0o755)?;
    mount_fs(
        "devpts",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620",
    )?;
    create_dir(Path::new("/dev/shm"), 0o1777)?;
    create_dir(Path::new("/run"), 0o755)?;
    create_dir(Path::new("/tmp"), 0o1777)?;
    replace_ptmx_link()?;
    create_symlink("/proc/self/fd", "/dev/fd")?;
    create_symlink("/proc/self/fd/0", "/dev/stdin")?;
    create_symlink("/proc/self/fd/1", "/dev/stdout")?;
    create_symlink("/proc/self/fd/2", "/dev/stderr")?;
    Ok(())
}

fn mount_state(device: &Path) -> Result<()> {
    create_dir(Path::new(STATE_MOUNT_PATH), 0o700)?;
    let device = device
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("state disk path is not UTF-8"))?;
    mount_fs(
        device,
        STATE_MOUNT_PATH,
        "ext4",
        libc::MS_NOSUID | libc::MS_NODEV,
        "errors=remount-ro",
    )
    .context("mount persistent state disk")
}

fn create_state_layout() -> Result<()> {
    for (path, mode) in [
        (CONTROL_PATH, 0o700),
        (PERSISTENT_WORKSPACE_PATH, 0o700),
        (PERSISTENT_HOME_PATH, 0o700),
    ] {
        create_dir(Path::new(path), mode)?;
    }
    File::open(STATE_MOUNT_PATH)
        .context("open state mount for fsync")?
        .sync_all()
        .context("fsync state layout")?;
    Ok(())
}

fn expose_persistent_layout() -> Result<()> {
    create_dir(Path::new(WORKSPACE_PATH), 0o700)?;
    create_dir(Path::new("/home"), 0o755)?;
    create_dir(Path::new(HOME_PATH), 0o700)?;
    bind_mount(PERSISTENT_WORKSPACE_PATH, WORKSPACE_PATH)?;
    bind_mount(PERSISTENT_HOME_PATH, HOME_PATH)
}

fn bind_mount(source: &str, target: &str) -> Result<()> {
    mount_fs(source, target, "none", libc::MS_BIND, "")
        .with_context(|| format!("bind persistent guest path {source} at {target}"))?;
    mount_fs(
        source,
        target,
        "none",
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )
    .with_context(|| format!("confine persistent guest bind mount {target}"))
}

fn create_dir(path: &Path, mode: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "required path is not a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set directory mode {}", path.display()))?;
    Ok(())
}

fn create_symlink(target: &str, link: &str) -> Result<()> {
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::read_link(link).ok().as_deref() == Some(Path::new(target)),
                "existing guest device link has unexpected target"
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("create guest device link {link}")),
    }
}

fn replace_ptmx_link() -> Result<()> {
    let path = Path::new("/dev/ptmx");
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_symlink() || metadata.file_type().is_char_device(),
                "existing /dev/ptmx has an unexpected file type"
            );
            if metadata.file_type().is_symlink()
                && fs::read_link(path).ok().as_deref() == Some(Path::new("/dev/pts/ptmx"))
            {
                return Ok(());
            }
            fs::remove_file(path).context("replace devtmpfs /dev/ptmx")?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect devtmpfs /dev/ptmx"),
    }
    std::os::unix::fs::symlink("/dev/pts/ptmx", path).context("link active devpts ptmx")
}

fn mount_fs(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    data: &str,
) -> Result<()> {
    let source = CString::new(source).context("mount source contains NUL")?;
    let target_c = CString::new(target).context("mount target contains NUL")?;
    let kind = CString::new(kind).context("mount type contains NUL")?;
    let data = CString::new(data).context("mount data contains NUL")?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            kind.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("mount {kind:?} at {target}"));
    }
    Ok(())
}

fn spawn_daemon() -> Result<libc::pid_t> {
    let mut command = Command::new(INIT_PATH);
    command
        .arg("daemon")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let child = command
        .spawn()
        .context("spawn environment-free guest daemon")?;
    let pid = libc::pid_t::try_from(child.id()).context("guest daemon PID exceeds pid_t")?;
    drop(child);
    Ok(pid)
}

fn supervise_daemon(daemon_pid: libc::pid_t) -> Result<()> {
    loop {
        if POWEROFF_REQUESTED.load(Ordering::Acquire) {
            stop_daemon(daemon_pid);
            return power_off();
        }

        let mut status = 0;
        // Do not block in waitpid: a poweroff signal can arrive after the
        // flag check but before waitpid enters the kernel, in which case the
        // handler has already run and there may be no later signal to wake a
        // blocking wait. Bounded polling keeps signal handling and adopted-
        // child reaping race-free without letting PID 1 steal waits from the
        // still-running Tokio daemon.
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped == daemon_pid {
            eprintln!("guest daemon exited; powering off generation");
            return power_off();
        }
        if reaped > 0 {
            // This can only be a child adopted after its Tokio-owning daemon
            // parent exited. PID 1 is the sole waiter for adopted processes.
            continue;
        }
        if reaped == 0 {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            bail!("guest daemon disappeared without a waitable child");
        }
        return Err(error).context("reap guest child");
    }
}

fn stop_daemon(daemon_pid: libc::pid_t) {
    unsafe {
        libc::kill(daemon_pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + DAEMON_SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if reaped == daemon_pid
            || (reaped == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(daemon_pid, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(daemon_pid, &mut status, 0) == -1
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
}

extern "C" fn request_poweroff_signal(_: libc::c_int) {
    POWEROFF_REQUESTED.store(true, Ordering::Release);
}

fn install_poweroff_handlers() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_poweroff_signal as *const () as usize;
    action.sa_flags = libc::SA_NOCLDSTOP;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGUSR1, libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
            return Err(io::Error::last_os_error()).context("install guest init signal handler");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        return;
    };
    let Ok(mut interrupt) = signal(SignalKind::interrupt()) else {
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

fn power_off() -> Result<()> {
    unsafe {
        libc::sync();
    }
    let result = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("power off guest");
    }
    bail!("guest poweroff syscall unexpectedly returned")
}

/// PID 1 must not return into the kernel after a setup or supervision error.
/// Attempt a synchronized poweroff and, if the syscall itself fails, attempt
/// to kill the remaining workload and keep polling for exited children until
/// the host force-stops the failed VM.
pub fn halt_after_init_failure() -> ! {
    unsafe {
        libc::sync();
        if libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) == -1 {
            // The VM should grant PID 1 CAP_SYS_BOOT. If it does not, make a
            // best-effort attempt to stop every other guest process while the
            // host times out and force-stops the failed VM.
            libc::kill(-1, libc::SIGKILL);
        }
    }
    eprintln!("guest PID 1 poweroff failed; halting without exiting");
    loop {
        unsafe {
            let mut status = 0;
            while libc::waitpid(-1, &mut status, libc::WNOHANG) > 0 {}
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn validate_nonce(nonce: &OsStr) -> Result<&str> {
    let nonce = nonce
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("nonce is not UTF-8"))?;
    ensure!(
        !nonce.is_empty() && nonce.len() <= NONCE_MAX_LEN,
        "nonce length is invalid"
    );
    ensure!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "nonce contains invalid characters"
    );
    Ok(nonce)
}

fn read_nonce(path: &Path) -> Result<String> {
    ensure!(path.is_absolute(), "nonce path must be absolute");
    let bytes = read_bounded(path, NONCE_MAX_LEN + 1).context("read guest nonce")?;
    let nonce = OsStr::from_bytes(&bytes);
    Ok(validate_nonce(nonce)?.to_owned())
}

fn write_durable(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    ensure!(path.is_absolute(), "durable output path must be absolute");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable output has no parent"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("durable output name is invalid"))?;

    for _ in 0..16 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp.{}.{}", std::process::id(), sequence));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create durable temporary file"),
        };
        let operation = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(parent)?.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = operation {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("commit durable guest file");
        }
        return Ok(());
    }
    bail!("durable temporary filename collisions exceeded limit")
}

fn verify_loopback_only(sys_net: &Path, route: &Path, ipv6_route: &Path) -> Result<()> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir(sys_net)
        .with_context(|| format!("read guest network interfaces {}", sys_net.display()))?
    {
        interfaces.push(entry.context("read guest network interface")?.file_name());
    }
    interfaces.sort();
    ensure!(
        interfaces.as_slice() == [OsStr::new("lo")],
        "guest has a non-loopback network interface"
    );

    let routes = fs::read_to_string(route)
        .with_context(|| format!("read guest route table {}", route.display()))?;
    for line in routes
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let interface = line
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("guest route table is malformed"))?;
        ensure!(interface == "lo", "guest has a non-loopback route");
    }

    match fs::read_to_string(ipv6_route) {
        Ok(routes) => {
            for line in routes.lines().filter(|line| !line.trim().is_empty()) {
                let interface = line
                    .split_ascii_whitespace()
                    .next_back()
                    .ok_or_else(|| anyhow::anyhow!("guest IPv6 route table is malformed"))?;
                ensure!(interface == "lo", "guest has a non-loopback IPv6 route");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A kernel with IPv6 disabled has no IPv6 route surface.
        }
        Err(error) => return Err(error).context("read guest IPv6 route table"),
    }
    Ok(())
}

fn verify_no_ip_egress_canaries() -> Result<()> {
    // TEST-NET-1 is reserved for documentation and must never be routed by
    // this no-net VM. Opening each socket is the positive control that the
    // corresponding syscall/protocol path ran; connect must then fail at
    // route lookup rather than silently succeeding.
    for (label, socket_type, protocol, address, port) in [
        (
            "TCP",
            libc::SOCK_STREAM,
            libc::IPPROTO_TCP,
            [192, 0, 2, 1],
            9,
        ),
        (
            "UDP",
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
            [192, 0, 2, 1],
            9,
        ),
        (
            "DNS",
            libc::SOCK_DGRAM,
            libc::IPPROTO_UDP,
            [192, 0, 2, 53],
            53,
        ),
        (
            "ICMP",
            libc::SOCK_DGRAM,
            libc::IPPROTO_ICMP,
            [192, 0, 2, 1],
            0,
        ),
    ] {
        verify_unroutable_ipv4(label, socket_type, protocol, address, port)?;
    }
    Ok(())
}

fn verify_unroutable_ipv4(
    label: &str,
    socket_type: libc::c_int,
    protocol: libc::c_int,
    address: [u8; 4],
    port: u16,
) -> Result<()> {
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, socket_type | libc::SOCK_CLOEXEC, protocol) };
    if descriptor == -1 {
        let error = io::Error::last_os_error();
        if label == "ICMP" && acceptable_icmp_socket_denial(error.raw_os_error()) {
            // Ping datagram sockets are subject to the kernel's ping-group and
            // protocol policy even for a uid-0 process without capabilities.
            // TCP/UDP/DNS above remain mandatory route-lookup canaries; an
            // narrow kernel policy denial is itself a fail-closed result rather
            // than evidence of an egress path. Unsupported protocol errors are
            // rejected because they would skip the intended ICMP canary.
            return Ok(());
        }
        return Err(error).with_context(|| format!("open {label} canary socket"));
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let endpoint = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address),
        },
        sin_zero: [0; 8],
    };
    let result = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&descriptor),
            (&raw const endpoint).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    ensure!(
        result == -1,
        "guest {label} canary unexpectedly found an IP route"
    );
    let error = io::Error::last_os_error();
    ensure!(
        matches!(
            error.raw_os_error(),
            Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH) | Some(libc::ENODEV)
        ),
        "guest {label} canary failed for a reason other than no route: {error}"
    );
    Ok(())
}

fn acceptable_icmp_socket_denial(error: Option<libc::c_int>) -> bool {
    matches!(error, Some(libc::EACCES | libc::EPERM))
}

fn ensure_init_is_expected() -> Result<()> {
    let executable = fs::read_link("/proc/1/exe").context("inspect guest PID 1 executable")?;
    ensure!(
        executable == Path::new(INIT_PATH),
        "guest PID 1 is not /init"
    );
    Ok(())
}

trait PoweroffOperations {
    fn persist_marker(&mut self) -> Result<()>;
    fn emit_marker(&mut self) -> Result<()>;
    fn signal_init(&mut self) -> Result<()>;
}

fn request_poweroff(operations: &mut impl PoweroffOperations) -> Result<()> {
    operations.persist_marker()?;
    operations.emit_marker()?;
    operations.signal_init()
}

struct RealPoweroffOperations {
    marker: String,
}

impl PoweroffOperations for RealPoweroffOperations {
    fn persist_marker(&mut self) -> Result<()> {
        write_durable(
            Path::new(POWEROFF_MARKER_PATH),
            self.marker.as_bytes(),
            0o600,
        )
    }

    fn emit_marker(&mut self) -> Result<()> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(self.marker.as_bytes())?;
        stdout.flush()?;
        Ok(())
    }

    fn signal_init(&mut self) -> Result<()> {
        if unsafe { libc::kill(1, libc::SIGUSR1) } == -1 {
            return Err(io::Error::last_os_error()).context("signal guest init for poweroff");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use tempfile::TempDir;

    #[derive(Default)]
    struct CountingWake(AtomicU64);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn disk_discovery_requires_one_exact_whole_disk_serial() {
        let temporary = TempDir::new().unwrap();
        let sys = temporary.path().join("sys");
        let dev = temporary.path().join("dev");
        fs::create_dir_all(&sys).unwrap();
        fs::create_dir_all(&dev).unwrap();
        for (name, serial) in [
            ("vda", "CWSTATE1\n"),
            ("vda1", "CWSTATE1\n"),
            ("vdb", "other\n"),
        ] {
            fs::create_dir(sys.join(name)).unwrap();
            fs::write(sys.join(name).join("serial"), serial).unwrap();
        }

        assert_eq!(
            find_disk_by_serial(&sys, &dev, STATE_DISK_SERIAL).unwrap(),
            dev.join("vda")
        );
        fs::write(sys.join("vdb").join("serial"), "CWSTATE1\n").unwrap();
        assert!(
            find_disk_by_serial(&sys, &dev, STATE_DISK_SERIAL)
                .unwrap_err()
                .to_string()
                .contains("multiple")
        );
    }

    #[test]
    fn nonce_write_is_atomic_and_strict() {
        let temporary = TempDir::new().unwrap();
        let output = temporary.path().join("nonce");

        write_durable(&output, b"nonce_123", 0o600).unwrap();
        assert_eq!(read_nonce(&output).unwrap(), "nonce_123");
        write_durable(&output, b"replacement-456", 0o600).unwrap();
        assert_eq!(read_nonce(&output).unwrap(), "replacement-456");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(validate_nonce(OsStr::new("contains space")).is_err());
        assert!(!fs::read_dir(temporary.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")
        }));
    }

    #[test]
    fn network_check_requires_exactly_loopback() {
        let temporary = TempDir::new().unwrap();
        let sys = temporary.path().join("net");
        fs::create_dir(&sys).unwrap();
        fs::create_dir(sys.join("lo")).unwrap();
        let route = temporary.path().join("route");
        fs::write(&route, "Iface Destination Gateway Flags\n").unwrap();
        let ipv6_route = temporary.path().join("ipv6_route");
        fs::write(
            &ipv6_route,
            "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000 00000001 00000000 80200001 lo\n",
        )
        .unwrap();
        verify_loopback_only(&sys, &route, &ipv6_route).unwrap();

        fs::create_dir(sys.join("eth0")).unwrap();
        assert!(verify_loopback_only(&sys, &route, &ipv6_route).is_err());
    }

    #[test]
    fn only_explicit_icmp_socket_policy_denials_are_accepted() {
        for error in [libc::EACCES, libc::EPERM] {
            assert!(acceptable_icmp_socket_denial(Some(error)));
        }
        for error in [
            libc::EAFNOSUPPORT,
            libc::EPROTONOSUPPORT,
            libc::ENETUNREACH,
            libc::EINVAL,
            libc::EMFILE,
        ] {
            assert!(!acceptable_icmp_socket_denial(Some(error)));
        }
        assert!(!acceptable_icmp_socket_denial(None));
    }

    #[derive(Default)]
    struct RecordingPoweroff {
        events: Vec<&'static str>,
        fail_emit: bool,
    }

    impl PoweroffOperations for RecordingPoweroff {
        fn persist_marker(&mut self) -> Result<()> {
            self.events.push("persist");
            Ok(())
        }

        fn emit_marker(&mut self) -> Result<()> {
            self.events.push("emit");
            if self.fail_emit {
                bail!("emit failed")
            }
            Ok(())
        }

        fn signal_init(&mut self) -> Result<()> {
            self.events.push("signal");
            Ok(())
        }
    }

    #[test]
    fn poweroff_signals_only_after_durable_and_emitted_acceptance() {
        let mut operations = RecordingPoweroff::default();
        request_poweroff(&mut operations).unwrap();
        assert_eq!(operations.events, ["persist", "emit", "signal"]);

        let mut operations = RecordingPoweroff {
            fail_emit: true,
            ..RecordingPoweroff::default()
        };
        assert!(request_poweroff(&mut operations).is_err());
        assert_eq!(operations.events, ["persist", "emit"]);
    }

    #[test]
    fn daemon_transport_accepts_only_the_host_cid() {
        assert!(is_host_cid(VMADDR_CID_HOST));
        assert!(!is_host_cid(VMADDR_CID_ANY));
        assert!(!is_host_cid(3));
        assert!(!is_host_cid(u32::MAX));
    }

    #[test]
    fn rejected_guest_connections_yield_at_the_bounded_budget() {
        let wake = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = TaskContext::from_waker(&waker);
        let mut rejected = 0;

        for _ in 1..HOST_ONLY_REJECTION_BUDGET {
            assert!(!rejected_connection_requires_yield(
                &mut rejected,
                &mut context
            ));
        }
        assert_eq!(wake.0.load(Ordering::Relaxed), 0);
        assert!(rejected_connection_requires_yield(
            &mut rejected,
            &mut context
        ));
        assert_eq!(rejected, HOST_ONLY_REJECTION_BUDGET);
        assert_eq!(wake.0.load(Ordering::Relaxed), 1);
    }
}
