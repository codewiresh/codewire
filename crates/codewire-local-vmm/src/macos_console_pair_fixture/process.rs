use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::descriptor as fd;
use super::{Result, invalid};
use crate::linux::confinement::{
    install_deny_all_filesystem_domain, lock_process_privileges, require_single_threaded_process,
};

pub(super) const ADAPTER_PREPARED: u8 = b'P';
pub(super) const ADAPTER_GO: u8 = b'G';
pub(super) const ADAPTER_STOP: u8 = b'S';
pub(super) const ADAPTER_CHAR_EOF: u8 = b'E';
pub(super) const ADAPTER_UNIX_EOF: u8 = b'U';
pub(super) const ADAPTER_CANCELLED: u8 = b'C';
pub(super) const ADAPTER_FAILED: u8 = b'F';

pub(super) struct OwnedChild {
    child: Child,
    status: Option<ExitStatus>,
    uncertain: bool,
}

impl OwnedChild {
    pub(super) fn poll(&mut self) -> Result<Option<ExitStatus>> {
        if self.uncertain {
            return Err(invalid());
        }
        if self.status.is_none() {
            match self.child.try_wait() {
                Ok(value) => self.status = value,
                Err(error) => {
                    self.uncertain = true;
                    return Err(error);
                }
            }
        }
        Ok(self.status)
    }

    /// Sole reaper; a live/unreaped direct child reserves its PID. Never adopt
    /// or signal an already-reaped/recovered PID, and never target a group.
    pub(super) fn terminate(&mut self, deadline: Instant) -> Result<ExitStatus> {
        if let Some(status) = self.poll()? {
            return Ok(status);
        }
        self.child.kill()?;
        loop {
            if let Some(status) = self.poll()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.uncertain = true;
                return Err(invalid());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.uncertain && self.status.is_none() {
            let _ = self.terminate(Instant::now() + Duration::from_secs(2));
        }
    }
}

pub(super) fn spawn(
    executable: &std::path::Path,
    arguments: &[String],
    mappings: &[(RawFd, RawFd)],
) -> Result<OwnedChild> {
    let expected_parent = unsafe { libc::getpid() };
    let mut originals = std::collections::BTreeSet::new();
    let mut targets = std::collections::BTreeSet::new();
    let mut copies = Vec::new();
    for &(source, target) in mappings {
        if !(3..=5).contains(&target) || !originals.insert(source) || !targets.insert(target) {
            return Err(invalid());
        }
        let copied = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 16) };
        if copied < 0 {
            return Err(io::Error::last_os_error());
        }
        copies.push((unsafe { OwnedFd::from_raw_fd(copied) }, target));
    }
    let mapped = copies
        .iter()
        .map(|(source, target)| (source.as_raw_fd(), *target))
        .collect::<Vec<_>>();
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Single-threaded trusted parent; the hook invokes only fixed descriptor,
    // signal, capability and prctl operations before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::getppid() != expected_parent
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != expected_parent
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for &(source, target) in &mapped {
                if libc::dup2(source, target) < 0 || libc::fcntl(target, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            lock_process_privileges()?;
            if libc::getppid() != expected_parent {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    Ok(OwnedChild {
        child,
        status: None,
        uncertain: false,
    })
}

pub(super) fn child_invariants(expected_fds: &[RawFd]) -> Result<()> {
    if std::env::vars_os().next().is_some() || unsafe { libc::getppid() } != 1 {
        return Err(invalid());
    }
    let mut death_signal: libc::c_int = 0;
    if unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut death_signal) } != 0
        || death_signal != libc::SIGKILL
    {
        return Err(invalid());
    }
    require_single_threaded_process()?;
    lock_process_privileges()?; // exec may reset dumpability; close it again.
    fd::distinct(expected_fds)?;
    // Check fixed inheritance without opening /proc/self/fd or accepting a
    // dynamic allowlist; close_range in pre-exec already handles all high FDs.
    for number in 3..16 {
        if unsafe { libc::fcntl(number, libc::F_GETFD) } >= 0 && !expected_fds.contains(&number) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Adapter-only default-deny syscall policy. It has no need to receive new
/// descriptors, duplicate a handle, perform an ioctl or create a process.
pub(super) fn install_adapter_filter() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("console fixture supports only reviewed Linux architectures");
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let mut program = vec![
        statement(0x20, 4),
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: ARCH,
        },
        statement(0x06, 0x8000_0000),
        statement(0x20, 0),
    ];
    for call in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_ppoll,
        libc::SYS_clock_gettime,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
    ] {
        program.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: call as u32,
        });
        program.push(statement(0x06, 0x7fff_0000));
    }
    program.push(statement(0x06, 0x0005_0000 | libc::EPERM as u32));
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &filter) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn exec_denial_canary(executable: &std::ffi::CStr) -> Result<()> {
    // If the boundary is absent, only this retained disposable child is
    // replaced. The same admitted binary rejects the fixed unsupported mode;
    // successful exec never returns a false successful denial observation.
    let arguments = [
        executable.as_ptr(),
        c"--execution-canary-must-not-run".as_ptr(),
        std::ptr::null(),
    ];
    let environment = [std::ptr::null::<libc::c_char>()];
    let result = unsafe {
        libc::syscall(
            libc::SYS_execve,
            executable.as_ptr(),
            arguments.as_ptr(),
            environment.as_ptr(),
        )
    };
    if result != -1 {
        return Err(invalid());
    }
    let error = io::Error::last_os_error();
    // The worker's existing Landlock layer returns EACCES; the adapter's
    // default-deny syscall layer returns EPERM. Missing/invalid executables
    // never prove confinement and must remain failures.
    if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
        Ok(())
    } else {
        Err(error)
    }
}

pub(super) fn denial_canaries(executable: &std::ffi::CStr) -> Result<()> {
    let pathname = unsafe { libc::open(c"/init".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if pathname >= 0 {
        unsafe {
            libc::close(pathname);
        }
        return Err(invalid());
    }
    if !matches!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::EACCES | libc::EPERM)
    ) {
        return Err(invalid());
    }
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket >= 0 {
        unsafe {
            libc::close(socket);
        }
        return Err(invalid());
    }
    if io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return Err(invalid());
    }
    exec_denial_canary(executable)?;
    // getpid is absent from the adapter policy. kill(0, 0) is a nonmutating
    // existence query; seccomp must reject it before resolving any target.
    if unsafe { libc::kill(0, 0) } != -1
        || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
    {
        return Err(invalid());
    }
    Ok(())
}

struct Buffer {
    bytes: [u8; 32 * 1024],
    start: usize,
    end: usize,
}
impl Buffer {
    fn new() -> Self {
        Self {
            bytes: [0; 32 * 1024],
            start: 0,
            end: 0,
        }
    }
    fn empty(&self) -> bool {
        self.start == self.end
    }
    fn write(&mut self, destination: RawFd) -> Result<()> {
        if self.empty() {
            return Ok(());
        }
        match fd::write_some(destination, &self.bytes[self.start..self.end]) {
            Ok(0) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => {
                self.start += count;
                if self.empty() {
                    self.start = 0;
                    self.end = 0;
                }
                Ok(())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    fn read(&mut self, source: RawFd) -> Result<bool> {
        if !self.empty() {
            return Ok(false);
        }
        match fd::read_some(source, &mut self.bytes) {
            Ok(0) => Ok(true),
            Ok(count) => {
                self.start = 0;
                self.end = count;
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

pub(super) fn bridge(
    character: RawFd,
    unix: RawFd,
    control: RawFd,
    deadline: Instant,
) -> Result<u8> {
    let mut to_unix = Buffer::new();
    let mut to_char = Buffer::new();
    loop {
        let mut events = [
            fd::pollfd(control, libc::POLLIN),
            fd::pollfd(
                character,
                (if to_unix.empty() { libc::POLLIN } else { 0 })
                    | (if !to_char.empty() { libc::POLLOUT } else { 0 }),
            ),
            fd::pollfd(
                unix,
                (if to_char.empty() { libc::POLLIN } else { 0 })
                    | (if !to_unix.empty() { libc::POLLOUT } else { 0 }),
            ),
        ];
        fd::poll(&mut events, deadline)?;
        // Cancellation takes precedence over more guest input.
        if events[0].revents != 0 {
            let mut byte = [0];
            match fd::read_some(control, &mut byte) {
                Ok(0) => return Ok(ADAPTER_CANCELLED),
                Ok(1) if byte[0] == ADAPTER_STOP => return Ok(ADAPTER_CANCELLED),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                _ => return Err(invalid()),
            }
        }
        for event in &events[1..] {
            if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(invalid());
            }
        }
        if events[1].revents & libc::POLLOUT != 0 {
            to_char.write(character)?;
        }
        if events[2].revents & libc::POLLOUT != 0 {
            to_unix.write(unix)?;
        }
        if events[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 && to_unix.read(character)? {
            return Ok(ADAPTER_CHAR_EOF);
        }
        if events[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 && to_char.read(unix)? {
            return Ok(ADAPTER_UNIX_EOF);
        }
    }
}

pub(super) fn adapter() -> Result<()> {
    child_invariants(&[3, 4, 5])?;
    if fd::stat(3)?.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Err(invalid());
    }
    for number in [3, 4, 5] {
        fd::require_rw_nonblocking(number)?;
    }
    fd::unix_stream(4)?;
    fd::unix_stream(5)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    install_deny_all_filesystem_domain()?;
    install_adapter_filter()?;
    denial_canaries(c"/init")?;
    prepared_adapter(deadline)
}

// Shared by the fixed production adapter and a test-only confined subprocess.
// Tests do not add a CLI mode or relax production descriptor/parent admission.
pub(super) fn prepared_adapter(deadline: Instant) -> Result<()> {
    fd::write_all(5, &[ADAPTER_PREPARED], deadline)?;
    // No character/packet FD is read or polled before one-use GO.
    let prepare_deadline = deadline.min(Instant::now() + Duration::from_secs(20));
    loop {
        fd::poll(&mut [fd::pollfd(5, libc::POLLIN)], prepare_deadline)?;
        let mut byte = [0];
        match fd::read_some(5, &mut byte) {
            Ok(1) if byte[0] == ADAPTER_GO => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            _ => return Err(invalid()),
        }
    }
    let result = bridge(3, 4, 5, deadline);
    let code = result.as_ref().copied().unwrap_or(ADAPTER_FAILED);
    fd::write_all(5, &[code], Instant::now() + Duration::from_secs(1))?;
    result.map(|_| ())
}
