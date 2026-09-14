use std::ffi::CStr;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::io::Write as _;
#[cfg(test)]
use std::os::unix::net::UnixStream;

#[cfg(test)]
use super::topology::local_address;
use super::topology::validate_listener;
use super::{PAYLOAD_LEN, destination, payload};
use crate::linux::confinement::install_deny_all_filesystem_domain;
#[cfg(test)]
use crate::linux::confinement::lock_process_privileges;
use crate::macos_console_pair_fixture::{Result, descriptor as fd, invalid, process};

pub(in crate::macos_console_pair_fixture) const ENDPOINT_READY_MESSAGE: &[u8] = b"CWPNEND1 ready\n";
pub(in crate::macos_console_pair_fixture) const ENDPOINT_COMPLETED_MESSAGE: &[u8] =
    b"CWPNEND1 completed\n";
pub(in crate::macos_console_pair_fixture) const ENDPOINT_CANCEL_MESSAGE: &[u8] =
    b"CWPNEND1 cancel\n";

const ENDPOINT_LISTENER_FD: RawFd = 3;
const ENDPOINT_CONTROL_FD: RawFd = 4;
const ENDPOINT_RUNTIME: Duration = Duration::from_secs(20);

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_DATA_SYSCALL_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGUMENT_0_OFFSET: u32 = 16;
const SECCOMP_DATA_ARGUMENT_3_OFFSET: u32 = 40;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("product-network fixture supports only reviewed Linux architectures");

/// Run the sealed endpoint child with its two exact inherited capabilities.
pub(in crate::macos_console_pair_fixture) fn run_inherited_endpoint() -> Result<()> {
    process::child_invariants(&[ENDPOINT_LISTENER_FD, ENDPOINT_CONTROL_FD])?;
    run_endpoint(
        ENDPOINT_LISTENER_FD,
        ENDPOINT_CONTROL_FD,
        destination(),
        c"/init",
    )
}

fn run_endpoint(
    listener_fd: RawFd,
    control_fd: RawFd,
    expected: SocketAddr,
    executable: &CStr,
) -> Result<()> {
    if listener_fd != ENDPOINT_LISTENER_FD || control_fd != ENDPOINT_CONTROL_FD {
        return Err(invalid());
    }
    fd::distinct(&[listener_fd, control_fd])?;
    set_cloexec(listener_fd)?;
    set_cloexec(control_fd)?;
    validate_listener(listener_fd, expected)?;
    fd::require_rw_nonblocking(control_fd)?;
    fd::unix_stream(control_fd)?;

    let listener = unsafe { OwnedFd::from_raw_fd(listener_fd) };
    let control = unsafe { OwnedFd::from_raw_fd(control_fd) };
    install_deny_all_filesystem_domain()?;
    install_endpoint_filter()?;
    process::denial_canaries(executable)?;
    endpoint_denial_canaries()?;

    let deadline = Instant::now() + ENDPOINT_RUNTIME;
    let mut cancellation = CancelReader::new();
    fd::write_all(control.as_raw_fd(), ENDPOINT_READY_MESSAGE, deadline)?;
    let connected = accept_one(&listener, &control, &mut cancellation, expected, deadline)?;
    drop(listener);
    exchange(&connected, &control, &mut cancellation, deadline)?;
    drop(connected);
    check_control_now(&control, &mut cancellation, deadline)?;
    cancellation.require_empty()?;
    fd::write_all(control.as_raw_fd(), ENDPOINT_COMPLETED_MESSAGE, deadline)
}

fn endpoint_denial_canaries() -> Result<()> {
    require_denied(unsafe {
        libc::syscall(
            libc::SYS_accept,
            ENDPOINT_LISTENER_FD,
            std::ptr::null_mut::<libc::sockaddr>(),
            std::ptr::null_mut::<libc::socklen_t>(),
        )
    })?;
    require_denied(unsafe {
        libc::syscall(
            libc::SYS_accept4,
            ENDPOINT_CONTROL_FD,
            std::ptr::null_mut::<libc::sockaddr>(),
            std::ptr::null_mut::<libc::socklen_t>(),
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    })?;
    require_denied(unsafe {
        libc::syscall(
            libc::SYS_accept4,
            ENDPOINT_LISTENER_FD,
            std::ptr::null_mut::<libc::sockaddr>(),
            std::ptr::null_mut::<libc::socklen_t>(),
            0,
        )
    })
}

fn require_denied(result: libc::c_long) -> Result<()> {
    let error = io::Error::last_os_error();
    if result == -1 && error.raw_os_error() == Some(libc::EPERM) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn set_cloexec(descriptor: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn accept_one(
    listener: &OwnedFd,
    control: &OwnedFd,
    cancellation: &mut CancelReader,
    expected: SocketAddr,
    deadline: Instant,
) -> Result<OwnedFd> {
    let expected_ip = expected.ip();
    loop {
        let mut events = [
            fd::pollfd(control.as_raw_fd(), libc::POLLIN),
            fd::pollfd(listener.as_raw_fd(), libc::POLLIN),
        ];
        fd::poll(&mut events, deadline)?;
        cancellation.check(&events[0], control.as_raw_fd())?;
        reject_invalid_event(&events[1])?;
        if events[1].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            continue;
        }
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        let accepted = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                (&raw mut address).cast(),
                &mut length,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if accepted < 0 {
            let error = io::Error::last_os_error();
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) {
                continue;
            }
            return Err(error);
        }
        let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
        if length as usize != std::mem::size_of_val(&address)
            || address.sin_family as libc::c_int != libc::AF_INET
        {
            return Err(invalid());
        }
        let peer = SocketAddr::from((
            address.sin_addr.s_addr.to_ne_bytes(),
            u16::from_be(address.sin_port),
        ));
        if peer.ip() != expected_ip || peer.port() == 0 || peer.port() == expected.port() {
            return Err(invalid());
        }
        return Ok(accepted);
    }
}

fn exchange(
    stream: &OwnedFd,
    control: &OwnedFd,
    cancellation: &mut CancelReader,
    deadline: Instant,
) -> Result<()> {
    let expected = payload(false);
    let mut received = [0_u8; PAYLOAD_LEN];
    let mut position = 0;
    while position < received.len() {
        wait_stream_or_cancel(stream, control, cancellation, libc::POLLIN, deadline)?;
        match fd::read_some(stream.as_raw_fd(), &mut received[position..]) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(count) => position += count,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(error) => return Err(error),
        }
    }
    if received != expected {
        return Err(invalid());
    }

    let mut extra = [0_u8; 1];
    loop {
        wait_stream_or_cancel(stream, control, cancellation, libc::POLLIN, deadline)?;
        match fd::read_some(stream.as_raw_fd(), &mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(invalid()),
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(error) => return Err(error),
        }
    }

    let response = payload(true);
    let mut position = 0;
    while position < response.len() {
        check_control_now(control, cancellation, deadline)?;
        match fd::write_some(stream.as_raw_fd(), &response[position..]) {
            Ok(0) => return Err(io::Error::from(ErrorKind::WriteZero)),
            Ok(count) => position += count,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                wait_stream_or_cancel(stream, control, cancellation, libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    if unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_WR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn check_control_now(
    control: &OwnedFd,
    cancellation: &mut CancelReader,
    deadline: Instant,
) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        let mut event = fd::pollfd(control.as_raw_fd(), libc::POLLIN);
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let polled =
            unsafe { libc::ppoll(&raw mut event, 1, &raw const timeout, std::ptr::null()) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if polled == 0 {
            return Ok(());
        }
        return cancellation.check(&event, control.as_raw_fd());
    }
}

fn wait_stream_or_cancel(
    stream: &OwnedFd,
    control: &OwnedFd,
    cancellation: &mut CancelReader,
    stream_events: i16,
    deadline: Instant,
) -> Result<()> {
    let mut events = [
        fd::pollfd(control.as_raw_fd(), libc::POLLIN),
        fd::pollfd(stream.as_raw_fd(), stream_events),
    ];
    fd::poll(&mut events, deadline)?;
    cancellation.check(&events[0], control.as_raw_fd())?;
    reject_invalid_event(&events[1])
}

fn reject_invalid_event(event: &libc::pollfd) -> Result<()> {
    if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        Err(invalid())
    } else {
        Ok(())
    }
}

struct CancelReader {
    bytes: [u8; ENDPOINT_CANCEL_MESSAGE.len()],
    position: usize,
}

impl CancelReader {
    fn new() -> Self {
        Self {
            bytes: [0; ENDPOINT_CANCEL_MESSAGE.len()],
            position: 0,
        }
    }

    fn check(&mut self, event: &libc::pollfd, descriptor: RawFd) -> Result<()> {
        if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(invalid());
        }
        if event.revents & libc::POLLIN == 0 {
            return Ok(());
        }
        match fd::read_some(descriptor, &mut self.bytes[self.position..]) {
            Ok(0) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(count) => {
                self.position += count;
                if !ENDPOINT_CANCEL_MESSAGE.starts_with(&self.bytes[..self.position]) {
                    return Err(invalid());
                }
                if self.position == ENDPOINT_CANCEL_MESSAGE.len() {
                    return Err(io::Error::from(ErrorKind::Interrupted));
                }
                Ok(())
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn require_empty(&self) -> Result<()> {
        if self.position == 0 {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn install_endpoint_filter() -> Result<()> {
    let statement = |code, value| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    };
    let equal = |value, yes, no| libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: yes,
        jf: no,
        k: value,
    };
    let mut program = vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        equal(AUDIT_ARCH_NATIVE, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_SYSCALL_OFFSET),
    ];
    for call in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_ppoll,
        libc::SYS_clock_gettime,
        libc::SYS_shutdown,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
    ] {
        program.push(equal(call as u32, 0, 1));
        program.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    }

    let accept_check = program.len();
    program.push(equal(libc::SYS_accept4 as u32, 0, 0));
    let mut guards = Vec::new();
    for (offset, expected) in [
        (SECCOMP_DATA_ARGUMENT_0_OFFSET, ENDPOINT_LISTENER_FD as u32),
        (SECCOMP_DATA_ARGUMENT_0_OFFSET + 4, 0),
        (
            SECCOMP_DATA_ARGUMENT_3_OFFSET,
            (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u32,
        ),
        (SECCOMP_DATA_ARGUMENT_3_OFFSET + 4, 0),
    ] {
        program.push(statement(BPF_LD_W_ABS, offset));
        guards.push(program.len());
        program.push(equal(expected, 0, 0));
    }
    program.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let denied = program.len();
    program.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    program[accept_check].jf = jump_to(accept_check, denied)?;
    for guard in guards {
        program[guard].jf = jump_to(guard, denied)?;
    }
    let filter = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(|_| invalid())?,
        filter: program.as_mut_ptr(),
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 1_u32, 0_u32, &raw const filter) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn jump_to(from: usize, to: usize) -> Result<u8> {
    to.checked_sub(from + 1)
        .and_then(|distance| u8::try_from(distance).ok())
        .ok_or_else(invalid)
}

#[cfg(test)]
pub(super) fn run_inherited_endpoint_for_test(executable: &CStr) -> Result<()> {
    if std::env::vars_os().next().is_some() {
        return Err(invalid());
    }
    lock_process_privileges()?;
    let expected = local_address(ENDPOINT_LISTENER_FD)?;
    if !expected.ip().is_loopback() || expected.port() == 0 {
        return Err(invalid());
    }
    run_endpoint(
        ENDPOINT_LISTENER_FD,
        ENDPOINT_CONTROL_FD,
        expected,
        executable,
    )
}

#[cfg(test)]
pub(super) fn verify_zero_wait_and_retained_partial_cancel() -> Result<()> {
    let (reader, mut writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    writer.set_nonblocking(true)?;
    let reader = OwnedFd::from(reader);
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut cancellation = CancelReader::new();

    check_control_now(&reader, &mut cancellation, deadline)?;
    writer.write_all(&ENDPOINT_CANCEL_MESSAGE[..5])?;
    check_control_now(&reader, &mut cancellation, deadline)?;
    if cancellation.require_empty().is_ok() {
        return Err(invalid());
    }
    writer.write_all(&ENDPOINT_CANCEL_MESSAGE[5..])?;
    match check_control_now(&reader, &mut cancellation, deadline) {
        Err(error) if error.kind() == ErrorKind::Interrupted => Ok(()),
        _ => Err(invalid()),
    }
}
