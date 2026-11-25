//! A guest-carried daemon's inherited gRPC listener (#5602, cw-security's
//! conditions). In a standard Pod's guest, guest init binds the daemon's
//! listener as root in the workspace namespace before the container starts,
//! holds it for the guest's life, and passes it to the hosted daemon alone,
//! so no workspace process can bind that address. The daemon takes it in
//! `main`, before any thread starts: it checks the descriptor, makes it
//! close-on-exec and removes its variable, so no child gets either, and makes
//! itself undumpable, so no process of the same uid can take it. Without the
//! variable, as on Kata, nothing here runs.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Mutex;

use anyhow::{Context as _, ensure};
use codewire_vmm_guest_probe::hosted_control::{
    HOSTED_DAEMON_GUEST_PORT, HOSTED_DAEMON_LISTENER_FD, HOSTED_DAEMON_LISTENER_FD_ENV,
};

static INHERITED: Mutex<Option<std::net::TcpListener>> = Mutex::new(None);

/// Takes the inherited listener, if the guest passed one. Call from `main`
/// before any thread starts: it changes the process environment.
pub fn take_from_environment() -> anyhow::Result<()> {
    let Some(value) = std::env::var_os(HOSTED_DAEMON_LISTENER_FD_ENV) else {
        return Ok(());
    };
    // SAFETY: `main` calls this before it starts the runtime or any other
    // thread, so nothing reads the environment concurrently.
    unsafe { std::env::remove_var(HOSTED_DAEMON_LISTENER_FD_ENV) };
    ensure!(
        value == HOSTED_DAEMON_LISTENER_FD.to_string().as_str(),
        "the variable {HOSTED_DAEMON_LISTENER_FD_ENV} names another descriptor"
    );
    // SAFETY: F_GETFD only reads the descriptor's flags.
    ensure!(
        unsafe { libc::fcntl(HOSTED_DAEMON_LISTENER_FD, libc::F_GETFD) } != -1,
        "the inherited listener descriptor is not open"
    );
    // SAFETY: the guest passed this descriptor to this process alone, and
    // nothing else in it owns the number.
    let descriptor = unsafe { OwnedFd::from_raw_fd(HOSTED_DAEMON_LISTENER_FD) };
    let listener = admit(descriptor)?;
    make_undumpable()?;
    *INHERITED
        .lock()
        .map_err(|_| anyhow::anyhow!("the inherited listener's lock is poisoned"))? =
        Some(listener);
    Ok(())
}

/// For `cw __hosted-daemon`, takes the inherited listener before `main`
/// starts any thread (#5602); a failure ends the process.
pub fn take_before_runtime() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|role| role == "__hosted-daemon")
        && let Err(error) = take_from_environment()
    {
        eprintln!("cw: {error:#}");
        std::process::exit(1);
    }
}

/// The inherited listener, once.
pub fn take() -> Option<std::net::TcpListener> {
    INHERITED.lock().ok()?.take()
}

/// The descriptor as the guest must have made it: close-on-exec from here
/// on, a listening TCP socket on 127.0.0.1 at the daemon's port, without
/// `SO_REUSEPORT`.
fn admit(descriptor: OwnedFd) -> anyhow::Result<std::net::TcpListener> {
    let fd = descriptor.as_raw_fd();
    // SAFETY: setting FD_CLOEXEC on an owned descriptor.
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != -1,
        "mark the inherited listener close-on-exec"
    );
    let option = |level, name| -> anyhow::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())?;
        // SAFETY: a live, correctly sized option buffer for an owned socket.
        let read = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        ensure!(read == 0, "the inherited listener is not a socket");
        Ok(value)
    };
    ensure!(
        option(libc::SOL_SOCKET, libc::SO_DOMAIN)? == libc::AF_INET
            && option(libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_STREAM
            && option(libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? == 1,
        "the inherited descriptor is not a listening TCP socket"
    );
    ensure!(
        option(libc::SOL_SOCKET, libc::SO_REUSEPORT)? == 0,
        "the inherited listener allows SO_REUSEPORT"
    );
    let listener = std::net::TcpListener::from(descriptor);
    let address = listener
        .local_addr()
        .context("read the inherited listener's address")?;
    ensure!(
        address
            == std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                HOSTED_DAEMON_GUEST_PORT
            )),
        "the inherited listener is bound to {address}, not the daemon's loopback port"
    );
    listener
        .set_nonblocking(true)
        .context("make the inherited listener nonblocking")?;
    Ok(listener)
}

/// No process of the same uid may trace this one or take its descriptors.
fn make_undumpable() -> anyhow::Result<()> {
    // SAFETY: plain prctl calls with integer arguments.
    unsafe {
        ensure!(
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0,
            "make the hosted daemon undumpable"
        );
        ensure!(
            libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0,
            "the hosted daemon is still dumpable"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marks the re-executed test binary that plays the hosted daemon.
    const CHILD_ENV: &str = "CODEWIRE_TEST_HOSTED_LISTENER_CHILD";
    const CHILD_TEST: &str = "hosted_listener::tests::inherited_listener_child";

    /// The daemon's side of the next test: it takes the listener as `main`
    /// does, then starts a grandchild and reports what that one can see.
    #[test]
    fn inherited_listener_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        take_from_environment().unwrap();
        assert!(std::env::var_os(HOSTED_DAEMON_LISTENER_FD_ENV).is_none());
        assert!(take().is_some(), "the listener was not taken");
        let grandchild = crate::process::command("/bin/sh", &[])
            .args([
                "-c",
                &format!(
                    "test -e /proc/self/fd/{HOSTED_DAEMON_LISTENER_FD} && echo HAS_FD; env | grep -c {HOSTED_DAEMON_LISTENER_FD_ENV} || true"
                ),
            ])
            .output()
            .unwrap();
        let seen = String::from_utf8(grandchild.stdout).unwrap();
        assert_eq!(seen.trim(), "0", "the grandchild saw: {seen}");
    }

    /// cw-security's condition: neither the variable nor the descriptor
    /// reaches anything the daemon starts. The test binary runs again as the
    /// daemon, given descriptor 9 and the variable as the guest gives them.
    #[test]
    fn no_child_of_the_daemon_inherits_the_listener_or_its_variable() {
        use std::os::unix::process::CommandExt as _;
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        let _port = DAEMON_PORT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The daemon's port may be taken on a shared test host.
        let Ok(listener) =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, HOSTED_DAEMON_GUEST_PORT))
        else {
            eprintln!("127.0.0.1:{HOSTED_DAEMON_GUEST_PORT} is taken here; nothing to show");
            return;
        };
        let source = listener.as_raw_fd();
        let mut child = crate::process::command(std::env::current_exe().unwrap(), &[]);
        child
            .args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .env(
                HOSTED_DAEMON_LISTENER_FD_ENV,
                HOSTED_DAEMON_LISTENER_FD.to_string(),
            );
        // SAFETY: only dup2 and fcntl between fork and exec.
        unsafe {
            child.pre_exec(move || {
                if libc::dup2(source, HOSTED_DAEMON_LISTENER_FD) == -1
                    || libc::fcntl(HOSTED_DAEMON_LISTENER_FD, libc::F_SETFD, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        drop(listener);
        assert!(
            output.status.success(),
            "the daemon side failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    fn listener_on(address: (std::net::Ipv4Addr, u16)) -> Option<OwnedFd> {
        std::net::TcpListener::bind(address).ok().map(OwnedFd::from)
    }

    /// Both tests below bind the daemon's port; one at a time.
    static DAEMON_PORT: Mutex<()> = Mutex::new(());

    #[test]
    fn only_a_loopback_listener_on_the_daemon_port_is_admitted() {
        let _port = DAEMON_PORT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The daemon's port may be taken on a shared test host; then only
        // the refusals below are shown.
        if let Some(descriptor) =
            listener_on((std::net::Ipv4Addr::LOCALHOST, HOSTED_DAEMON_GUEST_PORT))
        {
            drop(admit(descriptor).unwrap());
        }
        let elsewhere = listener_on((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(
            admit(elsewhere)
                .unwrap_err()
                .to_string()
                .contains("not the daemon's loopback port")
        );
        let (stream, _) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(admit(OwnedFd::from(stream)).is_err());
        let unbound = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(admit(OwnedFd::from(unbound)).is_err());
    }
}
