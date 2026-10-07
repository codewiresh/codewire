//! Seatbelt confinement and thread observation for single-purpose workers.
//!
//! Seatbelt applies to the whole process at once, so a profile installed by
//! one thread also binds every other thread. The single-thread check still
//! guards the workers' design: nothing runs beside the confined event loop.

use std::ffi::{CStr, c_char, c_int};
use std::io;

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Deny every sandboxed operation. Descriptors the process already holds keep
/// working; any new file, named or network endpoint, process, signal or Mach
/// service is refused. An unnamed socketpair, which reaches nothing, remains.
const DENY_ALL_PROFILE: &CStr = c"(version 1)(deny default)";

/// The general egress broker's profile: everything is denied except dialing
/// TCP to any address and the broker's own DNS. Hickory binds its own UDP
/// port, sends each query to port 53 and receives the reply unconnected, so
/// it needs a UDP bind and inbound UDP; Seatbelt matches inbound datagrams
/// only by their local address. TCP to port 53 (the truncation fallback) is
/// ordinary outbound TCP. Files, processes, signals, Mach services, Unix
/// sockets, TCP listeners and UDP to any other port are refused. The egress
/// policy, not this profile, decides which destinations the broker dials.
const EGRESS_BROKER_PROFILE: &CStr = c"(version 1)(deny default)\
(allow network-outbound (remote tcp \"*:*\"))\
(allow network-outbound (remote udp \"*:53\"))\
(allow network-bind (local udp \"*:*\"))\
(allow network-inbound (local udp \"*:*\"))";

/// Irreversibly confine this process to the descriptors it already holds.
pub(crate) fn deny_all() -> io::Result<()> {
    apply(DENY_ALL_PROFILE)
}

/// Irreversibly confine the egress broker to outbound TCP and its own DNS.
pub(crate) fn confine_egress_broker() -> io::Result<()> {
    apply(EGRESS_BROKER_PROFILE)
}

fn apply(profile: &CStr) -> io::Result<()> {
    let mut error = std::ptr::null_mut();
    // SAFETY: the profile is NUL-terminated and static; flags 0 selects an
    // inline profile. Any error buffer the call allocates is freed below.
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut error) };
    if !error.is_null() {
        // SAFETY: the buffer came from sandbox_init and is freed once.
        unsafe { sandbox_free_error(error) };
    }
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::other("the Seatbelt profile was not applied"))
    }
}

/// Fail unless this process has exactly one thread.
pub(crate) fn require_single_thread() -> io::Result<()> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = c_int::try_from(std::mem::size_of::<libc::proc_taskinfo>())
        .map_err(|_| io::Error::other("task information size overflow"))?;
    // SAFETY: the buffer is a live, writable proc_taskinfo of the stated size.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    if written != size {
        return Err(io::Error::last_os_error());
    }
    if info.pti_threadnum == 1 {
        Ok(())
    } else {
        Err(io::Error::other("the process has more than one thread"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn single_thread_guard_rejects_an_extra_thread() {
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            ready_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        });
        ready_receiver.recv().unwrap();
        assert!(require_single_thread().is_err());
        release_sender.send(()).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn deny_all_keeps_held_descriptors_and_refuses_new_authority() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_DENY_ALL";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let (mut held, mut peer) = UnixStream::pair().unwrap();
            deny_all().unwrap();
            held.write_all(b"ok").unwrap();
            let mut received = [0_u8; 2];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"ok");
            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            // An unnamed socketpair reaches nothing, and Seatbelt allows it;
            // every named or network endpoint is refused.
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err());
            assert!(
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .and_then(|socket| socket.send_to(b"x", "127.0.0.1:9"))
                    .is_err()
            );
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "darwin::sandbox::tests::deny_all_keeps_held_descriptors_and_refuses_new_authority",
            )
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// The broker profile admits exactly what the broker does after
    /// confinement: dial TCP, hand the connected stream on over a held Unix
    /// socket, and run hickory's DNS exchange (UDP bind, send to port 53,
    /// unconnected receive). Everything else stays refused. If Seatbelt stops
    /// accepting the profile, or narrows or widens it, this test fails.
    #[test]
    fn egress_broker_profile_admits_only_tcp_dials_and_dns() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_EGRESS_BROKER";
        if let Some(port) = std::env::var_os(CHILD_MARKER) {
            let port: u16 = port.to_str().unwrap().parse().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (held, mut peer) = UnixStream::pair().unwrap();
            confine_egress_broker().unwrap();

            let dialed = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            crate::network_worker::send_worker_host_port_descriptor(
                held.as_raw_fd(),
                dialed.as_raw_fd(),
            )
            .unwrap();
            let mut marker = [0_u8; 1];
            peer.read_exact(&mut marker).unwrap();

            let dns = std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
            dns.send_to(b"query", "127.0.0.1:53").unwrap();
            let refused = dns.send_to(b"query", "127.0.0.1:9").unwrap_err();
            assert_eq!(refused.raw_os_error(), Some(libc::EPERM));
            dns.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reply = [0_u8; 5];
            let (length, _) = dns.recv_from(&mut reply).unwrap();
            assert_eq!(&reply[..length], b"reply");

            let error = std::fs::File::open("/etc/hosts").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(std::fs::File::create("/private/tmp/codewire-broker-probe").is_err());
            assert!(
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err()
            );
            assert!(UnixStream::connect("/var/run/mDNSResponder").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            return;
        }
        // The parent keeps sending the "reply" datagram to the child's DNS
        // port until the child exits; only inbound UDP lets the child see it.
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("darwin::sandbox::tests::egress_broker_profile_admits_only_tcp_dials_and_dns")
            .arg("--nocapture")
            .env(CHILD_MARKER, port.to_string())
            .spawn()
            .unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("the confined broker probe did not finish");
            }
            let _ = sender.send_to(b"reply", ("127.0.0.1", port));
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(status.success());
    }
}
