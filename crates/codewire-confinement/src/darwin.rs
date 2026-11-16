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

/// Irreversibly confine this process to the descriptors it already holds.
pub fn deny_all() -> io::Result<()> {
    apply_profile(DENY_ALL_PROFILE)
}

/// Irreversibly confine this whole process with one inline Seatbelt profile.
/// The caller owns the profile text; build it only from validated values.
pub fn apply_profile(profile: &CStr) -> io::Result<()> {
    let mut error = std::ptr::null_mut();
    // SAFETY: the profile is NUL-terminated and outlives the call; flags 0
    // selects an inline profile. Any error buffer the call allocates is
    // freed below.
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
pub fn require_single_thread() -> io::Result<()> {
    // SAFETY: proc_taskinfo is a plain C struct of integers, for which all-zero
    // bytes are a valid value.
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

    /// A profile Seatbelt refuses is reported as an error, never as success
    /// with partial confinement: the worker and broker start only after this
    /// call succeeds (#1905 condition 1), and refuse with their confinement
    /// exit status otherwise.
    #[test]
    fn a_profile_seatbelt_refuses_is_an_error_and_confines_nothing() {
        const CHILD_MARKER: &str = "CODEWIRE_TEST_DARWIN_REFUSED_PROFILE";
        if std::env::var_os(CHILD_MARKER).is_some() {
            assert!(apply_profile(c"(version 1)(this-is-not-an-operation)").is_err());
            assert!(apply_profile(c"").is_err());
            std::fs::File::open("/etc/hosts").unwrap();
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("darwin::tests::a_profile_seatbelt_refuses_is_an_error_and_confines_nothing")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
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
            .arg("darwin::tests::deny_all_keeps_held_descriptors_and_refuses_new_authority")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
