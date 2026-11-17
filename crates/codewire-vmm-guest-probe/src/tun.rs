//! A guest's TUN device, the one place the TUN ioctls are made. A local VM's
//! PID 1 attaches its interface with [`open`]. A hosted sandbox's init
//! container creates its interface once with [`create_persistent`], owned by
//! the workspace user, and the daemon then attaches it with [`open`] (#4000).

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use thiserror::Error;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// `_IOW('T', n, int)`: the direction bits sit higher on these architectures.
const IOC_WRITE: libc::c_ulong = if cfg!(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc64"
)) {
    0x8004_5400
} else {
    0x4004_5400
};
const TUNSETIFF: libc::c_ulong = IOC_WRITE | 0xca;
const TUNSETPERSIST: libc::c_ulong = IOC_WRITE | 0xcb;
const TUNSETOWNER: libc::c_ulong = IOC_WRITE | 0xcc;

/// `struct ifreq` as TUNSETIFF reads it: the name, then the flags, padded to
/// the union's size.
#[repr(C)]
struct TunIfreq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    flags: libc::c_short,
    padding: [u8; 22],
}

const _: () = assert!(std::mem::size_of::<TunIfreq>() == 40);

#[derive(Debug, Error)]
pub enum TunError {
    #[error("the TUN interface name {0:?} is empty, too long or not plain ASCII")]
    InvalidName(String),
    #[error("open /dev/net/tun")]
    Open(#[source] io::Error),
    #[error("attach the TUN interface")]
    Attach(#[source] io::Error),
    #[error("make the TUN interface persistent for its owner")]
    Persist(#[source] io::Error),
}

/// Attach `name`, creating it unless it exists, as a packet-only TUN (no
/// packet information header), nonblocking and close-on-exec.
pub fn open(name: &str) -> Result<OwnedFd, TunError> {
    let mut request = request(name)?;
    // SAFETY: the path is a NUL-terminated literal, and the flags are plain
    // open(2) flags; the call has no other inputs.
    let raw = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(TunError::Open(io::Error::last_os_error()));
    }
    // SAFETY: open(2) just returned `raw` as a new descriptor this process
    // owns and nothing else holds.
    let device = unsafe { OwnedFd::from_raw_fd(raw) };
    ioctl(&device, TUNSETIFF, &mut request).map_err(TunError::Attach)?;
    Ok(device)
}

/// Create `name` as a persistent TUN owned by `owner`, so that user's daemon
/// can attach it later without any privilege of its own.
pub fn create_persistent(name: &str, owner: libc::uid_t) -> Result<(), TunError> {
    let device = open(name)?;
    ioctl_value(&device, TUNSETOWNER, libc::c_ulong::from(owner)).map_err(TunError::Persist)?;
    ioctl_value(&device, TUNSETPERSIST, 1).map_err(TunError::Persist)
}

fn request(name: &str) -> Result<TunIfreq, TunError> {
    // The kernel needs room for the terminating NUL.
    if name.is_empty()
        || name.len() >= libc::IF_NAMESIZE
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/')
    {
        return Err(TunError::InvalidName(name.to_owned()));
    }
    let mut request = TunIfreq {
        name: [0; libc::IF_NAMESIZE],
        flags: IFF_TUN | IFF_NO_PI,
        padding: [0; 22],
    };
    for (destination, byte) in request.name.iter_mut().zip(name.bytes()) {
        *destination = libc::c_char::try_from(byte).expect("the name was checked to be ASCII");
    }
    Ok(request)
}

// `request as _`: ioctl(2)'s request is a c_ulong with glibc and a c_int with
// musl, the guest's libc.
fn ioctl(device: &OwnedFd, request: libc::c_ulong, ifreq: &mut TunIfreq) -> io::Result<()> {
    // SAFETY: `ifreq` is a live, writable `struct ifreq` of the size the
    // kernel reads for TUNSETIFF, and `device` is an open /dev/net/tun.
    if unsafe { libc::ioctl(device.as_raw_fd(), request as _, ifreq as *mut TunIfreq) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An ioctl whose argument the kernel reads as an unsigned long value, not a
/// pointer: TUNSETOWNER's uid and TUNSETPERSIST's flag.
fn ioctl_value(device: &OwnedFd, request: libc::c_ulong, value: libc::c_ulong) -> io::Result<()> {
    // SAFETY: the argument is passed by value and never dereferenced, on an
    // attached TUN descriptor that `device` owns.
    if unsafe { libc::ioctl(device.as_raw_fd(), request as _, value) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_names_a_packet_only_tun() {
        let request = request("cwegress0").unwrap();
        assert_eq!(request.flags, IFF_TUN | IFF_NO_PI);
        let name: Vec<u8> = request.name[..9]
            .iter()
            .map(|c| u8::try_from(*c).unwrap())
            .collect();
        assert_eq!(name, b"cwegress0");
        assert!(request.name[9..].iter().all(|c| *c == 0));
    }

    #[test]
    fn a_name_the_kernel_would_refuse_is_refused_first() {
        for name in ["", "a/b", "has space", "é", "0123456789abcdef"] {
            assert!(
                matches!(request(name), Err(TunError::InvalidName(_))),
                "{name:?}"
            );
        }
        assert!(request("0123456789abcde").is_ok());
    }

    #[test]
    fn the_ioctl_numbers_are_the_kernels() {
        if cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64") {
            assert_eq!(TUNSETIFF, 0x4004_54ca);
            assert_eq!(TUNSETPERSIST, 0x4004_54cb);
            assert_eq!(TUNSETOWNER, 0x4004_54cc);
        }
    }
}
