//! A guest's TUN device, the one place the TUN ioctls are made. A local VM's
//! PID 1 attaches its interface with [`open`]. A hosted sandbox's init
//! container creates its interface once with [`create_persistent`], owned by
//! the workspace user, and the daemon then attaches it with [`open`] (#4000).
//!
//! A Kata container has no `/dev/net/tun`, so the init container makes the
//! device node itself, in a memory-backed volume at `/dev/net` that the
//! workspace can also write. It trusts nothing it finds there:
//! [`create_persistent`] replaces the path with a fresh node, opens it without
//! following a link, and checks the open descriptor is the TUN before any
//! ioctl (`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`, "Hosted Egress Setup").

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use rustix::fs::{self, FileType, Mode, OFlags, Uid};
use rustix::io::Errno;

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

const TUN_PATH: &CStr = c"/dev/net/tun";
/// The TUN's character device: the misc major and the kernel's `TUN_MINOR`.
const TUN_MAJOR: u32 = 10;
const TUN_MINOR: u32 = 200;
/// statfs(2)'s `f_type` for tmpfs, `TMPFS_MAGIC` in linux/magic.h.
const TMPFS_MAGIC: u64 = 0x0102_1994;

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
    #[error("replace /dev/net/tun with a fresh TUN device node")]
    Node(#[source] io::Error),
    #[error("/dev/net/tun is not the TUN device (character 10:200)")]
    NotTun,
    #[error("/dev/net/tun is not on a memory-backed filesystem (tmpfs)")]
    NotMemory,
    #[error("give /dev/net/tun to its owner, mode 0600")]
    Own(#[source] io::Error),
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
/// can attach it later without any privilege of its own. The device node is
/// made afresh first, mode 0600 and owned by `owner`, which needs root.
pub fn create_persistent(name: &str, owner: libc::uid_t) -> Result<(), TunError> {
    let mut request = request(name)?;
    let device = fresh_node(TUN_PATH, owner)?;
    ioctl(&device, TUNSETIFF, &mut request).map_err(TunError::Attach)?;
    ioctl_value(&device, TUNSETOWNER, libc::c_ulong::from(owner)).map_err(TunError::Persist)?;
    ioctl_value(&device, TUNSETPERSIST, 1).map_err(TunError::Persist)
}

/// Replace whatever is at `path` with a new TUN device node, open it, and give
/// it to `owner` through the open descriptor, so a path swapped meanwhile is
/// never what gets the owner.
fn fresh_node(path: &CStr, owner: libc::uid_t) -> Result<OwnedFd, TunError> {
    remove(path)?;
    fs::mknodat(
        fs::CWD,
        path,
        FileType::CharacterDevice,
        Mode::RUSR | Mode::WUSR,
        fs::makedev(TUN_MAJOR, TUN_MINOR),
    )
    .map_err(|error| TunError::Node(error.into()))?;
    let device = open_verified(path)?;
    // The node's volume is memory-backed: on a disk-backed one it would sit on
    // the host's filesystem shared into the VM. Admission pins the volume;
    // this refuses it at the node itself as well.
    let filesystem = fs::fstatfs(&device).map_err(|error| TunError::Open(error.into()))?;
    if !is_memory(filesystem.f_type as u64) {
        return Err(TunError::NotMemory);
    }
    fs::fchown(&device, Some(Uid::from_raw(owner)), None)
        .and_then(|()| fs::fchmod(&device, Mode::RUSR | Mode::WUSR))
        .map_err(|error| TunError::Own(error.into()))?;
    Ok(device)
}

/// Remove whatever is at `path`. unlink(2) removes a symbolic link itself,
/// never its target; a directory there is refused.
fn remove(path: &CStr) -> Result<(), TunError> {
    match fs::unlink(path) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(TunError::Node(error.into())),
    }
}

/// Open `path` without following a link, and keep it only if the descriptor
/// is the TUN's character device.
fn open_verified(path: &CStr) -> Result<OwnedFd, TunError> {
    let device = fs::open(
        path,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| TunError::Open(error.into()))?;
    let stat = fs::fstat(&device).map_err(|error| TunError::Open(error.into()))?;
    if !is_tun(FileType::from_raw_mode(stat.st_mode), stat.st_rdev) {
        return Err(TunError::NotTun);
    }
    Ok(device)
}

fn is_memory(filesystem: u64) -> bool {
    filesystem == TMPFS_MAGIC
}

fn is_tun(kind: FileType, rdev: fs::Dev) -> bool {
    kind == FileType::CharacterDevice
        && fs::major(rdev) == TUN_MAJOR
        && fs::minor(rdev) == TUN_MINOR
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

    fn path(path: &std::path::Path) -> std::ffi::CString {
        use std::os::unix::ffi::OsStrExt as _;
        std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    #[test]
    fn a_planted_symlink_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"kept").unwrap();
        let tun = dir.path().join("tun");
        std::os::unix::fs::symlink(&target, &tun).unwrap();

        let error = open_verified(&path(&tun)).unwrap_err();
        assert!(
            matches!(&error, TunError::Open(error) if error.raw_os_error() == Some(libc::ELOOP)),
            "{error:?}"
        );
        remove(&path(&tun)).unwrap();
        assert!(std::fs::symlink_metadata(&tun).is_err(), "the link is gone");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"kept",
            "its target is untouched"
        );
    }

    #[test]
    fn a_device_other_than_the_tun_is_refused_after_opening() {
        // /dev/null is character 1:3; a regular file is no device at all.
        assert!(matches!(open_verified(c"/dev/null"), Err(TunError::NotTun)));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tun");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(open_verified(&path(&file)), Err(TunError::NotTun)));
    }

    #[test]
    fn only_character_10_200_is_the_tun() {
        let tun = fs::makedev(10, 200);
        assert!(is_tun(FileType::CharacterDevice, tun));
        assert!(!is_tun(FileType::BlockDevice, tun));
        assert!(!is_tun(FileType::CharacterDevice, fs::makedev(10, 201)));
        assert!(!is_tun(FileType::CharacterDevice, fs::makedev(1, 200)));
    }

    #[test]
    fn only_tmpfs_is_memory_backed() {
        assert!(is_memory(0x0102_1994));
        // ext4, xfs, btrfs and overlayfs.
        for disk in [0xef53, 0x5846_5342, 0x9123_683e, 0x794c_7630] {
            assert!(!is_memory(disk), "{disk:#x}");
        }
    }

    #[test]
    fn removing_a_missing_path_succeeds_and_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        remove(&path(&dir.path().join("absent"))).unwrap();
        let sub = dir.path().join("tun");
        std::fs::create_dir(&sub).unwrap();
        assert!(matches!(remove(&path(&sub)), Err(TunError::Node(_))));
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
