use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use super::{Result, invalid};

pub(super) const PACKET_PORT: &str = "org.codewire.console-pair.packet";
pub(super) const STATUS_PORT: &str = "org.codewire.console-pair.status";
pub(super) const CONTROL_PORT: &str = "org.codewire.console-pair.control";

pub(super) fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn dev_number(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let text = text.strip_suffix('\n').ok_or_else(invalid)?;
    let (major, minor) = text.split_once(':').ok_or_else(invalid)?;
    let parse = |part: &str| -> Result<u32> {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) || part.len() > 10 {
            return Err(invalid());
        }
        part.parse().map_err(|_| invalid())
    };
    Ok(libc::makedev(parse(major)?, parse(minor)?))
}

/// sysfs class entries are kernel-owned symlinks; only the final devtmpfs node
/// is opened NOFOLLOW. Do not depend on udev aliases or ordinal enumeration.
pub(super) fn discover_port_at(class: &Path, dev: &Path, name: &str) -> Result<OwnedFd> {
    let mut selected = None;
    let mut count = 0;
    for entry in fs::read_dir(class)? {
        count += 1;
        if count > 16 {
            return Err(invalid());
        }
        let entry = entry?;
        let component = entry.file_name();
        let component = component.to_str().ok_or_else(invalid)?;
        if !component.starts_with("vport") || !component.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(invalid());
        }
        let discovered = bounded_file(&entry.path().join("name"), 128)?;
        if discovered != format!("{name}\n").as_bytes() {
            continue;
        }
        if selected.is_some() {
            return Err(invalid());
        }
        let expected = dev_number(&bounded_file(&entry.path().join("dev"), 32)?)?;
        selected = Some((dev.join(component), expected));
    }
    let (path, expected) = selected.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != expected {
        return Err(invalid());
    }
    // The driver's non-console open rejects a port marked as a console.
    Ok(file.into())
}

pub(super) fn discover_port(name: &str, deadline: Instant) -> Result<OwnedFd> {
    loop {
        match discover_port_at(
            Path::new("/sys/class/virtio-ports"),
            Path::new("/dev"),
            name,
        ) {
            Ok(fd) => return Ok(fd),
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn stat(fd: RawFd) -> Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::zeroed();
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { value.assume_init() })
}

pub(super) fn distinct(fds: &[RawFd]) -> Result<()> {
    let mut numbers = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    let mut characters = BTreeSet::new();
    for &fd in fds {
        let value = stat(fd)?;
        if !numbers.insert(fd)
            || !inodes.insert((value.st_dev, value.st_ino))
            || (value.st_mode & libc::S_IFMT == libc::S_IFCHR && !characters.insert(value.st_rdev))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn require_rw_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR || flags & libc::O_NONBLOCK == 0 {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn unix_stream(fd: RawFd) -> Result<()> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_ACCEPTCONN, 0),
    ] {
        let mut value: libc::c_int = -1;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &mut size,
            )
        } != 0
            || value != expected
        {
            return Err(invalid());
        }
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe { libc::getpeername(fd, (&raw mut address).cast(), &mut size) } != 0
        || address.sun_family as i32 != libc::AF_UNIX
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn read_some(fd: RawFd, output: &mut [u8]) -> Result<usize> {
    let result = unsafe { libc::read(fd, output.as_mut_ptr().cast(), output.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub(super) fn write_some(fd: RawFd, input: &[u8]) -> Result<usize> {
    let result = unsafe { libc::write(fd, input.as_ptr().cast(), input.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub(super) fn poll(fds: &mut [libc::pollfd], deadline: Instant) -> Result<()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    let millis = (deadline - now).as_millis().clamp(1, 50) as i32;
    // ppoll is available on both supported Linux architectures (poll isn't
    // a native arm64 syscall). libc handles its fixed userspace wrapper.
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::c_long::from(millis) * 1_000_000,
    };
    let result =
        unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as _, &timeout, std::ptr::null()) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error());
    }
    if fds.iter().any(|p| p.revents & libc::POLLNVAL != 0) {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn pollfd(fd: RawFd, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

pub(super) fn write_all(fd: RawFd, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        match write_some(fd, bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                poll(&mut [pollfd(fd, libc::POLLOUT)], deadline)?;
            }
            Err(e) => return Err(e),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
    }
    Ok(())
}
