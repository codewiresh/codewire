//! Copy-on-write file copies for local disk snapshots and VM checkpoints.
//!
//! A disk is copied into a new file by clone where the filesystem shares
//! blocks between files: `FICLONE` on Linux (btrfs, XFS), `fclonefileat` on
//! macOS (APFS). The copy costs only metadata until either file changes. Where
//! it does not, the copy is sparse: only the source's data ranges, found with
//! `SEEK_DATA` and `SEEK_HOLE`, are copied (with `copy_file_range` on Linux),
//! so a mostly empty disk stays mostly holes. A sparse copy costs its allocated
//! bytes at once, so its caller checks free space first. On Linux `FIEMAP`
//! reports how many of a file's bytes are still shared with another file.
//!
//! macOS can only clone into a file it creates, so every copy here creates its
//! destination: an existing file is refused.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

/// How a file was copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloneMode {
    /// The copy shares the source's extents until either changes.
    Reflink,
    /// The source's data ranges were copied; holes stay holes.
    Copy,
}

impl CloneMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reflink => "reflink",
            Self::Copy => "copy",
        }
    }
}

/// `FICLONE`: `_IOW(0x94, 9, int)`.
#[cfg(target_os = "linux")]
const FICLONE: libc::c_ulong = 0x4004_9409;
/// `FS_IOC_FIEMAP`: `_IOWR('f', 11, struct fiemap)`.
#[cfg(target_os = "linux")]
const FS_IOC_FIEMAP: libc::c_ulong = 0xc020_660b;
#[cfg(target_os = "linux")]
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
#[cfg(target_os = "linux")]
const FIEMAP_EXTENT_LAST: u32 = 0x0000_0001;
#[cfg(target_os = "linux")]
const FIEMAP_EXTENT_SHARED: u32 = 0x0000_2000;
#[cfg(target_os = "linux")]
const FIEMAP_BATCH: usize = 256;
/// The largest single `copy_file_range` request.
#[cfg(target_os = "linux")]
const COPY_CHUNK: u64 = 1 << 30;
/// The largest `pread`/`pwrite` buffer when the kernel copies nothing itself.
const FALLBACK_BUFFER: usize = 1 << 20;

/// Copy `source` into the new file `destination` (0600), by clone where the
/// filesystem allows it, otherwise sparsely after `reserve` accepts the bytes
/// the copy will allocate. `destination` must not exist, and is synced either
/// way.
pub(crate) fn clone_or_copy(
    source: &File,
    destination: &Path,
    reserve: impl FnOnce(u64) -> io::Result<()>,
) -> io::Result<(File, CloneMode)> {
    let (target, mode) = match clone_new(source, destination) {
        Ok(target) => (target, CloneMode::Reflink),
        Err(error) if reflink_unsupported(&error) => {
            reserve(allocated_bytes(source)?)?;
            let target = create_new(destination)?;
            sparse_copy(source, &target)?;
            (target, CloneMode::Copy)
        }
        Err(error) => return Err(error),
    };
    target.sync_all()?;
    Ok((target, mode))
}

/// Create `destination` (0600) as a clone of `source`: it shares every block
/// of `source` until either changes, and nothing is copied. A VM checkpoint
/// clones a running VM's disks this way while it is paused: the filesystem
/// writes back the source's dirty pages first, so the clone is the disk
/// exactly as the paused VM left it. Leaves nothing behind when it fails.
pub(crate) fn clone_new(source: &File, destination: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        let target = create_new(destination)?;
        if let Err(error) = reflink(source, &target) {
            drop(target);
            // The clone's error matters, not this cleanup's.
            let _ = std::fs::remove_file(destination);
            return Err(error);
        }
        Ok(target)
    }
    #[cfg(target_os = "macos")]
    {
        clonefile(source, destination)
    }
}

/// Create the empty file `destination` (0600), refusing an existing one.
fn create_new(destination: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
}

#[cfg(target_os = "linux")]
fn reflink(source: &File, destination: &File) -> io::Result<()> {
    // SAFETY: both descriptors are live for the call; FICLONE takes the source
    // descriptor as its integer argument and writes nothing back.
    let result = unsafe {
        libc::ioctl(
            destination.as_raw_fd(),
            FICLONE as _,
            source.as_raw_fd() as libc::c_long,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `fclonefileat` into `destination`'s directory. The clone takes `source`'s
/// mode, so it is set to 0600 before anything is returned.
#[cfg(target_os = "macos")]
fn clonefile(source: &File, destination: &Path) -> io::Result<File> {
    use rustix::fs::CloneFlags;
    use std::os::unix::fs::PermissionsExt as _;
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "not a file path");
    let parent = destination.parent().ok_or_else(invalid)?;
    let name = destination.file_name().ok_or_else(invalid)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?;
    // The clone is owned by this process's user, never the source's owner.
    rustix::fs::fclonefileat(
        source,
        &directory,
        name,
        CloneFlags::NOFOLLOW | CloneFlags::NOOWNERCOPY,
    )?;
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
        .and_then(|target| {
            target.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            Ok(target)
        });
    if opened.is_err() {
        // The open's error matters; this only removes the clone it made.
        let _ = std::fs::remove_file(destination);
    }
    opened
}

/// Whether files in `directory` can share extents: a VM checkpoint needs
/// that, since it clones the disks while the VM is paused (#3046 R4).
pub(crate) fn reflink_works(directory: &Path) -> io::Result<bool> {
    use std::io::Write as _;
    let probe = |name: &str| {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(name))
    };
    let token = uuid::Uuid::new_v4();
    let source_name = format!(".reflink-probe-{token}-a");
    let destination_name = format!(".reflink-probe-{token}-b");
    let result = (|| {
        let mut source = probe(&source_name)?;
        source.write_all(&[0x5a; 4096])?;
        source.sync_all()?;
        match clone_new(&source, &directory.join(&destination_name)) {
            Ok(_) => Ok(true),
            Err(error) if reflink_unsupported(&error) => Ok(false),
            Err(error) => Err(error),
        }
    })();
    for name in [&source_name, &destination_name] {
        match std::fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    result
}

/// Errors that mean "this filesystem cannot share extents here", not a
/// failure of the files themselves.
fn reflink_unsupported(error: &io::Error) -> bool {
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(libc::ENOTSUP) {
        return true;
    }
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY | libc::ENOSYS)
    )
}

/// Copy `source`'s data ranges into `destination` at the same offsets and
/// give it `source`'s length; the rest stays holes.
pub(crate) fn sparse_copy(source: &File, destination: &File) -> io::Result<()> {
    let length = source.metadata()?.len();
    let mut offset = 0;
    while offset < length {
        let Some(start) = seek(source, offset, libc::SEEK_DATA)? else {
            break;
        };
        let end = seek(source, start, libc::SEEK_HOLE)?
            .unwrap_or(length)
            .min(length);
        copy_range(source, destination, start, end)?;
        offset = end;
    }
    // Last, so a trailing hole keeps its length and a refused write leaves
    // only what was copied.
    destination.set_len(length)
}

/// `lseek` with `whence`; `None` past the last data range (`ENXIO`).
fn seek(file: &File, offset: u64, whence: libc::c_int) -> io::Result<Option<u64>> {
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
    // SAFETY: a plain lseek on a live descriptor.
    let result = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(result as u64))
}

/// macOS has no `copy_file_range`, so its data ranges go through memory.
#[cfg(target_os = "macos")]
fn copy_range(source: &File, destination: &File, start: u64, end: u64) -> io::Result<()> {
    copy_range_through_memory(source, destination, start, end)
}

#[cfg(target_os = "linux")]
fn copy_range(source: &File, destination: &File, start: u64, end: u64) -> io::Result<()> {
    let mut position = start;
    while position < end {
        let mut input = position as libc::loff_t;
        let mut output = position as libc::loff_t;
        let wanted = (end - position).min(COPY_CHUNK) as usize;
        // SAFETY: both descriptors are live and the offsets are owned locals
        // the kernel advances.
        let copied = unsafe {
            libc::copy_file_range(
                source.as_raw_fd(),
                &mut input,
                destination.as_raw_fd(),
                &mut output,
                wanted,
                0,
            )
        };
        if copied < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EXDEV | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
            ) {
                return copy_range_through_memory(source, destination, position, end);
            }
            return Err(error);
        }
        if copied == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "a disk shrank while it was copied",
            ));
        }
        position += copied as u64;
    }
    Ok(())
}

pub(crate) fn copy_range_through_memory(
    source: &File,
    destination: &File,
    start: u64,
    end: u64,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; FALLBACK_BUFFER];
    let mut position = start;
    while position < end {
        let wanted = (end - position).min(FALLBACK_BUFFER as u64) as usize;
        let read = source.read_at(&mut buffer[..wanted], position)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "a disk shrank while it was copied",
            ));
        }
        destination.write_all_at(&buffer[..read], position)?;
        position += read as u64;
    }
    Ok(())
}

/// Bytes `file` holds on its filesystem.
pub(crate) fn allocated_bytes(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.blocks().saturating_mul(512))
}

/// Bytes the filesystem holding `directory` can still give this user.
pub(crate) fn free_bytes(directory: &Path) -> io::Result<u64> {
    let stat = rustix::fs::statvfs(directory).map_err(io::Error::from)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// Of `file`'s mapped bytes, how many the filesystem reports as shared with
/// another file; `None` when it reports no extent map, as macOS never does.
#[cfg(target_os = "macos")]
pub(crate) fn shared_bytes(_file: &File) -> Option<u64> {
    None
}

/// Of `file`'s mapped bytes, how many the filesystem reports as shared with
/// another file; `None` when it reports no extent map.
#[cfg(target_os = "linux")]
pub(crate) fn shared_bytes(file: &File) -> Option<u64> {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Extent {
        logical: u64,
        physical: u64,
        length: u64,
        reserved64: [u64; 2],
        flags: u32,
        reserved: [u32; 3],
    }
    #[repr(C)]
    struct Request {
        start: u64,
        length: u64,
        flags: u32,
        mapped_extents: u32,
        extent_count: u32,
        reserved: u32,
        extents: [Extent; FIEMAP_BATCH],
    }
    let mut shared = 0_u64;
    let mut start = 0_u64;
    loop {
        let mut request = Request {
            start,
            length: u64::MAX - start,
            flags: FIEMAP_FLAG_SYNC,
            mapped_extents: 0,
            extent_count: FIEMAP_BATCH as u32,
            reserved: 0,
            extents: [Extent::default(); FIEMAP_BATCH],
        };
        // SAFETY: `request` is a correctly sized fiemap with room for
        // `extent_count` extents, live for the call.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                FS_IOC_FIEMAP as _,
                std::ptr::from_mut(&mut request),
            )
        };
        if result != 0 {
            return None;
        }
        let mapped = (request.mapped_extents as usize).min(FIEMAP_BATCH);
        if mapped == 0 {
            return Some(shared);
        }
        for extent in &request.extents[..mapped] {
            if extent.flags & FIEMAP_EXTENT_SHARED != 0 {
                shared = shared.saturating_add(extent.length);
            }
            if extent.flags & FIEMAP_EXTENT_LAST != 0 {
                return Some(shared);
            }
        }
        let last = request.extents[mapped - 1];
        let next = last.logical.saturating_add(last.length);
        if next <= start {
            return Some(shared);
        }
        start = next;
    }
}

#[cfg(test)]
mod tests;
