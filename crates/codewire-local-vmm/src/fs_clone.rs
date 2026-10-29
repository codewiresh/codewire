//! Copy-on-write file copies for local disk snapshots (Linux).
//!
//! A disk is copied with `FICLONE` where the filesystem shares extents
//! (btrfs, XFS): the copy costs only metadata until either file changes. Where
//! it does not, the copy is sparse: only the source's data ranges, found with
//! `SEEK_DATA` and `SEEK_HOLE`, are copied with `copy_file_range`, so a mostly
//! empty disk stays mostly holes. A sparse copy costs its allocated bytes at
//! once, so its caller checks free space first. `FIEMAP` reports how many of a
//! file's bytes are still shared with another file.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
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
const FICLONE: libc::c_ulong = 0x4004_9409;
/// `FS_IOC_FIEMAP`: `_IOWR('f', 11, struct fiemap)`.
const FS_IOC_FIEMAP: libc::c_ulong = 0xc020_660b;
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
const FIEMAP_EXTENT_LAST: u32 = 0x0000_0001;
const FIEMAP_EXTENT_SHARED: u32 = 0x0000_2000;
const FIEMAP_BATCH: usize = 256;
/// The largest single `copy_file_range` request.
const COPY_CHUNK: u64 = 1 << 30;
/// The largest `pread`/`pwrite` buffer when the kernel copies nothing itself.
const FALLBACK_BUFFER: usize = 1 << 20;

/// Copy `source` into the empty `destination`, by reflink where the
/// filesystem allows it, otherwise sparsely after `reserve` accepts the bytes
/// the copy will allocate. `destination` is synced either way.
pub(crate) fn clone_or_copy(
    source: &File,
    destination: &File,
    reserve: impl FnOnce(u64) -> io::Result<()>,
) -> io::Result<CloneMode> {
    if destination.metadata()?.len() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a copy destination is not empty",
        ));
    }
    let mode = match reflink(source, destination) {
        Ok(()) => CloneMode::Reflink,
        Err(error) if reflink_unsupported(&error) => {
            reserve(allocated_bytes(source)?)?;
            sparse_copy(source, destination)?;
            CloneMode::Copy
        }
        Err(error) => return Err(error),
    };
    destination.sync_all()?;
    Ok(mode)
}

/// Share every extent of `source` with the empty `destination`. A VM
/// checkpoint clones a running VM's disks this way while it is paused: the
/// filesystem writes back the source's dirty pages first, so the clone is the
/// disk exactly as the paused VM left it.
pub(crate) fn reflink(source: &File, destination: &File) -> io::Result<()> {
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

/// Whether files in `directory` can share extents: a VM checkpoint needs
/// that, since it clones the disks while the VM is paused (#3046 R4).
pub(crate) fn reflink_works(directory: &Path) -> io::Result<bool> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let probe = |name: &str| {
        std::fs::OpenOptions::new()
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
        let destination = probe(&destination_name)?;
        match reflink(&source, &destination) {
            Ok(()) => Ok(true),
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
/// another file; `None` when it reports no extent map.
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
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn sparse_source(path: &Path) -> File {
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.set_len(64 * MIB).unwrap();
        for (offset, byte) in [(0, b'a'), (20 * MIB, b'b'), (63 * MIB, b'c')] {
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&vec![byte; MIB as usize]).unwrap();
        }
        file.sync_all().unwrap();
        file
    }

    fn new_file(path: &Path) -> File {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    fn contents(mut file: &File) -> Vec<u8> {
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn a_sparse_copy_keeps_the_bytes_and_the_holes() {
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let destination = new_file(&directory.path().join("destination"));

        sparse_copy(&source, &destination).unwrap();

        assert_eq!(destination.metadata().unwrap().len(), 64 * MIB);
        assert_eq!(contents(&source), contents(&destination));
        // Three mebibytes of data; the 61 MiB between them stay holes.
        assert!(allocated_bytes(&destination).unwrap() < 8 * MIB);
    }

    #[test]
    fn a_copy_falls_back_when_the_filesystem_cannot_share_extents() {
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let destination = new_file(&directory.path().join("destination"));
        let mut reserved = None;

        let mode = clone_or_copy(&source, &destination, |bytes| {
            reserved = Some(bytes);
            Ok(())
        })
        .unwrap();

        assert_eq!(contents(&source), contents(&destination));
        match mode {
            // A filesystem that shares extents reserves nothing.
            CloneMode::Reflink => assert_eq!(reserved, None),
            CloneMode::Copy => assert!(reserved.is_some_and(|bytes| bytes >= 3 * MIB)),
        }
    }

    #[test]
    fn a_copy_between_filesystems_is_sparse_and_checks_space_first() {
        // tmpfs never shares extents with the test directory's filesystem.
        let Ok(shared_memory) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let destination = new_file(&shared_memory.path().join("destination"));

        let refused = clone_or_copy(&source, &destination, |bytes| {
            Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!("{bytes} bytes needed"),
            ))
        })
        .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::StorageFull);
        assert_eq!(destination.metadata().unwrap().len(), 0);

        let mode = clone_or_copy(&source, &destination, |_| Ok(())).unwrap();
        assert_eq!(mode, CloneMode::Copy);
        assert_eq!(contents(&source), contents(&destination));
    }

    #[test]
    fn a_reflink_shares_its_extents_where_the_filesystem_allows_it() {
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let destination = new_file(&directory.path().join("destination"));
        if reflink(&source, &destination).is_err() {
            return;
        }
        assert_eq!(contents(&source), contents(&destination));
        if let Some(shared) = shared_bytes(&destination) {
            assert!(shared >= 3 * MIB);
        }
        let destination_path = directory.path().join("destination");
        OpenOptions::new()
            .write(true)
            .open(&destination_path)
            .unwrap()
            .write_all_at(b"changed", 0)
            .unwrap();
        assert_eq!(contents(&source)[..7], [b'a'; 7]);
    }

    #[test]
    fn the_reflink_probe_agrees_with_a_reflink_and_leaves_nothing_behind() {
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let destination = new_file(&directory.path().join("destination"));
        let works = reflink(&source, &destination).is_ok();
        let probe = tempfile::tempdir().unwrap();
        assert_eq!(reflink_works(probe.path()).unwrap(), works);
        assert_eq!(std::fs::read_dir(probe.path()).unwrap().count(), 0);
    }

    const REFUSED_WRITE_CHILD: &str = "CODEWIRE_FS_CLONE_REFUSED_WRITE_CHILD";

    /// Run in a child whose file-size limit is 8 MiB: the kernel refuses the
    /// copy's write past it (EFBIG), as a full disk refuses one (ENOSPC).
    #[test]
    fn refused_write_child() {
        let Some(directory) = std::env::var_os(REFUSED_WRITE_CHILD) else {
            return;
        };
        let directory = Path::new(&directory);
        let source = File::open(directory.join("source")).unwrap();
        let destination = OpenOptions::new()
            .write(true)
            .open(directory.join("destination"))
            .unwrap();
        let error = clone_or_copy(&source, &destination, |_| Ok(())).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EFBIG), "{error}");
    }

    #[test]
    fn a_write_the_filesystem_refuses_mid_copy_fails_the_copy() {
        use std::os::unix::process::CommandExt as _;

        let Ok(shared_memory) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        // The source lives on another filesystem, so the copy is sparse; its
        // second data range lies past the limit.
        let directory = tempfile::tempdir().unwrap();
        sparse_source(&directory.path().join("source"));
        std::os::unix::fs::symlink(
            directory.path().join("source"),
            shared_memory.path().join("source"),
        )
        .unwrap();
        new_file(&shared_memory.path().join("destination"));
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "fs_clone::tests::refused_write_child",
                "--nocapture",
            ])
            .env(REFUSED_WRITE_CHILD, shared_memory.path())
            .stdin(std::process::Stdio::null());
        // SAFETY: only async-signal-safe calls run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 8 * MIB,
                    rlim_max: 8 * MIB,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
                    || libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = command.status().unwrap();
        assert!(status.success(), "{status}");
    }

    #[test]
    fn a_non_empty_destination_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let source = sparse_source(&directory.path().join("source"));
        let mut destination = new_file(&directory.path().join("destination"));
        destination.write_all(b"existing").unwrap();
        let error = clone_or_copy(&source, &destination, |_| Ok(())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }
}
