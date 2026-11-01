//! Private local Mesh and member state, on Linux and macOS: a held owner-only
//! directory whose files are read, replaced and removed only through it, and
//! the control lock. These are the user's own processes, not a sandbox or a
//! boundary against the same user.
use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

const MAX_STATE: usize = 64 * 1024;
const LOCK: &str = "mesh-control.lock";

fn euid() -> u32 {
    // SAFETY: geteuid has no arguments or effects.
    unsafe { libc::geteuid() }
}

fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> anyhow::Result<File> {
    let name = std::ffi::CString::new(name)?;
    // All callers provide one fixed basename. NOFOLLOW is deliberate for state
    // and proc files; the kernel's proc/exe seam is the sole explicit exception.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn stamp(value: &fs::Metadata) -> FileStamp {
    FileStamp {
        dev: value.dev(),
        inode: value.ino(),
        uid: value.uid(),
        mode: value.mode(),
        links: value.nlink(),
        bytes: value.len(),
        modified: (value.mtime(), value.mtime_nsec()),
        changed: (value.ctime(), value.ctime_nsec()),
    }
}

fn private_file(file: &File, maximum: usize) -> anyhow::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == euid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() <= maximum as u64,
        "local Mesh state is not a bounded owner-private regular file"
    );
    Ok(metadata)
}

pub(crate) struct StateDir {
    path: PathBuf,
    directory: File,
}

impl StateDir {
    pub(crate) fn open(path: &Path, create: bool) -> anyhow::Result<Option<Self>> {
        if create {
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("create private local Mesh directory"),
            }
        }
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error).context("open private local Mesh directory"),
        };
        let value = Self {
            path: path.to_owned(),
            directory,
        };
        value.check(create)?;
        Ok(Some(value))
    }

    fn check(&self, writable: bool) -> anyhow::Result<()> {
        let fd = self.directory.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        anyhow::ensure!(
            fd.is_dir()
                && path.is_dir()
                && fd.dev() == path.dev()
                && fd.ino() == path.ino()
                && fd.uid() == euid()
                && fd.mode() & 0o7077 == 0
                && fd.mode() & 0o500 == 0o500,
            "local Mesh directory ownership changed"
        );
        if writable {
            anyhow::ensure!(fd.mode() & 0o200 != 0, "local Mesh directory is read-only");
        }
        Ok(())
    }

    fn named_file(&self, name: &str, flags: i32, maximum: usize) -> anyhow::Result<Option<File>> {
        self.check(false)?;
        let file = match open_at(
            &self.directory,
            name,
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error).context("open local Mesh state"),
        };
        let metadata = private_file(&file, maximum)?;
        let path = fs::symlink_metadata(self.path.join(name))?;
        anyhow::ensure!(
            stamp(&metadata) == stamp(&path),
            "local Mesh state identity changed"
        );
        self.check(false)?;
        Ok(Some(file))
    }

    pub(crate) fn read(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.named_file(name, libc::O_RDONLY, MAX_STATE)? else {
            return Ok(None);
        };
        let before = file.metadata()?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= MAX_STATE && stamp(&before) == stamp(&file.metadata()?),
            "local Mesh state changed during read"
        );
        let current = fs::symlink_metadata(self.path.join(name))?;
        anyhow::ensure!(
            stamp(&before) == stamp(&current),
            "local Mesh state pathname changed"
        );
        self.check(false)?;
        Ok(Some(bytes))
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.check(true)?;
        anyhow::ensure!(
            bytes.len() <= MAX_STATE,
            "local Mesh state exceeds its bound"
        );
        let before = self.read(name)?;
        let temporary = format!(".mesh-state-{}", uuid::Uuid::new_v4().simple());
        let mut file = open_at(
            &self.directory,
            &temporary,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )?;
        let result = (|| -> anyhow::Result<()> {
            private_file(&file, MAX_STATE)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            self.check(true)?;
            anyhow::ensure!(
                before == self.read(name)?,
                "local Mesh state changed before publication"
            );
            // A first record is never written over one that appeared meanwhile.
            let flags = if before.is_none() {
                rustix::fs::RenameFlags::NOREPLACE
            } else {
                rustix::fs::RenameFlags::empty()
            };
            rustix::fs::renameat_with(&self.directory, &temporary, &self.directory, name, flags)
                .map_err(std::io::Error::from)?;
            self.directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            // This name was created exclusively by this call, inside the held
            // private directory. Never remove the destination after uncertain ACK.
            let _ = self.remove(&temporary, Some(bytes));
        }
        result
    }

    pub(crate) fn remove(&self, name: &str, expected: Option<&[u8]>) -> anyhow::Result<()> {
        self.check(true)?;
        let Some(bytes) = self.read(name)? else {
            return Ok(());
        };
        if let Some(expected) = expected {
            anyhow::ensure!(
                bytes == expected,
                "local Mesh record changed before cleanup"
            );
        }
        let name = std::ffi::CString::new(name)?;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        Ok(())
    }

    pub(crate) fn log(&self, name: &str) -> anyhow::Result<File> {
        self.check(true)?;
        if let Some(file) =
            self.named_file(name, libc::O_WRONLY | libc::O_APPEND, 64 * 1024 * 1024)?
        {
            return Ok(file);
        }
        let file = open_at(
            &self.directory,
            name,
            libc::O_WRONLY
                | libc::O_APPEND
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600,
        )?;
        private_file(&file, 64 * 1024 * 1024)?;
        self.check(true)?;
        Ok(file)
    }

    pub(crate) async fn lock(&self) -> anyhow::Result<ControlLock> {
        self.check(true)?;
        let file = match self.named_file(LOCK, libc::O_RDWR, 0)? {
            Some(file) => file,
            None => match open_at(
                &self.directory,
                LOCK,
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            ) {
                Ok(file) => file,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    self.named_file(LOCK, libc::O_RDWR, 0)?
                        .context("local Mesh lock disappeared")?
                }
                Err(error) => return Err(error),
            },
        };
        private_file(&file, 0)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            anyhow::ensure!(
                matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EINTR)),
                "local Mesh lock failed: {error}"
            );
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "local Mesh control lock timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let locked = ControlLock(file);
        locked.check(self)?;
        Ok(locked)
    }
}

pub(crate) struct ControlLock(File);
impl ControlLock {
    pub(crate) fn check(&self, directory: &StateDir) -> anyhow::Result<()> {
        directory.check(true)?;
        let current = directory
            .named_file(LOCK, libc::O_RDONLY, 0)?
            .context("local Mesh lock disappeared")?;
        anyhow::ensure!(
            stamp(&self.0.metadata()?) == stamp(&current.metadata()?),
            "local Mesh lock pathname changed"
        );
        Ok(())
    }
}
impl Drop for ControlLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(target_os = "linux")]
mod member;
#[cfg(target_os = "linux")]
pub(crate) use member::*;

#[cfg(test)]
mod tests;
