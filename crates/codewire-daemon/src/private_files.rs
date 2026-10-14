//! Owner-only files a hosted daemon writes: its state under `/codewire/run`,
//! Codewire's files in Codex's home and Claude Code's `~/.claude.json`. Every
//! write goes through a temporary file created exclusively in the target
//! directory with its final mode, so a reader never observes a partial file or
//! a wider mode, and no write follows a symlink.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Create the owner-only directory `path`, or tighten an existing one to
/// `mode`. A symlink or other non-directory is refused.
pub(crate) fn ensure_private_directory(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(not_a_directory()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            match fs::DirBuilder::new().mode(mode).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(path)?.is_dir() {
                        return Err(not_a_directory());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn not_a_directory() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "hosted daemon state path is not a directory",
    )
}

/// Write `contents` to `path` with exactly `mode`, through an exclusive
/// temporary sibling and a rename.
pub(crate) fn write_atomically(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let temporary = temporary_sibling(path, &std::process::id().to_string())?;
    write_new(&temporary, contents, mode)?;
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

/// The hidden sibling `.<file name>.<tag>.tmp` of `path`.
pub(crate) fn temporary_sibling(path: &Path, tag: &str) -> io::Result<PathBuf> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    Ok(directory.join(format!(".{}.{tag}.tmp", name.to_string_lossy())))
}

/// Create `path` exclusively with exactly `mode`, then write and sync it. A
/// stale file or symlink of that name is unlinked first, never followed.
pub(crate) fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // The umask may have narrowed the mode; never widen it past `mode`.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

/// Make the entries just created, renamed or removed in `directory` durable.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(target_os = "linux")]
pub(crate) use at::{Entry, OwnedEntry, PrivateDirectory};

/// Operations relative to one directory opened without following a symlink,
/// for files a user's process may race: no step resolves a path through a
/// symlink, and every replacement or removal names the entry the caller
/// checked. Linux only: they rely on `renameat2`.
#[cfg(target_os = "linux")]
mod at {
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::path::Path;

    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
    use zeroize::Zeroizing;

    /// A directory opened with `O_DIRECTORY|O_NOFOLLOW`, owned by the
    /// effective uid, or by root for [`PrivateDirectory::open_home`].
    #[derive(Debug)]
    pub(crate) struct PrivateDirectory(OwnedFd);

    /// One regular file of the effective uid, read through a descriptor
    /// opened with `O_NOFOLLOW`. Its bytes are zeroized on drop.
    pub(crate) struct OwnedEntry {
        pub identity: (u64, u64),
        pub mode: u32,
        pub contents: Zeroizing<Vec<u8>>,
    }

    /// What a name in the directory is, without following a symlink.
    pub(crate) enum Entry {
        Absent,
        /// A symlink, a non-regular file, another uid's file, or a file
        /// larger than the caller reads.
        Foreign,
        Owned(OwnedEntry),
    }

    impl PrivateDirectory {
        /// Open `path` as a directory of the effective uid. `Ok(None)` when
        /// it is a symlink, not a directory, or another uid's; `NotFound`
        /// passes through.
        pub(crate) fn open(path: &Path) -> io::Result<Option<Self>> {
            Self::open_owned(path, false)
        }

        /// [`Self::open`] for the workspace user's home, which root may also
        /// own: kubelet leaves the root of the home volume to root and gives
        /// the workspace group write access (`fsGroup`). Another unprivileged
        /// uid's directory is still refused. Only entries of the effective uid
        /// are ever read or replaced in it.
        pub(crate) fn open_home(path: &Path) -> io::Result<Option<Self>> {
            Self::open_owned(path, true)
        }

        fn open_owned(path: &Path, root_may_own: bool) -> io::Result<Option<Self>> {
            let descriptor = match rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let stat = rustix::fs::fstat(&descriptor)?;
            let owned = stat.st_uid == rustix::process::geteuid().as_raw()
                || (root_may_own && stat.st_uid == 0);
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || !owned {
                return Ok(None);
            }
            Ok(Some(Self(descriptor)))
        }

        /// Open the directory `name` here, creating it with `mode` when it is
        /// absent. `Ok(None)` when it is a symlink, not a directory, or not
        /// the effective uid's: it is then left exactly as it is.
        pub(crate) fn open_or_create_child(
            &self,
            name: &str,
            mode: u32,
        ) -> io::Result<Option<Self>> {
            match rustix::fs::mkdirat(&self.0, name, Mode::from_raw_mode(mode)) {
                Ok(()) => self.sync()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            self.open_child(name)
        }

        /// Open the existing directory `name` here. `Ok(None)` when it is a
        /// symlink, not a directory, or not the effective uid's; `NotFound`
        /// passes through.
        pub(crate) fn open_child(&self, name: &str) -> io::Result<Option<Self>> {
            let descriptor = match rustix::fs::openat(
                &self.0,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let stat = rustix::fs::fstat(&descriptor)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                || stat.st_uid != rustix::process::geteuid().as_raw()
            {
                return Ok(None);
            }
            Ok(Some(Self(descriptor)))
        }

        /// Make entries created, renamed or removed here durable.
        pub(crate) fn sync(&self) -> io::Result<()> {
            Ok(rustix::fs::fsync(&self.0)?)
        }

        /// Read `name` if it is a regular file of the effective uid of at
        /// most `max_bytes`.
        pub(crate) fn read(&self, name: &str, max_bytes: u64) -> io::Result<Entry> {
            let descriptor = match rustix::fs::openat(
                &self.0,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::NOENT) => return Ok(Entry::Absent),
                // A symlink; a FIFO or device never blocks with O_NONBLOCK.
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NXIO) => {
                    return Ok(Entry::Foreign);
                }
                Err(error) => return Err(error.into()),
            };
            let stat = rustix::fs::fstat(&descriptor)?;
            let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || size > max_bytes
            {
                return Ok(Entry::Foreign);
            }
            // Sized up front so the buffer is not reallocated, leaving no
            // unzeroized copy behind.
            let mut contents = Zeroizing::new(Vec::with_capacity(
                usize::try_from(max_bytes.min(size.saturating_add(1)))
                    .unwrap_or(0)
                    .saturating_add(1),
            ));
            std::fs::File::from(descriptor)
                .take(max_bytes + 1)
                .read_to_end(&mut contents)?;
            if contents.len() as u64 > max_bytes {
                return Ok(Entry::Foreign);
            }
            Ok(Entry::Owned(OwnedEntry {
                identity: (stat.st_dev, stat.st_ino),
                mode: stat.st_mode & 0o7777,
                contents,
            }))
        }

        /// Create `name` with `O_CREAT|O_EXCL|O_NOFOLLOW` and exactly `mode`,
        /// then write and fsync it. A failed write removes it again.
        pub(crate) fn write_new(&self, name: &str, contents: &[u8], mode: u32) -> io::Result<()> {
            let descriptor = rustix::fs::openat(
                &self.0,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(mode),
            )?;
            let result = (|| {
                // The umask may have narrowed the mode; never widen it past `mode`.
                rustix::fs::fchmod(&descriptor, Mode::from_raw_mode(mode))?;
                let mut file = std::fs::File::from(descriptor.try_clone()?);
                file.write_all(contents)?;
                file.sync_all()
            })();
            if result.is_err() {
                let _ = self.unlink(name);
            }
            result
        }

        /// Rename `from` to `to`, replacing `to` atomically.
        pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            Ok(rustix::fs::renameat(&self.0, from, &self.0, to)?)
        }

        /// Rename `from` to `to` only if `to` does not exist: `Ok(false)` when
        /// it does. Where the file system has no `RENAME_NOREPLACE`, a hard
        /// link (which never replaces) and an unlink do the same.
        pub(crate) fn rename_noreplace(&self, from: &str, to: &str) -> io::Result<bool> {
            match rustix::fs::renameat_with(&self.0, from, &self.0, to, RenameFlags::NOREPLACE) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::EXIST) => Ok(false),
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => {
                    match rustix::fs::linkat(&self.0, from, &self.0, to, AtFlags::empty()) {
                        Ok(()) => {
                            self.unlink(from)?;
                            Ok(true)
                        }
                        Err(rustix::io::Errno::EXIST) => Ok(false),
                        Err(error) => Err(error.into()),
                    }
                }
                Err(error) => Err(error.into()),
            }
        }

        /// Remove `name`; an absent name is not an error.
        pub(crate) fn unlink(&self, name: &str) -> io::Result<()> {
            match rustix::fs::unlinkat(&self.0, name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
                Err(error) => Err(error.into()),
            }
        }

        /// Install `contents` as `name` with exactly `mode` where the caller
        /// found no `name`, through the exclusive `temporary`. `Ok(false)`
        /// when one appeared since: it stays, as the rename never replaces.
        pub(crate) fn install_new(
            &self,
            temporary: &str,
            name: &str,
            contents: &[u8],
            mode: u32,
        ) -> io::Result<bool> {
            self.write_new(temporary, contents, mode)?;
            let installed = self.rename_noreplace(temporary, name);
            if !matches!(installed, Ok(true)) {
                let _ = self.unlink(temporary);
            }
            let installed = installed?;
            self.sync()?;
            Ok(installed)
        }

        /// Replace `name` with `contents` and exactly `mode`, through the
        /// exclusive `temporary`, only while it is still the `inspected` file
        /// with the same bytes, compared right before the rename. `Ok(false)`
        /// when it changed: the changed file stays.
        pub(crate) fn replace_unchanged(
            &self,
            temporary: &str,
            name: &str,
            inspected: &OwnedEntry,
            max_bytes: u64,
            contents: &[u8],
            mode: u32,
        ) -> io::Result<bool> {
            self.write_new(temporary, contents, mode)?;
            let unchanged = match self.read(name, max_bytes) {
                Ok(Entry::Owned(current)) => {
                    current.identity == inspected.identity && current.contents == inspected.contents
                }
                Ok(_) => false,
                Err(error) => {
                    let _ = self.unlink(temporary);
                    return Err(error);
                }
            };
            let replaced = if unchanged {
                self.rename(temporary, name).map(|()| true)
            } else {
                Ok(false)
            };
            if !matches!(replaced, Ok(true)) {
                let _ = self.unlink(temporary);
            }
            let replaced = replaced?;
            self.sync()?;
            Ok(replaced)
        }
    }
}
