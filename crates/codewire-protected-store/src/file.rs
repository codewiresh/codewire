//! Owner-only file protected store: one 0600 file per exact entry inside one
//! 0700 directory, written by atomic replace. This matches Codex's and
//! Claude Code's plaintext file stores on Linux: values rely on filesystem
//! permissions and disk encryption (FileVault), not a login-password key.
//! On macOS the directory carries the Time Machine exclusion attribute so
//! values are not copied into backups.

use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue, protected_value_from_store,
};

const DIRECTORY_MODE: Mode = Mode::RWXU;
const ENTRY_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
/// Entry IDs never contain `+`, so mapping `/` to `+` is one-to-one, and no
/// entry name starts with `.`, so staged names cannot collide with entries.
const SEGMENT_SEPARATOR: char = '+';

#[cfg(target_os = "macos")]
const TIME_MACHINE_EXCLUSION: &str = "com.apple.metadata:com_apple_backup_excludeItem";
/// The binary property list for the string `com.apple.backupd`, exactly as
/// `tmutil addexclusion` writes it.
#[cfg(target_os = "macos")]
const TIME_MACHINE_EXCLUSION_VALUE: &[u8] = &[
    0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x5f, 0x10, 0x11, b'c', b'o', b'm', b'.', b'a',
    b'p', b'p', b'l', b'e', b'.', b'b', b'a', b'c', b'k', b'u', b'p', b'd', 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
];

#[derive(Clone, PartialEq, Eq)]
pub struct FileProtectedStore {
    directory: PathBuf,
}

impl fmt::Debug for FileProtectedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileProtectedStore([REDACTED])")
    }
}

impl FileProtectedStore {
    /// `directory` is created on first write inside its existing private
    /// parent; nothing is touched until an operation runs.
    pub fn new(directory: PathBuf) -> Result<Self, ProtectedStoreError> {
        if !directory.is_absolute()
            || directory.parent().is_none()
            || directory.file_name().is_none()
        {
            return Err(ProtectedStoreError::Unavailable);
        }
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn open_directory(&self, create: bool) -> Result<Option<OwnedFd>, ProtectedStoreError> {
        let parent = self
            .directory
            .parent()
            .ok_or(ProtectedStoreError::Unavailable)?;
        let name = self
            .directory
            .file_name()
            .ok_or(ProtectedStoreError::Unavailable)?;
        let parent = rustix::fs::openat(
            CWD,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProtectedStoreError::Unavailable)?;
        if create {
            match rustix::fs::mkdirat(&parent, name, DIRECTORY_MODE) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(_) => return Err(ProtectedStoreError::Unavailable),
            }
        }
        let directory = match rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(Errno::NOENT) if !create => return Ok(None),
            Err(_) => return Err(ProtectedStoreError::AccessDenied),
        };
        let stat = rustix::fs::fstat(&directory).map_err(|_| ProtectedStoreError::Unavailable)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || Mode::from_raw_mode(stat.st_mode) != DIRECTORY_MODE
        {
            return Err(ProtectedStoreError::AccessDenied);
        }
        #[cfg(target_os = "macos")]
        if create {
            rustix::fs::fsetxattr(
                &directory,
                TIME_MACHINE_EXCLUSION,
                TIME_MACHINE_EXCLUSION_VALUE,
                rustix::fs::XattrFlags::empty(),
            )
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        }
        Ok(Some(directory))
    }
}

fn entry_name(id: &ProtectedEntryId) -> String {
    id.expose_reference()
        .replace('/', &SEGMENT_SEPARATOR.to_string())
}

fn staged_name(id: &ProtectedEntryId) -> String {
    format!(".{}.tmp", entry_name(id))
}

fn validate_entry_file(file: &OwnedFd) -> Result<u64, ProtectedStoreError> {
    let stat = rustix::fs::fstat(file).map_err(|_| ProtectedStoreError::Unavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode) != ENTRY_MODE
    {
        return Err(ProtectedStoreError::AccessDenied);
    }
    u64::try_from(stat.st_size).map_err(|_| ProtectedStoreError::CorruptEntry)
}

impl ProtectedStore for FileProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        let Some(directory) = self.open_directory(false)? else {
            return Ok(None);
        };
        let file = match rustix::fs::openat(
            &directory,
            entry_name(id),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ProtectedStoreError::AccessDenied),
        };
        let size = validate_entry_file(&file)?;
        if size == 0 || size > MAX_PROTECTED_VALUE_BYTES as u64 {
            return Err(ProtectedStoreError::CorruptEntry);
        }
        let mut value = Zeroizing::new(Vec::with_capacity(size as usize + 1));
        File::from(file)
            .take(MAX_PROTECTED_VALUE_BYTES as u64 + 1)
            .read_to_end(&mut value)
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        protected_value_from_store(std::mem::take(&mut *value)).map(Some)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let directory = self
            .open_directory(true)?
            .ok_or(ProtectedStoreError::Unavailable)?;
        let staged = staged_name(id);
        // A staged file survives only an interrupted write of this entry.
        match rustix::fs::unlinkat(&directory, &staged, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => return Err(ProtectedStoreError::Unavailable),
        }
        let file = rustix::fs::openat(
            &directory,
            &staged,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            ENTRY_MODE,
        )
        .map_err(|_| ProtectedStoreError::Unavailable)?;
        let written = (|| {
            rustix::fs::fchmod(&file, ENTRY_MODE)?;
            let mut file = File::from(file);
            file.write_all(value.expose_secret())?;
            file.sync_all()?;
            rustix::fs::renameat(&directory, &staged, &directory, entry_name(id))?;
            rustix::fs::fsync(&directory)?;
            Ok::<_, std::io::Error>(())
        })();
        if written.is_err() {
            let _ = rustix::fs::unlinkat(&directory, &staged, AtFlags::empty());
            return Err(ProtectedStoreError::Unavailable);
        }
        Ok(())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        let Some(directory) = self.open_directory(false)? else {
            return Ok(());
        };
        for name in [entry_name(id), staged_name(id)] {
            match rustix::fs::unlinkat(&directory, &name, AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(_) => return Err(ProtectedStoreError::Unavailable),
            }
        }
        rustix::fs::fsync(&directory).map_err(|_| ProtectedStoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn entry(value: &str) -> ProtectedEntryId {
        ProtectedEntryId::parse(value).unwrap()
    }

    fn private_parent() -> tempfile::TempDir {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        parent
    }

    fn file_text(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    #[test]
    fn entries_are_exact_private_files_replaced_atomically() {
        let parent = private_parent();
        let directory = parent.path().join("protected-v1");
        let store = FileProtectedStore::new(directory.clone()).unwrap();
        let first = entry("local/credentials/a/material-v1");
        let second = entry("local/credentials/a/material-v2");
        assert_eq!(
            store.persistence(),
            ProtectedStorePersistence::OperatingSystem
        );
        assert!(store.get(&first).unwrap().is_none());
        store.delete(&first).unwrap();
        assert!(!directory.exists(), "reads and deletes create nothing");

        store
            .put(
                &first,
                &ProtectedValue::from_slice(b"synthetic-one").unwrap(),
            )
            .unwrap();
        store
            .put(&first, &ProtectedValue::from_slice(&[0, 255, 10]).unwrap())
            .unwrap();
        store
            .put(
                &second,
                &ProtectedValue::from_slice(b"synthetic-two").unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.get(&first).unwrap().unwrap().expose_secret(),
            &[0, 255, 10]
        );
        let directory_metadata = std::fs::metadata(&directory).unwrap();
        assert_eq!(directory_metadata.mode() & 0o7777, 0o700);
        let path = directory.join("local+credentials+a+material-v1");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(file_text(&path), [0, 255, 10]);
        let mut names = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "local+credentials+a+material-v1",
                "local+credentials+a+material-v2"
            ]
        );

        store.delete(&first).unwrap();
        store.delete(&first).unwrap();
        assert!(store.get(&first).unwrap().is_none());
        assert_eq!(
            store.get(&second).unwrap().unwrap().expose_secret(),
            b"synthetic-two"
        );
        assert_eq!(format!("{store:?}"), "FileProtectedStore([REDACTED])");
    }

    #[test]
    fn foreign_links_modes_and_sizes_fail_closed() {
        let parent = private_parent();
        let directory = parent.path().join("protected-v1");
        let store = FileProtectedStore::new(directory.clone()).unwrap();
        let id = entry("local/credentials/a/material-v1");
        store
            .put(&id, &ProtectedValue::from_slice(b"synthetic").unwrap())
            .unwrap();
        let path = directory.join("local+credentials+a+material-v1");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::CorruptEntry)
        );

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(parent.path().join("elsewhere"), &path).unwrap();
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        std::fs::remove_file(&path).unwrap();

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            store.get(&id).err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();

        let linked_parent = private_parent();
        let target = linked_parent.path().join("target");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .unwrap();
        let linked = linked_parent.path().join("protected-v1");
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        let linked = FileProtectedStore::new(linked).unwrap();
        assert_eq!(
            linked.get(&id).err(),
            Some(ProtectedStoreError::AccessDenied)
        );
        assert!(
            linked
                .put(&id, &ProtectedValue::from_slice(b"synthetic").unwrap())
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);

        assert!(FileProtectedStore::new("relative".into()).is_err());
        assert!(FileProtectedStore::new("/".into()).is_err());
    }

    #[test]
    fn an_interrupted_staged_write_is_replaced_and_removed() {
        let parent = private_parent();
        let directory = parent.path().join("protected-v1");
        let store = FileProtectedStore::new(directory.clone()).unwrap();
        let id = entry("local/credentials/a/material-v1");
        store
            .put(&id, &ProtectedValue::from_slice(b"first").unwrap())
            .unwrap();
        let staged = directory.join(".local+credentials+a+material-v1.tmp");
        std::fs::write(&staged, b"partial").unwrap();
        store
            .put(&id, &ProtectedValue::from_slice(b"second").unwrap())
            .unwrap();
        assert!(!staged.exists());
        assert_eq!(store.get(&id).unwrap().unwrap().expose_secret(), b"second");
        std::fs::write(&staged, b"partial").unwrap();
        store.delete(&id).unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_directory_is_excluded_from_time_machine() {
        let parent = private_parent();
        let directory = parent.path().join("protected-v1");
        let store = FileProtectedStore::new(directory.clone()).unwrap();
        store
            .put(
                &entry("local/credentials/a/material-v1"),
                &ProtectedValue::from_slice(b"synthetic").unwrap(),
            )
            .unwrap();
        let mut value = vec![0; 128];
        let length =
            rustix::fs::getxattr(&directory, TIME_MACHINE_EXCLUSION, value.as_mut_slice()).unwrap();
        assert_eq!(&value[..length], TIME_MACHINE_EXCLUSION_VALUE);
        let output = std::process::Command::new("/usr/bin/tmutil")
            .arg("isexcluded")
            .arg(&directory)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&output.stdout).contains("[Excluded]"));
    }
}
