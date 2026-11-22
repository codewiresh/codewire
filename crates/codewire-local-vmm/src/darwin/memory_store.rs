//! Directories that hold a VM's memory stay off the Mac's backups (#4654,
//! cw-security's condition 10): a VM checkpoint's saved state holds
//! everything the guest's memory held, delivered sign-ins included. Spotlight
//! needs nothing here: no importer reads a saved state, and macOS 27 ignores
//! the never-index marker, so none is written (recorded on #4654).

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// The attribute `tmutil addexclusion` sets: Time Machine skips the item and
/// everything under it, and the exclusion moves with it.
const BACKUP_EXCLUDE_ATTRIBUTE: &CStr = c"com.apple.metadata:com_apple_backup_excludeItem";

/// The attribute's value: a binary property list holding the string
/// `com.apple.backupd`, as `tmutil addexclusion` writes it.
const BACKUP_EXCLUDE_VALUE: [u8; 61] = backup_exclude_value();

const fn backup_exclude_value() -> [u8; 61] {
    const STRING: &[u8; 17] = b"com.apple.backupd";
    let mut value = [0_u8; 61];
    let header = b"bplist00";
    let mut index = 0;
    while index < header.len() {
        value[index] = header[index];
        index += 1;
    }
    // One ASCII string object of 17 bytes: marker 0x5F, then its length as
    // a one-byte integer object.
    value[8] = 0x5f;
    value[9] = 0x10;
    value[10] = 17;
    index = 0;
    while index < STRING.len() {
        value[11 + index] = STRING[index];
        index += 1;
    }
    // The offset table: the one object starts at byte 8.
    value[28] = 8;
    // The trailer: one-byte offsets and references, one object, object 0
    // on top, the offset table at byte 28.
    value[35] = 1;
    value[36] = 1;
    value[44] = 1;
    value[60] = 28;
    value
}

fn open_directory(directory: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
}

/// Whether Time Machine skips `directory`.
pub(crate) fn excluded_from_backup(directory: &Path) -> io::Result<bool> {
    let directory = open_directory(directory)?;
    let mut value = [0_u8; BACKUP_EXCLUDE_VALUE.len() + 1];
    // SAFETY: the descriptor, the NUL-terminated name and the buffer with
    // its length stay live for the call; position 0 and no options read
    // the whole attribute.
    let read = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            BACKUP_EXCLUDE_ATTRIBUTE.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    if read < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOATTR) => Ok(false),
            _ => Err(error),
        };
    }
    Ok(value.get(..read.unsigned_abs()) == Some(&BACKUP_EXCLUDE_VALUE[..]))
}

/// Keep `directory` and everything under it out of Time Machine, as
/// `tmutil addexclusion` would. Safe to repeat; it writes only when missing.
pub(crate) fn exclude_from_backup(directory: &Path) -> io::Result<()> {
    if excluded_from_backup(directory)? {
        return Ok(());
    }
    let opened = open_directory(directory)?;
    // SAFETY: the descriptor, the NUL-terminated name and the value with its
    // length stay live for the call.
    let result = unsafe {
        libc::fsetxattr(
            opened.as_raw_fd(),
            BACKUP_EXCLUDE_ATTRIBUTE.as_ptr(),
            BACKUP_EXCLUDE_VALUE.as_ptr().cast(),
            BACKUP_EXCLUDE_VALUE.len(),
            0,
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exclusion_value_is_tmutils_property_list() {
        let mut expected = b"bplist00_\x10\x11com.apple.backupd\x08".to_vec();
        expected.extend([0; 6]);
        expected.extend([1, 1]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend([0; 8]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 28]);
        assert_eq!(BACKUP_EXCLUDE_VALUE.to_vec(), expected);
    }

    #[test]
    fn a_directory_is_excluded_once_and_a_link_is_never_followed() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!excluded_from_backup(directory.path()).unwrap());
        exclude_from_backup(directory.path()).unwrap();
        assert!(excluded_from_backup(directory.path()).unwrap());
        exclude_from_backup(directory.path()).unwrap();
        let link = directory.path().join("link");
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), &link).unwrap();
        assert!(exclude_from_backup(&link).is_err());
        assert!(!excluded_from_backup(other.path()).unwrap());
    }
}
