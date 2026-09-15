//! Runtime discriminators for public Darwin filesystem primitives. These run
//! through the checked-in Mac developer loop before the adapter uses them.

use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

// Public SDK27 sys/fcntl.h and sys/errno.h. libc0.2.186 does not expose these
// newer constants. Success alone is insufficient: the tests require the actual
// documented rejection semantics, so a kernel ignoring unknown flags fails.
const O_RESOLVE_BENEATH: libc::c_int = 0x0000_1000;
const O_UNIQUE: libc::c_int = 0x0000_2000;
const ENOTCAPABLE: libc::c_int = 107;

fn root() -> (tempfile::TempDir, PathBuf, File) {
    let temporary = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(temporary.path()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY)
        .open(&path)
        .unwrap();
    (temporary, path, directory)
}

fn open_at(directory: &File, path: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the dirfd and NUL-terminated pathname stay alive through openat.
    // Callers never pass O_CREAT, so no variadic mode argument is required.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn flags() -> libc::c_int {
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY | O_RESOLVE_BENEATH
}

fn regular(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

#[test]
fn beneath_flag_rejects_parent_escape_in_the_kernel() {
    let (_temporary, path, directory) = root();
    let _file = regular(&path.join("inside"));
    assert!(open_at(&directory, c"inside", flags()).is_ok());
    let error = open_at(&directory, c"..", flags() | libc::O_DIRECTORY).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(ENOTCAPABLE));
}

#[test]
fn nofollow_any_rejects_an_intermediate_symlink_in_the_kernel() {
    let (_temporary, path, directory) = root();
    fs::create_dir(path.join("actual")).unwrap();
    let _file = regular(&path.join("actual/file"));
    symlink("actual", path.join("alias")).unwrap();
    assert!(open_at(&directory, c"actual/file", flags()).is_ok());
    let error = open_at(&directory, c"alias/file", flags()).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
}

#[test]
fn unique_flag_rejects_multiple_hardlinks_in_the_kernel() {
    let (_temporary, path, directory) = root();
    let _file = regular(&path.join("first"));
    assert!(open_at(&directory, c"first", flags() | O_UNIQUE).is_ok());
    fs::hard_link(path.join("first"), path.join("second")).unwrap();
    let error = open_at(&directory, c"first", flags() | O_UNIQUE).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(ENOTCAPABLE));
}

#[test]
fn retained_file_and_directory_support_fsync_then_fullfsync() {
    let (_temporary, path, directory) = root();
    let mut file = regular(&path.join("file"));
    file.write_all(b"native private-path capability fixture")
        .unwrap();
    for object in [&file, &directory] {
        object.sync_all().unwrap();
        // SAFETY: the live fd is owned and F_FULLFSYNC has no pointer argument.
        let result = unsafe { libc::fcntl(object.as_raw_fd(), libc::F_FULLFSYNC) };
        assert_eq!(result, 0, "F_FULLFSYNC: {}", io::Error::last_os_error());
    }
}
