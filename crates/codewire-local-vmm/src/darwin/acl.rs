//! Retained-descriptor extended-ACL admission through public Darwin libSystem.
//!
//! Absence and validated zero-entry ACLs are distinct empty states. Every access
//! entry, unsupported capability, or incomplete security read is rejected.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

// Public SDK27 fcntl.h and sys/acl.h declarations missing from libc0.2.186.
const ACL_FIRST_ENTRY: libc::c_int = 0;
const FILESEC_OWNER: libc::c_int = 1;
const FILESEC_GROUP: libc::c_int = 2;
const FILESEC_MODE: libc::c_int = 4;
const FILESEC_ACL: libc::c_int = 5;

unsafe extern "C" {
    fn filesec_init() -> *mut c_void;
    fn filesec_free(security: *mut c_void);
    fn filesec_query_property(
        security: *mut c_void,
        property: libc::c_int,
        present: *mut libc::c_int,
    ) -> libc::c_int;
    fn filesec_get_property(
        security: *mut c_void,
        property: libc::c_int,
        value: *mut c_void,
    ) -> libc::c_int;
    // Match sys/stat.h's __DARWIN_INODE64 declaration and libc::stat layout.
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: libc::c_int, metadata: *mut libc::stat, security: *mut c_void) -> libc::c_int;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_get_entry(
        acl: *mut c_void,
        entry_id: libc::c_int,
        entry: *mut *mut c_void,
    ) -> libc::c_int;
    fn acl_free(object: *mut c_void) -> libc::c_int;
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: this allocated ACL object has one owner and is freed once.
        unsafe { acl_free(self.0) };
    }
}

#[derive(Debug)]
struct FileSecurity(*mut c_void);

impl Drop for FileSecurity {
    fn drop(&mut self) {
        // SAFETY: this object came from filesec_init and is freed once.
        unsafe { filesec_free(self.0) };
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AclState {
    Absent,
    Empty,
    Entries,
}

/// Reject every extended ACL entry on this retained file or directory.
///
/// This borrows the descriptor and changes no ACL or ownership. Callers retain
/// responsibility for file type, private-path identity, ownership and mode.
pub(super) fn require_empty(file: &File) -> io::Result<()> {
    match acl_state(file)? {
        AclState::Absent | AclState::Empty => Ok(()),
        AclState::Entries => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "extended ACL contains entries",
        )),
    }
}

fn acl_state(file: &File) -> io::Result<AclState> {
    // SAFETY: file owns a live fd. __error is this thread's errno; clearing it
    // distinguishes indeterminate fpathconf(-1) from a reported syscall error.
    let capability = unsafe {
        *libc::__error() = 0;
        libc::fpathconf(file.as_raw_fd(), libc::_PC_EXTENDED_SECURITY_NP)
    };
    if capability < 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(0) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "indeterminate extended security support",
            )
        } else {
            error
        });
    }
    if capability == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "extended security is unsupported",
        ));
    }

    let (security, metadata) = stat_security(file.as_raw_fd())?;
    let retained = file.metadata()?;
    if metadata.st_dev as u64 != retained.dev()
        || metadata.st_ino != retained.ino()
        || metadata.st_uid != retained.uid()
        || metadata.st_gid != retained.gid()
        || u32::from(metadata.st_mode) != retained.mode()
        || u64::from(metadata.st_nlink) != retained.nlink()
    {
        return Err(invalid_security("inconsistent retained file metadata"));
    }
    security_acl_state(&security)
}

fn stat_security(fd: libc::c_int) -> io::Result<(FileSecurity, libc::stat)> {
    // SAFETY: filesec_init has no arguments and allocates an owned object.
    let pointer = unsafe { filesec_init() };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let security = FileSecurity(pointer);
    let mut metadata = std::mem::MaybeUninit::uninit();
    // SAFETY: both output objects are valid. Invalid fds are diagnosed by libc;
    // the stat buffer is read only after successful initialization.
    if unsafe { fstatx_np(fd, metadata.as_mut_ptr(), security.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a zero return initialized stat, including the known later ACL
    // allocation failure path. Completion of filesec is checked separately.
    let metadata = unsafe { metadata.assume_init() };
    security_metadata_matches(&security, &metadata)?;
    Ok((security, metadata))
}

fn security_metadata_matches(security: &FileSecurity, metadata: &libc::stat) -> io::Result<()> {
    // Apple's statx1 can return zero after realloc fails, before populating
    // filesec. Successful getters require all three completion fields to exist;
    // errno after a zero stat result cannot distinguish that failure safely.
    let (mut owner, mut group, mut mode): (libc::uid_t, libc::gid_t, libc::mode_t) = (0, 0, 0);
    for (property, output) in [
        (
            FILESEC_OWNER,
            (&mut owner as *mut libc::uid_t).cast::<c_void>(),
        ),
        (
            FILESEC_GROUP,
            (&mut group as *mut libc::gid_t).cast::<c_void>(),
        ),
        (
            FILESEC_MODE,
            (&mut mode as *mut libc::mode_t).cast::<c_void>(),
        ),
    ] {
        // SAFETY: each property has its exact public SDK output type, and the
        // three local destinations and filesec allocation stay valid.
        if unsafe { filesec_get_property(security.0, property, output) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if (owner, group, mode) != (metadata.st_uid, metadata.st_gid, metadata.st_mode) {
        return Err(invalid_security("inconsistent file security metadata"));
    }
    Ok(())
}

fn query_property(
    security: &FileSecurity,
    property: libc::c_int,
    present: &mut libc::c_int,
) -> io::Result<()> {
    // SAFETY: the filesec and output reference are live. Invalid selectors are
    // diagnosed by the public API, not interpreted as absent values.
    if unsafe { filesec_query_property(security.0, property, present) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn security_acl_state(security: &FileSecurity) -> io::Result<AclState> {
    let mut present = -1;
    query_property(security, FILESEC_ACL, &mut present)?;
    if present == 0 {
        return Ok(AclState::Absent);
    }
    let mut pointer: *mut c_void = std::ptr::null_mut();
    // SAFETY: FILESEC_ACL requires an ACL-pointer output. A successful getter
    // allocates an independent copy, not a borrow of filesec's backing storage.
    if unsafe {
        filesec_get_property(
            security.0,
            FILESEC_ACL,
            (&mut pointer as *mut *mut c_void).cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if pointer.is_null() || pointer as usize == 1 {
        // The remove-ACL sentinel is not allocated and must not be validated or
        // freed. Neither it nor NULL is an accepted property read result.
        return Err(invalid_security("missing allocated ACL"));
    }
    let acl = Acl(pointer);
    acl_entry_state(&acl)
}

fn acl_entry_state(acl: &Acl) -> io::Result<AclState> {
    // SAFETY: the live ACL object came from the public allocator.
    if unsafe { acl_valid(acl.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: the ACL and output pointer are valid; FIRST_ENTRY is public.
    let result = unsafe {
        *libc::__error() = 0;
        acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry)
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::EINVAL) {
            Ok(AclState::Empty)
        } else if error.raw_os_error() == Some(0) {
            Err(invalid_security("ACL enumeration failed without errno"))
        } else {
            Err(error)
        };
    }
    if result != 0 || entry.is_null() {
        return Err(invalid_security("invalid ACL enumeration result"));
    }
    Ok(AclState::Entries)
}

fn invalid_security(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    unsafe extern "C" {
        fn filesec_set_property(
            security: *mut c_void,
            property: libc::c_int,
            value: *const c_void,
        ) -> libc::c_int;
        fn acl_init(count: libc::c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
    }

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

    fn regular(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    fn chmod(path: &Path, arguments: &[&str]) {
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(arguments)
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn retained_security_distinguishes_absent_present_and_removed_acls() {
        let (_temporary, path, directory) = root();
        let file = regular(&path.join("file"));
        for (object, name) in [(&directory, path.clone()), (&file, path.join("file"))] {
            assert_eq!(acl_state(object).unwrap(), AclState::Absent);
            require_empty(object).unwrap();
            chmod(&name, &["+a", "everyone allow readattr"]);
            assert_eq!(acl_state(object).unwrap(), AclState::Entries);
            assert_eq!(
                require_empty(object).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            chmod(&name, &["-N"]);
            assert_eq!(acl_state(object).unwrap(), AclState::Absent);
            require_empty(object).unwrap();
        }
    }

    #[test]
    fn explicit_zero_entry_acl_is_distinct_before_filesystem_normalization() {
        let (_temporary, path, directory) = root();
        let file = regular(&path.join("file"));
        // SAFETY: acl_init allocates an owned, initially empty ACL.
        let pointer = unsafe { acl_init(0) };
        assert!(!pointer.is_null());
        let acl = Acl(pointer);
        assert_eq!(acl_entry_state(&acl).unwrap(), AclState::Empty);
        let (security, _) = stat_security(file.as_raw_fd()).unwrap();
        // SAFETY: this public setter copies a valid ACL; the input is a pointer
        // to acl_t, not the ACL object itself. Both owners stay live.
        assert_eq!(
            unsafe {
                filesec_set_property(
                    security.0,
                    FILESEC_ACL,
                    (&acl.0 as *const *mut c_void).cast(),
                )
            },
            0
        );
        assert_eq!(security_acl_state(&security).unwrap(), AclState::Empty);
        for object in [&directory, &file] {
            // SAFETY: these newly created synthetic objects and the borrowed
            // ACL remain live. acl_set_fd_np does not consume the ACL.
            assert_eq!(
                unsafe { acl_set_fd_np(object.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) },
                0
            );
            // Filesystems may normalize zero entries to absence, but entries
            // and inspection errors are never admitted by either call.
            assert!(matches!(
                acl_state(object).unwrap(),
                AclState::Absent | AclState::Empty
            ));
            require_empty(object).unwrap();
        }
    }

    #[test]
    fn inherited_acl_entries_are_observed_on_the_created_child() {
        let (_temporary, path, directory) = root();
        chmod(
            &path,
            &[
                "+a",
                "everyone allow readattr,file_inherit,directory_inherit",
            ],
        );
        assert_eq!(acl_state(&directory).unwrap(), AclState::Entries);
        assert_eq!(
            require_empty(&directory).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let child = regular(&path.join("child"));
        assert_eq!(acl_state(&child).unwrap(), AclState::Entries);
        assert_eq!(
            require_empty(&child).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn failed_security_reads_and_queries_cannot_be_acl_absence() {
        let error = match stat_security(-1) {
            Ok(_) => panic!("invalid descriptor must fail before property query"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let (_temporary, _path, directory) = root();
        let (security, _) = stat_security(directory.as_raw_fd()).unwrap();
        let mut present = -1;
        let error = query_property(&security, -1, &mut present).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(present, -1, "failed query must not fabricate absence");
    }

    #[test]
    fn incomplete_security_metadata_cannot_masquerade_as_no_acl() {
        let (_temporary, _path, directory) = root();
        let (complete, mut metadata) = stat_security(directory.as_raw_fd()).unwrap();
        // SAFETY: a fresh, deliberately unpopulated filesec models statx1's
        // early-return failure shape without inducing OOM.
        let pointer = unsafe { filesec_init() };
        assert!(!pointer.is_null());
        let incomplete = FileSecurity(pointer);
        let error = security_metadata_matches(&incomplete, &metadata).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
        metadata.st_uid = metadata.st_uid.wrapping_add(1);
        assert_eq!(
            security_metadata_matches(&complete, &metadata)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
