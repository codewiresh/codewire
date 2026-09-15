//! Runtime discriminators for public Darwin filesystem primitives. These run
//! through the checked-in Mac developer loop before the adapter uses them.

use std::ffi::{CStr, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

// Public SDK27 sys/fcntl.h and sys/errno.h. libc0.2.186 does not expose these
// newer constants. Success alone is insufficient: the tests require the actual
// documented rejection semantics, so a kernel ignoring unknown flags fails.
const O_RESOLVE_BENEATH: libc::c_int = 0x0000_1000;
const O_UNIQUE: libc::c_int = 0x0000_2000;
const ENOTCAPABLE: libc::c_int = 107;
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const FILESEC_ACL: libc::c_int = 5;

// Public libSystem ACL API, not an Apple framework or private API.
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
    fn filesec_set_property(
        security: *mut c_void,
        property: libc::c_int,
        value: *const c_void,
    ) -> libc::c_int;
    // Match sys/stat.h's __DARWIN_INODE64 declaration and libc::stat layout.
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: libc::c_int, metadata: *mut libc::stat, security: *mut c_void) -> libc::c_int;
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
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

fn stat_security(fd: libc::c_int) -> io::Result<(FileSecurity, libc::stat)> {
    // SAFETY: filesec_init has no arguments and allocates an owned object.
    let pointer = unsafe { filesec_init() };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let security = FileSecurity(pointer);
    let mut metadata = std::mem::MaybeUninit::uninit();
    // SAFETY: both output objects are valid. Invalid fds are diagnosed by libc;
    // the stat buffer is read only after the syscall initializes it successfully.
    if unsafe { fstatx_np(fd, metadata.as_mut_ptr(), security.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatx_np initialized the correctly sized stat buffer.
    let metadata = unsafe { metadata.assume_init() };
    security_metadata_matches(&security, &metadata)?;
    Ok((security, metadata))
}

fn security_metadata_matches(security: &FileSecurity, metadata: &libc::stat) -> io::Result<()> {
    // Apple's statx1 has a realloc failure path that can return zero before
    // populating filesec. Require its completion fields before ACL absence can
    // be considered. Do not infer success/failure from errno after a zero return.
    let (mut owner, mut group, mut mode): (libc::uid_t, libc::gid_t, libc::mode_t) = (0, 0, 0);
    for (property, output) in [
        (1, (&mut owner as *mut libc::uid_t).cast::<c_void>()),
        (2, (&mut group as *mut libc::gid_t).cast::<c_void>()),
        (4, (&mut mode as *mut libc::mode_t).cast::<c_void>()),
    ] {
        // SAFETY: FILESEC_OWNER/GROUP/MODE output types match the public SDK;
        // the three local destinations and filesec allocation stay valid.
        if unsafe { filesec_get_property(security.0, property, output) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if (owner, group, mode) != (metadata.st_uid, metadata.st_gid, metadata.st_mode) {
        return Err(io::Error::other("inconsistent file security metadata"));
    }
    Ok(())
}

fn acl_first_entry(acl: &Acl) -> (libc::c_int, Option<libc::c_int>) {
    // SAFETY: the live ACL object came from the public allocator above.
    assert_eq!(unsafe { acl_valid(acl.0) }, 0, "ACL object must validate");
    let mut entry = std::ptr::null_mut();
    // SAFETY: __error is this thread's errno; ACL and output pointer are valid.
    let result = unsafe {
        *libc::__error() = 0;
        acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry)
    };
    let error = (result == -1)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    if result == 0 {
        assert!(!entry.is_null(), "successful ACL entry must exist");
    }
    (result, error)
}

fn acl_state(file: &File) -> AclState {
    // SAFETY: file owns a live fd and the selector is public sys/unistd.h.
    let capability = unsafe { libc::fpathconf(file.as_raw_fd(), libc::_PC_EXTENDED_SECURITY_NP) };
    assert!(
        capability > 0,
        "retained mount must support extended security"
    );
    let (security, metadata) = stat_security(file.as_raw_fd()).unwrap();
    let retained = file.metadata().unwrap();
    assert_eq!(metadata.st_dev as u64, retained.dev());
    assert_eq!(metadata.st_ino, retained.ino());
    assert_eq!(metadata.st_uid, retained.uid());
    assert_eq!(metadata.st_gid, retained.gid());
    assert_eq!(u32::from(metadata.st_mode), retained.mode());
    assert_eq!(u64::from(metadata.st_nlink), retained.nlink());
    security_acl_state(&security)
}

fn security_acl_state(security: &FileSecurity) -> AclState {
    let mut present = -1;
    // SAFETY: this fresh filesec was filled by a successful retained-FD stat;
    // query distinguishes absent property from failed metadata retrieval.
    assert_eq!(
        unsafe { filesec_query_property(security.0, FILESEC_ACL, &mut present) },
        0
    );
    if present == 0 {
        return AclState::Absent;
    }
    let mut pointer: *mut c_void = std::ptr::null_mut();
    // SAFETY: the output is an ACL pointer, as specified for FILESEC_ACL. This
    // allocates a separate ACL copy, owned independently from the filesec object.
    assert_eq!(
        unsafe {
            filesec_get_property(
                security.0,
                FILESEC_ACL,
                (&mut pointer as *mut *mut c_void).cast(),
            )
        },
        0
    );
    assert!(
        !pointer.is_null() && pointer as usize != 1,
        "expected an allocated ACL"
    );
    let acl = Acl(pointer);
    match acl_first_entry(&acl) {
        (-1, Some(libc::EINVAL)) => AclState::Empty,
        (0, None) => AclState::Entries,
        other => panic!("unexpected ACL enumeration result: {other:?}"),
    }
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
fn retained_security_distinguishes_absent_present_and_removed_acls() {
    let (_temporary, path, directory) = root();
    let file = regular(&path.join("file"));
    for (object, name) in [(&directory, path.clone()), (&file, path.join("file"))] {
        assert_eq!(acl_state(object), AclState::Absent);
        chmod(&name, &["+a", "everyone allow readattr"]);
        assert_eq!(acl_state(object), AclState::Entries);
        chmod(&name, &["-N"]);
        assert_eq!(acl_state(object), AclState::Absent);
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
    assert_eq!(acl_first_entry(&acl), (-1, Some(libc::EINVAL)));
    let (security, _) = stat_security(file.as_raw_fd()).unwrap();
    // SAFETY: the public property setter copies this valid ACL into filesec;
    // the input type is a pointer to acl_t, not the ACL object itself.
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
    assert_eq!(security_acl_state(&security), AclState::Empty);
    for object in [&directory, &file] {
        // SAFETY: both objects are newly created synthetic fixtures. The ACL
        // and descriptor stay valid; acl_set_fd_np does not consume the ACL.
        assert_eq!(
            unsafe { acl_set_fd_np(object.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) },
            0
        );
        // The tested APFS path normalizes the zero-entry on-disk form to absent.
        // Neither accepted representation may acquire access entries or hide
        // an inspection failure. The present-empty decoder is proven above.
        assert!(matches!(
            acl_state(object),
            AclState::Absent | AclState::Empty
        ));
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
    assert_eq!(acl_state(&directory), AclState::Entries);
    let child = regular(&path.join("child"));
    assert_eq!(acl_state(&child), AclState::Entries);
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
    // SAFETY: object/output are live; an invalid property is defined as EINVAL.
    let result = unsafe { filesec_query_property(security.0, -1, &mut present) };
    let error = io::Error::last_os_error();
    assert_eq!(result, -1);
    assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    assert_eq!(present, -1, "failed query must not fabricate absence");
}

#[test]
fn incomplete_security_metadata_cannot_masquerade_as_no_acl() {
    let (_temporary, _path, directory) = root();
    let (_complete, metadata) = stat_security(directory.as_raw_fd()).unwrap();
    // SAFETY: allocate a fresh, deliberately unpopulated filesec. This models
    // the statx1 early-return allocation-failure shape without inducing OOM.
    let pointer = unsafe { filesec_init() };
    assert!(!pointer.is_null());
    let incomplete = FileSecurity(pointer);
    let error = security_metadata_matches(&incomplete, &metadata).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
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
