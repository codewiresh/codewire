//! Admission and launch-time revalidation for explicit host directory shares.
//!
//! Direct shares are intentionally path-addressed in private durable state so
//! an offline restart can find them again, but the path never crosses the
//! host-only runner boundary.  The persisted identity binds the directory,
//! filesystem, and mount instance; every launch reopens the path without
//! following symlinks and refuses replacement or mount-topology changes.
//! Linux serves the admitted descriptor through virtiofsd. Darwin admits only
//! APFS directories and hands the exact admitted path and identity to the
//! Virtualization.framework helper, which checks them again around VM start.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Component, Path, PathBuf};

use codewire_vmm_guest_probe::DirectShareMount;
#[cfg(target_os = "linux")]
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, StatxFlags, openat2, statx};

use crate::host::path::current_uid;
use crate::supervisor_metadata::direct_share::allowed_filesystem;
pub(crate) use crate::supervisor_metadata::direct_share::{
    DirectShareDiscriminator, DirectShareError, DirectShareIdentity,
};

const MAXIMUM_HOST_PATH_BYTES: usize = 4096;

/// An admitted directory, held open. While it lives the directory's inode
/// stays allocated, so a directory created at its path has another inode
/// number and any (device, inode) comparison against it is exact.
#[derive(Debug)]
pub(crate) struct AdmittedDirectShare {
    path: PathBuf,
    identity: DirectShareIdentity,
    discriminator: DirectShareDiscriminator,
    descriptor: OwnedFd,
}

impl AdmittedDirectShare {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &DirectShareIdentity {
        &self.identity
    }

    /// The discriminator read from the held descriptor at admission.
    pub(crate) fn discriminator(&self) -> &DirectShareDiscriminator {
        &self.discriminator
    }

    pub(crate) fn descriptor(&self) -> &OwnedFd {
        &self.descriptor
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DirectShareRequest {
    pub(crate) source_path: PathBuf,
    pub(crate) identity: DirectShareIdentity,
    pub(crate) mount: DirectShareMount,
}

impl fmt::Debug for DirectShareRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectShareRequest")
            .field("source_path", &"[REDACTED]")
            .field("identity", &self.identity)
            .field("mount", &self.mount)
            .finish()
    }
}

impl DirectShareRequest {
    pub(crate) fn new(
        source_path: PathBuf,
        identity: DirectShareIdentity,
        mount: DirectShareMount,
    ) -> Result<Self, DirectShareError> {
        validate_normal_absolute_path(&source_path)?;
        identity.validate()?;
        Ok(Self {
            source_path,
            identity,
            mount,
        })
    }

    pub(crate) fn reopen(
        &self,
        forbidden_roots: &[PathBuf],
    ) -> Result<AdmittedDirectShare, DirectShareError> {
        reopen_direct_share(&self.source_path, &self.identity, forbidden_roots)
    }
}

/// Admit a canonical user-owned directory that is disjoint from all private
/// Codewire state supplied by the caller and from common credential stores.
pub(crate) fn admit_direct_share(
    requested: &Path,
    forbidden_roots: &[PathBuf],
) -> Result<AdmittedDirectShare, DirectShareError> {
    validate_normal_absolute_path(requested)?;
    let canonical = fs::canonicalize(requested).map_err(|source| DirectShareError::Io {
        path: requested.to_owned(),
        source,
    })?;
    if canonical != requested {
        return Err(DirectShareError::NonCanonical(requested.to_owned()));
    }
    validate_source_policy(&canonical, forbidden_roots)?;
    let descriptor = open_exact_directory(&canonical)?;
    let opened_path = descriptor_path(&descriptor)?;
    if opened_path != canonical {
        return Err(DirectShareError::SourceChanged(canonical));
    }
    let identity = capture_identity(&descriptor)?;
    if identity.owner_uid() != current_uid() {
        return Err(DirectShareError::WrongOwner(canonical));
    }
    if !allowed_filesystem(identity.filesystem_magic()) {
        return Err(DirectShareError::UnsupportedFilesystem(canonical));
    }
    identity.validate()?;
    reject_mount_alias_or_submounts(&canonical, identity.mount_id())?;
    let discriminator = capture_discriminator(&descriptor)?;
    Ok(AdmittedDirectShare {
        path: canonical,
        identity,
        discriminator,
        descriptor,
    })
}

/// Reopen a durable direct-share path and require its exact admitted identity.
pub(crate) fn reopen_direct_share(
    path: &Path,
    expected: &DirectShareIdentity,
    forbidden_roots: &[PathBuf],
) -> Result<AdmittedDirectShare, DirectShareError> {
    let admitted = admit_direct_share(path, forbidden_roots)?;
    if admitted.identity != *expected {
        return Err(DirectShareError::SourceChanged(path.to_owned()));
    }
    Ok(admitted)
}

#[cfg(target_os = "linux")]
fn open_exact_directory(path: &Path) -> Result<OwnedFd, DirectShareError> {
    openat2(
        rustix::fs::CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|source| DirectShareError::Open {
        path: path.to_owned(),
        source,
    })
}

#[cfg(target_os = "linux")]
fn descriptor_path(descriptor: &OwnedFd) -> Result<PathBuf, DirectShareError> {
    let link = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
    let path =
        fs::read_link(&link).map_err(|source| DirectShareError::Io { path: link, source })?;
    if path
        .as_os_str()
        .as_bytes()
        .strip_suffix(b" (deleted)")
        .is_some()
    {
        return Err(DirectShareError::SourceChanged(path));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn capture_identity(descriptor: &OwnedFd) -> Result<DirectShareIdentity, DirectShareError> {
    let required = StatxFlags::TYPE | StatxFlags::UID | StatxFlags::INO | StatxFlags::MNT_ID;
    let metadata = statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        required,
    )
    .map_err(DirectShareError::Inspect)?;
    if !StatxFlags::from_bits_retain(metadata.stx_mask).contains(required)
        || u32::from(metadata.stx_mode) & libc::S_IFMT != libc::S_IFDIR
        || metadata.stx_ino == 0
        || metadata.stx_mnt_id == 0
    {
        return Err(DirectShareError::InvalidDirectory);
    }
    let filesystem = rustix::fs::fstatfs(descriptor).map_err(DirectShareError::Inspect)?;
    Ok(DirectShareIdentity::from_captured_parts(
        metadata.stx_dev_major,
        metadata.stx_dev_minor,
        metadata.stx_ino,
        metadata.stx_mnt_id,
        metadata.stx_uid,
        filesystem.f_type as i64,
    ))
}

/// The held directory's file handle (`name_to_handle_at` with
/// `AT_EMPTY_PATH`), which embeds its inode generation. It needs no
/// privilege and survives a reboot. A filesystem without handles
/// (`EOPNOTSUPP`, as overlay answers) or a kernel without the call
/// (`ENOSYS`) reads as unsupported and keeps the identity comparison; any
/// other failure fails admission rather than weakening the record.
#[cfg(target_os = "linux")]
fn capture_discriminator(
    descriptor: &OwnedFd,
) -> Result<DirectShareDiscriminator, DirectShareError> {
    use crate::supervisor_metadata::direct_share::MAXIMUM_FILE_HANDLE_BYTES;

    #[repr(C)]
    struct FileHandle {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        f_handle: [u8; MAXIMUM_FILE_HANDLE_BYTES],
    }

    let mut handle = FileHandle {
        handle_bytes: MAXIMUM_FILE_HANDLE_BYTES as libc::c_uint,
        handle_type: 0,
        f_handle: [0; MAXIMUM_FILE_HANDLE_BYTES],
    };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: the descriptor is live, the path is an empty C string used
    // with AT_EMPTY_PATH, and `handle` is a `struct file_handle` header
    // followed by MAX_HANDLE_SZ bytes, the size `handle_bytes` announces.
    let result = unsafe {
        libc::name_to_handle_at(
            descriptor.as_raw_fd(),
            c"".as_ptr(),
            (&raw mut handle).cast::<libc::file_handle>(),
            &raw mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if result != 0 {
        let error = rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
            .unwrap_or(rustix::io::Errno::IO);
        return if error == rustix::io::Errno::OPNOTSUPP || error == rustix::io::Errno::NOSYS {
            Ok(DirectShareDiscriminator::Unsupported)
        } else {
            Err(DirectShareError::Inspect(error))
        };
    }
    usize::try_from(handle.handle_bytes)
        .ok()
        .and_then(|length| handle.f_handle.get(..length))
        .and_then(|bytes| DirectShareDiscriminator::handle(handle.handle_type, bytes))
        .ok_or(DirectShareError::Inspect(rustix::io::Errno::OVERFLOW))
}

/// Darwin has no file handles; APFS allocates file IDs from a per-volume
/// counter, so its identity comparison stands alone.
#[cfg(target_os = "macos")]
fn capture_discriminator(
    _descriptor: &OwnedFd,
) -> Result<DirectShareDiscriminator, DirectShareError> {
    Ok(DirectShareDiscriminator::Unsupported)
}

/// Open the directory itself. `O_NOFOLLOW_ANY` refuses a symlink in any
/// component, not only the last, so a replaced parent cannot redirect it.
#[cfg(target_os = "macos")]
fn open_exact_directory(path: &Path) -> Result<OwnedFd, DirectShareError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(path)
        .map(OwnedFd::from)
        .map_err(|error| DirectShareError::Open {
            path: path.to_owned(),
            source: darwin_errno(&error),
        })
}

/// The kernel's current path for the opened directory (`F_GETPATH`).
#[cfg(target_os = "macos")]
fn descriptor_path(descriptor: &OwnedFd) -> Result<PathBuf, DirectShareError> {
    let mut buffer = [0_u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most MAXPATHLEN
    // (PATH_MAX) bytes into the supplied buffer of exactly that size.
    if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
        return Err(DirectShareError::Inspect(darwin_errno(
            &std::io::Error::last_os_error(),
        )));
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DirectShareError::InvalidDirectory)?;
    Ok(PathBuf::from(OsString::from_vec(buffer[..end].to_vec())))
}

#[cfg(target_os = "macos")]
fn capture_identity(descriptor: &OwnedFd) -> Result<DirectShareIdentity, DirectShareError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is live and the buffer has libc's stat layout.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(DirectShareError::Inspect(darwin_errno(
            &std::io::Error::last_os_error(),
        )));
    }
    // SAFETY: a successful fstat initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR || metadata.st_ino == 0 {
        return Err(DirectShareError::InvalidDirectory);
    }
    let filesystem = darwin_statfs(descriptor)?;
    let device = metadata.st_dev as u32;
    Ok(DirectShareIdentity::from_captured_parts(
        device >> 24,
        device & 0x00ff_ffff,
        metadata.st_ino,
        darwin_mount_id(&filesystem),
        metadata.st_uid,
        darwin_filesystem_magic(&filesystem),
    ))
}

#[cfg(target_os = "macos")]
fn darwin_statfs(descriptor: &OwnedFd) -> Result<libc::statfs, DirectShareError> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the descriptor is live and the buffer has libc's statfs layout.
    if unsafe { libc::fstatfs(descriptor.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(DirectShareError::Inspect(darwin_errno(
            &std::io::Error::last_os_error(),
        )));
    }
    // SAFETY: a successful fstatfs initialized the complete structure.
    Ok(unsafe { filesystem.assume_init() })
}

/// Darwin has no mount ID; the mounted filesystem's `f_fsid` stands in for it.
#[cfg(target_os = "macos")]
fn darwin_mount_id(filesystem: &libc::statfs) -> u64 {
    // SAFETY: fsid_t is repr(C), exactly two int32 values without padding.
    let [high, low] = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(filesystem.f_fsid) };
    (u64::from(high as u32) << 32) | u64::from(low as u32)
}

/// Only APFS is admitted; every other filesystem reports no magic.
#[cfg(target_os = "macos")]
fn darwin_filesystem_magic(filesystem: &libc::statfs) -> i64 {
    if c_chars_to_bytes(&filesystem.f_fstypename) == Some(b"apfs".as_slice()) {
        crate::supervisor_metadata::direct_share::APFS_VOLUME_MAGIC
    } else {
        0
    }
}

#[cfg(target_os = "macos")]
fn c_chars_to_bytes(value: &[libc::c_char]) -> Option<&[u8]> {
    let end = value.iter().position(|byte| *byte == 0)?;
    // SAFETY: c_char and u8 have the same size and alignment.
    Some(unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), end) })
}

#[cfg(target_os = "macos")]
fn darwin_errno(error: &std::io::Error) -> rustix::io::Errno {
    rustix::io::Errno::from_io_error(error).unwrap_or(rustix::io::Errno::IO)
}

fn validate_normal_absolute_path(path: &Path) -> Result<(), DirectShareError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAXIMUM_HOST_PATH_BYTES
        || bytes.contains(&0)
        || path == Path::new("/")
    {
        return Err(DirectShareError::InvalidPath(path.to_owned()));
    }
    for component in path.components().skip(1) {
        if !matches!(component, Component::Normal(_)) {
            return Err(DirectShareError::InvalidPath(path.to_owned()));
        }
    }
    Ok(())
}

/// Roots that are never shared themselves; directories beneath them may be.
#[cfg(target_os = "linux")]
const BROAD_ROOTS: &[&str] = &[
    "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/tmp", "/usr", "/var",
];
/// Trees that are never shared at any depth.
#[cfg(target_os = "linux")]
const FORBIDDEN_TREES: &[&str] = &["/dev", "/proc", "/run", "/sys"];
#[cfg(target_os = "macos")]
const BROAD_ROOTS: &[&str] = &[
    "/Applications",
    "/Library",
    "/System",
    "/Users",
    "/Volumes",
    "/bin",
    "/cores",
    "/dev",
    "/etc",
    "/opt",
    "/private",
    "/private/etc",
    "/private/tmp",
    "/private/var",
    "/sbin",
    "/tmp",
    "/usr",
    "/var",
];
/// `/System` also holds the firmlinked alias of every user directory.
#[cfg(target_os = "macos")]
const FORBIDDEN_TREES: &[&str] = &["/System", "/dev", "/private/etc", "/private/var/db"];
/// Credential stores beneath the user's home directory.
const HOME_CREDENTIAL_STORES: &[&str] = &[
    ".aws",
    ".claude",
    ".codex",
    ".config/gh",
    ".config/gcloud",
    ".docker",
    ".gnupg",
    ".kube",
    ".local/share/keyrings",
    ".ssh",
    ".switch",
];
#[cfg(target_os = "linux")]
const PLATFORM_HOME_CREDENTIAL_STORES: &[&str] = &[];
#[cfg(target_os = "macos")]
const PLATFORM_HOME_CREDENTIAL_STORES: &[&str] = &["Library/Keychains"];

/// Why a host directory may never become a workspace source (mounted, copied
/// or cloned), or `None` when the share policy admits it. This is the same
/// policy that admits explicit direct shares, phrased for the person creating
/// the environment. `path` must already be canonical.
pub fn workspace_source_refusal(path: &Path) -> Option<&'static str> {
    if path == Path::new("/") || BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return Some("it is a system or shared top-level directory");
    }
    if FORBIDDEN_TREES.iter().any(|root| path.starts_with(root)) {
        return Some("it is inside a protected system directory");
    }
    let Ok(home) = current_home_directory() else {
        return Some("your home directory could not be determined");
    };
    if path == home {
        return Some("it is your home directory");
    }
    if home.starts_with(path) {
        return Some("it contains your home directory");
    }
    if HOME_CREDENTIAL_STORES
        .iter()
        .chain(PLATFORM_HOME_CREDENTIAL_STORES)
        .any(|relative| paths_overlap(path, &home.join(relative)))
    {
        return Some("it is or contains a credential store (such as ~/.ssh)");
    }
    None
}

fn validate_source_policy(
    path: &Path,
    forbidden_roots: &[PathBuf],
) -> Result<(), DirectShareError> {
    if BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return Err(DirectShareError::ForbiddenSource(path.to_owned()));
    }
    if FORBIDDEN_TREES.iter().any(|root| path.starts_with(root)) {
        return Err(DirectShareError::ForbiddenSource(path.to_owned()));
    }
    for root in forbidden_roots {
        if paths_overlap(path, root) {
            return Err(DirectShareError::ForbiddenSource(path.to_owned()));
        }
    }
    let home = current_home_directory()?;
    if path == home {
        return Err(DirectShareError::ForbiddenSource(path.to_owned()));
    }
    for relative in HOME_CREDENTIAL_STORES
        .iter()
        .chain(PLATFORM_HOME_CREDENTIAL_STORES)
    {
        if paths_overlap(path, &home.join(relative)) {
            return Err(DirectShareError::ForbiddenSource(path.to_owned()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_home_directory() -> Result<PathBuf, DirectShareError> {
    let passwd = fs::read_to_string("/etc/passwd").map_err(|source| DirectShareError::Io {
        path: PathBuf::from("/etc/passwd"),
        source,
    })?;
    let uid = current_uid().to_string();
    for line in passwd.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() == 7 && fields[2] == uid {
            let home = PathBuf::from(fields[5]);
            validate_normal_absolute_path(&home)?;
            return Ok(home);
        }
    }
    Err(DirectShareError::MissingHomeDirectory)
}

/// The account's home directory from Directory Services, never `$HOME`.
/// It is canonicalized because a home beneath `/var` lives in `/private/var`.
#[cfg(target_os = "macos")]
fn current_home_directory() -> Result<PathBuf, DirectShareError> {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live buffer of the stated size; the
    // returned strings point into `buffer`, which outlives their use below.
    let status = unsafe {
        libc::getpwuid_r(
            current_uid(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(DirectShareError::MissingHomeDirectory);
    }
    // SAFETY: a successful lookup set `result` to `entry` with a NUL-terminated
    // pw_dir inside `buffer`.
    let directory = unsafe { std::ffi::CStr::from_ptr((*result).pw_dir) };
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(directory.to_bytes()));
    validate_normal_absolute_path(&home)?;
    Ok(fs::canonicalize(&home).unwrap_or(home))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[cfg(target_os = "linux")]
fn reject_mount_alias_or_submounts(
    path: &Path,
    source_mount_id: u64,
) -> Result<(), DirectShareError> {
    let mountinfo = fs::read("/proc/self/mountinfo").map_err(|source| DirectShareError::Io {
        path: PathBuf::from("/proc/self/mountinfo"),
        source,
    })?;
    reject_mount_alias_or_submounts_from(path, source_mount_id, &mountinfo)
}

#[cfg(target_os = "linux")]
fn reject_mount_alias_or_submounts_from(
    path: &Path,
    source_mount_id: u64,
    mountinfo: &[u8],
) -> Result<(), DirectShareError> {
    for line in mountinfo.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
        if fields.len() < 6 {
            return Err(DirectShareError::InvalidMountTable);
        }
        let mount_id = parse_u64(fields[0]).ok_or(DirectShareError::InvalidMountTable)?;
        let mountpoint = PathBuf::from(OsString::from_vec(unescape_mount_field(fields[4])?));
        if mountpoint == path && mount_id == source_mount_id {
            return Err(DirectShareError::MountAlias(path.to_owned()));
        }
        if mountpoint != path && mountpoint.starts_with(path) {
            return Err(DirectShareError::NestedMount(mountpoint));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.parse().ok()
}

#[cfg(target_os = "linux")]
fn unescape_mount_field(field: &[u8]) -> Result<Vec<u8>, DirectShareError> {
    let mut output = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            output.push(field[index]);
            index += 1;
            continue;
        }
        let escaped = field
            .get(index + 1..index + 4)
            .ok_or(DirectShareError::InvalidMountTable)?;
        if !escaped.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(DirectShareError::InvalidMountTable);
        }
        let value = (escaped[0] - b'0') * 64 + (escaped[1] - b'0') * 8 + escaped[2] - b'0';
        if value == 0 {
            return Err(DirectShareError::InvalidMountTable);
        }
        output.push(value);
        index += 4;
    }
    Ok(output)
}

/// Refuse a share that is itself a mount root, or that has a filesystem
/// mounted beneath it, as Linux does from its mount table.
#[cfg(target_os = "macos")]
fn reject_mount_alias_or_submounts(
    path: &Path,
    source_mount_id: u64,
) -> Result<(), DirectShareError> {
    reject_mount_alias_or_submounts_in(path, source_mount_id, &darwin_mounts()?)
}

#[cfg(target_os = "macos")]
fn reject_mount_alias_or_submounts_in(
    path: &Path,
    source_mount_id: u64,
    mounts: &[(PathBuf, u64)],
) -> Result<(), DirectShareError> {
    for (mountpoint, mount_id) in mounts {
        if mountpoint == path && *mount_id == source_mount_id {
            return Err(DirectShareError::MountAlias(path.to_owned()));
        }
        if mountpoint != path && mountpoint.starts_with(path) {
            return Err(DirectShareError::NestedMount(mountpoint.clone()));
        }
    }
    Ok(())
}

/// Every mounted filesystem's mount point and `f_fsid`.
#[cfg(target_os = "macos")]
fn darwin_mounts() -> Result<Vec<(PathBuf, u64)>, DirectShareError> {
    // The table can grow between the count and the copy; retry a bounded
    // number of times rather than trusting a possibly truncated copy.
    for _ in 0..4 {
        // SAFETY: a null buffer asks only for the current count.
        let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        let count = usize::try_from(count).map_err(|_| DirectShareError::InvalidMountTable)?;
        let capacity = count + 8;
        let bytes = libc::c_int::try_from(capacity * std::mem::size_of::<libc::statfs>())
            .map_err(|_| DirectShareError::InvalidMountTable)?;
        let mut table = Vec::<libc::statfs>::with_capacity(capacity);
        // SAFETY: the buffer holds `capacity` statfs entries, which is `bytes`.
        let filled = unsafe { libc::getfsstat(table.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
        let filled = usize::try_from(filled).map_err(|_| DirectShareError::InvalidMountTable)?;
        if filled >= capacity {
            continue;
        }
        // SAFETY: getfsstat initialized exactly `filled` leading entries.
        unsafe { table.set_len(filled) };
        return table
            .iter()
            .map(|filesystem| {
                let mountpoint = c_chars_to_bytes(&filesystem.f_mntonname)
                    .filter(|bytes| bytes.first() == Some(&b'/'))
                    .ok_or(DirectShareError::InvalidMountTable)?;
                Ok((
                    PathBuf::from(OsString::from_vec(mountpoint.to_vec())),
                    darwin_mount_id(filesystem),
                ))
            })
            .collect();
    }
    Err(DirectShareError::InvalidMountTable)
}

/// Remove the directory at `path` and create it again until it takes
/// `inode`'s number, as ext4 and overlay over it do, for a bounded number of
/// tries. Whether it did is the result; tmpfs and btrfs never do.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn recreate_directory_reusing_inode(path: &Path, inode: u64) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    for _ in 0..64 {
        fs::remove_dir(path).unwrap();
        fs::create_dir(path).unwrap();
        if fs::symlink_metadata(path).unwrap().ino() == inode {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor_metadata::direct_share::{
        DirectShareDiscriminators, direct_share_identity_sha256,
    };
    use std::os::unix::fs::symlink;

    #[cfg(target_os = "linux")]
    const OVERLAYFS_MAGIC: i64 = 0x794c_7630;

    #[test]
    fn owned_local_directory_is_bound_and_reopened() {
        let source = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(source.path()).unwrap();
        let admitted = admit_direct_share(&canonical, &[]).unwrap();
        assert_eq!(admitted.path(), canonical);
        assert!(admitted.descriptor().as_raw_fd() >= 0);
        let reopened = reopen_direct_share(&canonical, admitted.identity(), &[]).unwrap();
        assert_eq!(reopened.identity(), admitted.identity());
    }

    #[test]
    fn symlink_spelling_and_replacement_are_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let original = parent.path().join("original");
        let replacement = parent.path().join("replacement");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&replacement).unwrap();
        let link = parent.path().join("link");
        symlink(&original, &link).unwrap();
        assert!(matches!(
            admit_direct_share(&link, &[]),
            Err(DirectShareError::NonCanonical(_))
        ));

        let admitted = admit_direct_share(&original, &[]).unwrap();
        let parked = parent.path().join("parked");
        fs::rename(&original, &parked).unwrap();
        fs::rename(&replacement, &original).unwrap();
        assert!(matches!(
            reopen_direct_share(&original, admitted.identity(), &[]),
            Err(DirectShareError::SourceChanged(_))
        ));
    }

    #[test]
    fn forbidden_roots_are_rejected_in_both_directions() {
        let source = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(source.path()).unwrap();
        assert!(matches!(
            admit_direct_share(&canonical, &[canonical.join("private")]),
            Err(DirectShareError::ForbiddenSource(_))
        ));
        assert!(matches!(
            admit_direct_share(&canonical, std::slice::from_ref(&canonical)),
            Err(DirectShareError::ForbiddenSource(_))
        ));
    }

    #[test]
    fn a_recorded_handle_must_read_back_equal_and_an_unsupported_one_keeps_the_identity() {
        let handle = |byte: u8| DirectShareDiscriminator::Handle {
            handle_type: 1,
            handle: format!("{byte:02x}"),
        };
        let unsupported = DirectShareDiscriminator::Unsupported;
        let admit = DirectShareDiscriminator::admit;
        // Nothing recorded: accepted once, recording what was read.
        assert_eq!(admit(None, &handle(1)), Some(handle(1)));
        assert_eq!(admit(None, &unsupported), Some(unsupported.clone()));
        // Recorded without a handle: the identity alone decided, and a
        // handle is recorded once one can be read.
        assert_eq!(
            admit(Some(&unsupported), &unsupported),
            Some(unsupported.clone())
        );
        assert_eq!(admit(Some(&unsupported), &handle(1)), Some(handle(1)));
        // Recorded with a handle: only that handle, read again, is accepted.
        assert_eq!(admit(Some(&handle(1)), &handle(1)), Some(handle(1)));
        assert_eq!(admit(Some(&handle(1)), &handle(2)), None);
        assert_eq!(admit(Some(&handle(1)), &unsupported), None);
    }

    #[test]
    fn discriminator_rows_round_trip_and_bind_the_whole_plan_entry() {
        let identity = DirectShareIdentity::from_captured_parts(8, 1, 42, 7, 1000, 0xef53);
        let digest = direct_share_identity_sha256(b"/work/project", &identity);
        let mut recorded = DirectShareDiscriminators::default();
        recorded.insert(
            digest.clone(),
            DirectShareDiscriminator::Handle {
                handle_type: 1,
                handle: "2a000000efbeadde".to_owned(),
            },
        );
        recorded.insert("0".repeat(64), DirectShareDiscriminator::Unsupported);
        assert_eq!(
            DirectShareDiscriminators::decode(&recorded.encode()),
            recorded
        );

        // Another path or any other identity field names another entry.
        assert_ne!(
            direct_share_identity_sha256(b"/work/other", &identity),
            digest
        );
        for changed in [
            DirectShareIdentity::from_captured_parts(9, 1, 42, 7, 1000, 0xef53),
            DirectShareIdentity::from_captured_parts(8, 2, 42, 7, 1000, 0xef53),
            DirectShareIdentity::from_captured_parts(8, 1, 43, 7, 1000, 0xef53),
            DirectShareIdentity::from_captured_parts(8, 1, 42, 8, 1000, 0xef53),
            DirectShareIdentity::from_captured_parts(8, 1, 42, 7, 1001, 0xef53),
            DirectShareIdentity::from_captured_parts(8, 1, 42, 7, 1000, 0x9123_683e),
        ] {
            assert_ne!(
                direct_share_identity_sha256(b"/work/project", &changed),
                digest
            );
        }

        // A malformed row reads as nothing recorded, as before #3209.
        for malformed in [
            "",
            "{}",
            "[{\"identity_sha256\":\"00\",\"discriminator\":\"unsupported\"}]",
            &format!(
                "[{{\"identity_sha256\":\"{}\",\"discriminator\":{{\"handle\":{{\"handle_type\":1,\"handle\":\"XYZ\"}}}}}}]",
                "0".repeat(64)
            ),
            &format!(
                "[{{\"identity_sha256\":\"{}\",\"discriminator\":\"unsupported\",\"extra\":1}}]",
                "0".repeat(64)
            ),
        ] {
            assert!(DirectShareDiscriminators::decode(malformed).is_empty());
        }
    }

    /// The filesystem decides whether a share has a handle: overlay has
    /// none, and every other admitted Linux filesystem does.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_share_records_its_file_handle_except_on_overlay() {
        let source = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(source.path()).unwrap();
        let admitted = admit_direct_share(&canonical, &[]).unwrap();
        let overlay = admitted.identity().filesystem_magic() == OVERLAYFS_MAGIC;
        assert_eq!(
            matches!(
                admitted.discriminator(),
                DirectShareDiscriminator::Unsupported
            ),
            overlay
        );
        // The same directory reads back the same discriminator.
        let reopened = reopen_direct_share(&canonical, admitted.identity(), &[]).unwrap();
        assert_eq!(reopened.discriminator(), admitted.discriminator());
    }

    /// #3209: on a filesystem that reuses inode numbers, a directory removed
    /// while nothing holds it and created again at its path passes the
    /// identity comparison; its file handle tells it apart. TMPDIR on ext4
    /// exercises the reuse; elsewhere the test stops once none happens.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_directory_recreated_with_the_same_inode_number_has_another_handle() {
        let parent = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(parent.path()).unwrap().join("share");
        fs::create_dir(&path).unwrap();
        let admitted = admit_direct_share(&path, &[]).unwrap();
        let identity = admitted.identity().clone();
        let recorded = admitted.discriminator().clone();
        // A stopped VM holds nothing.
        drop(admitted);
        if !recreate_directory_reusing_inode(&path, identity.inode()) {
            eprintln!("TMPDIR's filesystem did not reuse the inode number; nothing to tell apart");
            return;
        }

        let replacement = reopen_direct_share(&path, &identity, &[])
            .expect("a reused inode number passes the identity comparison");
        let admitted_again =
            DirectShareDiscriminator::admit(Some(&recorded), replacement.discriminator());
        if recorded == DirectShareDiscriminator::Unsupported {
            // Overlay over ext4: no handle, the documented limit.
            assert_eq!(identity.filesystem_magic(), OVERLAYFS_MAGIC);
            assert!(admitted_again.is_some());
        } else {
            assert_ne!(replacement.discriminator(), &recorded);
            assert_eq!(admitted_again, None);
        }
    }

    /// #3209 overlay fallback: overlay gives no file handle, so a share there
    /// records none and keeps the identity comparison, and copying the
    /// directory up between boots, as any write in it does, keeps that
    /// identity. Run it against a directory only an overlay's lower layer
    /// holds, owned by the test's user.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs CODEWIRE_TEST_OVERLAY_SHARE, a directory present only in an overlay's lower layer"]
    fn a_share_copied_up_on_overlay_between_boots_is_not_refused() {
        let path = PathBuf::from(
            std::env::var_os("CODEWIRE_TEST_OVERLAY_SHARE")
                .expect("CODEWIRE_TEST_OVERLAY_SHARE names the lower-layer directory"),
        );
        let admitted = admit_direct_share(&path, &[]).unwrap();
        assert_eq!(admitted.identity().filesystem_magic(), OVERLAYFS_MAGIC);
        assert_eq!(
            admitted.discriminator(),
            &DirectShareDiscriminator::Unsupported
        );
        let identity = admitted.identity().clone();
        let recorded = admitted.discriminator().clone();
        drop(admitted);

        fs::write(path.join("copied-up"), b"").unwrap();

        let reopened = reopen_direct_share(&path, &identity, &[]).unwrap();
        assert_eq!(
            DirectShareDiscriminator::admit(Some(&recorded), reopened.discriminator()),
            Some(DirectShareDiscriminator::Unsupported)
        );
    }

    /// While a share is held, as the supervisor holds its checked shares
    /// until the runner's StartVm returns, a directory created at its path
    /// cannot take its inode number, so the runner's (device, inode) reopen
    /// refuses it even on ext4.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_held_share_keeps_its_inode_number_from_a_recreated_directory() {
        let parent = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(parent.path()).unwrap().join("share");
        fs::create_dir(&path).unwrap();
        let held = admit_direct_share(&path, &[]).unwrap();

        assert!(!recreate_directory_reusing_inode(
            &path,
            held.identity().inode()
        ));
        assert!(matches!(
            reopen_direct_share(&path, held.identity(), &[]),
            Err(DirectShareError::SourceChanged(_))
        ));
        drop(held);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_and_runtime_pseudo_filesystem_trees_are_always_forbidden() {
        for path in ["/dev/shm", "/proc/self", "/run/user", "/sys/kernel"] {
            assert!(matches!(
                validate_source_policy(Path::new(path), &[]),
                Err(DirectShareError::ForbiddenSource(rejected)) if rejected == Path::new(path)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_table_parser_rejects_aliases_nested_mounts_and_bad_escapes() {
        let path = Path::new("/home/user/project");
        assert!(matches!(
            reject_mount_alias_or_submounts_from(
                path,
                42,
                b"42 1 8:1 / /home/user/project rw - ext4 /dev/x rw\n"
            ),
            Err(DirectShareError::MountAlias(_))
        ));
        assert!(matches!(
            reject_mount_alias_or_submounts_from(
                path,
                10,
                b"10 1 8:1 / /home rw - ext4 /dev/x rw\n11 10 8:2 / /home/user/project/vendor rw - ext4 /dev/y rw\n"
            ),
            Err(DirectShareError::NestedMount(_))
        ));
        assert!(reject_mount_alias_or_submounts_from(
            Path::new("/home/user/project with space"),
            10,
            b"10 1 8:1 / /home rw - ext4 /dev/x rw\n11 10 8:2 / /other\\040path rw - ext4 /dev/y rw\n"
        )
        .is_ok());
        assert!(matches!(
            unescape_mount_field(b"/bad\\09x"),
            Err(DirectShareError::InvalidMountTable)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_system_trees_broad_roots_and_credential_stores_are_forbidden() {
        for path in [
            "/System/Volumes/Data/Users",
            "/dev/fd",
            "/private/etc/ssh",
            "/private/var/db/dslocal",
            "/Users",
            "/Volumes",
            "/private/tmp",
            "/private/var",
        ] {
            assert!(
                matches!(
                    validate_source_policy(Path::new(path), &[]),
                    Err(DirectShareError::ForbiddenSource(rejected)) if rejected == Path::new(path)
                ),
                "{path} must be forbidden"
            );
        }
        let home = current_home_directory().unwrap();
        for relative in ["", ".ssh/keys", "Library/Keychains", "Library"] {
            let path = if relative.is_empty() {
                home.clone()
            } else {
                home.join(relative)
            };
            assert!(
                matches!(
                    validate_source_policy(&path, &[]),
                    Err(DirectShareError::ForbiddenSource(_))
                ),
                "{} must be forbidden",
                path.display()
            );
        }
        validate_source_policy(Path::new("/private/tmp/project"), &[]).unwrap();
        validate_source_policy(&home.join("src/project"), &[]).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_open_refuses_a_symlink_in_any_component() {
        let parent = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(parent.path()).unwrap();
        fs::create_dir_all(parent.join("real/child")).unwrap();
        symlink(parent.join("real"), parent.join("link")).unwrap();
        assert!(open_exact_directory(&parent.join("real/child")).is_ok());
        for path in [parent.join("link"), parent.join("link/child")] {
            assert!(matches!(
                open_exact_directory(&path),
                Err(DirectShareError::Open { .. })
            ));
        }
        assert!(matches!(
            admit_direct_share(&parent.join("link/child"), &[]),
            Err(DirectShareError::NonCanonical(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_identity_binds_apfs_and_refuses_other_filesystems() {
        let source = tempfile::tempdir().unwrap();
        let canonical = fs::canonicalize(source.path()).unwrap();
        let admitted = admit_direct_share(&canonical, &[]).unwrap();
        let identity = admitted.identity();
        assert_eq!(
            identity.filesystem_magic(),
            crate::supervisor_metadata::direct_share::APFS_VOLUME_MAGIC
        );
        assert_ne!(identity.mount_id(), 0);
        assert_eq!(identity.owner_uid(), current_uid());
        assert_eq!(descriptor_path(admitted.descriptor()).unwrap(), canonical);

        // devfs is not APFS, so its identity can never be admitted.
        let devfs = open_exact_directory(Path::new("/dev")).unwrap();
        let identity = capture_identity(&devfs).unwrap();
        assert!(!allowed_filesystem(identity.filesystem_magic()));
        assert!(identity.validate().is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_mount_check_refuses_mount_roots_and_nested_mounts() {
        let path = Path::new("/Users/someone/project");
        let mounts = |entries: &[(&str, u64)]| {
            entries
                .iter()
                .map(|(path, id)| (PathBuf::from(path), *id))
                .collect::<Vec<_>>()
        };
        assert!(
            reject_mount_alias_or_submounts_in(
                path,
                7,
                &mounts(&[("/", 1), ("/System/Volumes/Data", 7)])
            )
            .is_ok()
        );
        assert!(matches!(
            reject_mount_alias_or_submounts_in(path, 9, &mounts(&[("/Users/someone/project", 9)])),
            Err(DirectShareError::MountAlias(_))
        ));
        assert!(matches!(
            reject_mount_alias_or_submounts_in(
                path,
                7,
                &mounts(&[("/Users/someone/project/disk", 11)])
            ),
            Err(DirectShareError::NestedMount(mounted)) if mounted == Path::new("/Users/someone/project/disk")
        ));
        assert!(
            reject_mount_alias_or_submounts_in(
                path,
                7,
                &mounts(&[("/Users/someone/project-other", 11)])
            )
            .is_ok()
        );
        // The live table always has a root filesystem.
        assert!(
            darwin_mounts()
                .unwrap()
                .iter()
                .any(|(mountpoint, _)| mountpoint == Path::new("/"))
        );
    }
}
