//! Admission and launch-time revalidation for explicit host directory shares.
//!
//! Direct shares are intentionally path-addressed in private durable state so
//! an offline restart can find them again, but the path never crosses the
//! host-only runner boundary.  The persisted identity binds the directory,
//! filesystem, and mount instance; every launch reopens the path without
//! following symlinks and refuses replacement or mount-topology changes.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Component, Path, PathBuf};

use codewire_vmm_guest_probe::DirectShareMount;
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, StatxFlags, openat2, statx};

use crate::linux::path::current_uid;
use crate::supervisor_metadata::direct_share::allowed_filesystem;
pub(crate) use crate::supervisor_metadata::direct_share::{DirectShareError, DirectShareIdentity};

const MAXIMUM_HOST_PATH_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct AdmittedDirectShare {
    path: PathBuf,
    identity: DirectShareIdentity,
    descriptor: OwnedFd,
}

impl AdmittedDirectShare {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &DirectShareIdentity {
        &self.identity
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
    Ok(AdmittedDirectShare {
        path: canonical,
        identity,
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

fn validate_source_policy(
    path: &Path,
    forbidden_roots: &[PathBuf],
) -> Result<(), DirectShareError> {
    const BROAD_ROOTS: &[&str] = &[
        "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/tmp", "/usr", "/var",
    ];
    if BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return Err(DirectShareError::ForbiddenSource(path.to_owned()));
    }
    if ["/dev", "/proc", "/run", "/sys"]
        .iter()
        .any(|root| path.starts_with(root))
    {
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
    for relative in [
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
    ] {
        if paths_overlap(path, &home.join(relative)) {
            return Err(DirectShareError::ForbiddenSource(path.to_owned()));
        }
    }
    Ok(())
}

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

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

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

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.parse().ok()
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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
    fn kernel_and_runtime_pseudo_filesystem_trees_are_always_forbidden() {
        for path in ["/dev/shm", "/proc/self", "/run/user", "/sys/kernel"] {
            assert!(matches!(
                validate_source_policy(Path::new(path), &[]),
                Err(DirectShareError::ForbiddenSource(rejected)) if rejected == Path::new(path)
            ));
        }
    }

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
}
