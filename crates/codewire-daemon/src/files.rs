use std::fs;
#[cfg(not(target_os = "linux"))]
use std::fs::{File, OpenOptions};
#[cfg(not(target_os = "linux"))]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(not(target_os = "linux"))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_daemon_proto::daemon::v1;
#[cfg(not(target_os = "linux"))]
use filetime::FileTime;
use prost_types::Timestamp;

use crate::config::{Config, clean_path};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    declared_mounts, list, mkdir, open_file, read, readlink, remove, rename, set_stat, stat, write,
};

const GO_MODE_DIR: u32 = 1 << 31;
const GO_MODE_SYMLINK: u32 = 1 << 27;
const GO_MODE_DEVICE: u32 = 1 << 26;
const GO_MODE_NAMED_PIPE: u32 = 1 << 25;
const GO_MODE_SOCKET: u32 = 1 << 24;
const GO_MODE_CHAR_DEVICE: u32 = 1 << 21;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("path must stay under /workspace or /home/codewire")]
    PathOutsideWorkspace,
    #[error("configured workspace root is not a stable canonical directory")]
    UntrustedRoot,
    #[error("the live mount here is not mounted or has moved; restart the environment")]
    MountUnavailable,
    #[error("path traversal through a symlink, magic link, or nested mount is denied")]
    TraversalDenied,
    #[error("operation requires a path below the workspace root")]
    InvalidPath,
    #[error("path is not a regular file")]
    NotRegularFile,
    #[error("path is not a symbolic link")]
    NotSymlink,
    #[error("invalid offset")]
    InvalidOffset,
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid size")]
    InvalidSize,
    #[error("path is a directory")]
    IsDirectory,
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FileError>;

/// Run one file operation as the workload user (#3025). A local VM's guest
/// daemon runs as root while its workload runs as an unprivileged user; file
/// operations must create files that user owns and check access as theirs.
/// `setfsuid`/`setfsgid` change only the calling thread's filesystem identity,
/// and every file operation is synchronous, so nothing else runs on the thread
/// before the guard restores it. Every other placement already runs as the
/// workload user and calls `operation` unchanged.
pub fn as_workload_user<T>(config: &Config, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(target_os = "linux")]
    if let crate::execution::ProcessExecution::Runc(execution) = &config.process_execution
        && execution.uid != 0
    {
        let _identity = linux::FilesystemIdentity::switch(execution.uid, execution.gid)?;
        return operation();
    }
    let _ = config;
    operation()
}

pub fn resolve_workspace_path(config: &Config, raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    let raw_path = if trimmed.is_empty() {
        config.workspace_root.clone()
    } else {
        PathBuf::from(trimmed)
    };
    let cleaned = if raw_path.is_absolute() {
        clean_path(&raw_path)
    } else {
        clean_path(&config.workspace_root.join(raw_path))
    };

    if is_allowed_workspace_path(config, &cleaned) {
        Ok(cleaned)
    } else {
        Err(FileError::PathOutsideWorkspace)
    }
}

/// Refuse a path below the workspace or home root that passes through a
/// symlink, for daemon file RPCs on non-Linux platforms (#2505 L4).
///
/// [`resolve_workspace_path`] is lexical, so `workspace/link/file` passes even
/// when `link` points outside. Linux confines every operation with `openat2`
/// (`RESOLVE_BENEATH | NO_MAGICLINKS | NO_XDEV`, see `files/linux.rs`). Without
/// it this check refuses a symlink at any component below the configured root,
/// probing with lstat. The root itself is configuration and may sit under a
/// symlink, such as macOS `/var` or `/tmp`. Callers that only name an entry
/// (`stat` without follow, `readlink`) may name a symlink leaf but never pass
/// through one.
///
/// This stops a link that is already in place. It is check-then-use, so a
/// process that swaps a directory for a link between the check and the
/// operation can still redirect it. Non-Linux daemons serve development and
/// host builds only; Sandbox guests run Linux.
///
/// Compiled under `test` on every platform so Linux CI runs its tests.
#[cfg(any(test, not(target_os = "linux")))]
pub(crate) fn reject_symlinked_components(
    root: &Path,
    path: &Path,
    allow_leaf_symlink: bool,
    is_symlink: impl Fn(&Path) -> bool,
) -> Result<()> {
    let below_root = path
        .strip_prefix(root)
        .map_err(|_| FileError::PathOutsideWorkspace)?;
    let mut components = below_root.components().peekable();
    let mut prefix = root.to_path_buf();
    while let Some(component) = components.next() {
        prefix.push(component);
        let leaf = components.peek().is_none();
        if !(leaf && allow_leaf_symlink) && is_symlink(&prefix) {
            return Err(FileError::TraversalDenied);
        }
    }
    Ok(())
}

/// Resolve a workspace path for a non-Linux file RPC: lexical confinement,
/// then the symlink refusal above against the most specific configured root.
/// Missing components pass; the operation reports them.
#[cfg(not(target_os = "linux"))]
fn resolve_confined_path(config: &Config, path: &str, allow_leaf_symlink: bool) -> Result<PathBuf> {
    let resolved = resolve_workspace_path(config, path)?;
    let root = [&config.workspace_root, &config.home_root]
        .into_iter()
        .filter(|root| resolved.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or(FileError::PathOutsideWorkspace)?;
    reject_symlinked_components(root, &resolved, allow_leaf_symlink, |probe| {
        fs::symlink_metadata(probe)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
    })?;
    Ok(resolved)
}

pub fn is_allowed_workspace_path(config: &Config, path: &Path) -> bool {
    path == config.workspace_root
        || path.starts_with(&config.workspace_root)
        || path == config.home_root
        || path.starts_with(&config.home_root)
}

#[cfg(not(target_os = "linux"))]
pub fn list(config: &Config, path: &str) -> Result<Vec<v1::FileMetadata>> {
    // Listing enters the directory, so it may not be a link. Entries that are
    // links are named from lstat and never entered.
    let target = resolve_confined_path(config, path, false)?;
    let entries = fs::read_dir(&target)?;
    let mut result = Vec::new();

    for entry in entries.flatten() {
        let full_path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&full_path) else {
            continue;
        };
        if let Ok(entry) = file_metadata_from_info(&full_path, &metadata) {
            result.push(entry);
        }
    }

    Ok(result)
}

#[cfg(not(target_os = "linux"))]
pub fn stat(config: &Config, path: &str, follow: bool) -> Result<v1::FileMetadata> {
    // Without follow, a link leaf is named from lstat; following one is
    // refused because the lexical path says nothing about where it lands.
    let target = resolve_confined_path(config, path, !follow)?;
    let metadata = fs::symlink_metadata(&target)?;
    file_metadata_from_info(&target, &metadata)
}

#[cfg(not(target_os = "linux"))]
pub fn open_file(
    config: &Config,
    path: &str,
    options: Option<&v1::FileOpenOptions>,
    perm: u32,
) -> Result<()> {
    let target = resolve_confined_path(config, path, false)?;
    let options = options.cloned().unwrap_or_default();
    let mut open = OpenOptions::new();
    open.read(options.read || !options.write);
    open.write(options.write || options.append);
    open.append(options.append);
    open.create(options.create);
    open.truncate(options.truncate);
    open.create_new(options.exclusive);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(file_mode_or_default(perm, 0o644));
    }

    let file = open.open(target)?;
    drop(file);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn read(config: &Config, path: &str, offset: i64, length: i64) -> Result<Vec<u8>> {
    let target = resolve_confined_path(config, path, false)?;
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }
    if length < 0 {
        return Err(FileError::InvalidLength);
    }

    let mut file = File::open(target)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Err(FileError::IsDirectory);
    }
    file.seek(SeekFrom::Start(offset as u64))?;

    if length > 0 {
        let available = metadata.size().saturating_sub(offset as u64);
        let length = u64::try_from(length).unwrap_or(u64::MAX).min(available);
        let mut data = Vec::new();
        file.take(length).read_to_end(&mut data)?;
        Ok(data)
    } else {
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn write(config: &Config, path: &str, offset: i64, data: &[u8]) -> Result<i64> {
    let target = resolve_confined_path(config, path, false)?;
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }

    let mut file = OpenOptions::new().write(true).open(target)?;
    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(data)?;
    Ok(i64::try_from(data.len()).unwrap_or(i64::MAX))
}

#[cfg(not(target_os = "linux"))]
pub fn mkdir(config: &Config, path: &str, perm: u32) -> Result<()> {
    let target = resolve_confined_path(config, path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(file_mode_or_default(perm, 0o755));
        builder.create(target)?;
    }
    #[cfg(not(unix))]
    {
        let _ = perm;
        fs::create_dir(target)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn remove(config: &Config, path: &str) -> Result<()> {
    let target = resolve_confined_path(config, path, false)?;
    fs::remove_file(&target).or_else(|err| {
        if err.kind() == std::io::ErrorKind::IsADirectory {
            fs::remove_dir(target)
        } else {
            Err(err)
        }
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn rename(config: &Config, old_path: &str, new_path: &str) -> Result<()> {
    let old_path = resolve_confined_path(config, old_path, false)?;
    let new_path = resolve_confined_path(config, new_path, false)?;
    fs::rename(old_path, new_path)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_stat(config: &Config, request: &v1::SetStatRequest) -> Result<()> {
    let target = resolve_confined_path(config, &request.path, false)?;
    if let Some(size) = request.size {
        if size < 0 {
            return Err(FileError::InvalidSize);
        }
        File::options()
            .write(true)
            .open(&target)?
            .set_len(size as u64)?;
    }
    if let Some(mode) = request.mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o7777))?;
        }
    }
    if request.access_time.is_some() || request.mod_time.is_some() {
        let now = SystemTime::now();
        let metadata = fs::metadata(&target).ok();
        let atime = request
            .access_time
            .as_ref()
            .map(system_time_from_timestamp)
            .unwrap_or(now);
        let mtime = request
            .mod_time
            .as_ref()
            .map(system_time_from_timestamp)
            .or_else(|| metadata.and_then(|metadata| metadata.modified().ok()))
            .unwrap_or(now);
        filetime::set_file_times(
            &target,
            FileTime::from_system_time(atime),
            FileTime::from_system_time(mtime),
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn readlink(config: &Config, path: &str) -> Result<String> {
    // Reading a link's target never passes through it.
    let target = resolve_confined_path(config, path, true)?;
    Ok(fs::read_link(target)?.to_string_lossy().into_owned())
}

pub fn file_metadata_from_info(path: &Path, metadata: &fs::Metadata) -> Result<v1::FileMetadata> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let link_target = if metadata.file_type().is_symlink() {
        fs::read_link(path)
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(v1::FileMetadata {
        name,
        path: path.to_string_lossy().into_owned(),
        size: i64::try_from(metadata.len()).unwrap_or(i64::MAX),
        mode: go_mode_from_metadata(metadata),
        mod_time: Some(timestamp_from_system_time(
            metadata.modified().unwrap_or(UNIX_EPOCH),
        )),
        link_target,
    })
}

fn file_mode_or_default(mode: u32, fallback: u32) -> u32 {
    if mode == 0 { fallback } else { mode & 0o7777 }
}

fn timestamp_from_system_time(time: SystemTime) -> Timestamp {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: duration.subsec_nanos() as i32,
        },
        Err(err) => {
            let duration = err.duration();
            Timestamp {
                seconds: -i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
                nanos: -(duration.subsec_nanos() as i32),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn system_time_from_timestamp(timestamp: &Timestamp) -> SystemTime {
    if timestamp.seconds >= 0 {
        UNIX_EPOCH + Duration::new(timestamp.seconds as u64, timestamp.nanos.max(0) as u32)
    } else {
        UNIX_EPOCH - Duration::new((-timestamp.seconds) as u64, timestamp.nanos.max(0) as u32)
    }
}

fn go_mode_from_metadata(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let file_type = metadata.file_type();
        let permissions = metadata.mode() & 0o7777;
        let kind = if file_type.is_dir() {
            GO_MODE_DIR
        } else if file_type.is_symlink() {
            GO_MODE_SYMLINK
        } else if file_type.is_fifo() {
            GO_MODE_NAMED_PIPE
        } else if file_type.is_socket() {
            GO_MODE_SOCKET
        } else if file_type.is_char_device() {
            GO_MODE_DEVICE | GO_MODE_CHAR_DEVICE
        } else if file_type.is_block_device() {
            GO_MODE_DEVICE
        } else {
            0
        };
        kind | permissions
    }
    #[cfg(not(unix))]
    {
        let permissions = if metadata.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        if metadata.is_dir() {
            GO_MODE_DIR | permissions
        } else {
            permissions
        }
    }
}

#[cfg(not(target_os = "linux"))]
trait FileLenExt {
    fn size(&self) -> u64;
}

#[cfg(not(target_os = "linux"))]
impl FileLenExt for fs::Metadata {
    fn size(&self) -> u64 {
        self.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config(workspace_root: PathBuf, home_root: PathBuf) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".into(),
            workspace_root,
            home_root,
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("daemon-files-test-token").unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn runc(config: Config, uid: u32, gid: u32) -> Config {
        Config {
            process_execution: crate::execution::ProcessExecution::Runc(
                crate::execution::RuncExecution {
                    helper_path: PathBuf::from("/init"),
                    process_directory: PathBuf::from("/run/codewire/runc"),
                    container_id: "workspace".into(),
                    process_wrapper: Vec::new(),
                    default_shell: "/bin/sh".into(),
                    base_environment: Vec::new(),
                    uid,
                    gid,
                    additional_gids: Vec::new(),
                    network_namespace: "/run/codewire/netns/workspace".into(),
                },
            ),
            ..config
        }
    }

    #[cfg(target_os = "linux")]
    fn filesystem_ids() -> (u32, u32) {
        // SAFETY: -1 queries this thread's filesystem IDs without changing them.
        unsafe {
            (
                libc::setfsuid(u32::MAX) as u32,
                libc::setfsgid(u32::MAX) as u32,
            )
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_local_vm_file_operation_acts_as_the_workload_user_and_restores_the_thread() {
        use std::os::unix::fs::MetadataExt as _;
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let (uid, gid) = filesystem_ids();
        // The test runs unprivileged, so the workload user it can act as is
        // its own; the switch is still taken and read back.
        let cfg = runc(
            config(workspace.clone(), temp.path().join("home")),
            uid,
            gid,
        );
        let observed = as_workload_user(&cfg, || {
            std::fs::write(workspace.join("created"), b"x").map_err(FileError::from)?;
            Ok(filesystem_ids())
        })
        .unwrap();
        assert_eq!(observed, (uid, gid));
        let metadata = std::fs::metadata(workspace.join("created")).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
        assert_eq!(filesystem_ids(), (uid, gid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_workload_user_the_daemon_cannot_become_fails_closed() {
        let (uid, gid) = filesystem_ids();
        if uid == 0 {
            // Root can become any user; the refusal is for a daemon that cannot.
            return;
        }
        let other = uid.checked_add(1).unwrap();
        let cfg = runc(
            config(PathBuf::from("/workspace"), PathBuf::from("/home")),
            other,
            gid,
        );
        let mut ran = false;
        let result = as_workload_user(&cfg, || {
            ran = true;
            Ok(())
        });
        assert!(
            matches!(&result, Err(FileError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied),
            "{result:?}"
        );
        assert!(!ran, "no file operation runs under the wrong identity");
        assert_eq!(
            filesystem_ids(),
            (uid, gid),
            "the thread keeps its own identity"
        );
    }

    #[test]
    fn every_other_placement_runs_file_operations_unchanged() {
        let cfg = config(PathBuf::from("/workspace"), PathBuf::from("/home/codewire"));
        assert_eq!(as_workload_user(&cfg, || Ok(7)).unwrap(), 7);
    }

    #[test]
    fn path_resolution_stays_inside_workspace_or_home() {
        let cfg = config(PathBuf::from("/workspace"), PathBuf::from("/home/codewire"));

        assert_eq!(
            resolve_workspace_path(&cfg, "src/main.rs").unwrap(),
            PathBuf::from("/workspace/src/main.rs")
        );
        assert_eq!(
            resolve_workspace_path(&cfg, "/home/codewire/.profile").unwrap(),
            PathBuf::from("/home/codewire/.profile")
        );
        assert!(matches!(
            resolve_workspace_path(&cfg, "../etc/passwd"),
            Err(FileError::PathOutsideWorkspace)
        ));
        assert!(matches!(
            resolve_workspace_path(&cfg, "/workspace2/file"),
            Err(FileError::PathOutsideWorkspace)
        ));
    }

    #[test]
    fn file_lifecycle_matches_daemon_rpc_semantics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("home");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&home).expect("home");
        let cfg = config(workspace.clone(), home);

        open_file(
            &cfg,
            "hello.txt",
            Some(&v1::FileOpenOptions {
                write: true,
                create: true,
                truncate: true,
                ..Default::default()
            }),
            // Not the 0o644 default, and kept whole by any umask that leaves
            // the owner's read and write (077 as well as 022).
            0o600,
        )
        .expect("open");
        write(&cfg, "hello.txt", 0, b"hello world").expect("write");
        assert_eq!(read(&cfg, "hello.txt", 6, 5).expect("read"), b"world");

        let entry = stat(&cfg, "hello.txt", false).expect("stat");
        assert_eq!(entry.size, 11);
        assert_eq!(entry.mode & 0o777, 0o600);

        let entries = list(&cfg, "").expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");

        rename(&cfg, "hello.txt", "renamed.txt").expect("rename");
        assert!(stat(&cfg, "renamed.txt", false).is_ok());
        remove(&cfg, "renamed.txt").expect("remove");
        assert!(matches!(
            stat(&cfg, "renamed.txt", false),
            Err(FileError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_metadata_uses_go_mode_bits_and_link_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"x").expect("target");
        symlink("target", &link).expect("symlink");

        let metadata = fs::symlink_metadata(&link).expect("metadata");
        let entry = file_metadata_from_info(&link, &metadata).expect("entry");
        assert_ne!(entry.mode & GO_MODE_SYMLINK, 0);
        assert_eq!(entry.link_target, "target");
    }

    /// #2505 L4: the non-Linux walker refuses a symlink at any depth below
    /// the root, ignores links above it, and lets lstat-style callers name a
    /// link leaf. A probe stands in for lstat so Linux CI runs it.
    #[test]
    fn symlinked_components_below_the_root_are_refused() {
        let is_symlink = |probe: &Path| {
            probe.file_name().is_some_and(|name| name == "link") || probe == Path::new("/var")
        };
        let root = Path::new("/var/workspace");
        let check = |path: &str, allow_leaf: bool| {
            reject_symlinked_components(root, Path::new(path), allow_leaf, is_symlink)
        };

        assert!(
            check("/var/workspace", false).is_ok(),
            "a link above the root is configuration"
        );
        assert!(check("/var/workspace/src/main.rs", false).is_ok());
        assert!(matches!(
            check("/var/workspace/link", false),
            Err(FileError::TraversalDenied)
        ));
        assert!(
            matches!(
                check("/var/workspace/link/secret", false),
                Err(FileError::TraversalDenied)
            ),
            "the lexical path stays inside, but the link decides where it lands"
        );
        assert!(
            check("/var/workspace/src/link", true).is_ok(),
            "naming a link leaf"
        );
        assert!(
            matches!(
                check("/var/workspace/link/secret", true),
                Err(FileError::TraversalDenied)
            ),
            "naming a leaf never passes through a link"
        );
        assert!(matches!(
            check("/elsewhere/file", false),
            Err(FileError::PathOutsideWorkspace)
        ));
    }
}
