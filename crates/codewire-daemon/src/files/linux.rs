use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use codewire_daemon_proto::daemon::v1;
use filetime::FileTime;
use prost_types::Timestamp;
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, ResolveFlags, fchmod, mkdirat, openat, openat2, readlinkat,
    renameat, statat, unlinkat,
};

use super::{
    FileError, GO_MODE_CHAR_DEVICE, GO_MODE_DEVICE, GO_MODE_DIR, GO_MODE_NAMED_PIPE,
    GO_MODE_SOCKET, GO_MODE_SYMLINK, Result, file_mode_or_default, resolve_workspace_path,
    timestamp_from_system_time,
};
use crate::config::{Config, DeclaredMount};
use crate::execution::ProcessExecution;

/// This thread's filesystem identity, switched to the workload user until
/// dropped. `setfsuid` and `setfsgid` report the previous value and never an
/// error, so each switch is read back and refused if it did not take effect.
pub(super) struct FilesystemIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl FilesystemIdentity {
    pub(super) fn switch(uid: u32, gid: u32) -> Result<Self> {
        // SAFETY: setfsgid and setfsuid take scalar IDs and change only this
        // thread's filesystem credentials; `u32::MAX` (-1) queries them.
        let previous = unsafe {
            Self {
                gid: libc::setfsgid(gid) as libc::gid_t,
                uid: libc::setfsuid(uid) as libc::uid_t,
            }
        };
        let (current_uid, current_gid) =
            unsafe { (libc::setfsuid(u32::MAX), libc::setfsgid(u32::MAX)) };
        if current_uid as u32 != uid || current_gid as u32 != gid {
            drop(previous);
            return Err(FileError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file operations could not act as the workload user",
            )));
        }
        Ok(previous)
    }
}

impl Drop for FilesystemIdentity {
    fn drop(&mut self) {
        // SAFETY: as in `switch`; restore the user first, then the group, so
        // the thread never holds root's group with the workload's user.
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
        }
    }
}

/// `NO_XDEV` also keeps the platform's run directory out under a root that
/// contains it: a relative link to `../codewire/run` stays beneath `/`, and
/// is refused only because `/codewire/run` is its own mount wherever the
/// identity token files exist (admission pins the volume, and the standard
/// guest bind-mounts it). If that ever stops holding, refusing the platform
/// directory needs a check of the opened path too (#4664).
const RESOLVE_WORKSPACE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

#[derive(Debug)]
struct WorkspaceRoot {
    directory: File,
}

#[derive(Debug)]
struct WorkspacePath {
    root: WorkspaceRoot,
    relative: PathBuf,
    display: PathBuf,
}

impl WorkspaceRoot {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(FileError::UntrustedRoot);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let opened = directory.metadata()?;
        let named = fs::symlink_metadata(path)?;
        let canonical = fs::canonicalize(path)?;
        if !opened.is_dir()
            || !named.is_dir()
            || canonical != path
            || opened.dev() != named.dev()
            || opened.ino() != named.ino()
        {
            return Err(FileError::UntrustedRoot);
        }
        Ok(Self { directory })
    }

    /// For a declared mount: the opened root must be that exact mount's root,
    /// checked on the descriptor itself, so a missing, moved or swapped mount
    /// is refused rather than written beneath (#4102).
    fn verify_mount(&self, expected: Option<u64>) -> Result<()> {
        let expected = expected.ok_or(FileError::MountUnavailable)?;
        let status = rustix::fs::statx(
            self.directory.as_fd(),
            "",
            AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::MNT_ID,
        )
        .map_err(|error| FileError::Io(error.into()))?;
        let mount_root = rustix::fs::StatxAttributes::MOUNT_ROOT;
        if status.stx_mask & rustix::fs::StatxFlags::MNT_ID.bits() == 0
            || !status.stx_attributes_mask.contains(mount_root)
            || !status.stx_attributes.contains(mount_root)
            || status.stx_mnt_id != expected
        {
            return Err(FileError::MountUnavailable);
        }
        Ok(())
    }

    /// Cross from this root into the kept folder at `kept.relative`: open its
    /// parent beneath this root, open the folder itself with one `openat` that
    /// follows no link, and require the descriptor to be the root of exactly
    /// the mount the table matched (#4139).
    fn enter_kept(&self, kept: &KeptRoot) -> Result<Self> {
        let leaf = kept.relative.file_name().ok_or(FileError::InvalidPath)?;
        let parent = kept.relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = self.open_directory(parent)?;
        let directory = openat(
            parent.as_fd(),
            leaf,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(confined_error)?;
        let entered = Self {
            directory: File::from(directory),
        };
        entered.verify_mount(Some(kept.mount_id))?;
        Ok(entered)
    }

    fn open_directory(&self, relative: &Path) -> Result<File> {
        if relative.as_os_str().is_empty() {
            return Ok(self.directory.try_clone()?);
        }
        let owned = openat2(
            self.directory.as_fd(),
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_WORKSPACE,
        )
        .map_err(confined_error)?;
        Ok(File::from(owned))
    }

    fn open_regular(&self, relative: &Path, flags: OFlags, mode: Mode) -> Result<File> {
        require_leaf(relative)?;
        let mode = if flags.intersects(OFlags::CREATE | OFlags::TMPFILE) {
            mode
        } else {
            Mode::empty()
        };
        let owned = openat2(
            self.directory.as_fd(),
            relative,
            flags | OFlags::CLOEXEC | OFlags::NONBLOCK,
            mode,
            RESOLVE_WORKSPACE,
        )
        .map_err(confined_error)?;
        let file = File::from(owned);
        if !file.metadata()?.is_file() {
            return Err(FileError::NotRegularFile);
        }
        Ok(file)
    }

    fn metadata_nofollow(&self, relative: &Path) -> Result<fs::Metadata> {
        if relative.as_os_str().is_empty() {
            return Ok(self.directory.metadata()?);
        }
        let (parent, leaf) = self.open_parent(relative)?;
        let admitted =
            statat(parent.as_fd(), leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(confined_error)?;
        let owned = openat(
            parent.as_fd(),
            leaf,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(confined_error)?;
        let metadata = File::from(owned).metadata()?;
        if metadata.dev() != admitted.st_dev as u64 || metadata.ino() != admitted.st_ino as u64 {
            return Err(FileError::TraversalDenied);
        }
        Ok(metadata)
    }

    fn open_parent<'a>(&self, relative: &'a Path) -> Result<(File, &'a Path)> {
        require_leaf(relative)?;
        let leaf = relative.file_name().ok_or(FileError::InvalidPath)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        Ok((self.open_directory(parent)?, Path::new(leaf)))
    }

    fn read_link(&self, relative: &Path) -> Result<String> {
        let (parent, leaf) = self.open_parent(relative)?;
        let before =
            statat(parent.as_fd(), leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(confined_error)?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Symlink {
            return Err(FileError::NotSymlink);
        }
        let target = readlinkat(parent.as_fd(), leaf, Vec::new()).map_err(confined_error)?;
        let after =
            statat(parent.as_fd(), leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(confined_error)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(FileError::TraversalDenied);
        }
        Ok(OsStr::from_bytes(&target.into_bytes())
            .to_string_lossy()
            .into_owned())
    }
}

/// The root a path resolves from, and the path relative to it: the deepest
/// of the environment's own mounts below `/workspace` that holds it, else
/// the workspace or the home root. Resolution never crosses a mount
/// (`NO_XDEV`), so a declared mount must be its own root, and any other
/// mount below `/workspace` stays refused (#4102).
fn select_root<'a>(
    config: &'a Config,
    display: &'a Path,
) -> Option<(&'a Path, &'a Path, Option<&'a DeclaredMount>)> {
    config
        .mount_roots
        .iter()
        .filter(|mount| mount.path.starts_with(&config.workspace_root))
        .filter_map(|mount| {
            Some((
                mount.path.as_path(),
                display.strip_prefix(&mount.path).ok()?,
                Some(mount),
            ))
        })
        .max_by_key(|(root, _, _)| root.components().count())
        .or_else(|| {
            [&config.workspace_root, &config.home_root]
                .into_iter()
                .find_map(|root| Some((root.as_path(), display.strip_prefix(root).ok()?, None)))
        })
}

/// The kernel's ID of each declared mount, from this process's
/// `/proc/self/mountinfo`, read when the daemon starts; none where nothing is
/// mounted (#4102). The top of a stacked mount point wins.
pub fn declared_mounts(paths: impl IntoIterator<Item = PathBuf>) -> Vec<DeclaredMount> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    paths
        .into_iter()
        .map(|path| DeclaredMount {
            mount_id: mount_id_at(&mountinfo, &path),
            path,
        })
        .collect()
}

/// The ID of the last mount `mountinfo` lists at `path`.
fn mount_id_at(mountinfo: &str, path: &Path) -> Option<u64> {
    mountinfo.lines().rev().find_map(|line| {
        let mut fields = line.split(' ');
        let id = fields.next()?.parse().ok()?;
        let point = fields.nth(3)?;
        (Path::new(&unescape_mountinfo(point)) == path).then_some(id)
    })
}

/// `mountinfo` writes space, tab, newline and backslash in a path as `\\ooo`.
fn unescape_mountinfo(field: &str) -> std::ffi::OsString {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let octal = (bytes[index] == b'\\')
            .then(|| bytes.get(index + 1..index + 4))
            .flatten()
            .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
            .and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok());
        match octal {
            Some(byte) => {
                out.push(byte);
                index += 4;
            }
            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }
    std::ffi::OsString::from_vec(out)
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    id: u64,
    device: (u32, u32),
    root: PathBuf,
    point: PathBuf,
}

/// Every line of this process's own mount table. A line that does not parse
/// fails the request: a kept folder is recognised from this table, so a table
/// read only in part recognises nothing (#4139).
fn read_mount_table() -> Result<Vec<MountEntry>> {
    parse_mount_table(&fs::read_to_string("/proc/self/mountinfo")?)
}

fn parse_mount_table(text: &str) -> Result<Vec<MountEntry>> {
    text.lines()
        .map(|line| parse_mount_line(line).ok_or(FileError::MountUnavailable))
        .collect()
}

fn parse_mount_line(line: &str) -> Option<MountEntry> {
    let mut fields = line.split(' ');
    let id = fields.next()?.parse().ok()?;
    let _parent: u64 = fields.next()?.parse().ok()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let device = (major.parse().ok()?, minor.parse().ok()?);
    let root = PathBuf::from(unescape_mountinfo(fields.next()?));
    let point = PathBuf::from(unescape_mountinfo(fields.next()?));
    // Mount options, optional fields, then "-" before the filesystem type.
    fields.any(|field| field == "-").then_some(MountEntry {
        id,
        device,
        root,
        point,
    })
}

/// A folder kept on the VM's own disk below a root, and the ID of the mount
/// that holds it now.
#[derive(Debug, PartialEq, Eq)]
struct KeptRoot {
    relative: PathBuf,
    mount_id: u64,
}

/// What lies between `root` and `root/relative`: nothing mounted, a kept
/// folder, or some other mount.
#[derive(Debug, PartialEq, Eq)]
enum Crossing {
    None,
    Kept(KeptRoot),
    Other(PathBuf),
}

/// The first mount between `root` and `root/relative`, read from the
/// daemon's own mount table (#4139).
///
/// A kept folder is recognised by what it is, not from a list: the top mount
/// at its path is a bind of `/vm-only/<the path's backing name>` on the state
/// disk's device. A kept folder is bound again under a new mount ID whenever
/// the host replaces it, so no ID can be pinned at start, as shares are.
///
/// The boundary this protects is the unprivileged workspace user against the
/// root daemon as a confused deputy (cw-security's review on #4139). The
/// daemon shares init's mount namespace; the workload's mounts stay in its
/// own namespace and the backing root is root-only and outside its view, so
/// the workload cannot make such a mount here. With Docker on, the workload
/// can reach VM root and no in-guest check is a boundary; the host's is the
/// share confinement, which this does not change.
fn crossing(table: &[MountEntry], root: &Path, relative: &Path) -> Crossing {
    let state = table
        .iter()
        .rev()
        .find(|entry| entry.point == Path::new(super::STATE_MOUNT_POINT))
        .map(|entry| entry.device);
    let mut prefix = PathBuf::new();
    for component in relative.components() {
        prefix.push(component);
        let point = root.join(&prefix);
        let Some(top) = table.iter().rev().find(|entry| entry.point == point) else {
            continue;
        };
        let backing = point.to_str().map(|guest| {
            Path::new("/")
                .join(super::VM_ONLY_BACKING_DIRECTORY)
                .join(super::vm_only_backing_name(guest))
        });
        if state == Some(top.device) && backing.as_deref() == Some(top.root.as_path()) {
            return Crossing::Kept(KeptRoot {
                relative: prefix,
                mount_id: top.id,
            });
        }
        return Crossing::Other(point);
    }
    Crossing::None
}

impl WorkspacePath {
    fn resolve(config: &Config, raw: &str) -> Result<Self> {
        let display = resolve_workspace_path(config, raw)?;
        let (root_path, relative, declared) =
            select_root(config, &display).ok_or(FileError::PathOutsideWorkspace)?;
        let root = WorkspaceRoot::open(root_path)?;
        if let Some(declared) = declared {
            root.verify_mount(declared.mount_id)?;
        }
        // Only a local VM's guest keeps folders on its own disk (#4139).
        if matches!(config.process_execution, ProcessExecution::Runc(_))
            && root_path.starts_with(&config.workspace_root)
        {
            match crossing(&read_mount_table()?, root_path, relative) {
                Crossing::None => {}
                Crossing::Other(point) => return Err(FileError::NestedMount(point)),
                // The folder and everything beneath it resolve from the
                // folder's own root. The folder itself is that root, so it can
                // be listed and stated but never replaced or removed.
                Crossing::Kept(kept) => {
                    let beneath = relative
                        .strip_prefix(&kept.relative)
                        .map_err(|_| FileError::InvalidPath)?
                        .to_owned();
                    return Ok(Self {
                        root: root.enter_kept(&kept)?,
                        relative: beneath,
                        display,
                    });
                }
            }
        }
        Ok(Self {
            root,
            relative: relative.to_owned(),
            display,
        })
    }

    fn open_parent(&self) -> Result<(File, &Path)> {
        self.root.open_parent(&self.relative)
    }
}

pub fn list(config: &Config, path: &str) -> Result<Vec<v1::FileMetadata>> {
    let target = WorkspacePath::resolve(config, path)?;
    let directory = target.root.open_directory(&target.relative)?;
    let mut entries = Dir::read_from(&directory).map_err(confined_error)?;
    let mut result = Vec::new();
    while let Some(entry) = entries.read() {
        let Ok(entry) = entry else {
            break;
        };
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        let relative = target.relative.join(name);
        let Ok(metadata) = target.root.metadata_nofollow(&relative) else {
            continue;
        };
        let link_target = if metadata.file_type().is_symlink() {
            target.root.read_link(&relative).ok()
        } else {
            None
        };
        result.push(file_metadata_from_info(
            &target.display.join(name),
            &metadata,
            link_target,
        ));
    }
    Ok(result)
}

pub fn stat(config: &Config, path: &str, follow: bool) -> Result<v1::FileMetadata> {
    let target = WorkspacePath::resolve(config, path)?;
    let metadata = if target.relative.as_os_str().is_empty() {
        target.root.directory.metadata()?
    } else if follow {
        let opened = openat2(
            target.root.directory.as_fd(),
            &target.relative,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_WORKSPACE,
        )
        .map_err(confined_error)?;
        File::from(opened).metadata()?
    } else {
        target.root.metadata_nofollow(&target.relative)?
    };
    let link_target = if metadata.file_type().is_symlink() {
        Some(target.root.read_link(&target.relative)?)
    } else {
        None
    };
    Ok(file_metadata_from_info(
        &target.display,
        &metadata,
        link_target,
    ))
}

pub fn open_file(
    config: &Config,
    path: &str,
    options: Option<&v1::FileOpenOptions>,
    perm: u32,
) -> Result<()> {
    let target = WorkspacePath::resolve(config, path)?;
    let options = options.cloned().unwrap_or_default();
    let mut flags = if options.read && (options.write || options.append) {
        OFlags::RDWR
    } else if options.write || options.append {
        OFlags::WRONLY
    } else {
        OFlags::RDONLY
    };
    if options.append {
        flags |= OFlags::APPEND;
    }
    if options.create {
        flags |= OFlags::CREATE;
    }
    if options.truncate {
        flags |= OFlags::TRUNC;
    }
    if options.exclusive {
        flags |= OFlags::EXCL;
    }
    target.root.open_regular(
        &target.relative,
        flags,
        Mode::from_raw_mode(file_mode_or_default(perm, 0o644)),
    )?;
    Ok(())
}

pub fn read(config: &Config, path: &str, offset: i64, length: i64) -> Result<Vec<u8>> {
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }
    if length < 0 {
        return Err(FileError::InvalidLength);
    }
    let target = WorkspacePath::resolve(config, path)?;
    let mut file = target
        .root
        .open_regular(&target.relative, OFlags::RDONLY, Mode::empty())?;
    let size = file.metadata()?.len();
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut data = Vec::new();
    if length > 0 {
        let available = size.saturating_sub(offset as u64);
        file.take((length as u64).min(available))
            .read_to_end(&mut data)?;
    } else {
        file.read_to_end(&mut data)?;
    }
    Ok(data)
}

pub fn write(config: &Config, path: &str, offset: i64, data: &[u8]) -> Result<i64> {
    if offset < 0 {
        return Err(FileError::InvalidOffset);
    }
    let target = WorkspacePath::resolve(config, path)?;
    let mut file = target
        .root
        .open_regular(&target.relative, OFlags::WRONLY, Mode::empty())?;
    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(data)?;
    Ok(i64::try_from(data.len()).unwrap_or(i64::MAX))
}

pub fn mkdir(config: &Config, path: &str, perm: u32) -> Result<()> {
    let target = WorkspacePath::resolve(config, path)?;
    let (parent, leaf) = target.open_parent()?;
    mkdirat(
        parent.as_fd(),
        leaf,
        Mode::from_raw_mode(file_mode_or_default(perm, 0o755)),
    )
    .map_err(confined_error)?;
    Ok(())
}

pub fn remove(config: &Config, path: &str) -> Result<()> {
    let target = WorkspacePath::resolve(config, path)?;
    let (parent, leaf) = target.open_parent()?;
    let metadata =
        statat(parent.as_fd(), leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(confined_error)?;
    let flags = if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
        == rustix::fs::FileType::Directory
    {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    unlinkat(parent.as_fd(), leaf, flags).map_err(confined_error)?;
    Ok(())
}

pub fn rename(config: &Config, old_path: &str, new_path: &str) -> Result<()> {
    let old = WorkspacePath::resolve(config, old_path)?;
    let new = WorkspacePath::resolve(config, new_path)?;
    let (old_parent, old_leaf) = old.open_parent()?;
    let (new_parent, new_leaf) = new.open_parent()?;
    renameat(old_parent.as_fd(), old_leaf, new_parent.as_fd(), new_leaf).map_err(confined_error)?;
    Ok(())
}

pub fn set_stat(config: &Config, request: &v1::SetStatRequest) -> Result<()> {
    if request.size.is_some_and(|size| size < 0) {
        return Err(FileError::InvalidSize);
    }
    let target = WorkspacePath::resolve(config, &request.path)?;
    require_leaf(&target.relative)?;
    let flags = if request.size.is_some() {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let owned = openat2(
        target.root.directory.as_fd(),
        &target.relative,
        flags | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        RESOLVE_WORKSPACE,
    )
    .map_err(confined_error)?;
    let file = File::from(owned);
    let metadata = file.metadata()?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(FileError::NotRegularFile);
    }
    if let Some(size) = request.size {
        if !metadata.is_file() {
            return Err(FileError::NotRegularFile);
        }
        file.set_len(size as u64)?;
    }
    if let Some(mode) = request.mode {
        fchmod(&file, Mode::from_raw_mode(mode & 0o7777)).map_err(confined_error)?;
    }
    if request.access_time.is_some() || request.mod_time.is_some() {
        let atime = request.access_time.as_ref().map(file_time_from_timestamp);
        let mtime = request.mod_time.as_ref().map(file_time_from_timestamp);
        filetime::set_file_handle_times(&file, atime, mtime)?;
    }
    Ok(())
}

pub fn readlink(config: &Config, path: &str) -> Result<String> {
    let target = WorkspacePath::resolve(config, path)?;
    target.root.read_link(&target.relative)
}

fn file_metadata_from_info(
    path: &Path,
    metadata: &fs::Metadata,
    link_target: Option<String>,
) -> v1::FileMetadata {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    v1::FileMetadata {
        name,
        path: path.to_string_lossy().into_owned(),
        size: i64::try_from(metadata.len()).unwrap_or(i64::MAX),
        mode: go_mode_from_metadata(metadata),
        mod_time: Some(timestamp_from_system_time(
            metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
        )),
        link_target: link_target.unwrap_or_default(),
    }
}

fn go_mode_from_metadata(metadata: &fs::Metadata) -> u32 {
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

fn file_time_from_timestamp(timestamp: &Timestamp) -> FileTime {
    FileTime::from_unix_time(timestamp.seconds, timestamp.nanos.max(0) as u32)
}

fn require_leaf(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        Err(FileError::InvalidPath)
    } else {
        Ok(())
    }
}

fn confined_error(error: rustix::io::Errno) -> FileError {
    match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::XDEV | rustix::io::Errno::NOTDIR => {
            FileError::TraversalDenied
        }
        error => FileError::Io(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ProcessExecution;

    fn declared(path: PathBuf, mount_id: Option<u64>) -> DeclaredMount {
        DeclaredMount { path, mount_id }
    }

    #[test]
    fn a_declared_mount_is_its_own_root_and_nothing_else_is() {
        let (_temp, mut config, workspace) = roots();
        let app = workspace.join("app");
        config.mount_roots = vec![
            declared(app.clone(), Some(1)),
            declared(workspace.join("app/deeper"), Some(2)),
            declared(PathBuf::from("/elsewhere"), Some(3)),
        ];
        let root = |path: PathBuf| {
            select_root(&config, &path).map(|(root, relative, mount)| {
                (
                    root.to_owned(),
                    relative.to_owned(),
                    mount.and_then(|mount| mount.mount_id),
                )
            })
        };
        // Inside a declared mount: resolved from it, so nothing is crossed.
        assert_eq!(
            root(app.join("src/main.rs")),
            Some((app.clone(), PathBuf::from("src/main.rs"), Some(1)))
        );
        assert_eq!(
            root(app.clone()),
            Some((app.clone(), PathBuf::new(), Some(1)))
        );
        // The deepest declared mount wins.
        assert_eq!(
            root(app.join("deeper/x")),
            Some((workspace.join("app/deeper"), PathBuf::from("x"), Some(2)))
        );
        // A name that only shares a prefix is not inside it, and an
        // undeclared folder resolves from /workspace, where NO_XDEV refuses
        // any mount it would cross.
        assert_eq!(
            root(workspace.join("application/x")),
            Some((workspace.clone(), PathBuf::from("application/x"), None))
        );
        assert_eq!(
            root(workspace.join("other/y")),
            Some((workspace.clone(), PathBuf::from("other/y"), None))
        );
        // A declared root outside /workspace is never used.
        assert_eq!(root(PathBuf::from("/elsewhere/z")), None);
        assert_eq!(
            root(config.home_root.join(".bashrc")),
            Some((config.home_root.clone(), PathBuf::from(".bashrc"), None))
        );
    }

    #[test]
    fn mountinfo_gives_the_top_mount_at_an_exact_path() {
        let mountinfo = "\
22 1 0:20 / / rw - ext4 /dev/vda rw
40 22 0:41 / /workspace rw - ext4 /dev/vdb rw
41 40 0:42 / /workspace/my\\040app rw - virtiofs cw-direct-00 rw
42 40 0:43 / /workspace/app rw - virtiofs cw-direct-01 rw
43 42 0:44 / /workspace/app rw - virtiofs cw-direct-01 rw
";
        assert_eq!(
            mount_id_at(mountinfo, Path::new("/workspace/my app")),
            Some(41)
        );
        assert_eq!(
            mount_id_at(mountinfo, Path::new("/workspace/app")),
            Some(43)
        );
        assert_eq!(mount_id_at(mountinfo, Path::new("/workspace/ap")), None);
        assert_eq!(mount_id_at(mountinfo, Path::new("/workspace/app/x")), None);
    }

    #[test]
    fn a_declared_root_must_be_that_exact_mount() {
        // /proc is a mount root in any test environment.
        let proc_root = PathBuf::from("/proc");
        let proc_id = declared_mounts([proc_root.clone()])[0]
            .mount_id
            .expect("/proc is mounted");
        let root = WorkspaceRoot::open(&proc_root).expect("open /proc");
        root.verify_mount(Some(proc_id))
            .expect("the real mount is admitted");
        assert!(matches!(
            root.verify_mount(Some(proc_id + 1)),
            Err(FileError::MountUnavailable)
        ));
        assert!(matches!(
            root.verify_mount(None),
            Err(FileError::MountUnavailable)
        ));

        // A declared path that is a plain directory (never mounted, or a mount
        // moved away and the path recreated) is refused, even with the ID of
        // the filesystem it is on, and nothing is listed or written there.
        let (_temp, mut config, workspace) = roots();
        let app = workspace.join("app");
        fs::create_dir(&app).expect("app");
        let containing = rustix::fs::statx(
            fs::File::open(&app).expect("open app").as_fd(),
            "",
            AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::MNT_ID,
        )
        .expect("statx")
        .stx_mnt_id;
        for mount_id in [None, Some(containing)] {
            config.mount_roots = vec![declared(app.clone(), mount_id)];
            assert!(matches!(
                list(&config, app.to_str().unwrap()),
                Err(FileError::MountUnavailable)
            ));
            assert!(matches!(
                write(&config, app.join("x.txt").to_str().unwrap(), 0, b"nope"),
                Err(FileError::MountUnavailable)
            ));
        }
        assert!(!app.join("x.txt").exists());
    }

    fn roots() -> (tempfile::TempDir, Config, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("home");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&home).expect("home");
        let config = Config {
            interception: None,
            listen_addr: "127.0.0.1:0".into(),
            workspace_root: workspace.clone(),
            home_root: home,
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("daemon-linux-files-test-token").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
            sandbox_server_url: None,
        };
        (temp, config, workspace)
    }

    #[test]
    fn symlink_entries_are_visible_but_never_traversed() {
        use std::os::unix::fs::symlink;

        let (temp, config, workspace) = roots();
        let outside_dir = temp.path().join("outside");
        let outside_file = outside_dir.join("secret");
        fs::create_dir(&outside_dir).expect("outside dir");
        fs::write(&outside_file, b"outside").expect("outside file");
        fs::write(workspace.join("inside"), b"inside").expect("inside file");
        symlink(&outside_file, workspace.join("file-link")).expect("file link");
        symlink(&outside_dir, workspace.join("dir-link")).expect("dir link");

        let entry = stat(&config, "file-link", false).expect("lstat link");
        assert_ne!(entry.mode & GO_MODE_SYMLINK, 0);
        assert_eq!(entry.link_target, outside_file.to_string_lossy());
        assert!(matches!(
            stat(&config, "file-link", true),
            Err(FileError::TraversalDenied)
        ));
        assert_eq!(
            readlink(&config, "file-link").expect("readlink"),
            outside_file.to_string_lossy()
        );
        assert!(
            list(&config, "")
                .expect("list")
                .iter()
                .any(|entry| { entry.name == "file-link" && entry.mode & GO_MODE_SYMLINK != 0 })
        );

        assert!(matches!(
            read(&config, "file-link", 0, 0),
            Err(FileError::TraversalDenied)
        ));
        assert!(matches!(
            write(&config, "file-link", 0, b"changed"),
            Err(FileError::TraversalDenied)
        ));
        let open_link = open_file(
            &config,
            "file-link",
            Some(&v1::FileOpenOptions {
                write: true,
                truncate: true,
                ..Default::default()
            }),
            0o644,
        );
        assert!(
            matches!(open_link, Err(FileError::TraversalDenied)),
            "unexpected symlink-open result: {open_link:?}"
        );
        assert!(matches!(
            mkdir(&config, "dir-link/new", 0o755),
            Err(FileError::TraversalDenied)
        ));
        assert!(matches!(
            rename(&config, "inside", "dir-link/moved"),
            Err(FileError::TraversalDenied)
        ));
        assert!(matches!(
            remove(&config, "dir-link/secret"),
            Err(FileError::TraversalDenied)
        ));
        assert!(matches!(
            set_stat(
                &config,
                &v1::SetStatRequest {
                    path: "file-link".into(),
                    size: Some(0),
                    ..Default::default()
                }
            ),
            Err(FileError::TraversalDenied)
        ));
        assert_eq!(
            fs::read(&outside_file).expect("outside unchanged"),
            b"outside"
        );

        remove(&config, "file-link").expect("remove link itself");
        assert_eq!(
            fs::read(&outside_file).expect("outside remains"),
            b"outside"
        );
    }

    #[test]
    fn symlinks_may_resolve_only_to_objects_beneath_the_admitted_root() {
        use std::os::unix::fs::symlink;

        let (_temp, config, workspace) = roots();
        fs::create_dir(workspace.join("real-dir")).expect("real directory");
        fs::write(workspace.join("real-dir/value"), b"inside").expect("inside file");
        symlink("real-dir", workspace.join("dir-link")).expect("directory link");
        symlink("real-dir/value", workspace.join("file-link")).expect("file link");

        assert_eq!(
            read(&config, "file-link", 0, 0).expect("read internal link"),
            b"inside"
        );
        write(&config, "file-link", 0, b"updated").expect("write internal link");
        assert_eq!(
            fs::read(workspace.join("real-dir/value")).expect("updated target"),
            b"updated"
        );
        let followed = stat(&config, "file-link", true).expect("follow internal link");
        assert_eq!(followed.mode & GO_MODE_SYMLINK, 0);
        assert_eq!(followed.size, 7);
        assert_eq!(
            list(&config, "dir-link").expect("list internal directory link")[0].name,
            "value"
        );

        rename(&config, "dir-link/value", "dir-link/renamed")
            .expect("rename beneath internal directory link");
        remove(&config, "dir-link/renamed").expect("remove beneath internal directory link");
    }

    #[test]
    fn the_run_directory_is_refused_by_path_and_through_a_link() {
        use std::os::unix::fs::symlink;

        // By path, under a root override that contains it (#4664).
        let (_temp, mut everything, _) = roots();
        everything.home_root = PathBuf::from("/");
        let token = "/codewire/run/identity/k8s.jwt";
        for refused in [
            list(&everything, "/codewire/run/identity").map(drop),
            stat(&everything, token, true).map(drop),
            open_file(&everything, token, None, 0),
            read(&everything, token, 0, 0).map(drop),
        ] {
            assert!(
                matches!(refused, Err(FileError::PlatformDirectory)),
                "{refused:?}"
            );
        }
        assert_eq!(
            crate::service::status_from_file_error(FileError::PlatformDirectory).code(),
            tonic::Code::InvalidArgument
        );

        // Through links from the workspace into a stand-in run directory:
        // resolution never leaves the root, so the link is refused.
        let (temp, config, workspace) = roots();
        let run = temp.path().join("run");
        fs::create_dir_all(run.join("identity")).expect("run directory");
        fs::write(run.join("identity/k8s.jwt"), b"token-sentinel").expect("token file");
        symlink(&run, workspace.join("run")).expect("directory link");
        symlink(run.join("identity/k8s.jwt"), workspace.join("k8s.jwt")).expect("file link");
        for refused in [
            list(&config, "run/identity").map(drop),
            stat(&config, "run/identity/k8s.jwt", true).map(drop),
            stat(&config, "k8s.jwt", true).map(drop),
            open_file(&config, "k8s.jwt", None, 0),
            read(&config, "k8s.jwt", 0, 0).map(drop),
            read(&config, "run/identity/k8s.jwt", 0, 0).map(drop),
        ] {
            assert!(
                matches!(refused, Err(FileError::TraversalDenied)),
                "{refused:?}"
            );
        }
        assert_eq!(
            fs::read(run.join("identity/k8s.jwt")).expect("token file kept"),
            b"token-sentinel"
        );
    }

    #[test]
    fn retained_root_fd_cannot_be_redirected_by_path_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let retained = temp.path().join("retained");
        let outside = temp.path().join("outside");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&outside).expect("outside");
        fs::write(workspace.join("value"), b"inside").expect("inside");
        fs::write(outside.join("value"), b"outside").expect("outside");

        let root = WorkspaceRoot::open(&workspace).expect("admit root");
        fs::rename(&workspace, &retained).expect("move admitted root");
        symlink(&outside, &workspace).expect("replace name with symlink");
        let mut file = root
            .open_regular(Path::new("value"), OFlags::RDONLY, Mode::empty())
            .expect("open through retained fd");
        let mut value = String::new();
        file.read_to_string(&mut value).expect("read retained file");
        assert_eq!(value, "inside");
    }

    #[test]
    fn racing_intermediate_symlink_never_reaches_outside_file() {
        use std::os::unix::fs::symlink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (temp, config, workspace) = roots();
        let outside = temp.path().join("outside");
        let race = workspace.join("race");
        let parked = workspace.join("parked");
        fs::create_dir(&outside).expect("outside");
        fs::create_dir(&race).expect("race directory");
        fs::write(outside.join("target"), b"outside-sentinel").expect("outside sentinel");
        fs::write(race.join("target"), b"inside").expect("inside target");

        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let thread_race = race.clone();
        let thread_parked = parked.clone();
        let thread_outside = outside.clone();
        let attacker = std::thread::spawn(move || {
            for _ in 0..2_000 {
                fs::rename(&thread_race, &thread_parked).expect("park admitted directory");
                symlink(&thread_outside, &thread_race).expect("install racing symlink");
                std::thread::yield_now();
                fs::remove_file(&thread_race).expect("remove racing symlink");
                fs::rename(&thread_parked, &thread_race).expect("restore admitted directory");
            }
            thread_running.store(false, Ordering::Release);
        });

        while running.load(Ordering::Acquire) {
            let _ = open_file(
                &config,
                "race/target",
                Some(&v1::FileOpenOptions {
                    write: true,
                    truncate: true,
                    ..Default::default()
                }),
                0o600,
            );
            let _ = write(&config, "race/target", 0, b"inside-change");
            let _ = set_stat(
                &config,
                &v1::SetStatRequest {
                    path: "race/target".into(),
                    mode: Some(0o600),
                    ..Default::default()
                },
            );
        }
        attacker.join().expect("join racing attacker");
        assert_eq!(
            fs::read(outside.join("target")).expect("outside target"),
            b"outside-sentinel"
        );
    }

    #[test]
    fn nested_mounts_are_denied() {
        if !Path::new("/proc").is_dir() {
            return;
        }
        let root = WorkspaceRoot::open(Path::new("/")).expect("root");
        assert!(matches!(
            root.open_directory(Path::new("proc")),
            Err(FileError::TraversalDenied)
        ));
    }

    /// A mountinfo line: ID, parent, device, root, mount point, then the
    /// rest a real line carries.
    fn mount_line(id: u64, device: &str, root: &str, point: &str) -> String {
        format!("{id} 1 {device} {root} {point} rw,nosuid shared:7 - ext4 /dev/vdb rw")
    }

    fn kept_backing(point: &str) -> String {
        format!("/vm-only/{}", super::super::vm_only_backing_name(point))
    }

    fn table(lines: &[String]) -> Vec<MountEntry> {
        parse_mount_table(&lines.join("\n")).unwrap()
    }

    #[test]
    fn mount_table_lines_parse_with_escapes_and_a_bad_line_refuses_the_table() {
        let parsed = table(&[mount_line(40, "253:1", "/a\\040b", "/workspace/my\\040app")]);
        assert_eq!(
            parsed,
            vec![MountEntry {
                id: 40,
                device: (253, 1),
                root: PathBuf::from("/a b"),
                point: PathBuf::from("/workspace/my app"),
            }]
        );
        for bad in [
            "x 1 253:1 / /state rw - ext4 /dev/vdb rw",
            "40 1 253 / /state rw - ext4 /dev/vdb rw",
            "40 1 253:1 / /state rw shared:7",
            "   ",
        ] {
            let text = format!("{}\n{bad}", mount_line(1, "0:1", "/", "/"));
            assert!(
                matches!(parse_mount_table(&text), Err(FileError::MountUnavailable)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_kept_folder_is_recognised_by_its_backing_on_the_state_disk() {
        let point = "/workspace/app/node_modules";
        let root = Path::new("/workspace/app");
        let state = mount_line(30, "253:1", "/", "/state");
        let share = mount_line(31, "0:40", "/", "/workspace/app");
        let kept = mount_line(32, "253:1", &kept_backing(point), point);
        let found = crossing(
            &table(&[state.clone(), share.clone(), kept]),
            root,
            Path::new("node_modules/left-pad/index.js"),
        );
        assert_eq!(
            found,
            Crossing::Kept(KeptRoot {
                relative: PathBuf::from("node_modules"),
                mount_id: 32,
            })
        );
        // Bound again after the host replaced the folder: the top mount, with
        // its new ID, is the one that counts.
        let first = mount_line(32, "253:1", &kept_backing(point), point);
        let again = mount_line(57, "253:1", &kept_backing(point), point);
        assert_eq!(
            crossing(
                &table(&[state.clone(), share.clone(), first, again]),
                root,
                Path::new("node_modules/x")
            ),
            Crossing::Kept(KeptRoot {
                relative: PathBuf::from("node_modules"),
                mount_id: 57,
            })
        );
        // Nothing mounted below the root.
        assert_eq!(
            crossing(&table(&[state, share]), root, Path::new("src/main.rs")),
            Crossing::None
        );
    }

    #[test]
    fn any_other_mount_is_refused_by_name() {
        let point = "/workspace/app/node_modules";
        let root = Path::new("/workspace/app");
        let state = mount_line(30, "253:1", "/", "/state");
        let other = |line: String, tables: &[String]| {
            let mut lines = tables.to_vec();
            lines.push(line);
            crossing(&table(&lines), root, Path::new("node_modules/x"))
        };
        let refused = Crossing::Other(PathBuf::from(point));
        // Another path's backing, the right backing on another device, a
        // mount with no backing at all, and no state disk to compare with.
        let wrong_hash = kept_backing("/workspace/app/target");
        assert_eq!(
            other(
                mount_line(32, "253:1", &wrong_hash, point),
                std::slice::from_ref(&state)
            ),
            refused
        );
        assert_eq!(
            other(
                mount_line(32, "0:99", &kept_backing(point), point),
                std::slice::from_ref(&state)
            ),
            refused
        );
        assert_eq!(
            other(
                mount_line(32, "253:1", "/", point),
                std::slice::from_ref(&state)
            ),
            refused
        );
        assert_eq!(
            other(mount_line(32, "253:1", &kept_backing(point), point), &[]),
            refused
        );
        // A backing moved to another path by a rename names the old path.
        let moved = mount_line(32, "253:1", &kept_backing("/workspace/app/old"), point);
        assert_eq!(other(moved, &[state]), refused);
    }

    #[test]
    fn the_kept_folder_itself_can_be_listed_and_stated_but_never_replaced() {
        // A request that names the kept folder itself resolves to the folder's
        // own root with an empty relative path (#4139). Listing and stating it
        // work; every operation that writes, creates, removes, renames or sets
        // a stat needs a parent and a leaf, so none reaches the folder itself.
        let temp = tempfile::tempdir().unwrap();
        let root = WorkspaceRoot::open(&temp.path().canonicalize().unwrap()).unwrap();
        let none = Path::new("");
        assert!(root.open_directory(none).is_ok(), "list");
        assert!(root.metadata_nofollow(none).unwrap().is_dir(), "stat");
        assert!(matches!(
            root.open_parent(none),
            Err(FileError::InvalidPath)
        ));
        assert!(matches!(require_leaf(none), Err(FileError::InvalidPath)));
        assert!(
            root.open_regular(
                none,
                OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
                Mode::from_raw_mode(0o644)
            )
            .is_err()
        );
    }
}
