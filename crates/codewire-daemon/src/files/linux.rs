use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use codewire_gateway_proto::daemon::v1;
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
use crate::config::Config;

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

impl WorkspacePath {
    fn resolve(config: &Config, raw: &str) -> Result<Self> {
        let display = resolve_workspace_path(config, raw)?;
        let (root_path, relative) =
            if let Ok(relative) = display.strip_prefix(&config.workspace_root) {
                (&config.workspace_root, relative)
            } else if let Ok(relative) = display.strip_prefix(&config.home_root) {
                (&config.home_root, relative)
            } else {
                return Err(FileError::PathOutsideWorkspace);
            };
        Ok(Self {
            root: WorkspaceRoot::open(root_path)?,
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

    fn roots() -> (tempfile::TempDir, Config, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("home");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&home).expect("home");
        let config = Config {
            listen_addr: "127.0.0.1:0".into(),
            workspace_root: workspace.clone(),
            home_root: home,
            auth_token: crate::DaemonAuthToken::new("daemon-linux-files-test-token").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
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
}
