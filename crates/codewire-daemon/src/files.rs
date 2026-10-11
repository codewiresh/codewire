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
pub use linux::{list, mkdir, open_file, read, readlink, remove, rename, set_stat, stat, write};

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

pub fn is_allowed_workspace_path(config: &Config, path: &Path) -> bool {
    path == config.workspace_root
        || path.starts_with(&config.workspace_root)
        || path == config.home_root
        || path.starts_with(&config.home_root)
}

#[cfg(not(target_os = "linux"))]
pub fn list(config: &Config, path: &str) -> Result<Vec<v1::FileMetadata>> {
    let target = resolve_workspace_path(config, path)?;
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
    let target = resolve_workspace_path(config, path)?;
    let mut metadata = fs::symlink_metadata(&target)?;
    if follow && metadata.file_type().is_symlink() {
        metadata = fs::metadata(&target)?;
    }
    file_metadata_from_info(&target, &metadata)
}

#[cfg(not(target_os = "linux"))]
pub fn open_file(
    config: &Config,
    path: &str,
    options: Option<&v1::FileOpenOptions>,
    perm: u32,
) -> Result<()> {
    let target = resolve_workspace_path(config, path)?;
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
    let target = resolve_workspace_path(config, path)?;
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
    let target = resolve_workspace_path(config, path)?;
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
    let target = resolve_workspace_path(config, path)?;
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
    let target = resolve_workspace_path(config, path)?;
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
    let old_path = resolve_workspace_path(config, old_path)?;
    let new_path = resolve_workspace_path(config, new_path)?;
    fs::rename(old_path, new_path)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_stat(config: &Config, request: &v1::SetStatRequest) -> Result<()> {
    let target = resolve_workspace_path(config, &request.path)?;
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
    let target = resolve_workspace_path(config, path)?;
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
            auth_token: crate::DaemonAuthToken::new("daemon-files-test-token").unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        }
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
            0o644,
        )
        .expect("open");
        write(&cfg, "hello.txt", 0, b"hello world").expect("write");
        assert_eq!(read(&cfg, "hello.txt", 6, 5).expect("read"), b"world");

        let entry = stat(&cfg, "hello.txt", false).expect("stat");
        assert_eq!(entry.size, 11);
        assert_eq!(entry.mode & 0o777, 0o644);

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
}
