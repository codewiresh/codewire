//! Clean-Git workspace snapshot provisioning for the first native preview.
//!
//! Host worktree paths are used only to ask a fixed `/usr/bin/git` for the
//! checked-out commit and cleanliness. File contents come from Git object
//! bytes, never by following the host worktree, filters, hooks, or mounts.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

use uuid::Uuid;

use crate::linux::path::PrivateRoot;
use crate::linux::state::{MINIMUM_STATE_DISK_BYTES, VmPaths};

const GIT: &str = "/usr/bin/git";
const MAX_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const MINIMUM_EXT4_HEADROOM: u64 = 128 * 1024 * 1024;
const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/v1\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    pub source_path: PathBuf,
    pub commit: String,
    pub state_disk: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeEntry {
    mode: u32,
    object_id: String,
    path: PathBuf,
}

/// Create a new sparse ext4 state disk containing `workspace/` and `home/`.
/// The destination must not already exist. A failed operation removes only the
/// UUID-named staging directory and the newly-created incomplete disk.
pub fn provision_clean_git_workspace(
    engine_state_root: &Path,
    vm_id: Uuid,
    requested_source: &Path,
    disk_bytes: u64,
) -> Result<WorkspaceSnapshot, WorkspaceError> {
    if disk_bytes < MINIMUM_STATE_DISK_BYTES
        || !disk_bytes.is_multiple_of(1024 * 1024)
        || disk_bytes <= MINIMUM_EXT4_HEADROOM
    {
        return Err(WorkspaceError::InvalidDiskSize(disk_bytes));
    }
    let source_path = fs::canonicalize(requested_source).map_err(|source| WorkspaceError::Io {
        path: requested_source.to_owned(),
        source,
    })?;
    if !fs::metadata(&source_path)
        .map_err(|source| WorkspaceError::Io {
            path: source_path.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(WorkspaceError::SourceNotDirectory(source_path));
    }

    let top_level = git_text(&source_path, &["rev-parse", "--show-toplevel"])?;
    let top_level = fs::canonicalize(top_level.trim()).map_err(|source| WorkspaceError::Io {
        path: PathBuf::from(top_level.trim()),
        source,
    })?;
    if top_level != source_path {
        return Err(WorkspaceError::SourceMustBeWorktreeRoot {
            requested: source_path,
            root: top_level,
        });
    }
    let bare = git_text(&top_level, &["rev-parse", "--is-bare-repository"])?;
    if bare.trim() != "false" {
        return Err(WorkspaceError::BareRepository);
    }
    let commit = git_text(&top_level, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim()
        .to_owned();
    if !valid_object_id(&commit) {
        return Err(WorkspaceError::InvalidCommit);
    }
    let status = git_output(
        &top_level,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    if !status.stdout.is_empty() {
        return Err(WorkspaceError::DirtyWorktree);
    }
    let tree = git_output(
        &top_level,
        &["ls-tree", "-r", "-z", "--full-tree", &commit],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let entries = parse_tree(&tree.stdout)?;

    let engine_root = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine_root, vm_id)?;
    if fs::symlink_metadata(&paths.state_disk).is_ok() {
        return Err(WorkspaceError::StateDiskAlreadyExists(paths.state_disk));
    }
    let staging_name = format!("provision-{vm_id}");
    let staging_dir = engine_root.create_dir(Path::new(&staging_name), 0o700)?;
    let mut cleanup = ProvisionCleanup::new(staging_dir.clone(), paths.state_disk.clone());
    let workspace = staging_dir.join("workspace");
    let home = staging_dir.join("home");
    fs::create_dir(&workspace).map_err(|source| WorkspaceError::Io {
        path: workspace.clone(),
        source,
    })?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o755)).map_err(|source| {
        WorkspaceError::Io {
            path: workspace.clone(),
            source,
        }
    })?;
    fs::create_dir(&home).map_err(|source| WorkspaceError::Io {
        path: home.clone(),
        source,
    })?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).map_err(|source| {
        WorkspaceError::Io {
            path: home.clone(),
            source,
        }
    })?;

    let content_limit = disk_bytes - MINIMUM_EXT4_HEADROOM;
    let mut total_bytes = 0_u64;
    for entry in entries {
        let size_text = git_text(&top_level, &["cat-file", "-s", &entry.object_id])?;
        let size = size_text
            .trim()
            .parse::<u64>()
            .map_err(|_| WorkspaceError::InvalidObjectSize)?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(WorkspaceError::WorkspaceTooLarge)?;
        if total_bytes > content_limit || size > usize::MAX as u64 {
            return Err(WorkspaceError::WorkspaceTooLarge);
        }
        let object = git_output(
            &top_level,
            &["cat-file", "blob", &entry.object_id],
            usize::try_from(size).map_err(|_| WorkspaceError::WorkspaceTooLarge)?,
        )?;
        if object.stdout.starts_with(LFS_POINTER_PREFIX) {
            return Err(WorkspaceError::GitLfsUnsupported(entry.path));
        }
        write_tree_file(&workspace, &entry, &object.stdout)?;
    }

    let disk = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&paths.state_disk)
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;
    disk.set_len(disk_bytes)
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;
    drop(disk);
    format_ext4(&staging_dir, &paths.state_disk)?;
    File::open(&paths.state_disk)
        .and_then(|file| file.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;

    cleanup.remove_staging()?;
    cleanup.disarm_disk();
    Ok(WorkspaceSnapshot {
        source_path: top_level,
        commit,
        state_disk: paths.state_disk,
    })
}

fn git_text(source: &Path, arguments: &[&str]) -> Result<String, WorkspaceError> {
    let output = git_output(source, arguments, MAX_GIT_CONTROL_OUTPUT)?;
    String::from_utf8(output.stdout).map_err(|_| WorkspaceError::InvalidGitOutput)
}

fn git_output(
    source: &Path,
    arguments: &[&str],
    maximum_stdout: usize,
) -> Result<Output, WorkspaceError> {
    let output = Command::new(GIT)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.lfs.required=false",
            "-c",
            "filter.lfs.smudge=",
        ])
        .args(arguments)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    if !output.status.success() {
        return Err(WorkspaceError::GitCommandFailed);
    }
    // `cat-file` callers pass the exact object size. Control output receives a
    // separate fixed bound. One extra byte is not accepted as a benign drift.
    if output.stdout.len() > maximum_stdout {
        return Err(WorkspaceError::GitOutputTooLarge);
    }
    Ok(output)
}

fn parse_tree(bytes: &[u8]) -> Result<Vec<TreeEntry>, WorkspaceError> {
    let mut entries = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(WorkspaceError::InvalidTree)?;
        let header =
            std::str::from_utf8(&record[..tab]).map_err(|_| WorkspaceError::InvalidTree)?;
        let mut header = header.split_ascii_whitespace();
        let mode = header.next().ok_or(WorkspaceError::InvalidTree)?;
        let object_type = header.next().ok_or(WorkspaceError::InvalidTree)?;
        let object_id = header.next().ok_or(WorkspaceError::InvalidTree)?;
        if header.next().is_some() || object_type != "blob" || !valid_object_id(object_id) {
            return Err(WorkspaceError::UnsupportedTreeEntry);
        }
        let mode = match mode {
            "100644" => 0o644,
            "100755" => 0o755,
            "120000" => return Err(WorkspaceError::SymlinkUnsupported),
            "160000" => return Err(WorkspaceError::SubmoduleUnsupported),
            _ => return Err(WorkspaceError::UnsupportedTreeEntry),
        };
        let path = PathBuf::from(OsString::from_vec(record[tab + 1..].to_vec()));
        validate_tree_path(&path)?;
        if path == Path::new(".gitmodules") {
            return Err(WorkspaceError::SubmoduleUnsupported);
        }
        entries.push(TreeEntry {
            mode,
            object_id: object_id.to_owned(),
            path,
        });
    }
    Ok(entries)
}

fn validate_tree_path(path: &Path) -> Result<(), WorkspaceError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkspaceError::InvalidTreePath);
    }
    Ok(())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_tree_file(
    workspace: &Path,
    entry: &TreeEntry,
    contents: &[u8],
) -> Result<(), WorkspaceError> {
    let destination = workspace.join(&entry.path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|source| WorkspaceError::Io {
            path: parent.to_owned(),
            source,
        })?;
        // Every parent remains inside an owner-only staging root and contains
        // no symlink because Codewire created the tree from scratch.
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(|source| {
            WorkspaceError::Io {
                path: parent.to_owned(),
                source,
            }
        })?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(entry.mode)
        .open(&destination)
        .map_err(|source| WorkspaceError::Io {
            path: destination.clone(),
            source,
        })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: destination,
            source,
        })
}

fn format_ext4(staging: &Path, disk: &Path) -> Result<(), WorkspaceError> {
    let mkfs = ["/usr/sbin/mkfs.ext4", "/usr/bin/mkfs.ext4"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or(WorkspaceError::MkfsUnavailable)?;
    let status = Command::new(mkfs)
        .args([
            OsStr::new("-q"),
            OsStr::new("-F"),
            OsStr::new("-m"),
            OsStr::new("0"),
        ])
        .arg("-d")
        .arg(staging)
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| WorkspaceError::MkfsUnavailable)?;
    if !status.success() {
        return Err(WorkspaceError::MkfsFailed);
    }
    Ok(())
}

struct ProvisionCleanup {
    staging: Option<PathBuf>,
    disk: Option<PathBuf>,
}

impl ProvisionCleanup {
    fn new(staging: PathBuf, disk: PathBuf) -> Self {
        Self {
            staging: Some(staging),
            disk: Some(disk),
        }
    }

    fn remove_staging(&mut self) -> Result<(), WorkspaceError> {
        let staging = self
            .staging
            .take()
            .expect("armed provisioning cleanup has staging");
        fs::remove_dir_all(&staging).map_err(|source| WorkspaceError::Io {
            path: staging,
            source,
        })
    }

    fn disarm_disk(&mut self) {
        self.disk = None;
    }
}

impl Drop for ProvisionCleanup {
    fn drop(&mut self) {
        if let Some(staging) = self.staging.take() {
            let _ = fs::remove_dir_all(staging);
        }
        if let Some(disk) = self.disk.take() {
            let _ = fs::remove_file(disk);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace disk size is invalid: {0}")]
    InvalidDiskSize(u64),
    #[error("workspace source is not a directory: {0}")]
    SourceNotDirectory(PathBuf),
    #[error("--path must name the Git worktree root ({requested} is inside {root})")]
    SourceMustBeWorktreeRoot { requested: PathBuf, root: PathBuf },
    #[error("bare Git repositories are not supported")]
    BareRepository,
    #[error("workspace Git commit is invalid")]
    InvalidCommit,
    #[error("workspace has modified, staged, or untracked files; commit or clean it first")]
    DirtyWorktree,
    #[error("Git submodules are not supported by the native preview")]
    SubmoduleUnsupported,
    #[error("Git symlinks are not supported by the native preview")]
    SymlinkUnsupported,
    #[error("Git LFS content is not supported by the native preview: {0}")]
    GitLfsUnsupported(PathBuf),
    #[error("workspace contains an unsupported Git tree entry")]
    UnsupportedTreeEntry,
    #[error("workspace contains an invalid Git tree path")]
    InvalidTreePath,
    #[error("workspace Git tree is malformed")]
    InvalidTree,
    #[error("workspace Git object size is invalid")]
    InvalidObjectSize,
    #[error("workspace content does not fit on the requested disk")]
    WorkspaceTooLarge,
    #[error("/usr/bin/git is required for native clone-mode snapshots")]
    GitUnavailable,
    #[error("Git could not inspect the requested clean commit")]
    GitCommandFailed,
    #[error("Git output exceeded the native preview safety limit")]
    GitOutputTooLarge,
    #[error("Git returned invalid text")]
    InvalidGitOutput,
    #[error("workspace state disk already exists: {0}")]
    StateDiskAlreadyExists(PathBuf),
    #[error("mkfs.ext4 is required for native workspace provisioning")]
    MkfsUnavailable,
    #[error("mkfs.ext4 failed to create the workspace disk")]
    MkfsFailed,
    #[error(transparent)]
    Path(#[from] crate::linux::path::PathError),
    #[error(transparent)]
    State(#[from] crate::linux::state::StateError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_parser_accepts_only_regular_git_blobs() {
        let tree = b"100644 blob 0123456789012345678901234567890123456789\tREADME.md\0\
100755 blob abcdefabcdefabcdefabcdefabcdefabcdefabcd\tbin/run\0";
        let parsed = parse_tree(tree).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mode, 0o644);
        assert_eq!(parsed[1].mode, 0o755);
        assert_eq!(parsed[1].path, Path::new("bin/run"));
    }

    #[test]
    fn tree_parser_rejects_symlinks_submodules_and_traversal() {
        let hash = "0123456789012345678901234567890123456789";
        assert!(matches!(
            parse_tree(format!("120000 blob {hash}\tlink\0").as_bytes()),
            Err(WorkspaceError::SymlinkUnsupported)
        ));
        assert!(matches!(
            parse_tree(format!("160000 commit {hash}\tdep\0").as_bytes()),
            Err(WorkspaceError::UnsupportedTreeEntry | WorkspaceError::SubmoduleUnsupported)
        ));
        assert!(matches!(
            parse_tree(format!("100644 blob {hash}\t../escape\0").as_bytes()),
            Err(WorkspaceError::InvalidTreePath)
        ));
    }

    #[test]
    fn lfs_pointer_prefix_is_exact() {
        assert!(
            b"version https://git-lfs.github.com/spec/v1\noid sha256:x\n"
                .starts_with(LFS_POINTER_PREFIX)
        );
        assert!(!b"version https://example.invalid/spec/v1\n".starts_with(LFS_POINTER_PREFIX));
    }
}
