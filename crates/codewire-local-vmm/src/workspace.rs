//! Clean-Git workspace snapshot provisioning for the first native preview.
//!
//! Host worktree paths are used only to ask a fixed `/usr/bin/git` for the
//! checked-out commit and cleanliness. File contents come from Git object
//! bytes, never by following the host worktree, filters, hooks, or mounts.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

use uuid::Uuid;

use crate::linux::path::{PrivateRoot, current_uid};
use crate::linux::state::{MINIMUM_STATE_DISK_BYTES, StateDiskIdentity, VmPaths};

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
pub struct WorkspaceSource {
    pub source_path: PathBuf,
    pub commit: String,
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
    let source = inspect_clean_git_workspace(requested_source)?;
    let top_level = source.source_path;
    let commit = source.commit;
    let tree = git_output(
        &top_level,
        &["ls-tree", "-r", "-z", "--full-tree", &commit],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let entries = parse_tree(&tree.stdout)?;

    let engine_root = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine_root, vm_id)?;
    cleanup_provisioning_staging(&engine_root, vm_id)?;
    if fs::symlink_metadata(&paths.state_disk).is_ok() {
        return Err(WorkspaceError::StateDiskAlreadyExists(paths.state_disk));
    }
    let staging_name = provisioning_staging_name(vm_id);
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

pub fn inspect_clean_git_workspace(
    requested_source: &Path,
) -> Result<WorkspaceSource, WorkspaceError> {
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
    Ok(WorkspaceSource {
        source_path: top_level,
        commit,
    })
}

pub fn ensure_clean_git_workspace(
    engine_state_root: &Path,
    vm_id: Uuid,
    source: &WorkspaceSource,
    disk_bytes: u64,
) -> Result<WorkspaceSnapshot, WorkspaceError> {
    if !valid_object_id(&source.commit) || !source.source_path.is_absolute() {
        return Err(WorkspaceError::InvalidCommit);
    }
    let engine_root = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine_root, vm_id)?;
    cleanup_provisioning_staging(&engine_root, vm_id)?;
    match fs::symlink_metadata(&paths.state_disk) {
        Ok(_) => {
            let identity = StateDiskIdentity::capture(&paths.state_disk)?;
            if identity.file.size != disk_bytes {
                return Err(WorkspaceError::ExistingDiskSizeMismatch {
                    path: paths.state_disk,
                    expected: disk_bytes,
                    actual: identity.file.size,
                });
            }
            Ok(WorkspaceSnapshot {
                source_path: source.source_path.clone(),
                commit: source.commit.clone(),
                state_disk: paths.state_disk,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let admitted = inspect_clean_git_workspace(&source.source_path)?;
            if admitted != *source {
                return Err(WorkspaceError::SourceChanged);
            }
            provision_clean_git_workspace(engine_state_root, vm_id, &source.source_path, disk_bytes)
        }
        Err(source_error) => Err(WorkspaceError::Io {
            path: paths.state_disk,
            source: source_error,
        }),
    }
}

fn provisioning_staging_name(vm_id: Uuid) -> String {
    format!("provision-{vm_id}")
}

pub(crate) fn cleanup_interrupted_workspace_provisioning(
    engine_state_root: &Path,
    vm_id: Uuid,
) -> Result<(), WorkspaceError> {
    cleanup_provisioning_staging(&PrivateRoot::open(engine_state_root)?, vm_id)
}

fn cleanup_provisioning_staging(
    engine_root: &PrivateRoot,
    vm_id: Uuid,
) -> Result<(), WorkspaceError> {
    let staging = engine_root.path().join(provisioning_staging_name(vm_id));
    let metadata = match fs::symlink_metadata(&staging) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: staging,
                source,
            });
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(WorkspaceError::UnsafeProvisioningStaging(staging));
    }
    // RecordEnvironment commits this exact UUID-derived path before the
    // provisioning effect begins. Its contents are a disposable Git-object
    // assembly owned wholly by that effect, so an interrupted replay may
    // remove this one admitted tree after checking its root identity.
    fs::remove_dir_all(&staging).map_err(|source| WorkspaceError::Io {
        path: staging.clone(),
        source,
    })?;
    File::open(engine_root.path())
        .and_then(|root| root.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: engine_root.path().to_owned(),
            source,
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
    #[error("workspace provisioning staging path is unsafe: {0}")]
    UnsafeProvisioningStaging(PathBuf),
    #[error("workspace source changed after its create intent was recorded")]
    SourceChanged,
    #[error(
        "existing workspace disk has size {actual}, but the recorded manifest requires {expected}: {path}"
    )]
    ExistingDiskSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
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
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::symlink;

    use super::*;

    fn write_test_ext4(path: &Path, size: u64) {
        let mut disk = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        disk.set_len(size).unwrap();
        let mut superblock = [0_u8; 0x78];
        superblock[0x38..0x3a].copy_from_slice(&[0x53, 0xef]);
        superblock[0x68..0x78].copy_from_slice(Uuid::new_v4().as_bytes());
        disk.seek(SeekFrom::Start(1024)).unwrap();
        disk.write_all(&superblock).unwrap();
        disk.sync_all().unwrap();
    }

    #[test]
    fn replay_accepts_only_the_recorded_valid_existing_workspace_disk() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine_root = PrivateRoot::open(engine.path()).unwrap();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine_root, vm_id).unwrap();
        write_test_ext4(&paths.state_disk, MINIMUM_STATE_DISK_BYTES);
        let interrupted_staging = engine.path().join(provisioning_staging_name(vm_id));
        fs::create_dir(&interrupted_staging).unwrap();
        fs::set_permissions(&interrupted_staging, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(interrupted_staging.join("partial-object"), b"partial").unwrap();
        let source = WorkspaceSource {
            source_path: PathBuf::from("/source/no-longer-required"),
            commit: "a".repeat(40),
        };

        let snapshot =
            ensure_clean_git_workspace(engine.path(), vm_id, &source, MINIMUM_STATE_DISK_BYTES)
                .unwrap();
        assert_eq!(snapshot.source_path, source.source_path);
        assert_eq!(snapshot.commit, source.commit);
        assert_eq!(snapshot.state_disk, paths.state_disk);
        assert!(!interrupted_staging.exists());

        assert!(matches!(
            ensure_clean_git_workspace(
                engine.path(),
                vm_id,
                &source,
                MINIMUM_STATE_DISK_BYTES + 1024 * 1024,
            ),
            Err(WorkspaceError::ExistingDiskSizeMismatch { .. })
        ));
    }

    #[test]
    fn replay_refuses_a_replaced_workspace_staging_root() {
        let parent = tempfile::tempdir().unwrap();
        let engine = parent.path().join("engine");
        let outside = parent.path().join("outside");
        fs::create_dir(&engine).unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"preserve").unwrap();
        let vm_id = Uuid::new_v4();
        let staging = engine.join(provisioning_staging_name(vm_id));
        symlink(&outside, &staging).unwrap();
        let source = WorkspaceSource {
            source_path: PathBuf::from("/source/no-longer-required"),
            commit: "a".repeat(40),
        };

        assert!(matches!(
            ensure_clean_git_workspace(
                &engine,
                vm_id,
                &source,
                MINIMUM_STATE_DISK_BYTES,
            ),
            Err(WorkspaceError::UnsafeProvisioningStaging(path)) if path == staging
        ));
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"preserve");
    }

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
