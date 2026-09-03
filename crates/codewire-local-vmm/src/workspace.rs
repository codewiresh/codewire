//! Environment-owned workspace preparation for the native runtime.
//!
//! Git worktrees are cloned from committed state. Ordinary directories are
//! copied through dirfd-relative, no-follow traversal. Neither preparation
//! leaves a host mount attached to the VM.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, openat2, readlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::linux::path::{PrivateRoot, current_uid};
use crate::linux::state::{MINIMUM_STATE_DISK_BYTES, StateDiskIdentity, VmPaths};
use crate::oci::ContentStore;
use crate::workspace_plan::{WorkspaceInput, WorkspacePlan};
use codewire_vmm_guest_probe::DIRECT_SHARE_PLAN_RELATIVE_PATH;

const GIT: &str = "/usr/bin/git";
const MAX_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const MINIMUM_EXT4_HEADROOM: u64 = 128 * 1024 * 1024;
const MAXIMUM_COPY_ENTRIES: u64 = 1_000_000;
const MAXIMUM_COPY_DEPTH: usize = 128;
const MAXIMUM_COPY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const COPY_MANIFEST_SCHEMA: &[u8] = b"codewire-workspace-copy-v1\0";
const RESOLVE_SOURCE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

pub fn workspace_content_limit(disk_bytes: u64) -> u64 {
    disk_bytes.saturating_sub(MINIMUM_EXT4_HEADROOM)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceSelection {
    Auto,
    Clone,
    Copy,
    Direct,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSourceMode {
    Clone,
    Copy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    pub source_path: PathBuf,
    pub commit: String,
    pub mode: WorkspaceSourceMode,
    pub state_disk: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSource {
    pub source_path: PathBuf,
    pub commit: String,
    pub mode: WorkspaceSourceMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspacePlanSnapshot {
    pub(crate) plan_sha256: String,
    pub(crate) state_disk: PathBuf,
}

#[derive(Debug)]
struct SourceDirectory {
    path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct DirectorySnapshot {
    pub(crate) sha256: String,
    pub(crate) regular_bytes: u64,
    pub(crate) entries: u64,
}

pub fn resolve_workspace_mode(
    requested_source: &Path,
    requested_mode: WorkspaceSelection,
) -> Result<WorkspaceSourceMode, WorkspaceError> {
    let source = open_source_directory(requested_source)?;
    match requested_mode {
        WorkspaceSelection::Auto => match fs::symlink_metadata(source.path.join(".git")) {
            Ok(metadata) if metadata.is_dir() || metadata.is_file() => {
                Ok(WorkspaceSourceMode::Clone)
            }
            Ok(_) => Err(WorkspaceError::UnsafeGitMarker(source.path.join(".git"))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(WorkspaceSourceMode::Copy),
            Err(source_error) => Err(WorkspaceError::Io {
                path: source.path.join(".git"),
                source: source_error,
            }),
        },
        WorkspaceSelection::Clone => Ok(WorkspaceSourceMode::Clone),
        WorkspaceSelection::Copy => Ok(WorkspaceSourceMode::Copy),
        WorkspaceSelection::Direct => Err(WorkspaceError::DirectModeUnavailable),
    }
}

pub fn inspect_workspace(
    requested_source: &Path,
    requested_mode: WorkspaceSelection,
    maximum_copy_bytes: u64,
) -> Result<WorkspaceSource, WorkspaceError> {
    match resolve_workspace_mode(requested_source, requested_mode)? {
        WorkspaceSourceMode::Clone => inspect_clean_git_workspace(requested_source),
        WorkspaceSourceMode::Copy => {
            inspect_copy_workspace(requested_source, maximum_copy_bytes.min(MAXIMUM_COPY_BYTES))
        }
    }
}

/// Create a sparse ext4 state disk containing `workspace/` and `home/`.
/// The destination must not already exist. A failed operation removes only the
/// UUID-named staging directory and the newly-created incomplete disk.
fn provision_workspace(
    engine_state_root: &Path,
    vm_id: Uuid,
    source: &WorkspaceSource,
    disk_bytes: u64,
) -> Result<WorkspaceSnapshot, WorkspaceError> {
    if disk_bytes < MINIMUM_STATE_DISK_BYTES
        || !disk_bytes.is_multiple_of(1024 * 1024)
        || disk_bytes <= MINIMUM_EXT4_HEADROOM
    {
        return Err(WorkspaceError::InvalidDiskSize(disk_bytes));
    }
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

    let content_limit = workspace_content_limit(disk_bytes);
    let prepared_identity = match source.mode {
        WorkspaceSourceMode::Clone => {
            prepare_git_clone(source, &workspace, &staging_dir)?;
            let bytes = bounded_staging_regular_bytes(&workspace, content_limit)?;
            if bytes > content_limit {
                return Err(WorkspaceError::WorkspaceTooLarge);
            }
            source.commit.clone()
        }
        WorkspaceSourceMode::Copy => {
            let manifest = copy_directory_manifest(
                &open_source_directory(&source.source_path)?,
                Some(&workspace),
                content_limit,
                MAXIMUM_COPY_ENTRIES,
            )?;
            manifest.sha256
        }
    };
    if prepared_identity != source.commit {
        return Err(WorkspaceError::SourceChanged);
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
        .and_then(|()| File::open(&paths.disks_dir)?.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;

    cleanup.remove_staging()?;
    cleanup.disarm_disk();
    Ok(WorkspaceSnapshot {
        source_path: source.source_path.clone(),
        commit: source.commit.clone(),
        mode: source.mode,
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
    reject_git_submodules(&top_level, &commit)?;
    let status = git_output(
        &top_level,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    if !status.stdout.is_empty() {
        return Err(WorkspaceError::DirtyWorktree);
    }
    Ok(WorkspaceSource {
        source_path: top_level,
        commit,
        mode: WorkspaceSourceMode::Clone,
    })
}

fn inspect_copy_workspace(
    requested_source: &Path,
    maximum_bytes: u64,
) -> Result<WorkspaceSource, WorkspaceError> {
    let source = open_source_directory(requested_source)?;
    let manifest = copy_directory_manifest(&source, None, maximum_bytes, MAXIMUM_COPY_ENTRIES)?;
    Ok(WorkspaceSource {
        source_path: source.path,
        commit: manifest.sha256,
        mode: WorkspaceSourceMode::Copy,
    })
}

pub fn ensure_workspace(
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
                mode: source.mode,
                state_disk: paths.state_disk,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let selection = match source.mode {
                WorkspaceSourceMode::Clone => WorkspaceSelection::Clone,
                WorkspaceSourceMode::Copy => WorkspaceSelection::Copy,
            };
            let admitted = inspect_workspace(
                &source.source_path,
                selection,
                workspace_content_limit(disk_bytes),
            )?;
            if admitted != *source {
                return Err(WorkspaceError::SourceChanged);
            }
            provision_workspace(engine_state_root, vm_id, source, disk_bytes)
        }
        Err(source_error) => Err(WorkspaceError::Io {
            path: paths.state_disk,
            source: source_error,
        }),
    }
}

pub(crate) fn ensure_workspace_plan(
    engine_state_root: &Path,
    vm_id: Uuid,
    plan: &WorkspacePlan,
    disk_bytes: u64,
) -> Result<WorkspacePlanSnapshot, WorkspaceError> {
    plan.validate()?;
    let plan_sha256 = plan.sha256()?;
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
            Ok(WorkspacePlanSnapshot {
                plan_sha256,
                state_disk: paths.state_disk,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            provision_workspace_plan(engine_state_root, vm_id, plan, disk_bytes)
        }
        Err(source_error) => Err(WorkspaceError::Io {
            path: paths.state_disk,
            source: source_error,
        }),
    }
}

fn provision_workspace_plan(
    engine_state_root: &Path,
    vm_id: Uuid,
    plan: &WorkspacePlan,
    disk_bytes: u64,
) -> Result<WorkspacePlanSnapshot, WorkspaceError> {
    plan.validate()?;
    if disk_bytes < MINIMUM_STATE_DISK_BYTES
        || !disk_bytes.is_multiple_of(1024 * 1024)
        || disk_bytes <= MINIMUM_EXT4_HEADROOM
    {
        return Err(WorkspaceError::InvalidDiskSize(disk_bytes));
    }
    let engine_root = PrivateRoot::open(engine_state_root)?;
    let content = ContentStore::create(&engine_root)?;
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

    for input in &plan.inputs {
        let destination = staging_workspace_destination(&staging_dir, input.destination())?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| WorkspaceError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }
        match input {
            WorkspaceInput::Local { identity, mode, .. } => {
                let source = input
                    .local_source()
                    .ok_or(WorkspaceError::InvalidWorkspacePlan)?;
                let admitted = inspect_workspace(
                    &source.source_path,
                    match mode {
                        WorkspaceSourceMode::Clone => WorkspaceSelection::Clone,
                        WorkspaceSourceMode::Copy => WorkspaceSelection::Copy,
                    },
                    workspace_content_limit(disk_bytes),
                )?;
                if admitted != source {
                    return Err(WorkspaceError::SourceChanged);
                }
                match mode {
                    WorkspaceSourceMode::Clone => {
                        prepare_git_clone(&source, &destination, &staging_dir)?;
                    }
                    WorkspaceSourceMode::Copy => {
                        prepare_copy_input(
                            &source,
                            identity,
                            &destination,
                            &workspace,
                            workspace_content_limit(disk_bytes),
                        )?;
                    }
                }
            }
            WorkspaceInput::Direct { .. } => {
                let forbidden_roots = [engine_state_root.to_owned()];
                input
                    .direct_source(&forbidden_roots)
                    .map_err(|_| WorkspaceError::SourceChanged)?
                    .ok_or(WorkspaceError::InvalidWorkspacePlan)?;
                fs::create_dir(&destination).map_err(|source| WorkspaceError::Io {
                    path: destination.clone(),
                    source,
                })?;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).map_err(
                    |source| WorkspaceError::Io {
                        path: destination.clone(),
                        source,
                    },
                )?;
            }
            WorkspaceInput::Repository {
                source,
                commit,
                branch,
                bundle_digest,
                bundle_size,
                ..
            } => {
                let bundle = content.verified_blob_path(bundle_digest, *bundle_size)?;
                prepare_git_bundle(&bundle, &destination, &staging_dir, source, commit, branch)?;
            }
        }
    }
    if let Some(direct_shares) = plan.direct_share_plan()? {
        let bytes = direct_shares
            .encode_canonical()
            .map_err(|_| WorkspaceError::InvalidWorkspacePlan)?;
        let path = staging_dir.join(DIRECT_SHARE_PLAN_RELATIVE_PATH);
        let parent = path.parent().ok_or(WorkspaceError::InvalidWorkspacePlan)?;
        fs::create_dir(parent).map_err(|source| WorkspaceError::Io {
            path: parent.to_owned(),
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            WorkspaceError::Io {
                path: parent.to_owned(),
                source,
            }
        })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o400)
            .open(&path)
            .map_err(|source| WorkspaceError::Io {
                path: path.clone(),
                source,
            })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| WorkspaceError::Io { path, source })?;
    }
    bounded_staging_regular_bytes(&workspace, workspace_content_limit(disk_bytes))?;

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
        .and_then(|()| File::open(&paths.disks_dir)?.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;

    cleanup.remove_staging()?;
    cleanup.disarm_disk();
    Ok(WorkspacePlanSnapshot {
        plan_sha256: plan.sha256()?,
        state_disk: paths.state_disk,
    })
}

fn prepare_copy_input(
    source: &WorkspaceSource,
    identity: &str,
    destination: &Path,
    workspace: &Path,
    maximum_bytes: u64,
) -> Result<(), WorkspaceError> {
    let existing_bytes = bounded_staging_regular_bytes(workspace, maximum_bytes)?;
    let remaining_bytes = maximum_bytes
        .checked_sub(existing_bytes)
        .ok_or(WorkspaceError::WorkspaceTooLarge)?;
    if destination != workspace {
        fs::create_dir(destination).map_err(|source| WorkspaceError::Io {
            path: destination.to_owned(),
            source,
        })?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).map_err(|source| {
            WorkspaceError::Io {
                path: destination.to_owned(),
                source,
            }
        })?;
    }
    let manifest = copy_directory_manifest(
        &open_source_directory(&source.source_path)?,
        Some(destination),
        remaining_bytes,
        MAXIMUM_COPY_ENTRIES,
    )?;
    if manifest.sha256 != identity {
        return Err(WorkspaceError::SourceChanged);
    }
    Ok(())
}

fn staging_workspace_destination(
    staging: &Path,
    destination: &str,
) -> Result<PathBuf, WorkspaceError> {
    if destination == "/workspace" {
        return Ok(staging.join("workspace"));
    }
    let relative = destination
        .strip_prefix("/workspace/")
        .ok_or(WorkspaceError::InvalidWorkspacePlan)?;
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(WorkspaceError::InvalidWorkspacePlan);
    }
    Ok(staging.join("workspace").join(relative))
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
    let stdout_limit = maximum_stdout
        .checked_add(1)
        .ok_or(WorkspaceError::GitOutputTooLarge)? as u64;
    let mut command = Command::new(GIT);
    command
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
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    let mut stdout = Vec::new();
    let Some(pipe) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkspaceError::GitCommandFailed);
    };
    if pipe.take(stdout_limit).read_to_end(&mut stdout).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkspaceError::GitCommandFailed);
    }
    if stdout.len() > maximum_stdout {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkspaceError::GitOutputTooLarge);
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkspaceError::GitCommandFailed);
        }
    };
    let output = Output {
        status,
        stdout,
        stderr: Vec::new(),
    };
    if !output.status.success() {
        return Err(WorkspaceError::GitCommandFailed);
    }
    Ok(output)
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn open_source_directory(requested_source: &Path) -> Result<SourceDirectory, WorkspaceError> {
    let path = fs::canonicalize(requested_source).map_err(|source| WorkspaceError::Io {
        path: requested_source.to_owned(),
        source,
    })?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|source| WorkspaceError::Io {
            path: path.clone(),
            source,
        })?;
    let opened = directory.metadata().map_err(|source| WorkspaceError::Io {
        path: path.clone(),
        source,
    })?;
    let named = fs::symlink_metadata(&path).map_err(|source| WorkspaceError::Io {
        path: path.clone(),
        source,
    })?;
    if !opened.is_dir() || !named.is_dir() {
        return Err(WorkspaceError::SourceNotDirectory(path));
    }
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(WorkspaceError::SourceRootChanged(path));
    }
    Ok(SourceDirectory {
        path,
        directory,
        device: opened.dev(),
        inode: opened.ino(),
    })
}

fn verify_source_root(source: &SourceDirectory) -> Result<(), WorkspaceError> {
    let named = fs::symlink_metadata(&source.path).map_err(|source_error| WorkspaceError::Io {
        path: source.path.clone(),
        source: source_error,
    })?;
    if !named.is_dir() || named.dev() != source.device || named.ino() != source.inode {
        return Err(WorkspaceError::SourceRootChanged(source.path.clone()));
    }
    Ok(())
}

struct CopyWalk {
    hasher: Sha256,
    regular_bytes: u64,
    entries: u64,
    maximum_bytes: u64,
    maximum_entries: u64,
}

fn copy_directory_manifest(
    source: &SourceDirectory,
    destination: Option<&Path>,
    maximum_bytes: u64,
    maximum_entries: u64,
) -> Result<DirectorySnapshot, WorkspaceError> {
    let mut walk = CopyWalk {
        hasher: Sha256::new(),
        regular_bytes: 0,
        entries: 0,
        maximum_bytes,
        maximum_entries,
    };
    walk.hasher.update(COPY_MANIFEST_SCHEMA);
    copy_directory_level(
        source,
        &source.directory,
        Path::new(""),
        destination,
        0,
        &mut walk,
    )?;
    verify_source_root(source)?;
    Ok(DirectorySnapshot {
        sha256: format!("{:x}", walk.hasher.finalize()),
        regular_bytes: walk.regular_bytes,
        entries: walk.entries,
    })
}

/// Copy one exact relative directory beneath an already-selected root using
/// the same no-follow, no-mount-crossing and race-detecting walk as workspace
/// copies. The selected directory itself may not be a symlink.
pub(crate) fn snapshot_confined_directory(
    requested_root: &Path,
    relative: &Path,
    destination: &Path,
    maximum_bytes: u64,
    maximum_entries: u64,
) -> Result<DirectorySnapshot, WorkspaceError> {
    let root = open_source_directory(requested_root)?;
    if root.path != requested_root {
        return Err(WorkspaceError::SourceRootChanged(requested_root.to_owned()));
    }
    snapshot_confined_source_directory(root, relative, destination, maximum_bytes, maximum_entries)
}

/// Copy from an exact already-admitted directory descriptor. This keeps a
/// direct-share identity pinned while the selected skill is snapshotted and
/// still rejects a renamed or replaced host path.
pub(crate) fn snapshot_confined_open_directory(
    requested_root: &Path,
    root_descriptor: BorrowedFd<'_>,
    relative: &Path,
    destination: &Path,
    maximum_bytes: u64,
    maximum_entries: u64,
) -> Result<DirectorySnapshot, WorkspaceError> {
    let directory = openat2(
        root_descriptor,
        Path::new("."),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE.union(ResolveFlags::NO_SYMLINKS),
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: requested_root.to_owned(),
        source,
    })?;
    let directory = File::from(directory);
    let metadata = directory.metadata().map_err(|source| WorkspaceError::Io {
        path: requested_root.to_owned(),
        source,
    })?;
    let root = SourceDirectory {
        path: requested_root.to_owned(),
        directory,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    verify_source_root(&root)?;
    snapshot_confined_source_directory(root, relative, destination, maximum_bytes, maximum_entries)
}

fn snapshot_confined_source_directory(
    root: SourceDirectory,
    relative: &Path,
    destination: &Path,
    maximum_bytes: u64,
    maximum_entries: u64,
) -> Result<DirectorySnapshot, WorkspaceError> {
    if relative.as_os_str().is_empty() {
        return copy_directory_manifest(&root, Some(destination), maximum_bytes, maximum_entries);
    }
    validate_copy_path(relative)?;
    let selected_path = root.path.join(relative);
    let directory = openat2(
        root.directory.as_fd(),
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE.union(ResolveFlags::NO_SYMLINKS),
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: selected_path.clone(),
        source,
    })?;
    let directory = File::from(directory);
    let metadata = directory.metadata().map_err(|source| WorkspaceError::Io {
        path: selected_path.clone(),
        source,
    })?;
    if !metadata.is_dir() || metadata.dev() != root.device {
        return Err(WorkspaceError::SourceMountBoundary(relative.to_owned()));
    }
    let source = SourceDirectory {
        path: selected_path.clone(),
        directory,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let snapshot =
        copy_directory_manifest(&source, Some(destination), maximum_bytes, maximum_entries)?;

    let reopened = openat2(
        root.directory.as_fd(),
        relative,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE.union(ResolveFlags::NO_SYMLINKS),
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: selected_path.clone(),
        source,
    })?;
    let reopened = rustix::fs::fstat(&reopened).map_err(|source| WorkspaceError::SourceOpen {
        path: selected_path.clone(),
        source,
    })?;
    if reopened.st_dev != metadata.dev() || reopened.st_ino != metadata.ino() {
        return Err(WorkspaceError::SourceRootChanged(selected_path));
    }
    verify_source_root(&root)?;
    Ok(snapshot)
}

pub(crate) fn manifest_directory(
    requested_root: &Path,
    maximum_bytes: u64,
    maximum_entries: u64,
) -> Result<DirectorySnapshot, WorkspaceError> {
    let source = open_source_directory(requested_root)?;
    if source.path != requested_root {
        return Err(WorkspaceError::SourceRootChanged(requested_root.to_owned()));
    }
    copy_directory_manifest(&source, None, maximum_bytes, maximum_entries)
}

fn copy_directory_level(
    source: &SourceDirectory,
    directory: &File,
    relative: &Path,
    destination_root: Option<&Path>,
    depth: usize,
    walk: &mut CopyWalk,
) -> Result<(), WorkspaceError> {
    if depth > MAXIMUM_COPY_DEPTH {
        return Err(WorkspaceError::CopyDepthExceeded);
    }
    let before = directory
        .metadata()
        .map_err(|source_error| WorkspaceError::Io {
            path: source.path.join(relative),
            source: source_error,
        })?;
    let mut entries =
        Dir::read_from(directory.as_fd()).map_err(|source_error| WorkspaceError::SourceOpen {
            path: source.path.join(relative),
            source: source_error,
        })?;
    let mut names = Vec::new();
    for entry in &mut entries {
        let entry = entry.map_err(|source_error| WorkspaceError::SourceOpen {
            path: source.path.join(relative),
            source: source_error,
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if bytes.is_empty() || bytes.contains(&b'/') {
            return Err(WorkspaceError::InvalidCopyPath(relative.to_owned()));
        }
        if names.len() as u64 == walk.maximum_entries {
            return Err(WorkspaceError::CopyEntryLimitExceeded);
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        walk.entries = walk
            .entries
            .checked_add(1)
            .ok_or(WorkspaceError::WorkspaceTooLarge)?;
        if walk.entries > walk.maximum_entries {
            return Err(WorkspaceError::CopyEntryLimitExceeded);
        }
        let entry_relative = relative.join(&name);
        validate_copy_path(&entry_relative)?;
        let identity = open_source_entry(directory, Path::new(&name), &entry_relative)?;
        let metadata = identity
            .metadata()
            .map_err(|source_error| WorkspaceError::Io {
                path: source.path.join(&entry_relative),
                source: source_error,
            })?;
        if metadata.dev() != source.device {
            return Err(WorkspaceError::SourceMountBoundary(entry_relative));
        }
        let destination = destination_root.map(|root| root.join(&entry_relative));
        if metadata.is_dir() {
            let mode = safe_copy_mode(&entry_relative, &metadata)?;
            record_copy_entry(walk, b'd', &entry_relative, mode, 0);
            let child = open_source_directory_entry(directory, Path::new(&name), &entry_relative)?;
            if let Some(destination) = destination.as_ref() {
                fs::create_dir(destination).map_err(|source_error| WorkspaceError::Io {
                    path: destination.clone(),
                    source: source_error,
                })?;
                fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).map_err(
                    |source_error| WorkspaceError::Io {
                        path: destination.clone(),
                        source: source_error,
                    },
                )?;
            }
            copy_directory_level(
                source,
                &child,
                &entry_relative,
                destination_root,
                depth + 1,
                walk,
            )?;
            if let Some(destination) = destination.as_ref() {
                fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(
                    |source_error| WorkspaceError::Io {
                        path: destination.clone(),
                        source: source_error,
                    },
                )?;
            }
        } else if metadata.is_file() {
            let mode = safe_copy_mode(&entry_relative, &metadata)?;
            let mut input =
                open_source_regular_entry(directory, Path::new(&name), &entry_relative)?;
            let opened = input
                .metadata()
                .map_err(|source_error| WorkspaceError::Io {
                    path: source.path.join(&entry_relative),
                    source: source_error,
                })?;
            if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
                return Err(WorkspaceError::SourceEntryChanged(entry_relative));
            }
            walk.regular_bytes = walk
                .regular_bytes
                .checked_add(opened.len())
                .ok_or(WorkspaceError::WorkspaceTooLarge)?;
            if walk.regular_bytes > walk.maximum_bytes {
                return Err(WorkspaceError::WorkspaceTooLarge);
            }
            record_copy_entry(walk, b'f', &entry_relative, mode, opened.len());
            copy_regular_contents(
                source,
                &entry_relative,
                &mut input,
                &opened,
                destination.as_deref(),
                mode,
                walk,
            )?;
        } else if metadata.file_type().is_symlink() {
            let target =
                readlinkat(&identity, Path::new(""), Vec::new()).map_err(|source_error| {
                    WorkspaceError::SourceOpen {
                        path: source.path.join(&entry_relative),
                        source: source_error,
                    }
                })?;
            let target = PathBuf::from(OsString::from_vec(target.to_bytes().to_vec()));
            validate_internal_symlink(&entry_relative, &target)?;
            record_copy_entry(
                walk,
                b'l',
                &entry_relative,
                0,
                target.as_os_str().as_bytes().len() as u64,
            );
            walk.hasher.update(target.as_os_str().as_bytes());
            if let Some(destination) = destination.as_ref() {
                symlink(&target, destination).map_err(|source_error| WorkspaceError::Io {
                    path: destination.clone(),
                    source: source_error,
                })?;
            }
        } else {
            return Err(WorkspaceError::UnsupportedCopyEntry(entry_relative));
        }
    }

    let after = directory
        .metadata()
        .map_err(|source_error| WorkspaceError::Io {
            path: source.path.join(relative),
            source: source_error,
        })?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(WorkspaceError::SourceEntryChanged(relative.to_owned()));
    }
    Ok(())
}

fn open_source_entry(
    directory: &File,
    name: &Path,
    relative: &Path,
) -> Result<File, WorkspaceError> {
    let owned = openat2(
        directory.as_fd(),
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE,
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: relative.to_owned(),
        source,
    })?;
    Ok(File::from(owned))
}

fn open_source_directory_entry(
    directory: &File,
    name: &Path,
    relative: &Path,
) -> Result<File, WorkspaceError> {
    let owned = openat2(
        directory.as_fd(),
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE,
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: relative.to_owned(),
        source,
    })?;
    Ok(File::from(owned))
}

fn open_source_regular_entry(
    directory: &File,
    name: &Path,
    relative: &Path,
) -> Result<File, WorkspaceError> {
    let owned = openat2(
        directory.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SOURCE,
    )
    .map_err(|source| WorkspaceError::SourceOpen {
        path: relative.to_owned(),
        source,
    })?;
    Ok(File::from(owned))
}

fn validate_copy_path(path: &Path) -> Result<(), WorkspaceError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().count() > MAXIMUM_COPY_DEPTH
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkspaceError::InvalidCopyPath(path.to_owned()));
    }
    Ok(())
}

fn safe_copy_mode(path: &Path, metadata: &fs::Metadata) -> Result<u32, WorkspaceError> {
    let mode = metadata.permissions().mode();
    if mode & 0o7000 != 0 {
        return Err(WorkspaceError::UnsafeCopyMode(path.to_owned()));
    }
    Ok(mode & 0o777)
}

fn validate_internal_symlink(path: &Path, target: &Path) -> Result<(), WorkspaceError> {
    if target.as_os_str().is_empty() || target.is_absolute() {
        return Err(WorkspaceError::UnsafeCopySymlink(path.to_owned()));
    }
    let mut depth = path
        .parent()
        .map_or(0, |parent| parent.components().count());
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceError::UnsafeCopySymlink(path.to_owned()));
            }
        }
    }
    Ok(())
}

fn record_copy_entry(walk: &mut CopyWalk, kind: u8, path: &Path, mode: u32, size: u64) {
    let bytes = path.as_os_str().as_bytes();
    walk.hasher.update([kind]);
    walk.hasher.update((bytes.len() as u64).to_le_bytes());
    walk.hasher.update(bytes);
    walk.hasher.update(mode.to_le_bytes());
    walk.hasher.update(size.to_le_bytes());
}

fn copy_regular_contents(
    source: &SourceDirectory,
    relative: &Path,
    input: &mut File,
    expected: &fs::Metadata,
    destination: Option<&Path>,
    mode: u32,
    walk: &mut CopyWalk,
) -> Result<(), WorkspaceError> {
    let mut output = destination
        .map(|destination| {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(destination)
                .map_err(|source_error| WorkspaceError::Io {
                    path: destination.to_owned(),
                    source: source_error,
                })
        })
        .transpose()?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied_bytes = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|source_error| WorkspaceError::Io {
                path: source.path.join(relative),
                source: source_error,
            })?;
        if read == 0 {
            break;
        }
        copied_bytes = copied_bytes
            .checked_add(read as u64)
            .ok_or(WorkspaceError::WorkspaceTooLarge)?;
        if copied_bytes > expected.len() {
            return Err(WorkspaceError::SourceEntryChanged(relative.to_owned()));
        }
        walk.hasher.update(&buffer[..read]);
        if let Some(output) = output.as_mut() {
            output
                .write_all(&buffer[..read])
                .map_err(|source_error| WorkspaceError::Io {
                    path: destination.expect("output has destination").to_owned(),
                    source: source_error,
                })?;
        }
    }
    if copied_bytes != expected.len() {
        return Err(WorkspaceError::SourceEntryChanged(relative.to_owned()));
    }
    let after = input
        .metadata()
        .map_err(|source_error| WorkspaceError::Io {
            path: source.path.join(relative),
            source: source_error,
        })?;
    if expected.dev() != after.dev()
        || expected.ino() != after.ino()
        || expected.len() != after.len()
        || expected.mtime() != after.mtime()
        || expected.mtime_nsec() != after.mtime_nsec()
        || expected.ctime() != after.ctime()
        || expected.ctime_nsec() != after.ctime_nsec()
    {
        return Err(WorkspaceError::SourceEntryChanged(relative.to_owned()));
    }
    if let (Some(mut output), Some(destination)) = (output, destination) {
        output.flush().map_err(|source_error| WorkspaceError::Io {
            path: destination.to_owned(),
            source: source_error,
        })?;
        output
            .sync_all()
            .map_err(|source_error| WorkspaceError::Io {
                path: destination.to_owned(),
                source: source_error,
            })?;
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(
            |source_error| WorkspaceError::Io {
                path: destination.to_owned(),
                source: source_error,
            },
        )?;
    }
    Ok(())
}

pub(crate) fn prepare_git_clone(
    source: &WorkspaceSource,
    workspace: &Path,
    staging: &Path,
) -> Result<(), WorkspaceError> {
    reject_git_submodules(&source.source_path, &source.commit)?;
    let template = staging.join("git-template");
    fs::create_dir(&template).map_err(|source_error| WorkspaceError::Io {
        path: template.clone(),
        source: source_error,
    })?;
    let output = git_clone_output(&source.source_path, workspace, &template)?;
    if !output.status.success() {
        return Err(WorkspaceError::GitCloneFailed);
    }
    fs::remove_dir(&template).map_err(|source_error| WorkspaceError::Io {
        path: template,
        source: source_error,
    })?;
    git_output(
        workspace,
        &["checkout", "--detach", "--force", &source.commit],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let head = git_text(workspace, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head.trim() != source.commit {
        return Err(WorkspaceError::SourceChanged);
    }
    let object_format = git_text(workspace, &["rev-parse", "--show-object-format"])?;
    write_sanitized_git_config(workspace, object_format.trim())?;
    remove_git_trace_files(workspace)?;
    remove_unselected_git_refs(workspace)?;
    git_output(
        workspace,
        &["reflog", "expire", "--expire=now", "--all"],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    git_output(workspace, &["repack", "-Ad"], MAX_GIT_CONTROL_OUTPUT)?;
    git_output(
        workspace,
        &["prune", "--expire=now"],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let alternates = workspace.join(".git/objects/info/alternates");
    if fs::symlink_metadata(&alternates).is_ok() {
        return Err(WorkspaceError::GitAlternatesPresent);
    }
    let status = git_output(
        workspace,
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
        return Err(WorkspaceError::GitCloneNotClean);
    }
    Ok(())
}

pub(crate) fn prepare_git_bundle(
    bundle: &Path,
    workspace: &Path,
    staging: &Path,
    source: &str,
    commit: &str,
    branch: &str,
) -> Result<(), WorkspaceError> {
    if !valid_object_id(commit) {
        return Err(WorkspaceError::InvalidCommit);
    }
    let template = staging.join(format!("git-template-{}", Uuid::new_v4()));
    fs::create_dir(&template).map_err(|source_error| WorkspaceError::Io {
        path: template.clone(),
        source: source_error,
    })?;
    import_git_bundle(bundle, workspace, &template)?;
    fs::remove_dir(&template).map_err(|source_error| WorkspaceError::Io {
        path: template,
        source: source_error,
    })?;
    git_output(
        workspace,
        &["checkout", "--detach", "--force", commit],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let head = git_text(workspace, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head.trim() != commit {
        return Err(WorkspaceError::SourceChanged);
    }
    reject_git_submodules(workspace, commit)?;
    let object_format = git_text(workspace, &["rev-parse", "--show-object-format"])?;
    remove_git_trace_files(workspace)?;
    remove_unselected_git_refs(workspace)?;
    if !branch.is_empty() {
        let local_ref = format!("refs/heads/{branch}");
        let remote_ref = format!("refs/remotes/origin/{branch}");
        git_output(
            workspace,
            &["update-ref", &local_ref, commit],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
        git_output(
            workspace,
            &["update-ref", &remote_ref, commit],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
        git_output(
            workspace,
            &["symbolic-ref", "HEAD", &local_ref],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
        git_output(
            workspace,
            &["reset", "--hard", commit],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
    }
    write_repository_git_config(workspace, object_format.trim(), source, branch)?;
    git_output(
        workspace,
        &["reflog", "expire", "--expire=now", "--all"],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    git_output(workspace, &["repack", "-Ad"], MAX_GIT_CONTROL_OUTPUT)?;
    git_output(
        workspace,
        &["prune", "--expire=now"],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    let alternates = workspace.join(".git/objects/info/alternates");
    if fs::symlink_metadata(&alternates).is_ok() {
        return Err(WorkspaceError::GitAlternatesPresent);
    }
    let status = git_output(
        workspace,
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
        return Err(WorkspaceError::GitCloneNotClean);
    }
    Ok(())
}

fn import_git_bundle(
    bundle: &Path,
    destination: &Path,
    template: &Path,
) -> Result<(), WorkspaceError> {
    let initialized = Command::new(GIT)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "init",
            "--quiet",
            "--template",
        ])
        .arg(template)
        .arg("--")
        .arg(destination)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    if !initialized.success() {
        return Err(WorkspaceError::GitCloneFailed);
    }

    let fetched = Command::new(GIT)
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--quiet",
            "--no-tags",
            "--force",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "--",
        ])
        .arg(bundle)
        .arg("refs/codewire/source:refs/codewire/source")
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    if !fetched.success() {
        return Err(WorkspaceError::GitCloneFailed);
    }
    Ok(())
}

fn git_clone_output(
    source: &Path,
    destination: &Path,
    template: &Path,
) -> Result<Output, WorkspaceError> {
    Command::new(GIT)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--no-tags",
            "--dissociate",
            "--template",
        ])
        .arg(template)
        .arg("--")
        .arg(source)
        .arg(destination)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| WorkspaceError::GitUnavailable)
}

fn reject_git_submodules(source: &Path, commit: &str) -> Result<(), WorkspaceError> {
    let tree = git_output(
        source,
        &["ls-tree", "-r", "-z", "--full-tree", commit],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    for record in tree.stdout.split(|byte| *byte == 0) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            if record.is_empty() {
                continue;
            }
            return Err(WorkspaceError::InvalidTree);
        };
        if record[..tab].starts_with(b"160000 commit ") {
            return Err(WorkspaceError::SubmoduleUnsupported);
        }
    }
    Ok(())
}

fn write_sanitized_git_config(workspace: &Path, object_format: &str) -> Result<(), WorkspaceError> {
    let contents = match object_format {
        "sha1" => {
            b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
                .as_slice()
        }
        "sha256" => b"[core]\n\trepositoryformatversion = 1\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[extensions]\n\tobjectformat = sha256\n".as_slice(),
        _ => return Err(WorkspaceError::InvalidGitObjectFormat),
    };
    let config = workspace.join(".git/config");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&config)
        .map_err(|source_error| WorkspaceError::Io {
            path: config.clone(),
            source: source_error,
        })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|source_error| WorkspaceError::Io {
            path: config,
            source: source_error,
        })
}

fn write_repository_git_config(
    workspace: &Path,
    object_format: &str,
    source: &str,
    branch: &str,
) -> Result<(), WorkspaceError> {
    write_sanitized_git_config(workspace, object_format)?;
    git_output(
        workspace,
        &["config", "--local", "remote.origin.url", source],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    git_output(
        workspace,
        &[
            "config",
            "--local",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
        MAX_GIT_CONTROL_OUTPUT,
    )?;
    if !branch.is_empty() {
        let remote_key = format!("branch.{branch}.remote");
        let merge_key = format!("branch.{branch}.merge");
        let merge_ref = format!("refs/heads/{branch}");
        git_output(
            workspace,
            &["config", "--local", &remote_key, "origin"],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
        git_output(
            workspace,
            &["config", "--local", &merge_key, &merge_ref],
            MAX_GIT_CONTROL_OUTPUT,
        )?;
    }
    Ok(())
}

fn remove_git_trace_files(workspace: &Path) -> Result<(), WorkspaceError> {
    for relative in [".git/logs", ".git/FETCH_HEAD"] {
        let path = workspace.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                fs::remove_dir_all(&path).map_err(|source_error| WorkspaceError::Io {
                    path,
                    source: source_error,
                })?;
            }
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&path).map_err(|source_error| WorkspaceError::Io {
                    path,
                    source: source_error,
                })?;
            }
            Ok(_) => return Err(WorkspaceError::UnsafeGitMetadata(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source_error) => {
                return Err(WorkspaceError::Io {
                    path,
                    source: source_error,
                });
            }
        }
    }
    Ok(())
}

fn remove_unselected_git_refs(workspace: &Path) -> Result<(), WorkspaceError> {
    let git_dir = workspace.join(".git");
    let refs = git_dir.join("refs");
    match fs::symlink_metadata(&refs) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(&refs).map_err(|source_error| WorkspaceError::Io {
                path: refs.clone(),
                source: source_error,
            })?;
        }
        Ok(_) => return Err(WorkspaceError::UnsafeGitMetadata(refs)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source_error) => {
            return Err(WorkspaceError::Io {
                path: refs,
                source: source_error,
            });
        }
    }
    for relative in ["refs", "refs/heads", "refs/tags"] {
        let path = git_dir.join(relative);
        fs::create_dir(&path).map_err(|source_error| WorkspaceError::Io {
            path,
            source: source_error,
        })?;
    }
    let packed_refs = git_dir.join("packed-refs");
    match fs::symlink_metadata(&packed_refs) {
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(&packed_refs).map_err(|source_error| WorkspaceError::Io {
                path: packed_refs,
                source: source_error,
            })?;
        }
        Ok(_) => return Err(WorkspaceError::UnsafeGitMetadata(packed_refs)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source_error) => {
            return Err(WorkspaceError::Io {
                path: packed_refs,
                source: source_error,
            });
        }
    }
    Ok(())
}

fn bounded_staging_regular_bytes(root: &Path, maximum: u64) -> Result<u64, WorkspaceError> {
    fn visit(path: &Path, total: &mut u64, maximum: u64) -> Result<(), WorkspaceError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| WorkspaceError::Io {
            path: path.to_owned(),
            source,
        })?;
        if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .ok_or(WorkspaceError::WorkspaceTooLarge)?;
            if *total > maximum {
                return Err(WorkspaceError::WorkspaceTooLarge);
            }
        } else if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|source| WorkspaceError::Io {
                path: path.to_owned(),
                source,
            })? {
                let entry = entry.map_err(|source| WorkspaceError::Io {
                    path: path.to_owned(),
                    source,
                })?;
                visit(&entry.path(), total, maximum)?;
            }
        } else if !metadata.file_type().is_symlink() {
            return Err(WorkspaceError::UnsupportedCopyEntry(path.to_owned()));
        }
        Ok(())
    }

    let mut total = 0;
    visit(root, &mut total, maximum)?;
    Ok(total)
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
    #[error("workspace source root changed while it was being opened or copied: {0}")]
    SourceRootChanged(PathBuf),
    #[error("workspace source has an unsafe .git marker: {0}")]
    UnsafeGitMarker(PathBuf),
    #[error("direct workspace mounts are not available in this native runtime slice")]
    DirectModeUnavailable,
    #[error("--path must name the Git worktree root ({requested} is inside {root})")]
    SourceMustBeWorktreeRoot { requested: PathBuf, root: PathBuf },
    #[error("bare Git repositories are not supported")]
    BareRepository,
    #[error("workspace source identity is invalid")]
    InvalidCommit,
    #[error("workspace input plan is invalid")]
    InvalidWorkspacePlan,
    #[error(
        "workspace has local Git changes; commit them, use --path-mode copy for a point-in-time directory snapshot, or declare an explicit direct mount"
    )]
    DirtyWorktree,
    #[error("Git submodules are not supported by the native preview")]
    SubmoduleUnsupported,
    #[error("workspace Git tree is malformed")]
    InvalidTree,
    #[error("workspace source entry could not be opened safely at {path}: {source}")]
    SourceOpen {
        path: PathBuf,
        source: rustix::io::Errno,
    },
    #[error("workspace copy crossed a mount boundary at {0}")]
    SourceMountBoundary(PathBuf),
    #[error("workspace source entry changed while it was copied: {0}")]
    SourceEntryChanged(PathBuf),
    #[error("workspace copy contains an invalid relative path: {0}")]
    InvalidCopyPath(PathBuf),
    #[error("workspace copy exceeds the maximum directory depth")]
    CopyDepthExceeded,
    #[error("workspace copy exceeds the maximum entry count")]
    CopyEntryLimitExceeded,
    #[error("workspace copy contains an unsupported special entry: {0}")]
    UnsupportedCopyEntry(PathBuf),
    #[error("workspace copy contains set-id or sticky permissions: {0}")]
    UnsafeCopyMode(PathBuf),
    #[error("workspace copy contains a symlink that leaves the selected root: {0}")]
    UnsafeCopySymlink(PathBuf),
    #[error("workspace content does not fit on the requested disk")]
    WorkspaceTooLarge,
    #[error("/usr/bin/git is required for native clone-mode workspaces")]
    GitUnavailable,
    #[error("Git could not inspect the requested clean commit")]
    GitCommandFailed,
    #[error("Git could not create an independent local clone")]
    GitCloneFailed,
    #[error("the prepared Git clone contains an external object alternate")]
    GitAlternatesPresent,
    #[error("the prepared Git clone is not clean")]
    GitCloneNotClean,
    #[error("the prepared Git clone uses an unsupported object format")]
    InvalidGitObjectFormat,
    #[error("the prepared Git clone contains unsafe metadata: {0}")]
    UnsafeGitMetadata(PathBuf),
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
    #[error(transparent)]
    Plan(#[from] crate::workspace_plan::WorkspacePlanError),
    #[error(transparent)]
    Content(#[from] crate::oci::ContentStoreError),
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
            mode: WorkspaceSourceMode::Clone,
        };

        let snapshot =
            ensure_workspace(engine.path(), vm_id, &source, MINIMUM_STATE_DISK_BYTES).unwrap();
        assert_eq!(snapshot.source_path, source.source_path);
        assert_eq!(snapshot.commit, source.commit);
        assert_eq!(snapshot.state_disk, paths.state_disk);
        assert!(!interrupted_staging.exists());

        assert!(matches!(
            ensure_workspace(
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
            mode: WorkspaceSourceMode::Clone,
        };

        assert!(matches!(
            ensure_workspace(
                &engine,
                vm_id,
                &source,
                MINIMUM_STATE_DISK_BYTES,
            ),
            Err(WorkspaceError::UnsafeProvisioningStaging(path)) if path == staging
        ));
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"preserve");
    }

    fn git(source: &Path, arguments: &[&str]) {
        let status = Command::new(GIT)
            .args(arguments)
            .current_dir(source)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?} failed");
    }

    #[test]
    fn auto_classifies_exact_git_roots_and_ordinary_directories() {
        let ordinary = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_workspace_mode(ordinary.path(), WorkspaceSelection::Auto).unwrap(),
            WorkspaceSourceMode::Copy
        );

        let repository = tempfile::tempdir().unwrap();
        git(repository.path(), &["init", "-q"]);
        assert_eq!(
            resolve_workspace_mode(repository.path(), WorkspaceSelection::Auto).unwrap(),
            WorkspaceSourceMode::Clone
        );
        assert!(matches!(
            resolve_workspace_mode(repository.path(), WorkspaceSelection::Direct),
            Err(WorkspaceError::DirectModeUnavailable)
        ));
    }

    #[test]
    fn git_control_output_is_stopped_at_the_requested_read_bound() {
        let repository = tempfile::tempdir().unwrap();
        git(repository.path(), &["init", "-q"]);
        fs::write(repository.path().join("untracked"), b"contents").unwrap();

        assert!(matches!(
            git_output(
                repository.path(),
                &["status", "--porcelain=v1", "--untracked-files=all"],
                4,
            ),
            Err(WorkspaceError::GitOutputTooLarge)
        ));
    }

    #[test]
    fn copy_snapshot_includes_hidden_files_and_materializes_hardlinks() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("sub")).unwrap();
        fs::write(source.path().join("sub/file"), b"contents").unwrap();
        fs::write(source.path().join(".hidden"), b"hidden").unwrap();
        fs::hard_link(
            source.path().join("sub/file"),
            source.path().join("hardlink"),
        )
        .unwrap();
        symlink("sub/file", source.path().join("link")).unwrap();

        let admitted =
            inspect_workspace(source.path(), WorkspaceSelection::Copy, MAXIMUM_COPY_BYTES).unwrap();
        assert_eq!(admitted.mode, WorkspaceSourceMode::Copy);
        let destination = tempfile::tempdir().unwrap();
        let copied = copy_directory_manifest(
            &open_source_directory(source.path()).unwrap(),
            Some(destination.path()),
            MAXIMUM_COPY_BYTES,
            MAXIMUM_COPY_ENTRIES,
        )
        .unwrap();
        assert_eq!(copied.sha256, admitted.commit);
        assert_eq!(
            fs::read(destination.path().join(".hidden")).unwrap(),
            b"hidden"
        );
        assert_eq!(
            fs::read_link(destination.path().join("link")).unwrap(),
            Path::new("sub/file")
        );
        assert_eq!(
            fs::metadata(destination.path().join("sub/file"))
                .unwrap()
                .nlink(),
            1
        );
        assert_eq!(
            fs::metadata(destination.path().join("hardlink"))
                .unwrap()
                .nlink(),
            1
        );

        fs::write(source.path().join("sub/file"), b"changed").unwrap();
        let changed =
            inspect_workspace(source.path(), WorkspaceSelection::Copy, MAXIMUM_COPY_BYTES).unwrap();
        assert_ne!(changed.commit, admitted.commit);
    }

    #[test]
    fn confined_snapshot_enforces_its_narrow_entry_budget_during_copy() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("skill")).unwrap();
        fs::write(source.path().join("skill/SKILL.md"), b"skill\n").unwrap();
        fs::write(source.path().join("skill/extra"), b"extra\n").unwrap();
        let destination = tempfile::tempdir().unwrap();

        assert!(matches!(
            snapshot_confined_directory(
                source.path(),
                Path::new("skill"),
                destination.path(),
                MAXIMUM_COPY_BYTES,
                1,
            ),
            Err(WorkspaceError::CopyEntryLimitExceeded)
        ));
    }

    #[test]
    fn copy_snapshot_rejects_external_symlinks_and_sockets() {
        let source = tempfile::tempdir().unwrap();
        symlink("../outside", source.path().join("escape")).unwrap();
        assert!(matches!(
            inspect_workspace(
                source.path(),
                WorkspaceSelection::Copy,
                MAXIMUM_COPY_BYTES,
            ),
            Err(WorkspaceError::UnsafeCopySymlink(path)) if path == Path::new("escape")
        ));

        fs::remove_file(source.path().join("escape")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(source.path().join("socket")).unwrap();
        assert!(matches!(
            inspect_workspace(
                source.path(),
                WorkspaceSelection::Copy,
                MAXIMUM_COPY_BYTES,
            ),
            Err(WorkspaceError::UnsupportedCopyEntry(path)) if path == Path::new("socket")
        ));
    }

    #[test]
    fn copy_snapshot_enforces_size_and_mode_bounds_before_provisioning() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("large"), b"12345678").unwrap();
        assert!(matches!(
            inspect_workspace(source.path(), WorkspaceSelection::Copy, 7),
            Err(WorkspaceError::WorkspaceTooLarge)
        ));

        fs::set_permissions(
            source.path().join("large"),
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        assert!(matches!(
            inspect_workspace(
                source.path(),
                WorkspaceSelection::Copy,
                MAXIMUM_COPY_BYTES,
            ),
            Err(WorkspaceError::UnsafeCopyMode(path)) if path == Path::new("large")
        ));
    }

    #[test]
    fn copy_snapshot_rejects_file_growth_after_entry_admission() {
        let source = tempfile::tempdir().unwrap();
        let path = source.path().join("changing");
        fs::write(&path, b"before").unwrap();
        let source = open_source_directory(source.path()).unwrap();
        let mut input = open_source_regular_entry(
            &source.directory,
            Path::new("changing"),
            Path::new("changing"),
        )
        .unwrap();
        let expected = input.metadata().unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"-after")
            .unwrap();
        let mut walk = CopyWalk {
            hasher: Sha256::new(),
            regular_bytes: expected.len(),
            entries: 1,
            maximum_bytes: MAXIMUM_COPY_BYTES,
            maximum_entries: MAXIMUM_COPY_ENTRIES,
        };

        assert!(matches!(
            copy_regular_contents(
                &source,
                Path::new("changing"),
                &mut input,
                &expected,
                None,
                0o644,
                &mut walk,
            ),
            Err(WorkspaceError::SourceEntryChanged(path)) if path == Path::new("changing")
        ));
    }

    #[test]
    fn clone_requires_clean_state_and_creates_independent_sanitized_git_metadata() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "-q"]);
        fs::write(source.path().join("README.md"), b"committed\n").unwrap();
        git(source.path(), &["add", "README.md"]);
        git(
            source.path(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "initial",
            ],
        );
        git(
            source.path(),
            &["config", "credential.helper", "malicious-helper"],
        );
        git(
            source.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://user:secret@example.invalid/repo.git",
            ],
        );
        fs::write(source.path().join("dangling-secret"), b"not selected\n").unwrap();
        let dangling = git_text(source.path(), &["hash-object", "-w", "dangling-secret"])
            .unwrap()
            .trim()
            .to_owned();
        fs::remove_file(source.path().join("dangling-secret")).unwrap();
        let marker = source.path().join("hook-ran");
        let hook = source.path().join(".git/hooks/post-checkout");
        fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();

        let admitted =
            inspect_workspace(source.path(), WorkspaceSelection::Clone, MAXIMUM_COPY_BYTES)
                .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let workspace = staging.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        prepare_git_clone(&admitted, &workspace, staging.path()).unwrap();

        assert!(!marker.exists());
        assert_eq!(
            fs::read(workspace.join("README.md")).unwrap(),
            b"committed\n"
        );
        let config = fs::read_to_string(workspace.join(".git/config")).unwrap();
        assert!(!config.contains("credential"));
        assert!(!config.contains("secret"));
        assert!(!config.contains(source.path().to_string_lossy().as_ref()));
        assert!(!workspace.join(".git/objects/info/alternates").exists());
        assert!(!workspace.join(".git/logs").exists());
        assert!(
            git_output(
                &workspace,
                &["for-each-ref", "--format=%(refname)"],
                MAX_GIT_CONTROL_OUTPUT,
            )
            .unwrap()
            .stdout
            .is_empty()
        );
        assert!(matches!(
            git_output(
                &workspace,
                &["cat-file", "-e", &dangling],
                MAX_GIT_CONTROL_OUTPUT,
            ),
            Err(WorkspaceError::GitCommandFailed)
        ));

        fs::write(source.path().join("README.md"), b"dirty\n").unwrap();
        assert!(matches!(
            inspect_workspace(source.path(), WorkspaceSelection::Clone, MAXIMUM_COPY_BYTES,),
            Err(WorkspaceError::DirtyWorktree)
        ));
    }

    #[test]
    fn repository_bundle_imports_only_the_resolved_commit_with_a_safe_origin() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "-q"]);
        fs::write(source.path().join("README.md"), b"bundled\n").unwrap();
        git(source.path(), &["add", "README.md"]);
        git(
            source.path(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "initial",
            ],
        );
        let commit = git_text(source.path(), &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_owned();
        git(
            source.path(),
            &["update-ref", "refs/codewire/source", &commit],
        );

        let staging = tempfile::tempdir().unwrap();
        let bundle = staging.path().join("source.bundle");
        let status = Command::new(GIT)
            .args(["bundle", "create"])
            .arg(&bundle)
            .arg("refs/codewire/source")
            .current_dir(source.path())
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success());

        let workspace = staging.path().join("workspace");
        prepare_git_bundle(
            &bundle,
            &workspace,
            staging.path(),
            "https://example.invalid/acme/repository.git",
            &commit,
            "main",
        )
        .unwrap();

        assert_eq!(fs::read(workspace.join("README.md")).unwrap(), b"bundled\n");
        assert_eq!(
            git_text(&workspace, &["rev-parse", "HEAD"]).unwrap().trim(),
            commit
        );
        let config = fs::read_to_string(workspace.join(".git/config")).unwrap();
        assert!(config.contains("https://example.invalid/acme/repository.git"));
        assert!(!config.contains(source.path().to_string_lossy().as_ref()));
        assert!(!config.contains(bundle.to_string_lossy().as_ref()));
        assert!(!config.contains("credential"));
        assert_eq!(
            git_text(&workspace, &["symbolic-ref", "HEAD"])
                .unwrap()
                .trim(),
            "refs/heads/main"
        );
        assert_eq!(
            git_text(&workspace, &["for-each-ref", "--format=%(refname)"],).unwrap(),
            "refs/heads/main\nrefs/remotes/origin/main\n"
        );
    }

    #[test]
    fn clone_provisioning_builds_the_ext4_workspace_disk() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "-q"]);
        fs::write(source.path().join("README.md"), b"provisioned\n").unwrap();
        git(source.path(), &["add", "README.md"]);
        git(
            source.path(),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "initial",
            ],
        );
        let admitted =
            inspect_workspace(source.path(), WorkspaceSelection::Clone, MAXIMUM_COPY_BYTES)
                .unwrap();
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = provision_workspace(
            engine.path(),
            Uuid::new_v4(),
            &admitted,
            MINIMUM_STATE_DISK_BYTES,
        )
        .unwrap();
        assert_eq!(snapshot.commit, admitted.commit);
        assert_eq!(snapshot.mode, WorkspaceSourceMode::Clone);
        assert_eq!(
            fs::metadata(&snapshot.state_disk).unwrap().len(),
            MINIMUM_STATE_DISK_BYTES
        );
    }

    #[test]
    fn nested_copy_input_provisioning_builds_the_ext4_workspace_disk() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fixture.txt"), b"copied\n").unwrap();
        let admitted =
            inspect_workspace(source.path(), WorkspaceSelection::Copy, MAXIMUM_COPY_BYTES).unwrap();
        let plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::local(
            &admitted,
            "/workspace/fixtures",
        )])
        .unwrap();
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let snapshot = ensure_workspace_plan(
            engine.path(),
            Uuid::new_v4(),
            &plan,
            MINIMUM_STATE_DISK_BYTES,
        )
        .unwrap();

        assert_eq!(snapshot.plan_sha256, plan.sha256().unwrap());
        assert_eq!(
            fs::metadata(&snapshot.state_disk).unwrap().len(),
            MINIMUM_STATE_DISK_BYTES
        );
    }

    #[test]
    fn copy_input_respects_the_remaining_aggregate_workspace_budget() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fixture.txt"), b"four").unwrap();
        let admitted = inspect_workspace(source.path(), WorkspaceSelection::Copy, 4).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let workspace = staging.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("existing.txt"), b"12345").unwrap();

        assert!(matches!(
            prepare_copy_input(
                &admitted,
                &admitted.commit,
                &workspace.join("fixtures"),
                &workspace,
                8,
            ),
            Err(WorkspaceError::WorkspaceTooLarge)
        ));
    }
}
