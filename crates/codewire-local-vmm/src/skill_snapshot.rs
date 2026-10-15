//! Environment-owned immutable skill snapshot preparation.
//!
//! Only declared repository paths and Codewire's explicit user-skill store are
//! read. The private temporary tree seeds a digest-addressed environment root
//! disk and is removed afterward; ambient agent homes are never consulted.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use codewire_project::{ProjectSpec, SkillSource};
use codewire_vmm_guest_probe::{
    SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH, SKILL_SNAPSHOT_PLAN_RELATIVE_PATH, SkillSnapshot,
    SkillSnapshotPlan, SkillSnapshotSource,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::direct_share::AdmittedDirectShare;
use crate::host::path::{PrivateRoot, current_uid};
use crate::oci::ContentStore;
use crate::workspace::{
    WorkspaceError, WorkspaceSelection, WorkspaceSourceMode, inspect_workspace,
    inspect_workspace_skipping, manifest_directory, prepare_git_bundle, prepare_git_clone,
    snapshot_confined_directory, snapshot_confined_open_directory, workspace_content_limit,
};
use crate::workspace_plan::{WorkspaceInput, WorkspacePlan, WorkspacePlanError};

const MAXIMUM_SKILL_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_SKILL_SNAPSHOT_ENTRIES: u64 = 100_000;

pub(crate) struct PreparedSkillSnapshot {
    plan: SkillSnapshotPlan,
    root: PathBuf,
    staging: PathBuf,
}

impl PreparedSkillSnapshot {
    pub(crate) fn plan(&self) -> &SkillSnapshotPlan {
        &self.plan
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for PreparedSkillSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.staging);
    }
}

struct StagingCleanup(Option<PathBuf>);

impl StagingCleanup {
    fn finish(mut self) -> PathBuf {
        self.0.take().expect("skill snapshot staging is present")
    }
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub(crate) struct SkillSnapshotRequest<'a> {
    pub(crate) engine_state_root: &'a Path,
    pub(crate) vm_id: Uuid,
    pub(crate) workspace_plan: &'a WorkspacePlan,
    pub(crate) project: &'a ProjectSpec,
    pub(crate) project_sha256: &'a str,
    pub(crate) user_skills_root: &'a Path,
    pub(crate) forbidden_direct_roots: &'a [PathBuf],
    pub(crate) plan_generation: u64,
    pub(crate) expected: Option<&'a SkillSnapshotPlan>,
}

pub(crate) fn prepare_skill_snapshot(
    request: SkillSnapshotRequest<'_>,
) -> Result<Option<PreparedSkillSnapshot>, SkillSnapshotPreparationError> {
    let SkillSnapshotRequest {
        engine_state_root,
        vm_id,
        workspace_plan,
        project,
        project_sha256,
        user_skills_root,
        forbidden_direct_roots,
        plan_generation,
        expected,
    } = request;
    project
        .validate()
        .map_err(|_| SkillSnapshotPreparationError::InvalidProject)?;
    workspace_plan
        .validate_for_project(project)
        .map_err(|_| SkillSnapshotPreparationError::InvalidProject)?;
    if project.skills.is_empty() {
        return if expected.is_none() {
            Ok(None)
        } else {
            Err(SkillSnapshotPreparationError::SnapshotChanged)
        };
    }
    if plan_generation == 0 {
        return Err(SkillSnapshotPreparationError::InvalidProject);
    }

    let engine = PrivateRoot::open(engine_state_root)?;
    cleanup_skill_snapshot_staging(&engine, vm_id)?;
    let staging_name = format!("skill-snapshot-{vm_id}");
    let staging = engine.create_dir(Path::new(&staging_name), 0o700)?;
    let cleanup = StagingCleanup(Some(staging.clone()));
    let root = staging.join("root");
    let source_staging = staging.join("sources");
    let codewire = root.join("codewire");
    let contents = root.join(SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH);
    for path in [&root, &source_staging, &codewire, &contents] {
        fs::create_dir(path).map_err(|source| SkillSnapshotPreparationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            SkillSnapshotPreparationError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }

    let selected_inputs = project
        .skills
        .iter()
        .filter(|selection| selection.source == SkillSource::Repository)
        .map(|selection| {
            workspace_plan
                .inputs
                .iter()
                .position(|input| {
                    relative_skill_path(&selection.reference, input.destination()).is_some()
                })
                .ok_or_else(|| {
                    SkillSnapshotPreparationError::MissingRepositorySkill(
                        selection.reference.clone(),
                    )
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let content = ContentStore::create(&engine)?;
    let repository_roots = prepare_repository_roots(
        workspace_plan,
        &content,
        &source_staging,
        &selected_inputs,
        forbidden_direct_roots,
        expected.is_none() && plan_generation == 1,
    )?;
    let mut snapshots = Vec::new();
    let mut total_bytes = 0_u64;
    let mut total_entries = 0_u64;

    for (selection_index, selection) in project.skills.iter().enumerate() {
        let agents = if selection.agents.is_empty() {
            &project.agents.tools
        } else {
            &selection.agents
        };
        if agents.is_empty() {
            return Err(SkillSnapshotPreparationError::MissingAgents(
                selection.reference.clone(),
            ));
        }
        let name = Path::new(&selection.reference)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                SkillSnapshotPreparationError::InvalidReference(selection.reference.clone())
            })?;
        match selection.source {
            SkillSource::Repository => {
                let mut matched = false;
                for (input_index, source) in repository_roots.iter().enumerate() {
                    let Some(source) = source else {
                        continue;
                    };
                    let Some(relative) = source.relative_skill_path(&selection.reference) else {
                        continue;
                    };
                    let pending =
                        contents.join(format!(".pending-{selection_index:03}-{input_index:03}"));
                    fs::create_dir(&pending).map_err(|source| {
                        SkillSnapshotPreparationError::Io {
                            path: pending.clone(),
                            source,
                        }
                    })?;
                    let remaining = remaining_bytes(total_bytes)?;
                    let remaining_entries = remaining_entries(total_entries)?;
                    let _copied =
                        match source.snapshot(&relative, &pending, remaining, remaining_entries) {
                            Ok(snapshot) => snapshot,
                            Err(error) if workspace_error_is_not_found(&error) => {
                                fs::remove_dir(&pending).map_err(|source| {
                                    SkillSnapshotPreparationError::Io {
                                        path: pending.clone(),
                                        source,
                                    }
                                })?;
                                continue;
                            }
                            Err(error) => return Err(error.into()),
                        };
                    matched = true;
                    admit_copied_skill(&pending)?;
                    normalize_snapshot_tree(&pending)?;
                    let snapshot = manifest_directory(&pending, remaining, remaining_entries)?;
                    account_snapshot(
                        &mut total_bytes,
                        &mut total_entries,
                        snapshot.regular_bytes,
                        snapshot.entries,
                    )?;
                    publish_content(&pending, &contents, &snapshot.sha256)?;
                    snapshots.push(SkillSnapshot::new(
                        SkillSnapshotSource::Repository,
                        source.source_identity.clone(),
                        selection.reference.clone(),
                        snapshot.sha256,
                        name,
                        agents,
                    )?);
                }
                if !matched {
                    return Err(SkillSnapshotPreparationError::MissingRepositorySkill(
                        selection.reference.clone(),
                    ));
                }
            }
            SkillSource::User => {
                let pending = contents.join(format!(".pending-{selection_index:03}-user"));
                fs::create_dir(&pending).map_err(|source| SkillSnapshotPreparationError::Io {
                    path: pending.clone(),
                    source,
                })?;
                let _copied = snapshot_confined_directory(
                    user_skills_root,
                    Path::new(&selection.reference),
                    &pending,
                    remaining_bytes(total_bytes)?,
                    remaining_entries(total_entries)?,
                )
                .map_err(|error| {
                    if workspace_error_is_not_found(&error) {
                        SkillSnapshotPreparationError::MissingUserSkill(selection.reference.clone())
                    } else {
                        error.into()
                    }
                })?;
                admit_copied_skill(&pending)?;
                normalize_snapshot_tree(&pending)?;
                let snapshot = manifest_directory(
                    &pending,
                    remaining_bytes(total_bytes)?,
                    remaining_entries(total_entries)?,
                )?;
                account_snapshot(
                    &mut total_bytes,
                    &mut total_entries,
                    snapshot.regular_bytes,
                    snapshot.entries,
                )?;
                publish_content(&pending, &contents, &snapshot.sha256)?;
                snapshots.push(SkillSnapshot::new(
                    SkillSnapshotSource::User,
                    format!("user:{}", selection.reference),
                    selection.reference.clone(),
                    snapshot.sha256,
                    name,
                    agents,
                )?);
            }
        }
    }

    let plan = SkillSnapshotPlan::new(project_sha256.to_owned(), plan_generation, snapshots)?;
    if expected.is_some_and(|expected| expected != &plan) {
        return Err(SkillSnapshotPreparationError::SnapshotChanged);
    }
    let plan_path = root.join(SKILL_SNAPSHOT_PLAN_RELATIVE_PATH);
    let plan_bytes = plan.encode_canonical()?;
    let mut plan_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&plan_path)
        .map_err(|source| SkillSnapshotPreparationError::Io {
            path: plan_path.clone(),
            source,
        })?;
    plan_file
        .set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|source| SkillSnapshotPreparationError::Io {
            path: plan_path.clone(),
            source,
        })?;
    plan_file
        .write_all(&plan_bytes)
        .and_then(|()| plan_file.sync_all())
        .map_err(|source| SkillSnapshotPreparationError::Io {
            path: plan_path,
            source,
        })?;
    File::open(&contents)
        .and_then(|directory| directory.sync_all())
        .and_then(|()| File::open(&codewire)?.sync_all())
        .and_then(|()| File::open(&root)?.sync_all())
        .map_err(|source| SkillSnapshotPreparationError::Io {
            path: root.clone(),
            source,
        })?;
    Ok(Some(PreparedSkillSnapshot {
        plan,
        root,
        staging: cleanup.finish(),
    }))
}

pub(crate) fn cleanup_interrupted_skill_snapshot(
    engine_state_root: &Path,
    vm_id: Uuid,
) -> Result<(), SkillSnapshotPreparationError> {
    cleanup_skill_snapshot_staging(&PrivateRoot::open(engine_state_root)?, vm_id)
}

fn cleanup_skill_snapshot_staging(
    engine: &PrivateRoot,
    vm_id: Uuid,
) -> Result<(), SkillSnapshotPreparationError> {
    let staging = engine.path().join(format!("skill-snapshot-{vm_id}"));
    let metadata = match fs::symlink_metadata(&staging) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SkillSnapshotPreparationError::Io {
                path: staging,
                source,
            });
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(SkillSnapshotPreparationError::UnsafeStaging(staging));
    }
    fs::remove_dir_all(&staging).map_err(|source| SkillSnapshotPreparationError::Io {
        path: staging.clone(),
        source,
    })?;
    File::open(engine.path())
        .and_then(|root| root.sync_all())
        .map_err(|source| SkillSnapshotPreparationError::Io {
            path: engine.path().to_owned(),
            source,
        })
}

enum WorkspaceSkillSource {
    Prepared(PathBuf),
    Direct(AdmittedDirectShare),
}

struct RepositorySkillRoot {
    source: WorkspaceSkillSource,
    source_identity: String,
    destination: String,
}

impl RepositorySkillRoot {
    fn relative_skill_path(&self, reference: &str) -> Option<PathBuf> {
        relative_skill_path(reference, &self.destination)
    }

    fn snapshot(
        &self,
        relative: &Path,
        destination: &Path,
        maximum_bytes: u64,
        maximum_entries: u64,
    ) -> Result<crate::workspace::DirectorySnapshot, WorkspaceError> {
        match &self.source {
            WorkspaceSkillSource::Prepared(root) => snapshot_confined_directory(
                root,
                relative,
                destination,
                maximum_bytes,
                maximum_entries,
            ),
            WorkspaceSkillSource::Direct(source) => snapshot_confined_open_directory(
                source.path(),
                source.descriptor().as_fd(),
                relative,
                destination,
                maximum_bytes,
                maximum_entries,
            ),
        }
    }
}

fn relative_skill_path(reference: &str, destination: &str) -> Option<PathBuf> {
    Path::new("/workspace")
        .join(reference)
        .strip_prefix(Path::new(destination))
        .ok()
        .map(Path::to_path_buf)
}

fn prepare_repository_roots(
    workspace_plan: &WorkspacePlan,
    content: &ContentStore,
    staging: &Path,
    selected_inputs: &BTreeSet<usize>,
    forbidden_direct_roots: &[PathBuf],
    require_exact_copy_source: bool,
) -> Result<Vec<Option<RepositorySkillRoot>>, SkillSnapshotPreparationError> {
    let mut roots = Vec::with_capacity(workspace_plan.inputs.len());
    for (index, input) in workspace_plan.inputs.iter().enumerate() {
        if !selected_inputs.contains(&index) {
            roots.push(None);
            continue;
        }
        let prepared = match input {
            WorkspaceInput::Direct {
                identity,
                destination,
                ..
            } => {
                let source = input
                    .direct_source(forbidden_direct_roots)?
                    .ok_or(SkillSnapshotPreparationError::InvalidProject)?;
                let identity = format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(identity)
                            .map_err(|_| SkillSnapshotPreparationError::InvalidProject)?
                    )
                );
                RepositorySkillRoot {
                    source: WorkspaceSkillSource::Direct(source),
                    source_identity: format!("direct:{destination}@{identity}"),
                    destination: destination.clone(),
                }
            }
            WorkspaceInput::Local {
                identity,
                mode,
                destination,
                ..
            } => {
                let source = input
                    .local_source()
                    .ok_or(SkillSnapshotPreparationError::InvalidProject)?;
                let source_root = match mode {
                    WorkspaceSourceMode::Clone => {
                        let admitted = inspect_workspace(
                            &source.source_path,
                            WorkspaceSelection::Clone,
                            workspace_content_limit(u64::MAX),
                        )?;
                        if admitted != source {
                            return Err(SkillSnapshotPreparationError::SnapshotChanged);
                        }
                        let checkout = staging.join(format!("local-clone-{index:03}"));
                        prepare_git_clone(&source, &checkout, staging)?;
                        checkout
                    }
                    WorkspaceSourceMode::Copy => {
                        if require_exact_copy_source {
                            let admitted = inspect_workspace_skipping(
                                &source.source_path,
                                WorkspaceSelection::Copy,
                                workspace_content_limit(u64::MAX),
                                &source.vm_only,
                            )?;
                            if admitted != source {
                                return Err(SkillSnapshotPreparationError::SnapshotChanged);
                            }
                        }
                        source.source_path
                    }
                };
                RepositorySkillRoot {
                    source: WorkspaceSkillSource::Prepared(source_root),
                    source_identity: format!("workspace:{destination}@{identity}"),
                    destination: destination.clone(),
                }
            }
            WorkspaceInput::Repository {
                source,
                commit,
                branch,
                destination,
                bundle_digest,
                bundle_size,
            } => {
                let bundle = content.verified_blob_path(bundle_digest, *bundle_size)?;
                let checkout = staging.join(format!("repository-{index:03}"));
                prepare_git_bundle(&bundle, &checkout, staging, source, commit, branch)?;
                RepositorySkillRoot {
                    source: WorkspaceSkillSource::Prepared(checkout),
                    source_identity: format!("repository:{destination}@{commit}"),
                    destination: destination.clone(),
                }
            }
        };
        roots.push(Some(prepared));
    }
    Ok(roots)
}

fn remaining_bytes(total: u64) -> Result<u64, SkillSnapshotPreparationError> {
    MAXIMUM_SKILL_SNAPSHOT_BYTES
        .checked_sub(total)
        .filter(|remaining| *remaining > 0)
        .ok_or(SkillSnapshotPreparationError::TooLarge)
}

fn remaining_entries(total: u64) -> Result<u64, SkillSnapshotPreparationError> {
    MAXIMUM_SKILL_SNAPSHOT_ENTRIES
        .checked_sub(total)
        .filter(|remaining| *remaining > 0)
        .ok_or(SkillSnapshotPreparationError::TooLarge)
}

fn account_snapshot(
    total_bytes: &mut u64,
    total_entries: &mut u64,
    bytes: u64,
    entries: u64,
) -> Result<(), SkillSnapshotPreparationError> {
    *total_bytes = total_bytes
        .checked_add(bytes)
        .filter(|value| *value <= MAXIMUM_SKILL_SNAPSHOT_BYTES)
        .ok_or(SkillSnapshotPreparationError::TooLarge)?;
    *total_entries = total_entries
        .checked_add(entries)
        .filter(|value| *value <= MAXIMUM_SKILL_SNAPSHOT_ENTRIES)
        .ok_or(SkillSnapshotPreparationError::TooLarge)?;
    Ok(())
}

fn admit_copied_skill(path: &Path) -> Result<(), SkillSnapshotPreparationError> {
    let skill = path.join("SKILL.md");
    let metadata = match fs::symlink_metadata(&skill) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SkillSnapshotPreparationError::MissingSkillManifest(skill));
        }
        Err(source) => {
            return Err(SkillSnapshotPreparationError::Io {
                path: skill,
                source,
            });
        }
    };
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(SkillSnapshotPreparationError::MissingSkillManifest(skill));
    }
    Ok(())
}

fn normalize_snapshot_tree(path: &Path) -> Result<(), SkillSnapshotPreparationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| SkillSnapshotPreparationError::Io {
            path: path.to_owned(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| {
            SkillSnapshotPreparationError::Io {
                path: path.to_owned(),
                source,
            }
        })?;
        let mut children = fs::read_dir(path)
            .map_err(|source| SkillSnapshotPreparationError::Io {
                path: path.to_owned(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| SkillSnapshotPreparationError::Io {
                path: path.to_owned(),
                source,
            })?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            normalize_snapshot_tree(&child.path())?;
        }
        return Ok(());
    }
    if metadata.is_file() {
        let mode = if metadata.permissions().mode() & 0o111 == 0 {
            0o444
        } else {
            0o555
        };
        return fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            SkillSnapshotPreparationError::Io {
                path: path.to_owned(),
                source,
            }
        });
    }
    Err(SkillSnapshotPreparationError::SnapshotChanged)
}

fn publish_content(
    pending: &Path,
    contents: &Path,
    digest: &str,
) -> Result<(), SkillSnapshotPreparationError> {
    let destination = contents.join(digest);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(pending).map_err(|source| SkillSnapshotPreparationError::Io {
                path: pending.to_owned(),
                source,
            })?;
            Ok(())
        }
        Ok(_) => Err(SkillSnapshotPreparationError::SnapshotChanged),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::rename(pending, &destination)
            .map_err(|source| SkillSnapshotPreparationError::Io {
                path: destination,
                source,
            }),
        Err(source) => Err(SkillSnapshotPreparationError::Io {
            path: destination,
            source,
        }),
    }
}

fn workspace_error_is_not_found(error: &WorkspaceError) -> bool {
    match error {
        WorkspaceError::SourceOpen { source, .. } => *source == rustix::io::Errno::NOENT,
        WorkspaceError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SkillSnapshotPreparationError {
    #[error("native skill snapshot project is invalid")]
    InvalidProject,
    #[error("skill {0:?} needs explicit agents or project agents")]
    MissingAgents(String),
    #[error("skill reference {0:?} is invalid")]
    InvalidReference(String),
    #[error("repository skill {0:?} does not exist in a prepared workspace input")]
    MissingRepositorySkill(String),
    #[error("Codewire user skill {0:?} does not exist")]
    MissingUserSkill(String),
    #[error("selected skill does not contain a regular single-link SKILL.md: {0}")]
    MissingSkillManifest(PathBuf),
    #[error("selected skills exceed the native snapshot size or entry limit")]
    TooLarge,
    #[error("selected skill content changed while its generation was staged")]
    SnapshotChanged,
    #[error("skill snapshot staging path is unsafe: {0}")]
    UnsafeStaging(PathBuf),
    #[error(transparent)]
    Snapshot(#[from] codewire_vmm_guest_probe::SkillSnapshotError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    WorkspacePlan(#[from] WorkspacePlanError),
    #[error(transparent)]
    Content(#[from] crate::oci::ContentStoreError),
    #[error(transparent)]
    Path(#[from] crate::host::path::PathError),
    #[error("skill snapshot filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_project::{AgentsSpec, SkillSelection};

    #[cfg(target_os = "linux")]
    use crate::direct_share::admit_direct_share;

    fn private_temp() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temporary
    }

    fn git(repository: &Path, arguments: &[&str]) {
        let status = std::process::Command::new("/usr/bin/git")
            .args([
                "-c",
                "maintenance.autoDetach=false",
                "-c",
                "gc.autoDetach=false",
            ])
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn project(skills: Vec<SkillSelection>) -> (ProjectSpec, Vec<u8>, String) {
        let project = ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            agents: AgentsSpec {
                install: None,
                tools: vec!["codex".to_owned()],
            },
            skills,
            ..Default::default()
        };
        let bytes = project.canonical_json().unwrap();
        let sha256 = codewire_vmm_guest_probe::Sha256Value::calculate(&bytes).to_string();
        (project, bytes, sha256)
    }

    #[test]
    fn declared_repository_and_user_skills_become_one_private_canonical_snapshot() {
        let engine = private_temp();
        let workspace = private_temp();
        let user = private_temp();
        let repository_skill = workspace.path().join(".agents/skills/repo-skill");
        let user_skill = user.path().join("user-skill");
        fs::create_dir_all(&repository_skill).unwrap();
        fs::create_dir_all(&user_skill).unwrap();
        fs::write(repository_skill.join("SKILL.md"), b"repository skill\n").unwrap();
        fs::write(user_skill.join("SKILL.md"), b"user skill\n").unwrap();
        let source = inspect_workspace(
            workspace.path(),
            WorkspaceSelection::Copy,
            workspace_content_limit(u64::MAX),
        )
        .unwrap();
        let workspace_plan =
            WorkspacePlan::from_inputs(vec![WorkspaceInput::local(&source, "/workspace/fixtures")])
                .unwrap();
        let (project, _bytes, project_sha256) = project(vec![
            SkillSelection {
                source: SkillSource::Repository,
                reference: "fixtures/.agents/skills/repo-skill".to_owned(),
                agents: vec!["codex".to_owned(), "claude-code".to_owned()],
            },
            SkillSelection {
                source: SkillSource::User,
                reference: "user-skill".to_owned(),
                agents: vec!["codex".to_owned()],
            },
        ]);

        let first_id = Uuid::new_v4();
        let prepared = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id: first_id,
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(prepared.plan().skills().len(), 2);
        assert_eq!(prepared.plan().plan_generation(), 1);
        for skill in prepared.plan().skills() {
            let content = prepared
                .root()
                .join(SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH)
                .join(skill.digest())
                .join("SKILL.md");
            assert!(content.is_file());
            assert_eq!(
                fs::metadata(content).unwrap().permissions().mode() & 0o777,
                0o444
            );
        }
        let second = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id: Uuid::new_v4(),
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(second.plan(), prepared.plan());
        assert_ne!(second.root(), prepared.root());
        let staging = prepared.staging.clone();
        drop(prepared);
        assert!(!staging.exists());
        assert!(second.root().is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_destination_root_is_copied_from_its_pinned_admission() {
        let engine = private_temp();
        let direct = private_temp();
        let user = private_temp();
        fs::write(direct.path().join("SKILL.md"), b"direct skill\n").unwrap();
        let admitted = admit_direct_share(direct.path(), &[]).unwrap();
        let workspace_plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::direct(
            &admitted,
            "/workspace/direct-skill",
            true,
            Vec::new(),
        )])
        .unwrap();
        let (project, _, project_sha256) = project(vec![SkillSelection {
            source: SkillSource::Repository,
            reference: "direct-skill".to_owned(),
            agents: vec!["codex".to_owned()],
        }]);

        let prepared = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id: Uuid::new_v4(),
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(prepared.plan().skills().len(), 1);
        assert_eq!(prepared.plan().skills()[0].relative_path(), "direct-skill");
        assert!(
            prepared.plan().skills()[0]
                .source_identity()
                .starts_with("direct:/workspace/direct-skill@")
        );
    }

    #[test]
    fn local_git_skill_resolution_uses_the_sanitized_committed_clone() {
        let engine = private_temp();
        let repository = private_temp();
        let user = private_temp();
        git(repository.path(), &["init", "-q"]);
        fs::write(repository.path().join("README.md"), b"committed\n").unwrap();
        let tracked = repository.path().join(".agents/skills/tracked");
        fs::create_dir_all(&tracked).unwrap();
        fs::write(tracked.join("SKILL.md"), b"tracked skill\n").unwrap();
        git(repository.path(), &["add", "README.md", ".agents"]);
        git(
            repository.path(),
            &[
                "-c",
                "user.name=Codewire Test",
                "-c",
                "user.email=test@invalid.example",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        );
        let host_private = repository.path().join(".git/private-skill");
        fs::create_dir(&host_private).unwrap();
        fs::write(host_private.join("SKILL.md"), b"must not be imported\n").unwrap();
        let source = inspect_workspace(
            repository.path(),
            WorkspaceSelection::Clone,
            workspace_content_limit(u64::MAX),
        )
        .unwrap();
        let workspace_plan = WorkspacePlan::local(&source).unwrap();
        let (tracked_project, _, tracked_project_sha256) = project(vec![SkillSelection {
            source: SkillSource::Repository,
            reference: ".agents/skills/tracked".to_owned(),
            agents: vec!["codex".to_owned()],
        }]);
        let prepared = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id: Uuid::new_v4(),
            workspace_plan: &workspace_plan,
            project: &tracked_project,
            project_sha256: &tracked_project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(prepared.plan().skills().len(), 1);
        drop(prepared);

        let (project, _, project_sha256) = project(vec![SkillSelection {
            source: SkillSource::Repository,
            reference: ".git/private-skill".to_owned(),
            agents: vec!["codex".to_owned()],
        }]);

        assert!(matches!(
            prepare_skill_snapshot(SkillSnapshotRequest {
                engine_state_root: engine.path(),
                vm_id: Uuid::new_v4(),
                workspace_plan: &workspace_plan,
                project: &project,
                project_sha256: &project_sha256,
                user_skills_root: user.path(),
                forbidden_direct_roots: &[],
                plan_generation: 1,
                expected: None,
            }),
            Err(SkillSnapshotPreparationError::MissingRepositorySkill(reference))
                if reference == ".git/private-skill"
        ));
    }

    #[test]
    fn expected_snapshot_fails_closed_when_declared_content_changes() {
        let engine = private_temp();
        let workspace = private_temp();
        let user = private_temp();
        let skill = workspace.path().join("skill");
        fs::create_dir(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), b"first\n").unwrap();
        let source = inspect_workspace(
            workspace.path(),
            WorkspaceSelection::Copy,
            workspace_content_limit(u64::MAX),
        )
        .unwrap();
        let workspace_plan = WorkspacePlan::local(&source).unwrap();
        let (project, _, project_sha256) = project(vec![SkillSelection {
            source: SkillSource::Repository,
            reference: "skill".to_owned(),
            agents: vec!["codex".to_owned()],
        }]);
        let vm_id = Uuid::new_v4();
        let expected = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id,
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: None,
        })
        .unwrap()
        .unwrap()
        .plan()
        .clone();
        fs::write(
            workspace.path().join("unrelated"),
            b"changed outside skill\n",
        )
        .unwrap();
        let reconstructed = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id,
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 1,
            expected: Some(&expected),
        })
        .unwrap()
        .unwrap();
        assert_eq!(reconstructed.plan(), &expected);
        drop(reconstructed);

        fs::write(skill.join("SKILL.md"), b"second\n").unwrap();
        let refreshed = prepare_skill_snapshot(SkillSnapshotRequest {
            engine_state_root: engine.path(),
            vm_id,
            workspace_plan: &workspace_plan,
            project: &project,
            project_sha256: &project_sha256,
            user_skills_root: user.path(),
            forbidden_direct_roots: &[],
            plan_generation: 2,
            expected: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(refreshed.plan().plan_generation(), 2);
        assert_ne!(
            refreshed.plan().skills()[0].digest(),
            expected.skills()[0].digest()
        );
        drop(refreshed);

        assert!(matches!(
            prepare_skill_snapshot(SkillSnapshotRequest {
                engine_state_root: engine.path(),
                vm_id,
                workspace_plan: &workspace_plan,
                project: &project,
                project_sha256: &project_sha256,
                user_skills_root: user.path(),
                forbidden_direct_roots: &[],
                plan_generation: 1,
                expected: Some(&expected),
            }),
            Err(SkillSnapshotPreparationError::SnapshotChanged)
                | Err(SkillSnapshotPreparationError::Workspace(
                    WorkspaceError::SourceChanged
                ))
        ));
    }
}
