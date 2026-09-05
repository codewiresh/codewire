//! Durable, credential-free workspace inputs for one local environment.
//!
//! Remote Git is resolved before the lifecycle intent is journaled. The plan
//! records only an exact commit, a safe public origin, and a digest-addressed
//! bundle. Replaying the journal therefore never needs network access or host
//! Git configuration.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_access::AccessProfileId;
use codewire_local_credentials::{
    AuthorityRuntimeConfig, LocalCredentialControlClient, validate_github_https_source,
};
use codewire_project::{ProjectSpec, RepositorySpec};
use codewire_vmm_guest_probe::{DirectShareMount, DirectSharePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use crate::direct_share::{
    AdmittedDirectShare, DirectShareIdentity, admit_direct_share, reopen_direct_share,
};
use crate::linux::path::{PathError, PrivateRoot, current_uid};
use crate::oci::{ContentStore, ContentStoreError, Sha256Digest};
use crate::workspace::{WorkspaceSource, WorkspaceSourceMode};

const GIT: &str = "/usr/bin/git";
const WORKSPACE_PLAN_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_WORKSPACE_PLAN_BYTES: usize = 512 * 1024;
const MAXIMUM_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const MAXIMUM_GIT_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspacePlan {
    pub(crate) schema_version: u32,
    pub(crate) inputs: Vec<WorkspaceInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WorkspaceInput {
    Local {
        source_path: Vec<u8>,
        identity: String,
        mode: WorkspaceSourceMode,
        destination: String,
    },
    Direct {
        source_path: Vec<u8>,
        identity: DirectShareIdentity,
        destination: String,
        read_only: bool,
    },
    Repository {
        source: String,
        commit: String,
        branch: String,
        destination: String,
        bundle_digest: Sha256Digest,
        bundle_size: u64,
    },
}

impl WorkspacePlan {
    pub(crate) fn local(source: &WorkspaceSource) -> Result<Self, WorkspacePlanError> {
        Self::from_inputs(vec![WorkspaceInput::local(source, "/workspace")])
    }

    pub(crate) fn from_inputs(inputs: Vec<WorkspaceInput>) -> Result<Self, WorkspacePlanError> {
        let plan = Self {
            schema_version: WORKSPACE_PLAN_SCHEMA_VERSION,
            inputs,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub(crate) fn validate(&self) -> Result<(), WorkspacePlanError> {
        if self.schema_version != WORKSPACE_PLAN_SCHEMA_VERSION
            || self.inputs.is_empty()
            || self.inputs.len()
                > codewire_project::MAX_REPOSITORIES + codewire_project::MAX_LOCAL_MOUNTS
        {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        let mut destinations = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let destination = input.destination();
            validate_destination(destination)?;
            destinations.push(destination);
            match input {
                WorkspaceInput::Local {
                    source_path,
                    identity,
                    mode,
                    destination,
                } => {
                    let path = PathBuf::from(OsString::from_vec(source_path.clone()));
                    if !path.is_absolute()
                        || !valid_object_id(identity)
                        || (*mode == WorkspaceSourceMode::Clone && destination != "/workspace")
                    {
                        return Err(WorkspacePlanError::InvalidPlan);
                    }
                }
                WorkspaceInput::Direct {
                    source_path,
                    identity,
                    ..
                } => {
                    let path = PathBuf::from(OsString::from_vec(source_path.clone()));
                    if !path.is_absolute() || identity.validate().is_err() {
                        return Err(WorkspacePlanError::InvalidPlan);
                    }
                }
                WorkspaceInput::Repository {
                    source,
                    commit,
                    branch,
                    bundle_size,
                    ..
                } => {
                    validate_anonymous_https_source(source)?;
                    if !valid_object_id(commit)
                        || (!branch.is_empty() && !valid_git_selector(branch))
                        || *bundle_size == 0
                        || *bundle_size > MAXIMUM_GIT_BUNDLE_BYTES
                    {
                        return Err(WorkspacePlanError::InvalidPlan);
                    }
                }
            }
        }
        destinations.sort_unstable();
        for pair in destinations.windows(2) {
            if pair[0] == pair[1]
                || pair[1]
                    .strip_prefix(pair[0])
                    .is_some_and(|suffix| suffix.starts_with('/'))
            {
                return Err(WorkspacePlanError::OverlappingDestinations);
            }
        }
        self.direct_share_plan()?;
        Ok(())
    }

    pub(crate) fn validate_for_project(
        &self,
        project: &ProjectSpec,
    ) -> Result<(), WorkspacePlanError> {
        self.validate()?;
        if project.repositories.len() > self.inputs.len() {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        for (repository, input) in project.repositories.iter().zip(&self.inputs) {
            let WorkspaceInput::Repository {
                source,
                branch,
                destination,
                ..
            } = input
            else {
                return Err(WorkspacePlanError::InvalidPlan);
            };
            if source != &repository.source
                || destination != &repository.destination
                || (!repository.branch.is_empty() && branch != &repository.branch)
            {
                return Err(WorkspacePlanError::InvalidPlan);
            }
        }
        if self.inputs[project.repositories.len()..]
            .iter()
            .any(|input| matches!(input, WorkspaceInput::Repository { .. }))
        {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        if project.working_directory != "/workspace"
            && !self.inputs.iter().any(|input| {
                let destination = input.destination();
                project.working_directory == destination
                    || project
                        .working_directory
                        .strip_prefix(destination)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        Ok(())
    }

    pub(crate) fn encode_canonical(&self) -> Result<Vec<u8>, WorkspacePlanError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| WorkspacePlanError::InvalidPlan)?;
        if bytes.len() > MAXIMUM_WORKSPACE_PLAN_BYTES {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        Ok(bytes)
    }

    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkspacePlanError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_WORKSPACE_PLAN_BYTES {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        let plan: Self =
            serde_json::from_slice(bytes).map_err(|_| WorkspacePlanError::InvalidPlan)?;
        plan.validate()?;
        if plan.encode_canonical()? != bytes {
            return Err(WorkspacePlanError::InvalidPlan);
        }
        Ok(plan)
    }

    pub(crate) fn sha256(&self) -> Result<String, WorkspacePlanError> {
        Ok(format!("{:x}", Sha256::digest(self.encode_canonical()?)))
    }

    pub(crate) fn retained_bundles(&self) -> impl Iterator<Item = (&Sha256Digest, u64)> {
        self.inputs.iter().filter_map(|input| match input {
            WorkspaceInput::Repository {
                bundle_digest,
                bundle_size,
                ..
            } => Some((bundle_digest, *bundle_size)),
            WorkspaceInput::Local { .. } | WorkspaceInput::Direct { .. } => None,
        })
    }

    pub(crate) fn direct_share_plan(&self) -> Result<Option<DirectSharePlan>, WorkspacePlanError> {
        let mounts = self
            .inputs
            .iter()
            .filter_map(|input| match input {
                WorkspaceInput::Direct {
                    destination,
                    read_only,
                    ..
                } => Some((destination, *read_only)),
                WorkspaceInput::Local { .. } | WorkspaceInput::Repository { .. } => None,
            })
            .enumerate()
            .map(|(index, (destination, read_only))| {
                DirectShareMount::for_index(index, destination.clone(), read_only)
                    .map_err(|_| WorkspacePlanError::InvalidPlan)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if mounts.is_empty() {
            Ok(None)
        } else {
            DirectSharePlan::new(mounts)
                .map(Some)
                .map_err(|_| WorkspacePlanError::InvalidPlan)
        }
    }
}

impl WorkspaceInput {
    pub(crate) fn local(source: &WorkspaceSource, destination: &str) -> Self {
        Self::Local {
            source_path: source.source_path.as_os_str().as_bytes().to_vec(),
            identity: source.commit.clone(),
            mode: source.mode,
            destination: destination.to_owned(),
        }
    }

    pub(crate) fn direct(source: &AdmittedDirectShare, destination: &str, read_only: bool) -> Self {
        Self::Direct {
            source_path: source.path().as_os_str().as_bytes().to_vec(),
            identity: source.identity().clone(),
            destination: destination.to_owned(),
            read_only,
        }
    }

    pub(crate) fn destination(&self) -> &str {
        match self {
            Self::Local { destination, .. }
            | Self::Direct { destination, .. }
            | Self::Repository { destination, .. } => destination,
        }
    }

    pub(crate) fn local_source(&self) -> Option<WorkspaceSource> {
        match self {
            Self::Local {
                source_path,
                identity,
                mode,
                ..
            } => Some(WorkspaceSource {
                source_path: PathBuf::from(OsString::from_vec(source_path.clone())),
                commit: identity.clone(),
                mode: *mode,
            }),
            Self::Repository { .. } => None,
            Self::Direct { .. } => None,
        }
    }

    pub(crate) fn direct_source(
        &self,
        forbidden_roots: &[PathBuf],
    ) -> Result<Option<AdmittedDirectShare>, WorkspacePlanError> {
        let Self::Direct {
            source_path,
            identity,
            ..
        } = self
        else {
            return Ok(None);
        };
        let path = PathBuf::from(OsString::from_vec(source_path.clone()));
        reopen_direct_share(&path, identity, forbidden_roots)
            .map(Some)
            .map_err(|_| WorkspacePlanError::DirectShareChanged)
    }
}

pub(crate) fn prepare_direct_input(
    requested_source: &Path,
    destination: &str,
    read_only: bool,
    forbidden_roots: &[PathBuf],
) -> Result<WorkspaceInput, WorkspacePlanError> {
    validate_local_mount_destination(destination)?;
    let admitted = admit_direct_share(requested_source, forbidden_roots)
        .map_err(|_| WorkspacePlanError::DirectShareInvalid)?;
    Ok(WorkspaceInput::direct(&admitted, destination, read_only))
}

pub(crate) fn validate_local_mount_destination(
    destination: &str,
) -> Result<(), WorkspacePlanError> {
    validate_destination(destination)?;
    if destination == "/workspace" {
        return Err(WorkspacePlanError::InvalidPlan);
    }
    Ok(())
}

pub(crate) async fn prepare_repository_plan(
    engine_state_root: &Path,
    repositories: &[RepositorySpec],
    credential_access: Option<&RepositoryCredentialAccess>,
    credential_authority: &AuthorityRuntimeConfig,
) -> Result<WorkspacePlan, WorkspacePlanError> {
    if repositories.is_empty() || repositories.len() > codewire_project::MAX_REPOSITORIES {
        return Err(WorkspacePlanError::InvalidPlan);
    }
    let root = PrivateRoot::open(engine_state_root)?;
    let content = ContentStore::create(&root)?;
    let mut inputs = Vec::with_capacity(repositories.len());
    for repository in repositories {
        inputs.push(
            prepare_repository(
                &root,
                &content,
                repository,
                credential_access,
                credential_authority,
            )
            .await?,
        );
    }
    WorkspacePlan::from_inputs(inputs)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepositoryCredentialAccess {
    pub(crate) request_id: Uuid,
    pub(crate) profile_id: AccessProfileId,
    pub(crate) profile_revision: u64,
}

async fn prepare_repository(
    root: &PrivateRoot,
    content: &ContentStore,
    repository: &RepositorySpec,
    credential_access: Option<&RepositoryCredentialAccess>,
    credential_authority: &AuthorityRuntimeConfig,
) -> Result<WorkspaceInput, WorkspacePlanError> {
    match prepare_anonymous_repository(root, content, repository).await {
        Ok(input) => Ok(input),
        Err(WorkspacePlanError::GitCommandFailed)
            if credential_access.is_some()
                && validate_github_https_source(&repository.source).is_ok() =>
        {
            prepare_authenticated_repository(
                root,
                content,
                repository,
                credential_access.expect("credential access checked"),
                credential_authority,
            )
            .await
        }
        Err(error) => Err(error),
    }
}

async fn prepare_anonymous_repository(
    root: &PrivateRoot,
    content: &ContentStore,
    repository: &RepositorySpec,
) -> Result<WorkspaceInput, WorkspacePlanError> {
    validate_anonymous_https_source(&repository.source)?;
    let staging_name = format!("repository-prepare-{}", Uuid::new_v4());
    let staging = root.create_dir(Path::new(&staging_name), 0o700)?;
    let mut cleanup = PreparationCleanup::new(staging.clone());
    let bare = staging.join("source.git");
    git_status(
        &staging,
        [
            OsStr::new("init"),
            OsStr::new("--bare"),
            OsStr::new("--quiet"),
            bare.as_os_str(),
        ],
    )
    .await?;

    let branch = if !repository.branch.is_empty() {
        repository.branch.clone()
    } else if repository.revision.is_empty() {
        resolve_default_branch(&staging, &repository.source).await?
    } else {
        String::new()
    };
    let selector = if !repository.revision.is_empty() {
        repository.revision.clone()
    } else {
        format!("refs/heads/{branch}")
    };
    let refspec = format!("{selector}:refs/codewire/source");
    git_status(
        &bare,
        [
            OsStr::new("fetch"),
            OsStr::new("--quiet"),
            OsStr::new("--no-tags"),
            OsStr::new("--force"),
            OsStr::new("--no-recurse-submodules"),
            OsStr::new("--"),
            OsStr::new(&repository.source),
            OsStr::new(&refspec),
        ],
    )
    .await?;
    let commit = git_text(
        &bare,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("refs/codewire/source^{commit}"),
        ],
        256,
    )
    .await?
    .trim()
    .to_owned();
    if !valid_object_id(&commit) {
        return Err(WorkspacePlanError::InvalidRemoteCommit);
    }
    reject_submodules(&bare, &commit).await?;

    let bundle = staging.join("source.bundle");
    git_status(
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("create"),
            bundle.as_os_str(),
            OsStr::new("refs/codewire/source"),
        ],
    )
    .await?;
    git_status(
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("verify"),
            bundle.as_os_str(),
        ],
    )
    .await?;
    let (digest, size, file) = digest_bundle(&bundle)?;
    content.admit_file(&digest, size, file).await?;
    cleanup.remove()?;

    Ok(WorkspaceInput::Repository {
        source: repository.source.clone(),
        commit,
        branch,
        destination: repository.destination.clone(),
        bundle_digest: digest,
        bundle_size: size,
    })
}

async fn prepare_authenticated_repository(
    root: &PrivateRoot,
    content: &ContentStore,
    repository: &RepositorySpec,
    access: &RepositoryCredentialAccess,
    credential_authority: &AuthorityRuntimeConfig,
) -> Result<WorkspaceInput, WorkspacePlanError> {
    validate_github_https_source(&repository.source)
        .map_err(|_| WorkspacePlanError::UnsupportedRepositorySource)?;
    let staging_name = format!("repository-prepare-{}", Uuid::new_v4());
    let staging = root.create_dir(Path::new(&staging_name), 0o700)?;
    let mut cleanup = PreparationCleanup::new(staging.clone());
    let bare = staging.join("source.git");
    git_status(
        &staging,
        [
            OsStr::new("init"),
            OsStr::new("--bare"),
            OsStr::new("--quiet"),
            bare.as_os_str(),
        ],
    )
    .await?;
    let mut client = LocalCredentialControlClient::connect(credential_authority)
        .await
        .map_err(|_| WorkspacePlanError::CredentialAuthorityUnavailable)?;
    let mut prepared = client
        .prepare_git_repository(
            access.request_id,
            &access.profile_id,
            access.profile_revision,
            repository.source.clone(),
            repository.branch.clone(),
            repository.revision.clone(),
        )
        .await
        .map_err(|_| WorkspacePlanError::CredentialRepositoryUnavailable)?;
    if (!repository.branch.is_empty() && prepared.branch != repository.branch)
        || (!repository.revision.is_empty() && !prepared.branch.is_empty())
    {
        return Err(WorkspacePlanError::CredentialRepositoryInvalid);
    }
    let bundle = staging.join("source.bundle");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bundle)
        .map_err(|source| WorkspacePlanError::Io {
            path: bundle.clone(),
            source,
        })?;
    let mut file = tokio::fs::File::from_std(file);
    let mut written = 0_u64;
    while let Some(chunk) = prepared
        .next_bundle_chunk()
        .await
        .map_err(|_| WorkspacePlanError::CredentialRepositoryInvalid)?
    {
        written = written
            .checked_add(
                u64::try_from(chunk.len()).map_err(|_| WorkspacePlanError::BundleTooLarge)?,
            )
            .ok_or(WorkspacePlanError::BundleTooLarge)?;
        if written > MAXIMUM_GIT_BUNDLE_BYTES {
            return Err(WorkspacePlanError::BundleTooLarge);
        }
        file.write_all(&chunk)
            .await
            .map_err(|source| WorkspacePlanError::Io {
                path: bundle.clone(),
                source,
            })?;
    }
    file.flush()
        .await
        .map_err(|source| WorkspacePlanError::Io {
            path: bundle.clone(),
            source,
        })?;
    drop(file);
    if written != prepared.bundle_size {
        return Err(WorkspacePlanError::CredentialRepositoryInvalid);
    }
    git_status(
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("verify"),
            bundle.as_os_str(),
        ],
    )
    .await?;
    let listed = git_text(
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("list-heads"),
            bundle.as_os_str(),
            OsStr::new("refs/codewire/source"),
        ],
        512,
    )
    .await?;
    if listed.trim() != format!("{} refs/codewire/source", prepared.commit) {
        return Err(WorkspacePlanError::CredentialRepositoryInvalid);
    }
    let (digest, size, file) = digest_bundle(&bundle)?;
    if size != prepared.bundle_size {
        return Err(WorkspacePlanError::CredentialRepositoryInvalid);
    }
    content.admit_file(&digest, size, file).await?;
    cleanup.remove()?;

    Ok(WorkspaceInput::Repository {
        source: repository.source.clone(),
        commit: prepared.commit,
        branch: prepared.branch,
        destination: repository.destination.clone(),
        bundle_digest: digest,
        bundle_size: size,
    })
}

async fn resolve_default_branch(
    working_directory: &Path,
    source: &str,
) -> Result<String, WorkspacePlanError> {
    let output = git_text(
        working_directory,
        [
            OsStr::new("ls-remote"),
            OsStr::new("--symref"),
            OsStr::new("--exit-code"),
            OsStr::new("--"),
            OsStr::new(source),
            OsStr::new("HEAD"),
        ],
        4096,
    )
    .await?;
    let branch = output.lines().find_map(|line| {
        let reference = line.strip_prefix("ref: refs/heads/")?;
        reference.strip_suffix("\tHEAD")
    });
    branch
        .filter(|branch| valid_git_selector(branch))
        .map(str::to_owned)
        .ok_or(WorkspacePlanError::InvalidRemoteHead)
}

async fn reject_submodules(bare: &Path, commit: &str) -> Result<(), WorkspacePlanError> {
    let output = git_output(
        bare,
        [
            OsStr::new("ls-tree"),
            OsStr::new("-r"),
            OsStr::new("-z"),
            OsStr::new("--full-tree"),
            OsStr::new(commit),
        ],
        MAXIMUM_GIT_CONTROL_OUTPUT,
    )
    .await?;
    for record in output.split(|byte| *byte == 0) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            if record.is_empty() {
                continue;
            }
            return Err(WorkspacePlanError::InvalidRemoteTree);
        };
        if record[..tab].starts_with(b"160000 commit ") {
            return Err(WorkspacePlanError::SubmoduleUnsupported);
        }
    }
    Ok(())
}

async fn git_status<'a>(
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<(), WorkspacePlanError> {
    let mut command = git_command(working_directory);
    command
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = timeout(GIT_COMMAND_TIMEOUT, command.status())
        .await
        .map_err(|_| WorkspacePlanError::GitTimeout)?
        .map_err(|_| WorkspacePlanError::GitUnavailable)?;
    if !status.success() {
        return Err(WorkspacePlanError::GitCommandFailed);
    }
    Ok(())
}

async fn git_text<'a>(
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
) -> Result<String, WorkspacePlanError> {
    let output = git_output(working_directory, arguments, maximum_output).await?;
    String::from_utf8(output).map_err(|_| WorkspacePlanError::InvalidGitOutput)
}

async fn git_output<'a>(
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
) -> Result<Vec<u8>, WorkspacePlanError> {
    let maximum_output_plus_one = maximum_output
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WorkspacePlanError::GitOutputTooLarge)?;
    let mut command = git_command(working_directory);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| WorkspacePlanError::GitUnavailable)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(WorkspacePlanError::GitUnavailable)?;
    timeout(GIT_COMMAND_TIMEOUT, async move {
        let mut output = Vec::with_capacity(maximum_output.min(64 * 1024));
        stdout
            .take(maximum_output_plus_one)
            .read_to_end(&mut output)
            .await
            .map_err(|_| WorkspacePlanError::GitUnavailable)?;
        if output.len() > maximum_output {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(WorkspacePlanError::GitOutputTooLarge);
        }
        let status = child
            .wait()
            .await
            .map_err(|_| WorkspacePlanError::GitUnavailable)?;
        if !status.success() {
            return Err(WorkspacePlanError::GitCommandFailed);
        }
        Ok(output)
    })
    .await
    .map_err(|_| WorkspacePlanError::GitTimeout)?
}

fn git_command(working_directory: &Path) -> Command {
    let mut command = Command::new(GIT);
    command
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.lfs.required=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
        ])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

fn digest_bundle(path: &Path) -> Result<(Sha256Digest, u64, File), WorkspacePlanError> {
    let mut file = File::open(path).map_err(|source| WorkspacePlanError::Io {
        path: path.to_owned(),
        source,
    })?;
    let before = file.metadata().map_err(|source| WorkspacePlanError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !before.is_file() || before.len() == 0 || before.len() > MAXIMUM_GIT_BUNDLE_BYTES {
        return Err(WorkspacePlanError::BundleTooLarge);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|source| WorkspacePlanError::Io {
                path: path.to_owned(),
                source,
            })?;
        if length == 0 {
            break;
        }
        read = read
            .checked_add(u64::try_from(length).map_err(|_| WorkspacePlanError::BundleTooLarge)?)
            .ok_or(WorkspacePlanError::BundleTooLarge)?;
        if read > MAXIMUM_GIT_BUNDLE_BYTES {
            return Err(WorkspacePlanError::BundleTooLarge);
        }
        hasher.update(&buffer[..length]);
    }
    let after = file.metadata().map_err(|source| WorkspacePlanError::Io {
        path: path.to_owned(),
        source,
    })?;
    if read != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(WorkspacePlanError::BundleChanged);
    }
    let digest = Sha256Digest::parse(&format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| WorkspacePlanError::InvalidPlan)?;
    file.rewind().map_err(|source| WorkspacePlanError::Io {
        path: path.to_owned(),
        source,
    })?;
    Ok((digest, read, file))
}

fn validate_anonymous_https_source(source: &str) -> Result<(), WorkspacePlanError> {
    if source.starts_with('-') {
        return Err(WorkspacePlanError::UnsupportedRepositorySource);
    }
    let url = Url::parse(source).map_err(|_| WorkspacePlanError::UnsupportedRepositorySource)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WorkspacePlanError::UnsupportedRepositorySource);
    }
    Ok(())
}

fn validate_destination(destination: &str) -> Result<(), WorkspacePlanError> {
    if destination == "/workspace" {
        return Ok(());
    }
    let relative = destination
        .strip_prefix("/workspace/")
        .ok_or(WorkspacePlanError::InvalidPlan)?;
    if relative.is_empty()
        || destination.ends_with('/')
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(WorkspacePlanError::InvalidPlan);
    }
    Ok(())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_git_selector(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.ends_with(".lock")
        && !value.contains(char::is_whitespace)
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.contains(['~', '^', ':', '?', '*', '[', '\\'])
}

struct PreparationCleanup {
    path: Option<PathBuf>,
}

impl PreparationCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn remove(&mut self) -> Result<(), WorkspacePlanError> {
        let path = self.path.take().ok_or(WorkspacePlanError::InvalidPlan)?;
        validate_preparation_directory(&path)?;
        fs::remove_dir_all(&path).map_err(|source| WorkspacePlanError::Io { path, source })
    }
}

impl Drop for PreparationCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take()
            && validate_preparation_directory(&path).is_ok()
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_preparation_directory(path: &Path) -> Result<(), WorkspacePlanError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| WorkspacePlanError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || !path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("repository-prepare-") && name.len() == 55)
    {
        return Err(WorkspacePlanError::UnsafePreparation(path.to_owned()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspacePlanError {
    #[error("workspace input plan is invalid")]
    InvalidPlan,
    #[error("workspace input destinations overlap")]
    OverlappingDestinations,
    #[error(
        "native remote repositories currently require anonymous HTTPS; protected repositories are added by #1922/#1912"
    )]
    UnsupportedRepositorySource,
    #[error("remote repository has no valid default branch")]
    InvalidRemoteHead,
    #[error("remote repository did not resolve to a valid commit")]
    InvalidRemoteCommit,
    #[error("remote repository tree is malformed")]
    InvalidRemoteTree,
    #[error("Git submodules are not supported by this repository slice")]
    SubmoduleUnsupported,
    #[error("Git is required to prepare native remote repositories")]
    GitUnavailable,
    #[error("remote Git preparation failed")]
    GitCommandFailed,
    #[error("local credential authority is unavailable for protected repository preparation")]
    CredentialAuthorityUnavailable,
    #[error("protected GitHub repository preparation is unavailable")]
    CredentialRepositoryUnavailable,
    #[error("protected GitHub repository output is invalid")]
    CredentialRepositoryInvalid,
    #[error("remote Git preparation timed out")]
    GitTimeout,
    #[error("remote Git output exceeded the safety limit")]
    GitOutputTooLarge,
    #[error("remote Git returned invalid text")]
    InvalidGitOutput,
    #[error("remote Git bundle exceeds the content bound")]
    BundleTooLarge,
    #[error("remote Git bundle changed while it was admitted")]
    BundleChanged,
    #[error("direct-share source is unsafe or unsupported")]
    DirectShareInvalid,
    #[error("direct-share source changed after admission")]
    DirectShareChanged,
    #[error("remote repository preparation path is unsafe: {0}")]
    UnsafePreparation(PathBuf),
    #[error(transparent)]
    Content(#[from] ContentStoreError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("repository preparation filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_reject_non_https_and_overlapping_destinations() {
        assert!(matches!(
            validate_anonymous_https_source("ssh://git@example.test/org/app.git"),
            Err(WorkspacePlanError::UnsupportedRepositorySource)
        ));
        assert!(validate_anonymous_https_source("https://example.test/org/app.git").is_ok());

        let digest = Sha256Digest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let plan = WorkspacePlan {
            schema_version: WORKSPACE_PLAN_SCHEMA_VERSION,
            inputs: vec![
                WorkspaceInput::Repository {
                    source: "https://example.test/org/app.git".to_owned(),
                    commit: "b".repeat(40),
                    branch: "main".to_owned(),
                    destination: "/workspace/app".to_owned(),
                    bundle_digest: digest.clone(),
                    bundle_size: 1,
                },
                WorkspaceInput::Repository {
                    source: "https://example.test/org/tools.git".to_owned(),
                    commit: "c".repeat(40),
                    branch: String::new(),
                    destination: "/workspace/app/tools".to_owned(),
                    bundle_digest: digest,
                    bundle_size: 1,
                },
            ],
        };
        assert!(matches!(
            plan.validate(),
            Err(WorkspacePlanError::OverlappingDestinations)
        ));
    }

    #[test]
    fn canonical_plan_round_trip_preserves_non_utf8_local_paths() {
        let source = WorkspaceSource {
            source_path: PathBuf::from(OsString::from_vec(vec![b'/', b'w', 0xff])),
            commit: "d".repeat(40),
            mode: WorkspaceSourceMode::Clone,
        };
        let plan = WorkspacePlan::local(&source).unwrap();
        let bytes = plan.encode_canonical().unwrap();
        assert_eq!(WorkspacePlan::decode_canonical(&bytes).unwrap(), plan);
    }

    #[test]
    fn mixed_plans_bind_project_destinations_and_working_directory() {
        let source = WorkspaceSource {
            source_path: PathBuf::from("/host/fixtures"),
            commit: "d".repeat(40),
            mode: WorkspaceSourceMode::Copy,
        };
        let digest = Sha256Digest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let plan = WorkspacePlan::from_inputs(vec![
            WorkspaceInput::Repository {
                source: "https://example.test/org/app.git".to_owned(),
                commit: "b".repeat(40),
                branch: "main".to_owned(),
                destination: "/workspace/app".to_owned(),
                bundle_digest: digest,
                bundle_size: 1,
            },
            WorkspaceInput::local(&source, "/workspace/fixtures"),
        ])
        .unwrap();
        let project = ProjectSpec {
            repositories: vec![RepositorySpec {
                source: "https://example.test/org/app.git".to_owned(),
                revision: String::new(),
                branch: "main".to_owned(),
                destination: "/workspace/app".to_owned(),
            }],
            working_directory: "/workspace/fixtures/subdir".to_owned(),
            ..ProjectSpec::default()
        };
        plan.validate_for_project(&project).unwrap();

        let mut mismatched = project;
        mismatched.working_directory = "/workspace/missing".to_owned();
        assert!(matches!(
            plan.validate_for_project(&mismatched),
            Err(WorkspacePlanError::InvalidPlan)
        ));
    }

    #[test]
    fn explicit_local_mount_destinations_must_be_below_workspace_root() {
        assert!(validate_local_mount_destination("/workspace/fixtures").is_ok());
        assert!(validate_local_mount_destination("/workspace").is_err());
        assert!(validate_local_mount_destination("/tmp/fixtures").is_err());
    }

    #[tokio::test]
    async fn remote_git_output_is_stopped_at_the_requested_read_bound() {
        let working_directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            git_output(working_directory.path(), [OsStr::new("--version")], 4,).await,
            Err(WorkspacePlanError::GitOutputTooLarge)
        ));
    }
}
