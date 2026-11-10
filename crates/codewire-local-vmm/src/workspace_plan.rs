//! Durable, credential-free workspace inputs for one local environment.
//!
//! Remote Git is resolved before the lifecycle intent is journaled. The plan
//! records only an exact commit, a safe public origin, and a digest-addressed
//! bundle. Replaying the journal therefore never needs network access or host
//! Git configuration.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Seek as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_access::{AccessProfileId, GITHUB_HTTPS_URL};
use codewire_local_credentials::{
    AuthorityRuntimeConfig, LocalCredentialControlClient, LocalRepositoryGit,
    validate_github_https_source,
};
use codewire_project::{
    GitHubSourceForm, RepositorySpec, canonical_repository_known_hosts, github_repository_path,
    parse_repository_ssh_host,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tokio::time::timeout;
use uuid::Uuid;

use crate::direct_share::{
    AdmittedDirectShare, DirectShareDiscriminator, admit_direct_share, reopen_direct_share,
};
use crate::host::path::{PrivateRoot, current_uid};
use crate::oci::{ContentStore, Sha256Digest};
pub(crate) use crate::supervisor_metadata::direct_share::DirectShareDiscriminators;
use crate::supervisor_metadata::direct_share::direct_share_identity_sha256;
#[cfg(test)]
use crate::supervisor_metadata::workspace_plan::{
    WORKSPACE_PLAN_SCHEMA_VERSION, validate_retained_repository_source,
};
pub(crate) use crate::supervisor_metadata::workspace_plan::{
    WorkspaceInput, WorkspacePlan, WorkspacePlanError,
};
use crate::supervisor_metadata::workspace_plan::{
    valid_git_selector, valid_object_id, validate_anonymous_https_source, validate_destination,
};
use crate::workspace::WorkspaceSource;

/// Never present: a host without an admitted git fails its spawn.
const MISSING_GIT: &str = "/nonexistent/codewire-runtime/git";
const MAXIMUM_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const MAXIMUM_GIT_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

impl WorkspacePlan {
    pub(crate) fn local(source: &WorkspaceSource) -> Result<Self, WorkspacePlanError> {
        Self::from_inputs(vec![WorkspaceInput::local(source, "/workspace")])
    }
}

impl WorkspaceInput {
    pub(crate) fn local(source: &WorkspaceSource, destination: &str) -> Self {
        Self::Local {
            source_path: source.source_path.as_os_str().as_bytes().to_vec(),
            identity: source.commit.clone(),
            mode: source.mode,
            destination: destination.to_owned(),
            vm_only: source.vm_only.clone(),
        }
    }

    pub(crate) fn direct(
        source: &AdmittedDirectShare,
        destination: &str,
        read_only: bool,
        vm_only: Vec<String>,
    ) -> Self {
        Self::Direct {
            source_path: source.path().as_os_str().as_bytes().to_vec(),
            identity: source.identity().clone(),
            destination: destination.to_owned(),
            read_only,
            vm_only,
        }
    }

    pub(crate) fn local_source(&self) -> Option<WorkspaceSource> {
        match self {
            Self::Local {
                source_path,
                identity,
                mode,
                vm_only,
                ..
            } => Some(WorkspaceSource {
                source_path: PathBuf::from(OsString::from_vec(source_path.clone())),
                commit: identity.clone(),
                mode: *mode,
                vm_only: vm_only.clone(),
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

    /// The digest its recorded discriminator is kept under, for a direct
    /// share.
    pub(crate) fn direct_identity_sha256(&self) -> Option<String> {
        match self {
            Self::Direct {
                source_path,
                identity,
                ..
            } => Some(direct_share_identity_sha256(source_path, identity)),
            Self::Local { .. } | Self::Repository { .. } => None,
        }
    }
}

/// A plan's direct shares admitted again, held open, and the discriminators
/// to record for them.
#[derive(Debug, Default)]
pub(crate) struct CheckedDirectShares {
    pub(crate) shares: Vec<AdmittedDirectShare>,
    pub(crate) discriminators: DirectShareDiscriminators,
}

impl WorkspacePlan {
    /// Admit every direct share again and apply its recorded discriminator
    /// (#3209). Any share that changed, or whose recorded file handle cannot
    /// be read back equal, refuses the whole plan. The result holds every
    /// share open: until it drops, nothing created at a share's path can
    /// take the admitted inode's number, so later reopens (the runner's
    /// among them) compare exactly.
    pub(crate) fn check_direct_shares(
        &self,
        forbidden_roots: &[PathBuf],
        recorded: &DirectShareDiscriminators,
    ) -> Result<CheckedDirectShares, WorkspacePlanError> {
        let mut checked = CheckedDirectShares::default();
        for input in &self.inputs {
            let (Some(admitted), Some(identity_sha256)) = (
                input.direct_source(forbidden_roots)?,
                input.direct_identity_sha256(),
            ) else {
                continue;
            };
            let discriminator = DirectShareDiscriminator::admit(
                recorded.get(&identity_sha256),
                admitted.discriminator(),
            )
            .ok_or(WorkspacePlanError::DirectShareChanged)?;
            checked
                .discriminators
                .insert(identity_sha256, discriminator);
            checked.shares.push(admitted);
        }
        Ok(checked)
    }

    /// The discriminators to record at supervisor startup: one for each
    /// share that still matches its recorded identity and has no handle
    /// recorded yet. Nothing is refused here; a share that does not match is
    /// left as it was, for its next boot to refuse.
    pub(crate) fn sweep_direct_share_discriminators(
        &self,
        forbidden_roots: &[PathBuf],
        recorded: &DirectShareDiscriminators,
    ) -> DirectShareDiscriminators {
        let mut swept = DirectShareDiscriminators::default();
        for input in &self.inputs {
            let Some(identity_sha256) = input.direct_identity_sha256() else {
                continue;
            };
            let recorded = recorded.get(&identity_sha256);
            let discriminator = match recorded {
                Some(handle @ DirectShareDiscriminator::Handle { .. }) => Some(handle.clone()),
                _ => match input.direct_source(forbidden_roots) {
                    Ok(Some(admitted)) => {
                        DirectShareDiscriminator::admit(recorded, admitted.discriminator())
                    }
                    Ok(None) | Err(_) => recorded.cloned(),
                },
            };
            if let Some(discriminator) = discriminator {
                swept.insert(identity_sha256, discriminator);
            }
        }
        swept
    }
}

/// A direct share admitted for a new plan, with the discriminator read from
/// the same held descriptor, recorded in the create's own transaction.
pub(crate) fn prepare_direct_input(
    requested_source: &Path,
    destination: &str,
    read_only: bool,
    vm_only: Vec<String>,
    forbidden_roots: &[PathBuf],
) -> Result<(WorkspaceInput, DirectShareDiscriminator), WorkspacePlanError> {
    validate_local_mount_destination(destination)?;
    let admitted = admit_direct_share(requested_source, forbidden_roots)
        .map_err(|_| WorkspacePlanError::DirectShareInvalid)?;
    Ok((
        WorkspaceInput::direct(&admitted, destination, read_only, vm_only),
        admitted.discriminator().clone(),
    ))
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
    for repository in repositories {
        validate_repository_trust(repository)?;
        if parse_repository_ssh_host(&repository.source)
            .ok()
            .flatten()
            .is_some()
            && credential_access.is_none()
        {
            return Err(WorkspacePlanError::MissingRepositoryCredentialProfile);
        }
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
    pub(crate) platform: Option<codewire_local_credentials::RepositoryPlatformAccess>,
    /// Whether the selected profile has an SSH key. It is read only for a
    /// github.com source in SSH form, the one source it changes.
    pub(crate) ssh_key: bool,
}

/// The source and host trust the authority fetches a repository with. SSH
/// first: only without an SSH key does a github.com source in SSH form go
/// through the GitHub connection, as its canonical HTTPS path (#2723). The
/// prepared input keeps the user's source, so the stored source and origin
/// stay in SSH form.
fn repository_fetch(
    repository: &RepositorySpec,
    access: &RepositoryCredentialAccess,
) -> (String, Vec<String>) {
    match github_repository_path(&repository.source) {
        Some((path, GitHubSourceForm::Ssh)) if !access.ssh_key => {
            (format!("{GITHUB_HTTPS_URL}{path}"), Vec::new())
        }
        _ => (repository.source.clone(), repository.known_hosts.clone()),
    }
}

async fn prepare_repository(
    root: &PrivateRoot,
    content: &ContentStore,
    repository: &RepositorySpec,
    credential_access: Option<&RepositoryCredentialAccess>,
    credential_authority: &AuthorityRuntimeConfig,
) -> Result<WorkspaceInput, WorkspacePlanError> {
    if parse_repository_ssh_host(&repository.source)
        .map_err(|_| WorkspacePlanError::UnsupportedRepositorySource)?
        .is_some()
    {
        return prepare_authenticated_repository(
            root,
            content,
            repository,
            credential_access.ok_or(WorkspacePlanError::MissingRepositoryCredentialProfile)?,
            credential_authority,
        )
        .await;
    }
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
    validate_repository_trust(repository)?;
    let (source, known_hosts) = repository_fetch(repository, access);
    if parse_repository_ssh_host(&source).ok().flatten().is_none() {
        validate_github_https_source(&source)
            .map_err(|_| WorkspacePlanError::UnsupportedRepositorySource)?;
    }
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
    // The authority's executor runs the same admitted git as this planner;
    // Linux executors use the system git.
    let git = match crate::host::git() {
        Some(git) => git.exec_path.map(|exec_path| LocalRepositoryGit {
            program: git.program,
            exec_path,
        }),
        None => return Err(WorkspacePlanError::GitUnavailable),
    };
    let mut client = LocalCredentialControlClient::connect(credential_authority)
        .await
        .map_err(|_| WorkspacePlanError::CredentialAuthorityUnavailable)?;
    let mut prepared = client
        .prepare_git_repository(
            access.request_id,
            &access.profile_id,
            access.profile_revision,
            source,
            repository.branch.clone(),
            repository.revision.clone(),
            known_hosts,
            access.platform.clone(),
            git,
        )
        .await
        .map_err(credential_repository_rejection)?;
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

fn credential_repository_rejection(status: tonic::Status) -> WorkspacePlanError {
    // A repository that outlasts the preparation deadline is a timeout, not
    // a rejection; say so instead of naming a status code.
    if status.code() == tonic::Code::DeadlineExceeded {
        return WorkspacePlanError::GitTimeout;
    }
    WorkspacePlanError::CredentialRepositoryRejected(status.code())
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
    // Without an admitted git the spawn fails, and the callers report
    // GitUnavailable with reinstall guidance.
    let git = crate::host::git();
    let program = git
        .as_ref()
        .map_or_else(|| PathBuf::from(MISSING_GIT), |git| git.program.clone());
    let mut command = Command::new(program);
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
        .envs(git.into_iter().flat_map(|git| git.environment))
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

fn validate_repository_trust(repository: &RepositorySpec) -> Result<(), WorkspacePlanError> {
    if canonical_repository_known_hosts(&repository.source, repository.known_hosts.clone())
        .ok()
        .as_ref()
        != Some(&repository.known_hosts)
    {
        return Err(WorkspacePlanError::InvalidRepositoryHostTrust);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use codewire_project::ProjectSpec;

    use crate::workspace::WorkspaceSourceMode;

    use super::*;

    #[test]
    fn credential_repository_rejection_preserves_only_status_code() {
        use tonic::{Code, Status, metadata::MetadataMap};

        const MESSAGE: &str = "hostile-provider-message-canary";
        const DETAILS: &str = "hostile-provider-details-canary";
        const METADATA: &str = "hostile-provider-metadata-canary";
        for code in [
            Code::Cancelled,
            Code::Unknown,
            Code::InvalidArgument,
            Code::NotFound,
            Code::AlreadyExists,
            Code::PermissionDenied,
            Code::ResourceExhausted,
            Code::FailedPrecondition,
            Code::Aborted,
            Code::OutOfRange,
            Code::Unimplemented,
            Code::Internal,
            Code::Unavailable,
            Code::DataLoss,
            Code::Unauthenticated,
        ] {
            let mut metadata = MetadataMap::new();
            metadata.insert("provider-canary", METADATA.parse().unwrap());
            let status = Status::with_details_and_metadata(
                code,
                MESSAGE,
                bytes::Bytes::from_static(DETAILS.as_bytes()),
                metadata,
            );
            let error = credential_repository_rejection(status);
            let display = error.to_string();
            let debug = format!("{error:?}");
            let hint = if matches!(
                code,
                Code::FailedPrecondition
                    | Code::PermissionDenied
                    | Code::Unauthenticated
                    | Code::NotFound
            ) {
                "; check that GitHub is connected and can read the repository: cw credentials --local list"
            } else {
                ""
            };
            assert_eq!(
                display,
                format!("protected repository preparation was rejected ({code:?}){hint}")
            );
            assert_eq!(debug, format!("CredentialRepositoryRejected({code:?})"));
            for canary in [MESSAGE, DETAILS, METADATA] {
                assert!(!display.contains(canary));
                assert!(!debug.contains(canary));
            }
            assert!(std::error::Error::source(&error).is_none());
        }
        let timeout = credential_repository_rejection(Status::with_details_and_metadata(
            Code::DeadlineExceeded,
            MESSAGE,
            bytes::Bytes::from_static(DETAILS.as_bytes()),
            MetadataMap::new(),
        ));
        assert_eq!(timeout.to_string(), "remote Git preparation timed out");
    }

    #[test]
    fn pinned_ssh_checkout_trust_is_distinct_from_offline_bundle_metadata() {
        let mut repository = RepositorySpec {
            source: "ssh://git@example.test:2222/repo.git".to_owned(),
            destination: "/workspace".to_owned(),
            branch: "main".to_owned(),
            revision: String::new(),
            known_hosts: vec!["[example.test]:2222 ssh-ed25519 AAAA".to_owned()],
        };
        assert!(validate_repository_trust(&repository).is_ok());
        assert!(validate_retained_repository_source(&repository.source).is_ok());
        assert!(validate_anonymous_https_source(&repository.source).is_err());
        repository.known_hosts.clear();
        assert!(matches!(
            validate_repository_trust(&repository),
            Err(WorkspacePlanError::InvalidRepositoryHostTrust)
        ));
        repository
            .known_hosts
            .push("[other.test]:2222 ssh-ed25519 AAAA".to_owned());
        assert!(validate_repository_trust(&repository).is_err());
        repository.source = "https://example.test/repo.git".to_owned();
        assert!(validate_repository_trust(&repository).is_err());
        repository.known_hosts.clear();
        assert!(validate_repository_trust(&repository).is_ok());

        // A github.com SSH source's canonical trust is GitHub's published
        // keys (#2720); an empty list is not canonical for it.
        repository.source = "git@github.com:org/app.git".to_owned();
        assert!(matches!(
            validate_repository_trust(&repository),
            Err(WorkspacePlanError::InvalidRepositoryHostTrust)
        ));
        repository.known_hosts = codewire_project::GITHUB_SSH_KNOWN_HOSTS
            .map(str::to_owned)
            .to_vec();
        assert!(validate_repository_trust(&repository).is_ok());
    }

    #[test]
    fn a_github_ssh_source_uses_the_key_first_then_the_github_connection() {
        let github_keys = codewire_project::GITHUB_SSH_KNOWN_HOSTS
            .map(str::to_owned)
            .to_vec();
        let other_keys = vec!["[example.test]:2222 ssh-ed25519 AAAA".to_owned()];
        let fetch = |source: &str, known_hosts: &[String], ssh_key: bool| {
            let repository = RepositorySpec {
                source: source.to_owned(),
                destination: "/workspace".to_owned(),
                branch: String::new(),
                revision: String::new(),
                known_hosts: known_hosts.to_vec(),
            };
            let access = RepositoryCredentialAccess {
                request_id: Uuid::new_v4(),
                profile_id: AccessProfileId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                profile_revision: 1,
                platform: None,
                ssh_key,
            };
            repository_fetch(&repository, &access)
        };
        let same = |source: &str, known_hosts: &[String]| (source.to_owned(), known_hosts.to_vec());

        for source in ["git@github.com:org/app.git", "ssh://git@github.com/org/app"] {
            // A key, alone or with the GitHub connection: SSH, no fallback.
            assert_eq!(
                fetch(source, &github_keys, true),
                same(source, &github_keys)
            );
            // No key (the GitHub connection only, or neither): the canonical
            // HTTPS path, which the authority admits only for the GitHub
            // connection and refuses without one.
            let (https, known_hosts) = fetch(source, &github_keys, false);
            assert!(known_hosts.is_empty());
            assert!(validate_github_https_source(&https).is_ok(), "{https}");
            assert_eq!(
                https,
                source
                    .replace("git@github.com:", "https://github.com/")
                    .replace("ssh://git@github.com/", "https://github.com/")
            );
        }
        // Other SSH hosts still need the key.
        for ssh_key in [false, true] {
            let source = "ssh://git@example.test:2222/repo.git";
            assert_eq!(
                fetch(source, &other_keys, ssh_key),
                same(source, &other_keys)
            );
        }
        // An HTTPS source is fetched as written.
        let source = "https://github.com/org/app.git";
        assert_eq!(fetch(source, &[], false), same(source, &[]));
    }

    #[test]
    fn plans_reject_non_https_and_overlapping_destinations_but_allow_nested_repositories() {
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
        // A repository may sit inside another (#4024).
        plan.validate().unwrap();

        // Not inside a copied folder, and never twice at one destination.
        let mut nested_in_copy = plan.clone();
        nested_in_copy.inputs[0] = WorkspaceInput::Local {
            source_path: b"/srv/app".to_vec(),
            identity: "d".repeat(40),
            mode: WorkspaceSourceMode::Copy,
            destination: "/workspace/app".to_owned(),
            vm_only: Vec::new(),
        };
        assert!(matches!(
            nested_in_copy.validate(),
            Err(WorkspacePlanError::OverlappingDestinations)
        ));
        let mut duplicate = plan.clone();
        if let WorkspaceInput::Repository { destination, .. } = &mut duplicate.inputs[1] {
            *destination = "/workspace/app".to_owned();
        }
        assert!(matches!(
            duplicate.validate(),
            Err(WorkspacePlanError::OverlappingDestinations)
        ));
    }

    #[test]
    fn canonical_plan_round_trip_preserves_non_utf8_local_paths() {
        let source = WorkspaceSource {
            vm_only: Vec::new(),
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
            vm_only: Vec::new(),
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
                known_hosts: Vec::new(),
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

    fn direct_plan(source: &Path) -> (WorkspacePlan, DirectShareDiscriminator, String) {
        let (input, discriminator) =
            prepare_direct_input(source, "/workspace/share", false, Vec::new(), &[]).unwrap();
        let identity_sha256 = input.direct_identity_sha256().unwrap();
        (
            WorkspacePlan::from_inputs(vec![input]).unwrap(),
            discriminator,
            identity_sha256,
        )
    }

    fn other_handle(discriminator: &DirectShareDiscriminator) -> DirectShareDiscriminator {
        DirectShareDiscriminator::Handle {
            handle_type: 1,
            handle: match discriminator {
                DirectShareDiscriminator::Handle { handle, .. } if handle == "00" => "01",
                _ => "00",
            }
            .to_owned(),
        }
    }

    /// The three recorded states (#3209), on whatever filesystem TMPDIR is.
    #[test]
    fn a_boot_check_applies_each_recorded_discriminator_state() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let (plan, admitted, identity_sha256) = direct_plan(&source);
        let recorded_as = |discriminator: DirectShareDiscriminator| {
            let mut recorded = DirectShareDiscriminators::default();
            recorded.insert(identity_sha256.clone(), discriminator);
            recorded
        };
        let admitted_alone = recorded_as(admitted.clone());

        // Absent: accepted once, recording what the share reads now.
        let checked = plan
            .check_direct_shares(&[], &DirectShareDiscriminators::default())
            .unwrap();
        assert_eq!(checked.shares.len(), 1);
        assert_eq!(checked.discriminators, admitted_alone);
        // A digest that names no plan entry counts as absent and is dropped.
        let mut stale = recorded_as(admitted.clone());
        stale.insert("f".repeat(64), other_handle(&admitted));
        let mut moved = DirectShareDiscriminators::default();
        moved.insert("f".repeat(64), other_handle(&admitted));
        for recorded in [stale, moved] {
            assert_eq!(
                plan.check_direct_shares(&[], &recorded)
                    .unwrap()
                    .discriminators,
                admitted_alone
            );
        }
        // Unsupported: the identity decides, and a handle is recorded once
        // one can be read.
        assert_eq!(
            plan.check_direct_shares(&[], &recorded_as(DirectShareDiscriminator::Unsupported))
                .unwrap()
                .discriminators,
            admitted_alone
        );
        // A handle: the same one is accepted; another one, or none read now,
        // as on overlay, refuses the plan.
        assert_eq!(
            plan.check_direct_shares(&[], &admitted_alone)
                .unwrap()
                .discriminators,
            admitted_alone
        );
        assert!(matches!(
            plan.check_direct_shares(&[], &recorded_as(other_handle(&admitted))),
            Err(WorkspacePlanError::DirectShareChanged)
        ));
    }

    /// The startup sweep records only shares that still match their
    /// identity, never replaces a recorded handle, and refuses nothing.
    #[test]
    fn the_startup_sweep_records_matching_shares_and_keeps_recorded_handles() {
        let parent = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(parent.path()).unwrap();
        let source = parent.join("share");
        fs::create_dir(&source).unwrap();
        let (plan, admitted, identity_sha256) = direct_plan(&source);
        let recorded_as = |discriminator: DirectShareDiscriminator| {
            let mut recorded = DirectShareDiscriminators::default();
            recorded.insert(identity_sha256.clone(), discriminator);
            recorded
        };

        // Written before #3209: the matching share is recorded now.
        assert_eq!(
            plan.sweep_direct_share_discriminators(&[], &DirectShareDiscriminators::default()),
            recorded_as(admitted.clone())
        );
        let handle = recorded_as(other_handle(&admitted));
        assert_eq!(plan.sweep_direct_share_discriminators(&[], &handle), handle);

        // A share replaced before the sweep is not recorded, and one
        // recorded without a handle keeps that record.
        fs::rename(&source, parent.join("parked")).unwrap();
        fs::create_dir(&source).unwrap();
        assert!(
            plan.sweep_direct_share_discriminators(&[], &DirectShareDiscriminators::default())
                .is_empty()
        );
        let unsupported = recorded_as(DirectShareDiscriminator::Unsupported);
        assert_eq!(
            plan.sweep_direct_share_discriminators(&[], &unsupported),
            unsupported
        );
    }

    /// #3209 handoff: a replacement injected after the supervisor's check
    /// and before the runner prepares is refused by the runner's own reopen,
    /// because the checked shares hold every admitted inode until StartVm
    /// returns. TMPDIR on ext4 makes the replacement try to reuse it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_replacement_between_the_boot_check_and_the_runner_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(parent.path()).unwrap().join("share");
        fs::create_dir(&source).unwrap();
        let (plan, admitted, identity_sha256) = direct_plan(&source);
        let mut recorded = DirectShareDiscriminators::default();
        recorded.insert(identity_sha256, admitted);
        let WorkspaceInput::Direct { identity, .. } = &plan.inputs[0] else {
            unreachable!("a direct plan");
        };
        let runner_request = crate::direct_share::DirectShareRequest::new(
            source.clone(),
            identity.clone(),
            plan.direct_share_plan().unwrap().unwrap().mounts()[0].clone(),
        )
        .unwrap();

        let checked = plan.check_direct_shares(&[], &recorded).unwrap();
        assert!(!crate::direct_share::recreate_directory_reusing_inode(
            &source,
            identity.inode()
        ));
        assert!(runner_request.reopen(&[]).is_err());
        drop(checked);
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
