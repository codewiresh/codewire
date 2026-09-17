//! Exact credential-free workspace plan codec shared by supervisor metadata.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use codewire_project::{ProjectSpec, parse_repository_ssh_host};
use codewire_vmm_guest_probe::{DirectShareMount, DirectSharePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::direct_share::DirectShareIdentity;
use super::oci::Sha256Digest;
use super::workspace::WorkspaceSourceMode;

pub(crate) const WORKSPACE_PLAN_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_WORKSPACE_PLAN_BYTES: usize = 512 * 1024;
const MAXIMUM_GIT_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
    #[cfg(any(target_os = "linux", test))]
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
                    validate_retained_repository_source(source)?;
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

    #[cfg(any(target_os = "linux", test))]
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
    pub(crate) fn destination(&self) -> &str {
        match self {
            Self::Local { destination, .. }
            | Self::Direct { destination, .. }
            | Self::Repository { destination, .. } => destination,
        }
    }
}

pub(crate) fn validate_retained_repository_source(source: &str) -> Result<(), WorkspacePlanError> {
    if parse_repository_ssh_host(source)
        .map_err(|_| WorkspacePlanError::UnsupportedRepositorySource)?
        .is_some()
    {
        return Ok(());
    }
    validate_anonymous_https_source(source)
}

pub(crate) fn validate_anonymous_https_source(source: &str) -> Result<(), WorkspacePlanError> {
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

pub(crate) fn validate_destination(destination: &str) -> Result<(), WorkspacePlanError> {
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

pub(crate) fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_git_selector(value: &str) -> bool {
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
    #[cfg(target_os = "linux")]
    #[error("SSH repository checkout requires a selected credential profile")]
    MissingRepositoryCredentialProfile,
    #[cfg(target_os = "linux")]
    #[error("repository host trust is missing or noncanonical")]
    InvalidRepositoryHostTrust,
    #[cfg(target_os = "linux")]
    #[error("remote repository has no valid default branch")]
    InvalidRemoteHead,
    #[cfg(target_os = "linux")]
    #[error("remote repository did not resolve to a valid commit")]
    InvalidRemoteCommit,
    #[cfg(target_os = "linux")]
    #[error("remote repository tree is malformed")]
    InvalidRemoteTree,
    #[cfg(target_os = "linux")]
    #[error("Git submodules are not supported by this repository slice")]
    SubmoduleUnsupported,
    #[cfg(target_os = "linux")]
    #[error("Git is required to prepare native remote repositories")]
    GitUnavailable,
    #[cfg(target_os = "linux")]
    #[error("remote Git preparation failed")]
    GitCommandFailed,
    #[cfg(target_os = "linux")]
    #[error("local credential authority is unavailable for protected repository preparation")]
    CredentialAuthorityUnavailable,
    #[cfg(target_os = "linux")]
    #[error("protected repository preparation is unavailable")]
    CredentialRepositoryUnavailable,
    #[cfg(target_os = "linux")]
    #[error("protected repository preparation was rejected ({0:?})")]
    CredentialRepositoryRejected(tonic::Code),
    #[cfg(target_os = "linux")]
    #[error("protected repository output is invalid")]
    CredentialRepositoryInvalid,
    #[cfg(target_os = "linux")]
    #[error("remote Git preparation timed out")]
    GitTimeout,
    #[cfg(target_os = "linux")]
    #[error("remote Git output exceeded the safety limit")]
    GitOutputTooLarge,
    #[cfg(target_os = "linux")]
    #[error("remote Git returned invalid text")]
    InvalidGitOutput,
    #[cfg(target_os = "linux")]
    #[error("remote Git bundle exceeds the content bound")]
    BundleTooLarge,
    #[cfg(target_os = "linux")]
    #[error("remote Git bundle changed while it was admitted")]
    BundleChanged,
    #[cfg(target_os = "linux")]
    #[error("direct-share source is unsafe or unsupported")]
    DirectShareInvalid,
    #[cfg(target_os = "linux")]
    #[error("direct-share source changed after admission")]
    DirectShareChanged,
    #[cfg(target_os = "linux")]
    #[error("remote repository preparation path is unsafe: {0}")]
    UnsafePreparation(PathBuf),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Content(#[from] crate::oci::ContentStoreError),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Path(#[from] crate::linux::path::PathError),
    #[cfg(target_os = "linux")]
    #[error("repository preparation filesystem operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}
