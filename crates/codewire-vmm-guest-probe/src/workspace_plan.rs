//! Sealed, image-derived workspace execution plans.
//!
//! The setup pack carries canonical Codewire project intent and an OCI image
//! configuration, but neither document is executable authority by itself.
//! This module independently validates both documents, resolves the image
//! identity through confined rootfs reads, and emits the small plan consumed
//! by trusted container PID 1 and the out-of-container daemon.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;

use codewire_project::{ProjectSpec, is_valid_environment_key};
use oci_spec::image::ImageConfiguration;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SetupArchitecture, SetupHeader, Sha256Value};

pub(crate) const WORKSPACE_PLAN_PATH: &str = "/generation/workspace-plan.json";
pub(crate) const ACTIVE_WORKSPACE_PLAN_PATH: &str = "/run/codewire/workspace-plan.json";
pub(crate) const CONTAINER_PLAN_PATH: &str = "/run/codewire-runtime/plan.json";

pub(crate) const PLAN_SCHEMA_VERSION: u32 = 5;
pub(crate) const MAX_PLAN_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_FILE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_ENTRIES: usize = 65_536;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT: usize = 4096;
const MAX_ADDITIONAL_GROUPS: usize = 256;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceIdentity {
    pub username: String,
    pub home: String,
    pub shell: String,
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

impl fmt::Debug for WorkspaceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceIdentity")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("additional_gid_count", &self.additional_gids.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspacePlan {
    pub schema_version: u32,
    pub root_generation: String,
    pub project_sha256: String,
    pub identity: WorkspaceIdentity,
    pub environment: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explicit_environment_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload_args: Vec<String>,
    pub workload_cwd: String,
    pub session_cwd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub install_command: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub startup_script: String,
    pub skills_selected: bool,
}

impl fmt::Debug for WorkspacePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspacePlan")
            .field("schema_version", &self.schema_version)
            .field("root_generation", &self.root_generation)
            .field("project_sha256", &self.project_sha256)
            .field("identity", &self.identity)
            .field("environment_count", &self.environment.len())
            .field(
                "explicit_environment_key_count",
                &self.explicit_environment_keys.len(),
            )
            .field("workload_argument_count", &self.workload_args.len())
            .field("install_present", &!self.install_command.is_empty())
            .field("startup_present", &!self.startup_script.is_empty())
            .field("skills_selected", &self.skills_selected)
            .finish_non_exhaustive()
    }
}

impl WorkspacePlan {
    pub(crate) fn from_verified_setup(
        project_bytes: &[u8],
        config_bytes: &[u8],
        header: &SetupHeader,
        lower: &Path,
    ) -> Result<Self, WorkspacePlanError> {
        let project: ProjectSpec =
            serde_json::from_slice(project_bytes).map_err(|_| WorkspacePlanError::Project)?;
        project
            .validate()
            .map_err(|_| WorkspacePlanError::Project)?;
        if project
            .canonical_json()
            .map_err(|_| WorkspacePlanError::Project)?
            != project_bytes
        {
            return Err(WorkspacePlanError::Project);
        }

        let configuration = ImageConfiguration::from_reader(config_bytes)
            .map_err(|_| WorkspacePlanError::ImageConfiguration)?;
        validate_platform(&configuration, header)?;
        let runtime = configuration.config().as_ref();
        let requested_user = runtime
            .and_then(|config| config.user().as_deref())
            .unwrap_or("");
        let mut identity = resolve_identity(lower, requested_user)?;

        let mut environment = BTreeMap::new();
        if let Some(entries) = runtime.and_then(|config| config.env().as_ref()) {
            merge_environment(&mut environment, entries)?;
        }
        for (key, value) in &project.environment {
            validate_environment_key(key)?;
            validate_value(value)?;
            environment.insert(key.clone(), value.clone());
        }
        environment
            .entry("HOME".to_owned())
            .or_insert_with(|| identity.home.clone());
        environment
            .entry("USER".to_owned())
            .or_insert_with(|| identity.username.clone());
        environment
            .entry("LOGNAME".to_owned())
            .or_insert_with(|| identity.username.clone());
        environment.entry("PATH".to_owned()).or_insert_with(|| {
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()
        });
        environment
            .entry("LANG".to_owned())
            .or_insert_with(|| "C.UTF-8".to_owned());
        // This is a credential-free Codewire route, not inherited image or
        // project authority. Reserve the variable so every daemon exec and
        // image workload uses the same fail-closed protected-provider path.
        environment.insert(
            "CODEX_HOME".to_owned(),
            crate::CODEX_GUEST_HOME_PATH.to_owned(),
        );
        if let Some(shell) = environment.get("SHELL") {
            validate_absolute_path(shell)?;
            identity.shell.clone_from(shell);
        } else {
            environment.insert("SHELL".to_owned(), identity.shell.clone());
        }

        let mut workload_args = runtime
            .and_then(|config| config.entrypoint().as_ref())
            .cloned()
            .unwrap_or_default();
        let command = runtime
            .and_then(|config| config.cmd().as_ref())
            .cloned()
            .unwrap_or_default();
        if workload_args.is_empty() {
            workload_args = command;
        } else {
            workload_args.extend(command);
        }
        validate_arguments(&workload_args)?;

        let workload_cwd = runtime
            .and_then(|config| config.working_dir().as_deref())
            .filter(|value| !value.is_empty())
            .unwrap_or("/")
            .to_owned();
        validate_absolute_path(&workload_cwd)?;
        validate_absolute_path(&project.working_directory)?;
        validate_value(&project.install_command)?;
        validate_value(&project.startup_script)?;

        let plan = Self {
            schema_version: PLAN_SCHEMA_VERSION,
            root_generation: header.root_generation.to_string(),
            project_sha256: Sha256Value::calculate(project_bytes).to_string(),
            identity,
            environment: environment
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect(),
            explicit_environment_keys: project.environment.keys().cloned().collect(),
            workload_args,
            workload_cwd,
            session_cwd: project.working_directory,
            install_command: project.install_command,
            startup_script: project.startup_script,
            skills_selected: !project.skills.is_empty(),
        };
        plan.validate()?;
        Ok(plan)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, WorkspacePlanError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| WorkspacePlanError::Plan)?;
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(WorkspacePlanError::Plan);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WorkspacePlanError> {
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(WorkspacePlanError::Plan);
        }
        let plan: Self = serde_json::from_slice(bytes).map_err(|_| WorkspacePlanError::Plan)?;
        plan.validate()?;
        if plan.encode()? != bytes {
            return Err(WorkspacePlanError::Plan);
        }
        Ok(plan)
    }

    fn validate(&self) -> Result<(), WorkspacePlanError> {
        if self.schema_version != PLAN_SCHEMA_VERSION
            || !valid_sha256(&self.root_generation)
            || !valid_sha256(&self.project_sha256)
            || self.identity.username.is_empty()
            || self.identity.username.len() > 256
            || !valid_account_name(&self.identity.username)
            || self.identity.additional_gids.len() > MAX_ADDITIONAL_GROUPS
            || self
                .identity
                .additional_gids
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self.identity.additional_gids.contains(&self.identity.gid)
        {
            return Err(WorkspacePlanError::Plan);
        }
        validate_home_path(&self.identity.home)?;
        validate_absolute_path(&self.identity.shell)?;
        validate_absolute_path(&self.workload_cwd)?;
        validate_absolute_path(&self.session_cwd)?;
        validate_arguments(&self.workload_args)?;
        validate_value(&self.install_command)?;
        validate_value(&self.startup_script)?;

        if self.environment.is_empty() || self.environment.len() > MAX_ENVIRONMENT {
            return Err(WorkspacePlanError::Plan);
        }
        let mut keys = BTreeSet::new();
        let mut total = 0_usize;
        for entry in &self.environment {
            validate_value(entry)?;
            total = total
                .checked_add(entry.len())
                .filter(|value| *value <= MAX_PLAN_BYTES)
                .ok_or(WorkspacePlanError::Plan)?;
            let (key, value) = entry.split_once('=').ok_or(WorkspacePlanError::Plan)?;
            validate_environment_key(key)?;
            if key == "CODEX_HOME" && value != crate::CODEX_GUEST_HOME_PATH {
                return Err(WorkspacePlanError::Plan);
            }
            if !keys.insert(key) {
                return Err(WorkspacePlanError::Plan);
            }
        }
        for required in ["CODEX_HOME", "HOME", "USER", "LOGNAME", "PATH", "SHELL"] {
            if !keys.contains(required) {
                return Err(WorkspacePlanError::Plan);
            }
        }
        if self.explicit_environment_keys.len() > MAX_ENVIRONMENT
            || self
                .explicit_environment_keys
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(WorkspacePlanError::Plan);
        }
        for key in &self.explicit_environment_keys {
            validate_environment_key(key)?;
            if !keys.contains(key.as_str()) {
                return Err(WorkspacePlanError::Plan);
            }
        }
        Ok(())
    }
}

fn validate_platform(
    configuration: &ImageConfiguration,
    header: &SetupHeader,
) -> Result<(), WorkspacePlanError> {
    let (architecture, variant) = match header.architecture {
        SetupArchitecture::Amd64 => ("amd64", None),
        SetupArchitecture::Arm64 => ("arm64", Some("v8")),
    };
    if configuration.os().to_string() != "linux"
        || configuration.architecture().to_string() != architecture
        || configuration
            .variant()
            .as_deref()
            .is_some_and(|actual| Some(actual) != variant)
        || configuration.rootfs().typ() != "layers"
        || configuration
            .os_features()
            .as_ref()
            .is_some_and(|features| !features.is_empty())
        || configuration.rootfs().diff_ids().len() != header.layers.len()
        || configuration
            .rootfs()
            .diff_ids()
            .iter()
            .zip(&header.layers)
            .any(|(actual, expected)| {
                Sha256Value::parse_digest(actual).ok() != Some(expected.diff_id)
            })
    {
        return Err(WorkspacePlanError::UnsupportedPlatform);
    }
    Ok(())
}

fn merge_environment(
    output: &mut BTreeMap<String, String>,
    entries: &[String],
) -> Result<(), WorkspacePlanError> {
    if entries.len() > MAX_ENVIRONMENT {
        return Err(WorkspacePlanError::Environment);
    }
    for entry in entries {
        validate_value(entry)?;
        let (key, value) = entry
            .split_once('=')
            .ok_or(WorkspacePlanError::Environment)?;
        validate_environment_key(key)?;
        validate_value(value)?;
        output.insert(key.to_owned(), value.to_owned());
    }
    Ok(())
}

fn validate_environment_key(key: &str) -> Result<(), WorkspacePlanError> {
    if !is_valid_environment_key(key) {
        return Err(WorkspacePlanError::Environment);
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), WorkspacePlanError> {
    if arguments.len() > MAX_ARGUMENTS
        || arguments.first().is_some_and(String::is_empty)
        || arguments
            .iter()
            .any(|argument| validate_value(argument).is_err())
        || arguments
            .iter()
            .map(String::len)
            .try_fold(0_usize, usize::checked_add)
            .is_none_or(|total| total > MAX_PLAN_BYTES)
    {
        return Err(WorkspacePlanError::Command);
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), WorkspacePlanError> {
    if value.len() > MAX_STRING_BYTES || value.as_bytes().contains(&0) {
        return Err(WorkspacePlanError::Value);
    }
    Ok(())
}

fn validate_absolute_path(value: &str) -> Result<(), WorkspacePlanError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || (value != "/"
            && value
                .split('/')
                .skip(1)
                .any(|component| component.is_empty() || matches!(component, "." | "..")))
    {
        return Err(WorkspacePlanError::Path);
    }
    Ok(())
}

fn validate_home_path(value: &str) -> Result<(), WorkspacePlanError> {
    validate_absolute_path(value)?;
    if value != "/root"
        && !value.strip_prefix("/home/").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(WorkspacePlanError::Path);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug)]
struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

#[derive(Debug)]
struct GroupEntry {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn resolve_identity(root: &Path, requested: &str) -> Result<WorkspaceIdentity, WorkspacePlanError> {
    let passwd = parse_passwd(read_confined_optional(root, b"etc/passwd")?.as_deref())?;
    let groups = parse_group(read_confined_optional(root, b"etc/group")?.as_deref())?;
    let (user, group) = parse_user_request(requested)?;

    let entry = match user {
        RequestedIdentity::Id(uid) => passwd.iter().find(|entry| entry.uid == uid),
        RequestedIdentity::Name(name) => passwd.iter().find(|entry| entry.name == name),
    };
    if matches!(user, RequestedIdentity::Name(_)) && entry.is_none() {
        return Err(WorkspacePlanError::Identity);
    }
    let uid = match user {
        RequestedIdentity::Id(uid) => uid,
        RequestedIdentity::Name(_) => entry.ok_or(WorkspacePlanError::Identity)?.uid,
    };
    let username = entry.map(|entry| entry.name.clone()).unwrap_or_else(|| {
        if uid == 0 {
            "root".to_owned()
        } else {
            uid.to_string()
        }
    });
    let gid = match group {
        Some(RequestedIdentity::Id(gid)) => gid,
        Some(RequestedIdentity::Name(name)) => groups
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.gid)
            .ok_or(WorkspacePlanError::Identity)?,
        None => entry.map_or(0, |entry| entry.gid),
    };
    let home = entry
        .map(|entry| entry.home.clone())
        .unwrap_or_else(|| if uid == 0 { "/root" } else { "/home/codewire" }.to_owned());
    let shell = entry
        .map(|entry| entry.shell.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_owned());
    validate_home_path(&home)?;
    validate_absolute_path(&shell)?;

    let mut additional_gids = groups
        .iter()
        .filter(|entry| entry.gid != gid && entry.members.iter().any(|member| member == &username))
        .map(|entry| entry.gid)
        .collect::<Vec<_>>();
    additional_gids.sort_unstable();
    additional_gids.dedup();
    if additional_gids.len() > MAX_ADDITIONAL_GROUPS {
        return Err(WorkspacePlanError::Identity);
    }
    Ok(WorkspaceIdentity {
        username,
        home,
        shell,
        uid,
        gid,
        additional_gids,
    })
}

#[derive(Clone, Copy)]
enum RequestedIdentity<'a> {
    Id(u32),
    Name(&'a str),
}

fn parse_user_request(
    requested: &str,
) -> Result<(RequestedIdentity<'_>, Option<RequestedIdentity<'_>>), WorkspacePlanError> {
    if requested.matches(':').count() > 1 {
        return Err(WorkspacePlanError::Identity);
    }
    let (user, group) = requested
        .split_once(':')
        .map_or((requested, None), |(user, group)| (user, Some(group)));
    let user = if user.is_empty() { "0" } else { user };
    let user = parse_requested_identity(user)?;
    let group = group.map(parse_requested_identity).transpose()?;
    Ok((user, group))
}

fn parse_requested_identity(value: &str) -> Result<RequestedIdentity<'_>, WorkspacePlanError> {
    if value.is_empty() {
        return Err(WorkspacePlanError::Identity);
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value
            .parse::<u32>()
            .map(RequestedIdentity::Id)
            .map_err(|_| WorkspacePlanError::Identity);
    }
    if valid_account_name(value) {
        Ok(RequestedIdentity::Name(value))
    } else {
        Err(WorkspacePlanError::Identity)
    }
}

fn valid_account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn parse_passwd(bytes: Option<&[u8]>) -> Result<Vec<PasswdEntry>, WorkspacePlanError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(bytes).map_err(|_| WorkspacePlanError::IdentityDatabase)?;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        if entries.len() >= MAX_IDENTITY_ENTRIES || line.len() > MAX_STRING_BYTES {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 || !valid_account_name(fields[0]) || !names.insert(fields[0]) {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        let uid = parse_id(fields[2])?;
        if !ids.insert(uid) {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        entries.push(PasswdEntry {
            name: fields[0].to_owned(),
            uid,
            gid: parse_id(fields[3])?,
            home: fields[5].to_owned(),
            shell: fields[6].to_owned(),
        });
    }
    Ok(entries)
}

fn parse_group(bytes: Option<&[u8]>) -> Result<Vec<GroupEntry>, WorkspacePlanError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(bytes).map_err(|_| WorkspacePlanError::IdentityDatabase)?;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        if entries.len() >= MAX_IDENTITY_ENTRIES || line.len() > MAX_STRING_BYTES {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 || !valid_account_name(fields[0]) || !names.insert(fields[0]) {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        let gid = parse_id(fields[2])?;
        if !ids.insert(gid) {
            return Err(WorkspacePlanError::IdentityDatabase);
        }
        let members = if fields[3].is_empty() {
            Vec::new()
        } else {
            let members = fields[3].split(',').map(str::to_owned).collect::<Vec<_>>();
            if members.len() > MAX_ADDITIONAL_GROUPS
                || members.iter().any(|member| !valid_account_name(member))
            {
                return Err(WorkspacePlanError::IdentityDatabase);
            }
            members
        };
        entries.push(GroupEntry {
            name: fields[0].to_owned(),
            gid,
            members,
        });
    }
    Ok(entries)
}

fn parse_id(value: &str) -> Result<u32, WorkspacePlanError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WorkspacePlanError::IdentityDatabase);
    }
    value
        .parse()
        .map_err(|_| WorkspacePlanError::IdentityDatabase)
}

fn read_confined_optional(
    root: &Path,
    relative: &[u8],
) -> Result<Option<Vec<u8>>, WorkspacePlanError> {
    let root = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| WorkspacePlanError::Fs {
        action: "open OCI identity root",
        source,
    })?;
    let descriptor = match rustix::fs::openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(source) => {
            return Err(WorkspacePlanError::Fs {
                action: "open confined OCI identity file",
                source,
            });
        }
    };
    let stat = rustix::fs::fstat(&descriptor).map_err(|source| WorkspacePlanError::Fs {
        action: "inspect confined OCI identity file",
        source,
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > MAX_IDENTITY_FILE_BYTES
    {
        return Err(WorkspacePlanError::IdentityDatabase);
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    File::from(descriptor)
        .take(MAX_IDENTITY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| WorkspacePlanError::Io {
            action: "read confined OCI identity file",
            source,
        })?;
    if bytes.len() != stat.st_size as usize {
        return Err(WorkspacePlanError::IdentityDatabase);
    }
    Ok(Some(bytes))
}

#[derive(Debug, Error)]
pub(crate) enum WorkspacePlanError {
    #[error("verified Codewire project intent is not canonical")]
    Project,
    #[error("verified OCI image configuration is invalid")]
    ImageConfiguration,
    #[error("verified OCI image configuration is not native Linux content")]
    UnsupportedPlatform,
    #[error("OCI image identity is invalid or unavailable")]
    Identity,
    #[error("OCI image identity database is invalid")]
    IdentityDatabase,
    #[error("workspace environment is invalid")]
    Environment,
    #[error("workspace command is invalid")]
    Command,
    #[error("workspace path is invalid")]
    Path,
    #[error("workspace value is invalid")]
    Value,
    #[error("sealed workspace execution plan is invalid")]
    Plan,
    #[error("{action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{action}: {source}")]
    Fs {
        action: &'static str,
        #[source]
        source: Errno,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use codewire_project::ProjectSpec;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{LayerEncoding, SetupBlob, SetupLayerBlob, Sha256Value, oci_root_generation};

    #[test]
    fn guest_environment_names_use_the_canonical_project_boundary() {
        let maximum = format!(
            "A{}",
            "_".repeat(codewire_project::MAX_ENVIRONMENT_KEY_BYTES - 1)
        );
        let too_long = format!(
            "A{}",
            "_".repeat(codewire_project::MAX_ENVIRONMENT_KEY_BYTES)
        );

        assert!(validate_environment_key(&maximum).is_ok());
        assert!(matches!(
            validate_environment_key(&too_long),
            Err(WorkspacePlanError::Environment)
        ));
    }

    fn root() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/passwd"),
            b"root:x:0:0:root:/root:/bin/sh\ncodewire:x:1000:1000:Codewire:/home/codewire:/bin/bash\n",
        )
        .unwrap();
        fs::write(
            root.path().join("etc/group"),
            b"root:x:0:\ncodewire:x:1000:\ndocker:x:998:codewire\n",
        )
        .unwrap();
        root
    }

    fn project() -> Vec<u8> {
        let mut project = ProjectSpec {
            image: "registry.example/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            ..ProjectSpec::default()
        };
        project.environment.insert("PROJECT".into(), "yes".into());
        project.install_command = "true".into();
        project.startup_script = "sleep 1".into();
        project.canonical_json().unwrap()
    }

    fn setup(config: &[u8]) -> SetupHeader {
        let project = project();
        let project_sha = Sha256Value::calculate(&project);
        let config_sha = Sha256Value::calculate(config);
        let diff_id = Sha256Value::calculate(b"layer");
        let manifest = Sha256Value::calculate(b"manifest");
        let generation = oci_root_generation(project_sha, manifest, SetupArchitecture::Amd64);
        SetupHeader::layout(
            generation,
            manifest,
            SetupArchitecture::Amd64,
            SetupBlob {
                size: project.len() as u64,
                sha256: project_sha,
            },
            SetupBlob {
                size: config.len() as u64,
                sha256: config_sha,
            },
            vec![SetupLayerBlob {
                blob: SetupBlob {
                    size: 5,
                    sha256: Sha256Value::calculate(b"layer"),
                },
                diff_id,
                encoding: LayerEncoding::Tar,
            }],
        )
        .unwrap()
    }

    fn config(overrides: serde_json::Value) -> Vec<u8> {
        let mut value = json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "codewire",
                "Env": ["PATH=/image/bin:/bin", "SHELL=/bin/bash", "IMAGE=yes", "CODEX_HOME=/image/codex"],
                "Entrypoint": ["/entrypoint.sh"],
                "Cmd": ["sleep", "infinity"],
                "WorkingDir": "/home/codewire"
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [format!("sha256:{}", Sha256Value::calculate(b"layer"))]
            }
        });
        merge_json(&mut value, overrides);
        serde_json::to_vec(&value).unwrap()
    }

    fn merge_json(target: &mut serde_json::Value, source: serde_json::Value) {
        match (target, source) {
            (serde_json::Value::Object(target), serde_json::Value::Object(source)) => {
                for (key, value) in source {
                    merge_json(target.entry(key).or_insert(serde_json::Value::Null), value);
                }
            }
            (target, source) => *target = source,
        }
    }

    #[test]
    fn canonical_image_plan_honors_identity_environment_and_process_contract() {
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let plan =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();

        assert_eq!(plan.identity.uid, 1000);
        assert_eq!(plan.identity.gid, 1000);
        assert_eq!(plan.identity.additional_gids, vec![998]);
        assert_eq!(plan.identity.home, "/home/codewire");
        assert_eq!(plan.identity.shell, "/bin/bash");
        assert_eq!(plan.workload_cwd, "/home/codewire");
        assert_eq!(plan.session_cwd, "/workspace");
        assert_eq!(
            plan.project_sha256,
            Sha256Value::calculate(&project()).to_string()
        );
        assert!(!plan.skills_selected);
        assert_eq!(plan.workload_args, ["/entrypoint.sh", "sleep", "infinity"]);
        assert!(plan.environment.contains(&"IMAGE=yes".to_owned()));
        assert!(plan.environment.contains(&"PROJECT=yes".to_owned()));
        assert!(
            plan.environment
                .contains(&format!("CODEX_HOME={}", crate::CODEX_GUEST_HOME_PATH))
        );
        assert!(
            !plan
                .environment
                .contains(&"CODEX_HOME=/image/codex".to_owned())
        );
        assert_eq!(
            WorkspacePlan::decode(&plan.encode().unwrap()).unwrap(),
            plan
        );
    }

    #[test]
    fn numeric_identity_and_explicit_group_do_not_require_named_entries() {
        let root = root();
        let config = config(json!({"config": {"User": "1234:4321"}}));
        let header = setup(&config);
        let plan =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        assert_eq!(plan.identity.uid, 1234);
        assert_eq!(plan.identity.gid, 4321);
        assert_eq!(plan.identity.home, "/home/codewire");
    }

    #[test]
    fn wrong_diff_id_and_noncanonical_project_fail_closed() {
        let root = root();
        let bad_config = config(
            json!({"rootfs": {"diff_ids": [format!("sha256:{}", Sha256Value::calculate(b"other"))]}}),
        );
        let header = setup(&bad_config);
        assert!(matches!(
            WorkspacePlan::from_verified_setup(&project(), &bad_config, &header, root.path()),
            Err(WorkspacePlanError::UnsupportedPlatform)
        ));

        let config = config(json!({}));
        let header = setup(&config);
        let mut value: serde_json::Value = serde_json::from_slice(&project()).unwrap();
        value["working_directory"] = "/other".into();
        let noncanonical = serde_json::to_vec_pretty(&value).unwrap();
        assert!(matches!(
            WorkspacePlan::from_verified_setup(&noncanonical, &config, &header, root.path()),
            Err(WorkspacePlanError::Project)
        ));
    }

    #[test]
    fn identity_database_symlinks_and_attacker_values_are_rejected_without_echo() {
        let root = root();
        fs::remove_file(root.path().join("etc/passwd")).unwrap();
        symlink("/etc/passwd", root.path().join("etc/passwd")).unwrap();
        let config = config(json!({"config": {"User": "attacker-canary"}}));
        let header = setup(&config);
        let error = WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path())
            .unwrap_err();
        assert!(!error.to_string().contains("attacker-canary"));
    }

    #[test]
    fn persisted_plan_rejects_unknown_fields_and_noncanonical_bytes() {
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let mut plan =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        let bytes = plan.encode().unwrap();
        assert_eq!(WorkspacePlan::decode(&bytes).unwrap(), plan);

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unknown"] = true.into();
        assert!(WorkspacePlan::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["schema_version"] = 1.into();
        assert!(WorkspacePlan::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(WorkspacePlan::decode(&serde_json::to_vec_pretty(&plan).unwrap()).is_err());

        let mut wrong_codex_home = plan.clone();
        let entry = wrong_codex_home
            .environment
            .iter_mut()
            .find(|entry| entry.starts_with("CODEX_HOME="))
            .unwrap();
        *entry = "CODEX_HOME=/tmp/attacker".to_owned();
        assert!(wrong_codex_home.encode().is_err());

        plan.identity.username = "attacker-user-canary".into();
        plan.workload_args = vec!["attacker-command-canary".into()];
        plan.environment = vec!["ATTACKER=environment-canary".into()];
        plan.install_command = "attacker-install-canary".into();
        let debug = format!("{plan:?}");
        for canary in [
            "attacker-user-canary",
            "attacker-command-canary",
            "environment-canary",
            "attacker-install-canary",
        ] {
            assert!(!debug.contains(canary));
        }
    }

    #[test]
    fn persistent_home_is_limited_to_one_confined_account_directory() {
        assert!(validate_home_path("/root").is_ok());
        assert!(validate_home_path("/home/codewire").is_ok());
        assert!(matches!(
            validate_home_path("/home/team/codewire"),
            Err(WorkspacePlanError::Path)
        ));
        assert!(matches!(
            validate_home_path("/srv/codewire"),
            Err(WorkspacePlanError::Path)
        ));
    }
}
