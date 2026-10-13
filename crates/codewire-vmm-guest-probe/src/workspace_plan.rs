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

pub(crate) const PLAN_SCHEMA_VERSION: u32 = 6;
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
    /// Active-only binding to the exact ordinary plan before client routing.
    /// This is neither a new generation nor authority supplied by the workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_plan_sha256: Option<String>,
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
            .field("active", &self.installation_plan_sha256.is_some())
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
            if key == "CODEX_HOME" {
                return Err(WorkspacePlanError::Project);
            }
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
        // Native agent-home ownership predates credential routing: this fixed
        // mount preserves skills and session state independently of profiles.
        // Only this boot's selected client decides whether provider config is
        // published there; the directory itself grants no provider access.
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
            installation_plan_sha256: None,
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

    /// Overlay only this boot's selected client routes on the active copy.
    /// The durable image/project plan remains unchanged for update and clear.
    pub(crate) fn with_managed_credential_clients(
        mut self,
        clients: codewire_access::ManagedCredentialClients,
    ) -> Result<Self, WorkspacePlanError> {
        self.require_ordinary()?;
        if self
            .explicit_environment_keys
            .iter()
            .any(|key| key == "CODEX_HOME")
        {
            return Err(WorkspacePlanError::Plan);
        }
        clients
            .check_collisions(self.explicit_environment_keys.iter().map(String::as_str))
            .map_err(|_| WorkspacePlanError::Plan)?;
        let installation_plan_sha256 = Sha256Value::calculate(&self.encode()?).to_string();
        let projection =
            clients.for_placement(codewire_access::ManagedCredentialClientPlacement::Native);
        let mut environment: BTreeMap<String, String> = self
            .environment
            .iter()
            .map(|entry| {
                entry
                    .split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .ok_or(WorkspacePlanError::Plan)
            })
            .collect::<Result<_, _>>()?;
        // An image value of a selected client's name is removed, whether or
        // not that name is projected (the Anthropic form that was not
        // selected is reserved but absent), as the daemon does for the
        // sessions it starts.
        let reserved = clients.reserved_environment_keys();
        environment.retain(|name, _| !reserved.contains(name.as_str()));
        environment.extend(projection.environment);
        // Every managed HTTP route is the workspace's loopback ingress. A
        // proxy the image or the project declares must never receive those
        // requests, so the exemption list is extended (never replaced) by
        // the shared rule, as the daemon does for the sessions it starts.
        for name in codewire_access::NO_PROXY_NAMES {
            if let Some(value) = clients.no_proxy(environment.get(name).map(String::as_str)) {
                environment.insert(name.to_owned(), value);
            }
        }
        self.environment = environment
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        self.installation_plan_sha256 = Some(installation_plan_sha256);
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn require_ordinary(&self) -> Result<(), WorkspacePlanError> {
        self.validate()?;
        if self.installation_plan_sha256.is_some() {
            return Err(WorkspacePlanError::Plan);
        }
        Ok(())
    }

    pub(crate) fn require_active(&self) -> Result<(), WorkspacePlanError> {
        self.validate()?;
        if self.installation_plan_sha256.is_none() {
            return Err(WorkspacePlanError::Plan);
        }
        Ok(())
    }

    /// Installation belongs to immutable image/project intent, whereas the
    /// active plan's encoding still binds this boot's Ready/ack messages.
    pub(crate) fn installation_identity(&self) -> Result<Sha256Value, WorkspacePlanError> {
        let bytes = self.encode()?;
        match &self.installation_plan_sha256 {
            Some(hash) => Sha256Value::parse_hex(hash).map_err(|_| WorkspacePlanError::Plan),
            None => Ok(Sha256Value::calculate(&bytes)),
        }
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
            || self
                .installation_plan_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash) || hash.bytes().all(|byte| byte == b'0'))
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
    fn selected_clients_are_applied_to_each_active_copy_without_stale_setup_routing() {
        use codewire_access::ManagedCredentialClients;
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let persisted =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        let bytes = persisted.encode().unwrap();
        let installation_identity = Sha256Value::calculate(&bytes);
        assert!(persisted.installation_plan_sha256.is_none());
        assert!(persisted.require_ordinary().is_ok());
        assert!(persisted.require_active().is_err());
        for (slots, codex, openai, anthropic, ssh) in [
            (vec![], false, false, false, false),
            (vec!["codex"], true, false, false, false),
            (vec!["openai"], false, true, false, false),
            (vec!["anthropic"], false, false, true, false),
            (vec!["ssh"], false, false, false, true),
            (vec!["github"], false, false, false, false),
            (
                vec!["codex", "openai", "anthropic", "ssh", "github"],
                true,
                true,
                true,
                true,
            ),
            (vec![], false, false, false, false),
        ] {
            let clients = ManagedCredentialClients::from_profile_slots(slots).unwrap();
            let active = WorkspacePlan::decode(&bytes)
                .unwrap()
                .with_managed_credential_clients(clients)
                .unwrap();
            let env: BTreeMap<_, _> = active
                .environment
                .iter()
                .map(|entry| entry.split_once('=').unwrap())
                .collect();
            assert_eq!(env["CODEX_HOME"], crate::CODEX_GUEST_HOME_PATH);
            assert_eq!(
                clients.contains(codewire_access::ManagedCredentialClient::Codex),
                codex
            );
            assert_eq!(env.contains_key("OPENAI_BASE_URL"), openai);
            assert_eq!(env.contains_key("ANTHROPIC_BASE_URL"), anthropic);
            assert_eq!(
                env.get("SSH_AUTH_SOCK").copied(),
                ssh.then_some(codewire_access::SSH_NATIVE_AUTH_SOCK)
            );
            assert_eq!(active.project_sha256, persisted.project_sha256);
            assert_eq!(
                active.installation_identity().unwrap(),
                installation_identity
            );
            assert!(active.require_active().is_ok());
            assert!(active.require_ordinary().is_err());
            assert_eq!(
                WorkspacePlan::decode(&active.encode().unwrap()).unwrap(),
                active
            );
            assert!(
                active
                    .with_managed_credential_clients(ManagedCredentialClients::default())
                    .is_err()
            );
            assert_eq!(persisted.encode().unwrap(), bytes);
        }
        let mut declared = persisted.clone();
        declared.explicit_environment_keys.push("CODEX_HOME".into());
        declared.explicit_environment_keys.sort();
        assert!(
            declared
                .clone()
                .with_managed_credential_clients(ManagedCredentialClients::default())
                .is_err()
        );
        let mut declared_ssh = persisted.clone();
        declared_ssh
            .environment
            .push("SSH_AUTH_SOCK=/project/ssh-agent.sock".into());
        declared_ssh.environment.sort();
        declared_ssh
            .explicit_environment_keys
            .push("SSH_AUTH_SOCK".into());
        declared_ssh.explicit_environment_keys.sort();
        assert!(
            declared_ssh
                .clone()
                .with_managed_credential_clients(ManagedCredentialClients::default())
                .is_ok()
        );
        assert!(
            declared_ssh
                .with_managed_credential_clients(
                    ManagedCredentialClients::from_profile_slots(["ssh"]).unwrap()
                )
                .is_err()
        );
        assert!(
            declared
                .with_managed_credential_clients(
                    ManagedCredentialClients::from_profile_slots(["codex"]).unwrap()
                )
                .is_err()
        );
    }

    /// The workspace's own environment exempts loopback from a declared proxy
    /// while an HTTP client is selected, by the rule the daemon applies to
    /// the sessions it starts: a declared list is extended, never replaced.
    #[test]
    fn a_declared_proxy_is_bypassed_for_loopback_while_an_http_client_is_selected() {
        use codewire_access::ManagedCredentialClients;
        const LOOPBACK: &str = "127.0.0.1,localhost,::1";
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let plain =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        let mut declared = plain.clone();
        for (name, value) in [
            ("HTTPS_PROXY", "http://proxy.example:3128"),
            ("NO_PROXY", "corp.example,10.0.0.0/8"),
        ] {
            declared.environment.push(format!("{name}={value}"));
            declared.explicit_environment_keys.push(name.into());
        }
        declared.environment.sort();
        declared.explicit_environment_keys.sort();
        let values = |plan: WorkspacePlan, slots: &[&str]| -> BTreeMap<String, String> {
            plan.with_managed_credential_clients(
                ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap(),
            )
            .unwrap()
            .environment
            .iter()
            .map(|entry| {
                let (name, value) = entry.split_once('=').unwrap();
                (name.to_owned(), value.to_owned())
            })
            .collect()
        };
        for slots in [&["anthropic"][..], &["codex", "github", "ssh"]] {
            let environment = values(plain.clone(), slots);
            assert_eq!(environment["NO_PROXY"], LOOPBACK, "{slots:?}");
            assert_eq!(environment["no_proxy"], LOOPBACK, "{slots:?}");

            let environment = values(declared.clone(), slots);
            assert_eq!(environment["HTTPS_PROXY"], "http://proxy.example:3128");
            assert_eq!(
                environment["NO_PROXY"],
                format!("corp.example,10.0.0.0/8,{LOOPBACK}")
            );
            assert_eq!(environment["no_proxy"], LOOPBACK);
        }
        // The signer alone, or no selection, uses no HTTP route.
        for slots in [&[][..], &["ssh"]] {
            let environment = values(plain.clone(), slots);
            assert!(!environment.contains_key("NO_PROXY") && !environment.contains_key("no_proxy"));
            let environment = values(declared.clone(), slots);
            assert_eq!(environment["NO_PROXY"], "corp.example,10.0.0.0/8");
            assert!(!environment.contains_key("no_proxy"));
        }
    }

    /// The `gh` names are projected without being reserved, so a declared
    /// value is not refused. The managed value wins over it while GitHub is
    /// selected, as it does in a hosted Sandbox, and the declared value is
    /// the workload's own otherwise.
    #[test]
    fn a_declared_gh_configuration_loses_to_the_managed_one_while_github_is_selected() {
        use codewire_access::ManagedCredentialClients;
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let mut declared =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        for (name, value) in [
            ("GH_CONFIG_DIR", "/home/codewire/.config/gh"),
            ("GH_TOKEN", "declared"),
        ] {
            declared.environment.push(format!("{name}={value}"));
            declared.explicit_environment_keys.push(name.into());
        }
        declared.environment.sort();
        declared.explicit_environment_keys.sort();
        let values = |plan: &WorkspacePlan| -> BTreeMap<String, String> {
            plan.environment
                .iter()
                .map(|entry| {
                    let (name, value) = entry.split_once('=').unwrap();
                    (name.to_owned(), value.to_owned())
                })
                .collect()
        };

        let selected = declared
            .clone()
            .with_managed_credential_clients(
                ManagedCredentialClients::from_profile_slots(["github"]).unwrap(),
            )
            .unwrap();
        let environment = values(&selected);
        assert_eq!(
            environment["GH_CONFIG_DIR"],
            codewire_access::GH_NATIVE_CONFIG_DIR
        );
        assert_eq!(
            environment["GH_TOKEN"],
            codewire_access::GH_TOKEN_PLACEHOLDER
        );
        assert_eq!(
            selected
                .environment
                .iter()
                .filter(|entry| entry.starts_with("GH_"))
                .count(),
            2
        );

        let unselected = declared
            .with_managed_credential_clients(
                ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
            )
            .unwrap();
        let environment = values(&unselected);
        assert_eq!(environment["GH_CONFIG_DIR"], "/home/codewire/.config/gh");
        assert_eq!(environment["GH_TOKEN"], "declared");
    }

    /// Issue #2720: a local VM's Git rewrites GitHub's URL forms for the
    /// selected Git credential, as a hosted Sandbox's does. The entries the
    /// selection does not reserve replace a declared value of the same name.
    #[test]
    fn the_github_url_rewrite_replaces_declared_git_entries_in_a_local_vm() {
        use codewire_access::ManagedCredentialClients;
        const MANAGED: &str = "url.http://127.0.0.1:38081/_codewire/github/.insteadOf";
        const SSH: &str = "url.git@github.com:.insteadOf";
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let mut declared =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        for (name, value) in [
            ("GIT_CONFIG_KEY_1", "core.editor"),
            ("GIT_CONFIG_VALUE_1", "vi"),
        ] {
            declared.environment.push(format!("{name}={value}"));
            declared.explicit_environment_keys.push(name.into());
        }
        declared.environment.sort();
        declared.explicit_environment_keys.sort();
        let git = |plan: &WorkspacePlan| -> BTreeMap<String, String> {
            plan.environment
                .iter()
                .filter(|entry| entry.starts_with("GIT_CONFIG_"))
                .map(|entry| {
                    let (name, value) = entry.split_once('=').unwrap();
                    (name.to_owned(), value.to_owned())
                })
                .collect()
        };
        for (slots, expected) in [
            (
                &["github"][..],
                &[
                    ("GIT_CONFIG_COUNT", "4"),
                    ("GIT_CONFIG_KEY_0", MANAGED),
                    ("GIT_CONFIG_VALUE_0", "https://github.com/"),
                    ("GIT_CONFIG_KEY_1", MANAGED),
                    ("GIT_CONFIG_VALUE_1", "git://github.com/"),
                    ("GIT_CONFIG_KEY_2", MANAGED),
                    ("GIT_CONFIG_VALUE_2", "git@github.com:"),
                    ("GIT_CONFIG_KEY_3", MANAGED),
                    ("GIT_CONFIG_VALUE_3", "ssh://git@github.com/"),
                ][..],
            ),
            (
                &["ssh"],
                &[
                    ("GIT_CONFIG_COUNT", "2"),
                    ("GIT_CONFIG_KEY_0", SSH),
                    ("GIT_CONFIG_VALUE_0", "https://github.com/"),
                    ("GIT_CONFIG_KEY_1", SSH),
                    ("GIT_CONFIG_VALUE_1", "git://github.com/"),
                ],
            ),
            (
                &["github", "ssh"],
                &[
                    ("GIT_CONFIG_COUNT", "2"),
                    ("GIT_CONFIG_KEY_0", MANAGED),
                    ("GIT_CONFIG_VALUE_0", "https://github.com/"),
                    ("GIT_CONFIG_KEY_1", MANAGED),
                    ("GIT_CONFIG_VALUE_1", "git://github.com/"),
                ],
            ),
            // Neither Git credential: the declared entries are the workload's.
            (
                &["codex"],
                &[
                    ("GIT_CONFIG_KEY_1", "core.editor"),
                    ("GIT_CONFIG_VALUE_1", "vi"),
                ],
            ),
        ] {
            let selected = declared
                .clone()
                .with_managed_credential_clients(
                    ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                git(&selected),
                expected
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
                "{slots:?}"
            );
        }
    }

    /// An image value of an Anthropic name never reaches the workspace while
    /// the Anthropic client is selected: each form projects only its own
    /// variable, and the other names are removed, not emptied.
    #[test]
    fn an_image_value_of_the_unselected_anthropic_form_is_removed() {
        use codewire_access::ManagedCredentialClients;
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let mut plan =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        for name in [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ] {
            plan.environment.push(format!("{name}=image-value"));
        }
        plan.environment.sort();
        let names = |plan: &WorkspacePlan| -> BTreeMap<String, String> {
            plan.environment
                .iter()
                .map(|entry| {
                    let (name, value) = entry.split_once('=').unwrap();
                    (name.to_owned(), value.to_owned())
                })
                .collect()
        };
        let api_key = ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap();
        for (clients, own, others) in [
            (
                api_key,
                "ANTHROPIC_AUTH_TOKEN",
                ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"],
            ),
            (
                api_key.with_anthropic_subscription_token().unwrap(),
                "CLAUDE_CODE_OAUTH_TOKEN",
                ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
            ),
        ] {
            let environment = names(
                &plan
                    .clone()
                    .with_managed_credential_clients(clients)
                    .unwrap(),
            );
            assert_eq!(environment[own], "codewire-managed");
            for other in others {
                assert!(!environment.contains_key(other), "{other}");
            }
        }
        // Without the Anthropic client the image's values are the workload's.
        let environment = names(
            &plan
                .with_managed_credential_clients(
                    ManagedCredentialClients::from_profile_slots(["codex"]).unwrap(),
                )
                .unwrap(),
        );
        assert_eq!(environment["ANTHROPIC_API_KEY"], "image-value");
    }

    #[test]
    fn installation_binding_requires_current_canonical_nonzero_digest_and_active_admission() {
        let root = root();
        let config = config(json!({}));
        let header = setup(&config);
        let ordinary =
            WorkspacePlan::from_verified_setup(&project(), &config, &header, root.path()).unwrap();
        let active = ordinary
            .clone()
            .with_managed_credential_clients(codewire_access::ManagedCredentialClients::default())
            .unwrap();
        assert_eq!(
            active.installation_plan_sha256,
            Some(Sha256Value::calculate(&ordinary.encode().unwrap()).to_string())
        );
        for hash in [
            String::new(),
            "0".repeat(64),
            "A".repeat(64),
            "g".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            format!("sha256:{}", "a".repeat(64)),
        ] {
            let mut invalid = active.clone();
            invalid.installation_plan_sha256 = Some(hash);
            assert!(invalid.require_active().is_err());
            assert!(invalid.installation_identity().is_err());
            assert!(invalid.encode().is_err());
            assert!(WorkspacePlan::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut missing = active;
        missing.installation_plan_sha256 = None;
        assert!(missing.require_active().is_err());
        for version in 1..PLAN_SCHEMA_VERSION {
            let mut retired = ordinary.clone();
            retired.schema_version = version;
            assert!(WorkspacePlan::decode(&serde_json::to_vec(&retired).unwrap()).is_err());
        }
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
