//! A new environment as a person enters it in a create form, and the rules
//! that turn it into a project and the request's own fields. The dashboard's
//! Create Sandbox form and the iOS app's Create sheet both build their create
//! from here, so each accepts and refuses the same input with the same words
//! (`docs/journeys/ios-app.md` `ios-create`).

use std::collections::HashSet;
use std::fmt;

use url::Url;

use crate::{
    ApplicationPort, PROJECT_SCHEMA_VERSION, ProjectSpec, RepositorySpec, ResourceSpec,
    validate_repository_destinations,
};

pub const MAX_REPOSITORIES: usize = 108;
pub const MAX_APP_PORTS: usize = 16;
/// The longest value one field may hold, in bytes.
pub const MAX_FIELD: usize = 16_384;

/// The fields as typed: numbers and lifetimes stay text until [`CreateInput::draft`]
/// reads them, so a refusal can name the field it came from.
#[derive(Clone, Default)]
pub struct CreateInput {
    pub name: String,
    pub preset_id: String,
    pub image: String,
    pub install_command: String,
    pub startup_script: String,
    /// Millicores.
    pub cpu: String,
    /// MiB.
    pub memory: String,
    /// GiB.
    pub disk: String,
    /// Delete after: a number with `s`, `m`, `h` or `d`; minutes without one.
    pub ttl: String,
    pub isolation_tier: String,
    pub repositories: Vec<RepositoryInput>,
    pub app_ports: Vec<PortInput>,
    /// The form said which previews it wants, so none means none, not the
    /// preset's.
    pub application_previews_explicit: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryInput {
    pub url: String,
    pub branch: String,
    pub mount_path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortInput {
    pub port: String,
    pub label: String,
    pub access: String,
}

/// What a preset fills in when the form left a field empty.
#[derive(Clone, Debug, Default)]
pub struct PresetDefaults {
    pub image: String,
    pub cpu_millicores: Option<u32>,
    pub memory_mib: Option<u64>,
    pub disk_gib: Option<u64>,
    pub ttl_seconds: Option<i32>,
    pub install_command: String,
    pub startup_script: String,
    pub app_ports: Vec<PortInput>,
}

/// A create the rules accepted.
#[derive(Clone, Debug)]
pub struct CreateDraft {
    pub preset_id: Option<String>,
    pub name: Option<String>,
    pub ttl_seconds: Option<i32>,
    pub isolation: Isolation,
    pub omit_application_previews: bool,
    pub project_spec: ProjectSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    Standard,
    Confidential,
}

/// One refusal: the field it belongs to and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateError {
    pub field: CreateField,
    pub reason: CreateReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateField {
    Repositories,
    Image,
    Name,
    Cpu,
    Memory,
    Disk,
    Ttl,
    /// The form as a whole: isolation, the project.
    Form,
    /// A preview row, by its index in [`CreateInput::app_ports`].
    PortNumber(usize),
    PortLabel(usize),
    PortAccess(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateReason {
    RepositoryUrl,
    RepositoryDestinations,
    ImageRequired,
    NameTooLong,
    OutOfRange { minimum: i32, maximum: i32 },
    Lifetime,
    ConfidentialUnavailable,
    IsolationTier,
    PortNumber,
    PortReserved,
    PortInUse,
    PortLabel,
    PortLabelInUse,
    PortAccess,
    ProjectInvalid,
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self.reason {
            CreateReason::OutOfRange { minimum, maximum } => {
                let label = match self.field {
                    CreateField::Cpu => "CPU",
                    CreateField::Memory => "Memory",
                    CreateField::Disk => "Disk",
                    _ => "Value",
                };
                return write!(f, "{label} must be between {minimum} and {maximum}.");
            }
            CreateReason::RepositoryUrl => {
                "Repository URLs must be clean HTTP(S) URLs without embedded credentials."
            }
            CreateReason::RepositoryDestinations => {
                "Repository destinations must be distinct paths inside /workspace."
            }
            CreateReason::ImageRequired => "Enter a workspace image or choose a repository.",
            CreateReason::NameTooLong => "Name must be 128 characters or fewer.",
            CreateReason::Lifetime => {
                "Enter a duration from 60 seconds to 365 days, such as 8h or 7d, or leave it empty."
            }
            CreateReason::ConfidentialUnavailable => {
                "Confidential Sandboxes are not available for this organization."
            }
            CreateReason::IsolationTier => "Choose a valid isolation tier.",
            CreateReason::PortNumber => "Enter an internal port from 1 to 65535.",
            CreateReason::PortReserved => "Port 2222 is reserved for the Sandbox runtime.",
            CreateReason::PortInUse => "This internal port is already used in another row.",
            CreateReason::PortLabel => {
                "Use 2–22 lowercase letters, digits or hyphens; start and end with a letter or digit."
            }
            CreateReason::PortLabelInUse => "This preview label is already used in another row.",
            CreateReason::PortAccess => "Choose who can open this HTTPS preview.",
            CreateReason::ProjectInvalid => "The Sandbox project configuration is invalid.",
        };
        f.write_str(text)
    }
}

impl PresetDefaults {
    /// A preset's defaults: its canonical project and its default lifetime.
    pub fn from_project(spec: ProjectSpec, ttl_seconds: Option<i32>) -> Self {
        Self {
            image: spec.image,
            cpu_millicores: spec.resources.cpu_millicores,
            memory_mib: spec.resources.memory_mib,
            disk_gib: spec.resources.disk_gib,
            ttl_seconds,
            install_command: spec.install_command,
            startup_script: spec.startup_script,
            app_ports: spec
                .application_ports
                .into_iter()
                .map(|port| PortInput {
                    port: port.port.to_string(),
                    label: port.label,
                    access: port.access,
                })
                .collect(),
        }
    }
}

impl CreateInput {
    /// Fills only the fields the form left empty, so an edit always wins.
    pub fn apply_preset_defaults(&mut self, preset: &PresetDefaults) {
        if self.image.trim().is_empty() {
            self.image = preset.image.clone();
        }
        if self.cpu.trim().is_empty()
            && let Some(cpu) = preset.cpu_millicores
        {
            self.cpu = cpu.to_string();
        }
        if self.memory.trim().is_empty()
            && let Some(memory) = preset.memory_mib
        {
            self.memory = memory.to_string();
        }
        if self.disk.trim().is_empty()
            && let Some(disk) = preset.disk_gib
        {
            self.disk = disk.to_string();
        }
        if ttl_uses_default(&self.ttl)
            && let Some(ttl) = preset.ttl_seconds
        {
            self.ttl = lifetime_field_value(ttl);
        }
        if self.install_command.is_empty() {
            self.install_command = preset.install_command.clone();
        }
        if self.startup_script.is_empty() {
            self.startup_script = preset.startup_script.clone();
        }
        if self.app_ports.is_empty() && !self.application_previews_explicit {
            self.app_ports = preset.app_ports.clone();
        }
    }

    /// The create these fields ask for, or every refusal in the order the
    /// form shows them; a later refusal of the same field replaces an earlier
    /// one.
    pub fn draft(&self, confidential_available: bool) -> Result<CreateDraft, Vec<CreateError>> {
        let mut errors = Vec::new();
        let mut refuse = |field, reason| errors.push(CreateError { field, reason });

        let mut repositories: Vec<RepositorySpec> = self
            .repositories
            .iter()
            .filter_map(|repository| {
                let url = repository.url.trim();
                (!url.is_empty()).then(|| RepositorySpec {
                    source: url.to_owned(),
                    revision: String::new(),
                    branch: repository.branch.trim().to_owned(),
                    destination: workspace_mount_path(&repository.mount_path),
                    known_hosts: Vec::new(),
                })
            })
            .collect();
        if repositories
            .iter()
            .any(|repository| !valid_repository_url(&repository.source))
        {
            refuse(CreateField::Repositories, CreateReason::RepositoryUrl);
        }
        if repositories.is_empty()
            && self.image.trim().is_empty()
            && self.preset_id.trim().is_empty()
        {
            refuse(CreateField::Image, CreateReason::ImageRequired);
        }
        match validate_repository_destinations(
            repositories
                .iter()
                .map(|repository| (repository.source.as_str(), repository.destination.as_str())),
        ) {
            Ok(destinations) => {
                for (repository, destination) in repositories.iter_mut().zip(destinations) {
                    repository.destination = destination;
                }
            }
            Err(_) => refuse(
                CreateField::Repositories,
                CreateReason::RepositoryDestinations,
            ),
        }

        if self.name.len() > 128 || self.name.bytes().any(|byte| byte.is_ascii_control()) {
            refuse(CreateField::Name, CreateReason::NameTooLong);
        }
        let mut bounded = |value: &str, minimum, maximum, field| {
            parse_bounded_i32(value, minimum, maximum).unwrap_or_else(|reason| {
                refuse(field, reason);
                None
            })
        };
        let cpu = bounded(&self.cpu, 100, 128_000, CreateField::Cpu);
        let memory = bounded(&self.memory, 128, 1_048_576, CreateField::Memory);
        let disk = bounded(&self.disk, 1, 16_384, CreateField::Disk);
        let ttl = parse_ttl(&self.ttl).unwrap_or_else(|reason| {
            refuse(CreateField::Ttl, reason);
            None
        });
        let isolation = match self.isolation_tier.trim() {
            "" | "standard" => Some(Isolation::Standard),
            "confidential" if confidential_available => Some(Isolation::Confidential),
            "confidential" => {
                refuse(CreateField::Form, CreateReason::ConfidentialUnavailable);
                None
            }
            _ => {
                refuse(CreateField::Form, CreateReason::IsolationTier);
                None
            }
        };

        let mut ports = Vec::new();
        let mut seen_ports = HashSet::new();
        let mut seen_labels = HashSet::new();
        for (index, row) in self.app_ports.iter().enumerate() {
            let (port, label) = (row.port.trim(), row.label.trim());
            if port.is_empty() && label.is_empty() {
                continue;
            }
            let mut row_refused = false;
            let mut refuse_row = |field, reason| {
                refuse(field, reason);
                row_refused = true;
            };
            let port_number = port.parse::<u16>().ok().filter(|port| *port != 0);
            match port_number {
                None => refuse_row(CreateField::PortNumber(index), CreateReason::PortNumber),
                Some(2222) => {
                    refuse_row(CreateField::PortNumber(index), CreateReason::PortReserved)
                }
                Some(port) if !seen_ports.insert(port) => {
                    refuse_row(CreateField::PortNumber(index), CreateReason::PortInUse)
                }
                Some(_) => {}
            }
            if !valid_port_label(label) {
                refuse_row(CreateField::PortLabel(index), CreateReason::PortLabel);
            } else if !seen_labels.insert(label) {
                refuse_row(CreateField::PortLabel(index), CreateReason::PortLabelInUse);
            }
            if !matches!(
                row.access.as_str(),
                "" | "creator" | "org_members" | "public"
            ) {
                refuse_row(CreateField::PortAccess(index), CreateReason::PortAccess);
            }
            if let (false, Some(port)) = (row_refused, port_number) {
                ports.push(ApplicationPort {
                    port,
                    label: label.to_owned(),
                    access: allowlisted_access(&row.access).to_owned(),
                });
            }
        }

        let Some(isolation) = isolation.filter(|_| errors.is_empty()) else {
            return Err(errors);
        };
        let working_directory = match repositories.as_slice() {
            [repository] => repository.destination.clone(),
            _ => "/workspace".to_owned(),
        };
        let omit_application_previews = self.application_previews_explicit && ports.is_empty();
        let project_spec = ProjectSpec {
            schema_version: PROJECT_SCHEMA_VERSION,
            image: self.image.trim().to_owned(),
            repositories,
            working_directory,
            install_command: self.install_command.clone(),
            startup_script: self.startup_script.clone(),
            application_ports: ports,
            resources: ResourceSpec {
                // The bounds above keep each value positive.
                cpu_millicores: cpu.map(i32::unsigned_abs),
                memory_mib: memory.map(|value| u64::from(value.unsigned_abs())),
                disk_gib: disk.map(|value| u64::from(value.unsigned_abs())),
            },
            ..ProjectSpec::default()
        };
        if project_spec.validate().is_err() {
            return Err(vec![CreateError {
                field: CreateField::Form,
                reason: CreateReason::ProjectInvalid,
            }]);
        }
        Ok(CreateDraft {
            preset_id: non_empty(self.preset_id.trim()),
            name: non_empty(self.name.trim()),
            ttl_seconds: ttl,
            isolation,
            omit_application_previews,
            project_spec,
        })
    }
}

/// Empty asks Create for the configuration's default lifetime. `0`,
/// `infinity` and `∞` are accepted with the same meaning for older input and
/// saved drafts.
pub fn ttl_uses_default(value: &str) -> bool {
    let value = value.trim();
    value.is_empty() || value == "0" || value.eq_ignore_ascii_case("infinity") || value == "∞"
}

/// A lifetime in the largest exact unit the Delete after field accepts, such
/// as `1h` for 3600 seconds or `90m` for 5400.
pub fn lifetime_field_value(seconds: i32) -> String {
    if seconds > 0 {
        for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
            if seconds % size == 0 {
                return format!("{}{unit}", seconds / size);
            }
        }
    }
    format!("{seconds}s")
}

/// Delete after in seconds, `None` for the default; minutes when no unit is
/// given.
pub fn parse_ttl(value: &str) -> Result<Option<i32>, CreateReason> {
    let value = value.trim();
    if ttl_uses_default(value) {
        return Ok(None);
    }
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1_i64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        Some(b'd') => (&value[..value.len() - 1], 86_400),
        _ => (value, 60),
    };
    digits
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|seconds| (60..=31_536_000).contains(seconds))
        .and_then(|seconds| i32::try_from(seconds).ok())
        .map(Some)
        .ok_or(CreateReason::Lifetime)
}

fn parse_bounded_i32(value: &str, minimum: i32, maximum: i32) -> Result<Option<i32>, CreateReason> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    match value.trim().parse::<i32>() {
        Ok(value) if (minimum..=maximum).contains(&value) => Ok(Some(value)),
        _ => Err(CreateReason::OutOfRange { minimum, maximum }),
    }
}

pub fn valid_repository_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

/// A mount path under `/workspace`; empty leaves it to the repository's name.
pub fn workspace_mount_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "/workspace" || value == "/workspace/" {
        return String::new();
    }
    let suffix = value
        .strip_prefix("/workspace/")
        .unwrap_or(value)
        .trim_start_matches('/');
    format!("/workspace/{suffix}")
}

pub fn valid_port_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=22).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Who may open a preview; anything else is the creator alone.
pub fn allowlisted_access(value: &str) -> &'static str {
    match value {
        "public" => "public",
        "org_members" => "org_members",
        _ => "creator",
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests;
