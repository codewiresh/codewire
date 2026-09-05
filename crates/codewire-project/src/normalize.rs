use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(super) fn normalize_raw_project(raw: RawProject) -> Result<ProjectDocument, ProjectError> {
    let schema_version = raw.version.unwrap_or(PROJECT_SCHEMA_VERSION);
    if schema_version != PROJECT_SCHEMA_VERSION {
        return Err(ProjectError::UnsupportedSchema(schema_version));
    }

    enforce_count("repositories", raw.repositories.len(), MAX_REPOSITORIES)?;
    enforce_count("environment", raw.environment.len(), MAX_ENVIRONMENT_VALUES)?;
    enforce_count("ports", raw.ports.len(), MAX_APPLICATION_PORTS)?;
    enforce_count("skills", raw.skills.len(), MAX_SKILLS)?;
    enforce_count("mounts", raw.mounts.len(), MAX_LOCAL_MOUNTS)?;

    let repositories = normalize_repositories(raw.repositories)?;
    let mounts = normalize_mounts(raw.mounts)?;
    let working_directory_explicit = !raw.working_directory.trim().is_empty();
    let working_directory =
        normalize_working_directory(&raw.working_directory, &repositories, &mounts)?;
    let agents = normalize_agents(raw.agents)?;
    let skills = normalize_skills(raw.skills)?;
    let (application_ports, host_ports) = normalize_ports(raw.ports)?;
    let resources = ResourceSpec {
        cpu_millicores: raw.cpu.map(normalize_cpu).transpose()?,
        memory_mib: raw.memory.map(normalize_memory).transpose()?,
        disk_gib: raw.disk.map(normalize_disk).transpose()?,
    };
    let secrets = normalize_secrets(raw.secrets)?;
    let access = raw.access.map(|access| AccessBinding {
        profile: access.profile,
    });
    validate_workspace_input_destinations(&repositories, &mounts)?;
    let environment = normalize_environment("environment", raw.environment)?;

    let document = ProjectDocument {
        spec: ProjectSpec {
            schema_version,
            preset: short_value("preset", &raw.preset)?,
            image: short_value("image", &raw.image)?,
            repositories,
            working_directory,
            install_command: command_value("install_command", &raw.install_command)?,
            startup_script: command_value("startup_script", &raw.startup_script)?,
            environment,
            agents,
            skills,
            application_ports,
            resources,
            secrets,
            access,
        },
        local: LocalProjectIntent { mounts, host_ports },
        working_directory_explicit,
    };
    document.spec.validate()?;
    Ok(document)
}

pub(super) fn validate_project_spec(spec: &ProjectSpec) -> Result<(), ProjectError> {
    if spec.schema_version != PROJECT_SCHEMA_VERSION {
        return Err(ProjectError::UnsupportedSchema(spec.schema_version));
    }
    enforce_count("repositories", spec.repositories.len(), MAX_REPOSITORIES)?;
    enforce_count(
        "environment",
        spec.environment.len(),
        MAX_ENVIRONMENT_VALUES,
    )?;
    enforce_count("agents", spec.agents.tools.len(), MAX_AGENTS)?;
    enforce_count("skills", spec.skills.len(), MAX_SKILLS)?;
    enforce_count("ports", spec.application_ports.len(), MAX_APPLICATION_PORTS)?;

    ensure_short_value("preset", &spec.preset)?;
    ensure_short_value("image", &spec.image)?;
    ensure_command_value("install_command", &spec.install_command)?;
    ensure_command_value("startup_script", &spec.startup_script)?;
    normalize_environment("environment", spec.environment.clone())?;

    let repositories = normalize_repositories(
        spec.repositories
            .iter()
            .map(|repository| RawRepository {
                source: repository.source.clone(),
                revision: repository.revision.clone(),
                branch: repository.branch.clone(),
                destination: repository.destination.clone(),
            })
            .collect(),
    )?;
    if repositories != spec.repositories {
        return invalid("repositories", "must already be in canonical form");
    }
    ensure_short_value("working_directory", &spec.working_directory)?;
    validate_workspace_path("working_directory", &spec.working_directory, true)?;

    let mut agent_seen = BTreeSet::new();
    for agent in &spec.agents.tools {
        if canonical_agent_id(agent)? != Some(agent.as_str()) || !agent_seen.insert(agent) {
            return invalid("agents", "must contain unique canonical agent identifiers");
        }
    }

    let mut previous_skill: Option<&SkillSelection> = None;
    for skill in &spec.skills {
        ensure_short_value("skills.reference", &skill.reference)?;
        enforce_count("skills.agents", skill.agents.len(), MAX_AGENTS)?;
        match skill.source {
            SkillSource::Repository => validate_relative_path("skills.path", &skill.reference)?,
            SkillSource::User => validate_identifier("skills.name", &skill.reference)?,
        }
        let mut seen = BTreeSet::new();
        for agent in &skill.agents {
            if canonical_agent_id(agent)? != Some(agent.as_str()) || !seen.insert(agent) {
                return invalid(
                    "skills.agents",
                    "must contain unique canonical agent identifiers",
                );
            }
        }
        if previous_skill.is_some_and(|previous| previous >= skill) {
            return invalid("skills", "must be unique and canonically ordered");
        }
        previous_skill = Some(skill);
    }

    let mut ports = BTreeSet::new();
    for port in &spec.application_ports {
        if port.port == 0 || !ports.insert(port.port) {
            return invalid("ports.port", "must contain unique non-zero ports");
        }
        ensure_short_value("ports.label", &port.label)?;
        ensure_short_value("ports.access", &port.access)?;
    }

    if let Some(cpu) = spec.resources.cpu_millicores
        && !(100..=256_000).contains(&cpu)
    {
        return invalid("cpu", "must be from 100m through 256 CPUs");
    }
    if let Some(memory) = spec.resources.memory_mib
        && !(128..=1_048_576).contains(&memory)
    {
        return invalid("memory", "must be from 128Mi through 1Ti");
    }
    if let Some(disk) = spec.resources.disk_gib
        && !(1..=16_384).contains(&disk)
    {
        return invalid("disk", "must be from 1Gi through 16384Gi");
    }

    ensure_short_value("secrets.project", &spec.secrets.project)?;
    Ok(())
}

fn normalize_repositories(
    repositories: Vec<RawRepository>,
) -> Result<Vec<RepositorySpec>, ProjectError> {
    let mut normalized = Vec::with_capacity(repositories.len());
    for (index, repository) in repositories.into_iter().enumerate() {
        let source = short_value("repositories.source", &repository.source)?;
        if source.is_empty() {
            return invalid("repositories.source", format!("entry {index} is empty"));
        }
        if source.chars().any(char::is_whitespace) {
            return invalid(
                "repositories.source",
                format!("entry {index} contains whitespace"),
            );
        }
        validate_repository_source(index, &source)?;
        let revision = short_value("repositories.revision", &repository.revision)?;
        let branch = short_value("repositories.branch", &repository.branch)?;
        if !revision.is_empty() && !branch.is_empty() {
            return invalid(
                "repositories",
                format!("entry {index} cannot set both revision and branch"),
            );
        }
        validate_git_selector("repositories.revision", &revision)?;
        validate_git_selector("repositories.branch", &branch)?;
        let destination = if repository.destination.trim().is_empty() {
            let name = repository_name(&source);
            if name.is_empty() {
                return invalid(
                    "repositories.destination",
                    format!("entry {index} has no derivable repository name"),
                );
            }
            format!("{WORKSPACE_ROOT}/{name}")
        } else {
            repository.destination.trim().to_string()
        };
        validate_workspace_path("repositories.destination", &destination, false)?;
        normalized.push(RepositorySpec {
            source,
            revision,
            branch,
            destination,
        });
    }

    let mut destinations = normalized
        .iter()
        .map(|repository| repository.destination.as_str())
        .collect::<Vec<_>>();
    destinations.sort_unstable();
    for pair in destinations.windows(2) {
        if pair[0] == pair[1] {
            return invalid(
                "repositories.destination",
                format!("duplicate destination {}", pair[0]),
            );
        }
        if pair[1]
            .strip_prefix(pair[0])
            .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return invalid(
                "repositories.destination",
                format!("overlapping destinations {} and {}", pair[0], pair[1]),
            );
        }
    }
    Ok(normalized)
}

fn normalize_working_directory(
    working_directory: &str,
    repositories: &[RepositorySpec],
    mounts: &[LocalMountIntent],
) -> Result<String, ProjectError> {
    let working_directory = short_value("working_directory", working_directory)?;
    if !working_directory.is_empty() {
        validate_workspace_path("working_directory", &working_directory, true)?;
        return Ok(working_directory);
    }
    match (repositories, mounts) {
        ([repository], []) => Ok(repository.destination.clone()),
        ([], [mount]) => Ok(mount.destination.clone()),
        _ => Ok(WORKSPACE_ROOT.to_string()),
    }
}

fn normalize_agents(agents: Option<RawAgentsBlock>) -> Result<AgentsSpec, ProjectError> {
    let Some(RawAgentsBlock { install, tools }) = agents else {
        return Ok(AgentsSpec::default());
    };
    enforce_count("agents", tools.len(), MAX_AGENTS)?;
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for tool in tools {
        let Some(tool) = canonical_agent_id(&tool)? else {
            return invalid("agents", "agent identifier cannot be empty");
        };
        if !seen.insert(tool.to_string()) {
            return invalid("agents", format!("duplicate agent {tool:?}"));
        }
        normalized.push(tool.to_string());
    }
    Ok(AgentsSpec {
        install,
        tools: normalized,
    })
}

fn normalize_skills(skills: Vec<RawSkillBlock>) -> Result<Vec<SkillSelection>, ProjectError> {
    let mut normalized = Vec::with_capacity(skills.len());
    for block in skills {
        let source = block.source;
        let reference = match source {
            SkillSource::Repository
                if !block.path.trim().is_empty() && block.name.trim().is_empty() =>
            {
                block.path
            }
            SkillSource::User if !block.name.trim().is_empty() && block.path.trim().is_empty() => {
                block.name
            }
            SkillSource::Repository => {
                return invalid("skills", "repository source requires path and forbids name");
            }
            SkillSource::User => {
                return invalid("skills", "user source requires name and forbids path");
            }
        };
        let agents = block.agents;
        let reference = short_value("skills.reference", &reference)?;
        if reference.is_empty() {
            return invalid("skills.reference", "value is required");
        }
        match source {
            SkillSource::Repository => validate_relative_path("skills.path", &reference)?,
            SkillSource::User => validate_identifier("skills.name", &reference)?,
        }
        let mut canonical_agents = Vec::new();
        let mut seen = BTreeSet::new();
        enforce_count("skills.agents", agents.len(), MAX_AGENTS)?;
        for agent in agents {
            let Some(agent) = canonical_agent_id(&agent)? else {
                return invalid("skills.agents", "agent identifier cannot be empty");
            };
            if !seen.insert(agent.to_string()) {
                return invalid("skills.agents", format!("duplicate agent {agent:?}"));
            }
            canonical_agents.push(agent.to_string());
        }
        normalized.push(SkillSelection {
            source,
            reference,
            agents: canonical_agents,
        });
    }
    normalized.sort();
    for pair in normalized.windows(2) {
        if pair[0] == pair[1] {
            return invalid("skills", "duplicate selection");
        }
    }
    Ok(normalized)
}

fn normalize_ports(
    ports: Vec<RawPortBlock>,
) -> Result<(Vec<ApplicationPort>, Vec<HostPortBinding>), ProjectError> {
    let mut application_ports = Vec::with_capacity(ports.len());
    let mut host_ports = Vec::new();
    let mut guest_seen = BTreeSet::new();
    let mut host_seen = BTreeSet::new();
    for port in ports {
        let host_pair = port.host_port != 0 || port.guest_port != 0;
        let (host, guest) = match (port.port != 0, host_pair) {
            (true, false) => (None, port.port),
            (false, true) if port.host_port != 0 && port.guest_port != 0 => {
                (Some(port.host_port), port.guest_port)
            }
            _ => {
                return invalid(
                    "ports",
                    "use either port or a complete host_port/guest_port pair",
                );
            }
        };
        let label = port.label;
        let access = port.access;
        let guest = valid_port("ports.port", guest)?;
        if !guest_seen.insert(guest) {
            return invalid("ports.port", format!("duplicate guest port {guest}"));
        }
        let label = short_value("ports.label", &label)?;
        let access = short_value("ports.access", &access)?;
        application_ports.push(ApplicationPort {
            port: guest,
            label,
            access,
        });
        if let Some(host) = host {
            let host = valid_port("ports.host_port", host)?;
            if !host_seen.insert(host) {
                return invalid("ports.host_port", format!("duplicate host port {host}"));
            }
            host_ports.push(HostPortBinding {
                host_port: host,
                guest_port: guest,
            });
        }
    }
    Ok((application_ports, host_ports))
}

fn normalize_cpu(quantity: RawQuantity) -> Result<u32, ProjectError> {
    let value = {
        let value = quantity.0.trim();
        if let Some(value) = value.strip_suffix('m') {
            parse_i64("cpu", value)?
        } else {
            parse_i64("cpu", value)?.checked_mul(1000).ok_or_else(|| {
                ProjectError::InvalidField {
                    field: "cpu",
                    detail: "quantity is too large".to_string(),
                }
            })?
        }
    };
    if !(100..=256_000).contains(&value) {
        return invalid("cpu", "must be from 100m through 256 CPUs");
    }
    Ok(value as u32)
}

fn normalize_memory(quantity: RawQuantity) -> Result<u64, ProjectError> {
    let value = normalize_binary_quantity("memory", quantity, 1)?;
    if !(128..=1_048_576).contains(&value) {
        return invalid("memory", "must be from 128Mi through 1Ti");
    }
    Ok(value)
}

fn normalize_disk(quantity: RawQuantity) -> Result<u64, ProjectError> {
    let mib = normalize_binary_quantity("disk", quantity, 1024)?;
    if !mib.is_multiple_of(1024) {
        return invalid("disk", "must resolve to a whole GiB");
    }
    let value = mib / 1024;
    if !(1..=16_384).contains(&value) {
        return invalid("disk", "must be from 1Gi through 16384Gi");
    }
    Ok(value)
}

fn normalize_binary_quantity(
    field: &'static str,
    quantity: RawQuantity,
    default_multiplier_mib: u64,
) -> Result<u64, ProjectError> {
    let value = quantity.0.trim();
    let lowercase = value.to_ascii_lowercase();
    let (suffix_len, multiplier) = if lowercase.ends_with("gib") {
        (3, 1024_u64)
    } else if lowercase.ends_with("gi") || lowercase.ends_with("gb") {
        (2, 1024_u64)
    } else if lowercase.ends_with("mib") {
        (3, 1_u64)
    } else if lowercase.ends_with("mi") || lowercase.ends_with("mb") {
        (2, 1_u64)
    } else {
        (0, default_multiplier_mib)
    };
    let number = &value[..value.len() - suffix_len];
    let number = number
        .trim()
        .parse::<u64>()
        .map_err(|_| ProjectError::InvalidField {
            field,
            detail: format!("invalid binary quantity {value:?}"),
        })?;
    number
        .checked_mul(multiplier)
        .ok_or_else(|| ProjectError::InvalidField {
            field,
            detail: "quantity is too large".to_string(),
        })
}

fn normalize_secrets(secrets: Option<RawSecretsBlock>) -> Result<SecretBindings, ProjectError> {
    let Some(secrets) = secrets else {
        return Ok(SecretBindings::default());
    };
    Ok(SecretBindings {
        project: short_value("secrets.project", &secrets.project)?,
        organization: secrets.organization,
        user: secrets.user,
    })
}

fn normalize_mounts(mounts: Vec<RawMountBlock>) -> Result<Vec<LocalMountIntent>, ProjectError> {
    mounts
        .into_iter()
        .map(|mount| {
            let source = short_value("mounts.source", &mount.source)?;
            if source.is_empty() {
                return invalid("mounts.source", "value is required");
            }
            validate_explicit_local_source("mounts.source", &source)?;
            let destination = short_value("mounts.destination", &mount.destination)?;
            if destination.is_empty() {
                return invalid("mounts.destination", "value is required");
            }
            validate_workspace_path("mounts.destination", &destination, false)?;
            let mode = match mount.mode.trim().to_ascii_lowercase().as_str() {
                "copy" => LocalMountMode::Copy,
                "direct" => LocalMountMode::Direct,
                "" => return invalid("mounts.mode", "value is required: copy or direct"),
                other => {
                    return invalid(
                        "mounts.mode",
                        format!("unsupported mode {other:?}; use copy or direct"),
                    );
                }
            };
            if mode == LocalMountMode::Copy && mount.read_only.is_some() {
                return invalid("mounts.read_only", "only applies to direct mounts");
            }
            if mode == LocalMountMode::Direct && mount.read_only.is_none() {
                return invalid(
                    "mounts.read_only",
                    "must explicitly select true or false for a direct mount",
                );
            }
            Ok(LocalMountIntent {
                source,
                destination,
                mode,
                read_only: mount.read_only,
            })
        })
        .collect()
}

fn validate_workspace_input_destinations(
    repositories: &[RepositorySpec],
    mounts: &[LocalMountIntent],
) -> Result<(), ProjectError> {
    let mut destinations = repositories
        .iter()
        .map(|repository| (repository.destination.as_str(), "repository"))
        .chain(mounts.iter().map(|mount| {
            let kind = match mount.mode {
                LocalMountMode::Copy => "copy mount",
                LocalMountMode::Direct => "direct mount",
            };
            (mount.destination.as_str(), kind)
        }))
        .collect::<Vec<_>>();
    destinations.sort_unstable_by(|left, right| left.0.cmp(right.0));
    for pair in destinations.windows(2) {
        let (left_path, left_kind) = pair[0];
        let (right_path, right_kind) = pair[1];
        let duplicate = left_path == right_path;
        let nested = right_path
            .strip_prefix(left_path)
            .is_some_and(|suffix| suffix.starts_with('/'));
        if duplicate || nested {
            return invalid(
                "workspace destinations",
                format!(
                    "{left_kind} destination {left_path} overlaps {right_kind} destination {right_path}"
                ),
            );
        }
    }
    Ok(())
}

pub fn canonical_agent_id(raw: &str) -> Result<Option<&'static str>, ProjectError> {
    match raw.trim() {
        "" => Ok(None),
        "claude-code" => Ok(Some("claude-code")),
        "codex" => Ok(Some("codex")),
        "gemini-cli" => Ok(Some("gemini-cli")),
        "kimi-code" => Ok(Some("kimi-code")),
        "pi" => Ok(Some("pi")),
        "aider" => Ok(Some("aider")),
        other => invalid("agents", format!("unsupported agent {other:?}")),
    }
}

pub fn display_agent_id(raw: &str) -> Result<Option<&'static str>, ProjectError> {
    Ok(match canonical_agent_id(raw)? {
        Some("claude-code") => Some("claude"),
        Some("gemini-cli") => Some("gemini"),
        Some("kimi-code") => Some("kimi"),
        other => other,
    })
}

pub fn repository_name(source: &str) -> String {
    let source = source.split(['?', '#']).next().unwrap_or(source);
    if source.ends_with('/') {
        return String::new();
    }
    if source
        .split_once("://")
        .is_some_and(|(_, remainder)| !remainder.contains('/'))
    {
        return String::new();
    }
    let source = source.trim_end_matches('/');
    let source = source.strip_suffix(".git").unwrap_or(source);
    source
        .rsplit(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_string()
}

fn validate_repository_source(index: usize, source: &str) -> Result<(), ProjectError> {
    if source.starts_with('-')
        || source.starts_with('/')
        || source.starts_with('~')
        || source == "."
        || source == ".."
        || source.starts_with("./")
        || source.starts_with("../")
        || source.contains('\\')
    {
        return invalid(
            "repositories.source",
            format!("entry {index} must be a remote repository, not a local path"),
        );
    }
    if source.contains(['?', '#']) {
        return invalid(
            "repositories.source",
            format!("entry {index} must not contain a query or fragment"),
        );
    }

    if let Some((scheme, remainder)) = source.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "ssh" | "git") {
            return invalid(
                "repositories.source",
                format!("entry {index} uses unsupported scheme {scheme:?}"),
            );
        }
        let Some((authority, path)) = remainder.split_once('/') else {
            return invalid(
                "repositories.source",
                format!("entry {index} must include a repository path"),
            );
        };
        if authority.is_empty() || path.is_empty() || path.ends_with('/') {
            return invalid(
                "repositories.source",
                format!("entry {index} must include a host and repository name"),
            );
        }
        // HTTP authority is structural input, not an opaque URL component.
        // Reject every percent escape there so an encoded `@` (including a
        // double-encoded form interpreted by a downstream client) can never
        // turn an apparently credential-free host into URL userinfo later.
        // Percent-encoded repository path bytes remain valid.
        if matches!(scheme.as_str(), "http" | "https") && authority.contains('%') {
            return invalid(
                "repositories.source",
                format!("entry {index} must not percent-encode URL authority characters"),
            );
        }
        if path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return invalid(
                "repositories.source",
                format!("entry {index} must use a normalized repository path"),
            );
        }
        if let Some((user_info, host)) = authority.rsplit_once('@') {
            let valid_ssh_user = scheme == "ssh"
                && !user_info.is_empty()
                && !user_info.contains(':')
                && !user_info.contains('@')
                && !user_info.to_ascii_lowercase().contains("%3a")
                && !host.is_empty();
            if !valid_ssh_user {
                return invalid(
                    "repositories.source",
                    format!("entry {index} must not embed URL credentials"),
                );
            }
        }
    } else if let Some((authority, path)) = source.split_once(':') {
        if authority.is_empty() || path.is_empty() || path.ends_with('/') {
            return invalid(
                "repositories.source",
                format!("entry {index} has invalid SSH scp syntax"),
            );
        }
        let valid_authority = authority.split_once('@').map_or_else(
            || !authority.contains('/'),
            |(user, host)| {
                !user.is_empty()
                    && !host.is_empty()
                    && !user.contains('@')
                    && !host.contains(['@', '/'])
            },
        );
        let normalized_path = path.trim_start_matches('/');
        if !valid_authority
            || normalized_path.is_empty()
            || normalized_path
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return invalid(
                "repositories.source",
                format!("entry {index} has invalid SSH scp syntax"),
            );
        }
    } else {
        return invalid(
            "repositories.source",
            format!("entry {index} must use a remote URL or SSH scp syntax"),
        );
    }
    if repository_name(source).is_empty() {
        return invalid(
            "repositories.source",
            format!("entry {index} has no repository name"),
        );
    }
    Ok(())
}

fn validate_git_selector(field: &'static str, value: &str) -> Result<(), ProjectError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.starts_with('-')
        || value.ends_with('/')
        || value.ends_with('.')
        || value.ends_with(".lock")
        || value.contains(char::is_whitespace)
        || value.contains("..")
        || value.contains("@{")
        || value.contains("//")
        || value.contains(['~', '^', ':', '?', '*', '[', '\\'])
    {
        return invalid(field, "must be a normalized Git branch or revision");
    }
    Ok(())
}

pub fn validate_repository_destinations<'a>(
    repositories: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<String>, ProjectError> {
    normalize_repositories(
        repositories
            .into_iter()
            .map(|(source, destination)| RawRepository {
                source: source.to_string(),
                destination: destination.to_string(),
                revision: String::new(),
                branch: String::new(),
            })
            .collect(),
    )
    .map(|repositories| {
        repositories
            .into_iter()
            .map(|repository| repository.destination)
            .collect()
    })
}

fn normalize_environment(
    field: &'static str,
    environment: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ProjectError> {
    for (key, value) in &environment {
        if !is_valid_environment_key(key) {
            return invalid(field, format!("invalid environment name {key:?}"));
        }
        if RESERVED_RUNTIME_ENVIRONMENT_KEYS.contains(&key.as_str()) {
            return invalid(
                field,
                format!("{key} is reserved for Codewire runtime control"),
            );
        }
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES {
            return invalid(field, format!("value for {key:?} is too large"));
        }
        if value.contains('\0') {
            return invalid(field, format!("value for {key:?} contains NUL"));
        }
    }
    Ok(environment)
}

fn short_value(field: &'static str, value: &str) -> Result<String, ProjectError> {
    let value = value.trim();
    if value.len() > MAX_SHORT_VALUE_BYTES {
        return invalid(field, "value is too large");
    }
    if value.contains('\0') || value.chars().any(|ch| ch.is_control() && ch != '\t') {
        return invalid(field, "value contains a control character");
    }
    Ok(value.to_string())
}

fn ensure_short_value(field: &'static str, value: &str) -> Result<(), ProjectError> {
    if short_value(field, value)? != value {
        return invalid(field, "must not contain leading or trailing whitespace");
    }
    Ok(())
}

fn command_value(field: &'static str, value: &str) -> Result<String, ProjectError> {
    let value = value.trim();
    if value.len() > MAX_COMMAND_BYTES {
        return invalid(field, "command is too large");
    }
    if value.contains('\0') {
        return invalid(field, "command contains NUL");
    }
    Ok(value.to_string())
}

fn ensure_command_value(field: &'static str, value: &str) -> Result<(), ProjectError> {
    if command_value(field, value)? != value {
        return invalid(field, "must not contain leading or trailing whitespace");
    }
    Ok(())
}

fn enforce_count(field: &'static str, actual: usize, maximum: usize) -> Result<(), ProjectError> {
    if actual > maximum {
        return Err(ProjectError::TooManyEntries { field, maximum });
    }
    Ok(())
}

fn valid_port(field: &'static str, port: i64) -> Result<u16, ProjectError> {
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ProjectError::InvalidField {
            field,
            detail: "must be from 1 through 65535".to_string(),
        })
}

fn parse_i64(field: &'static str, value: &str) -> Result<i64, ProjectError> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| ProjectError::InvalidField {
            field,
            detail: format!("invalid integer {value:?}"),
        })
}

fn validate_workspace_path(
    field: &'static str,
    path: &str,
    allow_root: bool,
) -> Result<(), ProjectError> {
    if allow_root && path == WORKSPACE_ROOT {
        return Ok(());
    }
    let Some(relative) = path.strip_prefix("/workspace/") else {
        return invalid(field, "must be below /workspace");
    };
    if relative.is_empty() || path.ends_with('/') {
        return invalid(field, "must name a normalized path below /workspace");
    }
    validate_path_segments(field, relative)
}

fn validate_relative_path(field: &'static str, path: &str) -> Result<(), ProjectError> {
    if path.starts_with('/') || path.is_empty() || path.ends_with('/') {
        return invalid(field, "must be a normalized relative path");
    }
    validate_path_segments(field, path)
}

fn validate_explicit_local_source(field: &'static str, path: &str) -> Result<(), ProjectError> {
    if path.is_empty() || path == "/" || path.ends_with('/') || path.chars().any(char::is_control) {
        return invalid(field, "must name an explicit local path");
    }
    let segments = path.split('/').skip(usize::from(path.starts_with('/')));
    if segments.into_iter().any(|segment| segment.is_empty()) {
        return invalid(field, "must not contain empty path segments");
    }
    Ok(())
}

fn validate_path_segments(field: &'static str, relative: &str) -> Result<(), ProjectError> {
    if relative.chars().any(char::is_control)
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return invalid(field, "must not contain empty, . or .. segments");
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProjectError> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().enumerate().all(|(index, ch)| {
            ch.is_ascii_lowercase()
                || index > 0 && ch.is_ascii_digit()
                || index > 0 && matches!(ch, '-' | '_' | '.')
        })
    {
        return invalid(
            field,
            "must be a lowercase identifier using letters, digits, ., _ or -",
        );
    }
    Ok(())
}

fn invalid<T>(field: &'static str, detail: impl Into<String>) -> Result<T, ProjectError> {
    Err(ProjectError::InvalidField {
        field,
        detail: detail.into(),
    })
}
