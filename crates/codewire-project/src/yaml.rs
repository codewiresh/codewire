//! The inverse of [`parse_project_yaml`](crate::parse_project_yaml): a
//! codewire.yaml document for a saved project. Parsing what
//! [`ProjectDocument::to_yaml`] writes yields the same document.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    AgentsSpec, CredentialBinding, LocalMountMode, LocalProjectIntent, ProjectDocument,
    ProjectError, ProjectSpec, RepositorySpec, SecretBindings, SkillSource, WorkspacePathMode,
};

impl ProjectDocument {
    /// A document for a saved spec and its local-only intent. When
    /// `working_directory_explicit` is false, [`Self::to_yaml`] leaves the
    /// working directory out, so whoever creates from the file derives it.
    pub fn new(
        spec: ProjectSpec,
        local: LocalProjectIntent,
        working_directory_explicit: bool,
    ) -> Self {
        Self {
            spec,
            local,
            working_directory_explicit,
        }
    }

    /// The document as codewire.yaml, in the schema's key order. A host port
    /// binding is written as its application port's `host_port`/`guest_port`
    /// pair; a binding whose guest port is not an application port is
    /// appended, and so becomes one when the file is parsed.
    pub fn to_yaml(&self) -> Result<String, ProjectError> {
        self.spec.validate()?;
        let spec = &self.spec;
        let local = &self.local;
        let mut ports = spec
            .application_ports
            .iter()
            .map(|port| {
                let host = local
                    .host_ports
                    .iter()
                    .find(|binding| binding.guest_port == port.port);
                YamlPort {
                    port: host.is_none().then_some(port.port),
                    host_port: host.map(|binding| binding.host_port),
                    guest_port: host.map(|binding| binding.guest_port),
                    label: &port.label,
                    access: &port.access,
                }
            })
            .collect::<Vec<_>>();
        ports.extend(
            local
                .host_ports
                .iter()
                .filter(|binding| {
                    !spec
                        .application_ports
                        .iter()
                        .any(|port| port.port == binding.guest_port)
                })
                .map(|binding| YamlPort {
                    port: None,
                    host_port: Some(binding.host_port),
                    guest_port: Some(binding.guest_port),
                    label: "",
                    access: "",
                }),
        );
        let document = YamlProject {
            version: spec.schema_version,
            preset: &spec.preset,
            image: &spec.image,
            repositories: &spec.repositories,
            working_directory: self
                .working_directory_explicit
                .then_some(spec.working_directory.as_str()),
            install_command: &spec.install_command,
            startup_script: &spec.startup_script,
            secrets: (!spec.secrets.is_empty()).then_some(&spec.secrets),
            environment: &spec.environment,
            agents: (!spec.agents.is_empty()).then_some(&spec.agents),
            skills: spec
                .skills
                .iter()
                .map(|skill| match skill.source {
                    SkillSource::Repository => YamlSkill {
                        source: "repository",
                        path: &skill.reference,
                        name: "",
                        agents: &skill.agents,
                    },
                    SkillSource::User => YamlSkill {
                        source: "user",
                        path: "",
                        name: &skill.reference,
                        agents: &skill.agents,
                    },
                })
                .collect(),
            ports,
            cpu: spec.resources.cpu_millicores.map(cpu_quantity),
            memory: spec.resources.memory_mib.map(memory_quantity),
            disk: spec.resources.disk_gib.map(|value| format!("{value}Gi")),
            credentials: spec.credentials.as_ref(),
            mounts: local
                .mounts
                .iter()
                .map(|mount| YamlMount {
                    source: &mount.source,
                    destination: &mount.destination,
                    mode: match mount.mode {
                        LocalMountMode::Copy => "copy",
                        LocalMountMode::Direct => "direct",
                    },
                    read_only: mount.read_only,
                })
                .collect(),
            workspace: (local.vm_only.is_some() || local.path_mode.is_some()).then(|| {
                YamlWorkspace {
                    vm_only: local.vm_only.as_deref(),
                    path_mode: local.path_mode.map(WorkspacePathMode::as_str),
                }
            }),
        };
        serde_yaml::to_string(&document).map_err(ProjectError::Yaml)
    }
}

/// Whole CPUs as a count, as people write them; otherwise millicores.
fn cpu_quantity(millicores: u32) -> String {
    if millicores.is_multiple_of(1000) {
        (millicores / 1000).to_string()
    } else {
        format!("{millicores}m")
    }
}

/// Whole GiB as `Gi`; otherwise MiB.
fn memory_quantity(mib: u64) -> String {
    if mib.is_multiple_of(1024) {
        format!("{}Gi", mib / 1024)
    } else {
        format!("{mib}Mi")
    }
}

#[derive(Serialize)]
struct YamlProject<'a> {
    version: u32,
    #[serde(skip_serializing_if = "str::is_empty")]
    preset: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    image: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    repositories: &'a [RepositorySpec],
    #[serde(skip_serializing_if = "Option::is_none")]
    working_directory: Option<&'a str>,
    #[serde(skip_serializing_if = "str::is_empty")]
    install_command: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    startup_script: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets: Option<&'a SecretBindings>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    environment: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agents: Option<&'a AgentsSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skills: Vec<YamlSkill<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<YamlPort<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<&'a CredentialBinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<YamlMount<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<YamlWorkspace<'a>>,
}

#[derive(Serialize)]
struct YamlSkill<'a> {
    source: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    path: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    agents: &'a [String],
}

#[derive(Serialize)]
struct YamlPort<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_port: Option<u16>,
    #[serde(skip_serializing_if = "str::is_empty")]
    label: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    access: &'a str,
}

#[derive(Serialize)]
struct YamlMount<'a> {
    source: &'a str,
    destination: &'a str,
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_only: Option<bool>,
}

#[derive(Serialize)]
struct YamlWorkspace<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    vm_only: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_mode: Option<&'static str>,
}
