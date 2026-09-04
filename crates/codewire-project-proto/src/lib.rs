//! Lossless adapters between the public portable project contract and the
//! I/O-free canonical project model. Placement and runtime resolution stay in
//! their owning API/supervisor layers.

use std::collections::BTreeMap;

use codewire_project as project;
use codewire_proto::codewire::v1 as proto;

pub fn from_proto(
    value: proto::ProjectSpec,
) -> Result<project::ProjectSpec, project::ProjectError> {
    let agents = value.agents.into_option().unwrap_or_default();
    let resources = value.resources.into_option().unwrap_or_default();
    let secrets = value.secrets.into_option().unwrap_or_default();
    let access = value
        .access
        .into_option()
        .map(|access| {
            access
                .profile
                .parse()
                .map(|profile| project::AccessBinding { profile })
                .map_err(|_| project::ProjectError::InvalidField {
                    field: "project_spec.access.profile",
                    detail: "must be a canonical scope-qualified profile reference".to_string(),
                })
        })
        .transpose()?;
    let mut skills = Vec::with_capacity(value.skills.len());
    for skill in value.skills {
        let source = match skill.source.as_known() {
            Some(proto::ProjectSkillSource::Repository) => project::SkillSource::Repository,
            Some(proto::ProjectSkillSource::User) => project::SkillSource::User,
            Some(proto::ProjectSkillSource::Unspecified) => {
                return invalid("project_spec.skills.source", "must be specified");
            }
            None => return invalid("project_spec.skills.source", "contains an unknown value"),
        };
        skills.push(project::SkillSelection {
            source,
            reference: skill.reference,
            agents: skill.agents,
        });
    }

    let spec = project::ProjectSpec {
        schema_version: value.schema_version,
        preset: value.preset,
        image: value.image,
        repositories: value
            .repositories
            .into_iter()
            .map(|repository| project::RepositorySpec {
                source: repository.url,
                revision: repository.revision,
                branch: repository.branch,
                destination: repository.mount_path,
            })
            .collect(),
        working_directory: value.working_directory,
        install_command: value.install_command,
        startup_script: value.startup_script,
        environment: ordered_map(value.environment),
        agents: project::AgentsSpec {
            install: agents.install,
            tools: agents.tools,
        },
        skills,
        application_ports: value
            .application_ports
            .into_iter()
            .map(|port| project::ApplicationPort {
                port: u16::try_from(port.port).unwrap_or_default(),
                label: port.label,
                access: port.access,
            })
            .collect(),
        resources: project::ResourceSpec {
            cpu_millicores: resources.cpu_millicores,
            memory_mib: resources.memory_mib,
            disk_gib: resources.disk_gib,
        },
        secrets: project::SecretBindings {
            project: secrets.project,
            organization: secrets.organization,
            user: secrets.user,
        },
        access,
    };
    spec.validate()?;
    Ok(spec)
}

pub fn to_proto(value: project::ProjectSpec) -> proto::ProjectSpec {
    let agents = (!value.agents.is_empty()).then(|| proto::ProjectAgents {
        install: value.agents.install,
        tools: value.agents.tools,
        ..Default::default()
    });
    let resources = (!value.resources.is_empty()).then(|| proto::ProjectResources {
        cpu_millicores: value.resources.cpu_millicores,
        memory_mib: value.resources.memory_mib,
        disk_gib: value.resources.disk_gib,
        ..Default::default()
    });
    let secrets = (!value.secrets.is_empty()).then(|| proto::ProjectSecretBindings {
        project: value.secrets.project,
        organization: value.secrets.organization,
        user: value.secrets.user,
        ..Default::default()
    });
    let access = value.access.map(|access| proto::ProjectAccessBinding {
        profile: access.profile.to_string(),
        ..Default::default()
    });
    proto::ProjectSpec {
        schema_version: value.schema_version,
        preset: value.preset,
        image: value.image,
        repositories: value
            .repositories
            .into_iter()
            .map(|repository| proto::RepoEntry {
                url: repository.source,
                branch: repository.branch,
                mount_path: repository.destination,
                revision: repository.revision,
                ..Default::default()
            })
            .collect(),
        working_directory: value.working_directory,
        install_command: value.install_command,
        startup_script: value.startup_script,
        environment: value.environment.into_iter().collect(),
        agents: agents.into(),
        skills: value
            .skills
            .into_iter()
            .map(|skill| proto::ProjectSkillSelection {
                source: match skill.source {
                    project::SkillSource::Repository => {
                        proto::ProjectSkillSource::Repository.into()
                    }
                    project::SkillSource::User => proto::ProjectSkillSource::User.into(),
                },
                reference: skill.reference,
                agents: skill.agents,
                ..Default::default()
            })
            .collect(),
        application_ports: value
            .application_ports
            .into_iter()
            .map(|port| proto::AppPort {
                port: i32::from(port.port),
                label: port.label,
                access: port.access,
                ..Default::default()
            })
            .collect(),
        resources: resources.into(),
        secrets: secrets.into(),
        access: access.into(),
        ..Default::default()
    }
}

fn ordered_map<K: Ord, V>(values: impl IntoIterator<Item = (K, V)>) -> BTreeMap<K, V> {
    values.into_iter().collect()
}

fn invalid<T>(field: &'static str, detail: impl Into<String>) -> Result<T, project::ProjectError> {
    Err(project::ProjectError::InvalidField {
        field,
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_project_spec_round_trips_canonical_intent() {
        let original = project::parse_project_yaml(
            r#"
version: 1
image: ghcr.io/example/workspace@sha256:abc
repositories:
  - source: https://example.test/org/app.git
    revision: deadbeef
    destination: /workspace/app
working_directory: /workspace/app
env: {RUST_LOG: info}
agents: [claude, codex]
skills: [{path: .agents/skills/rust, agents: [codex]}]
ports: [{port: 8080, label: web, access: private}]
cpu: 2
memory: 16Gi
disk: 40Gi
secrets: {project: dev, organization: false, user: true}
access: {profile: user/work}
"#,
        )
        .unwrap()
        .spec;
        let decoded = from_proto(to_proto(original.clone())).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.canonical_json().unwrap(),
            original.canonical_json().unwrap()
        );
    }

    #[test]
    fn public_project_spec_rejects_local_paths_and_noncanonical_values() {
        let proto = proto::ProjectSpec {
            schema_version: project::PROJECT_SCHEMA_VERSION,
            working_directory: "/workspace".to_string(),
            access: Some(proto::ProjectAccessBinding {
                profile: "work".to_string(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(from_proto(proto).is_err());

        let descriptor_json = serde_json::to_string(&to_proto(project::ProjectSpec::default()))
            .expect("serialize public project spec");
        for forbidden in ["hostPath", "token", "secretValue", "backendSocket"] {
            assert!(
                !descriptor_json.contains(forbidden),
                "unexpected {forbidden}"
            );
        }
    }
}
