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
    let credentials =
        value
            .credentials
            .into_option()
            .map(|credentials| project::CredentialBinding {
                profile: credentials.profile,
            });
    let user = secrets
        .user
        .map(|placement| match placement.as_known() {
            Some(proto::ProjectStoragePlacement::Local) => Ok(project::StoragePlacement::Local),
            Some(proto::ProjectStoragePlacement::Platform) => {
                Ok(project::StoragePlacement::Platform)
            }
            _ => invalid(
                "project_spec.secrets.user",
                "must specify local or platform",
            ),
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
                source: repository.source,
                revision: repository.revision,
                branch: repository.branch,
                destination: repository.destination,
                known_hosts: repository.known_hosts,
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
            user,
        },
        credentials,
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
        user: value.secrets.user.map(|placement| match placement {
            project::StoragePlacement::Local => proto::ProjectStoragePlacement::Local.into(),
            project::StoragePlacement::Platform => proto::ProjectStoragePlacement::Platform.into(),
        }),
        ..Default::default()
    });
    let credentials = value
        .credentials
        .map(|credentials| proto::ProjectCredentialBinding {
            profile: credentials.profile,
            ..Default::default()
        });
    proto::ProjectSpec {
        schema_version: value.schema_version,
        preset: value.preset,
        image: value.image,
        repositories: value
            .repositories
            .into_iter()
            .map(|repository| proto::RepositorySpec {
                source: repository.source,
                branch: repository.branch,
                destination: repository.destination,
                revision: repository.revision,
                known_hosts: repository.known_hosts,
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
            .map(|port| proto::ApplicationPort {
                port: i32::from(port.port),
                label: port.label,
                access: port.access,
                ..Default::default()
            })
            .collect(),
        resources: resources.into(),
        secrets: secrets.into(),
        credentials: credentials.into(),
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
environment: {RUST_LOG: info}
agents: {tools: [claude-code, codex]}
skills: [{source: repository, path: .agents/skills/rust, agents: [codex]}]
ports: [{port: 8080, label: web, access: private}]
cpu: "2"
memory: "16Gi"
disk: "40Gi"
secrets: {project: platform:dev, organization: false, user: local}
credentials: {profile: platform:work}
"#,
        )
        .unwrap()
        .spec;
        let encoded = to_proto(original.clone());
        assert_eq!(
            encoded.repositories[0].source,
            "https://example.test/org/app.git"
        );
        assert_eq!(encoded.repositories[0].destination, "/workspace/app");
        assert_eq!(encoded.application_ports[0].port, 8080);
        let decoded = from_proto(encoded).unwrap();
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
            credentials: Some(proto::ProjectCredentialBinding {
                profile: "unknown:work".to_string(),
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

    #[test]
    fn public_repository_host_trust_round_trips_and_validates_through_one_model() {
        let known_host = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx";
        let original = project::parse_project_yaml(&format!(
            "repositories: [{{source: 'git@example.com:org/app.git', destination: /workspace/app, known_hosts: [{known_host:?}]}}]\n"
        ))
        .unwrap()
        .spec;
        let encoded = to_proto(original.clone());
        assert_eq!(
            encoded.repositories[0].known_hosts,
            vec![known_host.to_owned()]
        );
        assert_eq!(from_proto(encoded).unwrap(), original);

        let invalid = proto::ProjectSpec {
            schema_version: project::PROJECT_SCHEMA_VERSION,
            working_directory: "/workspace/app".into(),
            repositories: vec![proto::RepositorySpec {
                source: "https://example.com/org/app.git".into(),
                destination: "/workspace/app".into(),
                known_hosts: vec![known_host.into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(from_proto(invalid).is_err());
    }
}
