use std::collections::BTreeMap;
use std::path::PathBuf;

use codewire_access::{AccessProfileId, EnvironmentAccessBinding, EnvironmentId};
use uuid::Uuid;

use crate::control::v1;
use crate::host_port::HostPortBinding;
use crate::linux::path::FileIdentity;
use crate::mesh_ingress::{MeshAttachment, MeshEnrollmentAuthSource};
use crate::oci::{OciArchitecture, ResolvedDescriptor, ResolvedImage, Sha256Digest};

use super::*;

fn with_lf(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(b'\n');
    bytes
}

fn runner_record() -> RunnerRecord {
    RunnerRecord {
        process: ProcessIdentity {
            pid: 123,
            boot_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            start_time_ticks: 456,
            executable: PathBuf::from("/usr/bin/cw"),
            executable_file: FileIdentity {
                device: 1,
                inode: 2,
                size: 3,
                uid: 501,
                mode: 0o100500,
                links: 1,
            },
            executable_sha256: "a".repeat(64),
        },
        socket: SocketIdentity {
            device: 4,
            inode: 5,
            uid: 501,
            mode: 0o140600,
        },
        artifact_generation: "c".repeat(64),
        error_code: Some("runner_failed".to_owned()),
    }
}

fn descriptor(media_type: &str, byte: char, size: u64) -> ResolvedDescriptor {
    ResolvedDescriptor {
        media_type: media_type.to_owned(),
        digest: Sha256Digest::parse(&format!("sha256:{}", byte.to_string().repeat(64))).unwrap(),
        size,
    }
}

fn workspace_generation(root: char, artifact: char) -> WorkspaceGenerationRecord {
    WorkspaceGenerationRecord {
        schema_version: 4,
        root_generation: root.to_string().repeat(64),
        project_sha256: "d".repeat(64),
        project_spec_json: "{}".to_owned(),
        artifact_generation: artifact.to_string().repeat(64),
        image: ResolvedImage {
            source_reference: "registry.synthetic.invalid/workspace:latest".to_owned(),
            architecture: OciArchitecture::Amd64,
            source: descriptor("application/vnd.oci.image.index.v1+json", '1', 101),
            manifest: descriptor("application/vnd.oci.image.manifest.v1+json", '2', 102),
            config: descriptor("application/vnd.oci.image.config.v1+json", '3', 103),
            layers: Vec::new(),
        },
        root_disk_bytes: 8 * 1024 * 1024 * 1024,
        skill_snapshot: None,
    }
}

fn complete_environment() -> EnvironmentRecord {
    // This fully populated record pins the byte codec. Semantic admission is
    // covered by the existing supervisor and store validation tests.
    let mut environment = super::super::tests::project_environment();
    environment.id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    environment.state = StoredEnvironmentState::Error;
    environment.docker_disk_bytes = 4 * 1024 * 1024 * 1024;
    environment.generation = 7;
    environment.host_ports = vec![HostPortBinding::new(18_080, 3_000).unwrap()];
    environment.mesh = Some(MeshAttachment {
        auth_source: MeshEnrollmentAuthSource::StandaloneLocal,
        mesh_url: "https://mesh.synthetic.invalid/".to_owned(),
        organization_id: "synthetic-org".to_owned(),
        network_id: "synthetic-network".to_owned(),
        node_name: "dev".to_owned(),
        guest_ports: vec![3_000],
    });
    environment.project_spec_json = Some(b"{}".to_vec());
    environment.project_spec_sha256 = Some("d".repeat(64));
    environment.access_profile = Some("user/work".parse().unwrap());
    environment.access_binding = Some(EnvironmentAccessBinding {
        environment_id: EnvironmentId::parse("environment-1").unwrap(),
        profile_id: AccessProfileId::parse("profile-1").unwrap(),
        profile_revision: 9,
    });
    environment.platform_source_authority = Some(
        PlatformSourceAuthority::from_proto(&v1::PlatformSourceAuthority {
            server_url: "https://synthetic.invalid".to_owned(),
            organization_id: "synthetic-org".to_owned(),
            user_id: "synthetic-owner".to_owned(),
            profile_slots: vec!["codex".to_owned(), "openai".to_owned()],
        })
        .unwrap(),
    );
    environment.runner = Some(runner_record());
    environment.active_artifact_generation = Some("b".repeat(64));
    environment.staging_artifact_generation = Some("c".repeat(64));
    environment.active_workspace_generation = Some(workspace_generation('e', 'b'));
    environment.staging_workspace_generation = Some(workspace_generation('f', 'c'));
    environment.rollback_workspace_generation = Some(workspace_generation('9', 'a'));
    environment
}

fn complete_state() -> SupervisorState {
    let environment = complete_environment();
    SupervisorState {
        schema_version: SUPERVISOR_STATE_SCHEMA,
        current: Some(environment.name.clone()),
        environments: BTreeMap::from([(environment.name.clone(), environment)]),
    }
}

#[test]
fn default_and_complete_state_bytes_are_stable() {
    let state = SupervisorState::default();
    assert_eq!(
        with_lf(serde_json::to_vec(&state).unwrap()),
        include_bytes!("testdata/default-state.json").to_vec()
    );
    assert_eq!(
        serde_json::from_slice::<SupervisorState>(include_bytes!("testdata/default-state.json"))
            .unwrap(),
        state
    );

    let state = complete_state();
    assert_eq!(
        with_lf(serde_json::to_vec(&state).unwrap()),
        include_bytes!("testdata/complete-state.json").to_vec()
    );
    assert_eq!(
        serde_json::from_slice::<SupervisorState>(include_bytes!("testdata/complete-state.json"))
            .unwrap(),
        state
    );
}

#[test]
fn omitted_environment_fields_keep_the_existing_defaults() {
    let mut encoded = serde_json::to_value(complete_environment()).unwrap();
    let fields = encoded.as_object_mut().unwrap();
    for field in [
        "docker_disk_bytes",
        "host_ports",
        "mesh",
        "project_spec_json",
        "project_spec_sha256",
        "access_profile",
        "access_binding",
        "platform_source_authority",
        "active_artifact_generation",
        "staging_artifact_generation",
        "active_workspace_generation",
        "staging_workspace_generation",
        "rollback_workspace_generation",
    ] {
        assert!(
            fields.remove(field).is_some(),
            "missing fixture field {field}"
        );
    }
    let decoded: EnvironmentRecord = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.docker_disk_bytes, 0);
    assert!(decoded.host_ports.is_empty());
    assert!(decoded.mesh.is_none());
    assert!(decoded.project_spec_json.is_none());
    assert!(decoded.project_spec_sha256.is_none());
    assert!(decoded.access_profile.is_none());
    assert!(decoded.access_binding.is_none());
    assert!(decoded.platform_source_authority.is_none());
    assert!(decoded.active_artifact_generation.is_none());
    assert!(decoded.staging_artifact_generation.is_none());
    assert!(decoded.active_workspace_generation.is_none());
    assert!(decoded.staging_workspace_generation.is_none());
    assert!(decoded.rollback_workspace_generation.is_none());

    let mut missing_required = serde_json::to_value(complete_environment()).unwrap();
    assert!(
        missing_required
            .as_object_mut()
            .unwrap()
            .remove("runner")
            .is_some()
    );
    assert!(
        serde_json::from_value::<EnvironmentRecord>(missing_required)
            .unwrap()
            .runner
            .is_none()
    );

    let mut missing_required = serde_json::to_value(complete_environment()).unwrap();
    assert!(
        missing_required
            .as_object_mut()
            .unwrap()
            .remove("generation")
            .is_some()
    );
    assert!(serde_json::from_value::<EnvironmentRecord>(missing_required).is_err());
}

#[test]
fn durable_metadata_rejects_unknown_fields() {
    let mut runner = serde_json::to_value(runner_record()).unwrap();
    runner
        .as_object_mut()
        .unwrap()
        .insert("future".to_owned(), serde_json::Value::Null);
    assert!(serde_json::from_value::<RunnerRecord>(runner).is_err());

    let mut environment = serde_json::to_value(complete_environment()).unwrap();
    environment
        .as_object_mut()
        .unwrap()
        .insert("future".to_owned(), serde_json::Value::Null);
    assert!(serde_json::from_value::<EnvironmentRecord>(environment).is_err());

    let mut state = serde_json::to_value(SupervisorState::default()).unwrap();
    state
        .as_object_mut()
        .unwrap()
        .insert("future".to_owned(), serde_json::Value::Null);
    assert!(serde_json::from_value::<SupervisorState>(state).is_err());
    assert!(serde_json::from_str::<StoredEnvironmentState>(r#""future""#).is_err());
}
