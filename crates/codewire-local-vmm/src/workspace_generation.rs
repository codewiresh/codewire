//! Durable, credential-free identity for an OCI workspace root generation.
//!
//! Registry credentials are deliberately absent. The record contains only the
//! verified descriptors needed to replay from the owner-private CAS, together
//! with the project, runtime-artifact generation, and root-disk policy that
//! define the guest generation.

use codewire_project::{MAX_PROJECT_DOCUMENT_BYTES, ProjectSpec};
use codewire_vmm_guest_probe::{
    SetupArchitecture, Sha256Value, SkillSnapshotPlan, oci_root_generation,
};
use serde::{Deserialize, Serialize};

use crate::generation::valid_root_disk_bytes;
use crate::oci::{OciArchitecture, ResolvedImage};

const WORKSPACE_GENERATION_SCHEMA_VERSION: u32 = 4;
const MAXIMUM_WORKSPACE_GENERATION_BYTES: usize = 512 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceGenerationRecord {
    pub(crate) schema_version: u32,
    pub(crate) root_generation: String,
    pub(crate) project_sha256: String,
    pub(crate) project_spec_json: String,
    pub(crate) artifact_generation: String,
    pub(crate) image: ResolvedImage,
    pub(crate) root_disk_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) skill_snapshot: Option<SkillSnapshotPlan>,
}

impl std::fmt::Debug for WorkspaceGenerationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceGenerationRecord")
            .field("schema_version", &self.schema_version)
            .field("root_generation", &self.root_generation)
            .field("project_sha256", &self.project_sha256)
            .field("artifact_generation", &self.artifact_generation)
            .field("architecture", &self.image.architecture)
            .field("source_digest", &self.image.source.digest)
            .field("manifest_digest", &self.image.manifest.digest)
            .field("layer_count", &self.image.layers.len())
            .field("root_disk_bytes", &self.root_disk_bytes)
            .field(
                "skill_snapshot_generation",
                &self
                    .skill_snapshot
                    .as_ref()
                    .map(SkillSnapshotPlan::plan_generation),
            )
            .finish()
    }
}

impl WorkspaceGenerationRecord {
    #[cfg(test)]
    pub(crate) fn new(
        project_spec_json: &[u8],
        project_sha256: String,
        artifact_generation: String,
        image: ResolvedImage,
        root_disk_bytes: u64,
    ) -> Result<Self, WorkspaceGenerationError> {
        Self::new_with_skill_snapshot(
            project_spec_json,
            project_sha256,
            artifact_generation,
            image,
            root_disk_bytes,
            None,
        )
    }

    pub(crate) fn new_with_skill_snapshot(
        project_spec_json: &[u8],
        project_sha256: String,
        artifact_generation: String,
        image: ResolvedImage,
        root_disk_bytes: u64,
        skill_snapshot: Option<SkillSnapshotPlan>,
    ) -> Result<Self, WorkspaceGenerationError> {
        let project = validate_project_spec(project_spec_json, &project_sha256)?;
        if project.image != image.source_reference {
            return Err(WorkspaceGenerationError);
        }
        validate_artifact_generation(&artifact_generation)?;
        let root_generation = calculated_root_generation(&project_sha256, &image)?;
        let record = Self {
            schema_version: WORKSPACE_GENERATION_SCHEMA_VERSION,
            root_generation,
            project_sha256,
            project_spec_json: std::str::from_utf8(project_spec_json)
                .map_err(|_| WorkspaceGenerationError)?
                .to_owned(),
            artifact_generation,
            image,
            root_disk_bytes,
            skill_snapshot,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), WorkspaceGenerationError> {
        if self.schema_version != WORKSPACE_GENERATION_SCHEMA_VERSION {
            return Err(WorkspaceGenerationError);
        }
        let project =
            validate_project_spec(self.project_spec_json.as_bytes(), &self.project_sha256)?;
        if project.image != self.image.source_reference
            || validate_artifact_generation(&self.artifact_generation).is_err()
        {
            return Err(WorkspaceGenerationError);
        }
        if !valid_root_disk_bytes(self.root_disk_bytes)
            || self.image.architecture
                != OciArchitecture::native().map_err(|_| WorkspaceGenerationError)?
        {
            return Err(WorkspaceGenerationError);
        }
        match (&project.skills[..], &self.skill_snapshot) {
            ([], None) => {}
            ([], Some(_)) | (_, None) => return Err(WorkspaceGenerationError),
            (_, Some(snapshot)) => {
                snapshot
                    .encode_canonical()
                    .map_err(|_| WorkspaceGenerationError)?;
                if snapshot.project_sha256() != self.project_sha256 {
                    return Err(WorkspaceGenerationError);
                }
            }
        }
        self.image
            .validate_metadata()
            .map_err(|_| WorkspaceGenerationError)?;
        if calculated_root_generation(&self.project_sha256, &self.image)? != self.root_generation {
            return Err(WorkspaceGenerationError);
        }
        Ok(())
    }

    pub(crate) fn validate_for_project(
        &self,
        expected_project_sha256: &str,
    ) -> Result<(), WorkspaceGenerationError> {
        self.validate()?;
        if self.project_sha256 != expected_project_sha256 {
            return Err(WorkspaceGenerationError);
        }
        Ok(())
    }

    pub(crate) fn validate_for_project_intent(
        &self,
        project_spec_json: &[u8],
        project_sha256: &str,
    ) -> Result<(), WorkspaceGenerationError> {
        self.validate_for_project(project_sha256)?;
        let project = validate_project_spec(project_spec_json, project_sha256)?;
        if project.image != self.image.source_reference
            || self.project_spec_json.as_bytes() != project_spec_json
        {
            return Err(WorkspaceGenerationError);
        }
        Ok(())
    }

    pub(crate) fn project_spec_json(&self) -> Result<&[u8], WorkspaceGenerationError> {
        self.validate()?;
        Ok(self.project_spec_json.as_bytes())
    }

    pub(crate) fn artifact_generation(&self) -> Result<&str, WorkspaceGenerationError> {
        self.validate()?;
        Ok(&self.artifact_generation)
    }

    pub(crate) fn skill_snapshot(
        &self,
    ) -> Result<Option<&SkillSnapshotPlan>, WorkspaceGenerationError> {
        self.validate()?;
        Ok(self.skill_snapshot.as_ref())
    }

    pub(crate) fn encode_canonical(&self) -> Result<Vec<u8>, WorkspaceGenerationError> {
        self.validate()?;
        encode_bounded(self)
    }

    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, WorkspaceGenerationError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_WORKSPACE_GENERATION_BYTES {
            return Err(WorkspaceGenerationError);
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| WorkspaceGenerationError)?;
        record.validate()?;
        if encode_bounded(&record)? != bytes {
            return Err(WorkspaceGenerationError);
        }
        Ok(record)
    }
}

fn validate_artifact_generation(value: &str) -> Result<(), WorkspaceGenerationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WorkspaceGenerationError);
    }
    Ok(())
}

fn validate_project_spec(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<ProjectSpec, WorkspaceGenerationError> {
    if bytes.is_empty() || bytes.len() > MAX_PROJECT_DOCUMENT_BYTES {
        return Err(WorkspaceGenerationError);
    }
    let project: ProjectSpec =
        serde_json::from_slice(bytes).map_err(|_| WorkspaceGenerationError)?;
    let canonical = project
        .canonical_json()
        .map_err(|_| WorkspaceGenerationError)?;
    if canonical != bytes || Sha256Value::calculate(bytes).to_string() != expected_sha256 {
        return Err(WorkspaceGenerationError);
    }
    Ok(project)
}

fn calculated_root_generation(
    project_sha256: &str,
    image: &ResolvedImage,
) -> Result<String, WorkspaceGenerationError> {
    let project_sha256 =
        Sha256Value::parse_hex(project_sha256).map_err(|_| WorkspaceGenerationError)?;
    let manifest_sha256 = Sha256Value::parse_digest(image.manifest.digest.as_str())
        .map_err(|_| WorkspaceGenerationError)?;
    let architecture = match image.architecture {
        OciArchitecture::Amd64 => SetupArchitecture::Amd64,
        OciArchitecture::Arm64 => SetupArchitecture::Arm64,
    };
    Ok(oci_root_generation(project_sha256, manifest_sha256, architecture).to_string())
}

fn encode_bounded(record: &WorkspaceGenerationRecord) -> Result<Vec<u8>, WorkspaceGenerationError> {
    let bytes = serde_json::to_vec(record).map_err(|_| WorkspaceGenerationError)?;
    if bytes.len() > MAXIMUM_WORKSPACE_GENERATION_BYTES {
        return Err(WorkspaceGenerationError);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("workspace generation record is invalid")]
pub(crate) struct WorkspaceGenerationError;

#[cfg(test)]
mod tests {
    use codewire_project::{AgentsSpec, SkillSelection, SkillSource};
    use codewire_vmm_guest_probe::{SkillSnapshot, SkillSnapshotSource};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::oci::{ResolvedDescriptor, ResolvedLayer, Sha256Digest};

    fn digest(seed: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(seed))).unwrap()
    }

    fn record() -> WorkspaceGenerationRecord {
        let manifest_digest = digest(b"manifest");
        let manifest = ResolvedDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            digest: manifest_digest.clone(),
            size: 512,
        };
        let image = ResolvedImage {
            source_reference: format!(
                "registry.example/codewire/workspace@{}",
                manifest_digest.as_str()
            ),
            architecture: OciArchitecture::native().unwrap(),
            source: manifest.clone(),
            manifest,
            config: ResolvedDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                digest: digest(b"config"),
                size: 256,
            },
            layers: vec![ResolvedLayer {
                descriptor: ResolvedDescriptor {
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                    digest: digest(b"compressed layer"),
                    size: 1024,
                },
                diff_id: digest(b"uncompressed layer"),
            }],
        };
        let project = ProjectSpec {
            image: image.source_reference.clone(),
            ..Default::default()
        };
        let project_spec_json = project.canonical_json().unwrap();
        let project_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
        let root_generation = calculated_root_generation(&project_sha256, &image).unwrap();
        WorkspaceGenerationRecord {
            schema_version: WORKSPACE_GENERATION_SCHEMA_VERSION,
            root_generation,
            project_sha256,
            project_spec_json: String::from_utf8(project_spec_json).unwrap(),
            artifact_generation: "a".repeat(64),
            image,
            root_disk_bytes: crate::linux::state::MINIMUM_ROOT_DISK_BYTES,
            skill_snapshot: None,
        }
    }

    #[test]
    fn canonical_record_round_trips_without_registry_credentials() {
        let record = record();
        let bytes = record.encode_canonical().unwrap();
        assert_eq!(
            WorkspaceGenerationRecord::decode_canonical(&bytes).unwrap(),
            record
        );
        assert!(
            !bytes
                .windows("credential".len())
                .any(|part| part == b"credential")
        );
        assert!(!bytes.windows("token".len()).any(|part| part == b"token"));
    }

    #[test]
    fn constructor_derives_and_validates_the_exact_generation() {
        let expected = record();
        let constructed = WorkspaceGenerationRecord::new(
            expected.project_spec_json.as_bytes(),
            expected.project_sha256.clone(),
            expected.artifact_generation.clone(),
            expected.image.clone(),
            expected.root_disk_bytes,
        )
        .unwrap();

        assert_eq!(constructed, expected);
    }

    #[test]
    fn selected_skills_require_an_exact_project_bound_snapshot_plan() {
        let baseline = record();
        let project = ProjectSpec {
            image: baseline.image.source_reference.clone(),
            agents: AgentsSpec {
                install: None,
                tools: vec!["codex".to_owned()],
            },
            skills: vec![SkillSelection {
                source: SkillSource::User,
                reference: "rust".to_owned(),
                agents: vec!["codex".to_owned()],
            }],
            ..Default::default()
        };
        let project_json = project.canonical_json().unwrap();
        let project_sha256 = format!("{:x}", Sha256::digest(&project_json));
        let snapshot = SkillSnapshot::new(
            SkillSnapshotSource::User,
            "user:rust".to_owned(),
            "rust".to_owned(),
            "b".repeat(64),
            "rust",
            &["codex".to_owned()],
        )
        .unwrap();
        let plan = SkillSnapshotPlan::new(project_sha256.clone(), 1, vec![snapshot]).unwrap();
        let record = WorkspaceGenerationRecord::new_with_skill_snapshot(
            &project_json,
            project_sha256.clone(),
            baseline.artifact_generation,
            baseline.image,
            baseline.root_disk_bytes,
            Some(plan.clone()),
        )
        .unwrap();
        assert_eq!(
            WorkspaceGenerationRecord::decode_canonical(&record.encode_canonical().unwrap())
                .unwrap(),
            record
        );

        assert!(
            WorkspaceGenerationRecord::new_with_skill_snapshot(
                &project_json,
                project_sha256,
                record.artifact_generation.clone(),
                record.image.clone(),
                record.root_disk_bytes,
                None,
            )
            .is_err()
        );
        let wrong_plan = SkillSnapshotPlan::new(
            "c".repeat(64),
            plan.plan_generation(),
            plan.skills().to_vec(),
        )
        .unwrap();
        let mut invalid = record;
        invalid.skill_snapshot = Some(wrong_plan);
        assert!(invalid.encode_canonical().is_err());
    }

    #[test]
    fn noncanonical_unknown_and_oversized_records_fail_closed() {
        let record = record();
        let mut bytes = record.encode_canonical().unwrap();
        bytes.push(b' ');
        assert!(WorkspaceGenerationRecord::decode_canonical(&bytes).is_err());

        let mut value = serde_json::to_value(&record).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Null);
        assert!(
            WorkspaceGenerationRecord::decode_canonical(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
        assert!(
            WorkspaceGenerationRecord::decode_canonical(&vec![
                b' ';
                MAXIMUM_WORKSPACE_GENERATION_BYTES
                    + 1
            ])
            .is_err()
        );

        let mut invalid_artifact = record.clone();
        invalid_artifact.artifact_generation = "g".repeat(64);
        assert!(invalid_artifact.encode_canonical().is_err());

        let mut old_schema = record.clone();
        old_schema.schema_version = 2;
        assert!(old_schema.encode_canonical().is_err());
    }

    #[test]
    fn generation_is_bound_to_project_manifest_architecture_and_disk_policy() {
        let expected = record();

        let mut changed = expected.clone();
        changed.project_sha256 = "f".repeat(64);
        assert!(
            changed
                .validate_for_project(&changed.project_sha256)
                .is_err()
        );

        let mut changed = expected.clone();
        changed.image.manifest.digest = digest(b"different manifest");
        assert!(
            changed
                .validate_for_project(&changed.project_sha256)
                .is_err()
        );

        let mut changed = expected.clone();
        changed.image.architecture = match changed.image.architecture {
            OciArchitecture::Amd64 => OciArchitecture::Arm64,
            OciArchitecture::Arm64 => OciArchitecture::Amd64,
        };
        assert!(
            changed
                .validate_for_project(&changed.project_sha256)
                .is_err()
        );

        let mut changed = expected;
        changed.root_disk_bytes += 1;
        assert!(
            changed
                .validate_for_project(&changed.project_sha256)
                .is_err()
        );
    }

    #[test]
    fn debug_output_excludes_the_registry_reference() {
        let record = record();
        let debug = format!("{record:?}");
        assert!(!debug.contains(&record.image.source_reference));
        assert!(debug.contains(record.image.manifest.digest.as_str()));
    }
}
