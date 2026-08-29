//! Durable, credential-free identity for an OCI workspace root generation.
//!
//! Registry credentials are deliberately absent. The record contains only the
//! verified descriptors needed to replay from the owner-private CAS, together
//! with the project and root-disk policy that define the guest generation.

use codewire_project::{MAX_PROJECT_DOCUMENT_BYTES, ProjectSpec};
use codewire_vmm_guest_probe::{SetupArchitecture, Sha256Value, oci_root_generation};
use serde::{Deserialize, Serialize};

use crate::generation::valid_root_disk_bytes;
use crate::oci::{OciArchitecture, ResolvedImage};

const LEGACY_WORKSPACE_GENERATION_SCHEMA_VERSION: u32 = 1;
const WORKSPACE_GENERATION_SCHEMA_VERSION: u32 = 2;
const MAXIMUM_WORKSPACE_GENERATION_BYTES: usize = 512 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceGenerationRecord {
    pub(crate) schema_version: u32,
    pub(crate) root_generation: String,
    pub(crate) project_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_json: Option<String>,
    pub(crate) image: ResolvedImage,
    pub(crate) root_disk_bytes: u64,
}

impl std::fmt::Debug for WorkspaceGenerationRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceGenerationRecord")
            .field("schema_version", &self.schema_version)
            .field("root_generation", &self.root_generation)
            .field("project_sha256", &self.project_sha256)
            .field("architecture", &self.image.architecture)
            .field("source_digest", &self.image.source.digest)
            .field("manifest_digest", &self.image.manifest.digest)
            .field("layer_count", &self.image.layers.len())
            .field("root_disk_bytes", &self.root_disk_bytes)
            .finish()
    }
}

impl WorkspaceGenerationRecord {
    pub(crate) fn new(
        project_spec_json: &[u8],
        project_sha256: String,
        image: ResolvedImage,
        root_disk_bytes: u64,
    ) -> Result<Self, WorkspaceGenerationError> {
        let project = validate_project_spec(project_spec_json, &project_sha256)?;
        if project.image != image.source_reference {
            return Err(WorkspaceGenerationError);
        }
        let root_generation = calculated_root_generation(&project_sha256, &image)?;
        let record = Self {
            schema_version: WORKSPACE_GENERATION_SCHEMA_VERSION,
            root_generation,
            project_sha256,
            project_spec_json: Some(
                std::str::from_utf8(project_spec_json)
                    .map_err(|_| WorkspaceGenerationError)?
                    .to_owned(),
            ),
            image,
            root_disk_bytes,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), WorkspaceGenerationError> {
        match (self.schema_version, self.project_spec_json.as_deref()) {
            (LEGACY_WORKSPACE_GENERATION_SCHEMA_VERSION, None) => {}
            (WORKSPACE_GENERATION_SCHEMA_VERSION, Some(project_json)) => {
                let project = validate_project_spec(project_json.as_bytes(), &self.project_sha256)?;
                if project.image != self.image.source_reference {
                    return Err(WorkspaceGenerationError);
                }
            }
            _ => return Err(WorkspaceGenerationError),
        }
        if !valid_root_disk_bytes(self.root_disk_bytes)
            || self.image.architecture
                != OciArchitecture::native().map_err(|_| WorkspaceGenerationError)?
        {
            return Err(WorkspaceGenerationError);
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
            || self
                .project_spec_json
                .as_deref()
                .is_some_and(|embedded| embedded.as_bytes() != project_spec_json)
        {
            return Err(WorkspaceGenerationError);
        }
        Ok(())
    }

    pub(crate) fn project_spec_json<'a>(
        &'a self,
        legacy_project_spec_json: &'a [u8],
        legacy_project_sha256: &str,
    ) -> Result<&'a [u8], WorkspaceGenerationError> {
        match self.project_spec_json.as_deref() {
            Some(project_json) => {
                self.validate()?;
                Ok(project_json.as_bytes())
            }
            None => {
                self.validate_for_project_intent(legacy_project_spec_json, legacy_project_sha256)?;
                Ok(legacy_project_spec_json)
            }
        }
    }

    pub(crate) fn ensure_embedded_project(
        &mut self,
        project_spec_json: &[u8],
        project_sha256: &str,
    ) -> Result<(), WorkspaceGenerationError> {
        self.validate_for_project_intent(project_spec_json, project_sha256)?;
        if self.project_spec_json.is_none() {
            self.schema_version = WORKSPACE_GENERATION_SCHEMA_VERSION;
            self.project_spec_json = Some(
                std::str::from_utf8(project_spec_json)
                    .map_err(|_| WorkspaceGenerationError)?
                    .to_owned(),
            );
        }
        self.validate()
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
            project_spec_json: Some(String::from_utf8(project_spec_json).unwrap()),
            image,
            root_disk_bytes: crate::linux::state::MINIMUM_ROOT_DISK_BYTES,
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
            expected.project_spec_json.as_deref().unwrap().as_bytes(),
            expected.project_sha256.clone(),
            expected.image.clone(),
            expected.root_disk_bytes,
        )
        .unwrap();

        assert_eq!(constructed, expected);
    }

    #[test]
    fn legacy_record_round_trips_exactly_and_upgrades_without_changing_identity() {
        let current = record();
        let project_json = current
            .project_spec_json
            .as_deref()
            .unwrap()
            .as_bytes()
            .to_vec();
        let project_sha256 = current.project_sha256.clone();
        let mut legacy = current.clone();
        legacy.schema_version = LEGACY_WORKSPACE_GENERATION_SCHEMA_VERSION;
        legacy.project_spec_json = None;
        let encoded = legacy.encode_canonical().unwrap();
        assert_eq!(
            WorkspaceGenerationRecord::decode_canonical(&encoded).unwrap(),
            legacy
        );

        legacy
            .ensure_embedded_project(&project_json, &project_sha256)
            .unwrap();

        assert_eq!(legacy.schema_version, WORKSPACE_GENERATION_SCHEMA_VERSION);
        assert_eq!(legacy.root_generation, current.root_generation);
        assert_eq!(legacy.project_spec_json, current.project_spec_json);
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
