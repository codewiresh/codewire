//! Credential-free, generation-scoped OCI setup-pack construction.
//!
//! Registry authentication and hostile layer extraction are deliberately not
//! part of this boundary. The host copies already verified CAS objects into a
//! seed-bound read-only raw device; trusted guest init re-verifies and applies
//! them inside the VM.

use std::fs::{self, File};
use std::io::{self, Cursor, Read, Seek as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use codewire_vmm_guest_probe::{
    LayerEncoding, SETUP_HEADER_LEN, SetupArchitecture, SetupBlob, SetupError, SetupHeader,
    SetupLayerBlob, SetupObject, Sha256Value,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::linux::path::{PathError, PrivateRoot};
use crate::oci::{
    ContentStore, ContentStoreError, OciArchitecture, RegistryResolverError, ResolvedImage,
    Sha256Digest,
};
use crate::state::{RootGenerationPaths, StateError, VmPaths};

const SETUP_FILE_NAME: &str = "setup.raw";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

pub struct SetupPackRequest<'a> {
    pub project_json: &'a [u8],
    pub project_sha256: &'a str,
    pub storage_generation: &'a str,
    pub root_generation: &'a str,
    pub image: &'a ResolvedImage,
}

impl std::fmt::Debug for SetupPackRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SetupPackRequest")
            .field("project_bytes", &self.project_json.len())
            .field("project_sha256", &self.project_sha256)
            .field("storage_generation", &self.storage_generation)
            .field("root_generation", &self.root_generation)
            .field("manifest", &self.image.manifest.digest)
            .field("layer_count", &self.image.layers.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPack {
    pub path: PathBuf,
    pub header: SetupHeader,
    pub header_sha256: Sha256Value,
}

pub fn ensure_setup_pack(
    engine_state_root: &Path,
    vm_id: Uuid,
    store: &ContentStore,
    request: SetupPackRequest<'_>,
) -> Result<SetupPack, SetupPackError> {
    request.image.verify_cached(store)?;
    let project_sha256 = Sha256Value::parse_hex(request.project_sha256)?;
    if Sha256Value::calculate(request.project_json) != project_sha256 {
        return Err(SetupPackError::ProjectDigestMismatch);
    }

    let header = setup_header(&request, project_sha256)?;
    let header_bytes = header.encode()?;
    let header_sha256 = Sha256Value::calculate(&header_bytes);
    let engine = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine, vm_id)?;
    let generation = RootGenerationPaths::create(&paths, request.storage_generation)?;
    let root = PrivateRoot::open(&generation.generation_dir)?;
    let final_name = Path::new(SETUP_FILE_NAME);
    let final_path = generation.setup_disk.clone();

    match root.open_regular(
        final_name,
        false,
        Some(header.total_bytes),
        false,
        Some(0o400),
    ) {
        Ok(opened) => {
            verify_setup_pack(opened.into_file(), &header, &header_bytes)?;
            return Ok(SetupPack {
                path: final_path,
                header,
                header_sha256,
            });
        }
        Err(error) if path_error_is_not_found(&error) => {}
        Err(error) => return Err(error.into()),
    }

    let temporary_name = format!(".setup-{}.raw", Uuid::new_v4());
    let opened = root.create_regular(Path::new(&temporary_name), 0o600, true)?;
    let mut cleanup = TemporarySetup::new(&generation.generation_dir, &temporary_name);
    let mut output = opened.into_file();
    write_setup_pack(&mut output, store, &request, &header, &header_bytes)?;
    output.sync_all().map_err(|source| SetupPackError::Io {
        path: generation.generation_dir.join(&temporary_name),
        source,
    })?;
    output
        .set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|source| SetupPackError::Io {
            path: generation.generation_dir.join(&temporary_name),
            source,
        })?;
    output.sync_all().map_err(|source| SetupPackError::Io {
        path: generation.generation_dir.join(&temporary_name),
        source,
    })?;
    drop(output);
    cleanup.permissions = 0o400;

    let published =
        root.publish_private_regular_no_replace(Path::new(&temporary_name), final_name, 0o400)?;
    if published {
        cleanup.disarm();
    }
    let opened = root.open_regular(
        final_name,
        false,
        Some(header.total_bytes),
        false,
        Some(0o400),
    )?;
    verify_setup_pack(opened.into_file(), &header, &header_bytes)?;
    Ok(SetupPack {
        path: final_path,
        header,
        header_sha256,
    })
}

fn setup_header(
    request: &SetupPackRequest<'_>,
    project_sha256: Sha256Value,
) -> Result<SetupHeader, SetupPackError> {
    let architecture = match request.image.architecture {
        OciArchitecture::Amd64 => SetupArchitecture::Amd64,
        OciArchitecture::Arm64 => SetupArchitecture::Arm64,
    };
    let mut layers = Vec::with_capacity(request.image.layers.len());
    for layer in &request.image.layers {
        layers.push(SetupLayerBlob {
            blob: SetupBlob {
                size: layer.descriptor.size,
                sha256: setup_digest(&layer.descriptor.digest)?,
            },
            diff_id: setup_digest(&layer.diff_id)?,
            encoding: layer_encoding(&layer.descriptor.media_type)?,
        });
    }
    Ok(SetupHeader::layout(
        Sha256Value::parse_hex(request.root_generation)?,
        setup_digest(&request.image.manifest.digest)?,
        architecture,
        SetupBlob {
            size: u64::try_from(request.project_json.len())
                .map_err(|_| SetupPackError::ProjectTooLarge)?,
            sha256: project_sha256,
        },
        SetupBlob {
            size: request.image.config.size,
            sha256: setup_digest(&request.image.config.digest)?,
        },
        layers,
    )?)
}

fn setup_digest(digest: &Sha256Digest) -> Result<Sha256Value, SetupPackError> {
    Ok(Sha256Value::parse_digest(digest.as_str())?)
}

fn layer_encoding(media_type: &str) -> Result<LayerEncoding, SetupPackError> {
    match media_type {
        OCI_LAYER => Ok(LayerEncoding::Tar),
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP => Ok(LayerEncoding::Gzip),
        OCI_LAYER_ZSTD => Ok(LayerEncoding::Zstd),
        _ => Err(SetupPackError::UnsupportedLayerEncoding),
    }
}

fn write_setup_pack(
    output: &mut File,
    store: &ContentStore,
    request: &SetupPackRequest<'_>,
    header: &SetupHeader,
    header_bytes: &[u8],
) -> Result<(), SetupPackError> {
    output
        .write_all(header_bytes)
        .map_err(SetupPackError::Write)?;
    let mut project = Cursor::new(request.project_json);
    copy_object(output, &mut project, header.project)?;
    let mut config = store.open_blob(&request.image.config.digest, request.image.config.size)?;
    copy_object(output, &mut config, header.config)?;
    for (resolved, layer) in request.image.layers.iter().zip(&header.layers) {
        let mut input = store.open_blob(&resolved.descriptor.digest, resolved.descriptor.size)?;
        copy_object(output, &mut input, layer.object)?;
    }
    pad_to(output, header.total_bytes)?;
    if output.stream_position().map_err(SetupPackError::Write)? != header.total_bytes {
        return Err(SetupPackError::InvalidPack);
    }
    Ok(())
}

fn copy_object(
    output: &mut File,
    input: &mut impl Read,
    object: SetupObject,
) -> Result<(), SetupPackError> {
    pad_to(output, object.offset)?;
    let mut remaining = object.size;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| SetupPackError::InvalidPack)?;
        let read = input
            .read(&mut buffer[..maximum])
            .map_err(SetupPackError::Read)?;
        if read == 0 {
            return Err(SetupPackError::ObjectSizeMismatch);
        }
        output
            .write_all(&buffer[..read])
            .map_err(SetupPackError::Write)?;
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    if input.read(&mut extra).map_err(SetupPackError::Read)? != 0 {
        return Err(SetupPackError::ObjectSizeMismatch);
    }
    let actual = Sha256Value::from_bytes(hasher.finalize().into());
    if actual != object.sha256 {
        return Err(SetupPackError::ObjectDigestMismatch);
    }
    Ok(())
}

fn pad_to(output: &mut File, target: u64) -> Result<(), SetupPackError> {
    let position = output.stream_position().map_err(SetupPackError::Write)?;
    if position > target {
        return Err(SetupPackError::InvalidPack);
    }
    let mut remaining = target - position;
    let zeros = [0_u8; 4096];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| SetupPackError::InvalidPack)?;
        output
            .write_all(&zeros[..count])
            .map_err(SetupPackError::Write)?;
        remaining -= count as u64;
    }
    Ok(())
}

fn verify_setup_pack(
    mut input: File,
    expected: &SetupHeader,
    expected_header_bytes: &[u8],
) -> Result<(), SetupPackError> {
    let mut header_bytes = vec![0_u8; SETUP_HEADER_LEN];
    input
        .read_exact(&mut header_bytes)
        .map_err(SetupPackError::Read)?;
    if header_bytes != expected_header_bytes || SetupHeader::decode(&header_bytes)? != *expected {
        return Err(SetupPackError::ExistingPackMismatch);
    }
    verify_object(&mut input, expected.project)?;
    verify_object(&mut input, expected.config)?;
    for layer in &expected.layers {
        verify_object(&mut input, layer.object)?;
    }
    verify_zero_padding(&mut input, expected.total_bytes)?;
    let mut extra = [0_u8; 1];
    if input.read(&mut extra).map_err(SetupPackError::Read)? != 0 {
        return Err(SetupPackError::ExistingPackMismatch);
    }
    Ok(())
}

fn verify_object(input: &mut File, object: SetupObject) -> Result<(), SetupPackError> {
    verify_zero_padding(input, object.offset)?;
    let mut remaining = object.size;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| SetupPackError::InvalidPack)?;
        let read = input
            .read(&mut buffer[..maximum])
            .map_err(SetupPackError::Read)?;
        if read == 0 {
            return Err(SetupPackError::ExistingPackMismatch);
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let actual = Sha256Value::from_bytes(hasher.finalize().into());
    if actual != object.sha256 {
        return Err(SetupPackError::ExistingPackMismatch);
    }
    Ok(())
}

fn verify_zero_padding(input: &mut File, target: u64) -> Result<(), SetupPackError> {
    let position = input.stream_position().map_err(SetupPackError::Read)?;
    if position > target {
        return Err(SetupPackError::ExistingPackMismatch);
    }
    let mut remaining = target - position;
    let mut buffer = [0_u8; 4096];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| SetupPackError::InvalidPack)?;
        input
            .read_exact(&mut buffer[..count])
            .map_err(SetupPackError::Read)?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(SetupPackError::ExistingPackMismatch);
        }
        remaining -= count as u64;
    }
    Ok(())
}

struct TemporarySetup {
    root: PathBuf,
    name: String,
    permissions: u32,
    active: bool,
}

impl TemporarySetup {
    fn new(root: &Path, name: &str) -> Self {
        Self {
            root: root.to_owned(),
            name: name.to_owned(),
            permissions: 0o600,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TemporarySetup {
    fn drop(&mut self) {
        if self.active
            && let Ok(root) = PrivateRoot::open(&self.root)
        {
            let _ = root.remove_private_regular(Path::new(&self.name), self.permissions);
        }
    }
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetupPackError {
    #[error("canonical project digest does not match its bytes")]
    ProjectDigestMismatch,
    #[error("canonical project document is too large")]
    ProjectTooLarge,
    #[error("OCI layer encoding is unsupported by the guest setup ABI")]
    UnsupportedLayerEncoding,
    #[error("setup object size differs from its descriptor")]
    ObjectSizeMismatch,
    #[error("setup object digest differs from its descriptor")]
    ObjectDigestMismatch,
    #[error("setup pack layout is invalid")]
    InvalidPack,
    #[error("existing setup pack does not match its generation identity")]
    ExistingPackMismatch,
    #[error("read setup input: {0}")]
    Read(io::Error),
    #[error("write setup pack: {0}")]
    Write(io::Error),
    #[error("setup pack filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Header(#[from] SetupError),
    #[error(transparent)]
    Content(#[from] ContentStoreError),
    #[error(transparent)]
    Registry(#[from] RegistryResolverError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    State(#[from] StateError),
}

#[cfg(test)]
mod tests {
    use std::io::SeekFrom;
    use std::os::unix::fs::MetadataExt as _;

    use bytes::Bytes;
    use serde_json::json;

    use super::*;
    use crate::oci::{ResolvedDescriptor, ResolvedLayer};

    fn root_generation(image: &ResolvedImage, project_sha256: &str) -> String {
        codewire_vmm_guest_probe::oci_root_generation(
            Sha256Value::parse_hex(project_sha256).unwrap(),
            setup_digest(&image.manifest.digest).unwrap(),
            SetupArchitecture::Amd64,
        )
        .to_string()
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
    }

    async fn fixture() -> (
        tempfile::TempDir,
        ContentStore,
        ResolvedImage,
        Vec<u8>,
        String,
    ) {
        let parent = tempfile::tempdir().unwrap();
        let runtime = parent.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&runtime).unwrap();
        let store = ContentStore::create(&root).unwrap();

        let layer = b"synthetic-compressed-layer".to_vec();
        let layer_digest = digest(&layer);
        let diff_id = digest(b"synthetic-uncompressed-layer");
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [diff_id.as_str()]}
        }))
        .unwrap();
        let config_digest = digest(&config);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.as_str(),
                "size": config.len()
            },
            "layers": [{
                "mediaType": OCI_LAYER_GZIP,
                "digest": layer_digest.as_str(),
                "size": layer.len()
            }]
        }))
        .unwrap();
        let manifest_digest = digest(&manifest);
        for (object_digest, bytes) in [
            (&manifest_digest, manifest.as_slice()),
            (&config_digest, config.as_slice()),
            (&layer_digest, layer.as_slice()),
        ] {
            store
                .admit_bytes(object_digest, Bytes::copy_from_slice(bytes))
                .await
                .unwrap();
        }
        let manifest_descriptor = ResolvedDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            digest: manifest_digest.clone(),
            size: manifest.len() as u64,
        };
        let image = ResolvedImage {
            source_reference: format!(
                "registry.example/test/workspace@{}",
                manifest_digest.as_str()
            ),
            architecture: OciArchitecture::Amd64,
            source: manifest_descriptor.clone(),
            manifest: manifest_descriptor,
            config: ResolvedDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                digest: config_digest,
                size: config.len() as u64,
            },
            layers: vec![ResolvedLayer {
                descriptor: ResolvedDescriptor {
                    media_type: OCI_LAYER_GZIP.to_owned(),
                    digest: layer_digest,
                    size: layer.len() as u64,
                },
                diff_id,
            }],
        };
        let project = br#"{"schema_version":1,"image":"registry.example/test/workspace","working_directory":"/workspace"}"#.to_vec();
        let project_sha256 = format!("{:x}", Sha256::digest(&project));
        (parent, store, image, project, project_sha256)
    }

    #[tokio::test]
    async fn setup_pack_is_private_exact_replayable_and_credential_free() {
        let (parent, store, image, project, project_sha256) = fixture().await;
        let root_generation = root_generation(&image, &project_sha256);
        let storage_generation = "c".repeat(64);
        let vm_id = Uuid::new_v4();
        let request = || SetupPackRequest {
            project_json: &project,
            project_sha256: &project_sha256,
            storage_generation: &storage_generation,
            root_generation: &root_generation,
            image: &image,
        };
        let first = ensure_setup_pack(
            parent.path().join("runtime").as_path(),
            vm_id,
            &store,
            request(),
        )
        .unwrap();
        let second = ensure_setup_pack(
            parent.path().join("runtime").as_path(),
            vm_id,
            &store,
            request(),
        )
        .unwrap();
        assert_eq!(first, second);
        let metadata = fs::symlink_metadata(&first.path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), first.header.total_bytes);
        assert_eq!(first.header_sha256, first.header.encoded_sha256().unwrap());
        let bytes = fs::read(&first.path).unwrap();
        assert_eq!(
            &bytes[first.header.project.offset as usize
                ..(first.header.project.offset + first.header.project.size) as usize],
            project.as_slice()
        );
        let rendered = format!("{request:?}", request = request());
        assert!(!rendered.contains(std::str::from_utf8(&project).unwrap()));
        assert!(
            !bytes
                .windows("Bearer ".len())
                .any(|window| window == b"Bearer ")
        );
    }

    #[tokio::test]
    async fn setup_pack_replay_rejects_corruption_without_replacement() {
        let (parent, store, image, project, project_sha256) = fixture().await;
        let root_generation = root_generation(&image, &project_sha256);
        let storage_generation = "c".repeat(64);
        let vm_id = Uuid::new_v4();
        let request = || SetupPackRequest {
            project_json: &project,
            project_sha256: &project_sha256,
            storage_generation: &storage_generation,
            root_generation: &root_generation,
            image: &image,
        };
        let pack = ensure_setup_pack(
            parent.path().join("runtime").as_path(),
            vm_id,
            &store,
            request(),
        )
        .unwrap();
        fs::set_permissions(&pack.path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = fs::OpenOptions::new().write(true).open(&pack.path).unwrap();
        file.seek(SeekFrom::Start(pack.header.config.offset))
            .unwrap();
        file.write_all(b"!").unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::set_permissions(&pack.path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            ensure_setup_pack(
                parent.path().join("runtime").as_path(),
                vm_id,
                &store,
                request()
            ),
            Err(SetupPackError::ExistingPackMismatch)
        ));
    }

    #[test]
    fn unsupported_layer_media_type_fails_closed() {
        assert!(matches!(
            layer_encoding("application/example"),
            Err(SetupPackError::UnsupportedLayerEncoding)
        ));
    }
}
