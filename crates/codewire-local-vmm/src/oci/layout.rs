use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use oci_spec::image::ImageIndex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;
use uuid::Uuid;

use super::registry::{source_descriptor_from_oci, validate_layout_index};
use super::{
    ContentStore, ContentStoreError, OciArchitecture, RegistryResolverError, ResolvedDescriptor,
    ResolvedImage, Sha256Digest,
};
use crate::linux::path::{PathError, PrivateRoot};

const PIN_FILE: &str = "synthetic-workspace-image-v1.json";
const MAXIMUM_ARCHIVE_BYTES: u64 = 80 * 1024 * 1024 * 1024;
const MAXIMUM_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAXIMUM_ARCHIVE_OBJECTS: usize = 65_536;
const MAXIMUM_PIN_BYTES: u64 = 512 * 1024;
const SYNTHETIC_REFERENCE_PREFIX: &str = "registry.invalid/codewire/workspace@";

#[derive(Debug)]
pub struct SyntheticOciArchiveInput {
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub source_digest: String,
    pub state_root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticImagePin {
    schema_version: u32,
    image: ResolvedImage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

#[derive(Debug, Clone, Copy)]
struct BlobLocation {
    offset: u64,
    size: u64,
}

struct LayoutInventory {
    index: Vec<u8>,
    blobs: BTreeMap<Sha256Digest, BlobLocation>,
}

pub async fn import_synthetic_oci_archive(
    input: SyntheticOciArchiveInput,
) -> Result<String, SyntheticOciImportError> {
    validate_input_scalars(&input)?;
    let mut archive = open_archive(&input)?;
    verify_archive(&mut archive, &input)?;
    let inventory = inventory(&archive, input.archive_size)?;
    let source_digest = Sha256Digest::parse(&input.source_digest)?;
    let source_reference = format!("{SYNTHETIC_REFERENCE_PREFIX}{source_digest}");
    let source = source_from_layout_index(&inventory.index, &source_digest)?;

    let root = PrivateRoot::create(&input.state_root)?;
    let mut state_entries = fs::read_dir(root.path()).map_err(SyntheticOciImportError::Io)?;
    if state_entries
        .next()
        .transpose()
        .map_err(SyntheticOciImportError::Io)?
        .is_some()
    {
        return Err(SyntheticOciImportError::StateRootNotFresh);
    }
    drop(state_entries);
    let engine_path = root.create_dir(Path::new("engine"), 0o700)?;
    let engine = PrivateRoot::open(&engine_path)?;
    let store = ContentStore::create(&engine)?;
    let imported = async {
        for (digest, location) in &inventory.blobs {
            admit_archive_blob(&store, &archive, digest, *location).await?;
        }
        let image = ResolvedImage::from_cached_source(
            source_reference.clone(),
            OciArchitecture::native()?,
            source,
            &store,
        )?;
        require_exact_closure(&inventory.blobs, &image)?;
        image.verify_cached(&store)?;
        publish_pin(&engine, &image)?;
        Ok(source_reference)
    }
    .await;
    if imported.is_err() {
        let _ = store.collect_unreferenced(&BTreeMap::new());
    }
    imported
}

pub(crate) fn load_synthetic_image_pin(
    engine: &PrivateRoot,
    store: &ContentStore,
) -> Result<Option<ResolvedImage>, SyntheticOciImportError> {
    let opened = match engine.open_regular(Path::new(PIN_FILE), false, None, false, Some(0o400)) {
        Ok(opened) => opened,
        Err(error) if path_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if opened.identity().size == 0 || opened.identity().size > MAXIMUM_PIN_BYTES {
        return Err(SyntheticOciImportError::InvalidPin);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.identity().size).map_err(|_| SyntheticOciImportError::InvalidPin)?,
    );
    opened
        .into_file()
        .read_to_end(&mut bytes)
        .map_err(SyntheticOciImportError::Io)?;
    let pin: SyntheticImagePin =
        serde_json::from_slice(&bytes).map_err(|_| SyntheticOciImportError::InvalidPin)?;
    if pin.schema_version != 1
        || !pin
            .image
            .source_reference
            .starts_with(SYNTHETIC_REFERENCE_PREFIX)
    {
        return Err(SyntheticOciImportError::InvalidPin);
    }
    let expected = pin
        .image
        .source_reference
        .strip_prefix(SYNTHETIC_REFERENCE_PREFIX)
        .ok_or(SyntheticOciImportError::InvalidPin)?;
    if expected != pin.image.source.digest.as_str() {
        return Err(SyntheticOciImportError::InvalidPin);
    }
    pin.image.verify_cached(store)?;
    Ok(Some(pin.image))
}

fn validate_input_scalars(input: &SyntheticOciArchiveInput) -> Result<(), SyntheticOciImportError> {
    if !input.archive.is_absolute()
        || !input.state_root.is_absolute()
        || input.archive_size == 0
        || input.archive_size > MAXIMUM_ARCHIVE_BYTES
        || input.archive_sha256.len() != 64
        || !input
            .archive_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SyntheticOciImportError::InvalidInput);
    }
    Sha256Digest::parse(&input.source_digest)?;
    Ok(())
}

fn open_archive(input: &SyntheticOciArchiveInput) -> Result<File, SyntheticOciImportError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&input.archive)
        .map_err(SyntheticOciImportError::Io)?;
    let opened = file.metadata().map_err(SyntheticOciImportError::Io)?;
    let named = fs::symlink_metadata(&input.archive).map_err(SyntheticOciImportError::Io)?;
    if !opened.is_file()
        || !named.is_file()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.nlink() != 1
        || opened.mode() & 0o777 != 0o400
        || opened.len() != input.archive_size
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || fs::canonicalize(&input.archive).map_err(SyntheticOciImportError::Io)? != input.archive
    {
        return Err(SyntheticOciImportError::UnsafeArchive);
    }
    Ok(file)
}

fn verify_archive(
    archive: &mut File,
    input: &SyntheticOciArchiveInput,
) -> Result<(), SyntheticOciImportError> {
    archive
        .seek(SeekFrom::Start(0))
        .map_err(SyntheticOciImportError::Io)?;
    let mut hasher = Sha256::new();
    let mut bounded = archive.take(input.archive_size);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(SyntheticOciImportError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if format!("{:x}", hasher.finalize()) != input.archive_sha256 {
        return Err(SyntheticOciImportError::ArchiveDigestMismatch);
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(SyntheticOciImportError::Io)?;
    Ok(())
}

fn inventory(
    archive: &File,
    archive_size: u64,
) -> Result<LayoutInventory, SyntheticOciImportError> {
    let mut tar = tar::Archive::new(archive.try_clone().map_err(SyntheticOciImportError::Io)?);
    let mut names = BTreeSet::new();
    let mut layout = None;
    let mut index = None;
    let mut blobs = BTreeMap::new();
    let mut object_count = 0_usize;
    for entry in tar.entries().map_err(SyntheticOciImportError::Io)? {
        let mut entry = entry.map_err(SyntheticOciImportError::Io)?;
        object_count = object_count
            .checked_add(1)
            .ok_or(SyntheticOciImportError::ArchiveObjectLimit)?;
        if object_count > MAXIMUM_ARCHIVE_OBJECTS
            || entry
                .pax_extensions()
                .map_err(SyntheticOciImportError::Io)?
                .is_some()
            || entry.path_bytes().as_ref() != entry.header().path_bytes().as_ref()
        {
            return Err(SyntheticOciImportError::InvalidArchive);
        }
        let name = std::str::from_utf8(entry.path_bytes().as_ref())
            .map_err(|_| SyntheticOciImportError::InvalidArchive)?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(SyntheticOciImportError::InvalidArchive);
        }
        let entry_type = entry.header().entry_type();
        match name.as_str() {
            "blobs/" | "blobs/sha256/" if entry_type.is_dir() && entry.size() == 0 => {}
            "oci-layout" if entry_type.is_file() => {
                layout = Some(read_document(&mut entry)?);
            }
            "index.json" if entry_type.is_file() => {
                index = Some(read_document(&mut entry)?);
            }
            _ if entry_type.is_file() => {
                let digest = blob_digest_from_path(&name)?;
                let location = BlobLocation {
                    offset: entry.raw_file_position(),
                    size: entry.size(),
                };
                if location
                    .offset
                    .checked_add(location.size)
                    .is_none_or(|end| end > archive_size)
                    || blobs.insert(digest, location).is_some()
                {
                    return Err(SyntheticOciImportError::InvalidArchive);
                }
            }
            _ => return Err(SyntheticOciImportError::InvalidArchive),
        }
    }
    let layout: OciLayout = serde_json::from_slice(
        layout
            .as_deref()
            .ok_or(SyntheticOciImportError::InvalidArchive)?,
    )
    .map_err(|_| SyntheticOciImportError::InvalidArchive)?;
    if layout.image_layout_version != "1.0.0" || blobs.is_empty() {
        return Err(SyntheticOciImportError::InvalidArchive);
    }
    Ok(LayoutInventory {
        index: index.ok_or(SyntheticOciImportError::InvalidArchive)?,
        blobs,
    })
}

async fn admit_archive_blob(
    store: &ContentStore,
    archive: &File,
    digest: &Sha256Digest,
    location: BlobLocation,
) -> Result<(), SyntheticOciImportError> {
    let mut source = archive.try_clone().map_err(SyntheticOciImportError::Io)?;
    source
        .seek(SeekFrom::Start(location.offset))
        .map_err(SyntheticOciImportError::Io)?;
    let stream = futures::stream::try_unfold(
        (tokio::fs::File::from_std(source), location.size),
        |(mut source, remaining)| async move {
            if remaining == 0 {
                return Ok::<_, io::Error>(None);
            }
            let capacity = usize::try_from(remaining.min(64 * 1024))
                .map_err(|_| io::Error::other("OCI archive blob chunk exceeds usize"))?;
            let mut buffer = vec![0_u8; capacity];
            let read = source.read(&mut buffer).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "OCI archive blob ended early",
                ));
            }
            buffer.truncate(read);
            let read = u64::try_from(read)
                .map_err(|_| io::Error::other("OCI archive read length exceeds u64"))?;
            Ok(Some((Bytes::from(buffer), (source, remaining - read))))
        },
    );
    store.admit_stream(digest, location.size, stream).await?;
    Ok(())
}

fn read_document(reader: &mut impl std::io::Read) -> Result<Vec<u8>, SyntheticOciImportError> {
    let mut bytes = Vec::new();
    reader
        .take(MAXIMUM_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(SyntheticOciImportError::Io)?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_DOCUMENT_BYTES {
        return Err(SyntheticOciImportError::InvalidArchive);
    }
    Ok(bytes)
}

fn blob_digest_from_path(name: &str) -> Result<Sha256Digest, SyntheticOciImportError> {
    let hex = name
        .strip_prefix("blobs/sha256/")
        .filter(|hex| !hex.contains('/') && hex.len() == 64)
        .ok_or(SyntheticOciImportError::InvalidArchive)?;
    Sha256Digest::parse(&format!("sha256:{hex}")).map_err(Into::into)
}

fn source_from_layout_index(
    bytes: &[u8],
    expected_digest: &Sha256Digest,
) -> Result<ResolvedDescriptor, SyntheticOciImportError> {
    let index =
        ImageIndex::from_reader(bytes).map_err(|_| SyntheticOciImportError::InvalidIndex)?;
    validate_layout_index(&index)?;
    if index.manifests().len() != 1 {
        return Err(SyntheticOciImportError::InvalidIndex);
    }
    let source = source_descriptor_from_oci(&index.manifests()[0])?;
    if &source.digest != expected_digest {
        return Err(SyntheticOciImportError::SourceDigestMismatch);
    }
    Ok(source)
}

fn require_exact_closure(
    inventory: &BTreeMap<Sha256Digest, BlobLocation>,
    image: &ResolvedImage,
) -> Result<(), SyntheticOciImportError> {
    let mut expected = BTreeMap::new();
    for descriptor in [&image.source, &image.manifest, &image.config] {
        insert_descriptor(&mut expected, descriptor)?;
    }
    for layer in &image.layers {
        insert_descriptor(&mut expected, &layer.descriptor)?;
    }
    if expected.len() != inventory.len()
        || expected.iter().any(|(digest, size)| {
            inventory
                .get(digest)
                .is_none_or(|location| location.size != *size)
        })
    {
        return Err(SyntheticOciImportError::UnexpectedClosure);
    }
    Ok(())
}

fn insert_descriptor(
    expected: &mut BTreeMap<Sha256Digest, u64>,
    descriptor: &ResolvedDescriptor,
) -> Result<(), SyntheticOciImportError> {
    if expected
        .insert(descriptor.digest.clone(), descriptor.size)
        .is_some_and(|size| size != descriptor.size)
    {
        return Err(SyntheticOciImportError::UnexpectedClosure);
    }
    Ok(())
}

fn publish_pin(engine: &PrivateRoot, image: &ResolvedImage) -> Result<(), SyntheticOciImportError> {
    if fs::symlink_metadata(engine.path().join(PIN_FILE)).is_ok() {
        return Err(SyntheticOciImportError::InvalidPin);
    }
    let bytes = serde_json::to_vec(&SyntheticImagePin {
        schema_version: 1,
        image: image.clone(),
    })
    .map_err(|_| SyntheticOciImportError::InvalidPin)?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_PIN_BYTES {
        return Err(SyntheticOciImportError::InvalidPin);
    }
    let temporary = format!(".synthetic-pin-{}", Uuid::new_v4());
    let opened = engine.create_regular(Path::new(&temporary), 0o400, true)?;
    let mut file = opened.into_file();
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = engine.remove_private_regular(Path::new(&temporary), 0o400);
        return Err(SyntheticOciImportError::Io(error));
    }
    drop(file);
    if !engine.publish_private_regular_no_replace(
        Path::new(&temporary),
        Path::new(PIN_FILE),
        0o400,
    )? {
        engine.remove_private_regular(Path::new(&temporary), 0o400)?;
        return Err(SyntheticOciImportError::InvalidPin);
    }
    Ok(())
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

#[cfg(test)]
pub(crate) async fn install_test_synthetic_image_pin(engine: &PrivateRoot) -> ResolvedImage {
    use oci_spec::image::MediaType;
    use serde_json::json;

    fn descriptor(media_type: MediaType, bytes: &[u8]) -> ResolvedDescriptor {
        ResolvedDescriptor {
            media_type: media_type.to_string(),
            digest: Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap(),
            size: bytes.len() as u64,
        }
    }

    let layer = b"supervisor synthetic pin layer";
    let layer_descriptor = descriptor(MediaType::ImageLayer, layer);
    let config = serde_json::to_vec(&json!({
        "architecture": OciArchitecture::native().unwrap().as_str(),
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_descriptor.digest.as_str()]},
    }))
    .unwrap();
    let config_descriptor = descriptor(MediaType::ImageConfig, &config);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": MediaType::ImageManifest.to_string(),
        "config": {
            "mediaType": config_descriptor.media_type.as_str(),
            "digest": config_descriptor.digest.as_str(),
            "size": config_descriptor.size,
        },
        "layers": [{
            "mediaType": layer_descriptor.media_type.as_str(),
            "digest": layer_descriptor.digest.as_str(),
            "size": layer_descriptor.size,
        }],
    }))
    .unwrap();
    let source = descriptor(MediaType::ImageManifest, &manifest);
    let source_reference = format!("{SYNTHETIC_REFERENCE_PREFIX}{}", source.digest);
    let store = ContentStore::create(engine).unwrap();
    for (descriptor, bytes) in [
        (&source, manifest.as_slice()),
        (&config_descriptor, config.as_slice()),
        (&layer_descriptor, layer.as_slice()),
    ] {
        store
            .admit_bytes(&descriptor.digest, Bytes::copy_from_slice(bytes))
            .await
            .unwrap();
    }
    let image = ResolvedImage::from_cached_source(
        source_reference,
        OciArchitecture::native().unwrap(),
        source,
        &store,
    )
    .unwrap();
    publish_pin(engine, &image).unwrap();
    image
}

#[derive(Debug, thiserror::Error)]
pub enum SyntheticOciImportError {
    #[error("synthetic OCI input is invalid")]
    InvalidInput,
    #[error("synthetic OCI archive is unsafe")]
    UnsafeArchive,
    #[error("synthetic OCI archive digest does not match")]
    ArchiveDigestMismatch,
    #[error("synthetic OCI archive is invalid")]
    InvalidArchive,
    #[error("synthetic OCI archive contains too many objects")]
    ArchiveObjectLimit,
    #[error("synthetic OCI layout index is invalid")]
    InvalidIndex,
    #[error("synthetic OCI source digest does not match")]
    SourceDigestMismatch,
    #[error("synthetic OCI archive has an unexpected content closure")]
    UnexpectedClosure,
    #[error("synthetic OCI state root is not fresh")]
    StateRootNotFresh,
    #[error("synthetic OCI pin is invalid")]
    InvalidPin,
    #[error("synthetic OCI filesystem I/O failed")]
    Io(#[source] io::Error),
    #[error(transparent)]
    Registry(#[from] RegistryResolverError),
    #[error(transparent)]
    Content(#[from] ContentStoreError),
    #[error(transparent)]
    Reference(#[from] super::RegistryReferenceError),
    #[error(transparent)]
    Path(#[from] PathError),
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use oci_spec::image::MediaType;
    use serde_json::json;

    use super::*;

    struct Fixture {
        archive: PathBuf,
        archive_sha256: String,
        archive_size: u64,
        source_digest: String,
    }

    fn private_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn descriptor(media_type: &str, bytes: &[u8]) -> serde_json::Value {
        json!({
            "mediaType": media_type,
            "digest": digest(bytes),
            "size": bytes.len(),
        })
    }

    fn append(builder: &mut tar::Builder<File>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::file());
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn fixture(
        parent: &Path,
        indexed_source: bool,
        wrong_architecture: bool,
        corrupt_layer: bool,
        extra_blob: bool,
    ) -> Fixture {
        let layer = b"synthetic-layer";
        let layer_digest = digest(layer);
        let native_architecture = OciArchitecture::native().unwrap();
        let architecture = if wrong_architecture {
            match native_architecture {
                OciArchitecture::Amd64 => OciArchitecture::Arm64,
                OciArchitecture::Arm64 => OciArchitecture::Amd64,
            }
        } else {
            native_architecture
        };
        let config = serde_json::to_vec(&json!({
            "architecture": architecture.as_str(),
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": MediaType::ImageManifest.to_string(),
            "config": descriptor(MediaType::ImageConfig.as_ref(), &config),
            "layers": [descriptor(MediaType::ImageLayer.as_ref(), layer)],
        }))
        .unwrap();
        let source_index = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": MediaType::ImageIndex.to_string(),
            "manifests": [{
                "mediaType": MediaType::ImageManifest.to_string(),
                "digest": digest(&manifest),
                "size": manifest.len(),
                "platform": {
                    "architecture": native_architecture.as_str(),
                    "os": "linux",
                },
            }],
        }))
        .unwrap();
        let (source_media_type, source) = if indexed_source {
            (MediaType::ImageIndex, source_index.as_slice())
        } else {
            (MediaType::ImageManifest, manifest.as_slice())
        };
        let source_digest = digest(source);
        let index = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": MediaType::ImageIndex.to_string(),
            "manifests": [descriptor(source_media_type.as_ref(), source)],
        }))
        .unwrap();
        let archive = parent.join("workspace.oci.tar");
        let file = File::create(&archive).unwrap();
        let mut builder = tar::Builder::new(file);
        append(
            &mut builder,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        append(&mut builder, "index.json", &index);
        append(
            &mut builder,
            &format!("blobs/sha256/{}", &digest(&manifest)[7..]),
            &manifest,
        );
        if indexed_source {
            append(
                &mut builder,
                &format!("blobs/sha256/{}", &source_digest[7..]),
                &source_index,
            );
        }
        append(
            &mut builder,
            &format!("blobs/sha256/{}", &digest(&config)[7..]),
            &config,
        );
        append(
            &mut builder,
            &format!("blobs/sha256/{}", &digest(layer)[7..]),
            if corrupt_layer {
                b"corrupt-layer".as_slice()
            } else {
                layer.as_slice()
            },
        );
        if extra_blob {
            let extra = b"unexpected";
            append(
                &mut builder,
                &format!("blobs/sha256/{}", &digest(extra)[7..]),
                extra,
            );
        }
        builder.finish().unwrap();
        drop(builder);
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o400)).unwrap();
        let bytes = fs::read(&archive).unwrap();
        Fixture {
            archive,
            archive_sha256: format!("{:x}", Sha256::digest(&bytes)),
            archive_size: bytes.len() as u64,
            source_digest,
        }
    }

    fn input(fixture: &Fixture, state_root: PathBuf) -> SyntheticOciArchiveInput {
        SyntheticOciArchiveInput {
            archive: fixture.archive.clone(),
            archive_sha256: fixture.archive_sha256.clone(),
            archive_size: fixture.archive_size,
            source_digest: fixture.source_digest.clone(),
            state_root,
        }
    }

    #[tokio::test]
    async fn exact_layout_imports_and_publishes_a_verified_pin() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, false, false);
        let state_root = parent.path().join("state");
        let reference = import_synthetic_oci_archive(input(&fixture, state_root.clone()))
            .await
            .unwrap();
        assert_eq!(
            reference,
            format!("{SYNTHETIC_REFERENCE_PREFIX}{}", fixture.source_digest)
        );
        let root = PrivateRoot::open(&state_root).unwrap();
        let engine = root
            .open_private_directory(Path::new("engine"), 0o700)
            .unwrap();
        let store = ContentStore::create(&engine).unwrap();
        let pin = load_synthetic_image_pin(&engine, &store).unwrap().unwrap();
        assert_eq!(pin.source_reference, reference);
        pin.verify_cached(&store).unwrap();
    }

    #[tokio::test]
    async fn existing_empty_private_state_root_is_accepted() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, false, false);
        let state_root = parent.path().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();

        let reference = import_synthetic_oci_archive(input(&fixture, state_root.clone()))
            .await
            .unwrap();

        assert_eq!(
            reference,
            format!("{SYNTHETIC_REFERENCE_PREFIX}{}", fixture.source_digest)
        );
        assert!(state_root.join("engine").join(PIN_FILE).is_file());
    }

    #[tokio::test]
    async fn occupied_state_root_is_rejected_without_changing_it() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, false, false);
        let state_root = parent.path().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(state_root.join("existing"), b"unchanged").unwrap();

        assert!(matches!(
            import_synthetic_oci_archive(input(&fixture, state_root.clone())).await,
            Err(SyntheticOciImportError::StateRootNotFresh)
        ));
        assert_eq!(fs::read(state_root.join("existing")).unwrap(), b"unchanged");
        assert!(!state_root.join("engine").exists());
    }

    #[tokio::test]
    async fn corrupt_late_blob_never_publishes_a_pin_or_partial_content() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, true, false);
        let state_root = parent.path().join("state");
        assert!(
            import_synthetic_oci_archive(input(&fixture, state_root.clone()))
                .await
                .is_err()
        );
        let root = PrivateRoot::open(&state_root).unwrap();
        let engine = root
            .open_private_directory(Path::new("engine"), 0o700)
            .unwrap();
        assert!(!engine.path().join(PIN_FILE).exists());
        let store = ContentStore::create(&engine).unwrap();
        assert!(
            store
                .collect_unreferenced(&BTreeMap::new())
                .unwrap()
                .removed_blobs
                .is_empty()
        );
    }

    #[tokio::test]
    async fn layout_with_unreachable_blob_fails_closed_without_a_pin() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, false, true);
        let state_root = parent.path().join("state");
        assert!(matches!(
            import_synthetic_oci_archive(input(&fixture, state_root.clone())).await,
            Err(SyntheticOciImportError::UnexpectedClosure)
        ));
        assert!(!state_root.join("engine").join(PIN_FILE).exists());
    }

    #[tokio::test]
    async fn indexed_source_selects_the_exact_native_manifest() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), true, false, false, false);
        let state_root = parent.path().join("state");

        let reference = import_synthetic_oci_archive(input(&fixture, state_root))
            .await
            .unwrap();

        assert_eq!(
            reference,
            format!("{SYNTHETIC_REFERENCE_PREFIX}{}", fixture.source_digest)
        );
    }

    #[tokio::test]
    async fn wrong_configuration_architecture_fails_without_a_pin() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, true, false, false);
        let state_root = parent.path().join("state");

        assert!(matches!(
            import_synthetic_oci_archive(input(&fixture, state_root.clone())).await,
            Err(SyntheticOciImportError::Registry(
                RegistryResolverError::UnsupportedPlatform
            ))
        ));
        assert!(!state_root.join("engine").join(PIN_FILE).exists());
    }

    #[tokio::test]
    async fn archive_symlink_is_never_admitted() {
        let parent = private_tempdir();
        let fixture = fixture(parent.path(), false, false, false, false);
        let link = parent.path().join("workspace-link.oci.tar");
        symlink(&fixture.archive, &link).unwrap();
        let mut input = input(&fixture, parent.path().join("state"));
        input.archive = link;

        assert!(import_synthetic_oci_archive(input).await.is_err());
        assert!(!parent.path().join("state").exists());
    }

    #[tokio::test]
    async fn archive_fifo_is_rejected_without_waiting_for_a_writer() {
        let parent = private_tempdir();
        let fifo = parent.path().join("workspace.oci.tar");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o400) }, 0);
        let input = SyntheticOciArchiveInput {
            archive: fifo,
            archive_sha256: "a".repeat(64),
            archive_size: 1,
            source_digest: format!("sha256:{}", "b".repeat(64)),
            state_root: parent.path().join("state"),
        };

        assert!(import_synthetic_oci_archive(input).await.is_err());
        assert!(!parent.path().join("state").exists());
    }

    #[tokio::test]
    async fn archive_wrapper_bound_is_checked_before_opening_a_path() {
        let input = SyntheticOciArchiveInput {
            archive: PathBuf::from("/does/not/exist"),
            archive_sha256: "a".repeat(64),
            archive_size: MAXIMUM_ARCHIVE_BYTES + 1,
            source_digest: format!("sha256:{}", "b".repeat(64)),
            state_root: PathBuf::from("/does/not/exist-state"),
        };

        assert!(matches!(
            import_synthetic_oci_archive(input).await,
            Err(SyntheticOciImportError::InvalidInput)
        ));
    }
}
