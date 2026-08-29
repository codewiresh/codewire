//! Guest-side verification of credential-free OCI setup-pack contents.
//!
//! The host verifies registry content before constructing a setup pack, but it
//! is not the root-filesystem mutation boundary. Trusted guest init therefore
//! rereads every exact object range, requires canonical zero padding, verifies
//! the compressed descriptor digest, and independently streams the complete
//! uncompressed diff ID before any layer entry may be applied.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use flate2::read::MultiGzDecoder;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::setup_archive::{ArchiveError, TarImageBudget, VerifiedLayerPlan, scan_tar};
use crate::{LayerEncoding, SETUP_HEADER_LEN, SetupHeader, SetupLayer, SetupObject, Sha256Value};

const BUFFER_BYTES: usize = 64 * 1024;
const MAX_UNCOMPRESSED_LAYER_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_UNCOMPRESSED_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSetupContents {
    pub project_bytes: u64,
    pub config_bytes: u64,
    pub layer_uncompressed_bytes: Vec<u64>,
    pub total_uncompressed_bytes: u64,
    pub layer_plans: Vec<VerifiedLayerPlan>,
}

impl fmt::Debug for VerifiedSetupContents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSetupContents")
            .field("project_bytes", &self.project_bytes)
            .field("config_bytes", &self.config_bytes)
            .field("layer_uncompressed_bytes", &self.layer_uncompressed_bytes)
            .field("total_uncompressed_bytes", &self.total_uncompressed_bytes)
            .field("layer_plans", &self.layer_plans)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct VerificationLimits {
    layer_uncompressed_bytes: u64,
    image_uncompressed_bytes: u64,
}

impl VerificationLimits {
    const PRODUCTION: Self = Self {
        layer_uncompressed_bytes: MAX_UNCOMPRESSED_LAYER_BYTES,
        image_uncompressed_bytes: MAX_UNCOMPRESSED_IMAGE_BYTES,
    };
}

pub(crate) fn verify_setup_contents(
    input: &mut (impl Read + Seek),
    header: &SetupHeader,
) -> Result<VerifiedSetupContents, SetupContentError> {
    verify_setup_contents_with_limits(input, header, VerificationLimits::PRODUCTION)
}

fn verify_setup_contents_with_limits(
    input: &mut (impl Read + Seek),
    header: &SetupHeader,
    limits: VerificationLimits,
) -> Result<VerifiedSetupContents, SetupContentError> {
    if limits.layer_uncompressed_bytes == 0
        || limits.image_uncompressed_bytes == 0
        || input
            .seek(SeekFrom::End(0))
            .map_err(SetupContentError::Read)?
            != header.total_bytes
    {
        return Err(SetupContentError::InvalidFraming);
    }

    verify_zero_range(input, SETUP_HEADER_LEN as u64, header.project.offset)?;
    verify_object(input, header.project)?;
    let mut previous_end = object_end(header.project)?;
    verify_zero_range(input, previous_end, header.config.offset)?;
    verify_object(input, header.config)?;
    previous_end = object_end(header.config)?;

    let mut layer_uncompressed_bytes = Vec::with_capacity(header.layers.len());
    let mut layer_plans = Vec::with_capacity(header.layers.len());
    let mut tar_budget = TarImageBudget::default();
    let mut total_uncompressed_bytes = 0_u64;
    for layer in &header.layers {
        verify_zero_range(input, previous_end, layer.object.offset)?;
        // This first pass is deliberately independent of decompression. A
        // decoder cannot redefine which exact compressed bytes were admitted.
        verify_object(input, layer.object)?;
        let (layer_bytes, layer_plan) = verify_layer_diff_id(
            input,
            layer,
            total_uncompressed_bytes,
            limits,
            &mut tar_budget,
        )?;
        total_uncompressed_bytes = total_uncompressed_bytes
            .checked_add(layer_bytes)
            .filter(|total| *total <= limits.image_uncompressed_bytes)
            .ok_or(SetupContentError::ImageExpansionLimit)?;
        layer_uncompressed_bytes.push(layer_bytes);
        layer_plans.push(layer_plan);
        previous_end = object_end(layer.object)?;
    }
    verify_zero_range(input, previous_end, header.total_bytes)?;

    Ok(VerifiedSetupContents {
        project_bytes: header.project.size,
        config_bytes: header.config.size,
        layer_uncompressed_bytes,
        total_uncompressed_bytes,
        layer_plans,
    })
}

fn verify_object(
    input: &mut (impl Read + Seek),
    object: SetupObject,
) -> Result<(), SetupContentError> {
    input
        .seek(SeekFrom::Start(object.offset))
        .map_err(SetupContentError::Read)?;
    let mut range = input.take(object.size);
    let actual = hash_exact(&mut range, object.size)?;
    if range.limit() != 0 {
        return Err(SetupContentError::TruncatedObject);
    }
    if actual != object.sha256 {
        return Err(SetupContentError::ObjectDigestMismatch);
    }
    Ok(())
}

fn verify_layer_diff_id(
    input: &mut (impl Read + Seek),
    layer: &SetupLayer,
    current_total: u64,
    limits: VerificationLimits,
    tar_budget: &mut TarImageBudget,
) -> Result<(u64, VerifiedLayerPlan), SetupContentError> {
    let remaining_image = limits
        .image_uncompressed_bytes
        .checked_sub(current_total)
        .ok_or(SetupContentError::ImageExpansionLimit)?;
    let output_limit = limits.layer_uncompressed_bytes.min(remaining_image);
    let image_is_tighter = remaining_image <= limits.layer_uncompressed_bytes;
    if output_limit == 0 {
        return Err(SetupContentError::ImageExpansionLimit);
    }

    input
        .seek(SeekFrom::Start(layer.object.offset))
        .map_err(SetupContentError::Read)?;
    let mut range = input.take(layer.object.size);
    let scanned = match layer.encoding {
        LayerEncoding::Tar => scan_tar(&mut range, output_limit, tar_budget),
        LayerEncoding::Gzip => {
            let mut decoder = MultiGzDecoder::new(range);
            let outcome = scan_tar(&mut decoder, output_limit, tar_budget);
            range = decoder.into_inner();
            outcome
        }
        LayerEncoding::Zstd => return Err(SetupContentError::UnsupportedLayerEncoding),
    };
    let scanned = match scanned {
        Ok(scanned) => scanned,
        Err(ArchiveError::ExpansionLimit) if image_is_tighter => {
            return Err(SetupContentError::ImageExpansionLimit);
        }
        Err(ArchiveError::ExpansionLimit) => return Err(SetupContentError::LayerExpansionLimit),
        Err(error) => return Err(SetupContentError::Archive(error)),
    };
    if range.limit() != 0 {
        return Err(SetupContentError::TruncatedObject);
    }
    if scanned.digest != layer.diff_id {
        return Err(SetupContentError::LayerDiffIdMismatch);
    }
    Ok((scanned.bytes, scanned.plan))
}

fn hash_exact(input: &mut impl Read, bytes: u64) -> Result<Sha256Value, SetupContentError> {
    let mut remaining = bytes;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; BUFFER_BYTES];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded setup read always fits usize");
        let read = input
            .read(&mut buffer[..count])
            .map_err(SetupContentError::Read)?;
        if read == 0 {
            return Err(SetupContentError::TruncatedObject);
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(Sha256Value::from_bytes(digest.finalize().into()))
}

fn verify_zero_range(
    input: &mut (impl Read + Seek),
    start: u64,
    end: u64,
) -> Result<(), SetupContentError> {
    let bytes = end
        .checked_sub(start)
        .ok_or(SetupContentError::InvalidFraming)?;
    input
        .seek(SeekFrom::Start(start))
        .map_err(SetupContentError::Read)?;
    let mut remaining = bytes;
    let mut buffer = [0_u8; 4096];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded setup padding read always fits usize");
        input
            .read_exact(&mut buffer[..count])
            .map_err(SetupContentError::Read)?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(SetupContentError::NonZeroPadding);
        }
        remaining -= count as u64;
    }
    Ok(())
}

fn object_end(object: SetupObject) -> Result<u64, SetupContentError> {
    object
        .offset
        .checked_add(object.size)
        .ok_or(SetupContentError::InvalidFraming)
}

#[derive(Debug, Error)]
pub(crate) enum SetupContentError {
    #[error("setup pack framing differs from its verified header")]
    InvalidFraming,
    #[error("setup pack contains nonzero alignment padding")]
    NonZeroPadding,
    #[error("setup object ended before its descriptor size")]
    TruncatedObject,
    #[error("setup object digest differs from its descriptor")]
    ObjectDigestMismatch,
    #[error("setup layer diff ID differs from its image configuration")]
    LayerDiffIdMismatch,
    #[error("setup layer exceeds the uncompressed per-layer limit")]
    LayerExpansionLimit,
    #[error("setup image exceeds the total uncompressed limit")]
    ImageExpansionLimit,
    #[error("setup layer encoding is not supported by this guest ABI")]
    UnsupportedLayerEncoding,
    #[error(transparent)]
    Archive(ArchiveError),
    #[error("read setup object: {0}")]
    Read(io::Error),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write as _};

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::{SetupArchitecture, SetupBlob, SetupLayerBlob, oci_root_generation};

    struct LayerFixture {
        encoding: LayerEncoding,
        compressed: Vec<u8>,
        diff_id: Sha256Value,
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_file(path: &str, contents: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_path(path).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append(&header, contents).unwrap();
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn fixture(layers: Vec<LayerFixture>) -> (SetupHeader, Vec<u8>) {
        let project = br#"{"image":"example.invalid/workspace"}"#;
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let project_digest = Sha256Value::calculate(project);
        let manifest_digest = Sha256Value::calculate(b"manifest");
        let layer_blobs = layers
            .iter()
            .map(|layer| SetupLayerBlob {
                blob: SetupBlob {
                    size: layer.compressed.len() as u64,
                    sha256: Sha256Value::calculate(&layer.compressed),
                },
                diff_id: layer.diff_id,
                encoding: layer.encoding,
            })
            .collect();
        let header = SetupHeader::layout(
            oci_root_generation(project_digest, manifest_digest, SetupArchitecture::Amd64),
            manifest_digest,
            SetupArchitecture::Amd64,
            SetupBlob {
                size: project.len() as u64,
                sha256: project_digest,
            },
            SetupBlob {
                size: config.len() as u64,
                sha256: Sha256Value::calculate(config),
            },
            layer_blobs,
        )
        .unwrap();
        let mut pack = vec![0_u8; header.total_bytes as usize];
        pack[..SETUP_HEADER_LEN].copy_from_slice(&header.encode().unwrap());
        copy_object(&mut pack, header.project, project);
        copy_object(&mut pack, header.config, config);
        for (layer, descriptor) in layers.iter().zip(&header.layers) {
            copy_object(&mut pack, descriptor.object, &layer.compressed);
        }
        (header, pack)
    }

    fn copy_object(pack: &mut [u8], object: SetupObject, bytes: &[u8]) {
        let start = object.offset as usize;
        let end = start + object.size as usize;
        pack[start..end].copy_from_slice(bytes);
    }

    #[test]
    fn verifies_exact_objects_padding_and_independent_diff_ids() {
        let tar = tar_file("plain", b"plain uncompressed tar bytes");
        let gzip_contents = tar_file("gzip", b"gzip uncompressed tar bytes");
        let split = gzip_contents.len() / 2;
        let mut concatenated_gzip = gzip(&gzip_contents[..split]);
        concatenated_gzip.extend_from_slice(&gzip(&gzip_contents[split..]));
        let (header, pack) = fixture(vec![
            LayerFixture {
                encoding: LayerEncoding::Tar,
                compressed: tar.clone(),
                diff_id: Sha256Value::calculate(&tar),
            },
            LayerFixture {
                encoding: LayerEncoding::Gzip,
                compressed: concatenated_gzip,
                diff_id: Sha256Value::calculate(&gzip_contents),
            },
        ]);
        let summary = verify_setup_contents(&mut Cursor::new(pack), &header).unwrap();
        assert_eq!(
            summary.layer_uncompressed_bytes,
            vec![tar.len() as u64, gzip_contents.len() as u64]
        );
        assert_eq!(
            summary.total_uncompressed_bytes,
            (tar.len() + gzip_contents.len()) as u64
        );
        assert_eq!(summary.layer_plans[0].entries(), 1);
        assert_eq!(summary.layer_plans[1].entries(), 1);
        assert!(!format!("{summary:?}").contains("uncompressed tar bytes"));
    }

    #[test]
    fn rejects_object_diff_id_padding_and_device_corruption() {
        let contents = tar_file("verified", b"verified layer");
        let (header, pack) = fixture(vec![LayerFixture {
            encoding: LayerEncoding::Tar,
            compressed: contents.clone(),
            diff_id: Sha256Value::calculate(&contents),
        }]);

        let mut corrupt_object = pack.clone();
        corrupt_object[header.config.offset as usize] ^= 1;
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(corrupt_object), &header),
            Err(SetupContentError::ObjectDigestMismatch)
        ));

        let mut corrupt_layer = pack.clone();
        corrupt_layer[header.layers[0].object.offset as usize] ^= 1;
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(corrupt_layer), &header),
            Err(SetupContentError::ObjectDigestMismatch)
        ));

        let mut corrupt_padding = pack.clone();
        corrupt_padding[(header.project.offset + header.project.size) as usize] = 1;
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(corrupt_padding), &header),
            Err(SetupContentError::NonZeroPadding)
        ));

        let (wrong_diff_header, wrong_diff_pack) = fixture(vec![LayerFixture {
            encoding: LayerEncoding::Tar,
            compressed: contents,
            diff_id: Sha256Value::calculate(b"different uncompressed bytes"),
        }]);
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(wrong_diff_pack), &wrong_diff_header),
            Err(SetupContentError::LayerDiffIdMismatch)
        ));

        let mut truncated = pack;
        truncated.pop();
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(truncated), &header),
            Err(SetupContentError::InvalidFraming)
        ));
    }

    #[test]
    fn rejects_invalid_gzip_trailing_data_and_unsupported_zstd() {
        let contents = tar_file("gzip", b"gzip payload");
        let mut trailing = gzip(&contents);
        trailing.extend_from_slice(b"not another gzip member");
        let (header, pack) = fixture(vec![LayerFixture {
            encoding: LayerEncoding::Gzip,
            compressed: trailing,
            diff_id: Sha256Value::calculate(&contents),
        }]);
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(pack), &header),
            Err(SetupContentError::Archive(ArchiveError::InvalidTar))
        ));

        let compressed = b"zstd-shaped but deliberately unsupported".to_vec();
        let (header, pack) = fixture(vec![LayerFixture {
            encoding: LayerEncoding::Zstd,
            compressed,
            diff_id: Sha256Value::calculate(b"uncompressed"),
        }]);
        assert!(matches!(
            verify_setup_contents(&mut Cursor::new(pack), &header),
            Err(SetupContentError::UnsupportedLayerEncoding)
        ));
    }

    #[test]
    fn expansion_limits_fail_before_unbounded_output_is_consumed() {
        let expanded = tar_file("expanded", &vec![0_u8; 2048]);
        let (header, pack) = fixture(vec![LayerFixture {
            encoding: LayerEncoding::Gzip,
            compressed: gzip(&expanded),
            diff_id: Sha256Value::calculate(&expanded),
        }]);
        assert!(matches!(
            verify_setup_contents_with_limits(
                &mut Cursor::new(pack),
                &header,
                VerificationLimits {
                    layer_uncompressed_bytes: 1024,
                    image_uncompressed_bytes: 4096,
                },
            ),
            Err(SetupContentError::LayerExpansionLimit)
        ));

        let first = tar_file("first", &vec![1_u8; 700]);
        let second = tar_file("second", &vec![2_u8; 700]);
        let (header, pack) = fixture(vec![
            LayerFixture {
                encoding: LayerEncoding::Tar,
                compressed: first.clone(),
                diff_id: Sha256Value::calculate(&first),
            },
            LayerFixture {
                encoding: LayerEncoding::Tar,
                compressed: second.clone(),
                diff_id: Sha256Value::calculate(&second),
            },
        ]);
        assert!(matches!(
            verify_setup_contents_with_limits(
                &mut Cursor::new(pack),
                &header,
                VerificationLimits {
                    layer_uncompressed_bytes: 16 * 1024,
                    image_uncompressed_bytes: first.len() as u64 + second.len() as u64 / 2,
                },
            ),
            Err(SetupContentError::ImageExpansionLimit)
        ));
    }
}
