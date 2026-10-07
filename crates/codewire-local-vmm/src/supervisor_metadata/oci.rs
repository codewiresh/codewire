//! Pure OCI references and resolved descriptor metadata retained by supervisor state.

use serde::{Deserialize, Serialize};

mod reference {
    include!("../oci/reference.rs");
}

pub use reference::{RegistryReference, RegistryReferenceError, Sha256Digest};

pub(crate) const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub(crate) const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub(crate) const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub(crate) const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
pub(crate) const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub(crate) const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub(crate) const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub(crate) const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub(crate) const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
pub(crate) const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
pub(crate) const MAXIMUM_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAXIMUM_LAYERS: usize = 128;
pub(crate) const MAXIMUM_TOTAL_LAYER_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OciArchitecture {
    Amd64,
    Arm64,
}

impl OciArchitecture {
    pub fn native() -> Result<Self, RegistryResolverError> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::Amd64),
            "aarch64" => Ok(Self::Arm64),
            _ => Err(RegistryResolverError::UnsupportedHostArchitecture),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    pub(crate) fn admits_variant(self, variant: Option<&str>) -> bool {
        match self {
            Self::Amd64 => variant.is_none(),
            Self::Arm64 => variant.is_none() || variant == Some("v8"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDescriptor {
    pub media_type: String,
    pub digest: Sha256Digest,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedLayer {
    pub descriptor: ResolvedDescriptor,
    pub diff_id: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedImage {
    pub source_reference: String,
    pub architecture: OciArchitecture,
    pub source: ResolvedDescriptor,
    pub manifest: ResolvedDescriptor,
    pub config: ResolvedDescriptor,
    pub layers: Vec<ResolvedLayer>,
}

impl ResolvedImage {
    pub(crate) fn validate_metadata(&self) -> Result<(), RegistryResolverError> {
        let reference = RegistryReference::parse(&self.source_reference)?;
        validate_resolved_descriptor(&self.source, DescriptorKind::Source)?;
        validate_resolved_descriptor(&self.manifest, DescriptorKind::Manifest)?;
        validate_resolved_descriptor(&self.config, DescriptorKind::Config)?;
        if self.layers.len() > MAXIMUM_LAYERS {
            return Err(RegistryResolverError::InvalidManifest);
        }
        if reference
            .digest()
            .is_some_and(|digest| digest != &self.source.digest)
        {
            return Err(RegistryResolverError::DigestMismatch);
        }
        if !is_index_media_type(&self.source.media_type) && self.source != self.manifest {
            return Err(RegistryResolverError::DescriptorMismatch);
        }
        let mut total = 0_u64;
        for layer in &self.layers {
            validate_resolved_descriptor(&layer.descriptor, DescriptorKind::Layer)?;
            Sha256Digest::parse(layer.diff_id.as_str())?;
            total = total
                .checked_add(layer.descriptor.size)
                .ok_or(RegistryResolverError::ImageTooLarge)?;
            if total > MAXIMUM_TOTAL_LAYER_BYTES {
                return Err(RegistryResolverError::ImageTooLarge);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DescriptorKind {
    Source,
    Manifest,
    Config,
    Layer,
}

pub(crate) fn validate_resolved_descriptor(
    descriptor: &ResolvedDescriptor,
    kind: DescriptorKind,
) -> Result<(), RegistryResolverError> {
    let media_valid = match kind {
        DescriptorKind::Source => {
            is_manifest_media_type(&descriptor.media_type)
                || is_index_media_type(&descriptor.media_type)
        }
        DescriptorKind::Manifest => is_manifest_media_type(&descriptor.media_type),
        DescriptorKind::Config => {
            matches!(descriptor.media_type.as_str(), OCI_CONFIG | DOCKER_CONFIG)
        }
        DescriptorKind::Layer => matches!(
            descriptor.media_type.as_str(),
            OCI_LAYER | OCI_LAYER_GZIP | OCI_LAYER_ZSTD | DOCKER_LAYER_GZIP
        ),
    };
    let maximum = match kind {
        DescriptorKind::Source | DescriptorKind::Manifest | DescriptorKind::Config => {
            MAXIMUM_DOCUMENT_BYTES
        }
        DescriptorKind::Layer => MAXIMUM_TOTAL_LAYER_BYTES,
    };
    if !media_valid || descriptor.size > maximum {
        return Err(RegistryResolverError::InvalidDescriptor);
    }
    Sha256Digest::parse(descriptor.digest.as_str())?;
    Ok(())
}

pub(crate) fn is_index_media_type(media_type: &str) -> bool {
    matches!(media_type, OCI_INDEX | DOCKER_INDEX)
}

pub(crate) fn is_manifest_media_type(media_type: &str) -> bool {
    matches!(media_type, OCI_MANIFEST | DOCKER_MANIFEST)
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryResolverError {
    #[error("this host architecture is not supported by the native OCI resolver")]
    UnsupportedHostArchitecture,
    #[error("construct native OCI registry client failed")]
    Client,
    #[error("OCI registry transport failed")]
    Transport,
    #[error("OCI registry URL is unsafe")]
    UnsafeUrl,
    #[error("OCI registry redirect is unsafe")]
    UnsafeRedirect,
    #[error("OCI registry redirect limit exceeded")]
    TooManyRedirects,
    #[error("OCI registry authentication is required")]
    AuthenticationRequired,
    #[error("OCI registry authentication failed")]
    AuthenticationFailed,
    #[error("OCI registry object was not found")]
    NotFound,
    #[error("OCI registry returned an unsupported response")]
    RegistryResponse,
    #[error("OCI document exceeds its size bound")]
    DocumentTooLarge,
    #[error("OCI object digest does not match its descriptor")]
    DigestMismatch,
    #[error("OCI object does not match its descriptor")]
    DescriptorMismatch,
    #[error("OCI media type is unsupported")]
    UnsupportedMediaType,
    #[error("OCI digest algorithm is unsupported")]
    UnsupportedDigest,
    #[error("OCI descriptor is invalid")]
    InvalidDescriptor,
    #[error("OCI image index is invalid")]
    InvalidIndex,
    #[error("OCI image manifest is invalid")]
    InvalidManifest,
    #[error("OCI image configuration is invalid")]
    InvalidConfiguration,
    #[cfg_attr(
        not(target_os = "macos"),
        error("OCI image does not contain the required native Linux platform")
    )]
    #[cfg_attr(
        target_os = "macos",
        error(
            "OCI image has no linux/arm64 image; macOS local environments run arm64 Linux, so choose a multi-architecture or arm64 image"
        )
    )]
    PlatformUnavailable,
    #[error("OCI image contains more than one matching native Linux platform")]
    AmbiguousPlatform,
    #[cfg_attr(not(target_os = "macos"), error("OCI image platform is unsupported"))]
    #[cfg_attr(
        target_os = "macos",
        error(
            "OCI image is not a linux/arm64 image; macOS local environments run arm64 Linux, so choose a multi-architecture or arm64 image"
        )
    )]
    UnsupportedPlatform,
    #[error("OCI image exceeds the local compressed-content bound")]
    ImageTooLarge,
    #[error(transparent)]
    Reference(#[from] RegistryReferenceError),
    #[error(transparent)]
    Content(#[from] crate::oci::ContentStoreError),
}
