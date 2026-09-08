//! Host-only OCI Distribution resolution and digest-addressed content.
//!
//! This boundary never extracts image layers. Registry authentication and
//! descriptor selection happen here; only verified, credential-free content
//! is admitted to the owner-private CAS for later guest-side revalidation.

mod cas;
#[cfg(feature = "synthetic-oci-input-smoke")]
mod layout;
mod reference;
mod registry;

pub use cas::{BlobAdmission, ContentStore, ContentStoreError};
#[cfg(all(test, feature = "synthetic-oci-input-smoke"))]
pub(crate) use layout::install_test_synthetic_image_pin;
#[cfg(feature = "synthetic-oci-input-smoke")]
pub(crate) use layout::load_synthetic_image_pin;
#[cfg(feature = "synthetic-oci-input-smoke")]
pub use layout::{SyntheticOciArchiveInput, SyntheticOciImportError, import_synthetic_oci_archive};
pub use reference::{RegistryReference, RegistryReferenceError, Sha256Digest};
pub use registry::{
    OciArchitecture, RegistryResolver, RegistryResolverError, ResolvedDescriptor, ResolvedImage,
    ResolvedLayer,
};
