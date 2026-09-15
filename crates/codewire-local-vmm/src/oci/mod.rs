//! Host-only OCI Distribution resolution and digest-addressed content.
//!
//! This boundary never extracts image layers. Registry authentication and
//! descriptor selection happen here; only verified, credential-free content
//! is admitted to the owner-private CAS for later guest-side revalidation.

#[cfg(target_os = "linux")]
mod cas;
#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
mod layout;
#[cfg(target_os = "linux")]
mod registry;

pub use crate::supervisor_metadata::oci::{OciArchitecture, ResolvedImage};
#[cfg(any(target_os = "linux", test))]
pub use crate::supervisor_metadata::oci::{
    RegistryReference, RegistryReferenceError, RegistryResolverError, ResolvedDescriptor,
    ResolvedLayer, Sha256Digest,
};
#[cfg(target_os = "linux")]
pub use cas::{BlobAdmission, ContentStore, ContentStoreError};
#[cfg(all(test, target_os = "linux", feature = "synthetic-oci-input-smoke"))]
pub(crate) use layout::install_test_synthetic_image_pin;
#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
pub(crate) use layout::load_synthetic_image_pin;
#[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
pub use layout::{SyntheticOciArchiveInput, SyntheticOciImportError, import_synthetic_oci_archive};
#[cfg(target_os = "linux")]
pub use registry::RegistryResolver;
