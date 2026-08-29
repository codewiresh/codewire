//! Host-only OCI Distribution resolution and digest-addressed content.
//!
//! This boundary never extracts image layers. Registry authentication and
//! descriptor selection happen here; only verified, credential-free content
//! is admitted to the owner-private CAS for later guest-side revalidation.

mod cas;
mod reference;
mod registry;

pub use cas::{BlobAdmission, ContentStore, ContentStoreError};
pub use reference::{RegistryReference, RegistryReferenceError, Sha256Digest};
pub use registry::{
    OciArchitecture, RegistryResolver, RegistryResolverError, ResolvedDescriptor, ResolvedImage,
    ResolvedLayer,
};
