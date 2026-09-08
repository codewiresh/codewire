//! Original-owner OAuth authority for platform sources used by a local runtime.
//!
//! The trusted host asserts the exact local environment operation and selected
//! platform sources; this is not VM attestation. Provider operations remain in
//! the isolated platform broker. Constructing an authority mounts no listener.

mod authority;
mod wire;

pub use authority::{OwnerLocalRuntimeAuthority, OwnerLocalSelection};
pub(crate) use wire::router;
