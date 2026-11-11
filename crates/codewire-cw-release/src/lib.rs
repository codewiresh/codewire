//! Release identity for `cw` executables and the ordinary-user version store.
//!
//! [`identity`] owns the schema-2 payload identity shared by OCI delivery,
//! native runtime packs and release archives. [`store`] keeps every admitted
//! executable at an immutable digest path and moves one managed entry between
//! them, so running processes keep their original bytes and path while new
//! invocations select another version.
//!
//! An ordinary store is writable by its owner. It is not an OS-enforced
//! immutable boundary and is never a trusted managed-helper source.

// Predates these workspace lints; #4125 tracks removing the allow.
#![allow(clippy::undocumented_unsafe_blocks, clippy::unwrap_used)]

#[cfg(unix)]
pub mod build_record;
pub mod identity;
pub mod local_runtime;
pub mod openpgp;
pub mod release;
pub mod sha256;
#[cfg(unix)]
pub mod store;
