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

pub mod identity;
pub mod release;
#[cfg(unix)]
pub mod store;
