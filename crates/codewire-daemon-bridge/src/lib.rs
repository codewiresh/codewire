//! Host-side adapters between public Codewire RPCs and the private workspace
//! daemon protocol.
//!
//! This crate contains no platform authentication, Kubernetes discovery,
//! local supervisor state, daemon credential issuance, or guest server. Those
//! responsibilities stay behind backend traits so the public protocol and
//! stream behavior have one implementation without merging trust boundaries.

pub mod client;
pub mod drain;
pub mod exec;
pub mod file;
pub mod session;

#[cfg(test)]
mod test_support;
