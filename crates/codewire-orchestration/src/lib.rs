//! Codewire orchestration service (#36).
//!
//! This crate owns environment APIs, lifecycle, sandbox integration, and
//! workers. The environment lifecycle runs entirely on Temporal: the
//! [`temporal`] worker dispatches the [`worker`] handlers as activities,
//! and one workflow per environment id serializes commands. The NATS
//! consumer plane and the `TENANT_LOCKS` distributed lock are retired.

pub mod access_profiles;
pub mod api;
pub mod confidential_storage;
pub mod connect;
pub mod credentials;
pub(crate) mod gateway_binding_identity;
pub mod lifecycle;
pub(crate) mod repository_mount;
pub mod resize_metrics;
pub mod runtime_transport;
pub mod sandbox;
pub mod start_metrics;
pub mod temporal;
/// Isolated-database fixtures shared by the crate's ignored database tests.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../codewire-platform-credentials/tests/support/mod.rs"]
pub(crate) mod test_database_support;
pub mod worker;
