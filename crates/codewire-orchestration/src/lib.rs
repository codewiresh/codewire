//! Codewire orchestration service (#36).
//!
//! This crate owns environment APIs, lifecycle, sandbox integration, and
//! workers. The environment lifecycle runs entirely on Temporal: the
//! [`temporal`] worker dispatches the [`worker`] handlers as activities,
//! and one workflow per environment id serializes commands. The NATS
//! consumer plane and the `TENANT_LOCKS` distributed lock are retired.

pub mod api;
pub mod confidential_storage;
pub mod connect;
pub mod lifecycle;
pub(crate) mod openbao_workload_identity;
pub(crate) mod repository_mount;
pub mod resize_metrics;
pub mod runtime_transport;
pub mod sandbox;
pub mod temporal;
pub mod worker;
