//! Codewire orchestration service (#36).
//!
//! This crate owns environment APIs, lifecycle, sandbox integration, and
//! workers. The environment lifecycle runs entirely on Temporal: the
//! [`temporal`] worker dispatches the [`worker`] handlers as activities,
//! and one workflow per environment id serializes commands. The NATS
//! consumer plane and the `TENANT_LOCKS` distributed lock are retired.

pub mod api;
pub mod connect;
pub mod lifecycle;
pub mod resize_metrics;
pub mod runtime_transport;
pub mod sandbox;
pub mod temporal;
pub mod worker;
