//! Codewire's confined host egress processes (#4000).
//!
//! The network worker terminates an environment's raw-IP stream in a
//! userspace stack and holds no dial authority; the egress broker dials on its
//! behalf under the environment's fixed policy. Each runs confined, from
//! inherited descriptors only. The local runtime and cw-egress both run them.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod broker_control;
#[cfg(target_os = "macos")]
pub mod darwin;
pub mod host_addresses;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod hosted;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod parent;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod worker;
