//! Host-side runtime for Codewire-owned local microVMs.
//!
//! The first engine is intentionally Linux- and Cloud-Hypervisor-specific. The
//! crate does not expose a generic VMM trait: macOS will have a separate native
//! implementation behind the same higher-level supervisor, not a lowest-common-
//! denominator VMM abstraction.

#[cfg(target_os = "linux")]
pub mod artifact;
#[cfg(target_os = "linux")]
mod artifact_store;
#[cfg(target_os = "linux")]
pub mod ch_api;
#[cfg(target_os = "linux")]
pub mod cloud_hypervisor;
pub mod control;
#[cfg(target_os = "linux")]
pub mod egress_broker;
#[cfg(target_os = "linux")]
pub mod generation;
#[cfg(target_os = "linux")]
pub mod host_port;
#[cfg(target_os = "linux")]
pub mod hybrid_vsock;
#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(target_os = "linux")]
pub mod mesh_ingress;
#[cfg(target_os = "linux")]
pub mod mesh_transport;
#[cfg(target_os = "linux")]
pub mod network_worker;
#[cfg(target_os = "linux")]
pub mod workspace;
#[cfg(target_os = "linux")]
mod workspace_plan;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod oci;
#[cfg(target_os = "linux")]
mod orphan;
#[cfg(target_os = "linux")]
pub mod public_client;
#[cfg(target_os = "linux")]
pub mod runner_service;
#[cfg(target_os = "linux")]
pub mod setup_pack;
#[cfg(target_os = "linux")]
pub mod supervisor;
#[cfg(target_os = "linux")]
mod supervisor_store;
#[cfg(target_os = "linux")]
mod uds;
#[cfg(target_os = "linux")]
mod workspace_generation;

#[cfg(target_os = "linux")]
pub use linux::{
    CloudHypervisorRunner, CreateVmRequest, ExitClass, LiveProcess, PreparedVm, ProcessIdentity,
    RecoveredVm, RecoveryError, RunnerConfig, RunnerError, RunningVm, StateDiskIdentity, VmPaths,
};

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::{CloudHypervisorRunner, RunnerConfig, RunnerError};
