//! Host-side runtime for Codewire-owned local microVMs.
//!
//! The first engine is intentionally Linux- and Cloud-Hypervisor-specific. The
//! crate does not expose a generic VMM trait: macOS will have a separate native
//! implementation behind the same higher-level supervisor, not a lowest-common-
//! denominator VMM abstraction.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod artifact;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod artifact_store;
#[cfg(target_os = "linux")]
pub mod ch_api;
#[cfg(target_os = "linux")]
pub mod cloud_hypervisor;
pub mod control;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod cw_runtime;
#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod direct_share;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod egress_broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod generation;
#[cfg(target_os = "linux")]
pub mod host_port;
#[cfg(target_os = "macos")]
pub(crate) mod host_port;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod hybrid_vsock;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod lifecycle;
#[cfg(all(target_os = "linux", feature = "macos-console-pair-fixture"))]
pub mod macos_console_pair_fixture;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_enrollment;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_ingress;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_process;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_transport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network_session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network_worker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod process_birth;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod supervisor_client;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod supervisor_config;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod supervisor_metadata;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supervisor_store_codec;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supervisor_store_error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod workspace;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod workspace_plan;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod host_git;
#[cfg(target_os = "linux")]
pub mod linux;
// Host primitives with the same names on each supported platform.
#[cfg(target_os = "macos")]
pub(crate) use darwin as host;
#[cfg(target_os = "linux")]
pub(crate) use linux as host;

/// Spawn a long-lived test child without descriptors that concurrent tests are
/// still creating, so it cannot keep another test's socket or pipe open.
/// Linux creates every descriptor close-on-exec in one call; Darwin needs the
/// sweep its product spawns make.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn test_child(command: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(target_os = "macos")]
    // SAFETY: the sweep makes only getdtablesize and fcntl calls.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(command, || {
            darwin::process::mark_inherited_descriptors_close_on_exec();
            Ok(())
        });
    }
    command
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod oci;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod orphan;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod public_client;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod runner;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod runner_service;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod runtime_install;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod setup_pack;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod skill_snapshot;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod state;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod supervisor;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supervisor_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod uds;
#[cfg(target_os = "macos")]
mod vz;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod workspace_generation;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use direct_share::{DirectShareRequest, workspace_source_refusal};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use host::process::{LiveProcess, ProcessIdentity, RecoveryError};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use runner::{
    CloudHypervisorRunner, CreateVmRequest, ExitClass, PreparedVm, RecoveredVm, RunnerConfig,
    RunnerError, RunningVm,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use state::{StateDiskIdentity, VmPaths};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use supervisor_metadata::valid_environment_name;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::{CloudHypervisorRunner, RunnerConfig, RunnerError};
