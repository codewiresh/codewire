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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod broker_control;
#[cfg(target_os = "linux")]
pub mod ch_api;
#[cfg(target_os = "linux")]
pub mod cloud_hypervisor;
#[cfg(target_os = "linux")]
mod cloud_hypervisor_restore;
pub mod control;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod cw_runtime;
#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod diagnostic_log;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod direct_share;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod egress_broker;
#[cfg(target_os = "linux")]
mod fs_clone;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod generation;
pub mod host_addresses;
#[cfg(target_os = "linux")]
pub mod host_port;
#[cfg(target_os = "macos")]
pub(crate) mod host_port;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod hybrid_vsock;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod lifecycle;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_enrollment;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_ingress;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_process;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_transport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network_policy_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network_session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod network_worker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod process_birth;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod process_peer;
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
pub mod supervisor_upgrade;
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

/// Kill and reap, when this test process exits, a long-lived test child it
/// still owns (#3813). A fixture that hands its `Child` to a structure the test
/// drops would otherwise leave the child running past the test binary: a
/// dropped `Child` is neither killed nor reaped. At exit each registered PID is
/// signalled only while `waitpid` reports it as this process's own unreaped,
/// running child, so a PID a test already reaped, which the kernel may have
/// reused, is never signalled.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn reap_at_exit(pid: u32) {
    use std::sync::{Mutex, Once};
    static PIDS: Mutex<Vec<libc::pid_t>> = Mutex::new(Vec::new());
    static REGISTER: Once = Once::new();
    extern "C" fn reap_registered() {
        let pids = match PIDS.lock() {
            Ok(pids) => pids.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        for pid in pids {
            reap_owned_child(pid);
        }
    }
    REGISTER.call_once(|| {
        // SAFETY: registers a plain function with no captured state.
        unsafe { libc::atexit(reap_registered) };
    });
    let pid = libc::pid_t::try_from(pid).expect("a child PID fits pid_t");
    match PIDS.lock() {
        Ok(mut pids) => pids.push(pid),
        Err(poisoned) => poisoned.into_inner().push(pid),
    }
}

/// Kill and reap `pid` only while it is this process's own running child;
/// leave anything else alone. Whether it was signalled is returned.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn reap_owned_child(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG on one PID only reads its state.
    if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != 0 {
        // Already exited and now reaped, or not this process's child.
        return false;
    }
    // Still running and unreaped, so the PID cannot have been reused.
    // SAFETY: signals exactly that child, then waits for it.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    true
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[test]
fn only_an_owned_running_child_is_reaped_at_exit() {
    let sleep = if cfg!(target_os = "macos") {
        "/bin/sleep"
    } else {
        "/usr/bin/sleep"
    };
    #[expect(
        clippy::zombie_processes,
        reason = "reap_owned_child reaps it with waitpid, which is what this test checks"
    )]
    let running = test_child(&mut std::process::Command::new(sleep))
        .arg("60")
        .spawn()
        .unwrap();
    let pid = libc::pid_t::try_from(running.id()).unwrap();
    assert!(
        reap_owned_child(pid),
        "an owned running child was not reaped"
    );
    // SAFETY: probes the PID with signal 0 only.
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "the reaped child still exists"
    );
    let mut finished = test_child(&mut std::process::Command::new(sleep))
        .arg("0")
        .spawn()
        .unwrap();
    let finished_pid = libc::pid_t::try_from(finished.id()).unwrap();
    finished.wait().unwrap();
    assert!(
        !reap_owned_child(finished_pid),
        "an already reaped PID was signalled"
    );
}

/// Spawn an executable this test process just wrote or copied. A concurrent
/// test's fork child holds the write descriptor until its own exec, so the
/// kernel briefly refuses this exec with ETXTBSY; retry only that, bounded.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn spawn_written<T>(
    mut spawn: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    for _ in 1..50 {
        match spawn() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            result => return result,
        }
    }
    spawn()
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
mod snapshot_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod socket_dir;
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
