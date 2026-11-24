//! Host-side runtime for Codewire-owned local microVMs.
//!
//! The first engine is intentionally Linux- and Cloud-Hypervisor-specific. The
//! crate does not expose a generic VMM trait: macOS will have a separate native
//! implementation behind the same higher-level supervisor, not a lowest-common-
//! denominator VMM abstraction.

// Predates these workspace lints; #4125 tracks removing the allow.
#![allow(clippy::undocumented_unsafe_blocks, clippy::unwrap_used)]
// Every child starts through `swept_command` (clippy.toml). Only macOS
// needs the sweep, so only the Darwin cross clippy enforces it (#4806).
#![cfg_attr(not(target_os = "macos"), allow(clippy::disallowed_methods))]

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod artifact;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod artifact_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod broker_control;
#[cfg(target_os = "linux")]
pub mod ch_api;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod checkpoint_pin;
#[cfg(target_os = "linux")]
pub mod cloud_hypervisor;
#[cfg(target_os = "linux")]
mod cloud_hypervisor_restore;
pub mod console_lock;
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod engine_root;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod front_door;
#[cfg(any(target_os = "linux", target_os = "macos"))]
// Disk snapshots and VM checkpoints call it on macOS from #4654's later slices.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod fs_clone;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod generation;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod guest_loopback;
pub mod host_addresses;
#[cfg(target_os = "linux")]
pub mod host_port;
#[cfg(target_os = "macos")]
pub(crate) mod host_port;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod hybrid_vsock;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod image_disk;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod lifecycle;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod local_https;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_enrollment;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mesh_ingress;
mod mesh_ingress_ack;
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
// Puts the non-shipping feature in a build's dep-info for release admission (#4986).
#[cfg(feature = "synthetic-oci-input-smoke")]
mod non_shipping_synthetic_oci_input_smoke;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod process_birth;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod process_end;
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

/// A child this crate starts, as a `std::process::Command` (#4806). Darwin
/// creates sockets, pipes and accepted descriptors first and marks them
/// close-on-exec in a second call, so a child forked in between would keep
/// one open (#4654, cw-security condition 1). On macOS the child therefore
/// marks every descriptor from 3 up close-on-exec between fork and exec,
/// then clears the flag on `keep`, the descriptors it is meant to inherit.
/// Linux creates every descriptor close-on-exec in one call, so there only
/// `keep` is cleared. The hook runs before any the caller adds.
///
/// This and [`swept_tokio_command`] are the crate's only process
/// constructors: its clippy.toml disallows every other way to fork, spawn
/// or exec, and the Darwin cross clippy enforces it. A `pre_exec` hook
/// makes the standard library fork and exec rather than `posix_spawn`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::disallowed_methods)]
#[doc(hidden)]
pub fn swept_command(
    program: impl AsRef<std::ffi::OsStr>,
    keep: &[std::os::fd::RawFd],
) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    if let Some(hook) = inheritance_hook(keep) {
        // SAFETY: the hook makes only async-signal-safe fcntl calls and reads
        // memory prepared before the fork (`inheritance_hook`).
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, hook);
        }
    }
    command
}

/// [`swept_command`] as a `tokio::process::Command`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::disallowed_methods)]
#[doc(hidden)]
pub fn swept_tokio_command(
    program: impl AsRef<std::ffi::OsStr>,
    keep: &[std::os::fd::RawFd],
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    if let Some(hook) = inheritance_hook(keep) {
        // SAFETY: as in `swept_command`.
        unsafe {
            command.pre_exec(hook);
        }
    }
    command
}

/// The hook both constructors install: always on macOS, and on Linux only
/// when something is kept, since a hook makes the child fork and exec
/// rather than `posix_spawn`. Everything it reads, the descriptor table's
/// bound and the copy of `keep`, is prepared here in the parent, so between
/// fork and exec it allocates nothing, takes no lock and opens no directory:
/// only fcntl calls.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inheritance_hook(
    keep: &[std::os::fd::RawFd],
) -> Option<impl FnMut() -> std::io::Result<()> + Send + Sync + 'static> {
    if cfg!(target_os = "linux") && keep.is_empty() {
        return None;
    }
    #[cfg(target_os = "macos")]
    let bound = darwin::process::descriptor_bound();
    let keep = keep.to_vec();
    Some(move || {
        #[cfg(target_os = "macos")]
        darwin::process::mark_inherited_descriptors_close_on_exec_below(bound);
        for &descriptor in &keep {
            // SAFETY: a scalar fcntl on a descriptor number.
            if unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    })
}

/// A long-lived test child, swept like every other child, so it cannot keep
/// another test's socket or pipe open.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn test_child(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    swept_command(program, &[])
}

/// A short-lived test child, started as `Command::new` starts one: with
/// `posix_spawn` and no hook, so no fork holds another parallel test's
/// descriptors (a lock, or an executable it rewrites) while it runs a
/// sweep. It may inherit a descriptor a parallel test is creating, which a
/// child that ends within its test can't keep open; one that outlives its
/// test is a [`test_child`].
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[allow(clippy::disallowed_methods)]
pub(crate) fn test_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    std::process::Command::new(program)
}

/// [`test_command`] as a `tokio::process::Command`.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[allow(clippy::disallowed_methods)]
pub(crate) fn test_tokio_command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    tokio::process::Command::new(program)
}

/// Replace this test process with `command`, which must come from one of
/// this crate's constructors: the only exec this crate allows.
#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::disallowed_methods)]
pub(crate) fn test_exec(command: &mut std::process::Command) -> std::io::Error {
    std::os::unix::process::CommandExt::exec(command)
}

/// Copy `source` to `destination`, an executable the test then runs, with a
/// `cp` child, so this process never opens the copy for writing. A child that
/// another test thread forks holds this process's descriptors until it execs,
/// close-on-exec or not; while it holds a writable one to the copy, running the
/// copy fails with ETXTBSY (#4210). Renaming a copy into place leaves the same
/// file open, and retrying would only wait the race out.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn copy_test_executable(source: &std::path::Path, destination: &std::path::Path) {
    let status = crate::test_command("cp")
        .arg("--")
        .arg(source)
        .arg(destination)
        .status()
        .expect("run cp for a test executable");
    assert!(status.success(), "cp {source:?} {destination:?}: {status}");
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
    let running = test_child(sleep).arg("60").spawn().unwrap();
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
    let mut finished = test_child(sleep).arg("0").spawn().unwrap();
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
#[cfg(target_os = "linux")]
pub mod pod_runtime;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod public_client;
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
/// How many live (direct) mounts one local VM serves.
pub use codewire_vmm_guest_probe::MAX_DIRECT_SHARES;
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
