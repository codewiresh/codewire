//! The macOS VMM: the signed Virtualization.framework helper.
//!
//! `codewire-vz-runner vm --config FILE` is the counterpart of the Cloud
//! Hypervisor process on Linux. It boots the same kernel, initramfs and disks
//! by serial, and serves the guest's vsock ports on one hybrid-vsock Unix
//! socket with the CONNECT/OK protocol the runner already speaks. It stops
//! its VM when SIGTERM arrives or when this runner (its parent) exits.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use codewire_vmm_guest_probe::{
    DOCKER_DISK_SERIAL, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SETUP_DISK_SERIAL, STATE_DISK_SERIAL,
};
use serde::Serialize;

use crate::runner::RunnerError;
use crate::state::VmLock;

/// The configuration file inside the private VM directory.
pub(crate) const CONFIG_NAME: &str = "vz.json";
/// The kernel command line Cloud Hypervisor boots on Linux, plus
/// `codewire.clock=rtc`: the guest follows the VM's RTC, which reads the host's
/// time, because Virtualization.framework stops the guest's clocks while the VM
/// does not run, such as during host sleep.
const GUEST_KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init panic=-1 codewire.clock=rtc";
/// `VMConfiguration.schemaVersion` in the helper.
const SCHEMA_VERSION: u32 = 1;

/// The helper's schema-1 `VMConfiguration`. It refuses unknown or missing
/// fields, so these names must match it exactly.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VzConfiguration {
    schema_version: u32,
    kernel: PathBuf,
    initial_ramdisk: PathBuf,
    command_line: &'static str,
    cpu_count: u8,
    #[serde(rename = "memoryMiB")]
    memory_mib: u32,
    disks: Vec<VzDisk>,
    vsock_socket: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VzDisk {
    path: PathBuf,
    serial: &'static str,
    read_only: bool,
}

/// The VM's disks, in the order Cloud Hypervisor attaches them on Linux.
pub(crate) struct VzDisks<'a> {
    pub(crate) state: &'a Path,
    pub(crate) docker: Option<&'a Path>,
    pub(crate) root: &'a Path,
    pub(crate) seed: &'a Path,
    pub(crate) setup: Option<&'a Path>,
}

impl VzConfiguration {
    pub(crate) fn new(
        kernel: &Path,
        initramfs: &Path,
        vcpus: u8,
        memory_mib: u32,
        disks: VzDisks<'_>,
        vsock_socket: &Path,
    ) -> Self {
        let disk = |path: &Path, serial, read_only| VzDisk {
            path: path.to_owned(),
            serial,
            read_only,
        };
        let mut attached = vec![disk(disks.state, STATE_DISK_SERIAL, false)];
        attached.extend(
            disks
                .docker
                .map(|path| disk(path, DOCKER_DISK_SERIAL, false)),
        );
        attached.push(disk(disks.root, ROOT_DISK_SERIAL, false));
        attached.push(disk(disks.seed, SEED_DISK_SERIAL, true));
        attached.extend(disks.setup.map(|path| disk(path, SETUP_DISK_SERIAL, true)));
        Self {
            schema_version: SCHEMA_VERSION,
            kernel: kernel.to_owned(),
            initial_ramdisk: initramfs.to_owned(),
            command_line: GUEST_KERNEL_CMDLINE,
            cpu_count: vcpus,
            memory_mib,
            disks: attached,
            vsock_socket: vsock_socket.to_owned(),
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, RunnerError> {
        serde_json::to_vec(self).map_err(|_| RunnerError::InvalidRequest)
    }
}

/// Spawn the helper. Its only inherited descriptor beyond null stdio is the
/// open `vm.lock`, so a helper that outlives this runner still holds the lock
/// and a second boot of the same disks fails with `AlreadyLocked`.
pub(crate) fn spawn(
    executable: &Path,
    config: &Path,
    working_directory: &Path,
    lock: &VmLock,
) -> Result<tokio::process::Child, RunnerError> {
    let lock = lock.file().as_raw_fd();
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("vm")
        .arg("--config")
        .arg(config)
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: scalar fcntl and umask between fork and exec. Clearing
    // close-on-exec here affects only the child's copy of the lock descriptor,
    // the one descriptor beyond stdio the helper inherits.
    unsafe {
        command.pre_exec(move || {
            crate::darwin::process::mark_inherited_descriptors_close_on_exec();
            if libc::fcntl(lock, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    command.spawn().map_err(|_| RunnerError::Spawn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_names_and_disk_order_match_the_helper_schema() {
        let configuration = VzConfiguration::new(
            Path::new("/a/kernel"),
            Path::new("/a/initramfs"),
            2,
            4096,
            VzDisks {
                state: Path::new("/vm/disks/state.raw"),
                docker: None,
                root: Path::new("/vm/generations/x/root.raw"),
                seed: Path::new("/vm/seed/seed.raw"),
                setup: Some(Path::new("/vm/setup.raw")),
            },
            Path::new("/vm/vsock/v"),
        );
        let value: serde_json::Value =
            serde_json::from_slice(&configuration.encode().unwrap()).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "commandLine",
                "cpuCount",
                "disks",
                "initialRamdisk",
                "kernel",
                "memoryMiB",
                "schemaVersion",
                "vsockSocket"
            ]
        );
        let serials: Vec<_> = value["disks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|disk| {
                (
                    disk["serial"].as_str().unwrap().to_owned(),
                    disk["readOnly"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            serials,
            [
                (STATE_DISK_SERIAL.to_owned(), false),
                (ROOT_DISK_SERIAL.to_owned(), false),
                (SEED_DISK_SERIAL.to_owned(), true),
                (SETUP_DISK_SERIAL.to_owned(), true),
            ]
        );
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["commandLine"], GUEST_KERNEL_CMDLINE);
    }
}
