//! The macOS VMM: the signed Virtualization.framework helper.
//!
//! `codewire-vz-runner vm --config FILE` is the counterpart of the Cloud
//! Hypervisor process on Linux. It boots the same kernel, initramfs and disks
//! by serial, and serves the guest's vsock ports on one hybrid-vsock Unix
//! socket with the CONNECT/OK protocol the runner already speaks. It stops
//! its VM when SIGTERM arrives or when this runner (its parent) exits.
//! Direct shares use Virtualization.framework's built-in virtio-fs device
//! with the same tag the guest mounts on Linux.

use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_DISK_SERIAL;
use codewire_vmm_guest_probe::{
    DOCKER_DISK_SERIAL, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SETUP_DISK_SERIAL, STATE_DISK_SERIAL,
};
use serde::Serialize;

use crate::direct_share::DirectShareIdentity;
use crate::runner::RunnerError;
use crate::state::VmLock;

/// The configuration file inside the private VM directory.
pub(crate) const CONFIG_NAME: &str = "vz.json";
/// The kernel command line Cloud Hypervisor boots on Linux, plus
/// `codewire.clock=rtc`: the guest follows the VM's RTC, which reads the host's
/// time, because Virtualization.framework stops the guest's clocks while the VM
/// does not run, such as during host sleep.
const GUEST_KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init panic=-1 codewire.clock=rtc";
/// `VMConfiguration.schemaVersion` in the helper. Schema 2 added `shares`.
const SCHEMA_VERSION: u32 = 2;

/// The helper's schema-2 `VMConfiguration`. It refuses unknown or missing
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
    shares: Vec<VzShare>,
    vsock_socket: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VzDisk {
    path: PathBuf,
    serial: &'static str,
    read_only: bool,
}

/// One admitted host directory, served by the helper's virtio-fs device under
/// the guest-visible tag. The helper opens the path without following any
/// symlink and requires this exact directory before and after VM start.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VzShare {
    tag: String,
    path: PathBuf,
    read_only: bool,
    /// The raw `st_dev` of the admitted directory.
    device: u32,
    inode: u64,
}

impl VzShare {
    pub(crate) fn new(
        tag: &str,
        path: &Path,
        read_only: bool,
        identity: &DirectShareIdentity,
    ) -> Self {
        Self {
            tag: tag.to_owned(),
            path: path.to_owned(),
            read_only,
            device: (identity.device_major() << 24) | identity.device_minor(),
            inode: identity.inode(),
        }
    }
}

/// The VM's disks, in the order Cloud Hypervisor attaches them on Linux.
pub(crate) struct VzDisks<'a> {
    pub(crate) state: &'a Path,
    pub(crate) docker: Option<&'a Path>,
    pub(crate) root: &'a Path,
    pub(crate) seed: &'a Path,
    pub(crate) setup: Option<&'a Path>,
    /// The read-only cw runtime catalog the guest mounts at `/codewire-cw`.
    pub(crate) cw_runtime: Option<&'a Path>,
}

impl VzConfiguration {
    pub(crate) fn new(
        kernel: &Path,
        initramfs: &Path,
        vcpus: u8,
        memory_mib: u32,
        disks: VzDisks<'_>,
        shares: Vec<VzShare>,
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
        attached.extend(
            disks
                .cw_runtime
                .map(|path| disk(path, CW_RUNTIME_DISK_SERIAL, true)),
        );
        Self {
            schema_version: SCHEMA_VERSION,
            kernel: kernel.to_owned(),
            initial_ramdisk: initramfs.to_owned(),
            command_line: GUEST_KERNEL_CMDLINE,
            cpu_count: vcpus,
            memory_mib,
            disks: attached,
            shares,
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
    fn configuration_names_disk_order_and_shares_match_the_helper_schema() {
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
                cw_runtime: Some(Path::new("/engine/cw-runtimes/catalogs/c/runtime.raw")),
            },
            vec![VzShare {
                tag: "cw-direct-00".to_owned(),
                path: PathBuf::from("/Users/someone/project"),
                read_only: true,
                device: 0x0100_0012,
                inode: 42,
            }],
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
                "shares",
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
                (CW_RUNTIME_DISK_SERIAL.to_owned(), true),
            ]
        );
        assert_eq!(value["schemaVersion"], 2);
        assert_eq!(
            value["shares"],
            serde_json::json!([{
                "tag": "cw-direct-00",
                "path": "/Users/someone/project",
                "readOnly": true,
                "device": 0x0100_0012,
                "inode": 42,
            }])
        );
        assert_eq!(value["commandLine"], GUEST_KERNEL_CMDLINE);
    }
}
