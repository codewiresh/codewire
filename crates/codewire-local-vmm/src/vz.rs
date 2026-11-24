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
use codewire_vmm_guest_probe::image_disk::IMAGE_DISK_SERIAL;
use codewire_vmm_guest_probe::{
    DOCKER_DISK_SERIAL, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SETUP_DISK_SERIAL, STATE_DISK_SERIAL,
};
use serde::Serialize;

use crate::direct_share::DirectShareIdentity;
use crate::host::path::PrivateRoot;
use crate::runner::RunnerError;
use crate::state::VmLock;

mod checkpointing;
mod control;

pub(crate) use checkpointing::{Checkpointing, ProtocolCache};
pub(crate) use control::{ControlPair, VzControl, VzOperation, VzReply, is_machine_identifier};

/// The configuration file inside the private VM directory.
pub(crate) const CONFIG_NAME: &str = "vz.json";
/// The VM's machine identifier, beside `vz.json`: base64 of the helper's
/// `VZGenericMachineIdentifier`, kept from its first start because a restore
/// needs the identifier its state was saved with (#4654).
pub(crate) const MACHINE_IDENTIFIER_NAME: &str = "vz-machine-id";
/// The one file a schema 3 helper's `save` writes, in the VM's
/// `checkpoints/` directory.
pub(crate) const SAVE_STATE_NAME: &str = "vz-save";
/// A captured VM's saved state in its VM checkpoint's `vmm/` (design §5).
pub(crate) const CHECKPOINT_STATE_NAME: &str = "state.vzsave";
/// The helper's identity in a VM checkpoint's manifest (`vmm.version`): the
/// configuration schema its checkpoints are taken with (design §6).
pub(crate) const CHECKPOINT_VMM_VERSION: &str = "vz-3";
/// What the helper's `protocol` command may print.
const PROTOCOL_OUTPUT_LIMIT: u64 = 16;
/// The status a helper from before schema 3 exits with, printing its usage,
/// when asked for `protocol`.
const USAGE_STATUS: i32 = 2;
const PROTOCOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// The kernel command line Cloud Hypervisor boots on Linux, plus
/// `codewire.clock=rtc`: the guest follows the VM's RTC, which reads the host's
/// time, because Virtualization.framework stops the guest's clocks while the VM
/// does not run, such as during host sleep.
const GUEST_KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init panic=-1 codewire.clock=rtc";
/// `VMConfiguration.schemaVersion` in the helper. Schema 2 added `shares`;
/// schema 3 adds the control channel and the checkpoint files (#4654), and is
/// written only to a helper whose `protocol` command reports it.
const SCHEMA_VERSION: u32 = 2;
pub(crate) const CHECKPOINTING_SCHEMA_VERSION: u32 = 3;
/// The helper's `VMExit.startRefusedBase`: a start Virtualization.framework
/// refused exits this plus the refusal's `VZError.Code` for codes 1...63, and
/// exactly this for any other code (#4478).
const START_REFUSED_BASE: i32 = 64;

/// The `VZError.Code` of a start the helper reports as refused, 0 when the
/// framework gave none in range, or `None` for any other end of the helper.
pub(crate) fn start_refused_code(status: std::process::ExitStatus) -> Option<u8> {
    let offset = status.code()?.checked_sub(START_REFUSED_BASE)?;
    u8::try_from(offset).ok().filter(|offset| *offset < 64)
}

/// The helper's `VMConfiguration`, schema 2, or schema 3 with
/// `checkpointing`. It refuses unknown or missing fields, so these names must
/// match it exactly.
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
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    checkpointing: Option<VzCheckpointing>,
}

/// Schema 3's four fields. All four are written, `null` included, because the
/// helper refuses a missing one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VzCheckpointing {
    /// Base64 of the helper's `VZGenericMachineIdentifier` data
    /// representation, as its `started` event reported it; `None` on a VM's
    /// first start, when the helper makes one.
    pub(crate) machine_identifier: Option<String>,
    /// The one file a save writes, inside the VM's directory.
    pub(crate) save_state: PathBuf,
    /// A saved state to restore instead of starting.
    pub(crate) restore_state: Option<PathBuf>,
    /// The helper's end of the control socketpair, inherited at this number.
    pub(crate) control_descriptor: i32,
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
    /// The shared read-only image disk (#4646), always after the runtime.
    pub(crate) image: Option<&'a Path>,
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
        attached.extend(disks.image.map(|path| disk(path, IMAGE_DISK_SERIAL, true)));
        Self {
            schema_version: SCHEMA_VERSION,
            checkpointing: None,
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

    /// Schema 3, for a helper that speaks it.
    pub(crate) fn with_checkpointing(mut self, checkpointing: VzCheckpointing) -> Self {
        self.schema_version = CHECKPOINTING_SCHEMA_VERSION;
        self.checkpointing = Some(checkpointing);
        self
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, RunnerError> {
        serde_json::to_vec(self).map_err(|_| RunnerError::InvalidRequest)
    }
}

/// Spawn the helper. Beyond null stdio it inherits exactly the open
/// `vm.lock`, so a helper that outlives this runner still holds the lock and a
/// second boot of the same disks fails with `AlreadyLocked`, and, for schema
/// 3, its end of the control socketpair (cw-security, condition 1, #4654).
pub(crate) fn spawn(
    executable: &Path,
    config: &Path,
    working_directory: &Path,
    lock: &VmLock,
    control: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<tokio::process::Child, RunnerError> {
    let lock = lock.file().as_raw_fd();
    let control = control.map(|descriptor| descriptor.as_raw_fd());
    // The lock and the control descriptor are the only descriptors beyond
    // stdio the helper inherits.
    let inherited: Vec<_> = std::iter::once(lock).chain(control).collect();
    let mut command = crate::swept_tokio_command(executable, &inherited);
    command
        .arg("vm")
        .arg("--config")
        .arg(config)
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: a scalar umask between fork and exec.
    unsafe {
        command.pre_exec(move || {
            libc::umask(0o077);
            Ok(())
        });
    }
    command.spawn().map_err(|_| RunnerError::Spawn)
}

/// The newest configuration schema the helper at `executable` accepts, when
/// it answers for certain: a clean `3`, or the usage exit of a helper from
/// before schema 3, which has no `protocol` command (#4654). `None` when the
/// helper could not be asked, such as a spawn failure or no answer in time;
/// the caller then starts on schema 2 and asks again next time.
pub(crate) async fn probe_protocol(executable: &Path) -> Option<u32> {
    probe_protocol_within(executable, PROTOCOL_TIMEOUT).await
}

/// [`probe_protocol`] with the time the helper has to answer.
async fn probe_protocol_within(executable: &Path, timeout: std::time::Duration) -> Option<u32> {
    use tokio::io::AsyncReadExt as _;
    let mut command = crate::swept_tokio_command(executable, &[]);
    command
        .arg("protocol")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let probe = async {
        let mut output = Vec::new();
        let stdout = child.stdout.take()?;
        stdout
            .take(PROTOCOL_OUTPUT_LIMIT)
            .read_to_end(&mut output)
            .await
            .ok()?;
        let status = child.wait().await.ok()?;
        if status.success() && output == format!("{CHECKPOINTING_SCHEMA_VERSION}\n").as_bytes() {
            Some(CHECKPOINTING_SCHEMA_VERSION)
        } else if status.code() == Some(USAGE_STATUS) {
            Some(SCHEMA_VERSION)
        } else {
            None
        }
    };
    tokio::time::timeout(timeout, probe).await.ok().flatten()
}

/// The machine identifier kept for this VM, if its helper reported one.
pub(crate) fn read_machine_identifier(vm: &PrivateRoot) -> Result<Option<String>, RunnerError> {
    use std::io::Read as _;
    let file = match vm.open_regular(
        Path::new(MACHINE_IDENTIFIER_NAME),
        false,
        None,
        false,
        Some(0o600),
    ) {
        Ok(file) => file,
        Err(error) if crate::state::path_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut text = String::new();
    file.file()
        .take(4096)
        .read_to_string(&mut text)
        .map_err(|_| RunnerError::VzMachineIdentifier)?;
    let identifier = text.trim_end_matches('\n');
    if !is_machine_identifier(identifier) {
        return Err(RunnerError::VzMachineIdentifier);
    }
    Ok(Some(identifier.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;

    use super::*;

    const PROBE_OUT: &str = "CW_FD_PROBE_OUT";

    /// The child half of the descriptor probe. A script that a spawn under
    /// test runs in place of the helper re-executes this test binary for just
    /// this test, which writes the descriptors it holds to `CW_FD_PROBE_OUT`.
    #[test]
    fn descriptor_probe_child() {
        let Some(out) = std::env::var_os(PROBE_OUT) else {
            return;
        };
        let open: Vec<String> = (0..1024)
            // SAFETY: F_GETFD only reads a descriptor's flags.
            .filter(|descriptor| unsafe { libc::fcntl(*descriptor, libc::F_GETFD) } != -1)
            .map(|descriptor| descriptor.to_string())
            .collect();
        std::fs::write(out, open.join(" ")).unwrap();
    }

    /// cw-security, condition 1 and its addition (b), #4654. The helper
    /// inherits exactly stdio, the VM lock and its end of the control
    /// channel, even while another thread keeps making descriptors; and an
    /// unrelated runner spawn made while the channel exists holds neither end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_helper_inherits_exactly_stdio_the_lock_and_its_control_end() {
        use std::collections::BTreeSet;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // PrivateRoot refuses a symlink in any component, and `/var` is one.
        let directory = temporary.path().canonicalize().unwrap();
        let directory = directory.as_path();
        let root = PrivateRoot::open(directory).unwrap();
        let paths = crate::state::VmPaths::create(&root, uuid::Uuid::new_v4()).unwrap();
        let lock = paths.lock().unwrap();
        let pair = ControlPair::new().unwrap();
        let exe = std::env::current_exe().unwrap();
        let probe = |name: &str| {
            let script = directory.join(name);
            let out = directory.join(format!("{name}.out"));
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\n{PROBE_OUT}='{}' exec '{}' --exact vz::tests::descriptor_probe_child --nocapture --test-threads 1\n",
                    out.display(),
                    exe.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            (script, out)
        };
        let held = |out: &Path| -> BTreeSet<i32> {
            std::fs::read_to_string(out)
                .unwrap()
                .split_whitespace()
                .map(|descriptor| descriptor.parse().unwrap())
                .collect()
        };

        let stop = Arc::new(AtomicBool::new(false));
        let churn = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    drop(UnixStream::pair());
                }
            })
        };
        let (script, out) = probe("helper");
        let mut child = spawn(
            &script,
            &directory.join(CONFIG_NAME),
            directory,
            &lock,
            Some(pair.helper()),
        )
        .unwrap();
        assert!(child.wait().await.unwrap().success());
        let expected =
            BTreeSet::from([0, 1, 2, lock.file().as_raw_fd(), pair.helper().as_raw_fd()]);
        assert_eq!(held(&out), expected, "the helper's descriptors");

        // (b): another runner spawn, the protocol probe, while both ends exist.
        // The stand-in exits cleanly and prints nothing: no answer.
        let (other, other_out) = probe("other");
        assert_eq!(probe_protocol(&other).await, None);
        let other_held = held(&other_out);
        stop.store(true, Ordering::Relaxed);
        churn.join().unwrap();
        assert!(
            !other_held.contains(&pair.helper().as_raw_fd())
                && !other_held.contains(&pair.runner_for_test().as_raw_fd())
                && !other_held.contains(&lock.file().as_raw_fd()),
            "an unrelated spawn held {other_held:?}"
        );
    }

    #[test]
    fn a_refused_start_is_read_from_the_helpers_exit_status() {
        use std::os::unix::process::ExitStatusExt as _;
        let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        assert_eq!(start_refused_code(exited(65)), Some(1));
        assert_eq!(start_refused_code(exited(127)), Some(63));
        assert_eq!(start_refused_code(exited(64)), Some(0));
        for other in [0, 1, 2, 63, 128, 255] {
            assert_eq!(start_refused_code(exited(other)), None, "{other}");
        }
        let killed = std::process::ExitStatus::from_raw(libc::SIGKILL);
        assert_eq!(start_refused_code(killed), None);
    }

    #[test]
    fn configuration_names_disk_order_and_shares_match_the_helper_schema() {
        let configuration = VzConfiguration::new(
            Path::new("/a/kernel"),
            Path::new("/a/initramfs"),
            2,
            4096,
            VzDisks {
                state: Path::new("/vm/disks/state.raw"),
                docker: Some(Path::new("/vm/disks/docker.raw")),
                root: Path::new("/vm/generations/x/root.raw"),
                seed: Path::new("/vm/seed/seed.raw"),
                setup: Some(Path::new("/vm/setup.raw")),
                cw_runtime: Some(Path::new("/engine/cw-runtimes/catalogs/c/runtime.raw")),
                image: Some(Path::new("/engine/image-disks/disks/i/image.raw")),
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
                (DOCKER_DISK_SERIAL.to_owned(), false),
                (ROOT_DISK_SERIAL.to_owned(), false),
                (SEED_DISK_SERIAL.to_owned(), true),
                (SETUP_DISK_SERIAL.to_owned(), true),
                (CW_RUNTIME_DISK_SERIAL.to_owned(), true),
                (IMAGE_DISK_SERIAL.to_owned(), true),
            ]
        );
        // Every disk at once stays under the helper's limit of eight.
        assert_eq!(serials.len(), 7);
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

    /// Schema 3 writes all four of its fields, `null` included, beside
    /// schema 2's: the helper refuses a missing or renamed one.
    #[test]
    fn schema_3_names_its_four_fields_as_the_helper_does() {
        let configuration = || {
            VzConfiguration::new(
                Path::new("/a/kernel"),
                Path::new("/a/initramfs"),
                2,
                4096,
                VzDisks {
                    state: Path::new("/vm/disks/state.raw"),
                    docker: None,
                    root: Path::new("/vm/generations/x/root.raw"),
                    seed: Path::new("/vm/seed/seed.raw"),
                    setup: None,
                    cw_runtime: None,
                    image: None,
                },
                Vec::new(),
                Path::new("/vm/vsock/v"),
            )
        };
        let encoded = |checkpointing| -> serde_json::Value {
            serde_json::from_slice(
                &configuration()
                    .with_checkpointing(checkpointing)
                    .encode()
                    .unwrap(),
            )
            .unwrap()
        };
        let first = encoded(VzCheckpointing {
            machine_identifier: None,
            save_state: PathBuf::from("/vm/checkpoints/vz-save"),
            restore_state: None,
            control_descriptor: 7,
        });
        assert_eq!(first["schemaVersion"], 3);
        assert_eq!(first["machineIdentifier"], serde_json::Value::Null);
        assert_eq!(first["saveState"], "/vm/checkpoints/vz-save");
        assert_eq!(first["restoreState"], serde_json::Value::Null);
        assert_eq!(first["controlDescriptor"], 7);
        let mut keys: Vec<_> = first.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "commandLine",
                "controlDescriptor",
                "cpuCount",
                "disks",
                "initialRamdisk",
                "kernel",
                "machineIdentifier",
                "memoryMiB",
                "restoreState",
                "saveState",
                "schemaVersion",
                "shares",
                "vsockSocket"
            ]
        );
        let kept = encoded(VzCheckpointing {
            machine_identifier: Some("YnBsaXN0MDA=".to_owned()),
            save_state: PathBuf::from("/vm/checkpoints/vz-save"),
            restore_state: Some(PathBuf::from("/vm/checkpoints/in")),
            control_descriptor: 7,
        });
        assert_eq!(kept["machineIdentifier"], "YnBsaXN0MDA=");
        assert_eq!(kept["restoreState"], "/vm/checkpoints/in");
    }

    /// A helper script in a private directory.
    fn helper(directory: &Path, body: &str) -> PathBuf {
        let script = directory.join("helper");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    /// Only a definite answer counts: a clean `3`, or an older helper's usage
    /// exit. A helper that cannot be run or does not answer in time is no
    /// answer, so the runner asks it again on its next start.
    #[tokio::test]
    async fn the_probe_answers_only_when_the_helper_does() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path();
        // A bound no run reaches for the answers, and a short one for the
        // helper that never answers, so a loaded machine changes nothing.
        let answer = std::time::Duration::from_secs(3600);
        for (body, expected) in [
            ("echo 3", Some(CHECKPOINTING_SCHEMA_VERSION)),
            ("echo usage >&2; exit 2", Some(SCHEMA_VERSION)),
            ("echo 4", None),
            ("exit 1", None),
        ] {
            let script = helper(directory, body);
            assert_eq!(
                probe_protocol_within(&script, answer).await,
                expected,
                "{body}"
            );
        }
        assert_eq!(
            probe_protocol_within(&directory.join("absent"), answer).await,
            None
        );
        let silent = helper(directory, "sleep 5");
        assert_eq!(
            probe_protocol_within(&silent, std::time::Duration::from_millis(100)).await,
            None
        );
    }

    /// A probe with no answer is asked again; a definite one is kept.
    #[tokio::test]
    async fn only_a_definite_probe_is_kept() {
        let temporary = tempfile::tempdir().unwrap();
        let script = helper(temporary.path(), "exit 1");
        let cache = ProtocolCache::default();
        assert_eq!(cache.schema(&script).await, SCHEMA_VERSION);
        helper(temporary.path(), "echo 3");
        assert_eq!(cache.schema(&script).await, CHECKPOINTING_SCHEMA_VERSION);
        helper(temporary.path(), "exit 2");
        assert_eq!(cache.schema(&script).await, CHECKPOINTING_SCHEMA_VERSION);
    }

    #[test]
    fn a_kept_machine_identifier_is_read_or_refused() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let vm = PrivateRoot::open(temporary.path()).unwrap();
        assert_eq!(read_machine_identifier(&vm).unwrap(), None);
        let file = temporary.path().join(MACHINE_IDENTIFIER_NAME);
        std::fs::write(&file, "YnBsaXN0MDA=\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_machine_identifier(&vm).unwrap().as_deref(),
            Some("YnBsaXN0MDA=")
        );
        std::fs::write(&file, "not base64!\n").unwrap();
        assert!(matches!(
            read_machine_identifier(&vm),
            Err(RunnerError::VzMachineIdentifier)
        ));
    }
}
