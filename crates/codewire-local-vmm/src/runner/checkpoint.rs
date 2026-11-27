//! VM checkpoints of a running VM (#3046 R4), a child of `runner`.
//!
//! A capture freezes the guest's workload through PID 1's checkpoint hook,
//! pauses the VM, has the VMM write its memory and device state, clones its
//! writable disks, resumes it and thaws the workload. Everything lands in
//! `vms/<id>/checkpoints/out-<operation>`. On Linux that is the one directory
//! Landlock lets Cloud Hypervisor write; on macOS the helper writes only its
//! `saveState` file, which the runner moves in (`vz`, #4654). The supervisor
//! takes that tree over and admits it as untrusted input before it publishes
//! anything. Restoring one is Linux-only for now.

#[cfg(target_os = "linux")]
mod sleep;
#[cfg(target_os = "linux")]
pub use sleep::Hibernation;
#[cfg(target_os = "macos")]
mod vz;
#[cfg(target_os = "macos")]
pub(super) use vz::{RestoreInput, restore_configuration, restore_input};

use std::time::Instant;

use codewire_vmm_guest_probe::{
    CHECKPOINT_HELLO_LEN, CHECKPOINT_HOST_ENTROPY_LEN, CHECKPOINT_REPLY_LEN, CheckpointAction,
    CheckpointHello, CheckpointKey, CheckpointReply, CheckpointRequest, CheckpointStatus,
    GUEST_CHECKPOINT_ABI, GUEST_CHECKPOINT_THAW_CLOCK_ABI, GUEST_CHECKPOINT_VSOCK_PORT,
};

use super::*;
use crate::state::{
    CHECKPOINT_OUT_PREFIX, CHECKPOINT_VMM_FILES, checkpoint_tree_names, remove_checkpoint_tree,
};

/// One hook exchange, connect to reply.
const HOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// Writing the memory: a base, plus a second for every GiB.
const SNAPSHOT_BASE_TIMEOUT: Duration = Duration::from_secs(30);

/// What one capture left in `checkpoints/out-<operation>`.
#[derive(Debug, Clone)]
pub struct CheckpointCapture {
    pub timings: CaptureTimings,
    pub memory_bytes: u64,
    pub guest_abi: u32,
    /// The captured boot's setup disk, when it had one.
    pub setup_disk_bytes: Option<u64>,
    /// The image disk the captured boot sat on, which its restore must
    /// attach (#4646); the disk itself is never copied.
    pub image_disk: Option<CheckpointImageDisk>,
    /// The checkpoint is complete, but the VM did not resume.
    pub resume_failed: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureTimings {
    pub guest_freeze: Duration,
    pub workload_frozen: Duration,
    pub vm_paused: Duration,
    pub memory_write: Duration,
    pub disk_clone: Duration,
}

impl CloudHypervisorRunner {
    /// The pinned VMM's release and sha256, which a checkpoint restores only
    /// into.
    #[cfg(target_os = "linux")]
    pub fn vmm_identity(&self) -> (&'static str, String) {
        (
            crate::artifact::CLOUD_HYPERVISOR_RELEASE,
            self.artifacts.cloud_hypervisor.sha256().to_owned(),
        )
    }

    /// The pinned helper's schema and sha256, which a checkpoint restores
    /// only into (#4654 design §6).
    #[cfg(target_os = "macos")]
    pub fn vmm_identity(&self) -> (&'static str, String) {
        (
            crate::vz::CHECKPOINT_VMM_VERSION,
            self.artifacts.vz_runner.sha256().to_owned(),
        )
    }

    /// The hook ABI a capture's requests use. A Mac's guest clocks stop while
    /// its VM is paused, so a Mac guest whose init carries the marker gets
    /// ABI 2, whose `Thaw` steps its clock; Linux keeps ABI 1 (#4654).
    pub(crate) fn guest_checkpoint_request_abi(&self) -> Result<u32, RunnerError> {
        #[cfg(target_os = "macos")]
        if self.artifacts.guest_checkpoint_thaw_clock()? {
            return Ok(GUEST_CHECKPOINT_THAW_CLOCK_ABI);
        }
        Ok(GUEST_CHECKPOINT_ABI)
    }
}

impl RunningVm {
    /// The seed bindings this boot's guest applied, which a restore must
    /// repeat exactly.
    pub(crate) fn boot_bindings(&self) -> &CreateVmRequest {
        &self.request
    }

    pub(crate) fn has_docker_disk(&self) -> bool {
        self.docker_disk.is_some()
    }

    /// What the guest reported, when this boot resumed from a VM checkpoint.
    pub(crate) fn restore_report(&self) -> Option<RestoreReport> {
        self.restored
    }

    /// Capture a VM checkpoint into `checkpoints/out-<operation_id>`, with
    /// hook requests of ABI `abi`. On any failure the VM is running and thawed
    /// again, as far as it can be, and the tree is removed.
    pub async fn checkpoint(
        &mut self,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<CheckpointCapture, RunnerError> {
        if !matches!(self.try_exit()?, ExitClass::StillRunning) {
            return Err(RunnerError::Checkpoint("the VM is not running"));
        }
        let checkpoints = PrivateRoot::open(&self.paths.checkpoints_dir)?;
        // A capture an earlier runner left unfinished.
        for name in checkpoint_tree_names(&checkpoints)? {
            if name.starts_with(CHECKPOINT_OUT_PREFIX) {
                remove_checkpoint_tree(&checkpoints, &name)?;
            }
        }
        let out_name = format!("{CHECKPOINT_OUT_PREFIX}{operation_id}");
        let out = checkpoints.create_dir(Path::new(&out_name), 0o700)?;
        let result = self.capture_into(&out, operation_id, abi).await;
        if result.is_err() {
            let _ = remove_checkpoint_tree(&checkpoints, &out_name);
        }
        result
    }

    async fn capture_into(
        &mut self,
        out: &Path,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<CheckpointCapture, RunnerError> {
        let out_root = PrivateRoot::open(out)?;
        let vmm = out_root.create_dir(Path::new("vmm"), 0o700)?;
        let disks = out_root.create_dir(Path::new("disks"), 0o700)?;
        let root = out_root.create_dir(Path::new("root"), 0o700)?;
        let generation_dir = PrivateRoot::open(&root)?
            .create_dir(Path::new(&self.request.root_generation), 0o700)?;

        let frozen_at = Instant::now();
        let freeze = self
            .hook(CheckpointAction::Freeze, operation_id, abi)
            .await?;
        if freeze.status != CheckpointStatus::Done {
            // A failed freeze has thawed again in the guest.
            return Err(RunnerError::Checkpoint(
                "the guest could not freeze its workload; a process may be stuck in I/O, so try again",
            ));
        }
        let captured = self.pause_and_capture(&vmm, &disks, &generation_dir).await;
        // The workload thaws on every path once the VM runs again.
        let thawed = match &captured {
            Ok((_, false)) | Err(_) => self.hook(CheckpointAction::Thaw, operation_id, abi).await,
            Ok((_, true)) => Ok(freeze),
        };
        let workload_frozen = frozen_at.elapsed();
        let (mut timings, resume_failed) = captured?;
        if !resume_failed {
            let thawed = thawed?;
            if thawed.status != CheckpointStatus::Done {
                return Err(RunnerError::Checkpoint(
                    "the guest did not thaw its workload after the checkpoint",
                ));
            }
        }
        timings.guest_freeze = Duration::from_micros(freeze.elapsed_us);
        timings.workload_frozen = workload_frozen;

        // Outside the pause: everything durable before the supervisor sees it.
        let memory_bytes = seal_vmm_files(&vmm, self.request.memory_mib)?;
        for directory in [&disks, &generation_dir, &root, &out.to_owned()] {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| PathError::Io {
                    path: directory.clone(),
                    source,
                })?;
        }
        Ok(CheckpointCapture {
            timings,
            memory_bytes,
            guest_abi: abi,
            setup_disk_bytes: self.setup_disk.as_ref().map(|setup| setup.file.size),
            image_disk: self
                .request
                .image_disk
                .as_ref()
                .map(CheckpointImageDisk::from),
            resume_failed,
        })
    }

    /// Each writable disk and the clone a capture makes of it.
    fn disk_clones(
        &self,
        disks: &Path,
        generation_dir: &Path,
    ) -> Result<Vec<(PathBuf, PathBuf)>, RunnerError> {
        let mut clones = vec![
            (self.paths.state_disk.clone(), disks.join("state.raw")),
            (
                RootGenerationPaths::create(&self.paths, &self.request.root_generation)?.root_disk,
                generation_dir.join("root.raw"),
            ),
        ];
        if self.docker_disk.is_some() {
            clones.push((self.paths.docker_disk.clone(), disks.join("docker.raw")));
        }
        Ok(clones)
    }

    /// Pause, write the VMM's state, clone the disks, resume. Returns the
    /// timings and whether the resume failed after a complete capture.
    #[cfg(target_os = "linux")]
    async fn pause_and_capture(
        &mut self,
        vmm: &Path,
        disks: &Path,
        generation_dir: &Path,
    ) -> Result<(CaptureTimings, bool), RunnerError> {
        let clones = self.disk_clones(disks, generation_dir)?;
        let mut timings = CaptureTimings::default();
        let paused_at = Instant::now();
        self.api.pause().await?;
        let captured = async {
            let started = Instant::now();
            self.api
                .snapshot(vmm, snapshot_timeout(self.request.memory_mib))
                .await?;
            timings.memory_write = started.elapsed();
            let started = Instant::now();
            for (source, destination) in &clones {
                clone_disk(source, destination)?;
            }
            timings.disk_clone = started.elapsed();
            Ok::<_, RunnerError>(())
        }
        .await;
        let resumed = self.api.resume().await;
        timings.vm_paused = paused_at.elapsed();
        match (captured, resumed) {
            (Ok(()), Ok(())) => Ok((timings, false)),
            // Consistent and complete: kept, and the VM is reported failed.
            (Ok(()), Err(_)) => Ok((timings, true)),
            (Err(error), Ok(())) => Err(error),
            (Err(_), Err(_)) => Err(RunnerError::Checkpoint(
                "the checkpoint failed and the VM did not resume",
            )),
        }
    }

    /// One authenticated exchange with the guest's checkpoint hook, as this
    /// boot. An ABI 2 `Thaw` carries the host's clock.
    async fn hook(
        &self,
        action: CheckpointAction,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<CheckpointReply, RunnerError> {
        let host_time_ns =
            if action == CheckpointAction::Thaw && abi == GUEST_CHECKPOINT_THAW_CLOCK_ABI {
                host_time_ns()?
            } else {
                0
            };
        hook_exchange(
            &self.hybrid.socket,
            &self.token,
            CheckpointRequest {
                abi,
                action,
                operation_id,
                vm_id: self.request.vm_id,
                generation: self.request.generation,
                host_entropy: [0; CHECKPOINT_HOST_ENTROPY_LEN],
                host_time_ns,
            },
        )
        .await
    }
}

/// Send `request` to the guest's checkpoint hook over `socket`, MACed with
/// the key of `token` and the request's identity, and read its answer.
pub(crate) async fn hook_exchange(
    socket: &Path,
    token: &str,
    request: CheckpointRequest,
) -> Result<CheckpointReply, RunnerError> {
    let key = CheckpointKey::derive(token, request.vm_id, request.generation)
        .map_err(|_| RunnerError::Checkpoint("the checkpoint hook key is invalid"))?;
    tokio::time::timeout(HOOK_TIMEOUT, async {
        let mut stream =
            crate::hybrid_vsock::connect_hybrid_vsock(socket, GUEST_CHECKPOINT_VSOCK_PORT).await?;
        let mut hello = [0_u8; CHECKPOINT_HELLO_LEN];
        stream
            .read_exact(&mut hello)
            .await
            .map_err(|_| RunnerError::Checkpoint("the guest's checkpoint hook did not answer"))?;
        let hello = CheckpointHello::decode(&hello)
            .map_err(|_| RunnerError::Checkpoint("the guest's checkpoint hook is invalid"))?;
        if hello.abi != GUEST_CHECKPOINT_ABI {
            return Err(RunnerError::Checkpoint(
                "the guest speaks another checkpoint hook protocol",
            ));
        }
        let bytes = request
            .encode(&key, &hello.challenge)
            .map_err(|_| RunnerError::Checkpoint("the checkpoint request is invalid"))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| RunnerError::Checkpoint("the checkpoint request was not sent"))?;
        let mut reply = [0_u8; CHECKPOINT_REPLY_LEN];
        stream.read_exact(&mut reply).await.map_err(|_| {
            RunnerError::Checkpoint("the guest refused or dropped the checkpoint request")
        })?;
        CheckpointReply::decode(&reply, &key, &hello.challenge, &request)
            .map_err(|_| RunnerError::Checkpoint("the guest's checkpoint reply is invalid"))
    })
    .await
    .map_err(|_| RunnerError::Checkpoint("the guest's checkpoint hook timed out"))?
}

/// The host's wall clock, in nanoseconds since the epoch.
fn host_time_ns() -> Result<u64, RunnerError> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RunnerError::Checkpoint("the host clock is before the epoch"))?
            .as_nanos(),
    )
    .map_err(|_| RunnerError::Checkpoint("the host clock is out of range"))
}

fn snapshot_timeout(memory_mib: u32) -> Duration {
    SNAPSHOT_BASE_TIMEOUT + Duration::from_secs(u64::from(memory_mib).div_ceil(1024))
}

/// Clone `source` into the new `destination` (0600) by reflink only: a copy
/// would hold the VM paused for as long as it took.
fn clone_disk(source: &Path, destination: &Path) -> Result<(), RunnerError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let io_error = |path: &Path, source: io::Error| PathError::Io {
        path: path.to_owned(),
        source,
    };
    let source_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| io_error(source, error))?;
    let target = crate::fs_clone::clone_new(&source_file, destination).map_err(|_| {
        RunnerError::Checkpoint(
            "the disks could not be cloned; VM checkpoints need a filesystem that shares blocks (btrfs or XFS)",
        )
    })?;
    target
        .sync_all()
        .map_err(|error| io_error(destination, error))?;
    Ok(())
}

/// How long a stop waits for the VMM to exit by itself before it signals
/// it. A restore's stop discards the guest's state: on Linux Cloud
/// Hypervisor is told to end at once (`vm.shutdown` would leave it up until
/// the bound), and a Mac's helper has no such call, so there it is
/// signalled at once rather than after the bound (#6124).
pub(super) fn vmm_exit_wait(discard_guest_state: bool) -> Duration {
    if discard_guest_state && cfg!(target_os = "macos") {
        Duration::ZERO
    } else {
        GRACEFUL_STOP_TIMEOUT
    }
}

/// Sync the VMM's checkpoint files and their directory, make the files
/// read-only (0400), and return the memory image size in bytes.
pub(super) fn seal_vmm_files(vmm: &Path, memory_mib: u32) -> Result<u64, RunnerError> {
    #[cfg(target_os = "linux")]
    let _ = memory_mib;
    for name in CHECKPOINT_VMM_FILES {
        let path = vmm.join(name);
        let io_error = |source| PathError::Io {
            path: path.clone(),
            source,
        };
        let file = File::open(&path).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .map_err(io_error)?;
    }
    // Cloud Hypervisor writes the memory as it is; Virtualization.framework's
    // saved state is opaque, so the VM's memory is what it saved.
    #[cfg(target_os = "linux")]
    let memory_bytes = std::fs::metadata(vmm.join("memory-ranges"))
        .map_err(|source| PathError::Io {
            path: vmm.join("memory-ranges"),
            source,
        })?
        .len();
    #[cfg(target_os = "macos")]
    let memory_bytes = u64::from(memory_mib) << 20;
    File::open(vmm)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| PathError::Io {
            path: vmm.to_owned(),
            source,
        })?;
    Ok(memory_bytes)
}

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;

#[cfg(test)]
mod tests {
    use super::*;

    /// A Mac's restore stop never waits out the graceful bound: it took
    /// 5.0 s of every Mac restore (#6124).
    #[test]
    fn a_restores_stop_signals_a_macs_helper_at_once() {
        assert_eq!(vmm_exit_wait(false), GRACEFUL_STOP_TIMEOUT);
        let discarding = if cfg!(target_os = "macos") {
            Duration::ZERO
        } else {
            GRACEFUL_STOP_TIMEOUT
        };
        assert_eq!(vmm_exit_wait(true), discarding);
    }

    #[test]
    fn memory_writes_get_more_time_for_more_memory() {
        assert_eq!(snapshot_timeout(512), Duration::from_secs(31));
        assert_eq!(snapshot_timeout(4096), Duration::from_secs(34));
        assert_eq!(snapshot_timeout(65_536), Duration::from_secs(94));
    }

    #[test]
    fn a_clone_is_a_reflink_or_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.raw");
        std::fs::write(&source, vec![7_u8; 1 << 20]).unwrap();
        let destination = directory.path().join("clone.raw");
        match clone_disk(&source, &destination) {
            Ok(()) => assert_eq!(
                std::fs::read(&destination).unwrap(),
                std::fs::read(&source).unwrap()
            ),
            Err(RunnerError::Checkpoint(message)) => {
                assert!(message.contains("shares blocks"), "{message}");
            }
            Err(other) => panic!("{other}"),
        }
        // An existing destination is never replaced.
        assert!(clone_disk(&source, &source).is_err());
    }

    /// A published disk directory holding `build`, and an attachment that
    /// names it with `named_build`.
    fn published(
        directory: &Path,
        build: &str,
        named_build: &str,
    ) -> (ImageDiskAttachment, CheckpointImageDisk) {
        use crate::image_disk::{IMAGE_DISK_FORMAT_VERSION, ImageDiskRecord, image_disk_id};
        let id = image_disk_id("amd64", &"1".repeat(64)).unwrap();
        let record = ImageDiskRecord {
            schema_version: 1,
            image_disk_id: id.clone(),
            build_id: build.to_owned(),
            format_version: IMAGE_DISK_FORMAT_VERSION,
            architecture: "amd64".to_owned(),
            manifest_sha256: "1".repeat(64),
            disk_bytes: 8192,
        };
        std::fs::write(
            directory.join("record.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("image.raw"), vec![0_u8; 8192]).unwrap();
        let attachment = ImageDiskAttachment::Published {
            directory: directory.to_owned(),
            image_disk_id: id,
            build_id: named_build.to_owned(),
        };
        let recorded = CheckpointImageDisk::from(&attachment);
        (attachment, recorded)
    }

    #[test]
    fn a_restore_attaches_exactly_the_image_disk_its_checkpoint_names() {
        let engine = tempfile::tempdir().unwrap();
        std::fs::set_permissions(engine.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::open(engine.path()).unwrap();
        let disk = tempfile::tempdir().unwrap();
        let build = crate::image_disk::new_build_id();
        let (attachment, recorded) = published(disk.path(), &build, &build);
        let refusal = |named, recorded| match admit_restored_image_disk(&engine, named, recorded) {
            Err(RunnerError::RestoreImageDisk(error)) => error,
            other => panic!("{other:?}"),
        };

        admit_restored_image_disk(&engine, None, None).unwrap();
        admit_restored_image_disk(&engine, Some(&attachment), Some(&recorded)).unwrap();
        assert_eq!(
            refusal(None, Some(&recorded)),
            RestoreImageDiskError::NotNamed(recorded.clone())
        );
        assert_eq!(
            refusal(Some(&attachment), None),
            RestoreImageDiskError::NotRecorded(recorded.clone())
        );
        let other_build = crate::image_disk::new_build_id();
        let (other, named) = published(disk.path(), &build, &other_build);
        assert_eq!(
            refusal(Some(&other), Some(&recorded)),
            RestoreImageDiskError::Other {
                recorded: recorded.clone(),
                named,
            }
        );

        // The disk was rebuilt after the checkpoint: the boot names the
        // checkpoint's build, and the host holds another.
        let rebuilt = crate::image_disk::new_build_id();
        let (attachment, recorded) = published(disk.path(), &rebuilt, &build);
        let error = refusal(Some(&attachment), Some(&recorded));
        let message = RunnerError::from(error.clone()).to_string();
        assert_eq!(
            error,
            RestoreImageDiskError::Rebuilt {
                recorded,
                found: rebuilt.clone(),
            }
        );
        assert!(
            message.contains(&build) && message.contains(&rebuilt),
            "{message}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_request_allows_image_disk_with_checkpoint_on_linux() {
        let build = crate::image_disk::new_build_id();
        let image_disk_id = crate::image_disk::image_disk_id("amd64", &"1".repeat(64)).unwrap();
        let attachment = ImageDiskAttachment::Published {
            directory: PathBuf::from("/image"),
            image_disk_id: image_disk_id.clone(),
            build_id: build.clone(),
        };
        let request = CreateVmRequest {
            vm_id: Uuid::new_v4(),
            generation: 2,
            vsock_cid: 10,
            daemon_vsock_port: 7777,
            state_disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: None,
            root_generation: "a".repeat(64),
            root_disk_bytes: crate::runner::MINIMUM_ROOT_DISK_BYTES,
            vcpus: 2,
            memory_mib: 512,
            setup: None,
            host_ports: Vec::new(),
            mesh: None,
            direct_shares: Vec::new(),
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: Default::default(),
            cw_runtime_catalog_generation: None,
            cw_runtime_moved_from_generation: None,
            image_disk: Some(attachment),
            network_policy: codewire_egress_policy::CompiledPolicy::locked(),
            udp_peers: Vec::new(),
            intercepts: Default::default(),
            credential_placeholders: Default::default(),
            checkpoint: Some(RestoreBoot {
                checkpoint_id: Uuid::new_v4(),
                source_environment_id: Uuid::new_v4(),
                config_sha256: "b".repeat(64),
                state_sha256: "c".repeat(64),
                memory_bytes: 512 * 1024 * 1024,
                setup_disk_bytes: None,
                vmm_sha256: "d".repeat(64),
                source_generation: 1,
                skill_snapshot_sha256: None,
                environment_projection_sha256: None,
                managed_credential_clients: Default::default(),
                docker: false,
                cw_runtime_catalog_generation: None,
                daemon_vsock_port: 7777,
                intercept: false,
                image_disk: Some(CheckpointImageDisk {
                    image_disk_id,
                    build_id: build,
                }),
                state_identity: None,
            }),
        };
        crate::runner::validate_request(&request).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Restore.

/// A boot restored from the VM checkpoint the supervisor placed in
/// `checkpoints/in` (`StartVmRequest.checkpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreBoot {
    pub checkpoint_id: Uuid,
    pub source_environment_id: Uuid,
    pub config_sha256: String,
    pub state_sha256: String,
    pub memory_bytes: u64,
    pub setup_disk_bytes: Option<u64>,
    pub vmm_sha256: String,
    pub source_generation: u64,
    /// What the captured guest applied at boot.
    pub skill_snapshot_sha256: Option<Sha256Value>,
    pub environment_projection_sha256: Option<Sha256Value>,
    pub managed_credential_clients: codewire_access::ManagedCredentialClients,
    pub docker: bool,
    pub cw_runtime_catalog_generation: Option<String>,
    pub daemon_vsock_port: u32,
    /// The captured boot intercepted agent hosts (#3999).
    pub intercept: bool,
    /// The image disk the captured boot sat on (#4646).
    pub image_disk: Option<CheckpointImageDisk>,
    /// On a Mac, the identity the supervisor pinned for the saved state it
    /// cloned into `checkpoints/in`: a match skips the digest (#6124).
    pub(crate) state_identity: Option<crate::checkpoint_pin::StateIdentity>,
}

/// The image disk a checkpointed boot sat on: which disk and which build.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointImageDisk {
    pub image_disk_id: String,
    pub build_id: String,
}

impl From<&ImageDiskAttachment> for CheckpointImageDisk {
    fn from(disk: &ImageDiskAttachment) -> Self {
        Self {
            image_disk_id: disk.image_disk_id().to_owned(),
            build_id: disk.build_id().to_owned(),
        }
    }
}

impl std::fmt::Display for CheckpointImageDisk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "image disk {} build {}",
            self.image_disk_id, self.build_id
        )
    }
}

/// Why a restore's boot cannot attach the image disk its checkpoint names.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RestoreImageDiskError {
    #[error("this VM checkpoint was taken over {0}, and this boot names no image disk")]
    NotNamed(CheckpointImageDisk),
    #[error("this VM checkpoint was taken on a combined root disk, and this boot names {0}")]
    NotRecorded(CheckpointImageDisk),
    #[error("this VM checkpoint was taken over {recorded}, and this boot names {named}")]
    Other {
        recorded: CheckpointImageDisk,
        named: CheckpointImageDisk,
    },
    #[error(
        "this VM checkpoint was taken over {recorded}, and the disk on this host is build \
         {found}; a VM checkpoint restores only onto the build it was taken on"
    )]
    Rebuilt {
        recorded: CheckpointImageDisk,
        found: String,
    },
}

/// What the guest reported when the restored VM resumed.
#[derive(Debug, Clone, Copy)]
pub struct RestoreReport {
    pub reseeded: bool,
    pub vmgenid_driver: bool,
    pub removed_logins: bool,
    pub clock_skew_ms: i64,
    /// Admitting and rewriting the checkpoint's VMM configuration.
    pub admit: Duration,
    /// Starting the direct shares' virtiofsd processes.
    pub shares: Duration,
    /// From spawning the VMM until it answers: Cloud Hypervisor with
    /// `--restore` and its API, or the macOS helper with `restoreState` and
    /// its vsock endpoint.
    pub vmm: Duration,
    pub resume: Duration,
    pub thaw: Duration,
}

const SETUP_PLACEHOLDER: &str = "setup.raw";

impl CloudHypervisorRunner {
    /// Refuse a restore this runner cannot make exactly: another VMM build,
    /// a guest without the hook, a boot whose seed bindings differ from the
    /// captured guest's, or direct shares.
    pub(super) fn admit_restore(
        &self,
        request: &CreateVmRequest,
        restore: &RestoreBoot,
    ) -> Result<(), RunnerError> {
        self.artifacts.require_guest_checkpoint_abi()?;
        #[cfg(target_os = "linux")]
        let (vmm_sha256, another_build) = (
            self.artifacts.cloud_hypervisor.sha256(),
            "the VM checkpoint was taken by another Cloud Hypervisor build; it restores only into its own",
        );
        #[cfg(target_os = "macos")]
        let (vmm_sha256, another_build) = (
            self.artifacts.vz_runner.sha256(),
            "the VM checkpoint was taken by another VZ helper build; it restores only into its own",
        );
        if vmm_sha256 != restore.vmm_sha256 {
            return Err(RunnerError::Checkpoint(another_build));
        }
        if request.setup.is_some() {
            return Err(RunnerError::Checkpoint("a restored VM has no setup pack"));
        }
        super::intercept::admit_restored_interception(restore.intercept, &request.intercepts)?;
        if request.skill_snapshot_sha256 != restore.skill_snapshot_sha256
            || request.environment_projection_sha256 != restore.environment_projection_sha256
            || request.managed_credential_clients != restore.managed_credential_clients
            || request.docker_disk_bytes.is_some() != restore.docker
            || request.cw_runtime_catalog_generation != restore.cw_runtime_catalog_generation
            || request.daemon_vsock_port != restore.daemon_vsock_port
            || request.generation <= restore.source_generation
                && request.vm_id == restore.source_environment_id
        {
            return Err(RunnerError::Checkpoint(
                "this boot's bindings differ from the checkpointed guest's",
            ));
        }
        admit_restored_image_disk(
            &self.state_root,
            request.image_disk.as_ref(),
            restore.image_disk.as_ref(),
        )
    }

    /// The restore command for `config`: admit the checkpoint's VMM files in
    /// `checkpoints/in`, rewrite its configuration to this VM's paths, and
    /// return `cloud-hypervisor --restore` of them.
    #[cfg(target_os = "linux")]
    pub(super) fn restore_command(
        &self,
        paths: &VmPaths,
        config: &CloudHypervisorConfig,
        restore: &RestoreBoot,
    ) -> Result<CommandSpec, RunnerError> {
        use crate::cloud_hypervisor_restore::{RestoreDisk, RestoreTarget, admit_and_rewrite};
        let checkpoints = PrivateRoot::open(&paths.checkpoints_dir)?;
        let input = checkpoints.open_private_directory(Path::new(CHECKPOINT_IN), 0o700)?;
        let read = |name: &str, limit: usize| -> Result<Vec<u8>, RunnerError> {
            let opened = input.open_regular(Path::new(name), false, None, false, Some(0o400))?;
            let mut bytes = Vec::new();
            io::Read::read_to_end(
                &mut io::Read::take(opened.file(), limit as u64 + 1),
                &mut bytes,
            )
            .map_err(|source| PathError::Io {
                path: input.path().join(name),
                source,
            })?;
            if bytes.len() > limit {
                return Err(RunnerError::Checkpoint("a VM checkpoint file is too large"));
            }
            Ok(bytes)
        };
        let captured = read(
            "config.json",
            crate::cloud_hypervisor_restore::MAXIMUM_CONFIG_BYTES,
        )?;
        let state = read("state.json", 64 * 1024 * 1024)?;
        if format!("{:x}", Sha256::digest(&captured)) != restore.config_sha256
            || format!("{:x}", Sha256::digest(&state)) != restore.state_sha256
        {
            return Err(RunnerError::Checkpoint(
                "the placed VM checkpoint is not the recorded one",
            ));
        }
        input.open_regular(
            Path::new("memory-ranges"),
            false,
            Some(restore.memory_bytes),
            false,
            Some(0o400),
        )?;
        let mut target = RestoreTarget {
            vcpus: config.vcpus,
            memory_mib: config.memory_mib,
            vsock_cid: config.vsock_cid,
            disks: Default::default(),
            vsock_socket: config.vsock_socket.clone(),
            checkpoint_dir: paths.checkpoints_dir.clone(),
            kernel: config.kernel.clone(),
            initramfs: config.initramfs.clone(),
            // Each direct share's fresh virtiofsd, which Cloud Hypervisor
            // gives the saved filesystem state to (R4b).
            virtiofs: config
                .virtiofs
                .iter()
                .map(|share| (share.tag.clone(), share.socket.clone()))
                .collect(),
        }
        .with_disk(RestoreDisk::State, config.state_disk.clone())
        .with_disk(RestoreDisk::Root, config.root_disk.clone())
        .with_disk(RestoreDisk::Seed, config.seed_disk.clone());
        if let Some(docker) = &config.docker_disk {
            target = target.with_disk(RestoreDisk::Docker, docker.clone());
        }
        if let Some(runtime) = &config.cw_runtime_disk {
            target = target.with_disk(RestoreDisk::CwRuntime, runtime.clone());
        }
        if let Some(image) = &config.image_disk {
            target = target.with_disk(RestoreDisk::Image, image.clone());
        }
        if let Some(bytes) = restore.setup_disk_bytes {
            // The guest read its setup disk only while it booted; the device
            // must exist for its restored state, so it gets an empty one.
            let placeholder = input.create_regular(Path::new(SETUP_PLACEHOLDER), 0o600, true)?;
            placeholder
                .file()
                .set_len(bytes)
                .and_then(|()| placeholder.file().sync_all())
                .and_then(|()| {
                    placeholder
                        .file()
                        .set_permissions(std::fs::Permissions::from_mode(0o400))
                })
                .map_err(|source| PathError::Io {
                    path: input.path().join(SETUP_PLACEHOLDER),
                    source,
                })?;
            target = target.with_disk(RestoreDisk::Setup, input.path().join(SETUP_PLACEHOLDER));
        }
        let rewritten = admit_and_rewrite(&captured, &target).map_err(|error| match error {
            crate::cloud_hypervisor_restore::RestoreConfigError::Refused(reason) => {
                RunnerError::Checkpoint(reason)
            }
        })?;
        input.remove_private_regular(Path::new("config.json"), 0o400)?;
        let written = input.create_regular(Path::new("config.json"), 0o600, true)?;
        written
            .file()
            .write_all_at(&rewritten, 0)
            .and_then(|()| written.file().sync_all())
            .and_then(|()| {
                written
                    .file()
                    .set_permissions(std::fs::Permissions::from_mode(0o400))
            })
            .map_err(|source| PathError::Io {
                path: input.path().join("config.json"),
                source,
            })?;
        let arguments =
            crate::cloud_hypervisor_restore::restore_arguments(&paths.api_socket, input.path())
                .map_err(|_| RunnerError::Checkpoint("the restore command is invalid"))?;
        Ok(CommandSpec::restore(config.executable.clone(), arguments))
    }
}

/// Admit the image disk a restore attaches: exactly the one its checkpoint
/// names, by id and build. The restored memory holds that disk mounted, so
/// the resumed guest cannot check it again; this is the only check (design
/// section 5 of #4646). Prepare admits the disk again for the attachment.
fn admit_restored_image_disk(
    engine_root: &PrivateRoot,
    named: Option<&ImageDiskAttachment>,
    recorded: Option<&CheckpointImageDisk>,
) -> Result<(), RunnerError> {
    let refused = match (named, recorded) {
        (None, None) => return Ok(()),
        (Some(named), None) => RestoreImageDiskError::NotRecorded(named.into()),
        (None, Some(recorded)) => RestoreImageDiskError::NotNamed(recorded.clone()),
        (Some(named), Some(recorded)) if CheckpointImageDisk::from(named) != *recorded => {
            RestoreImageDiskError::Other {
                recorded: recorded.clone(),
                named: named.into(),
            }
        }
        (Some(named), Some(recorded)) => match named.admit(engine_root) {
            Ok(_) => return Ok(()),
            Err(ImageDiskError::BuildMismatch { found, .. }) => RestoreImageDiskError::Rebuilt {
                recorded: recorded.clone(),
                found,
            },
            Err(other) => return Err(other.into()),
        },
    };
    Err(refused.into())
}

/// State between `CheckpointAction::Resume` (workload still frozen, boot
/// identity moved) and `CheckpointAction::Thaw` (#6647).
pub(super) struct FrozenRestore {
    operation_id: Uuid,
    resumed: CheckpointReply,
    resume_elapsed: Duration,
}

/// Step 1 of restoring a VM: run `CheckpointAction::Resume` while `/workload`
/// remains frozen, reseeding RNG, stepping clock, rotating boot identity, and
/// (on hosted guests) deleting the old daemon credential and arming
/// `RestoreSettings` (#6647).
pub(super) async fn resume_restored_frozen(
    socket: &Path,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    abi: u32,
) -> Result<FrozenRestore, RunnerError> {
    let operation_id = Uuid::new_v4();
    let mut host_entropy = [0_u8; CHECKPOINT_HOST_ENTROPY_LEN];
    OsRng.fill_bytes(&mut host_entropy);
    let resume_time_ns = host_time_ns()?;
    let started = Instant::now();
    let resumed = hook_exchange(
        socket,
        token,
        CheckpointRequest {
            abi,
            action: CheckpointAction::Resume,
            operation_id,
            vm_id,
            generation,
            host_entropy,
            host_time_ns: resume_time_ns,
        },
    )
    .await?;
    if resumed.status != CheckpointStatus::Done || !resumed.resume.reseeded {
        return Err(RunnerError::Checkpoint(
            "the restored guest refused to move to this boot's identity",
        ));
    }
    Ok(FrozenRestore {
        operation_id,
        resumed,
        resume_elapsed: started.elapsed(),
    })
}

/// Step 2 of restoring a VM: run `CheckpointAction::Thaw` after any pre-thaw
/// hosted restore settings/tokens handover has completed (#6647).
pub(super) async fn thaw_restored(
    frozen: FrozenRestore,
    socket: &Path,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    abi: u32,
) -> Result<RestoreReport, RunnerError> {
    let started = Instant::now();
    let thawed = hook_exchange(
        socket,
        token,
        CheckpointRequest {
            abi,
            action: CheckpointAction::Thaw,
            operation_id: frozen.operation_id,
            vm_id,
            generation,
            host_entropy: [0; CHECKPOINT_HOST_ENTROPY_LEN],
            // A Mac guest's clocks stopped while it was saved (#4654).
            host_time_ns: if abi == GUEST_CHECKPOINT_THAW_CLOCK_ABI {
                host_time_ns()?
            } else {
                0
            },
        },
    )
    .await?;
    if thawed.status != CheckpointStatus::Done {
        return Err(RunnerError::Checkpoint(
            "the restored guest did not thaw its workload",
        ));
    }
    Ok(RestoreReport {
        reseeded: frozen.resumed.resume.reseeded,
        vmgenid_driver: frozen.resumed.resume.vmgenid_driver,
        removed_logins: frozen.resumed.resume.removed_logins,
        clock_skew_ms: frozen.resumed.clock_skew_ms,
        admit: Duration::ZERO,
        shares: Duration::ZERO,
        vmm: Duration::ZERO,
        resume: frozen.resume_elapsed,
        thaw: started.elapsed(),
    })
}

/// Resume a VM restored from a VM checkpoint, its workload still frozen:
/// the guest reseeds its RNG with host entropy and moves every boot-scoped
/// secret to this boot's seed, then thaws. Any failure leaves the workload
/// frozen; the caller kills the VMM.
pub(super) async fn resume_restored(
    socket: &Path,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    abi: u32,
) -> Result<RestoreReport, RunnerError> {
    let frozen = resume_restored_frozen(socket, token, vm_id, generation, abi).await?;
    thaw_restored(frozen, socket, token, vm_id, generation, abi).await
}

/// Remove the VM checkpoint an earlier boot restored from: no VMM maps it
/// any more. A restoring boot keeps the one just placed.
pub(super) fn remove_restored_input(paths: &VmPaths) -> Result<(), RunnerError> {
    let checkpoints = PrivateRoot::open(&paths.checkpoints_dir)?;
    remove_checkpoint_tree(&checkpoints, CHECKPOINT_IN)?;
    Ok(())
}

use crate::state::CHECKPOINT_IN;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt as _;
