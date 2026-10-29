//! VM checkpoints of a running VM (#3046 R4), a child of `runner`.
//!
//! A capture freezes the guest's workload through PID 1's checkpoint hook,
//! pauses the VM, has Cloud Hypervisor write its memory and device state,
//! clones its writable disks, resumes it and thaws the workload. Everything
//! lands in `vms/<id>/checkpoints/out-<operation>`, the one directory Landlock
//! lets the VMM write. The supervisor takes that tree over and admits it as
//! untrusted input before it publishes anything.

use std::time::Instant;

use codewire_vmm_guest_probe::{
    CHECKPOINT_HELLO_LEN, CHECKPOINT_HOST_ENTROPY_LEN, CHECKPOINT_REPLY_LEN, CheckpointAction,
    CheckpointHello, CheckpointKey, CheckpointReply, CheckpointRequest, CheckpointStatus,
    GUEST_CHECKPOINT_ABI, GUEST_CHECKPOINT_VSOCK_PORT,
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
pub(crate) struct CheckpointCapture {
    pub(crate) timings: CaptureTimings,
    pub(crate) memory_bytes: u64,
    pub(crate) guest_abi: u32,
    /// The captured boot's setup disk, when it had one.
    pub(crate) setup_disk_bytes: Option<u64>,
    /// The checkpoint is complete, but the VM did not resume.
    pub(crate) resume_failed: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CaptureTimings {
    pub(crate) guest_freeze: Duration,
    pub(crate) workload_frozen: Duration,
    pub(crate) vm_paused: Duration,
    pub(crate) memory_write: Duration,
    pub(crate) disk_clone: Duration,
}

impl CloudHypervisorRunner {
    /// The pinned VMM's release and sha256, which a checkpoint restores only
    /// into.
    pub(crate) fn vmm_identity(&self) -> (&'static str, String) {
        (
            crate::artifact::CLOUD_HYPERVISOR_RELEASE,
            self.artifacts.cloud_hypervisor.sha256().to_owned(),
        )
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

    /// Capture a VM checkpoint into `checkpoints/out-<operation_id>`. On any
    /// failure the VM is running and thawed again, as far as it can be, and
    /// the tree is removed.
    pub(crate) async fn checkpoint(
        &mut self,
        operation_id: Uuid,
    ) -> Result<CheckpointCapture, RunnerError> {
        if !self.direct_shares.is_empty() {
            return Err(RunnerError::Checkpoint(
                "a VM with direct mounts cannot be checkpointed yet",
            ));
        }
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
        let result = self.capture_into(&out, operation_id).await;
        if result.is_err() {
            let _ = remove_checkpoint_tree(&checkpoints, &out_name);
        }
        result
    }

    async fn capture_into(
        &mut self,
        out: &Path,
        operation_id: Uuid,
    ) -> Result<CheckpointCapture, RunnerError> {
        let out_root = PrivateRoot::open(out)?;
        let vmm = out_root.create_dir(Path::new("vmm"), 0o700)?;
        let disks = out_root.create_dir(Path::new("disks"), 0o700)?;
        let root = out_root.create_dir(Path::new("root"), 0o700)?;
        let generation_dir = PrivateRoot::open(&root)?
            .create_dir(Path::new(&self.request.root_generation), 0o700)?;

        let frozen_at = Instant::now();
        let freeze = self.hook(CheckpointAction::Freeze, operation_id).await?;
        if freeze.status != CheckpointStatus::Done {
            // A failed freeze has thawed again in the guest.
            return Err(RunnerError::Checkpoint(
                "the guest could not freeze its workload; a process may be stuck in I/O, so try again",
            ));
        }
        let captured = self.pause_and_capture(&vmm, &disks, &generation_dir).await;
        // The workload thaws on every path once the VM runs again.
        let thawed = match &captured {
            Ok((_, false)) | Err(_) => self.hook(CheckpointAction::Thaw, operation_id).await,
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
        let mut memory_bytes = 0;
        for name in CHECKPOINT_VMM_FILES {
            let path = vmm.join(name);
            let file = File::open(&path).map_err(|source| PathError::Io {
                path: path.clone(),
                source,
            })?;
            file.sync_all().map_err(|source| PathError::Io {
                path: path.clone(),
                source,
            })?;
            if name == "memory-ranges" {
                memory_bytes = file
                    .metadata()
                    .map_err(|source| PathError::Io {
                        path: path.clone(),
                        source,
                    })?
                    .len();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).map_err(
                |source| PathError::Io {
                    path: path.clone(),
                    source,
                },
            )?;
        }
        for directory in [&vmm, &disks, &generation_dir, &root, &out.to_owned()] {
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
            guest_abi: GUEST_CHECKPOINT_ABI,
            setup_disk_bytes: self.setup_disk.as_ref().map(|setup| setup.file.size),
            resume_failed,
        })
    }

    /// Pause, write the VMM's state, clone the disks, resume. Returns the
    /// timings and whether the resume failed after a complete capture.
    async fn pause_and_capture(
        &mut self,
        vmm: &Path,
        disks: &Path,
        generation_dir: &Path,
    ) -> Result<(CaptureTimings, bool), RunnerError> {
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
            let mut clones = vec![
                (self.paths.state_disk.clone(), disks.join("state.raw")),
                (
                    RootGenerationPaths::create(&self.paths, &self.request.root_generation)?
                        .root_disk,
                    generation_dir.join("root.raw"),
                ),
            ];
            if self.docker_disk.is_some() {
                clones.push((self.paths.docker_disk.clone(), disks.join("docker.raw")));
            }
            for (source, destination) in clones {
                clone_disk(&source, &destination)?;
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
    /// boot.
    async fn hook(
        &self,
        action: CheckpointAction,
        operation_id: Uuid,
    ) -> Result<CheckpointReply, RunnerError> {
        hook_exchange(
            &self.hybrid.socket,
            &self.token,
            CheckpointRequest {
                action,
                operation_id,
                vm_id: self.request.vm_id,
                generation: self.request.generation,
                host_entropy: [0; CHECKPOINT_HOST_ENTROPY_LEN],
                host_time_ns: 0,
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
    let target = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
        .map_err(|error| io_error(destination, error))?;
    crate::fs_clone::reflink(&source_file, &target).map_err(|_| {
        RunnerError::Checkpoint(
            "the disks could not be cloned; VM checkpoints need a filesystem that shares blocks (btrfs or XFS)",
        )
    })?;
    target
        .sync_all()
        .map_err(|error| io_error(destination, error))?;
    Ok(())
}

use std::fs::File;
use std::os::unix::fs::PermissionsExt as _;

#[cfg(test)]
mod tests {
    use super::*;

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
}
