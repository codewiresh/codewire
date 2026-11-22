//! Building an image disk (#4646) with a short-lived builder guest.
//!
//! The host stages an empty disk, writes the builder's seed and setup pack
//! into a private work directory of their own, and runs the builder guest
//! with exactly those three disks (`cloud_hypervisor::ImageBuildVmConfig`).
//! It promotes the disk only after the guest reported its layers ready over
//! the boot progress channel *and* its VMM exited cleanly. Any other end, a
//! failure stage, a crash, a timeout or a missed report, drops the staged
//! disk, so the store holds nothing and the next create builds again. The
//! host never mounts or reads the disk it promotes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_vmm_guest_probe::{GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, Seed, SetupBinding};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    NetworkProgressAttemptError, NetworkProgressGoal, boot_seed::generate_auth_token,
    spawn_cloud_hypervisor, wait_for_network_progress_attempt,
};
use crate::CloudHypervisorRunner;
use crate::artifact::AdmittedArtifacts;
use crate::cloud_hypervisor::{CloudHypervisorConfigError, ImageBuildVmConfig};
use crate::host::path::{PathError, PrivateRoot, set_socket_private};
use crate::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use crate::image_disk::{
    AdmittedImageDisk, ImageDiskError, ImageDiskLock, ImageDiskStore, StagedImageDisk,
    build_id_bytes,
};
use crate::oci::{ContentStore, OciArchitecture, ResolvedImage};
use crate::setup_pack::{SetupPackError, write_image_build_pack};
use crate::state::{StateError, publish_seed};

/// The builder's shape: more vCPUs than a workspace so decompression can run
/// ahead of the writer (design section 3); not yet measured.
const BUILDER_VCPUS: u8 = 4;
const BUILDER_MEMORY_MIB: u32 = 2_048;
/// The longest a build may take. The guest's own limits bound the work; this
/// bounds a stuck guest.
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// After "ready" the guest only syncs, waits for its report to be flushed and
/// powers off.
const EXIT_AFTER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_millis(50);
/// A builder runs no daemon; its seed still names a port.
const BUILDER_DAEMON_PORT: u32 = 7_777;
const WORK_DIRECTORY: &str = "image-builds";

#[derive(Debug, thiserror::Error)]
pub enum ImageBuildError {
    #[error(transparent)]
    Store(#[from] ImageDiskError),
    #[error(transparent)]
    Pack(#[from] SetupPackError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Config(#[from] CloudHypervisorConfigError),
    #[error(transparent)]
    Vsock(#[from] HybridVsockError),
    #[error("the image disk builder could not start")]
    Spawn,
    #[error("the image disk builder failed: {0:?}")]
    GuestFailed(GuestBootStage),
    #[error("the image disk builder stopped before its layers were ready")]
    Incomplete,
    #[error("the image disk builder did not finish in time")]
    Timeout,
    #[error("the image disk builder's progress was not authentic")]
    ProgressRejected,
    #[error("the image disk builder's work directory is invalid")]
    InvalidWork,
}

/// The builder's own files: `image-builds/<uuid>/` with its seed, setup
/// pack and the two sockets. The supervisor creates it and removes it when
/// the build ends, whatever its end; the builder process only opens it.
struct BuildWork {
    parent: PrivateRoot,
    name: String,
    root: PrivateRoot,
    api: PrivateRoot,
    vsock: PrivateRoot,
    seed: PathBuf,
    api_socket: PathBuf,
    vsock_socket: PathBuf,
    owner: bool,
}

const SEED_NAME: &str = "seed.raw";
const SETUP_NAME: &str = "setup.raw";
const API_SOCKET_NAME: &str = "api.sock";
const VSOCK_SOCKET_NAME: &str = "vsock.sock";

impl BuildWork {
    fn create(state_root: &PrivateRoot) -> Result<Self, ImageBuildError> {
        let parent = PrivateRoot::open(&state_root.ensure_dir(Path::new(WORK_DIRECTORY), 0o700)?)?;
        let name = Uuid::new_v4().simple().to_string();
        let root = PrivateRoot::open(&parent.create_dir(Path::new(&name), 0o700)?)?;
        // The API and vsock sockets sit in separate directories, as a VM's do.
        root.create_dir(Path::new("api"), 0o700)?;
        root.create_dir(Path::new("vsock"), 0o700)?;
        Self::with(parent, name, root, true)
    }

    /// The builder process's view of a work directory the supervisor made.
    fn open(state_root: &PrivateRoot, name: &str) -> Result<Self, ImageBuildError> {
        if Uuid::try_parse(name)
            .map(|id| id.simple().to_string())
            .ok()
            .as_deref()
            != Some(name)
        {
            return Err(ImageBuildError::InvalidWork);
        }
        let parent = PrivateRoot::open(&state_root.path().join(WORK_DIRECTORY))?;
        let root = PrivateRoot::open(&parent.path().join(name))?;
        Self::with(parent, name.to_owned(), root, false)
    }

    fn with(
        parent: PrivateRoot,
        name: String,
        root: PrivateRoot,
        owner: bool,
    ) -> Result<Self, ImageBuildError> {
        let api = PrivateRoot::open(&root.path().join("api"))?;
        let vsock = PrivateRoot::open(&root.path().join("vsock"))?;
        Ok(Self {
            seed: root.path().join(SEED_NAME),
            api_socket: api.path().join(API_SOCKET_NAME),
            vsock_socket: vsock.path().join(VSOCK_SOCKET_NAME),
            parent,
            name,
            root,
            api,
            vsock,
            owner,
        })
    }
}

impl Drop for BuildWork {
    fn drop(&mut self) {
        let _ = self.api.remove_private_socket(Path::new(API_SOCKET_NAME));
        let _ = self
            .vsock
            .remove_private_socket(Path::new(VSOCK_SOCKET_NAME));
        if !self.owner {
            return;
        }
        for name in [SEED_NAME, SETUP_NAME] {
            if let Ok(metadata) = std::fs::symlink_metadata(self.root.path().join(name)) {
                use std::os::unix::fs::MetadataExt as _;
                let _ = self
                    .root
                    .remove_private_regular(Path::new(name), metadata.mode() & 0o777);
            }
        }
        let _ = self.root.remove_empty_private_directory(Path::new("api"));
        let _ = self.root.remove_empty_private_directory(Path::new("vsock"));
        let _ = self
            .parent
            .remove_empty_private_directory(Path::new(&self.name));
    }
}

/// A build the supervisor prepared under the image's lock: the staged disk
/// and the builder's seed and setup pack. Dropped without
/// [`finish_image_build`], both are removed and the store holds nothing.
pub struct PreparedImageBuild<'a> {
    staged: StagedImageDisk<'a>,
    work: BuildWork,
}

impl PreparedImageBuild<'_> {
    /// The work directory's name, which the builder process is given.
    pub fn work_name(&self) -> &str {
        &self.work.name
    }

    /// The staged disk's name in the store, which the builder process is given.
    pub fn staged_name(&self) -> &str {
        self.staged.name()
    }
}

/// The supervisor's half before the builder runs: stage an empty disk with
/// a new build id, and write the builder's setup pack (the layers and the
/// build id only) and its seed.
pub fn prepare_image_build<'a>(
    state_root: &PrivateRoot,
    store: &'a ImageDiskStore,
    lock: &ImageDiskLock,
    content: &ContentStore,
    image: &ResolvedImage,
) -> Result<PreparedImageBuild<'a>, ImageBuildError> {
    let architecture = match image.architecture {
        OciArchitecture::Amd64 => "amd64",
        OciArchitecture::Arm64 => "arm64",
    };
    let staged = store.stage(lock, architecture, image.manifest.digest.hex())?;
    let build_id = build_id_bytes(&staged.record.build_id)
        .ok_or_else(|| ImageDiskError::InvalidRecord(lock.image_disk_id().to_owned()))?;
    let work = BuildWork::create(state_root)?;
    let pack = write_image_build_pack(&work.root, Path::new(SETUP_NAME), content, image, build_id)?;
    let token = Zeroizing::new(generate_auth_token());
    let binding = SetupBinding::new(
        pack.header.total_bytes,
        pack.header.root_generation,
        pack.header_sha256,
    )
    .map_err(|_| ImageBuildError::Pack(SetupPackError::InvalidPack))?;
    let seed = Seed::for_image_build(
        Uuid::new_v4(),
        BUILDER_DAEMON_PORT,
        token.to_string(),
        binding,
    )
    .map_err(|_| ImageBuildError::Pack(SetupPackError::InvalidPack))?;
    publish_seed(&work.seed, &seed.encode())?;
    Ok(PreparedImageBuild { staged, work })
}

/// The supervisor's half after its builder process exited 0: seal the inode
/// the store staged, never whatever the path names by then.
pub fn finish_image_build(
    store: &ImageDiskStore,
    lock: &ImageDiskLock,
    prepared: PreparedImageBuild<'_>,
) -> Result<AdmittedImageDisk, ImageBuildError> {
    let PreparedImageBuild { staged, work } = prepared;
    drop(work);
    Ok(store.promote(lock, staged)?)
}

/// The builder process's whole job (`cw __native-image-builder`): run only
/// the builder guest, from the work directory and onto the staged disk the
/// supervisor prepared, and return Ok only once the guest reported its
/// layers ready and its VMM exited cleanly. It promotes nothing.
pub async fn run_image_build_vm(
    artifacts: &AdmittedArtifacts,
    state_root: &PrivateRoot,
    work_name: &str,
    staged_disk: &Path,
) -> Result<(), ImageBuildError> {
    let work = BuildWork::open(state_root, work_name)?;
    let bytes =
        Zeroizing::new(std::fs::read(&work.seed).map_err(|_| ImageBuildError::InvalidWork)?);
    let seed = Seed::decode(&bytes).map_err(|_| ImageBuildError::InvalidWork)?;
    if !seed.image_build() || seed.setup().is_none() {
        return Err(ImageBuildError::InvalidWork);
    }
    let command = ImageBuildVmConfig::new(
        artifacts,
        work.seed.clone(),
        work.root.path().join(SETUP_NAME),
        staged_disk.to_owned(),
        work.api_socket.clone(),
        work.vsock_socket.clone(),
        builder_cid(seed.vm_id()),
        BUILDER_VCPUS,
        BUILDER_MEMORY_MIB,
    )
    .command()?;
    let mut child =
        spawn_cloud_hypervisor(&command, work.root.path()).map_err(|_| ImageBuildError::Spawn)?;
    let outcome = await_build(
        &mut child,
        &work.vsock_socket,
        seed.auth_token(),
        seed.vm_id(),
    )
    .await;
    if outcome.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    outcome
}

impl CloudHypervisorRunner {
    /// Builds and promotes the image disk for `image` in this process, for
    /// the qualification smoke. The supervisor runs the builder guest in a
    /// process of its own instead.
    pub async fn build_image_disk(
        &self,
        store: &ImageDiskStore,
        lock: &ImageDiskLock,
        content: &ContentStore,
        image: &ResolvedImage,
    ) -> Result<AdmittedImageDisk, ImageBuildError> {
        let prepared = prepare_image_build(&self.state_root, store, lock, content, image)?;
        let staged_disk = store.staged_disk_path(prepared.staged_name())?;
        run_image_build_vm(
            &self.artifacts,
            &self.state_root,
            prepared.work_name(),
            &staged_disk,
        )
        .await?;
        finish_image_build(store, lock, prepared)
    }
}

/// A CID derived from the build's VM id, as the supervisor derives a VM's.
/// A hybrid vsock reaches the guest through its own socket, so two VMs with
/// the same CID never meet.
fn builder_cid(build_vm: Uuid) -> u32 {
    let bytes = build_vm.as_bytes();
    3 + u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % (u32::MAX - 4)
}

/// Waits for the builder's "ready", then for its VMM to exit cleanly.
async fn await_build(
    child: &mut tokio::process::Child,
    vsock_socket: &Path,
    token: &str,
    vm_id: Uuid,
) -> Result<(), ImageBuildError> {
    let deadline = tokio::time::Instant::now() + IMAGE_BUILD_TIMEOUT;
    while !vsock_socket.exists() {
        if child
            .try_wait()
            .map_err(|_| ImageBuildError::Spawn)?
            .is_some()
        {
            return Err(ImageBuildError::Incomplete);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ImageBuildError::Timeout);
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
    set_socket_private(vsock_socket)?;
    let hybrid = HybridVsockTarget::new(vsock_socket.to_owned(), GUEST_PROGRESS_VSOCK_PORT)?;
    loop {
        match wait_for_network_progress_attempt(
            &hybrid,
            token,
            vm_id,
            1,
            deadline,
            NetworkProgressGoal::LayersReady,
            None,
        )
        .await
        {
            Ok(GuestBootStage::RootLayersReady) => break,
            Ok(stage) => return Err(ImageBuildError::GuestFailed(stage)),
            Err(NetworkProgressAttemptError::Timeout) => return Err(ImageBuildError::Timeout),
            Err(NetworkProgressAttemptError::Rejected) => {
                return Err(ImageBuildError::ProgressRejected);
            }
            Err(NetworkProgressAttemptError::Retry) => {
                if child
                    .try_wait()
                    .map_err(|_| ImageBuildError::Spawn)?
                    .is_some()
                {
                    return Err(ImageBuildError::Incomplete);
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
    match tokio::time::timeout(EXIT_AFTER_READY_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(_) => Err(ImageBuildError::Incomplete),
        Err(_) => Err(ImageBuildError::Timeout),
    }
}
