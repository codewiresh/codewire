//! `cw __pod-runtime` (#5602): the one container of a `standard` sandbox
//! Pod. It boots one VM with the local runner, over the workspace image's
//! published disk, and keeps it running for the Pod's life.
//!
//! It takes no arguments: admission pins the image and its entrypoint. The
//! paths are fixed by the Pod's shape, and the few values that differ per
//! sandbox come from the template's environment.
//!
//! This first version boots the guest with its own daemon and no network at
//! all: the egress broker runs the locked policy, the only mode. The hosted
//! daemon, its settings and tokens, and the platform peers it may reach come
//! next, under the conditions cw-security set on #5602.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_egress_policy::CompiledPolicy;
use codewire_egress_policy::intercept::InterceptSet;
use codewire_project::ProjectSpec;
use codewire_vmm_guest_probe::{
    MAX_SETUP_CONFIG_BYTES, SetupArchitecture, SetupBinding, Sha256Value,
};
use uuid::Uuid;

use crate::generation::ensure_empty_root_generation;
use crate::host::path::PrivateRoot;
use crate::image_disk::{ImageDiskAttachment, admit_published, build_id_bytes};
use crate::runner::ExitClass;
use crate::setup_pack::{PublishedSetupRequest, ensure_published_setup_pack};
use crate::workspace::ensure_empty_state_disk;
use crate::{CloudHypervisorRunner, CreateVmRequest, RunnerConfig, RunnerError};

mod hosted;
use codewire_vmm_guest_probe::image_disk::BuildId;
pub use hosted::HostedPaths;

/// The runtime image's own artifacts: Cloud Hypervisor, the guest kernel and
/// the guest root, with the lock that pins them.
const ARTIFACT_ROOT: &str = "/opt/codewire/runtime/artifacts";
const ARTIFACT_LOCK: &str = "/opt/codewire/runtime/artifacts.lock";
/// The sandbox's volume. The VM's disks live under `runtime/` in it.
const STATE_VOLUME: &str = "/state";
/// The workspace image's published disk, an image volume.
const IMAGE_DISK_DIRECTORY: &str = "/image";
const IMAGE_CONFIG_NAME: &str = "config.json";
/// The image index the disk's manifest came from, when it came from one.
const IMAGE_INDEX_NAME: &str = "index.json";
const MAX_IMAGE_INDEX_BYTES: u64 = 1024 * 1024;
/// The memory volume the kubelet's readiness probe reads. The probe tests
/// the same file a Kata Pod's daemon writes, `daemon/ready`.
const RUN_DIRECTORY: &str = "/codewire/run";
const READY_DIRECTORY: &str = "daemon";
const READY_NAME: &str = "ready";

const DAEMON_VSOCK_PORT: u32 = 7_777;
/// The VM's changes over the image. It shares the claim with the state disk,
/// which orchestration sizes to leave room for it (#5602).
const ROOT_DISK_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// The one VM on a sandbox's volume. A template carries no environment
/// identity (the daemon learns it at the bind), so the VM's id is fixed; it
/// names the VM's files and channel, never the environment.
const POD_VM_ID: Uuid = Uuid::from_u128(0x5ead_0001_0000_4000_8000_0000_0000_0001);
const BOOT_TIMEOUT: Duration = Duration::from_secs(120);
/// Inside the Pod's 60 s grace: the guest powers off, else the VMM stops.
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const EXIT_POLL: Duration = Duration::from_millis(500);
const GENERATION_NAME: &str = "pod-generation";

#[derive(Debug, thiserror::Error)]
pub enum PodRuntimeError {
    #[error("the Pod setting {0} is missing or invalid")]
    Setting(&'static str),
    #[error("the workspace image's disk is unusable: {0}")]
    ImageDisk(#[from] crate::image_disk::ImageDiskError),
    #[error("the workspace image's config is unreadable")]
    ImageConfig,
    #[error("the workspace image is not the one its disk was built from")]
    ImageMismatch,
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Hosted(#[from] crate::runner::HostedSendError),
    #[error(transparent)]
    CwRuntime(#[from] crate::cw_runtime::CwRuntimeError),
    #[error(transparent)]
    Policy(#[from] codewire_egress_policy::PolicyError),
    #[error(transparent)]
    Generation(#[from] crate::generation::GenerationError),
    #[error(transparent)]
    Workspace(#[from] crate::workspace::WorkspaceError),
    #[error(transparent)]
    SetupPack(#[from] crate::setup_pack::SetupPackError),
    #[error(transparent)]
    Path(#[from] crate::host::path::PathError),
    #[error("the boot counter is unreadable")]
    BootCounter,
    #[error("the VM's disks need {needed} bytes but the sandbox's volume holds {volume}")]
    DisksExceedVolume { needed: u64, volume: u64 },
    #[error(
        "the sandbox's state disk is missing from its volume, so its work is gone; refusing to boot it empty"
    )]
    StateDiskMissing,
    #[error("the guest did not finish booting: {0}")]
    GuestFailed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What one sandbox's VM is, from the template's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSettings {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub state_disk_bytes: u64,
    /// The workspace's own Docker data disk, when the sandbox has Docker.
    pub docker_disk_bytes: Option<u64>,
    pub workspace_image: String,
    pub image_disk_id: String,
    pub build_id: String,
    /// The platform peers the host end may dial for the hosted daemon.
    pub platform_peers: Vec<std::net::SocketAddrV4>,
    /// `CODEWIRE_VM_STATE`: whether this sandbox's state disk may be made.
    pub vm_state: VmState,
}

/// Orchestration renders `new` and sets `existing` once the sandbox's
/// daemon has bound, so a later Pod never boots a fresh, empty disk where the
/// sandbox's work was (change 7, #5602).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// Made if absent; used if present.
    New,
    /// Must be present; a missing disk fails the boot.
    Existing,
}

impl PodSettings {
    /// Reads the settings by fixed names. Nothing else in the environment is
    /// read.
    pub fn from_environment(
        variable: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, PodRuntimeError> {
        let read = |name: &'static str| variable(name).ok_or(PodRuntimeError::Setting(name));
        let number = |name: &'static str| -> Result<u64, PodRuntimeError> {
            read(name)?
                .parse()
                .map_err(|_| PodRuntimeError::Setting(name))
        };
        let vcpus = u8::try_from(number("CODEWIRE_VM_VCPUS")?)
            .ok()
            .filter(|count| (1..=32).contains(count))
            .ok_or(PodRuntimeError::Setting("CODEWIRE_VM_VCPUS"))?;
        let memory_mib = u32::try_from(number("CODEWIRE_VM_MEMORY_MIB")?)
            .ok()
            .filter(|mib| (128..=65_536).contains(mib))
            .ok_or(PodRuntimeError::Setting("CODEWIRE_VM_MEMORY_MIB"))?;
        let state_disk_bytes = number("CODEWIRE_VM_STATE_DISK_MIB")?
            .checked_mul(1024 * 1024)
            .ok_or(PodRuntimeError::Setting("CODEWIRE_VM_STATE_DISK_MIB"))?;
        // Docker is optional: unset means none, and a set size must be one the
        // runner admits.
        let docker_disk_bytes = variable("CODEWIRE_VM_DOCKER_DISK_MIB")
            .map(|mib| {
                mib.parse::<u64>()
                    .ok()
                    .and_then(|mib| mib.checked_mul(1024 * 1024))
                    .filter(|bytes| *bytes >= crate::state::MINIMUM_DOCKER_DISK_BYTES)
                    .ok_or(PodRuntimeError::Setting("CODEWIRE_VM_DOCKER_DISK_MIB"))
            })
            .transpose()?;
        let settings = Self {
            vcpus,
            memory_mib,
            state_disk_bytes,
            docker_disk_bytes,
            workspace_image: read("CODEWIRE_WORKSPACE_IMAGE")?,
            image_disk_id: read("CODEWIRE_IMAGE_DISK_ID")?,
            build_id: read("CODEWIRE_IMAGE_DISK_BUILD_ID")?,
            platform_peers: match variable("CODEWIRE_POD_PLATFORM_PEERS") {
                Some(peers) => hosted::parse_platform_peers(&peers)?,
                None => Vec::new(),
            },
            vm_state: match read("CODEWIRE_VM_STATE")?.as_str() {
                "new" => VmState::New,
                "existing" => VmState::Existing,
                _ => return Err(PodRuntimeError::Setting("CODEWIRE_VM_STATE")),
            },
        };
        if !settings
            .attachment(Path::new(IMAGE_DISK_DIRECTORY))
            .is_valid()
        {
            return Err(PodRuntimeError::Setting("CODEWIRE_IMAGE_DISK_ID"));
        }
        Ok(settings)
    }

    fn attachment(&self, directory: &Path) -> ImageDiskAttachment {
        ImageDiskAttachment::Published {
            directory: directory.to_owned(),
            image_disk_id: self.image_disk_id.clone(),
            build_id: self.build_id.clone(),
        }
    }
}

/// Where the Pod's parts are; fixed in a Pod, chosen by a test.
#[derive(Debug, Clone)]
pub struct PodPaths {
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
    pub state_volume: PathBuf,
    pub image_disk: PathBuf,
    pub run_directory: PathBuf,
    /// The sealed cw runtime the guest's hosted daemon runs from.
    pub cw_runtime_lock: PathBuf,
    pub hosted: hosted::HostedPaths,
}

impl Default for PodPaths {
    fn default() -> Self {
        Self {
            artifact_root: ARTIFACT_ROOT.into(),
            artifact_lock: ARTIFACT_LOCK.into(),
            state_volume: STATE_VOLUME.into(),
            image_disk: IMAGE_DISK_DIRECTORY.into(),
            run_directory: RUN_DIRECTORY.into(),
            cw_runtime_lock: Path::new(ARTIFACT_LOCK).with_file_name("cw-runtime.lock.json"),
            hosted: hosted::HostedPaths::default(),
        }
    }
}

/// The entrypoint: boot the VM, report it ready, and stop it when the Pod is
/// deleted. Returns when the VM has ended, either way.
pub async fn run_pod_runtime() -> Result<(), PodRuntimeError> {
    let settings = PodSettings::from_environment(|name| std::env::var(name).ok())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    run(&settings, &PodPaths::default(), async move {
        terminate.recv().await;
    })
    .await
}

/// Boots the VM described by `settings` and runs it until `stop` resolves
/// or the VM ends.
pub async fn run(
    settings: &PodSettings,
    paths: &PodPaths,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), PodRuntimeError> {
    let engine_root = ensure_private_dir(&paths.state_volume.join("runtime"))?;
    let runner = CloudHypervisorRunner::new(RunnerConfig {
        state_root: engine_root.clone(),
        artifact_root: paths.artifact_root.clone(),
        artifact_lock: paths.artifact_lock.clone(),
    })
    .await?;
    let image = admit_image(settings, paths)?;
    let catalog = install_cw_runtime(&engine_root, &paths.cw_runtime_lock)?;
    let request = boot_request(settings, paths, &engine_root, &image, catalog)?;
    boot_and_wait(&runner, request, settings, paths, stop).await
}

/// The published disk, admitted and checked against the image the project
/// names, with the image's config and the project made from it.
struct AdmittedImage {
    architecture: SetupArchitecture,
    manifest_sha256: Sha256Value,
    build_id: BuildId,
    config_json: Vec<u8>,
    project_json: Vec<u8>,
}

fn admit_image(settings: &PodSettings, paths: &PodPaths) -> Result<AdmittedImage, PodRuntimeError> {
    let disk = admit_published(
        &paths.image_disk,
        &settings.image_disk_id,
        &settings.build_id,
    )?;
    let architecture = match disk.record.architecture.as_str() {
        "amd64" => SetupArchitecture::Amd64,
        "arm64" => SetupArchitecture::Arm64,
        _ => return Err(PodRuntimeError::Setting("CODEWIRE_IMAGE_DISK_ID")),
    };
    let manifest_sha256 = Sha256Value::parse_hex(&disk.record.manifest_sha256)
        .map_err(|_| PodRuntimeError::Setting("CODEWIRE_IMAGE_DISK_ID"))?;
    // The image the project names is the one the disk was built from.
    let named = workspace_image_manifest(&settings.workspace_image)
        .ok_or(PodRuntimeError::ImageMismatch)?;
    if named != disk.record.manifest_sha256
        && !index_selects(&paths.image_disk, named, &disk.record)?
    {
        return Err(PodRuntimeError::ImageMismatch);
    }
    let build_id = build_id_bytes(&settings.build_id)
        .ok_or(PodRuntimeError::Setting("CODEWIRE_IMAGE_DISK_BUILD_ID"))?;
    let config_json = read_bounded(
        &paths.image_disk.join(IMAGE_CONFIG_NAME),
        MAX_SETUP_CONFIG_BYTES,
    )
    .map_err(|_| PodRuntimeError::ImageConfig)?;
    let project_json = ProjectSpec {
        image: settings.workspace_image.clone(),
        ..ProjectSpec::default()
    }
    .canonical_json()
    .map_err(|_| PodRuntimeError::Setting("CODEWIRE_WORKSPACE_IMAGE"))?;
    Ok(AdmittedImage {
        architecture,
        manifest_sha256,
        build_id,
        config_json,
        project_json,
    })
}

/// The state, Docker and root disks together fit within `volume` bytes.
fn disks_fit(settings: &PodSettings, volume: u64) -> Result<(), PodRuntimeError> {
    let needed = settings
        .state_disk_bytes
        .saturating_add(settings.docker_disk_bytes.unwrap_or(0))
        .saturating_add(ROOT_DISK_BYTES);
    if needed > volume {
        return Err(PodRuntimeError::DisksExceedVolume { needed, volume });
    }
    Ok(())
}

/// Under `existing` the sandbox's state disk must already be on its volume:
/// a missing one means the volume lost the sandbox's work, and the boot fails
/// rather than starting the sandbox empty. Any other error reading it is that
/// error, not a lost disk.
fn admit_vm_state(engine_root: &Path, vm_state: VmState) -> Result<(), PodRuntimeError> {
    if vm_state == VmState::Existing {
        match fs::symlink_metadata(crate::state::state_disk_path(engine_root, POD_VM_ID)) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PodRuntimeError::StateDiskMissing);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// The VM's disks on the sandbox's volume, its one-boot setup pack on a new
/// root, and the runner's request for this boot.
fn boot_request(
    settings: &PodSettings,
    paths: &PodPaths,
    engine_root: &Path,
    image: &AdmittedImage,
    cw_runtime_catalog_generation: String,
) -> Result<CreateVmRequest, PodRuntimeError> {
    admit_vm_state(engine_root, settings.vm_state)?;
    // The disks are sparse files on the sandbox's volume, so their sizes must
    // fit it, or the guest could fill the volume under them.
    let volume = rustix::fs::statvfs(engine_root).map_err(io::Error::from)?;
    disks_fit(settings, volume.f_blocks.saturating_mul(volume.f_frsize))?;
    ensure_empty_state_disk(engine_root, POD_VM_ID, settings.state_disk_bytes)?;
    if let Some(bytes) = settings.docker_disk_bytes {
        crate::workspace::ensure_docker_data_disk(engine_root, POD_VM_ID, bytes)?;
    }
    // The root disk is named by the build it sits on, so a new image build
    // starts a new root over it.
    let storage_generation = codewire_vmm_guest_probe::image_disk::image_root_generation(
        Sha256Value::calculate(&image.project_json),
        Sha256Value::parse_hex(&settings.image_disk_id)
            .map_err(|_| PodRuntimeError::Setting("CODEWIRE_IMAGE_DISK_ID"))?,
        image.build_id,
    )
    .to_string();
    let root =
        ensure_empty_root_generation(engine_root, POD_VM_ID, &storage_generation, ROOT_DISK_BYTES)?;
    let setup = if root.created {
        let pack = ensure_published_setup_pack(
            engine_root,
            POD_VM_ID,
            PublishedSetupRequest {
                project_json: &image.project_json,
                storage_generation: &storage_generation,
                config_json: &image.config_json,
                manifest_sha256: image.manifest_sha256,
                architecture: image.architecture,
                build_id: image.build_id,
            },
        )?;
        Some(
            SetupBinding::new(
                pack.header.total_bytes,
                pack.header.root_generation,
                pack.header_sha256,
            )
            .map_err(|_| {
                PodRuntimeError::SetupPack(crate::setup_pack::SetupPackError::InvalidPack)
            })?,
        )
    } else {
        None
    };
    Ok(CreateVmRequest {
        vm_id: POD_VM_ID,
        generation: next_generation(engine_root)?,
        vsock_cid: vsock_cid(POD_VM_ID),
        daemon_vsock_port: DAEMON_VSOCK_PORT,
        state_disk_bytes: settings.state_disk_bytes,
        docker_disk_bytes: settings.docker_disk_bytes,
        root_generation: storage_generation,
        root_disk_bytes: ROOT_DISK_BYTES,
        vcpus: settings.vcpus,
        memory_mib: settings.memory_mib,
        setup,
        // The Pod's ports reach the guest through its own ingress, not the
        // runner's host ports (see `hosted::publish_ports`).
        host_ports: Vec::new(),
        mesh: None,
        direct_shares: Vec::new(),
        skill_snapshot_sha256: None,
        environment_projection_sha256: None,
        managed_credential_clients: codewire_access::ManagedCredentialClients::default(),
        cw_runtime_catalog_generation: Some(cw_runtime_catalog_generation),
        cw_runtime_moved_from_generation: None,
        image_disk: Some(settings.attachment(&paths.image_disk)),
        // Closed is the only mode, with the platform peers alone open to the
        // daemon (cw-security, #5602).
        network_policy: CompiledPolicy::locked_with_platform_peers(&settings.platform_peers)?,
        intercepts: InterceptSet::default(),
        credential_placeholders: Default::default(),
        checkpoint: None,
    })
}

/// Boots the VM, reports it ready, and runs it until `stop` resolves or the
/// VM ends; only a guest shutdown is a clean end.
async fn boot_and_wait(
    runner: &CloudHypervisorRunner,
    request: CreateVmRequest,
    settings: &PodSettings,
    paths: &PodPaths,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), PodRuntimeError> {
    eprintln!(
        "standard runtime: booting the VM over image disk {}",
        settings.image_disk_id
    );
    // Read before the boot, so a Pod missing its settings fails at once.
    let hosted_settings = hosted::read_settings(|name| std::env::var(name).ok(), &paths.hosted)?;
    let mut tokens = hosted::read_tokens(&paths.hosted)?;
    let booting = std::time::Instant::now();
    let prepared = runner.prepare_hosted(request).await?;
    let mut running = runner.start(prepared).await?;
    // The guest waits for these before it starts the workspace, network
    // readiness included, so they go before the network worker's wait.
    hosted::hand_over(&running, hosted_settings, tokens.clone()).await?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    running
        .start_network_worker(&executable, BOOT_TIMEOUT)
        .await?;
    let _published = hosted::publish_ports(&running.paths().vsock_socket).await?;
    let stage = running
        .authenticated_guest_terminal_stage(BOOT_TIMEOUT)
        .await?;
    if stage.is_failure() {
        // The boot already failed; that error is the one to report.
        let _ = running.stop().await;
        return Err(PodRuntimeError::GuestFailed(format!("{stage:?}")));
    }
    mark_ready(&paths.run_directory)?;
    eprintln!(
        "standard runtime: the guest is up after {} ms",
        booting.elapsed().as_millis()
    );

    tokio::pin!(stop);
    let exit = loop {
        tokio::select! {
            () = &mut stop => {
                eprintln!("standard runtime: stopping the VM");
                break tokio::time::timeout(STOP_TIMEOUT, running.stop())
                    .await
                    .unwrap_or(Ok(ExitClass::StillRunning))?;
            }
            () = tokio::time::sleep(EXIT_POLL) => {
                let exit = running.try_exit()?;
                if exit != ExitClass::StillRunning {
                    break exit;
                }
                tokens = hosted::refresh_tokens(&running, &paths.hosted, tokens).await?;
            }
        }
    };
    clear_ready(&paths.run_directory);
    eprintln!("standard runtime: the VM ended: {exit:?}");
    match exit {
        ExitClass::GuestShutdown => Ok(()),
        other => Err(PodRuntimeError::GuestFailed(format!("{other:?}"))),
    }
}

/// The image's sealed cw runtime, installed as a catalog the VM attaches
/// read-only; the guest's hosted daemon runs from it.
fn install_cw_runtime(engine_root: &Path, lock: &Path) -> Result<String, PodRuntimeError> {
    let store = crate::cw_runtime::CwRuntimeStore::create(&PrivateRoot::open(engine_root)?)?;
    let asset = store.admit_source(lock)?;
    Ok(store
        .prepare_catalog(&asset.provenance, &std::collections::BTreeMap::new())?
        .generation)
}

fn ensure_private_dir(path: &Path) -> Result<PathBuf, PodRuntimeError> {
    use std::os::unix::fs::PermissionsExt as _;
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let root = PrivateRoot::open(path)?;
    Ok(root.path().to_owned())
}

/// A boot generation the runner has not seen: one more than the last boot of
/// this Pod's VM, kept on the sandbox's volume.
fn next_generation(engine_root: &Path) -> Result<u64, PodRuntimeError> {
    let path = engine_root.join(GENERATION_NAME);
    let previous = match fs::read_to_string(&path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|_| PodRuntimeError::BootCounter)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(_) => return Err(PodRuntimeError::BootCounter),
    };
    let next = previous
        .checked_add(1)
        .ok_or(PodRuntimeError::BootCounter)?;
    let staged = engine_root.join(format!(".{GENERATION_NAME}"));
    fs::write(&staged, format!("{next}\n"))?;
    fs::File::open(&staged)?.sync_all()?;
    fs::rename(&staged, &path)?;
    Ok(next)
}

/// Whether the published disk's `index.json` is the image index `named` and
/// selects the disk's manifest for its architecture on Linux. A workspace
/// image is published as an index, and environments name it by that digest.
fn index_selects(
    directory: &Path,
    named: &str,
    record: &crate::image_disk::ImageDiskRecord,
) -> Result<bool, PodRuntimeError> {
    let bytes = match read_bounded(&directory.join(IMAGE_INDEX_NAME), MAX_IMAGE_INDEX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(PodRuntimeError::ImageMismatch),
    };
    if Sha256Value::calculate(&bytes).to_string() != named {
        return Ok(false);
    }
    #[derive(serde::Deserialize)]
    struct Index {
        manifests: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        digest: String,
        platform: Option<Platform>,
    }
    #[derive(serde::Deserialize)]
    struct Platform {
        os: String,
        architecture: String,
    }
    let index: Index =
        serde_json::from_slice(&bytes).map_err(|_| PodRuntimeError::ImageMismatch)?;
    let manifest = format!("sha256:{}", record.manifest_sha256);
    Ok(index.manifests.iter().any(|entry| {
        entry.digest == manifest
            && entry.platform.as_ref().is_some_and(|platform| {
                platform.os == "linux" && platform.architecture == record.architecture
            })
    }))
}

/// The manifest digest a `repo@sha256:<hex>` reference names.
fn workspace_image_manifest(reference: &str) -> Option<&str> {
    let (_, digest) = reference.rsplit_once("@sha256:")?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    .then_some(digest)
}

/// The guest channel's CID, from the VM's id, as the supervisor derives one.
fn vsock_cid(vm_id: Uuid) -> u32 {
    let bytes = vm_id.as_bytes();
    3 + u32::from_be_bytes([bytes[0], bytes[5], bytes[10], bytes[15]]) % (u32::MAX - 4)
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || !u64::try_from(bytes.len()).is_ok_and(|length| length <= limit) {
        return Err(io::Error::other("size out of bounds"));
    }
    Ok(bytes)
}

fn mark_ready(run_directory: &Path) -> io::Result<()> {
    let directory = run_directory.join(READY_DIRECTORY);
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let staged = directory.join(format!(".{READY_NAME}"));
    fs::write(&staged, b"ready\n")?;
    fs::rename(staged, directory.join(READY_NAME))
}

fn clear_ready(run_directory: &Path) {
    // The Pod is ending; a probe that still reads ready changes nothing.
    let _ = fs::remove_file(run_directory.join(READY_DIRECTORY).join(READY_NAME));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(overrides: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut values: Vec<(String, String)> = [
            ("CODEWIRE_VM_VCPUS", "2"),
            ("CODEWIRE_VM_MEMORY_MIB", "4096"),
            ("CODEWIRE_VM_STATE_DISK_MIB", "20480"),
            ("CODEWIRE_VM_STATE", "new"),
            ("CODEWIRE_WORKSPACE_IMAGE", "registry.example/workspace:1"),
            (
                "CODEWIRE_IMAGE_DISK_ID",
                "674bf52f32a20f048b034d4b56e8280f6e6c81271212dbdbd8e0ad1be8d8f723",
            ),
            (
                "CODEWIRE_IMAGE_DISK_BUILD_ID",
                "0123456789abcdef0123456789abcdef",
            ),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
        for (name, value) in overrides {
            values.retain(|(existing, _)| existing != name);
            if !value.is_empty() {
                values.push(((*name).to_owned(), (*value).to_owned()));
            }
        }
        move |name: &str| {
            values
                .iter()
                .find(|(existing, _)| existing == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// Under `existing` a missing state disk fails the boot; under `new` it
    /// is made. A disk already there is used either way.
    #[test]
    fn an_existing_sandbox_never_boots_without_its_state_disk() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            admit_vm_state(root.path(), VmState::Existing),
            Err(PodRuntimeError::StateDiskMissing)
        ));
        admit_vm_state(root.path(), VmState::New).unwrap();
        let disk = crate::state::state_disk_path(root.path(), POD_VM_ID);
        fs::create_dir_all(disk.parent().unwrap()).unwrap();
        fs::write(&disk, b"").unwrap();
        admit_vm_state(root.path(), VmState::Existing).unwrap();
    }

    #[test]
    fn an_index_pairs_only_when_it_is_the_named_one_and_selects_the_disks_manifest() {
        let manifest = "0e".repeat(32);
        let record = crate::image_disk::ImageDiskRecord {
            schema_version: 1,
            image_disk_id: String::new(),
            build_id: String::new(),
            format_version: 1,
            architecture: "amd64".to_owned(),
            manifest_sha256: manifest.clone(),
            disk_bytes: 4096,
        };
        let directory = tempfile::tempdir().unwrap();
        let index = |architecture: &str| {
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "manifests": [
                    {"digest": format!("sha256:{manifest}"),
                     "platform": {"os": "linux", "architecture": architecture}},
                ],
            }))
            .unwrap()
        };
        // No index: only the manifest digest itself pairs.
        assert!(!index_selects(directory.path(), &"22".repeat(32), &record).unwrap());
        let bytes = index("amd64");
        fs::write(directory.path().join(IMAGE_INDEX_NAME), &bytes).unwrap();
        let named = Sha256Value::calculate(&bytes).to_string();
        assert!(index_selects(directory.path(), &named, &record).unwrap());
        // Another digest than the index's own, or an index that selects the
        // manifest for another architecture, does not pair.
        assert!(!index_selects(directory.path(), &"22".repeat(32), &record).unwrap());
        let other = index("arm64");
        fs::write(directory.path().join(IMAGE_INDEX_NAME), &other).unwrap();
        let named = Sha256Value::calculate(&other).to_string();
        assert!(!index_selects(directory.path(), &named, &record).unwrap());
    }

    #[test]
    fn the_disks_must_fit_the_volume() {
        let gib = 1024 * 1024 * 1024;
        let docker =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_DOCKER_DISK_MIB", "2048")]))
                .unwrap();
        // 20 GiB state + 2 GiB Docker + 4 GiB root.
        disks_fit(&docker, 26 * gib).unwrap();
        assert!(matches!(
            disks_fit(&docker, 26 * gib - 1),
            Err(PodRuntimeError::DisksExceedVolume { .. })
        ));
        let plain = PodSettings::from_environment(environment(&[])).unwrap();
        disks_fit(&plain, 24 * gib).unwrap();
        assert!(disks_fit(&plain, 24 * gib - 1).is_err());
    }

    #[test]
    fn the_pod_settings_are_read_by_fixed_names_and_bounded() {
        let settings = PodSettings::from_environment(environment(&[])).unwrap();
        assert_eq!(settings.vcpus, 2);
        assert_eq!(settings.memory_mib, 4096);
        assert_eq!(settings.state_disk_bytes, 20480 * 1024 * 1024);
        // Docker is off unless the Pod sizes its disk.
        assert_eq!(settings.docker_disk_bytes, None);
        let docker =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_DOCKER_DISK_MIB", "2048")]))
                .unwrap();
        assert_eq!(docker.docker_disk_bytes, Some(2048 * 1024 * 1024));
        assert_eq!(settings.vm_state, VmState::New);
        let existing =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_STATE", "existing")]))
                .unwrap();
        assert_eq!(existing.vm_state, VmState::Existing);
        for (name, value) in [
            ("CODEWIRE_VM_DOCKER_DISK_MIB", "lots"),
            ("CODEWIRE_VM_DOCKER_DISK_MIB", "512"),
            ("CODEWIRE_VM_VCPUS", "0"),
            ("CODEWIRE_VM_VCPUS", "33"),
            ("CODEWIRE_VM_MEMORY_MIB", "64"),
            ("CODEWIRE_VM_STATE_DISK_MIB", "lots"),
            ("CODEWIRE_IMAGE_DISK_ID", "../disk"),
            (
                "CODEWIRE_IMAGE_DISK_BUILD_ID",
                "ABCDEF0123456789abcdef0123456789",
            ),
            ("CODEWIRE_WORKSPACE_IMAGE", ""),
            ("CODEWIRE_VM_STATE", ""),
            ("CODEWIRE_VM_STATE", "New"),
            ("CODEWIRE_VM_STATE", "fresh"),
        ] {
            assert!(
                PodSettings::from_environment(environment(&[(name, value)])).is_err(),
                "{name}={value}"
            );
        }
    }

    /// A Pod carries no environment identity: nothing but the fixed names
    /// is read, and an environment id in the Pod changes nothing.
    #[test]
    fn the_pod_names_no_environment() {
        let with_id = PodSettings::from_environment(environment(&[(
            "CODEWIRE_ENVIRONMENT_ID",
            "6f1f8f0e-3c39-4c1e-9a55-0d2d0d7c2a11",
        )]))
        .unwrap();
        assert_eq!(
            with_id,
            PodSettings::from_environment(environment(&[])).unwrap()
        );
        assert!(!POD_VM_ID.is_nil());
    }

    /// The workspace image is named by the manifest digest its disk's
    /// record carries, and nothing else pairs with that disk.
    #[test]
    fn the_workspace_image_pairs_with_its_disk_by_manifest_digest() {
        let digest = "a".repeat(64);
        assert_eq!(
            workspace_image_manifest(&format!("registry.example/workspace@sha256:{digest}")),
            Some(digest.as_str())
        );
        for reference in [
            "registry.example/workspace:1".to_owned(),
            format!("registry.example/workspace@sha256:{}", "A".repeat(64)),
            format!("registry.example/workspace@sha256:{}", "a".repeat(63)),
            format!("registry.example/workspace@sha512:{digest}"),
        ] {
            assert_eq!(workspace_image_manifest(&reference), None, "{reference}");
        }
    }

    #[test]
    fn each_boot_has_a_new_generation() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(next_generation(root.path()).unwrap(), 1);
        assert_eq!(next_generation(root.path()).unwrap(), 2);
        fs::write(root.path().join(GENERATION_NAME), b"not a number").unwrap();
        assert!(next_generation(root.path()).is_err());
    }
}
