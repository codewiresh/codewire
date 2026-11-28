//! `cw __pod-runtime` (#5602): the one container of a `standard` sandbox
//! Pod. It boots one VM with the local runner, over the workspace image's
//! published disk, and keeps it running for the Pod's life.
//!
//! It takes no arguments: admission pins the image and its entrypoint. The
//! paths are fixed by the Pod's shape, and the few values that differ per
//! sandbox come from the template's environment.
//!
//! The guest runs the hosted daemon with the Pod's settings and tokens. The
//! host end's network worker runs the locked policy with the Pod's platform
//! peers alone open, in both egress modes ([`EgressMode`]): in broker mode
//! the workload's traffic reaches the network only inside the daemon's stream
//! to `cw-egress`, one of those peers (#5602, design: comment 130891).

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

mod baked_catalog;
mod guest_log;
mod hibernate;
mod hosted;
mod suspend;
pub use baked_catalog::prepare_baked_catalog;
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
/// How long a restored daemon has to re-bind and send `rebind-ok\n` before
/// falling back to a clean cold boot from disks (#6647).
const REBIND_TIMEOUT: Duration = Duration::from_secs(90);
/// Inside the Pod's 60 s grace: the guest powers off, else the VMM stops.
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
/// Grace budget for writing a hibernate memory image on SIGTERM.
const HIBERNATE_TIMEOUT: Duration = Duration::from_secs(45);
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
    /// Optional explicit literal `IPv4:port` tailnet UDP peers bridged on Pod
    /// `:31000` (#6637). Empty leaves the bridge disabled.
    pub udp_peers: Vec<std::net::SocketAddrV4>,
    /// `CODEWIRE_VM_STATE`: whether this sandbox's state disk may be made.
    pub vm_state: VmState,
    /// `CODEWIRE_VM_EGRESS_MODE`, which orchestration renders on every
    /// standard Pod. The runtime never defaults it.
    pub egress_mode: EgressMode,
    /// `CODEWIRE_WORKSPACE_INIT`, which orchestration renders on every
    /// standard Pod (`image` or `systemd`). The runtime never defaults it.
    pub workspace_init: codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit,
    /// `CODEWIRE_VM_RESTORE_GENERATION`: when set, this Pod attempts to
    /// restore the matching hibernate memory image once, falling back to a
    /// clean cold boot from disks on any mismatch or error (#6647).
    pub restore_generation: Option<u64>,
    /// `CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST`: the digest of this Pod's
    /// runtime image (`sha256:<64 hex>`), recorded beside a hibernate image
    /// and checked before restore (#6647).
    pub runtime_image_digest: Option<String>,
}

/// How the guest's workload reaches the network (#5602).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// The workload has no egress, and the daemon reaches only the platform
    /// peers. The runtime marks the guest with `codewire.guest_carried=1`.
    GuestCarried,
    /// Hosted broker mode inside the VM: the daemon carries the workload over
    /// `cwegress0` to `cw-egress` with the Pod's egress token, which crosses
    /// into the guest in this mode alone. The guest is marked
    /// `codewire.hosted_broker=1`.
    Broker,
}

impl EgressMode {
    fn hosted(self) -> codewire_vmm_guest_probe::hosted_control::HostedEgressMode {
        match self {
            Self::GuestCarried => {
                codewire_vmm_guest_probe::hosted_control::HostedEgressMode::GuestCarried
            }
            Self::Broker => codewire_vmm_guest_probe::hosted_control::HostedEgressMode::Broker,
        }
    }
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
            udp_peers: match variable(codewire_daemon_proto::POD_RUNTIME_UDP_PEERS_ENV) {
                Some(peers) => hosted::parse_udp_peers(&peers)?,
                None => Vec::new(),
            },
            vm_state: match read("CODEWIRE_VM_STATE")?.as_str() {
                "new" => VmState::New,
                "existing" => VmState::Existing,
                _ => return Err(PodRuntimeError::Setting("CODEWIRE_VM_STATE")),
            },
            // Exactly these two values; anything else is refused.
            egress_mode: match read("CODEWIRE_VM_EGRESS_MODE")?.as_str() {
                "guest-carried" => EgressMode::GuestCarried,
                "broker" => EgressMode::Broker,
                _ => return Err(PodRuntimeError::Setting("CODEWIRE_VM_EGRESS_MODE")),
            },
            // Exactly these two values; missing, empty or any other value is
            // refused (`docs/dev/SYSTEMD-WORKSPACE.md`, "On the `standard` profile").
            workspace_init: match read(codewire_daemon_proto::POD_RUNTIME_WORKSPACE_INIT_ENV)?
                .as_str()
            {
                "image" => codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit::Image,
                "systemd" => codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit::Systemd,
                _ => {
                    return Err(PodRuntimeError::Setting(
                        codewire_daemon_proto::POD_RUNTIME_WORKSPACE_INIT_ENV,
                    ));
                }
            },
            restore_generation: match variable(
                codewire_daemon_proto::POD_RUNTIME_RESTORE_GENERATION_ENV,
            )
            .as_deref()
            {
                None | Some("") => None,
                Some(raw) => Some(
                    raw.parse::<u64>()
                        .ok()
                        .filter(|generation| *generation >= 1)
                        .ok_or(PodRuntimeError::Setting(
                            codewire_daemon_proto::POD_RUNTIME_RESTORE_GENERATION_ENV,
                        ))?,
                ),
            },
            runtime_image_digest: match variable(
                codewire_daemon_proto::POD_RUNTIME_IMAGE_DIGEST_ENV,
            )
            .as_deref()
            {
                None | Some("") => None,
                Some(raw) if hibernate::is_valid_runtime_image_digest(raw) => Some(raw.to_owned()),
                Some(_) => {
                    return Err(PodRuntimeError::Setting(
                        codewire_daemon_proto::POD_RUNTIME_IMAGE_DIGEST_ENV,
                    ));
                }
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

/// Build-time entrypoint for `images/pod-runtime/Dockerfile`: pre-bakes the
/// sealed read-only `cw-runtime` ext4 catalog beside `cw-runtime.lock.json`.
pub fn prepare_pod_runtime_catalog() -> Result<String, PodRuntimeError> {
    prepare_baked_catalog(&PodPaths::default())
}

/// Per-phase millisecond timings collected across a `standard` Pod boot (#5602).
struct BootTimings {
    started: std::time::Instant,
    runner_ms: u128,
    image_ms: u128,
    cw_runtime_ms: u128,
    request_ms: u128,
}

/// Boots the VM described by `settings` and runs it until `stop` resolves
/// or the VM ends.
pub async fn run(
    settings: &PodSettings,
    paths: &PodPaths,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), PodRuntimeError> {
    let started = std::time::Instant::now();
    let engine_root = ensure_private_dir(&paths.state_volume.join("runtime"))?;
    let phase = std::time::Instant::now();
    let runner = CloudHypervisorRunner::new(RunnerConfig {
        state_root: engine_root.clone(),
        artifact_root: paths.artifact_root.clone(),
        artifact_lock: paths.artifact_lock.clone(),
    })
    .await?;
    let runner_ms = phase.elapsed().as_millis();
    let phase = std::time::Instant::now();
    let image = admit_image(settings, paths)?;
    let image_ms = phase.elapsed().as_millis();
    let phase = std::time::Instant::now();
    let (cw_runtime_root, catalog) =
        baked_catalog::resolve_cw_runtime(&engine_root, &paths.cw_runtime_lock)?;
    let runner = runner.with_cw_runtime_root(cw_runtime_root)?;
    let cw_runtime_ms = phase.elapsed().as_millis();
    tokio::pin!(stop);

    if let Some(expected_gen) = settings.restore_generation {
        let vmm_sha = runner.vmm_identity().1;
        match hibernate::admit_hibernate_restore(&engine_root, settings, expected_gen, &vmm_sha) {
            Ok(record) => {
                let phase = std::time::Instant::now();
                let restore_request = boot_request(
                    settings,
                    paths,
                    &engine_root,
                    &image,
                    catalog.clone(),
                    Some(record.to_restore_boot()),
                )?;
                let request_ms = phase.elapsed().as_millis();
                let timings = BootTimings {
                    started,
                    runner_ms,
                    image_ms,
                    cw_runtime_ms,
                    request_ms,
                };
                match restore_and_wait(
                    &runner,
                    &engine_root,
                    restore_request,
                    expected_gen,
                    settings,
                    paths,
                    timings,
                    stop.as_mut(),
                )
                .await
                {
                    RestoreOutcome::Finished(result) => return result,
                    RestoreOutcome::Fallback(reason) => {
                        hibernate::clear_hibernate_artifacts(&engine_root);
                        eprintln!("{}", hibernate::format_fallback_line(expected_gen, reason));
                    }
                }
            }
            Err(reason) => {
                eprintln!("{}", hibernate::format_fallback_line(expected_gen, reason));
            }
        }
    } else {
        // Cold boot: remove any leftover hibernate files from a prior boot.
        hibernate::clear_hibernate_artifacts(&engine_root);
    }

    let phase = std::time::Instant::now();
    let request = boot_request(settings, paths, &engine_root, &image, catalog, None)?;
    let request_ms = phase.elapsed().as_millis();
    let timings = BootTimings {
        started,
        runner_ms,
        image_ms,
        cw_runtime_ms,
        request_ms,
    };
    boot_and_wait(
        &runner,
        &engine_root,
        request,
        settings,
        paths,
        timings,
        stop,
    )
    .await
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
/// root, and the runner's request for this boot. When `checkpoint` is `Some`,
/// builds a hibernate-restore request (no setup pack; existing disks).
fn boot_request(
    settings: &PodSettings,
    paths: &PodPaths,
    engine_root: &Path,
    image: &AdmittedImage,
    cw_runtime_catalog_generation: String,
    checkpoint: Option<crate::runner::RestoreBoot>,
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
    let setup = if root.created && checkpoint.is_none() {
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
        // runner's host ports (see `hosted::open_published_ports`).
        host_ports: Vec::new(),
        mesh: None,
        direct_shares: Vec::new(),
        skill_snapshot_sha256: None,
        environment_projection_sha256: None,
        managed_credential_clients: codewire_access::ManagedCredentialClients::default(),
        cw_runtime_catalog_generation: Some(cw_runtime_catalog_generation),
        cw_runtime_moved_from_generation: None,
        image_disk: Some(settings.attachment(&paths.image_disk)),
        // Closed at the host end in both modes, with the platform peers alone
        // open (cw-security, #5602); in broker mode `cw-egress` is one of them.
        network_policy: CompiledPolicy::locked_with_platform_peers(&settings.platform_peers)?,
        udp_peers: settings.udp_peers.clone(),
        intercepts: InterceptSet::default(),
        credential_placeholders: Default::default(),
        bound_secrets: None,
        checkpoint,
    })
}

enum RestoreOutcome {
    Finished(Result<(), PodRuntimeError>),
    Fallback(hibernate::FallbackReason),
}

/// Attempts to restore a hibernated VM (`docs/dev/SANDBOX-SLEEP.md`, #6647):
/// 1. Starts VMM from `checkpoints/in`, delivers `RestoreSettings` + `Tokens`
///    while `/workload` is frozen, then thaws `/workload`.
/// 2. Keeps Pod TCP ports `7777` & `2222` closed and `daemon/ready` absent
///    until the restored daemon signals `rebind-ok\n` over vsock `7784`.
/// 3. On `rebind-ok\n`, deletes the memory file & metadata, opens `7777` and
///    `2222`, marks Ready, emits `vm-hibernate-record {"event":"restored"}`,
///    and enters the steady-state run loop.
/// 4. On any restore or re-bind failure, terminates the VMM cleanly and
///    returns `RestoreOutcome::Fallback` so the caller cold-boots from disks.
#[allow(clippy::too_many_arguments)]
async fn restore_and_wait(
    runner: &CloudHypervisorRunner,
    engine_root: &Path,
    request: CreateVmRequest,
    restore_generation: u64,
    settings: &PodSettings,
    paths: &PodPaths,
    timings: BootTimings,
    mut stop: std::pin::Pin<&mut (impl std::future::Future<Output = ()> + ?Sized)>,
) -> RestoreOutcome {
    eprintln!(
        "standard runtime: restoring hibernated VM (generation {restore_generation}) over image disk {}",
        settings.image_disk_id
    );
    let hosted_settings =
        match hosted::read_settings(|name| std::env::var(name).ok(), &paths.hosted) {
            Ok(settings) => settings,
            Err(error) => return RestoreOutcome::Finished(Err(error)),
        };
    let tokens = match hosted::read_tokens(&paths.hosted, settings.egress_mode) {
        Ok(tokens) => tokens,
        Err(error) => return RestoreOutcome::Finished(Err(error)),
    };
    let booting = std::time::Instant::now();
    let prepared = match runner
        .prepare_hosted(
            request,
            settings.egress_mode.hosted(),
            settings.workspace_init,
        )
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("standard runtime: hibernate restore prepare failed: {error}");
            return RestoreOutcome::Fallback(hibernate::FallbackReason::RestoreFailed);
        }
    };
    let mut running = match runner
        .start_hosted_restored(prepared, hosted_settings, tokens.clone())
        .await
    {
        Ok(running) => running,
        Err(error) => {
            eprintln!("standard runtime: hibernate restore start failed: {error}");
            return RestoreOutcome::Fallback(hibernate::FallbackReason::RestoreFailed);
        }
    };
    let suspender = Arc::new(suspend::Suspender::new(
        running.suspend_control(),
        running.generation(),
        tokens,
        {
            let hosted = paths.hosted.clone();
            let mode = settings.egress_mode;
            Box::new(move || hosted::read_tokens(&hosted, mode))
        },
        Box::new(|record| eprintln!("{}", record.line())),
    ));
    let hibernate_control = Arc::new(hibernate::HibernateControl::awaiting_rebind());
    let executable = match std::env::current_exe().and_then(fs::canonicalize) {
        Ok(path) => path,
        Err(error) => {
            let _ = running.stop_discarding_guest_state().await;
            return RestoreOutcome::Finished(Err(error.into()));
        }
    };
    let control_tasks = match hosted::open_control_channels(
        &running.paths().vsock_socket,
        Arc::clone(&suspender),
        Arc::clone(&hibernate_control),
    ) {
        Ok(tasks) => tasks,
        Err(error) => {
            eprintln!("standard runtime: restored VM control channels failed: {error}");
            let _ = running.stop_discarding_guest_state().await;
            return RestoreOutcome::Fallback(hibernate::FallbackReason::RestoreFailed);
        }
    };
    if let Err(error) = running
        .start_network_worker(&executable, BOOT_TIMEOUT)
        .await
    {
        eprintln!("standard runtime: restored VM network worker failed: {error}");
        for task in control_tasks {
            task.abort();
        }
        let _ = running.stop_discarding_guest_state().await;
        return RestoreOutcome::Fallback(hibernate::FallbackReason::RestoreFailed);
    }

    // Wait for `rebind-ok\n` while keeping Pod ports 7777 & 2222 closed.
    let rebind_deadline = tokio::time::Instant::now() + REBIND_TIMEOUT;
    let rebound = loop {
        tokio::select! {
            () = hibernate_control.wait_for_rebind() => break Ok(true),
            () = &mut stop => {
                // Pod deleted while still restoring: abort cleanly.
                for task in control_tasks {
                    task.abort();
                }
                let _ = running.stop_discarding_guest_state().await;
                return RestoreOutcome::Finished(Ok(()));
            }
            () = tokio::time::sleep_until(rebind_deadline) => {
                break Err("timed out waiting for restored daemon re-bind");
            }
            () = tokio::time::sleep(EXIT_POLL) => {
                match running.try_exit() {
                    Ok(ExitClass::StillRunning) => {}
                    Ok(exit) => {
                        eprintln!("standard runtime: restored VM exited before re-bind: {exit:?}");
                        break Err("restored VM exited before re-bind");
                    }
                    Err(error) => {
                        eprintln!("standard runtime: restored VM exit poll failed: {error}");
                        break Err("restored VM exit poll failed");
                    }
                }
            }
        }
    };

    if let Err(reason) = rebound {
        eprintln!("standard runtime: {reason}; falling back to cold boot");
        for task in control_tasks {
            task.abort();
        }
        let _ = running.stop_discarding_guest_state().await;
        return RestoreOutcome::Fallback(hibernate::FallbackReason::RebindFailed);
    }

    // Re-bind succeeded: delete memory file & metadata BEFORE opening ports
    // and marking Ready (`docs/dev/SANDBOX-SLEEP.md`, "After a restore").
    hibernate::clear_hibernate_artifacts(engine_root);
    let published_tasks =
        match hosted::open_published_ports(&running.paths().vsock_socket, Arc::clone(&suspender))
            .await
        {
            Ok(tasks) => tasks,
            Err(error) => {
                for task in control_tasks {
                    task.abort();
                }
                let _ = running.stop().await;
                return RestoreOutcome::Finished(Err(error));
            }
        };
    if let Err(error) = mark_ready(&paths.run_directory) {
        for task in control_tasks.into_iter().chain(published_tasks) {
            task.abort();
        }
        let _ = running.stop().await;
        return RestoreOutcome::Finished(Err(error.into()));
    }
    eprintln!("{}", hibernate::format_restored_line(restore_generation));
    eprintln!(
        "standard runtime: restored VM is serving after {} ms (total_ms={})",
        booting.elapsed().as_millis(),
        timings.started.elapsed().as_millis(),
    );

    let result = run_until_stop(
        runner,
        engine_root,
        running,
        suspender,
        hibernate_control,
        control_tasks,
        published_tasks,
        settings,
        paths,
        stop,
    )
    .await;
    RestoreOutcome::Finished(result)
}

/// Boots the VM, reports it ready, and runs it until `stop` resolves or the
/// VM ends; only a guest shutdown (or a clean hibernate on SIGTERM) is a clean end.
async fn boot_and_wait(
    runner: &CloudHypervisorRunner,
    engine_root: &Path,
    request: CreateVmRequest,
    settings: &PodSettings,
    paths: &PodPaths,
    timings: BootTimings,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), PodRuntimeError> {
    eprintln!(
        "standard runtime: booting the VM over image disk {}",
        settings.image_disk_id
    );
    // Read before the boot, so a Pod missing its settings fails at once.
    let hosted_settings = hosted::read_settings(|name| std::env::var(name).ok(), &paths.hosted)?;
    let tokens = hosted::read_tokens(&paths.hosted, settings.egress_mode)?;
    let booting = std::time::Instant::now();
    let phase = std::time::Instant::now();
    let prepared = runner
        .prepare_hosted(
            request,
            settings.egress_mode.hosted(),
            settings.workspace_init,
        )
        .await?;
    let prepare_ms = phase.elapsed().as_millis();
    let phase = std::time::Instant::now();
    let mut running = runner.start(prepared).await?;
    let start_ms = phase.elapsed().as_millis();
    // The guest waits for these before it starts the workspace, network
    // readiness included, so they go before the network worker's wait.
    let phase = std::time::Instant::now();
    hosted::hand_over(&running, hosted_settings, tokens.clone()).await?;
    let handover_ms = phase.elapsed().as_millis();
    // Suspend (#5529) & hibernate (#6647): pauses/wakes, hibernate arming, and
    // from here on every token delivery, which it holds while the VM is paused.
    let suspender = Arc::new(suspend::Suspender::new(
        running.suspend_control(),
        running.generation(),
        tokens,
        {
            let hosted = paths.hosted.clone();
            let mode = settings.egress_mode;
            Box::new(move || hosted::read_tokens(&hosted, mode))
        },
        Box::new(|record| eprintln!("{}", record.line())),
    ));
    let hibernate_control = Arc::new(hibernate::HibernateControl::normal());
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let phase = std::time::Instant::now();
    running
        .start_network_worker(&executable, BOOT_TIMEOUT)
        .await?;
    let control_tasks = hosted::open_control_channels(
        &running.paths().vsock_socket,
        Arc::clone(&suspender),
        Arc::clone(&hibernate_control),
    )?;
    let published_tasks =
        hosted::open_published_ports(&running.paths().vsock_socket, Arc::clone(&suspender)).await?;
    let network_ms = phase.elapsed().as_millis();
    let phase = std::time::Instant::now();
    let stage = running
        .authenticated_guest_terminal_stage(BOOT_TIMEOUT)
        .await?;
    let guest_ms = phase.elapsed().as_millis();
    if stage.is_failure() {
        // The boot already failed; that error is the one to report.
        for task in control_tasks.into_iter().chain(published_tasks) {
            task.abort();
        }
        let _ = running.stop().await;
        return Err(PodRuntimeError::GuestFailed(format!("{stage:?}")));
    }
    mark_ready(&paths.run_directory)?;
    eprintln!(
        "standard runtime: the guest is up after {} ms (runner_ms={} image_ms={} cw_runtime_ms={} request_ms={} prepare_ms={} start_ms={} handover_ms={} network_ms={} guest_ms={} total_ms={})",
        booting.elapsed().as_millis(),
        timings.runner_ms,
        timings.image_ms,
        timings.cw_runtime_ms,
        timings.request_ms,
        prepare_ms,
        start_ms,
        handover_ms,
        network_ms,
        guest_ms,
        timings.started.elapsed().as_millis(),
    );

    tokio::pin!(stop);
    run_until_stop(
        runner,
        engine_root,
        running,
        suspender,
        hibernate_control,
        control_tasks,
        published_tasks,
        settings,
        paths,
        stop,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_until_stop(
    runner: &CloudHypervisorRunner,
    engine_root: &Path,
    mut running: crate::runner::RunningVm,
    suspender: Arc<suspend::Suspender<crate::runner::SuspendControl>>,
    hibernate_control: Arc<hibernate::HibernateControl>,
    control_tasks: Vec<tokio::task::JoinHandle<()>>,
    published_tasks: Vec<tokio::task::JoinHandle<()>>,
    settings: &PodSettings,
    paths: &PodPaths,
    mut stop: std::pin::Pin<&mut (impl std::future::Future<Output = ()> + ?Sized)>,
) -> Result<(), PodRuntimeError> {
    let exit = loop {
        tokio::select! {
            () = &mut stop => {
                if hibernate_control.is_armed() {
                    return perform_hibernate(
                        runner,
                        engine_root,
                        &mut running,
                        &suspender,
                        control_tasks,
                        published_tasks,
                        settings,
                        paths,
                    )
                    .await;
                }
                eprintln!("standard runtime: stopping the VM");
                // A paused VM is woken first, so the guest shuts down cleanly.
                break suspend::stop_awake(
                    &suspender,
                    tokio::time::timeout(STOP_TIMEOUT, running.stop()),
                )
                .await
                .unwrap_or(Ok(ExitClass::StillRunning))?;
            }
            () = tokio::time::sleep(EXIT_POLL) => {
                let exit = running.try_exit()?;
                if exit != ExitClass::StillRunning {
                    break exit;
                }
                suspender.write_state_when_due().await;
                suspender.refresh().await?;
            }
        }
    };
    for task in control_tasks.into_iter().chain(published_tasks) {
        task.abort();
    }
    clear_ready(&paths.run_directory);
    eprintln!("standard runtime: the VM ended: {exit:?}");
    match exit {
        ExitClass::GuestShutdown => Ok(()),
        other => Err(PodRuntimeError::GuestFailed(format!("{other:?}"))),
    }
}

/// Runs `CloudHypervisorRunner::hibernate` on Kubernetes SIGTERM when
/// `hibernate\n` armed the supervisor (`docs/dev/SANDBOX-SLEEP.md`, steps
/// 2–5), writes the sibling metadata record and host-observed
/// `vm-hibernate-record` log line, and exits cleanly.
#[allow(clippy::too_many_arguments)]
async fn perform_hibernate(
    runner: &CloudHypervisorRunner,
    engine_root: &Path,
    running: &mut crate::runner::RunningVm,
    suspender: &Arc<suspend::Suspender<crate::runner::SuspendControl>>,
    control_tasks: Vec<tokio::task::JoinHandle<()>>,
    published_tasks: Vec<tokio::task::JoinHandle<()>>,
    settings: &PodSettings,
    paths: &PodPaths,
) -> Result<(), PodRuntimeError> {
    clear_ready(&paths.run_directory);
    for task in &published_tasks {
        task.abort();
    }
    eprintln!("standard runtime: hibernating the VM");
    if let Err(error) = suspender.wake().await {
        eprintln!("standard runtime: hibernate could not wake paused VM: {error}");
    }
    let restore_generation = running.generation();
    let vmm_sha = runner.vmm_identity().1;
    let runtime_digest = settings.runtime_image_digest.clone().unwrap_or_default();
    let failure_reason: Option<&'static str> = if hibernate::is_valid_runtime_image_digest(
        &runtime_digest,
    ) {
        match tokio::time::timeout(HIBERNATE_TIMEOUT, runner.hibernate(running, Uuid::new_v4()))
            .await
        {
            Ok(Ok(hib)) => {
                let record = hibernate::build_record(
                    settings,
                    restore_generation,
                    vmm_sha,
                    runtime_digest,
                    hib.restore,
                );
                match hibernate::write_hibernate_record(engine_root, &record) {
                    Ok(()) => {
                        eprintln!("{}", hibernate::format_hibernated_line(&record));
                        None
                    }
                    Err(error) => {
                        eprintln!("standard runtime: failed to write hibernate record: {error}");
                        hibernate::clear_hibernate_artifacts(engine_root);
                        Some("record-write-failed")
                    }
                }
            }
            Ok(Err(error)) => {
                eprintln!("standard runtime: hibernate failed: {error}");
                hibernate::clear_hibernate_artifacts(engine_root);
                Some("hibernate-failed")
            }
            Err(_) => {
                eprintln!("standard runtime: hibernate timed out");
                hibernate::clear_hibernate_artifacts(engine_root);
                Some("hibernate-timed-out")
            }
        }
    } else {
        eprintln!(
            "standard runtime: hibernate skipped because CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST is unset"
        );
        Some("missing-runtime-image-digest")
    };

    let result = if let Some(reason) = failure_reason {
        eprintln!("{}", hibernate::format_hibernate_failed_line(reason));
        let exit = tokio::time::timeout(STOP_TIMEOUT, running.stop())
            .await
            .unwrap_or(Ok(ExitClass::StillRunning))?;
        match exit {
            ExitClass::GuestShutdown => Ok(()),
            other => Err(PodRuntimeError::GuestFailed(format!("{other:?}"))),
        }
    } else {
        Ok(())
    };

    for task in control_tasks.into_iter().chain(published_tasks) {
        task.abort();
    }
    result
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
            ("CODEWIRE_VM_EGRESS_MODE", "guest-carried"),
            ("CODEWIRE_WORKSPACE_INIT", "image"),
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
        assert_eq!(settings.egress_mode, EgressMode::GuestCarried);
        let broker =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_EGRESS_MODE", "broker")]))
                .unwrap();
        assert_eq!(broker.egress_mode, EgressMode::Broker);
        assert_eq!(
            broker.egress_mode.hosted(),
            codewire_vmm_guest_probe::hosted_control::HostedEgressMode::Broker
        );
        // Docker is off unless the Pod sizes its disk.
        assert_eq!(settings.docker_disk_bytes, None);
        let docker =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_DOCKER_DISK_MIB", "2048")]))
                .unwrap();
        assert_eq!(docker.docker_disk_bytes, Some(2048 * 1024 * 1024));
        assert_eq!(
            settings.workspace_init,
            codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit::Image
        );
        let systemd =
            PodSettings::from_environment(environment(&[("CODEWIRE_WORKSPACE_INIT", "systemd")]))
                .unwrap();
        assert_eq!(
            systemd.workspace_init,
            codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit::Systemd
        );
        assert_eq!(settings.vm_state, VmState::New);
        let existing =
            PodSettings::from_environment(environment(&[("CODEWIRE_VM_STATE", "existing")]))
                .unwrap();
        assert_eq!(existing.vm_state, VmState::Existing);
        assert_eq!(settings.restore_generation, None);
        assert_eq!(settings.runtime_image_digest, None);
        let valid_digest = format!("sha256:{}", "a".repeat(64));
        let restoring = PodSettings::from_environment(environment(&[
            ("CODEWIRE_VM_RESTORE_GENERATION", "3"),
            ("CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST", &valid_digest),
        ]))
        .unwrap();
        assert_eq!(restoring.restore_generation, Some(3));
        assert_eq!(
            restoring.runtime_image_digest.as_deref(),
            Some(valid_digest.as_str())
        );
        for (name, value) in [
            ("CODEWIRE_VM_RESTORE_GENERATION", "0"),
            ("CODEWIRE_VM_RESTORE_GENERATION", "abc"),
            ("CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST", "sha256:short"),
            (
                "CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST",
                &format!("sha256:{}", "A".repeat(64)),
            ),
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
            // Missing or unknown: never defaulted.
            ("CODEWIRE_VM_EGRESS_MODE", ""),
            ("CODEWIRE_VM_EGRESS_MODE", "Broker"),
            ("CODEWIRE_VM_EGRESS_MODE", "Guest-carried"),
            ("CODEWIRE_VM_EGRESS_MODE", "direct"),
            ("CODEWIRE_WORKSPACE_INIT", ""),
            ("CODEWIRE_WORKSPACE_INIT", "Systemd"),
            ("CODEWIRE_WORKSPACE_INIT", "IMAGE"),
            ("CODEWIRE_WORKSPACE_INIT", "other"),
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

    #[test]
    fn udp_peers_parser_accepts_valid_literals_and_fails_closed_on_invalid_entries() {
        let own = [std::net::Ipv4Addr::new(10, 92, 0, 5)];
        // Empty string disables the bridge cleanly.
        assert_eq!(hosted::parse_udp_peers_with_own("", &own).unwrap(), vec![]);
        // Valid literal IPv4:port pairs are sorted and deduplicated.
        assert_eq!(
            hosted::parse_udp_peers_with_own(
                "203.0.113.40:41641,198.51.100.35:41641,198.51.100.35:41641",
                &own
            )
            .unwrap(),
            vec![
                "198.51.100.35:41641".parse().unwrap(),
                "203.0.113.40:41641".parse().unwrap(),
            ]
        );
        // Up to MAX_UDP_BRIDGE_PEERS (8) unique entries pass; 9 fail closed.
        let eight = (1..=8)
            .map(|n| format!("198.51.100.{n}:41641"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            hosted::parse_udp_peers_with_own(&eight, &own)
                .unwrap()
                .len(),
            8
        );
        let nine = (1..=9)
            .map(|n| format!("198.51.100.{n}:41641"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(hosted::parse_udp_peers_with_own(&nine, &own).is_err());

        for bad in [
            ",",
            "198.51.100.35:41641,",
            ",198.51.100.35:41641",
            "198.51.100.35:41641,,203.0.113.40:41641",
            " 198.51.100.35:41641",
            "198.51.100.35:0",
            "0.0.0.0:41641",
            "127.0.0.1:41641",
            "169.254.169.254:41641",
            "224.0.0.1:41641",
            "255.255.255.255:41641",
            "[2001:db8::1]:41641",
            "relay.example.invalid:41641",
            "10.92.0.5:41641", // Pod's own interface address
        ] {
            assert!(
                hosted::parse_udp_peers_with_own(bad, &own).is_err(),
                "must reject {bad:?}"
            );
        }

        // Unset or empty in PodSettings disables the bridge; malformed fails closed.
        let unset = PodSettings::from_environment(environment(&[])).unwrap();
        assert!(unset.udp_peers.is_empty());
        let empty =
            PodSettings::from_environment(environment(&[("CODEWIRE_POD_UDP_PEERS", "")])).unwrap();
        assert!(empty.udp_peers.is_empty());
        let set = PodSettings::from_environment(environment(&[(
            "CODEWIRE_POD_UDP_PEERS",
            "198.51.100.35:41641",
        )]))
        .unwrap();
        assert_eq!(set.udp_peers, vec!["198.51.100.35:41641".parse().unwrap()]);
        assert!(
            PodSettings::from_environment(environment(&[(
                "CODEWIRE_POD_UDP_PEERS",
                "127.0.0.1:41641",
            )]))
            .is_err()
        );
    }
}
