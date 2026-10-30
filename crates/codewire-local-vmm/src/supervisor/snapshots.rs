//! Local disk snapshots (#3046 R1, private-docs: designs/2026-10-24-local-disk-snapshots.md).
//!
//! A disk snapshot is a reusable copy of a stopped environment's disks on
//! this host: `state.raw`, `docker.raw` and its active root generation,
//! copied by reflink where the filesystem shares extents, otherwise sparsely.
//! It is an independent set of files under `engine/snapshots/<id>`, named by
//! the side store `snapshots.db` ([`crate::snapshot_store`]).
//!
//! Capture holds the source's name lease for the whole copy and its `vm.lock`
//! while it copies, as growing a stopped disk does. It refuses a source that
//! runs or has any staged change. In the copy of `state.raw`, never the
//! source, it removes every Codewire-delivered sign-in (docs/dev/
//! SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions"), recognised by
//! the daemon's own content rules: their blocks are zeroed, the files removed,
//! and every free block of the copy discarded, so no older copy of a token
//! survives in it either.
//!
//! A restore is an ordinary create (`OperationKind::Create`) whose journaled
//! payload names the snapshot. Its sources, credentials, cw runtime, host
//! ports and Mesh come from that create's own validated request; the
//! manifest's copies of them are information only. The create pins the
//! snapshot's runtime artifact generation, places reflinks of its disks into
//! a staging tree outside `vms/<id>` and publishes that tree in one rename,
//! then boots it as a stopped environment boots: no provisioning, no image
//! install, no setup. Everything identity-bearing is keyed by the new
//! environment's id, and the guest clears both agents' delivered logins on a
//! disk's first boot as another environment.

// Snapshots are Linux only, so most of this module is unused on other
// targets.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use super::*;
use crate::control::v1::local_snapshot_service_server::LocalSnapshotService;
use crate::snapshot_store::{
    Retained, SnapshotKind, SnapshotRow, SnapshotState, SnapshotStore, SnapshotStoreError,
};

#[cfg(target_os = "linux")]
use crate::fs_clone::{self, CloneMode};

const SNAPSHOTS_DIRECTORY: &str = "snapshots";
const TRASH_DIRECTORY: &str = "trash";
const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// A VM checkpoint's manifest: schema 1 plus its `checkpoint` object.
pub(in crate::supervisor) const CHECKPOINT_MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAXIMUM_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub(in crate::supervisor) const CAPTURE_STAGING_PREFIX: &str = ".staging-";
const RESTORE_STAGING_PREFIX: &str = ".restore-";
/// `trash/snapshot-delete-<operation>-<id>`, which the orphan inventory knows.
pub(crate) const TRASH_PREFIX: &str = "snapshot-delete-";
/// Free space a sparse copy leaves on the state root's filesystem.
#[cfg(target_os = "linux")]
const COPY_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
/// The largest login file capture reads from a disk image, as the daemon.
#[cfg(target_os = "linux")]
const MAXIMUM_LOGIN_FILE_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const DISK_TOOL_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(target_os = "linux")]
const MAXIMUM_TOOL_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const SPACE_WARNING: &str = "a snapshot and the environments made from it share space only until they change: each copy that diverges takes its own space, and a full host disk can force a running VM's filesystem read-only";
const COPY_WARNING: &str = "this filesystem cannot share blocks between files, so the snapshot is a full copy and holds its disks' allocated bytes now";
#[cfg(not(target_os = "linux"))]
const LINUX_ONLY: &str = "local disk snapshots need a Linux host for now";

/// Where a disk came from and goes back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::supervisor) enum DiskRole {
    State,
    Docker,
    Root,
}

impl DiskRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Docker => "docker",
            Self::Root => "root",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::supervisor) enum Consistency {
    /// The guest shut its filesystems down cleanly.
    Clean,
    /// What a power loss would have left, as after a forced stop.
    Crash,
    /// A VM checkpoint's disks: exact together with its memory, and
    /// crash-consistent alone.
    Paired,
}

impl Consistency {
    pub(in crate::supervisor) fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Crash => "crash",
            Self::Paired => "paired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct ManifestSource {
    pub(in crate::supervisor) environment_id: Uuid,
    pub(in crate::supervisor) name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct ManifestResources {
    pub(in crate::supervisor) vcpus: u8,
    pub(in crate::supervisor) memory_mib: u32,
    pub(in crate::supervisor) disk_bytes: u64,
    pub(in crate::supervisor) docker_disk_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct ManifestDisk {
    pub(in crate::supervisor) role: DiskRole,
    pub(in crate::supervisor) bytes: u64,
    /// `reflink` or `copy`.
    pub(in crate::supervisor) mode: String,
    /// The disk's ext4 UUID, which every copy of it keeps.
    pub(in crate::supervisor) filesystem_uuid: Uuid,
}

/// How the source was created, which a restore's request names again exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct SourceInputs {
    pub(in crate::supervisor) source_path: String,
    pub(in crate::supervisor) implicit_path_mode: String,
    pub(in crate::supervisor) implicit_vm_only: Vec<String>,
}

/// Recorded from the source as information only: a restore derives every
/// one of these again from its own request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct RecordedAuthority {
    pub(in crate::supervisor) platform_source_authority: Option<PlatformSourceAuthority>,
    pub(in crate::supervisor) access_profile_reference: String,
    pub(in crate::supervisor) cw_runtime_catalog_generation: Option<String>,
    pub(in crate::supervisor) host_ports: Vec<HostPortBinding>,
    pub(in crate::supervisor) mesh: Option<MeshAttachment>,
    pub(in crate::supervisor) network_policy: String,
}

/// A signed-in platform account: server, organization and user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct PlatformAccount {
    pub(in crate::supervisor) server_url: String,
    pub(in crate::supervisor) organization_id: String,
    pub(in crate::supervisor) user_id: String,
}

impl PlatformAccount {
    /// The account a request names, validated; `None` when it names none.
    pub(in crate::supervisor) fn from_proto(
        account: Option<&v1::PlatformAccount>,
    ) -> Result<Option<Self>, Status> {
        let Some(account) = account else {
            return Ok(None);
        };
        let valid = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        if ![
            &account.server_url,
            &account.organization_id,
            &account.user_id,
        ]
        .into_iter()
        .all(|value| valid(value))
        {
            return Err(Status::invalid_argument("the platform account is invalid"));
        }
        Ok(Some(Self {
            server_url: account.server_url.clone(),
            organization_id: account.organization_id.clone(),
            user_id: account.user_id.clone(),
        }))
    }

    pub(in crate::supervisor) fn proto(&self) -> v1::PlatformAccount {
        v1::PlatformAccount {
            server_url: self.server_url.clone(),
            organization_id: self.organization_id.clone(),
            user_id: self.user_id.clone(),
        }
    }
}

/// `manifest.json`, schema 1, or 2 for a VM checkpoint. It never holds
/// credential material, the seed or Mesh state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct Manifest {
    pub(in crate::supervisor) schema_version: u32,
    pub(in crate::supervisor) kind: String,
    pub(in crate::supervisor) id: Uuid,
    pub(in crate::supervisor) name: String,
    pub(in crate::supervisor) created_unix_ms: i64,
    pub(in crate::supervisor) source: ManifestSource,
    pub(in crate::supervisor) consistency: Consistency,
    pub(in crate::supervisor) locations: Vec<String>,
    pub(in crate::supervisor) architecture: String,
    pub(in crate::supervisor) resources: ManifestResources,
    pub(in crate::supervisor) disks: Vec<ManifestDisk>,
    pub(in crate::supervisor) project_spec_json: String,
    pub(in crate::supervisor) project_spec_sha256: String,
    pub(in crate::supervisor) workspace_plan: WorkspacePlan,
    pub(in crate::supervisor) root_generation: WorkspaceGenerationRecord,
    /// The source's direct-share admission discriminators, which a restore
    /// journals so a folder swapped since is refused at its boot.
    pub(in crate::supervisor) direct_share_discriminators: String,
    pub(in crate::supervisor) source_inputs: SourceInputs,
    pub(in crate::supervisor) recorded: RecordedAuthority,
    /// The platform account the capturing cw was signed in to, if any. A
    /// restore signed in to another one is refused.
    pub(in crate::supervisor) platform_account: Option<PlatformAccount>,
    pub(in crate::supervisor) removed_logins: u32,
    pub(in crate::supervisor) capture_milliseconds: u64,
    /// What makes a VM checkpoint: present exactly when `kind` is
    /// `checkpoint` (#3046 R4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::supervisor) checkpoint: Option<super::checkpoints::CheckpointManifest>,
}

impl Manifest {
    pub(in crate::supervisor) fn validate(&self, id: Uuid) -> Result<(), SupervisorError> {
        self.root_generation.validate()?;
        self.workspace_plan.validate()?;
        let kind_valid = match (self.kind.as_str(), &self.checkpoint) {
            ("disk", None) => {
                self.schema_version == MANIFEST_SCHEMA_VERSION
                    && self.consistency != Consistency::Paired
            }
            ("checkpoint", Some(checkpoint)) => {
                self.schema_version == CHECKPOINT_MANIFEST_SCHEMA_VERSION
                    && self.consistency == Consistency::Paired
                    && checkpoint.validate(self.resources.memory_mib).is_ok()
            }
            _ => false,
        };
        let roles = self.disks.iter().map(|disk| disk.role).collect::<Vec<_>>();
        let expected = if self.resources.docker_disk_bytes == 0 {
            vec![DiskRole::State, DiskRole::Root]
        } else {
            vec![DiskRole::State, DiskRole::Docker, DiskRole::Root]
        };
        if !kind_valid
            || self.id != id
            || !valid_environment_name(&self.name)
            || self.locations != ["local"]
            || roles != expected
            || validate_project_intent(
                self.project_spec_json.as_bytes(),
                &self.project_spec_sha256,
                None,
            )
            .is_err()
            || self
                .root_generation
                .validate_for_project_intent(
                    self.project_spec_json.as_bytes(),
                    &self.project_spec_sha256,
                )
                .is_err()
            || self.disk(DiskRole::State).map(|disk| disk.bytes) != Some(self.resources.disk_bytes)
            || self.disk(DiskRole::Root).map(|disk| disk.bytes)
                != Some(self.root_generation.root_disk_bytes)
            || (self.resources.docker_disk_bytes != 0
                && self.disk(DiskRole::Docker).map(|disk| disk.bytes)
                    != Some(self.resources.docker_disk_bytes))
        {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }

    /// The store row kind this manifest describes.
    pub(in crate::supervisor) fn row_kind(&self) -> SnapshotKind {
        match self.checkpoint {
            Some(_) => SnapshotKind::Checkpoint {
                source_environment_id: self.source.environment_id,
            },
            None => SnapshotKind::Disk,
        }
    }

    fn disk(&self, role: DiskRole) -> Option<&ManifestDisk> {
        self.disks.iter().find(|disk| disk.role == role)
    }

    pub(in crate::supervisor) fn storage_generation(&self) -> Result<String, SupervisorError> {
        workspace_storage_generation(&self.root_generation).map_err(Into::into)
    }

    /// What collection keeps so this snapshot still boots.
    pub(in crate::supervisor) fn retained(&self) -> Result<Retained, SupervisorError> {
        let mut content = BTreeMap::new();
        retain_image_content(&mut content, &self.root_generation.image)?;
        retain_workspace_plan_content(&mut content, &self.workspace_plan)?;
        Ok(Retained {
            artifact_generations: BTreeSet::from([self
                .root_generation
                .artifact_generation()?
                .to_owned()]),
            content,
        })
    }
}

/// Every snapshot store this process opened, by runtime root: each is
/// reconciled with its directories when it is first used.
static STORES: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<SnapshotStore>>>> =
    std::sync::OnceLock::new();

pub(in crate::supervisor) fn store(
    config: &NativeRuntimeConfig,
) -> Result<Arc<SnapshotStore>, SupervisorError> {
    let mut stores = STORES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(store) = stores.get(&config.root) {
        return Ok(Arc::clone(store));
    }
    let root = PrivateRoot::open(&config.root)?;
    let store = Arc::new(SnapshotStore::open(&root).map_err(store_error)?);
    reconcile(&config.engine_root(), &store)?;
    // Always, not only after an adoption: a new process has no record yet.
    publish_retention(config, &store, None)?;
    stores.insert(config.root.clone(), Arc::clone(&store));
    Ok(store)
}

/// Forget this process's open store and retention for `config`'s root, as
/// a new supervisor process starts without them.
#[cfg(test)]
fn forget_store(config: &NativeRuntimeConfig) {
    STORES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&config.root);
    retained_cache().remove(&config.root);
}

/// Staging trees, snapshot ids and trash trees a call in this process is
/// writing or removing: reconciliation leaves them alone. It holds this lock
/// for its whole pass, so nothing is registered or released while it reads
/// the store and decides what to remove.
static IN_FLIGHT: std::sync::OnceLock<std::sync::Mutex<BTreeSet<String>>> =
    std::sync::OnceLock::new();

fn in_flight() -> std::sync::MutexGuard<'static, BTreeSet<String>> {
    IN_FLIGHT
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One name in flight until dropped.
pub(in crate::supervisor) struct InFlight(String);

impl InFlight {
    pub(in crate::supervisor) fn new(name: String) -> Self {
        in_flight().insert(name.clone());
        Self(name)
    }

    /// `None` when another call already holds `name`.
    fn try_new(name: String) -> Option<Self> {
        in_flight().insert(name.clone()).then_some(Self(name))
    }
}

/// Test hooks at named points, by engine root.
#[cfg(test)]
type TestHook = Box<dyn FnOnce() + Send>;
#[cfg(test)]
static TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<HashMap<(PathBuf, &'static str), TestHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn set_test_hook(engine_root: &Path, point: &'static str, hook: impl FnOnce() + Send + 'static) {
    TEST_HOOKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((engine_root.to_owned(), point), Box::new(hook));
}

/// Run the test hook at `point`, if one is set.
fn test_hook(engine_root: &Path, point: &'static str) {
    #[cfg(test)]
    {
        let hook = TEST_HOOKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(engine_root.to_owned(), point));
        if let Some(hook) = hook {
            hook();
        }
    }
    #[cfg(not(test))]
    let _ = (engine_root, point);
}

impl Drop for InFlight {
    fn drop(&mut self) {
        in_flight().remove(&self.0);
    }
}

/// What collection keeps for every snapshot, by runtime root, in memory:
/// collection reads it under the supervisor's state lock, so it never opens
/// the store or reconciles there.
static RETAINED: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, Retained>>> =
    std::sync::OnceLock::new();
/// The same, beside the store, for a supervisor's first collection.
const RETENTION_FILE: &str = "snapshots-retained.json";

fn retained_cache() -> std::sync::MutexGuard<'static, HashMap<PathBuf, Retained>> {
    RETAINED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Record what collection must keep: every row's retention, plus `extra`,
/// a snapshot about to be inserted. Called before an insert (with it) and
/// after every change, so the record never keeps less than the store.
pub(in crate::supervisor) fn publish_retention(
    config: &NativeRuntimeConfig,
    store: &SnapshotStore,
    extra: Option<&Retained>,
) -> Result<(), SupervisorError> {
    let mut retained = store.retained().map_err(store_error)?;
    if let Some(extra) = extra {
        retained
            .artifact_generations
            .extend(extra.artifact_generations.iter().cloned());
        for (digest, size) in &extra.content {
            retained.content.entry(digest.clone()).or_insert(*size);
        }
    }
    let bytes = serde_json::to_vec(&retained).map_err(|_| SupervisorError::InvalidState)?;
    PrivateRoot::open(&config.root)?.atomic_replace(Path::new(RETENTION_FILE), &bytes, 0o600)?;
    retained_cache().insert(config.root.clone(), retained);
    Ok(())
}

pub(in crate::supervisor) fn store_error(error: SnapshotStoreError) -> SupervisorError {
    match error {
        SnapshotStoreError::Path(error) => SupervisorError::Path(error),
        _ => SupervisorError::InvalidState,
    }
}

pub(in crate::supervisor) fn store_status(error: SnapshotStoreError) -> Status {
    match error {
        SnapshotStoreError::AlreadyExists(_) => Status::already_exists(error.to_string()),
        SnapshotStoreError::TooManySnapshots => Status::resource_exhausted(error.to_string()),
        _ => Status::internal(format!("the local snapshot store failed: {error}")),
    }
}

fn status(error: SupervisorError) -> Status {
    Status::from(error)
}

pub(in crate::supervisor) fn snapshots_root(
    engine_root: &Path,
) -> Result<PrivateRoot, SupervisorError> {
    let engine = PrivateRoot::open(engine_root)?;
    let path = engine.ensure_dir(Path::new(SNAPSHOTS_DIRECTORY), 0o700)?;
    Ok(PrivateRoot::open(&path)?)
}

fn trash_root(engine_root: &Path) -> Result<PrivateRoot, SupervisorError> {
    let engine = PrivateRoot::open(engine_root)?;
    let path = engine.ensure_dir(Path::new(TRASH_DIRECTORY), 0o700)?;
    Ok(PrivateRoot::open(&path)?)
}

pub(in crate::supervisor) fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

pub(in crate::supervisor) fn canonical_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}

// ---------------------------------------------------------------------------
// Supervisor hooks (supervisor.rs calls each once).

/// Journal a create's `snapshot` selection in its payload. Absent unless the
/// request restores one, so every other create's payload is unchanged.
pub(super) fn journal_payload(
    payload: &mut serde_json::Value,
    request: &v1::CreateEnvironmentRequest,
) -> Result<(), SupervisorError> {
    let Some(snapshot) = request.snapshot.as_ref() else {
        return Ok(());
    };
    let id = canonical_id(&snapshot.snapshot_id).ok_or(SupervisorError::InvalidRequest)?;
    if !valid_restore_resources(snapshot.vcpus, snapshot.memory_mib) {
        return Err(SupervisorError::InvalidRequest);
    }
    let account = PlatformAccount::from_proto(snapshot.account.as_ref())
        .map_err(|_| SupervisorError::InvalidRequest)?;
    payload
        .as_object_mut()
        .ok_or(SupervisorError::InvalidState)?
        .insert(
            "snapshot".to_owned(),
            serde_json::json!({
                "id": id,
                "vcpus": snapshot.vcpus,
                "memory_mib": snapshot.memory_mib,
                "share_mounts": snapshot.share_mounts,
                "account": account,
            }),
        );
    Ok(())
}

/// The `snapshot` selection a journaled create payload names, if any.
pub(super) fn from_payload(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<v1::SnapshotRestore>, SupervisorError> {
    let Some(value) = fields.get("snapshot") else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .filter(|object| object.len() == 5)
        .ok_or(SupervisorError::InvalidState)?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(canonical_id)
        .ok_or(SupervisorError::InvalidState)?;
    let number = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(SupervisorError::InvalidState)
    };
    let restore = v1::SnapshotRestore {
        snapshot_id: id.to_string(),
        vcpus: number("vcpus")?,
        memory_mib: number("memory_mib")?,
        share_mounts: object
            .get("share_mounts")
            .and_then(serde_json::Value::as_bool)
            .ok_or(SupervisorError::InvalidState)?,
        account: serde_json::from_value::<Option<PlatformAccount>>(
            object
                .get("account")
                .cloned()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?
        .map(|account| account.proto()),
    };
    if PlatformAccount::from_proto(restore.account.as_ref()).is_err() {
        return Err(SupervisorError::InvalidState);
    }
    if !valid_restore_resources(restore.vcpus, restore.memory_mib) {
        return Err(SupervisorError::InvalidState);
    }
    Ok(Some(restore))
}

fn valid_restore_resources(vcpus: u32, memory_mib: u32) -> bool {
    (1..=32).contains(&vcpus) && (128..=65_536).contains(&memory_mib)
}

/// What a restoring create's RecordEnvironment records from its snapshot
/// instead of the installed runtime: the snapshot's pinned artifact
/// generation, the requested vCPUs and memory, and the snapshot's disk sizes.
pub(super) struct RestoreRecord {
    pub(super) artifact_generation: String,
    /// A VM checkpoint fork's recorded cw runtime catalog: `Some(None)` when
    /// the captured boot had none. `None` for a disk snapshot, which admits
    /// the installed runtime as a plain create does.
    pub(super) checkpoint_cw_runtime: Option<Option<String>>,
    pub(super) vcpus: u8,
    pub(super) memory_mib: u32,
    pub(super) disk_bytes: u64,
    pub(super) docker_disk_bytes: u64,
}

impl RestoreRecord {
    /// The recorded resources of a create: its request's, or a restore's.
    pub(super) fn resources(
        restore: Option<&Self>,
        request: &v1::CreateEnvironmentRequest,
    ) -> Result<(u8, u32, u64, u64), SupervisorError> {
        match restore {
            Some(restore) => Ok((
                restore.vcpus,
                restore.memory_mib,
                restore.disk_bytes,
                restore.docker_disk_bytes,
            )),
            None => Ok((
                u8::try_from(request.vcpus).map_err(|_| SupervisorError::InvalidRequest)?,
                request.memory_mib,
                request.disk_bytes,
                request.docker_disk_bytes,
            )),
        }
    }
}

/// For a create that restores a snapshot, what RecordEnvironment records from
/// it; `None` for any other create. The pinned artifact generation is
/// admitted as preflight admits the installed one.
pub(super) async fn record_inputs(
    supervisor: &Supervisor,
    request: &v1::CreateEnvironmentRequest,
) -> Result<Option<RestoreRecord>, SupervisorError> {
    let Some(restore) = request.snapshot.as_ref() else {
        return Ok(None);
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (supervisor, restore);
        Err(SupervisorError::InvalidRequest)
    }
    #[cfg(target_os = "linux")]
    {
        let id = canonical_id(&restore.snapshot_id).ok_or(SupervisorError::InvalidRequest)?;
        let (_, manifest) = ready_snapshot(&supervisor.config, id)?;
        if manifest.checkpoint.is_some()
            && (restore.vcpus != u32::from(manifest.resources.vcpus)
                || restore.memory_mib != manifest.resources.memory_mib)
        {
            return Err(SupervisorError::InvalidRequest);
        }
        let artifact_generation = manifest.root_generation.artifact_generation()?.to_owned();
        supervisor
            .require_guest_seed_abi_for_generation(&artifact_generation)
            .await?;
        if fs::symlink_metadata(supervisor.config.cw_runtime_lock()).is_ok() {
            let engine = PrivateRoot::open(&supervisor.config.engine_root())?;
            RuntimeArtifactStore::create(&engine)
                .map_err(artifact_store_error)?
                .open_generation(&artifact_generation)
                .await
                .map_err(artifact_store_error)?
                .require_live_cw_runtime_publisher()?;
        }
        crate::linux::preflight::preflight().map_err(RunnerError::from)?;
        Ok(Some(RestoreRecord {
            artifact_generation,
            checkpoint_cw_runtime: manifest
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.boot.cw_runtime_catalog_generation.clone()),
            vcpus: u8::try_from(restore.vcpus).map_err(|_| SupervisorError::InvalidRequest)?,
            memory_mib: restore.memory_mib,
            disk_bytes: manifest.resources.disk_bytes,
            docker_disk_bytes: manifest.resources.docker_disk_bytes,
        }))
    }
}

/// Open a VM checkpoint's recorded cw runtime catalog from the private store,
/// as a start opens its environment's binding. Never the installed runtime.
pub(super) fn open_recorded_cw_runtime_catalog(
    config: &NativeRuntimeConfig,
    generation: &str,
) -> Result<String, SupervisorError> {
    let engine = PrivateRoot::open(&config.engine_root())?;
    crate::cw_runtime::CwRuntimeStore::create(&engine)?.open_catalog(generation)?;
    Ok(generation.to_owned())
}

/// What garbage collection keeps for every snapshot: its artifact generation
/// and the content its root generation and workspace plan reference, so a
/// snapshot boots after `cw upgrade` even once its source is gone.
pub(super) fn retain(
    config: &NativeRuntimeConfig,
    content: &mut BTreeMap<Sha256Digest, u64>,
    artifacts: &mut BTreeSet<String>,
) -> Result<(), SupervisorError> {
    // The guard is released before a miss reads the record, which may
    // publish it again.
    let cached = retained_cache().get(&config.root).cloned();
    let retained = match cached {
        Some(retained) => retained,
        None => match read_retention(config) {
            Retention::Exact(retained) => {
                retained_cache().insert(config.root.clone(), retained.clone());
                retained
            }
            Retention::Everything => return retain_everything(config, content, artifacts),
        },
    };
    for (digest, size) in retained.content {
        retain_content_blob(content, &digest, size)?;
    }
    for generation in retained.artifact_generations {
        retain_artifact_generation(artifacts, &generation)?;
    }
    Ok(())
}

/// What collection keeps for snapshots when this process has no record in
/// memory.
enum Retention {
    Exact(Retained),
    /// Retention could not be read: keep everything this round.
    Everything,
}

/// The retention record a previous supervisor published; without one, what
/// the snapshot directories' manifests say, read-only. Any other failure
/// keeps everything. Never SQLite, never reconciliation: collection runs
/// under the supervisor's state lock.
fn read_retention(config: &NativeRuntimeConfig) -> Retention {
    let Ok(root) = PrivateRoot::open(&config.root) else {
        return Retention::Everything;
    };
    match root.open_regular(Path::new(RETENTION_FILE), false, None, false, Some(0o600)) {
        Ok(opened) => {
            let mut bytes = Vec::new();
            if io::Read::read_to_end(
                &mut io::Read::take(opened.file(), MAXIMUM_MANIFEST_BYTES + 1),
                &mut bytes,
            )
            .is_err()
            {
                return Retention::Everything;
            }
            serde_json::from_slice(&bytes).map_or(Retention::Everything, Retention::Exact)
        }
        Err(error) if path_not_found(&error) => retention_from_manifests(&config.engine_root())
            .map_or(Retention::Everything, Retention::Exact),
        Err(_) => Retention::Everything,
    }
}

fn path_not_found(error: &PathError) -> bool {
    match error {
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        _ => false,
    }
}

/// The retention of every snapshot directory, from its manifest, read-only.
/// A directory whose manifest cannot be read and validated fails it.
fn retention_from_manifests(engine_root: &Path) -> Result<Retained, SupervisorError> {
    let mut all = Retained::default();
    let directory = engine_root.join(SNAPSHOTS_DIRECTORY);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(all),
        Err(source) => {
            return Err(SupervisorError::Io {
                path: directory,
                source,
            });
        }
    };
    let snapshots = PrivateRoot::open(&directory)?;
    for entry in entries {
        let entry = entry.map_err(|source| SupervisorError::Io {
            path: directory.clone(),
            source,
        })?;
        let Some(id) = entry.file_name().to_str().and_then(canonical_id) else {
            continue;
        };
        let snapshot = snapshots.open_private_directory(Path::new(&id.to_string()), 0o700)?;
        let opened =
            snapshot.open_regular(Path::new(MANIFEST_FILE), false, None, false, Some(0o400))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(
            &mut io::Read::take(opened.file(), MAXIMUM_MANIFEST_BYTES + 1),
            &mut bytes,
        )
        .map_err(|source| SupervisorError::Io {
            path: snapshot.path().join(MANIFEST_FILE),
            source,
        })?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| SupervisorError::InvalidState)?;
        manifest.validate(id)?;
        let retained = manifest.retained()?;
        all.artifact_generations
            .extend(retained.artifact_generations);
        for (digest, size) in retained.content {
            all.content.entry(digest).or_insert(size);
        }
    }
    Ok(all)
}

/// Keep every runtime artifact generation and content blob on disk: what
/// collection does when it cannot read what snapshots need. Any listing it
/// cannot read fails it, so collection skips the round rather than keep
/// less than everything; a directory that does not exist holds nothing.
fn retain_everything(
    config: &NativeRuntimeConfig,
    content: &mut BTreeMap<Sha256Digest, u64>,
    artifacts: &mut BTreeSet<String>,
) -> Result<(), SupervisorError> {
    let engine = config.engine_root();
    let generations = engine.join("runtime-artifacts").join("generations");
    for entry in listing(&generations)? {
        if let Some(generation) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|generation| valid_sha256(generation))
        {
            artifacts.insert(generation.to_owned());
        }
    }
    let blobs = engine.join("content").join("blobs");
    for entry in listing(&blobs)? {
        let Some(digest) = entry
            .file_name()
            .to_str()
            .filter(|name| valid_sha256(name))
            .and_then(|name| Sha256Digest::parse(&format!("sha256:{name}")).ok())
        else {
            continue;
        };
        let metadata = entry.metadata().map_err(|source| SupervisorError::Io {
            path: entry.path(),
            source,
        })?;
        content.entry(digest).or_insert(metadata.len());
    }
    Ok(())
}

/// Every entry of `directory`, none when it does not exist; any other
/// error, for the directory or one entry, fails.
fn listing(directory: &Path) -> Result<Vec<fs::DirEntry>, SupervisorError> {
    let io_error = |source| SupervisorError::Io {
        path: directory.to_owned(),
        source,
    };
    match fs::read_dir(directory) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>().map_err(io_error),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(io_error(source)),
    }
}

/// The pre-journal admission of a create that restores a snapshot, in place
/// of preparing its workspace: the snapshot's workspace plan and its direct
/// shares' recorded discriminators, once every refusal has been checked.
pub(super) async fn restore_plan(
    supervisor: &Supervisor,
    request: &v1::CreateEnvironmentRequest,
) -> Result<(WorkspacePlan, DirectShareDiscriminators), Status> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (supervisor, request);
        Err(Status::unimplemented(LINUX_ONLY))
    }
    #[cfg(target_os = "linux")]
    {
        let restore = request
            .snapshot
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("the create names no snapshot"))?;
        let id = canonical_id(&restore.snapshot_id)
            .ok_or_else(|| Status::invalid_argument("a snapshot is named by its id"))?;
        let config = supervisor.config.clone();
        let (row, manifest) = tokio::task::spawn_blocking(move || ready_snapshot(&config, id))
            .await
            .map_err(|_| Status::internal("snapshot admission task failed"))?
            .map_err(|error| match error {
                SupervisorError::NotFound(_) => Status::not_found(format!(
                    "no local snapshot has id {id}; list them with `cw snapshot ls`"
                )),
                other => status(other),
            })?;
        admit_restore_request(&row, &manifest, request)?;
        // A fork boots the cw runtime catalog its VM checkpoint's memory was
        // booted with, never the installed one; refuse here, with the
        // checkpoint's name, if that catalog is gone (#3046).
        if let Some(generation) = manifest
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.boot.cw_runtime_catalog_generation.clone())
        {
            let config = supervisor.config.clone();
            let present = tokio::task::spawn_blocking(move || {
                open_recorded_cw_runtime_catalog(&config, &generation).is_ok()
            })
            .await
            .map_err(|_| Status::internal("snapshot admission task failed"))?;
            if !present {
                return Err(Status::failed_precondition(format!(
                    "VM checkpoint {}'s cw runtime is no longer in the local store; it cannot be forked",
                    row.name
                )));
            }
        }
        Ok((
            manifest.workspace_plan,
            DirectShareDiscriminators::decode(&manifest.direct_share_discriminators),
        ))
    }
}

/// Every refusal a restore's request can meet before it is journaled.
fn admit_restore_request(
    row: &SnapshotRow,
    manifest: &Manifest,
    request: &v1::CreateEnvironmentRequest,
) -> Result<(), Status> {
    let restore = request
        .snapshot
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("the create names no snapshot"))?;
    let name = &row.name;
    // A fork of a VM checkpoint creates through this path too.
    let (kind, flag) = if manifest.checkpoint.is_some() {
        ("VM checkpoint", "--checkpoint")
    } else {
        ("snapshot", "--snapshot")
    };
    let native = crate::oci::OciArchitecture::native()
        .map(|architecture| architecture.as_str())
        .unwrap_or("unknown");
    if manifest.architecture != native {
        return Err(Status::failed_precondition(format!(
            "{kind} {name} holds {} disks, and this host runs {native}",
            manifest.architecture
        )));
    }
    if !valid_restore_resources(restore.vcpus, restore.memory_mib) {
        return Err(Status::invalid_argument(
            "a restore takes 1 to 32 vCPUs and 128 to 65536 MiB of memory",
        ));
    }
    if manifest.checkpoint.is_some() {
        // A memory image cannot change shape.
        if restore.vcpus != u32::from(manifest.resources.vcpus)
            || restore.memory_mib != manifest.resources.memory_mib
        {
            return Err(Status::invalid_argument(format!(
                "a fork of VM checkpoint {name} has its {} vCPUs and {} MiB of memory",
                manifest.resources.vcpus, manifest.resources.memory_mib
            )));
        }
        if manifest
            .workspace_plan
            .inputs
            .iter()
            .any(|input| matches!(input, WorkspaceInput::Direct { .. }))
        {
            return Err(Status::failed_precondition(format!(
                "VM checkpoint {name}'s source mounts host folders directly, which forks do not support yet"
            )));
        }
    }
    // The built root accepts only its own project, sources aside.
    manifest
        .root_generation
        .validate_for_project_intent(&request.project_spec_json, &request.project_spec_sha256)
        .map_err(|_| {
            Status::failed_precondition(format!(
                "the create does not name {kind} {name}'s project; create from it with `cw create --local {flag} {name}`"
            ))
        })?;
    let project: codewire_project::ProjectSpec = serde_json::from_slice(&request.project_spec_json)
        .map_err(|_| Status::invalid_argument("the project is not valid JSON"))?;
    validate_request_workspace_plan(request, &project, &manifest.workspace_plan).map_err(|_| {
        Status::failed_precondition(format!(
            "the create does not name {kind} {name}'s workspace inputs exactly"
        ))
    })?;
    if request.docker_disk_bytes != manifest.resources.docker_disk_bytes {
        return Err(Status::failed_precondition(format!(
            "{kind} {name}'s Docker disk is {} bytes; a restore keeps it",
            manifest.resources.docker_disk_bytes
        )));
    }
    let direct = manifest
        .workspace_plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            WorkspaceInput::Direct { source_path, .. } => {
                Some(String::from_utf8_lossy(source_path).into_owned())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !direct.is_empty() && !restore.share_mounts {
        return Err(Status::failed_precondition(format!(
            "{kind} {name}'s source mounts host folders directly ({}); an environment made from it mounts the same folders live, shared with every other one that does. Pass --share-mounts to accept that",
            direct.join(", ")
        )));
    }
    // Signed in to two different platform accounts: the snapshot's and this
    // restore's. With either side signed out, nothing is compared.
    let fresh = PlatformAccount::from_proto(restore.account.as_ref())?;
    if let (Some(recorded), Some(fresh)) = (manifest.platform_account.as_ref(), fresh.as_ref())
        && recorded != fresh
    {
        return Err(Status::permission_denied(format!(
            "{kind} {name} was captured while signed in to {} as user {} in organization {}, and this cw is signed in to {} as user {} in organization {}; sign in as its account (`cw login`) to create from it",
            recorded.server_url,
            recorded.user_id,
            recorded.organization_id,
            fresh.server_url,
            fresh.user_id,
            fresh.organization_id
        )));
    }
    Ok(())
}

/// A restoring create's ProvisionWorkspace: place the snapshot's disks for
/// the new environment and record its root generation as active, in one
/// transaction with the checkpoint. Replay finds a complete tree and only
/// records it.
pub(super) async fn place_disks(
    supervisor: &Supervisor,
    request: &v1::CreateEnvironmentRequest,
    environment_id: Uuid,
    operation: &OperationRecord,
) -> Result<OperationRecord, SupervisorError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (supervisor, request, environment_id, operation);
        Err(SupervisorError::InvalidRequest)
    }
    #[cfg(target_os = "linux")]
    {
        let restore = request
            .snapshot
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let snapshot_id =
            canonical_id(&restore.snapshot_id).ok_or(SupervisorError::InvalidState)?;
        let environment = supervisor.environment(&request.name)?;
        if environment.id != environment_id {
            return Err(SupervisorError::InvalidState);
        }
        let config = supervisor.config.clone();
        let operation_id = operation.operation_id;
        let expected = (environment.disk_bytes, environment.docker_disk_bytes);
        let root_generation = tokio::task::spawn_blocking(move || {
            place_snapshot_tree(&config, snapshot_id, environment_id, operation_id, expected)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
        // ProvisionWorkspace is an idempotent external effect: the tree is
        // published, then its root generation recorded (again, identically,
        // on a replay), then the ordinary checkpoint taken.
        supervisor.update_environment(&request.name, |environment| {
            if environment.id != environment_id
                || environment.active_artifact_generation.as_deref()
                    != Some(root_generation.artifact_generation()?)
                || environment.staging_workspace_generation.is_some()
                || environment
                    .active_workspace_generation
                    .as_ref()
                    .is_some_and(|active| active != &root_generation)
            {
                return Err(SupervisorError::InvalidState);
            }
            environment.active_workspace_generation = Some(root_generation);
            Ok(())
        })?;
        supervisor.core().checkpoint_operation(operation)
    }
}

// ---------------------------------------------------------------------------
// The snapshot RPCs.

#[tonic::async_trait]
impl LocalSnapshotService for SupervisorRpc {
    async fn create_snapshot(
        &self,
        request: Request<v1::CreateSnapshotRequest>,
    ) -> Result<Response<v1::Snapshot>, Status> {
        self.start_drains()?;
        let request = request.into_inner();
        let supervisor = Arc::clone(&self.supervisor);
        // In a task of its own: a dropped request never cuts a copy short
        // while it holds the source's lease and lock.
        tokio::spawn(async move { capture(&supervisor, request).await })
            .await
            .map_err(|_| Status::internal("snapshot capture task failed"))?
            .map(Response::new)
    }

    async fn list_snapshots(
        &self,
        _request: Request<v1::ListSnapshotsRequest>,
    ) -> Result<Response<v1::ListSnapshotsResponse>, Status> {
        let config = self.supervisor.config.clone();
        let snapshots = tokio::task::spawn_blocking(move || list(&config))
            .await
            .map_err(|_| Status::internal("snapshot listing task failed"))??;
        Ok(Response::new(v1::ListSnapshotsResponse { snapshots }))
    }

    async fn get_snapshot(
        &self,
        request: Request<v1::SnapshotSelector>,
    ) -> Result<Response<v1::Snapshot>, Status> {
        let selector = request.into_inner().snapshot;
        let config = self.supervisor.config.clone();
        tokio::task::spawn_blocking(move || get(&config, &selector))
            .await
            .map_err(|_| Status::internal("snapshot inspection task failed"))?
            .map(Response::new)
    }

    async fn delete_snapshot(
        &self,
        request: Request<v1::SnapshotSelector>,
    ) -> Result<Response<v1::Snapshot>, Status> {
        let selector = request.into_inner().snapshot;
        let config = self.supervisor.config.clone();
        tokio::task::spawn_blocking(move || delete(&config, &selector))
            .await
            .map_err(|_| Status::internal("snapshot deletion task failed"))?
            .map(Response::new)
    }
}

#[cfg(not(target_os = "linux"))]
async fn capture(
    _supervisor: &Supervisor,
    _request: v1::CreateSnapshotRequest,
) -> Result<v1::Snapshot, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn list(_config: &NativeRuntimeConfig) -> Result<Vec<v1::Snapshot>, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn get(_config: &NativeRuntimeConfig, _selector: &str) -> Result<v1::Snapshot, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn delete(_config: &NativeRuntimeConfig, _selector: &str) -> Result<v1::Snapshot, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn reconcile(_engine_root: &Path, _store: &SnapshotStore) -> Result<(), SupervisorError> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};

    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;
    use zeroize::Zeroizing;

    use super::*;

    /// The ready snapshot or VM checkpoint `id` and its verified manifest:
    /// a create from a VM checkpoint is a live fork (#3046 R4), which places
    /// the checkpoint's disks as a restore places a snapshot's, plus its VMM
    /// files.
    pub(super) fn ready_snapshot(
        config: &NativeRuntimeConfig,
        id: Uuid,
    ) -> Result<(SnapshotRow, Manifest), SupervisorError> {
        let row = store(config)?
            .find(&id.to_string())
            .map_err(store_error)?
            .filter(|row| row.state == SnapshotState::Ready)
            .ok_or_else(|| SupervisorError::NotFound(id.to_string()))?;
        let manifest = read_manifest(&config.engine_root(), &row)?;
        Ok((row, manifest))
    }

    pub(in crate::supervisor) fn read_manifest(
        engine_root: &Path,
        row: &SnapshotRow,
    ) -> Result<Manifest, SupervisorError> {
        let snapshots = snapshots_root(engine_root)?;
        let directory = snapshots.open_private_directory(Path::new(&row.id.to_string()), 0o700)?;
        let opened =
            directory.open_regular(Path::new(MANIFEST_FILE), false, None, false, Some(0o400))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(
            &mut io::Read::take(opened.file(), MAXIMUM_MANIFEST_BYTES + 1),
            &mut bytes,
        )
        .map_err(|source| SupervisorError::Io {
            path: directory.path().join(MANIFEST_FILE),
            source,
        })?;
        if bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES
            || format!("{:x}", Sha256::digest(&bytes)) != row.manifest_sha256
        {
            return Err(SupervisorError::InvalidState);
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| SupervisorError::InvalidState)?;
        manifest.validate(row.id)?;
        if manifest.name != row.name || manifest.row_kind() != row.kind {
            return Err(SupervisorError::InvalidState);
        }
        Ok(manifest)
    }

    // -----------------------------------------------------------------------
    // Capture.

    pub(super) async fn capture(
        supervisor: &Supervisor,
        request: v1::CreateSnapshotRequest,
    ) -> Result<v1::Snapshot, Status> {
        let started = std::time::Instant::now();
        if !valid_environment_name(&request.environment) {
            return Err(Status::invalid_argument("name the environment to snapshot"));
        }
        if !valid_environment_name(&request.name) {
            return Err(Status::invalid_argument(
                "a snapshot name is 1 to 63 letters, digits, `-`, `_` or `.`, starting with a letter or digit",
            ));
        }
        if Uuid::parse_str(&request.name).is_ok() {
            return Err(Status::invalid_argument(
                "a snapshot name cannot be a UUID, which names snapshots by id; choose another name",
            ));
        }
        let account = PlatformAccount::from_proto(request.account.as_ref())?;
        // A publication an earlier call left unfinished is settled first,
        // off the async workers: settling may remove large trees.
        let settling = supervisor.config.clone();
        let store = tokio::task::spawn_blocking(move || {
            let store = store(&settling)?;
            settle(&settling, &store)?;
            Ok::<_, SupervisorError>(store)
        })
        .await
        .map_err(|_| Status::internal("snapshot reconciliation task failed"))?
        .map_err(status)?;
        store.require_free(&request.name).map_err(store_status)?;
        let name = request.environment.clone();
        // The name lease for the whole capture: no operation of the source
        // runs until it ends.
        let _lease = supervisor.quiet_lease(&name).await.map_err(status)?;
        let environment = admit_source(supervisor, &name).await?;
        let proto = supervisor.core().environment_proto(&name).map_err(status)?;
        let discriminators = supervisor
            .core()
            .store
            .direct_share_discriminators(environment.id)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let config = supervisor.config.clone();
        let snapshot_name = request.name.clone();
        let operation_id = Uuid::new_v4();
        let snapshot_id = Uuid::new_v4();
        let _staging_in_flight = InFlight::new(format!("{CAPTURE_STAGING_PREFIX}{operation_id}"));
        let _snapshot_in_flight = InFlight::new(snapshot_id.to_string());
        let staged = tokio::task::spawn_blocking(move || {
            copy_source(&config, &environment, operation_id).map(|copied| (environment, copied))
        })
        .await
        .map_err(|_| Status::internal("snapshot copy task failed"))??;
        let (environment, copied) = staged;
        let staging = copied.staging.clone();
        let mut cleanup = StagingCleanup::new(staging.clone());
        let consistency = copied.consistency;
        let removed_logins = scrub_state_disk(&staging.join("disks/state.raw"))
            .await
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "the copy of {name}'s state disk could not be cleared of delivered sign-ins, so no snapshot was kept: {error}"
                ))
            })?;
        let manifest = Manifest {
            checkpoint: None,
            schema_version: MANIFEST_SCHEMA_VERSION,
            kind: "disk".to_owned(),
            id: snapshot_id,
            name: snapshot_name.clone(),
            created_unix_ms: now_unix_ms(),
            source: ManifestSource {
                environment_id: environment.id,
                name: environment.name.clone(),
            },
            consistency,
            locations: vec!["local".to_owned()],
            architecture: environment
                .active_workspace_generation
                .as_ref()
                .map(|generation| generation.image.architecture.as_str().to_owned())
                .ok_or_else(|| status(SupervisorError::InvalidState))?,
            resources: ManifestResources {
                vcpus: environment.vcpus,
                memory_mib: environment.memory_mib,
                disk_bytes: environment.disk_bytes,
                docker_disk_bytes: environment.docker_disk_bytes,
            },
            disks: copied.disks.clone(),
            project_spec_json: String::from_utf8(
                environment
                    .project_spec_json
                    .clone()
                    .ok_or_else(|| status(SupervisorError::InvalidState))?,
            )
            .map_err(|_| status(SupervisorError::InvalidState))?,
            project_spec_sha256: environment
                .project_spec_sha256
                .clone()
                .ok_or_else(|| status(SupervisorError::InvalidState))?,
            workspace_plan: environment.workspace_plan.clone(),
            root_generation: environment
                .active_workspace_generation
                .clone()
                .ok_or_else(|| status(SupervisorError::InvalidState))?,
            direct_share_discriminators: discriminators.encode(),
            source_inputs: source_inputs(&environment).map_err(status)?,
            recorded: RecordedAuthority {
                platform_source_authority: environment.platform_source_authority.clone(),
                access_profile_reference: proto.access_profile.clone(),
                cw_runtime_catalog_generation: environment
                    .cw_runtime
                    .as_ref()
                    .map(|binding| binding.active_catalog_generation.clone()),
                host_ports: environment.host_ports.clone(),
                mesh: environment.mesh.clone(),
                network_policy: proto
                    .network_policy
                    .as_ref()
                    .map(|policy| policy.reference.clone())
                    .unwrap_or_default(),
            },
            platform_account: account,
            removed_logins,
            capture_milliseconds: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        let staging_name = copied.staging_name.clone();
        let row = publish(
            &supervisor.config,
            &store,
            staging_name,
            &manifest,
            &mut || cleanup.disarm(),
        )
        .await?;
        snapshot_proto(&supervisor.config.engine_root(), &row, &manifest, true).map_err(status)
    }

    /// Publish the complete staging tree `staging_name` under `manifest`'s
    /// id and name it in the store: a capture intent first, the retention
    /// collection must keep, the manifest and one rename, then the row.
    /// `published` runs once the tree has its final name.
    pub(in crate::supervisor) async fn publish(
        config: &NativeRuntimeConfig,
        store: &SnapshotStore,
        staging_name: String,
        manifest: &Manifest,
        published: &mut (dyn FnMut() + Send),
    ) -> Result<SnapshotRow, Status> {
        let id = manifest.id;
        manifest.validate(id).map_err(status)?;
        let retained = manifest.retained().map_err(status)?;
        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|_| status(SupervisorError::InvalidState))?;
        let engine_root = config.engine_root();
        let manifest_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let publish_root = engine_root.clone();
        // Before the directory is named: a directory with an intent and no
        // row is a capture that never finished. Collection keeps the new
        // snapshot's roots from here.
        store.record_intent(id).map_err(store_status)?;
        publish_retention(config, store, Some(&retained)).map_err(status)?;
        tokio::task::spawn_blocking(move || {
            publish_capture(&publish_root, &staging_name, id, &bytes)
        })
        .await
        .map_err(|_| Status::internal("snapshot publication task failed"))?
        .map_err(status)?;
        published();
        test_hook(&engine_root, "capture-published");
        let row = SnapshotRow {
            id,
            kind: manifest.row_kind(),
            name: manifest.name.clone(),
            state: SnapshotState::Ready,
            created_unix_ms: manifest.created_unix_ms,
            manifest_sha256,
            retained,
        };
        if let Err(error) = store.insert(&row) {
            // Published but not named: nothing can refer to it, so it goes,
            // here or at the next call's reconciliation.
            if remove_published(&engine_root, id, Uuid::new_v4()).is_ok() {
                let _ = store.remove_intent(id);
            }
            let _ = publish_retention(config, store, None);
            return Err(store_status(error));
        }
        publish_retention(config, store, None).map_err(status)?;
        Ok(row)
    }

    /// The source, stopped with no staged change, once its idle runner is
    /// retired. The caller holds its lease.
    async fn admit_source(
        supervisor: &Supervisor,
        name: &str,
    ) -> Result<EnvironmentRecord, Status> {
        let environment = supervisor.environment(name).map_err(|_| {
            Status::not_found(format!(
                "no local environment is named {name}; list them with `cw ls --local`"
            ))
        })?;
        require_stopped(&environment)?;
        if environment.runner.is_some() {
            // A stopped VM's runner stays idle for a while; retire it here, as
            // the idle reaper would, so nothing can start the VM meanwhile.
            if !supervisor.core().live_runners.contains_key(&environment.id) {
                supervisor.reconcile(name).await.map_err(status)?;
            }
            let current = supervisor.environment(name).map_err(status)?;
            require_stopped(&current)?;
            if let Some(runner) = current.runner.clone() {
                supervisor
                    .retire_idle_runner(name, &runner)
                    .await
                    .map_err(status)?;
                supervisor.core().idle_runners.remove(&current.id);
            }
        }
        let environment = supervisor.environment(name).map_err(status)?;
        require_stopped(&environment)?;
        require_settled(&environment)?;
        Ok(environment)
    }

    fn require_stopped(environment: &EnvironmentRecord) -> Result<(), Status> {
        let name = &environment.name;
        match environment.state {
            StoredEnvironmentState::Stopped => Ok(()),
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting => {
                Err(Status::failed_precondition(format!(
                    "{name} is running; stop it first (`cw stop {name}`), or snapshot it later with a VM checkpoint"
                )))
            }
            StoredEnvironmentState::Error | StoredEnvironmentState::Orphaned => {
                Err(Status::failed_precondition(format!(
                    "{name} is in state {}; start and stop it so it is cleanly stopped, then snapshot it",
                    environment.state.as_str()
                )))
            }
        }
    }

    /// No runner and nothing staged: the disks are exactly the active ones.
    fn require_settled(environment: &EnvironmentRecord) -> Result<(), Status> {
        let name = &environment.name;
        if environment.runner.is_some() {
            return Err(Status::failed_precondition(format!(
                "{name}'s runner is still live; try again in a moment"
            )));
        }
        if environment.staging_workspace_generation.is_some()
            || environment.staging_artifact_generation.is_some()
            || environment
                .cw_runtime
                .as_ref()
                .is_some_and(|binding| binding.staging_catalog_generation.is_some())
        {
            return Err(Status::failed_precondition(format!(
                "{name} has an unfinished workspace or runtime change; start it once so it completes (`cw start {name}`), stop it, then snapshot it"
            )));
        }
        if environment.active_workspace_generation.is_none()
            || environment.active_artifact_generation.is_none()
            || environment.generation == 0
        {
            return Err(Status::failed_precondition(format!(
                "{name} has never finished starting; start it once (`cw start {name}`), stop it, then snapshot it"
            )));
        }
        Ok(())
    }

    /// The source's request inputs, recovered from its workspace plan.
    pub(in crate::supervisor) fn source_inputs(
        environment: &EnvironmentRecord,
    ) -> Result<SourceInputs, SupervisorError> {
        let project: codewire_project::ProjectSpec = serde_json::from_slice(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?;
        if project.repositories.is_empty()
            && let [
                WorkspaceInput::Local {
                    source_path,
                    mode,
                    destination,
                    vm_only,
                    ..
                },
            ] = environment.workspace_plan.inputs.as_slice()
            && destination == "/workspace"
        {
            return Ok(SourceInputs {
                source_path: String::from_utf8(source_path.clone())
                    .map_err(|_| SupervisorError::InvalidState)?,
                implicit_path_mode: match mode {
                    WorkspaceSourceMode::Clone => "clone",
                    WorkspaceSourceMode::Copy => "copy",
                }
                .to_owned(),
                implicit_vm_only: vm_only.clone(),
            });
        }
        Ok(SourceInputs {
            source_path: String::new(),
            implicit_path_mode: String::new(),
            implicit_vm_only: Vec::new(),
        })
    }

    /// The request inputs a restore names again, as the proto carries them.
    fn local_mounts(manifest: &Manifest) -> Vec<v1::LocalMountInput> {
        let repositories =
            serde_json::from_str::<codewire_project::ProjectSpec>(&manifest.project_spec_json)
                .map(|project| project.repositories.len())
                .unwrap_or_default();
        local_mounts_from_workspace_plan(
            &manifest.source_inputs.source_path,
            repositories,
            &manifest.workspace_plan,
        )
        .unwrap_or_default()
    }

    struct Copied {
        staging: PathBuf,
        staging_name: String,
        disks: Vec<ManifestDisk>,
        consistency: Consistency,
    }

    /// Removes a staging tree unless disarmed.
    struct StagingCleanup(Option<PathBuf>);

    impl StagingCleanup {
        fn new(path: PathBuf) -> Self {
            Self(Some(path))
        }

        fn disarm(&mut self) {
            self.0 = None;
        }
    }

    impl Drop for StagingCleanup {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = remove_snapshot_tree(&path);
            }
        }
    }

    /// Under the source's `vm.lock`, with its VMM proven dead, copy its disks
    /// into `snapshots/.staging-<operation>`.
    fn copy_source(
        config: &NativeRuntimeConfig,
        environment: &EnvironmentRecord,
        operation_id: Uuid,
    ) -> Result<Copied, Status> {
        let name = &environment.name;
        let engine_root = config.engine_root();
        let engine = PrivateRoot::open(&engine_root)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let paths = VmPaths::create(&engine, environment.id)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let _lock = paths.lock().map_err(|_| {
            Status::failed_precondition(format!(
                "{name}'s VM is in use by another process; stop it (`cw stop {name}`) and try again"
            ))
        })?;
        require_vmm_dead(&paths, environment.id)?;
        if fs::symlink_metadata(paths.disks_dir.join("docker.raw.staging")).is_ok() {
            return Err(Status::failed_precondition(format!(
                "{name}'s Docker disk is being resized; start it once so that completes, stop it, then snapshot it"
            )));
        }
        let generation = environment
            .active_workspace_generation
            .as_ref()
            .ok_or_else(|| status(SupervisorError::InvalidState))?;
        let storage = workspace_storage_generation(generation)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let snapshots = snapshots_root(&engine_root).map_err(status)?;
        let staging_name = format!("{CAPTURE_STAGING_PREFIX}{operation_id}");
        let staging = snapshots
            .create_dir(Path::new(&staging_name), 0o700)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let mut cleanup = StagingCleanup::new(staging.clone());
        let staging_root = PrivateRoot::open(&staging)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let disks_dir = staging_root
            .create_dir(Path::new("disks"), 0o700)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let root_dir = staging_root
            .create_dir(Path::new("root"), 0o700)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let generation_dir = PrivateRoot::open(&root_dir)
            .and_then(|root| root.create_dir(Path::new(&storage), 0o700))
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let mut sources = vec![(
            DiskRole::State,
            paths.state_disk.clone(),
            disks_dir.join("state.raw"),
            environment.disk_bytes,
        )];
        if environment.docker_disk_bytes != 0 {
            sources.push((
                DiskRole::Docker,
                paths.docker_disk.clone(),
                disks_dir.join("docker.raw"),
                environment.docker_disk_bytes,
            ));
        }
        sources.push((
            DiskRole::Root,
            paths.generations_dir.join(&storage).join("root.raw"),
            generation_dir.join("root.raw"),
            generation.root_disk_bytes,
        ));
        let mut disks = Vec::new();
        let mut clean = true;
        for (role, source, destination, bytes) in sources {
            let (mode, superblock) = copy_disk(&source, &destination, bytes, role)?;
            clean &= superblock.clean();
            disks.push(ManifestDisk {
                role,
                bytes,
                mode: mode.as_str().to_owned(),
                filesystem_uuid: superblock.uuid,
            });
        }
        for directory in [&generation_dir, &root_dir, &disks_dir, &staging] {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| {
                    status(SupervisorError::Io {
                        path: directory.clone(),
                        source,
                    })
                })?;
        }
        cleanup.disarm();
        Ok(Copied {
            staging,
            staging_name,
            disks,
            consistency: if clean {
                Consistency::Clean
            } else {
                Consistency::Crash
            },
        })
    }

    pub(in crate::supervisor) fn require_vmm_dead(
        paths: &VmPaths,
        vm_id: Uuid,
    ) -> Result<(), Status> {
        let state = match crate::state::PersistedVmState::read(&paths.state_file) {
            Ok(state) => state,
            Err(error) if error.is_not_found() => return Ok(()),
            Err(error) => return Err(status(SupervisorError::from(error))),
        };
        if state.vm_id != vm_id {
            return Err(status(SupervisorError::InvalidState));
        }
        match LiveProcess::recover(&state.process) {
            Ok(_) => Err(Status::failed_precondition(
                "the environment's VM process still runs; stop it first",
            )),
            Err(RecoveryError::ReadProcess(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(())
            }
            Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => Ok(()),
            Err(_) => Err(Status::failed_precondition(
                "the environment's VM process could not be checked; stop it first",
            )),
        }
    }

    /// Copy one disk of `bytes` to the new `destination` (mode 0600, synced)
    /// and read the copy's ext4 superblock.
    fn copy_disk(
        source: &Path,
        destination: &Path,
        bytes: u64,
        role: DiskRole,
    ) -> Result<(CloneMode, crate::state::Ext4Superblock), Status> {
        let io_error = |path: &Path, source: io::Error| {
            status(SupervisorError::Io {
                path: path.to_owned(),
                source,
            })
        };
        let parent = source
            .parent()
            .ok_or_else(|| status(SupervisorError::InvalidState))?;
        let leaf = source
            .file_name()
            .map(Path::new)
            .ok_or_else(|| status(SupervisorError::InvalidState))?;
        let opened = PrivateRoot::open(parent)
            .and_then(|root| root.open_regular(leaf, false, Some(bytes), false, Some(0o600)))
            .map_err(|_| {
                Status::failed_precondition(format!(
                    "the source's {} disk is missing or not the size its record names",
                    role.as_str()
                ))
            })?;
        let target = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(destination)
            .map_err(|source| io_error(destination, source))?;
        let directory = destination
            .parent()
            .ok_or_else(|| status(SupervisorError::InvalidState))?
            .to_owned();
        let mode = fs_clone::clone_or_copy(opened.file(), &target, |needed| {
            require_space(&directory, needed)
        })
        .map_err(|error| copy_status(role, error))?;
        let superblock = crate::state::read_ext4_superblock(&target, destination)
            .map_err(|error| status(SupervisorError::from(error)))?;
        if target
            .metadata()
            .map_err(|source| io_error(destination, source))?
            .len()
            != bytes
        {
            return Err(status(SupervisorError::InvalidState));
        }
        Ok((mode, superblock))
    }

    fn require_space(directory: &Path, needed: u64) -> io::Result<()> {
        let free = fs_clone::free_bytes(directory)?;
        if free < needed.saturating_add(COPY_HEADROOM_BYTES) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "this filesystem cannot share blocks between files, so the copy needs {} free; {} are free",
                    bytes_text(needed.saturating_add(COPY_HEADROOM_BYTES)),
                    bytes_text(free)
                ),
            ));
        }
        Ok(())
    }

    fn copy_status(role: DiskRole, error: io::Error) -> Status {
        if error.kind() == io::ErrorKind::StorageFull || error.raw_os_error() == Some(libc::ENOSPC)
        {
            return Status::resource_exhausted(format!(
                "not enough free space to copy the {} disk: {error}",
                role.as_str()
            ));
        }
        Status::internal(format!(
            "copying the {} disk failed: {error}",
            role.as_str()
        ))
    }

    pub(crate) fn bytes_text(bytes: u64) -> String {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        format!("{:.1} GiB", bytes as f64 / GIB)
    }

    /// Write the manifest (0400), then rename the staging tree to its id.
    fn publish_capture(
        engine_root: &Path,
        staging_name: &str,
        id: Uuid,
        manifest: &[u8],
    ) -> Result<(), SupervisorError> {
        let snapshots = snapshots_root(engine_root)?;
        let staging = snapshots.open_private_directory(Path::new(staging_name), 0o700)?;
        let opened = staging.create_regular(Path::new(MANIFEST_FILE), 0o600, true)?;
        opened
            .file()
            .write_all_at(manifest, 0)
            .and_then(|()| opened.file().sync_all())
            .and_then(|()| {
                opened
                    .file()
                    .set_permissions(fs::Permissions::from_mode(0o400))
            })
            .and_then(|()| File::open(staging.path())?.sync_all())
            .map_err(|source| SupervisorError::Io {
                path: staging.path().join(MANIFEST_FILE),
                source,
            })?;
        drop(staging);
        snapshots.move_private_directory_to(
            Path::new(staging_name),
            &snapshots,
            Path::new(&id.to_string()),
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The sign-in scrub.

    /// The directories, in a state disk, where the guest daemon writes the
    /// creator's delivered logins.
    const LOGIN_DIRECTORIES: [(&[&str], LoginKind); 2] = [
        (&["agent-homes", "codex"], LoginKind::Codex),
        (&["home", ".claude"], LoginKind::Claude),
    ];

    /// Guest state on the state disk bound to the source environment's id,
    /// which a copy must not carry: the guest's live cw runtime selection,
    /// which it refuses under any other id. Without it a new environment's
    /// guest starts from the cw runtime its own create bound.
    const ENVIRONMENT_BOUND_TREES: [&[&str]; 1] = [&["codewire", "cw-runtime"]];
    /// The most entries one removed tree may hold.
    const MAXIMUM_TREE_ENTRIES: usize = 4096;
    /// How many blocks of each punched free range are read back.
    const PUNCH_SAMPLES: u64 = 3;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LoginKind {
        Codex,
        Claude,
    }

    /// What capture does with one entry of a login directory, by the
    /// daemon's own rules (`codex_home`, `claude_home`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LoginEntry {
        /// Not one of Codewire's names.
        Other,
        /// The login file: removed when its contents are Codewire's.
        File,
        /// A temporary that is a write in progress: removed unread.
        WriteInProgress,
        /// Another temporary: removed when it holds Codewire's login.
        Temporary,
    }

    impl LoginKind {
        fn entry(self, name: &str) -> LoginEntry {
            use codewire_daemon::{claude_home, codex_home};
            let (file, temporary, in_progress) = match self {
                Self::Codex => (
                    codex_home::CODEX_AUTH_FILE_NAME,
                    codex_home::is_codewire_temporary(name),
                    codex_home::is_codewire_write_in_progress(name),
                ),
                Self::Claude => (
                    claude_home::CLAUDE_CREDENTIALS_FILE_NAME,
                    claude_home::is_codewire_temporary(name),
                    claude_home::is_codewire_write_in_progress(name),
                ),
            };
            if name == file {
                LoginEntry::File
            } else if in_progress {
                LoginEntry::WriteInProgress
            } else if temporary {
                LoginEntry::Temporary
            } else {
                LoginEntry::Other
            }
        }

        fn codewire(self, name: &str, contents: &[u8]) -> bool {
            use codewire_daemon::{claude_home, codex_home};
            match (self, self.entry(name)) {
                (_, LoginEntry::Other) => false,
                (_, LoginEntry::WriteInProgress) => true,
                (Self::Codex, LoginEntry::File) => codex_home::is_codewire_auth_file(contents),
                (Self::Claude, LoginEntry::File) => claude_home::holds_codewire_login(contents),
                (Self::Codex, LoginEntry::Temporary) => {
                    codex_home::is_codewire_leftover(name, contents)
                }
                (Self::Claude, LoginEntry::Temporary) => {
                    claude_home::is_codewire_leftover(name, contents)
                }
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum ScrubError {
        #[error(
            "the host's e2fsprogs (debugfs, e2fsck, dumpe2fs) are unavailable; install your distribution's e2fsprogs package"
        )]
        ToolUnavailable,
        #[error("{0} could not run confined: {1}")]
        Confinement(&'static str, io::Error),
        #[error("{0} did not finish in time")]
        Timeout(&'static str),
        #[error("{0} failed (exit status {1:?})")]
        Failed(&'static str, Option<i32>),
        #[error("{0} reported an error")]
        Reported(&'static str),
        #[error("{0} reported something this cw cannot read")]
        Unreadable(&'static str),
        #[error(
            "a delivered sign-in or environment-bound state was still present after its removal"
        )]
        NotRemoved,
        #[error("a free block of the copy still held data after it was punched")]
        NotPunched,
        #[error(
            "the state disk's filesystem has the fs-verity feature, which Codewire never enables: the scrub would destroy verity files' Merkle trees, so it cannot be snapshotted"
        )]
        Verity,

        #[error("writing the copy failed: {0}")]
        Io(#[from] io::Error),
        #[error(transparent)]
        State(#[from] StateError),
    }

    /// Clear the state disk copy at `disk`, which no VM uses, of every
    /// Codewire-delivered sign-in and of environment-bound guest state:
    ///
    /// 1. a settling `e2fsck -f -p` (it replays an unclean journal, so a
    ///    later replay cannot undo a removal);
    /// 2. each delivered login, recognised by the daemon's own rules, has
    ///    its blocks zeroed and is removed, and the guest's live cw runtime
    ///    selection is removed; every debugfs call fails on any error it
    ///    reports, and an absent path is proven absent from its parent;
    /// 3. a second settling `e2fsck -f -p`, so the block bitmaps are exact;
    /// 4. every free range in those bitmaps is punched out of the copy, and
    ///    samples of each are read back as zeros.
    ///
    /// Returns how many logins it removed.
    pub(crate) async fn scrub_state_disk(disk: &Path) -> Result<u32, ScrubError> {
        // Refused before any change: punching past a verity file's end
        // would destroy its Merkle tree.
        if crate::state::read_ext4_superblock(&File::open(disk)?, disk)?.verity {
            return Err(ScrubError::Verity);
        }
        e2fsck(disk).await?;
        let block_size = {
            let file = File::open(disk)?;
            crate::state::read_ext4_superblock(&file, disk)?.block_size
        };
        let mut removed = 0;
        for (components, kind) in LOGIN_DIRECTORIES {
            let Some(entries) = directory_entries(disk, components).await? else {
                continue;
            };
            let directory = absolute(components);
            for entry in entries {
                let Some(name) = entry.name.as_deref() else {
                    continue;
                };
                if !entry.regular || kind.entry(name) == LoginEntry::Other {
                    continue;
                }
                let path = format!("{directory}/{name}");
                let codewire = if kind.entry(name) == LoginEntry::WriteInProgress {
                    true
                } else if entry.size > MAXIMUM_LOGIN_FILE_BYTES {
                    false
                } else {
                    let contents =
                        Zeroizing::new(debugfs(disk, false, &format!("cat {path}")).await?);
                    kind.codewire(name, &contents)
                };
                if !codewire {
                    continue;
                }
                zero_blocks(disk, &path, block_size).await?;
                debugfs(disk, true, &format!("rm {path}")).await?;
                if directory_entries(disk, components)
                    .await?
                    .is_some_and(|remaining| {
                        remaining
                            .iter()
                            .any(|other| other.name.as_deref() == Some(name))
                    })
                {
                    return Err(ScrubError::NotRemoved);
                }
                removed += 1;
            }
        }
        for components in ENVIRONMENT_BOUND_TREES {
            remove_tree(disk, components).await?;
        }
        e2fsck(disk).await?;
        punch_unreadable_blocks(disk, block_size).await?;
        Ok(removed)
    }

    fn absolute(components: &[&str]) -> String {
        format!("/{}", components.join("/"))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DirectoryEntry {
        /// `None` for a name that is not plain UTF-8 debugfs can name back,
        /// which no Codewire file has.
        name: Option<String>,
        regular: bool,
        directory: bool,
        size: u64,
    }

    /// The entries of the directory at `components` from the root, or
    /// `None` when it is absent: each component is looked up in its parent's
    /// own listing first, so an absent path is never inferred from an error.
    async fn directory_entries(
        disk: &Path,
        components: &[&str],
    ) -> Result<Option<Vec<DirectoryEntry>>, ScrubError> {
        let mut entries = list_directory(disk, "/").await?;
        for (index, component) in components.iter().enumerate() {
            let present = entries
                .iter()
                .any(|entry| entry.directory && entry.name.as_deref() == Some(*component));
            if !present {
                return Ok(None);
            }
            entries = list_directory(disk, &absolute(&components[..=index])).await?;
        }
        Ok(Some(entries))
    }

    /// Remove the tree at `components`, if present: every file first, then
    /// each directory, deepest first. It is the guest's own, so every name
    /// in it is one debugfs can name.
    async fn remove_tree(disk: &Path, components: &[&str]) -> Result<(), ScrubError> {
        let (parent, name) = components.split_at(components.len() - 1);
        let present = |entries: &Option<Vec<DirectoryEntry>>| {
            entries.as_ref().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.directory && entry.name.as_deref() == Some(name[0]))
            })
        };
        if !present(&directory_entries(disk, parent).await?) {
            return Ok(());
        }
        let mut directories = vec![absolute(components)];
        let mut files = Vec::new();
        let mut index = 0;
        while index < directories.len() {
            let directory = directories[index].clone();
            index += 1;
            for entry in list_directory(disk, &directory).await? {
                let name = entry.name.ok_or(ScrubError::Unreadable("debugfs"))?;
                let path = format!("{directory}/{name}");
                if entry.directory {
                    directories.push(path);
                } else {
                    files.push(path);
                }
                if directories.len() + files.len() > MAXIMUM_TREE_ENTRIES {
                    return Err(ScrubError::Unreadable("debugfs"));
                }
            }
        }
        for file in &files {
            debugfs(disk, true, &format!("rm {file}")).await?;
        }
        for directory in directories.iter().rev() {
            debugfs(disk, true, &format!("rmdir {directory}")).await?;
        }
        if present(&directory_entries(disk, parent).await?) {
            return Err(ScrubError::NotRemoved);
        }
        Ok(())
    }

    /// A name debugfs takes back as one argument, as every name Codewire
    /// writes is.
    fn nameable(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 255
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    /// `debugfs ls -p <directory>`, which must exist.
    async fn list_directory(
        disk: &Path,
        directory: &str,
    ) -> Result<Vec<DirectoryEntry>, ScrubError> {
        let output = debugfs(disk, false, &format!("ls -p {directory}")).await?;
        Ok(parse_listing(&output))
    }

    /// `ls -p` lines: `/inode/mode/uid/gid/name/size/`. A name with a
    /// newline, a slash or non-UTF-8 bytes breaks or bends its line; such a
    /// name is never one of Codewire's, so its pieces are skipped, and an
    /// entry whose name debugfs could not take back is kept nameless.
    fn parse_listing(output: &[u8]) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();
        for line in output.split(|byte| *byte == b'\n') {
            let fields = line.split(|byte| *byte == b'/').collect::<Vec<_>>();
            let [empty, inode, mode, _uid, _gid, name, size, trailing] = fields.as_slice() else {
                continue;
            };
            let text = |bytes: &[u8]| std::str::from_utf8(bytes).ok().map(str::to_owned);
            let (Some(inode), Some(mode)) = (text(inode), text(mode)) else {
                continue;
            };
            let Ok(mode) = u32::from_str_radix(&mode, 8) else {
                continue;
            };
            if !empty.is_empty() || !trailing.is_empty() || inode.parse::<u64>().is_err() {
                continue;
            }
            let name = text(name);
            if matches!(name.as_deref(), Some("." | "..")) {
                continue;
            }
            let regular = mode & 0o170_000 == 0o100_000;
            entries.push(DirectoryEntry {
                name: name.filter(|name| nameable(name)),
                regular,
                directory: mode & 0o170_000 == 0o040_000,
                size: if regular {
                    match text(size).and_then(|size| size.parse().ok()) {
                        Some(size) => size,
                        None => continue,
                    }
                } else {
                    0
                },
            });
        }
        entries
    }

    async fn zero_blocks(disk: &Path, path: &str, block_size: u64) -> Result<(), ScrubError> {
        let output = debugfs(disk, false, &format!("blocks {path}")).await?;
        let text = String::from_utf8(output).map_err(|_| ScrubError::Unreadable("debugfs"))?;
        let blocks = text
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ScrubError::Unreadable("debugfs"))?;
        let image = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(disk)?;
        let length = image.metadata()?.len();
        let zeros =
            vec![0_u8; usize::try_from(block_size).map_err(|_| ScrubError::Unreadable("debugfs"))?];
        for block in blocks {
            let offset = block
                .checked_mul(block_size)
                .filter(|offset| offset.saturating_add(block_size) <= length)
                .ok_or(ScrubError::Unreadable("debugfs"))?;
            image.write_all_at(&zeros, offset)?;
        }
        image.sync_all()?;
        Ok(())
    }

    /// Punch out of the file in `disk` every block the guest cannot read,
    /// then read samples of each range back as zeros: every free range of
    /// the filesystem, and in each regular file every unwritten extent and
    /// every block past its end. A token an earlier rewrite left in a freed
    /// block, even one since reallocated without being written, is gone,
    /// and nothing the guest reads changes.
    async fn punch_unreadable_blocks(disk: &Path, block_size: u64) -> Result<(), ScrubError> {
        let program = program("dumpe2fs")?;
        let (code, output, errors) = run_disk_tool("dumpe2fs", &program, &[], disk).await?;
        if code != Some(0) {
            return Err(ScrubError::Failed("dumpe2fs", code));
        }
        require_quiet("dumpe2fs", &errors)?;
        let mut ranges = free_ranges(&output)?;
        let inodes = used_inodes(&output)?;
        let block_count = block_count(&output)?;
        let unreadable = unreadable_file_blocks(disk, &inodes, block_size).await?;
        if unreadable.iter().any(|(_, last)| *last >= block_count) {
            return Err(ScrubError::Unreadable("debugfs"));
        }
        ranges.extend(unreadable);
        let ranges = merge_ranges(ranges);
        let image = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(disk)?;
        let length = image.metadata()?.len();
        for &(first, last) in &ranges {
            let offset = first
                .checked_mul(block_size)
                .ok_or(ScrubError::Unreadable("dumpe2fs"))?;
            let bytes = (last - first + 1)
                .checked_mul(block_size)
                .filter(|bytes| offset.saturating_add(*bytes) <= length)
                .ok_or(ScrubError::Unreadable("dumpe2fs"))?;
            punch_hole(&image, offset, bytes)?;
        }
        image.sync_all()?;
        let mut sample =
            vec![0_u8; usize::try_from(block_size).map_err(|_| ScrubError::NotPunched)?];
        for &(first, last) in &ranges {
            let samples = if last - first < PUNCH_SAMPLES {
                (first..=last).collect::<Vec<_>>()
            } else {
                vec![first, first + (last - first) / 2, last]
            };
            for block in samples {
                image.read_exact_at(&mut sample, block * block_size)?;
                if sample.iter().any(|byte| *byte != 0) {
                    return Err(ScrubError::NotPunched);
                }
            }
        }
        Ok(())
    }

    fn punch_hole(image: &File, offset: u64, bytes: u64) -> io::Result<()> {
        let (Ok(offset), Ok(bytes)) = (libc::off_t::try_from(offset), libc::off_t::try_from(bytes))
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "range too large",
            ));
        };
        // SAFETY: a plain fallocate on a live descriptor.
        let result = unsafe {
            libc::fallocate(
                image.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset,
                bytes,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// The free block ranges `dumpe2fs` reports, merged where adjacent:
    /// every group must report its free blocks, and every range must lie in
    /// the filesystem.
    fn free_ranges(output: &[u8]) -> Result<Vec<(u64, u64)>, ScrubError> {
        let unreadable = || ScrubError::Unreadable("dumpe2fs");
        let text = std::str::from_utf8(output).map_err(|_| unreadable())?;
        let mut block_count = None;
        let mut groups = 0_u64;
        let mut reports = 0_u64;
        let mut ranges = Vec::new();
        for line in text.lines() {
            if let Some(count) = line.strip_prefix("Block count:") {
                block_count = Some(count.trim().parse::<u64>().map_err(|_| unreadable())?);
            } else if line.starts_with("Group ") && line.contains(": (Blocks ") {
                groups += 1;
            } else if let Some(list) = line.strip_prefix("  Free blocks:") {
                reports += 1;
                for item in list
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    let (first, last) = match item.split_once('-') {
                        Some((first, last)) => (first, last),
                        None => (item, item),
                    };
                    let first = first.parse::<u64>().map_err(|_| unreadable())?;
                    let last = last.parse::<u64>().map_err(|_| unreadable())?;
                    if last < first {
                        return Err(unreadable());
                    }
                    ranges.push((first, last));
                }
            }
        }
        let block_count = block_count.ok_or_else(unreadable)?;
        if groups == 0 || groups != reports || ranges.iter().any(|(_, last)| *last >= block_count) {
            return Err(unreadable());
        }
        Ok(merge_ranges(ranges))
    }

    fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (first, last) in ranges {
            match merged.last_mut() {
                Some(previous) if first <= previous.1.saturating_add(1) => {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        merged
    }

    fn block_count(output: &[u8]) -> Result<u64, ScrubError> {
        String::from_utf8_lossy(output)
            .lines()
            .find_map(|line| line.strip_prefix("Block count:"))
            .and_then(|count| count.trim().parse().ok())
            .ok_or(ScrubError::Unreadable("dumpe2fs"))
    }

    /// Every inode `dumpe2fs` reports in use from the first ordinary one:
    /// each group's inodes but its free ones.
    fn used_inodes(output: &[u8]) -> Result<Vec<u64>, ScrubError> {
        let unreadable = || ScrubError::Unreadable("dumpe2fs");
        let text = std::str::from_utf8(output).map_err(|_| unreadable())?;
        let header = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| value.trim().parse::<u64>().ok())
        };
        let per_group = header("Inodes per group:")
            .filter(|count| *count > 0)
            .ok_or_else(unreadable)?;
        let first = header("First inode:").ok_or_else(unreadable)?;
        let count = header("Inode count:").ok_or_else(unreadable)?;
        let mut group = None;
        let mut used = Vec::new();
        let mut reports = 0_u64;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Group ")
                && line.contains(": (Blocks ")
            {
                group = Some(
                    rest.split(':')
                        .next()
                        .and_then(|number| number.trim().parse::<u64>().ok())
                        .ok_or_else(unreadable)?,
                );
            } else if let Some(list) = line.strip_prefix("  Free inodes:") {
                let group = group.take().ok_or_else(unreadable)?;
                reports += 1;
                let start = group * per_group + 1;
                let end = start + per_group - 1;
                let mut free = Vec::new();
                for item in list
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    let (low, high) = item.split_once('-').unwrap_or((item, item));
                    let low = low.parse::<u64>().map_err(|_| unreadable())?;
                    let high = high.parse::<u64>().map_err(|_| unreadable())?;
                    if high < low || low < start || high > end {
                        return Err(unreadable());
                    }
                    free.push((low, high));
                }
                free.sort_unstable();
                let mut next = start;
                for (low, high) in free.into_iter().chain([(end + 1, end + 1)]) {
                    used.extend((next..low).filter(|inode| *inode >= first));
                    next = next.max(high + 1);
                }
            }
        }
        if reports == 0 || reports * per_group != count {
            return Err(unreadable());
        }
        Ok(used)
    }

    /// The physical blocks of every regular file in `inodes` that the guest
    /// cannot read: unwritten extents and blocks past the file's end, from
    /// one confined debugfs session that stats each inode.
    async fn unreadable_file_blocks(
        disk: &Path,
        inodes: &[u64],
        block_size: u64,
    ) -> Result<Vec<(u64, u64)>, ScrubError> {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

        if inodes.is_empty() {
            return Ok(Vec::new());
        }
        let program = program("debugfs")?;
        let mut command = crate::linux::disk_tool::command(&program, &[], disk)
            .map_err(|error| ScrubError::Confinement("debugfs", error))?;
        let mut child = command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PAGER", "__none__")
            .env("DEBUGFS_PAGER", "__none__")
            .env("SS_READLINE_PATH", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| ScrubError::Confinement("debugfs", error))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(ScrubError::Unreadable("debugfs"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ScrubError::Unreadable("debugfs"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(ScrubError::Unreadable("debugfs"))?;
        let mut commands = String::with_capacity(inodes.len() * 16);
        for inode in inodes {
            commands.push_str(&format!("stat <{inode}>\n"));
        }
        let run = async {
            let write = async {
                stdin.write_all(commands.as_bytes()).await?;
                stdin.shutdown().await?;
                drop(stdin);
                Ok::<_, io::Error>(())
            };
            let read = async {
                let mut parser = InodeBlocks::new(block_size);
                let requested = inodes;
                let mut lines = tokio::io::BufReader::new(stdout);
                let mut line = Vec::new();
                loop {
                    line.clear();
                    if lines.read_until(b'\n', &mut line).await? == 0 {
                        break;
                    }
                    parser.line(&String::from_utf8_lossy(&line));
                }
                Ok::<_, io::Error>(parser.finish(requested))
            };
            let errors = async {
                let mut errors = Vec::new();
                (&mut stderr)
                    .take(MAXIMUM_TOOL_OUTPUT_BYTES as u64 + 1)
                    .read_to_end(&mut errors)
                    .await?;
                Ok::<_, io::Error>(errors)
            };
            let (written, ranges, errors) = tokio::join!(write, read, errors);
            written?;
            let status = child.wait().await?;
            Ok::<_, io::Error>((status.code(), ranges?, errors?))
        };
        let (code, ranges, errors) = tokio::time::timeout(DISK_TOOL_TIMEOUT, run)
            .await
            .map_err(|_| ScrubError::Timeout("debugfs"))??;
        if code != Some(0) {
            return Err(ScrubError::Failed("debugfs", code));
        }
        require_quiet("debugfs", &errors)?;
        ranges
    }

    /// One extent of a file, as `debugfs stat` prints it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FileExtent {
        logical: u64,
        physical: u64,
        length: u64,
        unwritten: bool,
    }

    /// Reads `debugfs stat` records and keeps, of each regular file, the
    /// physical blocks the guest cannot read. A file's map is either
    /// `EXTENTS:` or, for a file mapped by indirect blocks, `BLOCKS:`.
    struct InodeBlocks {
        block_size: u64,
        regular: bool,
        size: Option<u64>,
        extents: Vec<FileExtent>,
        in_map: bool,
        ranges: Vec<(u64, u64)>,
        /// Every record's inode, in order.
        seen: Vec<u64>,
        malformed: bool,
    }

    impl InodeBlocks {
        fn new(block_size: u64) -> Self {
            Self {
                block_size,
                regular: false,
                size: None,
                extents: Vec::new(),
                in_map: false,
                ranges: Vec::new(),
                seen: Vec::new(),
                malformed: false,
            }
        }

        fn line(&mut self, line: &str) {
            let mut line = line.trim_end();
            while let Some(rest) = line.strip_prefix("debugfs:") {
                line = rest.trim_start();
            }
            if let Some(rest) = line.strip_prefix("Inode: ") {
                self.end_record();
                match rest
                    .split_whitespace()
                    .next()
                    .and_then(|inode| inode.parse::<u64>().ok())
                {
                    Some(inode) => self.seen.push(inode),
                    None => self.malformed = true,
                }
                self.regular = rest
                    .split_whitespace()
                    .skip_while(|word| *word != "Type:")
                    .nth(1)
                    == Some("regular");
                return;
            }
            if line.starts_with("User:") {
                self.size = line
                    .rsplit_once("Size:")
                    .and_then(|(_, size)| size.trim().parse().ok());
                if self.size.is_none() {
                    self.malformed = true;
                }
                return;
            }
            if line == "EXTENTS:" || line == "BLOCKS:" {
                self.in_map = true;
                return;
            }
            if self.in_map {
                if !line.starts_with('(') {
                    self.in_map = false;
                    return;
                }
                for entry in line
                    .split(", ")
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                {
                    match parse_extent(entry) {
                        Some(Some(extent)) => self.extents.push(extent),
                        Some(None) => {}
                        None => self.malformed = true,
                    }
                }
            }
        }

        fn end_record(&mut self) {
            if self.regular && self.size.is_none() {
                // A regular file's record always says its size.
                self.malformed = true;
            }
            if self.regular
                && let Some(size) = self.size
            {
                let end = size.div_ceil(self.block_size);
                for extent in &self.extents {
                    let last = extent.physical + extent.length - 1;
                    if extent.unwritten {
                        self.ranges.push((extent.physical, last));
                    } else if extent.logical + extent.length > end {
                        let skipped = end.saturating_sub(extent.logical);
                        self.ranges.push((extent.physical + skipped, last));
                    }
                }
            }
            self.regular = false;
            self.size = None;
            self.extents.clear();
            self.in_map = false;
        }

        /// The ranges, once exactly one record was read for each of
        /// `requested`, in order.
        fn finish(mut self, requested: &[u64]) -> Result<Vec<(u64, u64)>, ScrubError> {
            self.end_record();
            if self.malformed || self.seen != requested {
                return Err(ScrubError::Unreadable("debugfs"));
            }
            Ok(self.ranges)
        }
    }

    /// One `stat` map entry: `(L[-L2][[u]]):P[-P2]`. `Some(None)` for a
    /// mapping block, an extent index (`(ETBn):P`) or an indirect block
    /// (`(IND):P`, `(DIND):P`, `(TIND):P`), `None` for anything unreadable.
    fn parse_extent(entry: &str) -> Option<Option<FileExtent>> {
        let (logical, physical) = entry.strip_prefix('(')?.split_once("):")?;
        if logical.starts_with("ETB") || matches!(logical, "IND" | "DIND" | "TIND") {
            physical.parse::<u64>().ok()?;
            return Some(None);
        }
        let (logical, unwritten) = match logical.strip_suffix("[u]") {
            Some(logical) => (logical, true),
            None => (logical, false),
        };
        let range = |text: &str| -> Option<(u64, u64)> {
            let (first, last) = text.split_once('-').unwrap_or((text, text));
            let (first, last) = (first.parse::<u64>().ok()?, last.parse::<u64>().ok()?);
            (last >= first).then_some((first, last))
        };
        let (logical_first, logical_last) = range(logical)?;
        let (physical_first, physical_last) = range(physical)?;
        if logical_last - logical_first != physical_last - physical_first {
            return None;
        }
        Some(Some(FileExtent {
            logical: logical_first,
            physical: physical_first,
            length: logical_last - logical_first + 1,
            unwritten,
        }))
    }

    fn program(name: &'static str) -> Result<PathBuf, ScrubError> {
        crate::host::e2fsprogs(name).ok_or(ScrubError::ToolUnavailable)
    }

    async fn debugfs(disk: &Path, write: bool, request: &str) -> Result<Vec<u8>, ScrubError> {
        let program = program("debugfs")?;
        let mut arguments = Vec::new();
        if write {
            arguments.push("-w");
        }
        arguments.extend(["-R", request]);
        let (code, output, errors) = run_disk_tool("debugfs", &program, &arguments, disk).await?;
        if code != Some(0) {
            return Err(ScrubError::Failed("debugfs", code));
        }
        // debugfs exits 0 after a failed request and says so only on stderr.
        require_quiet("debugfs", &errors)?;
        Ok(output)
    }

    /// Nothing on a tool's stderr but its version banner.
    fn require_quiet(label: &'static str, errors: &[u8]) -> Result<(), ScrubError> {
        let text = String::from_utf8_lossy(errors);
        let banner = |line: &str| line.starts_with(&format!("{label} ")) && line.ends_with(')');
        if text
            .lines()
            .map(str::trim)
            .any(|line| !line.is_empty() && !banner(line))
        {
            return Err(ScrubError::Reported(label));
        }
        Ok(())
    }

    /// A settling `e2fsck -f -p`: 0 clean, 1 corrected.
    async fn e2fsck(disk: &Path) -> Result<(), ScrubError> {
        let program = program("e2fsck")?;
        let (code, _, _) = run_disk_tool("e2fsck", &program, &["-f", "-p"], disk).await?;
        if !matches!(code, Some(0 | 1)) {
            return Err(ScrubError::Failed("e2fsck", code));
        }
        Ok(())
    }

    /// Run a host e2fsprogs tool confined to `disk` alone: its exit status,
    /// stdout and stderr.
    async fn run_disk_tool(
        label: &'static str,
        program: &Path,
        arguments: &[&str],
        disk: &Path,
    ) -> Result<(Option<i32>, Vec<u8>, Vec<u8>), ScrubError> {
        use tokio::io::AsyncReadExt as _;

        let mut command = crate::linux::disk_tool::command(program, arguments, disk)
            .map_err(|error| ScrubError::Confinement(label, error))?;
        let mut child = command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PAGER", "__none__")
            .env("DEBUGFS_PAGER", "__none__")
            .env("E2FSCK_CONFIG", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| ScrubError::Confinement(label, error))?;
        let mut stdout = child.stdout.take().ok_or(ScrubError::Unreadable(label))?;
        let mut stderr = child.stderr.take().ok_or(ScrubError::Unreadable(label))?;
        let run = async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let limit = MAXIMUM_TOOL_OUTPUT_BYTES as u64 + 1;
            let mut stdout = (&mut stdout).take(limit);
            let mut stderr = (&mut stderr).take(limit);
            let (out, err) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors),
            );
            out?;
            err?;
            let status = child.wait().await?;
            Ok::<_, io::Error>((status.code(), output, errors))
        };
        let (code, output, errors) = tokio::time::timeout(DISK_TOOL_TIMEOUT, run)
            .await
            .map_err(|_| ScrubError::Timeout(label))??;
        if output.len() > MAXIMUM_TOOL_OUTPUT_BYTES || errors.len() > MAXIMUM_TOOL_OUTPUT_BYTES {
            return Err(ScrubError::Unreadable(label));
        }
        Ok((code, output, errors))
    }

    // -----------------------------------------------------------------------
    // Placement.

    /// Place snapshot `snapshot_id`'s disks for environment `environment_id`:
    /// under the snapshot's shared lock, copy them into a staging tree
    /// outside `vms/`, then publish that tree as `vms/<id>` in one rename that
    /// never replaces. Replay finds the published tree and checks it. Returns
    /// the root generation the tree holds.
    pub(super) fn place_snapshot_tree(
        config: &NativeRuntimeConfig,
        snapshot_id: Uuid,
        environment_id: Uuid,
        operation_id: Uuid,
        (disk_bytes, docker_disk_bytes): (u64, u64),
    ) -> Result<WorkspaceGenerationRecord, SupervisorError> {
        let engine_root = config.engine_root();
        let engine = PrivateRoot::open(&engine_root)?;
        let vms_path = engine.ensure_dir(Path::new("vms"), 0o700)?;
        let vms = PrivateRoot::open(&vms_path)?;
        let snapshots = snapshots_root(&engine_root)?;
        let source =
            snapshots.open_private_directory(Path::new(&snapshot_id.to_string()), 0o700)?;
        let lock = File::open(source.path()).map_err(|source_error| SupervisorError::Io {
            path: source.path().to_owned(),
            source: source_error,
        })?;
        // Shared while this restore reads it; a delete takes it exclusively.
        flock(&lock, FlockOperation::NonBlockingLockShared)
            .map_err(|_| SupervisorError::InvalidState)?;
        let (_, manifest) = ready_snapshot(config, snapshot_id)?;
        if manifest.resources.disk_bytes != disk_bytes
            || manifest.resources.docker_disk_bytes != docker_disk_bytes
        {
            return Err(SupervisorError::InvalidState);
        }
        let storage = manifest.storage_generation()?;
        let name = environment_id.to_string();
        let files = placement_files(&manifest, &storage);
        if optional_directory(&vms, &name)?.is_some() {
            verify_placement(&vms_path.join(&name), &files)?;
            if let Some(checkpoint) = &manifest.checkpoint
                && !checkpoint.files_match_in(&vms_path.join(&name))
            {
                return Err(SupervisorError::InvalidState);
            }
            return Ok(manifest.root_generation);
        }
        let staging_name = format!("{RESTORE_STAGING_PREFIX}{operation_id}");
        let _in_flight = InFlight::new(staging_name.clone());
        let _ = remove_snapshot_tree(&snapshots.path().join(&staging_name));
        let staging = snapshots.create_dir(Path::new(&staging_name), 0o700)?;
        let _cleanup = StagingCleanup::new(staging.clone());
        let staging_root = PrivateRoot::open(&staging)?;
        let tree = staging_root.create_dir(Path::new("vm"), 0o700)?;
        let tree_root = PrivateRoot::open(&tree)?;
        tree_root.create_dir(Path::new("disks"), 0o700)?;
        let generations = tree_root.create_dir(Path::new("generations"), 0o700)?;
        PrivateRoot::open(&generations)?.create_dir(Path::new(&storage), 0o700)?;
        for file in &files {
            let target = tree.join(&file.placed);
            let (_, superblock) = copy_disk(
                &source.path().join(&file.stored),
                &target,
                file.bytes,
                file.role,
            )
            .map_err(|status| SupervisorError::Io {
                path: target.clone(),
                source: io::Error::other(status.message().to_owned()),
            })?;
            if superblock.uuid != file.filesystem_uuid {
                return Err(SupervisorError::InvalidState);
            }
        }
        // A fork of a VM checkpoint restores from its own reflinks of the
        // VMM files, which its VMM maps for as long as it runs.
        if let Some(checkpoint) = &manifest.checkpoint {
            let checkpoints =
                tree_root.create_dir(Path::new(crate::state::CHECKPOINTS_DIRECTORY), 0o700)?;
            let input = PrivateRoot::open(&checkpoints)?
                .create_dir(Path::new(crate::state::CHECKPOINT_IN), 0o700)?;
            for name in crate::state::CHECKPOINT_VMM_FILES {
                clone_sealed(&source.path().join("vmm").join(name), &input.join(name))?;
            }
            if !checkpoint.files_match_in(&tree) {
                return Err(SupervisorError::InvalidState);
            }
            for directory in [&input, &checkpoints] {
                File::open(directory)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|source| SupervisorError::Io {
                        path: directory.clone(),
                        source,
                    })?;
            }
        }
        for directory in [
            generations.join(&storage),
            generations.clone(),
            tree.join("disks"),
            tree.clone(),
        ] {
            File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| SupervisorError::Io {
                    path: directory.clone(),
                    source,
                })?;
        }
        staging_root.move_private_directory_to(Path::new("vm"), &vms, Path::new(&name))?;
        drop(lock);
        Ok(manifest.root_generation)
    }

    /// Reflink `source` into the new `destination`, sealed 0400.
    fn clone_sealed(source: &Path, destination: &Path) -> Result<(), SupervisorError> {
        let io_error = |path: &Path, error: io::Error| SupervisorError::Io {
            path: path.to_owned(),
            source: error,
        };
        let from = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)
            .map_err(|error| io_error(source, error))?;
        let to = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(destination)
            .map_err(|error| io_error(destination, error))?;
        fs_clone::reflink(&from, &to).map_err(|error| io_error(destination, error))?;
        to.sync_all()
            .and_then(|()| to.set_permissions(fs::Permissions::from_mode(0o400)))
            .map_err(|error| io_error(destination, error))
    }

    struct PlacedFile {
        role: DiskRole,
        /// Relative to the snapshot directory.
        stored: PathBuf,
        /// Relative to `vms/<id>`.
        placed: PathBuf,
        bytes: u64,
        filesystem_uuid: Uuid,
    }

    fn placement_files(manifest: &Manifest, storage: &str) -> Vec<PlacedFile> {
        manifest
            .disks
            .iter()
            .map(|disk| {
                let (stored, placed) = match disk.role {
                    DiskRole::State => (
                        PathBuf::from("disks/state.raw"),
                        PathBuf::from("disks/state.raw"),
                    ),
                    DiskRole::Docker => (
                        PathBuf::from("disks/docker.raw"),
                        PathBuf::from("disks/docker.raw"),
                    ),
                    DiskRole::Root => (
                        Path::new("root").join(storage).join("root.raw"),
                        Path::new("generations").join(storage).join("root.raw"),
                    ),
                };
                PlacedFile {
                    role: disk.role,
                    stored,
                    placed,
                    bytes: disk.bytes,
                    filesystem_uuid: disk.filesystem_uuid,
                }
            })
            .collect()
    }

    /// A published tree holds each disk at its size and with its filesystem.
    fn verify_placement(tree: &Path, files: &[PlacedFile]) -> Result<(), SupervisorError> {
        for file in files {
            let path = tree.join(&file.placed);
            let identity = crate::state::StateDiskIdentity::capture(&path)?;
            if identity.file.size != file.bytes || identity.filesystem_uuid != file.filesystem_uuid
            {
                return Err(SupervisorError::InvalidState);
            }
        }
        Ok(())
    }

    fn optional_directory(
        root: &PrivateRoot,
        name: &str,
    ) -> Result<Option<PrivateRoot>, SupervisorError> {
        match fs::symlink_metadata(root.path().join(name)) {
            Ok(_) => Ok(Some(root.open_private_directory(Path::new(name), 0o700)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(SupervisorError::Io {
                path: root.path().join(name),
                source,
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Listing, inspection and deletion.

    pub(super) fn list(config: &NativeRuntimeConfig) -> Result<Vec<v1::Snapshot>, Status> {
        let engine_root = config.engine_root();
        list_ready(config, false)?
            .iter()
            .map(|(row, manifest)| {
                snapshot_proto(&engine_root, row, manifest, false).map_err(status)
            })
            .collect()
    }

    /// Every ready disk snapshot, or every ready VM checkpoint, with its
    /// verified manifest.
    pub(in crate::supervisor) fn list_ready(
        config: &NativeRuntimeConfig,
        checkpoints: bool,
    ) -> Result<Vec<(SnapshotRow, Manifest)>, Status> {
        let store = store(config).map_err(status)?;
        let engine_root = config.engine_root();
        settle(config, &store).map_err(status)?;
        let mut ready = Vec::new();
        for row in store.list().map_err(store_status)? {
            if row.state != SnapshotState::Ready || row.kind.is_checkpoint() != checkpoints {
                continue;
            }
            let manifest = read_manifest(&engine_root, &row).map_err(status)?;
            ready.push((row, manifest));
        }
        Ok(ready)
    }

    pub(super) fn get(
        config: &NativeRuntimeConfig,
        selector: &str,
    ) -> Result<v1::Snapshot, Status> {
        let (row, manifest) = find_ready(config, selector, false)?;
        snapshot_proto(&config.engine_root(), &row, &manifest, true).map_err(status)
    }

    /// The ready disk snapshot, or VM checkpoint, `selector` names.
    pub(in crate::supervisor) fn find_ready(
        config: &NativeRuntimeConfig,
        selector: &str,
        checkpoint: bool,
    ) -> Result<(SnapshotRow, Manifest), Status> {
        let (noun, list) = if checkpoint {
            ("VM checkpoint", "cw checkpoint ls")
        } else {
            ("snapshot", "cw snapshot ls")
        };
        if selector.is_empty() {
            return Err(Status::invalid_argument(format!("name a {noun}")));
        }
        let row = store(config)
            .map_err(status)?
            .find(selector)
            .map_err(store_status)?
            .filter(|row| row.state == SnapshotState::Ready)
            .ok_or_else(|| {
                Status::not_found(format!(
                    "no local {noun} is named {selector}; list them with `{list}`"
                ))
            })?;
        if row.kind.is_checkpoint() != checkpoint {
            return Err(Status::failed_precondition(if checkpoint {
                format!("{selector} is a disk snapshot; use `cw snapshot` for it")
            } else {
                format!("{selector} is a VM checkpoint; use `cw checkpoint` for it")
            }));
        }
        let manifest = read_manifest(&config.engine_root(), &row).map_err(status)?;
        Ok((row, manifest))
    }

    /// Delete a snapshot: under its exclusive lock, mark it deleting, move
    /// its directory to trash, then remove exactly its files and its row.
    /// Environments made from it keep their own copies.
    pub(super) fn delete(
        config: &NativeRuntimeConfig,
        selector: &str,
    ) -> Result<v1::Snapshot, Status> {
        let engine_root = config.engine_root();
        delete_ready(config, selector, false, |row, manifest| {
            snapshot_proto(&engine_root, row, manifest, false).map_err(status)
        })
    }

    /// Delete the ready disk snapshot, or VM checkpoint, `selector` names,
    /// as [`delete`] does; `describe` runs on it before anything changes.
    pub(in crate::supervisor) fn delete_ready<T>(
        config: &NativeRuntimeConfig,
        selector: &str,
        checkpoint: bool,
        describe: impl FnOnce(&SnapshotRow, &Manifest) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let engine_root = config.engine_root();
        let store = store(config).map_err(status)?;
        // A delete an earlier call left unfinished is settled first.
        settle(config, &store).map_err(status)?;
        let (row, manifest) = find_ready(config, selector, checkpoint)?;
        let noun = if checkpoint {
            "VM checkpoint"
        } else {
            "snapshot"
        };
        let Some(_in_flight) = InFlight::try_new(row.id.to_string()) else {
            return Err(Status::failed_precondition(format!(
                "{noun} {} is being created or removed; try again when that finishes",
                row.name
            )));
        };
        let proto = describe(&row, &manifest)?;
        let snapshots = snapshots_root(&engine_root).map_err(status)?;
        let directory = snapshots
            .open_private_directory(Path::new(&row.id.to_string()), 0o700)
            .map_err(SupervisorError::from)
            .map_err(status)?;
        let lock = File::open(directory.path()).map_err(|source| {
            status(SupervisorError::Io {
                path: directory.path().to_owned(),
                source,
            })
        })?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            Status::failed_precondition(format!(
                "an environment is being created from {noun} {}; remove it once that finishes",
                row.name
            ))
        })?;
        // Durable before the row changes: a directory so marked is being
        // deleted, even to a supervisor that lost the store.
        mark_directory_deleting(&directory).map_err(status)?;
        test_hook(&engine_root, "delete-marked");
        let marked = store.mark_deleting(row.id);
        if !matches!(marked, Ok(true)) {
            // The delete failed: the snapshot stays, unmarked, as it was.
            unmark_directory_deleting(&directory).map_err(status)?;
            return Err(match marked {
                Err(error) => store_status(error),
                Ok(_) => Status::not_found(format!("no local {noun} is named {selector}")),
            });
        }
        drop(directory);
        remove_published(&engine_root, row.id, Uuid::new_v4()).map_err(status)?;
        store.remove(row.id).map_err(store_status)?;
        drop(lock);
        publish_retention(config, &store, None).map_err(status)?;
        Ok(proto)
    }

    /// Move `snapshots/<id>` to `trash/snapshot-delete-<operation>-<id>`, then
    /// remove it file by file, with the trash tree registered in flight.
    fn remove_published(
        engine_root: &Path,
        id: Uuid,
        operation_id: Uuid,
    ) -> Result<(), SupervisorError> {
        let trashed = format!("{TRASH_PREFIX}{operation_id}-{id}");
        let _in_flight = InFlight::new(trashed.clone());
        remove_published_as(engine_root, id, &trashed)
    }

    fn remove_published_as(
        engine_root: &Path,
        id: Uuid,
        trashed: &str,
    ) -> Result<(), SupervisorError> {
        let snapshots = snapshots_root(engine_root)?;
        let trash = trash_root(engine_root)?;
        snapshots.move_private_directory_to(
            Path::new(&id.to_string()),
            &trash,
            Path::new(trashed),
        )?;
        remove_snapshot_tree(&trash.path().join(trashed)).map_err(|source| SupervisorError::Io {
            path: trash.path().join(trashed),
            source,
        })
    }

    /// The file in a snapshot directory that says it is being deleted.
    const DELETING_MARKER: &str = "deleting";

    fn mark_directory_deleting(directory: &PrivateRoot) -> Result<(), SupervisorError> {
        let opened = directory.create_regular(Path::new(DELETING_MARKER), 0o600, false)?;
        opened
            .file()
            .sync_all()
            .and_then(|()| File::open(directory.path())?.sync_all())
            .map_err(|source| SupervisorError::Io {
                path: directory.path().join(DELETING_MARKER),
                source,
            })
    }

    /// Undo [`mark_directory_deleting`] for a delete that did not happen.
    /// The removal syncs the directory, so the undo is durable too.
    fn unmark_directory_deleting(directory: &PrivateRoot) -> Result<(), SupervisorError> {
        directory.remove_private_regular(Path::new(DELETING_MARKER), 0o600)?;
        Ok(())
    }

    fn marked_deleting(directory: &Path) -> bool {
        fs::symlink_metadata(directory.join(DELETING_MARKER)).is_ok()
    }

    pub(in crate::supervisor) fn snapshot_proto(
        engine_root: &Path,
        row: &SnapshotRow,
        manifest: &Manifest,
        measure_sharing: bool,
    ) -> Result<v1::Snapshot, SupervisorError> {
        let storage = manifest.storage_generation()?;
        let directory = snapshots_root(engine_root)?.path().join(row.id.to_string());
        let mut disks = Vec::new();
        for file in placement_files(manifest, &storage) {
            let opened =
                File::open(directory.join(&file.stored)).map_err(|source| SupervisorError::Io {
                    path: directory.join(&file.stored),
                    source,
                })?;
            let mode = manifest
                .disk(file.role)
                .map(|disk| disk.mode.clone())
                .unwrap_or_default();
            disks.push(v1::SnapshotDisk {
                role: file.role.as_str().to_owned(),
                bytes: file.bytes,
                mode,
                allocated_bytes: fs_clone::allocated_bytes(&opened).unwrap_or(0),
                shared_bytes: measure_sharing
                    .then(|| fs_clone::shared_bytes(&opened))
                    .flatten(),
            });
        }
        let reflink = disks
            .iter()
            .all(|disk| disk.mode == CloneMode::Reflink.as_str());
        let mut warnings = vec![SPACE_WARNING.to_owned()];
        if !reflink {
            warnings.push(COPY_WARNING.to_owned());
        }
        Ok(v1::Snapshot {
            id: row.id.to_string(),
            name: row.name.clone(),
            created_unix_ms: manifest.created_unix_ms,
            source_environment_id: manifest.source.environment_id.to_string(),
            source_name: manifest.source.name.clone(),
            consistency: manifest.consistency.as_str().to_owned(),
            locations: manifest.locations.clone(),
            architecture: manifest.architecture.clone(),
            mode: if reflink { "reflink" } else { "copy" }.to_owned(),
            disks,
            vcpus: u32::from(manifest.resources.vcpus),
            memory_mib: manifest.resources.memory_mib,
            disk_bytes: manifest.resources.disk_bytes,
            docker_disk_bytes: manifest.resources.docker_disk_bytes,
            image: manifest.root_generation.image.source_reference.clone(),
            project_spec_json: manifest.project_spec_json.as_bytes().to_vec(),
            project_spec_sha256: manifest.project_spec_sha256.clone(),
            source_path: manifest.source_inputs.source_path.clone(),
            implicit_path_mode: manifest.source_inputs.implicit_path_mode.clone(),
            local_mounts: local_mounts(manifest),
            implicit_vm_only: manifest.source_inputs.implicit_vm_only.clone(),
            platform_source_authority: manifest
                .recorded
                .platform_source_authority
                .as_ref()
                .map(PlatformSourceAuthority::proto),
            access_profile_reference: manifest.recorded.access_profile_reference.clone(),
            host_ports: host_ports_to_proto(&manifest.recorded.host_ports),
            mesh: mesh_attachment_to_proto(manifest.recorded.mesh.as_ref()),
            network_policy: manifest.recorded.network_policy.clone(),
            direct_mounts: manifest
                .workspace_plan
                .inputs
                .iter()
                .any(|input| matches!(input, WorkspaceInput::Direct { .. })),
            removed_logins: manifest.removed_logins,
            capture_milliseconds: manifest.capture_milliseconds,
            warnings,
            account: manifest
                .platform_account
                .as_ref()
                .map(PlatformAccount::proto),
        })
    }

    // -----------------------------------------------------------------------
    // Reconciliation: on the store's first use in a process, and before each
    // capture and delete.

    /// What one reconciliation changed that its caller must act on.
    #[derive(Debug, Default)]
    pub(super) struct Reconciled {
        /// It rebuilt a row from a snapshot's manifest: retention must be
        /// published again, so collection keeps what that snapshot needs.
        pub(super) adopted: bool,
    }

    /// Bring rows and directories into agreement after any crash or partial
    /// failure:
    ///
    /// - a directory marked deleting, or whose row is deleting, is removed;
    /// - one with no row gets its row back from its verified manifest, as
    ///   after the store was lost or a crash between publication and the
    ///   row; one that cannot be verified is removed only when its capture
    ///   intent is recorded, and otherwise left in place, unlisted;
    /// - staging trees go; a row whose directory is gone goes; deletions
    ///   left in trash finish.
    ///
    /// It decides under the in-flight lock, held throughout so no call
    /// registers or releases anything meanwhile and nothing registered is
    /// touched, and there it only renames: each tree it removes is moved
    /// into trash (or already is there) and registered in flight. The
    /// removals, which may be large, happen after the lock is released. A
    /// published directory is moved only under its exclusive lock; one a
    /// restore is reading stays, with its row, for a later pass.
    pub(super) fn reconcile(
        engine_root: &Path,
        store: &SnapshotStore,
    ) -> Result<Reconciled, SupervisorError> {
        let mut trashed = Vec::new();
        let decided = {
            let mut busy = in_flight();
            reconcile_held(engine_root, store, &mut busy, &mut trashed)
        };
        test_hook(engine_root, "reconcile-removing");
        let mut removed = Ok(());
        if !trashed.is_empty() {
            let trash = trash_root(engine_root)?;
            for held in &trashed {
                let path = trash.path().join(&held.0);
                if let Err(source) = remove_snapshot_tree(&path)
                    && removed.is_ok()
                {
                    removed = Err(SupervisorError::Io { path, source });
                }
            }
        }
        // Each trash tree leaves flight only now, after its removal.
        drop(trashed);
        let reconciled = decided?;
        removed?;
        Ok(reconciled)
    }

    /// [`reconcile`], then publish retention again if it adopted anything.
    pub(in crate::supervisor) fn settle(
        config: &NativeRuntimeConfig,
        store: &SnapshotStore,
    ) -> Result<(), SupervisorError> {
        if reconcile(&config.engine_root(), store)?.adopted {
            publish_retention(config, store, None)?;
        }
        Ok(())
    }

    /// `name` in flight, registered under the lock `busy` already holds.
    fn held(busy: &mut BTreeSet<String>, name: String) -> InFlight {
        busy.insert(name.clone());
        InFlight(name)
    }

    fn reconcile_held(
        engine_root: &Path,
        store: &SnapshotStore,
        busy: &mut BTreeSet<String>,
        trashed: &mut Vec<InFlight>,
    ) -> Result<Reconciled, SupervisorError> {
        let mut reconciled = Reconciled::default();
        let snapshots = snapshots_root(engine_root)?;
        let trash = trash_root(engine_root)?;
        let rows = store.list().map_err(store_error)?;
        let intents = store.intents().map_err(store_error)?;
        test_hook(engine_root, "reconcile-read");
        let entries = fs::read_dir(snapshots.path()).map_err(|source| SupervisorError::Io {
            path: snapshots.path().to_owned(),
            source,
        })?;
        let mut present = BTreeSet::new();
        // Directories a restore holds: neither they nor their rows change.
        let mut held_by_restore = BTreeSet::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if busy.contains(&name) {
                continue;
            }
            if name.starts_with(CAPTURE_STAGING_PREFIX) || name.starts_with(RESTORE_STAGING_PREFIX)
            {
                let trashed_name = format!("{TRASH_PREFIX}{}-{name}", Uuid::new_v4());
                if snapshots
                    .move_private_directory_to(Path::new(&name), &trash, Path::new(&trashed_name))
                    .is_ok()
                {
                    trashed.push(held(busy, trashed_name));
                }
                continue;
            }
            let Some(id) = canonical_id(&name) else {
                continue;
            };
            let marked = marked_deleting(&entry.path());
            let remove = match rows.iter().find(|row| row.id == id) {
                Some(row) if row.state == SnapshotState::Ready && !marked => {
                    present.insert(id);
                    false
                }
                Some(_) => true,
                None if marked => true,
                None => {
                    if adopt(engine_root, store, id).is_ok_and(|adopted| adopted) {
                        present.insert(id);
                        reconciled.adopted = true;
                        false
                    } else {
                        intents.contains(&id)
                    }
                }
            };
            if !remove {
                continue;
            }
            if trash_published(&snapshots, &trash, id, busy, trashed)? {
                store.remove_intent(id).map_err(store_error)?;
            } else {
                held_by_restore.insert(id);
            }
        }
        for row in rows {
            if !busy.contains(&row.id.to_string())
                && !held_by_restore.contains(&row.id)
                && (row.state != SnapshotState::Ready || !present.contains(&row.id))
            {
                store.remove(row.id).map_err(store_error)?;
            }
        }
        for id in intents {
            if !busy.contains(&id.to_string())
                && fs::symlink_metadata(snapshots.path().join(id.to_string()))
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                store.remove_intent(id).map_err(store_error)?;
            }
        }
        if let Ok(entries) = fs::read_dir(trash.path()) {
            for entry in entries.flatten() {
                if let Some(name) = entry
                    .file_name()
                    .to_str()
                    .filter(|name| name.starts_with(TRASH_PREFIX) && !busy.contains(*name))
                {
                    trashed.push(held(busy, name.to_owned()));
                }
            }
        }
        Ok(reconciled)
    }

    /// Move the published directory `id` into trash under its exclusive
    /// lock, registered in flight for removal once the lock is released.
    /// `false`, and nothing moved, while a restore holds it shared.
    fn trash_published(
        snapshots: &PrivateRoot,
        trash: &PrivateRoot,
        id: Uuid,
        busy: &mut BTreeSet<String>,
        trashed: &mut Vec<InFlight>,
    ) -> Result<bool, SupervisorError> {
        let directory = snapshots.open_private_directory(Path::new(&id.to_string()), 0o700)?;
        let lock = File::open(directory.path()).map_err(|source| SupervisorError::Io {
            path: directory.path().to_owned(),
            source,
        })?;
        if flock(&lock, FlockOperation::NonBlockingLockExclusive).is_err() {
            return Ok(false);
        }
        drop(directory);
        let trashed_name = format!("{TRASH_PREFIX}{}-{id}", Uuid::new_v4());
        snapshots.move_private_directory_to(
            Path::new(&id.to_string()),
            trash,
            Path::new(&trashed_name),
        )?;
        trashed.push(held(busy, trashed_name));
        drop(lock);
        Ok(true)
    }

    /// Rebuild the row of the row-less snapshot directory `id` from its
    /// manifest: valid, naming this id, every disk present at its size and
    /// with its filesystem, and its name free. `false` leaves it unlisted.
    fn adopt(engine_root: &Path, store: &SnapshotStore, id: Uuid) -> Result<bool, SupervisorError> {
        let snapshots = snapshots_root(engine_root)?;
        let directory = snapshots.open_private_directory(Path::new(&id.to_string()), 0o700)?;
        if marked_deleting(directory.path()) {
            return Ok(false);
        }
        let opened =
            directory.open_regular(Path::new(MANIFEST_FILE), false, None, false, Some(0o400))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(
            &mut io::Read::take(opened.file(), MAXIMUM_MANIFEST_BYTES + 1),
            &mut bytes,
        )
        .map_err(|source| SupervisorError::Io {
            path: directory.path().join(MANIFEST_FILE),
            source,
        })?;
        if bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES {
            return Ok(false);
        }
        let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes) else {
            return Ok(false);
        };
        if manifest.validate(id).is_err() || store.require_free(&manifest.name).is_err() {
            return Ok(false);
        }
        let storage = manifest.storage_generation()?;
        for file in placement_files(&manifest, &storage) {
            let identity =
                crate::state::StateDiskIdentity::capture(&directory.path().join(&file.stored));
            if !identity.is_ok_and(|identity| {
                identity.file.size == file.bytes && identity.filesystem_uuid == file.filesystem_uuid
            }) {
                return Ok(false);
            }
        }
        if let Some(checkpoint) = &manifest.checkpoint
            && !checkpoint.files_match(directory.path())
        {
            return Ok(false);
        }
        let row = SnapshotRow {
            id,
            kind: manifest.row_kind(),
            name: manifest.name.clone(),
            state: SnapshotState::Ready,
            created_unix_ms: manifest.created_unix_ms,
            manifest_sha256: format!("{:x}", Sha256::digest(&bytes)),
            retained: manifest.retained()?,
        };
        Ok(store.insert(&row).is_ok())
    }

    /// Remove a snapshot, capture-staging or restore-staging tree by its
    /// exact layout, opening every directory and file without following a
    /// link: only the files and directories a snapshot holds. An unexpected
    /// object leaves its directory, and the tree, for the orphan inventory.
    pub(in crate::supervisor) fn remove_snapshot_tree(tree: &Path) -> io::Result<()> {
        let (Some(parent), Some(name)) = (tree.parent(), tree.file_name()) else {
            return Err(io::Error::other("a snapshot tree has no parent"));
        };
        match fs::symlink_metadata(tree) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let parent = PrivateRoot::open(parent).map_err(path_io)?;
        let root = parent
            .open_private_directory(Path::new(name), 0o700)
            .map_err(path_io)?;
        remove_member(&root, MANIFEST_FILE)?;
        remove_member(&root, DELETING_MARKER)?;
        if let Some(vmm) = optional_member_directory(&root, "vmm")? {
            for name in crate::state::CHECKPOINT_VMM_FILES {
                remove_member(&vmm, name)?;
            }
            drop(vmm);
            root.remove_empty_private_directory(Path::new("vmm"))
                .map_err(path_io)?;
        }
        remove_disks(&root)?;
        remove_generations(&root, "root")?;
        if let Some(vm) = optional_member_directory(&root, "vm")? {
            remove_disks(&vm)?;
            remove_generations(&vm, "generations")?;
            if let Some(checkpoints) =
                optional_member_directory(&vm, crate::state::CHECKPOINTS_DIRECTORY)?
            {
                crate::state::remove_checkpoint_tree(&checkpoints, crate::state::CHECKPOINT_IN)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                drop(checkpoints);
                vm.remove_empty_private_directory(Path::new(crate::state::CHECKPOINTS_DIRECTORY))
                    .map_err(path_io)?;
            }
            drop(vm);
            root.remove_empty_private_directory(Path::new("vm"))
                .map_err(path_io)?;
        }
        drop(root);
        parent
            .remove_empty_private_directory(Path::new(name))
            .map_err(path_io)
    }

    fn path_io(error: PathError) -> io::Error {
        io::Error::other(error.to_string())
    }

    /// Remove the regular file `name` in `root` (mode 0600 or 0400), if any.
    fn remove_member(root: &PrivateRoot, name: &str) -> io::Result<()> {
        for mode in [0o600, 0o400] {
            match root.remove_private_regular(Path::new(name), mode) {
                Ok(_) => return Ok(()),
                Err(PathError::UnsafeFile(_)) => {}
                Err(error) => return Err(path_io(error)),
            }
        }
        Err(io::Error::other("unexpected object in a snapshot tree"))
    }

    fn optional_member_directory(
        root: &PrivateRoot,
        name: &str,
    ) -> io::Result<Option<PrivateRoot>> {
        match fs::symlink_metadata(root.path().join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
            Ok(_) => root
                .open_private_directory(Path::new(name), 0o700)
                .map(Some)
                .map_err(path_io),
        }
    }

    fn remove_disks(root: &PrivateRoot) -> io::Result<()> {
        let Some(disks) = optional_member_directory(root, "disks")? else {
            return Ok(());
        };
        remove_member(&disks, "state.raw")?;
        remove_member(&disks, "docker.raw")?;
        drop(disks);
        root.remove_empty_private_directory(Path::new("disks"))
            .map_err(path_io)
    }

    fn remove_generations(root: &PrivateRoot, name: &str) -> io::Result<()> {
        let Some(generations) = optional_member_directory(root, name)? else {
            return Ok(());
        };
        let names = crate::state::admitted_generation_names(&generations)
            .map_err(|error| io::Error::other(error.to_string()))?;
        for generation in names {
            let directory = generations
                .open_private_directory(Path::new(&generation), 0o700)
                .map_err(path_io)?;
            remove_member(&directory, "root.raw")?;
            drop(directory);
            generations
                .remove_empty_private_directory(Path::new(&generation))
                .map_err(path_io)?;
        }
        drop(generations);
        root.remove_empty_private_directory(Path::new(name))
            .map_err(path_io)
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(target_os = "linux")]
use linux::{capture, delete, get, list, place_snapshot_tree, ready_snapshot, reconcile};
#[cfg(target_os = "linux")]
pub(in crate::supervisor) use linux::{
    delete_ready, find_ready, list_ready, publish, remove_snapshot_tree, require_vmm_dead, settle,
    snapshot_proto, source_inputs,
};
