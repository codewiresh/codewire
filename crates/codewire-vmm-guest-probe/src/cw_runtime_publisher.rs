//! Guest-root publication. Workloads see only the readonly sealed view.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VsockAddr, VsockListener};
use uuid::Uuid;

use crate::cw_runtime::{
    CW_RUNTIME_MAX_BYTES, CW_RUNTIME_MAX_PACK, CW_RUNTIME_MAX_PROVENANCE, CW_RUNTIME_MAX_VERSIONS,
    CW_RUNTIME_ROOT, CwRuntimeCatalog, CwRuntimeProvenance, decode_runtime_pack,
};
use crate::cw_runtime_live::*;

const SELECTOR: &str = "selection.json";
const FS_IOC_ENABLE_VERITY: u32 = 0x4080_6685;
const FS_IOC_MEASURE_VERITY: u32 = 0xc004_6686;
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;
/// A member's fs-verity digest, set by the publisher once it has read the
/// sealed file back against the payload's SHA-256. It is an attribute and not
/// a member entry, so a publisher that predates it still reads the member. In
/// the `user` namespace because the launcher reads it as the workload; only
/// root can write it, since the file is root's and mode 0555.
const VERITY_RECORD: &std::ffi::CStr = c"user.codewire.verity";

pub struct RuntimeCache {
    root: PathBuf,
    view: PathBuf,
    uid: u32,
    _lock: File,
    binding: RuntimeBinding,
}

impl RuntimeCache {
    /// `moved_from` is the bootstrap catalog a move takes this environment
    /// off, named by the seed of the boot that completes the move.
    pub fn initialize(
        binding: RuntimeBinding,
        bootstrap: &CwRuntimeCatalog,
        bootstrap_root: &Path,
        launcher: &Path,
        moved_from: Option<&str>,
    ) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "runtime publisher must be guest root"
        );
        Self::initialize_at(
            Path::new(LIVE_RUNTIME_CACHE),
            binding,
            bootstrap,
            bootstrap_root,
            launcher,
            moved_from,
            0,
        )
    }

    fn initialize_at(
        root: &Path,
        binding: RuntimeBinding,
        bootstrap: &CwRuntimeCatalog,
        bootstrap_root: &Path,
        launcher: &Path,
        moved_from: Option<&str>,
        uid: u32,
    ) -> Result<Self> {
        binding.validate().map_err(anyhow::Error::msg)?;
        bootstrap.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            digest_bytes(&bootstrap.encode().map_err(anyhow::Error::msg)?)
                == binding.bootstrap_catalog_sha256,
            "bootstrap catalog identity changed"
        );
        ensure_directory(root.parent().context("runtime cache parent")?, uid, None)?;
        create_directory(root, uid, 0o700)?;
        let lock_path = root.join("control.lock");
        let lock = open_lock(&lock_path, uid)?;
        // This lifetime lock has no workload interface. Transfers happen
        // outside the selector mutex; only short admission/commit holds it.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "runtime publisher is already active"
        );
        let view = root.join("view");
        create_directory(&view, uid, 0o555)?;
        let cache = Self {
            root: root.to_owned(),
            view,
            uid,
            _lock: lock,
            binding,
        };
        cache.recover_staging()?;
        let selector = cache.view.join(SELECTOR);
        if exists_nofollow(&selector)? {
            let recorded = cache.recorded_selection()?;
            if recorded.admit_binding(&cache.binding).is_err()
                && moves_from(&recorded, &cache.binding, moved_from)
            {
                eprintln!(
                    "codewire guest: environment {} moves its cw runtime from bootstrap {} to {}; rebuilding the runtime cache",
                    cache.binding.environment_id,
                    recorded.bootstrap_catalog_sha256,
                    cache.binding.bootstrap_catalog_sha256
                );
                cache.clear_for_move()?;
            }
        }
        if exists_nofollow(&selector)? {
            let state = cache.selection()?;
            state
                .admit_binding(&cache.binding)
                .map_err(anyhow::Error::msg)?;
            for member in &bootstrap.runtimes {
                ensure!(
                    state.catalog.runtime(&member.payload.sha256) == Some(member),
                    "bootstrap member is missing or changed"
                );
            }
        } else {
            for member in &bootstrap.runtimes {
                let binary = read_sealed(
                    &bootstrap_root.join(&member.payload.sha256).join("cw"),
                    uid,
                    0o555,
                    CW_RUNTIME_MAX_BYTES,
                )?;
                member
                    .validate_payload(&binary)
                    .map_err(anyhow::Error::msg)?;
                cache.publish_member(member, &binary)?;
            }
            let selection = RuntimeSelection {
                schema_version: LIVE_RUNTIME_PROTOCOL,
                environment_id: cache.binding.environment_id,
                bootstrap_catalog_sha256: cache.binding.bootstrap_catalog_sha256.clone(),
                revision: 1,
                previous_sha256: None,
                catalog: bootstrap.clone(),
                operations: Vec::new(),
            };
            cache.commit(&selection)?;
        }
        cache.ensure_launcher(launcher)?;
        cache.validate_inventory()?;
        cache.recover_membership()?;
        Ok(cache)
    }

    /// Seals a staged `cw` with fs-verity where its filesystem can. The digest
    /// is recorded only after the sealed file reads back as the payload, so a
    /// recorded digest always stands for the provenance's bytes.
    fn seal_member(&self, cw: &Path, provenance: &CwRuntimeProvenance) -> Result<()> {
        let Some(digest) = enable_verity(cw)? else {
            return Ok(());
        };
        let binary = read_sealed(cw, self.uid, 0o555, CW_RUNTIME_MAX_BYTES)?;
        provenance
            .validate_payload(&binary)
            .map_err(anyhow::Error::msg)?;
        let file = File::open(cw)?;
        record_verity(&file, &digest)?;
        file.sync_all()?;
        Ok(())
    }

    /// Moves the publisher to a restored boot's identity (#3046 R4). A new
    /// generation of this environment only changes the binding. A fork is a
    /// new environment: the selection keeps its runtimes and revision, takes
    /// the fork's environment id, and drops the source's operation receipts,
    /// which no caller of the fork can observe.
    pub fn rebind(&mut self, environment_id: Uuid, generation: u64) -> Result<()> {
        let binding = RuntimeBinding {
            environment_id,
            generation,
            bootstrap_catalog_sha256: self.binding.bootstrap_catalog_sha256.clone(),
        };
        binding.validate().map_err(anyhow::Error::msg)?;
        if environment_id == self.binding.environment_id {
            self.binding = binding;
            return Ok(());
        }
        let mut selection = self.selection()?;
        selection.environment_id = environment_id;
        selection.operations.clear();
        let previous = std::mem::replace(&mut self.binding, binding);
        if let Err(error) = self.commit(&selection) {
            self.binding = previous;
            return Err(error);
        }
        Ok(())
    }

    /// The selection as recorded, before it is admitted for this boot.
    fn recorded_selection(&self) -> Result<RuntimeSelection> {
        self.validate_roots()?;
        let bytes = read_sealed(
            &self.view.join(SELECTOR),
            self.uid,
            0o444,
            LIVE_RUNTIME_MAX_FRAME,
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Removes the view's members and launcher, then its selector last, so
    /// a boot that stops part way finds the earlier selector and rebuilds
    /// again. Nothing is followed, and nothing on another filesystem or
    /// owned by anyone else is touched: such an entry fails the boot. As
    /// guest root it unlinks without changing any mode, so a boot that fails
    /// here leaves the cache's directories as they were for the retry.
    fn clear_for_move(&self) -> Result<()> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = rustix::fs::open(&self.root, flags, Mode::empty())?;
        let device = rustix::fs::fstat(&root)?.st_dev;
        let view = rustix::fs::openat(&root, "view", flags, Mode::empty())?;
        let expected = Expected {
            device,
            uid: self.uid,
        };
        expected.admit(&rustix::fs::fstat(&view)?, true)?;
        for name in directory_names(&view)? {
            if name.as_bytes() != SELECTOR.as_bytes() {
                remove_beneath(&view, &name, expected, CLEAR_DEPTH)?;
            }
        }
        rustix::fs::unlinkat(&view, SELECTOR, AtFlags::empty())?;
        rustix::fs::fsync(&view)?;
        Ok(())
    }

    pub fn selection(&self) -> Result<RuntimeSelection> {
        let deadline = Instant::now() + Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS);
        self.validate_roots()?;
        let bytes = read_sealed(
            &self.view.join(SELECTOR),
            self.uid,
            0o444,
            LIVE_RUNTIME_MAX_FRAME,
        )?;
        let selection: RuntimeSelection = serde_json::from_slice(&bytes)?;
        selection
            .admit_binding(&self.binding)
            .map_err(anyhow::Error::msg)?;
        for member in &selection.catalog.runtimes {
            self.verify_member_until(member, deadline)?;
        }
        Ok(selection)
    }

    fn validate_roots(&self) -> Result<()> {
        ensure_directory(&self.root, self.uid, Some(0o700))?;
        ensure_directory(&self.view, self.uid, Some(0o555))
    }

    fn verify_member(&self, member: &CwRuntimeProvenance) -> Result<()> {
        self.verify_member_until(
            member,
            Instant::now() + Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS),
        )
    }
    /// A member sealed with fs-verity is measured: the kernel checks every
    /// page against that digest as it is read. Any other is read in full.
    fn verify_member_until(&self, member: &CwRuntimeProvenance, deadline: Instant) -> Result<()> {
        let path = self.view.join(&member.payload.sha256);
        ensure_directory(&path, self.uid, Some(0o555))?;
        let mut entries = fs::read_dir(&path)?
            .take(3)
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        ensure!(
            entries
                == [
                    std::ffi::OsString::from("cw"),
                    std::ffi::OsString::from("provenance.json")
                ],
            "unexpected runtime member entry"
        );
        let provenance = read_sealed(
            &path.join("provenance.json"),
            self.uid,
            0o444,
            CW_RUNTIME_MAX_PROVENANCE,
        )?;
        ensure!(
            CwRuntimeProvenance::decode(&provenance).map_err(anyhow::Error::msg)? == *member,
            "runtime member provenance changed"
        );
        if verity_sealed(&path.join("cw"), self.uid)? {
            return Ok(());
        }
        let binary = read_sealed_until(
            &path.join("cw"),
            self.uid,
            0o555,
            CW_RUNTIME_MAX_BYTES,
            deadline,
        )?;
        member.validate_payload(&binary).map_err(anyhow::Error::msg)
    }

    fn validate_inventory(&self) -> Result<()> {
        self.validate_roots()?;
        let count = fs::read_dir(&self.view)?
            .take(CW_RUNTIME_MAX_VERSIONS + 3)
            .count();
        ensure!(
            count <= CW_RUNTIME_MAX_VERSIONS + 2,
            "runtime view inventory exceeds its bound"
        );
        let mut members = 0;
        for entry in fs::read_dir(&self.view)?.take(CW_RUNTIME_MAX_VERSIONS + 3) {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid runtime view entry"))?;
            if matches!(name.as_str(), SELECTOR | "cw") {
                continue;
            }
            ensure!(digest(&name), "unexpected runtime view entry");
            members += 1;
            ensure!(
                members <= CW_RUNTIME_MAX_VERSIONS,
                "runtime retention capacity reached"
            );
            let provenance = read_sealed(
                &entry.path().join("provenance.json"),
                self.uid,
                0o444,
                CW_RUNTIME_MAX_PROVENANCE,
            )?;
            let member = CwRuntimeProvenance::decode(&provenance).map_err(anyhow::Error::msg)?;
            ensure!(
                member.payload.sha256 == name,
                "runtime directory identity changed"
            );
            self.verify_member(&member)?;
        }
        Ok(())
    }

    fn recover_membership(&self) -> Result<()> {
        let mut selection = self.selection()?;
        let mut changed = false;
        for entry in fs::read_dir(&self.view)?.take(CW_RUNTIME_MAX_VERSIONS + 3) {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|name| digest(name)) else {
                continue;
            };
            if selection.catalog.runtime(name).is_none() {
                let bytes = read_sealed(
                    &entry.path().join("provenance.json"),
                    self.uid,
                    0o444,
                    CW_RUNTIME_MAX_PROVENANCE,
                )?;
                let member = CwRuntimeProvenance::decode(&bytes).map_err(anyhow::Error::msg)?;
                self.verify_member(&member)?;
                selection.catalog.runtimes.push(member);
                changed = true;
            }
        }
        if changed {
            selection
                .catalog
                .runtimes
                .sort_by(|a, b| a.payload.sha256.cmp(&b.payload.sha256));
            self.commit(&selection)?;
        }
        Ok(())
    }

    fn publish_member(&self, provenance: &CwRuntimeProvenance, binary: &[u8]) -> Result<()> {
        self.validate_roots()?;
        provenance
            .validate_payload(binary)
            .map_err(anyhow::Error::msg)?;
        let target = self.view.join(&provenance.payload.sha256);
        if exists_nofollow(&target)? {
            return self.verify_member(provenance);
        }
        let count = fs::read_dir(&self.view)?
            .take(CW_RUNTIME_MAX_VERSIONS + 3)
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_str().is_some_and(digest))
            .count();
        ensure!(
            count < CW_RUNTIME_MAX_VERSIONS,
            "runtime retention capacity reached"
        );
        let stage = self.root.join(format!("stage-{}", Uuid::new_v4()));
        create_directory(&stage, self.uid, 0o700)?;
        let result = (|| {
            write_new(&stage.join("cw"), binary, 0o555)?;
            self.seal_member(&stage.join("cw"), provenance)?;
            write_new(
                &stage.join("provenance.json"),
                &serde_json::to_vec(provenance)?,
                0o444,
            )?;
            File::open(&stage)?.sync_all()?;
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o555))?;
            no_replace(&stage, &target)?;
            File::open(&self.view)?.sync_all()?;
            self.verify_member(provenance)
        })();
        if exists_nofollow(&stage)? {
            self.remove_stage(&stage)?;
        }
        result
    }

    pub fn publish(
        &self,
        request: &RuntimeRequest,
        bytes: &[u8],
    ) -> Result<RuntimeReply, RuntimeRefusal> {
        self.admit(request)?;
        let RuntimeAction::Publish {
            pack_size,
            pack_sha256,
            provenance,
            operation_id,
        } = &request.action
        else {
            return Err(RuntimeRefusal::Invalid);
        };
        if bytes.len() as u64 != *pack_size || digest_bytes(bytes) != *pack_sha256 {
            return Err(RuntimeRefusal::Invalid);
        }
        let (actual, binary) = decode_runtime_pack(bytes).map_err(|_| RuntimeRefusal::Invalid)?;
        if &actual != provenance.as_ref() {
            return Err(RuntimeRefusal::Collision);
        }
        let mut state = self.selection().map_err(|_| RuntimeRefusal::Unavailable)?;
        if let Some(receipt) = state.receipt(*operation_id) {
            if receipt.generation != request.binding.generation
                || receipt.target_sha256 != provenance.payload.sha256
            {
                return Err(RuntimeRefusal::Collision);
            }
            if receipt.outcome == SelectionOutcome::Cancelled {
                return Err(RuntimeRefusal::Cancelled);
            }
        } else if state.operations.len() == LIVE_RUNTIME_MAX_OPERATIONS {
            return Err(RuntimeRefusal::Capacity);
        }
        if state.catalog.runtime(&provenance.payload.sha256).is_none()
            && state.catalog.runtimes.len() == CW_RUNTIME_MAX_VERSIONS
        {
            return Err(RuntimeRefusal::Capacity);
        }
        self.publish_member(provenance, binary)
            .map_err(|_| RuntimeRefusal::Collision)?;
        if state.catalog.runtime(&provenance.payload.sha256).is_none() {
            state.catalog.runtimes.push(provenance.as_ref().clone());
            state
                .catalog
                .runtimes
                .sort_by(|a, b| a.payload.sha256.cmp(&b.payload.sha256));
            // Membership publication does not change the default/revision.
            self.commit(&state)
                .map_err(|_| RuntimeRefusal::Unavailable)?;
        }
        self.reply(None)
    }

    fn admit(&self, request: &RuntimeRequest) -> Result<(), RuntimeRefusal> {
        request.validate().map_err(|_| RuntimeRefusal::Invalid)?;
        if request.binding != self.binding {
            return Err(RuntimeRefusal::Identity);
        }
        Ok(())
    }

    pub fn control(&self, request: &RuntimeRequest) -> Result<RuntimeReply, RuntimeRefusal> {
        self.admit(request)?;
        match &request.action {
            RuntimeAction::Info => self.reply(None),
            RuntimeAction::Observe { operation_id } => self.reply(Some(*operation_id)),
            RuntimeAction::Select {
                operation_id,
                expected_revision,
                target_sha256,
            }
            | RuntimeAction::RetainedSelect {
                operation_id,
                expected_revision,
                target_sha256,
            }
            | RuntimeAction::Cancel {
                operation_id,
                expected_revision,
                target_sha256,
            } => {
                let mut state = self.selection().map_err(|_| RuntimeRefusal::Unavailable)?;
                if let Some(receipt) = state.receipt(*operation_id) {
                    if receipt.generation != request.binding.generation
                        || receipt.expected_revision != *expected_revision
                        || receipt.target_sha256 != *target_sha256
                    {
                        return Err(RuntimeRefusal::Collision);
                    }
                    return self.reply(Some(*operation_id));
                }
                if state.operations.len() == LIVE_RUNTIME_MAX_OPERATIONS {
                    return Err(RuntimeRefusal::Capacity);
                }
                let cancelled = matches!(request.action, RuntimeAction::Cancel { .. });
                if !cancelled {
                    if state.revision != *expected_revision {
                        return Err(RuntimeRefusal::StaleRevision);
                    }
                    if matches!(request.action, RuntimeAction::RetainedSelect { .. })
                        && state.previous_sha256.as_ref() != Some(target_sha256)
                    {
                        return Err(RuntimeRefusal::Invalid);
                    }
                    let path = self.view.join(target_sha256).join("provenance.json");
                    let bytes = read_sealed(&path, self.uid, 0o444, CW_RUNTIME_MAX_PROVENANCE)
                        .map_err(|_| RuntimeRefusal::Invalid)?;
                    let member =
                        CwRuntimeProvenance::decode(&bytes).map_err(|_| RuntimeRefusal::Invalid)?;
                    if member.payload.sha256 != *target_sha256 {
                        return Err(RuntimeRefusal::Collision);
                    }
                    self.verify_member(&member)
                        .map_err(|_| RuntimeRefusal::Collision)?;
                    if state.catalog.runtime(target_sha256).is_none() {
                        state.catalog.runtimes.push(member);
                        state
                            .catalog
                            .runtimes
                            .sort_by(|a, b| a.payload.sha256.cmp(&b.payload.sha256));
                    }
                    state.previous_sha256 = Some(state.catalog.active_sha256.clone());
                    state.catalog.active_sha256 = target_sha256.clone();
                    state.revision = state
                        .revision
                        .checked_add(1)
                        .ok_or(RuntimeRefusal::Capacity)?;
                }
                state.operations.push(SelectionReceipt {
                    operation_id: *operation_id,
                    generation: request.binding.generation,
                    expected_revision: *expected_revision,
                    target_sha256: target_sha256.clone(),
                    outcome: if cancelled {
                        SelectionOutcome::Cancelled
                    } else {
                        SelectionOutcome::Committed
                    },
                    selection_revision: state.revision,
                });
                self.commit(&state)
                    .map_err(|_| RuntimeRefusal::Unavailable)?;
                self.reply(Some(*operation_id))
            }
            RuntimeAction::Publish { .. } => Err(RuntimeRefusal::Invalid),
        }
    }

    fn reply(&self, operation_id: Option<Uuid>) -> Result<RuntimeReply, RuntimeRefusal> {
        let selection = self.selection().map_err(|_| RuntimeRefusal::Unavailable)?;
        let observed = operation_id.and_then(|id| selection.receipt(id).cloned());
        Ok(RuntimeReply {
            protocol_version: LIVE_RUNTIME_PROTOCOL,
            binding: self.binding.clone(),
            selection,
            observed,
        })
    }

    fn commit(&self, state: &RuntimeSelection) -> Result<()> {
        state
            .admit_binding(&self.binding)
            .map_err(anyhow::Error::msg)?;
        let bytes = serde_json::to_vec(state)?;
        ensure!(
            bytes.len() <= LIVE_RUNTIME_MAX_FRAME,
            "runtime selector exceeds its bound"
        );
        let temp = self.root.join(format!("selector-{}", Uuid::new_v4()));
        write_new(&temp, &bytes, 0o444)?;
        let result = (|| {
            self.validate_roots()?;
            fs::rename(&temp, self.view.join(SELECTOR))?;
            File::open(&self.view)?.sync_all()?;
            Ok(())
        })();
        if exists_nofollow(&temp)? {
            fs::remove_file(temp)?;
        }
        result
    }

    fn ensure_launcher(&self, source: &Path) -> Result<()> {
        let binary = read_sealed(source, self.uid, 0o755, CW_RUNTIME_MAX_BYTES)?;
        let launcher = self.view.join("cw");
        if exists_nofollow(&launcher)? {
            let actual = read_sealed(&launcher, self.uid, 0o555, CW_RUNTIME_MAX_BYTES)?;
            ensure!(
                digest_bytes(&actual) == digest_bytes(&binary),
                "trusted runtime launcher changed"
            );
        } else {
            let stage = self.root.join(format!("launcher-{}", Uuid::new_v4()));
            write_new(&stage, &binary, 0o555)?;
            no_replace(&stage, &launcher)?;
            File::open(&self.view)?.sync_all()?;
        }
        Ok(())
    }

    fn recover_staging(&self) -> Result<()> {
        ensure!(
            fs::read_dir(&self.root)?.take(260).count() < 260,
            "runtime cache inventory exceeds its bound"
        );
        for entry in fs::read_dir(&self.root)?.take(260) {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid runtime cache entry"))?;
            if matches!(name.as_str(), "view" | "control.lock") {
                continue;
            }
            if let Some(id) = name.strip_prefix("stage-") {
                ensure!(
                    Uuid::parse_str(id).is_ok(),
                    "invalid runtime stage identity"
                );
                self.remove_stage(&entry.path())?;
            } else if let Some(id) = name.strip_prefix("selector-") {
                ensure!(
                    Uuid::parse_str(id).is_ok(),
                    "invalid runtime selector stage identity"
                );
                inspect_staged_file(
                    &entry.path(),
                    self.uid,
                    &[0o600, 0o444],
                    LIVE_RUNTIME_MAX_FRAME,
                )?;
                fs::remove_file(entry.path())?;
            } else if let Some(id) = name.strip_prefix("launcher-") {
                ensure!(
                    Uuid::parse_str(id).is_ok(),
                    "invalid runtime launcher stage identity"
                );
                inspect_staged_file(
                    &entry.path(),
                    self.uid,
                    &[0o600, 0o555],
                    CW_RUNTIME_MAX_BYTES,
                )?;
                fs::remove_file(entry.path())?;
            } else {
                bail!("unexpected runtime cache entry");
            }
        }
        Ok(())
    }

    fn remove_stage(&self, stage: &Path) -> Result<()> {
        ensure_directory(stage, self.uid, None)?;
        let entries = fs::read_dir(stage)?
            .take(3)
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(entries.len() <= 2, "invalid runtime stage inventory");
        for entry in &entries {
            let name = entry.file_name();
            let (mode, limit) = match name.to_str() {
                Some("cw") => (0o555, CW_RUNTIME_MAX_BYTES),
                Some("provenance.json") => (0o444, CW_RUNTIME_MAX_PROVENANCE),
                _ => bail!("unexpected runtime stage member"),
            };
            inspect_staged_file(&entry.path(), self.uid, &[0o600, mode], limit)?;
        }
        fs::set_permissions(stage, fs::Permissions::from_mode(0o700))?;
        for entry in entries {
            fs::remove_file(entry.path())?;
        }
        fs::remove_dir(stage)?;
        Ok(())
    }
}

/// Whether the recorded selection is exactly the one a move takes this
/// environment off: this environment, the bootstrap catalog the seed names,
/// and not this boot's. Every other mismatch is refused as before.
fn moves_from(
    recorded: &RuntimeSelection,
    binding: &RuntimeBinding,
    moved_from: Option<&str>,
) -> bool {
    moved_from.is_some_and(|from| {
        recorded.validate().is_ok()
            && recorded.environment_id == binding.environment_id
            && recorded.bootstrap_catalog_sha256 == from
            && from != binding.bootstrap_catalog_sha256
    })
}

/// A view member is `<sha256>/{cw,provenance.json}` beneath the view.
const CLEAR_DEPTH: usize = 2;
/// More entries than any view holds, as the cache root's bound.
const CLEAR_ENTRY_LIMIT: usize = 260;

/// What every entry the move's rebuild removes must be: on the cache's own
/// filesystem and owned by the publisher.
#[derive(Clone, Copy)]
struct Expected {
    device: u64,
    uid: u32,
}

impl Expected {
    fn admit(self, stat: &rustix::fs::Stat, directory: bool) -> Result<()> {
        ensure!(
            stat.st_dev == self.device
                && stat.st_uid == self.uid
                && (rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    == rustix::fs::FileType::Directory)
                    == directory,
            "runtime cache entry is not the publisher's"
        );
        Ok(())
    }
}

fn directory_names(directory: &rustix::fd::OwnedFd) -> Result<Vec<std::ffi::CString>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let name = entry?.file_name().to_owned();
        if !matches!(name.as_bytes(), b"." | b"..") {
            names.push(name);
        }
        ensure!(
            names.len() <= CLEAR_ENTRY_LIMIT,
            "runtime cache inventory exceeds its bound"
        );
    }
    Ok(names)
}

/// Removes `name` beneath `parent` without following it. A symlink or a
/// file is unlinked where it is; a directory is opened beneath its parent
/// and emptied first, at most `depth` levels down.
fn remove_beneath(
    parent: &rustix::fd::OwnedFd,
    name: &std::ffi::CStr,
    expected: Expected,
    depth: usize,
) -> Result<()> {
    let stat = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    match file_type {
        rustix::fs::FileType::RegularFile | rustix::fs::FileType::Symlink => {
            expected.admit(&stat, false)?;
            rustix::fs::unlinkat(parent, name, AtFlags::empty())?;
        }
        rustix::fs::FileType::Directory if depth > 0 => {
            let directory = rustix::fs::openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let opened = rustix::fs::fstat(&directory)?;
            ensure!(
                opened.st_ino == stat.st_ino && opened.st_dev == stat.st_dev,
                "runtime cache entry changed while it was removed"
            );
            expected.admit(&opened, true)?;
            for child in directory_names(&directory)? {
                remove_beneath(&directory, &child, expected, depth - 1)?;
            }
            rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR)?;
        }
        _ => bail!("unexpected runtime cache entry"),
    }
    Ok(())
}

fn exists_nofollow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn ensure_directory(path: &Path, uid: u32, mode: Option<u32>) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && (uid != 0 || metadata.gid() == 0)
            && metadata.mode() & 0o022 == 0
            && mode.is_none_or(|mode| metadata.mode() & 0o7777 == mode),
        "runtime directory ownership or mode changed"
    );
    Ok(())
}

fn create_directory(path: &Path, uid: u32, mode: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_directory(path, uid, Some(mode))
}

fn open_lock(path: &Path, uid: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && (uid != 0 || metadata.gid() == 0)
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "invalid runtime publisher lock"
    );
    Ok(file)
}

fn read_sealed(path: &Path, uid: u32, mode: u32, limit: usize) -> Result<Vec<u8>> {
    read_sealed_until(
        path,
        uid,
        mode,
        limit,
        Instant::now() + Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS),
    )
}
fn open_sealed(path: &Path, uid: u32, mode: u32, limit: usize) -> Result<(File, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == uid
            && (uid != 0 || before.gid() == 0)
            && before.mode() & 0o7777 == mode
            && before.nlink() == 1
            && before.len() > 0
            && before.len() <= limit as u64,
        "invalid sealed runtime file"
    );
    Ok((file, before))
}
fn ensure_sealed_unchanged(path: &Path, file: &File, before: &fs::Metadata) -> Result<()> {
    let after = file.metadata()?;
    let live = fs::symlink_metadata(path)?;
    ensure!(
        [after, live]
            .iter()
            .all(|metadata| metadata.dev() == before.dev()
                && metadata.ino() == before.ino()
                && metadata.len() == before.len()
                && metadata.uid() == before.uid()
                && metadata.gid() == before.gid()
                && metadata.mode() == before.mode()
                && metadata.nlink() == 1
                && metadata.mtime() == before.mtime()
                && metadata.mtime_nsec() == before.mtime_nsec()
                && metadata.ctime() == before.ctime()
                && metadata.ctime_nsec() == before.ctime_nsec()),
        "sealed runtime file changed"
    );
    Ok(())
}
fn read_sealed_until(
    path: &Path,
    uid: u32,
    mode: u32,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let (file, before) = open_sealed(path, uid, mode, limit)?;
    let mut bytes = Vec::new();
    let mut reader = (&file).take(limit as u64 + 1);
    let mut chunk = [0; 64 * 1024];
    loop {
        ensure!(Instant::now() < deadline, "runtime read deadline elapsed");
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    ensure!(
        bytes.len() as u64 == before.len(),
        "sealed runtime file changed"
    );
    ensure_sealed_unchanged(path, &file, &before)?;
    Ok(bytes)
}

/// Whether `path` is sealed with the fs-verity digest recorded for it. A
/// recorded digest the kernel does not measure is a changed member.
fn verity_sealed(path: &Path, uid: u32) -> Result<bool> {
    let (file, before) = open_sealed(path, uid, 0o555, CW_RUNTIME_MAX_BYTES)?;
    let Some(recorded) = recorded_verity(&file)? else {
        return Ok(false);
    };
    ensure!(
        measure_verity(&file)? == Some(recorded),
        "runtime member verity digest changed"
    );
    ensure_sealed_unchanged(path, &file, &before)?;
    Ok(true)
}

/// Seal `path`, returning its digest, or `None` where the filesystem cannot:
/// a state disk made before it had the `verity` feature, or another filesystem.
fn enable_verity(path: &Path) -> Result<Option<[u8; 32]>> {
    #[repr(C)]
    struct EnableArguments {
        version: u32,
        hash_algorithm: u32,
        block_size: u32,
        salt_size: u32,
        salt_pointer: u64,
        signature_size: u32,
        reserved1: u32,
        signature_pointer: u64,
        reserved2: [u64; 11],
    }
    let arguments = EnableArguments {
        version: 1,
        hash_algorithm: u32::from(FS_VERITY_HASH_ALG_SHA256),
        block_size: 4096,
        salt_size: 0,
        salt_pointer: 0,
        signature_size: 0,
        reserved1: 0,
        signature_pointer: 0,
        reserved2: [0; 11],
    };
    // The kernel requires a read-only descriptor and no writer.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_ENABLE_VERITY as _, &arguments) } != 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOTTY)) {
            return Ok(None);
        }
        return Err(error).context("seal runtime member");
    }
    Ok(Some(
        measure_verity(&file)?.context("sealed runtime member has no digest")?,
    ))
}

/// The kernel's digest of `file`, or `None` when it is not sealed.
fn measure_verity(file: &File) -> Result<Option<[u8; 32]>> {
    #[repr(C)]
    struct Measurement {
        algorithm: u16,
        size: u16,
        digest: [u8; 32],
    }
    let mut measurement = Measurement {
        algorithm: 0,
        size: 32,
        digest: [0; 32],
    };
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            FS_IOC_MEASURE_VERITY as _,
            &mut measurement,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENODATA | libc::EOPNOTSUPP | libc::ENOTTY)
        ) {
            return Ok(None);
        }
        return Err(error).context("measure runtime member");
    }
    ensure!(
        measurement.algorithm == FS_VERITY_HASH_ALG_SHA256 && measurement.size == 32,
        "unexpected runtime member verity digest"
    );
    Ok(Some(measurement.digest))
}

fn recorded_verity(file: &File) -> Result<Option<[u8; 32]>> {
    let mut digest = [0_u8; 33];
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            VERITY_RECORD.as_ptr(),
            digest.as_mut_ptr().cast(),
            digest.len(),
        )
    };
    if size < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
            return Ok(None);
        }
        return Err(error).context("read runtime member verity digest");
    }
    ensure!(size == 32, "unexpected runtime member verity digest");
    let mut recorded = [0_u8; 32];
    recorded.copy_from_slice(&digest[..32]);
    Ok(Some(recorded))
}

fn record_verity(file: &File, digest: &[u8; 32]) -> Result<()> {
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            VERITY_RECORD.as_ptr(),
            digest.as_ptr().cast(),
            digest.len(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("record runtime member digest");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn inspect_staged_file(path: &Path, uid: u32, modes: &[u32], limit: usize) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let live = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && (uid != 0 || metadata.gid() == 0)
            && metadata.nlink() == 1
            && modes.contains(&(metadata.mode() & 0o7777))
            && metadata.len() <= limit as u64
            && metadata.ino() == live.ino()
            && metadata.dev() == live.dev(),
        "invalid owned runtime staging file"
    );
    Ok(())
}

fn no_replace(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "runtime publication collision"
    );
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<T> {
    let size = stream.read_u32().await? as usize;
    ensure!(
        size > 0 && size <= LIVE_RUNTIME_MAX_FRAME,
        "runtime frame exceeds its bound"
    );
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).context("invalid runtime frame")
}

pub async fn serve(cache: Arc<Mutex<RuntimeCache>>) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, LIVE_RUNTIME_VSOCK_PORT))?;
    let transfer = Arc::new(tokio::sync::Semaphore::new(1));
    let connections = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let (stream, peer) = listener.accept().await?;
        if peer.cid() != VMADDR_CID_HOST {
            continue;
        }
        let Ok(connection) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let cache = cache.clone();
        let transfer = transfer.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS),
                handle(stream, cache, transfer, Some(Arc::new(connection))),
            )
            .await;
        });
    }
}

async fn handle(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    cache: Arc<Mutex<RuntimeCache>>,
    transfer: Arc<tokio::sync::Semaphore>,
    connection: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> Result<()> {
    let request: RuntimeRequest = read_frame(&mut stream).await?;
    request.validate().map_err(anyhow::Error::msg)?;
    // Admission happens before reading/allocating incoming pack bytes. Its
    // filesystem mutex never blocks an async daemon runtime thread.
    let admission_cache = cache.clone();
    let admission_request = request.clone();
    let admission_connection = connection.clone();
    tokio::task::spawn_blocking(move || {
        let _connection = admission_connection;
        admission_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime publisher poisoned"))?
            .admit(&admission_request)
            .map_err(|_| anyhow::anyhow!("runtime request identity refused"))
    })
    .await
    .context("runtime identity task")??;
    let result = if let RuntimeAction::Publish { pack_size, .. } = &request.action {
        let _permit = transfer
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("runtime transfer already active"))?;
        let mut bytes = Vec::new();
        (&mut stream)
            .take(*pack_size + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() as u64 == *pack_size && bytes.len() <= CW_RUNTIME_MAX_PACK,
            "runtime pack length changed"
        );
        tokio::task::spawn_blocking(move || {
            let _permit = _permit;
            let _connection = connection;
            cache
                .lock()
                .map_err(|_| anyhow::anyhow!("runtime publisher poisoned"))
                .map(|cache| cache.publish(&request, &bytes))
        })
        .await
        .context("runtime publication task")??
    } else {
        tokio::task::spawn_blocking(move || {
            let _connection = connection;
            cache
                .lock()
                .map_err(|_| anyhow::anyhow!("runtime publisher poisoned"))
                .map(|cache| cache.control(&request))
        })
        .await
        .context("runtime selector task")??
    };
    let response = match result {
        Ok(reply) => RuntimeResponse {
            reply: Some(reply),
            refusal: None,
        },
        Err(refusal) => RuntimeResponse {
            reply: None,
            refusal: Some(refusal),
        },
    };
    stream
        .write_all(&encode_frame(&response).map_err(anyhow::Error::msg)?)
        .await?;
    stream.shutdown().await?;
    Ok(())
}

pub fn launch_default(arguments: Vec<std::ffi::OsString>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;
    let root = Path::new(CW_RUNTIME_ROOT);
    ensure_directory(root, 0, Some(0o555))?;
    let bytes = read_sealed(&root.join(SELECTOR), 0, 0o444, LIVE_RUNTIME_MAX_FRAME)?;
    let selector: RuntimeSelection = serde_json::from_slice(&bytes)?;
    selector.validate().map_err(anyhow::Error::msg)?;
    let member = selector
        .catalog
        .runtime(&selector.catalog.active_sha256)
        .context("missing active runtime")?;
    let executable = root.join(&member.payload.sha256).join("cw");
    ensure_directory(
        executable.parent().context("runtime executable parent")?,
        0,
        Some(0o555),
    )?;
    if !verity_sealed(&executable, 0)? {
        let bytes = read_sealed(&executable, 0, 0o555, CW_RUNTIME_MAX_BYTES)?;
        member
            .validate_payload(&bytes)
            .map_err(anyhow::Error::msg)?;
    }
    let error = std::process::Command::new(executable)
        .args(arguments)
        .exec();
    Err(error).context("execute selected workload runtime")
}

#[cfg(test)]
mod tests;
