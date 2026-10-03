//! Guest-root publication. Workloads see only the readonly sealed view.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
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

pub struct RuntimeCache {
    root: PathBuf,
    view: PathBuf,
    uid: u32,
    _lock: File,
    binding: RuntimeBinding,
}

impl RuntimeCache {
    pub fn initialize(
        binding: RuntimeBinding,
        bootstrap: &CwRuntimeCatalog,
        bootstrap_root: &Path,
        launcher: &Path,
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
            0,
        )
    }

    fn initialize_at(
        root: &Path,
        binding: RuntimeBinding,
        bootstrap: &CwRuntimeCatalog,
        bootstrap_root: &Path,
        launcher: &Path,
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
fn read_sealed_until(
    path: &Path,
    uid: u32,
    mode: u32,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
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
    let after = file.metadata()?;
    let live = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && [after, live]
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
    Ok(bytes)
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

pub async fn serve(cache: RuntimeCache) -> Result<()> {
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, LIVE_RUNTIME_VSOCK_PORT))?;
    let cache = Arc::new(Mutex::new(cache));
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
    let bytes = read_sealed(&executable, 0, 0o555, CW_RUNTIME_MAX_BYTES)?;
    member
        .validate_payload(&bytes)
        .map_err(anyhow::Error::msg)?;
    let error = std::process::Command::new(executable)
        .args(arguments)
        .exec();
    Err(error).context("execute selected workload runtime")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        bootstrap_root: PathBuf,
        launcher: PathBuf,
        binding: RuntimeBinding,
        bootstrap: CwRuntimeCatalog,
        a: CwRuntimeProvenance,
        b: CwRuntimeProvenance,
        b_bytes: Vec<u8>,
        cache: Option<RuntimeCache>,
    }
    impl Fixture {
        fn new() -> Self {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "kernel fixture requires isolated root identity"
            );
            // Keep executable-mode assertions on the same executable
            // filesystem as this admitted ci-profile test ELF. /tmp may be
            // deliberately noexec on the owner workstation.
            let executable = std::env::current_exe().unwrap();
            let directory = tempfile::Builder::new()
                .prefix("cw-runtime-kernel-")
                .tempdir_in(executable.parent().unwrap())
                .unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let (a_bytes, a_json) = crate::cw_runtime::fixture();
            let a = CwRuntimeProvenance::decode(&a_json).unwrap();
            let mut b_bytes = a_bytes.clone();
            b_bytes[135] = 1;
            let mut b = a.clone();
            b.payload.sha256 = digest_bytes(&b_bytes);
            b.payload.package_version = "0.1.1".into();
            b.image_index_sha256 = "e".repeat(64);
            let bootstrap = CwRuntimeCatalog {
                schema_version: 1,
                active_sha256: a.payload.sha256.clone(),
                runtimes: vec![a.clone()],
            };
            let binding = RuntimeBinding {
                environment_id: Uuid::new_v4(),
                generation: 1,
                bootstrap_catalog_sha256: digest_bytes(&bootstrap.encode().unwrap()),
            };
            let bootstrap_root = directory.path().join("bootstrap");
            create_directory(&bootstrap_root, 0, 0o700).unwrap();
            let member = bootstrap_root.join(&a.payload.sha256);
            create_directory(&member, 0, 0o700).unwrap();
            write_new(&member.join("cw"), &a_bytes, 0o555).unwrap();
            write_new(&member.join("provenance.json"), &a_json, 0o444).unwrap();
            fs::set_permissions(&member, fs::Permissions::from_mode(0o555)).unwrap();
            let launcher = directory.path().join("trusted-init-fixture");
            // This is the checked-in test ELF, never an incoming candidate.
            write_new(
                &launcher,
                &fs::read(std::env::current_exe().unwrap()).unwrap(),
                0o755,
            )
            .unwrap();
            let root = directory.path().join("cache");
            let cache = RuntimeCache::initialize_at(
                &root,
                binding.clone(),
                &bootstrap,
                &bootstrap_root,
                &launcher,
                0,
            )
            .unwrap();
            Self {
                _directory: directory,
                root,
                bootstrap_root,
                launcher,
                binding,
                bootstrap,
                a,
                b,
                b_bytes,
                cache: Some(cache),
            }
        }
        fn cache(&self) -> &RuntimeCache {
            self.cache.as_ref().unwrap()
        }
        fn request(&self, action: RuntimeAction) -> RuntimeRequest {
            RuntimeRequest {
                protocol_version: LIVE_RUNTIME_PROTOCOL,
                binding: self.binding.clone(),
                action,
            }
        }
        fn pack(&self) -> Vec<u8> {
            pack(&self.b, &self.b_bytes)
        }
        fn publish(&self, id: Uuid) -> RuntimeReply {
            let pack = self.pack();
            let request = self.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: pack.len() as u64,
                pack_sha256: digest_bytes(&pack),
                provenance: Box::new(self.b.clone()),
            });
            self.cache().publish(&request, &pack).unwrap()
        }
        fn select(&self, id: Uuid) -> RuntimeRequest {
            self.request(RuntimeAction::Select {
                operation_id: id,
                expected_revision: 1,
                target_sha256: self.b.payload.sha256.clone(),
            })
        }
        fn reopen(&mut self, generation: u64) {
            drop(self.cache.take());
            self.binding.generation = generation;
            self.cache = Some(
                RuntimeCache::initialize_at(
                    &self.root,
                    self.binding.clone(),
                    &self.bootstrap,
                    &self.bootstrap_root,
                    &self.launcher,
                    0,
                )
                .unwrap(),
            );
        }
    }
    fn pack(member: &CwRuntimeProvenance, bytes: &[u8]) -> Vec<u8> {
        let provenance = serde_json::to_vec(member).unwrap();
        let mut pack = b"CWRPACK1".to_vec();
        pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
        pack.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        pack.extend(provenance);
        pack.extend(bytes);
        pack
    }

    fn scenario(name: &str) {
        let mut fixture = Fixture::new();
        let id = Uuid::new_v4();
        match name {
            "receipt_capacity" => {
                let mut last = None;
                for _ in 0..LIVE_RUNTIME_MAX_OPERATIONS {
                    let request = fixture.request(RuntimeAction::Cancel {
                        operation_id: Uuid::new_v4(),
                        expected_revision: 1,
                        target_sha256: fixture.b.payload.sha256.clone(),
                    });
                    fixture.cache().control(&request).unwrap();
                    last = Some(request);
                }
                let before = fixture.cache().selection().unwrap();
                assert_eq!(before.operations.len(), LIVE_RUNTIME_MAX_OPERATIONS);
                let pack = fixture.pack();
                let publication = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: pack.len() as u64,
                    pack_sha256: digest_bytes(&pack),
                    provenance: Box::new(fixture.b.clone()),
                });
                assert_eq!(
                    fixture.cache().publish(&publication, &pack),
                    Err(RuntimeRefusal::Capacity)
                );
                assert_eq!(
                    fixture.cache().control(&fixture.select(id)),
                    Err(RuntimeRefusal::Capacity)
                );
                assert_eq!(fixture.cache().selection().unwrap(), before);
                assert!(
                    !fixture
                        .root
                        .join("view")
                        .join(&fixture.b.payload.sha256)
                        .exists()
                );
                // Retention pressure cannot erase/reclassify an existing
                // receipt, even after the publisher itself is re-created.
                fixture.reopen(1);
                assert_eq!(
                    fixture
                        .cache()
                        .control(last.as_ref().unwrap())
                        .unwrap()
                        .selection,
                    before
                );
            }
            "member_capacity" => {
                for index in 2..=CW_RUNTIME_MAX_VERSIONS as u8 {
                    let mut bytes = fixture.b_bytes.clone();
                    bytes[135] = index;
                    let mut member = fixture.b.clone();
                    member.payload.sha256 = digest_bytes(&bytes);
                    let pack = pack(&member, &bytes);
                    let request = fixture.request(RuntimeAction::Publish {
                        operation_id: Uuid::new_v4(),
                        pack_size: pack.len() as u64,
                        pack_sha256: digest_bytes(&pack),
                        provenance: Box::new(member),
                    });
                    fixture.cache().publish(&request, &pack).unwrap();
                }
                let before = fixture.cache().selection().unwrap();
                assert_eq!(before.catalog.runtimes.len(), CW_RUNTIME_MAX_VERSIONS);
                let pack = fixture.pack();
                let request = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: pack.len() as u64,
                    pack_sha256: digest_bytes(&pack),
                    provenance: Box::new(fixture.b.clone()),
                });
                assert_eq!(
                    fixture.cache().publish(&request, &pack),
                    Err(RuntimeRefusal::Capacity)
                );
                assert_eq!(fixture.cache().selection().unwrap(), before);
                assert!(
                    !fixture
                        .root
                        .join("view")
                        .join(&fixture.b.payload.sha256)
                        .exists()
                );
                fixture.reopen(1);
                assert_eq!(fixture.cache().selection().unwrap(), before);
            }
            "retention" => {
                let publication = fixture.publish(id);
                assert_eq!(publication.selection.revision, 1);
                assert_eq!(
                    publication.selection.catalog.active_sha256,
                    fixture.a.payload.sha256
                );
                assert!(
                    publication
                        .selection
                        .catalog
                        .runtime(&fixture.b.payload.sha256)
                        .is_some()
                );
                let selected = fixture.cache().control(&fixture.select(id)).unwrap();
                assert_eq!(selected.selection.revision, 2);
                assert_eq!(
                    selected.selection.previous_sha256,
                    Some(fixture.a.payload.sha256.clone())
                );
                assert_eq!(
                    fixture.cache().control(&fixture.select(id)).unwrap(),
                    selected
                );
                fixture.reopen(1);
                assert_eq!(fixture.cache().selection().unwrap(), selected.selection);
                for member in [&fixture.a, &fixture.b] {
                    let path = fixture
                        .root
                        .join("view")
                        .join(&member.payload.sha256)
                        .join("cw");
                    let metadata = fs::symlink_metadata(path).unwrap();
                    assert_eq!(metadata.uid(), 0);
                    assert_eq!(metadata.gid(), 0);
                    assert_eq!(metadata.nlink(), 1);
                    assert_eq!(metadata.mode() & 0o7777, 0o555);
                }
            }
            "stale" => {
                fixture.publish(id);
                let mut request = fixture.select(id);
                if let RuntimeAction::Select {
                    expected_revision, ..
                } = &mut request.action
                {
                    *expected_revision = 2;
                }
                assert_eq!(
                    fixture.cache().control(&request),
                    Err(RuntimeRefusal::StaleRevision)
                );
                assert_eq!(fixture.cache().selection().unwrap().revision, 1);
                assert_eq!(
                    fixture.cache().selection().unwrap().catalog.active_sha256,
                    fixture.a.payload.sha256
                );
            }
            "corrupt" => {
                let mut bytes = fixture.pack();
                let request = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: bytes.len() as u64,
                    pack_sha256: digest_bytes(&bytes),
                    provenance: Box::new(fixture.b.clone()),
                });
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                assert_eq!(
                    fixture.cache().publish(&request, &bytes),
                    Err(RuntimeRefusal::Invalid)
                );
                assert!(
                    !fixture
                        .root
                        .join("view")
                        .join(&fixture.b.payload.sha256)
                        .exists()
                );
                assert_eq!(fixture.cache().selection().unwrap().revision, 1);
            }
            "conflict" => {
                let (a_bytes, _) = crate::cw_runtime::fixture();
                let mut candidate = fixture.a.clone();
                candidate.image_index_sha256 = "e".repeat(64);
                let bytes = pack(&candidate, &a_bytes);
                let request = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: bytes.len() as u64,
                    pack_sha256: digest_bytes(&bytes),
                    provenance: Box::new(candidate),
                });
                assert_eq!(
                    fixture.cache().publish(&request, &bytes),
                    Err(RuntimeRefusal::Collision)
                );
                assert_eq!(
                    fixture.cache().selection().unwrap().catalog.runtimes,
                    vec![fixture.a.clone()]
                );
            }
            "cancel_before" => {
                let cancel = fixture.request(RuntimeAction::Cancel {
                    operation_id: id,
                    expected_revision: 1,
                    target_sha256: fixture.b.payload.sha256.clone(),
                });
                let receipt = fixture.cache().control(&cancel).unwrap();
                assert_eq!(
                    receipt.observed.unwrap().outcome,
                    SelectionOutcome::Cancelled
                );
                let bytes = fixture.pack();
                let publication = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: bytes.len() as u64,
                    pack_sha256: digest_bytes(&bytes),
                    provenance: Box::new(fixture.b.clone()),
                });
                assert_eq!(
                    fixture.cache().publish(&publication, &bytes),
                    Err(RuntimeRefusal::Cancelled)
                );
                assert_eq!(
                    fixture
                        .cache()
                        .control(&fixture.select(id))
                        .unwrap()
                        .observed
                        .unwrap()
                        .outcome,
                    SelectionOutcome::Cancelled
                );
                assert_eq!(
                    fixture.cache().selection().unwrap().catalog.active_sha256,
                    fixture.a.payload.sha256
                );
            }
            "cancel_after" => {
                fixture.publish(id);
                let selected = fixture.cache().control(&fixture.select(id)).unwrap();
                let cancel = fixture.request(RuntimeAction::Cancel {
                    operation_id: id,
                    expected_revision: 1,
                    target_sha256: fixture.b.payload.sha256.clone(),
                });
                assert_eq!(fixture.cache().control(&cancel).unwrap(), selected);
                assert_eq!(
                    selected.observed.unwrap().outcome,
                    SelectionOutcome::Committed
                );
            }
            "rollback" => {
                fixture.publish(id);
                fixture.cache().control(&fixture.select(id)).unwrap();
                let request = fixture.request(RuntimeAction::RetainedSelect {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 2,
                    target_sha256: fixture.a.payload.sha256.clone(),
                });
                let restored = fixture.cache().control(&request).unwrap();
                assert_eq!(restored.selection.revision, 3);
                assert_eq!(
                    restored.selection.catalog.active_sha256,
                    fixture.a.payload.sha256
                );
                assert_eq!(
                    restored.selection.previous_sha256,
                    Some(fixture.b.payload.sha256.clone())
                );
                assert_eq!(restored.selection.catalog.runtimes.len(), 2);
            }
            "birth" => {
                fixture.publish(id);
                let old = fixture.select(id);
                fixture.cache().control(&old).unwrap();
                fixture.reopen(2);
                assert_eq!(fixture.cache().control(&old), Err(RuntimeRefusal::Identity));
                let observed = fixture
                    .cache()
                    .control(&fixture.request(RuntimeAction::Observe { operation_id: id }))
                    .unwrap();
                assert_eq!(observed.binding.generation, 2);
                assert_eq!(observed.observed.unwrap().generation, 1);
                assert_eq!(observed.selection.revision, 2);
                let mut foreign = fixture.request(RuntimeAction::Info);
                foreign.binding.environment_id = Uuid::new_v4();
                assert_eq!(
                    fixture.cache().control(&foreign),
                    Err(RuntimeRefusal::Identity)
                );
            }
            "staging" => {
                let stage = fixture.root.join(format!("stage-{}", Uuid::new_v4()));
                create_directory(&stage, 0, 0o700).unwrap();
                write_new(&stage.join("cw"), b"incomplete", 0o600).unwrap();
                let selector = fixture.root.join(format!("selector-{}", Uuid::new_v4()));
                write_new(&selector, b"incomplete", 0o600).unwrap();
                fixture.reopen(1);
                assert!(!stage.exists());
                assert!(!selector.exists());
                assert_eq!(fixture.cache().selection().unwrap().revision, 1);
                let unowned = fixture.root.join("unexpected");
                write_new(&unowned, b"preserve", 0o600).unwrap();
                drop(fixture.cache.take());
                assert!(
                    RuntimeCache::initialize_at(
                        &fixture.root,
                        fixture.binding.clone(),
                        &fixture.bootstrap,
                        &fixture.bootstrap_root,
                        &fixture.launcher,
                        0
                    )
                    .is_err()
                );
                assert_eq!(fs::read(&unowned).unwrap(), b"preserve");
            }
            "links" => {
                let path = fixture
                    .root
                    .join("view")
                    .join(&fixture.a.payload.sha256)
                    .join("cw");
                let alias = fixture.root.join("external-link");
                fs::hard_link(&path, &alias).unwrap();
                assert!(fixture.cache().selection().is_err());
                fs::remove_file(&alias).unwrap();
                assert!(fixture.cache().selection().is_ok());
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(&fixture.launcher, &path).unwrap();
                assert!(fixture.cache().selection().is_err());
            }
            "readonly" => {
                let view = File::open(fixture.root.join("view")).unwrap();
                let fd = view.as_raw_fd();
                let mut child = Command::new("/bin/sh");
                child.env_clear().env("PATH","/usr/bin:/bin").args(["-c","test -r selection.json && test -x cw && ! touch forbidden && ! rm selection.json && ! mkdir forbidden-dir"])
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).uid(65534).gid(65534);
                unsafe {
                    child.pre_exec(move || {
                        if libc::fchdir(fd) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let status = child.status().unwrap();
                assert!(
                    status.success(),
                    "readonly workload permission probe exited {status}"
                );
                assert!(!fixture.root.join("view/forbidden").exists());
                fixture.publish(id);
                fixture.cache().control(&fixture.select(id)).unwrap();
                assert!(
                    fixture
                        .root
                        .join("view")
                        .join(&fixture.a.payload.sha256)
                        .join("cw")
                        .is_file()
                );
            }
            "readonly_mount" => {
                // This scenario always runs in a separate source-bound test
                // process. Isolate propagation before touching its own mount.
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_NEWNS) },
                    0,
                    "private mount namespace unavailable: {}",
                    std::io::Error::last_os_error()
                );
                let slash = std::ffi::CString::new("/").unwrap();
                assert_eq!(
                    unsafe {
                        libc::mount(
                            std::ptr::null(),
                            slash.as_ptr(),
                            std::ptr::null(),
                            libc::MS_REC | libc::MS_PRIVATE,
                            std::ptr::null(),
                        )
                    },
                    0
                );
                let source = fixture.root.join("view");
                let target = fixture.root.parent().unwrap().join("readonly-view");
                create_directory(&target, 0, 0o555).unwrap();
                let source_c =
                    std::ffi::CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
                let target_c =
                    std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(
                    unsafe {
                        libc::mount(
                            source_c.as_ptr(),
                            target_c.as_ptr(),
                            std::ptr::null(),
                            libc::MS_BIND,
                            std::ptr::null(),
                        )
                    },
                    0
                );
                struct OwnedMount(std::ffi::CString);
                impl Drop for OwnedMount {
                    fn drop(&mut self) {
                        assert_eq!(
                            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) },
                            0
                        );
                    }
                }
                let _mount = OwnedMount(target_c.clone());
                assert_eq!(
                    unsafe {
                        libc::mount(
                            std::ptr::null(),
                            target_c.as_ptr(),
                            std::ptr::null(),
                            libc::MS_BIND
                                | libc::MS_REMOUNT
                                | libc::MS_RDONLY
                                | libc::MS_NOSUID
                                | libc::MS_NODEV,
                            std::ptr::null(),
                        )
                    },
                    0
                );
                // Even root's DAC override cannot alter the workload mount.
                assert_eq!(
                    fs::write(target.join("forbidden"), b"no")
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS)
                );
                assert_eq!(
                    fs::remove_file(target.join(SELECTOR))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS)
                );
                let before = fs::read(target.join(&fixture.a.payload.sha256).join("cw")).unwrap();
                fixture.publish(id);
                fixture.cache().control(&fixture.select(id)).unwrap();
                let selected: RuntimeSelection =
                    serde_json::from_slice(&fs::read(target.join(SELECTOR)).unwrap()).unwrap();
                assert_eq!(selected.catalog.active_sha256, fixture.b.payload.sha256);
                assert_eq!(
                    fs::read(target.join(&fixture.a.payload.sha256).join("cw")).unwrap(),
                    before
                );
                assert!(target.join(&fixture.b.payload.sha256).join("cw").is_file());
            }
            "lost_reply" => {
                fixture.publish(id);
                let cache = Arc::new(Mutex::new(fixture.cache.take().unwrap()));
                let request = fixture.select(id);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let (mut client, server) = tokio::io::duplex(1024 * 1024);
                    client
                        .write_all(&encode_frame(&request).unwrap())
                        .await
                        .unwrap();
                    client.shutdown().await.unwrap();
                    drop(client);
                    // Commit still occurs even though the response receiver
                    // disappears. The error is an uncertain reply, not rollback.
                    assert!(
                        handle(
                            server,
                            cache.clone(),
                            Arc::new(tokio::sync::Semaphore::new(1)),
                            None
                        )
                        .await
                        .is_err()
                    );
                });
                let observed = cache
                    .lock()
                    .unwrap()
                    .control(&fixture.request(RuntimeAction::Observe { operation_id: id }))
                    .unwrap();
                assert_eq!(
                    observed.observed.unwrap().outcome,
                    SelectionOutcome::Committed
                );
                assert_eq!(observed.selection.revision, 2);
            }
            "truncated" => {
                let bytes = fixture.pack();
                let request = fixture.request(RuntimeAction::Publish {
                    operation_id: id,
                    pack_size: bytes.len() as u64,
                    pack_sha256: digest_bytes(&bytes),
                    provenance: Box::new(fixture.b.clone()),
                });
                let cache = Arc::new(Mutex::new(fixture.cache.take().unwrap()));
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let (mut client, server) = tokio::io::duplex(1024 * 1024);
                    client
                        .write_all(&encode_frame(&request).unwrap())
                        .await
                        .unwrap();
                    client.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
                    client.shutdown().await.unwrap();
                    assert!(
                        handle(
                            server,
                            cache.clone(),
                            Arc::new(tokio::sync::Semaphore::new(1)),
                            None
                        )
                        .await
                        .is_err()
                    );
                });
                assert_eq!(cache.lock().unwrap().selection().unwrap().revision, 1);
                assert!(
                    !fixture
                        .root
                        .join("view")
                        .join(&fixture.b.payload.sha256)
                        .exists()
                );
            }
            _ => panic!("closed kernel fixture scenario refused"),
        }
    }
    fn kernel(name: &str) {
        let executable = std::env::current_exe().unwrap();
        let mut child = if unsafe { libc::geteuid() } == 0 {
            let mut child = Command::new(&executable);
            child
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LC_ALL", "C")
                .env("CW_RUNTIME_KERNEL_SCENARIO", name);
            child
        } else {
            let mut child = Command::new("/usr/bin/sudo");
            child
                .args(["-n", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C"])
                .arg(format!("CW_RUNTIME_KERNEL_SCENARIO={name}"))
                .arg(&executable);
            child
        };
        let output = child
            .args([
                "--ignored",
                "--exact",
                "cw_runtime_publisher::tests::root_kernel_child",
                "--test-threads=1",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("isolated kernel fixture invocation");
        assert!(
            output.status.success(),
            "actual root kernel fixture {name} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"));
    }
    #[test]
    fn live_runtime_receipt_capacity_preserves_selection_and_observation() {
        kernel("receipt_capacity");
    }
    #[test]
    fn live_runtime_member_capacity_refuses_before_publication() {
        kernel("member_capacity");
    }
    #[test]
    fn live_runtime_retains_versions_and_exact_receipts() {
        kernel("retention");
    }
    #[test]
    fn live_runtime_stale_revision_cannot_change_default() {
        kernel("stale");
    }
    #[test]
    fn live_runtime_corrupt_candidate_never_publishes() {
        kernel("corrupt");
    }
    #[test]
    fn live_runtime_conflicting_provenance_preserves_old_bytes() {
        kernel("conflict");
    }
    #[test]
    fn live_runtime_cancel_before_commit_never_replays() {
        kernel("cancel_before");
    }
    #[test]
    fn live_runtime_cancel_after_commit_reports_effect() {
        kernel("cancel_after");
    }
    #[test]
    fn live_runtime_rollback_retains_both_versions() {
        kernel("rollback");
    }
    #[test]
    fn live_runtime_new_birth_observes_without_old_request_replay() {
        kernel("birth");
    }
    #[test]
    fn live_runtime_recovers_only_exact_owned_staging() {
        kernel("staging");
    }
    #[test]
    fn live_runtime_refuses_hardlinks_and_symlinks() {
        kernel("links");
    }
    #[test]
    fn live_runtime_workload_cannot_mutate_root_owned_view() {
        kernel("readonly");
    }
    #[test]
    fn live_runtime_readonly_mount_exposes_new_members_without_replacing_old_bytes() {
        kernel("readonly_mount");
    }
    #[test]
    fn live_runtime_lost_reply_keeps_observable_commit() {
        kernel("lost_reply");
    }
    #[test]
    fn live_runtime_partial_transfer_has_no_selection_effect() {
        kernel("truncated");
    }
    #[test]
    #[ignore = "invoked exactly by the source-bound isolated kernel fixture; not optional proof"]
    fn root_kernel_child() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let name = std::env::var("CW_RUNTIME_KERNEL_SCENARIO").expect("closed fixture selector");
        scenario(&name);
    }
}
