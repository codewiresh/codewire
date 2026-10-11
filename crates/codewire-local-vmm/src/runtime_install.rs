//! Installs the pinned local VM runtime (#2492).
//!
//! A release publishes one `codewire.cw.local-runtime/v1` document holding,
//! per host target, the exact [`ArtifactLock`] the supervisor admits. The
//! installer fetches each pinned file by digest into a private staging
//! directory with its exact mode, admits the staged set with the supervisor's
//! own artifact admission, swaps it into place and writes the lock last, so a
//! reader never pairs a new lock with old files. An identical installed
//! runtime is re-admitted and, if any file is damaged, fetched again. A
//! different installed runtime is replaced only on request.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use codewire_cw_release::sha256::Sha256;

use crate::artifact::{ArtifactError, ArtifactLock};

pub use codewire_cw_release::local_runtime::{
    BlobRef, CwRuntimeFiles, LOCAL_RUNTIME_NAME as LOCAL_RUNTIME_DOCUMENT, LOCAL_RUNTIME_SCHEMA,
    LocalRuntimeDocument, RuntimeTarget,
};
use codewire_cw_release::release::MAX_JSON_BYTES;

const BLOB_LIMIT: u64 = 512 * 1024 * 1024;
const EXECUTABLE_MODE: u32 = 0o500;
/// How long an installer waits for the runtime directory's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
const DATA_MODE: u32 = 0o400;

/// One previous runtime is kept beside the current one, so a rollback to it
/// (#2255 A-B-A) reinstalls from local files without downloading.
const PREVIOUS_ROOT: &str = ".runtime-previous";
const PREVIOUS_LOCK: &str = ".runtime-previous.lock.json";
const PREVIOUS_CW_RUNTIME: &str = ".cw-runtime-previous";

/// The sealed cw runtime file names `cw` admits beside the artifact lock.
pub const CW_RUNTIME_LOCK: &str = "cw-runtime.lock.json";
pub const CW_RUNTIME_PACK: &str = "runtime.pack";

/// This host's target key: `<os>-<arch>`, for example `macos-aarch64`.
pub fn host_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("the local runtime document is invalid: {0}")]
    Document(String),
    #[error("this release has no local VM runtime for {0}")]
    UnknownTarget(String),
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    #[error("a different local VM runtime is installed at {0}; rerun with --replace to replace it")]
    DifferentRuntimeInstalled(PathBuf),
    #[error("the artifact root {root} and lock {lock} must share one parent directory")]
    SplitPaths { root: PathBuf, lock: PathBuf },
    #[error("{path} must be a private directory owned by you, not a link")]
    UnsafeDirectory { path: PathBuf },
    #[error("blob {sha256} is missing from the runtime source")]
    MissingBlob { sha256: String },
    #[error("blob {sha256} has the wrong size or digest; it was not installed")]
    BlobMismatch { sha256: String },
    #[error("another local VM runtime install is running")]
    Busy,
}

fn io_error(context: impl Into<String>) -> impl FnOnce(io::Error) -> InstallError {
    let context = context.into();
    move |source| InstallError::Io { context, source }
}

/// This host's runtime in `document`.
pub fn host_runtime(document: &LocalRuntimeDocument) -> Result<&RuntimeTarget, InstallError> {
    let target = host_target();
    document
        .targets
        .get(&target)
        .ok_or(InstallError::UnknownTarget(target))
}

/// The validated lock for this host in `document`.
pub fn host_lock(document: &LocalRuntimeDocument) -> Result<ArtifactLock, InstallError> {
    let target = host_target();
    let value = &host_runtime(document)?.lock;
    let lock: ArtifactLock = serde_json::from_value(value.clone())
        .map_err(|error| InstallError::Document(format!("{target} lock: {error}")))?;
    lock.validate_metadata()?;
    Ok(lock)
}

/// Where release blobs come from. Blobs are named by their SHA-256.
pub trait BlobSource {
    fn open(&self, sha256: &str) -> Result<Box<dyn Read + '_>, InstallError>;
}

/// A directory holding `blobs/sha256/<hex>`, as a release publishes them.
pub struct DirectoryBlobSource {
    root: PathBuf,
}

impl DirectoryBlobSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Reads the directory's runtime document.
    pub fn document(&self) -> Result<LocalRuntimeDocument, InstallError> {
        let path = self.root.join(LOCAL_RUNTIME_DOCUMENT);
        let file = open_regular(&path)?;
        let mut bytes = Vec::new();
        file.take(MAX_JSON_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(format!("read {}", path.display())))?;
        LocalRuntimeDocument::decode(&bytes)
            .map_err(|error| InstallError::Document(error.to_string()))
    }
}

impl BlobSource for DirectoryBlobSource {
    fn open(&self, sha256: &str) -> Result<Box<dyn Read + '_>, InstallError> {
        let path = self.root.join("blobs").join("sha256").join(sha256);
        match open_regular(&path) {
            Ok(file) => Ok(Box::new(file)),
            Err(InstallError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Err(InstallError::MissingBlob {
                    sha256: sha256.to_owned(),
                })
            }
            Err(error) => Err(error),
        }
    }
}

fn open_regular(path: &Path) -> Result<File, InstallError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error(format!("open {}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(io_error(format!("inspect {}", path.display())))?;
    if !metadata.is_file() {
        return Err(InstallError::Document(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// The installed runtime's paths, as `cw` resolves them.
#[derive(Debug, Clone)]
pub struct RuntimePaths {
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Fetched, admitted and published.
    Installed { generation: String },
    /// The same runtime was already installed and admitted intact.
    AlreadyInstalled { generation: String },
}

/// How the installed runtime compares with `document`'s for this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledRuntime {
    Missing,
    Same,
    /// This runtime's files, partly missing or damaged.
    Incomplete,
    Different,
}

/// Compares the installed artifact lock with `document`'s for this host. It
/// reads only the lock; [`install`] admits the files themselves.
pub fn installed_runtime(
    paths: &RuntimePaths,
    document: &LocalRuntimeDocument,
) -> Result<InstalledRuntime, InstallError> {
    let wanted = host_lock(document)?;
    let artifacts = match ArtifactLock::read(&paths.artifact_lock) {
        Ok(installed) if installed == wanted => InstalledRuntime::Same,
        Ok(_) => InstalledRuntime::Different,
        Err(_) if lock_missing(&paths.artifact_lock) => InstalledRuntime::Missing,
        Err(error) => return Err(error.into()),
    };
    if artifacts != InstalledRuntime::Same {
        return Ok(artifacts);
    }
    // Compare the cw runtime by its small lock and the pack's size: a start
    // never hashes the whole pack, which install admits in full.
    let parent = paths.artifact_lock.parent().unwrap_or(Path::new("/"));
    let wanted = host_runtime(document)?.cw_runtime.as_ref();
    let lock = file_digest(&parent.join(CW_RUNTIME_LOCK))?;
    Ok(match wanted {
        None if lock.is_none() => InstalledRuntime::Same,
        None => InstalledRuntime::Different,
        Some(_) if lock.is_none() => InstalledRuntime::Incomplete,
        Some(wanted) if !matches(&lock, &wanted.lock) => InstalledRuntime::Different,
        Some(wanted) => match fs::symlink_metadata(parent.join(CW_RUNTIME_PACK)) {
            Ok(metadata) if metadata.is_file() && metadata.len() == wanted.pack.size => {
                InstalledRuntime::Same
            }
            _ => InstalledRuntime::Incomplete,
        },
    })
}

/// The runtime files already on this host, current and previous, by digest.
/// Every file is checked against its digest again when it is installed.
pub struct LocalBlobs {
    files: BTreeMap<String, PathBuf>,
}

impl LocalBlobs {
    pub fn open(paths: &RuntimePaths) -> Result<Self, InstallError> {
        let mut files = BTreeMap::new();
        let parent = paths.artifact_lock.parent().unwrap_or(Path::new("/"));
        for (root, lock) in [
            (paths.artifact_root.clone(), paths.artifact_lock.clone()),
            (parent.join(PREVIOUS_ROOT), parent.join(PREVIOUS_LOCK)),
        ] {
            let Ok(lock) = ArtifactLock::read(&lock) else {
                continue;
            };
            let mut specs = lock.executables();
            specs.extend(lock.data_files());
            for spec in specs {
                files
                    .entry(spec.sha256.clone())
                    .or_insert_with(|| root.join(&spec.path));
            }
        }
        for directory in [parent.to_path_buf(), parent.join(PREVIOUS_CW_RUNTIME)] {
            for name in [CW_RUNTIME_LOCK, CW_RUNTIME_PACK] {
                let path = directory.join(name);
                if let Some((sha256, _)) = file_digest(&path)? {
                    files.entry(sha256).or_insert(path);
                }
            }
        }
        Ok(Self { files })
    }

    /// No local files: every blob comes from the fallback.
    pub fn empty() -> Self {
        Self {
            files: BTreeMap::new(),
        }
    }

    pub fn has(&self, sha256: &str) -> bool {
        self.files.contains_key(sha256)
    }
}

impl BlobSource for LocalBlobs {
    fn open(&self, sha256: &str) -> Result<Box<dyn Read + '_>, InstallError> {
        let path = self
            .files
            .get(sha256)
            .ok_or_else(|| InstallError::MissingBlob {
                sha256: sha256.to_owned(),
            })?;
        match open_regular(path) {
            Ok(file) => Ok(Box::new(file)),
            // A file a lock still names but that is gone (deleted, or a crash
            // between swapping a root and writing its lock) is simply absent.
            Err(InstallError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Err(InstallError::MissingBlob {
                    sha256: sha256.to_owned(),
                })
            }
            Err(error) => Err(error),
        }
    }
}

/// Local files first, then `fallback` for whatever this host lacks.
pub struct WithLocal<'a> {
    pub local: &'a LocalBlobs,
    pub fallback: &'a dyn BlobSource,
}

impl BlobSource for WithLocal<'_> {
    fn open(&self, sha256: &str) -> Result<Box<dyn Read + '_>, InstallError> {
        if self.local.has(sha256) {
            self.local.open(sha256)
        } else {
            self.fallback.open(sha256)
        }
    }
}

/// Installs `document`'s runtime for this host from `source`.
pub async fn install(
    paths: &RuntimePaths,
    document: &LocalRuntimeDocument,
    source: &dyn BlobSource,
    replace: bool,
) -> Result<InstallOutcome, InstallError> {
    install_with(paths, document, source, replace, |lock, root| async move {
        lock.admit(&root).await.map(|_| ())
    })
    .await
}

/// [`install`] with the admission step supplied, so tests can run the
/// install protocol without a real VM helper.
pub(crate) async fn install_with<A, F>(
    paths: &RuntimePaths,
    document: &LocalRuntimeDocument,
    source: &dyn BlobSource,
    replace: bool,
    admit: A,
) -> Result<InstallOutcome, InstallError>
where
    A: Fn(ArtifactLock, PathBuf) -> F,
    F: Future<Output = Result<(), ArtifactError>>,
{
    let lock = host_lock(document)?;
    let parent = paths
        .artifact_lock
        .parent()
        .filter(|parent| paths.artifact_root.parent() == Some(*parent))
        .ok_or_else(|| InstallError::SplitPaths {
            root: paths.artifact_root.clone(),
            lock: paths.artifact_lock.clone(),
        })?
        .to_path_buf();
    ensure_private_directory(&parent)?;
    let _guard = InstallGuard::acquire(&parent)?;
    let generation = lock.generation()?;

    let installed_lock = ArtifactLock::read(&paths.artifact_lock);
    // Repairing the installed runtime keeps the real previous one.
    let keep_previous = matches!(&installed_lock, Ok(existing) if *existing != lock);
    let artifacts_current = match installed_lock {
        // The same runtime is re-admitted; a damaged file is fetched again.
        Ok(existing) if existing == lock => admit(lock.clone(), paths.artifact_root.clone())
            .await
            .is_ok(),
        Ok(_) if !replace => {
            return Err(InstallError::DifferentRuntimeInstalled(
                paths.artifact_lock.clone(),
            ));
        }
        // An unreadable lock is never overwritten unless replacing.
        Err(error) if !replace && !lock_missing(&paths.artifact_lock) => {
            return Err(error.into());
        }
        _ => false,
    };
    let wanted_cw_runtime = host_runtime(document)?.cw_runtime.as_ref();
    let cw_runtime = cw_runtime_state(&parent, wanted_cw_runtime)?;
    if cw_runtime == CwRuntimeState::Different && !replace {
        return Err(InstallError::DifferentRuntimeInstalled(
            parent.join(CW_RUNTIME_LOCK),
        ));
    }
    if artifacts_current && cw_runtime == CwRuntimeState::Current {
        return Ok(InstallOutcome::AlreadyInstalled { generation });
    }

    if !artifacts_current {
        let stage = Workspace::create(&parent, "runtime-stage")?;
        let mut specs = lock.executables();
        let executables = specs.len();
        specs.extend(lock.data_files());
        for (index, spec) in specs.into_iter().enumerate() {
            let mode = if index < executables {
                EXECUTABLE_MODE
            } else {
                DATA_MODE
            };
            fetch(
                source,
                &spec.sha256,
                spec.size,
                &stage.path.join(&spec.path),
                mode,
            )?;
        }
        admit(lock.clone(), stage.path.clone()).await?;
        publish(paths, &parent, stage, &lock, keep_previous)?;
        admit(lock, paths.artifact_root.clone()).await?;
    }
    if cw_runtime != CwRuntimeState::Current {
        install_cw_runtime(&parent, source, wanted_cw_runtime)?;
    }
    Ok(InstallOutcome::Installed { generation })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CwRuntimeState {
    /// Installed exactly as wanted, or absent and not wanted.
    Current,
    /// Wanted and absent, or the wanted runtime with a damaged pack.
    Repairable,
    /// Another runtime is installed, or one is installed but not wanted.
    Different,
}

fn file_digest(path: &Path) -> Result<Option<(String, u64)>, InstallError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(format!("open {}", path.display()))(error)),
    };
    let mut digest = Sha256::new();
    let size =
        io::copy(&mut file, &mut digest).map_err(io_error(format!("read {}", path.display())))?;
    Ok(Some((format!("{:x}", digest.finalize()), size)))
}

fn matches(found: &Option<(String, u64)>, wanted: &BlobRef) -> bool {
    found
        .as_ref()
        .is_some_and(|(sha256, size)| *sha256 == wanted.sha256 && *size == wanted.size)
}

fn cw_runtime_state(
    parent: &Path,
    wanted: Option<&CwRuntimeFiles>,
) -> Result<CwRuntimeState, InstallError> {
    let lock = file_digest(&parent.join(CW_RUNTIME_LOCK))?;
    Ok(match (wanted, &lock) {
        (None, None) => CwRuntimeState::Current,
        (None, Some(_)) => CwRuntimeState::Different,
        (Some(_), None) => CwRuntimeState::Repairable,
        (Some(wanted), Some(_)) if !matches(&lock, &wanted.lock) => CwRuntimeState::Different,
        (Some(wanted), Some(_)) => {
            if matches(&file_digest(&parent.join(CW_RUNTIME_PACK))?, &wanted.pack) {
                CwRuntimeState::Current
            } else {
                CwRuntimeState::Repairable
            }
        }
    })
}

/// Writes the pack, then its lock, which commits the runtime cw admits; or
/// removes both when the release has none.
fn install_cw_runtime(
    parent: &Path,
    source: &dyn BlobSource,
    wanted: Option<&CwRuntimeFiles>,
) -> Result<(), InstallError> {
    let lock = parent.join(CW_RUNTIME_LOCK);
    let pack = parent.join(CW_RUNTIME_PACK);
    let Some(wanted) = wanted else {
        keep_previous_cw_runtime(parent, None)?;
        for path in [&lock, &pack] {
            remove_file_if_present(path)?;
        }
        return Ok(());
    };
    // Fetch first: the source may read the kept previous runtime, which the
    // rotation below replaces.
    let files = [
        (CW_RUNTIME_PACK, &wanted.pack),
        (CW_RUNTIME_LOCK, &wanted.lock),
    ];
    for (name, blob) in files {
        let partial = parent.join(format!(".{name}.partial"));
        let _ = fs::remove_file(&partial);
        if let Err(error) = fetch(source, &blob.sha256, blob.size, &partial, DATA_MODE) {
            for (name, _) in files {
                let _ = fs::remove_file(parent.join(format!(".{name}.partial")));
            }
            return Err(error);
        }
    }
    keep_previous_cw_runtime(parent, Some(wanted))?;
    for (name, _) in files {
        fs::rename(parent.join(format!(".{name}.partial")), parent.join(name))
            .map_err(io_error(format!("install {}", parent.join(name).display())))?;
    }
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Keeps an installed cw runtime other than `wanted` as the previous one,
/// replacing any older one, so a rollback reinstalls it without a download.
fn keep_previous_cw_runtime(
    parent: &Path,
    wanted: Option<&CwRuntimeFiles>,
) -> Result<(), InstallError> {
    let installed = file_digest(&parent.join(CW_RUNTIME_LOCK))?;
    if installed.is_none() || wanted.is_some_and(|wanted| matches(&installed, &wanted.lock)) {
        return Ok(());
    }
    let previous = parent.join(PREVIOUS_CW_RUNTIME);
    remove_tree(&previous)?;
    fs::create_dir(&previous).map_err(io_error(format!("create {}", previous.display())))?;
    fs::set_permissions(&previous, fs::Permissions::from_mode(0o700))
        .map_err(io_error(format!("protect {}", previous.display())))?;
    for name in [CW_RUNTIME_PACK, CW_RUNTIME_LOCK] {
        match fs::rename(parent.join(name), previous.join(name)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(io_error(format!("keep the previous {name}"))(error));
            }
            _ => {}
        }
    }
    Ok(())
}

fn lock_missing(lock: &Path) -> bool {
    matches!(fs::symlink_metadata(lock), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

fn ensure_private_directory(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(io_error(format!("create {}", path.display())))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(io_error(format!("protect {}", path.display())))?;
        }
        Err(error) => return Err(io_error(format!("inspect {}", path.display()))(error)),
        Ok(_) => {}
    }
    let metadata =
        fs::symlink_metadata(path).map_err(io_error(format!("inspect {}", path.display())))?;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(InstallError::UnsafeDirectory {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// One installer at a time per runtime directory.
struct InstallGuard {
    _file: File,
}

impl InstallGuard {
    fn acquire(parent: &Path) -> Result<Self, InstallError> {
        let path = parent.join(".runtime-install.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(io_error(format!("open {}", path.display())))?;
        use std::os::fd::AsRawFd;
        // A process forked while an earlier installer held the lock keeps
        // that open file until it execs; wait briefly before reporting a
        // concurrent install.
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            // SAFETY: flock takes an owned open descriptor and a flag.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
                || std::time::Instant::now() >= deadline
            {
                return Err(InstallError::Busy);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

/// A private sibling directory removed unless it is published.
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create(parent: &Path, prefix: &str) -> Result<Self, InstallError> {
        let path = parent.join(format!(".{prefix}-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).map_err(io_error(format!("create {}", path.display())))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(io_error(format!("protect {}", path.display())))?;
        Ok(Self { path })
    }

    fn keep(mut self) -> PathBuf {
        std::mem::take(&mut self.path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Copies one blob into `destination`, refusing any size or digest mismatch.
fn fetch(
    source: &dyn BlobSource,
    sha256: &str,
    size: u64,
    destination: &Path,
    mode: u32,
) -> Result<(), InstallError> {
    let mismatch = || InstallError::BlobMismatch {
        sha256: sha256.to_owned(),
    };
    if size > BLOB_LIMIT {
        return Err(mismatch());
    }
    let mut reader = source.open(sha256)?.take(size + 1);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)
        .map_err(io_error(format!("create {}", destination.display())))?;
    let mut digest = Sha256::new();
    let mut written = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(io_error(format!("read blob {sha256}")))?;
        if read == 0 {
            break;
        }
        written += read as u64;
        if written > size {
            return Err(mismatch());
        }
        digest.update(&buffer[..read]);
        file.write_all(&buffer[..read])
            .map_err(io_error(format!("write {}", destination.display())))?;
    }
    if written != size || format!("{:x}", digest.finalize()) != sha256 {
        return Err(mismatch());
    }
    file.sync_all()
        .map_err(io_error(format!("sync {}", destination.display())))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))
        .map_err(io_error(format!("protect {}", destination.display())))
}

/// Swaps the staged files into place, then writes the lock last.
fn publish(
    paths: &RuntimePaths,
    parent: &Path,
    stage: Workspace,
    lock: &ArtifactLock,
    keep_previous: bool,
) -> Result<(), InstallError> {
    // A replaced runtime becomes the previous one, replacing any older one
    // kept beside it. A repaired copy of the same runtime is discarded.
    let previous = if keep_previous {
        let previous = parent.join(PREVIOUS_ROOT);
        remove_tree(&previous)?;
        remove_file_if_present(&parent.join(PREVIOUS_LOCK))?;
        previous
    } else {
        parent.join(format!(".runtime-replaced-{:016x}", rand::random::<u64>()))
    };
    let had_previous = match fs::symlink_metadata(&paths.artifact_root) {
        Ok(_) => {
            fs::rename(&paths.artifact_root, &previous).map_err(io_error(format!(
                "move aside {}",
                paths.artifact_root.display()
            )))?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(io_error(format!(
                "inspect {}",
                paths.artifact_root.display()
            ))(error));
        }
    };
    let staged = stage.keep();
    if let Err(error) = fs::rename(&staged, &paths.artifact_root) {
        if had_previous {
            let _ = fs::rename(&previous, &paths.artifact_root);
        }
        let _ = fs::remove_dir_all(&staged);
        return Err(io_error(format!(
            "install {}",
            paths.artifact_root.display()
        ))(error));
    }

    let lock_name = paths
        .artifact_lock
        .file_name()
        .ok_or_else(|| InstallError::SplitPaths {
            root: paths.artifact_root.clone(),
            lock: paths.artifact_lock.clone(),
        })?;
    let partial = parent.join(format!(".{}.partial", lock_name.to_string_lossy()));
    let _ = fs::remove_file(&partial);
    if had_previous && keep_previous {
        match fs::rename(&paths.artifact_lock, parent.join(PREVIOUS_LOCK)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(io_error(format!(
                    "keep the previous {}",
                    paths.artifact_lock.display()
                ))(error));
            }
            _ => {}
        }
    }
    let mut bytes = serde_json::to_vec_pretty(lock).map_err(ArtifactError::EncodeLock)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&partial)
        .map_err(io_error(format!("create {}", partial.display())))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(io_error(format!("write {}", partial.display())))?;
    fs::set_permissions(&partial, fs::Permissions::from_mode(DATA_MODE))
        .map_err(io_error(format!("protect {}", partial.display())))?;
    fs::rename(&partial, &paths.artifact_lock).map_err(io_error(format!(
        "install {}",
        paths.artifact_lock.display()
    )))?;
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    if had_previous && !keep_previous {
        let _ = remove_tree(&previous);
    }
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(io_error(format!("remove {}", path.display()))(error))
        }
        _ => Ok(()),
    }
}

/// Removes a kept runtime directory, whose files are read-only.
fn remove_tree(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(format!("inspect {}", path.display()))(error)),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(InstallError::UnsafeDirectory {
                path: path.to_path_buf(),
            });
        }
        Ok(_) => {}
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    fs::remove_dir_all(path).map_err(io_error(format!("remove {}", path.display())))
}

#[cfg(test)]
mod tests;
