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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::{ArtifactError, ArtifactLock};

pub const LOCAL_RUNTIME_SCHEMA: &str = "codewire.cw.local-runtime/v1";
/// The document's name inside a release or `--from` directory.
pub const LOCAL_RUNTIME_DOCUMENT: &str = "local-runtime.json";
const DOCUMENT_LIMIT: u64 = 1024 * 1024;
const BLOB_LIMIT: u64 = 512 * 1024 * 1024;
const EXECUTABLE_MODE: u32 = 0o500;
/// How long an installer waits for the runtime directory's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
const DATA_MODE: u32 = 0o400;

/// One release's local VM runtime for every supported host target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimeDocument {
    pub schema: String,
    /// The source revision the guest root and cw were built from; the guest
    /// renders session environments, so they must match.
    pub source_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    /// Each target's runtime, keyed by [`host_target`].
    pub targets: BTreeMap<String, RuntimeTarget>,
}

/// One host target's runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTarget {
    /// The exact artifact lock the supervisor admits.
    pub lock: serde_json::Value,
    /// The sealed cw runtime for managed agents in local VMs, when published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cw_runtime: Option<CwRuntimeFiles>,
}

/// The sealed cw runtime's two files, installed beside the artifact lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeFiles {
    pub lock: BlobRef,
    pub pack: BlobRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub sha256: String,
    pub size: u64,
}

/// The cw runtime file names `cw` admits beside the artifact lock.
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

impl LocalRuntimeDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self, InstallError> {
        let document: Self = serde_json::from_slice(bytes)
            .map_err(|error| InstallError::Document(error.to_string()))?;
        if document.schema != LOCAL_RUNTIME_SCHEMA {
            return Err(InstallError::Document(format!(
                "schema {:?} is not {LOCAL_RUNTIME_SCHEMA}",
                document.schema
            )));
        }
        if document.source_revision.len() != 40
            || !document
                .source_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InstallError::Document(
                "source_revision must be a 40-character commit".into(),
            ));
        }
        Ok(document)
    }

    /// This host's runtime.
    pub fn host_target(&self) -> Result<&RuntimeTarget, InstallError> {
        let target = host_target();
        self.targets
            .get(&target)
            .ok_or(InstallError::UnknownTarget(target))
    }

    /// The validated lock for this host.
    pub fn host_lock(&self) -> Result<ArtifactLock, InstallError> {
        let target = host_target();
        let value = &self.host_target()?.lock;
        let lock: ArtifactLock = serde_json::from_value(value.clone())
            .map_err(|error| InstallError::Document(format!("{target} lock: {error}")))?;
        lock.validate_metadata()?;
        Ok(lock)
    }
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
        file.take(DOCUMENT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(format!("read {}", path.display())))?;
        if bytes.len() as u64 > DOCUMENT_LIMIT {
            return Err(InstallError::Document("the document is too large".into()));
        }
        LocalRuntimeDocument::parse(&bytes)
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
    let lock = document.host_lock()?;
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

    let artifacts_current = match ArtifactLock::read(&paths.artifact_lock) {
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
    let wanted_cw_runtime = document.host_target()?.cw_runtime.as_ref();
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
        specs.extend([&lock.kernel, &lock.initramfs]);
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
        publish(paths, &parent, stage, &lock)?;
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
        for path in [&lock, &pack] {
            match fs::remove_file(path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(io_error(format!("remove {}", path.display()))(error));
                }
                _ => {}
            }
        }
        return Ok(());
    };
    for (name, blob) in [
        (CW_RUNTIME_PACK, &wanted.pack),
        (CW_RUNTIME_LOCK, &wanted.lock),
    ] {
        let partial = parent.join(format!(".{name}.partial"));
        let _ = fs::remove_file(&partial);
        if let Err(error) = fetch(source, &blob.sha256, blob.size, &partial, DATA_MODE) {
            let _ = fs::remove_file(&partial);
            return Err(error);
        }
        fs::rename(&partial, parent.join(name))
            .map_err(io_error(format!("install {}", parent.join(name).display())))?;
    }
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
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
) -> Result<(), InstallError> {
    let previous = parent.join(format!(".runtime-previous-{:016x}", rand::random::<u64>()));
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
    if had_previous {
        let _ = fs::set_permissions(&previous, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&previous);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
