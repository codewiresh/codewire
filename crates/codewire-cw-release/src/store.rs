//! Ordinary-user immutable `cw` version store and generation-fenced selector.
//!
//! ```text
//! <root>/store.json                    0444  managed entry and platform
//! <root>/lock                          0600  advisory store lock
//! <root>/selection.json                0644  generation, current, previous, pending intent
//! <root>/versions/<sha256>/            0555
//! <root>/versions/<sha256>/cw          0555  regular file with one link
//! <root>/versions/<sha256>/identity.json 0444
//! <root>/versions/.staging-<operation>/      incomplete publication
//! ```
//!
//! The managed entry, normally `~/.local/bin/cw`, is a symbolic link to exactly
//! `<root>/versions/<sha256>/cw`. Selecting another version atomically renames
//! a new link over the entry. A running process keeps its executable, and
//! because its canonical path names an immutable version directory, a command
//! line it saved keeps naming those bytes. Versions are never removed here.
//!
//! Every mutation holds the entry lock (shared by all stores selecting that
//! entry) before the exclusive store lock and first recovers an
//! interrupted operation by observing the actual entry, never by trusting the
//! recorded intent alone. The owner can still write this store directly; it is
//! not an OS-enforced immutable boundary and never a trusted managed helper.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::sha256::Sha256;
use rustix::fs::{
    self as rfs, Access, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags,
};
use serde::{Deserialize, Serialize};

use crate::identity::{
    CwPayloadIdentity, EXECUTABLE_HEADER_BYTES, IdentityError, MAX_EXECUTABLE_BYTES,
    MAX_IDENTITY_BYTES, MIN_EXECUTABLE_BYTES, PROTOCOL_VERSION, Platform, RECORD_VERSION,
    canonical_json, is_sha256_hex, valid_package_version,
};

pub const STORE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

const MANIFEST: &str = "store.json";
const LOCK: &str = "lock";
const SELECTION: &str = "selection.json";
const SELECTION_TEMP_PREFIX: &str = "selection.json.tmp-";
const VERSIONS: &str = "versions";
const EXECUTABLE: &str = "cw";
const RECORD: &str = "identity.json";
const STAGING_PREFIX: &str = ".staging-";
const MAX_STATE_BYTES: usize = 16 * 1024;
const MAX_VERSIONS: usize = 1024;
const LOCK_POLL: Duration = Duration::from_millis(20);
const COPY_BUFFER: usize = 64 * 1024;
const ENTRY_LOCK_SUFFIX: &str = ".cw-update.lock";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("releases do not support this host platform")]
    UnsupportedHost,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("{path} is not a cw version store")]
    NotAStore { path: PathBuf },
    #[error("{path} is unsafe for a cw store: {reason}")]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error(
        "{path} is an unmanaged {kind}; cw will not replace or rename it because running \
         processes and saved commands may still use that path"
    )]
    UnmanagedEntry { path: PathBuf, kind: &'static str },
    #[error("{path} is not writable by this user")]
    NotWritable { path: PathBuf },
    #[error("store {store} manages {recorded}, not {requested}")]
    EntryMismatch {
        store: PathBuf,
        recorded: PathBuf,
        requested: PathBuf,
    },
    #[error("managed entry {path} changed outside cw (found {observed}); refusing to change it")]
    ExternallyChanged { path: PathBuf, observed: String },
    #[error("candidate executable does not match its admission: {0}")]
    CandidateMismatch(&'static str),
    #[error("stored cw version {sha256} is corrupt or substituted: {reason}")]
    CorruptVersion {
        sha256: String,
        reason: &'static str,
    },
    #[error("cw version {0} is not in the store")]
    UnknownVersion(String),
    #[error("version selector {0} matches more than one stored version")]
    AmbiguousVersion(String),
    #[error("no previous cw version is recorded")]
    NoPreviousVersion,
    #[error("selection generation is {actual}, not the expected {expected}")]
    GenerationMismatch { expected: u64, actual: u64 },
    #[error("timed out after {0:?} waiting for the cw store lock")]
    LockTimeout(Duration),
    #[error("cw for {found} cannot run on this {host} host")]
    PlatformMismatch { found: String, host: &'static str },
    #[error(
        "cw version uses protocol {protocol} and record format {record}; this cw supports \
         protocol {PROTOCOL_VERSION} and record format {RECORD_VERSION}"
    )]
    IncompatibleVersion { protocol: u32, record: u32 },
    #[error("store state {path} is malformed")]
    MalformedState { path: PathBuf },
    #[cfg(test)]
    #[error("injected interruption at {0:?}")]
    InjectedFault(Fault),
}

type Result<T, E = StoreError> = std::result::Result<T, E>;

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

fn rustix_error(path: &Path) -> impl FnOnce(rustix::io::Errno) -> StoreError + '_ {
    move |errno| StoreError::Io {
        path: path.to_owned(),
        source: errno.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Bytes admitted by an explicit digest pin and their schema-2 identity.
    PinnedRelease,
    /// A running cw importing its own bytes.
    SelfInstall,
}

/// Recorded identity of one stored version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRecord {
    pub schema_version: u32,
    pub origin: Origin,
    pub platform: String,
    pub package_version: String,
    pub protocol_version: u32,
    pub record_version: u32,
    pub sha256: String,
    pub size: u64,
    pub payload: Option<CwPayloadIdentity>,
}

impl VersionRecord {
    fn validate(&self, host: Platform) -> Result<()> {
        let consistent = self.schema_version == STORE_SCHEMA_VERSION
            && valid_package_version(&self.package_version)
            && is_sha256_hex(&self.sha256)
            && (MIN_EXECUTABLE_BYTES..=MAX_EXECUTABLE_BYTES).contains(&self.size);
        if !consistent {
            return Err(IdentityError::Unsupported("version record").into());
        }
        if Platform::parse(&self.platform) != Some(host) {
            return Err(StoreError::PlatformMismatch {
                found: self.platform.clone(),
                host: host.as_str(),
            });
        }
        if self.protocol_version != PROTOCOL_VERSION || self.record_version != RECORD_VERSION {
            return Err(StoreError::IncompatibleVersion {
                protocol: self.protocol_version,
                record: self.record_version,
            });
        }
        match (self.origin, &self.payload) {
            (Origin::SelfInstall, None) => Ok(()),
            (Origin::PinnedRelease, Some(payload)) => {
                let target = payload.validate()?;
                let matches = target.platform() == host
                    && payload.package_version == self.package_version
                    && payload.protocol_version == self.protocol_version
                    && payload.record_version == self.record_version
                    && payload.sha256 == self.sha256
                    && payload.size == self.size;
                if matches {
                    Ok(())
                } else {
                    Err(IdentityError::Unsupported("version record payload").into())
                }
            }
            _ => Err(IdentityError::Unsupported("version record origin").into()),
        }
    }
}

/// What admits candidate bytes into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Explicitly pinned release bytes. The pin must equal the identity digest.
    Pinned {
        identity: CwPayloadIdentity,
        sha256: String,
    },
    /// The running cw importing its own bytes, with this build's protocol and
    /// record versions.
    SelfInstall { package_version: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub executable: PathBuf,
    pub admission: Admission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreManifest {
    schema_version: u32,
    entry: PathBuf,
    platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub schema_version: u32,
    pub generation: u64,
    pub current: Option<String>,
    pub previous: Option<String>,
    pub pending: Option<PendingSelection>,
}

/// Intent recorded before the managed entry moves. Recovery resolves it from
/// the observed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSelection {
    pub operation: String,
    pub generation: u64,
    pub from: Option<String>,
    pub to: String,
}

impl Selection {
    fn empty() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            generation: 0,
            current: None,
            previous: None,
            pending: None,
        }
    }

    fn valid(&self) -> bool {
        let digest = |value: &Option<String>| value.as_deref().is_none_or(is_sha256_hex);
        self.schema_version == STORE_SCHEMA_VERSION
            && digest(&self.current)
            && digest(&self.previous)
            && (self.generation == 0) == self.current.is_none()
            && (self.previous.is_none() || self.previous != self.current)
            && self.pending.as_ref().is_none_or(|pending| {
                pending.generation == self.generation
                    && pending.from == self.current
                    && is_sha256_hex(&pending.to)
                    && Some(&pending.to) != pending.from.as_ref()
                    && uuid::Uuid::parse_str(&pending.operation)
                        .is_ok_and(|id| id.hyphenated().to_string() == pending.operation)
            })
    }
}

/// Observed state of the managed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum EntryState {
    Absent,
    Managed { sha256: String },
    ForeignLink { target: PathBuf },
    Unmanaged { kind: &'static str },
}

impl EntryState {
    fn describe(&self) -> String {
        match self {
            Self::Absent => "no entry".into(),
            Self::Managed { sha256 } => format!("managed version {sha256}"),
            Self::ForeignLink { target } => format!("a link to {}", target.display()),
            Self::Unmanaged { kind } => format!("an unmanaged {kind}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Published {
    pub sha256: String,
    pub created: bool,
    pub record: VersionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selected {
    pub generation: u64,
    pub current: String,
    pub previous: Option<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Recovery {
    /// No interrupted selection was recorded.
    Clean,
    /// The entry already named the intended version; the selection now does.
    Completed { generation: u64, current: String },
    /// The entry still named the prior version; the intent was discarded.
    Abandoned { generation: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionSummary {
    pub sha256: String,
    pub package_version: Option<String>,
    pub origin: Option<Origin>,
    pub size: Option<u64>,
    /// False when the recorded identity could not be read or validated.
    pub recorded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub root: PathBuf,
    pub entry: PathBuf,
    pub platform: &'static str,
    pub generation: u64,
    pub current: Option<String>,
    pub previous: Option<String>,
    pub pending: Option<PendingSelection>,
    pub entry_state: EntryState,
    /// True when the entry matches the recorded selection and nothing is pending.
    pub consistent: bool,
    pub versions: Vec<VersionSummary>,
}

#[derive(Debug)]
pub struct Installed {
    pub store: Store,
    pub created_store: bool,
    pub published: Published,
    pub selected: Selected,
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Staged,
    IntentWritten,
    SwapLinkCreated,
    EntrySwapped,
}

#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    entry: PathBuf,
    platform: Platform,
    lock_timeout: Duration,
    #[cfg(test)]
    pub(crate) fault: Option<Fault>,
    #[cfg(test)]
    before_entry_commit: Option<fn(&Path)>,
    #[cfg(test)]
    after_entry_check: Option<fn(&Path)>,
}

struct StoreLock {
    _file: File,
}

/// A stable lock beside the entry coordinates different stores. The parent
/// descriptor pins the directory used for the actual symlink publication.
struct EntryLock {
    _lock: StoreLock,
    directory: File,
    path: PathBuf,
    lock_path: PathBuf,
}

struct MutationLocks {
    entry: EntryLock,
    _store: StoreLock,
}

struct EntryObservation {
    state: EntryState,
    metadata: Option<rfs::Stat>,
}

impl EntryObservation {
    fn matches(&self, other: &Self) -> bool {
        self.state == other.state
            && match (&self.metadata, &other.metadata) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.st_dev == b.st_dev
                        && a.st_ino == b.st_ino
                        && a.st_mode == b.st_mode
                        && a.st_uid == b.st_uid
                        && a.st_nlink == b.st_nlink
                }
                _ => false,
            }
    }
}

impl EntryLock {
    fn acquire(entry: &Path, timeout: Duration) -> Result<Self> {
        let path = canonical_entry(entry)?;
        let parent = path.parent().expect("canonical entry has a parent");
        require_writable(parent)?;
        let directory = open_directory(parent)?;
        require_directory_identity(parent, &directory)?;
        let mut name = OsString::from(".");
        name.push(path.file_name().expect("entry has a name"));
        name.push(ENTRY_LOCK_SUFFIX);
        let lock_path = parent.join(&name);
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd = match rfs::openat(
            &directory,
            &name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                rfs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(rustix_error(&lock_path))?;
                rfs::fsync(&directory).map_err(rustix_error(parent))?;
                fd
            }
            Err(rustix::io::Errno::EXIST) => rfs::openat(&directory, &name, flags, Mode::empty())
                .map_err(rustix_error(&lock_path))?,
            Err(errno) => return Err(rustix_error(&lock_path)(errno)),
        };
        let lock = lock_file(&lock_path, File::from(fd), true, timeout)?;
        let held = Self {
            _lock: lock,
            directory,
            path,
            lock_path,
        };
        held.validate()?;
        Ok(held)
    }

    fn validate(&self) -> Result<()> {
        let parent = self.path.parent().expect("entry has a parent");
        check_private_dir(parent)?;
        require_directory_identity(parent, &self.directory)?;
        validate_lock(&self.lock_path, &self._lock._file)?;
        require_writable(parent)
    }

    fn observe(&self, root: Option<&Path>) -> Result<EntryObservation> {
        self.validate()?;
        let name = self.path.file_name().expect("entry has a name");
        let metadata = match rfs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => {
                return Ok(EntryObservation {
                    state: EntryState::Absent,
                    metadata: None,
                });
            }
            Err(errno) => return Err(rustix_error(&self.path)(errno)),
        };
        let kind = FileType::from_raw_mode(metadata.st_mode);
        let state = if kind == FileType::Symlink {
            let mut buffer = vec![0; MAX_STATE_BYTES];
            let length = rfs::readlinkat_raw(&self.directory, name, &mut buffer[..])
                .map_err(rustix_error(&self.path))?;
            if length == buffer.len() {
                return Err(StoreError::Unsafe {
                    path: self.path.clone(),
                    reason: "entry link exceeds its bound",
                });
            }
            buffer.truncate(length);
            classify_link(PathBuf::from(OsString::from_vec(buffer)), root)
        } else {
            EntryState::Unmanaged {
                kind: if kind == FileType::RegularFile {
                    "regular file"
                } else if kind == FileType::Directory {
                    "directory"
                } else {
                    "special file"
                },
            }
        };
        if matches!(state, EntryState::Managed { .. })
            && (metadata.st_uid != euid() || metadata.st_nlink != 1)
        {
            return Err(StoreError::Unsafe {
                path: self.path.clone(),
                reason: "managed entry owner or link count changed",
            });
        }
        let after = rfs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(rustix_error(&self.path))?;
        let observed = EntryObservation {
            state,
            metadata: Some(metadata),
        };
        let rechecked = EntryObservation {
            state: observed.state.clone(),
            metadata: Some(after),
        };
        if !observed.matches(&rechecked) {
            return Err(StoreError::ExternallyChanged {
                path: self.path.clone(),
                observed: "entry changed while it was observed".into(),
            });
        }
        self.validate()?;
        Ok(observed)
    }

    fn require_observation(&self, root: &Path, expected: &EntryObservation) -> Result<()> {
        let observed = self.observe(Some(root))?;
        if expected.matches(&observed) {
            Ok(())
        } else {
            Err(StoreError::ExternallyChanged {
                path: self.path.clone(),
                observed: observed.state.describe(),
            })
        }
    }
}

impl Store {
    /// The store containing `executable` when it is a managed version path.
    pub fn locate(executable: &Path) -> Option<PathBuf> {
        if executable.file_name()? != EXECUTABLE {
            return None;
        }
        let version = executable.parent()?;
        if !is_sha256_hex(version.file_name()?.to_str()?) {
            return None;
        }
        let versions = version.parent()?;
        if versions.file_name()? != VERSIONS {
            return None;
        }
        let root = versions.parent()?;
        fs::symlink_metadata(root.join(MANIFEST))
            .is_ok_and(|metadata| metadata.is_file())
            .then(|| root.to_owned())
    }

    /// Open an existing store, checking its ownership, modes and manifest.
    pub fn open(root: &Path, lock_timeout: Duration) -> Result<Self> {
        let platform = Platform::host().ok_or(StoreError::UnsupportedHost)?;
        let root = fs::canonicalize(root).map_err(io_error(root))?;
        check_private_dir(&root)?;
        let manifest_path = root.join(MANIFEST);
        let bytes = match read_owned_file(&manifest_path, MAX_STATE_BYTES, Some(0o444)) {
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotAStore { path: root });
            }
            other => other?,
        };
        let manifest: StoreManifest =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::MalformedState {
                path: manifest_path.clone(),
            })?;
        if manifest.schema_version != STORE_SCHEMA_VERSION
            || !manifest.entry.is_absolute()
            || manifest.entry.file_name().is_none()
        {
            return Err(StoreError::MalformedState {
                path: manifest_path,
            });
        }
        if Platform::parse(&manifest.platform) != Some(platform) {
            return Err(StoreError::PlatformMismatch {
                found: manifest.platform,
                host: platform.as_str(),
            });
        }
        check_private_dir(&root.join(VERSIONS))?;
        Ok(Self {
            root,
            entry: manifest.entry,
            platform,
            lock_timeout,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            before_entry_commit: None,
            #[cfg(test)]
            after_entry_check: None,
        })
    }

    /// Create an empty store for an absent managed entry. The store appears
    /// atomically; a concurrent creator wins and this call reports it.
    pub fn create(root: &Path, entry: &Path, lock_timeout: Duration) -> Result<Self> {
        let entry = canonical_entry(entry)?;
        match observe_entry_at(&entry, None)? {
            EntryState::Absent => {}
            state => return Err(entry_refusal(&entry, state)),
        }
        let held = EntryLock::acquire(&entry, lock_timeout)?;
        Self::create_locked(root, &entry, lock_timeout, &held)
    }

    fn create_locked(
        root: &Path,
        entry: &Path,
        lock_timeout: Duration,
        held: &EntryLock,
    ) -> Result<Self> {
        let platform = Platform::host().ok_or(StoreError::UnsupportedHost)?;
        held.validate()?;
        match held.observe(None)?.state {
            EntryState::Absent => {}
            state => return Err(entry_refusal(entry, state)),
        }
        let name = root
            .file_name()
            .ok_or_else(|| StoreError::Unsafe {
                path: root.to_owned(),
                reason: "store path has no final component",
            })?
            .to_owned();
        if !root.is_absolute() {
            return Err(StoreError::Unsafe {
                path: root.to_owned(),
                reason: "store path must be absolute",
            });
        }
        let parent = root.parent().expect("absolute store path has a parent");
        fs::create_dir_all(parent).map_err(io_error(parent))?;
        let parent = fs::canonicalize(parent).map_err(io_error(parent))?;
        require_writable(&parent)?;
        let root = parent.join(&name);

        let mut staging_name = OsString::from(".");
        staging_name.push(&name);
        staging_name.push(format!(".creating-{}", uuid::Uuid::new_v4()));
        let staging = parent.join(staging_name);
        let built = (|| {
            create_dir(&staging, 0o755)?;
            create_dir(&staging.join(VERSIONS), 0o755)?;
            let manifest = StoreManifest {
                schema_version: STORE_SCHEMA_VERSION,
                entry: entry.to_owned(),
                platform: platform.as_str().into(),
            };
            let manifest = canonical_json(&manifest)?;
            write_new_file(&staging.join(MANIFEST), &manifest, 0o444)?;
            write_new_file(
                &staging.join(SELECTION),
                &canonical_json(&Selection::empty())?,
                0o644,
            )?;
            write_new_file(&staging.join(LOCK), b"", 0o600)?;
            sync_dir(&staging)
        })();
        if let Err(error) = built {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        match rfs::renameat_with(rfs::CWD, &staging, rfs::CWD, &root, RenameFlags::NOREPLACE) {
            Ok(()) => sync_dir(&parent)?,
            Err(errno) => {
                let _ = fs::remove_dir_all(&staging);
                if errno == rustix::io::Errno::EXIST || errno == rustix::io::Errno::NOTEMPTY {
                    let store = Self::open(&root, lock_timeout)?;
                    store.require_entry(entry)?;
                    return Ok(store);
                }
                return Err(rustix_error(&root)(errno));
            }
        }
        Self::open(&root, lock_timeout)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn entry(&self) -> &Path {
        &self.entry
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn version_executable(&self, sha256: &str) -> PathBuf {
        self.root.join(VERSIONS).join(sha256).join(EXECUTABLE)
    }

    /// Refuse a store recorded for another managed entry.
    pub fn require_entry(&self, entry: &Path) -> Result<()> {
        let requested = canonical_entry(entry)?;
        if requested != self.entry {
            return Err(StoreError::EntryMismatch {
                store: self.root.clone(),
                recorded: self.entry.clone(),
                requested,
            });
        }
        Ok(())
    }

    /// Read-only status under a shared lock. It reports, but never resolves,
    /// an interrupted selection.
    pub fn status(&self) -> Result<Status> {
        let _lock = self.lock(false)?;
        let selection = self.read_selection()?;
        let entry_state = self.observe_entry()?;
        let consistent =
            selection.pending.is_none() && self.entry_matches(&selection, &entry_state);
        let mut versions = Vec::new();
        for sha256 in self.version_names()? {
            let summary = match self.read_record(&sha256) {
                Ok(record) => VersionSummary {
                    sha256,
                    package_version: Some(record.package_version),
                    origin: Some(record.origin),
                    size: Some(record.size),
                    recorded: true,
                },
                Err(_) => VersionSummary {
                    sha256,
                    package_version: None,
                    origin: None,
                    size: None,
                    recorded: false,
                },
            };
            versions.push(summary);
        }
        Ok(Status {
            root: self.root.clone(),
            entry: self.entry.clone(),
            platform: self.platform.as_str(),
            generation: selection.generation,
            current: selection.current,
            previous: selection.previous,
            pending: selection.pending,
            entry_state,
            consistent,
            versions,
        })
    }

    /// Resolve an interrupted operation from the observed entry.
    pub fn recover(&self) -> Result<Recovery> {
        let locks = self.mutation_locks()?;
        self.recover_locked(&locks.entry)
    }

    /// Admit candidate bytes as an immutable version without changing the
    /// selection. Republishing identical bytes is accepted.
    pub fn publish(&self, candidate: &Candidate) -> Result<Published> {
        let locks = self.mutation_locks()?;
        self.recover_locked(&locks.entry)?;
        self.publish_locked(candidate)
    }

    /// Make a stored version the default for new invocations.
    pub fn select(&self, sha256: &str, expected_generation: Option<u64>) -> Result<Selected> {
        let locks = self.mutation_locks()?;
        self.recover_locked(&locks.entry)?;
        self.select_locked(sha256, expected_generation, &locks.entry)
    }

    /// Publish candidate bytes and select them in one locked operation.
    pub fn publish_and_select(
        &self,
        candidate: &Candidate,
        expected_generation: Option<u64>,
    ) -> Result<(Published, Selected)> {
        let locks = self.mutation_locks()?;
        self.publish_and_select_locked(candidate, expected_generation, &locks.entry)
    }

    fn publish_and_select_locked(
        &self,
        candidate: &Candidate,
        expected_generation: Option<u64>,
        entry: &EntryLock,
    ) -> Result<(Published, Selected)> {
        self.recover_locked(entry)?;
        if let Some(expected) = expected_generation {
            let actual = self.read_selection()?.generation;
            if actual != expected {
                return Err(StoreError::GenerationMismatch { expected, actual });
            }
        }
        let published = self.publish_locked(candidate)?;
        let selected = self.select_locked(&published.sha256, expected_generation, entry)?;
        Ok((published, selected))
    }

    /// Select the previous version, or an explicit stored version given as a
    /// full digest, a unique digest prefix of at least 8 characters, or a
    /// unique package version.
    pub fn rollback(&self, to: Option<&str>, expected_generation: Option<u64>) -> Result<Selected> {
        let locks = self.mutation_locks()?;
        self.recover_locked(&locks.entry)?;
        let target = match to {
            Some(selector) => self.resolve_version(selector)?,
            None => self
                .read_selection()?
                .previous
                .ok_or(StoreError::NoPreviousVersion)?,
        };
        self.select_locked(&target, expected_generation, &locks.entry)
    }

    /// Fully re-verify one stored version, including its executable digest.
    pub fn verify(&self, sha256: &str) -> Result<VersionRecord> {
        let _lock = self.lock(false)?;
        self.verify_version(sha256)
    }

    fn lock(&self, exclusive: bool) -> Result<StoreLock> {
        let path = self.root.join(LOCK);
        let fd = rfs::open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_error(&path))?;
        lock_file(&path, File::from(fd), exclusive, self.lock_timeout)
    }

    fn mutation_locks(&self) -> Result<MutationLocks> {
        let entry = EntryLock::acquire(&self.entry, self.lock_timeout)?;
        let store = self.lock(true)?;
        self.require_mutable(&entry)?;
        Ok(MutationLocks {
            entry,
            _store: store,
        })
    }

    fn require_mutable(&self, entry: &EntryLock) -> Result<()> {
        entry.validate()?;
        for directory in [&self.root, &self.root.join(VERSIONS)] {
            check_private_dir(directory)?;
            require_writable(directory)?;
        }
        Ok(())
    }

    fn fault(&self, at: Fault) -> Result<()> {
        #[cfg(test)]
        if self.fault == Some(at) {
            return Err(StoreError::InjectedFault(at));
        }
        let _ = at;
        Ok(())
    }

    fn recover_locked(&self, entry: &EntryLock) -> Result<Recovery> {
        self.remove_stale_staging()?;
        self.remove_stale_selection_temps()?;
        let selection = self.read_selection()?;
        let Some(pending) = selection.pending.clone() else {
            let observed = entry.observe(Some(&self.root))?;
            self.require_entry_state(&selection, &observed.state)?;
            return Ok(Recovery::Clean);
        };
        let observed = entry.observe(Some(&self.root))?;
        let completed =
            matches!(&observed.state, EntryState::Managed { sha256 } if *sha256 == pending.to);
        let abandoned = match &observed.state {
            EntryState::Managed { sha256 } => pending.from.as_ref() == Some(sha256),
            EntryState::Absent => pending.from.is_none(),
            _ => false,
        };
        if completed {
            self.verify_version(&pending.to)?;
            entry.require_observation(&self.root, &observed)?;
            self.remove_swap_link(&pending.operation, &pending.to, entry)?;
            let generation = next_generation(pending.generation)?;
            self.write_selection(&Selection {
                schema_version: STORE_SCHEMA_VERSION,
                generation,
                current: Some(pending.to.clone()),
                previous: pending.from,
                pending: None,
            })?;
            Ok(Recovery::Completed {
                generation,
                current: pending.to,
            })
        } else if abandoned {
            if let Some(from) = &pending.from {
                self.verify_version(from)?;
            }
            entry.require_observation(&self.root, &observed)?;
            self.remove_swap_link(&pending.operation, &pending.to, entry)?;
            self.write_selection(&Selection {
                pending: None,
                ..selection
            })?;
            Ok(Recovery::Abandoned {
                generation: pending.generation,
            })
        } else {
            Err(StoreError::ExternallyChanged {
                path: self.entry.clone(),
                observed: observed.state.describe(),
            })
        }
    }

    fn publish_locked(&self, candidate: &Candidate) -> Result<Published> {
        let pinned = match &candidate.admission {
            Admission::Pinned { identity, sha256 } => {
                let target = identity.validate()?;
                if !is_sha256_hex(sha256) {
                    return Err(StoreError::CandidateMismatch("pin is not a SHA-256 digest"));
                }
                if identity.sha256 != *sha256 {
                    return Err(StoreError::CandidateMismatch(
                        "identity digest differs from the pin",
                    ));
                }
                if target.platform() != self.platform {
                    return Err(StoreError::PlatformMismatch {
                        found: identity.target.clone(),
                        host: self.platform.as_str(),
                    });
                }
                Some((sha256.as_str(), identity.size))
            }
            Admission::SelfInstall { package_version } => {
                if !valid_package_version(package_version) {
                    return Err(IdentityError::Unsupported("package_version").into());
                }
                None
            }
        };
        if let Some((sha256, _)) = pinned
            && self.version_exists(sha256)?
        {
            let record = self.verify_version(sha256)?;
            return Ok(Published {
                sha256: sha256.to_owned(),
                created: false,
                record,
            });
        }

        let count = self.version_names()?.len();
        if pinned.is_some() && count == MAX_VERSIONS {
            return Err(self.version_limit());
        }

        let versions = self.root.join(VERSIONS);
        let staging = versions.join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4()));
        create_dir(&staging, 0o700)?;
        let record = match self.stage(&staging, candidate, pinned) {
            Ok(record) => record,
            Err(error) => {
                remove_staging(&staging)?;
                return Err(error);
            }
        };
        // A self-install learns its digest only after staging. At capacity it
        // may reuse an already admitted version, but cannot publish a new one.
        if self.version_exists(&record.sha256)? {
            remove_staging(&staging)?;
            let existing = self.verify_version(&record.sha256)?;
            return Ok(Published {
                sha256: record.sha256,
                created: false,
                record: existing,
            });
        }
        if count == MAX_VERSIONS {
            remove_staging(&staging)?;
            return Err(self.version_limit());
        }
        self.fault(Fault::Staged)?;
        let target = versions.join(&record.sha256);
        match rfs::renameat_with(
            rfs::CWD,
            &staging,
            rfs::CWD,
            &target,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                sync_dir(&versions)?;
                Ok(Published {
                    sha256: record.sha256.clone(),
                    created: true,
                    record,
                })
            }
            Err(errno)
                if errno == rustix::io::Errno::EXIST || errno == rustix::io::Errno::NOTEMPTY =>
            {
                remove_staging(&staging)?;
                let existing = self.verify_version(&record.sha256)?;
                Ok(Published {
                    sha256: record.sha256,
                    created: false,
                    record: existing,
                })
            }
            Err(errno) => {
                remove_staging(&staging)?;
                Err(rustix_error(&target)(errno))
            }
        }
    }

    fn stage(
        &self,
        staging: &Path,
        candidate: &Candidate,
        pinned: Option<(&str, u64)>,
    ) -> Result<VersionRecord> {
        let source_path = &candidate.executable;
        let running_linux_image = cfg!(target_os = "linux")
            && matches!(candidate.admission, Admission::SelfInstall { .. })
            && source_path == Path::new("/proc/self/exe");
        let flags = OFlags::RDONLY
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC
            | if running_linux_image {
                OFlags::empty()
            } else {
                OFlags::NOFOLLOW
            };
        let fd = rfs::open(source_path, flags, Mode::empty()).map_err(rustix_error(source_path))?;
        let mut source = File::from(fd);
        let metadata = source.metadata().map_err(io_error(source_path))?;
        if !metadata.is_file() {
            return Err(StoreError::CandidateMismatch(
                "executable is not a regular file",
            ));
        }
        if metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(StoreError::CandidateMismatch(
                "executable exceeds its size bound",
            ));
        }
        let executable = staging.join(EXECUTABLE);
        let mut output = create_new_file(&executable, 0o600)?;
        let mut hasher = Sha256::new();
        let mut header = Vec::with_capacity(EXECUTABLE_HEADER_BYTES);
        let mut buffer = vec![0_u8; COPY_BUFFER];
        let mut total = 0_u64;
        loop {
            let read = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(source_path)(error)),
            };
            total += read as u64;
            if total > MAX_EXECUTABLE_BYTES {
                return Err(StoreError::CandidateMismatch(
                    "executable exceeds its size bound",
                ));
            }
            let chunk = &buffer[..read];
            let wanted = EXECUTABLE_HEADER_BYTES
                .saturating_sub(header.len())
                .min(read);
            header.extend_from_slice(&chunk[..wanted]);
            hasher.update(chunk);
            output.write_all(chunk).map_err(io_error(&executable))?;
        }
        if total < MIN_EXECUTABLE_BYTES {
            return Err(StoreError::CandidateMismatch("executable is too small"));
        }
        let after = source.metadata().map_err(io_error(source_path))?;
        if !same_file_metadata(&metadata, &after) || total != metadata.len() {
            return Err(StoreError::CandidateMismatch(
                "executable changed while it was copied",
            ));
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if let Some((pin, size)) = pinned {
            if total != size {
                return Err(StoreError::CandidateMismatch(
                    "size differs from the pinned identity",
                ));
            }
            if sha256 != pin {
                return Err(StoreError::CandidateMismatch("digest differs from the pin"));
            }
        }
        self.platform.validate_executable_header(&header)?;
        output.sync_all().map_err(io_error(&executable))?;
        rfs::fchmod(&output, Mode::from_raw_mode(0o555)).map_err(rustix_error(&executable))?;
        drop(output);

        let record = match &candidate.admission {
            Admission::Pinned { identity, .. } => VersionRecord {
                schema_version: STORE_SCHEMA_VERSION,
                origin: Origin::PinnedRelease,
                platform: self.platform.as_str().into(),
                package_version: identity.package_version.clone(),
                protocol_version: identity.protocol_version,
                record_version: identity.record_version,
                sha256,
                size: total,
                payload: Some(identity.clone()),
            },
            Admission::SelfInstall { package_version } => VersionRecord {
                schema_version: STORE_SCHEMA_VERSION,
                origin: Origin::SelfInstall,
                platform: self.platform.as_str().into(),
                package_version: package_version.clone(),
                protocol_version: PROTOCOL_VERSION,
                record_version: RECORD_VERSION,
                sha256,
                size: total,
                payload: None,
            },
        };
        record.validate(self.platform)?;
        write_new_file(&staging.join(RECORD), &canonical_json(&record)?, 0o444)?;
        set_mode(staging, 0o555)?;
        sync_dir(staging)?;
        Ok(record)
    }

    fn select_locked(
        &self,
        sha256: &str,
        expected_generation: Option<u64>,
        entry: &EntryLock,
    ) -> Result<Selected> {
        let selection = self.read_selection()?;
        if let Some(expected) = expected_generation
            && expected != selection.generation
        {
            return Err(StoreError::GenerationMismatch {
                expected,
                actual: selection.generation,
            });
        }
        self.verify_version(sha256)?;
        if selection.current.as_deref() == Some(sha256) {
            return Ok(Selected {
                generation: selection.generation,
                current: sha256.to_owned(),
                previous: selection.previous,
                changed: false,
            });
        }
        let observed = entry.observe(Some(&self.root))?;
        self.require_entry_state(&selection, &observed.state)?;
        let generation = next_generation(selection.generation)?;

        let operation = uuid::Uuid::new_v4().hyphenated().to_string();
        self.write_selection(&Selection {
            pending: Some(PendingSelection {
                operation: operation.clone(),
                generation: selection.generation,
                from: selection.current.clone(),
                to: sha256.to_owned(),
            }),
            ..selection.clone()
        })?;
        self.fault(Fault::IntentWritten)?;
        let swap = self.swap_link(&operation);
        let swap_name = swap.file_name().expect("swap link has a name");
        rfs::symlinkat(self.version_executable(sha256), &entry.directory, swap_name)
            .map_err(rustix_error(&swap))?;
        self.fault(Fault::SwapLinkCreated)?;
        #[cfg(test)]
        if let Some(hook) = self.before_entry_commit {
            hook(&self.entry);
        }
        // Recheck the exact observed link under the shared entry lock. This
        // coordinates all cw updaters; it is not a CAS against arbitrary
        // direct writes by the same UID to this owner-writable directory.
        entry.require_observation(&self.root, &observed)?;
        #[cfg(test)]
        if let Some(hook) = self.after_entry_check {
            hook(&self.entry);
        }
        let flags = if matches!(observed.state, EntryState::Absent) {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        rfs::renameat_with(
            &entry.directory,
            swap_name,
            &entry.directory,
            self.entry.file_name().expect("entry has a name"),
            flags,
        )
        .map_err(rustix_error(&self.entry))?;
        rfs::fsync(&entry.directory).map_err(rustix_error(
            self.entry.parent().expect("entry has a parent"),
        ))?;
        self.fault(Fault::EntrySwapped)?;
        self.write_selection(&Selection {
            schema_version: STORE_SCHEMA_VERSION,
            generation,
            current: Some(sha256.to_owned()),
            previous: selection.current.clone(),
            pending: None,
        })?;
        Ok(Selected {
            generation,
            current: sha256.to_owned(),
            previous: selection.current,
            changed: true,
        })
    }

    fn version_limit(&self) -> StoreError {
        StoreError::Unsafe {
            path: self.root.join(VERSIONS),
            reason: "too many stored versions",
        }
    }

    fn resolve_version(&self, selector: &str) -> Result<String> {
        if is_sha256_hex(selector) {
            return if self.version_exists(selector)? {
                Ok(selector.to_owned())
            } else {
                Err(StoreError::UnknownVersion(selector.to_owned()))
            };
        }
        let prefix = selector.len() >= 8
            && selector
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let mut matches = Vec::new();
        for sha256 in self.version_names()? {
            let selected = if prefix {
                sha256.starts_with(selector)
            } else {
                self.read_record(&sha256)
                    .is_ok_and(|record| record.package_version == selector)
            };
            if selected {
                matches.push(sha256);
            }
        }
        match matches.len() {
            0 => Err(StoreError::UnknownVersion(selector.to_owned())),
            1 => Ok(matches.remove(0)),
            _ => Err(StoreError::AmbiguousVersion(selector.to_owned())),
        }
    }

    fn version_exists(&self, sha256: &str) -> Result<bool> {
        let path = self.root.join(VERSIONS).join(sha256);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(&path)(error)),
        }
    }

    fn version_names(&self) -> Result<Vec<String>> {
        let versions = self.root.join(VERSIONS);
        let mut names = Vec::new();
        for entry in fs::read_dir(&versions).map_err(io_error(&versions))? {
            let entry = entry.map_err(io_error(&versions))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(StoreError::Unsafe {
                    path: entry.path(),
                    reason: "unexpected entry in versions",
                });
            };
            if name.starts_with(STAGING_PREFIX) {
                continue;
            }
            if !is_sha256_hex(name) {
                return Err(StoreError::Unsafe {
                    path: entry.path(),
                    reason: "unexpected entry in versions",
                });
            }
            if names.len() == MAX_VERSIONS {
                return Err(StoreError::Unsafe {
                    path: versions,
                    reason: "too many stored versions",
                });
            }
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn read_record(&self, sha256: &str) -> Result<VersionRecord> {
        let directory_path = self.root.join(VERSIONS).join(sha256);
        let directory = open_directory(&directory_path)?;
        let metadata = directory.metadata().map_err(io_error(&directory_path))?;
        if metadata.uid() != euid() || metadata.mode() & 0o7777 != 0o555 {
            return Err(StoreError::CorruptVersion {
                sha256: sha256.to_owned(),
                reason: "version directory owner or mode changed",
            });
        }
        let path = directory_path.join(RECORD);
        let fd = rfs::openat(
            &directory,
            RECORD,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_error(&path))?;
        let bytes = read_owned_descriptor(&path, File::from(fd), MAX_IDENTITY_BYTES, Some(0o444))?;
        require_directory_identity(&directory_path, &directory)?;
        let record: VersionRecord = serde_json::from_slice(&bytes)
            .map_err(|_| StoreError::MalformedState { path: path.clone() })?;
        record.validate(self.platform)?;
        if record.sha256 != sha256 {
            return Err(StoreError::MalformedState { path });
        }
        Ok(record)
    }

    /// Structural and digest verification of one stored version. The bytes are
    /// read, never executed.
    fn verify_version(&self, sha256: &str) -> Result<VersionRecord> {
        if !is_sha256_hex(sha256) {
            return Err(StoreError::UnknownVersion(sha256.to_owned()));
        }
        let corrupt = |reason| StoreError::CorruptVersion {
            sha256: sha256.to_owned(),
            reason,
        };
        let directory = self.root.join(VERSIONS).join(sha256);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::UnknownVersion(sha256.to_owned()));
            }
            Err(error) => return Err(io_error(&directory)(error)),
        };
        if !metadata.is_dir() || metadata.uid() != euid() || metadata.mode() & 0o7777 != 0o555 {
            return Err(corrupt("version directory type, owner or mode changed"));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&directory).map_err(io_error(&directory))? {
            names.push(entry.map_err(io_error(&directory))?.file_name());
            if names.len() > 2 {
                break;
            }
        }
        names.sort();
        if names != [OsString::from(EXECUTABLE), OsString::from(RECORD)] {
            return Err(corrupt("version directory membership changed"));
        }
        let record = self
            .read_record(sha256)
            .map_err(|_| corrupt("version identity is missing or invalid"))?;

        let path = directory.join(EXECUTABLE);
        let fd = rfs::open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| corrupt("executable is missing or not a regular file"))?;
        let mut file = File::from(fd);
        let before = file.metadata().map_err(io_error(&path))?;
        if !before.is_file()
            || before.uid() != euid()
            || before.mode() & 0o7777 != 0o555
            || before.nlink() != 1
            || before.len() != record.size
        {
            return Err(corrupt(
                "executable type, owner, mode, link count or size changed",
            ));
        }
        let mut hasher = Sha256::new();
        let mut header = Vec::with_capacity(EXECUTABLE_HEADER_BYTES);
        let mut buffer = vec![0_u8; COPY_BUFFER];
        let mut total = 0_u64;
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(&path)(error)),
            };
            total += read as u64;
            if total > record.size {
                return Err(corrupt("executable grew while it was verified"));
            }
            let wanted = EXECUTABLE_HEADER_BYTES
                .saturating_sub(header.len())
                .min(read);
            header.extend_from_slice(&buffer[..wanted]);
            hasher.update(&buffer[..read]);
        }
        let after = file.metadata().map_err(io_error(&path))?;
        if total != record.size || !same_file_metadata(&before, &after) {
            return Err(corrupt("executable changed while it was verified"));
        }
        if format!("{:x}", hasher.finalize()) != sha256 {
            return Err(corrupt("executable digest changed"));
        }
        self.platform
            .validate_executable_header(&header)
            .map_err(|_| corrupt("executable format does not match this host"))?;
        Ok(record)
    }

    fn observe_entry(&self) -> Result<EntryState> {
        observe_entry_at(&self.entry, Some(&self.root))
    }

    fn entry_matches(&self, selection: &Selection, observed: &EntryState) -> bool {
        match (observed, &selection.current) {
            (EntryState::Absent, None) => true,
            (EntryState::Managed { sha256 }, Some(current)) => sha256 == current,
            _ => false,
        }
    }

    fn require_entry_state(&self, selection: &Selection, observed: &EntryState) -> Result<()> {
        if self.entry_matches(selection, observed) {
            Ok(())
        } else {
            Err(StoreError::ExternallyChanged {
                path: self.entry.clone(),
                observed: observed.describe(),
            })
        }
    }

    fn swap_link(&self, operation: &str) -> PathBuf {
        let mut name = OsString::from(".");
        name.push(self.entry.file_name().expect("managed entry has a name"));
        name.push(format!(".{operation}.swap"));
        self.entry.with_file_name(name)
    }

    fn remove_swap_link(&self, operation: &str, to: &str, entry: &EntryLock) -> Result<()> {
        entry.validate()?;
        let swap = self.swap_link(operation);
        match fs::symlink_metadata(&swap) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if metadata.uid() != euid()
                    || metadata.nlink() != 1
                    || fs::read_link(&swap).map_err(io_error(&swap))? != self.version_executable(to)
                {
                    return Err(StoreError::Unsafe {
                        path: swap,
                        reason: "interrupted selection swap link changed",
                    });
                }
                entry.validate()?;
                rfs::unlinkat(
                    &entry.directory,
                    swap.file_name().expect("swap has a name"),
                    AtFlags::empty(),
                )
                .map_err(rustix_error(&swap))?;
                rfs::fsync(&entry.directory)
                    .map_err(rustix_error(swap.parent().expect("swap has a parent")))
            }
            Ok(_) => Err(StoreError::Unsafe {
                path: swap,
                reason: "interrupted selection left an unexpected non-link entry",
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(&swap)(error)),
        }
    }

    fn remove_stale_staging(&self) -> Result<()> {
        let versions = self.root.join(VERSIONS);
        for entry in fs::read_dir(&versions).map_err(io_error(&versions))? {
            let entry = entry.map_err(io_error(&versions))?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(STAGING_PREFIX)
            {
                remove_staging(&entry.path())?;
            }
        }
        Ok(())
    }

    fn remove_stale_selection_temps(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root).map_err(io_error(&self.root))? {
            let entry = entry.map_err(io_error(&self.root))?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(SELECTION_TEMP_PREFIX)
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_error(&path))?;
            if !metadata.is_file() || metadata.uid() != euid() {
                return Err(StoreError::Unsafe {
                    path,
                    reason: "unexpected selection temporary",
                });
            }
            fs::remove_file(&path).map_err(io_error(&path))?;
        }
        Ok(())
    }

    fn read_selection(&self) -> Result<Selection> {
        let path = self.root.join(SELECTION);
        let bytes = read_owned_file(&path, MAX_STATE_BYTES, Some(0o644))?;
        let selection: Selection = serde_json::from_slice(&bytes)
            .map_err(|_| StoreError::MalformedState { path: path.clone() })?;
        if !selection.valid() {
            return Err(StoreError::MalformedState { path });
        }
        Ok(selection)
    }

    fn write_selection(&self, selection: &Selection) -> Result<()> {
        if !selection.valid() {
            return Err(StoreError::MalformedState {
                path: self.root.join(SELECTION),
            });
        }
        let temporary = self
            .root
            .join(format!("{SELECTION_TEMP_PREFIX}{}", uuid::Uuid::new_v4()));
        write_new_file(&temporary, &canonical_json(selection)?, 0o644)?;
        let path = self.root.join(SELECTION);
        fs::rename(&temporary, &path).map_err(io_error(&path))?;
        sync_dir(&self.root)
    }
}

/// Install `candidate` behind `entry`: create the store for an absent entry,
/// or add and select a version behind an entry this store already manages.
/// Unmanaged entries, foreign links and unwritable directories are refused
/// before store publication. A shared lock beside the entry coordinates
/// installations using different roots.
pub fn install(
    root: &Path,
    entry: &Path,
    candidate: &Candidate,
    lock_timeout: Duration,
) -> Result<Installed> {
    Platform::host().ok_or(StoreError::UnsupportedHost)?;
    let entry = canonical_entry(entry)?;
    require_writable(entry.parent().expect("entry has a parent"))?;
    let existing = match Store::open(root, lock_timeout) {
        Ok(store) => Some(store),
        Err(StoreError::NotAStore { .. }) => None,
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let managed_root = existing.as_ref().map(Store::root);
    match observe_entry_at(&entry, managed_root)? {
        EntryState::Absent | EntryState::Managed { .. } => {}
        state => return Err(entry_refusal(&entry, state)),
    }
    let entry_lock = EntryLock::acquire(&entry, lock_timeout)?;
    match entry_lock.observe(managed_root)?.state {
        EntryState::Absent | EntryState::Managed { .. } => {}
        state => return Err(entry_refusal(&entry, state)),
    }
    let (store, created_store) = match existing {
        Some(store) => {
            store.require_entry(&entry)?;
            (store, false)
        }
        None => (
            Store::create_locked(root, &entry, lock_timeout, &entry_lock)?,
            true,
        ),
    };
    let store_lock = store.lock(true)?;
    store.require_mutable(&entry_lock)?;
    let (published, selected) = store.publish_and_select_locked(candidate, None, &entry_lock)?;
    drop(store_lock);
    Ok(Installed {
        store,
        created_store,
        published,
        selected,
    })
}

fn entry_refusal(entry: &Path, state: EntryState) -> StoreError {
    match state {
        EntryState::Unmanaged { kind } => StoreError::UnmanagedEntry {
            path: entry.to_owned(),
            kind,
        },
        EntryState::ForeignLink { .. } => StoreError::UnmanagedEntry {
            path: entry.to_owned(),
            kind: "symbolic link that this store does not manage",
        },
        EntryState::Managed { .. } | EntryState::Absent => StoreError::ExternallyChanged {
            path: entry.to_owned(),
            observed: state.describe(),
        },
    }
}

fn canonical_entry(entry: &Path) -> Result<PathBuf> {
    let name = entry.file_name().ok_or_else(|| StoreError::Unsafe {
        path: entry.to_owned(),
        reason: "managed entry has no file name",
    })?;
    if !entry.is_absolute() {
        return Err(StoreError::Unsafe {
            path: entry.to_owned(),
            reason: "managed entry must be absolute",
        });
    }
    let parent = entry.parent().expect("absolute entry has a parent");
    let metadata = fs::metadata(parent).map_err(io_error(parent))?;
    if !metadata.is_dir() {
        return Err(StoreError::Unsafe {
            path: parent.to_owned(),
            reason: "managed entry parent is not a directory",
        });
    }
    let parent = fs::canonicalize(parent).map_err(io_error(parent))?;
    check_private_dir(&parent)?;
    Ok(parent.join(name))
}

fn observe_entry_at(entry: &Path, root: Option<&Path>) -> Result<EntryState> {
    let metadata = match fs::symlink_metadata(entry) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(EntryState::Absent),
        Err(error) => return Err(io_error(entry)(error)),
    };
    let kind = metadata.file_type();
    if kind.is_symlink() {
        let target = fs::read_link(entry).map_err(io_error(entry))?;
        return Ok(classify_link(target, root));
    }
    Ok(EntryState::Unmanaged {
        kind: if kind.is_file() {
            "regular file"
        } else if kind.is_dir() {
            "directory"
        } else {
            "special file"
        },
    })
}

fn classify_link(target: PathBuf, root: Option<&Path>) -> EntryState {
    let managed = root.and_then(|root| {
        let versions = root.join(VERSIONS);
        let sha256 = target
            .strip_prefix(&versions)
            .ok()?
            .parent()?
            .to_str()
            .filter(|name| is_sha256_hex(name))?
            .to_owned();
        let expected = versions.join(&sha256).join(EXECUTABLE);
        (target.as_os_str() == expected.as_os_str()).then_some(sha256)
    });
    match managed {
        Some(sha256) => EntryState::Managed { sha256 },
        None => EntryState::ForeignLink { target },
    }
}

fn next_generation(generation: u64) -> Result<u64> {
    generation.checked_add(1).ok_or(StoreError::Unsafe {
        path: PathBuf::new(),
        reason: "selection generation overflow",
    })
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn require_writable(directory: &Path) -> Result<()> {
    // Refuse read-only mode bits even when privileged access could bypass
    // them. This is an admission decision, not a best-effort access probe.
    let metadata = fs::metadata(directory).map_err(io_error(directory))?;
    if !metadata.is_dir() || metadata.uid() != euid() || metadata.mode() & 0o300 != 0o300 {
        return Err(StoreError::NotWritable {
            path: directory.to_owned(),
        });
    }
    rfs::access(directory, Access::WRITE_OK | Access::EXEC_OK).map_err(|_| {
        StoreError::NotWritable {
            path: directory.to_owned(),
        }
    })
}

fn check_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    let reason = if !metadata.is_dir() {
        "not a directory"
    } else if metadata.uid() != euid() {
        "owned by another user"
    } else if metadata.mode() & 0o022 != 0 {
        "writable by group or others"
    } else {
        return Ok(());
    };
    Err(StoreError::Unsafe {
        path: path.to_owned(),
        reason,
    })
}

fn read_owned_file(path: &Path, limit: usize, mode: Option<u32>) -> Result<Vec<u8>> {
    let fd = rfs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_error(path))?;
    read_owned_descriptor(path, File::from(fd), limit, mode)
}

fn read_owned_descriptor(
    path: &Path,
    mut file: File,
    limit: usize,
    mode: Option<u32>,
) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(io_error(path))?;
    let mode_matches = mode.is_none_or(|mode| metadata.mode() & 0o7777 == mode);
    if !metadata.is_file()
        || metadata.uid() != euid()
        || metadata.nlink() != 1
        || !mode_matches
        || metadata.len() > limit as u64
    {
        return Err(StoreError::Unsafe {
            path: path.to_owned(),
            reason: "state file type, owner, mode, link count or size is unexpected",
        });
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(path))?;
    if bytes.len() > limit {
        return Err(StoreError::MalformedState {
            path: path.to_owned(),
        });
    }
    let after = file.metadata().map_err(io_error(path))?;
    if !same_file_metadata(&metadata, &after) || bytes.len() as u64 != metadata.len() {
        return Err(StoreError::MalformedState {
            path: path.to_owned(),
        });
    }
    Ok(bytes)
}

fn same_file_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.mode(),
        before.uid(),
        before.nlink(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) == (
        after.dev(),
        after.ino(),
        after.mode(),
        after.uid(),
        after.nlink(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    )
}

fn validate_lock(path: &Path, file: &File) -> Result<()> {
    let held = file.metadata().map_err(io_error(path))?;
    let named = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !held.is_file()
        || held.uid() != euid()
        || held.mode() & 0o7777 != 0o600
        || held.nlink() != 1
        || !named.is_file()
        || !same_file_metadata(&held, &named)
    {
        return Err(StoreError::Unsafe {
            path: path.to_owned(),
            reason: "lock type, owner, mode, link count or identity changed",
        });
    }
    Ok(())
}

fn lock_file(path: &Path, file: File, exclusive: bool, timeout: Duration) -> Result<StoreLock> {
    validate_lock(path, &file)?;
    let operation = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    let deadline = Instant::now() + timeout;
    loop {
        match rfs::flock(&file, operation) {
            Ok(()) => {
                validate_lock(path, &file)?;
                return Ok(StoreLock { _file: file });
            }
            Err(errno) if errno == rustix::io::Errno::WOULDBLOCK => {
                if Instant::now() >= deadline {
                    return Err(StoreError::LockTimeout(timeout));
                }
                std::thread::sleep(LOCK_POLL);
            }
            Err(errno) if errno == rustix::io::Errno::INTR => {
                if Instant::now() >= deadline {
                    return Err(StoreError::LockTimeout(timeout));
                }
            }
            Err(errno) => return Err(rustix_error(path)(errno)),
        }
    }
}

fn open_directory(path: &Path) -> Result<File> {
    rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(rustix_error(path))
}

fn require_directory_identity(path: &Path, held: &File) -> Result<()> {
    let named = fs::symlink_metadata(path).map_err(io_error(path))?;
    let held = held.metadata().map_err(io_error(path))?;
    if !named.is_dir() || !held.is_dir() || named.dev() != held.dev() || named.ino() != held.ino() {
        return Err(StoreError::Unsafe {
            path: path.to_owned(),
            reason: "directory identity changed",
        });
    }
    Ok(())
}

fn create_new_file(path: &Path, mode: rfs::RawMode) -> Result<File> {
    let fd = rfs::open(
        path,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )
    .map_err(rustix_error(path))?;
    let file = File::from(fd);
    rfs::fchmod(&file, Mode::from_raw_mode(mode)).map_err(rustix_error(path))?;
    Ok(file)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: rfs::RawMode) -> Result<()> {
    let mut file = create_new_file(path, 0o600)?;
    file.write_all(bytes).map_err(io_error(path))?;
    file.sync_all().map_err(io_error(path))?;
    rfs::fchmod(&file, Mode::from_raw_mode(mode)).map_err(rustix_error(path))
}

fn create_dir(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path).map_err(io_error(path))?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error(path))
}

fn sync_dir(path: &Path) -> Result<()> {
    let fd = open_directory(path)?;
    rfs::fsync(&fd).map_err(rustix_error(path))
}

/// Remove an incomplete publication owned by this user.
fn remove_staging(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !metadata.is_dir() || metadata.uid() != euid() {
        return Err(StoreError::Unsafe {
            path: path.to_owned(),
            reason: "staging entry is not a directory owned by this user",
        });
    }
    set_mode(path, 0o700)?;
    fs::remove_dir_all(path).map_err(io_error(path))?;
    sync_dir(path.parent().expect("staging has a parent"))
}

#[cfg(test)]
mod tests;
