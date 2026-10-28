//! Confined application of previously admitted OCI layer streams.
//!
//! The tar parser never receives a destination path. Every mutation is
//! relative to an already-open generation directory and every directory walk
//! rejects symlinks, magic links, mount crossings, and escapes with `openat2`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use flate2::read::MultiGzDecoder;
use rustix::fs::{
    self as rfs, AtFlags, FileType, Gid, Mode, OFlags, RenameFlags, ResolveFlags, Timespec,
    Timestamps, Uid, XattrFlags,
};
use rustix::io::Errno;
use thiserror::Error;

use crate::setup_archive::{
    AdmittedEntry, AdmittedKind, ArchiveError, EntryConsumer, ReplayError, VerifiedLayerPlan,
    Whiteout, replay_tar,
};
use crate::setup_verify::VerifiedSetupContents;
use crate::{LayerEncoding, SetupHeader, SetupLayer, Sha256Value};

const LOWER_NAME: &[u8] = b"lower";
pub(crate) const OCI_LOWER_ROOT_MODE: u32 = 0o755;
const COMPLETION_NAME: &[u8] = b"rootfs.complete";
const COMPLETION_TEMP_NAME: &[u8] = b".rootfs.complete.tmp";
const COMPLETION_VERSION: &str = "codewire-oci-lower-v1";
const MAX_REMOVAL_ENTRIES: u64 = 2_100_000;
const MAX_REMOVAL_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
    Applied,
    AlreadyComplete,
}

pub(crate) fn apply_setup_layers(
    input: &mut (impl Read + Seek),
    header: &SetupHeader,
    verified: &VerifiedSetupContents,
    generation_path: &Path,
) -> Result<ApplyOutcome, SetupApplyError> {
    apply_setup_layers_with(
        input,
        header,
        verified,
        generation_path,
        copy_regular_payload,
    )
}

fn apply_setup_layers_with<W>(
    input: &mut (impl Read + Seek),
    header: &SetupHeader,
    verified: &VerifiedSetupContents,
    generation_path: &Path,
    write_payload: W,
) -> Result<ApplyOutcome, SetupApplyError>
where
    W: FnMut(&mut File, &mut dyn Read, u64) -> io::Result<u64>,
{
    if header.layers.len() != verified.layer_uncompressed_bytes.len()
        || header.layers.len() != verified.layer_plans.len()
    {
        return Err(SetupApplyError::InvalidVerifiedState);
    }

    let generation = fs_result(
        "open root generation directory",
        rfs::open(
            generation_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ),
    )?;
    let marker = completion_bytes(header.root_generation);
    match read_completion(&generation, &marker)? {
        CompletionState::Absent => {}
        CompletionState::Exact => {
            let _ = open_directory_at(&generation, LOWER_NAME)?;
            return Ok(ApplyOutcome::AlreadyComplete);
        }
    }

    let mut removal = RemovalBudget::default();
    remove_at(&generation, COMPLETION_TEMP_NAME, &mut removal, 0)?;
    remove_at(&generation, LOWER_NAME, &mut removal, 0)?;
    fs_result(
        "create empty OCI lower directory",
        rfs::mkdirat(
            &generation,
            LOWER_NAME,
            Mode::from_raw_mode(OCI_LOWER_ROOT_MODE),
        ),
    )?;
    let lower = open_directory_at(&generation, LOWER_NAME)?;
    // The process umask narrows mkdirat's mode; the lower root's is exact.
    fs_result(
        "set OCI lower directory mode",
        rfs::fchmod(&lower, Mode::from_raw_mode(OCI_LOWER_ROOT_MODE)),
    )?;
    let mut writer = LayerWriter::new(lower, write_payload);

    for ((layer, uncompressed_bytes), plan) in header
        .layers
        .iter()
        .zip(&verified.layer_uncompressed_bytes)
        .zip(&verified.layer_plans)
    {
        writer.apply_whiteouts(plan)?;
        replay_layer(input, layer, *uncompressed_bytes, plan, &mut writer)?;
        writer.finish_layer()?;
    }

    fs_result(
        "sync completed OCI lower filesystem",
        rfs::syncfs(&writer.root),
    )?;
    publish_completion(&generation, &marker)?;
    Ok(ApplyOutcome::Applied)
}

fn copy_regular_payload(output: &mut File, input: &mut dyn Read, bytes: u64) -> io::Result<u64> {
    io::copy(&mut input.take(bytes), output)
}

pub(crate) fn verify_completed_setup_generation(
    generation_path: &Path,
    generation: Sha256Value,
) -> Result<(), SetupApplyError> {
    let root = fs_result(
        "open completed root generation directory",
        rfs::open(
            generation_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ),
    )?;
    match read_completion(&root, &completion_bytes(generation))? {
        CompletionState::Exact => {
            let _ = open_directory_at(&root, LOWER_NAME)?;
            Ok(())
        }
        CompletionState::Absent => Err(SetupApplyError::GenerationIncomplete),
    }
}

fn replay_layer<W>(
    input: &mut (impl Read + Seek),
    layer: &SetupLayer,
    uncompressed_bytes: u64,
    plan: &VerifiedLayerPlan,
    writer: &mut LayerWriter<W>,
) -> Result<(), SetupApplyError>
where
    W: FnMut(&mut File, &mut dyn Read, u64) -> io::Result<u64>,
{
    input
        .seek(SeekFrom::Start(layer.object.offset))
        .map_err(|source| SetupApplyError::Io {
            action: "seek verified setup layer",
            source,
        })?;
    let mut range = input.take(layer.object.size);
    let outcome = match layer.encoding {
        LayerEncoding::Tar => {
            replay_tar(&mut range, layer.diff_id, uncompressed_bytes, plan, writer)
        }
        LayerEncoding::Gzip => {
            let mut decoder = MultiGzDecoder::new(range);
            let outcome = replay_tar(
                &mut decoder,
                layer.diff_id,
                uncompressed_bytes,
                plan,
                writer,
            );
            range = decoder.into_inner();
            outcome
        }
        LayerEncoding::Zstd => return Err(SetupApplyError::UnsupportedLayerEncoding),
    };
    outcome.map_err(map_replay_error)?;
    if range.limit() != 0 {
        return Err(SetupApplyError::TruncatedLayerObject);
    }
    Ok(())
}

fn map_replay_error(error: ReplayError<SetupApplyError>) -> SetupApplyError {
    match error {
        ReplayError::Archive(error) => SetupApplyError::Archive(error),
        ReplayError::Consumer(error) => error,
        ReplayError::EntryDataNotConsumed => SetupApplyError::EntryDataNotConsumed,
        ReplayError::Mismatch => SetupApplyError::ReplayMismatch,
    }
}

struct LayerWriter<W> {
    root: OwnedFd,
    directories: Vec<DirectoryMetadata>,
    removal: RemovalBudget,
    temp_counter: u64,
    write_payload: W,
}

impl<W> LayerWriter<W>
where
    W: FnMut(&mut File, &mut dyn Read, u64) -> io::Result<u64>,
{
    fn new(root: OwnedFd, write_payload: W) -> Self {
        Self {
            root,
            directories: Vec::new(),
            removal: RemovalBudget::default(),
            temp_counter: 0,
            write_payload,
        }
    }

    fn apply_whiteouts(&mut self, plan: &VerifiedLayerPlan) -> Result<(), SetupApplyError> {
        for whiteout in plan.whiteouts() {
            match whiteout {
                Whiteout::Remove(path) => {
                    let (parent_path, name) = parent_and_name(path)?;
                    let parent = self.ensure_directory_path(parent_path)?;
                    remove_at(&parent, name, &mut self.removal, 0)?;
                }
                Whiteout::Opaque(path) => {
                    let directory = self.ensure_directory_path(path)?;
                    clear_directory(&directory, &mut self.removal, 0)?;
                }
            }
        }
        Ok(())
    }

    fn finish_layer(&mut self) -> Result<(), SetupApplyError> {
        let mut directories = std::mem::take(&mut self.directories);
        directories.sort_by_key(|metadata| std::cmp::Reverse(path_depth(&metadata.path)));
        for metadata in directories {
            let directory = if metadata.path.is_empty() {
                fs_result(
                    "duplicate OCI lower descriptor",
                    rustix::io::dup(&self.root),
                )?
            } else {
                self.open_existing_directory(&metadata.path)?
            };
            apply_fd_metadata(&directory, &metadata)?;
        }
        Ok(())
    }

    fn ensure_directory_path(&mut self, path: &[u8]) -> Result<OwnedFd, SetupApplyError> {
        let mut current = fs_result(
            "duplicate OCI lower descriptor",
            rustix::io::dup(&self.root),
        )?;
        if path.is_empty() {
            return Ok(current);
        }
        for component in path.split(|byte| *byte == b'/') {
            current = ensure_directory_component(&current, component, &mut self.removal)?;
        }
        Ok(current)
    }

    fn open_existing_directory(&self, path: &[u8]) -> Result<OwnedFd, SetupApplyError> {
        fs_result(
            "open admitted OCI directory",
            rfs::openat2(
                &self.root,
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                resolve_flags(),
            ),
        )
    }

    fn apply_regular(
        &mut self,
        entry: &AdmittedEntry,
        data: &mut dyn Read,
    ) -> Result<(), SetupApplyError> {
        let (parent_path, name) = parent_and_name(entry.path())?;
        let parent = self.ensure_directory_path(parent_path)?;
        self.temp_counter = self
            .temp_counter
            .checked_add(1)
            .ok_or(SetupApplyError::InvalidVerifiedState)?;
        let temporary = format!(".codewire-layer-{:016x}", self.temp_counter).into_bytes();
        let descriptor = fs_result(
            "create confined OCI layer temporary file",
            rfs::openat2(
                &parent,
                temporary.as_slice(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
                resolve_flags(),
            ),
        )?;
        let mut file = File::from(descriptor);
        let result = (|| {
            let copied = (self.write_payload)(&mut file, data, entry.size()).map_err(|source| {
                SetupApplyError::Io {
                    action: "write admitted OCI file payload",
                    source,
                }
            })?;
            if copied != entry.size() {
                return Err(SetupApplyError::TruncatedEntryData);
            }
            apply_fd_metadata(&file, &DirectoryMetadata::from_entry(entry))
        })();
        drop(file);
        if let Err(error) = result {
            let _ = rfs::unlinkat(&parent, temporary.as_slice(), AtFlags::empty());
            return Err(error);
        }

        if let Err(error) = remove_at(&parent, name, &mut self.removal, 0) {
            let _ = rfs::unlinkat(&parent, temporary.as_slice(), AtFlags::empty());
            return Err(error);
        }
        if let Err(source) = rfs::renameat(&parent, temporary.as_slice(), &parent, name) {
            let _ = rfs::unlinkat(&parent, temporary.as_slice(), AtFlags::empty());
            return Err(SetupApplyError::Fs {
                action: "publish admitted OCI regular file",
                source,
            });
        }
        Ok(())
    }

    fn apply_directory(&mut self, entry: &AdmittedEntry) -> Result<(), SetupApplyError> {
        if !entry.path().is_empty() {
            let (parent_path, name) = parent_and_name(entry.path())?;
            let parent = self.ensure_directory_path(parent_path)?;
            let _ = ensure_directory_component(&parent, name, &mut self.removal)?;
        }
        self.directories.push(DirectoryMetadata::from_entry(entry));
        Ok(())
    }

    fn apply_symlink(
        &mut self,
        entry: &AdmittedEntry,
        target: &[u8],
    ) -> Result<(), SetupApplyError> {
        let (parent_path, name) = parent_and_name(entry.path())?;
        let parent = self.ensure_directory_path(parent_path)?;
        remove_at(&parent, name, &mut self.removal, 0)?;
        fs_result(
            "create admitted OCI symbolic link",
            rfs::symlinkat(target, &parent, name),
        )?;
        apply_symlink_metadata(&parent, name, entry)
    }

    fn apply_hardlink(
        &mut self,
        entry: &AdmittedEntry,
        target: &[u8],
    ) -> Result<(), SetupApplyError> {
        let target_descriptor = fs_result(
            "open admitted OCI hard-link target",
            rfs::openat2(
                &self.root,
                target,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                resolve_flags(),
            ),
        )?;
        let target_stat = fs_result(
            "inspect admitted OCI hard-link target",
            rfs::fstat(&target_descriptor),
        )?;
        if FileType::from_raw_mode(target_stat.st_mode) != FileType::RegularFile {
            return Err(SetupApplyError::InvalidHardlinkTarget);
        }

        let (parent_path, name) = parent_and_name(entry.path())?;
        let parent = self.ensure_directory_path(parent_path)?;
        remove_at(&parent, name, &mut self.removal, 0)?;
        fs_result(
            "create admitted OCI hard link from its exact descriptor",
            rfs::linkat(
                &target_descriptor,
                &b""[..],
                &parent,
                name,
                AtFlags::EMPTY_PATH,
            ),
        )?;
        apply_fd_metadata(&target_descriptor, &DirectoryMetadata::from_entry(entry))
    }
}

impl<W> EntryConsumer for LayerWriter<W>
where
    W: FnMut(&mut File, &mut dyn Read, u64) -> io::Result<u64>,
{
    type Error = SetupApplyError;

    fn consume(&mut self, entry: &AdmittedEntry, data: &mut dyn Read) -> Result<(), Self::Error> {
        match entry.kind() {
            AdmittedKind::Regular => self.apply_regular(entry, data),
            AdmittedKind::Directory => self.apply_directory(entry),
            AdmittedKind::Symlink(target) => self.apply_symlink(entry, target),
            AdmittedKind::Hardlink(target) => self.apply_hardlink(entry, target),
            AdmittedKind::Whiteout(_) => Err(SetupApplyError::InvalidVerifiedState),
        }
    }
}

#[derive(Clone)]
struct DirectoryMetadata {
    path: Vec<u8>,
    security_capability: Option<Vec<u8>>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

impl DirectoryMetadata {
    fn from_entry(entry: &AdmittedEntry) -> Self {
        Self {
            path: entry.path().to_vec(),
            security_capability: entry.security_capability().map(<[u8]>::to_vec),
            mode: entry.mode(),
            uid: entry.uid(),
            gid: entry.gid(),
            mtime: entry.mtime(),
        }
    }
}

#[derive(Default)]
struct RemovalBudget {
    entries: u64,
}

fn ensure_directory_component(
    parent: &OwnedFd,
    name: &[u8],
    removal: &mut RemovalBudget,
) -> Result<OwnedFd, SetupApplyError> {
    match rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            open_directory_at(parent, name)
        }
        Ok(_) => {
            remove_at(parent, name, removal, 0)?;
            fs_result(
                "create admitted OCI directory component",
                rfs::mkdirat(parent, name, Mode::from_raw_mode(0o700)),
            )?;
            open_directory_at(parent, name)
        }
        Err(Errno::NOENT) => {
            fs_result(
                "create admitted OCI directory component",
                rfs::mkdirat(parent, name, Mode::from_raw_mode(0o700)),
            )?;
            open_directory_at(parent, name)
        }
        Err(source) => Err(SetupApplyError::Fs {
            action: "inspect admitted OCI directory component",
            source,
        }),
    }
}

fn open_directory_at(parent: &OwnedFd, name: &[u8]) -> Result<OwnedFd, SetupApplyError> {
    fs_result(
        "open confined OCI directory component",
        rfs::openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            resolve_flags(),
        ),
    )
}

fn remove_at(
    parent: &OwnedFd,
    name: &[u8],
    budget: &mut RemovalBudget,
    depth: usize,
) -> Result<(), SetupApplyError> {
    if depth > MAX_REMOVAL_DEPTH {
        return Err(SetupApplyError::RemovalLimit);
    }
    let stat = match rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(()),
        Err(source) => {
            return Err(SetupApplyError::Fs {
                action: "inspect confined OCI removal target",
                source,
            });
        }
    };
    budget.entries = budget
        .entries
        .checked_add(1)
        .filter(|entries| *entries <= MAX_REMOVAL_ENTRIES)
        .ok_or(SetupApplyError::RemovalLimit)?;

    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
        let directory = open_directory_at(parent, name)?;
        clear_directory(&directory, budget, depth + 1)?;
        fs_result(
            "remove confined OCI directory",
            rfs::unlinkat(parent, name, AtFlags::REMOVEDIR),
        )
    } else {
        fs_result(
            "remove confined OCI non-directory",
            rfs::unlinkat(parent, name, AtFlags::empty()),
        )
    }
}

fn clear_directory(
    directory: &OwnedFd,
    budget: &mut RemovalBudget,
    depth: usize,
) -> Result<(), SetupApplyError> {
    if depth > MAX_REMOVAL_DEPTH {
        return Err(SetupApplyError::RemovalLimit);
    }
    let mut stream = fs_result(
        "read confined OCI directory",
        rfs::Dir::read_from(directory),
    )?;
    let mut names = Vec::new();
    for entry in &mut stream {
        let entry = fs_result("read confined OCI directory entry", entry)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    drop(stream);
    for name in names {
        remove_at(directory, &name, budget, depth)?;
    }
    Ok(())
}

fn apply_fd_metadata(
    descriptor: &impl std::os::fd::AsFd,
    metadata: &DirectoryMetadata,
) -> Result<(), SetupApplyError> {
    fs_result(
        "set admitted OCI ownership",
        rfs::fchown(
            descriptor,
            Some(Uid::from_raw(metadata.uid)),
            Some(Gid::from_raw(metadata.gid)),
        ),
    )?;
    fs_result(
        "set admitted OCI mode",
        rfs::fchmod(descriptor, Mode::from_raw_mode(metadata.mode)),
    )?;
    fs_result(
        "set admitted OCI timestamps",
        rfs::futimens(descriptor, &timestamps(metadata.mtime)),
    )?;
    if let Some(capability) = &metadata.security_capability {
        rfs::fsetxattr(
            descriptor,
            b"security.capability" as &[u8],
            capability,
            XattrFlags::empty(),
        )
        .map_err(SetupApplyError::Capability)?;
    }
    Ok(())
}

fn apply_symlink_metadata(
    parent: &OwnedFd,
    name: &[u8],
    entry: &AdmittedEntry,
) -> Result<(), SetupApplyError> {
    fs_result(
        "set admitted OCI symbolic-link ownership",
        rfs::chownat(
            parent,
            name,
            Some(Uid::from_raw(entry.uid())),
            Some(Gid::from_raw(entry.gid())),
            AtFlags::SYMLINK_NOFOLLOW,
        ),
    )?;
    fs_result(
        "set admitted OCI symbolic-link timestamps",
        rfs::utimensat(
            parent,
            name,
            &timestamps(entry.mtime()),
            AtFlags::SYMLINK_NOFOLLOW,
        ),
    )
}

fn timestamps(seconds: i64) -> Timestamps {
    let time = Timespec {
        tv_sec: seconds,
        tv_nsec: 0,
    };
    Timestamps {
        last_access: time,
        last_modification: time,
    }
}

fn parent_and_name(path: &[u8]) -> Result<(&[u8], &[u8]), SetupApplyError> {
    if path.is_empty() {
        return Err(SetupApplyError::InvalidVerifiedState);
    }
    Ok(match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (&[][..], path),
    })
}

fn path_depth(path: &[u8]) -> usize {
    if path.is_empty() {
        0
    } else {
        path.iter().filter(|byte| **byte == b'/').count() + 1
    }
}

fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

enum CompletionState {
    Absent,
    Exact,
}

fn completion_bytes(generation: Sha256Value) -> Vec<u8> {
    format!("{COMPLETION_VERSION} {generation}\n").into_bytes()
}

fn read_completion(
    generation: &OwnedFd,
    expected: &[u8],
) -> Result<CompletionState, SetupApplyError> {
    let descriptor = match rfs::openat2(
        generation,
        COMPLETION_NAME,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        resolve_flags(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(CompletionState::Absent),
        Err(source) => {
            return Err(SetupApplyError::Fs {
                action: "open OCI completion marker",
                source,
            });
        }
    };
    let stat = fs_result("inspect OCI completion marker", rfs::fstat(&descriptor))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size != expected.len() as i64
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_gid != unsafe { libc::getegid() }
        || Mode::from_raw_mode(stat.st_mode) != Mode::from_raw_mode(0o400)
    {
        return Err(SetupApplyError::CompletionMismatch);
    }
    let file = File::from(descriptor);
    let mut actual = Vec::with_capacity(expected.len() + 1);
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)
        .map_err(|source| SetupApplyError::Io {
            action: "read OCI completion marker",
            source,
        })?;
    if actual != expected {
        return Err(SetupApplyError::CompletionMismatch);
    }
    Ok(CompletionState::Exact)
}

fn publish_completion(generation: &OwnedFd, contents: &[u8]) -> Result<(), SetupApplyError> {
    let mut cleanup = RemovalBudget::default();
    remove_at(generation, COMPLETION_TEMP_NAME, &mut cleanup, 0)?;
    let descriptor = fs_result(
        "create OCI completion marker temporary file",
        rfs::openat2(
            generation,
            COMPLETION_TEMP_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
            resolve_flags(),
        ),
    )?;
    let mut file = File::from(descriptor);
    let result = (|| {
        file.write_all(contents)
            .map_err(|source| SetupApplyError::Io {
                action: "write OCI completion marker",
                source,
            })?;
        fs_result(
            "seal OCI completion marker mode",
            rfs::fchmod(&file, Mode::from_raw_mode(0o400)),
        )?;
        fs_result("sync OCI completion marker", rfs::fsync(&file))
    })();
    drop(file);
    if let Err(error) = result {
        let _ = rfs::unlinkat(generation, COMPLETION_TEMP_NAME, AtFlags::empty());
        return Err(error);
    }
    fs_result(
        "publish OCI completion marker",
        rfs::renameat_with(
            generation,
            COMPLETION_TEMP_NAME,
            generation,
            COMPLETION_NAME,
            RenameFlags::NOREPLACE,
        ),
    )?;
    fs_result("sync OCI generation directory", rfs::fsync(generation))?;
    fs_result(
        "sync OCI generation filesystem after completion",
        rfs::syncfs(generation),
    )
}

fn fs_result<T>(action: &'static str, result: Result<T, Errno>) -> Result<T, SetupApplyError> {
    result.map_err(|source| SetupApplyError::Fs { action, source })
}

#[derive(Debug, Error)]
pub(crate) enum SetupApplyError {
    #[error("verified setup metadata is internally inconsistent")]
    InvalidVerifiedState,
    #[error("existing OCI completion marker does not match this generation")]
    CompletionMismatch,
    #[error("OCI root generation is not complete")]
    GenerationIncomplete,
    #[error("setup layer object ended before its admitted compressed size")]
    TruncatedLayerObject,
    #[error("setup layer entry ended before its admitted payload size")]
    TruncatedEntryData,
    #[error("setup entry consumer did not consume its exact admitted payload")]
    EntryDataNotConsumed,
    #[error("setup layer replay differs from its complete admission pass")]
    ReplayMismatch,
    #[error("setup layer encoding is not supported by this guest ABI")]
    UnsupportedLayerEncoding,
    #[error("setup hard-link target is not an admitted regular file")]
    InvalidHardlinkTarget,
    #[error("confined OCI cleanup exceeds its entry or depth bound")]
    RemovalLimit,
    #[error("set admitted OCI file capability: {0}")]
    Capability(#[source] Errno),
    #[error(transparent)]
    Archive(ArchiveError),
    #[error("{action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{action}: {source}")]
    Fs {
        action: &'static str,
        #[source]
        source: Errno,
    },
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;
    use crate::setup_archive::{TarImageBudget, scan_tar};
    use crate::setup_verify::verify_setup_contents;
    use crate::{
        SETUP_HEADER_LEN, SetupArchitecture, SetupBlob, SetupLayerBlob, SetupObject,
        oci_root_generation,
    };

    struct EntryFixture<'a> {
        path: &'a str,
        kind: tar::EntryType,
        link: Option<&'a [u8]>,
        contents: &'a [u8],
    }

    fn archive(entries: &[EntryFixture<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for entry in entries {
            let mut header = tar::Header::new_ustar();
            header.set_path(entry.path).unwrap();
            header.set_entry_type(entry.kind);
            header.set_mode(if entry.kind.is_dir() { 0o755 } else { 0o644 });
            header.set_uid(unsafe { libc::geteuid() }.into());
            header.set_gid(unsafe { libc::getegid() }.into());
            header.set_mtime(1);
            header.set_size(entry.contents.len() as u64);
            if let Some(link) = entry.link {
                header.set_link_name_literal(link).unwrap();
            }
            header.set_cksum();
            builder
                .append(&header, Cursor::new(entry.contents))
                .unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn apply_archive(root: &Path, bytes: &[u8]) -> Result<(), SetupApplyError> {
        let scanned = scan_tar(
            &mut Cursor::new(bytes),
            bytes.len() as u64,
            &mut TarImageBudget::default(),
        )
        .unwrap();
        let root = fs_result(
            "open test root",
            rfs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ),
        )?;
        let mut writer = LayerWriter::new(root, copy_regular_payload);
        writer.apply_whiteouts(&scanned.plan)?;
        replay_tar(
            &mut Cursor::new(bytes),
            scanned.digest,
            scanned.bytes,
            &scanned.plan,
            &mut writer,
        )
        .map_err(map_replay_error)?;
        writer.finish_layer()
    }

    fn setup_pack(layer: Vec<u8>) -> (SetupHeader, Vec<u8>) {
        setup_pack_with_layers(vec![(layer, LayerEncoding::Tar)])
    }

    fn gzip_setup_pack(layer: Vec<u8>) -> (SetupHeader, Vec<u8>) {
        setup_pack_with_layers(vec![(layer, LayerEncoding::Gzip)])
    }

    fn setup_pack_with_layers(layers: Vec<(Vec<u8>, LayerEncoding)>) -> (SetupHeader, Vec<u8>) {
        setup_pack_with_manifest(layers, b"synthetic manifest")
    }

    fn setup_pack_with_manifest(
        layers: Vec<(Vec<u8>, LayerEncoding)>,
        manifest: &[u8],
    ) -> (SetupHeader, Vec<u8>) {
        let project = br#"{"image":"registry.example/workspace"}"#;
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let project_digest = Sha256Value::calculate(project);
        let manifest_digest = Sha256Value::calculate(manifest);
        let stored_layers = layers
            .iter()
            .map(|(layer, encoding)| {
                let stored = match encoding {
                    LayerEncoding::Tar => layer.clone(),
                    LayerEncoding::Gzip => {
                        let mut encoder = flate2::write::GzEncoder::new(
                            Vec::new(),
                            flate2::Compression::default(),
                        );
                        encoder.write_all(layer).unwrap();
                        encoder.finish().unwrap()
                    }
                    LayerEncoding::Zstd => unreachable!(),
                };
                (layer, stored, *encoding)
            })
            .collect::<Vec<_>>();
        let header = SetupHeader::layout(
            oci_root_generation(project_digest, manifest_digest, SetupArchitecture::Amd64),
            manifest_digest,
            SetupArchitecture::Amd64,
            SetupBlob {
                size: project.len() as u64,
                sha256: project_digest,
            },
            SetupBlob {
                size: config.len() as u64,
                sha256: Sha256Value::calculate(config),
            },
            stored_layers
                .iter()
                .map(|(layer, stored, encoding)| SetupLayerBlob {
                    blob: SetupBlob {
                        size: stored.len() as u64,
                        sha256: Sha256Value::calculate(stored),
                    },
                    diff_id: Sha256Value::calculate(layer),
                    encoding: *encoding,
                })
                .collect(),
        )
        .unwrap();
        let mut pack = vec![0_u8; header.total_bytes as usize];
        pack[..SETUP_HEADER_LEN].copy_from_slice(&header.encode().unwrap());
        copy_object(&mut pack, header.project, project);
        copy_object(&mut pack, header.config, config);
        for (descriptor, (_, stored, _)) in header.layers.iter().zip(&stored_layers) {
            copy_object(&mut pack, descriptor.object, stored);
        }
        (header, pack)
    }

    fn copy_object(pack: &mut [u8], object: SetupObject, contents: &[u8]) {
        let start = object.offset as usize;
        let end = start + object.size as usize;
        pack[start..end].copy_from_slice(contents);
    }

    #[test]
    fn applies_replacements_links_and_order_independent_whiteouts_without_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(root.path().join("replace"), b"old").unwrap();
        fs::create_dir(root.path().join("opaque")).unwrap();
        fs::write(root.path().join("opaque/stale"), b"stale").unwrap();
        fs::create_dir(root.path().join("file-replaces-dir")).unwrap();
        fs::write(root.path().join("file-replaces-dir/child"), b"old").unwrap();
        fs::write(root.path().join("dir-replaces-file"), b"old").unwrap();
        fs::write(root.path().join("link-replaces-file"), b"old").unwrap();
        fs::write(outside.path().join("untouched"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();

        let layer = archive(&[
            EntryFixture {
                path: "replace",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"new",
            },
            EntryFixture {
                path: "opaque/new",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"new",
            },
            EntryFixture {
                path: "escape/pwn",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"confined",
            },
            EntryFixture {
                path: "target",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"linked",
            },
            EntryFixture {
                path: "hard",
                kind: tar::EntryType::Link,
                link: Some(b"target"),
                contents: b"",
            },
            EntryFixture {
                path: "file-replaces-dir",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"file",
            },
            EntryFixture {
                path: "dir-replaces-file",
                kind: tar::EntryType::Directory,
                link: None,
                contents: b"",
            },
            EntryFixture {
                path: "dir-replaces-file/child",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"child",
            },
            EntryFixture {
                path: "link-replaces-file",
                kind: tar::EntryType::Symlink,
                link: Some(b"target"),
                contents: b"",
            },
            EntryFixture {
                path: ".wh.replace",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
            EntryFixture {
                path: "opaque/.wh..wh..opq",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
        ]);

        apply_archive(root.path(), &layer).unwrap();
        assert_eq!(fs::read(root.path().join("replace")).unwrap(), b"new");
        assert!(!root.path().join("opaque/stale").exists());
        assert_eq!(fs::read(root.path().join("opaque/new")).unwrap(), b"new");
        assert_eq!(
            fs::read(outside.path().join("untouched")).unwrap(),
            b"outside"
        );
        assert!(!outside.path().join("pwn").exists());
        assert_eq!(
            fs::read(root.path().join("escape/pwn")).unwrap(),
            b"confined"
        );
        assert_eq!(
            fs::symlink_metadata(root.path().join("target"))
                .unwrap()
                .ino(),
            fs::symlink_metadata(root.path().join("hard"))
                .unwrap()
                .ino()
        );
        assert!(root.path().join("file-replaces-dir").is_file());
        assert_eq!(
            fs::read(root.path().join("dir-replaces-file/child")).unwrap(),
            b"child"
        );
        assert_eq!(
            fs::read_link(root.path().join("link-replaces-file")).unwrap(),
            Path::new("target")
        );
    }

    #[test]
    fn rejects_hardlink_through_an_archive_symlink_without_touching_outside() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("prefix")).unwrap();
        let layer = archive(&[EntryFixture {
            path: "hard",
            kind: tar::EntryType::Link,
            link: Some(b"prefix/file"),
            contents: b"",
        }]);

        assert!(apply_archive(root.path(), &layer).is_err());
        assert!(!root.path().join("hard").exists());
        assert_eq!(fs::read(outside.path().join("file")).unwrap(), b"outside");

        let directory_root = tempfile::tempdir().unwrap();
        fs::create_dir(directory_root.path().join("directory")).unwrap();
        let directory_link = archive(&[EntryFixture {
            path: "hard",
            kind: tar::EntryType::Link,
            link: Some(b"directory"),
            contents: b"",
        }]);
        assert!(matches!(
            apply_archive(directory_root.path(), &directory_link),
            Err(SetupApplyError::InvalidHardlinkTarget)
        ));
    }

    #[test]
    fn publishes_completion_last_and_reuses_only_the_exact_generation() {
        let layer = archive(&[EntryFixture {
            path: "image-file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"from-image",
        }]);
        let (header, pack) = gzip_setup_pack(layer);
        let verified = verify_setup_contents(&mut Cursor::new(&pack), &header).unwrap();
        let generation = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify_completed_setup_generation(generation.path(), header.root_generation),
            Err(SetupApplyError::GenerationIncomplete)
        ));

        assert_eq!(
            apply_setup_layers(
                &mut Cursor::new(&pack),
                &header,
                &verified,
                generation.path()
            )
            .unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(
            fs::read(generation.path().join("lower/image-file")).unwrap(),
            b"from-image"
        );
        assert_eq!(
            fs::symlink_metadata(generation.path().join("lower"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert_eq!(
            fs::read(generation.path().join("rootfs.complete")).unwrap(),
            completion_bytes(header.root_generation)
        );
        verify_completed_setup_generation(generation.path(), header.root_generation).unwrap();
        assert_eq!(
            apply_setup_layers(
                &mut Cursor::new(&pack),
                &header,
                &verified,
                generation.path()
            )
            .unwrap(),
            ApplyOutcome::AlreadyComplete
        );

        fs::rename(
            generation.path().join("lower"),
            generation.path().join("lower.saved"),
        )
        .unwrap();
        assert!(
            apply_setup_layers(
                &mut Cursor::new(&pack),
                &header,
                &verified,
                generation.path()
            )
            .is_err()
        );
        fs::rename(
            generation.path().join("lower.saved"),
            generation.path().join("lower"),
        )
        .unwrap();

        fs::set_permissions(
            generation.path().join("rootfs.complete"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(generation.path().join("rootfs.complete"), b"wrong").unwrap();
        assert!(matches!(
            verify_completed_setup_generation(generation.path(), header.root_generation),
            Err(SetupApplyError::CompletionMismatch)
        ));
        assert!(matches!(
            apply_setup_layers(
                &mut Cursor::new(&pack),
                &header,
                &verified,
                generation.path()
            ),
            Err(SetupApplyError::CompletionMismatch)
        ));
    }

    #[test]
    fn failed_application_leaves_no_completion_marker() {
        let layer = archive(&[EntryFixture {
            path: "hard",
            kind: tar::EntryType::Link,
            link: Some(b"missing"),
            contents: b"",
        }]);
        let (header, pack) = setup_pack(layer);
        let verified = verify_setup_contents(&mut Cursor::new(&pack), &header).unwrap();
        let generation = tempfile::tempdir().unwrap();

        assert!(
            apply_setup_layers(
                &mut Cursor::new(&pack),
                &header,
                &verified,
                generation.path()
            )
            .is_err()
        );
        assert!(!generation.path().join("rootfs.complete").exists());
    }

    #[test]
    fn image_deletions_apply_only_to_the_new_completed_generation() {
        let base = archive(&[
            EntryFixture {
                path: "obsolete",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"old",
            },
            EntryFixture {
                path: "opaque/stale",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"stale",
            },
            EntryFixture {
                path: "retained",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"retained",
            },
        ]);
        let deletion = archive(&[
            EntryFixture {
                path: ".wh.obsolete",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
            EntryFixture {
                path: "opaque/.wh..wh..opq",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
            EntryFixture {
                path: "opaque/new",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"new",
            },
        ]);
        let (prior_header, prior_pack) =
            setup_pack_with_manifest(vec![(base.clone(), LayerEncoding::Tar)], b"prior manifest");
        let (candidate_header, candidate_pack) = setup_pack_with_manifest(
            vec![(base, LayerEncoding::Tar), (deletion, LayerEncoding::Tar)],
            b"candidate manifest",
        );
        assert_ne!(
            prior_header.root_generation,
            candidate_header.root_generation
        );
        let prior_verified =
            verify_setup_contents(&mut Cursor::new(&prior_pack), &prior_header).unwrap();
        let candidate_verified =
            verify_setup_contents(&mut Cursor::new(&candidate_pack), &candidate_header).unwrap();
        let prior = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();

        apply_setup_layers(
            &mut Cursor::new(&prior_pack),
            &prior_header,
            &prior_verified,
            prior.path(),
        )
        .unwrap();
        apply_setup_layers(
            &mut Cursor::new(&candidate_pack),
            &candidate_header,
            &candidate_verified,
            candidate.path(),
        )
        .unwrap();

        assert_eq!(
            fs::read(prior.path().join("lower/obsolete")).unwrap(),
            b"old"
        );
        assert_eq!(
            fs::read(prior.path().join("lower/opaque/stale")).unwrap(),
            b"stale"
        );
        assert!(!candidate.path().join("lower/obsolete").exists());
        assert!(!candidate.path().join("lower/opaque/stale").exists());
        assert_eq!(
            fs::read(candidate.path().join("lower/opaque/new")).unwrap(),
            b"new"
        );
        assert_eq!(
            fs::read(candidate.path().join("lower/retained")).unwrap(),
            b"retained"
        );
        verify_completed_setup_generation(prior.path(), prior_header.root_generation).unwrap();
        verify_completed_setup_generation(candidate.path(), candidate_header.root_generation)
            .unwrap();
    }

    #[test]
    fn enospc_and_crash_residue_retry_without_displacing_a_completed_generation() {
        let prior_layer = archive(&[EntryFixture {
            path: "prior-only",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"retained",
        }]);
        let (prior_header, prior_pack) = setup_pack(prior_layer);
        let prior_verified =
            verify_setup_contents(&mut Cursor::new(&prior_pack), &prior_header).unwrap();
        let prior = tempfile::tempdir().unwrap();
        assert_eq!(
            apply_setup_layers(
                &mut Cursor::new(&prior_pack),
                &prior_header,
                &prior_verified,
                prior.path(),
            )
            .unwrap(),
            ApplyOutcome::Applied
        );
        let prior_marker = fs::read(prior.path().join("rootfs.complete")).unwrap();

        let candidate_layer = archive(&[EntryFixture {
            path: "candidate",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"candidate-payload",
        }]);
        let (candidate_header, candidate_pack) = setup_pack(candidate_layer);
        let candidate_verified =
            verify_setup_contents(&mut Cursor::new(&candidate_pack), &candidate_header).unwrap();
        let candidate = tempfile::tempdir().unwrap();

        let failure = apply_setup_layers_with(
            &mut Cursor::new(&candidate_pack),
            &candidate_header,
            &candidate_verified,
            candidate.path(),
            |output, input, _bytes| {
                let copied = io::copy(&mut input.take(4), output)?;
                assert_eq!(copied, 4);
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            },
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            SetupApplyError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ENOSPC)
        ));
        assert!(!candidate.path().join("rootfs.complete").exists());
        assert!(
            fs::read_dir(candidate.path().join("lower"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codewire-layer-"))
        );
        assert_eq!(
            fs::read(prior.path().join("lower/prior-only")).unwrap(),
            b"retained"
        );
        assert_eq!(
            fs::read(prior.path().join("rootfs.complete")).unwrap(),
            prior_marker
        );

        fs::write(candidate.path().join("lower/crash-residue"), b"incomplete").unwrap();
        fs::write(
            candidate.path().join(".rootfs.complete.tmp"),
            b"partial-marker",
        )
        .unwrap();

        assert_eq!(
            apply_setup_layers(
                &mut Cursor::new(&candidate_pack),
                &candidate_header,
                &candidate_verified,
                candidate.path(),
            )
            .unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(
            fs::read(candidate.path().join("lower/candidate")).unwrap(),
            b"candidate-payload"
        );
        assert!(!candidate.path().join("lower/crash-residue").exists());
        assert!(!candidate.path().join(".rootfs.complete.tmp").exists());
        verify_completed_setup_generation(candidate.path(), candidate_header.root_generation)
            .unwrap();
        assert_eq!(
            fs::read(prior.path().join("lower/prior-only")).unwrap(),
            b"retained"
        );
        assert_eq!(
            fs::read(prior.path().join("rootfs.complete")).unwrap(),
            prior_marker
        );
    }
}
