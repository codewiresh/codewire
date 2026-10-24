//! Bounded semantic admission of an untrusted OCI layer tar stream.
//!
//! The parser never receives filesystem authority. It runs during the same
//! pass that computes the complete diff ID, before any root mutation, and
//! returns only the whiteout operations whose ordering OCI defines relative
//! to same-layer entries.

use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::io::{self, Read};
use std::rc::Rc;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::Sha256Value;

const MAX_METADATA_READ_BYTES: u64 = 64 * 1024;
const MAX_PATH_BYTES: usize = 4095;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_PATH_COMPONENTS: usize = 256;
const MAX_LAYER_ENTRIES: u64 = 500_000;
const MAX_IMAGE_ENTRIES: u64 = 2_000_000;
const MAX_LAYER_PATH_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMAGE_PATH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LAYER_WHITEOUTS: u64 = 100_000;
const MAX_IMAGE_WHITEOUTS: u64 = 200_000;
const MAX_LAYER_WHITEOUT_PATH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IMAGE_WHITEOUT_PATH_BYTES: u64 = 32 * 1024 * 1024;
const SCHILY_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";
const SECURITY_CAPABILITY_XATTR: &[u8] = b"security.capability";
const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_1_BYTES: usize = 12;
const VFS_CAP_REVISION_2_BYTES: usize = 20;
const VFS_CAP_REVISION_2_HIGH_VALID_MASK: u32 = 0x0000_01ff;

#[derive(Debug, Default)]
pub(crate) struct TarImageBudget {
    entries: u64,
    path_bytes: u64,
    whiteouts: u64,
    whiteout_path_bytes: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedLayerPlan {
    whiteouts: Vec<Whiteout>,
    entries: u64,
    path_bytes: u64,
}

impl VerifiedLayerPlan {
    pub(crate) fn whiteouts(&self) -> &[Whiteout] {
        &self.whiteouts
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> u64 {
        self.entries
    }
}

impl fmt::Debug for VerifiedLayerPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLayerPlan")
            .field("whiteout_count", &self.whiteouts.len())
            .field("entries", &self.entries)
            .field("path_bytes", &self.path_bytes)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Whiteout {
    Remove(Vec<u8>),
    Opaque(Vec<u8>),
}

impl Whiteout {
    pub(crate) fn path(&self) -> &[u8] {
        match self {
            Self::Remove(path) | Self::Opaque(path) => path,
        }
    }

    pub(crate) fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque(_))
    }
}

impl fmt::Debug for Whiteout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Whiteout")
            .field("kind", &if self.is_opaque() { "opaque" } else { "remove" })
            .field("path_bytes", &self.path().len())
            .finish()
    }
}

pub(crate) struct ScannedTar {
    pub digest: Sha256Value,
    pub bytes: u64,
    pub plan: VerifiedLayerPlan,
}

impl fmt::Debug for ScannedTar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannedTar")
            .field("digest", &self.digest)
            .field("bytes", &self.bytes)
            .field("plan", &self.plan)
            .finish()
    }
}

pub(crate) fn scan_tar(
    input: &mut impl Read,
    maximum_bytes: u64,
    image_budget: &mut TarImageBudget,
) -> Result<ScannedTar, ArchiveError> {
    if maximum_bytes == 0 {
        return Err(ArchiveError::ExpansionLimit);
    }

    let state = Rc::new(ReadState::default());
    let digest_reader = BoundedDigestReader::new(input, maximum_bytes, Rc::clone(&state));
    let budget_reader = MetadataBudgetReader::new(digest_reader, Rc::clone(&state));
    let control = budget_reader.control();
    let mut archive = tar::Archive::new(budget_reader);
    let mut layer_paths = BTreeSet::new();
    let mut non_directory_paths = HashSet::new();
    let mut layer_entries = 0_u64;
    let mut layer_path_bytes = 0_u64;
    let mut layer_whiteouts = 0_u64;
    let mut layer_whiteout_path_bytes = 0_u64;
    let mut whiteouts = Vec::new();

    {
        control.begin();
        let entries = archive.entries();
        control.end();
        let mut entries = entries.map_err(|error| classify_read_error(error, &state))?;
        loop {
            control.begin();
            let next = entries.next();
            control.end();
            let Some(entry) = next else { break };
            let mut entry = entry.map_err(|error| classify_read_error(error, &state))?;
            let admitted = admit_entry(&mut entry)?;

            layer_entries = layer_entries
                .checked_add(1)
                .filter(|count| *count <= MAX_LAYER_ENTRIES)
                .ok_or(ArchiveError::LayerEntryLimit)?;
            image_budget.entries = image_budget
                .entries
                .checked_add(1)
                .filter(|count| *count <= MAX_IMAGE_ENTRIES)
                .ok_or(ArchiveError::ImageEntryLimit)?;
            let admitted_path_bytes = admitted
                .path()
                .len()
                .checked_add(admitted.link_path_bytes())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ArchiveError::PathBudgetLimit)?;
            layer_path_bytes = layer_path_bytes
                .checked_add(admitted_path_bytes)
                .filter(|bytes| *bytes <= MAX_LAYER_PATH_BYTES)
                .ok_or(ArchiveError::PathBudgetLimit)?;
            image_budget.path_bytes = image_budget
                .path_bytes
                .checked_add(admitted_path_bytes)
                .filter(|bytes| *bytes <= MAX_IMAGE_PATH_BYTES)
                .ok_or(ArchiveError::PathBudgetLimit)?;
            admit_layer_path(&mut layer_paths, &mut non_directory_paths, &admitted)?;
            if let Some(whiteout) = admitted.whiteout() {
                layer_whiteouts = layer_whiteouts
                    .checked_add(1)
                    .filter(|count| *count <= MAX_LAYER_WHITEOUTS)
                    .ok_or(ArchiveError::WhiteoutBudgetLimit)?;
                image_budget.whiteouts = image_budget
                    .whiteouts
                    .checked_add(1)
                    .filter(|count| *count <= MAX_IMAGE_WHITEOUTS)
                    .ok_or(ArchiveError::WhiteoutBudgetLimit)?;
                let stored_path_bytes = whiteout.path().len() as u64;
                layer_whiteout_path_bytes = layer_whiteout_path_bytes
                    .checked_add(stored_path_bytes)
                    .filter(|bytes| *bytes <= MAX_LAYER_WHITEOUT_PATH_BYTES)
                    .ok_or(ArchiveError::WhiteoutBudgetLimit)?;
                image_budget.whiteout_path_bytes = image_budget
                    .whiteout_path_bytes
                    .checked_add(stored_path_bytes)
                    .filter(|bytes| *bytes <= MAX_IMAGE_WHITEOUT_PATH_BYTES)
                    .ok_or(ArchiveError::WhiteoutBudgetLimit)?;
                whiteouts.push(whiteout.clone());
            }

            io::copy(&mut entry, &mut io::sink())
                .map_err(|error| classify_read_error(error, &state))?;
        }
    }

    control.end();
    let budget_reader = archive.into_inner();
    let mut digest_reader = budget_reader.into_inner();
    let mut trailing = [0_u8; 8192];
    loop {
        let read = digest_reader
            .read(&mut trailing)
            .map_err(|error| classify_read_error(error, &state))?;
        if read == 0 {
            break;
        }
        if trailing[..read].iter().any(|byte| *byte != 0) {
            return Err(ArchiveError::TrailingData);
        }
    }
    let (digest, bytes) = digest_reader.finish();

    Ok(ScannedTar {
        digest,
        bytes,
        plan: VerifiedLayerPlan {
            whiteouts,
            entries: layer_entries,
            path_bytes: layer_path_bytes,
        },
    })
}

pub(crate) trait EntryConsumer {
    type Error;

    fn consume(&mut self, entry: &AdmittedEntry, data: &mut dyn Read) -> Result<(), Self::Error>;
}

pub(crate) fn replay_tar<C: EntryConsumer>(
    input: &mut impl Read,
    expected_digest: Sha256Value,
    expected_bytes: u64,
    expected_plan: &VerifiedLayerPlan,
    consumer: &mut C,
) -> Result<(), ReplayError<C::Error>> {
    if expected_bytes == 0 {
        return Err(ReplayError::Mismatch);
    }

    let state = Rc::new(ReadState::default());
    let digest_reader = BoundedDigestReader::new(input, expected_bytes, Rc::clone(&state));
    let budget_reader = MetadataBudgetReader::new(digest_reader, Rc::clone(&state));
    let control = budget_reader.control();
    let mut archive = tar::Archive::new(budget_reader);
    let mut layer_paths = BTreeSet::new();
    let mut non_directory_paths = HashSet::new();
    let mut layer_entries = 0_u64;
    let mut layer_path_bytes = 0_u64;
    let mut whiteouts = Vec::new();

    {
        control.begin();
        let entries = archive.entries();
        control.end();
        let mut entries =
            entries.map_err(|error| ReplayError::Archive(classify_read_error(error, &state)))?;
        loop {
            control.begin();
            let next = entries.next();
            control.end();
            let Some(entry) = next else { break };
            let mut entry =
                entry.map_err(|error| ReplayError::Archive(classify_read_error(error, &state)))?;
            let admitted = admit_entry(&mut entry).map_err(ReplayError::Archive)?;

            layer_entries = layer_entries
                .checked_add(1)
                .filter(|count| *count <= expected_plan.entries)
                .ok_or(ReplayError::Mismatch)?;
            let admitted_path_bytes = admitted
                .path()
                .len()
                .checked_add(admitted.link_path_bytes())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ReplayError::Mismatch)?;
            layer_path_bytes = layer_path_bytes
                .checked_add(admitted_path_bytes)
                .filter(|bytes| *bytes <= expected_plan.path_bytes)
                .ok_or(ReplayError::Mismatch)?;
            admit_layer_path(&mut layer_paths, &mut non_directory_paths, &admitted)
                .map_err(ReplayError::Archive)?;
            if let Some(whiteout) = admitted.whiteout() {
                let expected = expected_plan
                    .whiteouts
                    .get(whiteouts.len())
                    .ok_or(ReplayError::Mismatch)?;
                if whiteout != expected {
                    return Err(ReplayError::Mismatch);
                }
                whiteouts.push(whiteout.clone());
            } else {
                consumer
                    .consume(&admitted, &mut entry)
                    .map_err(ReplayError::Consumer)?;
            }

            let remaining = io::copy(&mut entry, &mut io::sink())
                .map_err(|error| ReplayError::Archive(classify_read_error(error, &state)))?;
            if remaining != 0 {
                return Err(ReplayError::EntryDataNotConsumed);
            }
        }
    }

    control.end();
    let budget_reader = archive.into_inner();
    let mut digest_reader = budget_reader.into_inner();
    let mut trailing = [0_u8; 8192];
    loop {
        let read = digest_reader
            .read(&mut trailing)
            .map_err(|error| ReplayError::Archive(classify_read_error(error, &state)))?;
        if read == 0 {
            break;
        }
        if trailing[..read].iter().any(|byte| *byte != 0) {
            return Err(ReplayError::Archive(ArchiveError::TrailingData));
        }
    }
    let (digest, bytes) = digest_reader.finish();

    if digest != expected_digest
        || bytes != expected_bytes
        || layer_entries != expected_plan.entries
        || layer_path_bytes != expected_plan.path_bytes
        || whiteouts != expected_plan.whiteouts
    {
        return Err(ReplayError::Mismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ReplayError<E> {
    #[error(transparent)]
    Archive(ArchiveError),
    #[error("apply admitted setup entry")]
    Consumer(E),
    #[error("setup entry consumer did not consume its exact admitted payload")]
    EntryDataNotConsumed,
    #[error("setup layer replay differs from its complete admission pass")]
    Mismatch,
}

pub(crate) struct AdmittedEntry {
    path: Vec<u8>,
    kind: AdmittedKind,
    security_capability: Option<Vec<u8>>,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

impl AdmittedEntry {
    pub(crate) fn path(&self) -> &[u8] {
        &self.path
    }

    pub(crate) fn kind(&self) -> &AdmittedKind {
        &self.kind
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }

    pub(crate) fn mtime(&self) -> i64 {
        self.mtime
    }

    pub(crate) fn security_capability(&self) -> Option<&[u8]> {
        self.security_capability.as_deref()
    }

    fn whiteout(&self) -> Option<&Whiteout> {
        match &self.kind {
            AdmittedKind::Whiteout(whiteout) => Some(whiteout),
            _ => None,
        }
    }

    fn link_path_bytes(&self) -> usize {
        match &self.kind {
            AdmittedKind::Symlink(target) | AdmittedKind::Hardlink(target) => target.len(),
            _ => 0,
        }
    }
}

impl fmt::Debug for AdmittedEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedEntry")
            .field("path_bytes", &self.path.len())
            .field("kind", &self.kind)
            .field(
                "security_capability_bytes",
                &self.security_capability.as_ref().map(Vec::len),
            )
            .field("size", &self.size)
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("mtime", &self.mtime)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AdmittedKind {
    Regular,
    Directory,
    Symlink(Vec<u8>),
    Hardlink(Vec<u8>),
    Whiteout(Whiteout),
}

impl fmt::Debug for AdmittedKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, target_bytes) = match self {
            Self::Regular => ("regular", None),
            Self::Directory => ("directory", None),
            Self::Symlink(target) => ("symlink", Some(target.len())),
            Self::Hardlink(target) => ("hardlink", Some(target.len())),
            Self::Whiteout(_) => ("whiteout", None),
        };
        formatter
            .debug_struct("AdmittedKind")
            .field("kind", &kind)
            .field("target_bytes", &target_bytes)
            .finish()
    }
}

fn admit_layer_path(
    paths: &mut BTreeSet<Vec<u8>>,
    non_directories: &mut HashSet<Vec<u8>>,
    entry: &AdmittedEntry,
) -> Result<(), ArchiveError> {
    let path = entry.path();
    if paths.contains(path) {
        return Err(ArchiveError::DuplicatePath);
    }
    for separator in path
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'/').then_some(index))
    {
        if non_directories.contains(&path[..separator]) {
            return Err(ArchiveError::PathTypeConflict);
        }
    }
    if !matches!(entry.kind(), AdmittedKind::Directory) && !path.is_empty() {
        let mut prefix = path.to_vec();
        prefix.push(b'/');
        if paths
            .range(prefix.clone()..)
            .next()
            .is_some_and(|existing| existing.starts_with(&prefix))
        {
            return Err(ArchiveError::PathTypeConflict);
        }
        non_directories.insert(path.to_vec());
    }
    paths.insert(path.to_vec());
    Ok(())
}

/// The S_IFMT values a tar header mode may carry for its typeflag (#3326).
const MODE_TYPE_DIRECTORY: u32 = 0o040_000;
const MODE_TYPE_REGULAR: u32 = 0o100_000;
const MODE_TYPE_SYMLINK: u32 = 0o120_000;

fn admit_entry<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<AdmittedEntry, ArchiveError> {
    let entry_type = entry.header().entry_type();
    let raw_path = entry.path_bytes().into_owned();
    let link_name = entry.link_name_bytes().map(|name| name.into_owned());
    let size = entry.size();
    let raw_mode = entry
        .header()
        .mode()
        .map_err(|_| ArchiveError::InvalidTar)?;
    let uid = entry.header().uid().map_err(|_| ArchiveError::InvalidTar)?;
    let gid = entry.header().gid().map_err(|_| ArchiveError::InvalidTar)?;
    let mtime = entry
        .header()
        .mtime()
        .map_err(|_| ArchiveError::InvalidTar)?;
    let security_capability = validate_pax(entry, size, uid, gid)?;

    // Go's archive/tar and tools built on it wrote the file type's S_IFMT
    // bits into the header mode; Docker and containerd take the type from
    // the typeflag and the permissions from the low 12 bits (#3326). Admit
    // those bits only as the one value that matches the typeflag, checked
    // below, and keep only the permissions.
    let type_bits = raw_mode & !0o7777;
    let mode = raw_mode & 0o7777;
    if !matches!(
        type_bits,
        0 | MODE_TYPE_DIRECTORY | MODE_TYPE_REGULAR | MODE_TYPE_SYMLINK
    ) || uid >= u32::MAX as u64
        || gid >= u32::MAX as u64
        || mtime > i64::MAX as u64
    {
        return Err(ArchiveError::InvalidMetadata);
    }
    let path = normalize_entry_path(&raw_path)?;
    if path.is_empty() {
        if !entry_type.is_dir() || size != 0 || link_name.is_some() || security_capability.is_some()
        {
            return Err(ArchiveError::InvalidRootEntry);
        }
        if !matches!(type_bits, 0 | MODE_TYPE_DIRECTORY) {
            return Err(ArchiveError::InvalidMetadata);
        }
        return Ok(AdmittedEntry {
            path,
            kind: AdmittedKind::Directory,
            security_capability,
            size,
            mode,
            uid: uid as u32,
            gid: gid as u32,
            mtime: mtime as i64,
        });
    }

    if let Some(whiteout) = classify_whiteout(&path)? {
        if !entry_type.is_file()
            || size != 0
            || link_name.is_some()
            || security_capability.is_some()
        {
            return Err(ArchiveError::InvalidWhiteout);
        }
        if !matches!(type_bits, 0 | MODE_TYPE_REGULAR) {
            return Err(ArchiveError::InvalidMetadata);
        }
        return Ok(AdmittedEntry {
            path,
            kind: AdmittedKind::Whiteout(whiteout),
            security_capability,
            size,
            mode,
            uid: uid as u32,
            gid: gid as u32,
            mtime: mtime as i64,
        });
    }

    let kind = if entry_type.is_file() {
        if link_name.is_some() {
            return Err(ArchiveError::InvalidMetadata);
        }
        AdmittedKind::Regular
    } else if entry_type.is_dir() {
        if size != 0 || link_name.is_some() {
            return Err(ArchiveError::InvalidMetadata);
        }
        AdmittedKind::Directory
    } else if entry_type.is_symlink() {
        if size != 0 {
            return Err(ArchiveError::InvalidMetadata);
        }
        let target = link_name.ok_or(ArchiveError::InvalidMetadata)?;
        validate_symlink_target(&target)?;
        AdmittedKind::Symlink(target)
    } else if entry_type.is_hard_link() {
        if size != 0 {
            return Err(ArchiveError::InvalidMetadata);
        }
        let target =
            normalize_link_path(link_name.as_deref().ok_or(ArchiveError::InvalidMetadata)?)?;
        if target == path {
            return Err(ArchiveError::InvalidMetadata);
        }
        AdmittedKind::Hardlink(target)
    } else {
        return Err(ArchiveError::UnsupportedEntryType);
    };
    if security_capability.is_some()
        && !matches!(&kind, AdmittedKind::Regular | AdmittedKind::Hardlink(_))
    {
        return Err(ArchiveError::InvalidXattr);
    }
    let kind_type_bits = match &kind {
        AdmittedKind::Directory => MODE_TYPE_DIRECTORY,
        AdmittedKind::Symlink(_) => MODE_TYPE_SYMLINK,
        // A hard link's header is its target's: a regular file.
        AdmittedKind::Regular | AdmittedKind::Hardlink(_) | AdmittedKind::Whiteout(_) => {
            MODE_TYPE_REGULAR
        }
    };
    if type_bits != 0 && type_bits != kind_type_bits {
        return Err(ArchiveError::InvalidMetadata);
    }

    Ok(AdmittedEntry {
        path,
        kind,
        security_capability,
        size,
        mode,
        uid: uid as u32,
        gid: gid as u32,
        mtime: mtime as i64,
    })
}

fn validate_pax<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    size: u64,
    uid: u64,
    gid: u64,
) -> Result<Option<Vec<u8>>, ArchiveError> {
    let Some(extensions) = entry
        .pax_extensions()
        .map_err(|_| ArchiveError::InvalidPax)?
    else {
        return Ok(None);
    };
    let mut keys = HashSet::new();
    let mut security_capability = None;
    for extension in extensions {
        let extension = extension.map_err(|_| ArchiveError::InvalidPax)?;
        let key = extension.key_bytes();
        let value = extension.value_bytes();
        if key.is_empty()
            || key.len() > 128
            || key.iter().any(|byte| !byte.is_ascii_graphic())
            || !keys.insert(key.to_vec())
        {
            return Err(ArchiveError::InvalidPax);
        }
        match key {
            b"path" | b"linkpath" => validate_path_metadata_value(value)?,
            b"uname" | b"gname" | b"comment" | b"charset" => {
                validate_metadata_value(value)?;
            }
            b"size" if parse_decimal(value)? == size => {}
            b"uid" if parse_decimal(value)? == uid => {}
            b"gid" if parse_decimal(value)? == gid => {}
            b"mtime" | b"atime" | b"ctime" if valid_decimal_timestamp(value) => {}
            _ if key.strip_prefix(SCHILY_XATTR_PREFIX) == Some(SECURITY_CAPABILITY_XATTR) => {
                security_capability = Some(validate_security_capability(value)?);
            }
            _ if key.starts_with(SCHILY_XATTR_PREFIX) || key.starts_with(b"LIBARCHIVE.xattr.") => {
                return Err(ArchiveError::UnsupportedXattr);
            }
            _ if key.starts_with(b"GNU.sparse.") => {
                return Err(ArchiveError::UnsupportedSparse);
            }
            _ => return Err(ArchiveError::UnsupportedPax),
        }
    }
    Ok(security_capability)
}

fn validate_security_capability(value: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let magic_bytes: [u8; 4] = value
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArchiveError::InvalidXattr)?;
    let magic = u32::from_le_bytes(magic_bytes);
    let expected_bytes = match magic & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_1 => VFS_CAP_REVISION_1_BYTES,
        VFS_CAP_REVISION_2 => VFS_CAP_REVISION_2_BYTES,
        _ => return Err(ArchiveError::InvalidXattr),
    };
    if value.len() != expected_bytes
        || magic & !(VFS_CAP_REVISION_MASK | VFS_CAP_FLAGS_EFFECTIVE) != 0
    {
        return Err(ArchiveError::InvalidXattr);
    }
    if expected_bytes == VFS_CAP_REVISION_2_BYTES {
        let permitted_high = u32::from_le_bytes(
            value[12..16]
                .try_into()
                .map_err(|_| ArchiveError::InvalidXattr)?,
        );
        let inheritable_high = u32::from_le_bytes(
            value[16..20]
                .try_into()
                .map_err(|_| ArchiveError::InvalidXattr)?,
        );
        if permitted_high & !VFS_CAP_REVISION_2_HIGH_VALID_MASK != 0
            || inheritable_high & !VFS_CAP_REVISION_2_HIGH_VALID_MASK != 0
        {
            return Err(ArchiveError::InvalidXattr);
        }
    }
    Ok(value.to_vec())
}

fn validate_path_metadata_value(value: &[u8]) -> Result<(), ArchiveError> {
    if value.len() > MAX_PATH_BYTES || value.contains(&0) {
        return Err(ArchiveError::InvalidPax);
    }
    Ok(())
}

fn validate_metadata_value(value: &[u8]) -> Result<(), ArchiveError> {
    if value.len() > MAX_PATH_BYTES
        || value
            .iter()
            .any(|byte| *byte == 0 || byte.is_ascii_control())
    {
        return Err(ArchiveError::InvalidPax);
    }
    Ok(())
}

fn parse_decimal(value: &[u8]) -> Result<u64, ArchiveError> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(ArchiveError::InvalidPax);
    }
    value.iter().try_fold(0_u64, |number, byte| {
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(*byte - b'0')))
            .ok_or(ArchiveError::InvalidPax)
    })
}

fn valid_decimal_timestamp(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut digits = 0_usize;
    let mut points = 0_usize;
    for (index, byte) in value.iter().enumerate() {
        if byte.is_ascii_digit() {
            digits += 1;
        } else if *byte == b'.' {
            points += 1;
        } else if *byte != b'-' || index != 0 {
            return false;
        }
    }
    digits > 0 && points <= 1
}

fn normalize_entry_path(path: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    normalize_path(path, true)
}

fn normalize_link_path(path: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    normalize_path(path, false)
}

fn normalize_path(path: &[u8], allow_root: bool) -> Result<Vec<u8>, ArchiveError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(ArchiveError::PathLengthLimit);
    }
    if path.first() == Some(&b'/') {
        return Err(ArchiveError::AbsolutePath);
    }
    if path.contains(&0) {
        return Err(ArchiveError::NulPathByte);
    }
    let mut normalized = Vec::with_capacity(path.len());
    let mut components = path.split(|byte| *byte == b'/').peekable();
    let mut component_count = 0_usize;
    while let Some(component) = components.next() {
        if component.is_empty() {
            if components.peek().is_none() {
                continue;
            }
            return Err(ArchiveError::EmptyPathComponent);
        }
        if component == b"." {
            continue;
        }
        if component == b".." {
            return Err(ArchiveError::ParentPathComponent);
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(ArchiveError::PathComponentLengthLimit);
        }
        component_count = component_count
            .checked_add(1)
            .filter(|count| *count <= MAX_PATH_COMPONENTS)
            .ok_or(ArchiveError::PathComponentLimit)?;
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(component);
    }
    if normalized.is_empty() && !allow_root {
        return Err(ArchiveError::EmptyLinkPath);
    }
    Ok(normalized)
}

fn validate_symlink_target(target: &[u8]) -> Result<(), ArchiveError> {
    if target.is_empty() {
        return Err(ArchiveError::EmptySymlinkTarget);
    }
    if target.len() > MAX_PATH_BYTES {
        return Err(ArchiveError::PathLengthLimit);
    }
    if target.contains(&0) {
        return Err(ArchiveError::NulSymlinkTarget);
    }
    Ok(())
}

fn classify_whiteout(path: &[u8]) -> Result<Option<Whiteout>, ArchiveError> {
    let (parent, basename) = match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (&[][..], path),
    };
    if parent
        .split(|byte| *byte == b'/')
        .any(|component| component.starts_with(b".wh."))
    {
        return Err(ArchiveError::InvalidWhiteout);
    }
    if !basename.starts_with(b".wh.") {
        return Ok(None);
    }
    if basename == b".wh..wh..opq" {
        return Ok(Some(Whiteout::Opaque(parent.to_vec())));
    }
    let target = &basename[b".wh.".len()..];
    if target.is_empty() || target.starts_with(b".wh.") {
        return Err(ArchiveError::InvalidWhiteout);
    }
    let mut removed = parent.to_vec();
    if !removed.is_empty() {
        removed.push(b'/');
    }
    removed.extend_from_slice(target);
    Ok(Some(Whiteout::Remove(removed)))
}

#[derive(Default)]
struct ReadState {
    metadata_remaining: Cell<Option<u64>>,
    metadata_exceeded: Cell<bool>,
    expansion_exceeded: Cell<bool>,
}

#[derive(Clone)]
struct MetadataControl(Rc<ReadState>);

impl MetadataControl {
    fn begin(&self) {
        self.0.metadata_remaining.set(Some(MAX_METADATA_READ_BYTES));
    }

    fn end(&self) {
        self.0.metadata_remaining.set(None);
    }
}

struct MetadataBudgetReader<R> {
    inner: R,
    state: Rc<ReadState>,
}

impl<R> MetadataBudgetReader<R> {
    fn new(inner: R, state: Rc<ReadState>) -> Self {
        Self { inner, state }
    }

    fn control(&self) -> MetadataControl {
        MetadataControl(Rc::clone(&self.state))
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for MetadataBudgetReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = self.state.metadata_remaining.get() else {
            return self.inner.read(buffer);
        };
        if remaining == 0 {
            self.state.metadata_exceeded.set(true);
            return Err(io::Error::other("tar metadata read limit exceeded"));
        }
        let allowed = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded tar metadata read fits usize");
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.state
            .metadata_remaining
            .set(Some(remaining - read as u64));
        Ok(read)
    }
}

struct BoundedDigestReader<R> {
    inner: R,
    maximum: u64,
    bytes: u64,
    digest: Sha256,
    state: Rc<ReadState>,
}

impl<R> BoundedDigestReader<R> {
    fn new(inner: R, maximum: u64, state: Rc<ReadState>) -> Self {
        Self {
            inner,
            maximum,
            bytes: 0,
            digest: Sha256::new(),
            state,
        }
    }

    fn finish(self) -> (Sha256Value, u64) {
        (
            Sha256Value::from_bytes(self.digest.finalize().into()),
            self.bytes,
        )
    }
}

impl<R: Read> Read for BoundedDigestReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.maximum - self.bytes;
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            if self.inner.read(&mut probe)? == 0 {
                return Ok(0);
            }
            self.state.expansion_exceeded.set(true);
            return Err(io::Error::other("tar expansion limit exceeded"));
        }
        let allowed = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded tar content read fits usize");
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.digest.update(&buffer[..read]);
        self.bytes += read as u64;
        Ok(read)
    }
}

fn classify_read_error(_error: io::Error, state: &ReadState) -> ArchiveError {
    if state.expansion_exceeded.get() {
        ArchiveError::ExpansionLimit
    } else if state.metadata_exceeded.get() {
        ArchiveError::MetadataReadLimit
    } else {
        ArchiveError::InvalidTar
    }
}

#[derive(Debug, Error)]
pub(crate) enum ArchiveError {
    #[error("setup layer exceeds its admitted expansion bound")]
    ExpansionLimit,
    #[error("setup tar extension metadata exceeds its read bound")]
    MetadataReadLimit,
    #[error("setup layer is not a valid supported tar archive")]
    InvalidTar,
    #[error("setup tar root path metadata is invalid")]
    InvalidRootEntry,
    #[error("setup tar path exceeds the admitted length bound")]
    PathLengthLimit,
    #[error("setup tar contains an absolute entry or hardlink path")]
    AbsolutePath,
    #[error("setup tar path contains a NUL byte")]
    NulPathByte,
    #[error("setup tar path contains an empty interior component")]
    EmptyPathComponent,
    #[error("setup tar path contains a parent component")]
    ParentPathComponent,
    #[error("setup tar path component exceeds the admitted length bound")]
    PathComponentLengthLimit,
    #[error("setup tar path exceeds the admitted component bound")]
    PathComponentLimit,
    #[error("setup tar hardlink path normalizes to the archive root")]
    EmptyLinkPath,
    #[error("setup tar symbolic link has an empty target")]
    EmptySymlinkTarget,
    #[error("setup tar symbolic link target contains a NUL byte")]
    NulSymlinkTarget,
    #[error("setup tar repeats a normalized path")]
    DuplicatePath,
    #[error("setup tar uses a non-directory entry as another entry's parent")]
    PathTypeConflict,
    #[error("setup tar contains invalid ownership, mode, time, size, or link metadata")]
    InvalidMetadata,
    #[error("setup tar contains malformed PAX metadata")]
    InvalidPax,
    #[error("setup tar contains unsupported or unsafe PAX metadata")]
    UnsupportedPax,
    #[error("setup tar contains unsupported extended attributes")]
    UnsupportedXattr,
    #[error("setup tar contains a malformed supported extended attribute")]
    InvalidXattr,
    #[error("setup tar contains unsupported sparse-file metadata")]
    UnsupportedSparse,
    #[error("setup tar contains an unsupported inode type")]
    UnsupportedEntryType,
    #[error("setup tar contains a malformed OCI whiteout")]
    InvalidWhiteout,
    #[error("setup tar exceeds the per-layer entry limit")]
    LayerEntryLimit,
    #[error("setup image exceeds the total entry limit")]
    ImageEntryLimit,
    #[error("setup tar exceeds its admitted path-memory budget")]
    PathBudgetLimit,
    #[error("setup image exceeds its retained OCI whiteout budget")]
    WhiteoutBudgetLimit,
    #[error("setup tar contains nonzero data after its end marker")]
    TrailingData,
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::Cursor;

    use super::*;

    struct EntryFixture<'a> {
        path: &'a [u8],
        kind: tar::EntryType,
        link: Option<&'a [u8]>,
        contents: &'a [u8],
    }

    fn header(entry: &EntryFixture<'_>) -> tar::Header {
        assert!(entry.path.len() <= 100);
        let mut header = tar::Header::new_ustar();
        let name = &mut header.as_old_mut().name;
        name.fill(0);
        name[..entry.path.len()].copy_from_slice(entry.path);
        header.set_entry_type(entry.kind);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(entry.contents.len() as u64);
        if let Some(link) = entry.link {
            header.set_link_name_literal(link).unwrap();
        }
        header.set_cksum();
        header
    }

    fn archive(entries: &[EntryFixture<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for entry in entries {
            builder
                .append(&header(entry), Cursor::new(entry.contents))
                .unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn pax_file(key: &str, value: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        builder.append_pax_extensions([(key, value)]).unwrap();
        let file = EntryFixture {
            path: b"file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"data",
        };
        builder
            .append(&header(&file), Cursor::new(file.contents))
            .unwrap();
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    /// An archive whose headers carry exactly these raw mode fields.
    fn archive_with_modes(entries: &[(EntryFixture<'_>, u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (entry, mode) in entries {
            let mut header = header(entry);
            header.set_mode(*mode);
            header.set_cksum();
            builder
                .append(&header, Cursor::new(entry.contents))
                .unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    /// Go's archive/tar wrote S_IFMT bits into the header mode, and older
    /// images carry them (#3326). Each is admitted only as the value that
    /// matches its typeflag, and only the permissions are kept.
    #[test]
    fn admits_file_type_mode_bits_that_match_the_typeflag() {
        let fixture = |path, kind, link, contents| EntryFixture {
            path,
            kind,
            link,
            contents,
        };
        let bytes = archive_with_modes(&[
            (
                fixture(b"bin", tar::EntryType::Directory, None, b""),
                0o040_755,
            ),
            (
                fixture(b"bin/busybox", tar::EntryType::Regular, None, b"elf"),
                0o100_755,
            ),
            (
                fixture(
                    b"bin/sh",
                    tar::EntryType::Symlink,
                    Some(b"/bin/busybox"),
                    b"",
                ),
                0o120_777,
            ),
            (
                fixture(b"bin/ash", tar::EntryType::Link, Some(b"bin/busybox"), b""),
                0o100_755,
            ),
            (fixture(b"etc", tar::EntryType::Directory, None, b""), 0o755),
            (
                fixture(b"etc/.wh.old", tar::EntryType::Regular, None, b""),
                0o100_644,
            ),
        ]);
        let scanned = scan(&bytes).unwrap();
        let mut collector = Collector::default();
        replay_tar(
            &mut Cursor::new(bytes),
            scanned.digest,
            scanned.bytes,
            &scanned.plan,
            &mut collector,
        )
        .unwrap();
        // The whiteout is admitted but planned, not replayed.
        assert_eq!(collector.modes, vec![0o755, 0o755, 0o777, 0o755, 0o755]);

        for (entry, mode) in [
            // Type bits that disagree with the typeflag.
            (
                fixture(b"file", tar::EntryType::Regular, None, b""),
                0o040_644,
            ),
            (
                fixture(b"dir", tar::EntryType::Directory, None, b""),
                0o100_755,
            ),
            (
                fixture(b"link", tar::EntryType::Symlink, Some(b"target"), b""),
                0o100_777,
            ),
            (
                fixture(b".wh.gone", tar::EntryType::Regular, None, b""),
                0o120_644,
            ),
            // Bits that are no file type tar can carry.
            (
                fixture(b"file", tar::EntryType::Regular, None, b""),
                0o020_644,
            ),
            (
                fixture(b"file", tar::EntryType::Regular, None, b""),
                0o140_644,
            ),
            (
                fixture(b"file", tar::EntryType::Regular, None, b""),
                0o1_100_644,
            ),
        ] {
            assert!(
                matches!(
                    scan(&archive_with_modes(&[(entry, mode)])),
                    Err(ArchiveError::InvalidMetadata)
                ),
                "{mode:o}"
            );
        }
    }

    fn scan(bytes: &[u8]) -> Result<ScannedTar, ArchiveError> {
        scan_tar(
            &mut Cursor::new(bytes),
            bytes.len() as u64 + 1,
            &mut TarImageBudget::default(),
        )
    }

    #[derive(Default)]
    struct Collector {
        paths: Vec<Vec<u8>>,
        payloads: Vec<Vec<u8>>,
        modes: Vec<u32>,
    }

    impl EntryConsumer for Collector {
        type Error = Infallible;

        fn consume(
            &mut self,
            entry: &AdmittedEntry,
            data: &mut dyn Read,
        ) -> Result<(), Self::Error> {
            let mut payload = Vec::new();
            data.read_to_end(&mut payload).unwrap();
            self.paths.push(entry.path().to_vec());
            self.payloads.push(payload);
            self.modes.push(entry.mode());
            Ok(())
        }
    }

    #[test]
    fn admits_supported_entries_and_collects_order_independent_whiteouts() {
        let bytes = archive(&[
            EntryFixture {
                path: b"./a/new",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"new",
            },
            EntryFixture {
                path: b"a/link",
                kind: tar::EntryType::Symlink,
                link: Some(b"../target"),
                contents: b"",
            },
            EntryFixture {
                path: b"a/hard",
                kind: tar::EntryType::Link,
                link: Some(b"a/new"),
                contents: b"",
            },
            EntryFixture {
                path: b"a/.wh.old",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
            EntryFixture {
                path: b"a/.wh..wh..opq",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
        ]);
        let scanned = scan(&bytes).unwrap();
        assert_eq!(scanned.bytes, bytes.len() as u64);
        assert_eq!(scanned.digest, Sha256Value::calculate(&bytes));
        assert_eq!(scanned.plan.entries(), 5);
        assert_eq!(
            scanned.plan.whiteouts(),
            &[
                Whiteout::Remove(b"a/old".to_vec()),
                Whiteout::Opaque(b"a".to_vec()),
            ]
        );
        assert!(!format!("{scanned:?}").contains("a/old"));
    }

    #[test]
    fn rejects_duplicate_and_escaping_paths_and_hardlinks() {
        let duplicate = archive(&[
            EntryFixture {
                path: b"same",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"one",
            },
            EntryFixture {
                path: b"./same",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"two",
            },
        ]);
        assert!(matches!(scan(&duplicate), Err(ArchiveError::DuplicatePath)));

        for (path, expected) in [
            (&b"../escape"[..], ArchiveError::ParentPathComponent),
            (&b"/absolute"[..], ArchiveError::AbsolutePath),
            (&b"double//slash"[..], ArchiveError::EmptyPathComponent),
        ] {
            let bytes = archive(&[EntryFixture {
                path,
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"escape",
            }]);
            assert_eq!(
                std::mem::discriminant(&scan(&bytes).unwrap_err()),
                std::mem::discriminant(&expected)
            );
        }

        let hardlink = archive(&[EntryFixture {
            path: b"hard",
            kind: tar::EntryType::Link,
            link: Some(b"../../outside"),
            contents: b"",
        }]);
        assert!(matches!(
            scan(&hardlink),
            Err(ArchiveError::ParentPathComponent)
        ));

        let self_hardlink = archive(&[EntryFixture {
            path: b"hard",
            kind: tar::EntryType::Link,
            link: Some(b"./hard"),
            contents: b"",
        }]);
        assert!(matches!(
            scan(&self_hardlink),
            Err(ArchiveError::InvalidMetadata)
        ));

        assert!(matches!(
            normalize_entry_path(b"nul\0name"),
            Err(ArchiveError::NulPathByte)
        ));
        assert!(matches!(
            validate_symlink_target(b"nul\0target"),
            Err(ArchiveError::NulSymlinkTarget)
        ));

        for entries in [
            [
                EntryFixture {
                    path: b"link",
                    kind: tar::EntryType::Symlink,
                    link: Some(b"target"),
                    contents: b"",
                },
                EntryFixture {
                    path: b"link/child",
                    kind: tar::EntryType::Regular,
                    link: None,
                    contents: b"escape",
                },
            ],
            [
                EntryFixture {
                    path: b"file/child",
                    kind: tar::EntryType::Regular,
                    link: None,
                    contents: b"child",
                },
                EntryFixture {
                    path: b"file",
                    kind: tar::EntryType::Regular,
                    link: None,
                    contents: b"parent",
                },
            ],
        ] {
            assert!(matches!(
                scan(&archive(&entries)),
                Err(ArchiveError::PathTypeConflict)
            ));
        }
    }

    #[test]
    fn admits_linux_filename_bytes_without_exposing_them_in_debug_output() {
        let bytes = archive(&[
            EntryFixture {
                path: b"back\\slash",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"backslash",
            },
            EntryFixture {
                path: b"control\nname",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"control",
            },
            EntryFixture {
                path: b"link",
                kind: tar::EntryType::Symlink,
                link: Some(b"control\ntarget"),
                contents: b"",
            },
        ]);
        let scanned = scan(&bytes).unwrap();
        let debug = format!("{scanned:?}");
        assert!(!debug.contains("back\\\\slash"));
        assert!(!debug.contains("control"));

        let mut collector = Collector::default();
        replay_tar(
            &mut Cursor::new(bytes),
            scanned.digest,
            scanned.bytes,
            &scanned.plan,
            &mut collector,
        )
        .unwrap();
        assert_eq!(
            collector.paths,
            vec![
                b"back\\slash".to_vec(),
                b"control\nname".to_vec(),
                b"link".to_vec()
            ]
        );
    }

    #[test]
    fn rejects_special_files_malformed_whiteouts_and_unsafe_pax() {
        for kind in [
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
            tar::EntryType::Continuous,
            tar::EntryType::GNUSparse,
        ] {
            let bytes = archive(&[EntryFixture {
                path: b"special",
                kind,
                link: None,
                contents: b"",
            }]);
            assert!(matches!(
                scan(&bytes),
                Err(ArchiveError::UnsupportedEntryType) | Err(ArchiveError::InvalidTar)
            ));
        }

        for (path, contents) in [(&b".wh."[..], &b""[..]), (&b".wh.file"[..], &b"x"[..])] {
            let bytes = archive(&[EntryFixture {
                path,
                kind: tar::EntryType::Regular,
                link: None,
                contents,
            }]);
            assert!(matches!(scan(&bytes), Err(ArchiveError::InvalidWhiteout)));
        }

        let nested_whiteout_name = archive(&[EntryFixture {
            path: b".wh.parent/child",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"data",
        }]);
        assert!(matches!(
            scan(&nested_whiteout_name),
            Err(ArchiveError::InvalidWhiteout)
        ));

        let mut capability = [0_u8; VFS_CAP_REVISION_2_BYTES];
        capability[..4]
            .copy_from_slice(&(VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE).to_le_bytes());
        capability[4..8].copy_from_slice(&(1_u32 << 13).to_le_bytes());
        let capability_archive =
            pax_file("SCHILY.xattr.security.capability", capability.as_slice());
        let scanned = scan(&capability_archive).unwrap();
        assert!(!format!("{scanned:?}").contains("capability"));

        assert!(matches!(
            scan(&pax_file(
                "SCHILY.xattr.security.capability",
                b"attacker-controlled"
            )),
            Err(ArchiveError::InvalidXattr)
        ));
        assert!(matches!(
            scan(&pax_file("SCHILY.xattr.trusted.overlay.opaque", b"y")),
            Err(ArchiveError::UnsupportedXattr)
        ));

        capability[12..16].copy_from_slice(&0x200_u32.to_le_bytes());
        assert!(matches!(
            validate_security_capability(&capability),
            Err(ArchiveError::InvalidXattr)
        ));
    }

    #[test]
    fn bounds_extension_reads_and_rejects_nonzero_trailing_data() {
        let long_name = vec![b'a'; MAX_METADATA_READ_BYTES as usize];
        let metadata = EntryFixture {
            path: b"././@LongLink",
            kind: tar::EntryType::GNULongName,
            link: None,
            contents: &long_name,
        };
        let file = EntryFixture {
            path: b"placeholder",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"data",
        };
        assert!(matches!(
            scan(&archive(&[metadata, file])),
            Err(ArchiveError::MetadataReadLimit)
        ));

        let mut trailing = archive(&[EntryFixture {
            path: b"file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"data",
        }]);
        trailing.extend_from_slice(b"nonzero after tar end");
        assert!(matches!(scan(&trailing), Err(ArchiveError::TrailingData)));
    }

    #[test]
    fn image_wide_entry_and_path_budgets_fail_closed() {
        let bytes = archive(&[EntryFixture {
            path: b"file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"data",
        }]);
        let mut entries = TarImageBudget {
            entries: MAX_IMAGE_ENTRIES,
            path_bytes: 0,
            ..TarImageBudget::default()
        };
        assert!(matches!(
            scan_tar(
                &mut Cursor::new(&bytes),
                bytes.len() as u64 + 1,
                &mut entries
            ),
            Err(ArchiveError::ImageEntryLimit)
        ));

        let mut paths = TarImageBudget {
            entries: 0,
            path_bytes: MAX_IMAGE_PATH_BYTES,
            ..TarImageBudget::default()
        };
        assert!(matches!(
            scan_tar(&mut Cursor::new(&bytes), bytes.len() as u64 + 1, &mut paths),
            Err(ArchiveError::PathBudgetLimit)
        ));

        let whiteout = archive(&[EntryFixture {
            path: b".wh.file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"",
        }]);
        let mut whiteouts = TarImageBudget {
            whiteouts: MAX_IMAGE_WHITEOUTS,
            ..TarImageBudget::default()
        };
        assert!(matches!(
            scan_tar(
                &mut Cursor::new(&whiteout),
                whiteout.len() as u64 + 1,
                &mut whiteouts
            ),
            Err(ArchiveError::WhiteoutBudgetLimit)
        ));
    }

    #[test]
    fn replay_consumes_only_normal_entries_and_rechecks_the_exact_stream() {
        let bytes = archive(&[
            EntryFixture {
                path: b"file",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"verified",
            },
            EntryFixture {
                path: b".wh.old",
                kind: tar::EntryType::Regular,
                link: None,
                contents: b"",
            },
        ]);
        let scanned = scan(&bytes).unwrap();
        let mut collector = Collector::default();
        replay_tar(
            &mut Cursor::new(&bytes),
            scanned.digest,
            scanned.bytes,
            &scanned.plan,
            &mut collector,
        )
        .unwrap();
        assert_eq!(collector.paths, vec![b"file".to_vec()]);
        assert_eq!(collector.payloads, vec![b"verified".to_vec()]);

        let mut changed = bytes.clone();
        changed[512] ^= 1;
        assert!(matches!(
            replay_tar(
                &mut Cursor::new(changed),
                scanned.digest,
                scanned.bytes,
                &scanned.plan,
                &mut Collector::default(),
            ),
            Err(ReplayError::Mismatch)
        ));
    }

    #[test]
    fn replay_rejects_a_consumer_that_leaves_entry_data() {
        struct DoesNotRead;

        impl EntryConsumer for DoesNotRead {
            type Error = Infallible;

            fn consume(
                &mut self,
                _entry: &AdmittedEntry,
                _data: &mut dyn Read,
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let bytes = archive(&[EntryFixture {
            path: b"file",
            kind: tar::EntryType::Regular,
            link: None,
            contents: b"unconsumed",
        }]);
        let scanned = scan(&bytes).unwrap();
        assert!(matches!(
            replay_tar(
                &mut Cursor::new(bytes),
                scanned.digest,
                scanned.bytes,
                &scanned.plan,
                &mut DoesNotRead,
            ),
            Err(ReplayError::EntryDataNotConsumed)
        ));
    }
}
