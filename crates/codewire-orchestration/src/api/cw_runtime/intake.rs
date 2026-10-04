//! Bounded server-owned intake. No incoming bytes are executed or exposed as
//! an effect until the same held regular file passes complete record admission.
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use codewire_cw_release::build_record;
use codewire_cw_release::identity::{Arch, CwPayloadIdentity, Os, Platform};
use codewire_server_core::AppResult;
use futures_util::{Stream, StreamExt as _};
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::model::{invalid_request, unavailable};
use super::wire::{MAX_CHUNK, validate_identity};

pub(super) const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CHUNKS: usize = 8192;
// This separate server executable owns the trusted compile-time marker. The
// shared scanner never embeds one, and clients cannot select/override it.
pub(super) const BUILD_MARKER: &[u8] = b"\0codewire-cw-build-record-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Directory {
    file: File,
    name: Option<std::ffi::OsString>,
    id: (u64, u64),
}

/// Held ancestry through the server's admitted temporary parent, plus one
/// exclusive owner-private leaf. Foreign writable ancestors are refused;
/// root-owned sticky01777 is the sole shared-parent exception.
pub(super) struct Candidate {
    directories: Vec<Directory>,
    path: PathBuf,
    file: File,
    stamp: Stamp,
    identity: CwPayloadIdentity,
}

fn owner_directory(metadata: &Metadata, private: bool) -> AppResult<()> {
    let uid = rustix::process::geteuid().as_raw();
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir()
        || !matches!(metadata.uid(), 0) && metadata.uid() != uid
        || (private && (metadata.uid() != uid || mode != 0o700))
        || (!private && mode & 0o022 != 0 && !(metadata.uid() == 0 && mode == 0o1777))
    {
        return Err(unavailable());
    }
    Ok(())
}

impl Candidate {
    fn create(parent: &Path, identity: CwPayloadIdentity) -> AppResult<Self> {
        validate_identity(&identity)?;
        if !parent.is_absolute() || parent.as_os_str().len() > 4096 {
            return Err(unavailable());
        }
        let names = parent
            .components()
            .filter_map(|v| match v {
                Component::Normal(n) => Some(Ok(n)),
                Component::RootDir => None,
                _ => Some(Err(unavailable())),
            })
            .collect::<AppResult<Vec<_>>>()?;
        if names.len() > 64 {
            return Err(unavailable());
        }
        let root = File::from(
            rfs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| unavailable())?,
        );
        let m = root.metadata().map_err(|_| unavailable())?;
        owner_directory(&m, false)?;
        let mut directories = vec![Directory {
            file: root,
            name: None,
            id: (m.dev(), m.ino()),
        }];
        for name in names {
            let file = File::from(
                rfs::openat(
                    &directories.last().ok_or_else(unavailable)?.file,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| unavailable())?,
            );
            let m = file.metadata().map_err(|_| unavailable())?;
            owner_directory(&m, false)?;
            directories.push(Directory {
                file,
                name: Some(name.to_owned()),
                id: (m.dev(), m.ino()),
            });
        }
        let name = std::ffi::OsString::from(format!("codewire-cw-runtime-{}", Uuid::new_v4()));
        let parent_file = &directories.last().ok_or_else(unavailable)?.file;
        rfs::mkdirat(parent_file, &name, Mode::from_raw_mode(0o700)).map_err(|_| unavailable())?;
        let leaf = File::from(
            rfs::openat(
                parent_file,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| unavailable())?,
        );
        let m = leaf.metadata().map_err(|_| unavailable())?;
        owner_directory(&m, true)?;
        directories.push(Directory {
            file: leaf,
            name: Some(name.clone()),
            id: (m.dev(), m.ino()),
        });
        let file = File::from(
            rfs::openat(
                &directories.last().ok_or_else(unavailable)?.file,
                "candidate.cw",
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| unavailable())?,
        );
        let stamp = Stamp::of(&file.metadata().map_err(|_| unavailable())?);
        let value = Self {
            directories,
            path: parent.join(name).join("candidate.cw"),
            file,
            stamp,
            identity,
        };
        value.check()?;
        Ok(value)
    }

    pub fn identity(&self) -> &CwPayloadIdentity {
        &self.identity
    }

    fn directories_unchanged(&self) -> AppResult<()> {
        for (index, directory) in self.directories.iter().enumerate() {
            let m = directory.file.metadata().map_err(|_| unavailable())?;
            owner_directory(&m, index + 1 == self.directories.len())?;
            if (m.dev(), m.ino()) != directory.id {
                return Err(unavailable());
            }
            if let Some(name) = &directory.name {
                let named = rfs::statat(
                    &self.directories[index - 1].file,
                    name,
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| unavailable())?;
                if (named.st_dev, named.st_ino) != directory.id
                    || named.st_uid != m.uid()
                    || named.st_gid != m.gid()
                    || named.st_mode != m.mode()
                {
                    return Err(unavailable());
                }
            }
        }
        Ok(())
    }

    pub fn check(&self) -> AppResult<()> {
        self.directories_unchanged()?;
        let metadata = self.file.metadata().map_err(|_| unavailable())?;
        let uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.gid() != rustix::process::getegid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > self.identity.size
            || Stamp::of(&metadata) != self.stamp
        {
            return Err(unavailable());
        }
        let named = rfs::statat(
            &self.directories.last().ok_or_else(unavailable)?.file,
            "candidate.cw",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| unavailable())?;
        if named.st_dev != metadata.dev()
            || named.st_ino != metadata.ino()
            || named.st_mode != metadata.mode()
            || named.st_uid != metadata.uid()
            || named.st_gid != metadata.gid()
            || named.st_nlink != 1
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> AppResult<()> {
        self.check()?;
        if bytes.is_empty()
            || bytes.len() > MAX_CHUNK
            || self
                .stamp
                .size
                .checked_add(bytes.len() as u64)
                .is_none_or(|v| v > self.identity.size)
        {
            return Err(invalid_request());
        }
        self.file.write_all(bytes).map_err(|_| unavailable())?;
        self.stamp = Stamp::of(&self.file.metadata().map_err(|_| unavailable())?);
        self.check()
    }

    fn admit(mut self, hash: String) -> AppResult<Self> {
        self.check()?;
        if self.stamp.size != self.identity.size || hash != self.identity.sha256 {
            return Err(invalid_request());
        }
        self.file.sync_all().map_err(|_| unavailable())?;
        build_record::admit_incoming(
            &mut self.file,
            &self.path,
            &self.identity,
            Platform::new(Os::Linux, Arch::X86_64),
            BUILD_MARKER,
        )
        .map_err(|_| invalid_request())?;
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| unavailable())?;
        Ok(self)
    }

    pub fn rewind(&mut self) -> AppResult<()> {
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| unavailable())?;
        Ok(())
    }

    pub fn read_chunk(&mut self) -> AppResult<Vec<u8>> {
        self.check()?;
        let mut bytes = vec![0; MAX_CHUNK];
        let count = self.file.read(&mut bytes).map_err(|_| unavailable())?;
        bytes.truncate(count);
        self.check()?;
        Ok(bytes)
    }
}

impl Drop for Candidate {
    fn drop(&mut self) {
        // Never broad-remove a tree or use a replaced name to manufacture
        // custody. Unknown/foreign members leave the exact scratch retained.
        if self.check().is_err() {
            return;
        }
        let Some(leaf) = self.directories.last() else {
            return;
        };
        if rfs::unlinkat(&leaf.file, "candidate.cw", AtFlags::empty()).is_err() {
            return;
        }
        if self.directories_unchanged().is_err() {
            return;
        }
        let Some(parent) = self.directories.get(self.directories.len() - 2) else {
            return;
        };
        if let Some(name) = &leaf.name {
            let _ = rfs::unlinkat(&parent.file, name, AtFlags::REMOVEDIR);
        }
    }
}

pub(super) async fn receive<S>(identity: CwPayloadIdentity, mut stream: S) -> AppResult<Candidate>
where
    S: Stream<Item = AppResult<Vec<u8>>> + Unpin,
{
    receive_in(&std::env::temp_dir(), identity, &mut stream).await
}

async fn receive_in<S>(
    parent: &Path,
    identity: CwPayloadIdentity,
    stream: &mut S,
) -> AppResult<Candidate>
where
    S: Stream<Item = AppResult<Vec<u8>>> + Unpin,
{
    validate_identity(&identity)?;
    let mut candidate = Candidate::create(parent, identity)?;
    let mut hash = Sha256::new();
    let mut chunks = 0;
    let deadline = tokio::time::Instant::now() + UPLOAD_TIMEOUT;
    while let Some(next) = tokio::time::timeout_at(deadline, stream.next())
        .await
        .map_err(|_| invalid_request())?
    {
        let bytes = next?;
        chunks += 1;
        if chunks > MAX_CHUNKS {
            return Err(invalid_request());
        }
        candidate.write(&bytes)?;
        hash.update(&bytes);
    }
    candidate.admit(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
#[path = "intake_tests.rs"]
mod tests;
