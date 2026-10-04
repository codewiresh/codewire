//! Held owner/name/FD custody for the fixed ordinary-user runtime paths.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{self as rfs, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};

use super::wire::{Code, Correlation, MAX_JSON};
use super::{LOCK_BUDGET, Result, user};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileId {
    device: u64,
    inode: u64,
}

impl FileId {
    pub(super) fn of(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(|_| Code::Io)?;
        Ok(Self::metadata(&m))
    }

    fn metadata(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
        }
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct Stamp {
    id: FileId,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    pub(super) fn of(file: &File) -> Result<Self> {
        Ok(Self::metadata(&file.metadata().map_err(|_| Code::Io)?))
    }

    fn metadata(m: &fs::Metadata) -> Self {
        Self {
            id: FileId::metadata(m),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            size: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

pub(super) struct HeldFile {
    file: File,
    path: PathBuf,
    before: Stamp,
}

impl HeldFile {
    pub(super) fn open(path: &Path, maximum: u64, mode: u32) -> Result<Self> {
        let file = File::from(
            rfs::open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Code::UnsafeState)?,
        );
        Self::admit(file, path.to_owned(), maximum, mode)
    }

    fn admit(file: File, path: PathBuf, maximum: u64, mode: u32) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| Code::Io)?;
        if !metadata.is_file()
            || metadata.uid() != user().0
            || metadata.gid() != user().1
            || metadata.nlink() != 1
            || metadata.len() > maximum
            || metadata.mode() & 0o7777 != mode
        {
            return Err(Code::UnsafeState);
        }
        let held = Self {
            file,
            path,
            before: Stamp::metadata(&metadata),
        };
        held.check()?;
        Ok(held)
    }

    pub(super) fn check(&self) -> Result<()> {
        let named = fs::symlink_metadata(&self.path).map_err(|_| Code::UnsafeState)?;
        if !named.is_file()
            || Stamp::metadata(&named) != self.before
            || Stamp::of(&self.file)? != self.before
        {
            return Err(Code::UnsafeState);
        }
        Ok(())
    }

    pub(super) fn id(&self) -> Result<FileId> {
        FileId::of(&self.file)
    }
    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    #[cfg(test)]
    pub(super) fn into_file(self) -> File {
        self.file
    }
}

struct Anchor {
    file: File,
    path: PathBuf,
    id: FileId,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Anchor {
    fn new(file: File, path: PathBuf, owner_only: bool) -> Result<Self> {
        let m = file.metadata().map_err(|_| Code::Io)?;
        if !m.is_dir()
            || (m.uid() != user().0 && (owner_only || m.uid() != 0))
            || m.mode() & 0o7022 != 0
            || m.mode() & 0o500 != 0o500
        {
            return Err(Code::UnsafeState);
        }
        let anchor = Self {
            id: FileId::metadata(&m),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            file,
            path,
        };
        anchor.check()?;
        Ok(anchor)
    }

    fn check(&self) -> Result<()> {
        let held = self.file.metadata().map_err(|_| Code::Io)?;
        let named = fs::symlink_metadata(&self.path).map_err(|_| Code::UnsafeState)?;
        for m in [&held, &named] {
            if !m.is_dir()
                || FileId::metadata(m) != self.id
                || m.uid() != self.uid
                || m.gid() != self.gid
                || m.mode() != self.mode
            {
                return Err(Code::UnsafeState);
            }
        }
        Ok(())
    }

    fn copy(&self) -> Result<Self> {
        self.check()?;
        Ok(Self {
            file: self.file.try_clone().map_err(|_| Code::Io)?,
            path: self.path.clone(),
            id: self.id,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
        })
    }
}

pub(super) struct Dir {
    ancestors: Vec<Anchor>,
    own: Anchor,
}

impl Dir {
    fn home(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path.components().count() > 64 {
            return Err(Code::UnsafeState);
        }
        let file =
            File::from(rfs::open("/", dir_flags(), Mode::empty()).map_err(|_| Code::UnsafeState)?);
        let mut dir = Self {
            ancestors: Vec::new(),
            own: Anchor::new(file, PathBuf::from("/"), false)?,
        };
        let mut parts = path.components().peekable();
        if parts.next() != Some(Component::RootDir) {
            return Err(Code::UnsafeState);
        }
        while let Some(part) = parts.next() {
            let Component::Normal(name) = part else {
                return Err(Code::UnsafeState);
            };
            let name = name.to_str().ok_or(Code::UnsafeState)?;
            dir = dir
                .child_inner(name, false, parts.peek().is_none())?
                .ok_or(Code::UnsafeState)?;
        }
        if dir.own.uid != user().0 {
            return Err(Code::UnsafeState);
        }
        Ok(dir)
    }

    pub(super) fn path(&self) -> &Path {
        &self.own.path
    }
    pub(super) fn id(&self) -> Result<FileId> {
        self.check(false)?;
        Ok(self.own.id)
    }

    pub(super) fn check(&self, writable: bool) -> Result<()> {
        for parent in &self.ancestors {
            parent.check()?
        }
        self.own.check()?;
        if writable && (self.own.uid != user().0 || self.own.mode & 0o200 == 0) {
            return Err(Code::ReadOnly);
        }
        Ok(())
    }

    fn exact_private(&self) -> Result<()> {
        self.check(false)?;
        if self.own.uid != user().0 || self.own.gid != user().1 || self.own.mode & 0o7777 != 0o700 {
            return Err(Code::UnsafeState);
        }
        Ok(())
    }

    fn child(&self, name: &str, create: bool) -> Result<Option<Self>> {
        self.child_inner(name, create, true)
    }

    fn child_inner(&self, name: &str, create: bool, owner_only: bool) -> Result<Option<Self>> {
        basename(name)?;
        self.check(create)?;
        if create {
            match rfs::mkdirat(&self.own.file, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => self.own.file.sync_all().map_err(|_| Code::Io)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(Code::Io),
            }
        }
        let file = match rfs::openat(&self.own.file, name, dir_flags(), Mode::empty()) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(_) => return Err(Code::UnsafeState),
        };
        let mut ancestors = self
            .ancestors
            .iter()
            .map(Anchor::copy)
            .collect::<Result<Vec<_>>>()?;
        ancestors.push(self.own.copy()?);
        let own = Anchor::new(file, self.path().join(name), owner_only)?;
        let child = Self { ancestors, own };
        child.check(false)?;
        Ok(Some(child))
    }

    fn new_child(&self, name: &str) -> Result<Self> {
        basename(name)?;
        self.exact_private()?;
        self.check(true)?;
        rfs::mkdirat(&self.own.file, name, Mode::from_raw_mode(0o700)).map_err(|e| {
            if e == rustix::io::Errno::EXIST {
                Code::StageExists
            } else {
                Code::Io
            }
        })?;
        self.own.file.sync_all().map_err(|_| Code::Io)?;
        self.child(name, false)?.ok_or(Code::UnsafeState)
    }

    pub(super) fn create_file(&self, name: &str, mode: u32) -> Result<File> {
        basename(name)?;
        self.check(true)?;
        let file = File::from(
            rfs::openat(
                &self.own.file,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(mode),
            )
            .map_err(|e| {
                if e == rustix::io::Errno::EXIST {
                    Code::StageExists
                } else {
                    Code::Io
                }
            })?,
        );
        let m = file.metadata().map_err(|_| Code::Io)?;
        if !m.is_file()
            || m.uid() != user().0
            || m.gid() != user().1
            || m.nlink() != 1
            || m.mode() & 0o7777 != mode
        {
            return Err(Code::UnsafeState);
        }
        self.check(false)?;
        Ok(file)
    }

    pub(super) fn held_file(&self, name: &str, maximum: u64, mode: u32) -> Result<HeldFile> {
        basename(name)?;
        self.check(false)?;
        let file = File::from(
            rfs::openat(
                &self.own.file,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Code::UnsafeState)?,
        );
        let held = HeldFile::admit(file, self.path().join(name), maximum, mode)?;
        self.check(false)?;
        Ok(held)
    }

    fn optional_file(&self, name: &str, maximum: u64, mode: u32) -> Result<Option<HeldFile>> {
        basename(name)?;
        self.check(false)?;
        match rfs::statat(&self.own.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => self.held_file(name, maximum, mode).map(Some),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(_) => Err(Code::UnsafeState),
        }
    }

    pub(super) fn read(&self, name: &str, maximum: usize, mode: u32) -> Result<Vec<u8>> {
        let mut held = self.held_file(name, maximum as u64, mode)?;
        let mut bytes = Vec::new();
        held.file_mut()
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Code::Io)?;
        held.check()?;
        self.check(false)?;
        if bytes.len() > maximum {
            return Err(Code::UnsafeState);
        }
        Ok(bytes)
    }

    pub(super) fn atomic_json<T: serde::Serialize>(
        &self,
        name: &str,
        temp: &str,
        value: &T,
    ) -> Result<()> {
        let bytes =
            codewire_cw_release::identity::canonical_json(value).map_err(|_| Code::UnsafeState)?;
        if bytes.len() > MAX_JSON {
            return Err(Code::UnsafeState);
        }
        let previous = self.optional_file(name, MAX_JSON as u64, 0o400)?;
        let mut file = self.create_file(temp, 0o600)?;
        file.write_all(&bytes).map_err(|_| Code::Io)?;
        file.sync_all().map_err(|_| Code::Io)?;
        rfs::fchmod(&file, Mode::from_raw_mode(0o400)).map_err(|_| Code::Io)?;
        file.sync_all().map_err(|_| Code::Io)?;
        self.check(true)?;
        if let Some(previous) = previous {
            previous.check()?;
            rfs::renameat(&self.own.file, temp, &self.own.file, name).map_err(|_| Code::Io)?;
        } else {
            rfs::renameat_with(
                &self.own.file,
                temp,
                &self.own.file,
                name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| Code::UnsafeState)?;
        }
        self.own.file.sync_all().map_err(|_| Code::Io)?;
        self.check(false)
    }

    pub(super) fn finish_file(
        &self,
        pending: &str,
        ready: &str,
        file: &File,
        mode: u32,
    ) -> Result<()> {
        self.check(true)?;
        let before = self.held_file(
            pending,
            codewire_cw_release::identity::MAX_EXECUTABLE_BYTES,
            0o600,
        )?;
        if before.id()? != FileId::of(file)? {
            return Err(Code::UnsafeState);
        }
        before.check()?;
        rfs::fchmod(file, Mode::from_raw_mode(mode)).map_err(|_| Code::Io)?;
        file.sync_all().map_err(|_| Code::Io)?;
        rfs::renameat_with(
            &self.own.file,
            pending,
            &self.own.file,
            ready,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| Code::UnsafeState)?;
        self.own.file.sync_all().map_err(|_| Code::Io)?;
        self.check(false)
    }

    pub(super) fn require_inventory(&self, expected: &[&str]) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        self.check(false)?;
        // Intentional kernel FD seam: enumeration is of this held directory,
        // not a mutable pathname. Every eventual unlink is also openat-fenced.
        let entries = fs::read_dir(format!("/proc/self/fd/{}", self.own.file.as_raw_fd()))
            .map_err(|_| Code::Io)?;
        let mut found = Vec::new();
        for entry in entries {
            if found.len() >= 8 {
                return Err(Code::UnsafeState);
            }
            let entry = entry.map_err(|_| Code::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Code::UnsafeState)?;
            if !expected.contains(&name.as_str()) {
                return Err(Code::UnsafeState);
            }
            found.push(name);
        }
        if found.len() != expected.len() {
            return Err(Code::UnsafeState);
        }
        self.check(false)
    }

    pub(super) fn unlink_held(&self, name: &str, file: &HeldFile) -> Result<()> {
        self.check(true)?;
        if file.path != self.path().join(name) {
            return Err(Code::UnsafeState);
        }
        file.check()?;
        rfs::unlinkat(&self.own.file, name, AtFlags::empty()).map_err(|_| Code::Io)?;
        self.own.file.sync_all().map_err(|_| Code::Io)?;
        self.check(false)
    }
}

fn basename(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || matches!(name, "." | "..")
        || name.contains('/')
        || name.bytes().any(|b| b.is_ascii_control())
    {
        Err(Code::UnsafeState)
    } else {
        Ok(())
    }
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

#[derive(Clone)]
pub(super) struct Paths {
    home: PathBuf,
    pub(super) store: PathBuf,
    pub(super) entry: PathBuf,
}

impl Paths {
    pub(super) fn fixed() -> Self {
        Self::at(PathBuf::from("/home/codewire"))
    }
    fn at(home: PathBuf) -> Self {
        Self {
            store: home.join(".local/share/codewire/cli"),
            entry: home.join(".local/bin/cw"),
            home,
        }
    }
    #[cfg(test)]
    pub(super) fn fixture(home: &Path) -> Self {
        Self::at(home.to_owned())
    }
    #[cfg(test)]
    pub(super) fn home_for_test(&self) -> &Path {
        &self.home
    }
}

pub(super) struct Tree {
    home: Dir,
    local: Option<Dir>,
    bin: Option<Dir>,
    share: Option<Dir>,
    data: Option<Dir>,
    staging: Option<Dir>,
}

impl Tree {
    pub(super) fn open(paths: &Paths, create: bool) -> Result<Self> {
        let home = Dir::home(&paths.home)?;
        let local = home.child(".local", create)?;
        let bin = local
            .as_ref()
            .map(|d| d.child("bin", create))
            .transpose()?
            .flatten();
        let share = local
            .as_ref()
            .map(|d| d.child("share", create))
            .transpose()?
            .flatten();
        let data = share
            .as_ref()
            .map(|d| d.child("codewire", create))
            .transpose()?
            .flatten();
        let staging = data
            .as_ref()
            .map(|d| d.child("cw-runtime-staging", create))
            .transpose()?
            .flatten();
        if let Some(staging) = &staging {
            staging.exact_private()?
        }
        let tree = Self {
            home,
            local,
            bin,
            share,
            data,
            staging,
        };
        tree.check()?;
        Ok(tree)
    }

    pub(super) fn check(&self) -> Result<()> {
        for d in [
            Some(&self.home),
            self.local.as_ref(),
            self.bin.as_ref(),
            self.share.as_ref(),
            self.data.as_ref(),
            self.staging.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            d.check(false)?;
        }
        Ok(())
    }

    pub(super) fn require_writable_parents(&self) -> Result<()> {
        for d in [
            Some(&self.home),
            self.local.as_ref(),
            self.bin.as_ref(),
            self.share.as_ref(),
            self.data.as_ref(),
            self.staging.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            d.check(true)?;
        }
        if let Some(store) = self.store()? {
            store.check(true)?
        }
        Ok(())
    }

    pub(super) fn store(&self) -> Result<Option<Dir>> {
        self.data
            .as_ref()
            .map(|d| d.child("cli", false))
            .transpose()
            .map(Option::flatten)
    }

    pub(super) fn entry_present(&self) -> Result<bool> {
        let Some(bin) = &self.bin else {
            return Ok(false);
        };
        bin.check(false)?;
        match rfs::statat(&bin.own.file, "cw", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(Code::UnsafeState),
        }
    }

    fn lock(
        &self,
        create: bool,
        exclusive: bool,
        deadline: Instant,
    ) -> Result<Option<OperationLock>> {
        let Some(data) = &self.data else {
            return Ok(None);
        };
        let held = match data.optional_file("cw-runtime.lock", 0, 0o600)? {
            Some(file) => file,
            None if create => {
                match data.create_file("cw-runtime.lock", 0o600) {
                    Ok(file) => {
                        file.sync_all().map_err(|_| Code::Io)?;
                        data.own.file.sync_all().map_err(|_| Code::Io)?;
                    }
                    Err(Code::StageExists) => {}
                    Err(e) => return Err(e),
                }
                data.held_file("cw-runtime.lock", 0, 0o600)?
            }
            None => return Ok(None),
        };
        let operation = if exclusive {
            FlockOperation::NonBlockingLockExclusive
        } else {
            FlockOperation::NonBlockingLockShared
        };
        let deadline = deadline.min(Instant::now() + LOCK_BUDGET);
        loop {
            held.check()?;
            match rfs::flock(&held.file, operation) {
                Ok(()) => {
                    held.check()?;
                    self.check()?;
                    return Ok(Some(OperationLock { _held: held }));
                }
                Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(rustix::io::Errno::WOULDBLOCK) => return Err(Code::Deadline),
                Err(_) => return Err(Code::UnsafeState),
            }
        }
    }

    pub(super) fn read_lock(&self, deadline: Instant) -> Result<Option<OperationLock>> {
        self.lock(false, false, deadline)
    }
    pub(super) fn mutation_lock(&self, deadline: Instant) -> Result<OperationLock> {
        self.lock(true, true, deadline)?.ok_or(Code::UnsafeState)
    }
    pub(super) fn existing_mutation_lock(
        &self,
        deadline: Instant,
    ) -> Result<Option<OperationLock>> {
        self.lock(false, true, deadline)
    }

    pub(super) fn new_job(&self, c: &Correlation) -> Result<Dir> {
        let staging = self.staging.as_ref().ok_or(Code::UnsafeState)?;
        let pod = staging
            .child(&c.pod_uid.to_string(), true)?
            .ok_or(Code::UnsafeState)?;
        pod.exact_private()?;
        pod.new_child(&c.request_id.to_string())
    }

    pub(super) fn existing_job(&self, c: &Correlation) -> Result<Option<Dir>> {
        let Some(staging) = &self.staging else {
            return Ok(None);
        };
        let Some(pod) = staging.child(&c.pod_uid.to_string(), false)? else {
            return Ok(None);
        };
        pod.exact_private()?;
        let request = pod.child(&c.request_id.to_string(), false)?;
        if let Some(request) = &request {
            request.exact_private()?
        }
        Ok(request)
    }

    pub(super) fn remove_job(&self, c: &Correlation, directory: &Dir) -> Result<()> {
        let staging = self.staging.as_ref().ok_or(Code::UnsafeState)?;
        let pod = staging
            .child(&c.pod_uid.to_string(), false)?
            .ok_or(Code::UnsafeState)?;
        let observed = pod
            .child(&c.request_id.to_string(), false)?
            .ok_or(Code::UnsafeState)?;
        if observed.id()? != directory.id()? {
            return Err(Code::UnsafeState);
        }
        directory.require_inventory(&[])?;
        pod.check(true)?;
        rfs::unlinkat(&pod.own.file, c.request_id.to_string(), AtFlags::REMOVEDIR)
            .map_err(|_| Code::Io)?;
        pod.own.file.sync_all().map_err(|_| Code::Io)?;
        pod.check(false)
    }
}

pub(super) struct OperationLock {
    _held: HeldFile,
}
