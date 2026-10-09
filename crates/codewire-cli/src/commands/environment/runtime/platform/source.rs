//! Owner/root-admitted immutable local release input, pinned through EOF.
//! Nothing in this module executes or writes candidate bytes.
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use codewire_client::{ClientError, ErrorCode};
use codewire_cw_release::identity::{Arch, CwPayloadIdentity, MAX_IDENTITY_BYTES, Os, Platform};

#[derive(PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Stamp {
    fn new(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            size: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
struct Directory {
    path: PathBuf,
    file: File,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl Directory {
    fn open(path: PathBuf) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        let m = file.metadata()?;
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == uid)
                && (m.mode() & 0o22 == 0 || (m.uid() == 0 && m.mode() & 0o7777 == 0o1777)),
            "release directory ancestry is unsafe"
        );
        let result = Self {
            path,
            file,
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&self) -> anyhow::Result<()> {
        for m in [self.file.metadata()?, fs::symlink_metadata(&self.path)?] {
            anyhow::ensure!(
                m.is_dir()
                    && m.dev() == self.dev
                    && m.ino() == self.ino
                    && m.uid() == self.uid
                    && m.gid() == self.gid
                    && m.mode() == self.mode,
                "release directory ancestry changed"
            );
        }
        Ok(())
    }
}
struct Held {
    path: PathBuf,
    file: File,
    stamp: Stamp,
}
impl Held {
    fn open(path: PathBuf, maximum: u64) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && (metadata.uid() == uid || metadata.uid() == 0)
                && metadata.mode() & 0o22 == 0
                && metadata.len() > 0
                && metadata.len() <= maximum,
            "release input is not a bounded owned regular file"
        );
        let held = Self {
            path,
            file,
            stamp: Stamp::new(&metadata),
        };
        held.recheck()?;
        Ok(held)
    }
    fn recheck(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            Stamp::new(&self.file.metadata()?) == self.stamp
                && Stamp::new(&fs::symlink_metadata(&self.path)?) == self.stamp,
            "release input changed while held"
        );
        Ok(())
    }
}

pub(super) struct Candidate {
    pub(super) identity: CwPayloadIdentity,
    dirs: Vec<Directory>,
    executable: Held,
    descriptor: Held,
    count: u64,
    ended: bool,
}
impl Candidate {
    fn files(source: &Path, pin: &str) -> anyhow::Result<Self> {
        let absolute = if source.is_absolute() {
            source.to_owned()
        } else {
            std::env::current_dir()?.join(source)
        };
        anyhow::ensure!(
            absolute.as_os_str().len() <= 4096,
            "release directory path exceeds its bound"
        );
        let mut path = PathBuf::new();
        let mut dirs = Vec::new();
        for component in absolute.components() {
            match component {
                Component::RootDir => path.push("/"),
                Component::Normal(name) => path.push(name),
                Component::CurDir => continue,
                _ => anyhow::bail!("release directory contains unsupported components"),
            }
            anyhow::ensure!(dirs.len() < 64, "release ancestry exceeds its bound");
            dirs.push(Directory::open(path.clone())?);
        }
        let mut descriptor = Held::open(path.join("cw-runtime.json"), MAX_IDENTITY_BYTES as u64)?;
        let mut bytes = Vec::with_capacity(descriptor.stamp.size as usize);
        descriptor
            .file
            .by_ref()
            .take(MAX_IDENTITY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        descriptor.recheck()?;
        let identity = CwPayloadIdentity::decode(&bytes)?;
        anyhow::ensure!(
            identity.encode()? == bytes,
            "release identity is not canonical"
        );
        anyhow::ensure!(
            identity.target == "x86_64-unknown-linux-musl" && identity.sha256 == pin,
            "release identity differs from the static-musl target or explicit digest pin"
        );
        let executable = Held::open(path.join("cw"), identity.size)?;
        anyhow::ensure!(
            executable.stamp.size == identity.size,
            "release size differs from identity"
        );
        let result = Self {
            identity,
            dirs,
            executable,
            descriptor,
            count: 0,
            ended: false,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(super) fn open(source: &Path, pin: &str) -> anyhow::Result<Self> {
        let mut result = Self::files(source, pin)?;
        // Borrow the CLI's one existing compiled marker. Never add another
        // marker literal or execute incoming bytes to establish their version.
        crate::build_record::admit_incoming(
            &mut result.executable.file,
            &result.executable.path,
            &result.identity,
            Platform::new(Os::Linux, Arch::X86_64),
        )?;
        result.executable.file.seek(SeekFrom::Start(0))?;
        result.recheck()?;
        Ok(result)
    }
    pub(super) fn recheck(&self) -> anyhow::Result<()> {
        for directory in &self.dirs {
            directory.recheck()?;
        }
        self.descriptor.recheck()?;
        self.executable.recheck()
    }
    fn chunk(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        self.recheck()?;
        if self.count == self.identity.size {
            let mut extra = [0];
            anyhow::ensure!(
                self.executable.file.read(&mut extra)? == 0,
                "release contains bytes beyond identity"
            );
            self.recheck()?;
            return Ok(None);
        }
        let size = (self.identity.size - self.count).min(64 * 1024) as usize;
        let mut bytes = vec![0; size];
        let n = self.executable.file.read(&mut bytes)?;
        anyhow::ensure!(n > 0, "release ended before identity size");
        bytes.truncate(n);
        self.count += n as u64;
        self.recheck()?;
        Ok(Some(bytes))
    }
}
impl Iterator for Candidate {
    type Item = Result<Vec<u8>, ClientError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        match self.chunk() {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => {
                self.ended = true;
                None
            }
            Err(_) => {
                self.ended = true;
                Some(Err(ClientError::new(
                    ErrorCode::InvalidArgument,
                    "held runtime release input changed or could not be read",
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests;
