//! Temporary public bytes. The directory is retained if subprocess cleanup
//! cannot be confirmed; downloaded executables are never made executable here.

use std::fs::{self, File, Metadata};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use rustix::fs::{self as rfs, Mode, OFlags};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
const MAX_ANCESTORS: usize = 64;
const MAX_PARENT_BYTES: usize = 4096;

struct Directory {
    path: PathBuf,
    file: File,
}

pub(super) struct Scratch {
    path: PathBuf,
    ancestors: Vec<Directory>,
    directory: File,
    gnupg_directory: File,
    owner: u32,
    retain: AtomicBool,
    cleaned: AtomicBool,
}

impl Scratch {
    pub(super) fn new() -> anyhow::Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    pub(super) fn new_in(parent: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parent.is_absolute() && parent.as_os_str().len() <= MAX_PARENT_BYTES,
            "release scratch parent must be absolute and bounded"
        );
        // Discard the caller's spelling after resolution. The opened canonical
        // chain must be root/current-user controlled: another UID must never
        // redirect the GPG home or the later Candidate pathname.
        let parent = fs::canonicalize(parent).context("resolve release scratch parent")?;
        let owner = unsafe { libc::geteuid() };
        let ancestors = admit_parent(&parent, owner)?;
        let path = parent.join(format!("cw-public-release-{}", uuid::Uuid::new_v4()));
        let parent_directory = &ancestors
            .last()
            .context("hold release scratch parent")?
            .file;
        rfs::mkdirat(
            parent_directory,
            path.file_name().context("private scratch name")?,
            Mode::from_raw_mode(0o700),
        )
        .context("create private release scratch")?;
        let directory = File::from(
            rfs::openat(
                parent_directory,
                path.file_name().context("private scratch name")?,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .context("hold private release scratch")?,
        );
        let info = directory
            .metadata()
            .context("inspect private release scratch")?;
        anyhow::ensure!(
            info.is_dir() && info.uid() == owner && info.mode() & 0o7777 == 0o700,
            "release scratch is not an owner-private directory"
        );
        rfs::mkdirat(&directory, "gnupg", Mode::from_raw_mode(0o700))
            .context("create private release verifier home")?;
        let gnupg_directory = File::from(
            rfs::openat(&directory, "gnupg", DIRECTORY_FLAGS, Mode::empty())
                .context("hold private verifier home")?,
        );
        let value = Self {
            path,
            ancestors,
            directory,
            gnupg_directory,
            owner,
            retain: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
        };
        value.check_paths()?;
        Ok(value)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn gnupg_home(&self) -> PathBuf {
        self.path.join("gnupg")
    }

    pub(super) fn create(&self, name: &str) -> anyhow::Result<File> {
        self.check_paths()?;
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')),
            "invalid private release scratch filename"
        );
        let fd = rfs::openat(
            &self.directory,
            name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .context("create held release scratch file")?;
        let file = File::from(fd);
        self.check_file(&file)?;
        Ok(file)
    }

    pub(super) fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<File> {
        let mut file = self.create(name)?;
        file.write_all(bytes)
            .context("write held public release bytes")?;
        file.sync_all().context("sync held public release bytes")?;
        self.check_file(&file)?;
        Ok(file)
    }

    pub(super) fn check_file(&self, file: &File) -> anyhow::Result<()> {
        self.check_paths()?;
        let info = file.metadata().context("inspect held release file")?;
        anyhow::ensure!(
            info.is_file()
                && info.uid() == self.owner
                && info.nlink() == 1
                && info.mode() & 0o7777 == 0o600,
            "release scratch file has unsafe metadata"
        );
        Ok(())
    }

    pub(super) fn check_paths(&self) -> anyhow::Result<()> {
        check_ancestors(&self.ancestors, self.owner)?;
        let parent = &self
            .ancestors
            .last()
            .context("retained scratch parent")?
            .file;
        check_private_child(
            parent,
            self.path
                .file_name()
                .context("retained scratch name")?
                .as_ref(),
            &self.directory,
            self.owner,
        )?;
        check_private_child(
            &self.directory,
            Path::new("gnupg"),
            &self.gnupg_directory,
            self.owner,
        )
    }

    pub(super) fn retain(&self) {
        self.retain.store(true, Ordering::Release);
    }

    pub(super) fn cleanup(&self) -> anyhow::Result<()> {
        if self.cleaned.load(Ordering::Acquire) {
            return Ok(());
        }
        anyhow::ensure!(
            !self.retain.load(Ordering::Acquire),
            "release verifier cleanup is unknown; private scratch retained"
        );
        let result = self.cleanup_known();
        if result.is_err() {
            self.retain();
        }
        result
    }

    fn cleanup_known(&self) -> anyhow::Result<()> {
        self.check_paths()?;
        let held = self
            .directory
            .metadata()
            .context("inspect retained scratch descriptor")?;
        let named = fs::symlink_metadata(&self.path).context("inspect retained scratch name")?;
        anyhow::ensure!(
            named.is_dir()
                && named.uid() == self.owner
                && named.mode() & 0o7777 == 0o700
                && (named.dev(), named.ino()) == (held.dev(), held.ino()),
            "private scratch identity changed; automatic cleanup refused"
        );
        fs::remove_dir_all(&self.path).context("remove known private release scratch")?;
        self.cleaned.store(true, Ordering::Release);
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The known private directory is removed only after verifier guards
        // have killed/reaped their children. This ordinary-user scratch is not
        // an adversarial same-UID/root filesystem boundary. Other UIDs cannot
        // write/rename the admitted ancestry or remove its sticky-owned child.
        let _ = self.cleanup();
    }
}

fn admitted_directory(info: &Metadata, owner: u32) -> bool {
    admitted_owner_mode(info.is_dir(), info.uid(), info.mode(), owner)
}

fn admitted_owner_mode(directory: bool, uid: u32, mode: u32, owner: u32) -> bool {
    directory
        && (uid == owner || uid == 0)
        && (mode & 0o022 == 0 || (uid == 0 && mode & 0o7777 == 0o1777))
}

fn admit_parent(parent: &Path, owner: u32) -> anyhow::Result<Vec<Directory>> {
    anyhow::ensure!(
        parent.is_absolute() && parent.as_os_str().len() <= MAX_PARENT_BYTES,
        "canonical scratch parent is outside its bound"
    );
    let mut directories = Vec::new();
    for component in parent.components() {
        anyhow::ensure!(
            directories.len() < MAX_ANCESTORS,
            "scratch ancestry exceeds its bound"
        );
        let (path, file) = match component {
            Component::RootDir => (
                PathBuf::from("/"),
                File::from(
                    rfs::open("/", DIRECTORY_FLAGS, Mode::empty())
                        .context("hold scratch root ancestor")?,
                ),
            ),
            Component::Normal(name) => {
                let prior: &Directory =
                    directories.last().context("scratch ancestry has no root")?;
                (
                    prior.path.join(name),
                    File::from(
                        rfs::openat(&prior.file, name, DIRECTORY_FLAGS, Mode::empty())
                            .context("hold nofollow scratch ancestor")?,
                    ),
                )
            }
            _ => anyhow::bail!("scratch ancestry is not canonical"),
        };
        anyhow::ensure!(
            admitted_directory(&file.metadata()?, owner),
            "scratch ancestor is foreign-owned or writable by another UID"
        );
        directories.push(Directory { path, file });
    }
    check_ancestors(&directories, owner)?;
    Ok(directories)
}

fn check_ancestors(directories: &[Directory], owner: u32) -> anyhow::Result<()> {
    for (index, directory) in directories.iter().enumerate() {
        let held = directory.file.metadata()?;
        let named = if index == 0 {
            fs::symlink_metadata("/")?
        } else {
            File::from(
                rfs::openat(
                    &directories[index - 1].file,
                    directory
                        .path
                        .file_name()
                        .context("retained ancestor name")?,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )
                .context("reobserve retained scratch ancestor")?,
            )
            .metadata()?
        };
        anyhow::ensure!(
            admitted_directory(&held, owner)
                && admitted_directory(&named, owner)
                && (named.dev(), named.ino()) == (held.dev(), held.ino()),
            "scratch ancestry identity or ownership changed; pathname use refused"
        );
    }
    Ok(())
}

fn check_private_child(parent: &File, name: &Path, held: &File, owner: u32) -> anyhow::Result<()> {
    let named = File::from(
        rfs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
            .context("reobserve private release directory")?,
    )
    .metadata()?;
    let held = held.metadata()?;
    anyhow::ensure!(
        held.is_dir()
            && named.is_dir()
            && held.uid() == owner
            && named.uid() == owner
            && held.mode() & 0o7777 == 0o700
            && named.mode() & 0o7777 == 0o700
            && (named.dev(), named.ino()) == (held.dev(), held.ino()),
        "private release directory identity or ownership changed; pathname use refused"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn closed_ancestor_policy_refuses_foreign_owners_and_other_uid_write() {
        // Synthetic UID/mode evidence only; no privileged chown or foreign
        // keyring is needed to exercise the exact production predicate.
        let owner = 1000;
        for (uid, mode) in [(owner, 0o700), (owner, 0o755), (0, 0o755), (0, 0o1777)] {
            assert!(admitted_owner_mode(true, uid, mode, owner));
        }
        for (uid, mode) in [
            (1001, 0o700),
            (1001, 0o1777),
            (owner, 0o777),
            (owner, 0o1777),
            (owner, 0o775),
            (0, 0o777),
            (0, 0o1775),
            (0, 0o3777),
        ] {
            assert!(!admitted_owner_mode(true, uid, mode, owner));
        }
        assert!(!admitted_owner_mode(false, owner, 0o700, owner));
    }

    #[test]
    fn ancestry_is_bounded_before_scratch_creation() {
        let parent = tempfile::tempdir().unwrap();
        let mut path = parent.path().to_owned();
        for _ in 0..MAX_ANCESTORS {
            path.push("d");
            fs::create_dir(&path).unwrap();
        }
        assert!(Scratch::new_in(&path).is_err());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        assert!(Scratch::new_in(Path::new("relative")).is_err());
        assert!(
            Scratch::new_in(&PathBuf::from(format!("/{}", "x".repeat(MAX_PARENT_BYTES)))).is_err()
        );
    }
}
