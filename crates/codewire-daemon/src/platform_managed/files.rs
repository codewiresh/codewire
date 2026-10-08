//! Held owner-private state IO for this service only. Existing unsafe paths
//! refuse; no chmod of an existing entry, adoption, foreign unlink or crash
//! recovery is performed.
use super::Error;
use rustix::fs::{Mode, OFlags, RenameFlags};
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub(crate) struct Tree {
    pins: Vec<(PathBuf, File)>,
    /// The pin that is the workspace home, when the tree is below it.
    home: Option<usize>,
}
fn stamp(m: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
/// The workspace home is the Pod's own volume root. Kubernetes leaves it root
/// owned and group- or world-writable (fsGroup setgid 2775, local-path 0777),
/// and the workspace user cannot change that. The home alone is a held anchor:
/// a real directory owned by root or this user. Its ancestors and everything
/// below it stay owner-checked, so another account can at most make a
/// component refuse, and a later rename fails the held-descriptor check.
fn anchor(m: &Metadata) -> bool {
    m.is_dir() && [0, unsafe { libc::geteuid() }].contains(&m.uid())
}
fn dir(m: &Metadata, leaf: bool) -> bool {
    m.is_dir()
        && [0, unsafe { libc::geteuid() }].contains(&m.uid())
        && m.mode() & 0o022 == 0
        && (!leaf || (m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700))
}
fn leaf(m: &Metadata, bound: usize) -> bool {
    m.is_file()
        && m.uid() == unsafe { libc::geteuid() }
        && m.nlink() == 1
        && m.mode() & 0o7777 == 0o600
        && m.len() <= bound as u64
}
impl Tree {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self, Error> {
        Self::open_below(Path::new(super::HOME), path, create)
    }
    fn open_below(home: &Path, path: &Path, create: bool) -> Result<Self, Error> {
        if !path.is_absolute()
            || path.components().count() > 64
            || path
                .components()
                .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Refused);
        }
        let root = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Refused)?;
        let mut pins = vec![(PathBuf::from("/"), File::from(root))];
        let mut home_pin = None;
        let mut named = PathBuf::from("/");
        for part in path.components().filter_map(|p| match p {
            Component::Normal(p) => Some(p),
            _ => None,
        }) {
            let parent = &pins.last().ok_or(Error::Refused)?.1;
            let descriptor = match rustix::fs::openat(
                parent,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if create => {
                    rustix::fs::mkdirat(parent, part, Mode::from_raw_mode(0o700))
                        .map_err(|_| Error::Unknown)?;
                    rustix::fs::fsync(parent).map_err(|_| Error::Unknown)?;
                    let created = rustix::fs::openat(
                        parent,
                        part,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| Error::Unknown)?;
                    // A directory made below a setgid volume root inherits
                    // setgid; this one is set exactly private. A directory
                    // another account swapped in under the name refuses.
                    let made = rustix::fs::fstat(&created).map_err(|_| Error::Unknown)?;
                    if made.st_mode & libc::S_IFMT != libc::S_IFDIR
                        || made.st_uid != unsafe { libc::geteuid() }
                        || made.st_mode & 0o5777 != 0o700
                    {
                        return Err(Error::Refused);
                    }
                    rustix::fs::fchmod(&created, Mode::from_raw_mode(0o700))
                        .map_err(|_| Error::Unknown)?;
                    created
                }
                _ => return Err(Error::Refused),
            };
            named.push(part);
            let fd = File::from(descriptor);
            let metadata = fd.metadata().map_err(|_| Error::Refused)?;
            let is_home = named == home && named != path;
            if !(if is_home {
                anchor(&metadata)
            } else {
                dir(&metadata, named == path)
            }) {
                return Err(Error::Refused);
            }
            if is_home {
                home_pin = Some(pins.len());
            }
            pins.push((named.clone(), fd));
        }
        let tree = Self {
            pins,
            home: home_pin,
        };
        tree.check()?;
        Ok(tree)
    }
    pub(crate) fn check(&self) -> Result<(), Error> {
        for (i, (path, fd)) in self.pins.iter().enumerate() {
            let a = fd.metadata().map_err(|_| Error::Unknown)?;
            let b = std::fs::symlink_metadata(path).map_err(|_| Error::Unknown)?;
            let admitted = if self.home == Some(i) {
                anchor(&b)
            } else {
                dir(&b, i + 1 == self.pins.len())
            };
            if !admitted
                || (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
                    != (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
            {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }
    fn fd(&self) -> &File {
        &self.pins.last().expect("tree has root").1
    }
    fn path(&self, name: &str) -> Result<PathBuf, Error> {
        if name.is_empty()
            || name.len() > 128
            || name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        {
            return Err(Error::Refused);
        }
        Ok(self.pins.last().ok_or(Error::Refused)?.0.join(name))
    }
    pub(crate) fn read(&self, name: &str, bound: usize) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        let path = self.path(name)?;
        let fd = match rustix::fs::openat(
            self.fd(),
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            _ => return Err(Error::Refused),
        };
        let mut file = File::from(fd);
        let a = file.metadata().map_err(|_| Error::Refused)?;
        if !leaf(&a, bound) {
            return Err(Error::Refused);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(bound as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unknown)?;
        if bytes.len() > bound
            || stamp(&a) != stamp(&file.metadata().map_err(|_| Error::Unknown)?)
            || stamp(&a) != stamp(&std::fs::symlink_metadata(path).map_err(|_| Error::Unknown)?)
        {
            return Err(Error::Unknown);
        }
        self.check()?;
        Ok(Some(bytes))
    }
    pub(crate) fn write(&self, name: &str, bytes: &[u8], replace: bool) -> Result<(), Error> {
        self.check()?;
        let target = self.path(name)?;
        let before = match std::fs::symlink_metadata(&target) {
            Ok(m) if replace && leaf(&m, 128 * 1024) => Some(stamp(&m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            _ => return Err(Error::Refused),
        };
        if bytes.len() > 128 * 1024 {
            return Err(Error::Refused);
        }
        let temporary = format!(".{}.tmp", uuid::Uuid::new_v4());
        let fd = rustix::fs::openat(
            self.fd(),
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| Error::Unknown)?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(|_| Error::Unknown)?;
        file.sync_all().map_err(|_| Error::Unknown)?;
        self.check()?;
        let current = match std::fs::symlink_metadata(&target) {
            Ok(m) => Some(stamp(&m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            _ => return Err(Error::Unknown),
        };
        if current != before {
            return Err(Error::Unknown);
        }
        if replace && before.is_some() {
            rustix::fs::renameat(self.fd(), temporary.as_str(), self.fd(), name)
                .map_err(|_| Error::Unknown)?;
        } else {
            rustix::fs::renameat_with(
                self.fd(),
                temporary.as_str(),
                self.fd(),
                name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| Error::Unknown)?;
        }
        rustix::fs::fsync(self.fd()).map_err(|_| Error::Unknown)?;
        self.check()
    }
    pub(super) fn lock(&self) -> Result<File, Error> {
        self.check()?;
        let path = self.path("requests.lock")?;
        let fd = rustix::fs::openat(
            self.fd(),
            "requests.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| Error::Refused)?;
        let file = File::from(fd);
        let a = file.metadata().map_err(|_| Error::Refused)?;
        if !leaf(&a, 0)
            || stamp(&a) != stamp(&std::fs::symlink_metadata(path).map_err(|_| Error::Refused)?)
        {
            return Err(Error::Refused);
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error::Refused)?;
        self.check()?;
        Ok(file)
    }
    pub(super) fn count(&self) -> Result<usize, Error> {
        self.check()?;
        let held = &self.pins.last().ok_or(Error::Refused)?.1;
        let mut count = 0;
        for item in rustix::fs::Dir::read_from(held).map_err(|_| Error::Refused)? {
            let entry = item.map_err(|_| Error::Refused)?;
            let name = entry.file_name().to_str().map_err(|_| Error::Refused)?;
            if name == "." || name == ".." {
                continue;
            }
            if name == "requests.lock" {
                self.read(name, 0)?.ok_or(Error::Refused)?;
                continue;
            }
            if name == "scope.bin" {
                self.read(name, 4096)?.ok_or(Error::Refused)?;
                continue;
            }
            let id = name.strip_suffix(".bin").ok_or(Error::Refused)?;
            if !codewire_daemon_proto::platform_managed::valid_uuid(id) {
                return Err(Error::Refused);
            }
            self.read(name, 128 * 1024)?.ok_or(Error::Refused)?;
            count += 1;
            if count > 1024 {
                return Err(Error::Refused);
            }
        }
        self.check()?;
        Ok(count)
    }
}
pub(crate) fn publish_session(root: &Path, session: &str, bytes: &[u8]) -> Result<(), Error> {
    if !codewire_daemon_proto::platform_managed::valid_session(session) || bytes.len() > 128 * 1024
    {
        return Err(Error::Refused);
    }
    let tree = Tree::open(root, false)?;
    tree.check()?;
    let stage = format!(".platform-{}.tmp", uuid::Uuid::new_v4());
    rustix::fs::mkdirat(tree.fd(), stage.as_str(), Mode::from_raw_mode(0o700))
        .map_err(|_| Error::Unknown)?;
    let path = root.join(&stage);
    let staged = Tree::open(&path, false)?;
    staged.write("session.json", bytes, false)?;
    staged.write("output.bin", &[], false)?;
    staged.check()?;
    tree.check()?;
    rustix::fs::renameat_with(
        tree.fd(),
        stage.as_str(),
        tree.fd(),
        session,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| Error::Unknown)?;
    rustix::fs::fsync(tree.fd()).map_err(|_| Error::Unknown)?;
    tree.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn record(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fifo(path: &Path) {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn platform_files_nonblocking_reads_and_lock_refuse_fifo_links_and_overbound_bytes() {
        let root = private_root();
        let tree = Tree::open(root.path(), false).unwrap();
        record(&root.path().join("safe.bin"), b"original");
        fifo(&root.path().join("fifo.bin"));
        symlink("safe.bin", root.path().join("symlink.bin")).unwrap();
        std::fs::hard_link(root.path().join("safe.bin"), root.path().join("linked.bin")).unwrap();
        record(&root.path().join("large.bin"), b"too-large");
        fifo(&root.path().join("requests.lock"));
        let start = std::time::Instant::now();
        for name in ["fifo.bin", "symlink.bin", "linked.bin", "safe.bin"] {
            assert!(matches!(tree.read(name, 64), Err(Error::Refused)));
        }
        assert!(matches!(tree.read("large.bin", 4), Err(Error::Refused)));
        assert!(matches!(tree.lock(), Err(Error::Refused)));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(
            std::fs::read(root.path().join("safe.bin")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read_link(root.path().join("symlink.bin")).unwrap(),
            Path::new("safe.bin")
        );
        assert_eq!(
            std::fs::symlink_metadata(root.path().join("safe.bin"))
                .unwrap()
                .nlink(),
            2
        );
    }

    #[test]
    fn platform_files_admit_a_shared_home_volume_root_but_keep_the_store_private() {
        // The workspace home is root-owned 0777 on local-path volumes and a
        // setgid 2775 fsGroup volume elsewhere; only the store below it is ours.
        let base = private_root();
        let home = base.path().join("home");
        std::fs::create_dir(&home).unwrap();
        for mode in [0o777, 0o2775] {
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(mode)).unwrap();
            let store = home.join(format!(".codewire-{mode:o}/daemon/sessions"));
            let tree = Tree::open_below(&home, &store, true).unwrap();
            tree.write("probe.bin", b"probe", false).unwrap();
            for created in [
                store.parent().unwrap().parent().unwrap(),
                store.parent().unwrap(),
                &store,
            ] {
                assert_eq!(std::fs::metadata(created).unwrap().mode() & 0o7777, 0o700);
            }
            assert!(Tree::open_below(&home, &store, false).is_ok());
            // The same mode on a component below the home still refuses.
            let shared = home.join(format!("shared-{mode:o}"));
            std::fs::create_dir(&shared).unwrap();
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                Tree::open_below(&home, &shared.join("store"), true),
                Err(Error::Refused)
            ));
            assert!(!shared.join("store").exists());
        }
        // Without the home anchor, the shared root itself refuses.
        assert!(matches!(
            Tree::open(&home.join(".codewire-777/daemon/sessions"), false),
            Err(Error::Refused)
        ));
        // A symlinked or non-directory home is never an anchor.
        let linked = base.path().join("linked");
        std::os::unix::fs::symlink(&home, &linked).unwrap();
        let file = base.path().join("file");
        record(&file, b"");
        for home in [&linked, &file] {
            assert!(matches!(
                Tree::open_below(home, &home.join("store"), true),
                Err(Error::Refused)
            ));
        }
    }

    #[test]
    fn platform_files_readonly_admission_never_creates_or_chmods_state() {
        let root = private_root();
        let absent = root.path().join("absent");
        assert!(matches!(Tree::open(&absent, false), Err(Error::Refused)));
        assert!(!absent.exists());
        let tree = Tree::open(root.path(), false).unwrap();
        assert!(tree.read("unknown.bin", 8).unwrap().is_none());
        assert!(!root.path().join("requests.lock").exists());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(Tree::open(root.path(), true), Err(Error::Refused)));
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().mode() & 0o7777,
            0o500
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn platform_files_held_parent_refuses_named_replacement_and_preserves_both_sentinels() {
        let root = private_root();
        let path = root.path().join("state");
        let tree = Tree::open(&path, true).unwrap();
        tree.write("original.bin", b"held-original", false).unwrap();
        let moved = root.path().join("retained");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        record(&path.join("original.bin"), b"replacement-sentinel");
        assert!(matches!(tree.read("original.bin", 64), Err(Error::Unknown)));
        assert!(matches!(
            tree.write("original.bin", b"must-not-write", true),
            Err(Error::Unknown)
        ));
        assert_eq!(
            std::fs::read(moved.join("original.bin")).unwrap(),
            b"held-original"
        );
        assert_eq!(
            std::fs::read(path.join("original.bin")).unwrap(),
            b"replacement-sentinel"
        );
    }

    #[test]
    fn platform_files_no_replace_session_publication_retains_unknown_stage_without_clobber() {
        let root = private_root();
        let session = format!("session-{}", uuid::Uuid::new_v4());
        publish_session(root.path(), &session, b"first-metadata").unwrap();
        assert!(matches!(
            publish_session(root.path(), &session, b"second-metadata"),
            Err(Error::Unknown)
        ));
        assert_eq!(
            std::fs::read(root.path().join(&session).join("session.json")).unwrap(),
            b"first-metadata"
        );
        let stages = std::fs::read_dir(root.path())
            .unwrap()
            .map(|r| r.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(b".platform-")
            })
            .collect::<Vec<_>>();
        assert_eq!(stages.len(), 1);
        assert_eq!(
            std::fs::read(stages[0].join("session.json")).unwrap(),
            b"second-metadata"
        );
        assert_eq!(
            std::fs::metadata(&stages[0]).unwrap().mode() & 0o7777,
            0o700
        );
        let tree = Tree::open(root.path(), false).unwrap();
        let target = root.path().join("linked.bin");
        record(&root.path().join("sentinel.bin"), b"unrelated");
        symlink("sentinel.bin", &target).unwrap();
        assert!(matches!(
            tree.write("linked.bin", b"must-not-write", true),
            Err(Error::Refused)
        ));
        assert_eq!(
            std::fs::read(root.path().join("sentinel.bin")).unwrap(),
            b"unrelated"
        );
    }
}
