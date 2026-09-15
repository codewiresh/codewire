use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, mkdirat, openat2, renameat,
    renameat_with, unlinkat,
};

pub use crate::supervisor_metadata::legacy::{FileIdentity, SocketIdentity};

const RESOLVE_PRIVATE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

impl FileIdentity {
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
        }
    }
}

#[derive(Debug)]
pub struct ConfinedFile {
    file: File,
    identity: FileIdentity,
}

impl ConfinedFile {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[derive(Debug)]
pub struct PrivateRoot {
    path: PathBuf,
    directory: File,
}

impl PrivateRoot {
    pub fn create(path: &Path) -> Result<Self, PathError> {
        if !path.is_absolute() {
            return Err(PathError::RootNotAbsolute(path.to_owned()));
        }
        let parent_path = path
            .parent()
            .filter(|parent| *parent != path)
            .ok_or_else(|| PathError::UnsafeCreateParent(path.to_owned()))?;
        let leaf = path
            .file_name()
            .map(Path::new)
            .ok_or_else(|| PathError::UnsafeCreateParent(path.to_owned()))?;
        validate_single_component(leaf)?;
        let parent = Self::open(parent_path)?;
        match mkdirat(parent.directory.as_fd(), leaf, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                parent.open_directory(leaf, 0o700)?;
            }
            Err(source) => {
                return Err(PathError::Openat2 {
                    path: path.to_owned(),
                    source,
                });
            }
        }
        Self::open(path)
    }

    pub fn open(path: &Path) -> Result<Self, PathError> {
        if !path.is_absolute() {
            return Err(PathError::RootNotAbsolute(path.to_owned()));
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|source| PathError::Io {
                path: path.to_owned(),
                source,
            })?;
        // Validate the opened object, not a pathname lookup performed before
        // the open. This closes the attacker-controlled-parent race where a
        // checked directory could otherwise be replaced before O_NOFOLLOW is
        // applied. The post-open pathname identity check also fails closed if
        // the name no longer denotes the retained dirfd.
        let metadata = directory.metadata().map_err(|source| PathError::Io {
            path: path.to_owned(),
            source,
        })?;
        validate_private_directory(path, &metadata)?;
        let canonical = fs::canonicalize(path).map_err(|source| PathError::Io {
            path: path.to_owned(),
            source,
        })?;
        if canonical != path {
            return Err(PathError::NonCanonicalRoot(path.to_owned()));
        }
        let named_metadata = fs::symlink_metadata(path).map_err(|source| PathError::Io {
            path: path.to_owned(),
            source,
        })?;
        validate_private_directory(path, &named_metadata)?;
        if metadata.dev() != named_metadata.dev() || metadata.ino() != named_metadata.ino() {
            return Err(PathError::RootIdentityChanged(path.to_owned()));
        }
        Ok(Self {
            path: path.to_owned(),
            directory,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn create_dir(&self, relative: &Path, mode: u32) -> Result<PathBuf, PathError> {
        validate_single_component(relative)?;
        let path = self.path.join(relative);
        mkdirat(self.directory.as_fd(), relative, Mode::from_raw_mode(mode)).map_err(|source| {
            PathError::Openat2 {
                path: relative.to_owned(),
                source,
            }
        })?;
        self.open_directory(relative, mode)?;
        Ok(path)
    }

    pub fn ensure_dir(&self, relative: &Path, mode: u32) -> Result<PathBuf, PathError> {
        validate_single_component(relative)?;
        let path = self.path.join(relative);
        match mkdirat(self.directory.as_fd(), relative, Mode::from_raw_mode(mode)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(source) => {
                return Err(PathError::Openat2 {
                    path: relative.to_owned(),
                    source,
                });
            }
        }
        self.open_directory(relative, mode)?;
        Ok(path)
    }

    pub fn open_directory(&self, relative: &Path, mode: u32) -> Result<File, PathError> {
        validate_relative(relative)?;
        let owned = openat2(
            self.directory.as_fd(),
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_PRIVATE,
        )
        .map_err(|source| PathError::Openat2 {
            path: relative.to_owned(),
            source,
        })?;
        let file = File::from(owned);
        let metadata = file.metadata().map_err(|source| PathError::Io {
            path: self.path.join(relative),
            source,
        })?;
        if !metadata.is_dir() || metadata.uid() != current_uid() || metadata.mode() & 0o777 != mode
        {
            return Err(PathError::UnsafeDirectory(self.path.join(relative)));
        }
        Ok(file)
    }

    pub fn open_private_directory(&self, relative: &Path, mode: u32) -> Result<Self, PathError> {
        let directory = self.open_directory(relative, mode)?;
        Ok(Self {
            path: self.path.join(relative),
            directory,
        })
    }

    pub fn open_regular(
        &self,
        relative: &Path,
        writable: bool,
        expected_size: Option<u64>,
        require_executable: bool,
        exact_permissions: Option<u32>,
    ) -> Result<ConfinedFile, PathError> {
        validate_relative(relative)?;
        let access = if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
        let owned = openat2(
            self.directory.as_fd(),
            relative,
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_PRIVATE,
        )
        .map_err(|source| PathError::Openat2 {
            path: relative.to_owned(),
            source,
        })?;
        let file = File::from(owned);
        let metadata = file.metadata().map_err(|source| PathError::Io {
            path: self.path.join(relative),
            source,
        })?;
        let mode = metadata.mode();
        if !metadata.file_type().is_file()
            || metadata.uid() != current_uid()
            || metadata.nlink() != 1
            || mode & 0o022 != 0
            || require_executable && mode & 0o100 == 0
            || expected_size.is_some_and(|size| metadata.len() != size)
            || exact_permissions.is_some_and(|permissions| mode & 0o777 != permissions)
        {
            return Err(PathError::UnsafeFile(self.path.join(relative)));
        }
        Ok(ConfinedFile {
            identity: FileIdentity::from_metadata(&metadata),
            file,
        })
    }

    pub fn create_regular(
        &self,
        relative: &Path,
        permissions: u32,
        exclusive: bool,
    ) -> Result<ConfinedFile, PathError> {
        validate_single_component(relative)?;
        let mut flags = OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        if exclusive {
            flags |= OFlags::EXCL;
        }
        let owned = openat2(
            self.directory.as_fd(),
            relative,
            flags,
            Mode::from_raw_mode(permissions),
            RESOLVE_PRIVATE,
        )
        .map_err(|source| PathError::Openat2 {
            path: relative.to_owned(),
            source,
        })?;
        let file = File::from(owned);
        let metadata = file.metadata().map_err(|source| PathError::Io {
            path: self.path.join(relative),
            source,
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != current_uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != permissions
        {
            return Err(PathError::UnsafeFile(self.path.join(relative)));
        }
        Ok(ConfinedFile {
            identity: FileIdentity::from_metadata(&metadata),
            file,
        })
    }

    pub fn atomic_replace(
        &self,
        relative: &Path,
        bytes: &[u8],
        final_permissions: u32,
    ) -> Result<(), PathError> {
        validate_single_component(relative)?;
        let file_name = relative
            .to_str()
            .ok_or_else(|| PathError::InvalidRelativePath(relative.to_owned()))?;
        let temporary = PathBuf::from(format!(".{file_name}.tmp"));
        let opened = match self.create_regular(&temporary, 0o600, true) {
            Ok(opened) => opened,
            Err(PathError::Openat2 {
                source: rustix::io::Errno::EXIST,
                ..
            }) => {
                // A stale temp is removable only after dirfd-relative nofollow
                // admission proves it is our single-link 0600 regular file.
                self.open_regular(&temporary, true, None, false, Some(0o600))?;
                unlinkat(self.directory.as_fd(), &temporary, AtFlags::empty()).map_err(
                    |source| PathError::Openat2 {
                        path: temporary.clone(),
                        source,
                    },
                )?;
                self.create_regular(&temporary, 0o600, true)?
            }
            Err(error) => return Err(error),
        };
        let operation = (|| {
            let mut file = opened.file();
            file.write_all(bytes).map_err(|source| PathError::Io {
                path: self.path.join(&temporary),
                source,
            })?;
            file.sync_all().map_err(|source| PathError::Io {
                path: self.path.join(&temporary),
                source,
            })?;
            fchmod(file, Mode::from_raw_mode(final_permissions)).map_err(|source| {
                PathError::Openat2 {
                    path: temporary.clone(),
                    source,
                }
            })?;
            file.sync_all().map_err(|source| PathError::Io {
                path: self.path.join(&temporary),
                source,
            })?;
            renameat(
                self.directory.as_fd(),
                &temporary,
                self.directory.as_fd(),
                relative,
            )
            .map_err(|source| PathError::Openat2 {
                path: relative.to_owned(),
                source,
            })?;
            self.directory.sync_all().map_err(|source| PathError::Io {
                path: self.path.clone(),
                source,
            })?;
            Ok::<_, PathError>(())
        })();
        if operation.is_err() {
            let _ = unlinkat(self.directory.as_fd(), &temporary, AtFlags::empty());
        }
        operation
    }

    pub fn remove_private_socket(&self, relative: &Path) -> Result<bool, PathError> {
        self.remove_private_socket_with_permissions(relative, &[0o600])
    }

    pub(crate) fn remove_private_socket_with_permissions(
        &self,
        relative: &Path,
        exact_permissions: &[u32],
    ) -> Result<bool, PathError> {
        validate_single_component(relative)?;
        let path = self.path.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                SocketIdentity::capture_with_permissions(&path, exact_permissions)?;
                unlinkat(self.directory.as_fd(), relative, AtFlags::empty()).map_err(|source| {
                    PathError::Openat2 {
                        path: relative.to_owned(),
                        source,
                    }
                })?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(PathError::Io { path, source }),
        }
    }

    pub fn remove_private_regular(
        &self,
        relative: &Path,
        exact_permissions: u32,
    ) -> Result<bool, PathError> {
        validate_single_component(relative)?;
        let path = self.path.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                self.open_regular(relative, false, None, false, Some(exact_permissions))?;
                unlinkat(self.directory.as_fd(), relative, AtFlags::empty()).map_err(|source| {
                    PathError::Openat2 {
                        path: relative.to_owned(),
                        source,
                    }
                })?;
                self.directory.sync_all().map_err(|source| PathError::Io {
                    path: self.path.clone(),
                    source,
                })?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(PathError::Io { path, source }),
        }
    }

    pub fn move_private_directory_to(
        &self,
        source: &Path,
        destination_root: &Self,
        destination: &Path,
    ) -> Result<(), PathError> {
        validate_single_component(source)?;
        validate_single_component(destination)?;
        self.open_directory(source, 0o700)?;
        renameat_with(
            self.directory.as_fd(),
            source,
            destination_root.directory.as_fd(),
            destination,
            RenameFlags::NOREPLACE,
        )
        .map_err(|source_error| PathError::Openat2 {
            path: destination_root.path.join(destination),
            source: source_error,
        })?;
        self.directory
            .sync_all()
            .map_err(|source_error| PathError::Io {
                path: self.path.clone(),
                source: source_error,
            })?;
        destination_root
            .directory
            .sync_all()
            .map_err(|source_error| PathError::Io {
                path: destination_root.path.clone(),
                source: source_error,
            })?;
        destination_root.open_directory(destination, 0o700)?;
        Ok(())
    }

    /// Atomically publish a prepared owner-private regular file without ever
    /// replacing an existing content-addressed object. `false` means the
    /// destination already existed and neither pathname was changed.
    pub fn publish_private_regular_no_replace(
        &self,
        source: &Path,
        destination: &Path,
        exact_permissions: u32,
    ) -> Result<bool, PathError> {
        validate_single_component(source)?;
        validate_single_component(destination)?;
        self.open_regular(source, false, None, false, Some(exact_permissions))?;
        match renameat_with(
            self.directory.as_fd(),
            source,
            self.directory.as_fd(),
            destination,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => return Ok(false),
            Err(source_error) => {
                return Err(PathError::Openat2 {
                    path: self.path.join(destination),
                    source: source_error,
                });
            }
        }
        self.directory
            .sync_all()
            .map_err(|source_error| PathError::Io {
                path: self.path.clone(),
                source: source_error,
            })?;
        self.open_regular(destination, false, None, false, Some(exact_permissions))?;
        Ok(true)
    }

    pub fn remove_empty_private_directory(&self, relative: &Path) -> Result<(), PathError> {
        validate_single_component(relative)?;
        self.open_directory(relative, 0o700)?;
        unlinkat(self.directory.as_fd(), relative, AtFlags::REMOVEDIR).map_err(|source| {
            PathError::Openat2 {
                path: self.path.join(relative),
                source,
            }
        })?;
        self.directory.sync_all().map_err(|source| PathError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

impl SocketIdentity {
    pub fn capture(path: &Path) -> Result<Self, PathError> {
        Self::capture_with_permissions(path, &[0o600])
    }

    pub(crate) fn capture_with_permissions(
        path: &Path,
        exact_permissions: &[u32],
    ) -> Result<Self, PathError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| PathError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != current_uid()
            || metadata.nlink() != 1
            || !exact_permissions.contains(&(metadata.mode() & 0o777))
        {
            return Err(PathError::UnsafeSocket(path.to_owned()));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        })
    }

    pub fn revalidate(&self, path: &Path) -> Result<(), PathError> {
        if &Self::capture(path)? != self {
            return Err(PathError::SocketIdentityChanged(path.to_owned()));
        }
        Ok(())
    }
}

pub fn set_socket_private(path: &Path) -> Result<SocketIdentity, PathError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        PathError::Io {
            path: path.to_owned(),
            source,
        }
    })?;
    SocketIdentity::capture(path)
}

pub fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and no memory effects.
    unsafe { libc::geteuid() }
}

fn validate_private_directory(path: &Path, metadata: &Metadata) -> Result<(), PathError> {
    if !metadata.is_dir() || metadata.uid() != current_uid() || metadata.mode() & 0o777 != 0o700 {
        return Err(PathError::UnsafeDirectory(path.to_owned()));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), PathError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PathError::InvalidRelativePath(path.to_owned()));
    }
    Ok(())
}

fn validate_single_component(path: &Path) -> Result<(), PathError> {
    validate_relative(path)?;
    if path.components().count() != 1 {
        return Err(PathError::InvalidRelativePath(path.to_owned()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("private root must be an absolute path: {0}")]
    RootNotAbsolute(PathBuf),
    #[error("private root must not be a symlink or non-canonical alias: {0}")]
    NonCanonicalRoot(PathBuf),
    #[error("private root pathname changed while it was being admitted: {0}")]
    RootIdentityChanged(PathBuf),
    #[error("invalid confined relative path: {0}")]
    InvalidRelativePath(PathBuf),
    #[error("private root creation requires an existing canonical private parent: {0}")]
    UnsafeCreateParent(PathBuf),
    #[error("unsafe private directory metadata: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("unsafe private regular file metadata: {0}")]
    UnsafeFile(PathBuf),
    #[error("unsafe private Unix socket metadata: {0}")]
    UnsafeSocket(PathBuf),
    #[error("Unix socket identity changed: {0}")]
    SocketIdentityChanged(PathBuf),
    #[error("confined openat2 failed for {path}: {source}")]
    Openat2 {
        path: PathBuf,
        source: rustix::io::Errno,
    },
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    fn root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        (parent, root)
    }

    #[test]
    fn openat2_refuses_symlink_and_mount_escape_shapes() {
        let (parent, root) = root();
        let outside = parent.path().join("outside");
        File::create(&outside)
            .unwrap()
            .write_all(b"outside")
            .unwrap();
        symlink(&outside, root.path().join("link")).unwrap();
        assert!(matches!(
            root.open_regular(Path::new("link"), false, None, false, None),
            Err(PathError::Openat2 { .. })
        ));
        for path in ["../outside", "/etc/passwd", "a/../../outside"] {
            assert!(matches!(
                root.open_regular(Path::new(path), false, None, false, None),
                Err(PathError::InvalidRelativePath(_))
            ));
        }
    }

    #[test]
    fn remove_private_regular_admits_exact_file_before_unlink() {
        let (_parent, root) = root();
        root.create_regular(Path::new("seed.raw"), 0o400, true)
            .unwrap();
        assert!(
            root.remove_private_regular(Path::new("seed.raw"), 0o400)
                .unwrap()
        );
        assert!(
            !root
                .remove_private_regular(Path::new("seed.raw"), 0o400)
                .unwrap()
        );

        root.create_regular(Path::new("wrong.raw"), 0o600, true)
            .unwrap();
        assert!(matches!(
            root.remove_private_regular(Path::new("wrong.raw"), 0o400),
            Err(PathError::UnsafeFile(_))
        ));
        assert!(root.path().join("wrong.raw").exists());
    }

    #[test]
    fn hardlinks_and_world_writable_files_are_refused() {
        let (_parent, root) = root();
        let file = root.path().join("artifact");
        File::create(&file).unwrap().write_all(b"artifact").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&file, root.path().join("second-link")).unwrap();
        assert!(matches!(
            root.open_regular(Path::new("artifact"), false, None, false, None),
            Err(PathError::UnsafeFile(_))
        ));
        fs::remove_file(root.path().join("second-link")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(matches!(
            root.open_regular(Path::new("artifact"), false, None, false, None),
            Err(PathError::UnsafeFile(_))
        ));
    }

    #[test]
    fn open_regular_refuses_a_directory() {
        let (_parent, root) = root();
        let directory = root.path().join("not-a-file");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            root.open_regular(Path::new("not-a-file"), false, None, false, None),
            Err(PathError::UnsafeFile(path)) if path == directory
        ));
    }

    #[test]
    fn socket_identity_detects_replacement() {
        let (_parent, root) = root();
        let socket = root.path().join("socket");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let identity = set_socket_private(&socket).unwrap();
        drop(listener);
        fs::remove_file(&socket).unwrap();
        let _replacement = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            identity.revalidate(&socket),
            Err(PathError::SocketIdentityChanged(_))
        ));
    }

    #[test]
    fn atomic_replace_recovers_owned_temp_but_refuses_symlink_temp() {
        let (parent, root) = root();
        let stale = root.path().join(".state.json.tmp");
        File::create(&stale).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
        root.atomic_replace(Path::new("state.json"), b"first", 0o600)
            .unwrap();
        assert_eq!(fs::read(root.path().join("state.json")).unwrap(), b"first");

        let outside = parent.path().join("outside-temp-target");
        File::create(&outside).unwrap();
        symlink(&outside, &stale).unwrap();
        assert!(
            root.atomic_replace(Path::new("state.json"), b"second", 0o600)
                .is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"");
        assert_eq!(fs::read(root.path().join("state.json")).unwrap(), b"first");
    }

    #[test]
    fn private_directory_move_is_no_replace_and_durable() {
        let (_parent, root) = root();
        root.create_dir(Path::new("source"), 0o700).unwrap();
        let destination_path = root.create_dir(Path::new("destination"), 0o700).unwrap();
        let destination = PrivateRoot::open(&destination_path).unwrap();

        root.move_private_directory_to(Path::new("source"), &destination, Path::new("moved"))
            .unwrap();
        assert!(!root.path().join("source").exists());
        assert!(destination.path().join("moved").is_dir());

        root.create_dir(Path::new("second"), 0o700).unwrap();
        assert!(matches!(
            root.move_private_directory_to(Path::new("second"), &destination, Path::new("moved"),),
            Err(PathError::Openat2 {
                source: rustix::io::Errno::EXIST,
                ..
            })
        ));
        assert!(root.path().join("second").is_dir());
        assert!(destination.path().join("moved").is_dir());
    }

    #[test]
    fn private_regular_publish_is_no_replace_and_leaves_loser_intact() {
        let (_parent, root) = root();
        for name in ["first", "second"] {
            let mut file = root
                .create_regular(Path::new(name), 0o400, true)
                .unwrap()
                .into_file();
            file.write_all(name.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        assert!(
            root.publish_private_regular_no_replace(
                Path::new("first"),
                Path::new("published"),
                0o400,
            )
            .unwrap()
        );
        assert!(
            !root
                .publish_private_regular_no_replace(
                    Path::new("second"),
                    Path::new("published"),
                    0o400,
                )
                .unwrap()
        );
        assert_eq!(fs::read(root.path().join("published")).unwrap(), b"first");
        assert_eq!(fs::read(root.path().join("second")).unwrap(), b"second");
    }
}
