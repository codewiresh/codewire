//! Retained-directory filesystem operations for the native per-user runtime.
//!
//! The host kernel and ordinary owner are trusted. Private roots exclude other
//! users; the supervisor serializes namespace mutations. Darwin has no
//! identity-conditional unlink. No Linux mount identifier or persistence format
//! is reused here, and this module does not enable a runtime consumer.

use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::acl;
pub use crate::supervisor_metadata::legacy::{FileIdentity, SocketIdentity};

const O_RESOLVE_BENEATH: libc::c_int = 0x1000;
const O_UNIQUE: libc::c_int = 0x2000;
const PRIVATE_FLAGS: libc::c_int = libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY | O_RESOLVE_BENEATH;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountIdentity {
    device: u64,
    fsid: [i32; 2],
    mounted_on: Vec<u8>,
}

impl MountIdentity {
    fn read(file: &File) -> io::Result<Self> {
        let mut filesystem = std::mem::MaybeUninit::uninit();
        // SAFETY: file remains live and the output buffer has the public statfs layout.
        if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized the complete output structure.
        let filesystem: libc::statfs = unsafe { filesystem.assume_init() };
        // SAFETY: the public fsid_t is repr(C), exactly two int32 values with no
        // padding. transmute also enforces its size; neither value is reinterpreted
        // as a Linux mount ID or serialized into a product contract.
        let fsid = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(filesystem.f_fsid) };
        let mount_bytes: Vec<u8> = filesystem
            .f_mntonname
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        let end = mount_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| io::Error::other("unterminated filesystem mount path"))?;
        if end == 0 {
            return Err(io::Error::other("empty filesystem mount path"));
        }
        Ok(Self {
            device: file.metadata()?.dev(),
            fsid,
            mounted_on: mount_bytes[..end].to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct PrivateRoot {
    path: PathBuf,
    directory: File,
    mount: MountIdentity,
    permissions: u32,
}

impl PrivateRoot {
    pub fn create(path: &Path) -> Result<Self, PathError> {
        validate_absolute(path)?;
        let parent = path
            .parent()
            .filter(|parent| *parent != path)
            .ok_or_else(|| PathError::UnsafeCreateParent(path.to_owned()))?;
        let leaf = path
            .file_name()
            .map(Path::new)
            .ok_or_else(|| PathError::UnsafeCreateParent(path.to_owned()))?;
        let root = Self::open(parent)?;
        root.ensure_dir(leaf, 0o700)?;
        root.after_effect(leaf, || Self::open(path))
    }

    pub fn open(path: &Path) -> Result<Self, PathError> {
        validate_absolute(path)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY)
            .open(path)
            .map_err(|source| io_at(path, source))?;
        validate_directory(&directory, path, 0o700)?;
        let canonical = fs::canonicalize(path).map_err(|source| io_at(path, source))?;
        if canonical.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
            return Err(PathError::NonCanonicalRoot(path.to_owned()));
        }
        let mount = MountIdentity::read(&directory).map_err(|source| io_at(path, source))?;
        let root = Self {
            path: path.to_owned(),
            directory,
            mount,
            permissions: 0o700,
        };
        root.revalidate_named()?;
        Ok(root)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn revalidate_named(&self) -> Result<(), PathError> {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY)
            .open(&self.path)
            .map_err(|source| io_at(&self.path, source))?;
        validate_directory(&named, &self.path, self.permissions)?;
        let retained = self
            .directory
            .metadata()
            .map_err(|source| io_at(&self.path, source))?;
        let metadata = named
            .metadata()
            .map_err(|source| io_at(&self.path, source))?;
        if !same_node(&retained, &metadata) {
            return Err(PathError::RootIdentityChanged(self.path.clone()));
        }
        self.require_mount(&named, &self.path)
    }

    fn require_mount(&self, file: &File, path: &Path) -> Result<(), PathError> {
        if MountIdentity::read(file).map_err(|source| io_at(path, source))? != self.mount {
            return Err(PathError::MountBoundary(path.to_owned()));
        }
        Ok(())
    }

    fn walk(&self, relative: &Path, flags: libc::c_int, mode: u32) -> Result<File, PathError> {
        validate_relative(relative)?;
        self.revalidate_named()?;
        let mut parent = self
            .directory
            .try_clone()
            .map_err(|source| io_at(&self.path, source))?;
        let components: Vec<_> = relative
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .collect();
        let mut resolved = self.path.clone();
        for (index, component) in components.iter().enumerate() {
            let name = CString::new(*component)
                .map_err(|_| PathError::InvalidRelativePath(relative.to_owned()))?;
            let last = index + 1 == components.len();
            let selected = if last {
                flags
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY
            };
            // SAFETY: parent/name are valid; the variadic mode is promoted to int.
            // One raw normal component is resolved per call, never an unchecked path.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    selected | PRIVATE_FLAGS,
                    mode as libc::c_int,
                )
            };
            if fd < 0 {
                return Err(io_at(&self.path.join(relative), io::Error::last_os_error()));
            }
            // SAFETY: openat transferred this newly owned descriptor.
            let opened = unsafe { File::from_raw_fd(fd) };
            resolved.push(std::ffi::OsStr::from_bytes(component));
            if let Err(error) = self.require_mount(&opened, &resolved) {
                return Err(if last && flags & libc::O_CREAT != 0 {
                    PathError::PostEffectUncertain {
                        path: resolved,
                        source: Box::new(error),
                    }
                } else {
                    error
                });
            }
            parent = opened;
        }
        Ok(parent)
    }

    pub fn create_dir(&self, relative: &Path, mode: u32) -> Result<PathBuf, PathError> {
        self.make_directory(relative, mode, false)
    }

    pub fn ensure_dir(&self, relative: &Path, mode: u32) -> Result<PathBuf, PathError> {
        self.make_directory(relative, mode, true)
    }

    fn make_directory(
        &self,
        relative: &Path,
        mode: u32,
        existing: bool,
    ) -> Result<PathBuf, PathError> {
        let name = single_name(relative)?;
        validate_mode(mode)?;
        self.revalidate_named()?;
        // SAFETY: dirfd and single-component C string remain valid.
        let result = unsafe {
            libc::mkdirat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                mode as libc::mode_t,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if !(existing && error.kind() == io::ErrorKind::AlreadyExists) {
                return Err(io_at(&self.path.join(relative), error));
            }
            self.open_directory(relative, mode)?;
        } else {
            self.after_effect(relative, || {
                sync_full(&self.directory).map_err(|source| io_at(&self.path, source))?;
                self.open_directory(relative, mode)?;
                Ok(())
            })?;
        }
        Ok(self.path.join(relative))
    }

    pub fn open_directory(&self, relative: &Path, mode: u32) -> Result<File, PathError> {
        validate_mode(mode)?;
        let opened = self.walk(relative, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        validate_directory(&opened, &self.path.join(relative), mode)?;
        Ok(opened)
    }

    pub fn open_private_directory(&self, relative: &Path, mode: u32) -> Result<Self, PathError> {
        let directory = self.open_directory(relative, mode)?;
        Ok(Self {
            path: self.path.join(relative),
            directory,
            mount: self.mount.clone(),
            permissions: mode,
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
        let access = if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        let file = self.walk(relative, access | libc::O_NONBLOCK | O_UNIQUE, 0)?;
        admit_file(
            file,
            &self.path.join(relative),
            expected_size,
            require_executable,
            exact_permissions,
        )
    }

    pub fn create_regular(
        &self,
        relative: &Path,
        permissions: u32,
        exclusive: bool,
    ) -> Result<ConfinedFile, PathError> {
        single_name(relative)?;
        validate_mode(permissions)?;
        if permissions & 0o022 != 0 {
            return Err(PathError::InvalidPermissions(permissions));
        }
        let mut flags = libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK | O_UNIQUE;
        if exclusive {
            flags |= libc::O_EXCL;
        }
        let file = self.walk(relative, flags, permissions)?;
        self.after_effect(relative, || {
            let admitted = admit_file(
                file,
                &self.path.join(relative),
                None,
                false,
                Some(permissions),
            )?;
            sync_full(admitted.file())
                .map_err(|source| io_at(&self.path.join(relative), source))?;
            sync_full(&self.directory).map_err(|source| io_at(&self.path, source))?;
            self.revalidate_named()?;
            Ok(admitted)
        })
    }

    /// Revalidate a retained regular file without opening or closing that inode.
    /// SQLite uses process-owned POSIX locks: even closing an unrelated descriptor
    /// for its database or SHM would release locks outside SQLite's bookkeeping.
    pub(crate) fn revalidate_regular(
        &self,
        relative: &Path,
        retained: &ConfinedFile,
    ) -> Result<(), PathError> {
        single_name(relative)?;
        self.revalidate_named()?;
        let path = self.path.join(relative);
        self.require_mount(retained.file(), &path)?;
        let identity = regular_identity(
            retained.file(),
            &path,
            None,
            false,
            Some(retained.identity().mode & 0o777),
        )?;
        let expected = retained.identity();
        if identity.device != expected.device
            || identity.inode != expected.inode
            || identity.uid != expected.uid
            || identity.mode != expected.mode
            || identity.links != expected.links
        {
            return Err(PathError::ObjectIdentityChanged(path));
        }
        self.require_named_file(relative, retained.file())?;
        self.revalidate_named()
    }

    pub fn atomic_replace(
        &self,
        relative: &Path,
        bytes: &[u8],
        final_permissions: u32,
    ) -> Result<(), PathError> {
        single_name(relative)?;
        validate_mode(final_permissions)?;
        if final_permissions & 0o022 != 0 {
            return Err(PathError::InvalidPermissions(final_permissions));
        }
        let leaf = relative
            .to_str()
            .ok_or_else(|| PathError::InvalidRelativePath(relative.to_owned()))?;
        let temporary = PathBuf::from(format!(".{leaf}.tmp"));
        let opened = match self.create_regular(&temporary, 0o600, true) {
            Ok(opened) => opened,
            Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
                // Process death can leave the temp either before or after its
                // final chmod. Admit once, then remove only that retained node.
                let stale = self.open_regular(&temporary, false, None, false, None)?;
                self.cleanup_temporary(&temporary, stale.file(), &[0o600, final_permissions])?;
                self.create_regular(&temporary, 0o600, true)?
            }
            Err(error) => return Err(error),
        };
        let preparation = (|| {
            #[cfg(test)]
            tests::inject("write", &temporary)?;
            let mut file = opened.file();
            file.write_all(bytes)
                .map_err(|source| io_at(&self.path.join(&temporary), source))?;
            #[cfg(test)]
            tests::inject("chmod", &temporary)?;
            // SAFETY: changes the owned descriptor, never a re-resolved path.
            if unsafe { libc::fchmod(file.as_raw_fd(), final_permissions as libc::mode_t) } != 0 {
                return Err(io_at(
                    &self.path.join(&temporary),
                    io::Error::last_os_error(),
                ));
            }
            acl::require_empty(file)
                .map_err(|source| io_at(&self.path.join(&temporary), source))?;
            #[cfg(test)]
            tests::inject("file-sync", &temporary)?;
            sync_full(file).map_err(|source| io_at(&self.path.join(&temporary), source))?;
            self.require_named_file(&temporary, file)?;
            self.rename(&temporary, self, relative, false)
        })();
        if let Err(error) = preparation {
            // Cleanup is allowed only before a successful rename and only for
            // the exact still-owned private single-link temp. This also handles
            // a failure after final chmod (e.g.0400), which must not leave a
            // non-0600 stale temp wedging the next replacement attempt.
            self.cleanup_temporary(&temporary, opened.file(), &[0o600, final_permissions])?;
            return Err(error);
        }
        self.after_effect(relative, || {
            self.finish_file_publication(relative, opened.file(), final_permissions)
        })
    }

    fn cleanup_temporary(
        &self,
        relative: &Path,
        expected: &File,
        permissions: &[u32],
    ) -> Result<(), PathError> {
        let path = self.path.join(relative);
        let metadata = expected.metadata().map_err(|error| io_at(&path, error))?;
        let mode = metadata.mode() & 0o777;
        if !permissions.contains(&mode) {
            return Err(PathError::UnsafeFile(path));
        }
        admit_file(
            expected.try_clone().map_err(|error| io_at(&path, error))?,
            &path,
            None,
            false,
            Some(mode),
        )?;
        self.require_named_file(relative, expected)?;
        self.unlink(relative, false)?;
        self.after_effect(relative, || {
            sync_full(&self.directory).map_err(|error| io_at(&self.path, error))?;
            self.revalidate_named()
        })
    }

    pub fn remove_private_regular(
        &self,
        relative: &Path,
        exact_permissions: u32,
    ) -> Result<bool, PathError> {
        single_name(relative)?;
        if self.named_stat(relative)?.is_none() {
            return Ok(false);
        }
        let file = self.open_regular(relative, false, None, false, Some(exact_permissions))?;
        self.require_named_file(relative, file.file())?;
        self.unlink(relative, false)?;
        self.after_effect(relative, || {
            sync_full(&self.directory).map_err(|source| io_at(&self.path, source))?;
            self.revalidate_named()?;
            Ok(true)
        })
    }

    pub fn remove_private_socket(&self, relative: &Path) -> Result<bool, PathError> {
        self.remove_private_socket_with_permissions(relative, &[0o600])
    }

    pub(crate) fn remove_private_socket_with_permissions(
        &self,
        relative: &Path,
        permissions: &[u32],
    ) -> Result<bool, PathError> {
        single_name(relative)?;
        let Some(metadata) = self.named_stat(relative)? else {
            return Ok(false);
        };
        socket_identity(&metadata, &self.path.join(relative), permissions)?;
        // The parent is retained, owner-private and ACL-empty. Both inspection
        // and unlink use its descriptor; no pathname lookup is mixed with unlinkat.
        self.unlink(relative, false)?;
        self.after_effect(relative, || {
            sync_full(&self.directory).map_err(|source| io_at(&self.path, source))?;
            self.revalidate_named()?;
            Ok(true)
        })
    }

    pub fn remove_empty_private_directory(&self, relative: &Path) -> Result<(), PathError> {
        single_name(relative)?;
        let directory = self.open_directory(relative, 0o700)?;
        self.require_named_file(relative, &directory)?;
        self.unlink(relative, true)?;
        self.after_effect(relative, || {
            sync_full(&self.directory).map_err(|source| io_at(&self.path, source))?;
            self.revalidate_named()
        })
    }

    pub fn move_private_directory_to(
        &self,
        source: &Path,
        destination_root: &Self,
        destination: &Path,
    ) -> Result<(), PathError> {
        single_name(source)?;
        single_name(destination)?;
        let directory = self.open_directory(source, 0o700)?;
        self.require_named_file(source, &directory)?;
        sync_full(&directory).map_err(|error| io_at(&self.path.join(source), error))?;
        self.rename(source, destination_root, destination, true)?;
        destination_root.after_effect(destination, || {
            sync_full(&self.directory).map_err(|error| io_at(&self.path, error))?;
            sync_full(&destination_root.directory)
                .map_err(|error| io_at(&destination_root.path, error))?;
            let published = destination_root.open_directory(destination, 0o700)?;
            require_same_file(
                &directory,
                &published,
                &destination_root.path.join(destination),
            )?;
            sync_full(&published)
                .map_err(|error| io_at(&destination_root.path.join(destination), error))?;
            self.revalidate_named()
        })
    }

    /// `false` means an existing destination prevented publication; neither
    /// name was changed and the admitted source remains intact.
    pub fn publish_private_regular_no_replace(
        &self,
        source: &Path,
        destination: &Path,
        exact_permissions: u32,
    ) -> Result<bool, PathError> {
        single_name(source)?;
        single_name(destination)?;
        let file = self.open_regular(source, false, None, false, Some(exact_permissions))?;
        self.require_named_file(source, file.file())?;
        sync_full(file.file()).map_err(|error| io_at(&self.path.join(source), error))?;
        match self.rename(source, self, destination, true) {
            Ok(()) => {}
            Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        self.after_effect(destination, || {
            self.finish_file_publication(destination, file.file(), exact_permissions)?;
            Ok(true)
        })
    }

    fn finish_file_publication(
        &self,
        destination: &Path,
        source: &File,
        permissions: u32,
    ) -> Result<(), PathError> {
        #[cfg(test)]
        tests::inject("parent-sync", destination)?;
        sync_full(&self.directory).map_err(|error| io_at(&self.path, error))?;
        #[cfg(test)]
        tests::inject("readmission", destination)?;
        let published = self.open_regular(destination, false, None, false, Some(permissions))?;
        require_same_file(source, published.file(), &self.path.join(destination))?;
        // Post-rename admission observes materialized ACL inheritance too.
        sync_full(published.file()).map_err(|error| io_at(&self.path.join(destination), error))
    }

    fn named_stat(&self, relative: &Path) -> Result<Option<libc::stat>, PathError> {
        let name = single_name(relative)?;
        self.revalidate_named()?;
        let mut metadata = std::mem::MaybeUninit::uninit();
        // SAFETY: live parent/single leaf and correctly sized output. Nofollow
        // inspects a final symlink itself; later type admission rejects it.
        let result = unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(io_at(&self.path.join(relative), error));
        }
        // SAFETY: successful fstatat initialized metadata.
        Ok(Some(unsafe { metadata.assume_init() }))
    }

    fn require_named_file(&self, relative: &Path, file: &File) -> Result<(), PathError> {
        let retained = file
            .metadata()
            .map_err(|error| io_at(&self.path.join(relative), error))?;
        let named = self
            .named_stat(relative)?
            .ok_or_else(|| PathError::ObjectIdentityChanged(self.path.join(relative)))?;
        if named.st_dev as u64 != retained.dev()
            || named.st_ino != retained.ino()
            || named.st_uid != retained.uid()
            || u32::from(named.st_mode) != retained.mode()
        {
            return Err(PathError::ObjectIdentityChanged(self.path.join(relative)));
        }
        Ok(())
    }

    fn unlink(&self, relative: &Path, directory: bool) -> Result<(), PathError> {
        let name = single_name(relative)?;
        self.revalidate_named()?;
        let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: live retained dirfd, validated leaf, and public unlink flags.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            return Err(io_at(&self.path.join(relative), io::Error::last_os_error()));
        }
        Ok(())
    }

    fn rename(
        &self,
        source: &Path,
        destination_root: &Self,
        destination: &Path,
        exclusive: bool,
    ) -> Result<(), PathError> {
        let source_name = single_name(source)?;
        let destination_name = single_name(destination)?;
        self.revalidate_named()?;
        destination_root.revalidate_named()?;
        if self.mount != destination_root.mount {
            return Err(PathError::MountBoundary(destination_root.path.clone()));
        }
        #[cfg(test)]
        tests::inject("rename", source)?;
        // SAFETY: both retained descriptors and validated leaf names are live.
        // RENAME_EXCL is atomic no-replace, never a check-then-rename sequence.
        let result = unsafe {
            libc::renameatx_np(
                self.directory.as_raw_fd(),
                source_name.as_ptr(),
                destination_root.directory.as_raw_fd(),
                destination_name.as_ptr(),
                if exclusive { libc::RENAME_EXCL } else { 0 },
            )
        };
        if result != 0 {
            return Err(io_at(
                &destination_root.path.join(destination),
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn after_effect<T>(
        &self,
        relative: &Path,
        operation: impl FnOnce() -> Result<T, PathError>,
    ) -> Result<T, PathError> {
        #[cfg(test)]
        let outcome = tests::inject("after-effect", relative).and_then(|()| operation());
        #[cfg(not(test))]
        let outcome = operation();
        outcome.map_err(|source| PathError::PostEffectUncertain {
            path: self.path.join(relative),
            source: Box::new(source),
        })
    }
}

impl SocketIdentity {
    pub fn capture(path: &Path) -> Result<Self, PathError> {
        Self::capture_with_permissions(path, &[0o600])
    }

    pub(crate) fn capture_with_permissions(
        path: &Path,
        permissions: &[u32],
    ) -> Result<Self, PathError> {
        let (parent, leaf) = socket_parent(path)?;
        let metadata = parent
            .named_stat(leaf)?
            .ok_or_else(|| io_at(path, io::Error::from(io::ErrorKind::NotFound)))?;
        socket_identity(&metadata, path, permissions)
    }

    pub fn revalidate(&self, path: &Path) -> Result<(), PathError> {
        if &Self::capture(path)? != self {
            return Err(PathError::SocketIdentityChanged(path.to_owned()));
        }
        Ok(())
    }
}

pub fn set_socket_private(path: &Path) -> Result<SocketIdentity, PathError> {
    let (parent, leaf) = socket_parent(path)?;
    let before = parent
        .named_stat(leaf)?
        .ok_or_else(|| io_at(path, io::Error::from(io::ErrorKind::NotFound)))?;
    let identity = socket_identity(&before, path, &[u32::from(before.st_mode) & 0o777])?;
    let name = single_name(leaf)?;
    // SAFETY: admitted private parent and owned socket leaf; never follow a symlink.
    if unsafe {
        libc::fchmodat(
            parent.directory.as_raw_fd(),
            name.as_ptr(),
            0o600,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io_at(path, io::Error::last_os_error()));
    }
    parent.after_effect(leaf, || {
        let after = parent
            .named_stat(leaf)?
            .ok_or_else(|| PathError::SocketIdentityChanged(path.to_owned()))?;
        let admitted = socket_identity(&after, path, &[0o600])?;
        if (admitted.device, admitted.inode, admitted.uid)
            != (identity.device, identity.inode, identity.uid)
        {
            return Err(PathError::SocketIdentityChanged(path.to_owned()));
        }
        sync_full(&parent.directory).map_err(|error| io_at(parent.path(), error))?;
        Ok(admitted)
    })
}

fn socket_parent(path: &Path) -> Result<(PrivateRoot, &Path), PathError> {
    validate_absolute(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| PathError::UnsafeSocket(path.to_owned()))?;
    let leaf = path
        .file_name()
        .map(Path::new)
        .ok_or_else(|| PathError::UnsafeSocket(path.to_owned()))?;
    Ok((PrivateRoot::open(parent)?, leaf))
}

fn socket_identity(
    metadata: &libc::stat,
    path: &Path,
    permissions: &[u32],
) -> Result<SocketIdentity, PathError> {
    let mode = u32::from(metadata.st_mode);
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_uid != current_uid()
        || metadata.st_nlink != 1
        || !permissions.contains(&(mode & 0o777))
    {
        return Err(PathError::UnsafeSocket(path.to_owned()));
    }
    Ok(SocketIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino,
        uid: metadata.st_uid,
        mode,
    })
}

pub fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions or memory effects.
    unsafe { libc::geteuid() }
}

fn validate_directory(file: &File, path: &Path, mode: u32) -> Result<(), PathError> {
    let metadata = file.metadata().map_err(|error| io_at(path, error))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() || metadata.mode() & 0o777 != mode {
        return Err(PathError::UnsafeDirectory(path.to_owned()));
    }
    acl::require_empty(file).map_err(|error| io_at(path, error))
}

fn admit_file(
    file: File,
    path: &Path,
    expected_size: Option<u64>,
    executable: bool,
    permissions: Option<u32>,
) -> Result<ConfinedFile, PathError> {
    let identity = regular_identity(&file, path, expected_size, executable, permissions)?;
    Ok(ConfinedFile { identity, file })
}

fn regular_identity(
    file: &File,
    path: &Path,
    expected_size: Option<u64>,
    executable: bool,
    permissions: Option<u32>,
) -> Result<FileIdentity, PathError> {
    let metadata = file.metadata().map_err(|error| io_at(path, error))?;
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || executable && metadata.mode() & 0o100 == 0
        || expected_size.is_some_and(|size| size != metadata.len())
        || permissions.is_some_and(|mode| mode != metadata.mode() & 0o777)
    {
        return Err(PathError::UnsafeFile(path.to_owned()));
    }
    acl::require_empty(file).map_err(|error| io_at(path, error))?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn same_node(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.file_type() == right.file_type()
}

fn require_same_file(left: &File, right: &File, path: &Path) -> Result<(), PathError> {
    if !same_node(
        &left.metadata().map_err(|error| io_at(path, error))?,
        &right.metadata().map_err(|error| io_at(path, error))?,
    ) {
        return Err(PathError::ObjectIdentityChanged(path.to_owned()));
    }
    Ok(())
}

fn sync_full(file: &File) -> io::Result<()> {
    file.sync_all()?;
    // SAFETY: file owns a live descriptor; F_FULLFSYNC has no pointer argument.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_absolute(path: &Path) -> Result<(), PathError> {
    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"/") {
        return Err(PathError::RootNotAbsolute(path.to_owned()));
    }
    if bytes == b"/" {
        return Ok(());
    }
    if !valid_segments(&bytes[1..]) {
        return Err(PathError::NonCanonicalRoot(path.to_owned()));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), PathError> {
    if !valid_segments(path.as_os_str().as_bytes()) {
        return Err(PathError::InvalidRelativePath(path.to_owned()));
    }
    Ok(())
}

fn valid_segments(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
        && bytes
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

fn single_name(path: &Path) -> Result<CString, PathError> {
    validate_relative(path)?;
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&b'/') {
        return Err(PathError::InvalidRelativePath(path.to_owned()));
    }
    CString::new(bytes).map_err(|_| PathError::InvalidRelativePath(path.to_owned()))
}

fn validate_mode(mode: u32) -> Result<(), PathError> {
    if mode & !0o777 != 0 {
        return Err(PathError::InvalidPermissions(mode));
    }
    Ok(())
}

fn io_at(path: &Path, source: io::Error) -> PathError {
    PathError::Io {
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("private root must be absolute: {0}")]
    RootNotAbsolute(PathBuf),
    #[error("private root must have an exact canonical spelling: {0}")]
    NonCanonicalRoot(PathBuf),
    #[error("private root creation requires an existing private parent: {0}")]
    UnsafeCreateParent(PathBuf),
    #[error("private root pathname changed: {0}")]
    RootIdentityChanged(PathBuf),
    #[error("invalid confined relative path: {0}")]
    InvalidRelativePath(PathBuf),
    #[error("invalid filesystem permissions: {0:o}")]
    InvalidPermissions(u32),
    #[error("unsafe private directory: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("unsafe private regular file: {0}")]
    UnsafeFile(PathBuf),
    #[error("unsafe private Unix socket: {0}")]
    UnsafeSocket(PathBuf),
    #[error("Unix socket identity changed: {0}")]
    SocketIdentityChanged(PathBuf),
    #[error("retained object identity changed: {0}")]
    ObjectIdentityChanged(PathBuf),
    #[error("confined path crosses a filesystem mount boundary: {0}")]
    MountBoundary(PathBuf),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error(
        "filesystem effect may have occurred for {path}; preserve state for recovery: {source}"
    )]
    PostEffectUncertain {
        path: PathBuf,
        source: Box<PathError>,
    },
}

#[cfg(test)]
mod tests;
