use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::time::Duration;

use codewire_cw_release::sha256::Sha256;
#[cfg(test)]
use codewire_vmm_guest_probe::canonical_guest_root_newc;
use codewire_vmm_guest_probe::canonical_guest_root_newc_with_cw;
#[cfg(test)]
use codewire_vmm_guest_probe::canonical_newc;
use codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_PROVENANCE_ENTRY;
pub use codewire_vmm_guest_probe::cw_runtime::{
    CW_RUNTIME_ELF_MACHINE, CW_RUNTIME_ROOT, CW_RUNTIME_TARGET, CwRuntimeCatalog,
    CwRuntimeProvenance, validate_static_cw,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;

use crate::host::path::{FileIdentity, PathError, PrivateRoot};

pub const ARTIFACT_LOCK_SCHEMA_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
pub const CLOUD_HYPERVISOR_RELEASE: &str = "v54.0";
#[cfg(target_os = "linux")]
pub const VIRTIOFSD_RELEASE: &str = "v1.14.0";
#[cfg(target_os = "linux")]
const VERSION_OUTPUT_LIMIT: u64 = 4096;
#[cfg(target_os = "linux")]
const VERSION_TIMEOUT: Duration = Duration::from_secs(2);
const ARTIFACT_LOCK_LIMIT: u64 = 1024 * 1024;
const INITRAMFS_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactArchitecture {
    X86_64,
    Aarch64,
}

impl ArtifactArchitecture {
    pub fn host() -> Result<Self, ArtifactError> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            architecture => Err(ArtifactError::UnsupportedArchitecture(
                architecture.to_owned(),
            )),
        }
    }

    fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub architecture: ArtifactArchitecture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableArtifactSpec {
    #[serde(flatten)]
    pub artifact: ArtifactSpec,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLock {
    pub schema_version: u32,
    #[cfg(target_os = "linux")]
    pub cloud_hypervisor: ExecutableArtifactSpec,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtiofsd: Option<ExecutableArtifactSpec>,
    /// The signed Virtualization.framework helper. Its SHA-256 pins the exact
    /// signed bytes, so admission checks only its arm64 Mach-O header.
    #[cfg(target_os = "macos")]
    pub vz_runner: ArtifactSpec,
    /// The ext4 tools that format, check and resize this runtime's disks. A
    /// stock Mac has none, so the runtime ships its own pinned build.
    #[cfg(target_os = "macos")]
    pub e2fsprogs: E2fsprogsSpec,
    /// The git that checks out and bundles workspace repositories. A stock
    /// Mac has only a stub that asks for the Xcode Command Line Tools.
    #[cfg(target_os = "macos")]
    pub git: GitSpec,
    pub kernel: ArtifactSpec,
    pub initramfs: ArtifactSpec,
}

/// Pinned e2fsprogs programs (arm64 Mach-O, linked only to libSystem) and the
/// mke2fs configuration every format uses.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2fsprogsSpec {
    pub mkfs_ext4: ArtifactSpec,
    pub e2fsck: ArtifactSpec,
    pub resize2fs: ArtifactSpec,
    pub debugfs: ArtifactSpec,
    pub mke2fs_conf: ArtifactSpec,
}

/// Pinned git (arm64 Mach-O, linked only to stock system libraries) and the
/// HTTPS remote helper it runs from the same directory (`GIT_EXEC_PATH`).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSpec {
    pub git: ArtifactSpec,
    pub git_remote_https: ArtifactSpec,
}

/// The admitted git of a macOS runtime.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedGit {
    pub git: AdmittedArtifact,
    pub git_remote_https: AdmittedArtifact,
}

/// The admitted e2fsprogs of a macOS runtime.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedE2fsprogs {
    pub mkfs_ext4: AdmittedArtifact,
    pub e2fsck: AdmittedArtifact,
    pub resize2fs: AdmittedArtifact,
    pub debugfs: AdmittedArtifact,
    pub mke2fs_conf: AdmittedArtifact,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AdmittedArtifact {
    root: PathBuf,
    relative_path: PathBuf,
    path: PathBuf,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    executable: bool,
}

impl fmt::Debug for AdmittedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedArtifact")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl AdmittedArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    /// Re-open beneath the private dirfd and re-hash immediately before a
    /// spawn. Same-UID replacement remains explicitly inside the host trust
    /// boundary; a different inode is still rejected rather than adopted.
    pub fn revalidate(&self) -> Result<(), ArtifactError> {
        let file = self.open_exact()?;
        if sha256_file(&file, &self.path)? != self.sha256 {
            return Err(ArtifactError::IdentityChanged(self.path.clone()));
        }
        Ok(())
    }

    pub(crate) fn open_exact(&self) -> Result<File, ArtifactError> {
        let root = PrivateRoot::open(&self.root).map_err(ArtifactError::ConfinedPath)?;
        let opened = root
            .open_regular(
                &self.relative_path,
                false,
                Some(self.size),
                self.executable,
                Some(if self.executable { 0o500 } else { 0o400 }),
            )
            .map_err(ArtifactError::ConfinedPath)?;
        if opened.identity() != &self.identity {
            return Err(ArtifactError::IdentityChanged(self.path.clone()));
        }
        Ok(opened.into_file())
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            root: path.parent().unwrap_or(Path::new("/")).to_owned(),
            relative_path: path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("artifact")),
            path,
            identity: FileIdentity {
                device: 0,
                inode: 0,
                size: 1,
                uid: 0,
                mode: 0o100600,
                links: 1,
                pin: Default::default(),
            },
            size: 1,
            sha256: "a".repeat(64),
            executable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedArtifacts {
    #[cfg(target_os = "linux")]
    pub cloud_hypervisor: AdmittedArtifact,
    #[cfg(target_os = "linux")]
    pub virtiofsd: Option<AdmittedArtifact>,
    #[cfg(target_os = "macos")]
    pub vz_runner: AdmittedArtifact,
    #[cfg(target_os = "macos")]
    pub e2fsprogs: AdmittedE2fsprogs,
    #[cfg(target_os = "macos")]
    pub git: AdmittedGit,
    pub kernel: AdmittedArtifact,
    pub initramfs: AdmittedArtifact,
}

impl AdmittedArtifacts {
    pub fn revalidate(&self) -> Result<(), ArtifactError> {
        for executable in self.executables() {
            executable.revalidate()?;
        }
        for file in self.data_files() {
            file.revalidate()?;
        }
        Ok(())
    }

    /// The admitted data files, in the order of `ArtifactLock::data_files`.
    pub(crate) fn data_files(&self) -> Vec<&AdmittedArtifact> {
        let files = vec![&self.kernel, &self.initramfs];
        #[cfg(target_os = "macos")]
        let files = {
            let mut files = files;
            files.push(&self.e2fsprogs.mke2fs_conf);
            files
        };
        files
    }

    /// The admitted executables, in the order of `ArtifactLock::executables`.
    pub(crate) fn executables(&self) -> Vec<&AdmittedArtifact> {
        #[cfg(target_os = "linux")]
        {
            let mut executables = vec![&self.cloud_hypervisor];
            executables.extend(&self.virtiofsd);
            executables
        }
        #[cfg(target_os = "macos")]
        {
            let tools = &self.e2fsprogs;
            vec![
                &self.vz_runner,
                &tools.mkfs_ext4,
                &tools.e2fsck,
                &tools.resize2fs,
                &tools.debugfs,
                &self.git.git,
                &self.git.git_remote_https,
            ]
        }
    }

    /// Test artifacts whose host VMM executable is `vmm`, with no other helper.
    #[cfg(test)]
    pub(crate) fn for_test(
        vmm: AdmittedArtifact,
        kernel: AdmittedArtifact,
        initramfs: AdmittedArtifact,
    ) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            cloud_hypervisor: vmm,
            #[cfg(target_os = "linux")]
            virtiofsd: None,
            #[cfg(target_os = "macos")]
            vz_runner: vmm,
            #[cfg(target_os = "macos")]
            e2fsprogs: AdmittedE2fsprogs {
                mkfs_ext4: AdmittedArtifact::for_test("/unused/mkfs.ext4"),
                e2fsck: AdmittedArtifact::for_test("/unused/e2fsck"),
                resize2fs: AdmittedArtifact::for_test("/unused/resize2fs"),
                debugfs: AdmittedArtifact::for_test("/unused/debugfs"),
                mke2fs_conf: AdmittedArtifact::for_test("/unused/mke2fs.conf"),
            },
            #[cfg(target_os = "macos")]
            git: AdmittedGit {
                git: AdmittedArtifact::for_test("/unused/git"),
                git_remote_https: AdmittedArtifact::for_test("/unused/git-remote-https"),
            },
            kernel,
            initramfs,
        }
    }

    pub(crate) fn read_guest_busybox(&self) -> Result<Vec<u8>, ArtifactError> {
        read_canonical_initramfs_entry(&self.initramfs, b"bin/busybox")
    }

    pub(crate) fn require_current_guest_seed_abi(&self) -> Result<(), ArtifactError> {
        let init = read_canonical_initramfs_entry(&self.initramfs, b"init")?;
        let marker = codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER;
        let prefix = b"\0CWGUESTABI\0";
        if init
            .windows(marker.len())
            .filter(|bytes| *bytes == marker)
            .count()
            != 1
            || init
                .windows(prefix.len())
                .filter(|bytes| *bytes == prefix)
                .count()
                != 1
        {
            return Err(ArtifactError::GuestSeedProtocolUnsupported(
                self.initramfs.path().to_owned(),
            ));
        }
        Ok(())
    }

    /// The guest init binds `workspace.vm_only` paths (#vm_only); an older one
    /// would refuse such a plan only at boot.
    pub(crate) fn require_vm_only_guest(&self) -> Result<(), ArtifactError> {
        let init = read_canonical_initramfs_entry(&self.initramfs, b"init")?;
        let marker = codewire_vmm_guest_probe::VM_ONLY_CAPABILITY_MARKER;
        if init
            .windows(marker.len())
            .filter(|bytes| *bytes == marker)
            .count()
            != 1
        {
            return Err(ArtifactError::GuestVmOnlyUnsupported(
                self.initramfs.path().to_owned(),
            ));
        }
        Ok(())
    }

    /// The guest init answers the VM checkpoint hook (#3046 R4): only a boot
    /// of such a guest is checkpointed, and its checkpoints restored.
    #[cfg(target_os = "linux")]
    pub(crate) fn require_guest_checkpoint_abi(&self) -> Result<(), ArtifactError> {
        let init = read_canonical_initramfs_entry(&self.initramfs, b"init")?;
        let marker = codewire_vmm_guest_probe::GUEST_CHECKPOINT_ABI_MARKER;
        if init
            .windows(marker.len())
            .filter(|bytes| *bytes == marker)
            .count()
            != 1
        {
            return Err(ArtifactError::GuestCheckpointUnsupported(
                self.initramfs.path().to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn require_live_cw_runtime_publisher(&self) -> Result<(), ArtifactError> {
        let init = read_canonical_initramfs_entry(&self.initramfs, b"init")?;
        let marker = codewire_vmm_guest_probe::cw_runtime_live::LIVE_RUNTIME_CAPABILITY_MARKER;
        if init
            .windows(marker.len())
            .filter(|bytes| *bytes == marker)
            .count()
            != 1
        {
            return Err(ArtifactError::GuestLiveRuntimeUnsupported(
                self.initramfs.path().to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error(
        "retained guest has no trusted live cw publisher; it cannot be retrofitted without an explicit later boot: {0}"
    )]
    GuestLiveRuntimeUnsupported(PathBuf),
    #[error(
        "retained boot assets do not support the current startup protocol; explicitly upgrade the environment boot assets before starting or updating cw: {0}"
    )]
    GuestSeedProtocolUnsupported(PathBuf),
    #[error(
        "this environment's guest has no VM checkpoint hook; restart it once with this cw's runtime to enable VM checkpoints: {0}"
    )]
    GuestCheckpointUnsupported(PathBuf),
    #[error(
        "this local VM runtime cannot keep codewire.yaml workspace.vm_only folders on the VM's disk; reinstall it with `cw setup --local --replace`, or set `workspace: {{vm_only: []}}`: {0}"
    )]
    GuestVmOnlyUnsupported(PathBuf),
    #[error("read artifact lock {path}: {source}")]
    ReadLock { path: PathBuf, source: io::Error },
    #[error("decode artifact lock {path}: {source}")]
    DecodeLock {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("encode canonical artifact lock: {0}")]
    EncodeLock(serde_json::Error),
    #[error("artifact lock is empty or exceeds the 1 MiB admission limit: {0}")]
    InvalidLockSize(PathBuf),
    #[error("artifact lock schema {0} is unsupported")]
    UnsupportedSchema(u32),
    #[error("unsupported host architecture {0}")]
    UnsupportedArchitecture(String),
    #[error("artifact architecture does not match this host")]
    ArchitectureMismatch,
    #[error("artifact path must be a non-empty relative path without traversal: {0}")]
    InvalidRelativePath(PathBuf),
    #[error("artifact path contains characters unsafe for Cloud Hypervisor parameters: {0}")]
    UnsafePath(PathBuf),
    #[error("artifact SHA-256 must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error(transparent)]
    ConfinedPath(PathError),
    #[error("inspect artifact {path}: {source}")]
    Inspect { path: PathBuf, source: io::Error },
    #[error("artifact identity or content changed after admission: {0}")]
    IdentityChanged(PathBuf),
    #[error("artifact digest differs from its lock entry: {0}")]
    DigestMismatch(PathBuf),
    #[error("artifact has an invalid or wrong-architecture ELF header: {0}")]
    InvalidElf(PathBuf),
    #[error("artifact is not a thin arm64 Mach-O executable: {0}")]
    InvalidMachO(PathBuf),
    #[error("kernel artifact has an invalid or wrong-architecture image header: {0}")]
    InvalidKernel(PathBuf),
    #[error("initramfs is not an exact canonical Codewire guest-root newc archive: {0}")]
    InvalidInitramfs(PathBuf),
    #[cfg(target_os = "linux")]
    #[error("Cloud Hypervisor lock must pin release {expected}")]
    WrongCloudHypervisorRelease { expected: &'static str },
    #[cfg(target_os = "linux")]
    #[error("virtiofsd lock must pin release {expected}")]
    WrongVirtiofsdRelease { expected: &'static str },
    #[cfg(target_os = "linux")]
    #[error("runtime executable version probe failed")]
    VersionProbe,
    #[cfg(target_os = "linux")]
    #[error("runtime executable reported an unexpected version")]
    VersionMismatch,
}

impl ArtifactLock {
    pub(crate) fn canonical_json(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::EncodeLock)
    }

    pub(crate) fn generation(&self) -> Result<String, ArtifactError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_json()?)))
    }

    /// The executable entries in publication order.
    pub(crate) fn executables(&self) -> Vec<&ArtifactSpec> {
        #[cfg(target_os = "linux")]
        {
            let mut executables = vec![&self.cloud_hypervisor.artifact];
            executables.extend(self.virtiofsd.iter().map(|spec| &spec.artifact));
            executables
        }
        #[cfg(target_os = "macos")]
        {
            let tools = &self.e2fsprogs;
            vec![
                &self.vz_runner,
                &tools.mkfs_ext4,
                &tools.e2fsck,
                &tools.resize2fs,
                &tools.debugfs,
                &self.git.git,
                &self.git.git_remote_https,
            ]
        }
    }

    /// The non-executable entries in publication order.
    pub(crate) fn data_files(&self) -> Vec<&ArtifactSpec> {
        let files = vec![&self.kernel, &self.initramfs];
        #[cfg(target_os = "macos")]
        let files = {
            let mut files = files;
            files.push(&self.e2fsprogs.mke2fs_conf);
            files
        };
        files
    }

    pub(crate) fn data_files_mut(&mut self) -> Vec<&mut ArtifactSpec> {
        let files = vec![&mut self.kernel, &mut self.initramfs];
        #[cfg(target_os = "macos")]
        let files = {
            let mut files = files;
            files.push(&mut self.e2fsprogs.mke2fs_conf);
            files
        };
        files
    }

    /// A test lock whose host VMM executable is `vmm`, with no other helper.
    #[cfg(test)]
    pub(crate) fn for_test(
        vmm: ArtifactSpec,
        kernel: ArtifactSpec,
        initramfs: ArtifactSpec,
    ) -> Self {
        Self {
            schema_version: ARTIFACT_LOCK_SCHEMA_VERSION,
            #[cfg(target_os = "linux")]
            cloud_hypervisor: ExecutableArtifactSpec {
                artifact: vmm,
                version: CLOUD_HYPERVISOR_RELEASE.to_owned(),
            },
            #[cfg(target_os = "linux")]
            virtiofsd: None,
            // The test tools are installed copies of the VMM bytes, and the
            // configuration a copy of the initramfs, under their own names.
            #[cfg(target_os = "macos")]
            e2fsprogs: E2fsprogsSpec {
                mkfs_ext4: ArtifactSpec {
                    path: PathBuf::from("mkfs.ext4"),
                    ..vmm.clone()
                },
                e2fsck: ArtifactSpec {
                    path: PathBuf::from("e2fsck"),
                    ..vmm.clone()
                },
                resize2fs: ArtifactSpec {
                    path: PathBuf::from("resize2fs"),
                    ..vmm.clone()
                },
                debugfs: ArtifactSpec {
                    path: PathBuf::from("debugfs"),
                    ..vmm.clone()
                },
                mke2fs_conf: ArtifactSpec {
                    path: PathBuf::from("mke2fs.conf"),
                    ..initramfs.clone()
                },
            },
            #[cfg(target_os = "macos")]
            git: GitSpec {
                git: ArtifactSpec {
                    path: PathBuf::from("git"),
                    ..vmm.clone()
                },
                git_remote_https: ArtifactSpec {
                    path: PathBuf::from("git-remote-https"),
                    ..vmm.clone()
                },
            },
            #[cfg(target_os = "macos")]
            vz_runner: vmm,
            kernel,
            initramfs,
        }
    }

    /// The host VMM executable entry.
    #[cfg(test)]
    pub(crate) fn vmm(&self) -> &ArtifactSpec {
        self.executables()[0]
    }

    pub(crate) fn executables_mut(&mut self) -> Vec<&mut ArtifactSpec> {
        #[cfg(target_os = "linux")]
        {
            let mut executables = vec![&mut self.cloud_hypervisor.artifact];
            executables.extend(self.virtiofsd.iter_mut().map(|spec| &mut spec.artifact));
            executables
        }
        #[cfg(target_os = "macos")]
        {
            let tools = &mut self.e2fsprogs;
            vec![
                &mut self.vz_runner,
                &mut tools.mkfs_ext4,
                &mut tools.e2fsck,
                &mut tools.resize2fs,
                &mut tools.debugfs,
                &mut self.git.git,
                &mut self.git.git_remote_https,
            ]
        }
    }

    pub(crate) fn validate_metadata(&self) -> Result<ArtifactArchitecture, ArtifactError> {
        if self.schema_version != ARTIFACT_LOCK_SCHEMA_VERSION {
            return Err(ArtifactError::UnsupportedSchema(self.schema_version));
        }
        let architecture = ArtifactArchitecture::host()?;
        for spec in self.executables().into_iter().chain(self.data_files()) {
            validate_spec(spec, architecture)?;
        }
        #[cfg(target_os = "linux")]
        if self
            .virtiofsd
            .as_ref()
            .is_some_and(|virtiofsd| virtiofsd.version != VIRTIOFSD_RELEASE)
        {
            return Err(ArtifactError::WrongVirtiofsdRelease {
                expected: VIRTIOFSD_RELEASE,
            });
        }
        #[cfg(target_os = "linux")]
        if self.cloud_hypervisor.version != CLOUD_HYPERVISOR_RELEASE {
            return Err(ArtifactError::WrongCloudHypervisorRelease {
                expected: CLOUD_HYPERVISOR_RELEASE,
            });
        }
        Ok(architecture)
    }

    pub fn read(path: &Path) -> Result<Self, ArtifactError> {
        let parent_path = path
            .parent()
            .ok_or_else(|| ArtifactError::InvalidRelativePath(path.to_owned()))?;
        let file_name = path
            .file_name()
            .map(Path::new)
            .ok_or_else(|| ArtifactError::InvalidRelativePath(path.to_owned()))?;
        let parent = PrivateRoot::open(parent_path).map_err(ArtifactError::ConfinedPath)?;
        let opened = parent
            .open_regular(file_name, false, None, false, Some(0o400))
            .map_err(ArtifactError::ConfinedPath)?;
        if opened.identity().size == 0 || opened.identity().size > ARTIFACT_LOCK_LIMIT {
            return Err(ArtifactError::InvalidLockSize(path.to_owned()));
        }
        let mut bytes = Vec::with_capacity(opened.identity().size as usize);
        opened
            .file()
            .take(ARTIFACT_LOCK_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| ArtifactError::ReadLock {
                path: path.to_owned(),
                source,
            })?;
        if bytes.is_empty() || bytes.len() as u64 > ARTIFACT_LOCK_LIMIT {
            return Err(ArtifactError::InvalidLockSize(path.to_owned()));
        }
        serde_json::from_slice(&bytes).map_err(|source| ArtifactError::DecodeLock {
            path: path.to_owned(),
            source,
        })
    }

    pub async fn admit(&self, root_path: &Path) -> Result<AdmittedArtifacts, ArtifactError> {
        let architecture = self.validate_metadata()?;
        let root = PrivateRoot::open(root_path).map_err(ArtifactError::ConfinedPath)?;
        #[cfg(target_os = "linux")]
        let executables = self.admit_linux_executables(&root, architecture).await?;
        #[cfg(target_os = "macos")]
        let vz_runner = admit_macho(&root, &self.vz_runner)?;
        #[cfg(target_os = "macos")]
        let (e2fsprogs, git) = self.admit_tools(&root)?;

        let kernel = admit_one(&root, &self.kernel, false)?;
        with_opened(&root, &kernel, |file| {
            validate_kernel(file, kernel.path(), architecture)
        })?;

        let initramfs = admit_one(&root, &self.initramfs, false)?;
        with_opened(&root, &initramfs, |file| {
            validate_initramfs(file, initramfs.path(), architecture)
        })?;

        #[cfg(target_os = "linux")]
        let (cloud_hypervisor, virtiofsd) = executables;
        Ok(AdmittedArtifacts {
            #[cfg(target_os = "linux")]
            cloud_hypervisor,
            #[cfg(target_os = "linux")]
            virtiofsd,
            #[cfg(target_os = "macos")]
            vz_runner,
            #[cfg(target_os = "macos")]
            e2fsprogs,
            #[cfg(target_os = "macos")]
            git,
            kernel,
            initramfs,
        })
    }

    /// Admits only a macOS runtime's host tools and makes them the ones this
    /// process uses, so workspace preparation can run them before the VM
    /// inputs are admitted.
    #[cfg(target_os = "macos")]
    pub(crate) fn admit_host_tools(&self, root_path: &Path) -> Result<(), ArtifactError> {
        self.validate_metadata()?;
        let root = PrivateRoot::open(root_path).map_err(ArtifactError::ConfinedPath)?;
        self.admit_tools(&root).map(|_| ())
    }

    /// The runtime's git and helper directory, admitted against this lock
    /// from the installed runtime immediately before a credential-bearing
    /// process runs it. A path that is not exactly the admitted file is
    /// refused by the caller.
    #[cfg(target_os = "macos")]
    pub fn admit_runtime_git(&self, root_path: &Path) -> Result<(PathBuf, PathBuf), ArtifactError> {
        self.validate_metadata()?;
        let root = PrivateRoot::open(root_path).map_err(ArtifactError::ConfinedPath)?;
        let git = admit_macho(&root, &self.git.git)?;
        let helper = admit_macho(&root, &self.git.git_remote_https)?;
        let helpers = helper
            .path()
            .parent()
            .ok_or_else(|| ArtifactError::InvalidRelativePath(helper.path().to_owned()))?
            .to_owned();
        Ok((git.path().to_owned(), helpers))
    }

    #[cfg(target_os = "macos")]
    fn admit_tools(
        &self,
        root: &PrivateRoot,
    ) -> Result<(AdmittedE2fsprogs, AdmittedGit), ArtifactError> {
        let e2fsprogs = AdmittedE2fsprogs {
            mkfs_ext4: admit_macho(root, &self.e2fsprogs.mkfs_ext4)?,
            e2fsck: admit_macho(root, &self.e2fsprogs.e2fsck)?,
            resize2fs: admit_macho(root, &self.e2fsprogs.resize2fs)?,
            debugfs: admit_macho(root, &self.e2fsprogs.debugfs)?,
            mke2fs_conf: admit_one(root, &self.e2fsprogs.mke2fs_conf, false)?,
        };
        let git = AdmittedGit {
            git: admit_macho(root, &self.git.git)?,
            git_remote_https: admit_macho(root, &self.git.git_remote_https)?,
        };
        crate::host::use_runtime_tools(&e2fsprogs, &git);
        Ok((e2fsprogs, git))
    }

    #[cfg(target_os = "linux")]
    async fn admit_linux_executables(
        &self,
        root: &PrivateRoot,
        architecture: ArtifactArchitecture,
    ) -> Result<(AdmittedArtifact, Option<AdmittedArtifact>), ArtifactError> {
        let cloud_hypervisor = admit_one(root, &self.cloud_hypervisor.artifact, true)?;
        with_opened(root, &cloud_hypervisor, |file| {
            validate_elf(file, cloud_hypervisor.path(), architecture)
        })?;
        verify_cloud_hypervisor_version(cloud_hypervisor.path()).await?;

        let virtiofsd = if let Some(spec) = &self.virtiofsd {
            let artifact = admit_one(root, &spec.artifact, true)?;
            with_opened(root, &artifact, |file| {
                validate_elf(file, artifact.path(), architecture)
            })?;
            verify_virtiofsd_version(artifact.path()).await?;
            Some(artifact)
        } else {
            None
        };
        Ok((cloud_hypervisor, virtiofsd))
    }
}

#[cfg(target_os = "macos")]
fn admit_macho(root: &PrivateRoot, spec: &ArtifactSpec) -> Result<AdmittedArtifact, ArtifactError> {
    let artifact = admit_one(root, spec, true)?;
    with_opened(root, &artifact, |file| {
        validate_arm64_macho(file, artifact.path())
    })?;
    Ok(artifact)
}

fn validate_spec(
    spec: &ArtifactSpec,
    expected_architecture: ArtifactArchitecture,
) -> Result<(), ArtifactError> {
    validate_relative_path(&spec.path)?;
    validate_parameter_path(&spec.path)?;
    if spec.size == 0 {
        return Err(ArtifactError::IdentityChanged(spec.path.clone()));
    }
    if spec.architecture != expected_architecture {
        return Err(ArtifactError::ArchitectureMismatch);
    }
    if spec.sha256.len() != 64
        || !spec
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArtifactError::InvalidDigest);
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), ArtifactError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArtifactError::InvalidRelativePath(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_parameter_path(path: &Path) -> Result<(), ArtifactError> {
    let Some(path_text) = path.to_str() else {
        return Err(ArtifactError::UnsafePath(path.to_owned()));
    };
    if path_text
        .bytes()
        .any(|byte| matches!(byte, b',' | b'=' | b'\n' | b'\r' | 0))
    {
        return Err(ArtifactError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn admit_one(
    root: &PrivateRoot,
    spec: &ArtifactSpec,
    executable: bool,
) -> Result<AdmittedArtifact, ArtifactError> {
    let opened = root
        .open_regular(
            &spec.path,
            false,
            Some(spec.size),
            executable,
            Some(if executable { 0o500 } else { 0o400 }),
        )
        .map_err(ArtifactError::ConfinedPath)?;
    let path = root.path().join(&spec.path);
    if sha256_file(opened.file(), &path)? != spec.sha256 {
        return Err(ArtifactError::DigestMismatch(path));
    }
    Ok(AdmittedArtifact {
        root: root.path().to_owned(),
        relative_path: spec.path.clone(),
        path,
        identity: opened.identity().clone(),
        size: spec.size,
        sha256: spec.sha256.clone(),
        executable,
    })
}

#[cfg(test)]
pub(crate) fn admit_test_artifact(
    path: &Path,
    executable: bool,
) -> Result<AdmittedArtifact, ArtifactError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| ArtifactError::InvalidRelativePath(path.to_owned()))?;
    let relative = path
        .file_name()
        .map(PathBuf::from)
        .ok_or_else(|| ArtifactError::InvalidRelativePath(path.to_owned()))?;
    let root = PrivateRoot::open(parent_path).map_err(ArtifactError::ConfinedPath)?;
    let opened = root
        .open_regular(
            &relative,
            false,
            None,
            executable,
            Some(if executable { 0o500 } else { 0o400 }),
        )
        .map_err(ArtifactError::ConfinedPath)?;
    let spec = ArtifactSpec {
        path: relative,
        size: opened.identity().size,
        sha256: sha256_file(opened.file(), path)?,
        architecture: ArtifactArchitecture::host()?,
    };
    admit_one(&root, &spec, executable)
}

fn with_opened<T>(
    root: &PrivateRoot,
    artifact: &AdmittedArtifact,
    operation: impl FnOnce(&mut File) -> Result<T, ArtifactError>,
) -> Result<T, ArtifactError> {
    let opened = root
        .open_regular(
            &artifact.relative_path,
            false,
            Some(artifact.size),
            artifact.executable,
            Some(if artifact.executable { 0o500 } else { 0o400 }),
        )
        .map_err(ArtifactError::ConfinedPath)?;
    if opened.identity() != &artifact.identity {
        return Err(ArtifactError::IdentityChanged(artifact.path.clone()));
    }
    let mut file = opened.into_file();
    operation(&mut file)
}

fn sha256_file(file: &File, path: &Path) -> Result<String, ArtifactError> {
    let mut file = file.try_clone().map_err(|source| ArtifactError::Inspect {
        path: path.to_owned(),
        source,
    })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| ArtifactError::Inspect {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(target_os = "linux")]
fn validate_elf(
    file: &mut File,
    path: &Path,
    architecture: ArtifactArchitecture,
) -> Result<(), ArtifactError> {
    let bytes = read_prefix(file, path, 64)?;
    if !valid_elf_header(&bytes, architecture) {
        return Err(ArtifactError::InvalidElf(path.to_owned()));
    }
    Ok(())
}

fn valid_elf_header(bytes: &[u8], architecture: ArtifactArchitecture) -> bool {
    bytes.len() >= 20
        && &bytes[..4] == b"\x7fELF"
        && bytes[4] == 2
        && bytes[5] == 1
        && matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
        && u16::from_le_bytes([bytes[18], bytes[19]]) == architecture.elf_machine()
}

/// A thin 64-bit arm64 Mach-O executable (MH_MAGIC_64, CPU_TYPE_ARM64,
/// MH_EXECUTE). Universal binaries are refused.
#[cfg(target_os = "macos")]
fn validate_arm64_macho(file: &mut File, path: &Path) -> Result<(), ArtifactError> {
    let bytes = read_prefix(file, path, 16)?;
    if !valid_arm64_macho_header(&bytes) {
        return Err(ArtifactError::InvalidMachO(path.to_owned()));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn valid_arm64_macho_header(bytes: &[u8]) -> bool {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 2;
    let word = |offset: usize| {
        bytes
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_le_bytes)
    };
    word(0) == Some(MH_MAGIC_64) && word(4) == Some(CPU_TYPE_ARM64) && word(12) == Some(MH_EXECUTE)
}

fn validate_kernel(
    file: &mut File,
    path: &Path,
    architecture: ArtifactArchitecture,
) -> Result<(), ArtifactError> {
    let bytes = read_prefix(file, path, 0x240)?;
    let valid = match architecture {
        ArtifactArchitecture::X86_64 => {
            bytes.len() >= 0x206
                && bytes[510..512] == [0x55, 0xaa]
                && &bytes[0x202..0x206] == b"HdrS"
        }
        ArtifactArchitecture::Aarch64 => bytes.len() >= 0x3c && &bytes[0x38..0x3c] == b"ARM\x64",
    };
    if !valid {
        return Err(ArtifactError::InvalidKernel(path.to_owned()));
    }
    Ok(())
}

fn validate_initramfs(
    file: &mut File,
    path: &Path,
    architecture: ArtifactArchitecture,
) -> Result<(), ArtifactError> {
    if file
        .metadata()
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?
        .len()
        > INITRAMFS_LIMIT
    {
        return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    let mut bytes = Vec::new();
    file.take(INITRAMFS_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    let Some(init) = find_newc_entry(&bytes, b"init") else {
        return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
    };
    if !valid_elf_header(init, architecture) {
        return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
    }
    if bytes.len() as u64 > INITRAMFS_LIMIT {
        return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
    }
    let cw = if let Some(provenance) = find_newc_entry(&bytes, CW_RUNTIME_PROVENANCE_ENTRY) {
        let identity = CwRuntimeProvenance::decode(provenance)
            .map_err(|_| ArtifactError::InvalidInitramfs(path.to_owned()))?;
        let payload = find_newc_entry(&bytes, identity.archive_entry().as_bytes())
            .ok_or_else(|| ArtifactError::InvalidInitramfs(path.to_owned()))?;
        if architecture != ArtifactArchitecture::X86_64
            || identity.validate_payload(payload).is_err()
        {
            return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
        }
        Some((payload, provenance))
    } else {
        None
    };
    let product_canonical = find_newc_entry(&bytes, b"bin/busybox").is_some_and(|busybox| {
        find_newc_entry(&bytes, b"sbin/runc").is_some_and(|runc| {
            valid_static_elf_header(busybox, architecture)
                && valid_static_elf_header(runc, architecture)
                && canonical_guest_root_newc_with_cw(init, busybox, runc, cw)
                    .ok()
                    .is_some_and(|canonical| canonical == bytes)
        })
    });
    if !product_canonical {
        return Err(ArtifactError::InvalidInitramfs(path.to_owned()));
    }
    Ok(())
}

fn read_canonical_initramfs_entry(
    artifact: &AdmittedArtifact,
    expected: &[u8],
) -> Result<Vec<u8>, ArtifactError> {
    if artifact.size > INITRAMFS_LIMIT {
        return Err(ArtifactError::InvalidInitramfs(artifact.path.clone()));
    }
    let file = artifact.open_exact()?;
    let mut bytes = Vec::new();
    file.take(artifact.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ArtifactError::Inspect {
            path: artifact.path.clone(),
            source,
        })?;
    if bytes.len() as u64 != artifact.size
        || format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256
    {
        return Err(ArtifactError::IdentityChanged(artifact.path.clone()));
    }
    find_newc_entry(&bytes, expected)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ArtifactError::InvalidInitramfs(artifact.path.clone()))
}

#[cfg(test)]
fn find_newc_init(archive: &[u8]) -> Option<&[u8]> {
    find_newc_entry(archive, b"init")
}

fn find_newc_entry<'a>(archive: &'a [u8], expected: &[u8]) -> Option<&'a [u8]> {
    let mut offset = 0_usize;
    loop {
        let header_end = offset.checked_add(110)?;
        let header = archive.get(offset..header_end)?;
        if &header[..6] != b"070701" {
            return None;
        }
        let file_size = parse_hex_u32(&header[54..62])? as usize;
        let name_size = parse_hex_u32(&header[94..102])? as usize;
        if name_size == 0 {
            return None;
        }
        let name_start = header_end;
        let name_end = name_start.checked_add(name_size)?;
        let name = archive.get(name_start..name_end)?;
        let data_start = align4(name_end)?;
        let data_end = data_start.checked_add(file_size)?;
        let data = archive.get(data_start..data_end)?;
        if name.strip_suffix(&[0]) == Some(expected) {
            return Some(data);
        }
        if name == b"TRAILER!!!\0" {
            return None;
        }
        offset = align4(data_end)?;
    }
}

fn valid_static_elf_header(bytes: &[u8], architecture: ArtifactArchitecture) -> bool {
    if !valid_elf_header(bytes, architecture) || bytes.len() < 64 {
        return false;
    }
    let Some(program_offset) = bytes
        .get(32..40)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(entry_size) = bytes
        .get(54..56)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .map(usize::from)
    else {
        return false;
    };
    let Some(entry_count) = bytes
        .get(56..58)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .map(usize::from)
    else {
        return false;
    };
    if entry_count > 1024 || (entry_count > 0 && entry_size < 56) {
        return false;
    }
    for index in 0..entry_count {
        let Some(start) = index
            .checked_mul(entry_size)
            .and_then(|relative| program_offset.checked_add(relative))
        else {
            return false;
        };
        let Some(kind) = bytes
            .get(start..start.saturating_add(4))
            .and_then(|value| value.try_into().ok())
            .map(u32::from_le_bytes)
        else {
            return false;
        };
        if kind == 3 {
            return false;
        }
    }
    true
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| u32::from_str_radix(text, 16).ok())
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn read_prefix(file: &mut File, path: &Path, limit: usize) -> Result<Vec<u8>, ArtifactError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    let mut bytes = vec![0; limit];
    let read = file
        .read(&mut bytes)
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    bytes.truncate(read);
    Ok(bytes)
}

#[cfg(target_os = "linux")]
async fn verify_cloud_hypervisor_version(path: &Path) -> Result<(), ArtifactError> {
    verify_executable_version(path, expected_cloud_hypervisor_version_output).await
}

#[cfg(target_os = "linux")]
async fn verify_virtiofsd_version(path: &Path) -> Result<(), ArtifactError> {
    verify_executable_version(path, expected_virtiofsd_version_output).await
}

#[cfg(target_os = "linux")]
async fn verify_executable_version(
    path: &Path,
    expected: fn(&[u8]) -> bool,
) -> Result<(), ArtifactError> {
    let mut command = tokio::process::Command::new(path);
    command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| ArtifactError::VersionProbe)?;
    let mut stdout = child.stdout.take().ok_or(ArtifactError::VersionProbe)?;
    let probe = async {
        let mut bytes = Vec::new();
        (&mut stdout)
            .take(VERSION_OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| ArtifactError::VersionProbe)?;
        if bytes.len() as u64 > VERSION_OUTPUT_LIMIT {
            return Err(ArtifactError::VersionMismatch);
        }
        let status = child
            .wait()
            .await
            .map_err(|_| ArtifactError::VersionProbe)?;
        if !status.success() {
            return Err(ArtifactError::VersionProbe);
        }
        if !expected(&bytes) {
            return Err(ArtifactError::VersionMismatch);
        }
        Ok(())
    };
    let result = tokio::time::timeout(VERSION_TIMEOUT, probe)
        .await
        .unwrap_or(Err(ArtifactError::VersionProbe));
    if result.is_err() && !matches!(child.try_wait(), Ok(Some(_))) {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(VERSION_TIMEOUT, child.wait()).await;
    }
    result
}

#[cfg(target_os = "linux")]
fn expected_virtiofsd_version_output(bytes: &[u8]) -> bool {
    matches!(bytes, b"virtiofsd 1.14.0" | b"virtiofsd 1.14.0\n")
}

#[cfg(target_os = "linux")]
fn expected_cloud_hypervisor_version_output(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"cloud-hypervisor v54.0" | b"cloud-hypervisor v54.0\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn write_artifact(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn spec(path: &str, bytes: &[u8]) -> ArtifactSpec {
        ArtifactSpec {
            path: path.into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            architecture: ArtifactArchitecture::host().unwrap(),
        }
    }

    fn lock_json() -> Vec<u8> {
        let architecture = ArtifactArchitecture::host().unwrap();
        serde_json::to_vec(&ArtifactLock::for_test(
            ArtifactSpec {
                path: "cloud-hypervisor".into(),
                size: 1,
                sha256: "a".repeat(64),
                architecture,
            },
            ArtifactSpec {
                path: "kernel".into(),
                size: 1,
                sha256: "b".repeat(64),
                architecture,
            },
            ArtifactSpec {
                path: "initramfs".into(),
                size: 1,
                sha256: "c".repeat(64),
                architecture,
            },
        ))
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn version_probe_accepts_exact_v54_release_output_only() {
        for accepted in [
            b"cloud-hypervisor v54.0".as_slice(),
            b"cloud-hypervisor v54.0\n".as_slice(),
        ] {
            assert!(expected_cloud_hypervisor_version_output(accepted));
        }
        for rejected in [
            b"cloud-hypervisor v53.0\n".as_slice(),
            b"cloud-hypervisor v54.1".as_slice(),
            b"cloud-hypervisor v54.0\nMigration Protocol Versions: 0\n".as_slice(),
            b"cloud-hypervisor v54.0\nunexpected\n".as_slice(),
        ] {
            assert!(!expected_cloud_hypervisor_version_output(rejected));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn virtiofsd_version_probe_accepts_only_the_pinned_release() {
        for accepted in [
            b"virtiofsd 1.14.0".as_slice(),
            b"virtiofsd 1.14.0\n".as_slice(),
        ] {
            assert!(expected_virtiofsd_version_output(accepted));
        }
        for rejected in [
            b"virtiofsd 1.13.2".as_slice(),
            b"virtiofsd 1.14.0\nunexpected\n".as_slice(),
        ] {
            assert!(!expected_virtiofsd_version_output(rejected));
        }
    }

    #[test]
    fn lock_rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema_version": 1,
            "cloud_hypervisor": {
                "path": "cloud-hypervisor",
                "size": 1,
                "sha256": "a".repeat(64),
                "architecture": "x86_64",
                "version": "v54.0",
                "surprise": true
            },
            "kernel": {
                "path": "kernel",
                "size": 1,
                "sha256": "b".repeat(64),
                "architecture": "x86_64"
            },
            "initramfs": {
                "path": "initramfs",
                "size": 1,
                "sha256": "c".repeat(64),
                "architecture": "x86_64"
            }
        });
        assert!(serde_json::from_value::<ArtifactLock>(value).is_err());
    }

    #[test]
    fn lock_read_is_dirfd_confined_and_exactly_read_only() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = staging.path().join("artifacts.lock.json");
        std::fs::write(&lock, lock_json()).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
        ArtifactLock::read(&lock).unwrap();

        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            ArtifactLock::read(&lock),
            Err(ArtifactError::ConfinedPath(PathError::UnsafeFile(_)))
        ));

        std::fs::remove_file(&lock).unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside-lock.json");
        std::fs::write(&outside, lock_json()).unwrap();
        symlink(&outside, &lock).unwrap();
        #[cfg(target_os = "linux")]
        assert!(matches!(
            ArtifactLock::read(&lock),
            Err(ArtifactError::ConfinedPath(PathError::Openat2 { .. }))
        ));
        #[cfg(target_os = "macos")]
        assert!(matches!(
            ArtifactLock::read(&lock),
            Err(ArtifactError::ConfinedPath(_))
        ));
    }

    #[test]
    fn helper_header_admits_only_a_thin_arm64_executable() {
        let header = |magic: u32, cpu: u32, file_type: u32| {
            let mut bytes = Vec::new();
            for word in [magic, cpu, 0, file_type] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            bytes
        };
        assert!(valid_arm64_macho_header(&header(
            0xfeed_facf,
            0x0100_000c,
            2
        )));
        // x86_64, a dylib, a universal (fat) header and a short read.
        assert!(!valid_arm64_macho_header(&header(
            0xfeed_facf,
            0x0100_0007,
            2
        )));
        assert!(!valid_arm64_macho_header(&header(
            0xfeed_facf,
            0x0100_000c,
            6
        )));
        assert!(!valid_arm64_macho_header(&header(
            0xbeba_feca,
            0x0100_000c,
            2
        )));
        assert!(!valid_arm64_macho_header(
            &header(0xfeed_facf, 0x0100_000c, 2)[..12]
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_git_is_admitted_only_as_the_locked_file_in_the_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut program = Vec::new();
        for word in [0xfeed_facf_u32, 0x0100_000c, 0, 2] {
            program.extend_from_slice(&word.to_le_bytes());
        }
        program.extend_from_slice(b"synthetic git");
        for name in ["git", "git-remote-https"] {
            write_artifact(&root.join(name), &program, 0o500);
        }
        let lock = ArtifactLock::for_test(
            spec("git", &program),
            spec("kernel", b"kernel"),
            spec("initramfs", b"initramfs"),
        );
        assert_eq!(
            lock.admit_runtime_git(&root).unwrap(),
            (root.join("git"), root.clone())
        );

        // A git swapped in place, with the same name and mode, is refused.
        std::fs::remove_file(root.join("git")).unwrap();
        let mut swapped = program.clone();
        swapped.push(b'!');
        write_artifact(&root.join("git"), &swapped, 0o500);
        assert!(lock.admit_runtime_git(&root).is_err());
        assert!(lock.admit_runtime_git(&root.join("elsewhere")).is_err());
    }

    #[test]
    fn parameter_paths_reject_argument_injection_characters() {
        for path in ["a,b", "a=b", "a\nb", "a\rb"] {
            assert!(matches!(
                validate_parameter_path(Path::new(path)),
                Err(ArtifactError::UnsafePath(_))
            ));
        }
        assert!(validate_parameter_path(Path::new("safe/path.img")).is_ok());
    }

    #[test]
    fn immutable_admission_rejects_wrong_digest_and_size() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(staging.path()).unwrap();
        let bytes = b"immutable artifact";
        let path = staging.path().join("artifact");
        write_artifact(&path, bytes, 0o400);

        let mut wrong_digest = spec("artifact", bytes);
        wrong_digest.sha256 = "0".repeat(64);
        assert!(matches!(
            admit_one(&root, &wrong_digest, false),
            Err(ArtifactError::DigestMismatch(rejected)) if rejected == path
        ));

        let mut wrong_size = spec("artifact", bytes);
        wrong_size.size += 1;
        assert!(matches!(
            admit_one(&root, &wrong_size, false),
            Err(ArtifactError::ConfinedPath(PathError::UnsafeFile(rejected))) if rejected == path
        ));
    }

    #[test]
    fn immutable_format_checks_reject_wrong_architecture_elf_and_kernel() {
        let staging = tempfile::tempdir().unwrap();
        let host = ArtifactArchitecture::host().unwrap();
        let wrong_architecture = match host {
            ArtifactArchitecture::X86_64 => ArtifactArchitecture::Aarch64,
            ArtifactArchitecture::Aarch64 => ArtifactArchitecture::X86_64,
        };

        #[cfg(target_os = "linux")]
        {
            let elf_path = staging.path().join("wrong-architecture.elf");
            let mut elf = vec![0_u8; 64];
            elf[..4].copy_from_slice(b"\x7fELF");
            elf[4] = 2;
            elf[5] = 1;
            elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
            elf[18..20].copy_from_slice(&wrong_architecture.elf_machine().to_le_bytes());
            write_artifact(&elf_path, &elf, 0o400);
            let mut elf_file = File::open(&elf_path).unwrap();
            assert!(matches!(
                validate_elf(&mut elf_file, &elf_path, host),
                Err(ArtifactError::InvalidElf(rejected)) if rejected == elf_path
            ));
        }

        let kernel_path = staging.path().join("wrong-architecture.kernel");
        let mut kernel = vec![0_u8; 0x240];
        match wrong_architecture {
            ArtifactArchitecture::X86_64 => {
                kernel[510..512].copy_from_slice(&[0x55, 0xaa]);
                kernel[0x202..0x206].copy_from_slice(b"HdrS");
            }
            ArtifactArchitecture::Aarch64 => {
                kernel[0x38..0x3c].copy_from_slice(b"ARM\x64");
            }
        }
        write_artifact(&kernel_path, &kernel, 0o400);
        let mut kernel_file = File::open(&kernel_path).unwrap();
        assert!(matches!(
            validate_kernel(&mut kernel_file, &kernel_path, host),
            Err(ArtifactError::InvalidKernel(rejected)) if rejected == kernel_path
        ));
    }

    #[test]
    fn noncanonical_archive_is_rejected_even_if_it_contains_init() {
        let mut probe = vec![0_u8; 64];
        probe[..4].copy_from_slice(b"\x7fELF");
        probe[4] = 2;
        probe[5] = 1;
        probe[16..18].copy_from_slice(&2_u16.to_le_bytes());
        probe[18..20].copy_from_slice(
            &ArtifactArchitecture::host()
                .unwrap()
                .elf_machine()
                .to_le_bytes(),
        );
        let canonical = canonical_newc(&probe).unwrap();
        assert_eq!(find_newc_init(&canonical), Some(probe.as_slice()));
        let mut changed = canonical;
        changed.push(0);
        assert_ne!(
            canonical_newc(find_newc_init(&changed).unwrap()).unwrap(),
            changed
        );
    }

    #[test]
    fn current_guest_capability_is_read_from_the_exact_pinned_init_and_never_guessed() {
        let task = tempfile::tempdir().unwrap();
        std::fs::set_permissions(task.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(task.path()).unwrap();
        let marker = codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER;
        for (index, capability) in [
            Vec::new(),
            marker.to_vec(),
            [marker, marker].concat(),
            b"\0CWGUESTABI\0seed=8;cw_catalog=0\0".to_vec(),
            [marker, b"\0CWGUESTABI\0seed=10;cw_catalog=2\0"].concat(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut init = vec![0; 64];
            init[..4].copy_from_slice(b"\x7fELF");
            init.extend(capability);
            let archive = canonical_newc(&init).unwrap();
            let name = format!("boot-{index}");
            write_artifact(&root.path().join(&name), &archive, 0o400);
            let admitted = admit_one(&root, &spec(&name, &archive), false).unwrap();
            let artifacts = AdmittedArtifacts::for_test(
                AdmittedArtifact::for_test("/unused/ch"),
                AdmittedArtifact::for_test("/unused/kernel"),
                admitted,
            );
            assert_eq!(
                artifacts.require_current_guest_seed_abi().is_ok(),
                index == 1
            );
            if index == 1 {
                let mut changed = archive;
                *changed.last_mut().unwrap() ^= 1;
                std::fs::set_permissions(
                    root.path().join(&name),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                write_artifact(&root.path().join(&name), &changed, 0o400);
                assert!(matches!(
                    artifacts.require_current_guest_seed_abi(),
                    Err(ArtifactError::IdentityChanged(_))
                ));
            }
        }
    }

    #[test]
    fn vm_only_capability_requires_exactly_one_marker() {
        let task = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = PrivateRoot::open(task.path()).unwrap();
        let marker = codewire_vmm_guest_probe::VM_ONLY_CAPABILITY_MARKER;
        for (index, capability) in [
            Vec::new(),
            marker.to_vec(),
            [marker, marker].concat(),
            b"CODEWIRE_GUEST_VM_ONLY_V1\0".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut init = vec![0; 64];
            init[..4].copy_from_slice(b"\x7fELF");
            init.extend(codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER);
            init.extend(capability);
            let archive = canonical_newc(&init).unwrap();
            let name = format!("vm-only-{index}");
            write_artifact(&root.path().join(&name), &archive, 0o400);
            let artifacts = AdmittedArtifacts::for_test(
                AdmittedArtifact::for_test("/unused/ch"),
                AdmittedArtifact::for_test("/unused/kernel"),
                admit_one(&root, &spec(&name, &archive), false).unwrap(),
            );
            artifacts.require_current_guest_seed_abi().unwrap();
            if index == 1 {
                artifacts.require_vm_only_guest().unwrap();
            } else {
                assert!(matches!(
                    artifacts.require_vm_only_guest(),
                    Err(ArtifactError::GuestVmOnlyUnsupported(_))
                ));
            }
        }
    }

    #[test]
    fn live_runtime_capability_requires_the_exact_pinned_init() {
        let task = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let root = PrivateRoot::open(task.path()).unwrap();
        let marker = codewire_vmm_guest_probe::cw_runtime_live::LIVE_RUNTIME_CAPABILITY_MARKER;
        for (index, capability) in [
            Vec::new(),
            marker.to_vec(),
            [marker, marker].concat(),
            b"CODEWIRE_NATIVE_CW_LIVE_PUBLISHER_V0\0".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut init = vec![0; 64];
            init[..4].copy_from_slice(b"\x7fELF");
            init.extend(codewire_vmm_guest_probe::GUEST_RUNTIME_ABI_MARKER);
            init.extend(capability);
            let archive = canonical_newc(&init).unwrap();
            let name = format!("publisher-{index}");
            write_artifact(&root.path().join(&name), &archive, 0o400);
            let artifacts = AdmittedArtifacts::for_test(
                AdmittedArtifact::for_test("/unused/ch"),
                AdmittedArtifact::for_test("/unused/kernel"),
                admit_one(&root, &spec(&name, &archive), false).unwrap(),
            );
            // Seed9/disk support alone must never imply a trusted publisher.
            artifacts.require_current_guest_seed_abi().unwrap();
            assert_eq!(
                artifacts.require_live_cw_runtime_publisher().is_ok(),
                index == 1
            );
            if index == 1 {
                let mut changed = archive;
                *changed.last_mut().unwrap() ^= 1;
                std::fs::set_permissions(
                    root.path().join(&name),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                write_artifact(&root.path().join(&name), &changed, 0o400);
                assert!(matches!(
                    artifacts.require_live_cw_runtime_publisher(),
                    Err(ArtifactError::IdentityChanged(_))
                ));
            }
        }
    }

    #[test]
    fn probe_only_archive_is_not_admitted_as_a_product_guest_root() {
        let architecture = ArtifactArchitecture::host().unwrap();
        let mut init = vec![0_u8; 64];
        init[..4].copy_from_slice(b"\x7fELF");
        init[4] = 2;
        init[5] = 1;
        init[16..18].copy_from_slice(&2_u16.to_le_bytes());
        init[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
        let staging = tempfile::tempdir().unwrap();
        let path = staging.path().join("probe-only.cpio");
        std::fs::write(&path, canonical_newc(&init).unwrap()).unwrap();

        assert!(matches!(
            validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture),
            Err(ArtifactError::InvalidInitramfs(rejected)) if rejected == path
        ));
    }

    #[test]
    fn canonical_product_guest_root_requires_static_busybox_and_runc() {
        let architecture = ArtifactArchitecture::host().unwrap();
        let mut init = vec![0_u8; 64];
        init[..4].copy_from_slice(b"\x7fELF");
        init[4] = 2;
        init[5] = 1;
        init[16..18].copy_from_slice(&2_u16.to_le_bytes());
        init[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
        let busybox = init.clone();
        let runc = init.clone();
        let archive = canonical_guest_root_newc(&init, &busybox, &runc).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let path = staging.path().join("product.cpio");
        std::fs::write(&path, &archive).unwrap();
        validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture).unwrap();

        let mut dynamic_busybox = busybox.clone();
        dynamic_busybox[32..40].copy_from_slice(&64_u64.to_le_bytes());
        dynamic_busybox[54..56].copy_from_slice(&56_u16.to_le_bytes());
        dynamic_busybox[56..58].copy_from_slice(&1_u16.to_le_bytes());
        dynamic_busybox.resize(120, 0);
        dynamic_busybox[64..68].copy_from_slice(&3_u32.to_le_bytes());
        let dynamic_archive = canonical_guest_root_newc(&init, &dynamic_busybox, &runc).unwrap();
        std::fs::write(&path, dynamic_archive).unwrap();
        assert!(matches!(
            validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture),
            Err(ArtifactError::InvalidInitramfs(rejected)) if rejected == path
        ));

        let mut dynamic_runc = runc;
        dynamic_runc[32..40].copy_from_slice(&64_u64.to_le_bytes());
        dynamic_runc[54..56].copy_from_slice(&56_u16.to_le_bytes());
        dynamic_runc[56..58].copy_from_slice(&1_u16.to_le_bytes());
        dynamic_runc.resize(120, 0);
        dynamic_runc[64..68].copy_from_slice(&3_u32.to_le_bytes());
        let dynamic_archive = canonical_guest_root_newc(&init, &busybox, &dynamic_runc).unwrap();
        std::fs::write(&path, dynamic_archive).unwrap();
        assert!(matches!(
            validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture),
            Err(ArtifactError::InvalidInitramfs(rejected)) if rejected == path
        ));
    }

    // Only an x86_64 guest root may embed a cw, and only an x86_64 host
    // admits an x86_64 cw payload.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cw_image_boot_bundle_refuses_payload_provenance_and_mode_tampering() {
        use codewire_vmm_guest_probe::cw_runtime::{CwImageDescriptor, CwImagePayload};
        let mut cw = vec![0_u8; 136];
        cw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        cw[16..18].copy_from_slice(&2_u16.to_le_bytes());
        cw[18..20].copy_from_slice(&62_u16.to_le_bytes());
        cw[32..40].copy_from_slice(&64_u64.to_le_bytes());
        cw[54..56].copy_from_slice(&56_u16.to_le_bytes());
        cw[56..58].copy_from_slice(&1_u16.to_le_bytes());
        cw[64..68].copy_from_slice(&1_u32.to_le_bytes());
        let descriptor = CwImageDescriptor {
            sha256: "c".repeat(64),
            size: 10240,
        };
        let identity = CwRuntimeProvenance {
            schema_version: 1,
            image_index_sha256: "d".repeat(64),
            image_manifest: descriptor.clone(),
            image_config: descriptor.clone(),
            image_layer: descriptor,
            layer_diff_id: "c".repeat(64),
            payload: CwImagePayload {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: "0.1.0".to_owned(),
                target: "x86_64-unknown-linux-musl".into(),
                source_revision: "a".repeat(40),
                source_tree_sha256: "b".repeat(64),
                rustc: "rustc 1.93.0 (fixture)".into(),
                sha256: format!("{:x}", Sha256::digest(&cw)),
                size: cw.len() as u64,
            },
        };
        let provenance = serde_json::to_vec(&identity).unwrap();
        let archive =
            canonical_guest_root_newc_with_cw(&cw, &cw, &cw, Some((&cw, &provenance))).unwrap();
        let task = tempfile::tempdir().unwrap();
        let path = task.path().join("cw-boot.cpio");
        std::fs::write(&path, &archive).unwrap();
        validate_initramfs(
            &mut File::open(&path).unwrap(),
            &path,
            ArtifactArchitecture::X86_64,
        )
        .unwrap();
        assert!(
            validate_initramfs(
                &mut File::open(&path).unwrap(),
                &path,
                ArtifactArchitecture::Aarch64
            )
            .is_err()
        );
        let selected = find_newc_entry(&archive, identity.archive_entry().as_bytes()).unwrap();
        let start = selected.as_ptr() as usize - archive.as_ptr() as usize;
        let mut changed = archive.clone();
        changed[start + 135] = 1;
        std::fs::write(&path, &changed).unwrap();
        assert!(
            validate_initramfs(
                &mut File::open(&path).unwrap(),
                &path,
                ArtifactArchitecture::X86_64
            )
            .is_err()
        );
        let entry_name = identity.archive_entry();
        let name_offset = archive
            .windows(entry_name.len())
            .position(|window| window == entry_name.as_bytes())
            .unwrap();
        changed = archive.clone();
        // newc c_mode starts 14 bytes into the 110-byte header.
        changed[name_offset - 110 + 14..name_offset - 110 + 22].copy_from_slice(b"000081ff");
        std::fs::write(&path, &changed).unwrap();
        assert!(
            validate_initramfs(
                &mut File::open(&path).unwrap(),
                &path,
                ArtifactArchitecture::X86_64
            )
            .is_err()
        );
        changed = archive;
        changed.push(0);
        std::fs::write(&path, &changed).unwrap();
        assert!(
            validate_initramfs(
                &mut File::open(&path).unwrap(),
                &path,
                ArtifactArchitecture::X86_64
            )
            .is_err()
        );
        let mut changed_identity = identity;
        changed_identity.payload.protocol_version = 2;
        assert!(
            canonical_guest_root_newc_with_cw(
                &cw,
                &cw,
                &cw,
                Some((&cw, &serde_json::to_vec(&changed_identity).unwrap()))
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_product_guest_root_requires_exact_bootstrap_null_device() {
        let architecture = ArtifactArchitecture::host().unwrap();
        let mut executable = vec![0_u8; 64];
        executable[..4].copy_from_slice(b"\x7fELF");
        executable[4] = 2;
        executable[5] = 1;
        executable[16..18].copy_from_slice(&2_u16.to_le_bytes());
        executable[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
        let archive = canonical_guest_root_newc(&executable, &executable, &executable).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let path = staging.path().join("product.cpio");
        std::fs::write(&path, &archive).unwrap();
        validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture).unwrap();

        let null_name = archive
            .windows(9)
            .position(|bytes| bytes == b"dev/null\0")
            .unwrap();
        let null_header = null_name - 110;
        for (relative, replacement) in [
            (14, b"000081b6"), // regular file instead of character device
            (14, b"000021ff"), // excessive permissions
            (22, b"00000001"), // non-root owner
            (78, b"00000005"), // console major
            (86, b"00000005"), // /dev/zero instead of /dev/null
        ] {
            let mut changed = archive.clone();
            changed[null_header + relative..null_header + relative + 8]
                .copy_from_slice(replacement);
            std::fs::write(&path, changed).unwrap();
            assert!(matches!(
                validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture),
                Err(ArtifactError::InvalidInitramfs(_))
            ));
        }

        // Reconstruct the prior layout: no bootstrap dev entries and inode
        // numbering starts at one. Old archives require a rebuild; admission
        // must not silently continue accepting the broken startup contract.
        let product_start = (null_name + 9).next_multiple_of(4);
        let mut prior = archive[product_start..].to_vec();
        let mut offset = 0;
        loop {
            let name_size = parse_hex_u32(&prior[offset + 94..offset + 102]).unwrap() as usize;
            let size = parse_hex_u32(&prior[offset + 54..offset + 62]).unwrap() as usize;
            let name_end = offset + 110 + name_size;
            let next = (name_end.next_multiple_of(4) + size).next_multiple_of(4);
            if &prior[offset + 110..name_end] == b"TRAILER!!!\0" {
                prior.truncate(next);
                prior.resize(next.next_multiple_of(512), 0);
                break;
            }
            let inode = parse_hex_u32(&prior[offset + 6..offset + 14]).unwrap() - 2;
            prior[offset + 6..offset + 14].copy_from_slice(format!("{inode:08x}").as_bytes());
            offset = next;
        }
        std::fs::write(&path, prior).unwrap();
        assert!(matches!(
            validate_initramfs(&mut File::open(&path).unwrap(), &path, architecture),
            Err(ArtifactError::InvalidInitramfs(_))
        ));
    }

    #[test]
    fn admitted_product_busybox_is_reopened_and_digest_bound() {
        let architecture = ArtifactArchitecture::host().unwrap();
        let mut executable = vec![0_u8; 64];
        executable[..4].copy_from_slice(b"\x7fELF");
        executable[4] = 2;
        executable[5] = 1;
        executable[16..18].copy_from_slice(&2_u16.to_le_bytes());
        executable[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
        let archive = canonical_guest_root_newc(&executable, &executable, &executable).unwrap();
        let staging = tempfile::tempdir().unwrap();
        std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = staging.path().join("initramfs");
        write_artifact(&path, &archive, 0o400);
        let root = PrivateRoot::open(staging.path()).unwrap();
        let admitted = admit_one(&root, &spec("initramfs", &archive), false).unwrap();

        assert_eq!(
            read_canonical_initramfs_entry(&admitted, b"bin/busybox").unwrap(),
            executable
        );
        assert!(matches!(
            read_canonical_initramfs_entry(&admitted, b"missing"),
            Err(ArtifactError::InvalidInitramfs(rejected)) if rejected == path
        ));
    }
}
