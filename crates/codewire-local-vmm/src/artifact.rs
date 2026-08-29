use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_vmm_guest_probe::canonical_guest_root_newc;
#[cfg(test)]
use codewire_vmm_guest_probe::canonical_newc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::linux::path::{FileIdentity, PathError, PrivateRoot};

pub const ARTIFACT_LOCK_SCHEMA_VERSION: u32 = 1;
pub const CLOUD_HYPERVISOR_RELEASE: &str = "v53.0";
const VERSION_OUTPUT_LIMIT: u64 = 4096;
const VERSION_TIMEOUT: Duration = Duration::from_secs(2);
const ARTIFACT_LOCK_LIMIT: u64 = 1024 * 1024;

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
    pub cloud_hypervisor: ExecutableArtifactSpec,
    pub kernel: ArtifactSpec,
    pub initramfs: ArtifactSpec,
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
            },
            size: 1,
            sha256: "a".repeat(64),
            executable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedArtifacts {
    pub cloud_hypervisor: AdmittedArtifact,
    pub kernel: AdmittedArtifact,
    pub initramfs: AdmittedArtifact,
}

impl AdmittedArtifacts {
    pub fn revalidate(&self) -> Result<(), ArtifactError> {
        self.cloud_hypervisor.revalidate()?;
        self.kernel.revalidate()?;
        self.initramfs.revalidate()?;
        Ok(())
    }

    pub(crate) fn read_guest_busybox(&self) -> Result<Vec<u8>, ArtifactError> {
        read_canonical_initramfs_entry(&self.initramfs, b"bin/busybox")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
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
    #[error("kernel artifact has an invalid or wrong-architecture image header: {0}")]
    InvalidKernel(PathBuf),
    #[error("initramfs is not an exact canonical Codewire guest-root newc archive: {0}")]
    InvalidInitramfs(PathBuf),
    #[error("Cloud Hypervisor lock must pin release {expected}")]
    WrongCloudHypervisorRelease { expected: &'static str },
    #[error("Cloud Hypervisor version probe failed")]
    VersionProbe,
    #[error("Cloud Hypervisor reported an unexpected version")]
    VersionMismatch,
}

impl ArtifactLock {
    pub(crate) fn canonical_json(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::EncodeLock)
    }

    pub(crate) fn generation(&self) -> Result<String, ArtifactError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_json()?)))
    }

    pub(crate) fn validate_metadata(&self) -> Result<ArtifactArchitecture, ArtifactError> {
        if self.schema_version != ARTIFACT_LOCK_SCHEMA_VERSION {
            return Err(ArtifactError::UnsupportedSchema(self.schema_version));
        }
        let architecture = ArtifactArchitecture::host()?;
        for spec in [
            &self.cloud_hypervisor.artifact,
            &self.kernel,
            &self.initramfs,
        ] {
            validate_spec(spec, architecture)?;
        }
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

        let cloud_hypervisor = admit_one(&root, &self.cloud_hypervisor.artifact, true)?;
        with_opened(&root, &cloud_hypervisor, |file| {
            validate_elf(file, cloud_hypervisor.path(), architecture)
        })?;
        verify_cloud_hypervisor_version(cloud_hypervisor.path()).await?;

        let kernel = admit_one(&root, &self.kernel, false)?;
        with_opened(&root, &kernel, |file| {
            validate_kernel(file, kernel.path(), architecture)
        })?;

        let initramfs = admit_one(&root, &self.initramfs, false)?;
        with_opened(&root, &initramfs, |file| {
            validate_initramfs(file, initramfs.path(), architecture)
        })?;

        Ok(AdmittedArtifacts {
            cloud_hypervisor,
            kernel,
            initramfs,
        })
    }
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
    file.seek(SeekFrom::Start(0))
        .map_err(|source| ArtifactError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
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
    let product_canonical = find_newc_entry(&bytes, b"bin/busybox").is_some_and(|busybox| {
        find_newc_entry(&bytes, b"sbin/runc").is_some_and(|runc| {
            valid_static_elf_header(busybox, architecture)
                && valid_static_elf_header(runc, architecture)
                && canonical_guest_root_newc(init, busybox, runc)
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

async fn verify_cloud_hypervisor_version(path: &Path) -> Result<(), ArtifactError> {
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
        if !expected_cloud_hypervisor_version_output(&bytes) {
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

fn expected_cloud_hypervisor_version_output(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"cloud-hypervisor v53.0"
            | b"cloud-hypervisor v53.0\n"
            | b"cloud-hypervisor v53.0\nMigration Protocol Versions: 0\n"
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
        serde_json::to_vec(&ArtifactLock {
            schema_version: ARTIFACT_LOCK_SCHEMA_VERSION,
            cloud_hypervisor: ExecutableArtifactSpec {
                artifact: ArtifactSpec {
                    path: "cloud-hypervisor".into(),
                    size: 1,
                    sha256: "a".repeat(64),
                    architecture,
                },
                version: CLOUD_HYPERVISOR_RELEASE.to_owned(),
            },
            kernel: ArtifactSpec {
                path: "kernel".into(),
                size: 1,
                sha256: "b".repeat(64),
                architecture,
            },
            initramfs: ArtifactSpec {
                path: "initramfs".into(),
                size: 1,
                sha256: "c".repeat(64),
                architecture,
            },
        })
        .unwrap()
    }

    #[test]
    fn version_probe_accepts_exact_v53_release_output_only() {
        for accepted in [
            b"cloud-hypervisor v53.0".as_slice(),
            b"cloud-hypervisor v53.0\n".as_slice(),
            b"cloud-hypervisor v53.0\nMigration Protocol Versions: 0\n".as_slice(),
        ] {
            assert!(expected_cloud_hypervisor_version_output(accepted));
        }
        for rejected in [
            b"cloud-hypervisor v53.1".as_slice(),
            b"cloud-hypervisor v53.0\nMigration Protocol Versions: 1\n".as_slice(),
            b"cloud-hypervisor v53.0\nunexpected\n".as_slice(),
        ] {
            assert!(!expected_cloud_hypervisor_version_output(rejected));
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
                "version": "v53.0",
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
        assert!(matches!(
            ArtifactLock::read(&lock),
            Err(ArtifactError::ConfinedPath(PathError::Openat2 { .. }))
        ));
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
