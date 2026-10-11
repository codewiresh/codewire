//! The local VM runtime document (#2539). A release's cw embeds it, so the
//! runtime's exact digests are covered by the trust already placed in that cw
//! (install.sh's SHA256SUMS or `cw update`'s compiled-key signature); a
//! `--from` directory carries the same document beside its blobs. These
//! functions perform no I/O and grant no trust.
//!
//! Each host target's `lock` is the exact artifact lock the supervisor
//! admits. Its shape is checked here on every platform, so the Linux signing
//! job can verify a macOS lock; the supervisor decodes it again natively.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::{Platform, is_sha256_hex};
use crate::release::{MAX_OBJECT_BYTES, ReleaseError, decode_canonical, lower_hex};

pub const LOCAL_RUNTIME_SCHEMA: &str = "codewire.cw.local-runtime/v1";
/// The document's name in a release and in a `--from` directory.
pub const LOCAL_RUNTIME_NAME: &str = "local-runtime.json";
/// The largest runtime blob a document may pin, as for any release object.
pub const MAX_BLOB_BYTES: u64 = MAX_OBJECT_BYTES;
const MAX_COMPONENTS: usize = 32;
const MAX_TEXT: usize = 128;

type Result<T> = std::result::Result<T, ReleaseError>;

/// One release's local VM runtime for each supported host target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimeDocument {
    pub schema: String,
    /// The commit the runtime was built from. It also identifies the runtime's
    /// own sources, which cw's source-tree digest does not cover.
    pub source_revision: String,
    /// Each target's runtime, keyed by [`Platform::as_str`].
    pub targets: BTreeMap<String, RuntimeTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTarget {
    /// The exact artifact lock the supervisor admits.
    pub lock: serde_json::Value,
    /// The sealed cw runtime for managed agents in local VMs, when published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cw_runtime: Option<CwRuntimeFiles>,
    /// Third-party components with their licenses and exact sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeFiles {
    pub lock: BlobRef,
    pub pack: BlobRef,
}

/// A content-addressed file: `cw/v1/blobs/sha256/<sha256>` in a release,
/// `blobs/sha256/<sha256>` in a `--from` directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub sha256: String,
    pub size: u64,
}

/// A third-party component shipped in the runtime, with the source it was
/// built from (published beside the runtime for its license).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub version: String,
    /// An SPDX license expression.
    pub license: String,
    pub source: BlobRef,
}

impl LocalRuntimeDocument {
    /// Decode a canonical document and check its structure.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let document: Self = decode_canonical(bytes)?;
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != LOCAL_RUNTIME_SCHEMA || !lower_hex(&self.source_revision, 40) {
            return Err(ReleaseError::Invalid("local runtime identity"));
        }
        if self.targets.is_empty() {
            return Err(ReleaseError::Invalid("local runtime targets"));
        }
        for (key, target) in &self.targets {
            let platform =
                Platform::parse(key).ok_or(ReleaseError::Invalid("local runtime target"))?;
            target.validate(platform)?;
        }
        Ok(())
    }

    /// This document's runtime for `platform`.
    pub fn target(&self, platform: Platform) -> Option<&RuntimeTarget> {
        self.targets.get(platform.as_str())
    }

    /// Every blob the document references, each once.
    pub fn blobs(&self) -> Vec<BlobRef> {
        let mut blobs = BTreeMap::new();
        for target in self.targets.values() {
            for blob in target.blobs() {
                blobs.insert(blob.sha256.clone(), blob);
            }
        }
        blobs.into_values().collect()
    }
}

impl RuntimeTarget {
    fn validate(&self, platform: Platform) -> Result<()> {
        let lock = TargetLock::decode(platform, &self.lock)?;
        lock.validate(platform)?;
        if let Some(cw_runtime) = &self.cw_runtime {
            cw_runtime.lock.validate()?;
            cw_runtime.pack.validate()?;
        }
        if self.components.len() > MAX_COMPONENTS {
            return Err(ReleaseError::Invalid("local runtime components"));
        }
        for component in &self.components {
            component.validate()?;
        }
        Ok(())
    }

    /// What an install fetches: the lock's files and the cw runtime, each
    /// once. Component sources are published beside them, not installed.
    pub fn install_blobs(&self) -> Vec<BlobRef> {
        let mut blobs = BTreeMap::new();
        if let Ok(lock) = serde_json::from_value::<LockFiles>(self.lock.clone()) {
            for blob in lock.0 {
                blobs.insert(blob.sha256.clone(), blob);
            }
        }
        if let Some(cw_runtime) = &self.cw_runtime {
            for blob in [&cw_runtime.lock, &cw_runtime.pack] {
                blobs.insert(blob.sha256.clone(), blob.clone());
            }
        }
        blobs.into_values().collect()
    }

    /// Everything a release publishes for this target: the install blobs
    /// and every component source.
    pub fn blobs(&self) -> Vec<BlobRef> {
        let mut blobs = self.install_blobs();
        blobs.extend(
            self.components
                .iter()
                .map(|component| component.source.clone()),
        );
        blobs
    }
}

impl BlobRef {
    fn validate(&self) -> Result<()> {
        if !is_sha256_hex(&self.sha256) || !(1..=MAX_OBJECT_BYTES).contains(&self.size) {
            return Err(ReleaseError::Invalid("local runtime blob"));
        }
        Ok(())
    }
}

impl Component {
    fn validate(&self) -> Result<()> {
        let text_ok = |value: &str, extra: &[u8]| {
            !value.is_empty()
                && value.len() <= MAX_TEXT
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
        };
        if !text_ok(&self.name, b"-_.")
            || !text_ok(&self.version, b"-_.+")
            || !text_ok(&self.license, b"-_.+ ()")
        {
            return Err(ReleaseError::Invalid("local runtime component"));
        }
        self.source.validate()
    }
}

/// A platform-neutral view of the supervisor's artifact lock. Field names and
/// nesting match `codewire_local_vmm::artifact::ArtifactLock` for each host.
enum TargetLock {
    Macos(Box<MacosLock>),
    Linux(Box<LinuxLock>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MacosLock {
    schema_version: u32,
    vz_runner: Spec,
    e2fsprogs: E2fsprogs,
    git: Git,
    kernel: Spec,
    initramfs: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct E2fsprogs {
    mkfs_ext4: Spec,
    e2fsck: Spec,
    resize2fs: Spec,
    debugfs: Spec,
    mke2fs_conf: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Git {
    git: Spec,
    git_remote_https: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxLock {
    schema_version: u32,
    cloud_hypervisor: VersionedSpec,
    #[serde(default)]
    virtiofsd: Option<VersionedSpec>,
    kernel: Spec,
    initramfs: Spec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    path: String,
    size: u64,
    sha256: String,
    architecture: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedSpec {
    path: String,
    size: u64,
    sha256: String,
    architecture: String,
    version: String,
}

impl TargetLock {
    fn decode(platform: Platform, value: &serde_json::Value) -> Result<Self> {
        let malformed = |_| ReleaseError::Invalid("local runtime lock");
        if platform.as_str().starts_with("macos-") {
            serde_json::from_value(value.clone())
                .map(|lock| Self::Macos(Box::new(lock)))
                .map_err(malformed)
        } else {
            serde_json::from_value(value.clone())
                .map(|lock| Self::Linux(Box::new(lock)))
                .map_err(malformed)
        }
    }

    fn validate(&self, platform: Platform) -> Result<()> {
        let architecture = platform
            .as_str()
            .rsplit_once('-')
            .map(|(_, arch)| arch)
            .unwrap_or_default();
        let specs: Vec<(&str, u64, &str, &str)> = match self {
            Self::Macos(lock) => {
                if lock.schema_version != 1 || platform.as_str() != "macos-aarch64" {
                    return Err(ReleaseError::Invalid("local runtime lock"));
                }
                [
                    &lock.vz_runner,
                    &lock.kernel,
                    &lock.initramfs,
                    &lock.e2fsprogs.mkfs_ext4,
                    &lock.e2fsprogs.e2fsck,
                    &lock.e2fsprogs.resize2fs,
                    &lock.e2fsprogs.debugfs,
                    &lock.e2fsprogs.mke2fs_conf,
                    &lock.git.git,
                    &lock.git.git_remote_https,
                ]
                .into_iter()
                .map(|spec| {
                    (
                        spec.path.as_str(),
                        spec.size,
                        spec.sha256.as_str(),
                        spec.architecture.as_str(),
                    )
                })
                .collect()
            }
            Self::Linux(lock) => {
                if lock.schema_version != 1 {
                    return Err(ReleaseError::Invalid("local runtime lock"));
                }
                let mut specs = vec![
                    (
                        lock.cloud_hypervisor.path.as_str(),
                        lock.cloud_hypervisor.size,
                        lock.cloud_hypervisor.sha256.as_str(),
                        lock.cloud_hypervisor.architecture.as_str(),
                    ),
                    (
                        lock.kernel.path.as_str(),
                        lock.kernel.size,
                        lock.kernel.sha256.as_str(),
                        lock.kernel.architecture.as_str(),
                    ),
                    (
                        lock.initramfs.path.as_str(),
                        lock.initramfs.size,
                        lock.initramfs.sha256.as_str(),
                        lock.initramfs.architecture.as_str(),
                    ),
                ];
                if lock.cloud_hypervisor.version.is_empty()
                    || lock.cloud_hypervisor.version.len() > MAX_TEXT
                {
                    return Err(ReleaseError::Invalid("local runtime lock"));
                }
                if let Some(virtiofsd) = &lock.virtiofsd {
                    if virtiofsd.version.is_empty() || virtiofsd.version.len() > MAX_TEXT {
                        return Err(ReleaseError::Invalid("local runtime lock"));
                    }
                    specs.push((
                        virtiofsd.path.as_str(),
                        virtiofsd.size,
                        virtiofsd.sha256.as_str(),
                        virtiofsd.architecture.as_str(),
                    ));
                }
                specs
            }
        };
        let mut paths = std::collections::BTreeSet::new();
        for (path, size, sha256, spec_architecture) in specs {
            let plain = !path.is_empty()
                && path.len() <= MAX_TEXT
                && path != "."
                && path != ".."
                && path
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte));
            if !plain
                || !paths.insert(path)
                || !is_sha256_hex(sha256)
                || !(1..=MAX_OBJECT_BYTES).contains(&size)
                || spec_architecture != architecture
            {
                return Err(ReleaseError::Invalid("local runtime lock file"));
            }
        }
        Ok(())
    }
}

/// Every `{sha256, size}` file reference in a lock, in any nesting.
struct LockFiles(Vec<BlobRef>);

impl<'de> Deserialize<'de> for LockFiles {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        fn collect(value: &serde_json::Value, out: &mut Vec<BlobRef>) {
            if let serde_json::Value::Object(map) = value {
                if let (Some(serde_json::Value::String(sha256)), Some(size)) = (
                    map.get("sha256"),
                    map.get("size").and_then(|size| size.as_u64()),
                ) {
                    out.push(BlobRef {
                        sha256: sha256.clone(),
                        size,
                    });
                    return;
                }
                for nested in map.values() {
                    collect(nested, out);
                }
            }
        }
        let value = serde_json::Value::deserialize(deserializer)?;
        let mut files = Vec::new();
        collect(&value, &mut files);
        Ok(Self(files))
    }
}

#[cfg(test)]
mod tests;
