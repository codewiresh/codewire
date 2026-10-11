//! The local VM runtime this cw pins (#2539). A release's cw embeds its
//! runtime document, so the runtime's exact digests are covered by the trust
//! already placed in this cw; `cw setup --local` downloads exactly those
//! files. A development build embeds nothing and installs only `--from DIR`.

use anyhow::Context as _;
use codewire_local_vmm::runtime_install::{
    self, InstalledRuntime, LocalRuntimeDocument, RuntimePaths,
};

include!(concat!(env!("OUT_DIR"), "/local_runtime.rs"));

/// This cw's pinned runtime, or `None` for a development build.
pub(crate) fn embedded() -> anyhow::Result<Option<LocalRuntimeDocument>> {
    let revision = crate::build_record::embedded()?.source_revision;
    decode(LOCAL_RUNTIME, revision.as_deref())
}

fn decode(bytes: &[u8], revision: Option<&str>) -> anyhow::Result<Option<LocalRuntimeDocument>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let document = LocalRuntimeDocument::decode(bytes)
        .context("this cw's pinned local VM runtime is invalid")?;
    anyhow::ensure!(
        revision == Some(document.source_revision.as_str()),
        "this cw's pinned local VM runtime was built from other source"
    );
    Ok(Some(document))
}

/// Before creating or starting a local VM, require the runtime this cw pins.
/// Running VMs keep the generation they started with; this only stops a new
/// start from silently using a runtime another cw installed.
pub(crate) fn require_installed(paths: &RuntimePaths) -> anyhow::Result<()> {
    let Some(document) = embedded()? else {
        return Ok(());
    };
    if runtime_install::host_runtime(&document).is_err() {
        return Ok(());
    }
    match runtime_install::installed_runtime(paths, &document)? {
        InstalledRuntime::Same => Ok(()),
        InstalledRuntime::Missing => {
            anyhow::bail!("the local VM runtime is not installed; run `cw setup --local`")
        }
        InstalledRuntime::Different => anyhow::bail!(
            "the installed local VM runtime belongs to another cw version; run `cw setup --local` to install this one (running VMs keep theirs)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_embedded_runtime_must_decode_and_match_this_source() {
        assert!(decode(b"", Some(&"a".repeat(40))).unwrap().is_none());
        assert!(decode(b"", None).unwrap().is_none());
        assert!(decode(b"{}\n", Some(&"a".repeat(40))).is_err());

        let revision = "a".repeat(40);
        let digest = |seed: u8| format!("{seed:02x}").repeat(32);
        let spec = |path: &str, seed: u8| serde_json::json!({"path": path, "size": 10, "sha256": digest(seed), "architecture": "aarch64"});
        let document = serde_json::json!({
            "schema": runtime_install::LOCAL_RUNTIME_SCHEMA,
            "source_revision": revision,
            "targets": {"macos-aarch64": {"lock": {
                "schema_version": 1,
                "vz_runner": spec("codewire-vz-runner", 1),
                "kernel": spec("kernel", 2),
                "initramfs": spec("initramfs", 3),
                "e2fsprogs": {
                    "mkfs_ext4": spec("mkfs.ext4", 4), "e2fsck": spec("e2fsck", 5),
                    "resize2fs": spec("resize2fs", 6), "debugfs": spec("debugfs", 7),
                    "mke2fs_conf": spec("mke2fs.conf", 8),
                },
                "git": {"git": spec("git", 9), "git_remote_https": spec("git-remote-https", 10)},
            }}},
        });
        let bytes = codewire_cw_release::identity::canonical_json(&document).unwrap();
        assert!(decode(&bytes, Some(&revision)).unwrap().is_some());
        assert!(decode(&bytes, Some(&"b".repeat(40))).is_err());
        assert!(decode(&bytes, None).is_err());
    }
}
