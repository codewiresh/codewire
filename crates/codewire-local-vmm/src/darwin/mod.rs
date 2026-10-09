//! Darwin host primitives for the shared local runtime.

mod acl;
pub mod path;
pub mod process;
pub mod sandbox;
pub(crate) mod supervisor_peer;

#[cfg(test)]
mod path_capability_tests;

use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use crate::artifact::AdmittedE2fsprogs;

/// A stock Mac has no e2fsprogs, so the local runtime ships a pinned build.
/// Admitting a runtime makes its programs the ones this process formats,
/// checks and resizes ext4 disks with; nothing is found on PATH or in
/// Homebrew.
static E2FSPROGS: RwLock<Option<AdmittedE2fsprogs>> = RwLock::new(None);

pub(crate) fn use_e2fsprogs(tools: &AdmittedE2fsprogs) {
    *E2FSPROGS.write().unwrap_or_else(PoisonError::into_inner) = Some(tools.clone());
}

/// The admitted runtime's e2fsprogs program, such as `mkfs.ext4`, re-hashed
/// immediately before use; a changed file is never run.
pub(crate) fn e2fsprogs(program: &str) -> Option<PathBuf> {
    let tools = E2FSPROGS.read().unwrap_or_else(PoisonError::into_inner);
    let tools = tools.as_ref()?;
    let tool = match program {
        "mkfs.ext4" => &tools.mkfs_ext4,
        "e2fsck" => &tools.e2fsck,
        "resize2fs" => &tools.resize2fs,
        "debugfs" => &tools.debugfs,
        _ => return None,
    };
    tool.revalidate().ok()?;
    Some(tool.path().to_owned())
}

/// The pinned mke2fs configuration (`MKE2FS_CONFIG`) every format uses, so a
/// disk never depends on a host or build-machine file.
pub(crate) fn mke2fs_config() -> Option<PathBuf> {
    let tools = E2FSPROGS.read().unwrap_or_else(PoisonError::into_inner);
    let config = &tools.as_ref()?.mke2fs_conf;
    config.revalidate().ok()?;
    Some(config.path().to_owned())
}

/// Without the Xcode Command Line Tools (or Xcode), `/usr/bin/git` is only a
/// stub that asks to install them.
pub(crate) fn developer_tools_present() -> bool {
    [
        "/Library/Developer/CommandLineTools/usr/bin/git",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
    ]
    .iter()
    .any(|path| Path::new(path).is_file())
}

/// macOS privacy protection refuses protected folders, such as Desktop,
/// Documents, Downloads and removable volumes, with EPERM rather than EACCES.
pub(crate) fn privacy_hint(errno: i32) -> &'static str {
    if errno == libc::EPERM {
        "; macOS privacy protection may be blocking this folder: grant your terminal access in System Settings > Privacy & Security > Files and Folders (or Full Disk Access), then retry"
    } else {
        ""
    }
}

/// Why the Virtualization.framework helper cannot run a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VzHelperProblem {
    Missing,
    Unentitled,
}

/// Check the helper named by the artifact lock before admission, so a missing
/// or unentitled helper fails with its reason rather than as an opaque VMM
/// start failure. Admission still verifies its exact bytes afterwards.
pub(crate) fn vz_helper_problem(helper: &Path) -> Option<VzHelperProblem> {
    if !helper.is_file() {
        return Some(VzHelperProblem::Missing);
    }
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(helper)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let entitled = output.is_ok_and(|output| {
        output.status.success()
            && output
                .stdout
                .windows(VIRTUALIZATION_ENTITLEMENT.len())
                .any(|window| window == VIRTUALIZATION_ENTITLEMENT)
    });
    (!entitled).then_some(VzHelperProblem::Unentitled)
}

const VIRTUALIZATION_ENTITLEMENT: &[u8] = b"com.apple.security.virtualization";
