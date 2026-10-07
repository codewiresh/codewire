//! Darwin host primitives for the shared local runtime.

mod acl;
pub mod path;
pub mod process;
pub(crate) mod sandbox;
mod store;
pub mod supervisor;
pub(crate) mod supervisor_peer;

#[cfg(test)]
mod path_capability_tests;

use std::path::{Path, PathBuf};

/// Homebrew installs e2fsprogs keg-only, outside the default search path.
const E2FSPROGS_DIRECTORIES: [&str; 2] = [
    "/opt/homebrew/opt/e2fsprogs/sbin",
    "/usr/local/opt/e2fsprogs/sbin",
];

/// Locate one host e2fsprogs program, such as `mkfs.ext4`.
pub(crate) fn e2fsprogs(program: &str) -> Option<PathBuf> {
    E2FSPROGS_DIRECTORIES
        .iter()
        .map(|directory| Path::new(directory).join(program))
        .find(|path| path.is_file())
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
