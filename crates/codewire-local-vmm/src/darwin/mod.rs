//! Darwin host primitives for the shared local runtime.

mod acl;
pub(crate) mod disk_tool;
pub mod path;
pub mod process;
pub mod sandbox;
pub(crate) mod supervisor_peer;

#[cfg(test)]
mod path_capability_tests;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use crate::artifact::{AdmittedE2fsprogs, AdmittedGit};
use crate::host_git::HostGit;

/// A stock Mac has neither e2fsprogs nor a working git, so the local runtime
/// ships pinned builds. Admitting a runtime makes its programs the ones this
/// process formats, checks and resizes ext4 disks and prepares workspace
/// repositories with; nothing is found on PATH, in Homebrew or in the Xcode
/// Command Line Tools.
static RUNTIME_TOOLS: RwLock<Option<(AdmittedE2fsprogs, AdmittedGit)>> = RwLock::new(None);

pub(crate) fn use_runtime_tools(e2fsprogs: &AdmittedE2fsprogs, git: &AdmittedGit) {
    *RUNTIME_TOOLS
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Some((e2fsprogs.clone(), git.clone()));
}

fn runtime_tools() -> Option<(AdmittedE2fsprogs, AdmittedGit)> {
    #[cfg(test)]
    test_runtime_tools::admit_once();
    RUNTIME_TOOLS
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Tests run the same pinned programs a runtime ships, admitted from the
/// directory `CW_TEST_RUNTIME_TOOLS` names under their installed names
/// (`scripts/dev/macos-cli.py --runtime-tools`); nothing else is used.
#[cfg(test)]
mod test_runtime_tools {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    use crate::artifact::{AdmittedE2fsprogs, AdmittedGit, admit_test_artifact};

    static ADMITTED: Once = Once::new();

    pub(super) fn admit_once() {
        ADMITTED.call_once(|| {
            let Some(source) = std::env::var_os("CW_TEST_RUNTIME_TOOLS").map(PathBuf::from) else {
                return;
            };
            let root = tempfile::Builder::new()
                .prefix("cw-test-runtime-tools-")
                .tempdir()
                .unwrap()
                .keep();
            let root = fs::canonicalize(root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let admit = |name: &str, executable: bool| {
                let path = root.join(name);
                fs::copy(Path::new(&source).join(name), &path).unwrap();
                let mode = if executable { 0o500 } else { 0o400 };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                admit_test_artifact(&path, executable).unwrap()
            };
            super::use_runtime_tools(
                &AdmittedE2fsprogs {
                    mkfs_ext4: admit("mkfs.ext4", true),
                    e2fsck: admit("e2fsck", true),
                    resize2fs: admit("resize2fs", true),
                    debugfs: admit("debugfs", true),
                    mke2fs_conf: admit("mke2fs.conf", false),
                },
                &AdmittedGit {
                    git: admit("git", true),
                    git_remote_https: admit("git-remote-https", true),
                },
            );
        });
    }
}

/// The admitted runtime's git, re-hashed immediately before use, with its
/// helpers and (empty) templates pinned to the runtime.
pub(crate) fn git() -> Option<HostGit> {
    let (_, git) = runtime_tools()?;
    git.git.revalidate().ok()?;
    git.git_remote_https.revalidate().ok()?;
    let helpers = git.git_remote_https.path().parent()?.to_owned();
    Some(HostGit {
        program: git.git.path().to_owned(),
        environment: vec![
            ("GIT_EXEC_PATH", helpers.clone().into_os_string()),
            ("GIT_TEMPLATE_DIR", OsString::new()),
        ],
        exec_path: Some(helpers),
    })
}

/// The admitted runtime's e2fsprogs program, such as `mkfs.ext4`, re-hashed
/// immediately before use; a changed file is never run.
pub(crate) fn e2fsprogs(program: &str) -> Option<PathBuf> {
    let (tools, _) = runtime_tools()?;
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

/// The runtime's pinned `mke2fs.conf` ([`mke2fs_config`]) sets every new
/// disk's format, so `mkfs.ext4` takes no format options here.
pub(crate) const EXT4_FORMAT: [&str; 0] = [];

/// The pinned mke2fs configuration (`MKE2FS_CONFIG`) every format uses, so a
/// disk never depends on a host or build-machine file.
pub(crate) fn mke2fs_config() -> Option<PathBuf> {
    let (tools, _) = runtime_tools()?;
    let config = &tools.mke2fs_conf;
    config.revalidate().ok()?;
    Some(config.path().to_owned())
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
