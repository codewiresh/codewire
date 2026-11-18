//! Darwin primitives shared by the macOS credential children (the broker and
//! the repository executor and its Git helpers).
//!
//! The store a child reads is `credential_child_store`'s. Linux children prove
//! no-new-privileges, an empty capability set and a non-dumpable state; macOS
//! has none of those, so a child instead checks what its launcher set up (no
//! root, no core files, a new session and an empty environment where the
//! launcher provides them), exits with its parent and refuses debugger
//! attachment.

use std::path::{Path, PathBuf};

/// The local VM runtime's git and helper directory, admitted from the
/// installed runtime against its lock at this moment.
pub(crate) fn admit_runtime_git(root: &Path, lock: &Path) -> Option<(PathBuf, PathBuf)> {
    codewire_local_vmm::artifact::ArtifactLock::read(lock)
        .ok()?
        .admit_runtime_git(root)
        .ok()
}

/// No root, and a zero hard core-file limit (set by the launcher before exec
/// and inherited by every descendant).
pub(crate) fn unprivileged_without_core_files() -> bool {
    let mut core = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: getrlimit writes one rlimit owned by this frame.
    let core_read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0;
    !rustix::process::geteuid().is_root() && core_read && core.rlim_max == 0
}

/// A new session and an empty environment, as the authority launches its
/// children. CoreFoundation, which cw links, sets `__CF_USER_TEXT_ENCODING`
/// itself while the process loads; it is not inherited input.
pub(crate) fn isolated_session_and_environment() -> bool {
    rustix::process::getsid(None).ok() == Some(rustix::process::getpid())
        && std::env::vars_os().all(|(name, _)| name == "__CF_USER_TEXT_ENCODING")
}

/// Exit as soon as the parent does (Darwin has no parent-death signal), then
/// refuse debugger attachment by other processes of the same user, the macOS
/// counterpart of a non-dumpable Linux credential process.
pub(crate) fn bind_to_parent_and_deny_attachment() -> anyhow::Result<()> {
    codewire_local_vmm::darwin::process::exit_with_parent()
        .map_err(|_| anyhow::anyhow!("credential-bearing process is not parent bound"))?;
    // SAFETY: PT_DENY_ATTACH takes no address or data and affects only this
    // process.
    let denied = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    anyhow::ensure!(denied == 0, "credential-bearing process is not confined");
    Ok(())
}
