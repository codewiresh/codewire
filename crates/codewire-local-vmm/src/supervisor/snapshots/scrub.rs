//! The sign-in scrub of a state disk on this host (docs/dev/
//! SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions"): Codewire's
//! delivered logins, recognised by the daemon's own rules, are zeroed and
//! removed and every free block punched, with e2fsprogs confined to the one
//! disk.

use zeroize::Zeroizing;

use super::*;

/// The directories, in a state disk, where the guest daemon writes the
/// creator's delivered logins.
pub(super) const LOGIN_DIRECTORIES: [(&[&str], LoginKind); 2] = [
    (&["agent-homes", "codex"], LoginKind::Codex),
    (&["home", ".claude"], LoginKind::Claude),
];

/// Guest state on the state disk bound to the source environment's id,
/// which a copy must not carry: the guest's live cw runtime selection,
/// which it refuses under any other id. Without it a new environment's
/// guest starts from the cw runtime its own create bound.
pub(super) const ENVIRONMENT_BOUND_TREES: [&[&str]; 1] = [&["codewire", "cw-runtime"]];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoginKind {
    Codex,
    Claude,
}

/// What capture does with one entry of a login directory, by the
/// daemon's own rules (`codewire_daemon::delivered_logins`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoginEntry {
    /// Not one of Codewire's names.
    Other,
    /// The login file: removed when its contents are Codewire's.
    File,
    /// A temporary that is a write in progress: removed unread.
    WriteInProgress,
    /// Another temporary: removed when it holds Codewire's login.
    Temporary,
}

impl LoginKind {
    pub(super) fn entry(self, name: &str) -> LoginEntry {
        use codewire_daemon::delivered_logins::{claude, codex};
        let (file, temporary, in_progress) = match self {
            Self::Codex => (
                codex::CODEX_AUTH_FILE_NAME,
                codex::is_codewire_temporary(name),
                codex::is_codewire_write_in_progress(name),
            ),
            Self::Claude => (
                claude::CLAUDE_CREDENTIALS_FILE_NAME,
                claude::is_codewire_temporary(name),
                claude::is_codewire_write_in_progress(name),
            ),
        };
        if name == file {
            LoginEntry::File
        } else if in_progress {
            LoginEntry::WriteInProgress
        } else if temporary {
            LoginEntry::Temporary
        } else {
            LoginEntry::Other
        }
    }

    pub(super) fn codewire(self, name: &str, contents: &[u8]) -> bool {
        use codewire_daemon::delivered_logins::{claude, codex};
        match (self, self.entry(name)) {
            (_, LoginEntry::Other) => false,
            (_, LoginEntry::WriteInProgress) => true,
            (Self::Codex, LoginEntry::File) => codex::is_codewire_auth_file(contents),
            (Self::Claude, LoginEntry::File) => claude::holds_codewire_login(contents),
            (Self::Codex, LoginEntry::Temporary) => codex::is_codewire_leftover(name, contents),
            (Self::Claude, LoginEntry::Temporary) => claude::is_codewire_leftover(name, contents),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(in crate::supervisor) enum ScrubError {
    #[cfg_attr(
        target_os = "linux",
        error(
            "the host's e2fsprogs (debugfs, e2fsck, dumpe2fs) are unavailable; install your distribution's e2fsprogs package"
        )
    )]
    // A runtime packed before dumpe2fs shipped (#4654) has none.
    #[cfg_attr(
        target_os = "macos",
        error(
            "the local VM runtime's e2fsprogs (debugfs, e2fsck, dumpe2fs) are missing or changed; reinstall the local VM runtime: cw setup --local --replace"
        )
    )]
    ToolUnavailable,
    #[error("{0} could not run confined: {1}")]
    Confinement(&'static str, io::Error),
    #[error("{0} did not finish in time")]
    Timeout(&'static str),
    #[error("{0} failed (exit status {1:?})")]
    Failed(&'static str, Option<i32>),
    #[error("{0} reported an error")]
    Reported(&'static str),
    #[error("{0} reported something this cw cannot read")]
    Unreadable(&'static str),
    #[error("a delivered sign-in or environment-bound state was still present after its removal")]
    NotRemoved,
    #[error("a free block of the copy still held data after it was punched")]
    NotPunched,
    #[error("a delivered sign-in or environment-bound state is behind a symbolic link")]
    SymbolicLink,
    #[error("a delivered sign-in's data is not in blocks the scrub can overwrite")]
    DataNotInBlocks,

    #[error("writing the copy failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    State(#[from] StateError),
}

impl From<codewire_ext4_scrub::Error> for ScrubError {
    fn from(error: codewire_ext4_scrub::Error) -> Self {
        use codewire_ext4_scrub::Error;
        match error {
            Error::ToolUnavailable(_) => Self::ToolUnavailable,
            Error::Confinement(label, error) => Self::Confinement(label, error),
            Error::Timeout(label) => Self::Timeout(label),
            Error::Failed(label, code) => Self::Failed(label, code),
            Error::Reported(label) => Self::Reported(label),
            Error::Unreadable(label) => Self::Unreadable(label),
            Error::NotCleared => Self::NotPunched,
            Error::NotRemoved => Self::NotRemoved,
            Error::SymbolicLink => Self::SymbolicLink,
            Error::DataNotInBlocks => Self::DataNotInBlocks,
            Error::Io(error) => Self::Io(error),
        }
    }
}

/// One step of the scrub, which a clearing of a VM's own state disk names
/// when it fails (#6277).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubStep {
    /// The first settling `e2fsck`, which replays the journal.
    Check,
    /// Zeroing and removing the delivered logins.
    Logins,
    /// The second settling `e2fsck`.
    Recheck,
    /// Punching the free blocks.
    Punch,
}

impl ScrubStep {
    pub(in crate::supervisor) fn name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Logins => "logins",
            Self::Recheck => "recheck",
            Self::Punch => "punch",
        }
    }
}

/// The disk a scrub clears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::supervisor) enum ScrubTarget {
    /// A snapshot's private copy, which boots as another environment, so
    /// environment-bound guest state goes too.
    Copy,
    /// A stopped VM's own state disk, which boots as the same environment
    /// again, so its guest's cw runtime selection stays (#6277).
    OwnDisk,
}

/// Clear the state disk copy at `disk`, which no VM uses, of every
/// Codewire-delivered sign-in and of environment-bound guest state
/// ([`scrub`]). Returns how many logins it removed.
pub(in crate::supervisor) async fn scrub_state_disk(disk: &Path) -> Result<u32, ScrubError> {
    scrub(disk, ScrubTarget::Copy)
        .await
        .map_err(|(_, error)| error)
}

/// Clear the state disk at `disk`, which no VM uses, of every
/// Codewire-delivered sign-in:
///
/// 1. a settling `e2fsck -f -p` that exits 0 or 1 (it replays an unclean
///    journal, so a later replay cannot undo a removal);
/// 2. each delivered login, recognised by the daemon's own rules, has
///    its blocks zeroed and is removed, and for a [`ScrubTarget::Copy`] the
///    guest's live cw runtime selection is removed, through debugfs on the
///    unmounted disk ([`codewire_ext4_scrub::files`]); every debugfs call
///    fails on any error it reports, and an absent path is proven absent
///    from its parent;
/// 3. a second settling `e2fsck -f -p` that exits 0 or 1, so the block
///    bitmaps are exact;
/// 4. every free range in those bitmaps is punched out of the disk, and
///    samples of each are read back as zeros.
///
/// Returns how many logins it removed, or the step that failed.
pub(in crate::supervisor) async fn scrub(
    disk: &Path,
    target: ScrubTarget,
) -> Result<u32, (ScrubStep, ScrubError)> {
    let at = |step| move |error| (step, error);
    e2fsck(disk).await.map_err(at(ScrubStep::Check))?;
    let block_size = block_size(disk).map_err(at(ScrubStep::Check))?;
    let removed = remove_logins(disk, block_size, target)
        .await
        .map_err(at(ScrubStep::Logins))?;
    e2fsck(disk).await.map_err(at(ScrubStep::Recheck))?;
    punch_unreadable_blocks(disk, block_size)
        .await
        .map_err(at(ScrubStep::Punch))?;
    Ok(removed)
}

fn block_size(disk: &Path) -> Result<u64, ScrubError> {
    let file = File::open(disk)?;
    Ok(crate::state::read_ext4_superblock(&file, disk)?.block_size)
}

/// Step 2 of [`scrub`].
async fn remove_logins(
    disk: &Path,
    block_size: u64,
    target: ScrubTarget,
) -> Result<u32, ScrubError> {
    use codewire_ext4_scrub::files::{self, EntryKind, Lookup};

    let mut removed = 0;
    for (components, kind) in LOGIN_DIRECTORIES {
        let Lookup::Directory(entries) =
            files::lookup_directory(&HostTools, disk, components).await?
        else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry.name.as_deref() else {
                continue;
            };
            if entry.kind != EntryKind::File || kind.entry(name) == LoginEntry::Other {
                continue;
            }
            let codewire = if kind.entry(name) == LoginEntry::WriteInProgress {
                true
            } else if entry.size > MAXIMUM_LOGIN_FILE_BYTES {
                false
            } else {
                let contents =
                    Zeroizing::new(files::read_file(&HostTools, disk, components, name).await?);
                kind.codewire(name, &contents)
            };
            if !codewire {
                continue;
            }
            files::zero_and_remove(&HostTools, disk, components, name, entry.size, block_size)
                .await?;
            removed += 1;
        }
    }
    if target == ScrubTarget::Copy {
        for components in ENVIRONMENT_BOUND_TREES {
            files::remove_tree(&HostTools, disk, components).await?;
        }
    }
    Ok(removed)
}

/// Punch out of the file in `disk` every block the guest cannot read,
/// then read samples of each range back as zeros
/// ([`codewire_ext4_scrub::punch_unreadable_blocks`]).
pub(super) async fn punch_unreadable_blocks(
    disk: &Path,
    block_size: u64,
) -> Result<(), ScrubError> {
    Ok(codewire_ext4_scrub::punch_unreadable_blocks(&HostTools, disk, block_size).await?)
}

pub(super) async fn e2fsck(disk: &Path) -> Result<(), ScrubError> {
    Ok(codewire_ext4_scrub::e2fsck(&HostTools, disk).await?)
}

/// The e2fsprogs this host runs, each confined to the disk alone
/// ([`crate::host::disk_tool`]): the system's on Linux, the local VM
/// runtime's on a Mac.
pub(super) struct HostTools;

/// Every e2fsprogs program the scrub runs is found, before anything is
/// copied. A Mac admits the installed runtime's programs first, as a
/// create does before it prepares a workspace.
pub(in crate::supervisor) fn require_scrub_tools(
    config: &NativeRuntimeConfig,
) -> Result<(), Status> {
    // A runtime that cannot be admitted leaves this process's tools as
    // they were: none, which the check below refuses, or another
    // runtime's admitted earlier, each re-hashed before every use. Either
    // way no unadmitted program runs.
    #[cfg(target_os = "macos")]
    if let Ok(lock) = crate::artifact::ArtifactLock::read(&config.artifact_lock) {
        let _ = lock.admit_host_tools(&config.artifact_root);
    }
    let engine_root = config.engine_root();
    let found = |name: &'static str| {
        !missing_scrub_tool(&engine_root, name) && crate::host::e2fsprogs(name).is_some()
    };
    if ["e2fsck", "debugfs", "dumpe2fs"].into_iter().all(found) {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            ScrubError::ToolUnavailable.to_string(),
        ))
    }
}

impl codewire_ext4_scrub::Tools for HostTools {
    fn program(&self, name: &'static str) -> Option<PathBuf> {
        crate::host::e2fsprogs(name)
    }

    fn command(
        &self,
        program: &Path,
        leading_args: &[&str],
        disk: &Path,
    ) -> io::Result<tokio::process::Command> {
        crate::host::disk_tool::command(program, leading_args, disk)
    }
}
