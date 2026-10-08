//! Darwin primitives shared by the macOS credential children (the broker and
//! the repository executor and its Git helpers).
//!
//! The authority names its own store on each child's command line; a child
//! that reads material opens exactly that store. Linux children prove
//! no-new-privileges, an empty capability set and a non-dumpable state; macOS
//! has none of those, so a child instead checks what its launcher set up (no
//! root, no core files, a new session and an empty environment where the
//! launcher provides them), exits with its parent and refuses debugger
//! attachment.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;
use codewire_local_credentials::FILE_STORE_DIRECTORY;
use codewire_protected_store::{ProtectedStoreBackend, SelectedProtectedStore};

/// The authority store as a child receives it on its command line.
#[derive(Debug, Args)]
pub(crate) struct ChildStoreArgs {
    /// The authority's store: macOS children read the selected backend, not a
    /// platform default.
    #[arg(long)]
    pub(crate) protected_store: String,
    /// The file backend's entry directory inside the authority root.
    #[arg(long)]
    pub(crate) protected_store_directory: Option<PathBuf>,
    /// Test-only explicit keychain file for the keychain backend.
    #[arg(long)]
    pub(crate) keychain: Option<PathBuf>,
}

/// The authority store a child reads, validated before any effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChildStore {
    /// One owner-only file per entry in this directory.
    File { directory: PathBuf },
    /// The login keychain, or an explicit test keychain file.
    Keychain { keychain: Option<PathBuf> },
}

impl ChildStore {
    pub(crate) fn from_args(args: &ChildStoreArgs) -> anyhow::Result<Self> {
        let backend = ProtectedStoreBackend::parse(&args.protected_store)
            .filter(|backend| backend.supported())
            .context("invalid child protected store")?;
        match (backend, &args.protected_store_directory, &args.keychain) {
            (ProtectedStoreBackend::File, Some(directory), None) => {
                anyhow::ensure!(
                    directory.is_absolute()
                        && directory.file_name() == Some(OsStr::new(FILE_STORE_DIRECTORY))
                        && plain_path(directory).is_some(),
                    "invalid child protected store"
                );
                Ok(Self::File {
                    directory: directory.clone(),
                })
            }
            (ProtectedStoreBackend::Keychain, None, keychain) => {
                if let Some(keychain) = keychain {
                    anyhow::ensure!(
                        keychain.is_absolute() && plain_path(keychain).is_some(),
                        "invalid child protected store"
                    );
                }
                Ok(Self::Keychain {
                    keychain: keychain.clone(),
                })
            }
            _ => anyhow::bail!("invalid child protected store"),
        }
    }

    pub(crate) fn open(&self) -> anyhow::Result<SelectedProtectedStore> {
        let store = match self {
            Self::File { directory } => {
                SelectedProtectedStore::open(ProtectedStoreBackend::File, directory, None)
            }
            Self::Keychain { keychain } => SelectedProtectedStore::open(
                ProtectedStoreBackend::Keychain,
                Path::new("/"),
                keychain.as_deref(),
            ),
        };
        store.map_err(|error| anyhow::anyhow!("{error}"))
    }
}

/// An absolute path made only of characters that need no quoting in a
/// Seatbelt string, without `.` or `..` components.
pub(crate) fn plain_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    let plain = path.is_absolute()
        && text.len() <= 512
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
        && text.split('/').all(|part| !matches!(part, "." | ".."));
    plain.then_some(text)
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
