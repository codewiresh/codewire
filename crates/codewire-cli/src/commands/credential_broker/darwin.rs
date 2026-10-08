//! macOS confinement of the local credential broker.
//!
//! Linux confines the broker with no-new-privileges, Landlock and seccomp and
//! reads values from Secret Service. macOS has none of those; the broker
//! instead checks what its authority launcher set up (new session, empty
//! environment, no core files), exits with that authority, refuses debugger
//! attachment, and then installs one Seatbelt profile before it holds a
//! lease channel. The profile allows only:
//!
//! - outbound TCP to port 443, when a provider is selected (its addresses
//!   were resolved and pinned before confinement);
//! - reading exactly the authority's store: the file backend's entry
//!   directory, or running Apple's `/usr/bin/security` against the keychain.
//!
//! Every other file, network, process and Mach service is denied. Descriptors
//! held before confinement (the authority channel and the guest bridge) keep
//! working. Keychain exposure equals Linux Secret Service: any process of the
//! user that may run `security` can read Codewire's items while the keychain
//! is unlocked.

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use codewire_local_credentials::FILE_STORE_DIRECTORY;
use codewire_protected_store::{ProtectedStoreBackend, SelectedProtectedStore};

use super::LocalCredentialBrokerArgs;

const SECURITY_TOOL: &str = "/usr/bin/security";

/// The authority store this broker reads, validated before any effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BrokerStore {
    /// One owner-only file per entry in this directory.
    File { directory: PathBuf },
    /// The login keychain, or an explicit test keychain file.
    Keychain { keychain: Option<PathBuf> },
}

impl BrokerStore {
    pub(super) fn from_args(args: &LocalCredentialBrokerArgs) -> anyhow::Result<Self> {
        let backend = ProtectedStoreBackend::parse(&args.protected_store)
            .filter(|backend| backend.supported())
            .context("invalid broker protected store")?;
        match (backend, &args.protected_store_directory, &args.keychain) {
            (ProtectedStoreBackend::File, Some(directory), None) => {
                anyhow::ensure!(
                    directory.is_absolute()
                        && directory.file_name() == Some(OsStr::new(FILE_STORE_DIRECTORY))
                        && plain_path(directory).is_some(),
                    "invalid broker protected store"
                );
                Ok(Self::File {
                    directory: directory.clone(),
                })
            }
            (ProtectedStoreBackend::Keychain, None, keychain) => {
                if let Some(keychain) = keychain {
                    anyhow::ensure!(
                        keychain.is_absolute() && plain_path(keychain).is_some(),
                        "invalid broker protected store"
                    );
                }
                Ok(Self::Keychain {
                    keychain: keychain.clone(),
                })
            }
            _ => anyhow::bail!("invalid broker protected store"),
        }
    }

    pub(super) fn open(&self) -> anyhow::Result<SelectedProtectedStore> {
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

/// Fail unless the authority launched this broker as its confined child, then
/// bind this process's life to that authority.
pub(super) fn verify_process() -> anyhow::Result<()> {
    let mut core = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: getrlimit writes one rlimit owned by this frame.
    let core_read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0;
    let confined = !rustix::process::geteuid().is_root()
        && rustix::process::getsid(None).ok() == Some(rustix::process::getpid())
        // CoreFoundation, which cw links, sets this one name itself while
        // the process loads; it is not inherited input.
        && std::env::vars_os().all(|(name, _)| name == "__CF_USER_TEXT_ENCODING")
        && core_read
        && core.rlim_max == 0;
    anyhow::ensure!(confined, "local credential broker is not confined");
    // Darwin has no parent-death signal: exit as soon as the authority does.
    codewire_local_vmm::darwin::process::exit_with_parent()
        .map_err(|_| anyhow::anyhow!("local credential broker is not confined"))?;
    // The macOS counterpart of a non-dumpable Linux broker: refuse debugger
    // attachment by other processes of the same user.
    // SAFETY: PT_DENY_ATTACH takes no address or data and affects only this
    // process.
    let denied = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    anyhow::ensure!(denied == 0, "local credential broker is not confined");
    Ok(())
}

/// Install the broker's Seatbelt profile. Irreversible for the process.
pub(super) fn confine(store: &BrokerStore, provider_network: bool) -> anyhow::Result<()> {
    let home = match store {
        BrokerStore::Keychain { keychain: None } => Some(home_directory()?),
        _ => None,
    };
    let profile = profile(store, provider_network, home.as_deref())?;
    codewire_local_vmm::darwin::sandbox::apply_profile(&profile)
        .map_err(|_| anyhow::anyhow!("the broker Seatbelt profile was not applied"))
}

/// The broker's Seatbelt profile. Every path is checked against a closed
/// alphabet first, so no value can end a string or add a rule.
pub(super) fn profile(
    store: &BrokerStore,
    provider_network: bool,
    home: Option<&Path>,
) -> anyhow::Result<CString> {
    let mut rules = String::from("(version 1)\n(deny default)\n");
    if provider_network {
        // Provider addresses were resolved and pinned before confinement.
        rules.push_str("(allow network-outbound (remote tcp \"*:443\"))\n");
    }
    match store {
        BrokerStore::File { directory } => {
            let parent = directory
                .parent()
                .context("invalid broker protected store")?;
            rules.push_str(&format!(
                "(allow file-read* (literal \"{}\") (subpath \"{}\"))\n",
                quoted(parent)?,
                quoted(directory)?
            ));
        }
        BrokerStore::Keychain { keychain } => {
            // Each operation runs Apple's security tool, which inherits this
            // profile: its own binary and the system libraries, the keychain,
            // the security server that unlocks and decrypts items, and the
            // user database (the broker has no HOME to name the user's home).
            rules.push_str(&format!(
                concat!(
                    "(allow process-fork)\n",
                    "(allow process-exec (literal \"{tool}\"))\n",
                    "(allow file-read* (literal \"/\") (literal \"{tool}\") ",
                    "(subpath \"/usr/lib\") (subpath \"/System\") ",
                    "(subpath \"/private/var/db/dyld\") (literal \"/dev/null\"))\n",
                    "(allow file-write-data (literal \"/dev/null\"))\n",
                    "(allow file-read-metadata)\n",
                    "(allow sysctl-read)\n",
                    "(allow mach-lookup (global-name \"com.apple.SecurityServer\") ",
                    "(global-name \"com.apple.system.opendirectoryd.libinfo\"))\n",
                ),
                tool = SECURITY_TOOL
            ));
            match (keychain, home) {
                (Some(keychain), _) => rules.push_str(&format!(
                    "(allow file-read* (literal \"{}\"))\n",
                    quoted(keychain)?
                )),
                (None, Some(home)) => {
                    // The login keychain is found through the user's
                    // keychain search list and home directory.
                    rules.push_str(&format!(
                        concat!(
                            "(allow file-read* (subpath \"{home}/Library/Keychains\") ",
                            "(literal \"{home}/Library/Preferences/com.apple.security.plist\"))\n",
                            "(allow mach-lookup ",
                            "(global-name \"com.apple.cfprefsd.agent\") ",
                            "(global-name \"com.apple.cfprefsd.daemon\"))\n",
                        ),
                        home = quoted(home)?
                    ));
                }
                (None, None) => anyhow::bail!("invalid broker protected store"),
            }
        }
    }
    CString::new(rules).context("invalid broker Seatbelt profile")
}

fn quoted(path: &Path) -> anyhow::Result<&str> {
    plain_path(path).context("broker store path cannot be confined")
}

/// An absolute path made only of characters that need no quoting in a
/// Seatbelt string, without `.` or `..` components.
fn plain_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    let plain = path.is_absolute()
        && text.len() <= 512
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
        && text.split('/').all(|part| !matches!(part, "." | ".."));
    plain.then_some(text)
}

/// This user's home directory from the user database: the broker has no
/// environment, and the login keychain lives below it.
fn home_directory() -> anyhow::Result<PathBuf> {
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain old data; zero is a valid value to overwrite.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, writable value of the stated
    // size; on success `result` points at `entry`, whose strings live in
    // `buffer`, which outlives their use below.
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    anyhow::ensure!(
        status == 0 && !result.is_null() && !entry.pw_dir.is_null(),
        "resolve the broker user's home directory"
    );
    // SAFETY: pw_dir is a NUL-terminated string inside `buffer`.
    let home = unsafe { CStr::from_ptr(entry.pw_dir) };
    Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())))
}

#[cfg(test)]
mod tests;
