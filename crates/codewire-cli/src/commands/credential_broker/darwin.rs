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
//! A platform relay broker reads no store and dials no provider: its profile
//! denies everything, where Linux installs Landlock and then seccomp.
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

use super::super::credential_darwin::{
    ChildStore, bind_to_parent_and_deny_attachment, isolated_session_and_environment, plain_path,
    unprivileged_without_core_files,
};

const SECURITY_TOOL: &str = "/usr/bin/security";

/// Fail unless the authority launched this broker as its confined child, then
/// bind this process's life to that authority.
pub(super) fn verify_process() -> anyhow::Result<()> {
    anyhow::ensure!(
        unprivileged_without_core_files() && isolated_session_and_environment(),
        "local credential broker is not confined"
    );
    bind_to_parent_and_deny_attachment()
        .map_err(|_| anyhow::anyhow!("local credential broker is not confined"))
}

/// Install the platform relay's deny-all profile, which keeps only the guest
/// bridge and authority channel it already holds: it reads no store and dials
/// no provider. Irreversible.
pub(super) fn confine_relay() -> anyhow::Result<()> {
    codewire_local_vmm::darwin::sandbox::deny_all()
        .map_err(|_| anyhow::anyhow!("the relay Seatbelt profile was not applied"))
}

/// Install the broker's Seatbelt profile. Irreversible for the process.
pub(super) fn confine(store: &ChildStore, provider_network: bool) -> anyhow::Result<()> {
    let home = match store {
        ChildStore::Keychain { keychain: None } => Some(home_directory()?),
        _ => None,
    };
    let profile = profile(store, provider_network, home.as_deref())?;
    codewire_local_vmm::darwin::sandbox::apply_profile(&profile)
        .map_err(|_| anyhow::anyhow!("the broker Seatbelt profile was not applied"))
}

/// The broker's Seatbelt profile. Every path is checked against a closed
/// alphabet first, so no value can end a string or add a rule.
pub(super) fn profile(
    store: &ChildStore,
    provider_network: bool,
    home: Option<&Path>,
) -> anyhow::Result<CString> {
    let mut rules = String::from("(version 1)\n(deny default)\n");
    if provider_network {
        // Provider addresses were resolved and pinned before confinement.
        rules.push_str("(allow network-outbound (remote tcp \"*:443\"))\n");
    }
    match store {
        ChildStore::File { directory } => {
            let parent = directory
                .parent()
                .context("invalid broker protected store")?;
            rules.push_str(&format!(
                "(allow file-read* (literal \"{}\") (subpath \"{}\"))\n",
                quoted(parent)?,
                quoted(directory)?
            ));
        }
        ChildStore::Keychain { keychain } => {
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
