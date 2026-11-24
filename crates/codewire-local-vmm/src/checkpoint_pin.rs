//! The identity a VM checkpoint's saved state had when its digest was last
//! checked, so a later check digests it again only when the file changed
//! (#6124). A Mac's saved state holds the guest's memory, gigabytes that a
//! restore digested three times. The rule is the private design's Mac
//! checkpoints, condition 7, revision 3: an identity comes from `fstat` of an
//! open file, never a path; a pin sits beside the state it pins; and a file
//! whose identity doesn't match is digested in full against the manifest.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The pin's file name, beside the saved state it pins.
pub(crate) const PIN_NAME: &str = "state.pin";
/// A pin is a few hundred bytes of JSON.
const MAXIMUM_PIN_BYTES: u64 = 4096;

/// What moves whenever a file's content or mode may have changed: any write,
/// `chmod` or rename over the file moves its change time, and a copy is
/// another inode with another birth time. With the digest it vouches for.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) birth_seconds: i64,
    pub(crate) birth_nanoseconds: i64,
    pub(crate) change_seconds: i64,
    pub(crate) change_nanoseconds: i64,
    pub(crate) mode: u32,
    /// The saved state's sha256 that the digest recording this pin found.
    pub(crate) sha256: String,
}

impl StateIdentity {
    /// The identity of the open `file`, from its descriptor, vouching for no
    /// digest yet.
    #[cfg(target_os = "macos")]
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        use std::os::macos::fs::MetadataExt as _;
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.st_dev(),
            inode: metadata.st_ino(),
            size: metadata.st_size(),
            birth_seconds: metadata.st_birthtime(),
            birth_nanoseconds: metadata.st_birthtime_nsec(),
            change_seconds: metadata.st_ctime(),
            change_nanoseconds: metadata.st_ctime_nsec(),
            mode: metadata.st_mode(),
            sha256: String::new(),
        })
    }

    /// This identity, vouching for `sha256`.
    #[cfg(target_os = "macos")]
    pub(crate) fn vouching_for(self, sha256: &str) -> Self {
        Self {
            sha256: sha256.to_owned(),
            ..self
        }
    }

    /// Whether this pin vouches for exactly `sha256` and is the open
    /// `file`'s identity now: the file is then the one that digest read.
    #[cfg(target_os = "macos")]
    pub(crate) fn holds_for(&self, file: &File, sha256: &str) -> bool {
        !self.sha256.is_empty()
            && self.sha256 == sha256
            && Self::of(file).is_ok_and(|now| now.vouching_for(sha256) == *self)
    }
}

/// `directory`'s pin, or `None` when it has none or what it has is not one:
/// a regular file, not a link, sealed 0400, small, and exactly an identity.
/// `None` means the state is digested.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn read(directory: &Path) -> Option<StateIdentity> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(PIN_NAME))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != 0o400 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAXIMUM_PIN_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAXIMUM_PIN_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Record `identity` as `directory`'s pin, sealed 0400, in place of any
/// earlier one. A pin cut short by a crash doesn't parse, so it only costs
/// a digest.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn write(directory: &Path, identity: &StateIdentity) -> io::Result<()> {
    let path = directory.join(PIN_NAME);
    match fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(&serde_json::to_vec(identity).map_err(io::Error::other)?)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// The digest the test pins vouch for; the tests never digest.
    const SHA256: &str = "5a";

    /// A sealed state file and its pin, in a fresh private directory.
    fn pinned(directory: &Path) -> (std::path::PathBuf, StateIdentity) {
        let state = directory.join("state.vzsave");
        // A fresh file each time: the last one is sealed 0400.
        let _ = fs::remove_file(&state);
        fs::write(&state, b"saved state").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
        let identity = StateIdentity::of(&File::open(&state).unwrap())
            .unwrap()
            .vouching_for(SHA256);
        write(directory, &identity).unwrap();
        (state, identity)
    }

    #[test]
    fn an_unchanged_file_holds_its_pin_and_a_missing_pin_holds_nothing() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(read(directory.path()), None);
        let (state, identity) = pinned(directory.path());
        assert_eq!(read(directory.path()), Some(identity.clone()));
        assert!(identity.holds_for(&File::open(&state).unwrap(), SHA256));
        // It vouches for its own digest only.
        assert!(!identity.holds_for(&File::open(&state).unwrap(), "6b"));
    }

    #[test]
    fn a_write_a_chmod_or_a_copy_breaks_the_pin() {
        let directory = tempfile::tempdir().unwrap();
        let (state, identity) = pinned(directory.path());

        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            !identity.holds_for(&File::open(&state).unwrap(), SHA256),
            "chmod"
        );

        let (state, identity) = pinned(directory.path());
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        // Same length, so only the change time can tell.
        fs::write(&state, b"saved stbte").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            !identity.holds_for(&File::open(&state).unwrap(), SHA256),
            "write"
        );

        let (state, identity) = pinned(directory.path());
        let copy = directory.path().join("copy.vzsave");
        fs::copy(&state, &copy).unwrap();
        fs::remove_file(&state).unwrap();
        fs::rename(&copy, &state).unwrap();
        assert!(
            !identity.holds_for(&File::open(&state).unwrap(), SHA256),
            "copy"
        );
    }

    #[test]
    fn a_pin_that_is_not_sealed_or_not_an_identity_is_no_pin() {
        let directory = tempfile::tempdir().unwrap();
        let (_, identity) = pinned(directory.path());
        let pin = directory.path().join(PIN_NAME);
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(directory.path()), None, "not 0400");
        fs::write(&pin, b"{\"device\": 1}").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read(directory.path()), None, "not an identity");
        write(directory.path(), &identity).unwrap();
        assert_eq!(read(directory.path()), Some(identity), "rewritten");
    }
}
