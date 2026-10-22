//! A supervisor peer's process birth and the file it runs, shared by the Linux
//! and macOS peer pins (#2549).
//!
//! A pin observes the birth when it admits a peer and again on every
//! reconnect. That costs a few kernel queries and no read of the executable.
//! Only a peer running another cw version has its executable hashed, once per
//! birth, to admit it as a version the managed store retains. The platforms
//! differ only in how they name a birth and the file it runs.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_cw_release::store::Store;

use crate::host::path::FileIdentity;
use crate::host::process::{self, ProcessIdentity, RecoveryError};

/// A live process birth and the executable file it runs, without the file's
/// digest. Observing it again proves the same process still runs from the
/// same, unmodified file. The file's change time is part of it: any write,
/// chmod or rename of the file advances it, and a user process cannot set it
/// back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessBirth {
    pid: u32,
    boot_id: String,
    start_time: u64,
    executable: PathBuf,
    executable_file: FileIdentity,
    executable_changed: (i64, i64),
}

impl ProcessBirth {
    pub(crate) fn observe(pid: u32) -> Result<Self, RecoveryError> {
        let (boot_id, start_time) = process::birth_of(pid)?;
        let (executable, metadata) = process::executable_of(pid)?;
        if process::birth_of(pid)? != (boot_id.clone(), start_time) {
            return Err(RecoveryError::IdentityMismatch);
        }
        Ok(Self {
            pid,
            boot_id,
            start_time,
            executable,
            executable_file: FileIdentity::from_metadata(&metadata),
            executable_changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    /// Whether `identity` records this same birth and executable file.
    pub(crate) fn is(&self, identity: &ProcessIdentity) -> bool {
        identity.pid == self.pid
            && identity.boot_id == self.boot_id
            && identity.start_time_ticks == self.start_time
            && identity.executable == self.executable
            && identity.executable_file == self.executable_file
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Identity,
    Provenance,
}

/// Admit a peer that runs another cw version. `identity` carries the digest of
/// its executable, read once. It must describe this birth's file, the file
/// must not have changed while it was read, and the managed store must retain
/// it as a version with that digest.
pub(crate) fn admit_retained_version(
    peer: &ProcessBirth,
    identity: &ProcessIdentity,
) -> Result<(), AdmissionError> {
    if !peer.is(identity)
        || ProcessBirth::observe(peer.pid).map_err(|_| AdmissionError::Identity)? != *peer
    {
        return Err(AdmissionError::Identity);
    }
    let root = Store::locate(&identity.executable).ok_or(AdmissionError::Provenance)?;
    let store =
        Store::open(&root, Duration::from_secs(1)).map_err(|_| AdmissionError::Provenance)?;
    let record = store
        .verify(&identity.executable_sha256)
        .map_err(|_| AdmissionError::Provenance)?;
    if store.version_executable(&record.sha256) != identity.executable
        || record.sha256 != identity.executable_sha256
        || record.size != identity.executable_file.size
    {
        return Err(AdmissionError::Provenance);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    #[test]
    fn a_process_birth_matches_its_identity_without_reading_the_executable() {
        let pid = std::process::id();
        let birth = ProcessBirth::observe(pid).unwrap();
        assert_eq!(birth, ProcessBirth::observe(pid).unwrap());
        assert_eq!(birth.pid(), pid);
        let identity = ProcessIdentity::capture(pid).unwrap();
        assert!(birth.is(&identity));
        // Another birth, or the same birth under another file, is not this one.
        let mut other = identity.clone();
        other.start_time_ticks += 1;
        assert!(!birth.is(&other));
        let mut moved = identity;
        moved.executable_file.inode += 1;
        assert!(!birth.is(&moved));
        assert!(ProcessBirth::observe(0).is_err());
    }

    #[test]
    fn a_rewritten_executable_is_not_the_same_birth() {
        // A same-user process can change the file and restore its mode, size
        // and links; only its change time records that it happened.
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("sleeper");
        std::fs::copy(sleep_binary(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = Command::new(&executable);
        command.arg("30");
        let mut child = spawn_copied(&mut command);
        let pid = child.id();
        let birth = exec_birth(pid, &executable, &mut child);
        assert_eq!(birth, ProcessBirth::observe(pid).unwrap());
        std::thread::sleep(Duration::from_millis(20));
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let after = ProcessBirth::observe(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_ne!(after.unwrap(), birth);
    }

    /// The child's birth once it runs `executable`. `spawn` can return as the
    /// child releases its parent, a moment before the kernel switches it to
    /// the new image, so a first look could still see this test binary. This
    /// waits for that state, not for a clock; a child that ends first fails.
    fn exec_birth(pid: u32, executable: &Path, child: &mut std::process::Child) -> ProcessBirth {
        let executable = std::fs::canonicalize(executable).unwrap();
        loop {
            if let Ok(birth) = ProcessBirth::observe(pid)
                && birth.executable() == executable
            {
                return birth;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "the copied executable's child ended before its exec was visible"
            );
            std::thread::yield_now();
        }
    }

    /// Spawn an executable this test just copied. A concurrent test's fork
    /// child can hold the copy's write descriptor until its own exec, so the
    /// kernel briefly refuses it with ETXTBSY; retry only that, bounded.
    fn spawn_copied(command: &mut Command) -> std::process::Child {
        for _ in 1..50 {
            match command.spawn() {
                Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => return result.unwrap(),
            }
        }
        command.spawn().unwrap()
    }

    fn sleep_binary() -> PathBuf {
        ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .and_then(|path| std::fs::canonicalize(path).ok())
            .expect("a sleep executable")
    }
}
