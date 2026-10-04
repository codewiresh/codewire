//! Startup hardening of the credential service process.
//!
//! Every material read decrypts provider material in this process, and each
//! platform broker bridge epoch (hosted or owner-local delegation) may retain
//! a value for up to two minutes. The process is therefore not dumpable, so
//! another process of the same user without `CAP_SYS_PTRACE` can neither
//! attach to it nor read its `/proc/<pid>/mem`, and its core-file limit is
//! zero, soft and hard. Helpers it executes (`codex`, `gh`, `ssh-agent`,
//! `ssh-add`) are dumpable again after `exec`, because Linux resets the flag,
//! but inherit the zero core-file limit.

use super::RuntimeError;

/// Make this process non-dumpable with a zero core-file limit, then read
/// both back. Startup stops unless both are confirmed.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<(), RuntimeError> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: scalar prctl calls and one fixed-layout rlimit pointer; they
    // change only this process's dumpable flag and core-file limit.
    let applied = unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
            && libc::setrlimit(libc::RLIMIT_CORE, &none) == 0
    };
    let mut core = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: as above; getrlimit writes only the provided rlimit.
    let confirmed = unsafe {
        libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
            && libc::getrlimit(libc::RLIMIT_CORE, &mut core) == 0
    };
    if !applied || !confirmed || core.rlim_cur != 0 || core.rlim_max != 0 {
        return Err(RuntimeError::Hardening);
    }
    Ok(())
}

/// The service runs only on Linux; elsewhere it refuses to start.
#[cfg(not(target_os = "linux"))]
pub fn harden_process() -> Result<(), RuntimeError> {
    Err(RuntimeError::Hardening)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const CHILD: &str = "CODEWIRE_CREDENTIAL_SERVICE_HARDENING_CHILD";
    const NAME: &str =
        "runtime::hardening::tests::startup_leaves_the_process_undumpable_without_core_files";

    /// Hardening is process-wide and irreversible, so it runs in a re-executed
    /// copy of this test binary, never in the shared test process.
    #[test]
    fn startup_leaves_the_process_undumpable_without_core_files() {
        if std::env::var_os(CHILD).is_some() {
            harden_process().expect("hardening is confirmed");
            // SAFETY: scalar reads of this child's own process attributes.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            assert_eq!(dumpable, 0);
            let mut core = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            // SAFETY: getrlimit writes only the provided rlimit.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) }, 0);
            assert_eq!((core.rlim_cur, core.rlim_max), (0, 0));
            // Hardening again is idempotent.
            harden_process().expect("hardening is repeatable");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("re-execute this test binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "hardened child failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
