//! The CLI's process constructors (#6242). On macOS a child cw starts must
//! not inherit a descriptor it wasn't meant to: Darwin creates a socket or
//! pipe and only then marks it close-on-exec, so a child forked in between
//! keeps one open, whether it is a credential broker or a short tool cw waits
//! on. Every child therefore starts through codewire-local-vmm's swept
//! constructors: on macOS their hook marks every descriptor from 3 up
//! close-on-exec between fork and exec, then clears the flag on `keep`, the
//! descriptors the child is meant to inherit. On Linux, where every
//! descriptor is created close-on-exec at once, a child with nothing kept
//! gets no hook and starts exactly as `Command::new` starts it; the
//! credential paths there keep their own `close_range`.
//!
//! The crate's clippy.toml disallows every other way to fork, spawn or exec.
//! cw builds only for Linux and macOS, the targets where it depends on
//! codewire-local-vmm, so there is no other branch.

use std::ffi::OsStr;
use std::os::fd::RawFd;

/// A child as a `std::process::Command`, inheriting past stdio only `keep`.
/// A hook the caller adds runs after the sweep.
pub(crate) fn command(program: impl AsRef<OsStr>, keep: &[RawFd]) -> std::process::Command {
    codewire_local_vmm::swept_command(program, keep)
}

/// [`command`] as a `tokio::process::Command`.
pub(crate) fn tokio_command(program: impl AsRef<OsStr>, keep: &[RawFd]) -> tokio::process::Command {
    codewire_local_vmm::swept_tokio_command(program, keep)
}

/// Replace this process with `command`, which must come from [`command`]:
/// exec runs its hooks, the sweep first, in this process before it execs.
/// It returns only the error of an exec that failed.
#[expect(
    clippy::disallowed_methods,
    reason = "the crate's one exec, of a command built by `command` (#6242)"
)]
pub(crate) fn exec(command: &mut std::process::Command) -> std::io::Error {
    std::os::unix::process::CommandExt::exec(command)
}

/// The child the macOS descriptor tests start (#6242): this test binary,
/// exec'd with [`REPORT`] set to a path, writes there the numbers of the
/// descriptors open in it.
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod descriptor_report {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    /// Set to a path, it makes [`report`] write the open descriptors there.
    pub(crate) const REPORT: &str = "CODEWIRE_TEST_DESCRIPTOR_REPORT";
    /// The filter that runs [`report`] alone.
    pub(crate) const TEST: &str = "process::descriptor_report::report";

    /// Not a test on its own: with [`REPORT`] set it lists every open
    /// descriptor before it opens the report.
    #[test]
    fn report() {
        let Some(report) = std::env::var_os(REPORT) else {
            return;
        };
        // SAFETY: getdtablesize takes no arguments, and F_GETFD only reads
        // a descriptor's flags, failing on a number that isn't open.
        let open = (0..unsafe { libc::getdtablesize() })
            .filter(|&descriptor| unsafe { libc::fcntl(descriptor, libc::F_GETFD) } != -1)
            .map(|descriptor| descriptor.to_string())
            .collect::<Vec<_>>();
        std::fs::write(report, open.join(" ")).unwrap();
    }

    /// A descriptor without close-on-exec, at 64 or above so it is never one
    /// a child is handed: a child that holds it was not swept.
    pub(crate) fn planted() -> OwnedFd {
        let source = std::fs::File::open("/dev/null").unwrap();
        // F_DUPFD clears close-on-exec.
        // SAFETY: duplicates a descriptor this test owns.
        let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(raw >= 64);
        // SAFETY: `raw` is a fresh descriptor nothing else owns.
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    /// A shell script at `path` that runs [`report`] into `output`, for a
    /// child whose program is a path, such as Git's credential helper.
    pub(crate) fn script(path: &std::path::Path, output: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;

        let binary = std::env::current_exe().unwrap();
        let (binary, output) = (binary.to_str().unwrap(), output.to_str().unwrap());
        assert!(
            !binary.contains('\'') && !output.contains('\''),
            "quoted below"
        );
        std::fs::write(
            path,
            format!(
                "#!/bin/sh\n{REPORT}='{output}'; export {REPORT}\nexec '{binary}' --exact {TEST}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
