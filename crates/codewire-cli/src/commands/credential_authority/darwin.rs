//! Detached macOS launch of the local credential authority.
//!
//! `posix_spawn` gives the child a new session (`POSIX_SPAWN_SETSID`), closes
//! every inherited descriptor except stdin, stdout and stderr, which point at
//! `/dev/null` (`POSIX_SPAWN_CLOEXEC_DEFAULT`), resets signal dispositions and
//! the signal mask, passes an empty environment and starts in the authority
//! root. The authority sets its umask itself before creating any file.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

use codewire_local_credentials::SpawnedAuthority;

/// `<sys/spawn.h>`; the libc crate does not define it.
const POSIX_SPAWN_SETSID: libc::c_int = 0x0400;

unsafe extern "C" {
    // Present since macOS 10.15; newer SDKs also spell it without `_np`.
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

/// A spawned child this process still owns until it is admitted or reaped.
/// Dropping it neither kills nor waits: the authority outlives its starter.
pub(super) struct SpawnedProcess {
    pid: libc::pid_t,
    status: Option<ExitStatus>,
}

struct FileActions(libc::posix_spawn_file_actions_t);

impl Drop for FileActions {
    fn drop(&mut self) {
        // SAFETY: initialized by posix_spawn_file_actions_init and destroyed once.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

struct Attributes(libc::posix_spawnattr_t);

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized by posix_spawnattr_init and destroyed once.
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

fn c_string(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

pub(super) fn spawn_detached(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
) -> io::Result<SpawnedProcess> {
    let program = c_string(program.as_os_str())?;
    let directory = c_string(directory.as_os_str())?;
    let arguments = std::iter::once(Ok(program.clone()))
        .chain(arguments.iter().map(|argument| c_string(argument)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut argv = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());
    let envp = [std::ptr::null_mut::<libc::c_char>()];
    let null_device = c"/dev/null";

    // SAFETY: every pointer passed below refers to a live, NUL-terminated
    // C string or a null-terminated pointer array owned by this frame; the
    // action and attribute objects are initialized before use and destroyed
    // by their guards after posix_spawn returns.
    unsafe {
        let mut actions = MaybeUninit::uninit();
        check(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
        let mut actions = FileActions(actions.assume_init());
        for (descriptor, flags) in [
            (libc::STDIN_FILENO, libc::O_RDONLY),
            (libc::STDOUT_FILENO, libc::O_WRONLY),
            (libc::STDERR_FILENO, libc::O_WRONLY),
        ] {
            check(libc::posix_spawn_file_actions_addopen(
                &mut actions.0,
                descriptor,
                null_device.as_ptr(),
                flags,
                0,
            ))?;
        }
        check(posix_spawn_file_actions_addchdir_np(
            &mut actions.0,
            directory.as_ptr(),
        ))?;

        let mut attributes = MaybeUninit::uninit();
        check(libc::posix_spawnattr_init(attributes.as_mut_ptr()))?;
        let mut attributes = Attributes(attributes.assume_init());
        let flags = POSIX_SPAWN_SETSID
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_SETSIGMASK;
        check(libc::posix_spawnattr_setflags(
            &mut attributes.0,
            flags as libc::c_short,
        ))?;
        let mut defaults = MaybeUninit::uninit();
        libc::sigfillset(defaults.as_mut_ptr());
        check(libc::posix_spawnattr_setsigdefault(
            &mut attributes.0,
            defaults.as_ptr(),
        ))?;
        let mut mask = MaybeUninit::uninit();
        libc::sigemptyset(mask.as_mut_ptr());
        check(libc::posix_spawnattr_setsigmask(
            &mut attributes.0,
            mask.as_ptr(),
        ))?;

        let mut pid = 0;
        check(libc::posix_spawn(
            &mut pid,
            program.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        ))?;
        Ok(SpawnedProcess { pid, status: None })
    }
}

impl SpawnedProcess {
    fn wait_with(&mut self, options: libc::c_int) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        loop {
            let mut status = 0;
            // SAFETY: waits only for this exact, not yet reaped child.
            match unsafe { libc::waitpid(self.pid, &mut status, options) } {
                0 => return Ok(None),
                pid if pid == self.pid => {
                    let status = ExitStatus::from_raw(status);
                    self.status = Some(status);
                    return Ok(Some(status));
                }
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
}

impl SpawnedAuthority for SpawnedProcess {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.wait_with(libc::WNOHANG)
    }

    fn kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        // SAFETY: the pid is this process's unreaped child, so it cannot
        // have been reused for another process.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.wait_with(0)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;

    fn run(script: &str, directory: &Path) -> (SpawnedProcess, std::path::PathBuf) {
        let output = directory.join("observed");
        let child = spawn_detached(
            Path::new("/bin/sh"),
            &[
                "-c".into(),
                script.into(),
                "sh".into(),
                output.clone().into_os_string(),
            ],
            directory,
        )
        .unwrap();
        (child, output)
    }

    #[test]
    fn the_child_leads_a_new_session_without_environment_in_the_given_directory() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let (mut child, output) = run(
            "{ ps -o pgid= -p $$; echo $$; echo \"${HOME-unset}\"; pwd; } > \"$1\"",
            &directory,
        );
        let status = child.wait().unwrap();
        assert!(status.success());
        let observed = std::fs::read_to_string(output).unwrap();
        let lines = observed.lines().map(str::trim).collect::<Vec<_>>();
        assert_eq!(lines[0], lines[1], "setsid makes the child a group leader");
        assert_eq!(lines[2], "unset");
        assert_eq!(lines[3], directory.to_str().unwrap());
        assert_eq!(child.try_wait().unwrap(), Some(status));
    }

    #[test]
    fn inherited_descriptors_without_close_on_exec_are_closed() {
        let directory = tempfile::tempdir().unwrap();
        let leaked = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: clears FD_CLOEXEC on a descriptor this test owns.
        assert_eq!(
            unsafe { libc::fcntl(leaked.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let exists = |descriptor: i32| {
            spawn_detached(
                Path::new("/bin/test"),
                &["-e".into(), format!("/dev/fd/{descriptor}").into()],
                directory.path(),
            )
            .unwrap()
            .wait()
            .unwrap()
            .success()
        };
        assert!(exists(2), "stderr is reopened on /dev/null");
        assert!(!exists(leaked.as_raw_fd()));
    }

    #[test]
    fn an_unadmitted_child_can_be_killed_and_reaped() {
        let directory = tempfile::tempdir().unwrap();
        let (mut child, _) = run("exec sleep 30", directory.path());
        assert_eq!(child.try_wait().unwrap(), None);
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        child.kill().unwrap();
        let (mut child, _) = run("exit 83", directory.path());
        assert_eq!(child.wait().unwrap().code(), Some(83));
    }
}
