//! macOS launch of the local credential authority and of its brokers.
//!
//! The authority is detached: `posix_spawn` gives the child a new session
//! (`POSIX_SPAWN_SETSID`), closes every inherited descriptor except stdin,
//! stdout and stderr, which point at `/dev/null`
//! (`POSIX_SPAWN_CLOEXEC_DEFAULT`), resets signal dispositions and the signal
//! mask, passes an empty environment and starts in the authority root. The
//! authority sets its umask itself before creating any file.
//!
//! A broker is an owned child of the authority: it keeps only its authority
//! channel as descriptor 3, gets an empty environment, a new session, no core
//! files and umask 077, and exits with the authority (Darwin has no
//! parent-death signal; the broker watches its parent itself).

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use codewire_local_credentials::{
    AuthorityProtectedStore, FILE_STORE_DIRECTORY, LocalBrokerProcessConfig,
    LocalBrokerProcessSpawner, LocalBrokerSpawnError, SpawnedAuthority,
};
use codewire_protected_store::ProtectedStoreBackend;

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

/// Launches `cw __local-credential-broker` for one environment generation.
/// The broker reads values from exactly the authority's store.
pub(super) struct CwLocalCredentialBrokerSpawner {
    pub(super) executable: PathBuf,
    pub(super) authority_root: PathBuf,
    pub(super) store: AuthorityProtectedStore,
}

impl CwLocalCredentialBrokerSpawner {
    fn store_arguments(&self) -> Result<Vec<OsString>, LocalBrokerSpawnError> {
        let mut arguments = vec![
            OsString::from("--protected-store"),
            self.store.backend.as_str().into(),
        ];
        match (self.store.backend, &self.store.keychain) {
            (ProtectedStoreBackend::Keychain, keychain) => {
                if let Some(keychain) = keychain {
                    arguments.push("--keychain".into());
                    arguments.push(keychain.clone().into_os_string());
                }
            }
            (ProtectedStoreBackend::File, None) => {
                arguments.push("--protected-store-directory".into());
                arguments.push(
                    self.authority_root
                        .join(FILE_STORE_DIRECTORY)
                        .into_os_string(),
                );
            }
            _ => return Err(LocalBrokerSpawnError::InvalidConfiguration),
        }
        Ok(arguments)
    }
}

impl LocalBrokerProcessSpawner for CwLocalCredentialBrokerSpawner {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        // No platform relay exists on macOS; the authority has no connector.
        if config.platform_delegated {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        let store_arguments = self.store_arguments()?;
        // SAFETY: getpid has no preconditions.
        let parent_pid = unsafe { libc::getpid() };
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .arg("__local-credential-broker")
            .arg("--authority-fd")
            .arg("3")
            .arg("--environment-id")
            .arg(config.environment_id.to_string())
            .arg("--environment-generation")
            .arg(config.environment_generation.to_string())
            .arg("--environment-name")
            .arg(&config.environment_name)
            .arg("--runner-socket")
            .arg(&config.runner_socket)
            .args(store_arguments)
            .env_clear()
            .current_dir(&self.authority_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for provider in &config.http_providers {
            command.arg("--http-provider").arg(provider.as_str());
        }
        // SAFETY: this post-fork hook uses async-signal-safe system calls
        // only. It binds the child to this exact authority, starts a new
        // session, marks every descriptor from 3 up close-on-exec (Darwin
        // sets that flag in a second call, so a descriptor another thread is
        // creating could otherwise reach the child), then moves the
        // authority channel to fixed descriptor 3, and disables core files.
        unsafe {
            command.pre_exec(move || {
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                codewire_local_vmm::darwin::process::mark_inherited_descriptors_close_on_exec();
                if authority_fd == 3 {
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup2(authority_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let no_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        command.spawn().map_err(|_| LocalBrokerSpawnError::Spawn)
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

    #[tokio::test]
    async fn a_broker_keeps_only_its_authority_channel_in_a_new_empty_session() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let leaked = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: clears FD_CLOEXEC on a descriptor this test owns.
        assert_eq!(
            unsafe { libc::fcntl(leaked.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let broker = root.join("broker");
        std::fs::write(
            &broker,
            format!(
                concat!(
                    "#!/bin/sh\n",
                    "{{ ps -o pgid= -p $$; echo $$; ",
                    "env | cut -d= -f1 | grep -v -x -e PWD -e SHLVL -e _ | wc -l; ",
                    "ulimit -c; umask; ",
                    "test -e /dev/fd/3 && echo channel; ",
                    "test -e /dev/fd/{leaked} && echo leaked; ",
                    "pwd; echo \"$@\"; }} > observed\n",
                ),
                leaked = leaked.as_raw_fd()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&broker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let spawner = CwLocalCredentialBrokerSpawner {
            executable: broker,
            authority_root: root.clone(),
            store: AuthorityProtectedStore {
                backend: ProtectedStoreBackend::File,
                keychain: None,
            },
        };
        let environment = uuid::Uuid::new_v4().to_string();
        let config = LocalBrokerProcessConfig {
            environment_id: codewire_access::EnvironmentId::parse(environment.clone()).unwrap(),
            environment_generation: 1,
            environment_name: "env".to_owned(),
            runner_socket: root.join("runners").join(format!("{environment}.sock")),
            http_providers: [codewire_access::HttpProvider::OpenAiApiKey].into(),
            platform_delegated: false,
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = spawner.spawn(&config, peer).unwrap();
        assert!(child.wait().await.unwrap().success());
        let observed = std::fs::read_to_string(root.join("observed")).unwrap();
        let lines = observed.lines().map(str::trim).collect::<Vec<_>>();
        assert_eq!(lines[0], lines[1], "setsid makes the broker a group leader");
        assert_eq!(lines[2], "0", "only the shell's own variables are set");
        assert_eq!(lines[3], "0", "core files are disabled");
        assert_eq!(lines[4], "0077");
        assert_eq!(lines[5], "channel", "the authority channel is descriptor 3");
        assert_eq!(
            lines[6],
            root.to_str().unwrap(),
            "no other descriptor survives"
        );
        assert!(lines[7].starts_with(&format!(
            "__local-credential-broker --authority-fd 3 --environment-id {environment} "
        )));
        assert!(lines[7].ends_with(&format!(
            "--protected-store file --protected-store-directory {}/protected-v1 --http-provider openai-api-key",
            root.display()
        )));

        let platform = LocalBrokerProcessConfig {
            http_providers: Default::default(),
            platform_delegated: true,
            ..config
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(matches!(
            spawner.spawn(&platform, peer),
            Err(LocalBrokerSpawnError::InvalidConfiguration)
        ));
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
