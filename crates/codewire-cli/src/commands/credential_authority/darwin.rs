//! macOS launch of the local credential authority and of its brokers.
//!
//! The authority is detached: `posix_spawn` gives the child a new session
//! (`POSIX_SPAWN_SETSID`), closes every inherited descriptor except stdin,
//! stdout and stderr, which point at `/dev/null`
//! (`POSIX_SPAWN_CLOEXEC_DEFAULT`), resets signal dispositions and the signal
//! mask, passes an empty environment and starts in the authority root. The
//! authority sets its umask itself before creating any file.
//!
//! A broker or executor is an owned child of the authority: it keeps only
//! its authority channel as descriptor 3, and a broker a boot's secrets as
//! descriptor 4 when the boot has them. It gets an empty
//! environment, a new session, no core files and umask 077, and exits with
//! the authority (Darwin has no parent-death signal; the child watches its
//! parent itself). Its stderr is a pipe the authority drains: a broker keeps
//! the tail in its broker log (#2763), and a repository executor's lets the
//! authority stop its whole process group and observe every descendant exit.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use codewire_local_credentials::{
    AuthorityProtectedStore, LocalBrokerProcessConfig, LocalBrokerProcessSpawner,
    LocalBrokerSpawnError, LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner,
    LocalRepositorySpawnError, LocalRepositoryTransport, LocalRevocationProcessConfig,
    LocalRevocationProcessSpawner, LocalRevocationSpawnError, ProviderLookup, SpawnedAuthority,
};

use super::super::credential_child_store::child_store_arguments;
use super::super::credential_darwin::admit_runtime_git;

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

#[expect(
    clippy::disallowed_methods,
    reason = "with POSIX_SPAWN_CLOEXEC_DEFAULT the authority gets only what the file actions \
              hand it, with no window between fork and exec that a sweep after fork has (#6242)"
)]
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

/// Launches the authority's credential children: `cw __local-credential-broker`
/// for one environment generation and `cw __local-git-repository-executor` for
/// one repository preparation. Each reads values from exactly the authority's
/// store.
pub(super) struct CwLocalCredentialProcessSpawner {
    pub(super) executable: PathBuf,
    pub(super) authority_root: PathBuf,
    pub(super) store: AuthorityProtectedStore,
    /// The installed local VM runtime (artifact root, lock) whose git a
    /// repository executor may run.
    pub(super) runtime: Option<(PathBuf, PathBuf)>,
}

/// The descriptor each child of the authority holds its authority channel
/// at.
const AUTHORITY_FD: RawFd = 3;

/// What a child of the authority keeps through the close-on-exec sweep by
/// number: nothing. Its hook (`authority_child`) moves the authority channel
/// to [`AUTHORITY_FD`] and a broker's boot secrets to `BOOT_SECRETS_FD` with
/// `dup2`, whose copy is inheritable while each source, swept, is closed on
/// exec, so the child holds exactly stdio and those. Keeping a source would
/// hand the child that number as well, and keeping 3 or 4 would hand it
/// whatever the authority holds there when nothing is moved onto it.
const AUTHORITY_CHILD_KEEPS: &[RawFd] = &[];

/// A child bound to this exact authority before exec. The sweep of
/// `crate::process::tokio_command` runs first, marking every descriptor
/// from 3 up close-on-exec (Darwin sets that flag in a second call, so a
/// descriptor another thread is creating could otherwise reach the child).
/// Then the child checks its parent, starts a new session (so it leads its
/// own process group), gets `authority_fd` as [`AUTHORITY_FD`] and, when
/// `secrets_fd` is given, a boot's secrets as `BOOT_SECRETS_FD` (#3999),
/// with core files disabled and umask 077.
fn authority_child(
    executable: &Path,
    authority_fd: RawFd,
    secrets_fd: Option<RawFd>,
) -> tokio::process::Command {
    let mut command = crate::process::tokio_command(executable, AUTHORITY_CHILD_KEEPS);
    // SAFETY: getpid has no preconditions.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: this post-fork hook uses async-signal-safe system calls only.
    unsafe {
        command.pre_exec(move || {
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if authority_fd == AUTHORITY_FD {
                if libc::fcntl(AUTHORITY_FD, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(authority_fd, AUTHORITY_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            // After FD 3: the secrets' descriptor is above FD 4, so the move
            // to 3 never overwrites it, and dup2 leaves FD 4 inheritable.
            if let Some(secrets_fd) = secrets_fd
                && libc::dup2(secrets_fd, super::BOOT_SECRETS_FD) < 0
            {
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
    command
}

impl LocalBrokerProcessSpawner for CwLocalCredentialProcessSpawner {
    fn runner_protocol(&self) -> u32 {
        // The broker this starts is this cw's `__local-credential-broker`,
        // whose `RunnerClient` admits exactly this runner protocol.
        codewire_local_vmm::runner_service::NATIVE_RUNNER_PROTOCOL_VERSION
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        lookup: &ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        boot_secrets: &codewire_local_credentials::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        // An intercepting boot's pairing secret, for its front door (#3999).
        let boot_secrets = super::boot_secret_descriptor(boot_secrets)?;
        let secrets_fd = boot_secrets.as_ref().map(|secrets| secrets.as_raw_fd());
        let store_arguments = child_store_arguments(&self.store, &self.authority_root)
            .ok_or(LocalBrokerSpawnError::InvalidConfiguration)?;
        let mut command = authority_child(&self.executable, authority_fd, secrets_fd);
        command
            .arg("__local-credential-broker")
            .arg("--authority-fd")
            .arg(AUTHORITY_FD.to_string())
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
            // The authority keeps the tail of this pipe for its broker log.
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for provider in &config.http_providers {
            command.arg("--http-provider").arg(provider.as_str());
        }
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        if config.network_policy_allows_github {
            command.arg("--network-policy-allows-github");
        }
        for host in &config.network_policy_allowed_hosts {
            command.arg("--network-policy-allows-host").arg(host);
        }
        command.args(lookup.arguments());
        if secrets_fd.is_some() {
            command
                .arg("--boot-secrets-fd")
                .arg(super::BOOT_SECRETS_FD.to_string());
        }
        let child = command.spawn().map_err(|_| LocalBrokerSpawnError::Spawn);
        // The authority keeps no open end once the child has its own.
        drop(boot_secrets);
        child
    }
}

impl LocalRepositoryProcessSpawner for CwLocalCredentialProcessSpawner {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        }
        let mut command = authority_child(&self.executable, authority_fd, None);
        command
            .arg("__local-git-repository-executor")
            .arg("--transport")
            .arg(match config.transport {
                LocalRepositoryTransport::GitHubOAuth => "github-oauth",
                LocalRepositoryTransport::Ssh => "ssh",
            })
            .arg("--authority-fd")
            .arg(AUTHORITY_FD.to_string())
            .arg("--request-id")
            .arg(config.request_id.to_string())
            .arg("--staging-directory")
            .arg(&config.staging_directory)
            .env_clear()
            .current_dir(&config.staging_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // Either transport: the authority drains this inherited lifetime
            // pipe, discarding diagnostics, after stopping the whole group.
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(git) = &config.git {
            // Git receives the repository credential. Admit the runtime's git
            // against its lock here, immediately before exec, and run it only
            // when the supervisor named exactly that admitted file.
            let (root, lock) = self
                .runtime
                .as_ref()
                .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
            let (program, exec_path) = admit_runtime_git(root, lock)
                .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
            if program != git.program || exec_path != git.exec_path {
                return Err(LocalRepositorySpawnError::InvalidConfiguration);
            }
            command
                .arg("--git")
                .arg(&program)
                .arg("--git-exec-path")
                .arg(&exec_path)
                .arg("--runtime-artifact-root")
                .arg(root)
                .arg("--runtime-artifact-lock")
                .arg(lock);
        }
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        if config.transport == LocalRepositoryTransport::Ssh {
            let runtime = config
                .ssh_runtime_directory
                .as_ref()
                .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
            command.arg("--ssh-runtime-directory").arg(runtime);
        }
        command
            .spawn()
            .map_err(|_| LocalRepositorySpawnError::Spawn)
    }
}

/// The one-shot provider revocation executor (#4717): it opens no store, its
/// one value arriving in its lease (#4984), and starts no descendant, so its
/// stderr is not kept.
impl LocalRevocationProcessSpawner for CwLocalCredentialProcessSpawner {
    fn spawn(
        &self,
        config: &LocalRevocationProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRevocationSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalRevocationSpawnError::InvalidConfiguration);
        }
        let mut command = authority_child(&self.executable, authority_fd, None);
        command
            .arg("__local-provider-revocation-executor")
            .arg("--authority-fd")
            .arg(AUTHORITY_FD.to_string())
            .arg("--request-id")
            .arg(config.request_id.to_string())
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command
            .spawn()
            .map_err(|_| LocalRevocationSpawnError::Spawn)
    }
}

#[cfg(test)]
mod tests {
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

    /// Bounds each wait on a child, so a hang fails the test.
    const CHILD_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

    use crate::process::descriptor_report::{
        REPORT as DESCRIPTOR_REPORT, TEST as DESCRIPTOR_REPORT_TEST, planted as planted_descriptor,
    };

    /// The descriptors the last descriptor report under `root` found.
    fn reported_descriptors(root: &Path) -> String {
        std::fs::read_to_string(root.join("descriptors")).unwrap()
    }

    #[test]
    fn the_authority_holds_only_the_descriptors_its_file_actions_hand_it() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let _planted = planted_descriptor();
        let script = format!(
            "{DESCRIPTOR_REPORT}=\"$1\"; export {DESCRIPTOR_REPORT}; exec \"$0\" --exact \"$2\""
        );
        let mut child = spawn_detached(
            Path::new("/bin/sh"),
            &[
                "-c".into(),
                script.into(),
                std::env::current_exe().unwrap().into_os_string(),
                root.join("descriptors").into_os_string(),
                DESCRIPTOR_REPORT_TEST.into(),
            ],
            &root,
        )
        .unwrap();
        let deadline = std::time::Instant::now() + CHILD_WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the child never exited"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success());
        assert_eq!(
            reported_descriptors(&root),
            "0 1 2",
            "stdio on /dev/null alone"
        );
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

    /// A fake child that records its session, environment, limits,
    /// descriptors, directory and arguments, then writes a descriptor
    /// report into `root`. The probe descriptor is planted
    /// in this process for the child not to inherit.
    fn recording_child(root: &Path) -> (PathBuf, std::os::fd::OwnedFd) {
        use std::os::unix::fs::PermissionsExt as _;

        let leaked = planted_descriptor();
        let test_binary = std::env::current_exe().unwrap();
        let test_binary = test_binary.to_str().unwrap();
        assert!(!test_binary.contains('\''), "quoted in the script below");
        let child = root.join("child");
        std::fs::write(
            &child,
            format!(
                concat!(
                    "#!/bin/sh\n",
                    "test -p /dev/fd/2 && pipe=stderr-pipe\n",
                    "{{ ps -o pgid= -p $$; echo $$; ",
                    "env | cut -d= -f1 | grep -v -x -e PWD -e SHLVL -e _ | wc -l; ",
                    "ulimit -c; umask; ",
                    "test -e /dev/fd/3 && echo channel; ",
                    "test -e /dev/fd/{leaked} && echo leaked; ",
                    "test -n \"${{pipe-}}\" && echo \"$pipe\"; ",
                    "pwd; echo \"$@\"; }} > \"$OUTPUT_DIRECTORY/observed\"\n",
                    "{report}=\"$OUTPUT_DIRECTORY/descriptors\"; export {report}\n",
                    "exec '{test_binary}' --exact {test}\n",
                ),
                leaked = leaked.as_raw_fd(),
                report = DESCRIPTOR_REPORT,
                test_binary = test_binary,
                test = DESCRIPTOR_REPORT_TEST,
            )
            .replace("$OUTPUT_DIRECTORY", root.to_str().unwrap()),
        )
        .unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        (child, leaked)
    }

    fn observed(root: &Path) -> Vec<String> {
        std::fs::read_to_string(root.join("observed"))
            .unwrap()
            .lines()
            .map(|line| line.trim().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn a_broker_keeps_only_its_authority_channel_in_a_new_empty_session() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (broker, _leaked) = recording_child(&root);
        let spawner = CwLocalCredentialProcessSpawner {
            executable: broker,
            authority_root: root.clone(),
            runtime: None,
            store: AuthorityProtectedStore {
                backend: codewire_protected_store::ProtectedStoreBackend::File,
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
            network_policy_allows_github: false,
            network_policy_allowed_hosts: Default::default(),
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = LocalBrokerProcessSpawner::spawn(
            &spawner,
            &config,
            &ProviderLookup::Available,
            peer,
            &Default::default(),
        )
        .unwrap();
        let status = tokio::time::timeout(CHILD_WAIT, child.wait()).await;
        assert!(status.unwrap().unwrap().success());
        let lines = observed(&root);
        assert_eq!(lines[0], lines[1], "setsid makes the broker a group leader");
        assert_eq!(lines[2], "0", "only the shell's own variables are set");
        assert_eq!(lines[3], "0", "core files are disabled");
        assert_eq!(lines[4], "0077");
        assert_eq!(lines[5], "channel", "the authority channel is descriptor 3");
        assert_eq!(
            lines[6], "stderr-pipe",
            "stderr is the pipe whose tail the authority keeps in its broker log"
        );
        assert_eq!(
            lines[7],
            root.to_str().unwrap(),
            "no other descriptor survives"
        );
        assert!(lines[8].starts_with(&format!(
            "__local-credential-broker --authority-fd 3 --environment-id {environment} "
        )));
        assert!(lines[8].ends_with(&format!(
            "--protected-store file --protected-store-directory {}/protected-v1 --http-provider openai-api-key --start-whatever-resolves",
            root.display()
        )));
        assert_eq!(
            reported_descriptors(&root),
            "0 1 2 3",
            "nothing but stdio and the channel"
        );

        // A platform relay names no provider and is marked as a relay. A
        // replacement is told each host it may leave unresolved, here none.
        let platform = LocalBrokerProcessConfig {
            http_providers: Default::default(),
            platform_delegated: true,
            network_policy_allows_github: false,
            ..config
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = LocalBrokerProcessSpawner::spawn(
            &spawner,
            &platform,
            &ProviderLookup::NoFewerThan(Default::default()),
            peer,
            &Default::default(),
        )
        .unwrap();
        let status = tokio::time::timeout(CHILD_WAIT, child.wait()).await;
        assert!(status.unwrap().unwrap().success());
        let lines = observed(&root);
        assert!(lines[8].ends_with(&format!(
            "--protected-store file --protected-store-directory {}/protected-v1 --platform-delegated",
            root.display()
        )));
    }

    #[tokio::test]
    async fn a_broker_of_an_intercepting_boot_holds_exactly_its_channel_and_secrets() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (broker, _leaked) = recording_child(&root);
        let spawner = CwLocalCredentialProcessSpawner {
            executable: broker,
            authority_root: root.clone(),
            runtime: None,
            store: AuthorityProtectedStore {
                backend: codewire_protected_store::ProtectedStoreBackend::File,
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
            network_policy_allows_github: false,
            network_policy_allowed_hosts: Default::default(),
        };
        let secrets = codewire_local_credentials::BrokerBootSecrets::new([(
            codewire_local_credentials::BootSecretPurpose::FrontDoorPairing,
            vec![7; codewire_local_credentials::BOOT_SECRET_BYTES],
        )])
        .unwrap();
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = LocalBrokerProcessSpawner::spawn(
            &spawner,
            &config,
            &ProviderLookup::Available,
            peer,
            &secrets,
        )
        .unwrap();
        let status = tokio::time::timeout(CHILD_WAIT, child.wait()).await;
        assert!(status.unwrap().unwrap().success());
        assert!(observed(&root)[8].ends_with(" --boot-secrets-fd 4"));
        assert_eq!(
            reported_descriptors(&root),
            "0 1 2 3 4",
            "stdio, the channel and the boot's secrets, nothing else"
        );
    }

    #[tokio::test]
    async fn a_revocation_executor_holds_exactly_its_channel() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (executor, _leaked) = recording_child(&root);
        let spawner = CwLocalCredentialProcessSpawner {
            executable: executor,
            authority_root: root.clone(),
            runtime: None,
            store: AuthorityProtectedStore {
                backend: codewire_protected_store::ProtectedStoreBackend::File,
                keychain: None,
            },
        };
        let request = uuid::Uuid::new_v4();
        let config = LocalRevocationProcessConfig {
            request_id: request,
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = LocalRevocationProcessSpawner::spawn(&spawner, &config, peer).unwrap();
        let status = tokio::time::timeout(CHILD_WAIT, child.wait()).await;
        assert!(status.unwrap().unwrap().success());
        let lines = observed(&root);
        assert_eq!(
            lines[0], lines[1],
            "setsid makes the executor a group leader"
        );
        assert_eq!(lines[5], "channel", "the authority channel is descriptor 3");
        // Its stderr is null, so no pipe line comes before the directory.
        assert_eq!(lines[6], "/", "it starts in the root");
        assert_eq!(
            lines[7],
            format!("__local-provider-revocation-executor --authority-fd 3 --request-id {request}")
        );
        assert_eq!(
            reported_descriptors(&root),
            "0 1 2 3",
            "nothing but stdio and the channel"
        );
    }

    #[tokio::test]
    async fn a_repository_executor_leads_its_group_with_a_stderr_pipe_and_its_channel() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let (executor, _leaked) = recording_child(&root);
        let spawner = CwLocalCredentialProcessSpawner {
            executable: executor,
            authority_root: root.clone(),
            runtime: None,
            store: AuthorityProtectedStore {
                backend: codewire_protected_store::ProtectedStoreBackend::Keychain,
                keychain: Some("/private/tmp/synthetic.keychain-db".into()),
            },
        };
        let request = uuid::Uuid::new_v4();
        let staging = root.join(format!("repository-executor-{request}"));
        std::fs::create_dir(&staging).unwrap();
        let runtime = root.join(format!("ssh-{}", uuid::Uuid::new_v4()));
        for (transport, runtime_directory, expected) in [
            (
                LocalRepositoryTransport::GitHubOAuth,
                None,
                "--transport github-oauth".to_owned(),
            ),
            (
                LocalRepositoryTransport::Ssh,
                Some(runtime.clone()),
                "--transport ssh".to_owned(),
            ),
        ] {
            let config = LocalRepositoryProcessConfig {
                request_id: request,
                staging_directory: staging.clone(),
                transport,
                platform_delegated: false,
                ssh_runtime_directory: runtime_directory,
                git: None,
            };
            let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut child = LocalRepositoryProcessSpawner::spawn(&spawner, &config, peer).unwrap();
            let mut stderr = child.stderr.take().expect("stderr is piped");
            let status = tokio::time::timeout(CHILD_WAIT, child.wait()).await;
            assert!(status.unwrap().unwrap().success());
            let mut drained = Vec::new();
            let drain = tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut drained);
            tokio::time::timeout(CHILD_WAIT, drain)
                .await
                .unwrap()
                .unwrap();
            let lines = observed(&root);
            assert_eq!(
                lines[0], lines[1],
                "setsid makes the executor a group leader"
            );
            assert_eq!(lines[2], "0", "only the shell's own variables are set");
            assert_eq!(lines[3], "0", "core files are disabled");
            assert_eq!(lines[4], "0077");
            assert_eq!(lines[5], "channel", "the authority channel is descriptor 3");
            assert_eq!(lines[6], "stderr-pipe", "the authority drains stderr");
            assert_eq!(
                lines[7],
                staging.to_str().unwrap(),
                "no other descriptor survives"
            );
            assert!(lines[8].starts_with(&format!(
                "__local-git-repository-executor {expected} --authority-fd 3 --request-id {request} --staging-directory {}",
                staging.display()
            )));
            assert_eq!(
                reported_descriptors(&root),
                "0 1 2 3",
                "nothing but stdio and the channel"
            );
            assert_eq!(
                lines[8].ends_with(&format!("--ssh-runtime-directory {}", runtime.display())),
                transport == LocalRepositoryTransport::Ssh
            );
        }
        let ssh_without_runtime = LocalRepositoryProcessConfig {
            request_id: request,
            staging_directory: staging.clone(),
            transport: LocalRepositoryTransport::Ssh,
            platform_delegated: false,
            ssh_runtime_directory: None,
            git: None,
        };
        let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(matches!(
            LocalRepositoryProcessSpawner::spawn(&spawner, &ssh_without_runtime, peer),
            Err(LocalRepositorySpawnError::InvalidConfiguration)
        ));

        // A requested git runs only after the authority admits it from the
        // installed runtime; without an admissible runtime nothing is spawned.
        let named_git = LocalRepositoryProcessConfig {
            request_id: request,
            staging_directory: staging,
            transport: LocalRepositoryTransport::GitHubOAuth,
            platform_delegated: false,
            ssh_runtime_directory: None,
            git: Some(codewire_local_credentials::LocalRepositoryGit {
                program: root.join("runtime/git"),
                exec_path: root.join("runtime"),
            }),
        };
        let missing_runtime = CwLocalCredentialProcessSpawner {
            runtime: Some((root.join("runtime"), root.join("artifacts.lock.json"))),
            executable: spawner.executable.clone(),
            authority_root: root.clone(),
            store: spawner.store.clone(),
        };
        for spawner in [&spawner, &missing_runtime] {
            let (_authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            assert!(matches!(
                LocalRepositoryProcessSpawner::spawn(spawner, &named_git, peer),
                Err(LocalRepositorySpawnError::InvalidConfiguration)
            ));
        }
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
