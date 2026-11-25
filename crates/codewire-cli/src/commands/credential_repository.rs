#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd};

use anyhow::Context as _;
#[cfg(target_os = "linux")]
use codewire_local_credentials::AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
use codewire_local_credentials::{
    LocalRepositoryGit, LocalRepositoryGitProcessSpawner, LocalRepositoryProcessConfig,
    LocalRepositoryTransport, run_git_credential_helper_for_endpoint,
    run_local_repository_executor, run_local_ssh_repository_executor,
    run_platform_repository_executor,
};
use uuid::Uuid;

#[cfg(target_os = "macos")]
use super::credential_darwin::{
    admit_runtime_git, bind_to_parent_and_deny_attachment, isolated_session_and_environment,
    unprivileged_without_core_files,
};
use super::{LocalGitCredentialHelperArgs, LocalGitRepositoryExecutorArgs};

#[cfg(target_os = "linux")]
const GIT: &str = "/usr/bin/git";

/// A connected GitHub login is stored as the Codewire App's login bundle (or,
/// from older connections, a raw token). Git needs only its access token; a
/// bundle due for renewal is refreshed with the App's public client ID, as the
/// environment broker does.
struct CodewireGitHubLogin;

impl codewire_local_credentials::GitHubLoginRenewer for CodewireGitHubLogin {
    fn classify(
        &self,
        material: &[u8],
    ) -> Result<
        codewire_local_credentials::GitHubLoginState,
        codewire_local_credentials::RepositoryExecutorError,
    > {
        use codewire_credential_broker::GitHubAppAuthorizationError;
        use codewire_local_credentials::{GitHubLoginState, RepositoryExecutorError};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?
            .as_secs();
        match codewire_credential_broker::github_access_token(material, now) {
            Ok(token) => Ok(GitHubLoginState::Ready(token)),
            Err(GitHubAppAuthorizationError::Unavailable) => Ok(GitHubLoginState::Due),
            // An expired refresh token or malformed material needs a reconnect.
            Err(_) => Err(RepositoryExecutorError::InvalidCredential),
        }
    }

    fn renew<'a>(
        &'a self,
        material: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        codewire_protected_store::ProtectedValue,
                        codewire_local_credentials::RepositoryExecutorError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        use codewire_local_credentials::RepositoryExecutorError;
        Box::pin(async move {
            let bundle = codewire_credential_broker::GitHubAppUserOAuthBundle::parse(material)
                .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
            let owner = codewire_credential_broker::GitHubAppAuthorizationOwner::public_client(
                codewire_credential_broker::provider_oauth::github::codewire_github_app(),
                github_app_transport().await?,
            );
            let rotated =
                tokio::time::timeout(std::time::Duration::from_secs(30), owner.refresh(bundle))
                    .await
                    .map_err(|_| RepositoryExecutorError::InvalidCredential)?
                    .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
            codewire_protected_store::ProtectedValue::new(rotated.into_bytes().to_vec())
                .map_err(|_| RepositoryExecutorError::InvalidCredential)
        })
    }
}

#[cfg(not(feature = "local-broker-synthetic-smoke"))]
async fn github_app_transport() -> Result<
    std::sync::Arc<dyn codewire_credential_broker::BrokerUpstreamTransport>,
    codewire_local_credentials::RepositoryExecutorError,
> {
    Ok(std::sync::Arc::new(
        codewire_credential_broker::ProviderHttpsTransport::resolve(
            &std::collections::BTreeSet::from([
                codewire_access::HttpProvider::GitHubAppAuthorization,
            ]),
        )
        .await
        .map_err(|_| codewire_local_credentials::RepositoryExecutorError::InvalidCredential)?,
    ))
}

/// The non-shipping product smoke answers the App refresh in process.
#[cfg(feature = "local-broker-synthetic-smoke")]
async fn github_app_transport() -> Result<
    std::sync::Arc<dyn codewire_credential_broker::BrokerUpstreamTransport>,
    codewire_local_credentials::RepositoryExecutorError,
> {
    Ok(std::sync::Arc::new(
        codewire_credential_broker::SyntheticOpenAiSmokeTransport,
    ))
}

pub(crate) mod revocation;
mod ssh;
pub(crate) use ssh::run_git_ssh_helper;

pub(crate) async fn run_local_git_repository_executor(
    args: LocalGitRepositoryExecutorArgs,
) -> anyhow::Result<()> {
    verify_repository_executor_confinement()?;
    anyhow::ensure!(args.authority_fd == 3, "invalid repository lease channel");
    let request_id = Uuid::parse_str(&args.request_id)
        .ok()
        .filter(|request_id| !request_id.is_nil() && request_id.to_string() == args.request_id)
        .ok_or_else(|| anyhow::anyhow!("invalid repository request identity"))?;
    let config = LocalRepositoryProcessConfig {
        request_id,
        staging_directory: args.staging_directory,
        platform_delegated: args.platform_delegated,
        transport: match args.transport.as_str() {
            "github-oauth" => LocalRepositoryTransport::GitHubOAuth,
            "ssh" => LocalRepositoryTransport::Ssh,
            _ => anyhow::bail!("invalid repository transport"),
        },
        ssh_runtime_directory: args.ssh_runtime_directory,
        git: args
            .git
            .zip(args.git_exec_path)
            .map(|(program, exec_path)| LocalRepositoryGit { program, exec_path }),
    };
    // SAFETY: FD 3 is created by the authority immediately before exec and is
    // the only descriptor deliberately retained across that exec. Ownership is
    // transferred exactly once into this process.
    let authority_fd = unsafe { OwnedFd::from_raw_fd(args.authority_fd) };
    // Only the isolated executor owns this inherited capability. Git and its
    // helpers must neither use it nor keep the authority channel alive.
    rustix::io::fcntl_setfd(&authority_fd, rustix::io::FdFlags::CLOEXEC)
        .context("confine repository authority channel")?;
    let authority_stream = std::os::unix::net::UnixStream::from(authority_fd);
    authority_stream
        .set_nonblocking(true)
        .context("prepare repository lease channel")?;
    let authority_stream = tokio::net::UnixStream::from_std(authority_stream)
        .context("admit repository lease channel")?;
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("resolve repository credential helper")?;
    // A stock Mac's /usr/bin/git is only a stub: run the admitted runtime's
    // git, whose helpers come only from its own directory.
    #[cfg(target_os = "macos")]
    let (git, runtime) = config
        .git
        .clone()
        .zip(args.runtime_artifact_root.zip(args.runtime_artifact_lock))
        .context(
            "the local VM runtime's git is unavailable; reinstall it: cw setup --local --replace",
        )?;
    #[cfg(target_os = "linux")]
    let git = LocalRepositoryGit {
        program: GIT.into(),
        exec_path: std::path::PathBuf::new(),
    };
    let git_spawner = ConfinedGitSpawner {
        parent_pid: unsafe { libc::getpid() },
        #[cfg(target_os = "macos")]
        git: git.clone(),
        #[cfg(target_os = "macos")]
        runtime,
    };
    match config.transport {
        LocalRepositoryTransport::GitHubOAuth => {
            #[cfg(target_os = "linux")]
            let credential_runtime_directory = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .context("repository executor requires XDG_RUNTIME_DIR")?;
            // Darwin has no per-user runtime directory. The one-use credential
            // socket's private directory goes in the authority's short socket
            // directory (#2745), found from the authority root that holds this
            // executor's staging; the next authority removes one a killed
            // executor left behind.
            #[cfg(target_os = "macos")]
            let credential_runtime_directory = config
                .staging_directory
                .parent()
                .map(codewire_local_vmm::socket_dir::predicted)
                .context("invalid repository staging directory")?;
            if config.platform_delegated {
                return run_platform_repository_executor(
                    authority_stream,
                    config,
                    &credential_runtime_directory,
                    &git.program,
                    &executable,
                    &git_spawner,
                )
                .await
                .context("prepare platform repository");
            }
            run_local_repository_executor(
                authority_stream,
                config,
                &credential_runtime_directory,
                &git.program,
                &executable,
                &git_spawner,
                &CodewireGitHubLogin,
            )
            .await
        }
        LocalRepositoryTransport::Ssh => {
            run_local_ssh_repository_executor(
                authority_stream,
                config,
                &git.program,
                &executable,
                &git_spawner,
            )
            .await
        }
    }
    .context("prepare protected repository")
}

struct ConfinedGitSpawner {
    parent_pid: libc::pid_t,
    /// The runtime's git, which the authority admitted for this request.
    #[cfg(target_os = "macos")]
    git: LocalRepositoryGit,
    /// The installed runtime (artifact root, lock) that git belongs to.
    #[cfg(target_os = "macos")]
    runtime: (std::path::PathBuf, std::path::PathBuf),
}

#[cfg(target_os = "linux")]
impl LocalRepositoryGitProcessSpawner for ConfinedGitSpawner {
    fn spawn(&self, command: &mut tokio::process::Command) -> io::Result<tokio::process::Child> {
        let parent_pid = self.parent_pid;
        // SAFETY: this post-fork hook uses scalar prctl/getppid operations and
        // one fixed-layout rlimit pointer. It binds every Git subprocess to
        // the exact isolated executor and disables core dumps before exec.
        // Credential material is supplied later over the executor-owned
        // one-use socket and is never inherited by Git.
        unsafe {
            command.pre_exec(move || {
                let core_limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(core_limit)) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

/// Darwin has no parent-death signal: Git and its helpers stay in the
/// executor's process group, which the authority stops as a whole.
#[cfg(target_os = "macos")]
impl LocalRepositoryGitProcessSpawner for ConfinedGitSpawner {
    fn spawn(&self, command: &mut tokio::process::Command) -> io::Result<tokio::process::Child> {
        // Git receives the repository credential, so admit it against the
        // runtime lock again immediately before every spawn: a file swapped
        // since the authority admitted it is never run.
        let (root, lock) = &self.runtime;
        let admitted = admit_runtime_git(root, lock);
        if command.as_std().get_program() != self.git.program.as_os_str()
            || admitted != Some((self.git.program.clone(), self.git.exec_path.clone()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the local VM runtime's git is missing or changed",
            ));
        }
        prepare_confined_git(command, self.parent_pid, &self.git.exec_path);
        command.spawn()
    }
}

/// Git's preparation before every spawn, once the authority has admitted
/// it: the close-on-exec sweep, a hook binding it to `parent_pid` with core
/// files disabled, and its exec path.
#[cfg(target_os = "macos")]
fn prepare_confined_git(
    command: &mut tokio::process::Command,
    parent_pid: libc::pid_t,
    exec_path: &std::path::Path,
) {
    // codewire-local-credentials builds the command, so the sweep is
    // installed here, first: it keeps every inherited descriptor above
    // stderr out of Git (Darwin sets close-on-exec in a second call for
    // some descriptors), and Git inherits only its stdio.
    codewire_local_vmm::install_sweep(command, &[]);
    // SAFETY: this post-fork hook makes only getppid and setrlimit
    // calls. It binds every Git subprocess to the exact isolated executor
    // and disables core files before exec. Credential material is
    // supplied later over the executor-owned one-use socket.
    unsafe {
        command.pre_exec(move || {
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            let core_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(core_limit)) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
        .env("GIT_EXEC_PATH", exec_path)
        .env("GIT_TEMPLATE_DIR", "");
}

pub(crate) fn run_local_git_credential_helper(
    args: LocalGitCredentialHelperArgs,
) -> anyhow::Result<()> {
    verify_credential_helper_confinement()?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_git_credential_helper_for_endpoint(
        &args.operation,
        &args.credential_socket,
        args.brokered_endpoint.as_deref(),
        stdin.lock(),
        stdout.lock(),
    )
    .context("serve Git credential request")
}

#[cfg(target_os = "linux")]
pub(super) fn verify_repository_executor_confinement() -> anyhow::Result<()> {
    verify_common_confinement()?;
    let pid = rustix::process::getpid();
    anyhow::ensure!(
        rustix::process::getsid(None).ok() == Some(pid),
        "repository executor is not session isolated"
    );
    anyhow::ensure!(
        rustix::process::parent_process_death_signal().ok()
            == Some(Some(rustix::process::Signal::KILL)),
        "repository executor is not parent bound"
    );
    for (name, _) in std::env::vars_os() {
        anyhow::ensure!(
            AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
                .iter()
                .any(|allowed| name == OsStr::new(allowed)),
            "repository executor inherited ambient configuration"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_credential_helper_confinement() -> anyhow::Result<()> {
    verify_common_confinement()?;
    let parent = rustix::process::getppid()
        .filter(|parent| parent.as_raw_pid() > 1)
        .ok_or_else(|| anyhow::anyhow!("credential helper has no admissible Git parent"))?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|_| anyhow::anyhow!("credential helper is not parent bound"))?;
    anyhow::ensure!(
        rustix::process::getppid() == Some(parent),
        "credential helper parent changed before confinement"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_common_confinement() -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::thread::no_new_privs().unwrap_or(false),
        "credential-bearing process is not confined"
    );
    anyhow::ensure!(
        rustix::process::dumpable_behavior().ok()
            == Some(rustix::process::DumpableBehavior::NotDumpable),
        "credential-bearing process is dumpable"
    );
    let capabilities = rustix::thread::capabilities(None)
        .map_err(|_| anyhow::anyhow!("credential-bearing process is not confined"))?;
    anyhow::ensure!(
        capabilities.effective.is_empty()
            && capabilities.permitted.is_empty()
            && capabilities.inheritable.is_empty(),
        "credential-bearing process retained Linux capabilities"
    );
    Ok(())
}

/// The authority launched this executor in a new session with an empty
/// environment and no core files; it exits with that authority and refuses
/// debugger attachment.
#[cfg(target_os = "macos")]
pub(super) fn verify_repository_executor_confinement() -> anyhow::Result<()> {
    verify_common_confinement()?;
    anyhow::ensure!(
        isolated_session_and_environment(),
        "repository executor inherited ambient configuration or session"
    );
    bind_to_parent_and_deny_attachment()
        .map_err(|_| anyhow::anyhow!("repository executor is not parent bound"))
}

/// Git starts the helper with its own environment; the helper exits with
/// that exact Git parent and refuses debugger attachment.
#[cfg(target_os = "macos")]
fn verify_credential_helper_confinement() -> anyhow::Result<()> {
    verify_common_confinement()?;
    let parent = rustix::process::getppid()
        .filter(|parent| parent.as_raw_pid() > 1)
        .ok_or_else(|| anyhow::anyhow!("credential helper has no admissible Git parent"))?;
    bind_to_parent_and_deny_attachment()
        .map_err(|_| anyhow::anyhow!("credential helper is not parent bound"))?;
    anyhow::ensure!(
        rustix::process::getppid() == Some(parent),
        "credential helper parent changed before confinement"
    );
    Ok(())
}

/// macOS has no no-new-privileges bit, capabilities or dumpable flag: refuse
/// root, and require the zero core-file limit the executor's launcher set
/// and every descendant inherits.
#[cfg(target_os = "macos")]
fn verify_common_confinement() -> anyhow::Result<()> {
    anyhow::ensure!(
        unprivileged_without_core_files(),
        "credential-bearing process is not confined"
    );
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::os::fd::AsRawFd as _;
    use std::path::Path;
    use std::process::Stdio;

    use crate::process::descriptor_report::{planted, script};

    /// Git, and the credential helper it starts, inherit only stdio from
    /// the executor (#6242). The probe's own sweep keeps the planted
    /// descriptor, so only Git's preparation can close it.
    #[tokio::test]
    async fn git_and_its_credential_helper_hold_only_stdio() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let leaked = planted();
        let git = Path::new("/usr/bin/git");
        let exec_path = crate::process::command(git, &[])
            .arg("--exec-path")
            .output()
            .unwrap();
        assert!(exec_path.status.success());
        let exec_path = String::from_utf8(exec_path.stdout).unwrap();
        let reporter = root.join("reporter");
        let run = |program: &Path, arguments: &[&str], output: &Path| {
            script(&reporter, output);
            let mut command = crate::process::tokio_command(program, &[leaked.as_raw_fd()]);
            command
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &root)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .current_dir(&root)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: getpid has no preconditions.
            let parent = unsafe { libc::getpid() };
            super::prepare_confined_git(&mut command, parent, Path::new(exec_path.trim()));
            command
        };
        let finish = |mut child: tokio::process::Child| async move {
            let mut stdin = child.stdin.take().unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut stdin,
                b"protocol=https\nhost=example.invalid\n\n",
            )
            .await
            .unwrap();
            drop(stdin);
            // Git fails once the helper answers nothing; only the report counts.
            tokio::time::timeout(std::time::Duration::from_secs(60), child.wait())
                .await
                .unwrap()
                .unwrap();
        };

        let as_git = root.join("as-git");
        finish(run(&reporter, &[], &as_git).spawn().unwrap()).await;
        assert_eq!(
            std::fs::read_to_string(&as_git).unwrap(),
            "0 1 2",
            "Git holds stdio alone"
        );

        let helper = root.join("helper");
        let helper_config = format!("credential.helper=!{}", reporter.display());
        finish(
            run(git, &["-c", &helper_config, "credential", "fill"], &helper)
                .spawn()
                .unwrap(),
        )
        .await;
        assert_eq!(
            std::fs::read_to_string(&helper).unwrap(),
            "0 1 2",
            "Git's credential helper holds stdio alone"
        );
    }
}
