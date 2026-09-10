use std::ffi::OsStr;
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::Path;

use anyhow::Context as _;
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, LocalRepositoryGitProcessSpawner,
    LocalRepositoryProcessConfig, LocalRepositoryTransport, run_git_credential_helper_for_endpoint,
    run_local_repository_executor, run_local_ssh_repository_executor,
    run_platform_repository_executor,
};
use codewire_protected_store::ConnectedOsProtectedStore;
use uuid::Uuid;

use super::{LocalGitCredentialHelperArgs, LocalGitRepositoryExecutorArgs};

const GIT: &str = "/usr/bin/git";

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
    let git_spawner = ConfinedGitSpawner {
        parent_pid: unsafe { libc::getpid() },
    };
    match config.transport {
        LocalRepositoryTransport::GitHubOAuth => {
            let credential_runtime_directory = std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .context("repository executor requires XDG_RUNTIME_DIR")?;
            if config.platform_delegated {
                return run_platform_repository_executor(
                    authority_stream,
                    config,
                    &credential_runtime_directory,
                    Path::new(GIT),
                    &executable,
                    &git_spawner,
                )
                .await
                .context("prepare platform repository");
            }
            let store = ConnectedOsProtectedStore::connect()
                .context("connect repository executor protected store")?;
            run_local_repository_executor(
                authority_stream,
                store,
                config,
                &credential_runtime_directory,
                Path::new(GIT),
                &executable,
                &git_spawner,
            )
            .await
        }
        LocalRepositoryTransport::Ssh => {
            run_local_ssh_repository_executor(
                authority_stream,
                config,
                Path::new(GIT),
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
}

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

fn verify_repository_executor_confinement() -> anyhow::Result<()> {
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
