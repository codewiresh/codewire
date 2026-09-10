//! Initial SSH checkout through the existing preparation lease and agent codec.
//! Only public host trust and a bounded signing channel enter this executor.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use codewire_credential_bridge::{SshAgentRelay, serve_ssh_agent};
use codewire_gateway_proto::codewire::bridge::v1::{CredentialSshRequest, CredentialSshResponse};
use codewire_project::{
    RepositorySshHost, canonical_repository_known_hosts, parse_repository_ssh_host,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tonic::Status;

use super::executor::{
    GitAuthentication, GitExecution, execute_checkout, validate_credential_runtime_directory,
    validate_private_staging_directory,
};
use super::{
    LocalCredentialRepositoryLeaseClient, LocalRepositoryGitProcessSpawner,
    LocalRepositoryProcessConfig, LocalRepositoryTransport, RepositoryExecutorError,
};

pub const SSH_HELPER_BASENAME: &str = "cw-git-ssh";
pub const SSH_HELPER_RUNTIME_ENV: &str = "CODEWIRE_REPOSITORY_SSH_RUNTIME";
pub const SSH_HELPER_HOST_ENV: &str = "CODEWIRE_REPOSITORY_SSH_HOST";
pub const SSH_HELPER_PORT_ENV: &str = "CODEWIRE_REPOSITORY_SSH_PORT";
pub const SSH_HELPER_OWNER_ENV: &str = "CODEWIRE_REPOSITORY_SSH_OWNER";

pub(super) struct SshGitConfiguration {
    directory: PathBuf,
    host: RepositorySshHost,
}

impl SshGitConfiguration {
    fn create(
        runtime: &Path,
        executable: &Path,
        host: RepositorySshHost,
        pins: &[String],
    ) -> Result<Self, RepositoryExecutorError> {
        validate_credential_runtime_directory(runtime)?;
        if !runtime
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
            || !executable.is_absolute()
            || fs::canonicalize(executable).ok().as_deref() != Some(executable)
        {
            return Err(RepositoryExecutorError::InvalidConfiguration);
        }
        let configuration = Self {
            directory: runtime.to_owned(),
            host,
        };
        let mut trust = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(configuration.directory.join("known_hosts"))
            .map_err(|_| RepositoryExecutorError::Filesystem)?;
        for pin in pins {
            writeln!(trust, "{pin}").map_err(|_| RepositoryExecutorError::Filesystem)?;
        }
        // Git execs this exact binary without a shell. Its early entrypoint
        // establishes Git-parent lifetime before execing fixed stock SSH.
        symlink(
            executable,
            configuration.directory.join(SSH_HELPER_BASENAME),
        )
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
        Ok(configuration)
    }

    pub(super) fn apply(&self, command: &mut tokio::process::Command) {
        command
            .env("GIT_SSH", self.directory.join(SSH_HELPER_BASENAME))
            .env("GIT_SSH_VARIANT", "ssh")
            .env(SSH_HELPER_RUNTIME_ENV, &self.directory)
            .env(SSH_HELPER_HOST_ENV, self.host.host())
            .env(SSH_HELPER_PORT_ENV, self.host.port().to_string())
            .env(
                SSH_HELPER_OWNER_ENV,
                rustix::process::getpid().as_raw_pid().to_string(),
            );
    }
}

struct RepositorySshRelay(Mutex<LocalCredentialRepositoryLeaseClient>);

#[tonic::async_trait]
impl SshAgentRelay for RepositorySshRelay {
    async fn relay_ssh(
        &self,
        request: CredentialSshRequest,
    ) -> Result<CredentialSshResponse, Status> {
        self.0
            .lock()
            .await
            .ssh_operation(request)
            .await
            .map_err(|_| Status::unavailable("repository SSH authority unavailable"))
    }
}

/// Prepare a pinned SSH repository without constructing a protected-store client.
/// The authority retains admitted signing work when an agent waiter disappears;
/// the existing preparation finalizer waits for its channel drain before release.
pub async fn run_local_ssh_repository_executor(
    authority_stream: UnixStream,
    config: LocalRepositoryProcessConfig,
    git_executable: &Path,
    helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
) -> Result<(), RepositoryExecutorError> {
    config
        .validate()
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if config.transport != LocalRepositoryTransport::Ssh || !git_executable.is_absolute() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    validate_private_staging_directory(&config.staging_directory)?;
    let runtime_directory = config
        .ssh_runtime_directory
        .as_deref()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    validate_credential_runtime_directory(runtime_directory)?;
    let mut leases =
        LocalCredentialRepositoryLeaseClient::connect(authority_stream, config.request_id)
            .await
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    leases
        .report_ready()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let intent = leases
        .ssh_checkout()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let host = parse_repository_ssh_host(&intent.source)
        .ok()
        .flatten()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    if intent.preparation_request_id != config.request_id
        || canonical_repository_known_hosts(&intent.source, intent.known_hosts.clone())
            .ok()
            .as_ref()
            != Some(&intent.known_hosts)
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let configuration = SshGitConfiguration::create(
        runtime_directory,
        helper_executable,
        host,
        &intent.known_hosts,
    )?;
    let socket = configuration.directory.join("agent");
    let listener = UnixListener::bind(&socket).map_err(|_| RepositoryExecutorError::Filesystem)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    let relay = RepositorySshRelay(Mutex::new(leases));
    let git = GitExecution {
        executable: git_executable,
        helper_executable,
        credential_runtime_directory: runtime_directory,
        spawner: git_spawner,
        authentication: GitAuthentication::Ssh(&configuration),
    };
    let result = {
        let checkout = execute_checkout(
            &git,
            &config.staging_directory,
            &intent.source,
            &intent.branch,
            &intent.revision,
        );
        tokio::pin!(checkout);
        loop {
            tokio::select! {
                biased;
                result = &mut checkout => break result,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break Err(RepositoryExecutorError::Filesystem); };
                    if stream.peer_cred().ok().is_none_or(|peer| peer.uid() != rustix::process::getuid().as_raw()) {
                        continue;
                    }
                    // One stock SSH process per sequential Git command. The
                    // shared codec owns framing/deadlines, not another worker
                    // queue. Stream loss cancels delivery, never claims drain.
                    tokio::select! {
                        biased;
                        result = &mut checkout => break result,
                        _ = serve_ssh_agent(&relay, stream, std::future::pending()) => {},
                    }
                }
            }
        }
    };
    drop(listener);
    drop(relay);
    // The authority owns this exact directory through process-group and lease
    // drain. It cleans public files even when SIGKILL bypasses executor Drop.
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    #[test]
    fn public_runtime_is_private_shell_free_and_retained_for_its_authority_owner() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let host = parse_repository_ssh_host("ssh://git@example.test:2222/repo.git")
            .unwrap()
            .unwrap();
        let pins = vec!["[example.test]:2222 ssh-ed25519 AAAA".to_owned()];
        let configuration =
            SshGitConfiguration::create(temporary.path(), &executable, host, &pins).unwrap();
        let path = configuration.directory.clone();
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().uid(),
            rustix::process::getuid().as_raw()
        );
        assert_eq!(
            fs::read_to_string(path.join("known_hosts")).unwrap(),
            format!("{}\n", pins[0])
        );
        assert_eq!(
            fs::read_link(path.join(SSH_HELPER_BASENAME)).unwrap(),
            executable
        );
        let mut command = tokio::process::Command::new("/usr/bin/git");
        command.env_clear();
        configuration.apply(&mut command);
        let env = command
            .as_std()
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(std::ffi::OsStr::to_owned)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("GIT_SSH_VARIANT"))
                .unwrap()
                .as_deref(),
            Some(std::ffi::OsStr::new("ssh"))
        );
        assert!(!env.contains_key(std::ffi::OsStr::new("GIT_SSH_COMMAND")));
        assert!(!env.contains_key(std::ffi::OsStr::new("SSH_AUTH_SOCK")));
        assert!(!env.contains_key(std::ffi::OsStr::new("DBUS_SESSION_BUS_ADDRESS")));
        drop(configuration);
        assert!(path.join("known_hosts").exists());
        assert!(temporary.path().exists());
    }

    #[test]
    fn runtime_rejects_ambient_permissions_before_creating_files() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let host = parse_repository_ssh_host("git@example.test:repo.git")
            .unwrap()
            .unwrap();
        assert!(
            SshGitConfiguration::create(temporary.path(), Path::new("/usr/bin/cw"), host, &[])
                .is_err()
        );
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
    }
}
