//! Isolated Git repository executor and authority-owned staging helpers.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
    PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use codewire_credential_bridge::MANAGED_GITHUB_GIT_PREFIX;
use codewire_protected_store::ProtectedStore;
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use super::ssh_executor::SshGitConfiguration;
use super::{
    LocalCredentialRepositoryLeaseClient, LocalRepositoryProcessConfig, PreparedRepositoryMetadata,
    REPOSITORY_LEASE_REQUEST_TIMEOUT, valid_git_selector, valid_object_id,
    validate_github_https_source,
};

pub const MAX_GITHUB_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_GIT_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
pub(super) const RESULT_FILE_NAME: &str = "result";
pub(super) const BUNDLE_FILE_NAME: &str = "source.bundle";

/// Executor-local Git launcher. The production implementation applies a
/// parent-death signal in the post-fork child before every Git exec, so an
/// abrupt executor death cannot orphan a credential-bearing Git process.
/// Darwin has no parent-death signal: there the executor leads a process
/// group that its authority stops as a whole.
pub trait LocalRepositoryGitProcessSpawner: Send + Sync {
    fn spawn(&self, command: &mut Command) -> io::Result<tokio::process::Child>;
}

#[derive(Debug, Error)]
pub enum RepositoryExecutorError {
    #[error("repository executor configuration is invalid")]
    InvalidConfiguration,
    #[error("repository credential lease is unavailable")]
    LeaseUnavailable,
    #[error("repository credential material is invalid")]
    InvalidCredential,
    #[error("Git repository preparation failed")]
    GitFailed,
    #[error("Git repository preparation timed out")]
    GitTimeout,
    #[error("Git repository output exceeded its safety limit")]
    GitOutputTooLarge,
    #[error("Git executable is unavailable")]
    GitUnavailable,
    #[error("repository executor filesystem operation failed")]
    Filesystem,
}

/// A stored GitHub login as host Git sees it.
pub enum GitHubLoginState {
    /// Its access token, valid for this checkout.
    Ready(Zeroizing<String>),
    /// Due for renewal: refresh it before use.
    Due,
}

/// The GitHub login format, which the caller owns: whether a stored login is
/// ready or due, and the provider exchange of a due login for its rotated
/// material. A login that needs reconnecting is an error from `classify`.
pub trait GitHubLoginRenewer: Sync {
    fn classify(&self, material: &[u8]) -> Result<GitHubLoginState, RepositoryExecutorError>;

    fn renew<'a>(
        &'a self,
        material: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        codewire_protected_store::ProtectedValue,
                        RepositoryExecutorError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}

/// Leases, refresh attempts and waits for a broker's refresh, within the
/// authority's own bound for one channel.
const MAX_GITHUB_LOGIN_ATTEMPTS: u32 = 32;
const BROKER_REFRESH_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
pub async fn run_local_repository_executor<S>(
    authority_stream: UnixStream,
    protected_store: S,
    config: LocalRepositoryProcessConfig,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    credential_helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
    github_login: &dyn GitHubLoginRenewer,
) -> Result<(), RepositoryExecutorError>
where
    S: ProtectedStore + Clone + 'static,
{
    config
        .validate()
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if config.transport != super::LocalRepositoryTransport::GitHubOAuth || config.platform_delegated
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    validate_private_staging_directory(&config.staging_directory)?;
    validate_credential_runtime_directory(credential_runtime_directory)?;
    if !git_executable.is_absolute() || !credential_helper_executable.is_absolute() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let mut leases =
        LocalCredentialRepositoryLeaseClient::connect(authority_stream, config.request_id)
            .await
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    leases
        .report_ready()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let mut lease = leases
        .lease_github(protected_store.clone())
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    // A login due for renewal is refreshed through the authority's journal,
    // which a running environment's broker shares, then leased again: Git only
    // ever sends a token the authority has just admitted.
    let mut attempts = 0;
    let token = loop {
        if let GitHubLoginState::Ready(token) = github_login.classify(lease.material())? {
            break token;
        }
        attempts += 1;
        if attempts > MAX_GITHUB_LOGIN_ATTEMPTS {
            return Err(RepositoryExecutorError::LeaseUnavailable);
        }
        match leases
            .begin_github_refresh(&lease)
            .await
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?
        {
            super::RepositoryRefreshBegin::LeaseAgain { wait } => {
                if wait {
                    tokio::time::sleep(BROKER_REFRESH_WAIT).await;
                }
            }
            super::RepositoryRefreshBegin::Reserved(reservation) => {
                let started = leases
                    .start_github_refresh(reservation)
                    .await
                    .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
                match github_login.renew(lease.material()).await {
                    Ok(material) => leases
                        .commit_github_refresh(started, material, protected_store.clone())
                        .await
                        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?,
                    Err(error) => {
                        // Refused or ambiguous: the old refresh token may be
                        // spent, so the login is never retried with it.
                        let _ = leases.fail_github_refresh(started).await;
                        return Err(error);
                    }
                }
            }
        }
        lease = leases
            .lease_github(protected_store.clone())
            .await
            .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    };
    let token = token.as_bytes();
    if token.is_empty()
        || token.len() > MAX_GITHUB_TOKEN_BYTES
        || !token.iter().all(u8::is_ascii_graphic)
    {
        return Err(RepositoryExecutorError::InvalidCredential);
    }
    execute_git_repository(
        &config.staging_directory,
        credential_runtime_directory,
        git_executable,
        credential_helper_executable,
        git_spawner,
        &lease.source,
        &lease.branch,
        &lease.revision,
        token,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_git_repository(
    staging: &Path,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
    source: &str,
    requested_branch: &str,
    revision: &str,
    token: &[u8],
) -> Result<(), RepositoryExecutorError> {
    validate_github_https_source(source)
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let git = GitExecution {
        executable: git_executable,
        helper_executable,
        credential_runtime_directory,
        spawner: git_spawner,
        authentication: GitAuthentication::GitHub(token),
    };
    execute_checkout(&git, staging, source, requested_branch, revision).await
}

/// Run Git against one authority-owned loopback ingress. The original provider
/// source is used only to derive and validate the exact managed endpoint; the
/// capability remains in memory and reaches Git solely through the existing
/// one-use credential socket.
#[allow(clippy::too_many_arguments)]
pub async fn execute_brokered_git_repository(
    staging: &Path,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
    source: &str,
    requested_branch: &str,
    revision: &str,
    endpoint: &str,
    capability: &[u8],
) -> Result<(), RepositoryExecutorError> {
    validate_brokered_endpoint(source, endpoint)?;
    validate_credential(capability)?;
    let git = GitExecution {
        executable: git_executable,
        helper_executable,
        credential_runtime_directory,
        spawner: git_spawner,
        authentication: GitAuthentication::BrokeredGitHub {
            endpoint,
            capability,
        },
    };
    execute_checkout(&git, staging, endpoint, requested_branch, revision).await
}

pub(super) async fn execute_checkout(
    git: &GitExecution<'_>,
    staging: &Path,
    source: &str,
    requested_branch: &str,
    revision: &str,
) -> Result<(), RepositoryExecutorError> {
    if (!requested_branch.is_empty() && !valid_git_selector(requested_branch))
        || (!revision.is_empty() && !valid_git_selector(revision))
        || (!requested_branch.is_empty() && !revision.is_empty())
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let bare = staging.join("source.git");
    git_status(
        git,
        staging,
        [
            OsStr::new("init"),
            OsStr::new("--bare"),
            OsStr::new("--quiet"),
            bare.as_os_str(),
        ],
        false,
    )
    .await?;

    let branch = if !requested_branch.is_empty() {
        requested_branch.to_owned()
    } else if revision.is_empty() {
        resolve_default_branch(git, staging, source).await?
    } else {
        String::new()
    };
    let selector = if revision.is_empty() {
        format!("refs/heads/{branch}")
    } else {
        revision.to_owned()
    };
    let refspec = format!("{selector}:refs/codewire/source");
    git_status(
        git,
        &bare,
        [
            OsStr::new("fetch"),
            OsStr::new("--quiet"),
            OsStr::new("--no-tags"),
            OsStr::new("--force"),
            OsStr::new("--no-recurse-submodules"),
            OsStr::new("--"),
            OsStr::new(source),
            OsStr::new(&refspec),
        ],
        true,
    )
    .await?;
    let commit = git_text(
        git,
        &bare,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("refs/codewire/source^{commit}"),
        ],
        256,
        false,
    )
    .await?
    .trim()
    .to_owned();
    if !valid_object_id(&commit) {
        return Err(RepositoryExecutorError::GitFailed);
    }
    reject_submodules(git, &bare, &commit).await?;

    let bundle = staging.join(BUNDLE_FILE_NAME);
    git_status(
        git,
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("create"),
            bundle.as_os_str(),
            OsStr::new("refs/codewire/source"),
        ],
        false,
    )
    .await?;
    git_status(
        git,
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("verify"),
            bundle.as_os_str(),
        ],
        false,
    )
    .await?;
    let bundle_size = regular_file_size(&bundle)?;
    if bundle_size == 0 || bundle_size > MAX_GIT_BUNDLE_BYTES {
        return Err(RepositoryExecutorError::GitOutputTooLarge);
    }
    write_result(
        staging,
        &PreparedRepositoryMetadata {
            branch,
            commit,
            bundle_size,
        },
    )
}

async fn resolve_default_branch(
    git: &GitExecution<'_>,
    staging: &Path,
    source: &str,
) -> Result<String, RepositoryExecutorError> {
    let output = git_text(
        git,
        staging,
        [
            OsStr::new("ls-remote"),
            OsStr::new("--symref"),
            OsStr::new("--exit-code"),
            OsStr::new("--"),
            OsStr::new(source),
            OsStr::new("HEAD"),
        ],
        4096,
        true,
    )
    .await?;
    output
        .lines()
        .find_map(|line| {
            line.strip_prefix("ref: refs/heads/")?
                .strip_suffix("\tHEAD")
        })
        .filter(|branch| valid_git_selector(branch))
        .map(str::to_owned)
        .ok_or(RepositoryExecutorError::GitFailed)
}

async fn reject_submodules(
    git: &GitExecution<'_>,
    bare: &Path,
    commit: &str,
) -> Result<(), RepositoryExecutorError> {
    let output = git_output(
        git,
        bare,
        [
            OsStr::new("ls-tree"),
            OsStr::new("-r"),
            OsStr::new("-z"),
            OsStr::new("--full-tree"),
            OsStr::new(commit),
        ],
        MAX_GIT_CONTROL_OUTPUT,
        false,
    )
    .await?;
    for record in output.split(|byte| *byte == 0) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            if record.is_empty() {
                continue;
            }
            return Err(RepositoryExecutorError::GitFailed);
        };
        if record[..tab].starts_with(b"160000 commit ") {
            return Err(RepositoryExecutorError::GitFailed);
        }
    }
    Ok(())
}

pub(super) enum GitAuthentication<'a> {
    GitHub(&'a [u8]),
    BrokeredGitHub {
        endpoint: &'a str,
        capability: &'a [u8],
    },
    Ssh(&'a SshGitConfiguration),
}

pub(super) struct GitExecution<'a> {
    pub executable: &'a Path,
    pub helper_executable: &'a Path,
    pub credential_runtime_directory: &'a Path,
    pub spawner: &'a dyn LocalRepositoryGitProcessSpawner,
    pub authentication: GitAuthentication<'a>,
}

impl GitExecution<'_> {
    fn command(
        &self,
        working_directory: &Path,
        network: bool,
    ) -> Result<GitCommand, RepositoryExecutorError> {
        let credential = match (&self.authentication, network) {
            (GitAuthentication::GitHub(token), true) => Some(CredentialHelper {
                secret: token,
                brokered_endpoint: None,
            }),
            (
                GitAuthentication::BrokeredGitHub {
                    endpoint,
                    capability,
                },
                true,
            ) => Some(CredentialHelper {
                secret: capability,
                brokered_endpoint: Some(*endpoint),
            }),
            _ => None,
        };
        let mut command = git_command(
            self.executable,
            self.helper_executable,
            working_directory,
            self.credential_runtime_directory,
            credential,
        )?;
        command.command.args(["-c", "protocol.allow=never"]);
        if network {
            match self.authentication {
                GitAuthentication::GitHub(_) => {
                    command.command.args(["-c", "protocol.https.allow=always"]);
                }
                GitAuthentication::BrokeredGitHub { .. } => {
                    command.command.args([
                        "-c",
                        "protocol.http.allow=always",
                        "-c",
                        "credential.useHttpPath=true",
                        "-c",
                        "http.proxy=",
                        "-c",
                        "http.extraHeader=",
                    ]);
                }
                GitAuthentication::Ssh(configuration) => {
                    command.command.args(["-c", "protocol.ssh.allow=always"]);
                    configuration.apply(&mut command.command);
                }
            }
        }
        // The authority owns SSH preparation's inherited stderr pipe as its
        // descendant-lifetime witness; it discards bytes and waits for EOF.
        command.command.stderr(match self.authentication {
            GitAuthentication::Ssh(_) => Stdio::inherit(),
            GitAuthentication::GitHub(_) | GitAuthentication::BrokeredGitHub { .. } => {
                Stdio::null()
            }
        });
        Ok(command)
    }
}

async fn git_status<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    network: bool,
) -> Result<(), RepositoryExecutorError> {
    let mut command = git.command(working_directory, network)?;
    command.command.args(arguments).stdout(Stdio::null());
    let (mut child, mut credential_server) = command.spawn(git.spawner)?;
    let result = tokio::time::timeout(
        GIT_COMMAND_TIMEOUT,
        wait_for_git_child(&mut child, credential_server.as_mut()),
    )
    .await
    .unwrap_or(Err(RepositoryExecutorError::GitTimeout));
    if result.is_err() {
        child
            .kill()
            .await
            .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
        child
            .wait()
            .await
            .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
    }
    let status = result?;
    if !status.success() {
        return Err(RepositoryExecutorError::GitFailed);
    }
    Ok(())
}

async fn git_text<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
    network: bool,
) -> Result<String, RepositoryExecutorError> {
    let output = git_output(git, working_directory, arguments, maximum_output, network).await?;
    String::from_utf8(output).map_err(|_| RepositoryExecutorError::GitFailed)
}

async fn git_output<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
    network: bool,
) -> Result<Vec<u8>, RepositoryExecutorError> {
    use tokio::io::AsyncReadExt as _;

    let maximum_output_plus_one = maximum_output
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RepositoryExecutorError::GitOutputTooLarge)?;
    let mut command = git.command(working_directory, network)?;
    command.command.args(arguments).stdout(Stdio::piped());
    let (mut child, mut credential_server) = command.spawn(git.spawner)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(RepositoryExecutorError::GitUnavailable)?;
    let result = tokio::time::timeout(GIT_COMMAND_TIMEOUT, async {
        let read_output = async {
            let mut output = Vec::with_capacity(maximum_output.min(64 * 1024));
            stdout
                .take(maximum_output_plus_one)
                .read_to_end(&mut output)
                .await
                .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
            if output.len() > maximum_output {
                return Err(RepositoryExecutorError::GitOutputTooLarge);
            }
            Ok(output)
        };
        let (output, status) = tokio::try_join!(
            read_output,
            wait_for_git_child(&mut child, credential_server.as_mut())
        )?;
        if !status.success() {
            return Err(RepositoryExecutorError::GitFailed);
        }
        Ok(output)
    })
    .await
    .unwrap_or(Err(RepositoryExecutorError::GitTimeout));
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

struct GitCommand {
    command: Command,
    credential_server: Option<CredentialSocketServer>,
}

impl GitCommand {
    fn spawn(
        mut self,
        spawner: &dyn LocalRepositoryGitProcessSpawner,
    ) -> Result<(tokio::process::Child, Option<CredentialSocketServer>), RepositoryExecutorError>
    {
        let child = spawner
            .spawn(&mut self.command)
            .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
        Ok((child, self.credential_server.take()))
    }
}

struct CredentialSocketServer {
    listener: UnixListener,
    directory: PathBuf,
    path: PathBuf,
    token: Zeroizing<Vec<u8>>,
}

impl CredentialSocketServer {
    fn bind(runtime_directory: &Path, token: &[u8]) -> Result<Self, RepositoryExecutorError> {
        validate_credential_runtime_directory(runtime_directory)?;
        let directory = runtime_directory.join(format!("cwgr-{}", Uuid::new_v4()));
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| RepositoryExecutorError::Filesystem)?;
        let path = directory.join("c");
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(_) => {
                let _ = fs::remove_dir(&directory);
                return Err(RepositoryExecutorError::Filesystem);
            }
        };
        let server = Self {
            listener,
            directory,
            path,
            token: Zeroizing::new(token.to_vec()),
        };
        fs::set_permissions(&server.path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RepositoryExecutorError::Filesystem)?;
        validate_credential_socket_path(&server.path)?;
        Ok(server)
    }

    async fn serve(&mut self) -> Result<(), RepositoryExecutorError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        let peer = stream
            .peer_cred()
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        if peer.uid() != rustix::process::getuid().as_raw() {
            return Err(RepositoryExecutorError::InvalidCredential);
        }
        self.unlink()?;
        stream
            .write_all(&self.token)
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        stream
            .shutdown()
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        self.token.zeroize();
        Ok(())
    }

    fn unlink(&self) -> Result<(), RepositoryExecutorError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(RepositoryExecutorError::Filesystem),
        }
    }
}

impl Drop for CredentialSocketServer {
    fn drop(&mut self) {
        let _ = self.unlink();
        let _ = fs::remove_dir(&self.directory);
    }
}

async fn wait_for_git_child(
    child: &mut tokio::process::Child,
    credential_server: Option<&mut CredentialSocketServer>,
) -> Result<std::process::ExitStatus, RepositoryExecutorError> {
    let Some(credential_server) = credential_server else {
        return child
            .wait()
            .await
            .map_err(|_| RepositoryExecutorError::GitUnavailable);
    };
    tokio::select! {
        biased;
        result = credential_server.serve() => {
            result?;
            child
                .wait()
                .await
                .map_err(|_| RepositoryExecutorError::GitUnavailable)
        }
        status = child.wait() => {
            status.map_err(|_| RepositoryExecutorError::GitUnavailable)
        }
    }
}

fn git_command(
    git_executable: &Path,
    helper_executable: &Path,
    working_directory: &Path,
    credential_socket_directory: &Path,
    credential: Option<CredentialHelper<'_>>,
) -> Result<GitCommand, RepositoryExecutorError> {
    let follow_redirects = if credential.is_some_and(|helper| helper.brokered_endpoint.is_some()) {
        "http.followRedirects=false"
    } else {
        "http.followRedirects=initial"
    };
    let mut command = Command::new(git_executable);
    command
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "credential.useHttpPath=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.lfs.required=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            follow_redirects,
        ])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let credential_server = if let Some(credential) = credential {
        let server = CredentialSocketServer::bind(credential_socket_directory, credential.secret)?;
        let mut helper = format!(
            "!exec {} __local-git-credential-helper --credential-socket {}",
            quote_shell_word(helper_executable)?,
            quote_shell_word(&server.path)?,
        );
        if let Some(endpoint) = credential.brokered_endpoint {
            helper.push_str(" --brokered-endpoint ");
            helper.push_str(&quote_shell_word(Path::new(endpoint))?);
        }
        command.args(["-c", &format!("credential.helper={helper}")]);
        Some(server)
    } else {
        None
    };
    Ok(GitCommand {
        command,
        credential_server,
    })
}

#[derive(Clone, Copy)]
struct CredentialHelper<'a> {
    secret: &'a [u8],
    brokered_endpoint: Option<&'a str>,
}

fn validate_credential(value: &[u8]) -> Result<(), RepositoryExecutorError> {
    if value.is_empty()
        || value.len() > MAX_GITHUB_TOKEN_BYTES
        || !value.iter().all(u8::is_ascii_graphic)
    {
        return Err(RepositoryExecutorError::InvalidCredential);
    }
    Ok(())
}

fn validate_brokered_endpoint(source: &str, endpoint: &str) -> Result<(), RepositoryExecutorError> {
    validate_github_https_source(source)
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let source =
        url::Url::parse(source).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let endpoint_url =
        url::Url::parse(endpoint).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let port = endpoint_url
        .port()
        .filter(|port| *port > 0)
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    let expected_path = format!(
        "{MANAGED_GITHUB_GIT_PREFIX}{}",
        source.path().trim_start_matches('/')
    );
    let expected = format!("http://127.0.0.1:{port}{expected_path}");
    if endpoint != expected
        || endpoint_url.scheme() != "http"
        || endpoint_url.host_str() != Some("127.0.0.1")
        || endpoint_url.username() != ""
        || endpoint_url.password().is_some()
        || endpoint_url.query().is_some()
        || endpoint_url.fragment().is_some()
        || endpoint_url.path() != expected_path
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

fn brokered_credential_target(endpoint: &str) -> Result<(String, String), RepositoryExecutorError> {
    let endpoint_url =
        url::Url::parse(endpoint).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let provider_path = endpoint_url
        .path()
        .strip_prefix(MANAGED_GITHUB_GIT_PREFIX)
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    let source = format!("https://github.com/{provider_path}");
    validate_brokered_endpoint(&source, endpoint)?;
    let port = endpoint_url
        .port()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    Ok((
        format!("127.0.0.1:{port}"),
        endpoint_url.path().trim_start_matches('/').to_owned(),
    ))
}

fn quote_shell_word(path: &Path) -> Result<String, RepositoryExecutorError> {
    let value = path
        .to_str()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

pub(super) fn validate_private_staging_directory(
    path: &Path,
) -> Result<(), RepositoryExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

pub(super) fn validate_credential_runtime_directory(
    path: &Path,
) -> Result<(), RepositoryExecutorError> {
    validate_private_staging_directory(path)?;
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| RepositoryExecutorError::Filesystem)? != path
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

fn regular_file_size(path: &Path) -> Result<u64, RepositoryExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RepositoryExecutorError::Filesystem);
    }
    Ok(metadata.len())
}

fn write_result(
    staging: &Path,
    metadata: &PreparedRepositoryMetadata,
) -> Result<(), RepositoryExecutorError> {
    if !valid_object_id(&metadata.commit)
        || (!metadata.branch.is_empty() && !valid_git_selector(&metadata.branch))
        || metadata.bundle_size == 0
        || metadata.bundle_size > MAX_GIT_BUNDLE_BYTES
    {
        return Err(RepositoryExecutorError::GitFailed);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging.join(RESULT_FILE_NAME))
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    writeln!(
        file,
        "{}\n{}\n{}",
        metadata.branch, metadata.commit, metadata.bundle_size
    )
    .map_err(|_| RepositoryExecutorError::Filesystem)?;
    file.sync_all()
        .map_err(|_| RepositoryExecutorError::Filesystem)
}

pub(crate) fn read_prepared_repository(
    staging: &Path,
) -> Result<PreparedRepositoryMetadata, RepositoryExecutorError> {
    validate_private_staging_directory(staging)?;
    let result_path = staging.join(RESULT_FILE_NAME);
    if regular_file_size(&result_path)? > 4096 {
        return Err(RepositoryExecutorError::Filesystem);
    }
    let text = fs::read_to_string(result_path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    let mut lines = text.lines();
    let branch = lines.next().ok_or(RepositoryExecutorError::Filesystem)?;
    let commit = lines.next().ok_or(RepositoryExecutorError::Filesystem)?;
    let bundle_size = lines
        .next()
        .ok_or(RepositoryExecutorError::Filesystem)?
        .parse::<u64>()
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    if lines.next().is_some()
        || (!branch.is_empty() && !valid_git_selector(branch))
        || !valid_object_id(commit)
        || bundle_size == 0
        || bundle_size > MAX_GIT_BUNDLE_BYTES
        || regular_file_size(&staging.join(BUNDLE_FILE_NAME))? != bundle_size
    {
        return Err(RepositoryExecutorError::Filesystem);
    }
    Ok(PreparedRepositoryMetadata {
        branch: branch.to_owned(),
        commit: commit.to_owned(),
        bundle_size,
    })
}

pub(crate) fn prepared_bundle_path(staging: &Path) -> PathBuf {
    staging.join(BUNDLE_FILE_NAME)
}

pub(crate) fn create_repository_staging(
    authority_root: &Path,
) -> Result<PathBuf, RepositoryExecutorError> {
    let staging = authority_root.join(format!("repository-executor-{}", Uuid::new_v4()));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    validate_private_staging_directory(&staging)?;
    Ok(staging)
}

pub(crate) fn remove_repository_staging(path: &Path) -> Result<(), RepositoryExecutorError> {
    validate_private_staging_directory(path)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix("repository-executor-"))
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    let id = Uuid::parse_str(name).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if id.to_string() != name {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    fs::remove_dir_all(path).map_err(|_| RepositoryExecutorError::Filesystem)
}

pub(crate) fn cleanup_repository_staging(
    authority_root: &Path,
) -> Result<(), RepositoryExecutorError> {
    for entry in fs::read_dir(authority_root).map_err(|_| RepositoryExecutorError::Filesystem)? {
        let entry = entry.map_err(|_| RepositoryExecutorError::Filesystem)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_prefix("repository-executor-") else {
            continue;
        };
        if Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id) {
            remove_repository_staging(&entry.path())?;
        }
    }
    Ok(())
}

/// macOS executors put their one-use credential socket directory in the
/// authority root (Darwin has no per-user runtime directory). A killed
/// executor can leave that directory behind with at most its socket, never
/// material; the next authority removes it before serving.
#[cfg(target_os = "macos")]
pub(crate) fn cleanup_repository_credential_sockets(
    authority_root: &Path,
) -> Result<(), RepositoryExecutorError> {
    for entry in fs::read_dir(authority_root).map_err(|_| RepositoryExecutorError::Filesystem)? {
        let entry = entry.map_err(|_| RepositoryExecutorError::Filesystem)?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_prefix("cwgr-")) else {
            continue;
        };
        if Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id) {
            let path = entry.path();
            validate_private_staging_directory(&path)?;
            fs::remove_dir_all(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
        }
    }
    Ok(())
}

fn validate_credential_socket_path(path: &Path) -> Result<(), RepositoryExecutorError> {
    if !path.is_absolute() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let parent = path
        .parent()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    validate_private_staging_directory(parent)?;
    if fs::canonicalize(parent).map_err(|_| RepositoryExecutorError::Filesystem)? != parent {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let parent_id = parent
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix("cwgr-"))
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|id| parent.ends_with(format!("cwgr-{id}")))
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    if parent_id.is_nil() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    if path.file_name() != Some(OsStr::new("c")) {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

/// Read the token the executor writes once to a connected one-use socket.
fn read_one_use_token(
    stream: std::os::unix::net::UnixStream,
) -> Result<Zeroizing<Vec<u8>>, RepositoryExecutorError> {
    match stream.set_read_timeout(Some(REPOSITORY_LEASE_REQUEST_TIMEOUT)) {
        Ok(()) => {}
        // Darwin refuses socket options (EINVAL) once the executor has
        // written the token and closed its end. The token is then already
        // buffered and the read below returns it without blocking.
        #[cfg(target_os = "macos")]
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::INVAL.raw_os_error()) => {}
        Err(_) => return Err(RepositoryExecutorError::InvalidCredential),
    }
    let mut token = Zeroizing::new(Vec::with_capacity(MAX_GITHUB_TOKEN_BYTES));
    stream
        .take(u64::try_from(MAX_GITHUB_TOKEN_BYTES + 1).expect("token bound fits u64"))
        .read_to_end(&mut token)
        .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
    validate_credential(&token)?;
    Ok(token)
}

/// Implement Git's credential-helper protocol without consulting ambient
/// configuration. `get` consumes one private one-use socket; `store` and
/// `erase` only drain and zeroize the bounded request Git supplies.
pub fn run_git_credential_helper(
    operation: &str,
    credential_socket: &Path,
    input: impl io::Read,
    output: impl io::Write,
) -> Result<(), RepositoryExecutorError> {
    run_git_credential_helper_for_endpoint(operation, credential_socket, None, input, output)
}

/// Run the credential helper for either the original direct GitHub HTTPS
/// route or one exact authority-owned loopback repository endpoint.
pub fn run_git_credential_helper_for_endpoint(
    operation: &str,
    credential_socket: &Path,
    brokered_endpoint: Option<&str>,
    input: impl io::Read,
    mut output: impl io::Write,
) -> Result<(), RepositoryExecutorError> {
    let mut request = Zeroizing::new(Vec::with_capacity(1024));
    input
        .take(16 * 1024 + 1)
        .read_to_end(&mut request)
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if request.len() > 16 * 1024 {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    if operation != "get" {
        return if matches!(operation, "store" | "erase") {
            Ok(())
        } else {
            Err(RepositoryExecutorError::InvalidConfiguration)
        };
    }
    let request =
        std::str::from_utf8(&request).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let mut protocol = None;
    let mut host = None;
    let mut path = None;
    let mut username = None;
    for line in request.lines() {
        if let Some(value) = line.strip_prefix("protocol=") {
            if protocol.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            protocol = Some(value);
        } else if let Some(value) = line.strip_prefix("host=") {
            if host.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            host = Some(value);
        } else if let Some(value) = line.strip_prefix("path=") {
            if path.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            path = Some(value);
        } else if let Some(value) = line.strip_prefix("username=") {
            if username.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            username = Some(value);
        } else if brokered_endpoint.is_some() && !line.is_empty() {
            return Err(RepositoryExecutorError::InvalidConfiguration);
        }
    }
    if let Some(endpoint) = brokered_endpoint {
        let (expected_host, expected_path) = brokered_credential_target(endpoint)?;
        if protocol != Some("http")
            || host != Some(expected_host.as_str())
            || path != Some(expected_path.as_str())
            || !matches!(username, None | Some("x-access-token"))
        {
            return Err(RepositoryExecutorError::InvalidConfiguration);
        }
    } else if protocol != Some("https") || host != Some("github.com") {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    validate_credential_socket_path(credential_socket)?;
    let stream = std::os::unix::net::UnixStream::connect(credential_socket)
        .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
    let token = read_one_use_token(stream)?;
    output
        .write_all(b"username=x-access-token\npassword=")
        .and_then(|()| output.write_all(&token))
        .and_then(|()| output.write_all(b"\n\n"))
        .and_then(|()| output.flush())
        .map_err(|_| RepositoryExecutorError::InvalidCredential)
}

#[cfg(test)]
mod tests;
