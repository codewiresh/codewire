use std::env;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use crate::config::{Env, OsEnv, ResolvePaths};
use anyhow::Context as _;
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, AuthorityRuntimeConfig, AuthorityRuntimeError,
    LocalBrokerProcessConfig, LocalBrokerProcessSpawner, LocalBrokerSpawnError,
    LocalCredentialClient, LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner,
    LocalRepositorySpawnError, serve_os_local_credential_authority_with_process_spawners,
};

use super::{LocalCredentialAuthorityArgs, LocalCredentialAuthorityProbeArgs};

mod platform;
mod ssh;

const LOCAL_CREDENTIAL_ROOT_ENV: &str = "CODEWIRE_LOCAL_CREDENTIAL_ROOT";
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub(crate) async fn run_local_credential_authority(
    args: LocalCredentialAuthorityArgs,
) -> anyhow::Result<()> {
    let config = authority_config(args.root)?;
    let spawner = Arc::new(CwLocalCredentialProcessSpawner {
        executable: config.executable.clone(),
        authority_root: config.root.clone(),
    });
    let signer = Arc::new(ssh::LocalSshAgentAdapter::new(config.root.clone()));
    let result = serve_os_local_credential_authority_with_process_spawners(
        config,
        spawner.clone(),
        spawner,
        signer.clone(),
        Arc::new(platform::NativePlatformCredentialConnector),
    )
    .await;
    // Always drain an initialized owner, including authority-server failure.
    // An ordinary non-SSH authority never initializes tools or staging.
    signer.shutdown().await.context("drain local SSH signer")?;
    result.context("run local credential authority")
}

pub(crate) async fn run_local_credential_authority_probe(
    args: LocalCredentialAuthorityProbeArgs,
) -> anyhow::Result<()> {
    let config = authority_config(args.root)?;
    let client = LocalCredentialClient::connect_or_start_with(&config, spawn_authority)
        .await
        .context("connect to local credential authority")?;
    if args.shutdown {
        client
            .shutdown()
            .await
            .context("stop local credential authority")?;
    }
    Ok(())
}

pub(crate) async fn connect_local_credential_authority() -> anyhow::Result<LocalCredentialClient> {
    let env = OsEnv;
    let root = local_credential_root(&env)?;
    let config = authority_config(root)?;
    LocalCredentialClient::connect_or_start_with(&config, spawn_authority)
        .await
        .context("connect to local credential authority")
}

pub(crate) async fn admit_existing_local_credential_authority() -> anyhow::Result<()> {
    let env = OsEnv;
    let root = local_credential_root(&env)?;
    let config = authority_config(root)?;
    drop(
        LocalCredentialClient::admit_existing_or_replace_with(&config, spawn_authority)
            .await
            .context("admit existing local credential authority")?,
    );
    Ok(())
}

pub(crate) fn local_credential_root(env: &impl Env) -> anyhow::Result<PathBuf> {
    if let Some(value) = env.var(LOCAL_CREDENTIAL_ROOT_ENV) {
        let root = PathBuf::from(value);
        if !root.is_absolute() {
            anyhow::bail!("{LOCAL_CREDENTIAL_ROOT_ENV} must be an absolute path");
        }
        return Ok(root);
    }
    Ok(ResolvePaths::from_env(env)?
        .mesh_data_dir
        .join("credentials-v1"))
}

fn authority_config(root: PathBuf) -> anyhow::Result<AuthorityRuntimeConfig> {
    Ok(AuthorityRuntimeConfig {
        root,
        executable: canonical_current_executable()?,
    })
}

fn canonical_current_executable() -> anyhow::Result<PathBuf> {
    let executable = env::current_exe().context("resolve current cw executable")?;
    std::fs::canonicalize(&executable).with_context(|| {
        format!(
            "canonicalize current cw executable {}",
            executable.display()
        )
    })
}

fn spawn_authority(config: &AuthorityRuntimeConfig) -> Result<Child, AuthorityRuntimeError> {
    let allowed_environment = authority_environment(|name| env::var_os(name));
    let mut command = Command::new(&config.executable);
    command
        .arg("__local-credential-authority")
        .arg("--root")
        .arg(&config.root)
        .env_clear()
        .envs(allowed_environment)
        .current_dir(&config.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: scalar-only libc operations and one fixed-layout capset syscall
    // prepare a capability-empty, no-new-privileges, FD-clean detached
    // singleton before exec. No credential value or platform login variable is
    // inherited; only the two session-bus discovery variables are allowlisted.
    unsafe {
        command.pre_exec(|| {
            confine_spawned_process()?;
            if libc::setsid() < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    command.spawn().map_err(|_| AuthorityRuntimeError::Spawn)
}

struct CwLocalCredentialProcessSpawner {
    executable: PathBuf,
    authority_root: PathBuf,
}

impl LocalBrokerProcessSpawner for CwLocalCredentialProcessSpawner {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let authority_fd = authority_peer.as_raw_fd();
        if authority_fd < 3 {
            return Err(LocalBrokerSpawnError::InvalidConfiguration);
        }
        let parent_pid = unsafe { libc::getpid() };
        let allowed_environment = authority_environment(|name| env::var_os(name));
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
            .env_clear()
            .envs(allowed_environment)
            .current_dir(&self.authority_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for provider in &config.http_providers {
            command.arg("--http-provider").arg(provider.as_str());
        }
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        // SAFETY: this post-fork hook uses scalar libc operations only. It
        // transfers one authority-created socket to fixed FD 3, marks every
        // other inherited descriptor close-on-exec, removes capabilities,
        // disables dumps, and binds child death to the exact authority parent.
        unsafe {
            command.pre_exec(move || {
                confine_spawned_process()?;
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::setsid() < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                if authority_fd == 3 {
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup3(authority_fd, 3, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(
                    libc::SYS_close_range,
                    4_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        command.spawn().map_err(|_| LocalBrokerSpawnError::Spawn)
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
        let parent_pid = unsafe { libc::getpid() };
        // SSH uses the inherited signing channel and explicit public runtime
        // path only. Do not give its executor the Secret Service bus context.
        let allowed_environment = match config.transport {
            codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth
                if config.platform_delegated =>
            {
                // Only the helper's private runtime directory. No Secret
                // Service bus, owner HOME, agent socket or provider context.
                authority_environment(|name| {
                    if name == "XDG_RUNTIME_DIR" {
                        env::var_os(name)
                    } else {
                        None
                    }
                })
            }
            codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth => {
                authority_environment(|name| env::var_os(name))
            }
            codewire_local_credentials::LocalRepositoryTransport::Ssh => Vec::new(),
        };
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .arg("__local-git-repository-executor")
            .arg("--transport")
            .arg(match config.transport {
                codewire_local_credentials::LocalRepositoryTransport::GitHubOAuth => "github-oauth",
                codewire_local_credentials::LocalRepositoryTransport::Ssh => "ssh",
            })
            .arg("--authority-fd")
            .arg("3")
            .arg("--request-id")
            .arg(config.request_id.to_string())
            .arg("--staging-directory")
            .arg(&config.staging_directory)
            .env_clear()
            .envs(allowed_environment)
            .current_dir(&config.staging_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if config.platform_delegated {
            command.arg("--platform-delegated");
        }
        if config.transport == codewire_local_credentials::LocalRepositoryTransport::Ssh {
            let runtime = config
                .ssh_runtime_directory
                .as_ref()
                .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
            command.arg("--ssh-runtime-directory").arg(runtime);
            // The existing preparation owner drains this inherited lifetime
            // pipe, discarding diagnostics, before acknowledging cleanup.
            command.stderr(Stdio::piped());
        }
        // SAFETY: this post-fork hook transfers one authority-created socket
        // to FD 3 and applies the same capability-empty, no-new-privileges,
        // non-dumpable, parent-bound confinement as the long-lived broker.
        unsafe {
            command.pre_exec(move || {
                confine_spawned_process()?;
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::setsid() < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                if authority_fd == 3 {
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup3(authority_fd, 3, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(
                    libc::SYS_close_range,
                    4_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        command
            .spawn()
            .map_err(|_| LocalRepositorySpawnError::Spawn)
    }
}

fn authority_environment(read: impl Fn(&str) -> Option<OsString>) -> Vec<(OsString, OsString)> {
    let runtime_dir = read("XDG_RUNTIME_DIR").filter(|value| valid_runtime_dir(value));
    let bus_address = runtime_dir.as_ref().and_then(|runtime_dir| {
        let expected = OsString::from(format!(
            "unix:path={}",
            PathBuf::from(runtime_dir).join("bus").display()
        ));
        read("DBUS_SESSION_BUS_ADDRESS").filter(|value| *value == expected)
    });
    let mut environment = Vec::with_capacity(AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES.len());
    if let Some(bus_address) = bus_address {
        environment.push((OsString::from("DBUS_SESSION_BUS_ADDRESS"), bus_address));
    }
    if let Some(runtime_dir) = runtime_dir {
        environment.push((OsString::from("XDG_RUNTIME_DIR"), runtime_dir));
    }
    environment
}

fn valid_runtime_dir(value: &OsStr) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

pub(super) fn confine_spawned_process() -> io::Result<()> {
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [empty; 2];
    // SAFETY: capset v3 reads one fixed header and exactly two fixed data
    // elements. pid=0 targets only this post-fork child thread.
    if unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of!(header), data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both prctl operations use scalar arguments and mutate only this
    // post-fork child. Failure is fatal rather than launching less confined.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::MapEnv;

    use super::*;

    #[test]
    fn authority_process_inherits_only_session_bus_discovery() {
        let [authority_dbus_env, authority_xdg_runtime_env] =
            AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
        let ambient = BTreeMap::from([
            (authority_dbus_env, "unix:path=/run/user/1000/bus"),
            (authority_xdg_runtime_env, "/run/user/1000"),
            ("CODEWIRE_API_KEY", "synthetic-platform-token"),
            ("OPENAI_API_KEY", "synthetic-provider-token"),
            ("SSH_AUTH_SOCK", "/tmp/synthetic-agent.sock"),
        ]);
        let inherited = authority_environment(|name| ambient.get(name).map(OsString::from));

        assert_eq!(
            inherited,
            vec![
                (
                    OsString::from(authority_dbus_env),
                    OsString::from("unix:path=/run/user/1000/bus"),
                ),
                (
                    OsString::from(authority_xdg_runtime_env),
                    OsString::from("/run/user/1000"),
                ),
            ]
        );
    }

    #[test]
    fn authority_rejects_remote_or_noncanonical_session_bus_discovery() {
        for (runtime, bus) in [
            ("relative", "unix:path=relative/bus"),
            ("/run/user/1000/../1001", "unix:path=/run/user/1001/bus"),
            ("/run/user/1000", "tcp:host=127.0.0.1,port=5555"),
            ("/run/user/1000", "unix:path=/tmp/other-bus"),
        ] {
            let ambient = BTreeMap::from([
                ("XDG_RUNTIME_DIR", runtime),
                ("DBUS_SESSION_BUS_ADDRESS", bus),
            ]);
            let inherited = authority_environment(|name| ambient.get(name).map(OsString::from));
            assert!(
                inherited
                    .iter()
                    .all(|(name, _)| name != "DBUS_SESSION_BUS_ADDRESS"),
                "{runtime} {bus}"
            );
        }
    }

    #[test]
    fn local_credential_state_is_separate_from_platform_login() {
        let env = MapEnv::new([
            ("HOME", "/home/tester"),
            ("CW_CONFIG_DIR", "/tmp/platform-login"),
        ]);
        assert_eq!(
            local_credential_root(&env).unwrap(),
            PathBuf::from("/home/tester/.codewire/credentials-v1")
        );

        let overridden = MapEnv::new([
            ("HOME", "/home/tester"),
            (LOCAL_CREDENTIAL_ROOT_ENV, "/tmp/private/credentials"),
        ]);
        assert_eq!(
            local_credential_root(&overridden).unwrap(),
            PathBuf::from("/tmp/private/credentials")
        );
        assert!(
            local_credential_root(&MapEnv::new([(LOCAL_CREDENTIAL_ROOT_ENV, "relative")])).is_err()
        );
    }
}
