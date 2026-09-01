use std::env;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::Context as _;
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, AuthorityRuntimeConfig, AuthorityRuntimeError,
    LocalCredentialClient, serve_os_local_credential_authority,
};

use super::{LocalCredentialAuthorityArgs, LocalCredentialAuthorityProbeArgs};

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
    serve_os_local_credential_authority(authority_config(args.root)?)
        .await
        .context("run local credential authority")
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

fn authority_environment(read: impl Fn(&str) -> Option<OsString>) -> Vec<(OsString, OsString)> {
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
        .into_iter()
        .filter_map(|name| {
            read(name)
                .filter(|value| !value.is_empty())
                .map(|value| (OsString::from(name), value))
        })
        .collect()
}

fn confine_spawned_process() -> io::Result<()> {
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
}
