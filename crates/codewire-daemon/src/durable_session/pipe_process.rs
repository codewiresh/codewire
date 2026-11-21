//! How a pipe session's process is prepared: its environment from the one
//! shared builder, then the launch projection when this daemon has one.

use super::{PersistedSession, PreparedProcess, build_process_env_in};
use crate::Config;
use crate::credential_bridge::CredentialBridge;

/// One pipe session's process. Every session is prepared the same way, a
/// managed agent's driver included, because a managed agent works in the
/// user's environment: the one shared builder (the Git route, the SSH signer
/// socket, the provider routes), then the launch projection when this daemon
/// has one, with its own authority check for this launch. The driver, its
/// guardian and the provider inherit the result, and the guardian adds only
/// the managed login lockdown. Nothing resolved is kept: the values exist in
/// the launcher and the processes it becomes, never in the session record.
/// `daemon_environment` is this daemon's own environment, from which the
/// builder drops the daemon's internal configuration.
pub(super) fn prepare_pipe_process(
    config: &Config,
    bridge: &CredentialBridge,
    snapshot: &PersistedSession,
    daemon_environment: impl IntoIterator<Item = (String, String)>,
    display: &crate::desktop::Display,
) -> Result<PreparedProcess, String> {
    let mut environment =
        build_process_env_in(config, &snapshot.env, &snapshot.term, daemon_environment)
            .map_err(|error| format!("prepare session environment: {error}"))?;
    display.apply(&snapshot.env, &mut environment);
    PreparedProcess::prepare_configured(
        (config, bridge),
        &snapshot.command,
        &snapshot.working_dir,
        &environment,
        false,
        0,
        0,
    )
    .map_err(|error| format!("prepare session process: {error}"))
}

/// Confine a platform-managed driver to its owner: no new privileges, and it
/// dies with the daemon that started it. No daemon or foreign PID signaling
/// is exposed through the private service.
#[cfg(target_os = "linux")]
pub(super) fn confine_platform_driver(process: &mut tokio::process::Command) {
    // SAFETY: getpid takes no arguments and cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the closure makes only async-signal-safe calls (prctl, getppid)
    // between fork and exec, and touches no allocator state.
    unsafe {
        process.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != parent
            {
                // The child reports only the raw error, so this is what the
                // parent sees, and nothing allocates between fork and exec.
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            Ok(())
        });
    }
}
