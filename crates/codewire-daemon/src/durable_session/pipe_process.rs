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
