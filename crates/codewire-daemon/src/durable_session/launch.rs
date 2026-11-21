//! What a session's launch starts from: its configuration, and a PTY
//! session's environment built under it.

use std::borrow::Cow;

use super::{PersistedSession, SessionEngine, build_process_env};
use crate::Config;
use crate::env::ProcessEnvironment;

impl SessionEngine {
    /// [`CredentialBridge::launch_config`](crate::credential_bridge::CredentialBridge::launch_config)
    /// for this daemon's configuration.
    pub(super) async fn launch_config(&self) -> Cow<'_, Config> {
        self.inner
            .credential_bridge
            .launch_config(&self.inner.config)
            .await
    }
}

/// One PTY session's environment: the one shared builder under `config`,
/// then the desktop's display, as a pipe session's.
pub(super) fn pty_environment(
    config: &Config,
    snapshot: &PersistedSession,
    display: &crate::desktop::Display,
) -> Result<ProcessEnvironment, String> {
    let mut environment = build_process_env(config, &snapshot.env, &snapshot.term)
        .map_err(|error| format!("prepare session PTY environment: {error}"))?;
    display.apply(&snapshot.env, &mut environment);
    Ok(environment)
}
