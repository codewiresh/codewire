//! What a session's launch starts from: its configuration, and a PTY
//! session's environment built under it.

use std::borrow::Cow;

use super::{PersistedSession, SessionEngine};
use crate::Config;
use crate::launch::Launch;

impl SessionEngine {
    /// [`CredentialBridge::launch_config`](crate::credential_bridge::CredentialBridge::launch_config)
    /// for this daemon's configuration.
    pub(super) async fn launch_config(&self) -> Cow<'_, Config> {
        self.inner
            .credential_bridge
            .launch_config(&self.inner.config)
            .await
    }

    /// One PTY session's launch, through the one path `cw exec` and every
    /// PTY take (#6179).
    pub(super) async fn pty_launch(
        &self,
        snapshot: &PersistedSession,
    ) -> Result<Launch<'_>, String> {
        crate::launch::prepare(
            &self.inner.credential_bridge,
            &self.inner.config,
            &snapshot.env,
            &snapshot.term,
            &self.inner.display,
        )
        .await
        .map_err(|error| format!("prepare session PTY environment: {error}"))
    }
}
