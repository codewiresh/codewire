//! What the engine does differently for the desktop's session
//! (`docs/dev/SANDBOX-DESKTOP.md`, "What the daemon does"): no client writes
//! to it, by any path, and the display new processes get ends with it.

use codewire_daemon_proto::SESSION_INPUT_TIMEOUT;

use super::{SessionEngine, SessionError, lock};
use crate::desktop::Display;

impl SessionEngine {
    pub(crate) fn display(&self) -> Display {
        self.inner.display.clone()
    }

    /// Input from a client. One write and an attachment's stream both come
    /// through here, so the refusal holds for every path: the desktop's
    /// launcher takes the viewer password from the first line it reads, and
    /// a client's line before the daemon's would become the password.
    pub async fn input(&self, session_id: &str, data: Vec<u8>) -> Result<(), SessionError> {
        self.ensure_initialized().await?;
        let names_the_desktop = lock(&self.inner.sessions)
            .get(session_id)
            .is_some_and(|session| session.desktop);
        if names_the_desktop {
            return Err(SessionError::FailedPrecondition(
                "the desktop's session takes no input".into(),
            ));
        }
        self.write_input(session_id, data).await
    }

    /// The desktop's own write to its launcher: the one exception.
    pub(crate) async fn desktop_input(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), SessionError> {
        tokio::time::timeout(SESSION_INPUT_TIMEOUT, self.write_input(session_id, data))
            .await
            .map_err(|_| {
                SessionError::DeadlineExceeded(
                    "the desktop's launcher did not take its input in time".into(),
                )
            })?
    }
}
