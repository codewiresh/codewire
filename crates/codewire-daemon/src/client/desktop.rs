//! The environment's desktop through the daemon (`desktop.vnc.v1`,
//! `docs/dev/SANDBOX-DESKTOP.md`). A caller checks the capability first: a
//! daemon without it answers these calls `Unimplemented`.

use super::{SessionClient, SessionClientError, v1};

impl SessionClient {
    /// Starts the desktop, or returns the one that runs. The answer carries
    /// the viewer password; it is never logged.
    pub async fn start_desktop(&self) -> Result<v1::Desktop, SessionClientError> {
        let mut client = self.inner.clone();
        desktop(
            client
                .start_desktop(self.authorized(v1::StartDesktopRequest {}))
                .await?
                .into_inner()
                .desktop,
        )
    }

    pub async fn get_desktop(&self) -> Result<v1::Desktop, SessionClientError> {
        let mut client = self.inner.clone();
        desktop(
            client
                .get_desktop(self.authorized(v1::GetDesktopRequest {}))
                .await?
                .into_inner()
                .desktop,
        )
    }

    pub async fn stop_desktop(&self) -> Result<v1::Desktop, SessionClientError> {
        let mut client = self.inner.clone();
        desktop(
            client
                .stop_desktop(self.authorized(v1::StopDesktopRequest {}))
                .await?
                .into_inner()
                .desktop,
        )
    }
}

fn desktop(answer: Option<v1::Desktop>) -> Result<v1::Desktop, SessionClientError> {
    answer.ok_or_else(|| {
        SessionClientError::Status(tonic::Status::internal(
            "the environment daemon answered a desktop call with no desktop",
        ))
    })
}
