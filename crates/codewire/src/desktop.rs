//! An environment's graphical desktop (`codewire.v1.EnvironmentDesktopService`).
//!
//! A running desktop's answer carries its viewer password, which the VNC
//! server asks a viewer for. It is redacted in debug output; a caller that
//! prints or stores it decides that for itself.

use std::time::Duration;

use codewire_proto::codewire::v1::EnvironmentDesktopServiceClient;
pub use codewire_proto::codewire::v1::{
    EnvironmentDesktop, EnvironmentDesktopRunning, EnvironmentDesktopState, GetDesktopRequest,
    GetDesktopResponse, StartDesktopRequest, StartDesktopResponse, StopDesktopRequest,
    StopDesktopResponse,
};

use crate::{ClientError, CodewireClient, ReqwestConnectTransport};

/// A start answers only once the desktop accepts a viewer. The control
/// plane allows it 40 seconds; this waits a little longer, so the server's
/// own answer arrives instead of a local timeout.
const START_TIMEOUT: Duration = Duration::from_secs(45);

impl CodewireClient {
    fn desktop_client(
        &self,
    ) -> Result<EnvironmentDesktopServiceClient<ReqwestConnectTransport>, ClientError> {
        Ok(EnvironmentDesktopServiceClient::new(
            ReqwestConnectTransport(self.http.clone()),
            self.config.connect_config()?,
        ))
    }

    /// Starts the environment's desktop, or returns the one that runs.
    pub async fn start_desktop(
        &self,
        request: StartDesktopRequest,
    ) -> Result<StartDesktopResponse, ClientError> {
        let options = self.auth_options().await?.with_timeout(START_TIMEOUT);
        self.desktop_client()?
            .start_desktop_with_options(request, options)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_desktop(
        &self,
        request: GetDesktopRequest,
    ) -> Result<GetDesktopResponse, ClientError> {
        self.desktop_client()?
            .get_desktop_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Stops the desktop. Stopping one that does not run succeeds.
    pub async fn stop_desktop(
        &self,
        request: StopDesktopRequest,
    ) -> Result<StopDesktopResponse, ClientError> {
        self.desktop_client()?
            .stop_desktop_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}

#[cfg(test)]
#[path = "desktop_tests.rs"]
mod tests;
