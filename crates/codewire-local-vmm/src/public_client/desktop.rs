//! A local VM's desktop through the supervisor's public
//! `EnvironmentDesktopService`, the same contract the hosted control plane
//! serves. A running desktop's answer carries its viewer password; it is
//! redacted in debug output, and a caller that prints it decides that for
//! itself.

use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::v1::{
    EnvironmentDesktop, EnvironmentDesktopServiceClient, GetDesktopRequest, StartDesktopRequest,
    StopDesktopRequest,
};
use connectrpc::client::SharedHttp2Connection;

use super::{NativePublicClientError, connect_target};
use crate::host::supervisor_peer::SupervisorPeerPin;
use crate::supervisor::NativeRuntimeConfig;

/// A start answers only once the desktop accepts a viewer, within the
/// daemon's own ten seconds; this leaves the supervisor room to say why not.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct NativePublicDesktopClient {
    _supervisor_peer: Arc<SupervisorPeerPin>,
    inner: EnvironmentDesktopServiceClient<SharedHttp2Connection>,
    org_id: String,
    environment_id: String,
}

impl NativePublicDesktopClient {
    pub async fn connect_or_start(
        config: &NativeRuntimeConfig,
        target: &str,
    ) -> Result<Self, NativePublicClientError> {
        let target = connect_target(config, target).await?;
        Ok(Self {
            _supervisor_peer: target.peer_pin,
            inner: EnvironmentDesktopServiceClient::new(
                target.transport,
                target.client_config.with_default_timeout(CALL_TIMEOUT),
            ),
            org_id: target.org_id,
            environment_id: target.environment_id,
        })
    }

    /// Starts the desktop, or returns the one that runs.
    pub async fn start(&self) -> Result<EnvironmentDesktop, NativePublicClientError> {
        self.inner
            .start_desktop(StartDesktopRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned()
            .desktop
            .into_option()
            .ok_or(NativePublicClientError::Protocol)
    }

    pub async fn get(&self) -> Result<EnvironmentDesktop, NativePublicClientError> {
        self.inner
            .get_desktop(GetDesktopRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned()
            .desktop
            .into_option()
            .ok_or(NativePublicClientError::Protocol)
    }

    /// Stops the desktop. Stopping one that does not run succeeds.
    pub async fn stop(&self) -> Result<EnvironmentDesktop, NativePublicClientError> {
        self.inner
            .stop_desktop(StopDesktopRequest {
                org_id: self.org_id.clone(),
                environment_id: self.environment_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned()
            .desktop
            .into_option()
            .ok_or(NativePublicClientError::Protocol)
    }
}
