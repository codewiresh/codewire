//! An existing Sandbox's startup script (#5949): saved, replaced or removed
//! through the one call that writes it after create.

use codewire_proto::codewire::v1::{
    SetEnvironmentStartupScriptRequest, SetEnvironmentStartupScriptResponse,
};

use crate::{
    ClientError, CodewireClient, GeneratedEnvironmentServiceClient, ReqwestConnectTransport,
};

impl CodewireClient {
    /// Saves `startup_script` as the script every start of the environment
    /// runs; empty removes it. A running environment keeps running and runs
    /// it at its next start.
    pub async fn set_environment_startup_script(
        &self,
        org_id: &str,
        environment_id: &str,
        startup_script: &str,
    ) -> Result<SetEnvironmentStartupScriptResponse, ClientError> {
        // Built per call, as `environment_setup/retry.rs` does, so the SDK's
        // `lib.rs` stays as it is.
        GeneratedEnvironmentServiceClient::new(
            ReqwestConnectTransport(self.http().clone()),
            self.config().connect_config()?,
        )
        .set_environment_startup_script_with_options(
            SetEnvironmentStartupScriptRequest {
                org_id: org_id.to_owned(),
                environment_id: environment_id.to_owned(),
                startup_script: startup_script.to_owned(),
                ..Default::default()
            },
            self.auth_options().await?,
        )
        .await
        .map(|response| response.into_owned())
        .map_err(ClientError::from)
    }
}
