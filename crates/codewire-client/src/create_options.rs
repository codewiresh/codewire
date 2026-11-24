//! What an organization offers a new environment: its presets, whether the
//! confidential tier is available, and the domain previews are served under.
//! The dashboard's create form reads the same call.

use codewire_proto::codewire::console::v1::EnvironmentSetupServiceClient;
pub use codewire_proto::codewire::console::v1::{
    GetEnvironmentCreateOptionsRequest, GetEnvironmentCreateOptionsResponse,
};

use crate::*;

impl CodewireClient {
    pub async fn get_environment_create_options(
        &self,
        request: GetEnvironmentCreateOptionsRequest,
    ) -> Result<GetEnvironmentCreateOptionsResponse, ClientError> {
        // Built per call: only a create reads it, and `lib.rs` stays as it is.
        EnvironmentSetupServiceClient::new(self.transport(), self.config().connect_config()?)
            .get_environment_create_options_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
