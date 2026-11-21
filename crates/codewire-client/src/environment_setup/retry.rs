//! Retry setup (#4767): run a running Sandbox's failed setup again, from the
//! step it failed at. A retry from the clone step deletes the repository
//! directories first, so the service refuses it with `RECLONE_UNCONFIRMED`
//! until the caller confirms.

use codewire_proto::codewire::v1::RetryEnvironmentSetupRequest;

use crate::{
    ClientError, CodewireClient, GeneratedEnvironmentServiceClient, ReqwestConnectTransport,
};

/// The refusal reason that asks the caller to confirm a retry that clones
/// the repositories again; its message names the directories it deletes.
pub const RECLONE_UNCONFIRMED: &str = "RECLONE_UNCONFIRMED";

impl CodewireClient {
    /// Ask the service to retry the environment's failed setup. It returns
    /// once the retry is requested; the setup log shows it run.
    pub async fn retry_environment_setup(
        &self,
        org_id: &str,
        environment_id: &str,
        confirm_reclone: bool,
    ) -> Result<(), ClientError> {
        // Built per call, as `create_options.rs` does: only a retry reads it,
        // and the SDK's `lib.rs` stays as it is.
        GeneratedEnvironmentServiceClient::new(
            ReqwestConnectTransport(self.http().clone()),
            self.config().connect_config()?,
        )
        .retry_environment_setup_with_options(
            RetryEnvironmentSetupRequest {
                org_id: org_id.to_owned(),
                environment_id: environment_id.to_owned(),
                confirm_reclone,
                ..Default::default()
            },
            self.auth_options().await?,
        )
        .await
        .map(drop)
        .map_err(ClientError::from)
    }
}
