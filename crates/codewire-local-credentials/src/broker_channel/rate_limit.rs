//! A started refresh the provider rate-limited (#4975), on the broker's
//! channel: the authority closes it with its wait and keeps the credential.

use std::sync::Arc;

use codewire_protected_store::ProtectedStore;
use tonic::Status;

use super::{
    BrokerLeaseChannelError, BrokerLeaseRpc, LocalCredentialBrokerLeaseClient,
    StartedBrokerCredentialRefresh, map_client_status, map_server_error, parse_canonical_uuid, v1,
};

impl<S> BrokerLeaseRpc<S>
where
    S: ProtectedStore + 'static,
{
    pub(super) async fn rate_limit_refresh(
        &self,
        request: v1::BrokerCredentialRefreshRateLimitRequest,
    ) -> Result<v1::BrokerCredentialRefreshRateLimitResponse, Status> {
        self.require_local_mode()?;
        let refresh_id =
            parse_canonical_uuid(&request.refresh_id, "credential refresh rate limit")?;
        let request_id =
            parse_canonical_uuid(&request.request_id, "credential refresh rate limit")?;
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.rate_limit_environment_credential_refresh(
                channel_id,
                refresh_id,
                request_id,
                request.wait_seconds,
            )
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        Ok(v1::BrokerCredentialRefreshRateLimitResponse {})
    }
}

impl<S> LocalCredentialBrokerLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    /// Close a started refresh the provider answered 429, read in full, for
    /// `wait_seconds`, keeping the credential. Any error, a refresh already
    /// begun after a wait included, leaves the attempt started: the caller
    /// then fails it with `fail_credential_refresh`, which is terminal.
    pub async fn rate_limit_credential_refresh(
        &mut self,
        started: &StartedBrokerCredentialRefresh,
        wait_seconds: u64,
    ) -> Result<(), BrokerLeaseChannelError> {
        let permit = &started.reservation;
        self.validate_refresh_channel(permit)?;
        self.inner
            .rate_limit_credential_refresh(v1::BrokerCredentialRefreshRateLimitRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: permit.request_id.to_string(),
                wait_seconds,
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }
}
