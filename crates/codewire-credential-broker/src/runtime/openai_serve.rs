//! The OpenAI route's serving, shared by a loopback request and a front-door
//! Codex request that passed the swap rule (#3999).

use codewire_access::{BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind};
use http::StatusCode;
use uuid::Uuid;

use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError,
    BrokerUpstreamTransport, OpenAiBroker, PreparedOAuthRequest, ProviderStreamingResponse,
    current_unix_time, map_adapter_error, refresh_generation,
};
use crate::BrokerCredentialLease as _;
use crate::openai::ValidatedOpenAiRequest;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Serves `provider_request` with `lease`'s credential, its reply
    /// redacted: an API key, or a Codex sign-in refreshed when it is about to
    /// expire and once more on a 401.
    pub(super) async fn serve_openai(
        &self,
        request_id: Uuid,
        slot: &CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        lease: P::Lease,
        provider_request: ValidatedOpenAiRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let (prepared, oauth_retry) = match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => (
                self.api_key_adapter
                    .prepare_validated(lease, provider_request)
                    .map_err(map_adapter_error)?,
                None,
            ),
            CredentialAuthKind::OAuth => {
                if *slot != CapabilitySlot::codex() {
                    return Err(BrokerRequestError::Denied);
                }
                let admitted_grant = lease.grant().clone();
                let generation = refresh_generation(&lease);
                let credential = self
                    .oauth_adapter
                    .credential_from_lease(lease)
                    .map_err(map_adapter_error)?;
                let retry_request = provider_request.clone();
                let prepared = if credential.should_refresh(current_unix_time()?) {
                    self.prepare_oauth_after_refresh(
                        request_id,
                        operation.clone(),
                        route.clone(),
                        provider_request,
                        None,
                        &admitted_grant,
                    )
                    .await?
                } else {
                    PreparedOAuthRequest {
                        request: self
                            .oauth_adapter
                            .prepare_credential(credential, provider_request)
                            .map_err(map_adapter_error)?,
                        generation,
                    }
                };
                let generation = prepared.generation;
                (
                    prepared.request,
                    Some((retry_request, generation, admitted_grant)),
                )
            }
            _ => return Err(BrokerRequestError::Denied),
        };
        let (mut upstream, mut response_policy) = self.execute_prepared(prepared).await?;
        if upstream.status == StatusCode::UNAUTHORIZED
            && let Some((retry_request, rejected_generation, admitted_grant)) = oauth_retry
        {
            drop(upstream);
            let retry = self
                .prepare_oauth_after_refresh(
                    request_id,
                    operation,
                    route,
                    retry_request,
                    Some(&rejected_generation),
                    &admitted_grant,
                )
                .await?;
            (upstream, response_policy) = self.execute_prepared(retry.request).await?;
        }
        let (status, upstream_headers, body) = upstream.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = response_policy
            .begin(&upstream_headers)
            .map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(ProviderStreamingResponse::OpenAi(redactor)),
                finished: false,
            }),
        ))
    }
}
