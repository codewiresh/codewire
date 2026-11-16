//! The OpenAI route's serving, shared by a loopback request, a front-door
//! Codex request that passed the swap rule, and a front-door Codex WebSocket
//! handshake (#3999).

use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, DerivedGrant,
};
use http::StatusCode;
use uuid::Uuid;

use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError,
    BrokerUpstreamResponse, BrokerUpstreamTransport, OpenAiBroker, PreparedOAuthRequest,
    ProviderStreamingResponse, RefreshCredentialGeneration, current_unix_time, map_adapter_error,
    refresh_generation,
};
use crate::openai::ValidatedOpenAiRequest;
use crate::{BrokerCredentialLease as _, PreparedOpenAiRequest, PreparedOpenAiResponse};

/// What a Codex sign-in needs to retry once after a provider's 401.
pub(super) struct OAuthRetry {
    request: ValidatedOpenAiRequest,
    rejected: RefreshCredentialGeneration,
    grant: DerivedGrant,
}

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
        let (prepared, retry) = self
            .prepare_openai(
                request_id,
                slot,
                &operation,
                &route,
                lease,
                provider_request,
            )
            .await?;
        let (mut upstream, mut response_policy) = self.execute_prepared(prepared).await?;
        if upstream.status() == StatusCode::UNAUTHORIZED
            && let Some(retry) = retry
        {
            drop(upstream);
            let prepared = self
                .retry_openai(request_id, operation, route, retry)
                .await?;
            (upstream, response_policy) = self.execute_prepared(prepared).await?;
        }
        redacted_openai(upstream, response_policy)
    }

    /// `provider_request` with `lease`'s credential in it, and what a 401
    /// retry needs when the credential is a Codex sign-in.
    pub(super) async fn prepare_openai(
        &self,
        request_id: Uuid,
        slot: &CapabilitySlot,
        operation: &BrokerOperationId,
        route: &BrokerRouteId,
        lease: P::Lease,
        provider_request: ValidatedOpenAiRequest,
    ) -> Result<(PreparedOpenAiRequest, Option<OAuthRetry>), BrokerRequestError> {
        match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => Ok((
                self.api_key_adapter
                    .prepare_validated(lease, provider_request)
                    .map_err(map_adapter_error)?,
                None,
            )),
            CredentialAuthKind::OAuth => {
                if *slot != CapabilitySlot::codex() {
                    return Err(BrokerRequestError::Denied);
                }
                let grant = lease.grant().clone();
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
                        &grant,
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
                Ok((
                    prepared.request,
                    Some(OAuthRetry {
                        request: retry_request,
                        rejected: prepared.generation,
                        grant,
                    }),
                ))
            }
            _ => Err(BrokerRequestError::Denied),
        }
    }

    /// The request again after the provider refused the sign-in it carried:
    /// refreshed outside the environment, once.
    pub(super) async fn retry_openai(
        &self,
        request_id: Uuid,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        retry: OAuthRetry,
    ) -> Result<PreparedOpenAiRequest, BrokerRequestError> {
        Ok(self
            .prepare_oauth_after_refresh(
                request_id,
                operation,
                route,
                retry.request,
                Some(&retry.rejected),
                &retry.grant,
            )
            .await?
            .request)
    }
}

/// A provider reply under its route's response policy: filtered headers and
/// a redacted body.
pub(super) fn redacted_openai(
    upstream: BrokerUpstreamResponse,
    response_policy: PreparedOpenAiResponse,
) -> Result<BrokerHttpResponse, BrokerRequestError> {
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
