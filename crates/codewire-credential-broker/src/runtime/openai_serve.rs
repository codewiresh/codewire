//! The OpenAI route's serving, shared by a loopback request, a front-door
//! Codex request that passed the swap rule, and a front-door Codex WebSocket
//! handshake (#3999).

use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, DerivedGrant,
};
use http::StatusCode;
use uuid::Uuid;

use super::forced_refresh::{after_failed_refresh, forced_refresh_due, hold_rejection};
use super::{
    BrokerHttpResponse, BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError,
    BrokerUpstreamResponse, BrokerUpstreamTransport, CODEX_REFRESH_PROVIDER, OpenAiBroker,
    PreparedOAuthRequest, ProviderStreamingResponse, RefreshCredentialGeneration,
    current_unix_time, map_adapter_error, refresh_generation,
};
use crate::openai::ValidatedOpenAiRequest;
use crate::{BrokerCredentialLease as _, PreparedOpenAiRequest, PreparedOpenAiResponse};

/// What a Codex sign-in needs to retry once after a provider's 401.
pub(super) struct OAuthRetry {
    request: ValidatedOpenAiRequest,
    rejected: RefreshCredentialGeneration,
    /// When the sign-in that was sent was last refreshed, by its stored time.
    rejected_refreshed_at_unix: u64,
    grant: DerivedGrant,
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// Serves `provider_request` with `lease`'s credential, its reply
    /// redacted: an API key, or a Codex sign-in refreshed when it is about to
    /// expire, and once more on a 401 only when the sign-in that was sent was
    /// last refreshed `FORCED_REFRESH_MIN_AGE` ago or more (#4974).
    pub(super) async fn serve_openai(
        &self,
        request_id: Uuid,
        slot: &CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        lease: P::Lease,
        provider_request: ValidatedOpenAiRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        self.serve_openai_for_account(request_id, slot, operation, route, lease, provider_request)
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::serve_openai`], also giving the account id the broker sent
    /// with a Codex sign-in, the credential's own and never one the
    /// environment named (#3999).
    pub(super) async fn serve_openai_for_account(
        &self,
        request_id: Uuid,
        slot: &CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        lease: P::Lease,
        provider_request: ValidatedOpenAiRequest,
    ) -> Result<(BrokerHttpResponse, Option<String>), BrokerRequestError> {
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
        let account = prepared.account_id();
        let (mut upstream, mut response_policy) = self.execute_prepared(prepared).await?;
        if upstream.status() == StatusCode::UNAUTHORIZED
            && let Some(retry) = retry
        {
            let prepared;
            (upstream, prepared) = self
                .after_unauthorized(request_id, operation, route, retry, upstream)
                .await?;
            if let Some(prepared) = prepared {
                (upstream, response_policy) = self.execute_prepared(prepared).await?;
            }
        }
        Ok((redacted_openai(upstream, response_policy)?, account))
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
                    let refreshed_at_unix = credential.refreshed_at_unix();
                    PreparedOAuthRequest {
                        request: self
                            .oauth_adapter
                            .prepare_credential(credential, provider_request)
                            .map_err(map_adapter_error)?,
                        generation,
                        refreshed_at_unix,
                    }
                };
                Ok((
                    prepared.request,
                    Some(OAuthRetry {
                        request: retry_request,
                        rejected: prepared.generation,
                        rejected_refreshed_at_unix: prepared.refreshed_at_unix,
                        grant,
                    }),
                ))
            }
            _ => Err(BrokerRequestError::Denied),
        }
    }

    /// What follows the provider's 401 of the Codex sign-in `retry` was sent
    /// with (#4974): the request once more, with the sign-in refreshed
    /// outside the environment, when it was last refreshed
    /// `FORCED_REFRESH_MIN_AGE` ago or more and the 401 was held whole.
    /// Otherwise `upstream`, the provider's own 401, to answer as it came.
    pub(super) async fn after_unauthorized(
        &self,
        request_id: Uuid,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        retry: OAuthRetry,
        upstream: BrokerUpstreamResponse,
    ) -> Result<(BrokerUpstreamResponse, Option<PreparedOpenAiRequest>), BrokerRequestError> {
        if !forced_refresh_due(retry.rejected_refreshed_at_unix, current_unix_time()?) {
            return Ok((upstream, None));
        }
        let (upstream, whole) = hold_rejection(upstream).await;
        // A 401 that could not be held whole is answered as it is.
        if !whole {
            return Ok((upstream, None));
        }
        match self
            .prepare_oauth_after_refresh(
                request_id,
                operation,
                route,
                retry.request,
                Some(&retry.rejected),
                &retry.grant,
            )
            .await
        {
            Ok(prepared) => Ok((upstream, Some(prepared.request))),
            Err(failure) => {
                after_failed_refresh(failure, CODEX_REFRESH_PROVIDER).map(|()| (upstream, None))
            }
        }
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
