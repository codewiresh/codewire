//! The Anthropic route: a loopback request always gets the leased credential;
//! a front-door request first passes the swap rule (#3999, `swap.rs`).

use codewire_access::{BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind};
use uuid::Uuid;

use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, BrokerHttpResponse, BrokerLeaseProvider,
    BrokerRedactedBody, BrokerRequestError, BrokerUpstreamRequest, BrokerUpstreamTransport,
    OAuthPurpose, OpenAiBroker, Phase, ProviderStreamingResponse, ValidatedGuestRequest,
    current_unix_time, map_adapter_error, map_lease_error, map_upstream_error, timing,
    validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::anthropic::ValidatedAnthropicRequest;

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// A loopback Anthropic request: served with the leased credential.
    pub(super) async fn execute_anthropic(
        &self,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let validated = self.validate_anthropic(
            &request.method,
            &request.path,
            request.query.as_deref(),
            request.headers,
            request.body,
        )?;
        let operation = anthropic_operation()?;
        let lease = self
            .leases
            .lease_operation(
                request.request_id,
                request.slot.clone(),
                operation.clone(),
                request.route.clone(),
            )
            .await
            .map_err(map_lease_error)?;
        validate_http_lease_coordinates(&lease, &request.slot, &operation, &request.route)?;
        self.serve_anthropic(
            request.request_id,
            request.slot,
            request.route,
            operation,
            lease,
            validated,
        )
        .await
    }

    pub(super) fn validate_anthropic(
        &self,
        method: &http::Method,
        path: &str,
        query: Option<&str>,
        headers: http::HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedAnthropicRequest, BrokerRequestError> {
        self.anthropic_adapter
            .validate_request(method, path, query, headers, body)
            .map_err(map_adapter_error)
    }

    /// Serves `validated` with `lease`'s credential, its reply redacted.
    pub(super) async fn serve_anthropic(
        &self,
        request_id: Uuid,
        slot: CapabilitySlot,
        route: BrokerRouteId,
        operation: BrokerOperationId,
        lease: P::Lease,
        validated: ValidatedAnthropicRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        // The validated request is form-independent; the lease's credential
        // kind selects the API key, Claude subscription token or Claude
        // sign-in adapter. No provider response marks, deletes or withholds
        // any form: a Sandbox process shapes the request. Only a sign-in
        // refreshes, and only when its access token is about to expire.
        let prepared = match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => self
                .anthropic_adapter
                .prepare_validated(lease, validated)
                .map_err(map_adapter_error)?,
            CredentialAuthKind::OAuth => self
                .anthropic_subscription_adapter
                .prepare_validated(lease, validated)
                .map_err(map_adapter_error)?,
            CredentialAuthKind::ClaudeSignIn => {
                let admitted_grant = lease.grant().clone();
                let purpose = OAuthPurpose::Operation {
                    slot: slot.clone(),
                    operation: operation.clone(),
                    route: route.clone(),
                };
                let credential = self.claude_oauth_credential(lease, &purpose)?;
                let credential = if credential.should_refresh(current_unix_time()?) {
                    drop(credential);
                    self.fresh_oauth_credential(
                        request_id,
                        &purpose,
                        |lease| self.claude_oauth_credential(lease, &purpose),
                        None,
                        &admitted_grant,
                        ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
                    )
                    .await?
                    .0
                } else {
                    credential
                };
                self.anthropic_sign_in_adapter
                    .prepare_credential(&credential, validated)
                    .map_err(map_adapter_error)?
            }
            _ => return Err(BrokerRequestError::Denied),
        };
        let (method, target, headers, body, policy) = prepared.into_parts();
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
                body_stream: None,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        let (status, headers, body) = response.into_parts();
        if status.is_informational() {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        let (headers, redactor) = policy.begin(&headers).map_err(map_adapter_error)?;
        Ok(BrokerHttpResponse::new(
            status,
            headers,
            Box::pin(BrokerRedactedBody {
                upstream: body,
                redactor: Some(ProviderStreamingResponse::Anthropic(redactor)),
                finished: false,
            }),
        ))
    }
}

pub(super) fn anthropic_operation() -> Result<BrokerOperationId, BrokerRequestError> {
    BrokerOperationId::parse(crate::anthropic::OPERATION)
        .map_err(|_| BrokerRequestError::InvalidRequest)
}
