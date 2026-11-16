//! The Anthropic route: a loopback request always gets the leased credential;
//! a front-door request first passes the swap rule (#3999, `swap.rs`).
//!
//! A Claude sign-in the provider rejects with 401 is refreshed once, outside
//! the environment, and its request is sent once more (#3999), when the
//! sign-in was last refreshed long enough ago (`FORCED_REFRESH_MIN_AGE`).
//! A second 401 is returned as it is, and so is the first when that refresh
//! fails. An API key or a subscription token is never retried.

use bytes::Bytes;
use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, DerivedGrant,
};
use futures::StreamExt as _;
use http::StatusCode;
use uuid::Uuid;

use super::forced_refresh::forced_refresh_due;
use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, BrokerHttpResponse, BrokerLeaseProvider,
    BrokerRedactedBody, BrokerRequestError, BrokerUpstreamBody, BrokerUpstreamError,
    BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport, OAuthPurpose,
    OpenAiBroker, Phase, ProviderStreamingResponse, RefreshCredentialGeneration,
    ValidatedGuestRequest, current_unix_time, map_adapter_error, map_lease_error,
    map_upstream_error, refresh_generation, timing, validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::anthropic::{
    PreparedAnthropicRequest, PreparedAnthropicResponse, ValidatedAnthropicRequest,
};
use crate::claude_oauth::ClaudeOAuthCredential;

/// The most of a provider's 401 held in memory while the sign-in refreshes.
/// The API's rejection is a few hundred bytes of JSON. A larger one is
/// answered as it is, with no refresh.
const HELD_REJECTION_MAX_BYTES: usize = 64 * 1024;

/// Reads the provider's 401 to its end, so no upstream connection is held
/// open while the sign-in refreshes: an exchange can take as long as its
/// timeout. Returns the reply, still to be answered as it came, and whether
/// all of it was read. One longer than `HELD_REJECTION_MAX_BYTES`, or one
/// that failed while it was read, was not: what was read goes back in front
/// of the rest.
async fn hold_rejection(response: BrokerUpstreamResponse) -> (BrokerUpstreamResponse, bool) {
    let (status, headers, mut body) = response.into_parts();
    let mut held: Vec<Result<Bytes, BrokerUpstreamError>> = Vec::new();
    let mut held_bytes = 0_usize;
    let whole = loop {
        match body.next().await {
            None => break true,
            Some(Ok(chunk)) => {
                held_bytes = held_bytes.saturating_add(chunk.len());
                held.push(Ok(chunk));
                if held_bytes > HELD_REJECTION_MAX_BYTES {
                    break false;
                }
            }
            Some(Err(error)) => {
                held.push(Err(error));
                break false;
            }
        }
    };
    let held = futures::stream::iter(held);
    let body: BrokerUpstreamBody = if whole {
        Box::pin(held)
    } else {
        Box::pin(held.chain(body))
    };
    (BrokerUpstreamResponse::new(status, headers, body), whole)
}

/// What sends a Claude sign-in's request once more after the provider
/// rejected the token it was sent with.
struct SignInRetry {
    request: ValidatedAnthropicRequest,
    rejected: RefreshCredentialGeneration,
    /// When the sign-in the request was sent with was last refreshed.
    rejected_refreshed_at_unix: u64,
    admitted_grant: DerivedGrant,
    purpose: OAuthPurpose,
}

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

    /// The Claude sign-in a lease for `purpose` carries.
    pub(super) fn claude_oauth_credential(
        &self,
        lease: P::Lease,
        purpose: &OAuthPurpose,
    ) -> Result<ClaudeOAuthCredential, BrokerRequestError> {
        match purpose {
            OAuthPurpose::Operation { .. } => self
                .anthropic_sign_in_adapter
                .credential_from_lease(lease)
                .map_err(map_adapter_error),
            OAuthPurpose::ClaudeLogin => self
                .anthropic_sign_in_adapter
                .login_credential_from_lease(lease)
                .map_err(map_adapter_error),
            OAuthPurpose::CodexLogin => Err(BrokerRequestError::Denied),
        }
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
        // refreshes: when its access token is about to expire, and once more
        // when the provider rejects a token last refreshed long enough ago.
        let (prepared, retry) = match lease.credential_metadata().authentication_kind {
            CredentialAuthKind::ApiKey => (
                self.anthropic_adapter
                    .prepare_validated(lease, validated)
                    .map_err(map_adapter_error)?,
                None,
            ),
            CredentialAuthKind::OAuth => (
                self.anthropic_subscription_adapter
                    .prepare_validated(lease, validated)
                    .map_err(map_adapter_error)?,
                None,
            ),
            CredentialAuthKind::ClaudeSignIn => {
                let purpose = OAuthPurpose::Operation {
                    slot,
                    operation,
                    route,
                };
                let (prepared, retry) = self
                    .prepare_sign_in(request_id, purpose, lease, validated)
                    .await?;
                (prepared, Some(retry))
            }
            _ => return Err(BrokerRequestError::Denied),
        };
        let (mut response, mut policy) = self.send_anthropic(prepared).await?;
        if response.status() == StatusCode::UNAUTHORIZED
            && let Some(retry) = retry
            && forced_refresh_due(retry.rejected_refreshed_at_unix, current_unix_time()?)
        {
            let whole;
            (response, whole) = hold_rejection(response).await;
            // A 401 that could not be held whole is answered as it is.
            if whole {
                match self.prepare_sign_in_retry(request_id, retry).await {
                    Ok(prepared) => (response, policy) = self.send_anthropic(prepared).await?,
                    // The one failure that ends the epoch (a refresh the
                    // authority could not start or settle) still has to.
                    Err(BrokerRequestError::AuthorityUnavailable) => {
                        return Err(BrokerRequestError::AuthorityUnavailable);
                    }
                    // Any other failed refresh answers the provider's own
                    // 401, from the copy held above. The agent then asks the
                    // token endpoint itself, which is the one place that
                    // tells it whether its login is gone (`invalid_grant`) or
                    // the failure will pass. The refresh path has already
                    // logged the failure's class and, for a refused or
                    // uncertain exchange, left the sign-in "Reconnect needed".
                    Err(error) => {
                        tracing::info!(
                            %error,
                            "a Claude sign-in's 401 is returned after its forced refresh failed"
                        );
                    }
                }
            }
        }
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

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    /// `validated` with the lease's sign-in, refreshed first when its access
    /// token is about to expire, and what a retry of it needs.
    async fn prepare_sign_in(
        &self,
        request_id: Uuid,
        purpose: OAuthPurpose,
        lease: P::Lease,
        validated: ValidatedAnthropicRequest,
    ) -> Result<(PreparedAnthropicRequest, SignInRetry), BrokerRequestError> {
        let admitted_grant = lease.grant().clone();
        let leased = refresh_generation(&lease);
        let credential = self.claude_oauth_credential(lease, &purpose)?;
        // The generation the request is sent with is the one a 401 rejects.
        let (credential, sent) = if credential.should_refresh(current_unix_time()?) {
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
        } else {
            (credential, leased)
        };
        let rejected_refreshed_at_unix = credential.refreshed_at_unix();
        // A retry sends the body a second time, and by then the first send
        // has consumed it, so the copy is taken before any 401 is known. It
        // is bounded by the adapter's request limit (`MAX_REQUEST_BYTES` in
        // `anthropic.rs`, 4 MiB).
        let prepared = self
            .anthropic_sign_in_adapter
            .prepare_credential(&credential, validated.clone())
            .map_err(map_adapter_error)?;
        Ok((
            prepared,
            SignInRetry {
                request: validated,
                rejected: sent,
                rejected_refreshed_at_unix,
                admitted_grant,
                purpose,
            },
        ))
    }

    /// The rejected request with the sign-in refreshed past the generation
    /// the provider refused. A generation another request already replaced
    /// is used as it is, with no second exchange.
    async fn prepare_sign_in_retry(
        &self,
        request_id: Uuid,
        retry: SignInRetry,
    ) -> Result<PreparedAnthropicRequest, BrokerRequestError> {
        let SignInRetry {
            request,
            rejected,
            admitted_grant,
            purpose,
            ..
        } = retry;
        let (credential, _) = self
            .fresh_oauth_credential(
                request_id,
                &purpose,
                |lease| self.claude_oauth_credential(lease, &purpose),
                Some(&rejected),
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await?;
        self.anthropic_sign_in_adapter
            .prepare_credential(&credential, request)
            .map_err(map_adapter_error)
    }

    async fn send_anthropic(
        &self,
        prepared: PreparedAnthropicRequest,
    ) -> Result<(BrokerUpstreamResponse, PreparedAnthropicResponse), BrokerRequestError> {
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
        Ok((response, policy))
    }
}

pub(super) fn anthropic_operation() -> Result<BrokerOperationId, BrokerRequestError> {
    BrokerOperationId::parse(crate::anthropic::OPERATION)
        .map_err(|_| BrokerRequestError::InvalidRequest)
}

#[cfg(test)]
mod tests;
