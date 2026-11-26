//! Antigravity Cloud Code front-door swap route (#6555).
//!
//! Serves `daily-cloudcode-pa.googleapis.com` and `cloudcode-pa.googleapis.com`
//! strictly behind the front door:
//! - Swaps ONLY `Authorization: Bearer <cwp1_placeholder>` on exact
//!   `POST ^/v1internal:[A-Za-z][A-Za-z0-9_]*$` paths.
//! - Refuses any `cwp1_` placeholder in raw/percent-decoded query params or
//!   disallowed credential headers (`400`), `key`/`access_token` query params
//!   beside a swap (`400 credential_conflict`), and our placeholder on any
//!   non-`POST` or non-`/v1internal:` path (`403 path_not_served`).
//! - Refreshes proactively within 5 minutes of expiry and retries once on 401
//!   when the 10-minute forced-refresh cooldown allows.

use bytes::Bytes;
use codewire_access::{BrokerOperationId, DerivedGrant, Refusal, RefusalProvider};
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use uuid::Uuid;

use super::forced_refresh::{
    RetryFailure, after_failed_refresh, forced_refresh_due, hold_rejection,
};
use super::swap::{
    Presented, SwapCarrier, credential_conflict_response, query_carries_placeholder_tag,
    query_has_google_credential_param,
};
use super::{
    ACCESS_TOKEN_REFRESH_WINDOW_SECONDS, ANTIGRAVITY_REFRESH_PROVIDER, BrokerHttpResponse,
    BrokerLeaseProvider, BrokerRedactedBody, BrokerRequestError, BrokerUpstreamRequest,
    BrokerUpstreamResponse, BrokerUpstreamTransport, OAuthPurpose, OpenAiBroker, Phase,
    ProviderStreamingResponse, RefreshCredentialGeneration, ValidatedGuestRequest,
    current_unix_time, map_adapter_error, map_lease_error, map_upstream_error, refresh_generation,
    timing, validate_http_lease_coordinates,
};
use crate::BrokerCredentialLease as _;
use crate::antigravity::{
    PreparedAntigravityRequest, PreparedAntigravityResponse, ValidatedAntigravityRequest,
};
use crate::antigravity_oauth::AntigravityOAuthCredential;
use crate::network::RouteHost;

struct AntigravityRetry {
    host: &'static str,
    request: ValidatedAntigravityRequest,
    rejected: RefreshCredentialGeneration,
    rejected_refreshed_at_unix: u64,
    admitted_grant: DerivedGrant,
    purpose: OAuthPurpose,
}

impl<P, U> OpenAiBroker<P, U>
where
    P: BrokerLeaseProvider + 'static,
    U: BrokerUpstreamTransport + 'static,
{
    pub(super) fn antigravity_oauth_credential(
        &self,
        lease: P::Lease,
        purpose: &OAuthPurpose,
    ) -> Result<AntigravityOAuthCredential, BrokerRequestError> {
        match purpose {
            OAuthPurpose::Operation { .. } => self
                .antigravity_adapter
                .credential_from_lease(lease)
                .map_err(map_adapter_error),
            OAuthPurpose::AntigravityLogin => self
                .antigravity_adapter
                .login_credential_from_lease(lease)
                .map_err(map_adapter_error),
            OAuthPurpose::CodexLogin | OAuthPurpose::ClaudeLogin => Err(BrokerRequestError::Denied),
        }
    }

    pub(super) async fn execute_antigravity_swap(
        &self,
        host: RouteHost,
        request: ValidatedGuestRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let host_name = host.as_str();
        // Check raw and percent-decoded query params before any lease or
        // untouched-forward decision: a placeholder in the query fails closed.
        if query_carries_placeholder_tag(request.query.as_deref()) {
            return Err(BrokerRequestError::InvalidRequest);
        }
        let presented = Presented::of_for(&request.headers, SwapCarrier::AntigravityBearer);
        let validated = self
            .antigravity_adapter
            .validate_request(
                &request.method,
                &request.path,
                request.query.as_deref(),
                request.headers,
                request.body,
            )
            .map_err(map_adapter_error)?;
        let presented = match presented {
            Presented::DisallowedPlaceholder => return Err(BrokerRequestError::InvalidRequest),
            Presented::Conflict => return Ok(credential_conflict_response()),
            Presented::Foreign => return self.forward_antigravity(host_name, validated).await,
            Presented::Placeholder(placeholder) => placeholder,
        };
        if self.placeholders.known_foreign(&request.slot, &presented) {
            return self.forward_antigravity(host_name, validated).await;
        }
        let operation = BrokerOperationId::parse(crate::antigravity::OPERATION)
            .map_err(|_| BrokerRequestError::InvalidRequest)?;
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
        if lease.placeholder_failed() {
            drop(lease);
            return Err(BrokerRequestError::AuthorityUnavailable);
        }
        self.placeholders
            .remember(&request.slot, lease.placeholder());
        if !lease
            .placeholder()
            .is_some_and(|ours| ours.ct_eq(&presented))
        {
            drop(lease);
            return self.forward_antigravity(host_name, validated).await;
        }
        // Decoded `key` or `access_token` query param beside our swapped Bearer
        // header is a credential conflict (`400`).
        if query_has_google_credential_param(request.query.as_deref()) {
            return Ok(credential_conflict_response());
        }
        // Strict `POST ^/v1internal:[A-Za-z][A-Za-z0-9_]*$` grammar: our
        // placeholder outside that pinned surface is refused `403` and never
        // swaps or forwards.
        if !validated.is_swappable_endpoint() {
            return Ok(path_not_served_response(host_name));
        }
        self.serve_antigravity(
            host_name,
            request.request_id,
            OAuthPurpose::Operation {
                slot: request.slot,
                operation,
                route: request.route,
            },
            lease,
            validated,
        )
        .await
    }

    async fn serve_antigravity(
        &self,
        host: &'static str,
        request_id: Uuid,
        purpose: OAuthPurpose,
        lease: P::Lease,
        validated: ValidatedAntigravityRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let (prepared, retry) = self
            .prepare_antigravity(host, request_id, purpose, lease, validated)
            .await?;
        let (mut response, mut policy) = self.send_antigravity(prepared).await?;
        if response.status() == StatusCode::UNAUTHORIZED
            && forced_refresh_due(retry.rejected_refreshed_at_unix, current_unix_time()?)
        {
            let whole;
            (response, whole) = hold_rejection(response).await;
            if whole {
                match self.prepare_antigravity_retry(request_id, retry).await {
                    Ok(prepared) => (response, policy) = self.send_antigravity(prepared).await?,
                    Err(failure) => after_failed_refresh(failure, ANTIGRAVITY_REFRESH_PROVIDER)?,
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
                redactor: Some(ProviderStreamingResponse::Antigravity(redactor)),
                finished: false,
            }),
        ))
    }

    async fn prepare_antigravity(
        &self,
        host: &'static str,
        request_id: Uuid,
        purpose: OAuthPurpose,
        lease: P::Lease,
        validated: ValidatedAntigravityRequest,
    ) -> Result<(PreparedAntigravityRequest, AntigravityRetry), BrokerRequestError> {
        let admitted_grant = lease.grant().clone();
        let leased = refresh_generation(&lease);
        let credential = self.antigravity_oauth_credential(lease, &purpose)?;
        let (credential, sent) = if credential.should_refresh(current_unix_time()?) {
            drop(credential);
            self.fresh_oauth_credential(
                request_id,
                &purpose,
                |lease| self.antigravity_oauth_credential(lease, &purpose),
                None,
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await?
        } else {
            (credential, leased)
        };
        let rejected_refreshed_at_unix = credential.refreshed_at_unix();
        let prepared = self
            .antigravity_adapter
            .prepare_credential(host, &credential, validated.clone())
            .map_err(map_adapter_error)?;
        Ok((
            prepared,
            AntigravityRetry {
                host,
                request: validated,
                rejected: sent,
                rejected_refreshed_at_unix,
                admitted_grant,
                purpose,
            },
        ))
    }

    async fn prepare_antigravity_retry(
        &self,
        request_id: Uuid,
        retry: AntigravityRetry,
    ) -> Result<PreparedAntigravityRequest, RetryFailure> {
        let AntigravityRetry {
            host,
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
                |lease| self.antigravity_oauth_credential(lease, &purpose),
                Some(&rejected),
                &admitted_grant,
                ACCESS_TOKEN_REFRESH_WINDOW_SECONDS,
            )
            .await?;
        Ok(self
            .antigravity_adapter
            .prepare_credential(host, &credential, request)
            .map_err(map_adapter_error)?)
    }

    async fn send_antigravity(
        &self,
        prepared: PreparedAntigravityRequest,
    ) -> Result<(BrokerUpstreamResponse, PreparedAntigravityResponse), BrokerRequestError> {
        let (method, target, headers, body, policy) = prepared.into_parts();
        let response = timing::timed(
            Phase::Provider,
            self.upstream.execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
                body_stream: None,
                pinned: None,
            }),
        )
        .await
        .map_err(map_upstream_error)?;
        Ok((response, policy))
    }

    async fn forward_antigravity(
        &self,
        host: &'static str,
        validated: ValidatedAntigravityRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        let (method, target, headers, body) =
            validated.into_forwarded(host).map_err(map_adapter_error)?;
        self.forward(
            method,
            target,
            &headers,
            body,
            None,
            crate::antigravity::MAX_RESPONSE_BYTES,
        )
        .await
    }
}

fn path_not_served_response(host: &'static str) -> BrokerHttpResponse {
    let refusal = Refusal::PathNotServed;
    let mut headers = HeaderMap::new();
    for (name, value) in refusal.headers() {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    let body = Bytes::from(refusal.body(Some(RefusalProvider::Antigravity), Some(host)));
    BrokerHttpResponse::new(
        StatusCode::FORBIDDEN,
        headers,
        Box::pin(stream::once(async move { Ok(body) })),
    )
}
