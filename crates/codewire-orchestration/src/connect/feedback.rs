//! Connect-RPC adapter for `cw feedback` (#4061).
//!
//! Mount with [`connect_auth_layer`]: SubmitFeedback needs no credential and
//! uses one that is presented, so the handler reads the caller as optional.

use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_proto::codewire::v1::{
    FEEDBACK_SERVICE_SERVICE_NAME, FeedbackPlacement, FeedbackService, SubmitFeedbackRequest,
    SubmitFeedbackResponse,
};
use codewire_server_core::auth::{AuthState, AuthUser};
use codewire_server_core::client_address::forwarded_client_ip;
use codewire_server_core::connect::{ConnectAuthLayer, rpc_app_error, wire_error};
use codewire_server_core::connect_error::ConnectError as RenderedConnectError;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::api::feedback::{
    ClientAddressKey, NewFeedback, Placement, SubmitFeedbackError, submit_feedback,
};

/// The one method of the service, which takes anonymous callers.
pub fn submit_feedback_method() -> String {
    format!("/{FEEDBACK_SERVICE_SERVICE_NAME}/SubmitFeedback")
}

/// The service's auth: an authenticated mount on which SubmitFeedback also
/// admits a request that presents no credential.
pub fn connect_auth_layer(auth: AuthState) -> ConnectAuthLayer {
    ConnectAuthLayer::authenticated(auth).allow_anonymous([submit_feedback_method()])
}

pub fn router(pool: PgPool, key: ClientAddressKey) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(FeedbackConnectService { pool, key }))
}

struct FeedbackConnectService {
    pool: PgPool,
    key: ClientAddressKey,
}

#[allow(refining_impl_trait)]
impl FeedbackService for FeedbackConnectService {
    async fn submit_feedback(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SubmitFeedbackRequest>,
    ) -> ServiceResult<SubmitFeedbackResponse> {
        let user = ctx.extensions().get::<AuthUser>().cloned();
        let address = forwarded_client_ip(ctx.headers());
        let request = request.view();
        let placement = match request.placement.as_known() {
            Some(FeedbackPlacement::FEEDBACK_PLACEMENT_LOCAL) => Some(Placement::Local),
            Some(FeedbackPlacement::FEEDBACK_PLACEMENT_CLOUD) => Some(Placement::Cloud),
            _ => None,
        };
        let feedback = NewFeedback {
            message: request.message,
            cli_version: request.cli_version,
            os: request.os,
            arch: request.arch,
            placement,
            environment_id: request.environment_id,
            org_id: request.org_id,
        };
        let stored = submit_feedback(&self.pool, &self.key, user.as_ref(), address, &feedback)
            .await
            .map_err(|error| match error {
                SubmitFeedbackError::Rejected(error) => rpc_app_error(&error, &ctx),
                SubmitFeedbackError::Limited { scope, retry_after } => {
                    let error = codewire_server_core::AppError::Coded {
                        status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                        code: "rate_limited",
                        detail: SubmitFeedbackError::limited_message(scope, retry_after).into(),
                    };
                    let request_id = ctx
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok());
                    wire_error(
                        &RenderedConnectError::from_app_error(&error, request_id)
                            .with_retry_delay(retry_after),
                    )
                }
            })?;
        connectrpc::Response::ok(SubmitFeedbackResponse {
            id: stored.id,
            created_at: Some(Timestamp::from_unix(
                stored.created_at.timestamp(),
                stored.created_at.timestamp_subsec_nanos() as i32,
            ))
            .into(),
            signed_in: stored.signed_in,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_submit_feedback_takes_anonymous_callers() {
        assert_eq!(
            submit_feedback_method(),
            "/codewire.v1.FeedbackService/SubmitFeedback"
        );
    }
}
