//! Browser approval for the standard OAuth 2.0 device authorization grant.
//!
//! This is a permanent raw identity-protocol route rather than a Codewire
//! control-plane API. A live browser session is the only accepted credential,
//! and the standard OIDC provider owns all device authorization state.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router, middleware};
use codewire_oidc::{ErrorCode as OAuthErrorCode, Provider, Subject};
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct DeviceVerificationInput {
    user_code: String,
}

#[derive(Serialize)]
struct DeviceVerificationBody {
    approved: bool,
}

async fn approve_device(
    State(provider): State<Provider>,
    user: AuthUser,
    ValidatedJson(input): ValidatedJson<DeviceVerificationInput>,
) -> Result<Json<DeviceVerificationBody>, AppError> {
    let user_code = input.user_code.trim().to_uppercase();
    let request = provider
        .lookup_user_code(&user_code)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to look up device authorization");
            AppError::InternalMsg("Failed to look up device authorization".into())
        })?;
    if request.is_none() {
        return Err(AppError::NotFound("Invalid or expired device code".into()));
    }

    provider
        .approve_device(&user_code, Subject(user.user_id), None)
        .await
        .map_err(|error| {
            if error.code == OAuthErrorCode::InvalidRequest {
                AppError::BadRequest("Device code already used".into())
            } else {
                tracing::error!(%error, "failed to approve device authorization");
                AppError::InternalMsg("Failed to approve device authorization".into())
            }
        })?;

    Ok(Json(DeviceVerificationBody { approved: true }))
}

pub fn router(provider: Provider, auth: AuthState) -> Router {
    Router::new()
        .route("/api/oauth/device_verification", post(approve_device))
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth))
        .with_state(provider)
}
