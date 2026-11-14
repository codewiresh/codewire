//! The sign-up rate limit (#3297). An email or provider sign-up counts
//! against the site-wide [`rate_limit::SIGNUP`] once it has passed its own
//! checks (the fields, Turnstile, the access-request reason) and before it
//! looks up or creates the account. A malformed request or a failed
//! challenge counts nothing, so junk traffic can't use up everyone's
//! allowance, and a refused sign-up costs no account lookup and no password
//! hash. On an invite-only server an invited sign-up doesn't count: the
//! invitation bounds it, so uninvited traffic can't lock invitees out. The
//! count is the admin's global value, else the default. A per-address limit
//! follows once nothing but the edge and the dashboard can write the counted
//! address.
//!
//! A refusal is 429 `rate_limited`, naming the limit and when it resets, with
//! `Retry-After`. A database error refuses with 503, never lets a sign-up
//! through (#3256).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use codewire_server_core::{AppError, rate_limit};
use sqlx::PgPool;

/// The one subject the site-wide limit counts under.
const SITE: &str = "all";

/// Why a sign-up was not counted in: the limit was reached, or it couldn't be
/// read. Its response is what the IdP sends instead of creating the account.
#[derive(Debug)]
pub(crate) enum Refusal {
    Limited(rate_limit::Decision),
    Unavailable,
}

/// Counts one sign-up against the site-wide limit.
pub(crate) async fn take(pool: &PgPool) -> Result<(), Refusal> {
    let decision = async {
        let mut connection = pool.acquire().await?;
        rate_limit::take(&mut connection, &rate_limit::SIGNUP, SITE).await
    }
    .await;
    match decision {
        Ok(decision) if decision.allowed => Ok(()),
        Ok(decision) => {
            tracing::warn!(
                limit = rate_limit::SIGNUP.name,
                max = decision.max,
                "sign-up refused by its rate limit"
            );
            Err(Refusal::Limited(decision))
        }
        Err(error) => {
            tracing::error!(%error, limit = rate_limit::SIGNUP.name, "sign-up limit unavailable");
            Err(Refusal::Unavailable)
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Limited(decision) => {
                let mut response = AppError::Coded {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "rate_limited",
                    detail: decision.refusal("sign-ups", &rate_limit::SIGNUP).into(),
                }
                .into_response();
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from(decision.retry_after_secs(chrono::Utc::now())),
                );
                response
            }
            Refusal::Unavailable => AppError::Coded {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "rate_limit_unavailable",
                detail: "Sign-up is temporarily unavailable; try again shortly".into(),
            }
            .into_response(),
        }
    }
}
