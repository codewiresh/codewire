//! The sign-up rate limits (#3297). An email or provider sign-up counts
//! against [`rate_limit::SIGNUP_ADDRESS`] for its client address, then the
//! site-wide [`rate_limit::SIGNUP`], once it has passed its own checks (the
//! fields, Turnstile, the access-request reason) and before it looks up or
//! creates the account. A malformed request or a failed challenge counts
//! nothing, so junk traffic can't use up anyone's allowance, and a refused
//! sign-up costs no account lookup and no password hash. A sign-up that waits
//! for review counts like any other: it creates an account and sends mail. On
//! an invite-only server an invited sign-up doesn't count: the invitation
//! bounds it, so uninvited traffic can't lock invitees out. Each count is the
//! admin's global value, else the default.
//!
//! The address is the last `X-Forwarded-For` hop, which only the edge and the
//! dashboard can write: the IdP's NetworkPolicy admits no other caller, and
//! the dashboard forwards the hop its own edge wrote. It is counted as a keyed
//! hash of the unit an abuser controls ([`crate::client_address`]). The
//! address is checked first, so one address's refused sign-ups never spend
//! the site's allowance. A sign-up with no address, which the hosted edge
//! never sends, counts against the site-wide limit only.
//!
//! A refusal is 429 `rate_limited`, naming the limit and when it resets, with
//! `Retry-After`. A database error refuses with 503, never lets a sign-up
//! through (#3256).

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use codewire_server_core::client_address::forwarded_client_ip;
use codewire_server_core::{AppError, rate_limit};
use sqlx::PgConnection;

use crate::auth_session::SessionAuthState;

/// The one subject the site-wide limit counts under.
const SITE: &str = "all";

/// Why a sign-up was not counted in: a limit was reached, or it couldn't be
/// read. Its response is what the IdP sends instead of creating the account.
#[derive(Debug)]
pub(crate) enum Refusal {
    Limited {
        limit: &'static rate_limit::Limit,
        decision: rate_limit::Decision,
    },
    Unavailable,
}

/// Counts one sign-up from the client `headers` name against its address's
/// limit, then the site-wide one.
pub(crate) async fn take(state: &SessionAuthState, headers: &HeaderMap) -> Result<(), Refusal> {
    let address =
        crate::client_address::unit_hash(&state.client_address_key, forwarded_client_ip(headers));
    let mut connection = state.pool.acquire().await.map_err(|error| {
        tracing::error!(%error, "sign-up limit unavailable");
        Refusal::Unavailable
    })?;
    if let Some(address) = address {
        count(&mut connection, &rate_limit::SIGNUP_ADDRESS, &address).await?;
    }
    count(&mut connection, &rate_limit::SIGNUP, SITE).await
}

async fn count(
    connection: &mut PgConnection,
    limit: &'static rate_limit::Limit,
    subject: &str,
) -> Result<(), Refusal> {
    match rate_limit::take(connection, limit, subject).await {
        Ok(decision) if decision.allowed => Ok(()),
        Ok(decision) => {
            tracing::warn!(
                limit = limit.name,
                max = decision.max,
                "sign-up refused by its rate limit"
            );
            Err(Refusal::Limited { limit, decision })
        }
        Err(error) => {
            tracing::error!(%error, limit = limit.name, "sign-up limit unavailable");
            Err(Refusal::Unavailable)
        }
    }
}

/// What a refusal says the limit counts: "at most 30 sign-ups from one address
/// an hour".
fn counted(limit: &rate_limit::Limit) -> &'static str {
    if limit.name == rate_limit::SIGNUP_ADDRESS.name {
        "sign-ups from one address"
    } else {
        "sign-ups"
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Limited { limit, decision } => {
                let mut response = AppError::Coded {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "rate_limited",
                    detail: decision.refusal(counted(limit), limit).into(),
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
