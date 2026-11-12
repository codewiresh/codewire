//! The emailed link confirmation (#4062): `POST /api/auth/oauth/link/pending`
//! reads a `link_confirm` row for the dashboard's `/login/link` page, and
//! `POST /api/auth/oauth/link/confirm` uses it from the browser that started
//! the sign-in.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use codewire_server_core::auth::hash_session_token;
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{OAuthState, Provider, same_secret, valid_handle};
use crate::auth_session::{hex_id, log_audit_in, request_info};
use crate::email_password::send_provider_linked_email;

pub(super) fn router() -> Router<OAuthState> {
    Router::new()
        .route("/api/auth/oauth/link/pending", post(pending_link))
        .route("/api/auth/oauth/link/confirm", post(confirm_link))
}

#[derive(Deserialize, JsonSchema)]
struct LinkTokenRequest {
    token: String,
}

#[derive(Deserialize, JsonSchema)]
struct ConfirmLinkRequest {
    token: String,
    /// The requester secret from the browser's `/login/link` cookie.
    #[serde(default)]
    requester: String,
}

#[derive(Serialize)]
struct LinkBody {
    provider: &'static str,
    /// The provider account: GitHub login or Google email.
    account: String,
}

#[derive(Deserialize)]
struct LinkIdentity {
    subject: String,
    email: String,
    #[serde(default)]
    account: String,
}

impl LinkIdentity {
    fn account(&self) -> String {
        if self.account.is_empty() {
            self.email.clone()
        } else {
            self.account.clone()
        }
    }
}

fn link_expired() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "oauth_link_expired",
        detail: "This link has expired or was already used.".into(),
    }
}

fn link_refused() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "oauth_link_refused",
        detail: "This account can't be connected right now.".into(),
    }
}

/// The confirmation was opened in a browser other than the one that started
/// the sign-in. Nothing is used up.
fn link_wrong_browser() -> AppError {
    AppError::Coded {
        status: StatusCode::PRECONDITION_FAILED,
        code: "oauth_link_wrong_browser",
        detail: "Open this link in the browser where you started signing in.".into(),
    }
}

fn link_taken() -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "oauth_link_taken",
        detail: "This provider account is connected to another Codewire account.".into(),
    }
}

/// `POST /api/auth/oauth/link/pending`: which provider a live confirmation
/// would connect, for the dashboard's confirmation page. It reads only, so a
/// mail scanner that opens the emailed link uses nothing up.
async fn pending_link(
    State(state): State<OAuthState>,
    ValidatedJson(request): ValidatedJson<LinkTokenRequest>,
) -> Result<Response, AppError> {
    if !valid_handle(&request.token) {
        return Err(link_expired());
    }
    let (provider, identity): (String, serde_json::Value) = sqlx::query_as(
        r#"
        SELECT provider, provider_identity FROM oauth_states
         WHERE token_hash = $1 AND intent = 'link_confirm' AND expires_at > NOW()
        "#,
    )
    .bind(hash_session_token(&request.token))
    .fetch_optional(&state.session.pool)
    .await?
    .ok_or_else(link_expired)?;
    let provider = Provider::parse(&provider).ok_or_else(link_expired)?;
    let identity: LinkIdentity = serde_json::from_value(identity).map_err(|_| link_expired())?;
    Ok(Json(LinkBody {
        provider: provider.as_str(),
        account: identity.account(),
    })
    .into_response())
}

#[derive(sqlx::FromRow)]
struct ClaimedLink {
    id: String,
    user_id: String,
    provider: String,
    provider_identity: serde_json::Value,
    requester_hash: Option<String>,
    live: bool,
}

#[derive(sqlx::FromRow)]
struct LinkOwner {
    email: String,
    refused: bool,
}

/// `POST /api/auth/oauth/link/confirm`: the account's own address confirmed
/// the link, from the browser that started the sign-in. The emailed token
/// proves only that someone reads the account's mail; the requester secret,
/// which only the starting browser holds, proves it is the person who signed
/// in with the provider. Without it nothing changes and the token stays
/// usable. With it the token is used up; the account must still be enabled,
/// not locked out and own the address the identity proved, and the identity
/// must not belong to anyone else. It links and audits, and creates no
/// session: the person then signs in with the provider, through every gate
/// including the second factor.
async fn confirm_link(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    ValidatedJson(request): ValidatedJson<ConfirmLinkRequest>,
) -> Result<Response, AppError> {
    if !valid_handle(&request.token) {
        return Err(link_expired());
    }
    let pool = &state.session.pool;
    let mut tx = pool.begin().await?;
    // The row lock makes the use single even when two confirmations race:
    // the second waits, then finds the row gone.
    let claimed = sqlx::query_as::<_, ClaimedLink>(
        r#"
        SELECT id, user_id, provider, provider_identity, requester_hash,
               expires_at > NOW() AS live
          FROM oauth_states
         WHERE token_hash = $1 AND intent = 'link_confirm'
           FOR UPDATE
        "#,
    )
    .bind(hash_session_token(&request.token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(claimed) = claimed.filter(|claimed| claimed.live) else {
        tx.commit().await?;
        return Err(link_expired());
    };
    let requester_matches = valid_handle(&request.requester)
        && claimed.requester_hash.as_deref().is_some_and(|stored| {
            same_secret(
                stored.as_bytes(),
                hash_session_token(&request.requester).as_bytes(),
            )
        });
    if !requester_matches {
        tx.commit().await?;
        return Err(link_wrong_browser());
    }
    sqlx::query("DELETE FROM oauth_states WHERE id = $1")
        .bind(&claimed.id)
        .execute(&mut *tx)
        .await?;
    let provider = Provider::parse(&claimed.provider).ok_or_else(link_expired)?;
    let identity: LinkIdentity =
        serde_json::from_value(claimed.provider_identity).map_err(|_| link_expired())?;

    // The account lock first, as disablement takes it.
    let owner: Option<LinkOwner> = sqlx::query_as(
        r#"
        SELECT email,
               (NOT enabled OR COALESCE(locked_until > NOW(), false)) AS refused
          FROM users
         WHERE id = $1
           FOR UPDATE
        "#,
    )
    .bind(&claimed.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(owner) = owner else {
        tx.commit().await?;
        return Err(link_expired());
    };
    if owner.refused || owner.email.to_lowercase() != identity.email.to_lowercase() {
        // Used up either way: a new sign-in asks again.
        tx.commit().await?;
        return Err(link_refused());
    }
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = $1 AND account_id = $2",
    )
    .bind(provider.as_str())
    .bind(&identity.subject)
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        Some(user_id) if user_id == claimed.user_id => {
            tx.commit().await?;
            return Ok(Json(LinkBody {
                provider: provider.as_str(),
                account: identity.account(),
            })
            .into_response());
        }
        Some(_) => {
            tx.commit().await?;
            return Err(link_taken());
        }
        None => {}
    }
    sqlx::query(
        r#"
        INSERT INTO accounts (id, user_id, provider_id, account_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(hex_id())
    .bind(&claimed.user_id)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation())
        {
            link_taken()
        } else {
            tracing::error!(%error, "failed to link OAuth identity");
            AppError::InternalMsg("Failed to connect the account".into())
        }
    })?;
    let (ip, ua) = request_info(&headers);
    log_audit_in(
        &mut tx,
        "user.oauth.linked",
        &claimed.user_id,
        &ip,
        &ua,
        json!({
            "provider": provider.as_str(),
            "provider_subject": &identity.subject,
            "provider_email": &identity.email,
            "provider_account": identity.account(),
            "automatic": false,
            "confirmed_by": "email",
        }),
        "info",
    )
    .await?;
    tx.commit().await?;

    if state.session.email.is_configured() {
        let settings_url = format!(
            "{}/settings/",
            state.session.frontend_url.trim_end_matches('/')
        );
        if let Err(error) = send_provider_linked_email(
            &state.session.email,
            &owner.email,
            provider.label(),
            &settings_url,
        )
        .await
        {
            tracing::error!(%error, user_id = %claimed.user_id, "failed to send provider link notice");
        }
    }
    Ok(Json(LinkBody {
        provider: provider.as_str(),
        account: identity.account(),
    })
    .into_response())
}
