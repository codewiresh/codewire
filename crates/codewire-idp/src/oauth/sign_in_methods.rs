//! Sign-in methods in Settings (#4062): a signed-in account lists, connects
//! and disconnects GitHub or Google. Every route takes the account controls'
//! boundary: the session cookie and never a bearer, the account it names, an
//! enabled account and the dashboard's two-factor boundary (an enrolled
//! factor, or setup skipped by this browser session), so nothing is linked
//! before the second factor.
//!
//! - `GET /api/auth/oauth/identities?account_id=` names the configured
//!   providers, whether the account has a password, and its identities.
//! - `POST /api/auth/oauth/identities/link` (exact Origin) writes a
//!   single-use `link` row bound to the account and answers the provider's
//!   authorize URL with the state cookie set; the dashboard forwards both. No
//!   GET starts a link, so another site cannot start one.
//! - The callback hands a claimed `link` row to [`finish`]. It links only if
//!   the browser's session still belongs to that account, which is still
//!   enabled, not locked out and past the two-factor boundary, and only if
//!   the identity belongs to no one else. It creates no session.
//! - `POST /api/auth/oauth/identities/unlink` (exact Origin) removes an
//!   identity only when another way to sign in remains.
//!
//! A link and an unlink are audited (`user.oauth.linked`,
//! `user.oauth.unlinked`) and the account's address is emailed a notice.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Json, Router};
use chrono::NaiveDateTime;
use codewire_server_core::AppError;
use codewire_server_core::auth::hash_session_token;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction};

use super::{
    OAuthState, Provider, ProviderIdentity, STATE_COOKIE, STATE_COOKIE_PATH, STATE_TTL_SECS,
    cookie, hex_token, pkce_challenge, pkce_verifier, see_other, sweep_expired,
};
use crate::auth_session::{
    STATEMENT_CEILING, bounded_transaction_within, cookie_digest, exact_origin, format_time,
    hex_id, lock_account_actor, log_audit_in, private, request_info, unavailable, valid_id,
};
use crate::email_password::{send_provider_connected_email, send_provider_disconnected_email};

/// Where Settings shows this section.
const SETTINGS_PATH: &str = "/settings/";
const SETTINGS_FRAGMENT: &str = "sign-in-methods";
/// The provider account (GitHub login or Google email) the identity row `a`
/// of `accounts` was linked as. No column holds it (the design keeps the
/// provider's details in the audit log), so it is the latest audit row of a
/// link from Settings, an email match or confirmation, or a provider sign-up
/// that names this identity; NULL when none does.
pub(crate) const LINKED_ACCOUNT_SQL: &str = r#"(
    SELECT l.metadata->>'provider_account'
      FROM audit_logs l
     WHERE l.user_id = a.user_id
       AND l.action IN ('user.oauth.linked', 'user.signup', 'user.signup.access_requested')
       AND l.metadata->>'provider' = a.provider_id
       AND l.metadata->>'provider_subject' = a.account_id
     ORDER BY l."timestamp" DESC
     LIMIT 1)"#;

pub(super) fn router() -> Router<OAuthState> {
    Router::new()
        .route("/api/auth/oauth/identities", axum::routing::get(list))
        .route(
            "/api/auth/oauth/identities/link",
            axum::routing::post(start_link),
        )
        .route(
            "/api/auth/oauth/identities/unlink",
            axum::routing::post(unlink),
        )
}

/// The metadata an audit row about one identity carries, so Settings can
/// name the provider account without a column for it.
pub(super) fn identity_audit(provider: Provider, identity: &ProviderIdentity) -> serde_json::Value {
    json!({
        "provider": provider.as_str(),
        "provider_subject": &identity.subject,
        "provider_email": &identity.email,
        "provider_account": &identity.account,
    })
}

fn provider_unavailable() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "oauth_provider_unavailable",
        detail: "This provider isn't available.".into(),
    }
}

fn account_locked() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "account_locked",
        detail: "The account is temporarily locked.".into(),
    }
}

fn already_connected() -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "oauth_provider_connected",
        detail: "This provider is already connected.".into(),
    }
}

fn not_connected() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "oauth_provider_not_connected",
        detail: "This provider isn't connected.".into(),
    }
}

fn last_method() -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "oauth_last_sign_in_method",
        detail: "Add a password or connect another provider first.".into(),
    }
}

fn database(error: sqlx::Error) -> AppError {
    tracing::error!(%error, "sign-in methods database failure");
    unavailable()
}

/// Lock the account behind this browser's session, as the account controls
/// do: the account row, then this session, then a clock check. A locked-out
/// account is refused too.
async fn lock_actor(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    account_id: &str,
    mutating: bool,
) -> Result<(), AppError> {
    let digest = cookie_digest(headers)?;
    if !valid_id(account_id) {
        return Err(AppError::BadRequest("Invalid account".into()));
    }
    bounded_transaction_within(tx, STATEMENT_CEILING).await?;
    lock_account_actor(tx, &digest, account_id, mutating).await?;
    let locked: bool = sqlx::query_scalar(
        "SELECT COALESCE(locked_until > clock_timestamp()::timestamp, false) \
         FROM users WHERE id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(database)?;
    if locked {
        return Err(account_locked());
    }
    Ok(())
}

fn configured_names(state: &OAuthState) -> Vec<&'static str> {
    state
        .providers
        .configured()
        .into_iter()
        .map(Provider::as_str)
        .collect()
}

// --- GET /api/auth/oauth/identities ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQuery {
    account_id: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct IdentityRow {
    provider: String,
    /// The provider account it was linked as (GitHub login or Google email),
    /// when an audit row still names it.
    account: Option<String>,
    #[serde(serialize_with = "utc_time")]
    linked_at: NaiveDateTime,
}

#[derive(Serialize)]
struct MethodsBody {
    account_id: String,
    providers: Vec<&'static str>,
    password: bool,
    identities: Vec<IdentityRow>,
}

fn utc_time<S: serde::Serializer>(time: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_time(*time))
}

async fn list(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    query: Result<Query<AccountQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let result = async {
        let Query(query) = query.map_err(|_| AppError::BadRequest("Invalid account".into()))?;
        let providers = configured_names(&state);
        let mut tx = state.session.pool.begin().await.map_err(database)?;
        lock_actor(&mut tx, &headers, &query.account_id, false).await?;
        let password = has_password(&mut tx, &query.account_id).await?;
        let identities: Vec<IdentityRow> = sqlx::query_as(&format!(
            "SELECT a.provider_id AS provider, {LINKED_ACCOUNT_SQL} AS account, \
                    COALESCE(a.created_at, NOW()::timestamp) AS linked_at \
               FROM accounts a \
              WHERE a.user_id = $1 AND a.provider_id = ANY($2) \
              ORDER BY array_position($2, a.provider_id)"
        ))
        .bind(&query.account_id)
        .bind(&providers)
        .fetch_all(&mut *tx)
        .await
        .map_err(database)?;
        tx.commit().await.map_err(database)?;
        Ok::<_, AppError>(MethodsBody {
            account_id: query.account_id,
            providers,
            password,
            identities,
        })
    };
    match result.await {
        Ok(body) => private(Json(body)),
        Err(error) => private(error),
    }
}

async fn has_password(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE user_id = $1 \
         AND provider_id = 'credential' AND password IS NOT NULL)",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(database)
}

// --- POST /api/auth/oauth/identities/link ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderRequest {
    account_id: String,
    provider: String,
}

#[derive(Serialize)]
struct LinkStarted {
    /// The provider's authorize URL, where the dashboard sends the browser.
    location: String,
}

async fn start_link(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    request: Result<Json<ProviderRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let result = async {
        exact_origin(&headers, &state.session.frontend_url)?;
        let Json(request) = request.map_err(|_| AppError::BadRequest("Invalid request".into()))?;
        let provider = Provider::parse(&request.provider)
            .filter(|provider| state.providers.is_configured(*provider))
            .ok_or_else(provider_unavailable)?;
        let raw_state = hex_token();
        let verifier = pkce_verifier();
        let nonce = (provider == Provider::Google).then(hex_token);
        let location = state
            .providers
            .authorize_url(
                provider,
                &state.redirect_uri(provider),
                &raw_state,
                &pkce_challenge(&verifier),
                nonce.as_deref(),
            )
            .ok_or_else(provider_unavailable)?;

        let mut tx = state.session.pool.begin().await.map_err(database)?;
        lock_actor(&mut tx, &headers, &request.account_id, true).await?;
        let connected: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = $2)",
        )
        .bind(&request.account_id)
        .bind(provider.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(database)?;
        if connected {
            return Err(already_connected());
        }
        sweep_expired(&mut *tx).await.map_err(database)?;
        // One link in flight per account and provider: a new start replaces
        // the old, so a signed-in account cannot fill the table.
        sqlx::query(
            "DELETE FROM oauth_states WHERE intent = 'link' AND user_id = $1 AND provider = $2",
        )
        .bind(&request.account_id)
        .bind(provider.as_str())
        .execute(&mut *tx)
        .await
        .map_err(database)?;
        sqlx::query(
            r#"
            INSERT INTO oauth_states
                (id, token_hash, provider, intent, user_id, pkce_verifier, nonce, expires_at)
            VALUES ($1, $2, $3, 'link', $4, $5, $6,
                    NOW() + ($7::bigint * interval '1 second'))
            "#,
        )
        .bind(hex_id())
        .bind(hash_session_token(&raw_state))
        .bind(provider.as_str())
        .bind(&request.account_id)
        .bind(&verifier)
        .bind(&nonce)
        .bind(STATE_TTL_SECS)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
        tx.commit().await.map_err(database)?;
        Ok::<_, AppError>((location, raw_state))
    };
    match result.await {
        Ok((location, raw_state)) => {
            let mut response = private(Json(LinkStarted { location }));
            response.headers_mut().append(
                axum::http::header::SET_COOKIE,
                cookie(
                    STATE_COOKIE,
                    &raw_state,
                    STATE_COOKIE_PATH,
                    STATE_TTL_SECS,
                    state.session.secure,
                ),
            );
            response
        }
        Err(error) => private(error),
    }
}

// --- the callback of a `link` round trip ---

/// How a link round trip ends, as Settings shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LinkResult {
    Connected,
    /// The person cancelled at the provider.
    Cancelled,
    /// The state was missing, used or expired.
    Expired,
    /// The provider has no verified email for the account.
    UnverifiedEmail,
    /// The provider is not configured.
    Unavailable,
    /// The identity is linked to another Codewire account.
    Taken,
    /// The account already has another identity of this provider.
    AlreadyConnected,
    /// The browser's session no longer belongs to the account that started
    /// the link, or the account may no longer sign in.
    SessionChanged,
    Failed,
}

impl LinkResult {
    fn code(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::UnverifiedEmail => "unverified_email",
            Self::Unavailable => "unavailable",
            Self::Taken => "taken",
            Self::AlreadyConnected => "already_connected",
            Self::SessionChanged => "session_changed",
            Self::Failed => "failed",
        }
    }
}

/// Back to Settings with a fixed code the dashboard maps to its message.
pub(super) fn settings_landing(
    result: LinkResult,
    provider: Provider,
    cookies: Vec<HeaderValue>,
) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("sign_in_method", result.code())
        .append_pair("provider", provider.as_str())
        .finish();
    see_other(
        &format!("{SETTINGS_PATH}?{query}#{SETTINGS_FRAGMENT}"),
        cookies,
    )
}

/// Link `identity` to `account_id` if this browser's session still belongs
/// to it, then land on Settings. No session is created.
pub(super) async fn finish(
    state: &OAuthState,
    provider: Provider,
    account_id: &str,
    identity: &ProviderIdentity,
    headers: &HeaderMap,
    cookies: Vec<HeaderValue>,
) -> Response {
    let result = match link(state, provider, account_id, identity, headers).await {
        Ok(Some(email)) => {
            notify(state, provider, &identity.account, &email, true).await;
            LinkResult::Connected
        }
        Ok(None) => LinkResult::Connected,
        Err(result) => result,
    };
    settings_landing(result, provider, cookies)
}

/// Commit the link and return the account's address for the notice, or
/// `None` when the identity was already linked to this account.
async fn link(
    state: &OAuthState,
    provider: Provider,
    account_id: &str,
    identity: &ProviderIdentity,
    headers: &HeaderMap,
) -> Result<Option<String>, LinkResult> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to link a provider from Settings");
        LinkResult::Failed
    };
    let mut tx = state.session.pool.begin().await.map_err(failed)?;
    // The row was bound to the account when the link started; the session
    // may have been revoked, replaced by another account's or disabled since.
    lock_actor(&mut tx, headers, account_id, true)
        .await
        .map_err(|error| match error.into_response().status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => LinkResult::SessionChanged,
            _ => LinkResult::Failed,
        })?;
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = $1 AND account_id = $2",
    )
    .bind(provider.as_str())
    .bind(&identity.subject)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?;
    match owner {
        Some(owner) if owner == account_id => return Ok(None),
        Some(_) => return Err(LinkResult::Taken),
        None => {}
    }
    let connected: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = $2)",
    )
    .bind(account_id)
    .bind(provider.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(failed)?;
    if connected {
        return Err(LinkResult::AlreadyConnected);
    }
    let inserted = sqlx::query(
        r#"
        INSERT INTO accounts (id, user_id, provider_id, account_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (provider_id, account_id)
            WHERE provider_id = ANY (ARRAY['github'::text, 'google'::text])
        DO NOTHING
        "#,
    )
    .bind(hex_id())
    .bind(account_id)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .execute(&mut *tx)
    .await
    .map_err(failed)?
    .rows_affected();
    if inserted != 1 {
        // A concurrent sign-in or link took the identity first.
        return Err(LinkResult::Taken);
    }
    let mut metadata = identity_audit(provider, identity);
    metadata["automatic"] = json!(false);
    metadata["confirmed_by"] = json!("session");
    let (ip, ua) = request_info(headers);
    log_audit_in(
        &mut tx,
        "user.oauth.linked",
        account_id,
        &ip,
        &ua,
        metadata,
        "info",
    )
    .await
    .map_err(failed)?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    Ok(Some(email))
}

/// Email the account's address that a provider was connected or
/// disconnected. A failed notice is logged; the change stands.
async fn notify(state: &OAuthState, provider: Provider, account: &str, to: &str, connected: bool) {
    let email = &state.session.email;
    if !email.is_configured() {
        return;
    }
    let settings_url = format!(
        "{}{SETTINGS_PATH}#{SETTINGS_FRAGMENT}",
        state.session.frontend_url.trim_end_matches('/')
    );
    let sent = if connected {
        send_provider_connected_email(email, to, provider.label(), account, &settings_url).await
    } else {
        send_provider_disconnected_email(email, to, provider.label(), account, &settings_url).await
    };
    if let Err(error) = sent {
        tracing::error!(%error, provider = provider.as_str(), "failed to send a sign-in method notice");
    }
}

// --- POST /api/auth/oauth/identities/unlink ---

#[derive(sqlx::FromRow)]
struct LinkedIdentity {
    subject: String,
    account: Option<String>,
}

#[derive(Serialize)]
struct Unlinked {
    provider: &'static str,
}

async fn unlink(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    request: Result<Json<ProviderRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let result = async {
        exact_origin(&headers, &state.session.frontend_url)?;
        let Json(request) = request.map_err(|_| AppError::BadRequest("Invalid request".into()))?;
        let provider = Provider::parse(&request.provider).ok_or_else(not_connected)?;
        let mut tx = state.session.pool.begin().await.map_err(database)?;
        // The account row stays locked to the commit, so two disconnects
        // cannot each leave the other as the last way in.
        lock_actor(&mut tx, &headers, &request.account_id, true).await?;
        let identities: Vec<LinkedIdentity> = sqlx::query_as(&format!(
            "SELECT a.account_id AS subject, {LINKED_ACCOUNT_SQL} AS account \
               FROM accounts a WHERE a.user_id = $1 AND a.provider_id = $2"
        ))
        .bind(&request.account_id)
        .bind(provider.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(database)?;
        if identities.is_empty() {
            return Err(not_connected());
        }
        // Another way in: a password, or an identity of another provider
        // that is configured, so it can still sign in.
        let others: Vec<&'static str> = configured_names(&state)
            .into_iter()
            .filter(|other| *other != provider.as_str())
            .collect();
        let password = has_password(&mut tx, &request.account_id).await?;
        let other_provider: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE user_id = $1 AND provider_id = ANY($2))",
        )
        .bind(&request.account_id)
        .bind(&others)
        .fetch_one(&mut *tx)
        .await
        .map_err(database)?;
        if !password && !other_provider {
            return Err(last_method());
        }
        sqlx::query("DELETE FROM accounts WHERE user_id = $1 AND provider_id = $2")
            .bind(&request.account_id)
            .bind(provider.as_str())
            .execute(&mut *tx)
            .await
            .map_err(database)?;
        let (ip, ua) = request_info(&headers);
        for identity in &identities {
            log_audit_in(
                &mut tx,
                "user.oauth.unlinked",
                &request.account_id,
                &ip,
                &ua,
                json!({
                    "provider": provider.as_str(),
                    "provider_subject": &identity.subject,
                    "provider_account": &identity.account,
                }),
                "info",
            )
            .await
            .map_err(database)?;
        }
        let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(&request.account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
        tx.commit().await.map_err(database)?;
        let account = identities
            .iter()
            .find_map(|identity| identity.account.clone())
            .unwrap_or_default();
        notify(&state, provider, &account, &email, false).await;
        Ok::<_, AppError>(Unlinked {
            provider: provider.as_str(),
        })
    };
    match result.await {
        Ok(body) => private(Json(body)),
        Err(error) => private(error),
    }
}
