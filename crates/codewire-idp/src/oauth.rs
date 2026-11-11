//! Sign in with GitHub or Google (#4062): `codewire-idp` is an OAuth client
//! of both providers and owns the whole round trip.
//!
//! - `GET /api/auth/oauth/providers` names the configured providers (no
//!   secrets); the dashboard shows a button for each.
//! - `GET /api/auth/oauth/{provider}/start` writes a single-use
//!   `oauth_states` row (the hash of a random state, the PKCE verifier, a
//!   Google nonce, the return target), sets the raw state in an HttpOnly Lax
//!   cookie scoped to `/api/auth/oauth/`, and redirects to the provider. One
//!   client address may hold at most [`MAX_STARTS_PER_CLIENT`] unfinished
//!   starts.
//! - `GET /api/auth/oauth/{provider}/callback` requires the `state` query to
//!   equal that cookie and deletes its unexpired row in the statement that
//!   reads it, exchanges the code server-side with the verifier, reads a
//!   verified email (GitHub's primary, or Google's ID token after its `iss`,
//!   `aud`, `exp` and `nonce` checks) and resolves it:
//!   - a linked identity continues as a password sign-in does from the
//!     lockout check on: `enabled`, then the two-factor challenge, which the
//!     dashboard's `/two-factor` page finishes, then a session;
//!   - an unlinked identity whose email belongs to an account that verified
//!     it is linked at once (audited, and the account is emailed) only when
//!     Google vouches for the address (`@gmail.com`, or its `hd` domain) and
//!     the account has no second factor, then continues as a linked one;
//!     otherwise (every GitHub match, other Google addresses, any account
//!     with a second factor) nothing is linked: the account's own address
//!     gets a single-use `link_confirm` token, and `/login` says so;
//!   - a disabled or locked-out account is refused before any of that;
//!   - an unlinked identity whose email belongs to an account that never
//!     verified it is refused: the owner signs in and links from Settings;
//!   - an unknown email waits in a `sign_up` row for the dashboard's
//!     `/signup/complete` page.
//! - `POST /api/auth/oauth/signup/pending` reads that row for the page, and
//!   `POST /api/auth/oauth/signup/complete` creates the account with the same
//!   reason, invite policy and Turnstile as email sign-up, deleting the row.
//! - `POST /api/auth/oauth/link/pending` reads a link confirmation for the
//!   dashboard's `/login/link` page (a mail scanner's fetch uses nothing up),
//!   and `POST /api/auth/oauth/link/confirm` uses it: it links the identity
//!   if the account may still sign in and owns the address, and creates no
//!   session; signing in with the provider then passes every gate.
//!
//! Every failure of the round trip lands on `/login?oauth_error=<code>`; the
//! dashboard maps each fixed code to its message. No provider token is kept.

mod providers;

pub use providers::{
    OAuthProviders, OAuthUpstream, Provider, ReqwestUpstream, UpstreamError, UpstreamRequest,
    UpstreamResponse,
};

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::NaiveDateTime;
use codewire_email::EmailClient;
use codewire_server_core::auth::hash_session_token;
use codewire_server_core::{AppError, ValidatedJson};
use rand::RngCore as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::auth_session::{
    CreatedSession, MAX_ACCESS_REASON_CHARS, SessionAuthState, SessionResponse, SignupInvitePolicy,
    TWO_FACTOR_TOKEN_TTL_SECS, UserAuthRow, UserResponse, configured_human_verification,
    create_session, format_time, hex_id, hex_token, log_audit, log_audit_in, request_info,
    session_cookie_string, validate_turnstile,
};
use crate::email_password::{
    send_access_request_received_email, send_provider_link_confirmation_email,
    send_provider_linked_email,
};
use providers::{IdentityError, ProviderIdentity};

/// The browser's half of a round trip: the raw state.
const STATE_COOKIE: &str = "codewire_oauth_state";
const STATE_COOKIE_PATH: &str = "/api/auth/oauth/";
/// The browser's half of a pending sign-up.
const SIGNUP_COOKIE: &str = "codewire_oauth_signup";
const SIGNUP_COOKIE_PATH: &str = "/signup/complete";
/// The dashboard's two-factor challenge cookie (`TWO_FACTOR_CHALLENGE_COOKIE`
/// in codewire-dashboard-web), which its `/two-factor` page finishes.
const TWO_FACTOR_CHALLENGE_COOKIE: &str = "codewire_2fa_challenge";
const TWO_FACTOR_CHALLENGE_PATH: &str = "/two-factor";
/// The browser that started a sign-in needing an emailed link confirmation
/// holds this secret; the confirmation completes only with it. The dashboard's
/// `/login/link` page and its confirm action live under this path.
const LINK_REQUESTER_COOKIE: &str = "codewire_oauth_link_requester";
const LINK_REQUESTER_PATH: &str = "/login/link";

/// A round trip has ten minutes from start to callback.
const STATE_TTL_SECS: i64 = 10 * 60;
/// A pending sign-up has thirty minutes to be completed: the page asks for a
/// written reason.
const SIGNUP_TTL_SECS: i64 = 30 * 60;
/// An emailed link confirmation is valid for thirty minutes.
const LINK_CONFIRM_TTL_SECS: i64 = 30 * 60;
/// How many started sign-ins one client address may hold at once. A start
/// writes a row before the person reaches the provider, so an unauthenticated
/// client could otherwise fill the table; a finished or abandoned round trip
/// frees its place within ten minutes. Generous for a shared office address.
const MAX_STARTS_PER_CLIENT: i64 = 30;
/// The label the client-address hash key is derived under from the session
/// secret, so the stored hash cannot be reversed by trying every address.
pub const CLIENT_ADDRESS_KEY_LABEL: &str = "codewire/idp-oauth-client-address/v1";
const MAX_AUTH_REQUEST_ID_BYTES: usize = 256;
const MAX_RETURN_TO_BYTES: usize = 2048;
const MAX_CODE_BYTES: usize = 2048;
const MAX_HANDLE_BYTES: usize = 128;

/// The fixed reasons a round trip lands back on `/login`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The provider is not configured.
    Unavailable,
    /// The person cancelled or denied access at the provider.
    Cancelled,
    /// The state cookie or row is missing, mismatched, expired or used.
    Expired,
    /// The provider has no verified email for the account.
    UnverifiedEmail,
    /// An account has this email but never verified it: sign in and link.
    LinkRequired,
    /// The account is temporarily locked.
    Locked,
    /// The account's access is not enabled.
    Disabled,
    /// This client address holds too many started sign-ins.
    RateLimited,
    /// Anything else: the provider failed or answered badly.
    Failed,
}

impl Refusal {
    fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::UnverifiedEmail => "unverified_email",
            Self::LinkRequired => "link_required",
            Self::Locked => "locked",
            Self::Disabled => "disabled",
            Self::RateLimited => "rate_limited",
            Self::Failed => "failed",
        }
    }
}

/// Where a finished sign-in returns: the OIDC request it resumes, or a
/// same-origin path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReturnTarget {
    auth_request_id: Option<String>,
    return_to: Option<String>,
}

impl ReturnTarget {
    fn sanitized(auth_request_id: &str, return_to: &str) -> Self {
        Self {
            auth_request_id: clean_auth_request_id(auth_request_id),
            return_to: safe_return_to(return_to),
        }
    }

    /// The query a dashboard auth page carries forward.
    fn append(&self, query: &mut url::form_urlencoded::Serializer<'_, String>) {
        if let Some(id) = &self.auth_request_id {
            query.append_pair("authRequestID", id);
        }
        if let Some(path) = &self.return_to {
            query.append_pair("return_to", path);
        }
    }

    /// Where the browser goes once signed in, as the dashboard computes it.
    fn completion(&self) -> String {
        match (&self.auth_request_id, &self.return_to) {
            (Some(id), _) => {
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("id", id)
                    .finish();
                format!("/api/oidc/callback?{query}")
            }
            (None, Some(path)) => path.clone(),
            (None, None) => "/dashboard/".to_owned(),
        }
    }
}

fn clean_auth_request_id(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= MAX_AUTH_REQUEST_ID_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| value.to_owned())
}

/// A same-origin path, exactly as the dashboard's `safe_auth_continuation`
/// accepts one.
fn safe_return_to(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_RETURN_TO_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let parsed = reqwest::Url::parse(&format!("https://codewire.invalid{value}")).ok()?;
    (parsed.origin().ascii_serialization() == "https://codewire.invalid").then(|| value.to_owned())
}

/// Equal-length secrets compared without an early exit.
pub(crate) fn same_secret(left: &[u8], right: &[u8]) -> bool {
    let left = Sha256::digest(left);
    let right = Sha256::digest(right);
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[derive(Clone)]
struct OAuthState {
    session: SessionAuthState,
    providers: OAuthProviders,
    mailer: Arc<dyn LinkConfirmationMailer>,
    /// Keys the client-address hash that bounds started sign-ins.
    client_address_key: Arc<str>,
}

/// Sends the one-time link confirmation to a Codewire account's own address.
/// Production sends it through the IdP's email client; tests record it.
#[async_trait]
pub trait LinkConfirmationMailer: Send + Sync {
    /// Whether a confirmation can be sent at all. Without it, an email match
    /// that needs confirming is refused as before (sign in and link from
    /// Settings) and nothing is stored.
    fn is_available(&self) -> bool;
    /// `account` names the provider account (GitHub login or Google email).
    async fn send(
        &self,
        to: &str,
        provider: Provider,
        account: &str,
        confirm_url: &str,
    ) -> anyhow::Result<()>;
}

/// The production mailer: the IdP's transactional email.
pub struct EmailLinkMailer(pub EmailClient);

#[async_trait]
impl LinkConfirmationMailer for EmailLinkMailer {
    fn is_available(&self) -> bool {
        self.0.is_configured()
    }

    async fn send(
        &self,
        to: &str,
        provider: Provider,
        account: &str,
        confirm_url: &str,
    ) -> anyhow::Result<()> {
        send_provider_link_confirmation_email(&self.0, to, provider.label(), account, confirm_url)
            .await
    }
}

/// The keyed hash of the address an abuser controls as one unit: an IPv4
/// address (also when IPv4-mapped) or an IPv6 /64, as the feedback limiter
/// counts them. `None` when the edge named no address; those clients share
/// one allowance.
fn client_address_hash(key: &str, address: Option<IpAddr>) -> Option<String> {
    use hmac::Mac as _;
    let unit = match address? {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let segments = v6.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            }
        },
    };
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(unit.as_bytes());
    Some(crate::auth_session::hex_lower(&mac.finalize().into_bytes()))
}

impl OAuthState {
    fn redirect_uri(&self, provider: Provider) -> String {
        format!(
            "{}/api/auth/oauth/{}/callback",
            self.session.frontend_url.trim_end_matches('/'),
            provider.as_str()
        )
    }
}

/// The production router.
#[allow(clippy::too_many_arguments)]
pub fn router(
    pool: PgPool,
    secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    email: EmailClient,
    turnstile_secret_key: String,
    turnstile_bypass_email: String,
    providers: OAuthProviders,
    client_address_key: String,
) -> Router {
    let human_verification = configured_human_verification(&frontend_url, turnstile_secret_key);
    let mailer = Arc::new(EmailLinkMailer(email.clone()));
    router_with_state(OAuthState {
        session: SessionAuthState::new(
            pool,
            secure,
            signup_invite_policy,
            frontend_url,
            email,
            human_verification,
            turnstile_bypass_email,
        ),
        providers,
        mailer,
        client_address_key: client_address_key.into(),
    })
}

/// The trusted in-process test router: Turnstile passes, the IdP's own email
/// is off, and link confirmations go to `mailer`.
pub fn trusted_test_router(
    pool: PgPool,
    secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    providers: OAuthProviders,
    mailer: Arc<dyn LinkConfirmationMailer>,
) -> Router {
    router_with_state(OAuthState {
        session: SessionAuthState::trusted_test(pool, secure, signup_invite_policy, frontend_url),
        providers,
        mailer,
        client_address_key: "synthetic-oauth-client-address-key".into(),
    })
}

fn router_with_state(state: OAuthState) -> Router {
    Router::new()
        .route("/api/auth/oauth/providers", get(providers_list))
        .route("/api/auth/oauth/{provider}/start", get(start))
        .route("/api/auth/oauth/{provider}/callback", get(callback))
        .route("/api/auth/oauth/signup/pending", post(pending_signup))
        .route("/api/auth/oauth/signup/complete", post(complete_signup))
        .route("/api/auth/oauth/link/pending", post(pending_link))
        .route("/api/auth/oauth/link/confirm", post(confirm_link))
        .with_state(state)
}

// --- cookies and redirects ---

fn cookie(name: &str, value: &str, path: &str, max_age: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .expect("OAuth cookies are ASCII")
}

fn clear_cookie(name: &str, path: &str, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    ))
    .expect("OAuth cookies are ASCII")
}

/// The one value of a cookie the browser sent exactly once.
fn unique_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for pair in raw.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found.filter(|value| !value.is_empty() && value.len() <= MAX_HANDLE_BYTES)
}

fn see_other(location: &str, cookies: Vec<HeaderValue>) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/login")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    for value in cookies {
        headers.append(header::SET_COOKIE, value);
    }
    response
}

fn login_with_refusal(
    refusal: Refusal,
    target: &ReturnTarget,
    cookies: Vec<HeaderValue>,
) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("oauth_error", refusal.code());
    target.append(&mut query);
    see_other(&format!("/login?{}", query.finish()), cookies)
}

/// The emailed confirmation went out: `/login` says so, naming the provider.
fn login_with_link_sent(
    provider: Provider,
    target: &ReturnTarget,
    cookies: Vec<HeaderValue>,
) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("oauth_notice", "link_sent")
        .append_pair("provider", provider.as_str());
    target.append(&mut query);
    see_other(&format!("/login?{}", query.finish()), cookies)
}

fn path_with_target(path: &str, target: &ReturnTarget) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    target.append(&mut query);
    let query = query.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

/// 32 random bytes as a PKCE verifier (43 base64url characters).
fn pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn sweep_expired<'e, E: sqlx::PgExecutor<'e>>(executor: E) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oauth_states WHERE expires_at <= NOW()")
        .execute(executor)
        .await
        .map(|_| ())
}

// --- GET /api/auth/oauth/providers ---

#[derive(Serialize)]
struct ProvidersBody {
    providers: Vec<&'static str>,
}

async fn providers_list(State(state): State<OAuthState>) -> Response {
    let mut response = Json(ProvidersBody {
        providers: state
            .providers
            .configured()
            .into_iter()
            .map(Provider::as_str)
            .collect(),
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// --- GET /api/auth/oauth/{provider}/start ---

#[derive(Deserialize)]
struct StartQuery {
    #[serde(default)]
    return_to: String,
    #[serde(default, rename = "authRequestID")]
    auth_request_id: String,
}

async fn start(
    State(state): State<OAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<StartQuery>,
    headers: HeaderMap,
) -> Response {
    let target = ReturnTarget::sanitized(&query.auth_request_id, &query.return_to);
    let Some(provider) = Provider::parse(&provider).filter(|p| state.providers.is_configured(*p))
    else {
        return login_with_refusal(Refusal::Unavailable, &target, Vec::new());
    };

    let raw_state = hex_token();
    let verifier = pkce_verifier();
    let nonce = (provider == Provider::Google).then(hex_token);
    let Some(location) = state.providers.authorize_url(
        provider,
        &state.redirect_uri(provider),
        &raw_state,
        &pkce_challenge(&verifier),
        nonce.as_deref(),
    ) else {
        return login_with_refusal(Refusal::Unavailable, &target, Vec::new());
    };

    let address = client_address_hash(
        &state.client_address_key,
        codewire_server_core::client_address::forwarded_client_ip(&headers),
    );
    let stored = async {
        let mut tx = state.session.pool.begin().await?;
        sweep_expired(&mut *tx).await?;
        // One client's starts serialize on its own lock, so concurrent starts
        // cannot both pass the count below.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4062))")
            .bind(format!(
                "codewire-oauth-start:{}",
                address.as_deref().unwrap_or("unknown")
            ))
            .execute(&mut *tx)
            .await?;
        let held: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*) FROM oauth_states
             WHERE intent = 'sign_in' AND expires_at > NOW()
               AND client_address_hash IS NOT DISTINCT FROM $1
            "#,
        )
        .bind(&address)
        .fetch_one(&mut *tx)
        .await?;
        if held >= MAX_STARTS_PER_CLIENT {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            r#"
            INSERT INTO oauth_states
                (id, token_hash, provider, intent, pkce_verifier, nonce,
                 return_auth_request_id, return_to, client_address_hash, expires_at)
            VALUES ($1, $2, $3, 'sign_in', $4, $5, $6, $7, $8,
                    NOW() + ($9::bigint * interval '1 second'))
            "#,
        )
        .bind(hex_id())
        .bind(hash_session_token(&raw_state))
        .bind(provider.as_str())
        .bind(&verifier)
        .bind(&nonce)
        .bind(&target.auth_request_id)
        .bind(&target.return_to)
        .bind(&address)
        .bind(STATE_TTL_SECS)
        .execute(&mut *tx)
        .await?;
        tx.commit().await.map(|()| true)
    }
    .await;
    match stored {
        Ok(true) => {}
        Ok(false) => return login_with_refusal(Refusal::RateLimited, &target, Vec::new()),
        Err(error) => {
            tracing::error!(%error, provider = provider.as_str(), "failed to store OAuth state");
            return login_with_refusal(Refusal::Failed, &target, Vec::new());
        }
    }

    see_other(
        &location,
        vec![cookie(
            STATE_COOKIE,
            &raw_state,
            STATE_COOKIE_PATH,
            STATE_TTL_SECS,
            state.session.secure,
        )],
    )
}

// --- GET /api/auth/oauth/{provider}/callback ---

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

#[derive(sqlx::FromRow)]
struct ClaimedState {
    provider: String,
    intent: String,
    pkce_verifier: Option<String>,
    nonce: Option<String>,
    return_auth_request_id: Option<String>,
    return_to: Option<String>,
    live: bool,
}

/// What a resolved sign-in hands the browser.
enum Outcome {
    Session(CreatedSession),
    TwoFactor(String),
    SignUp(String),
    /// A link confirmation was emailed to the matching account; the browser
    /// keeps this requester secret to complete it.
    LinkSent(String),
}

async fn callback(
    State(state): State<OAuthState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let secure = state.session.secure;
    // The state cookie is single use whatever happens next.
    let mut cookies = vec![clear_cookie(STATE_COOKIE, STATE_COOKIE_PATH, secure)];
    let mut target = ReturnTarget::default();

    let Some(provider) = Provider::parse(&provider).filter(|p| state.providers.is_configured(*p))
    else {
        return login_with_refusal(Refusal::Unavailable, &target, cookies);
    };
    let browser_state = unique_cookie(&headers, STATE_COOKIE);
    let state_matches = browser_state.is_some_and(|cookie| {
        !query.state.is_empty() && same_secret(cookie.as_bytes(), query.state.as_bytes())
    });
    if !state_matches {
        return login_with_refusal(Refusal::Expired, &target, cookies);
    }

    let claimed = claim_state(&state.session.pool, &query.state).await;
    let claimed = match claimed {
        Ok(Some(claimed)) => claimed,
        Ok(None) => return login_with_refusal(Refusal::Expired, &target, cookies),
        Err(error) => {
            tracing::error!(%error, "failed to claim OAuth state");
            return login_with_refusal(Refusal::Failed, &target, cookies);
        }
    };
    target = ReturnTarget {
        auth_request_id: claimed.return_auth_request_id.clone(),
        return_to: claimed.return_to.clone(),
    };
    if !claimed.live || claimed.provider != provider.as_str() || claimed.intent != "sign_in" {
        return login_with_refusal(Refusal::Expired, &target, cookies);
    }
    if !query.error.is_empty() {
        let refusal = if query.error == "access_denied" {
            Refusal::Cancelled
        } else {
            Refusal::Failed
        };
        return login_with_refusal(refusal, &target, cookies);
    }
    let Some(verifier) = claimed.pkce_verifier.as_deref() else {
        return login_with_refusal(Refusal::Expired, &target, cookies);
    };
    if query.code.is_empty() || query.code.len() > MAX_CODE_BYTES {
        return login_with_refusal(Refusal::Failed, &target, cookies);
    }

    let identity = match state
        .providers
        .identify(
            provider,
            &query.code,
            verifier,
            &state.redirect_uri(provider),
            claimed.nonce.as_deref(),
        )
        .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                provider = provider.as_str(),
                ?error,
                "OAuth identity refused"
            );
            let refusal = match error {
                IdentityError::UnverifiedEmail => Refusal::UnverifiedEmail,
                IdentityError::Unavailable => Refusal::Unavailable,
                IdentityError::Upstream | IdentityError::Invalid => Refusal::Failed,
            };
            return login_with_refusal(refusal, &target, cookies);
        }
    };

    match resolve(&state, provider, &identity, &target, &headers).await {
        Ok(Outcome::Session(session)) => {
            cookies.push(
                HeaderValue::from_str(&session_cookie_string(&session.token, secure))
                    .expect("session cookies are ASCII"),
            );
            // As after a password sign-in: offer two-factor setup, which an
            // account without a factor may skip for this session.
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("return_to", &target.completion());
            see_other(&format!("/setup-2fa?{}", query.finish()), cookies)
        }
        Ok(Outcome::TwoFactor(challenge)) => {
            cookies.push(cookie(
                TWO_FACTOR_CHALLENGE_COOKIE,
                &challenge,
                TWO_FACTOR_CHALLENGE_PATH,
                TWO_FACTOR_TOKEN_TTL_SECS,
                secure,
            ));
            see_other(&path_with_target("/two-factor", &target), cookies)
        }
        Ok(Outcome::SignUp(handle)) => {
            cookies.push(cookie(
                SIGNUP_COOKIE,
                &handle,
                SIGNUP_COOKIE_PATH,
                SIGNUP_TTL_SECS,
                secure,
            ));
            see_other("/signup/complete", cookies)
        }
        Ok(Outcome::LinkSent(requester)) => {
            cookies.push(cookie(
                LINK_REQUESTER_COOKIE,
                &requester,
                LINK_REQUESTER_PATH,
                LINK_CONFIRM_TTL_SECS,
                secure,
            ));
            login_with_link_sent(provider, &target, cookies)
        }
        Err(refusal) => login_with_refusal(refusal, &target, cookies),
    }
}

/// Delete the round trip's row in the statement that reads it, so a state is
/// used once even when two callbacks race; sweep expired rows on the way.
async fn claim_state(pool: &PgPool, raw_state: &str) -> Result<Option<ClaimedState>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let claimed = sqlx::query_as::<_, ClaimedState>(
        r#"
        DELETE FROM oauth_states
         WHERE token_hash = $1
        RETURNING provider, intent, pkce_verifier, nonce,
                  return_auth_request_id, return_to, expires_at > NOW() AS live
        "#,
    )
    .bind(hash_session_token(raw_state))
    .fetch_optional(&mut *tx)
    .await?;
    sweep_expired(&mut *tx).await?;
    tx.commit().await?;
    Ok(claimed)
}

#[derive(sqlx::FromRow)]
struct EmailOwner {
    id: String,
    email: String,
    email_verified: bool,
    /// Disabled (or awaiting access) or locked out: the sign-in gates refuse
    /// it, so nothing is linked to it first.
    refused: bool,
    /// Enrolled in two-factor: a link made before the second factor passes
    /// would outlive a failed or abandoned challenge, so it is never automatic.
    two_factor: bool,
}

/// Find the Codewire account for a provider identity and apply the sign-in
/// gates. An unlinked identity whose email matches an account that verified
/// it is linked at once only when the provider vouches for the address (see
/// [`ProviderIdentity::provider_owns_email`]) and the account has no second
/// factor; otherwise the account's own address is emailed a one-time
/// confirmation and nothing is linked yet (owner, 2026-11-11, #4062).
async fn resolve(
    state: &OAuthState,
    provider: Provider,
    identity: &ProviderIdentity,
    target: &ReturnTarget,
    headers: &HeaderMap,
) -> Result<Outcome, Refusal> {
    let pool = &state.session.pool;
    let (ip, ua) = request_info(headers);
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to resolve OAuth identity");
        Refusal::Failed
    };

    let mut tx = pool.begin().await.map_err(failed)?;
    let linked: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM accounts WHERE provider_id = $1 AND account_id = $2",
    )
    .bind(provider.as_str())
    .bind(&identity.subject)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?;

    let mut linked_notice: Option<String> = None;
    let user_id = match linked {
        Some(user_id) => {
            tx.commit().await.map_err(failed)?;
            user_id
        }
        None => {
            // Emails are stored as typed; match them without case so a
            // provider's spelling cannot open a second account. Two accounts
            // that differ only by case are ambiguous and never linked.
            let owners: Vec<EmailOwner> = sqlx::query_as(
                r#"
                SELECT id, email, COALESCE(email_verified, false) AS email_verified,
                       (NOT enabled OR COALESCE(locked_until > NOW(), false)) AS refused,
                       COALESCE(two_factor_enabled, false) AS two_factor
                  FROM users
                 WHERE lower(email) = lower($1)
                 ORDER BY id
                 LIMIT 2
                   FOR UPDATE
                "#,
            )
            .bind(&identity.email)
            .fetch_all(&mut *tx)
            .await
            .map_err(failed)?;
            match owners.as_slice() {
                [] => {
                    tx.commit().await.map_err(failed)?;
                    return pending_signup_row(pool, provider, identity, target)
                        .await
                        .map(Outcome::SignUp)
                        .map_err(failed);
                }
                [owner] if owner.email_verified && owner.refused => {
                    // The gates would refuse this sign-in: refuse it the same
                    // way without linking the identity to the account.
                    tx.rollback().await.map_err(failed)?;
                    return sign_in_gates(pool, provider, &owner.id, &ip, &ua).await;
                }
                [owner]
                    if owner.email_verified
                        && (owner.two_factor || !identity.provider_owns_email(provider)) =>
                {
                    // No link before the second factor, and none on GitHub's
                    // or an unmanaged domain's word: the account's own
                    // address confirms it, and the link makes no session.
                    if !state.mailer.is_available() {
                        tx.rollback().await.map_err(failed)?;
                        return Err(Refusal::LinkRequired);
                    }
                    let (token, requester) =
                        link_confirmation_row(&mut tx, provider, identity, &owner.id)
                            .await
                            .map_err(failed)?;
                    log_audit_in(
                        &mut tx,
                        "user.oauth.link_requested",
                        &owner.id,
                        &ip,
                        &ua,
                        json!({
                            "provider": provider.as_str(),
                            "provider_email": &identity.email,
                        }),
                        "info",
                    )
                    .await
                    .map_err(failed)?;
                    tx.commit().await.map_err(failed)?;
                    let confirm_url = format!(
                        "{}/login/link?token={token}",
                        state.session.frontend_url.trim_end_matches('/')
                    );
                    if let Err(error) = state
                        .mailer
                        .send(&owner.email, provider, &identity.account, &confirm_url)
                        .await
                    {
                        tracing::error!(%error, user_id = %owner.id, "failed to send link confirmation");
                        let _ = sqlx::query("DELETE FROM oauth_states WHERE token_hash = $1")
                            .bind(hash_session_token(&token))
                            .execute(pool)
                            .await;
                        return Err(Refusal::Failed);
                    }
                    return Ok(Outcome::LinkSent(requester));
                }
                [owner] if owner.email_verified => {
                    let inserted = sqlx::query(
                        r#"
                        INSERT INTO accounts
                            (id, user_id, provider_id, account_id, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, NOW(), NOW())
                        ON CONFLICT (provider_id, account_id)
                            WHERE provider_id = ANY (ARRAY['github'::text, 'google'::text])
                        DO NOTHING
                        "#,
                    )
                    .bind(hex_id())
                    .bind(&owner.id)
                    .bind(provider.as_str())
                    .bind(&identity.subject)
                    .execute(&mut *tx)
                    .await
                    .map_err(failed)?
                    .rows_affected()
                        == 1;
                    if inserted {
                        log_audit_in(
                            &mut tx,
                            "user.oauth.linked",
                            &owner.id,
                            &ip,
                            &ua,
                            json!({
                                "provider": provider.as_str(),
                                "provider_email": &identity.email,
                                "automatic": true,
                                "confirmed_by": "provider",
                            }),
                            "info",
                        )
                        .await
                        .map_err(failed)?;
                        tx.commit().await.map_err(failed)?;
                        linked_notice = Some(owner.email.clone());
                        owner.id.clone()
                    } else {
                        // A concurrent callback linked it first; its owner is
                        // the account this identity signs in to.
                        tx.rollback().await.map_err(failed)?;
                        sqlx::query_scalar(
                            "SELECT user_id FROM accounts WHERE provider_id = $1 AND account_id = $2",
                        )
                        .bind(provider.as_str())
                        .bind(&identity.subject)
                        .fetch_optional(pool)
                        .await
                        .map_err(failed)?
                        .ok_or(Refusal::Failed)?
                    }
                }
                _ => {
                    tx.rollback().await.map_err(failed)?;
                    return Err(Refusal::LinkRequired);
                }
            }
        }
    };

    if let Some(to) = linked_notice
        && state.session.email.is_configured()
    {
        let settings_url = format!(
            "{}/settings/",
            state.session.frontend_url.trim_end_matches('/')
        );
        if let Err(error) =
            send_provider_linked_email(&state.session.email, &to, provider.label(), &settings_url)
                .await
        {
            tracing::error!(%error, user_id = %user_id, "failed to send provider link notice");
        }
    }

    sign_in_gates(pool, provider, &user_id, &ip, &ua).await
}

/// The gates a password sign-in applies after its password check, in its
/// order: lockout, `enabled`, then the two-factor challenge or a session.
async fn sign_in_gates(
    pool: &PgPool,
    provider: Provider,
    user_id: &str,
    ip: &str,
    ua: &str,
) -> Result<Outcome, Refusal> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to finish OAuth sign-in");
        Refusal::Failed
    };
    let user: UserAuthRow = sqlx::query_as(
        r#"
        SELECT id, email, email_verified, name, image, is_admin,
               two_factor_enabled, cli_signed_in_at IS NOT NULL AS cli_signed_in,
               enabled, locked_until, created_at
          FROM users WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(failed)?
    .ok_or(Refusal::Failed)?;

    if user
        .locked_until
        .is_some_and(|locked| locked > chrono::Utc::now().naive_utc())
    {
        return Err(Refusal::Locked);
    }
    if !user.enabled {
        return Err(Refusal::Disabled);
    }

    if user.two_factor_enabled.unwrap_or(false) {
        let challenge = hex_token();
        sqlx::query(
            r#"
            INSERT INTO two_factor_tokens (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, NOW() + ($4::bigint * interval '1 second'))
            "#,
        )
        .bind(hex_id())
        .bind(&user.id)
        .bind(hash_session_token(&challenge))
        .bind(TWO_FACTOR_TOKEN_TTL_SECS)
        .execute(pool)
        .await
        .map_err(failed)?;
        return Ok(Outcome::TwoFactor(challenge));
    }

    let _ = sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(&user.id)
    .execute(pool)
    .await;
    let session = create_session(pool, &user.id, ip, ua)
        .await
        .map_err(|_| Refusal::Disabled)?;
    log_audit(
        pool,
        "user.signin",
        &user.id,
        ip,
        ua,
        json!({ "email": &user.email, "method": provider.as_str() }),
        "info",
    )
    .await;
    Ok(Outcome::Session(session))
}

/// The identity waits here between the callback and the completion page.
async fn pending_signup_row(
    pool: &PgPool,
    provider: Provider,
    identity: &ProviderIdentity,
    target: &ReturnTarget,
) -> Result<String, sqlx::Error> {
    let handle = hex_token();
    sqlx::query(
        r#"
        INSERT INTO oauth_states
            (id, token_hash, provider, intent, provider_identity,
             return_auth_request_id, return_to, expires_at)
        VALUES ($1, $2, $3, 'sign_up', $4, $5, $6,
                NOW() + ($7::bigint * interval '1 second'))
        "#,
    )
    .bind(hex_id())
    .bind(hash_session_token(&handle))
    .bind(provider.as_str())
    .bind(json!({
        "subject": &identity.subject,
        "email": &identity.email,
        "name": &identity.name,
    }))
    .bind(&target.auth_request_id)
    .bind(&target.return_to)
    .bind(SIGNUP_TTL_SECS)
    .execute(pool)
    .await?;
    Ok(handle)
}

/// Store the one link confirmation for this account and provider, replacing
/// any earlier one, and return its raw emailed token and the raw requester
/// secret the starting browser keeps. Only their hashes are stored.
async fn link_confirmation_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    provider: Provider,
    identity: &ProviderIdentity,
    user_id: &str,
) -> Result<(String, String), sqlx::Error> {
    let token = hex_token();
    let requester = hex_token();
    sqlx::query(
        r#"
        INSERT INTO oauth_states
            (id, token_hash, provider, intent, user_id, provider_identity, requester_hash,
             expires_at)
        VALUES ($1, $2, $3, 'link_confirm', $4, $5, $6,
                NOW() + ($7::bigint * interval '1 second'))
        ON CONFLICT (user_id, provider) WHERE intent = 'link_confirm'
        DO UPDATE SET id = EXCLUDED.id,
                      token_hash = EXCLUDED.token_hash,
                      provider_identity = EXCLUDED.provider_identity,
                      requester_hash = EXCLUDED.requester_hash,
                      created_at = EXCLUDED.created_at,
                      expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(hex_id())
    .bind(hash_session_token(&token))
    .bind(provider.as_str())
    .bind(user_id)
    .bind(json!({
        "subject": &identity.subject,
        "email": &identity.email,
        "name": &identity.name,
        "account": &identity.account,
    }))
    .bind(hash_session_token(&requester))
    .bind(LINK_CONFIRM_TTL_SECS)
    .execute(&mut **tx)
    .await?;
    Ok((token, requester))
}

// --- POST /api/auth/oauth/link/{pending,confirm} ---

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
            "provider_email": &identity.email,
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

// --- POST /api/auth/oauth/signup/{pending,complete} ---

#[derive(Deserialize, JsonSchema)]
struct PendingSignupRequest {
    token: String,
}

#[derive(Deserialize, JsonSchema)]
struct CompleteSignupRequest {
    token: String,
    #[serde(default)]
    invite_code: String,
    #[serde(default)]
    reason: String,
    #[serde(default, rename = "turnstile_token")]
    turnstile_token: String,
}

#[derive(Deserialize)]
struct PendingIdentity {
    subject: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PendingRow {
    provider: String,
    provider_identity: serde_json::Value,
    return_auth_request_id: Option<String>,
    return_to: Option<String>,
}

#[derive(Serialize)]
struct PendingSignupBody {
    provider: &'static str,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_to: Option<String>,
}

#[derive(Serialize)]
struct CompleteSignupBody {
    user: UserResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionResponse>,
    #[serde(rename = "accessPending", skip_serializing_if = "std::ops::Not::not")]
    access_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_to: Option<String>,
}

fn signup_expired() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "oauth_signup_expired",
        detail: "This sign-up has expired. Start again.".into(),
    }
}

fn account_exists() -> AppError {
    AppError::Conflict("An account with this email already exists".into())
}

fn valid_handle(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn live_pending_row(pool: &PgPool, token: &str) -> Result<PendingRow, AppError> {
    if !valid_handle(token) {
        return Err(signup_expired());
    }
    sqlx::query_as::<_, PendingRow>(
        r#"
        SELECT provider, provider_identity, return_auth_request_id, return_to
          FROM oauth_states
         WHERE token_hash = $1 AND intent = 'sign_up' AND expires_at > NOW()
        "#,
    )
    .bind(hash_session_token(token))
    .fetch_optional(pool)
    .await?
    .ok_or_else(signup_expired)
}

fn pending_parts(row: &PendingRow) -> Result<(Provider, PendingIdentity), AppError> {
    let provider = Provider::parse(&row.provider).ok_or_else(signup_expired)?;
    let identity: PendingIdentity =
        serde_json::from_value(row.provider_identity.clone()).map_err(|_| signup_expired())?;
    Ok((provider, identity))
}

async fn pending_signup(
    State(state): State<OAuthState>,
    ValidatedJson(request): ValidatedJson<PendingSignupRequest>,
) -> Result<Response, AppError> {
    let row = live_pending_row(&state.session.pool, &request.token).await?;
    let (provider, identity) = pending_parts(&row)?;
    Ok(Json(PendingSignupBody {
        provider: provider.as_str(),
        email: identity.email,
        auth_request_id: row.return_auth_request_id,
        return_to: row.return_to,
    })
    .into_response())
}

async fn complete_signup(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    ValidatedJson(request): ValidatedJson<CompleteSignupRequest>,
) -> Result<Response, AppError> {
    let session = &state.session;
    let row = live_pending_row(&session.pool, &request.token).await?;
    let (provider, identity) = pending_parts(&row)?;

    // The same checks as email sign-up, before the row is used up, so a
    // failed challenge or a missing reason can be corrected on the page.
    validate_turnstile(session, &identity.email, &request.turnstile_token).await?;
    let enabled = session.signup_invite_policy.accepts(&request.invite_code);
    let access_reason = request.reason.trim();
    if !enabled
        && (access_reason.is_empty() || access_reason.chars().count() > MAX_ACCESS_REASON_CHARS)
    {
        return Err(AppError::BadRequest(
            "Tell us why you want to use Codewire".into(),
        ));
    }

    let mut tx = session.pool.begin().await?;
    let claimed: Option<String> = sqlx::query_scalar(
        r#"
        DELETE FROM oauth_states
         WHERE token_hash = $1 AND intent = 'sign_up' AND expires_at > NOW()
        RETURNING id
        "#,
    )
    .bind(hash_session_token(&request.token))
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.commit().await?;
        return Err(signup_expired());
    }

    let taken: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))
            OR EXISTS (SELECT 1 FROM accounts WHERE provider_id = $2 AND account_id = $3)
        "#,
    )
    .bind(&identity.email)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .fetch_one(&mut *tx)
    .await?;
    if taken {
        // The row stays used: the identity now signs in or links instead.
        tx.commit().await?;
        return Err(account_exists());
    }

    let user_id = hex_id();
    let stored_access_reason = (!enabled).then_some(access_reason);
    // The provider verified the email, so the account starts verified and
    // has no password; `enabled` follows the invite policy.
    let created_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO users
            (id, email, email_verified, name, enabled, access_reason, created_at, updated_at)
        VALUES ($1, $2, true, $3, $4, $5, NOW(), NOW())
        RETURNING created_at
        "#,
    )
    .bind(&user_id)
    .bind(&identity.email)
    .bind(&identity.name)
    .bind(enabled)
    .bind(stored_access_reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| conflict_or_internal(error, "failed to create OAuth user"))?;
    sqlx::query(
        r#"
        INSERT INTO accounts (id, user_id, provider_id, account_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(hex_id())
    .bind(&user_id)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .execute(&mut *tx)
    .await
    .map_err(|error| conflict_or_internal(error, "failed to link OAuth identity"))?;

    let (ip, ua) = request_info(&headers);
    log_audit_in(
        &mut tx,
        if enabled {
            "user.signup"
        } else {
            "user.signup.access_requested"
        },
        &user_id,
        &ip,
        &ua,
        json!({
            "email": &identity.email,
            "enabled": enabled,
            "method": provider.as_str(),
        }),
        "info",
    )
    .await?;
    tx.commit().await?;

    let user = UserResponse {
        id: user_id.clone(),
        email: identity.email.clone(),
        email_verified: true,
        name: identity.name.clone(),
        image: None,
        is_admin: false,
        two_factor_enabled: false,
        cli_signed_in: false,
        created_at: format_time(created_at),
    };

    if !enabled {
        if session.email.is_configured()
            && let Err(error) =
                send_access_request_received_email(&session.email, &identity.email).await
        {
            tracing::error!(%error, user_id = %user_id, "failed to send access request receipt");
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(CompleteSignupBody {
                user,
                session: None,
                access_pending: true,
                auth_request_id: row.return_auth_request_id,
                return_to: row.return_to,
            }),
        )
            .into_response());
    }

    let created = create_session(&session.pool, &user_id, &ip, &ua)
        .await
        .map_err(|_| AppError::InternalMsg("Account created but session failed".into()))?;
    let mut response = Json(CompleteSignupBody {
        user,
        session: Some(created.response),
        access_pending: false,
        auth_request_id: row.return_auth_request_id,
        return_to: row.return_to,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie_string(&created.token, session.secure))
            .expect("session cookies are ASCII"),
    );
    Ok(response)
}

/// A unique violation means another sign-up won the email or the identity.
fn conflict_or_internal(error: sqlx::Error, context: &'static str) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
    {
        return account_exists();
    }
    tracing::error!(%error, "{context}");
    AppError::InternalMsg("Failed to create account".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_targets_keep_only_same_origin_paths_and_bounded_request_ids() {
        let target = ReturnTarget::sanitized("request-id", "/device?user_code=ABCD-EFGH");
        assert_eq!(target.auth_request_id.as_deref(), Some("request-id"));
        assert_eq!(target.completion(), "/api/oidc/callback?id=request-id");

        let target = ReturnTarget::sanitized("", "/device?user_code=ABCD-EFGH");
        assert_eq!(target.completion(), "/device?user_code=ABCD-EFGH");

        for unsafe_path in [
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example",
            "/x\nLocation: https://evil.example",
            "dashboard",
        ] {
            assert_eq!(safe_return_to(unsafe_path), None, "{unsafe_path:?}");
        }
        assert_eq!(clean_auth_request_id(&"a".repeat(257)), None);
        assert_eq!(clean_auth_request_id("a\u{7}"), None);
        assert_eq!(ReturnTarget::default().completion(), "/dashboard/");
    }

    #[test]
    fn refusals_land_on_login_with_a_fixed_code_and_the_target() {
        let target = ReturnTarget::sanitized("request-id", "");
        let response = login_with_refusal(Refusal::LinkRequired, &target, Vec::new());
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/login?oauth_error=link_required&authRequestID=request-id"
        );
    }

    #[test]
    fn pkce_challenges_are_s256_of_the_verifier() {
        // RFC 7636 Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let verifier = pkce_verifier();
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn oauth_cookies_are_http_only_lax_scoped_and_secure_on_https() {
        let value = cookie(STATE_COOKIE, "abc", STATE_COOKIE_PATH, 600, true);
        assert_eq!(
            value,
            "codewire_oauth_state=abc; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        let cleared = clear_cookie(STATE_COOKIE, STATE_COOKIE_PATH, false);
        assert_eq!(
            cleared,
            "codewire_oauth_state=; Path=/api/auth/oauth/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn a_cookie_sent_twice_is_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire_oauth_state=one; other=x"),
        );
        assert_eq!(unique_cookie(&headers, STATE_COOKIE), Some("one"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("codewire_oauth_state=two"),
        );
        assert_eq!(unique_cookie(&headers, STATE_COOKIE), None);
    }
}
