//! Sign in with GitHub or Google (#4062): `codewire-idp` is an OAuth client
//! of both providers and owns the whole round trip.
//!
//! - `GET /api/auth/oauth/providers` names the configured providers (no
//!   secrets); the dashboard shows a button for each.
//! - `GET /api/auth/oauth/{provider}/start` writes nothing: it seals the
//!   hash of a random state, the PKCE verifier, a Google nonce and the return
//!   target into an HttpOnly Lax cookie scoped to `/api/auth/oauth/`
//!   ([`state_cookie`]), and redirects to the provider.
//! - `GET /api/auth/oauth/{provider}/callback` opens that cookie for the
//!   `state` query (a link from Settings instead claims its row), exchanges
//!   the code server-side with the verifier, records the state as used, reads
//!   a verified email (GitHub's primary, or Google's ID token after its `iss`,
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

mod link_confirm;
mod providers;
mod sign_in_methods;
mod sign_up;
mod state_cookie;

pub use providers::{
    OAuthProviders, OAuthUpstream, Provider, ReqwestUpstream, UpstreamError, UpstreamRequest,
    UpstreamResponse,
};
pub use state_cookie::{EmptySessionSecret, StateCookieKey};

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_email::EmailClient;
use codewire_server_core::auth::hash_session_token;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::auth_session::{
    CreatedSession, SessionAuthState, SignupInvitePolicy, SignupMode, TWO_FACTOR_TOKEN_TTL_SECS,
    UserAuthRow, configured_human_verification, create_session, hex_id, hex_token, log_audit,
    log_audit_in, request_info, session_cookie_string,
};
use crate::email_password::{send_provider_link_confirmation_email, send_provider_linked_email};
use providers::{IdentityError, ProviderIdentity};
pub(crate) use sign_in_methods::LINKED_ACCOUNT_SQL;
use state_cookie::SignInStart;

/// The browser's half of a round trip: a sealed sign-in, or the raw state of
/// a link's row.
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
/// How often the IdP deletes expired `oauth_states` rows, and how many
/// batches one pass may delete.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const MAX_SWEEP_BATCHES: u32 = 100;
/// What a used sign-in's marker row holds where the schema requires a PKCE
/// verifier and a Google nonce: the shortest values the checks accept.
const MARKER_VERIFIER: &str = "-------------------------------------------";
const MARKER_NONCE: &str = "----------------";
const MAX_AUTH_REQUEST_ID_BYTES: usize = 256;
const MAX_RETURN_TO_BYTES: usize = 2048;
const MAX_CODE_BYTES: usize = 2048;
/// A browser keeps a cookie of up to 4096 bytes; the largest sealed sign-in
/// fits.
const MAX_STATE_COOKIE_BYTES: usize = 4096;

/// The fixed reasons a round trip lands back on `/login`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The provider is not configured.
    Unavailable,
    /// The person cancelled or denied access at the provider.
    Cancelled,
    /// The state cookie or row is missing, mismatched, expired or used, or a
    /// newer start in another tab replaced the cookie.
    Expired,
    /// The provider has no verified email for the account.
    UnverifiedEmail,
    /// An account has this email but never verified it: sign in and link.
    LinkRequired,
    /// The account is temporarily locked.
    Locked,
    /// The account's access is not enabled.
    Disabled,
    /// An invite-only server: sign up from the invite link, then connect the
    /// provider in Settings (#4121).
    InviteOnly,
    /// Anything else: the provider failed or answered badly.
    Failed,
}

impl Refusal {
    /// The same refusal on a link from Settings.
    fn link_result(self) -> sign_in_methods::LinkResult {
        use sign_in_methods::LinkResult;
        match self {
            Self::Cancelled => LinkResult::Cancelled,
            Self::Expired => LinkResult::Expired,
            Self::UnverifiedEmail => LinkResult::UnverifiedEmail,
            Self::Unavailable => LinkResult::Unavailable,
            Self::LinkRequired
            | Self::Locked
            | Self::Disabled
            | Self::InviteOnly
            | Self::Failed => LinkResult::Failed,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::UnverifiedEmail => "unverified_email",
            Self::LinkRequired => "link_required",
            Self::Locked => "locked",
            Self::Disabled => "disabled",
            Self::InviteOnly => "invite_only",
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
    state_key: StateCookieKey,
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
    state_key: StateCookieKey,
    operator_email: Option<String>,
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
            client_address_key,
        )
        .with_operator_email(operator_email),
        providers,
        mailer,
        state_key,
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
        state_key: StateCookieKey::derive("synthetic-oauth-state-secret")
            .expect("the synthetic secret is not empty"),
    })
}

/// [`trusted_test_router`] whose sign-ups send the operator's notice to
/// `operator_email` through `email` (#5358).
#[allow(clippy::too_many_arguments)]
pub fn trusted_test_router_with_operator(
    pool: PgPool,
    secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    providers: OAuthProviders,
    mailer: Arc<dyn LinkConfirmationMailer>,
    email: EmailClient,
    operator_email: String,
) -> Router {
    let mut session =
        SessionAuthState::trusted_test(pool, secure, signup_invite_policy, frontend_url)
            .with_operator_email(Some(operator_email));
    session.email = email;
    router_with_state(OAuthState {
        session,
        providers,
        mailer,
        state_key: StateCookieKey::derive("synthetic-oauth-state-secret")
            .expect("the synthetic secret is not empty"),
    })
}

fn router_with_state(state: OAuthState) -> Router {
    Router::new()
        .route("/api/auth/oauth/providers", get(providers_list))
        .route("/api/auth/oauth/{provider}/start", get(start))
        .route("/api/auth/oauth/{provider}/callback", get(callback))
        .merge(sign_up::router())
        .merge(link_confirm::router())
        .merge(sign_in_methods::router())
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
    found.filter(|value| !value.is_empty() && value.len() <= MAX_STATE_COOKIE_BYTES)
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

/// Delete expired `oauth_states` rows every few minutes, whatever the
/// traffic: no request path deletes them.
pub fn spawn_expired_state_sweeper(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = sweep_expired_states(&pool).await {
                tracing::warn!(%error, "OAuth state sweep failed");
            }
        }
    });
}

/// One sweep: bounded batches of expired rows until none is left or the
/// pass has deleted [`MAX_SWEEP_BATCHES`] of them.
pub async fn sweep_expired_states(pool: &PgPool) -> Result<(), sqlx::Error> {
    for _ in 0..MAX_SWEEP_BATCHES {
        if !crate::expired_rows::oauth_states(pool).await? {
            break;
        }
    }
    Ok(())
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

    let start = SignInStart::new(
        &raw_state,
        verifier,
        nonce,
        target,
        chrono::Utc::now().timestamp() + STATE_TTL_SECS,
    );
    let sealed = match state_cookie::seal(&state.state_key, provider, &start) {
        Ok(sealed) => sealed,
        Err(error) => {
            tracing::error!(%error, provider = provider.as_str(), "failed to seal OAuth state");
            return login_with_refusal(Refusal::Failed, &start.target, Vec::new());
        }
    };

    see_other(
        &location,
        vec![cookie(
            STATE_COOKIE,
            &sealed,
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

/// A link's row, claimed by its callback.
#[derive(sqlx::FromRow)]
struct ClaimedLink {
    provider: String,
    user_id: String,
    pkce_verifier: String,
    nonce: Option<String>,
    live: bool,
}

/// A round trip refused before the exchange, by where it lands: `/login`, or
/// Settings once a link's row is claimed.
enum Unclaimed {
    SignIn(Refusal),
    Link(Refusal),
}

/// A round trip this browser started, ready for the provider exchange.
struct RoundTrip {
    intent: Intent,
    verifier: String,
    nonce: Option<String>,
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

/// What a claimed round trip was for: a sign-in returning to its target, or
/// a signed-in account linking a provider from Settings.
enum Intent {
    SignIn(ReturnTarget),
    Link(String),
}

impl Intent {
    fn refuse(&self, refusal: Refusal, provider: Provider, cookies: Vec<HeaderValue>) -> Response {
        match self {
            Self::SignIn(target) => login_with_refusal(refusal, target, cookies),
            Self::Link(_) => {
                sign_in_methods::settings_landing(refusal.link_result(), provider, cookies)
            }
        }
    }
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

    let Some(provider) = Provider::parse(&provider).filter(|p| state.providers.is_configured(*p))
    else {
        return login_with_refusal(Refusal::Unavailable, &ReturnTarget::default(), cookies);
    };
    let RoundTrip {
        intent,
        verifier,
        nonce,
    } = match claim_round_trip(&state, provider, &query.state, &headers).await {
        Ok(round_trip) => round_trip,
        Err(Unclaimed::SignIn(refusal)) => {
            return login_with_refusal(refusal, &ReturnTarget::default(), cookies);
        }
        Err(Unclaimed::Link(refusal)) => {
            return sign_in_methods::settings_landing(refusal.link_result(), provider, cookies);
        }
    };
    if !query.error.is_empty() {
        let refusal = if query.error == "access_denied" {
            Refusal::Cancelled
        } else {
            Refusal::Failed
        };
        return intent.refuse(refusal, provider, cookies);
    }
    if query.code.is_empty() || query.code.len() > MAX_CODE_BYTES {
        return intent.refuse(Refusal::Failed, provider, cookies);
    }

    let identity = match state
        .providers
        .identify(
            provider,
            &query.code,
            &verifier,
            &state.redirect_uri(provider),
            nonce.as_deref(),
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
            return intent.refuse(refusal, provider, cookies);
        }
    };
    let target = match intent {
        Intent::SignIn(target) => target,
        Intent::Link(account_id) => {
            return sign_in_methods::finish(
                &state,
                provider,
                &account_id,
                &identity,
                &headers,
                cookies,
            )
            .await;
        }
    };
    match mark_used(&state.session.pool, provider, &query.state).await {
        Ok(true) => {}
        Ok(false) => return login_with_refusal(Refusal::Expired, &target, cookies),
        Err(error) => {
            tracing::error!(%error, "failed to record a used OAuth state");
            return login_with_refusal(Refusal::Failed, &target, cookies);
        }
    }

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

/// Open this browser's round trip for `provider`'s callback, whose `state`
/// parameter is `raw_state`, or the refusal that ends it before any exchange.
/// A sign-in's cookie is sealed; a link's is the raw state of its row, which
/// is deleted in the statement that reads it, so it is used once even when
/// two callbacks race. Only `link` rows are claimed: a `sign_in` row is a
/// used state's marker, or a start from the release before sealed cookies.
async fn claim_round_trip(
    state: &OAuthState,
    provider: Provider,
    raw_state: &str,
    headers: &HeaderMap,
) -> Result<RoundTrip, Unclaimed> {
    let refuse = Unclaimed::SignIn;
    let Some(browser_state) = unique_cookie(headers, STATE_COOKIE) else {
        return Err(refuse(Refusal::Expired));
    };
    if !valid_handle(browser_state) {
        let now = chrono::Utc::now().timestamp();
        let start = state_cookie::open(&state.state_key, provider, browser_state, raw_state, now)
            .map_err(|error| {
            tracing::debug!(%error, provider = provider.as_str(), "OAuth state cookie refused");
            refuse(Refusal::Expired)
        })?;
        return Ok(RoundTrip {
            intent: Intent::SignIn(start.target),
            verifier: start.verifier,
            nonce: start.nonce,
        });
    }

    if raw_state.is_empty() || !same_secret(browser_state.as_bytes(), raw_state.as_bytes()) {
        return Err(refuse(Refusal::Expired));
    }
    let claimed = sqlx::query_as::<_, ClaimedLink>(
        r#"
        DELETE FROM oauth_states
         WHERE token_hash = $1 AND intent = 'link'
        RETURNING provider, user_id, pkce_verifier, nonce, expires_at > NOW() AS live
        "#,
    )
    .bind(hash_session_token(raw_state))
    .fetch_optional(&state.session.pool)
    .await;
    let claimed = match claimed {
        Ok(Some(claimed)) => claimed,
        Ok(None) => return Err(refuse(Refusal::Expired)),
        Err(error) => {
            tracing::error!(%error, "failed to claim OAuth state");
            return Err(refuse(Refusal::Failed));
        }
    };
    let intent = Intent::Link(claimed.user_id);
    if !claimed.live || claimed.provider != provider.as_str() {
        return Err(Unclaimed::Link(Refusal::Expired));
    }
    Ok(RoundTrip {
        intent,
        verifier: claimed.pkce_verifier,
        nonce: claimed.nonce,
    })
}

/// Record a sign-in's state as used once the provider has accepted its code,
/// so a second callback with it is refused: `false` when one already was.
/// Written after the exchange, a marker costs a real round trip, which an
/// unauthenticated client cannot repeat at will. The schema's `sign_in` shape
/// requires a verifier and, for Google, a nonce; the marker holds fixed
/// sentinels, never the spent values, and nothing reads them. The marker
/// lives a full round trip from now, past the cookie it guards.
async fn mark_used(
    pool: &PgPool,
    provider: Provider,
    raw_state: &str,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO oauth_states
            (id, token_hash, provider, intent, pkce_verifier, nonce, expires_at)
        VALUES ($1, $2, $3, 'sign_in', $4, $5,
                NOW() + ($6::bigint * interval '1 second'))
        ON CONFLICT (token_hash) DO NOTHING
        "#,
    )
    .bind(hex_id())
    .bind(hash_session_token(raw_state))
    .bind(provider.as_str())
    .bind(MARKER_VERIFIER)
    .bind((provider == Provider::Google).then_some(MARKER_NONCE))
    .bind(STATE_TTL_SECS)
    .execute(pool)
    .await?;
    Ok(inserted.rows_affected() == 1)
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
                [] if state.session.signup_invite_policy.mode() == SignupMode::InviteOnly => {
                    tx.rollback().await.map_err(failed)?;
                    return Err(Refusal::InviteOnly);
                }
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
                            {
                                let mut metadata =
                                    sign_in_methods::identity_audit(provider, identity);
                                metadata["automatic"] = json!(true);
                                metadata["confirmed_by"] = json!("provider");
                                metadata
                            },
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
               onboarding_completed_at IS NOT NULL AS onboarding_completed,
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
        "account": &identity.account,
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

fn valid_handle(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
