//! In-process synthetic provider. It never constructs an HTTP client.
//!
//! The public prompt markers select one-shot provider failure schedules. The
//! resulting counters prove only this provider schedule; the harness must
//! independently observe native auth-command rereads and real Pod identities.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};
#[cfg(feature = "kind-e2e")]
use codewire_credential_broker::{SyntheticOpenAiSmokeTransport, SyntheticProviderHost};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};

use super::TARGET;

pub(super) const ACCOUNT: &str = "codewire-kind-synthetic-account";
// Fixed public device-login values. Approval is automatic: the first poll
// after the challenge is approved, so the journey still observes a challenge.
const CODEX_DEVICE_AUTH_ID: &str = "kind-synthetic-codex-device-auth";
const CODEX_USER_CODE: &str = "KIND-CODX";
const CODEX_AUTHORIZATION_CODE: &str = "kind-synthetic-codex-authorization-code";
const CODEX_CODE_VERIFIER: &str = "kind-synthetic-codex-code-verifier";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const GITHUB_DEVICE_CODE: &str = "kind-synthetic-github-device-code";
const GITHUB_USER_CODE: &str = "KIND-GHUB";
const TOKEN_SIGNATURE: &str = "synthetic-kind-signature";
const MAX_GENERATION: u64 = 10_000;
const MAX_BODY: usize = 4 * 1024 * 1024;
const RETRY_MARKER: &[u8] = b"CW_KIND_BROKER_RETRY_ONCE";
const EXHAUSTED_MARKER: &[u8] = b"CW_KIND_BROKER_RETRY_EXHAUSTED";
const LEGACY_REREAD_MARKER: &[u8] = b"CW_KIND_NATIVE_REREAD";

// Fixed, non-secret identities for the checked-in Kind fixture.  They are
// deliberately accepted only by this in-process provider, never a network
// listener or production configuration path.
#[cfg(feature = "kind-e2e")]
pub(super) const OPENAI_API_KEY: &str = "cwlocalopenai0123456789abcdef0123456789abcdef";
#[cfg(feature = "kind-e2e")]
pub(super) const ANTHROPIC_API_KEY: &str = "cwlocalanthropic0123456789abcdef0123456789abcdef";
pub(super) const GITHUB_APP_CLIENT_ID: &str = "Iv1.kindsynthetic";
pub(super) const GITHUB_APP_CLIENT_SECRET: &str = "kind-synthetic-secret";
pub(super) const GITHUB_APP_SLUG: &str = "codewire-synthetic";
/// The registered GitHub App callback on the harness ingress origin.
pub(super) fn github_app_callback_url(public_origin: &str) -> String {
    format!("{public_origin}/api/v1/github/oauth/callback")
}
pub(super) const GITHUB_APP_USER_TOKEN: &str = "ghu_kind_synthetic_user_token_1234567890";
const GITHUB_APP_UNINSTALLED_USER_TOKEN: &str = "ghu_kind_synthetic_uninstalled_user_1234567890";
/// A login whose installations still have the grant from before the App asked
/// for write access: its own and an organization's. Connect succeeds, sends
/// the person to accept on the first and names the second.
const GITHUB_APP_LIMITED_USER_TOKEN: &str = "ghu_kind_synthetic_limited_user_token_1234567890";
/// A login whose installation listing answers its connect (which reads
/// `/user` first) and fails every later live status read (#2712): the page
/// must then show nothing and still render.
const GITHUB_APP_UNRELIABLE_USER_TOKEN: &str =
    "ghu_kind_synthetic_unreliable_user_token_1234567890";
pub(super) const GITHUB_APP_REFRESHED_USER_TOKEN: &str =
    "ghu_kind_synthetic_refreshed_user_token_1234567890";
const GITHUB_APP_INITIAL_REFRESH_TOKEN: &str =
    "ghr_kind_synthetic_initial_refresh_token_1234567890";
const GITHUB_APP_REFRESHED_REFRESH_TOKEN: &str =
    "ghr_kind_synthetic_refreshed_refresh_token_1234567890";
const GITHUB_APP_AUTHORIZATION_CODES: [&str; 2] =
    ["kind-synthetic-code-one", "kind-synthetic-code-two"];

// Fixed, public synthetic Anthropic credentials of the Kind Claude Code
// journey (scripts/ci/verify/kind/credentials.sh adds them through the public
// CLI). Each carries a distinctive marker that the in-workspace driver
// searches for to prove neither value reached the Sandbox. They are accepted
// only by this in-process provider, never by a listener or a real provider.
pub(super) const KIND_ANTHROPIC_API_KEY: &str =
    "sk-ant-api03-CW_KIND_SYNTHETIC_ANTHROPIC_KEY-0123456789abcdef";
pub(super) const KIND_CLAUDE_SUBSCRIPTION_TOKEN: &str =
    "sk-ant-oat01-CW_KIND_SYNTHETIC_CLAUDE_TOKEN-0123456789abcdef";
/// A well-formed subscription token the fixture refuses as a real provider
/// refuses an expired or revoked one: a 401 `authentication_error`. The
/// journey proves the broker passes that answer through and leaves the
/// credential Active until its owner replaces it.
pub(super) const KIND_CLAUDE_REFUSED_TOKEN: &str =
    "sk-ant-oat01-CW_KIND_SYNTHETIC_REFUSED_TOKEN-0123456789abcdef";
/// The one code the fixture's Claude token endpoint redeems for a sign-in.
/// The journey pastes it after `#` and the state of the authorize URL the CLI
/// prints, exactly as a person pastes what Claude shows.
pub(super) const KIND_CLAUDE_SIGN_IN_CODE: &str = "kind-synthetic-claude-sign-in-code";
const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_MANUAL_REDIRECT_URL: &str = "https://platform.claude.com/oauth/code/callback";
const CLAUDE_SIGN_IN_SCOPES: &str = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins";
/// A sign-in's first access token expires within the broker's five-minute
/// refresh window, so its first use refreshes it; rotated ones last 8 hours.
const CLAUDE_SIGN_IN_FIRST_LIFETIME: u64 = 301;
const CLAUDE_SIGN_IN_LIFETIME: u64 = 28_800;
/// The Sandbox's projected value. Reaching the provider means the broker did
/// not replace it, so it is always rejected.
const ANTHROPIC_PLACEHOLDER: &str = "codewire-managed";
const ANTHROPIC_OAUTH_BETA: &str = "oauth-2025-04-20";
/// Fixed public reply text Claude Code prints for the Kind journey.
const CLAUDE_MARKER: &str = "CWCLAUDE kind";
const MAX_ANTHROPIC_MODEL: usize = 128;

// Same minimal stock-Codex-compatible Responses SSE shape as the checked-in
// local-vmm Codex bridge smoke. All text is fixed, public and synthetic.
const SSE: &[u8] = concat!(
    "event: response.created\n",
    "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codewire_kind\"}}\n\n",
    "event: response.output_item.done\n",
    "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"role\":\"assistant\",\"id\":\"msg_codewire_kind\",\"content\":[{\"type\":\"output_text\",\"text\":\"CWCODEX149 kind\"}]}}\n\n",
    "event: response.completed\n",
    "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codewire_kind\",\"usage\":{\"input_tokens\":0,\"input_tokens_details\":null,\"output_tokens\":0,\"output_tokens_details\":null,\"total_tokens\":0}}}\n\n",
).as_bytes();

#[derive(Clone, Copy)]
enum Scenario {
    Baseline,
    BrokerRetryOnce,
    BrokerRetryExhausted,
}

impl Scenario {
    fn index(self) -> usize {
        match self {
            Self::Baseline => 0,
            Self::BrokerRetryOnce => 1,
            Self::BrokerRetryExhausted => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::BrokerRetryOnce => "broker_retry_once",
            Self::BrokerRetryExhausted => "broker_retry_exhausted",
        }
    }

    fn status(self, attempt: u64) -> StatusCode {
        match self {
            Self::Baseline => StatusCode::OK,
            Self::BrokerRetryOnce if attempt == 1 => StatusCode::UNAUTHORIZED,
            Self::BrokerRetryExhausted if attempt == 1 => StatusCode::UNAUTHORIZED,
            // Exercise a failed broker replay without also selecting stock
            // Codex's outer retry policy for 401/5xx. The broker unit test
            // retries_an_oauth_unauthorized_response_only_once separately
            // proves 401 -> refresh -> 401 with exactly two upstream calls.
            // Unexpected extra calls remain counted and fail the exact audit.
            Self::BrokerRetryExhausted => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        }
    }

    fn from_body(body: &[u8]) -> Result<Self, BrokerUpstreamError> {
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(BrokerUpstreamError::Protocol);
        }
        let request: Value =
            serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
        let input = request.get("input").ok_or(BrokerUpstreamError::Protocol)?;
        if !input.is_array() && !input.is_string() {
            return Err(BrokerUpstreamError::Protocol);
        }
        let input = serde_json::to_vec(input).map_err(|_| BrokerUpstreamError::Protocol)?;
        let retry = input
            .windows(RETRY_MARKER.len())
            .any(|window| window == RETRY_MARKER);
        if input
            .windows(LEGACY_REREAD_MARKER.len())
            .any(|window| window == LEGACY_REREAD_MARKER)
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let exhausted = input
            .windows(EXHAUSTED_MARKER.len())
            .any(|window| window == EXHAUSTED_MARKER);
        match (retry, exhausted) {
            (false, false) => Ok(Self::Baseline),
            (true, false) => Ok(Self::BrokerRetryOnce),
            (false, true) => Ok(Self::BrokerRetryExhausted),
            (true, true) => Err(BrokerUpstreamError::Protocol),
        }
    }
}

/// Which Anthropic credential form a request presented. The broker selects
/// it from the stored credential's kind; the provider only observes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnthropicKind {
    ApiKey,
    SubscriptionToken,
    SignIn,
}

impl AnthropicKind {
    fn name(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::SubscriptionToken => "subscription_token",
            Self::SignIn => "sign_in",
        }
    }
}

/// The fixture's synthetic Claude sign-in tokens of one generation. Each code
/// exchange or refresh issues the next generation; only the latest is valid,
/// so a stale or replayed token is refused like a rotated one.
fn claude_sign_in_access(generation: u64) -> String {
    format!("sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-{generation:06}")
}

fn claude_sign_in_refresh(generation: u64) -> String {
    format!("sk-ant-ort01-CW_KIND_SYNTHETIC_SIGN_IN_REFRESH-{generation:06}")
}

/// One admitted Anthropic request: the form and real synthetic credential it
/// presented, and whether that credential is the one the fixture refuses.
#[derive(Debug, PartialEq, Eq)]
struct AdmittedAnthropic {
    kind: AnthropicKind,
    route: AnthropicRoute,
    stream: bool,
    model: String,
    refused: bool,
    client_identity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnthropicRoute {
    Messages,
    CountTokens,
}

impl AnthropicRoute {
    fn name(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count_tokens",
        }
    }
}

/// Closed reasons a presented Anthropic request is rejected as malformed. Each
/// is a transport-level protocol failure, so a malformed request never looks
/// like the provider's 401 for the refused token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnthropicRejection {
    Route,
    Placeholder,
    Credential,
    OAuthBeta,
    Headers,
    Body,
}

impl AnthropicRejection {
    fn name(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Placeholder => "placeholder",
            Self::Credential => "credential",
            Self::OAuthBeta => "oauth_beta",
            Self::Headers => "headers",
            Self::Body => "body",
        }
    }
}

#[derive(Default)]
struct Counters {
    #[cfg(feature = "kind-e2e")]
    openai_api_attempts: u64,
    #[cfg(feature = "kind-e2e")]
    anthropic_api_attempts: u64,
    responses: u64,
    refreshes: u64,
    attempts: [u64; 3],
    required_generation: [Option<u64>; 3],
    last_refresh: Option<(u64, u64)>,
    github_advertisements: u64,
    github_upload_packs: u64,
    github_app_refreshes: u64,
    github_refreshed_advertisements: u64,
    github_refreshed_upload_packs: u64,
    anthropic_calls: u64,
    anthropic_rejections: u64,
    /// The latest Claude sign-in token generation issued; 0 before any.
    claude_sign_in_generation: u64,
    claude_sign_in_refreshes: u64,
    /// Set by `/user` for the unreliable login; its next installation
    /// listing, connect's, answers.
    github_unreliable_listing: bool,
}

#[derive(Clone)]
pub(super) struct SyntheticProvider(
    Arc<Mutex<Counters>>,
    Option<Arc<super::git::Fixture>>,
    // The GitHub App callback the exchange must name.
    Arc<str>,
);

impl SyntheticProvider {
    pub(super) fn new() -> Self {
        Self(
            Arc::new(Mutex::new(Counters::default())),
            None,
            github_app_callback_url(super::config::DEFAULT_PUBLIC_ORIGIN).into(),
        )
    }

    pub(super) fn with_git(git: Arc<super::git::Fixture>, public_origin: &str) -> Self {
        Self(
            Arc::new(Mutex::new(Counters::default())),
            Some(git),
            github_app_callback_url(public_origin).into(),
        )
    }

    fn github_app_exchange_body(&self, code: &str) -> String {
        let redirect_uri: String =
            url::form_urlencoded::byte_serialize(self.2.as_bytes()).collect();
        format!(
            "client_id={GITHUB_APP_CLIENT_ID}&client_secret={GITHUB_APP_CLIENT_SECRET}&code={code}&redirect_uri={redirect_uri}"
        )
    }

    async fn github_git(
        &self,
        method: &Method,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let fixture = self.1.as_ref().ok_or(BrokerUpstreamError::Protocol)?;
        let refreshed_app = github_refreshed_app_git_authorization(headers);
        let (operation, body) = fixture.execute(method, target, headers, body).await?;
        {
            let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
            match operation {
                super::git::Operation::Advertisement => {
                    counters.github_advertisements = increment(counters.github_advertisements)?;
                    if refreshed_app {
                        counters.github_refreshed_advertisements =
                            increment(counters.github_refreshed_advertisements)?;
                    }
                }
                super::git::Operation::UploadPack => {
                    counters.github_upload_packs = increment(counters.github_upload_packs)?;
                    if refreshed_app {
                        counters.github_refreshed_upload_packs =
                            increment(counters.github_refreshed_upload_packs)?;
                    }
                }
            }
            // Only successful authenticated backend responses advance these
            // closed counters. The refreshed-App counters identify only the
            // fixed public fixture scenario, never a header or token value.
            tracing::info!(target: TARGET, event = "github_git_response", operation = operation.name(),
                github_advertisement_calls = counters.github_advertisements,
                github_upload_pack_calls = counters.github_upload_packs,
                github_refreshed_advertisement_calls = counters.github_refreshed_advertisements,
                github_refreshed_upload_pack_calls = counters.github_refreshed_upload_packs,
                "github_git_response");
        }
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static(operation.media_type()),
            )]),
            Box::pin(futures::stream::once(async move { Ok(body.into()) })),
        ))
    }

    fn github_app_exchange(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !exact_headers(
            headers,
            &[
                ("accept", "application/json"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("user-agent", "Codewire-Credential-Service"),
            ],
        ) {
            return Err(BrokerUpstreamError::Protocol);
        }
        if body
            == self
                .github_app_exchange_body(GITHUB_APP_AUTHORIZATION_CODES[0])
                .as_bytes()
        {
            // 60 seconds is valid for GitHub App user tokens, but inside the
            // five-minute renewal skew. The managed browser journey therefore
            // proves durable controlled refresh before its protected checkout.
            return json_response(json!({
                "access_token": GITHUB_APP_USER_TOKEN,
                "token_type": "bearer",
                "expires_in": 60,
                "refresh_token": GITHUB_APP_INITIAL_REFRESH_TOKEN,
                "refresh_token_expires_in": 15_897_600,
            }));
        }
        if body
            == self
                .github_app_exchange_body(GITHUB_APP_AUTHORIZATION_CODES[1])
                .as_bytes()
        {
            // The duplicate-account browser path retains a non-expiring
            // response as a compatibility check; it is never persisted.
            return json_response(json!({
                "access_token": GITHUB_APP_USER_TOKEN,
                "token_type": "bearer",
            }));
        }
        if body
            == self
                .github_app_exchange_body("kind-synthetic-code-uninstalled")
                .as_bytes()
        {
            return json_response(json!({
                "access_token": GITHUB_APP_UNINSTALLED_USER_TOKEN,
                "token_type": "bearer",
            }));
        }
        if body
            == self
                .github_app_exchange_body("kind-synthetic-code-limited")
                .as_bytes()
        {
            return json_response(json!({
                "access_token": GITHUB_APP_LIMITED_USER_TOKEN,
                "token_type": "bearer",
            }));
        }
        if body
            == self
                .github_app_exchange_body("kind-synthetic-code-unreliable")
                .as_bytes()
        {
            return json_response(json!({
                "access_token": GITHUB_APP_UNRELIABLE_USER_TOKEN,
                "token_type": "bearer",
            }));
        }
        if body != github_app_refresh_body().as_bytes() {
            return Err(BrokerUpstreamError::Protocol);
        }
        let refreshes = {
            let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
            counters.github_app_refreshes = increment(counters.github_app_refreshes)?;
            counters.github_app_refreshes
        };
        // This closed count intentionally omits request material. It lets the
        // managed browser fixture distinguish the one durable App renewal
        // from a merely successful initial callback.
        tracing::info!(target: TARGET, event = "github_app_refresh",
            github_app_refresh_calls = refreshes, "github_app_refresh");
        json_response(json!({
            "access_token": GITHUB_APP_REFRESHED_USER_TOKEN,
            "token_type": "bearer",
            "expires_in": 28_800,
            "refresh_token": GITHUB_APP_REFRESHED_REFRESH_TOKEN,
            "refresh_token_expires_in": 15_897_600,
        }))
    }

    fn github_app_user(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !body.is_empty() || !github_app_api_headers(headers) {
            return Err(BrokerUpstreamError::Protocol);
        }
        if headers.get("authorization").is_some_and(|value| {
            value == format!("Bearer {GITHUB_APP_UNRELIABLE_USER_TOKEN}").as_str()
        }) {
            self.0
                .lock()
                .map_err(|_| BrokerUpstreamError::Protocol)?
                .github_unreliable_listing = true;
        }
        json_response(json!({"id": 7, "login": "synthetic-user"}))
    }

    fn github_app_installations(
        &self,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !body.is_empty()
            || target.as_str() != "https://api.github.com/user/installations?per_page=100&page=1"
            || !github_app_api_headers(headers)
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let bearer = |token: &str| {
            headers
                .get("authorization")
                .is_some_and(|value| value == format!("Bearer {token}").as_str())
        };
        if bearer(GITHUB_APP_UNINSTALLED_USER_TOKEN) {
            return json_response(json!({"installations": []}));
        }
        let account = json!({"login": "synthetic-user", "type": "User"});
        if bearer(GITHUB_APP_UNRELIABLE_USER_TOKEN) {
            let connecting = std::mem::take(
                &mut self
                    .0
                    .lock()
                    .map_err(|_| BrokerUpstreamError::Protocol)?
                    .github_unreliable_listing,
            );
            if !connecting {
                return Ok(BrokerUpstreamResponse::new(
                    StatusCode::BAD_GATEWAY,
                    HeaderMap::from_iter([(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    )]),
                    Box::pin(futures::stream::once(async { Ok(b"{}".to_vec().into()) })),
                ));
            }
            return json_response(json!({
                "installations": [{"id": 41, "app_slug": GITHUB_APP_SLUG, "account": account,
                    "repository_selection": "selected",
                    "permissions": {"contents": "read", "metadata": "read"}}],
            }));
        }
        if bearer(GITHUB_APP_LIMITED_USER_TOKEN) {
            // The same installation before its owner accepted write access,
            // and an organization's installation in the same state.
            let earlier = json!({"contents": "read", "metadata": "read"});
            return json_response(json!({
                "installations": [
                    {"id": 41, "app_slug": GITHUB_APP_SLUG, "account": account,
                        "repository_selection": "selected", "permissions": earlier.clone()},
                    {"id": 42, "app_slug": GITHUB_APP_SLUG,
                        "account": {"login": "synthetic-works", "type": "Organization"},
                        "repository_selection": "selected", "permissions": earlier},
                ],
            }));
        }
        json_response(json!({
            "installations": [{"id": 41, "app_slug": GITHUB_APP_SLUG, "account": account,
                "repository_selection": "selected",
                "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"}}],
        }))
    }

    fn github_repositories(
        &self,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let values = target.query_pairs().collect::<Vec<_>>();
        let size = values
            .first()
            .filter(|(key, _)| key == "per_page")
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .filter(|size| (1..=100).contains(size))
            .ok_or(BrokerUpstreamError::Protocol)?;
        let page = values
            .get(1)
            .filter(|(key, _)| key == "page")
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .filter(|page| (1..=10_000).contains(page))
            .ok_or(BrokerUpstreamError::Protocol)?;
        if !body.is_empty()
            || target.as_str()
                != format!(
                    "https://api.github.com/user/repos?per_page={size}&page={page}&sort=full_name&direction=asc"
                )
            || headers.get_all("authorization").iter().count() != 1
            || !github_bearer_authorization(headers)
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let repositories = github_repository_values(page, size);
        let bytes = serde_json::to_vec(&repositories).map_err(|_| BrokerUpstreamError::Protocol)?;
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move { Ok(bytes.into()) })),
        ))
    }

    pub(super) fn log_totals(&self) {
        if let Ok(counters) = self.0.lock() {
            tracing::info!(target: TARGET, event = "provider_totals", response_calls = counters.responses,
                refresh_calls = counters.refreshes, baseline_calls = counters.attempts[0],
                broker_retry_once_calls = counters.attempts[1], broker_retry_exhausted_calls = counters.attempts[2],
                github_advertisement_calls = counters.github_advertisements,
                github_upload_pack_calls = counters.github_upload_packs,
                github_app_refresh_calls = counters.github_app_refreshes,
                github_refreshed_advertisement_calls = counters.github_refreshed_advertisements,
                github_refreshed_upload_pack_calls = counters.github_refreshed_upload_packs,
                anthropic_calls = counters.anthropic_calls,
                anthropic_rejections = counters.anthropic_rejections,
                "provider_totals");
        }
    }

    /// The Anthropic Messages and token-counting routes as the broker sends
    /// them, for either credential form. An accepted request presented the
    /// fixture's real synthetic credential in exactly its form: the API key
    /// alone in `x-api-key`, or the subscription token alone as a bearer with
    /// the OAuth beta. The placeholder or any other value is refused. Only the
    /// closed form, route and counters are logged, never a header or body.
    fn anthropic(
        &self,
        method: &Method,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        match self.admit_anthropic(method, target, headers, body) {
            Ok(admitted) => {
                let calls = {
                    let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
                    counters.anthropic_calls = increment(counters.anthropic_calls)?;
                    counters.anthropic_calls
                };
                let status = if admitted.refused { 401_u16 } else { 200 };
                // `client_identity` is a closed boolean: whether Claude Code's
                // own `x-app` and `user-agent` reached the provider, which the
                // transparent broker route forwards in both forms.
                tracing::info!(target: TARGET, event = "anthropic_response",
                    kind = admitted.kind.name(), route = admitted.route.name(),
                    stream = admitted.stream, status, refused = admitted.refused,
                    client_identity = admitted.client_identity, anthropic_calls = calls,
                    "anthropic_response");
                if admitted.refused {
                    anthropic_refusal()
                } else {
                    anthropic_response(admitted.route, admitted.stream, &admitted.model)
                }
            }
            Err(rejection) => {
                let rejections = {
                    let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
                    counters.anthropic_rejections = increment(counters.anthropic_rejections)?;
                    counters.anthropic_rejections
                };
                tracing::info!(target: TARGET, event = "anthropic_rejected",
                    reason = rejection.name(), anthropic_rejections = rejections,
                    "anthropic_rejected");
                Err(BrokerUpstreamError::Protocol)
            }
        }
    }

    /// `Bearer` and the latest sign-in access token, once one was issued.
    fn current_claude_sign_in_bearer(&self) -> Option<String> {
        let generation = self.0.lock().ok()?.claude_sign_in_generation;
        (generation > 0).then(|| format!("Bearer {}", claude_sign_in_access(generation)))
    }

    /// An OAuth bearer must carry the provider's OAuth beta, once.
    fn require_oauth_beta(headers: &HeaderMap) -> Result<(), AnthropicRejection> {
        let mut betas = headers.get_all("anthropic-beta").iter();
        let beta = betas.next().and_then(|value| value.to_str().ok());
        if betas.next().is_some()
            || !beta.is_some_and(|beta| {
                beta.split(',')
                    .any(|token| token.trim() == ANTHROPIC_OAUTH_BETA)
            })
        {
            return Err(AnthropicRejection::OAuthBeta);
        }
        Ok(())
    }

    /// Claude's token endpoint as Codewire uses it: the sign-in's code
    /// exchange (the fixed code, Claude Code's client and manual redirect, a
    /// verifier and the state), or a refresh presenting exactly the latest
    /// refresh token with the scopes it was granted. Each issues the next
    /// generation; anything else is the provider's `invalid_grant`. Only the
    /// closed grant and generation are logged.
    fn claude_token(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (status, answer) = self.claude_token_answer(headers, body)?;
        json_status_response(status, &answer)
    }

    /// [`Self::claude_token`]'s status and JSON body.
    fn claude_token_answer(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(StatusCode, Value), BrokerUpstreamError> {
        if !exact_single(headers, "content-type", "application/json") || body.len() > 64 * 1024 {
            return Err(BrokerUpstreamError::Protocol);
        }
        let request: Value =
            serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
        let text = |field: &str| request.get(field).and_then(Value::as_str);
        let random = |field: &str| {
            text(field).is_some_and(|value| {
                value.len() == 43
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        };
        let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
        let current = counters.claude_sign_in_generation;
        let grant = text("grant_type");
        let accepted = text("client_id") == Some(CLAUDE_CLIENT_ID)
            && match grant {
                Some("authorization_code") => {
                    text("code") == Some(KIND_CLAUDE_SIGN_IN_CODE)
                        && text("redirect_uri") == Some(CLAUDE_MANUAL_REDIRECT_URL)
                        && random("code_verifier")
                        && random("state")
                }
                Some("refresh_token") => {
                    current > 0
                        && text("refresh_token") == Some(claude_sign_in_refresh(current).as_str())
                        && text("scope") == Some(CLAUDE_SIGN_IN_SCOPES)
                }
                _ => false,
            };
        if !accepted {
            tracing::info!(target: TARGET, event = "claude_sign_in_refused",
                grant = if grant == Some("refresh_token") { "refresh_token" } else { "authorization_code" },
                "claude_sign_in_refused");
            drop(counters);
            return Ok((
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Synthetic Kind refusal"}),
            ));
        }
        let generation = increment(current)?;
        counters.claude_sign_in_generation = generation;
        let lifetime = if grant == Some("refresh_token") {
            counters.claude_sign_in_refreshes = increment(counters.claude_sign_in_refreshes)?;
            CLAUDE_SIGN_IN_LIFETIME
        } else {
            CLAUDE_SIGN_IN_FIRST_LIFETIME
        };
        let refreshes = counters.claude_sign_in_refreshes;
        drop(counters);
        tracing::info!(target: TARGET, event = "claude_sign_in_token",
            grant = if grant == Some("refresh_token") { "refresh_token" } else { "authorization_code" },
            generation, claude_sign_in_refreshes = refreshes, "claude_sign_in_token");
        Ok((
            StatusCode::OK,
            json!({
                "token_type": "Bearer",
                "access_token": claude_sign_in_access(generation),
                "refresh_token": claude_sign_in_refresh(generation),
                "expires_in": lifetime,
                "scope": CLAUDE_SIGN_IN_SCOPES,
            }),
        ))
    }

    /// Claude's OAuth profile, read once by the sign-in with its new access
    /// token: a Max plan with a fixed public tier and email.
    fn claude_profile(
        &self,
        headers: &HeaderMap,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        json_response(self.claude_profile_answer(headers)?)
    }

    /// [`Self::claude_profile`]'s JSON body.
    fn claude_profile_answer(&self, headers: &HeaderMap) -> Result<Value, BrokerUpstreamError> {
        let expected = self
            .current_claude_sign_in_bearer()
            .ok_or(BrokerUpstreamError::Protocol)?;
        if !exact_single(headers, "authorization", &expected) {
            return Err(BrokerUpstreamError::Protocol);
        }
        tracing::info!(target: TARGET, event = "claude_profile", "claude_profile");
        Ok(json!({
            "account": {"uuid": "kind-synthetic-claude-account",
                        "email": "kind-claude@example.test"},
            "organization": {"uuid": "kind-synthetic-claude-organization",
                             "organization_type": "claude_max",
                             "rate_limit_tier": "default_claude_max_20x"},
        }))
    }

    fn admit_anthropic(
        &self,
        method: &Method,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<AdmittedAnthropic, AnthropicRejection> {
        let route = match (target.path(), target.query()) {
            ("/v1/messages", None | Some("beta=true")) => AnthropicRoute::Messages,
            ("/v1/messages/count_tokens", None | Some("beta=true")) => AnthropicRoute::CountTokens,
            _ => return Err(AnthropicRejection::Route),
        };
        if method != Method::POST {
            return Err(AnthropicRejection::Route);
        }
        let authorization = headers.get_all("authorization").iter().collect::<Vec<_>>();
        let api_key = headers.get_all("x-api-key").iter().collect::<Vec<_>>();
        if authorization.iter().chain(api_key.iter()).any(|value| {
            value
                .as_bytes()
                .windows(ANTHROPIC_PLACEHOLDER.len())
                .any(|window| window == ANTHROPIC_PLACEHOLDER.as_bytes())
        }) {
            return Err(AnthropicRejection::Placeholder);
        }
        let sign_in = self.current_claude_sign_in_bearer();
        let (kind, refused) = match (authorization.as_slice(), api_key.as_slice()) {
            ([], [key]) if key.as_bytes() == KIND_ANTHROPIC_API_KEY.as_bytes() => {
                (AnthropicKind::ApiKey, false)
            }
            ([bearer], [])
                if sign_in
                    .as_deref()
                    .is_some_and(|sign_in| bearer.as_bytes() == sign_in.as_bytes()) =>
            {
                Self::require_oauth_beta(headers)?;
                (AnthropicKind::SignIn, false)
            }
            ([bearer], [])
                if [KIND_CLAUDE_SUBSCRIPTION_TOKEN, KIND_CLAUDE_REFUSED_TOKEN]
                    .iter()
                    .any(|token| bearer.as_bytes() == format!("Bearer {token}").as_bytes()) =>
            {
                let mut betas = headers.get_all("anthropic-beta").iter();
                let beta = betas.next().and_then(|value| value.to_str().ok());
                if betas.next().is_some()
                    || !beta.is_some_and(|beta| {
                        beta.split(',')
                            .any(|token| token.trim() == ANTHROPIC_OAUTH_BETA)
                    })
                {
                    return Err(AnthropicRejection::OAuthBeta);
                }
                (
                    AnthropicKind::SubscriptionToken,
                    bearer.as_bytes() == format!("Bearer {KIND_CLAUDE_REFUSED_TOKEN}").as_bytes(),
                )
            }
            _ => return Err(AnthropicRejection::Credential),
        };
        if headers.contains_key("proxy-authorization")
            || headers.contains_key("cookie")
            || !exact_single(headers, "anthropic-version", "2023-06-01")
            || !exact_single(headers, "content-type", "application/json")
            || !exact_single(headers, "accept-encoding", "identity")
        {
            return Err(AnthropicRejection::Headers);
        }
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(AnthropicRejection::Body);
        }
        let request: Value = serde_json::from_slice(body).map_err(|_| AnthropicRejection::Body)?;
        let model = request
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| {
                !model.is_empty()
                    && model.len() <= MAX_ANTHROPIC_MODEL
                    && model.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')
                    })
            })
            .ok_or(AnthropicRejection::Body)?
            .to_owned();
        if !request.get("messages").is_some_and(Value::is_array) {
            return Err(AnthropicRejection::Body);
        }
        let stream = request.get("stream").and_then(Value::as_bool) == Some(true);
        if route == AnthropicRoute::CountTokens && request.get("stream").is_some() {
            return Err(AnthropicRejection::Body);
        }
        let client_identity = exact_single(headers, "x-app", "cli")
            && headers.get_all("user-agent").iter().count() == 1
            && headers
                .get("user-agent")
                .is_some_and(|value| value.as_bytes().starts_with(b"claude-cli/"));
        Ok(AdmittedAnthropic {
            kind,
            route,
            stream,
            model,
            refused,
            client_identity,
        })
    }

    fn responses(
        &self,
        headers: HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if headers.get_all("authorization").iter().count() != 1
            || headers.get_all("chatgpt-account-id").iter().count() != 1
            || headers.get("chatgpt-account-id") != Some(&HeaderValue::from_static(ACCOUNT))
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let access = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(BrokerUpstreamError::Protocol)?;
        let generation = validate_access(access)?;
        let scenario = Scenario::from_body(body)?;
        let status = {
            let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
            let attempt = increment(counters.attempts[scenario.index()])?;
            if !matches!(scenario, Scenario::Baseline) {
                if attempt == 1 {
                    counters.required_generation[scenario.index()] = Some(increment(generation)?);
                } else {
                    let required = counters.required_generation[scenario.index()]
                        .ok_or(BrokerUpstreamError::Protocol)?;
                    if generation != required
                        || counters.last_refresh != Some((required - 1, required))
                    {
                        return Err(BrokerUpstreamError::Protocol);
                    }
                }
            }
            counters.responses = increment(counters.responses)?;
            counters.attempts[scenario.index()] = attempt;
            let status = scenario.status(attempt);
            // `generation` is the fixture's public synthetic token counter: it
            // shows which login a request presented, never a token value.
            tracing::info!(target: TARGET, event = "provider_response", scenario = scenario.name(), attempt,
                status = status.as_u16(), generation, response_calls = counters.responses,
                refresh_calls = counters.refreshes, "provider_response");
            status
        };
        let (content_type, body) = if status == StatusCode::OK {
            ("text/event-stream", SSE)
        } else if status == StatusCode::UNAUTHORIZED {
            // Fixed synthetic text, never a reflected credential or request.
            ("application/json", br#"{"error":{"message":"Synthetic Kind authentication rejection","type":"invalid_request_error","code":"invalid_api_key"}}"#.as_slice())
        } else {
            ("application/json", br#"{"error":{"message":"Synthetic Kind terminal request rejection","type":"invalid_request_error","code":"invalid_request_error"}}"#.as_slice())
        };
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static(content_type));
        let split = body.len() / 2;
        Ok(BrokerUpstreamResponse::new(
            status,
            headers,
            Box::pin(futures::stream::iter([
                Ok(body[..split].to_vec().into()),
                Ok(body[split..].to_vec().into()),
            ])),
        ))
    }

    fn refresh(
        &self,
        headers: HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if body.is_empty()
            || body.len() > 16 * 1024
            || headers.contains_key("authorization")
            || headers.contains_key("chatgpt-account-id")
        {
            return Err(BrokerUpstreamError::Protocol);
        }
        let request: Value =
            serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
        if request["grant_type"] != "refresh_token" {
            return Err(BrokerUpstreamError::Protocol);
        }
        let refresh = request["refresh_token"]
            .as_str()
            .ok_or(BrokerUpstreamError::Protocol)?;
        let generation = refresh
            .strip_prefix("CW_KIND_SYNTHETIC_REFRESH_")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value < MAX_GENERATION)
            .ok_or(BrokerUpstreamError::Protocol)?;
        if refresh != refresh_token(generation) {
            return Err(BrokerUpstreamError::Protocol);
        }
        let body = serde_json::to_vec(&json!({"access_token":access_token(generation + 1)?,
            "refresh_token":refresh_token(generation + 1),"token_type":"bearer"}))
        .map_err(|_| BrokerUpstreamError::Protocol)?;
        {
            let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
            counters.refreshes = increment(counters.refreshes)?;
            counters.last_refresh = Some((generation, generation + 1));
            tracing::info!(target: TARGET, event = "provider_refresh", refresh_calls = counters.refreshes,
                response_calls = counters.responses, "provider_refresh");
        }
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Box::pin(futures::stream::once(async move { Ok(body.into()) })),
        ))
    }
}

#[async_trait]
impl BrokerUpstreamTransport for SyntheticProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        // Claude's token endpoint and OAuth profile (the sign-in's exchange,
        // profile read and refresh) are the fixture's own routes, not a
        // transparent-route call it lacks.
        let (method, target) = request.destination();
        if (*method == Method::POST
            && target.as_str() == "https://platform.claude.com/v1/oauth/token")
            || (*method == Method::GET
                && target.as_str() == "https://api.anthropic.com/api/oauth/profile")
        {
            let (method, _, headers, body) = request.into_parts();
            return if method == Method::POST {
                self.claude_token(&headers, &body)
            } else {
                self.claude_profile(&headers)
            };
        }
        // A stock client's other calls on a transparent route (#2536), such
        // as Codex's model list, reach here too. They neither count toward a
        // schedule nor fail as a transport error, which would end the bridge
        // epoch; the fixture answers them as the provider answers a route it
        // lacks.
        #[cfg(feature = "kind-e2e")]
        if let Some(host) = SyntheticOpenAiSmokeTransport::unserved_host(&request) {
            let (method, _, headers, _) = request.into_parts();
            return self.unserved(host, &method, &headers);
        }
        #[cfg(feature = "kind-e2e")]
        if let Some(family) = SyntheticOpenAiSmokeTransport::api_key_family(&request)
            && !SyntheticOpenAiSmokeTransport::is_kind_anthropic_fixture(&request)
        {
            let key = {
                let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
                let (attempt, key) = match family {
                    "openai" => {
                        counters.openai_api_attempts = increment(counters.openai_api_attempts)?;
                        (counters.openai_api_attempts, OPENAI_API_KEY)
                    }
                    "anthropic" => {
                        counters.anthropic_api_attempts =
                            increment(counters.anthropic_api_attempts)?;
                        (counters.anthropic_api_attempts, ANTHROPIC_API_KEY)
                    }
                    _ => return Err(BrokerUpstreamError::Protocol),
                };
                // HTTP attempts are distinct from OAuth and GitHub calls and
                // from the independently observed number of native launches.
                tracing::info!(target: TARGET, event = "api_key_attempt", family,
                    api_attempt = attempt, "api_key_attempt");
                key
            };
            SyntheticOpenAiSmokeTransport::validate_exact_api_key_request(&request, key)?;
            // Keep custody of the original request; no reconstruction, cloning
            // or secret-bearing accessor crosses the broker's boundary.
            return SyntheticOpenAiSmokeTransport.execute(request).await;
        }
        let (method, target, headers, body) = request.into_parts();
        if headers.contains_key("proxy-authorization") || headers.contains_key("cookie") {
            return Err(BrokerUpstreamError::Protocol);
        }
        if method == Method::POST && target.as_str() == "https://github.com/login/device/code" {
            return github_device_code(&headers, &body);
        }
        if method == Method::POST
            && target.as_str() == "https://github.com/login/oauth/access_token"
        {
            if url::form_urlencoded::parse(&body).any(|(key, value)| {
                key == "grant_type" && value == "urn:ietf:params:oauth:grant-type:device_code"
            }) {
                return github_device_token(&headers, &body);
            }
            return self.github_app_exchange(&headers, &body);
        }
        if target.host_str() == Some("github.com") {
            return self.github_git(&method, &target, &headers, &body).await;
        }
        if target.host_str() == Some("api.anthropic.com") {
            return self.anthropic(&method, &target, &headers, &body);
        }
        if method == Method::GET
            && target.origin().ascii_serialization() == "https://api.github.com"
        {
            return match target.path() {
                "/user" => self.github_app_user(&headers, &body),
                "/user/installations" => self.github_app_installations(&target, &headers, &body),
                "/user/repos" => self.github_repositories(&target, &headers, &body),
                _ => Err(BrokerUpstreamError::Protocol),
            };
        }
        if method != Method::POST {
            return Err(BrokerUpstreamError::Protocol);
        }
        match target.as_str() {
            "https://chatgpt.com/backend-api/codex/responses" => self.responses(headers, &body),
            "https://auth.openai.com/api/accounts/deviceauth/usercode" => {
                codex_device_usercode(&headers, &body)
            }
            "https://auth.openai.com/api/accounts/deviceauth/token" => {
                codex_device_token(&headers, &body)
            }
            "https://auth.openai.com/oauth/token"
                if headers.get("content-type")
                    == Some(&HeaderValue::from_static(
                        "application/x-www-form-urlencoded",
                    )) =>
            {
                codex_device_exchange(&headers, &body)
            }
            "https://auth.openai.com/oauth/token" => self.refresh(headers, &body),
            _ => Err(BrokerUpstreamError::Protocol),
        }
    }
}

#[cfg(feature = "kind-e2e")]
impl SyntheticProvider {
    /// A transparent-route request this fixture does not serve, carrying
    /// exactly a credential it issued: answered with the provider's 404 and
    /// logged by host and method only. Anything else still fails the fixture.
    fn unserved(
        &self,
        host: SyntheticProviderHost,
        method: &Method,
        headers: &HeaderMap,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        if !unserved_credential(
            host,
            headers,
            self.current_claude_sign_in_bearer().as_deref(),
        ) {
            return Err(BrokerUpstreamError::Protocol);
        }
        let method = match *method {
            Method::GET => "GET",
            Method::HEAD => "HEAD",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::PATCH => "PATCH",
            Method::DELETE => "DELETE",
            _ => "other",
        };
        tracing::info!(target: TARGET, event = "provider_unserved", host = host.name(), method,
            "provider_unserved");
        Ok(SyntheticOpenAiSmokeTransport::not_found(host))
    }
}

/// The request carries exactly one credential this fixture issued for that
/// host, the account it expects, and nothing a guest could have supplied.
#[cfg(feature = "kind-e2e")]
fn unserved_credential(
    host: SyntheticProviderHost,
    headers: &HeaderMap,
    claude_sign_in: Option<&str>,
) -> bool {
    if ["cookie", "proxy-authorization", "host"]
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return false;
    }
    let authorization = headers.get_all("authorization").iter().collect::<Vec<_>>();
    let api_key = headers.get_all("x-api-key").iter().collect::<Vec<_>>();
    match host {
        SyntheticProviderHost::Codex => {
            api_key.is_empty()
                && exact_single(headers, "chatgpt-account-id", ACCOUNT)
                && matches!(authorization.as_slice(), [bearer] if bearer
                    .to_str()
                    .ok()
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .is_some_and(|token| validate_access(token).is_ok()))
        }
        SyntheticProviderHost::OpenAi => {
            api_key.is_empty()
                && !headers.contains_key("chatgpt-account-id")
                && exact_single(
                    headers,
                    "authorization",
                    &format!("Bearer {OPENAI_API_KEY}"),
                )
        }
        SyntheticProviderHost::Anthropic => match (authorization.as_slice(), api_key.as_slice()) {
            ([], [key]) => [KIND_ANTHROPIC_API_KEY, ANTHROPIC_API_KEY]
                .iter()
                .any(|expected| key.as_bytes() == expected.as_bytes()),
            ([bearer], []) => {
                [KIND_CLAUDE_SUBSCRIPTION_TOKEN, KIND_CLAUDE_REFUSED_TOKEN]
                    .iter()
                    .any(|token| bearer.as_bytes() == format!("Bearer {token}").as_bytes())
                    || claude_sign_in
                        .is_some_and(|expected| bearer.as_bytes() == expected.as_bytes())
            }
            _ => false,
        },
    }
}

fn exact_single(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .is_some_and(|value| value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

/// Claude Code-compatible replies with fixed public text. The model is the
/// request's own validated identifier; nothing else is reflected.
fn anthropic_response(
    route: AnthropicRoute,
    stream: bool,
    model: &str,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let (content_type, mut body) = anthropic_reply(route, stream, model)?;
    let second = body.split_off(body.len() / 2);
    Ok(BrokerUpstreamResponse::new(
        StatusCode::OK,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        )]),
        Box::pin(futures::stream::iter([Ok(body.into()), Ok(second.into())])),
    ))
}

/// The provider's refusal of an expired or revoked subscription token, with
/// fixed public text.
fn anthropic_refusal() -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let body = anthropic_refusal_body()?;
    Ok(BrokerUpstreamResponse::new(
        StatusCode::UNAUTHORIZED,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move { Ok(body.into()) })),
    ))
}

fn anthropic_refusal_body() -> Result<Vec<u8>, BrokerUpstreamError> {
    serde_json::to_vec(&json!({
        "type": "error",
        "error": {"type": "authentication_error",
                  "message": "Synthetic Kind subscription token refusal"},
    }))
    .map_err(|_| BrokerUpstreamError::Protocol)
}

fn anthropic_reply(
    route: AnthropicRoute,
    stream: bool,
    model: &str,
) -> Result<(&'static str, Vec<u8>), BrokerUpstreamError> {
    let json = |value: Value| {
        serde_json::to_vec(&value)
            .map(|body| ("application/json", body))
            .map_err(|_| BrokerUpstreamError::Protocol)
    };
    if route == AnthropicRoute::CountTokens {
        return json(json!({"input_tokens": 1}));
    }
    let usage = json!({"input_tokens": 1, "output_tokens": 1});
    if !stream {
        return json(json!({
            "id": "msg_codewire_kind", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": CLAUDE_MARKER}],
            "stop_reason": "end_turn", "stop_sequence": null, "usage": usage,
        }));
    }
    let events = [
        (
            "message_start",
            json!({"type": "message_start", "message": {
            "id": "msg_codewire_kind", "type": "message", "role": "assistant", "model": model,
            "content": [], "stop_reason": null, "stop_sequence": null, "usage": usage}}),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": CLAUDE_MARKER}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({"type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {"output_tokens": 1}}),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ];
    let mut body = Vec::new();
    for (name, data) in events {
        body.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
    }
    Ok(("text/event-stream", body))
}

fn codex_device_usercode(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let request: Value = serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
    if !json_post_headers(headers) || request != json!({"client_id": CODEX_CLIENT_ID}) {
        return Err(BrokerUpstreamError::Protocol);
    }
    tracing::info!(target: TARGET, event = "codex_device_login", "codex_device_login");
    json_response(json!({
        "device_auth_id": CODEX_DEVICE_AUTH_ID,
        "user_code": CODEX_USER_CODE,
        "interval": "1",
    }))
}

fn codex_device_token(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let request: Value = serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
    if !json_post_headers(headers)
        || request != json!({"device_auth_id": CODEX_DEVICE_AUTH_ID, "user_code": CODEX_USER_CODE})
    {
        return Err(BrokerUpstreamError::Protocol);
    }
    json_response(json!({
        "authorization_code": CODEX_AUTHORIZATION_CODE,
        "code_challenge": "kind-synthetic-codex-code-challenge",
        "code_verifier": CODEX_CODE_VERIFIER,
    }))
}

fn codex_device_exchange(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let expected = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", CODEX_AUTHORIZATION_CODE)
        .append_pair(
            "redirect_uri",
            "https://auth.openai.com/deviceauth/callback",
        )
        .append_pair("client_id", CODEX_CLIENT_ID)
        .append_pair("code_verifier", CODEX_CODE_VERIFIER)
        .finish();
    if !exact_headers(
        headers,
        &[
            ("accept", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    ) || body != expected.as_bytes()
    {
        return Err(BrokerUpstreamError::Protocol);
    }
    // The claims stock Codex reads from a ChatGPT login's ID token, so the
    // login the daemon delivers reads as a ChatGPT account with a plan. A
    // personal plan: business, enterprise and edu make Codex fetch workspace
    // configuration at startup.
    let id_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "email": "kind-fixture@example.test",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": ACCOUNT,
                "chatgpt_plan_type": "plus",
                "chatgpt_user_id": "user-codewire-kind-synthetic",
            }
        }))
        .map_err(|_| BrokerUpstreamError::Protocol)?,
    );
    json_response(json!({
        "id_token": format!("e30.{id_payload}.{TOKEN_SIGNATURE}"),
        "access_token": access_token(0)?,
        "refresh_token": refresh_token(0),
    }))
}

fn github_device_code(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    if !github_device_headers(headers)
        || body != format!("client_id={GITHUB_APP_CLIENT_ID}").as_bytes()
    {
        return Err(BrokerUpstreamError::Protocol);
    }
    tracing::info!(target: TARGET, event = "github_device_login", "github_device_login");
    json_response(json!({
        "device_code": GITHUB_DEVICE_CODE,
        "user_code": GITHUB_USER_CODE,
        "verification_uri": "https://github.com/login/device",
        "expires_in": 900,
        "interval": 1,
    }))
}

fn github_device_token(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let expected = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", GITHUB_APP_CLIENT_ID)
        .append_pair("device_code", GITHUB_DEVICE_CODE)
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
        .finish();
    if !github_device_headers(headers) || body != expected.as_bytes() {
        return Err(BrokerUpstreamError::Protocol);
    }
    json_response(json!({"access_token": GITHUB_APP_USER_TOKEN, "token_type": "bearer"}))
}

fn json_post_headers(headers: &HeaderMap) -> bool {
    exact_headers(
        headers,
        &[
            ("accept", "application/json"),
            ("content-type", "application/json"),
        ],
    )
}

fn github_device_headers(headers: &HeaderMap) -> bool {
    exact_headers(
        headers,
        &[
            ("accept", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("user-agent", "Codewire"),
        ],
    )
}

fn github_app_refresh_body() -> String {
    format!(
        "client_id={GITHUB_APP_CLIENT_ID}&client_secret={GITHUB_APP_CLIENT_SECRET}&grant_type=refresh_token&refresh_token={GITHUB_APP_INITIAL_REFRESH_TOKEN}"
    )
}

fn exact_headers(headers: &HeaderMap, expected: &[(&str, &str)]) -> bool {
    headers.keys().all(|name| {
        expected
            .iter()
            .any(|(expected_name, _)| name.as_str() == *expected_name)
    }) && expected.iter().all(|(name, value)| {
        headers.get_all(*name).iter().count() == 1
            && HeaderValue::from_str(value)
                .is_ok_and(|expected| headers.get(*name) == Some(&expected))
    })
}

fn github_app_api_headers(headers: &HeaderMap) -> bool {
    [
        GITHUB_APP_USER_TOKEN,
        GITHUB_APP_REFRESHED_USER_TOKEN,
        GITHUB_APP_UNINSTALLED_USER_TOKEN,
        GITHUB_APP_LIMITED_USER_TOKEN,
        GITHUB_APP_UNRELIABLE_USER_TOKEN,
    ]
    .iter()
    .any(|token| {
        let authorization = format!("Bearer {token}");
        exact_headers(
            headers,
            &[
                ("authorization", &authorization),
                ("accept", "application/vnd.github+json"),
                ("user-agent", "Codewire-Credential-Service"),
            ],
        )
    })
}

fn github_bearer_authorization(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get("authorization") else {
        return false;
    };
    [GITHUB_APP_USER_TOKEN, GITHUB_APP_REFRESHED_USER_TOKEN]
        .iter()
        .any(|token| {
            value == HeaderValue::from_str(&format!("Bearer {token}")).expect("synthetic token")
        })
}

fn github_refreshed_app_git_authorization(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get("authorization") else {
        return false;
    };
    let authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("x-access-token:{GITHUB_APP_REFRESHED_USER_TOKEN}"))
    );
    value == HeaderValue::from_str(&authorization).expect("synthetic token")
}

fn json_status_response(
    status: StatusCode,
    value: &Value,
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let bytes = serde_json::to_vec(value).map_err(|_| BrokerUpstreamError::Protocol)?;
    Ok(BrokerUpstreamResponse::new(
        status,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move { Ok(bytes.into()) })),
    ))
}

fn json_response(value: Value) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| BrokerUpstreamError::Protocol)?;
    Ok(BrokerUpstreamResponse::new(
        StatusCode::OK,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::once(async move { Ok(bytes.into()) })),
    ))
}

fn github_repository_values(page: usize, size: usize) -> Vec<Value> {
    (1..=51).skip((page-1)*size).take(size).map(|index| json!({
        "id":index,"full_name":format!("synthetic-user/repository-{index:02}"),"default_branch":"main",
        "private":true,"archived":false,"disabled":index==50,
    })).collect()
}

fn increment(value: u64) -> Result<u64, BrokerUpstreamError> {
    value
        .checked_add(1)
        .ok_or(BrokerUpstreamError::ResourceLimit)
}

fn now() -> Result<u64, BrokerUpstreamError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| BrokerUpstreamError::Protocol)
}

pub(super) fn refresh_token(generation: u64) -> String {
    format!("CW_KIND_SYNTHETIC_REFRESH_{generation}")
}

pub(super) fn access_token(generation: u64) -> Result<String, BrokerUpstreamError> {
    let expiry = now()?
        .checked_add(24 * 3600)
        .ok_or(BrokerUpstreamError::Protocol)?;
    encoded_access(generation, expiry)
}

fn encoded_access(generation: u64, expiry: u64) -> Result<String, BrokerUpstreamError> {
    if generation > MAX_GENERATION {
        return Err(BrokerUpstreamError::Protocol);
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "exp":expiry,"generation":generation,"synthetic":"codewire-kind-credential-fixture"
        }))
        .map_err(|_| BrokerUpstreamError::Protocol)?,
    );
    Ok(format!("e30.{payload}.{TOKEN_SIGNATURE}"))
}

fn validate_access(token: &str) -> Result<u64, BrokerUpstreamError> {
    if token.len() > 1024 {
        return Err(BrokerUpstreamError::Protocol);
    }
    let mut parts = token.split('.');
    if parts.next() != Some("e30") {
        return Err(BrokerUpstreamError::Protocol);
    }
    let payload = parts.next().ok_or(BrokerUpstreamError::Protocol)?;
    if parts.next() != Some(TOKEN_SIGNATURE) || parts.next().is_some() {
        return Err(BrokerUpstreamError::Protocol);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| BrokerUpstreamError::Protocol)?;
    let claims: Value =
        serde_json::from_slice(&bytes).map_err(|_| BrokerUpstreamError::Protocol)?;
    let generation = claims["generation"]
        .as_u64()
        .ok_or(BrokerUpstreamError::Protocol)?;
    let expiry = claims["exp"]
        .as_u64()
        .ok_or(BrokerUpstreamError::Protocol)?;
    if expiry <= now()? || token != encoded_access(generation, expiry)? {
        return Err(BrokerUpstreamError::Protocol);
    }
    Ok(generation)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[cfg(feature = "kind-e2e")]
    mod api_key_tests {
        use std::collections::BTreeSet;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use codewire_access::{
            AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
            CredentialId, CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentId,
            GrantPermission, GrantProfile, Owner, OwnerId, Placement, ProviderId,
        };
        use codewire_credential_broker::{
            BrokerCredentialLease, BrokerCredentialRefreshRequest, BrokerLeaseError,
            BrokerLeaseProvider, BrokerRefreshAdmission, BrokerRefreshError, BrokerRequestError,
            CanonicalCodexOAuthBundle, OpenAiBroker,
        };
        use codewire_daemon_proto::codewire::bridge::v1::{
            CredentialBridgeRequest, CredentialHttpHeader,
        };
        use futures::StreamExt;
        use uuid::Uuid;

        use super::*;

        type LeaseCoordinates = (Uuid, String, String, String);

        #[derive(Clone)]
        struct Authority {
            slot: &'static str,
            material: &'static str,
            kind: CredentialAuthKind,
            status: CredentialStatus,
            denied: bool,
            calls: Arc<Mutex<Vec<LeaseCoordinates>>>,
            reads: Arc<AtomicUsize>,
        }

        impl Authority {
            fn new(slot: &'static str, material: &'static str) -> Self {
                Self {
                    slot,
                    material,
                    kind: CredentialAuthKind::ApiKey,
                    status: CredentialStatus::Active,
                    denied: false,
                    calls: Arc::new(Mutex::new(Vec::new())),
                    reads: Arc::new(AtomicUsize::new(0)),
                }
            }
        }

        struct Lease {
            metadata: CredentialMetadata,
            grant: DerivedGrant,
            permission: GrantPermission,
            material: zeroize::Zeroizing<Vec<u8>>,
            reads: Arc<AtomicUsize>,
        }

        impl BrokerCredentialLease for Lease {
            fn credential_metadata(&self) -> &CredentialMetadata {
                &self.metadata
            }
            fn grant(&self) -> &DerivedGrant {
                &self.grant
            }
            fn permission(&self) -> &GrantPermission {
                &self.permission
            }
            fn material_generation(&self) -> u64 {
                1
            }
            fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
                self.reads.fetch_add(1, Ordering::Relaxed);
                operation(&self.material)
            }
        }

        #[async_trait]
        impl BrokerLeaseProvider for Authority {
            type Lease = Lease;
            type RefreshReservation = ();
            type StartedRefresh = ();

            async fn lease_operation(
                &self,
                request_id: Uuid,
                slot: CapabilitySlot,
                operation: BrokerOperationId,
                route: BrokerRouteId,
            ) -> Result<Lease, BrokerLeaseError> {
                self.calls.lock().unwrap().push((
                    request_id,
                    slot.to_string(),
                    operation.to_string(),
                    route.to_string(),
                ));
                if self.denied || slot.as_str() != self.slot {
                    return Err(BrokerLeaseError::Denied);
                }
                let id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
                let permission = GrantPermission { operation, route };
                Ok(Lease {
                    metadata: CredentialMetadata {
                        id: id.clone(),
                        placement: Placement::Platform,
                        owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                        provider: ProviderId::parse(self.slot).unwrap(),
                        authentication_kind: self.kind,
                        display_name: "synthetic-only".into(),
                        account_hint: None,
                        ssh_public_key: None,
                        status: self.status,
                        expires_at_unix: None,
                        revocation_generation: 1,
                    },
                    grant: DerivedGrant {
                        environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                        environment_generation: 1,
                        profile: Some(GrantProfile {
                            id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222")
                                .unwrap(),
                            revision: 1,
                        }),
                        capability_slot: slot,
                        credential_id: id,
                        credential_revocation_generation: 1,
                        expires_at_unix: None,
                        permissions: BTreeSet::from([permission.clone()]),
                    },
                    permission,
                    material: zeroize::Zeroizing::new(self.material.as_bytes().to_vec()),
                    reads: self.reads.clone(),
                })
            }

            async fn begin_credential_refresh(
                &self,
                _: BrokerCredentialRefreshRequest,
            ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
                panic!("API-key fixture must not refresh OAuth")
            }
            async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
                panic!("API-key fixture must not refresh OAuth")
            }
            async fn commit_credential_refresh(
                &self,
                _: (),
                _: CanonicalCodexOAuthBundle,
            ) -> Result<(), BrokerRefreshError> {
                panic!("API-key fixture must not refresh OAuth")
            }
            async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
                panic!("API-key fixture must not refresh OAuth")
            }
            async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
                panic!("API-key fixture must not refresh OAuth")
            }
            async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
                Ok(())
            }
        }

        fn key(slot: &str) -> &'static str {
            match slot {
                "openai" => OPENAI_API_KEY,
                "anthropic" => ANTHROPIC_API_KEY,
                _ => panic!("fixture API slot"),
            }
        }

        fn request(slot: &str, path: &str, query: &str) -> CredentialBridgeRequest {
            let mut headers = vec![CredentialHttpHeader {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            }];
            let body = if slot == "anthropic" {
                headers.push(CredentialHttpHeader {
                    name: "anthropic-version".into(),
                    value: b"2023-06-01".to_vec(),
                });
                let mut body = json!({
                    "model":"claude-sonnet-4-6",
                    "messages":[{"role":"user","content":"canned fixture"}],
                });
                if path == "/v1/messages" {
                    body["stream"] = json!(true);
                    body["max_tokens"] = json!(64);
                }
                body
            } else {
                json!({"input":"canned fixture"})
            };
            CredentialBridgeRequest {
                request_id: Uuid::new_v4().to_string(),
                capability_slot: slot.into(),
                route: format!("{slot}-api"),
                method: "POST".into(),
                path: path.into(),
                query: query.into(),
                headers,
                body: serde_json::to_vec(&body).unwrap(),
            }
        }

        fn attempts(provider: &SyntheticProvider) -> (u64, u64) {
            let counters = provider.0.lock().unwrap();
            assert_eq!(counters.github_advertisements, 0);
            assert_eq!(counters.github_upload_packs, 0);
            assert_eq!(counters.github_app_refreshes, 0);
            assert_eq!(counters.github_refreshed_advertisements, 0);
            assert_eq!(counters.github_refreshed_upload_packs, 0);
            (
                counters.openai_api_attempts,
                counters.anthropic_api_attempts,
            )
        }

        #[tokio::test]
        async fn typed_api_routes_redact_and_keep_legacy_schedules_independent() {
            let provider = SyntheticProvider::new();
            // The transparent Anthropic route (#2536) leases one operation for
            // every path, token counting included.
            for (slot, path, query, operation) in [
                ("openai", "/responses", "", "responses"),
                ("anthropic", "/v1/messages", "", "messages"),
                ("anthropic", "/v1/messages", "beta=true", "messages"),
                ("anthropic", "/v1/messages/count_tokens", "", "messages"),
                (
                    "anthropic",
                    "/v1/messages/count_tokens",
                    "beta=true",
                    "messages",
                ),
            ] {
                let authority = Authority::new(slot, key(slot));
                let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                let request = request(slot, path, query);
                let id = Uuid::parse_str(&request.request_id).unwrap();
                let (status, headers, mut body) =
                    broker.execute(request).await.unwrap().into_parts();
                assert_eq!(status, StatusCode::OK);
                let request_header = if slot == "openai" {
                    "x-request-id"
                } else {
                    "request-id"
                };
                assert_eq!(headers[request_header], "[REDACTED]");
                // Transparent routes return every provider header, redacted
                // (#2536): the reflection survives without the key.
                assert!(headers.contains_key("x-error-json"));
                assert!(headers.values().all(|value| {
                    !value
                        .as_bytes()
                        .windows(key(slot).len())
                        .any(|bytes| bytes == key(slot).as_bytes())
                }));
                let mut bytes = Vec::new();
                while let Some(chunk) = body.next().await {
                    bytes.extend(chunk.unwrap());
                    assert!(bytes.len() <= 64 * 1024);
                }
                let output = String::from_utf8(bytes).unwrap();
                assert!(!output.contains(key(slot)));
                if path.ends_with("/count_tokens") {
                    assert_eq!(output, "{\"input_tokens\":42}");
                } else {
                    assert!(output.contains(if slot == "openai" {
                        "CWOPENAI broker [REDACTED]"
                    } else {
                        "CWCLAUDE21238 broker [REDACTED]"
                    }));
                }
                assert_eq!(authority.reads.load(Ordering::Relaxed), 1);
                assert_eq!(
                    *authority.calls.lock().unwrap(),
                    [(id, slot.into(), operation.into(), format!("{slot}-api"))]
                );
            }
            assert_eq!(attempts(&provider), (1, 4));
            {
                let counters = provider.0.lock().unwrap();
                assert_eq!(counters.responses, 0);
                assert_eq!(counters.refreshes, 0);
                assert_eq!(counters.attempts, [0; 3]);
                assert_eq!(counters.required_generation, [None; 3]);
                assert_eq!(counters.last_refresh, None);
            }
            // API traffic must not consume or reset the retained OAuth schedule.
            let exhausted = super::body("CW_KIND_BROKER_RETRY_EXHAUSTED");
            provider.responses(super::headers(1), &exhausted).unwrap();
            let refresh = serde_json::to_vec(&json!({
                "grant_type":"refresh_token",
                "refresh_token":refresh_token(1),
            }))
            .unwrap();
            provider.refresh(HeaderMap::new(), &refresh).unwrap();
            provider.responses(super::headers(2), &exhausted).unwrap();
            provider.responses(super::headers(2), &exhausted).unwrap();
            assert_eq!(attempts(&provider), (1, 4));
            let counters = provider.0.lock().unwrap();
            assert_eq!(counters.responses, 3);
            assert_eq!(counters.refreshes, 1);
            assert_eq!(counters.attempts[Scenario::BrokerRetryExhausted.index()], 3);
        }

        fn main_anthropic_request(path: &str) -> CredentialBridgeRequest {
            let mut request = request("anthropic", path, "beta=true");
            for (name, value) in [
                ("authorization", "Bearer codewire-managed"),
                ("anthropic-beta", "claude-code-20250219"),
                ("user-agent", "claude-cli/2.1.288 (external, sdk-cli)"),
                ("x-app", "cli"),
            ] {
                request.headers.push(CredentialHttpHeader {
                    name: name.into(),
                    value: value.as_bytes().to_vec(),
                });
            }
            request
        }

        #[tokio::test]
        async fn main_anthropic_modes_and_cw_api_dispatch_coexist_without_schedule_fallback() {
            let provider = SyntheticProvider::new();
            for (kind, material, status) in [
                (
                    CredentialAuthKind::ApiKey,
                    KIND_ANTHROPIC_API_KEY,
                    StatusCode::OK,
                ),
                (
                    CredentialAuthKind::OAuth,
                    KIND_CLAUDE_SUBSCRIPTION_TOKEN,
                    StatusCode::OK,
                ),
                (
                    CredentialAuthKind::OAuth,
                    KIND_CLAUDE_REFUSED_TOKEN,
                    StatusCode::UNAUTHORIZED,
                ),
            ] {
                for path in ["/v1/messages", "/v1/messages/count_tokens"] {
                    let mut authority = Authority::new("anthropic", material);
                    authority.kind = kind;
                    let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                    let guest_request = main_anthropic_request(path);
                    let id = Uuid::parse_str(&guest_request.request_id).unwrap();
                    let (actual_status, _, mut body) =
                        broker.execute(guest_request).await.unwrap().into_parts();
                    assert_eq!(actual_status, status);
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.next().await {
                        bytes.extend(chunk.unwrap());
                        assert!(bytes.len() <= 64 * 1024);
                    }
                    let output = String::from_utf8(bytes).unwrap();
                    assert!(!output.contains(material));
                    if status == StatusCode::UNAUTHORIZED {
                        assert!(output.contains("authentication_error"));
                    } else if path == "/v1/messages" {
                        assert!(output.contains(CLAUDE_MARKER));
                        assert!(!output.contains("CWCLAUDE21238"));
                    } else {
                        assert!(output.contains("input_tokens"));
                    }
                    assert_eq!(authority.reads.load(Ordering::Relaxed), 1);
                    // The transparent route (#2536) leases one operation
                    // for every Anthropic request, whatever its path.
                    assert_eq!(
                        *authority.calls.lock().unwrap(),
                        [(
                            id,
                            "anthropic".into(),
                            "messages".into(),
                            "anthropic-api".into()
                        )]
                    );
                    // Interleave the independent CW API mode. Neither a main
                    // provider 401 nor a prior main success may select it.
                    let cw_authority = Authority::new("anthropic", ANTHROPIC_API_KEY);
                    let cw = OpenAiBroker::new(cw_authority, provider.clone()).unwrap();
                    let (status, _, mut body) = cw
                        .execute(request("anthropic", "/v1/messages", ""))
                        .await
                        .unwrap()
                        .into_parts();
                    assert_eq!(status, StatusCode::OK);
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.next().await {
                        bytes.extend(chunk.unwrap());
                        assert!(bytes.len() <= 64 * 1024);
                    }
                    let output = String::from_utf8(bytes).unwrap();
                    assert!(output.contains("CWCLAUDE21238 broker [REDACTED]"));
                    assert!(!output.contains(ANTHROPIC_API_KEY));
                }
            }
            assert_eq!(attempts(&provider), (0, 6));
            let counters = provider.0.lock().unwrap();
            assert_eq!(counters.anthropic_calls, 6);
            assert_eq!(counters.anthropic_rejections, 0);
            assert_eq!(counters.responses, 0);
            assert_eq!(counters.refreshes, 0);
            assert_eq!(counters.attempts, [0; 3]);
        }

        #[tokio::test]
        async fn main_anthropic_lease_denial_or_revocation_never_reaches_material_or_dispatch() {
            for (kind, material) in [
                (CredentialAuthKind::ApiKey, KIND_ANTHROPIC_API_KEY),
                (CredentialAuthKind::OAuth, KIND_CLAUDE_SUBSCRIPTION_TOKEN),
                (CredentialAuthKind::OAuth, KIND_CLAUDE_REFUSED_TOKEN),
            ] {
                for (denied, status) in [
                    (true, CredentialStatus::Active),
                    (false, CredentialStatus::Revoked),
                ] {
                    let provider = SyntheticProvider::new();
                    let mut authority = Authority::new("anthropic", material);
                    authority.kind = kind;
                    authority.denied = denied;
                    authority.status = status;
                    let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                    assert!(matches!(
                        broker.execute(main_anthropic_request("/v1/messages")).await,
                        Err(BrokerRequestError::Denied)
                    ));
                    assert_eq!(authority.calls.lock().unwrap().len(), 1);
                    assert_eq!(authority.reads.load(Ordering::Relaxed), 0);
                    assert_eq!(attempts(&provider), (0, 0));
                    let counters = provider.0.lock().unwrap();
                    assert_eq!(counters.anthropic_calls, 0);
                    assert_eq!(counters.anthropic_rejections, 0);
                    assert_eq!(counters.responses, 0);
                    assert_eq!(counters.refreshes, 0);
                    assert_eq!(counters.attempts, [0; 3]);
                }
            }
        }

        #[tokio::test]
        async fn wrong_selected_api_material_refuses_without_fallback() {
            for (slot, material) in [
                ("openai", "cwlocalopenai00000000000000000000000000000000"),
                ("openai", ANTHROPIC_API_KEY),
                (
                    "anthropic",
                    "cwlocalanthropic00000000000000000000000000000000",
                ),
                ("anthropic", OPENAI_API_KEY),
            ] {
                let provider = SyntheticProvider::new();
                let authority = Authority::new(slot, material);
                let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                let path = if slot == "openai" {
                    "/responses"
                } else {
                    "/v1/messages"
                };
                assert!(matches!(
                    broker.execute(request(slot, path, "")).await,
                    Err(BrokerRequestError::UpstreamFailed)
                ));
                assert_eq!(authority.calls.lock().unwrap().len(), 1);
                assert_eq!(authority.reads.load(Ordering::Relaxed), 1);
                assert_eq!(
                    attempts(&provider),
                    if slot == "openai" { (1, 0) } else { (0, 1) }
                );
                let counters = provider.0.lock().unwrap();
                assert_eq!(counters.responses, 0);
                assert_eq!(counters.refreshes, 0);
                assert_eq!(counters.attempts, [0; 3]);
            }
        }

        #[tokio::test]
        async fn revoked_or_denied_api_lease_never_reads_or_dispatches() {
            for slot in ["openai", "anthropic"] {
                for (denied, status) in [
                    (true, CredentialStatus::Active),
                    (false, CredentialStatus::Revoked),
                ] {
                    let provider = SyntheticProvider::new();
                    let mut authority = Authority::new(slot, key(slot));
                    authority.denied = denied;
                    authority.status = status;
                    let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                    let path = if slot == "openai" {
                        "/responses"
                    } else {
                        "/v1/messages"
                    };
                    assert!(matches!(
                        broker.execute(request(slot, path, "")).await,
                        Err(BrokerRequestError::Denied)
                    ));
                    assert_eq!(authority.calls.lock().unwrap().len(), 1);
                    assert_eq!(authority.reads.load(Ordering::Relaxed), 0);
                    assert_eq!(attempts(&provider), (0, 0));
                }
            }
        }

        /// A foreign slot, route or oversized body is refused before any lease
        /// or attempt. A changed method, path or query is a stock-client
        /// request on the transparent route (#2536): it is leased and
        /// forwarded, and the fixture answers it as the provider answers a
        /// route it lacks, a 404 with no attempt counted. It must never be the
        /// transport failure that ends the whole bridge epoch.
        #[tokio::test]
        async fn typed_api_requests_refuse_foreign_slots_and_answer_unserved_routes() {
            for slot in ["openai", "anthropic"] {
                let provider = SyntheticProvider::new();
                let authority = Authority::new(slot, key(slot));
                let broker = OpenAiBroker::new(authority.clone(), provider.clone()).unwrap();
                let path = if slot == "openai" {
                    "/responses"
                } else {
                    "/v1/messages"
                };
                for change in ["slot", "route", "size"] {
                    let mut request = request(slot, path, "");
                    match change {
                        "slot" => request.capability_slot = "foreign".into(),
                        "route" => request.route = "github-https".into(),
                        "size" => request.body.resize(MAX_BODY + 1, b' '),
                        _ => unreachable!(),
                    }
                    assert!(broker.execute(request).await.is_err(), "{slot}/{change}");
                    assert!(authority.calls.lock().unwrap().is_empty());
                    assert_eq!(authority.reads.load(Ordering::Relaxed), 0);
                    assert_eq!(attempts(&provider), (0, 0));
                }
                for (leases, change) in ["method", "path", "query"].into_iter().enumerate() {
                    let mut request = request(slot, path, "");
                    match change {
                        "method" => request.method = "GET".into(),
                        "path" => request.path.push_str("/foreign"),
                        "query" => request.query = "foreign=true".into(),
                        _ => unreachable!(),
                    }
                    let (status, _, mut body) = broker
                        .execute(request)
                        .await
                        .unwrap_or_else(|_| panic!("{slot}/{change}: an HTTP answer"))
                        .into_parts();
                    assert_eq!(status, StatusCode::NOT_FOUND, "{slot}/{change}");
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.next().await {
                        bytes.extend(chunk.unwrap());
                    }
                    let output = String::from_utf8(bytes).unwrap();
                    assert!(output.contains("not_found"), "{slot}/{change}");
                    assert!(!output.contains(key(slot)));
                    assert_eq!(authority.calls.lock().unwrap().len(), leases + 1);
                    assert_eq!(attempts(&provider), (0, 0));
                }
            }
        }
    }

    #[tokio::test]
    async fn github_app_fixture_binds_all_exchange_branches_to_selected_origin() {
        use codewire_credential_broker::{
            GitHubAppAuthorizationConfig, GitHubAppAuthorizationError, GitHubAppAuthorizationOwner,
        };
        for port in [8090, 32767] {
            let callback = format!("http://127.0.0.1:{port}/api/v1/github/oauth/callback");
            let provider = SyntheticProvider(
                Arc::new(Mutex::new(Counters::default())),
                None,
                callback.clone().into(),
            );
            let config = GitHubAppAuthorizationConfig::new(
                GITHUB_APP_CLIENT_ID.into(),
                zeroize::Zeroizing::new(GITHUB_APP_CLIENT_SECRET.into()),
                GITHUB_APP_SLUG.into(),
                callback.clone(),
            )
            .unwrap();
            let owner = GitHubAppAuthorizationOwner::new(config, Arc::new(provider.clone()));
            for code in GITHUB_APP_AUTHORIZATION_CODES {
                assert!(
                    owner
                        .complete(zeroize::Zeroizing::new(code.as_bytes().to_vec()))
                        .await
                        .is_ok(),
                    "selected port {port} rejected installed exchange"
                );
            }
            assert!(
                matches!(
                    owner
                        .complete(zeroize::Zeroizing::new(
                            b"kind-synthetic-code-uninstalled".to_vec()
                        ))
                        .await,
                    Err(GitHubAppAuthorizationError::InstallationRequired)
                ),
                "selected port {port} rejected uninstalled exchange"
            );
            let wrong_port = if port == 8090 { 32767 } else { 8090 };
            let wrong = GitHubAppAuthorizationConfig::new(
                GITHUB_APP_CLIENT_ID.into(),
                zeroize::Zeroizing::new(GITHUB_APP_CLIENT_SECRET.into()),
                GITHUB_APP_SLUG.into(),
                format!("http://127.0.0.1:{wrong_port}/api/v1/github/oauth/callback"),
            )
            .unwrap();
            let wrong_owner = GitHubAppAuthorizationOwner::new(wrong, Arc::new(provider));
            assert!(
                wrong_owner
                    .complete(zeroize::Zeroizing::new(
                        GITHUB_APP_AUTHORIZATION_CODES[0].as_bytes().to_vec()
                    ))
                    .await
                    .is_err(),
                "mismatched port {wrong_port} was accepted by selected port {port}"
            );
        }
    }

    #[tokio::test]
    async fn github_fetch_counts_only_authenticated_successful_backend_responses() {
        use std::os::unix::fs::PermissionsExt;

        let runtime = tempfile::Builder::new()
            .prefix("kind-git-provider-test-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/dev/shm")
            .unwrap();
        let git = super::super::git::Fixture::create(runtime.path())
            .await
            .unwrap();
        let provider =
            SyntheticProvider::with_git(git.clone(), super::super::config::DEFAULT_PUBLIC_ORIGIN);
        let advertisement =
            "https://github.com/synthetic-user/repository-01.git/info/refs?service=git-upload-pack"
                .parse()
                .unwrap();
        let mut headers = HeaderMap::new();
        assert!(
            provider
                .github_git(&Method::GET, &advertisement, &headers, &[])
                .await
                .is_err()
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("x-access-token:{GITHUB_APP_USER_TOKEN}"))
            ))
            .unwrap(),
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_static("Codewire-Credential-Broker"),
        );
        headers.insert("accept-encoding", HeaderValue::from_static("identity"));
        let other =
            "https://github.com/synthetic-user/repository-02.git/info/refs?service=git-upload-pack"
                .parse()
                .unwrap();
        assert!(
            provider
                .github_git(&Method::GET, &other, &headers, &[])
                .await
                .is_err()
        );
        assert_eq!(provider.0.lock().unwrap().github_advertisements, 0);
        assert_eq!(provider.0.lock().unwrap().github_upload_packs, 0);
        provider
            .github_git(&Method::GET, &advertisement, &headers, &[])
            .await
            .unwrap();
        let upload = "https://github.com/synthetic-user/repository-01.git/git-upload-pack"
            .parse()
            .unwrap();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
        assert!(
            provider
                .github_git(&Method::POST, &upload, &headers, b"malformed")
                .await
                .is_err()
        );
        assert_eq!(provider.0.lock().unwrap().github_upload_packs, 0);
        let want = format!("want {}\n", super::super::git::REVISION);
        let request = format!("{:04x}{want}00000009done\n", want.len() + 4);
        provider
            .github_git(&Method::POST, &upload, &headers, request.as_bytes())
            .await
            .unwrap();
        assert_eq!(provider.0.lock().unwrap().github_advertisements, 1);
        assert_eq!(provider.0.lock().unwrap().github_upload_packs, 1);
        let refreshed_authorization = HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("x-access-token:{GITHUB_APP_REFRESHED_USER_TOKEN}"))
        ))
        .unwrap();
        let mut refreshed_get = headers.clone();
        refreshed_get.insert("authorization", refreshed_authorization.clone());
        refreshed_get.remove("content-type");
        provider
            .github_git(&Method::GET, &advertisement, &refreshed_get, &[])
            .await
            .unwrap();
        let mut refreshed_post = headers.clone();
        refreshed_post.insert("authorization", refreshed_authorization);
        provider
            .github_git(&Method::POST, &upload, &refreshed_post, request.as_bytes())
            .await
            .unwrap();
        {
            let counters = provider.0.lock().unwrap();
            assert_eq!(counters.github_advertisements, 2);
            assert_eq!(counters.github_upload_packs, 2);
            assert_eq!(counters.github_refreshed_advertisements, 1);
            assert_eq!(counters.github_refreshed_upload_packs, 1);
        }
        git.close().await.unwrap();
        assert!(
            provider
                .github_git(&Method::POST, &upload, &headers, request.as_bytes())
                .await
                .is_err()
        );
        assert_eq!(provider.0.lock().unwrap().github_upload_packs, 2);
    }

    #[test]
    fn repository_fixture_is_bounded_paginated_and_requires_its_synthetic_identity() {
        let provider = SyntheticProvider::new();
        for token in [GITHUB_APP_USER_TOKEN, GITHUB_APP_REFRESHED_USER_TOKEN] {
            let headers = HeaderMap::from_iter([(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            )]);
            for (page, count) in [(1, 50), (2, 1), (3, 0)] {
                let url = format!("https://api.github.com/user/repos?per_page=50&page={page}&sort=full_name&direction=asc").parse().unwrap();
                assert!(provider.github_repositories(&url, &headers, &[]).is_ok());
                let values = github_repository_values(page, 50);
                assert_eq!(values.len(), count);
                if page == 1 {
                    assert_eq!(values[0]["full_name"], "synthetic-user/repository-01");
                    assert_eq!(values[49]["disabled"], true);
                }
            }
        }
        let url =
            "https://api.github.com/user/repos?per_page=50&page=1&sort=full_name&direction=asc"
                .parse()
                .unwrap();
        assert!(
            provider
                .github_repositories(&url, &HeaderMap::new(), &[])
                .is_err()
        );
    }

    #[test]
    fn github_app_exchange_names_the_callback_on_the_harness_origin() {
        // The default port keeps the exact body the fixture always accepted.
        assert_eq!(
            SyntheticProvider::new().github_app_exchange_body("code"),
            format!(
                "client_id={GITHUB_APP_CLIENT_ID}&client_secret={GITHUB_APP_CLIENT_SECRET}&code=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A8090%2Fapi%2Fv1%2Fgithub%2Foauth%2Fcallback"
            )
        );
        let shifted = SyntheticProvider(
            Arc::new(Mutex::new(Counters::default())),
            None,
            github_app_callback_url("http://127.0.0.1:9090").into(),
        );
        assert!(shifted.github_app_exchange_body("code").ends_with(
            "&redirect_uri=http%3A%2F%2F127.0.0.1%3A9090%2Fapi%2Fv1%2Fgithub%2Foauth%2Fcallback"
        ));
    }

    #[test]
    fn github_app_fixture_requires_the_registered_exchange_and_identity_contract() {
        let provider = SyntheticProvider::new();
        let exchange_headers = HeaderMap::from_iter([
            (
                http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            ),
            (
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            ),
            (
                http::header::USER_AGENT,
                HeaderValue::from_static("Codewire-Credential-Service"),
            ),
        ]);
        assert!(
            provider
                .github_app_exchange(
                    &exchange_headers,
                    provider
                        .github_app_exchange_body(GITHUB_APP_AUTHORIZATION_CODES[0])
                        .as_bytes(),
                )
                .is_ok()
        );
        assert!(
            provider
                .github_app_exchange(&exchange_headers, github_app_refresh_body().as_bytes())
                .is_ok()
        );
        assert_eq!(provider.0.lock().unwrap().github_app_refreshes, 1);
        assert!(
            provider
                .github_app_exchange(&exchange_headers, b"client_id=wrong")
                .is_err()
        );

        let api_headers = HeaderMap::from_iter([
            (
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer ghu_kind_synthetic_user_token_1234567890"),
            ),
            (
                http::header::ACCEPT,
                HeaderValue::from_static("application/vnd.github+json"),
            ),
            (
                http::header::USER_AGENT,
                HeaderValue::from_static("Codewire-Credential-Service"),
            ),
        ]);
        assert!(provider.github_app_user(&api_headers, &[]).is_ok());
        let installations = "https://api.github.com/user/installations?per_page=100&page=1"
            .parse()
            .unwrap();
        assert!(
            provider
                .github_app_installations(&installations, &api_headers, &[])
                .is_ok()
        );
        let mut refreshed_api_headers = api_headers.clone();
        refreshed_api_headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ghu_kind_synthetic_refreshed_user_token_1234567890"),
        );
        assert!(
            provider
                .github_app_user(&refreshed_api_headers, &[])
                .is_ok()
        );
        assert!(
            provider
                .github_app_installations(&installations, &refreshed_api_headers, &[])
                .is_ok()
        );
        let wrong_installations = "https://api.github.com/user/installations?per_page=99&page=1"
            .parse()
            .unwrap();
        assert!(
            provider
                .github_app_installations(&wrong_installations, &api_headers, &[])
                .is_err()
        );

        let mut wrong_token = api_headers.clone();
        wrong_token.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        );
        assert!(provider.github_app_user(&wrong_token, &[]).is_err());
    }

    #[tokio::test]
    async fn github_app_fixture_distinguishes_installation_recovery_without_repository_access() {
        use codewire_credential_broker::{
            GitHubAppAuthorizationConfig, GitHubAppAuthorizationError, GitHubAppAuthorizationOwner,
        };
        let provider = SyntheticProvider::new();
        let config = GitHubAppAuthorizationConfig::new(
            GITHUB_APP_CLIENT_ID.into(),
            zeroize::Zeroizing::new(GITHUB_APP_CLIENT_SECRET.into()),
            GITHUB_APP_SLUG.into(),
            github_app_callback_url(super::super::config::DEFAULT_PUBLIC_ORIGIN),
        )
        .unwrap();
        let owner = GitHubAppAuthorizationOwner::new(config, std::sync::Arc::new(provider));
        assert!(matches!(
            owner
                .complete(zeroize::Zeroizing::new(
                    b"kind-synthetic-code-uninstalled".to_vec()
                ))
                .await,
            Err(GitHubAppAuthorizationError::InstallationRequired)
        ));
        assert!(
            owner
                .complete(zeroize::Zeroizing::new(
                    GITHUB_APP_AUTHORIZATION_CODES[0].as_bytes().to_vec()
                ))
                .await
                .is_ok()
        );
        let uninstalled = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {GITHUB_APP_UNINSTALLED_USER_TOKEN}")).unwrap(),
        )]);
        assert!(!github_bearer_authorization(&uninstalled));
        // #2712: the full grant names nothing; the earlier grant connects and
        // names its installation's settings page.
        let full = owner
            .complete(zeroize::Zeroizing::new(
                GITHUB_APP_AUTHORIZATION_CODES[0].as_bytes().to_vec(),
            ))
            .await
            .unwrap();
        assert!(
            full.reach()
                .iter()
                .all(|installation| installation.pending_permissions.is_none())
        );
        let limited = owner
            .complete(zeroize::Zeroizing::new(
                b"kind-synthetic-code-limited".to_vec(),
            ))
            .await
            .unwrap();
        let pending = limited.reach()[0].pending_permissions.as_ref().unwrap();
        assert_eq!(
            pending.settings_url(&limited.reach()[0].account).as_deref(),
            Some("https://github.com/settings/installations/41")
        );
        let pending = limited.reach()[1].pending_permissions.as_ref().unwrap();
        assert_eq!(
            pending.settings_url(&limited.reach()[1].account).as_deref(),
            Some("https://github.com/organizations/synthetic-works/settings/installations/42")
        );
        // The live status reads the stored connection the same way.
        assert_eq!(
            owner
                .pending_permissions(GITHUB_APP_LIMITED_USER_TOKEN.as_bytes())
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(
            owner
                .pending_permissions(GITHUB_APP_USER_TOKEN.as_bytes())
                .await
                .unwrap()
                .is_empty()
        );
        // The unreliable login connects, then every live read fails.
        let unreliable = owner
            .complete(zeroize::Zeroizing::new(
                b"kind-synthetic-code-unreliable".to_vec(),
            ))
            .await
            .unwrap();
        assert!(unreliable.reach()[0].pending_permissions.is_some());
        for _ in 0..2 {
            assert_eq!(
                owner
                    .pending_permissions(GITHUB_APP_UNRELIABLE_USER_TOKEN.as_bytes())
                    .await,
                Err(codewire_credential_broker::GitHubAppStatusError::Unavailable)
            );
        }
        let limited = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {GITHUB_APP_LIMITED_USER_TOKEN}")).unwrap(),
        )]);
        assert!(!github_bearer_authorization(&limited));
    }

    fn body(marker: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"input":marker})).unwrap()
    }

    fn headers(generation: u64) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", access_token(generation).unwrap()))
                .unwrap(),
        );
        headers.insert("chatgpt-account-id", HeaderValue::from_static(ACCOUNT));
        headers
    }

    #[test]
    fn provider_scenarios_reject_the_removed_marker_and_close_exhaustion() {
        assert!(Scenario::from_body(&body("CW_KIND_NATIVE_REREAD")).is_err());
        let exhausted = Scenario::from_body(&body("CW_KIND_BROKER_RETRY_EXHAUSTED")).unwrap();
        assert!(matches!(exhausted, Scenario::BrokerRetryExhausted));
        assert_eq!(exhausted.status(1), StatusCode::UNAUTHORIZED);
        assert_eq!(exhausted.status(2), StatusCode::BAD_REQUEST);
        assert_eq!(exhausted.status(3), StatusCode::BAD_REQUEST);
        assert_eq!(exhausted.status(u64::MAX), StatusCode::BAD_REQUEST);
    }

    fn anthropic_headers(kind: AnthropicKind) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("accept", "application/json"),
            ("content-type", "application/json"),
            ("anthropic-version", "2023-06-01"),
            ("accept-encoding", "identity"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        match kind {
            AnthropicKind::ApiKey => {
                headers.insert(
                    "x-api-key",
                    HeaderValue::from_static(KIND_ANTHROPIC_API_KEY),
                );
                headers.insert(
                    "anthropic-beta",
                    HeaderValue::from_static("claude-code-20250219"),
                );
            }
            AnthropicKind::SubscriptionToken | AnthropicKind::SignIn => {
                let token = if kind == AnthropicKind::SignIn {
                    claude_sign_in_access(1)
                } else {
                    KIND_CLAUDE_SUBSCRIPTION_TOKEN.to_owned()
                };
                headers.insert(
                    "authorization",
                    HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
                );
                headers.insert(
                    "anthropic-beta",
                    HeaderValue::from_static("claude-code-20250219,oauth-2025-04-20"),
                );
                headers.insert(
                    "user-agent",
                    HeaderValue::from_static("claude-cli/2.1.288 (external, sdk-cli)"),
                );
                headers.insert("x-app", HeaderValue::from_static("cli"));
            }
        }
        headers
    }

    fn anthropic_body(stream: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({"model":"claude-sonnet-5","max_tokens":32,
            "messages":[{"role":"user","content":"Reply"}],"stream":stream}))
        .unwrap()
    }

    fn messages() -> url::Url {
        "https://api.anthropic.com/v1/messages?beta=true"
            .parse()
            .unwrap()
    }

    /// Run `operation` with a JSON subscriber on the fixture's own target and
    /// return what it logged.
    fn logged<T>(operation: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "off,codewire_kind_credential_fixture=info",
            ))
            .with_writer(move || writer.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, operation);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (result, text)
    }

    fn claude_token_request(body: Value) -> Result<(StatusCode, Value), BrokerUpstreamError> {
        let provider = SyntheticProvider::new();
        claude_token_with(&provider, body)
    }

    fn claude_token_with(
        provider: &SyntheticProvider,
        body: Value,
    ) -> Result<(StatusCode, Value), BrokerUpstreamError> {
        let headers = HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]);
        provider.claude_token_answer(&headers, &serde_json::to_vec(&body).unwrap())
    }

    fn sign_in_exchange() -> Value {
        json!({"grant_type": "authorization_code", "code": KIND_CLAUDE_SIGN_IN_CODE,
               "redirect_uri": CLAUDE_MANUAL_REDIRECT_URL, "client_id": CLAUDE_CLIENT_ID,
               "code_verifier": "v".repeat(43), "state": "s".repeat(43)})
    }

    /// The synthetic Claude: the fixed code is exchanged for a first, nearly
    /// expired token; only the latest refresh token rotates, with exactly the
    /// granted scopes; a rotated or replayed token is refused, and the
    /// Anthropic route accepts only the latest access token as a sign-in.
    #[test]
    fn claude_sign_in_exchanges_rotates_and_refuses_stale_tokens() {
        let provider = SyntheticProvider::new();
        let (status, first) = claude_token_with(&provider, sign_in_exchange()).unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["access_token"], claude_sign_in_access(1));
        assert_eq!(first["expires_in"], CLAUDE_SIGN_IN_FIRST_LIFETIME);
        assert_eq!(first["scope"], CLAUDE_SIGN_IN_SCOPES);
        let profile = provider
            .claude_profile_answer(&HeaderMap::from_iter([(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", claude_sign_in_access(1))).unwrap(),
            )]))
            .unwrap();
        assert_eq!(profile["organization"]["organization_type"], "claude_max");
        let refresh = |token: String| {
            json!({"grant_type": "refresh_token", "refresh_token": token,
                   "client_id": CLAUDE_CLIENT_ID, "scope": CLAUDE_SIGN_IN_SCOPES})
        };
        let (status, second) =
            claude_token_with(&provider, refresh(claude_sign_in_refresh(1))).unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["access_token"], claude_sign_in_access(2));
        assert_eq!(second["expires_in"], CLAUDE_SIGN_IN_LIFETIME);
        // The rotated refresh token is spent, and so is the old access token.
        let (status, refused) =
            claude_token_with(&provider, refresh(claude_sign_in_refresh(1))).unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(refused["error"], "invalid_grant");
        let mut stale = anthropic_headers(AnthropicKind::SignIn);
        assert!(
            provider
                .admit_anthropic(&Method::POST, &messages(), &stale, &anthropic_body(true))
                .is_err()
        );
        stale.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", claude_sign_in_access(2))).unwrap(),
        );
        let admitted = provider
            .admit_anthropic(&Method::POST, &messages(), &stale, &anthropic_body(true))
            .unwrap();
        assert_eq!(admitted.kind, AnthropicKind::SignIn);
        // Without the OAuth beta the sign-in is refused.
        stale.remove("anthropic-beta");
        assert!(
            provider
                .admit_anthropic(&Method::POST, &messages(), &stale, &anthropic_body(true))
                .is_err()
        );
        // A wrong code, client, redirect or verifier shape is refused.
        for (field, value) in [
            ("code", json!("other")),
            ("client_id", json!("other")),
            ("redirect_uri", json!("https://example.test/callback")),
            ("code_verifier", json!("short")),
            ("state", json!("s".repeat(44))),
        ] {
            let mut body = sign_in_exchange();
            body[field] = value;
            assert_eq!(
                claude_token_request(body).unwrap().0,
                StatusCode::BAD_REQUEST
            );
        }
    }

    /// The refused token is answered as a real provider answers an expired
    /// or revoked one: a 401 `authentication_error` with fixed text.
    #[test]
    fn anthropic_refuses_the_refused_token_with_an_authentication_error() {
        let provider = SyntheticProvider::new();
        let mut headers = anthropic_headers(AnthropicKind::SubscriptionToken);
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {KIND_CLAUDE_REFUSED_TOKEN}")).unwrap(),
        );
        let (response, log) = logged(|| {
            provider.anthropic(&Method::POST, &messages(), &headers, &anthropic_body(true))
        });
        assert!(response.is_ok());
        let admitted = provider
            .admit_anthropic(&Method::POST, &messages(), &headers, &anthropic_body(true))
            .unwrap();
        assert!(admitted.refused && admitted.client_identity);
        assert_eq!(admitted.kind, AnthropicKind::SubscriptionToken);
        let bytes = anthropic_refusal_body().unwrap();
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["error"]["type"], "authentication_error");
        for secret in [KIND_CLAUDE_REFUSED_TOKEN, KIND_CLAUDE_SUBSCRIPTION_TOKEN] {
            assert!(!String::from_utf8_lossy(&bytes).contains(secret));
            assert!(!log.contains(secret));
        }
        let event: Value = serde_json::from_str(log.trim()).unwrap();
        assert_eq!(event["fields"]["event"], "anthropic_response");
        assert_eq!(event["fields"]["kind"], "subscription_token");
        assert_eq!(event["fields"]["status"], 401);
        assert_eq!(event["fields"]["refused"], true);
        // Its placeholder is still refused as malformed, never a 401.
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer codewire-managed"),
        );
        assert!(
            provider
                .anthropic(&Method::POST, &messages(), &headers, &anthropic_body(true))
                .is_err()
        );
    }

    #[test]
    fn anthropic_accepts_each_credential_form_and_replies_with_the_fixed_marker() {
        for kind in [AnthropicKind::ApiKey, AnthropicKind::SubscriptionToken] {
            let provider = SyntheticProvider::new();
            for stream in [true, false] {
                let (response, log) = logged(|| {
                    provider.anthropic(
                        &Method::POST,
                        &messages(),
                        &anthropic_headers(kind),
                        &anthropic_body(stream),
                    )
                });
                assert!(response.is_ok());
                let (content_type, body) =
                    anthropic_reply(AnthropicRoute::Messages, stream, "claude-sonnet-5").unwrap();
                assert_eq!(
                    content_type,
                    if stream {
                        "text/event-stream"
                    } else {
                        "application/json"
                    }
                );
                let text = String::from_utf8(body).unwrap();
                assert!(text.contains(CLAUDE_MARKER));
                for secret in [KIND_ANTHROPIC_API_KEY, KIND_CLAUDE_SUBSCRIPTION_TOKEN] {
                    assert!(!text.contains(secret));
                    assert!(!log.contains(secret));
                }
                let event: Value = serde_json::from_str(log.trim()).unwrap();
                let fields = &event["fields"];
                assert_eq!(fields["event"], "anthropic_response");
                assert_eq!(fields["kind"], kind.name());
                assert_eq!(fields["route"], "messages");
                assert_eq!(fields["stream"], stream);
                assert_eq!(fields["status"], 200);
                assert_eq!(fields["refused"], false);
                assert_eq!(
                    fields["client_identity"],
                    kind == AnthropicKind::SubscriptionToken
                );
                assert_eq!(
                    fields
                        .as_object()
                        .unwrap()
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([
                        "anthropic_calls",
                        "client_identity",
                        "event",
                        "kind",
                        "message",
                        "refused",
                        "route",
                        "status",
                        "stream",
                    ])
                );
            }
            let count = "https://api.anthropic.com/v1/messages/count_tokens"
                .parse()
                .unwrap();
            let mut body: Value = serde_json::from_slice(&anthropic_body(false)).unwrap();
            body.as_object_mut().unwrap().remove("stream");
            assert!(
                provider
                    .anthropic(
                        &Method::POST,
                        &count,
                        &anthropic_headers(kind),
                        &serde_json::to_vec(&body).unwrap(),
                    )
                    .is_ok()
            );
            assert_eq!(
                anthropic_reply(AnthropicRoute::CountTokens, false, "claude-sonnet-5").unwrap(),
                ("application/json", br#"{"input_tokens":1}"#.to_vec())
            );
            let counters = provider.0.lock().unwrap();
            assert_eq!(
                (counters.anthropic_calls, counters.anthropic_rejections),
                (3, 0)
            );
        }
    }

    #[test]
    fn anthropic_refuses_placeholders_mixed_or_wrong_credentials_and_a_missing_oauth_beta() {
        let provider = SyntheticProvider::new();
        let refused = |headers: HeaderMap, expected: AnthropicRejection| {
            let (result, log) = logged(|| {
                provider.anthropic(&Method::POST, &messages(), &headers, &anthropic_body(true))
            });
            assert!(result.is_err());
            assert_eq!(
                provider.admit_anthropic(
                    &Method::POST,
                    &messages(),
                    &headers,
                    &anthropic_body(true)
                ),
                Err(expected)
            );
            let event: Value = serde_json::from_str(log.trim()).unwrap();
            assert_eq!(event["fields"]["event"], "anthropic_rejected");
            assert_eq!(event["fields"]["reason"], expected.name());
            for secret in [
                KIND_ANTHROPIC_API_KEY,
                KIND_CLAUDE_SUBSCRIPTION_TOKEN,
                "codewire-managed",
            ] {
                assert!(!log.contains(secret));
            }
        };
        // The Sandbox placeholder in either header never reaches a provider.
        let mut placeholder = anthropic_headers(AnthropicKind::SubscriptionToken);
        placeholder.insert(
            "authorization",
            HeaderValue::from_static("Bearer codewire-managed"),
        );
        refused(placeholder, AnthropicRejection::Placeholder);
        let mut placeholder = anthropic_headers(AnthropicKind::ApiKey);
        placeholder.insert("x-api-key", HeaderValue::from_static("codewire-managed"));
        refused(placeholder, AnthropicRejection::Placeholder);
        // Both forms at once, or a form with the other's value, is refused.
        let mut both = anthropic_headers(AnthropicKind::SubscriptionToken);
        both.insert(
            "x-api-key",
            HeaderValue::from_static(KIND_ANTHROPIC_API_KEY),
        );
        refused(both, AnthropicRejection::Credential);
        let mut swapped = anthropic_headers(AnthropicKind::ApiKey);
        swapped.insert(
            "x-api-key",
            HeaderValue::from_static(KIND_CLAUDE_SUBSCRIPTION_TOKEN),
        );
        refused(swapped, AnthropicRejection::Credential);
        let mut bearer_key = anthropic_headers(AnthropicKind::SubscriptionToken);
        bearer_key.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {KIND_ANTHROPIC_API_KEY}")).unwrap(),
        );
        refused(bearer_key, AnthropicRejection::Credential);
        refused(HeaderMap::new(), AnthropicRejection::Credential);
        // An OAuth bearer requires the provider's OAuth beta.
        for beta in [None, Some("claude-code-20250219"), Some("oauth-2025-04-21")] {
            let mut headers = anthropic_headers(AnthropicKind::SubscriptionToken);
            headers.remove("anthropic-beta");
            if let Some(beta) = beta {
                headers.insert("anthropic-beta", HeaderValue::from_static(beta));
            }
            refused(headers, AnthropicRejection::OAuthBeta);
        }
        let mut encoded = anthropic_headers(AnthropicKind::ApiKey);
        encoded.insert("accept-encoding", HeaderValue::from_static("gzip"));
        refused(encoded, AnthropicRejection::Headers);
        assert_eq!(provider.0.lock().unwrap().anthropic_calls, 0);
        assert_eq!(provider.0.lock().unwrap().anthropic_rejections, 10);

        let headers = anthropic_headers(AnthropicKind::ApiKey);
        for (method, target) in [
            (Method::GET, "https://api.anthropic.com/v1/messages"),
            (
                Method::POST,
                "https://api.anthropic.com/v1/messages?beta=false",
            ),
            (Method::POST, "https://api.anthropic.com/v1/models"),
            (Method::POST, "https://api.anthropic.com/api/oauth/usage"),
        ] {
            assert_eq!(
                provider.admit_anthropic(
                    &method,
                    &target.parse().unwrap(),
                    &headers,
                    &anthropic_body(true)
                ),
                Err(AnthropicRejection::Route),
                "{target}"
            );
        }
        for body in [
            b"".to_vec(),
            b"not json".to_vec(),
            br#"{"messages":[]}"#.to_vec(),
        ] {
            assert_eq!(
                provider.admit_anthropic(&Method::POST, &messages(), &headers, &body),
                Err(AnthropicRejection::Body)
            );
        }
    }

    #[test]
    fn exhausted_schedule_counts_an_unexpected_third_request_as_failure() {
        let provider = SyntheticProvider::new();
        let exhausted = body("CW_KIND_BROKER_RETRY_EXHAUSTED");
        provider.responses(headers(1), &exhausted).unwrap();
        let refresh = serde_json::to_vec(&json!({
            "grant_type":"refresh_token",
            "refresh_token":refresh_token(1),
        }))
        .unwrap();
        provider.refresh(HeaderMap::new(), &refresh).unwrap();
        provider.responses(headers(2), &exhausted).unwrap();
        provider.responses(headers(2), &exhausted).unwrap();

        let counters = provider.0.lock().unwrap();
        assert_eq!(counters.responses, 3);
        assert_eq!(counters.refreshes, 1);
        assert_eq!(counters.attempts[Scenario::BrokerRetryExhausted.index()], 3);
    }
}
