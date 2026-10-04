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
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};

use super::TARGET;

pub(super) const ACCOUNT: &str = "codewire-kind-synthetic-account";
const TOKEN_SIGNATURE: &str = "synthetic-kind-signature";
const MAX_GENERATION: u64 = 10_000;
const MAX_BODY: usize = 4 * 1024 * 1024;
const RETRY_MARKER: &[u8] = b"CW_KIND_BROKER_RETRY_ONCE";
const EXHAUSTED_MARKER: &[u8] = b"CW_KIND_BROKER_RETRY_EXHAUSTED";
const LEGACY_REREAD_MARKER: &[u8] = b"CW_KIND_NATIVE_REREAD";

// Fixed, non-secret identities for the checked-in Kind fixture.  They are
// deliberately accepted only by this in-process provider, never a network
// listener or production configuration path.
pub(super) const GITHUB_DEVICE_TOKEN: &str = "gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub(super) const GITHUB_APP_CLIENT_ID: &str = "Iv1.kindsynthetic";
pub(super) const GITHUB_APP_CLIENT_SECRET: &str = "kind-synthetic-secret";
pub(super) const GITHUB_APP_SLUG: &str = "codewire-synthetic";
/// The registered GitHub App callback on the harness ingress origin.
pub(super) fn github_app_callback_url(public_origin: &str) -> String {
    format!("{public_origin}/api/v1/github/oauth/callback")
}
pub(super) const GITHUB_APP_USER_TOKEN: &str = "ghu_kind_synthetic_user_token_1234567890";
const GITHUB_APP_UNINSTALLED_USER_TOKEN: &str = "ghu_kind_synthetic_uninstalled_user_1234567890";
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
}

impl AnthropicKind {
    fn name(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::SubscriptionToken => "subscription_token",
        }
    }
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
        if headers.get("authorization").is_some_and(|value| {
            value == format!("Bearer {GITHUB_APP_UNINSTALLED_USER_TOKEN}").as_str()
        }) {
            return json_response(json!({"installations": []}));
        }
        json_response(json!({
            "installations": [{"id": 41, "app_slug": GITHUB_APP_SLUG}],
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
                // broker forwards for the subscription form only.
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
        let (kind, refused) = match (authorization.as_slice(), api_key.as_slice()) {
            ([], [key]) if key.as_bytes() == KIND_ANTHROPIC_API_KEY.as_bytes() => {
                (AnthropicKind::ApiKey, false)
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
        let (method, target, headers, body) = request.into_parts();
        if headers.contains_key("proxy-authorization") || headers.contains_key("cookie") {
            return Err(BrokerUpstreamError::Protocol);
        }
        if method == Method::POST
            && target.as_str() == "https://github.com/login/oauth/access_token"
        {
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
            "https://auth.openai.com/oauth/token" => self.refresh(headers, &body),
            _ => Err(BrokerUpstreamError::Protocol),
        }
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
    [
        GITHUB_DEVICE_TOKEN,
        GITHUB_APP_USER_TOKEN,
        GITHUB_APP_REFRESHED_USER_TOKEN,
    ]
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
                    .encode("x-access-token:gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
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
        for token in [
            GITHUB_DEVICE_TOKEN,
            GITHUB_APP_USER_TOKEN,
            GITHUB_APP_REFRESHED_USER_TOKEN,
        ] {
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
            AnthropicKind::SubscriptionToken => {
                headers.insert(
                    "authorization",
                    HeaderValue::from_str(&format!("Bearer {KIND_CLAUDE_SUBSCRIPTION_TOKEN}"))
                        .unwrap(),
                );
                headers.insert(
                    "anthropic-beta",
                    HeaderValue::from_static("claude-code-20250219,oauth-2025-04-20"),
                );
                headers.insert(
                    "user-agent",
                    HeaderValue::from_static("claude-cli/2.1.238 (external, sdk-cli)"),
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
