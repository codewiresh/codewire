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

#[derive(Default)]
struct Counters {
    responses: u64,
    refreshes: u64,
    attempts: [u64; 3],
    required_generation: [Option<u64>; 3],
    last_refresh: Option<(u64, u64)>,
    github_advertisements: u64,
    github_upload_packs: u64,
}

#[derive(Clone)]
pub(super) struct SyntheticProvider(Arc<Mutex<Counters>>, Option<Arc<super::git::Fixture>>);

impl SyntheticProvider {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Counters::default())), None)
    }

    pub(super) fn with_git(git: Arc<super::git::Fixture>) -> Self {
        Self(Arc::new(Mutex::new(Counters::default())), Some(git))
    }

    async fn github_git(
        &self,
        method: &Method,
        target: &url::Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let fixture = self.1.as_ref().ok_or(BrokerUpstreamError::Protocol)?;
        let (operation, body) = fixture.execute(method, target, headers, body).await?;
        {
            let mut counters = self.0.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
            match operation {
                super::git::Operation::Advertisement => {
                    counters.github_advertisements = increment(counters.github_advertisements)?
                }
                super::git::Operation::UploadPack => {
                    counters.github_upload_packs = increment(counters.github_upload_packs)?
                }
            }
            // Only successful authenticated backend responses advance these
            // closed counters. No request/header/body or private path is logged.
            tracing::info!(target: TARGET, event = "github_git_response", operation = operation.name(),
                github_advertisement_calls = counters.github_advertisements,
                github_upload_pack_calls = counters.github_upload_packs, "github_git_response");
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
            || headers.get("authorization")
                != Some(&HeaderValue::from_static(
                    "Bearer gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                ))
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
                "provider_totals");
        }
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
            tracing::info!(target: TARGET, event = "provider_response", scenario = scenario.name(), attempt,
                status = status.as_u16(), response_calls = counters.responses, refresh_calls = counters.refreshes,
                "provider_response");
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
        if target.host_str() == Some("github.com") {
            return self.github_git(&method, &target, &headers, &body).await;
        }
        if method == Method::GET
            && target.origin().ascii_serialization() == "https://api.github.com"
            && target.path() == "/user/repos"
        {
            return self.github_repositories(&target, &headers, &body);
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
        let provider = SyntheticProvider::with_git(git.clone());
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
        git.close().await.unwrap();
        assert!(
            provider
                .github_git(&Method::POST, &upload, &headers, request.as_bytes())
                .await
                .is_err()
        );
        assert_eq!(provider.0.lock().unwrap().github_upload_packs, 1);
    }

    #[test]
    fn repository_fixture_is_bounded_paginated_and_requires_its_synthetic_identity() {
        let provider = SyntheticProvider::new();
        let headers = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer gho_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
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
