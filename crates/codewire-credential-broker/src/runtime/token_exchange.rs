//! The provider token-refresh exchanges, Codex, Claude and the GitHub App:
//! one bounded request to a fixed token endpoint and the rotated material's
//! validation, shared by on-demand refresh and the platform keep-alive.

use super::*;

/// One bounded Codex refresh-token exchange plus rotated-material validation.
///
/// The caller owns a durable Started attempt. Every `Err` is terminal for that
/// attempt: the previous refresh token is never replayed. The closed failure
/// class is for operator diagnostics only. Shared by on-demand broker refresh
/// and the platform keep-alive so both send and validate exactly the same way.
pub(crate) async fn exchange_codex_oauth_refresh<U>(
    upstream: &U,
    credential: CodexOAuthCredential,
    refreshed_at_unix: u64,
) -> Result<CanonicalCodexOAuthBundle, (RefreshFailure, BrokerRequestError)>
where
    U: BrokerUpstreamTransport + ?Sized,
{
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        request_oauth_refresh(upstream, credential.refresh_token()),
    )
    .await;
    match exchange {
        Ok(Ok(tokens)) => credential
            .refreshed(
                tokens.id_token,
                tokens.access_token,
                tokens.refresh_token,
                refreshed_at_unix,
            )
            .and_then(|refreshed| refreshed.to_bundle())
            .map_err(|_| (RefreshFailure::Material, BrokerRequestError::Denied)),
        Ok(Err(OAuthRefreshError::Uncertain(error, failure))) => Err((failure, error)),
        Ok(Err(OAuthRefreshError::Permanent(failure))) => {
            Err((failure, BrokerRequestError::Denied))
        }
        Err(_) => Err((RefreshFailure::Timeout, BrokerRequestError::UpstreamFailed)),
    }
}

/// One bounded GitHub App user-token rotation through the private App owner.
/// Like the Codex exchange, every `Err` is terminal for the started attempt.
pub(crate) async fn exchange_github_app_refresh(
    owner: &GitHubAppAuthorizationOwner,
    bundle: GitHubAppUserOAuthBundle,
) -> Result<GitHubAppUserOAuthBundle, (RefreshFailure, BrokerRequestError)> {
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        owner.refresh(bundle),
    )
    .await;
    match exchange {
        Ok(Ok(bundle)) => Ok(bundle),
        Ok(Err(GitHubAppRefreshError::Permanent)) => {
            Err((RefreshFailure::ProviderRejected, BrokerRequestError::Denied))
        }
        Ok(Err(GitHubAppRefreshError::Uncertain)) => Err((
            RefreshFailure::ProviderUncertain,
            BrokerRequestError::UpstreamFailed,
        )),
        Ok(Err(GitHubAppRefreshError::RateLimited { wait_seconds })) => Err((
            RefreshFailure::RateLimited { wait_seconds },
            BrokerRequestError::UpstreamFailed,
        )),
        Err(_) => Err((RefreshFailure::Timeout, BrokerRequestError::UpstreamFailed)),
    }
}

async fn request_oauth_refresh<U>(
    upstream: &U,
    refresh_token: &str,
) -> Result<OAuthRefreshResponse, OAuthRefreshError>
where
    U: BrokerUpstreamTransport + ?Sized,
{
    // Request construction is local and fixed; failing it sends nothing.
    let local = OAuthRefreshError::Permanent(RefreshFailure::RequestBuild);
    let body = Zeroizing::new(
        serde_json::to_vec(&OAuthRefreshRequest {
            client_id: CODEX_OAUTH_CLIENT_ID,
            grant_type: "refresh_token",
            refresh_token,
        })
        .map_err(|_| local)?,
    );
    let target = Url::parse(OPENAI_TOKEN_URL).map_err(|_| local)?;
    let response = post_token_refresh(upstream, target, body, "application/json").await?;
    let parsed = serde_json::from_slice::<OAuthRefreshResponse>(&response)
        .map_err(|_| OAuthRefreshError::Permanent(RefreshFailure::ResponseParse))?;
    drop(response);
    if parsed.access_token.is_none() {
        return Err(OAuthRefreshError::Permanent(RefreshFailure::ResponseParse));
    }
    Ok(parsed)
}

/// One refresh request to a provider's fixed token endpoint: `body` is sent
/// once with `content_type`, and only a success's bounded, identity-encoded
/// body returns. A non-success answer is classified from allowlisted
/// identifiers only; its body, including any provider description, is zeroized
/// on drop.
async fn post_token_refresh<U>(
    upstream: &U,
    target: Url,
    mut body: Zeroizing<Vec<u8>>,
    content_type: &'static str,
) -> Result<Zeroizing<Vec<u8>>, OAuthRefreshError>
where
    U: BrokerUpstreamTransport + ?Sized,
{
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::ACCEPT,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    let upstream = upstream
        .execute(BrokerUpstreamRequest {
            method: Method::POST,
            target,
            headers,
            body: std::mem::take(&mut *body),
            body_stream: None,
            pinned: None,
        })
        .await
        .map_err(|error| {
            OAuthRefreshError::Uncertain(
                crate::refresh_failure::transport_request_error(error),
                RefreshFailure::Transport(error),
            )
        })?;
    let (status, headers, mut response_body) = upstream.into_parts();
    // Refresh bypasses the guest response redactor, but every transport
    // must still deliver identity bytes before internal token parsing.
    crate::openai::validate_response_encoding(&headers).map_err(|_| {
        OAuthRefreshError::Uncertain(
            BrokerRequestError::UpstreamFailed,
            RefreshFailure::ResponseEncoding,
        )
    })?;
    let body_failure = |error: BrokerRequestError| {
        if status.is_success() {
            OAuthRefreshError::Permanent(RefreshFailure::ResponseBody)
        } else {
            OAuthRefreshError::Uncertain(error, RefreshFailure::ResponseBody)
        }
    };
    let mut response = Zeroizing::new(Vec::new());
    while let Some(chunk) = response_body.next().await {
        let chunk = chunk.map_err(|error| body_failure(map_upstream_error(error)))?;
        let next_len = response
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_OAUTH_REFRESH_RESPONSE_BYTES)
            .ok_or_else(|| body_failure(BrokerRequestError::ResponseTooLarge))?;
        let additional = next_len.saturating_sub(response.len());
        response
            .try_reserve(additional)
            .map_err(|_| body_failure(BrokerRequestError::ResponseTooLarge))?;
        response.extend_from_slice(&chunk);
    }
    // A 429 read in full was not processed: the attempt waits instead of
    // failing (#4975). Only the provider's own answer here gets this.
    if status == http::StatusCode::TOO_MANY_REQUESTS {
        let wait_seconds = crate::refresh_failure::rate_limit_wait(&headers, SystemTime::now());
        return Err(OAuthRefreshError::Uncertain(
            BrokerRequestError::UpstreamFailed,
            RefreshFailure::RateLimited { wait_seconds },
        ));
    }
    if !status.is_success() {
        let rejection = ProviderRejection::classify(status, &response);
        return Err(if rejection.permanent {
            OAuthRefreshError::Permanent(RefreshFailure::Rejected(rejection))
        } else {
            OAuthRefreshError::Uncertain(
                BrokerRequestError::UpstreamFailed,
                RefreshFailure::Rejected(rejection),
            )
        });
    }
    Ok(response)
}

/// One bounded Claude sign-in refresh-token exchange plus rotated-material
/// validation: a non-empty access token, a lifetime in range and the required
/// scopes kept. Like the Codex exchange, every `Err` is terminal for the
/// started attempt and the previous refresh token is never replayed. Shared by
/// on-demand broker refresh and the platform keep-alive.
pub(crate) async fn exchange_claude_oauth_refresh<U>(
    upstream: &U,
    credential: ClaudeOAuthCredential,
    refreshed_at_unix: u64,
) -> Result<CanonicalClaudeOAuthBundle, (RefreshFailure, BrokerRequestError)>
where
    U: BrokerUpstreamTransport + ?Sized,
{
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        async {
            let (target, body) = crate::provider_oauth::claude::refresh_request(
                credential.refresh_token(),
                credential.scopes(),
            )
            .map_err(|_| OAuthRefreshError::Permanent(RefreshFailure::RequestBuild))?;
            let response = post_token_refresh(upstream, target, body, "application/json").await?;
            crate::provider_oauth::claude::parse_refresh_response(&response)
                .map_err(|_| OAuthRefreshError::Permanent(RefreshFailure::ResponseParse))
        },
    )
    .await;
    match exchange {
        Ok(Ok(tokens)) => credential
            .refreshed(tokens, refreshed_at_unix)
            .and_then(|refreshed| refreshed.to_bundle())
            .map_err(|_| (RefreshFailure::Material, BrokerRequestError::Denied)),
        Ok(Err(OAuthRefreshError::Uncertain(error, failure))) => Err((failure, error)),
        Ok(Err(OAuthRefreshError::Permanent(failure))) => {
            Err((failure, BrokerRequestError::Denied))
        }
        Err(_) => Err((RefreshFailure::Timeout, BrokerRequestError::UpstreamFailed)),
    }
}

/// One bounded Antigravity (Google OAuth) refresh-token exchange plus
/// rotated-material and strict scope allow-list validation. Google's token
/// endpoint expects `application/x-www-form-urlencoded`.
pub(crate) async fn exchange_antigravity_oauth_refresh<U>(
    upstream: &U,
    credential: AntigravityOAuthCredential,
    refreshed_at_unix: u64,
) -> Result<CanonicalAntigravityOAuthBundle, (RefreshFailure, BrokerRequestError)>
where
    U: BrokerUpstreamTransport + ?Sized,
{
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        async {
            let (target, body) =
                crate::provider_oauth::antigravity::refresh_request(credential.refresh_token())
                    .map_err(|_| OAuthRefreshError::Permanent(RefreshFailure::RequestBuild))?;
            let response =
                post_token_refresh(upstream, target, body, "application/x-www-form-urlencoded")
                    .await?;
            crate::provider_oauth::antigravity::parse_refresh_response(&response)
                .map_err(|_| OAuthRefreshError::Permanent(RefreshFailure::ResponseParse))
        },
    )
    .await;
    match exchange {
        Ok(Ok(tokens)) => credential
            .refreshed(tokens, refreshed_at_unix)
            .and_then(|refreshed| refreshed.to_bundle())
            .map_err(|_| (RefreshFailure::Material, BrokerRequestError::Denied)),
        Ok(Err(OAuthRefreshError::Uncertain(error, failure))) => Err((failure, error)),
        Ok(Err(OAuthRefreshError::Permanent(failure))) => {
            Err((failure, BrokerRequestError::Denied))
        }
        Err(_) => Err((RefreshFailure::Timeout, BrokerRequestError::UpstreamFailed)),
    }
}

/// Terminal refresh exchange outcomes. Both are recorded as an unknown
/// attempt; the closed failure class exists only for operator diagnostics.
#[derive(Clone, Copy)]
enum OAuthRefreshError {
    Permanent(RefreshFailure),
    Uncertain(BrokerRequestError, RefreshFailure),
}

#[derive(Serialize)]
struct OAuthRefreshRequest<'a> {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct OAuthRefreshResponse {
    id_token: Option<Zeroizing<String>>,
    access_token: Option<Zeroizing<String>>,
    refresh_token: Option<Zeroizing<String>>,
}
