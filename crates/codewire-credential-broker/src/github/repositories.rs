//! Finite account-owned repository discovery. This is not an environment grant
//! or a general provider proxy. Its isolated caller owns original account,
//! current profile and credential-version admission before and after this call.

use std::collections::BTreeSet;

use av_credential_proxy::RedactionSet;
use codewire_access::{CredentialAuthKind, CredentialMetadata, CredentialStatus};
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::GitHubOAuthAdapter;
use crate::github_app::GitHubOAuthCredential;
use crate::{BrokerUpstreamRequest, BrokerUpstreamTransport};

pub const MAX_PAGE: u32 = 10_000;
pub const MAX_PAGE_SIZE: u16 = 100;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Trusted account-operation lease, deliberately distinct from runtime grants.
/// Only the isolated authority may implement this for an owner/profile-admitted
/// exact protected version. No constructor accepts public request metadata.
pub trait GithubRepositoryAccountLease: Sized {
    fn metadata(&self) -> &CredentialMetadata;
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryDiscoveryError {
    InvalidRequest,
    Unauthorized,
    Denied,
    RateLimited,
    Unavailable,
    InvalidResponse,
}

/// Explicit response allowlist: no provider URLs, token fields or raw JSON.
#[derive(Debug, Eq, PartialEq)]
pub struct Repository {
    pub repository_id: String,
    pub full_name: String,
    pub default_branch: String,
    pub clone_url: String,
    pub is_private: bool,
    pub archived: bool,
    pub disabled: bool,
}

pub struct RepositoryPage {
    pub repositories: Vec<Repository>,
    pub has_more: bool,
}

pub async fn list_repositories(
    upstream: &dyn BrokerUpstreamTransport,
    lease: impl GithubRepositoryAccountLease,
    page: u32,
    page_size: u16,
) -> Result<RepositoryPage, RepositoryDiscoveryError> {
    use RepositoryDiscoveryError as Error;
    if page == 0 || page > MAX_PAGE || page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(Error::InvalidRequest);
    }
    let metadata = lease.metadata();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_secs();
    if metadata.provider.as_str() != "github"
        || metadata.authentication_kind != CredentialAuthKind::OAuth
        || metadata.status != CredentialStatus::Active
        || metadata.revocation_generation == 0
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
    {
        return Err(Error::Denied);
    }
    let adapter = GitHubOAuthAdapter::new().map_err(|_| Error::Unavailable)?;
    // The only request is a fixed provider path with server-generated numeric
    // pagination. Never accept a caller URL, query, headers, or Link target.
    let query = format!("per_page={page_size}&page={page}&sort=full_name&direction=asc");
    let request = adapter
        .validate_request(
            "github-api",
            &Method::GET,
            "/user/repos",
            Some(&query),
            HeaderMap::from_iter([(
                http::header::ACCEPT,
                HeaderValue::from_static("application/vnd.github+json"),
            )]),
            Vec::new(),
        )
        .map_err(|_| Error::InvalidRequest)?;
    let (prepared, decoded_redaction) = lease
        .with_material(|material| {
            let credential = GitHubOAuthCredential::parse(material)
                .map_err(|_| crate::CredentialBrokerError::InvalidCredentialMaterial)?;
            let prepared = adapter.prepare_credential(request, &credential)?;
            let authorization = prepared
                .headers
                .get(http::header::AUTHORIZATION)
                .ok_or(crate::CredentialBrokerError::InvalidCredentialMaterial)?;
            // JSON escape spellings are unbounded. Retain only broker-local,
            // zeroizing matchers and check decoded allowlisted strings too. A
            // canonical App bundle serializes its token fields, so redacting
            // only the whole envelope would miss JSON-escaped bare tokens.
            let components = credential
                .redaction_components()
                .map_err(|_| crate::CredentialBrokerError::InvalidCredentialMaterial)?;
            let mut patterns = components
                .iter()
                .map(|component| component.as_slice())
                .collect::<Vec<_>>();
            patterns.push(material);
            patterns.push(authorization.as_bytes());
            let decoded_redaction = RedactionSet::new(patterns);
            Ok::<_, crate::CredentialBrokerError>((prepared, decoded_redaction))
        })
        .map_err(|_| Error::Denied)?;
    let (method, target, headers, body, filter) = prepared.into_parts();
    let response = upstream
        .execute(BrokerUpstreamRequest::new(method, target, headers, body))
        .await
        .map_err(|_| Error::Unavailable)?;
    let (status, headers, mut body) = response.into_parts();
    // Error bodies may contain sensitive provider diagnostics. Never poll them.
    if status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (headers
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value == "0")
                || headers.get("retry-after").is_some_and(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<u32>().ok())
                        .is_some_and(|seconds| seconds <= 86_400)
                })))
    {
        return Err(Error::RateLimited);
    }
    if status == StatusCode::UNAUTHORIZED {
        return Err(Error::Unauthorized);
    }
    if status == StatusCode::FORBIDDEN {
        return Err(Error::Denied);
    }
    if status != StatusCode::OK {
        return Err(Error::Unavailable);
    }
    let (_, mut redactor) = filter
        .begin(status, &headers)
        .map_err(|_| Error::InvalidResponse)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut received = 0_usize;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| Error::Unavailable)?;
        received = received
            .checked_add(chunk.len())
            .filter(|size| *size <= MAX_RESPONSE_BYTES)
            .ok_or(Error::InvalidResponse)?;
        bytes.extend(redactor.push(&chunk).map_err(|_| Error::InvalidResponse)?);
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidResponse);
        }
    }
    bytes.extend(redactor.finish().map_err(|_| Error::InvalidResponse)?);
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::InvalidResponse);
    }
    parse_repositories(&bytes, page_size, &decoded_redaction)
}

#[derive(Deserialize)]
struct ProviderRepository {
    id: u64,
    full_name: String,
    default_branch: Option<String>,
    private: bool,
    archived: bool,
    disabled: bool,
}

impl Drop for ProviderRepository {
    fn drop(&mut self) {
        self.full_name.zeroize();
        self.default_branch.zeroize();
    }
}

fn parse_repositories(
    bytes: &[u8],
    page_size: u16,
    decoded_redaction: &RedactionSet,
) -> Result<RepositoryPage, RepositoryDiscoveryError> {
    use RepositoryDiscoveryError::InvalidResponse;
    let values: Vec<ProviderRepository> =
        serde_json::from_slice(bytes).map_err(|_| InvalidResponse)?;
    if values.len() > usize::from(page_size) {
        return Err(InvalidResponse);
    }
    let has_more = values.len() == usize::from(page_size);
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let repositories = values
        .into_iter()
        .map(|mut value| {
            let branch = Zeroizing::new(value.default_branch.take().unwrap_or_default());
            let repository_id = Zeroizing::new(value.id.to_string());
            let clone_url = Zeroizing::new(format!("https://github.com/{}.git", value.full_name));
            for field in [
                value.full_name.as_bytes(),
                branch.as_bytes(),
                repository_id.as_bytes(),
                clone_url.as_bytes(),
            ] {
                if Zeroizing::new(decoded_redaction.redact_bytes(field)).as_slice() != field {
                    return Err(InvalidResponse);
                }
            }
            let Some((owner, repository)) = value.full_name.split_once('/') else {
                return Err(InvalidResponse);
            };
            let valid_owner = !owner.is_empty()
                && owner.len() <= 39
                && !owner.starts_with('-')
                && !owner.ends_with('-')
                && !owner.contains("--")
                && owner
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
            let valid_repository = !repository.is_empty()
                && repository.len() <= 100
                && !matches!(repository, "." | "..")
                && repository
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if value.id == 0
                || !ids.insert(value.id)
                || !names.insert(value.full_name.to_ascii_lowercase())
                || !valid_owner
                || !valid_repository
                || branch.len() > 512
                || branch.starts_with('-')
                || branch.trim() != branch.as_str()
                || branch.chars().any(char::is_control)
            {
                return Err(InvalidResponse);
            }
            Ok(Repository {
                repository_id: repository_id.to_string(),
                clone_url: clone_url.to_string(),
                full_name: std::mem::take(&mut value.full_name),
                default_branch: branch.to_string(),
                is_private: value.private,
                archived: value.archived,
                disabled: value.disabled,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // A full last page may require one extra empty request. This deliberate
    // bounded rule avoids retaining or following a provider-controlled Link.
    Ok(RepositoryPage {
        repositories,
        has_more,
    })
}

#[cfg(test)]
mod tests;
