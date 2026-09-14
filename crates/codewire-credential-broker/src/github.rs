//! Selected GitHub OAuth identity: finite REST templates, GraphQL, and smart Git.
//!
//! References reviewed 2026-09-07:
//! <https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api>,
//! <https://docs.github.com/en/graphql/guides/forming-calls-with-graphql>,
//! <https://cli.github.com/manual/gh_api>, and
//! <https://git-scm.com/docs/gitprotocol-http>.
//!
//! GraphQL uses the selected token's provider permissions, not a repository or
//! field-level policy. REST routes below exclude admin, Actions, secrets, apps,
//! and release assets. Smart HTTP supports fetch/push only: no dumb HTTP, LFS,
//! redirects, arbitrary hosts, or credential-helper token disclosure.
//! Requests are capped at 4 MiB and responses at 256 MiB; larger Git transfers
//! fail closed. AV redacts its finite raw/JSON/percent/base64 patterns, including
//! the complete injected Bearer/Basic value. It does not inspect compressed Git
//! pack objects or guarantee arbitrary-transformation redaction. The ordinary
//! Git wire payload is binary; changing a matching pattern can invalidate it.
//! Stock Git gzip fetch requests are forwarded unchanged to the fixed GitHub
//! upload-pack endpoint. The 4 MiB request cap counts compressed wire bytes;
//! the broker neither decompresses nor claims an expanded-body size bound.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig,
    ValidatedProxyRequest, build_target_url, is_websocket_attempt, prepare_credentials,
    prepare_outbound_headers, validate_proxy_request, validate_proxy_route,
};
use codewire_access::{CredentialAuthKind, CredentialStatus};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use url::Url;

use crate::{
    BrokerCredentialLease, CredentialBrokerError, OpenAiStreamingResponse, PreparedOpenAiResponse,
};

pub mod repositories;

const TOKEN: &str = "GITHUB_OAUTH_TOKEN";
const API_VERSION: &str = "2022-11-28";
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "content-type",
    "git-protocol",
    "if-none-match",
    "if-modified-since",
];
const RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "etag",
    "last-modified",
    "cache-control",
    "link",
    "retry-after",
    "x-github-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
    "x-ratelimit-used",
];
const REST_QUERY: &[&str] = &[
    "page",
    "per_page",
    "state",
    "head",
    "base",
    "sort",
    "direction",
    "labels",
    "since",
    "milestone",
    "creator",
    "assignee",
    "mentioned",
    "type",
    "affiliation",
    "visibility",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitHubOperation {
    Rest,
    Graphql,
    GitFetch,
    GitPush,
}

impl GitHubOperation {
    pub fn operation_name(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Graphql => "graphql",
            Self::GitFetch => "git-fetch",
            Self::GitPush => "git-push",
        }
    }
    pub fn route_name(self) -> &'static str {
        match self {
            Self::Rest | Self::Graphql => "github-api",
            Self::GitFetch | Self::GitPush => "github-https",
        }
    }
    fn is_git(self) -> bool {
        matches!(self, Self::GitFetch | Self::GitPush)
    }
}

/// No caller-configurable destination, policy, header injection or identity.
pub struct GitHubOAuthAdapter;

impl GitHubOAuthAdapter {
    pub fn new() -> Result<Self, CredentialBrokerError> {
        for (operation, path) in [
            (GitHubOperation::Rest, "/user"),
            (GitHubOperation::GitFetch, "/owner/repo.git/git-upload-pack"),
        ] {
            validate_proxy_route(
                operation.route_name(),
                &policy(operation, path),
                false,
                false,
            )
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        }
        Ok(Self)
    }

    pub fn validate_request(
        &self,
        route: &str,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedGitHubRequest, CredentialBrokerError> {
        let denied = CredentialBrokerError::RequestDenied;
        let operation = classify_request(route, method, path, query)?;
        if body.len() > MAX_REQUEST_BYTES
            || !bounded_headers(&headers)
            || is_websocket_attempt(&headers)
            || !valid_request_encoding(operation, method, &headers)
            || REQUEST_HEADERS
                .iter()
                .any(|name| headers.get_all(*name).iter().count() > 1)
        {
            return Err(denied);
        }
        if method == Method::GET && !body.is_empty() {
            return Err(denied);
        }
        if let Some(version) = headers.get("x-github-api-version")
            && (headers.get_all("x-github-api-version").iter().count() != 1
                || version != API_VERSION)
        {
            return Err(denied);
        }
        if let Some(protocol) = headers.get("git-protocol")
            && (!operation.is_git() || !matches!(protocol.as_bytes(), b"version=1" | b"version=2"))
        {
            return Err(denied);
        }
        if !body.is_empty() {
            let expected = if operation.is_git() {
                if operation == GitHubOperation::GitFetch {
                    "application/x-git-upload-pack-request"
                } else {
                    "application/x-git-receive-pack-request"
                }
            } else {
                "application/json"
            };
            if media_type(&headers).as_deref() != Some(expected) {
                return Err(denied);
            }
            if !operation.is_git() {
                let json: serde_json::Value = serde_json::from_slice(&body).map_err(|_| denied)?;
                let object = json.as_object().ok_or(denied)?;
                if operation == GitHubOperation::Graphql
                    && (object
                        .get("query")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(str::is_empty)
                        || object.keys().any(|key| {
                            !matches!(key.as_str(), "query" | "variables" | "operationName")
                        })
                        || object
                            .get("variables")
                            .is_some_and(|value| !value.is_object() && !value.is_null())
                        || object
                            .get("operationName")
                            .is_some_and(|value| !value.is_string() && !value.is_null()))
                {
                    return Err(denied);
                }
            }
        } else if method == Method::POST {
            return Err(denied);
        }
        let policy = policy(operation, path);
        validate_proxy_route(operation.route_name(), &policy, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        let request = validate_proxy_request(&policy, path, query, method, &headers, body.len())
            .map_err(|_| denied)?;
        Ok(ValidatedGitHubRequest {
            operation,
            policy,
            request,
            method: method.clone(),
            headers,
            body,
        })
    }

    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedGitHubRequest,
    ) -> Result<PreparedGitHubRequest, CredentialBrokerError> {
        validate_lease(&lease, request.operation)?;
        lease.with_material(|material| self.prepare_material(request, material))
    }

    fn prepare_material(
        &self,
        request: ValidatedGitHubRequest,
        material: &[u8],
    ) -> Result<PreparedGitHubRequest, CredentialBrokerError> {
        let target = build_target_url(&request.policy, &request.request)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        if material.is_empty()
            || material.len() > 4096
            || !material.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CredentialBrokerError::InvalidCredentialMaterial);
        }
        let token = std::str::from_utf8(material)
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        let prepared = prepare_credentials(&request.policy, &Token(token), &request.body)
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        let mut headers = prepare_outbound_headers(&request.policy, &request.headers, &prepared)
            .map_err(|_| CredentialBrokerError::RequestDenied)?;
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Codewire-Credential-Broker"),
        );
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        if !request.operation.is_git() {
            headers.insert(
                "x-github-api-version",
                HeaderValue::from_static(API_VERSION),
            );
        }
        let (body, redaction) = prepared.into_body_and_redaction();
        let response = PreparedGitHubResponse {
            operation: request.operation,
            inner: PreparedOpenAiResponse::from_route_redaction(&request.policy, redaction)?,
        };
        Ok(PreparedGitHubRequest {
            method: request.method,
            target,
            headers,
            body,
            response,
        })
    }
}

pub struct ValidatedGitHubRequest {
    operation: GitHubOperation,
    policy: ProxyRouteConfig,
    request: ValidatedProxyRequest,
    method: Method,
    headers: HeaderMap,
    body: Vec<u8>,
}
impl ValidatedGitHubRequest {
    pub fn operation(&self) -> GitHubOperation {
        self.operation
    }
}

/// Broker-only, secret-bearing request. No Debug/Clone/serialization.
pub struct PreparedGitHubRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedGitHubResponse,
}
impl PreparedGitHubRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedGitHubResponse) {
        (
            self.method,
            self.target,
            self.headers,
            self.body,
            self.response,
        )
    }
}

pub struct PreparedGitHubResponse {
    operation: GitHubOperation,
    inner: PreparedOpenAiResponse,
}
impl PreparedGitHubResponse {
    /// Admit before releasing any headers or polling the upstream body.
    pub fn begin(
        self,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<(HeaderMap, OpenAiStreamingResponse), CredentialBrokerError> {
        if !bounded_headers(headers) {
            return Err(CredentialBrokerError::ResponseDenied);
        }
        if let Some(media) = media_type(headers) {
            let supported = matches!(
                media.as_str(),
                "application/json"
                    | "text/plain"
                    | "application/vnd.github+json"
                    | "application/vnd.github.v3.diff"
                    | "application/vnd.github.v3.patch"
            ) || (self.operation == GitHubOperation::GitFetch
                && matches!(
                    media.as_str(),
                    "application/x-git-upload-pack-advertisement"
                        | "application/x-git-upload-pack-result"
                ))
                || (self.operation == GitHubOperation::GitPush
                    && matches!(
                        media.as_str(),
                        "application/x-git-receive-pack-advertisement"
                            | "application/x-git-receive-pack-result"
                    ));
            if !supported {
                return Err(CredentialBrokerError::ResponseDenied);
            }
        } else if headers.contains_key(header::CONTENT_TYPE)
            || !matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED)
        {
            return Err(CredentialBrokerError::ResponseDenied);
        }
        // Missing Content-Type is possible for bodyless REST 204/304. The
        // authenticated provider/transport owns framing; no coding is admitted.
        self.inner.begin(headers)
    }
}

struct Token<'a>(&'a str);
impl CredentialSource for Token<'_> {
    fn credential(&self, name: &str) -> Option<&str> {
        (name == TOKEN).then_some(self.0)
    }
}

fn validate_lease(
    lease: &impl BrokerCredentialLease,
    operation: GitHubOperation,
) -> Result<(), CredentialBrokerError> {
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let permission = lease.permission();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialBrokerError::UnsupportedLease)?
        .as_secs();
    if metadata.provider.as_str() != "github"
        || metadata.authentication_kind != CredentialAuthKind::OAuth
        || metadata.status != CredentialStatus::Active
        || metadata.revocation_generation == 0
        || metadata.revocation_generation != grant.credential_revocation_generation
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.capability_slot.as_str() != "github"
        || grant.credential_id != metadata.id
        || grant.environment_generation == 0
        || grant.profile_revision == 0
        || lease.material_generation() == 0
        || permission.operation.as_str() != operation.operation_name()
        || permission.route.as_str() != operation.route_name()
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

/// Shared by adapter and pinned transport: exact route grammar, never URLs.
pub(crate) fn classify_request(
    route: &str,
    method: &Method,
    path: &str,
    query: Option<&str>,
) -> Result<GitHubOperation, CredentialBrokerError> {
    let denied = CredentialBrokerError::RequestDenied;
    if path.len() > 2048 || !path.starts_with('/') {
        return Err(denied);
    }
    let parts = path[1..].split('/').collect::<Vec<_>>();
    if parts.iter().any(|part| {
        part.is_empty()
            || matches!(*part, "." | "..")
            || part.len() > 128
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }) {
        return Err(denied);
    }
    if route == "github-https" {
        match parts.as_slice() {
            [_, _, "info", "refs"] if method == Method::GET => match query {
                Some("service=git-upload-pack") => Ok(GitHubOperation::GitFetch),
                Some("service=git-receive-pack") => Ok(GitHubOperation::GitPush),
                _ => Err(denied),
            },
            [_, _, "git-upload-pack"]
                if method == Method::POST && query.is_none_or(str::is_empty) =>
            {
                Ok(GitHubOperation::GitFetch)
            }
            [_, _, "git-receive-pack"]
                if method == Method::POST && query.is_none_or(str::is_empty) =>
            {
                Ok(GitHubOperation::GitPush)
            }
            _ => Err(denied),
        }
    } else if route == "github-api" {
        if path == "/graphql" {
            return if method == Method::POST && query.is_none_or(str::is_empty) {
                Ok(GitHubOperation::Graphql)
            } else {
                Err(denied)
            };
        }
        validate_rest_query(query)?;
        let m = method.as_str();
        let admitted = match parts.as_slice() {
            ["user"] => m == "GET",
            ["user", "repos"] | ["orgs", _, "repos"] => matches!(m, "GET" | "POST"),
            ["users", _, "repos"] => m == "GET",
            ["repos", _, _] => m == "GET",
            ["repos", _, _, "issues" | "pulls"] => matches!(m, "GET" | "POST"),
            ["repos", _, _, "issues" | "pulls", number] if numeric_id(number) => {
                matches!(m, "GET" | "PATCH")
            }
            ["repos", _, _, "issues" | "pulls", number, "comments"] if numeric_id(number) => {
                matches!(m, "GET" | "POST")
            }
            ["repos", _, _, "issues" | "pulls", "comments", number] if numeric_id(number) => {
                matches!(m, "GET" | "PATCH" | "DELETE")
            }
            ["repos", _, _, "pulls", number, "reviews"] if numeric_id(number) => {
                matches!(m, "GET" | "POST")
            }
            ["repos", _, _, "pulls", number, "commits" | "files"] if numeric_id(number) => {
                m == "GET"
            }
            ["repos", _, _, "pulls", number, "merge"] if numeric_id(number) => {
                matches!(m, "GET" | "PUT")
            }
            _ => false,
        };
        if admitted {
            Ok(GitHubOperation::Rest)
        } else {
            Err(denied)
        }
    } else {
        Err(denied)
    }
}

fn numeric_id(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|id| id > 0 && id.to_string() == value)
}

fn validate_rest_query(query: Option<&str>) -> Result<(), CredentialBrokerError> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(());
    };
    if query.len() > 4096 {
        return Err(CredentialBrokerError::RequestDenied);
    }
    let bytes = query.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(CredentialBrokerError::RequestDenied);
        }
    }
    let mut names = BTreeSet::new();
    for (name, value) in url::form_urlencoded::parse(bytes) {
        if !REST_QUERY.contains(&name.as_ref())
            || !names.insert(name.into_owned())
            || value.len() > 1024
            || value.chars().any(char::is_control)
        {
            return Err(CredentialBrokerError::RequestDenied);
        }
    }
    Ok(())
}

fn bounded_headers(headers: &HeaderMap) -> bool {
    headers.len() <= 64
        && headers
            .iter()
            .try_fold(0_usize, |total, (name, value)| {
                if name.as_str().len() > 128 || value.as_bytes().len() > 8192 {
                    return None;
                }
                total
                    .checked_add(name.as_str().len() + value.as_bytes().len())
                    .filter(|bytes| *bytes <= 64 * 1024)
            })
            .is_some()
}

fn media_type(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let mut parts = value.split(';').map(str::trim);
    let media = parts.next()?.to_ascii_lowercase();
    if let Some(parameter) = parts.next() {
        let (key, value) = parameter.split_once('=')?;
        if parts.next().is_some()
            || !key.trim().eq_ignore_ascii_case("charset")
            || !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "utf-8" | "\"utf-8\""
            )
        {
            return None;
        }
    }
    Some(media)
}

fn valid_request_encoding(
    operation: GitHubOperation,
    method: &Method,
    headers: &HeaderMap,
) -> bool {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    if let Some(value) = values.next()
        && value.as_bytes() == b"gzip"
    {
        // Stock remote-curl compresses buffered fetch requests over 1024
        // bytes. Preserve the opaque Git body: no decompressor, body rewrite,
        // API/GraphQL acceptance, alternate route or response-policy change.
        return values.next().is_none()
            && operation == GitHubOperation::GitFetch
            && method == Method::POST;
    }
    crate::openai::validate_response_encoding(headers).is_ok()
}

fn policy(operation: GitHubOperation, path: &str) -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-github-oauth".into(),
        base_url: if operation.is_git() {
            "https://github.com"
        } else {
            "https://api.github.com"
        }
        .into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(if operation.is_git() {
            ProxyInjectionConfig::Basic {
                username: "x-access-token".into(),
                password_secret_key: TOKEN.into(),
            }
        } else {
            ProxyInjectionConfig::Bearer {
                secret_key: TOKEN.into(),
            }
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: ["GET", "POST", "PATCH", "PUT", "DELETE"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        allowed_exact_paths: vec![path.into()],
        allowed_path_prefixes: Vec::new(),
        allowed_request_headers: REQUEST_HEADERS
            .iter()
            .copied()
            .chain(
                (operation == GitHubOperation::GitFetch && path.ends_with("/git-upload-pack"))
                    .then_some("content-encoding"),
            )
            .map(str::to_owned)
            .collect(),
        allowed_response_headers: RESPONSE_HEADERS.iter().map(|name| (*name).into()).collect(),
        allowed_query_parameters: if operation.is_git() {
            vec!["service".into()]
        } else {
            REST_QUERY.iter().map(|name| (*name).into()).collect()
        },
        allowed_content_types: [
            "application/json",
            "application/x-git-upload-pack-request",
            "application/x-git-receive-pack-request",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        max_body_bytes: MAX_REQUEST_BYTES,
        response_mode: ProxyResponseMode::Streaming,
        max_response_bytes: MAX_RESPONSE_BYTES,
        websocket: None,
    }
}

#[cfg(test)]
mod tests;
