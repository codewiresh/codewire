//! Material-free HTTP routing shared by ingress owners.
//!
//! This only selects a provider family. The Anthropic and OpenAI families are
//! transparent: every request under their base path reaches the broker, which
//! changes only its credential. GitHub keeps its closed families. Callers
//! authenticate the ingress first and validate its configured authority before
//! normalizing HTTP/2 to origin-form. Host is never an upstream URL.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use axum::http::{HeaderMap, Method, StatusCode, Uri, header::HOST, uri::Authority};

pub use codewire_access::{
    MANAGED_ANTHROPIC_API_PREFIX, MANAGED_GITHUB_GIT_PREFIX, MANAGED_OPENAI_API_PREFIX,
};

const GITHUB_API_HOST: &str = "api.github.com";
const MAX_PATH_BYTES: usize = 2048;
const MAX_QUERY_BYTES: usize = 4096;

/// Routing metadata, not proof of authorization. Paths remain borrowed from
/// the original URI; no decoding, URL resolution or destination lookup occurs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassifiedHttpRequest<'a> {
    pub capability_slot: &'static str,
    pub route: &'static str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

/// Classify origin-form managed requests or exact-host GitHub API calls.
///
/// Non-GitHub managed routes may omit Host after trusted ingress normalization;
/// a present Host must be unique and well formed. Its configured value remains
/// the ingress owner's responsibility. GitHub API routing requires the exact
/// canonical `api.github.com` Host, with no port, alias or fallback to another
/// provider. A provider family admits any method, path and query under its base
/// path; the path stays provider-relative. Unknown routes and malformed metadata
/// fail before body polling.
pub fn classify_http_request<'a>(
    method: &Method,
    uri: &'a Uri,
    headers: &HeaderMap,
) -> Result<ClassifiedHttpRequest<'a>, StatusCode> {
    let denied = StatusCode::FORBIDDEN;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(denied);
    }
    // Reject upgrade attempts before hop-by-hop header filtering can erase
    // them. None of these routes supports WebSocket, h2c or another upgrade.
    if headers.contains_key("upgrade")
        || headers
            .keys()
            .any(|name| name.as_str().starts_with("sec-websocket-"))
        || headers.get_all("connection").iter().any(|value| {
            value.to_str().map_or(true, |value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
    {
        return Err(denied);
    }
    let host = validate_host(headers)?;
    let path = uri.path();
    let query = uri.query();
    if host == Some(GITHUB_API_HOST) {
        // The API root has no segments; it is admitted for GET alone, with no
        // query, and every other path must have well-formed segments.
        let admitted = if path == "/" {
            method == Method::GET && query.is_none()
        } else {
            github_api_family(method, &path_parts(path).ok_or(denied)?, query)
        };
        if !admitted {
            return Err(denied);
        }
        validate_query(query)?;
        return Ok(ClassifiedHttpRequest {
            capability_slot: "github",
            route: "github-api",
            path,
            query,
        });
    }
    // Most specific base first: the Codex client's bare `/v1` comes last.
    let (capability_slot, route, path) =
        if let Some(provider_path) = under(path, MANAGED_ANTHROPIC_API_PREFIX) {
            ("anthropic", "anthropic-api", provider_path)
        } else if let Some(provider_path) = under(path, MANAGED_OPENAI_API_PREFIX) {
            ("openai", "openai-api", provider_path)
        } else if path.starts_with(MANAGED_GITHUB_GIT_PREFIX) {
            path_parts(path).ok_or(denied)?;
            let provider_path = &path[MANAGED_GITHUB_GIT_PREFIX.len() - 1..];
            let provider_parts = path_parts(provider_path).ok_or(denied)?;
            let admitted = match provider_parts.as_slice() {
                [_, _, "info", "refs"] => {
                    method == Method::GET
                        && matches!(
                            query,
                            Some("service=git-upload-pack" | "service=git-receive-pack")
                        )
                }
                [_, _, "git-upload-pack" | "git-receive-pack"] => {
                    method == Method::POST && query.is_none()
                }
                _ => false,
            };
            if !admitted {
                return Err(denied);
            }
            ("github", "github-https", provider_path)
        } else if let Some(provider_path) = under(path, "/v1") {
            ("codex", "openai-api", provider_path)
        } else {
            return Err(denied);
        };
    if capability_slot != "github"
        && (!matches!(
            *method,
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
        ) || !provider_path_is_safe(path)
            || query.is_some_and(|query| query.len() > MAX_QUERY_BYTES))
    {
        return Err(denied);
    }
    Ok(ClassifiedHttpRequest {
        capability_slot,
        route,
        path,
        query,
    })
}

fn validate_host(headers: &HeaderMap) -> Result<Option<&str>, StatusCode> {
    let denied = StatusCode::FORBIDDEN;
    let mut hosts = headers.get_all(HOST).iter();
    let Some(value) = hosts.next() else {
        return Ok(None);
    };
    if hosts.next().is_some() {
        return Err(denied);
    }
    let value = value.to_str().map_err(|_| denied)?;
    if value.is_empty()
        || value.len() > 259
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b'@' | b',' | b'/' | b'\\' | b'%' | b'?' | b'#')
        })
    {
        return Err(denied);
    }
    let authority: Authority = value.parse().map_err(|_| denied)?;
    let hostname = authority.host();
    if let Some(ip) = hostname.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        ip.parse::<Ipv6Addr>().map_err(|_| denied)?;
    } else if hostname.len() > 253
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(denied);
    }
    if let Some(port) = authority.port() {
        let number = port.as_u16();
        if number == 0 || number.to_string() != port.as_str() {
            return Err(denied);
        }
    } else if value != hostname {
        return Err(denied);
    }
    if hostname.eq_ignore_ascii_case(GITHUB_API_HOST) && value != GITHUB_API_HOST {
        return Err(denied);
    }
    Ok(Some(value))
}

fn path_parts(path: &str) -> Option<Vec<&str>> {
    if path.len() > MAX_PATH_BYTES || !path.starts_with('/') {
        return None;
    }
    let parts: Vec<_> = path[1..].split('/').collect();
    if parts.iter().any(|part| {
        part.is_empty()
            || part.len() > 128
            || matches!(*part, "." | "..")
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }) {
        return None;
    }
    Some(parts)
}

/// The provider-relative path under one base path, which itself maps to `/`.
fn under<'a>(path: &'a str, base: &str) -> Option<&'a str> {
    match path.strip_prefix(base) {
        Some("") => Some("/"),
        Some(rest) if rest.starts_with('/') => Some(rest),
        _ => None,
    }
}

/// A transparent route forwards any path the URI parser admitted, bounded and
/// without dot segments, empty segments or control characters.
fn provider_path_is_safe(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn github_api_family(method: &Method, parts: &[&str], query: Option<&str>) -> bool {
    match parts {
        ["graphql"] => method == Method::POST && query.is_none(),
        ["user"] | ["repos", _, _] | ["users", _, "repos"] => method == Method::GET,
        // The default README `gh repo view` shows, GET only and with no query.
        // Owner-accepted exception: for a private repository the response
        // carries a short-lived, GitHub-minted download URL token for that one
        // file. See docs/dev/SECRETS-AND-CREDENTIALS.md,
        // "Accepted exception: the README download URL token".
        ["repos", _, _, "readme"] => method == Method::GET && query.is_none(),
        ["user", "repos"] | ["orgs", _, "repos"] => {
            matches!(*method, Method::GET | Method::POST)
        }
        ["repos", _, _, "issues" | "pulls", tail @ ..] if tail.len() <= 3 => {
            // Deliberately not a second copy of the broker's operation policy:
            // numeric IDs, exact suffixes and per-operation methods are checked
            // there before material access. This is a bounded family selector.
            matches!(
                *method,
                Method::GET | Method::POST | Method::PATCH | Method::PUT | Method::DELETE
            )
        }
        _ => false,
    }
}

fn validate_query(query: Option<&str>) -> Result<(), StatusCode> {
    let Some(query) = query else {
        return Ok(());
    };
    let denied = StatusCode::FORBIDDEN;
    if query.is_empty() || query.len() > MAX_QUERY_BYTES {
        return Err(denied);
    }
    let mut names = BTreeSet::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or(denied)?;
        let key = decode_query_component(key).ok_or(denied)?;
        let value = decode_query_component(value).ok_or(denied)?;
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || value.len() > 1024
            || !names.insert(key)
            || names.len() > 32
        {
            return Err(denied);
        }
    }
    Ok(())
}

fn decode_query_component(value: &str) -> Option<String> {
    let mut bytes = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                u8::try_from(high * 16 + low).ok()?
            }
            b'+' => b' ',
            byte => byte,
        });
    }
    let decoded = String::from_utf8(decoded).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}

#[cfg(test)]
mod tests;
