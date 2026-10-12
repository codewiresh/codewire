//! Transparent provider routes (#2536).
//!
//! The Anthropic and OpenAI routes forward a guest request to their one pinned
//! provider host as the stock client sent it: any CRUD method, path and query,
//! every header and the body byte for byte. The broker changes only:
//!
//! - the credential: guest-supplied `authorization`, `x-api-key`, `cookie` and
//!   `proxy-authorization` are dropped and the selected credential injected;
//! - framing: `host`, `content-length` and hop-by-hop headers, which the
//!   transport sets itself;
//! - `accept-encoding`, fixed to `identity` so responses stay redactable.
//!
//! Responses return every header except framing, hop-by-hop and `set-cookie`,
//! and every header value and body byte passes the injected credential's AV
//! redaction. Redaction matches the credential's raw, JSON, percent and base64
//! forms; it does not decode arbitrary opaque encodings of a reflected value.

use av_credential_proxy::{RedactionSet, is_websocket_attempt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use url::Url;

use crate::CredentialBrokerError;

/// Bounds the bridge already enforces; kept here so a direct caller cannot
/// exceed them either.
const MAX_PATH_BYTES: usize = 2048;
const MAX_QUERY_BYTES: usize = 4096;

/// Request headers that carry guest credentials or framing.
const STRIPPED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "cookie",
    "proxy-authorization",
    "host",
    "content-length",
    "accept-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Response headers that carry framing or provider cookies.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "set-cookie",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One guest request admitted by a transparent route. It holds no credential.
#[derive(Clone)]
pub(crate) struct TransparentRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl TransparentRequest {
    /// Admit any CRUD method and any bounded path and query. Upgrades are
    /// refused: these routes carry HTTP requests, not WebSockets.
    pub(crate) fn admit(
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
        max_body_bytes: usize,
    ) -> Result<Self, CredentialBrokerError> {
        let denied = CredentialBrokerError::RequestDenied;
        if !matches!(
            *method,
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
        ) || !safe_path(path)
            || query.is_some_and(|query| {
                query.len() > MAX_QUERY_BYTES
                    || query.contains('#')
                    || query.chars().any(char::is_control)
            })
            || is_websocket_attempt(&headers)
            || body.len() > max_body_bytes
        {
            return Err(denied);
        }
        Ok(Self {
            method: method.clone(),
            path: path.to_owned(),
            query: query.filter(|query| !query.is_empty()).map(str::to_owned),
            headers,
            body,
        })
    }

    /// The pinned base joined with this request's path and query. The result
    /// must keep the base's scheme, host and port and gain no user info.
    pub(crate) fn target(&self, base: &str) -> Result<Url, CredentialBrokerError> {
        let invalid = CredentialBrokerError::InvalidProviderPolicy;
        let base = Url::parse(base).map_err(|_| invalid)?;
        let mut target = base.clone();
        target.set_path(&format!(
            "{}{}",
            base.path().trim_end_matches('/'),
            self.path
        ));
        target.set_query(self.query.as_deref());
        target.set_fragment(None);
        if target.scheme() != base.scheme()
            || target.host_str() != base.host_str()
            || target.port_or_known_default() != base.port_or_known_default()
            || !target.username().is_empty()
            || target.password().is_some()
            || !target.path().starts_with(base.path().trim_end_matches('/'))
        {
            return Err(invalid);
        }
        Ok(target)
    }

    /// Every guest header except credentials and framing, with identity
    /// coding requested. `also_stripped` names headers the caller derives from
    /// the credential itself.
    pub(crate) fn outbound_headers(&self, also_stripped: &[&str]) -> HeaderMap {
        let named_by_connection = connection_tokens(&self.headers);
        let mut outbound = HeaderMap::new();
        for (name, value) in &self.headers {
            let lower = name.as_str();
            if STRIPPED_REQUEST_HEADERS.contains(&lower)
                || also_stripped.contains(&lower)
                || named_by_connection.iter().any(|token| token == lower)
            {
                continue;
            }
            outbound.append(name.clone(), value.clone());
        }
        outbound.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        outbound
    }
}

/// Every upstream header except framing and cookies, redacted. The upstream
/// content coding must be identity, so the body can be redacted too.
pub(crate) fn response_headers(
    upstream: &HeaderMap,
    redaction: &RedactionSet,
) -> Result<HeaderMap, CredentialBrokerError> {
    crate::openai::validate_response_encoding(upstream)?;
    let named_by_connection = connection_tokens(upstream);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream {
        let lower = name.as_str();
        if STRIPPED_RESPONSE_HEADERS.contains(&lower)
            || named_by_connection.iter().any(|token| token == lower)
        {
            continue;
        }
        let value = redaction
            .redact_header(value)
            .ok_or(CredentialBrokerError::ResponseDenied)?;
        headers.append(name.clone(), value);
    }
    Ok(headers)
}

/// Header names listed in `Connection`, which are hop-by-hop by declaration.
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| HeaderName::from_bytes(token.as_bytes()).is_ok())
        .collect()
}

/// A provider-relative path: bounded, absolute, and free of dot segments,
/// empty segments, backslashes, `?`, `#` and control characters.
fn safe_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path.starts_with('/')
        && !path.contains("//")
        && !path.contains(['\\', '?', '#'])
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit(method: Method, path: &str, query: Option<&str>) -> Result<(), CredentialBrokerError> {
        TransparentRequest::admit(&method, path, query, HeaderMap::new(), Vec::new(), 16).map(drop)
    }

    #[test]
    fn any_crud_method_path_and_query_is_admitted() {
        for method in [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            admit(method, "/api/oauth/usage", Some("a=1&b=%2F")).unwrap();
        }
        admit(Method::POST, "/v1/messages", Some("beta=true")).unwrap();
        admit(Method::GET, "/v1/files/file%2Dabc:content", None).unwrap();
        admit(Method::GET, "/", None).unwrap();
    }

    #[test]
    fn unsafe_shapes_are_refused() {
        for path in [
            "", "v1", "//v1", "/v1/../x", "/v1/./x", "/v1\\x", "/v1?x", "/a\u{7}",
        ] {
            assert!(admit(Method::GET, path, None).is_err(), "{path:?}");
        }
        assert!(admit(Method::OPTIONS, "/v1", None).is_err());
        assert!(admit(Method::CONNECT, "/v1", None).is_err());
        assert!(admit(Method::GET, "/v1", Some("a#b")).is_err());
        assert!(
            TransparentRequest::admit(
                &Method::POST,
                "/v1",
                None,
                HeaderMap::new(),
                vec![0; 17],
                16
            )
            .is_err()
        );
        let mut upgrade = HeaderMap::new();
        upgrade.insert("upgrade", HeaderValue::from_static("websocket"));
        upgrade.insert("connection", HeaderValue::from_static("upgrade"));
        assert!(
            TransparentRequest::admit(&Method::GET, "/v1", None, upgrade, Vec::new(), 16).is_err()
        );
    }

    #[test]
    fn target_keeps_the_pinned_origin() {
        let request = TransparentRequest::admit(
            &Method::GET,
            "/v1/models",
            Some("limit=2"),
            HeaderMap::new(),
            Vec::new(),
            16,
        )
        .unwrap();
        assert_eq!(
            request
                .target("https://api.anthropic.com")
                .unwrap()
                .as_str(),
            "https://api.anthropic.com/v1/models?limit=2"
        );
        assert_eq!(
            request
                .target("https://chatgpt.com/backend-api/codex")
                .unwrap()
                .as_str(),
            "https://chatgpt.com/backend-api/codex/v1/models?limit=2"
        );
    }

    #[test]
    fn credentials_and_framing_never_leave_and_everything_else_does() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", "Bearer guest"),
            ("x-api-key", "guest"),
            ("cookie", "a=b"),
            ("proxy-authorization", "Basic x"),
            ("host", "127.0.0.1:38081"),
            ("content-length", "3"),
            ("accept-encoding", "gzip"),
            ("connection", "keep-alive, x-hop"),
            ("x-hop", "1"),
            ("te", "trailers"),
            ("user-agent", "claude-cli/2.1.288 (external, cli)"),
            ("x-app", "cli"),
            (
                "anthropic-beta",
                "dangerous-tool-use-2026-09-03,oauth-2025-04-20",
            ),
            ("anthropic-version", "2023-06-01"),
            ("x-stainless-lang", "js"),
            ("x-forwarded-for", "10.0.0.1"),
        ] {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        headers.append("x-repeated", HeaderValue::from_static("1"));
        headers.append("x-repeated", HeaderValue::from_static("2"));
        let request =
            TransparentRequest::admit(&Method::POST, "/v1/messages", None, headers, Vec::new(), 16)
                .unwrap();
        let outbound = request.outbound_headers(&["x-app"]);
        for gone in [
            "authorization",
            "x-api-key",
            "cookie",
            "proxy-authorization",
            "host",
            "content-length",
            "connection",
            "x-hop",
            "te",
            "x-app",
        ] {
            assert!(!outbound.contains_key(gone), "{gone}");
        }
        for kept in [
            "user-agent",
            "anthropic-beta",
            "anthropic-version",
            "x-stainless-lang",
            "x-forwarded-for",
        ] {
            assert_eq!(outbound.get(kept), request.headers.get(kept), "{kept}");
        }
        assert_eq!(outbound.get_all("x-repeated").iter().count(), 2);
        assert_eq!(outbound["accept-encoding"], "identity");
    }

    #[test]
    fn response_headers_pass_except_framing_and_cookies_and_are_redacted() {
        let redaction = RedactionSet::new(["sk-secret-value-123"]);
        let mut upstream = HeaderMap::new();
        for (name, value) in [
            ("content-type", "text/event-stream"),
            ("request-id", "req_sk-secret-value-123"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.2"),
            ("x-new-provider-header", "1"),
            ("set-cookie", "a=b"),
            ("content-length", "10"),
            ("transfer-encoding", "chunked"),
            ("connection", "close"),
        ] {
            upstream.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        let headers = response_headers(&upstream, &redaction).unwrap();
        for gone in [
            "set-cookie",
            "content-length",
            "transfer-encoding",
            "connection",
        ] {
            assert!(!headers.contains_key(gone), "{gone}");
        }
        assert_eq!(headers["anthropic-ratelimit-unified-5h-utilization"], "0.2");
        assert_eq!(headers["x-new-provider-header"], "1");
        assert!(
            !headers["request-id"]
                .to_str()
                .unwrap()
                .contains("sk-secret-value-123")
        );
        upstream.insert("content-encoding", HeaderValue::from_static("gzip"));
        assert!(response_headers(&upstream, &redaction).is_err());
    }
}
