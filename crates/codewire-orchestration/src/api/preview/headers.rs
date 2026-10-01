//! A preview workload is an untrusted application origin, not a Codewire
//! authentication endpoint. Platform authority terminates at this proxy.
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

fn reserved_cookie(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("codewire.")
        || name.starts_with("codewire_")
        || name.starts_with("__host-codewire")
        || name.starts_with("__secure-codewire")
}

fn hop_header(name: &HeaderName, headers: &HeaderMap) -> bool {
    super::is_hop_by_hop(name.as_str())
        || headers.get_all(header::CONNECTION).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(name.as_str()))
            })
        })
}

/// A Bearer credential the proxy authenticated with stops here, and a Codewire
/// API key never reaches a workload. Other Authorization values belong to the
/// app, including a bearer it sends to its own API under a preview grant.
fn platform_authorization(value: &HeaderValue, platform_bearer: bool) -> bool {
    let Ok(value) = value.to_str() else {
        return true;
    };
    let token = value
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("bearer "))
        .map(|_| value[7..].trim());
    token.is_some_and(|token| {
        platform_bearer
            || token
                .strip_prefix("cw_")
                .is_some_and(|rest| rest.len() == 64)
    })
}

pub(super) fn workload_request_headers(headers: &HeaderMap, platform_bearer: bool) -> HeaderMap {
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        if hop_header(name, headers)
            || name == header::HOST
            || (name == header::AUTHORIZATION && platform_authorization(value, platform_bearer))
            || name == header::COOKIE
            || name.as_str().starts_with("x-codewire-")
        {
            continue;
        }
        result.append(name.clone(), value.clone());
    }
    if !hop_header(&header::COOKIE, headers) {
        let mut cookies = Vec::new();
        for value in headers.get_all(header::COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            for pair in value.split(';').map(str::trim) {
                let Some((name, _)) = pair.split_once('=') else {
                    continue;
                };
                if !name.is_empty() && !reserved_cookie(name.trim()) {
                    cookies.push(pair);
                }
            }
        }
        if !cookies.is_empty()
            && let Ok(value) = HeaderValue::from_str(&cookies.join("; "))
        {
            result.insert(header::COOKIE, value);
        }
    }
    result
}

fn permitted_application_cookie(value: &HeaderValue, preview_host: &str) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    let mut parts = value.split(';');
    let Some((name, _)) = parts.next().and_then(|pair| pair.split_once('=')) else {
        return false;
    };
    if name.trim().is_empty() || reserved_cookie(name.trim()) {
        return false;
    }
    let host = super::strip_port(preview_host).to_ascii_lowercase();
    let mut domain_seen = false;
    for part in parts {
        if let Some((key, value)) = part.trim().split_once('=')
            && key.trim().eq_ignore_ascii_case("domain")
        {
            // A workload cannot plant cookies on sibling preview origins.
            // Duplicate or quoted Domain attributes fail closed.
            if domain_seen
                || !value
                    .trim()
                    .trim_start_matches('.')
                    .eq_ignore_ascii_case(&host)
            {
                return false;
            }
            domain_seen = true;
        }
    }
    true
}

pub(super) fn browser_response_headers(headers: &HeaderMap, preview_host: &str) -> HeaderMap {
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        if hop_header(name, headers)
            || name.as_str().starts_with("x-codewire-")
            || (name == header::SET_COOKIE && !permitted_application_cookie(value, preview_host))
        {
            continue;
        }
        result.append(name.clone(), value.clone());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    const HOST: &str = "web-abcde-org.preview.test";

    #[test]
    fn request_strips_platform_authority_and_preserves_app_cookies() {
        let mut input = HeaderMap::new();
        input.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer platform-canary"),
        );
        input.append(
            header::COOKIE,
            HeaderValue::from_static(
                "theme=dark; codewire.session_token=session-canary; codewire_ssr_csrf=csrf-canary",
            ),
        );
        input.append(header::COOKIE, HeaderValue::from_static("__Host-codewire-preview=grant-canary; __Host-codewire-preview-challenge=nonce-canary; app_session=app-value"));
        input.insert("x-codewire-user", HeaderValue::from_static("spoofed"));
        input.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        let output = workload_request_headers(&input, true);
        assert!(!output.contains_key(header::AUTHORIZATION));
        assert!(!output.contains_key("x-codewire-user"));
        assert_eq!(output[header::COOKIE], "theme=dark; app_session=app-value");
        assert_eq!(output[header::ACCEPT], "text/html");
    }

    #[test]
    fn an_app_bearer_survives_a_grant_but_a_codewire_api_key_never_does() {
        let api_key = format!("Bearer cw_{}", "a".repeat(64));
        let mut input = HeaderMap::new();
        input.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer app-token"),
        );
        input.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YXBwOnNlY3JldA=="),
        );
        input.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&api_key).unwrap(),
        );
        let forwarded = |platform_bearer| {
            workload_request_headers(&input, platform_bearer)
                .get_all(header::AUTHORIZATION)
                .iter()
                .map(|value| value.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        // Under a preview grant (or on a public preview) the app keeps its own
        // credentials; a Codewire API key is always removed.
        assert_eq!(
            forwarded(false),
            ["Bearer app-token", "Basic YXBwOnNlY3JldA=="]
        );
        // A Bearer the proxy authenticated with stops at the proxy.
        assert_eq!(forwarded(true), ["Basic YXBwOnNlY3JldA=="]);
    }

    #[test]
    fn every_accepted_form_of_a_platform_credential_is_removed() {
        let forwarded = |headers: &HeaderMap, platform_bearer| {
            workload_request_headers(headers, platform_bearer)
                .iter()
                .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap()))
                .collect::<Vec<_>>()
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static(HOST));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer synthetic-token"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YXBwOnNlY3JldA=="),
        );
        headers.insert("x-app-header", HeaderValue::from_static("kept"));
        // Spacing, tabs, repeats and a second header are all removed. A name
        // inside another cookie's value is not a credential.
        headers.append(
            header::COOKIE,
            HeaderValue::from_static(
                "theme=dark; codewire.session_token =a;\tcodewire.session_token=b; app=codewire.session_token=x",
            ),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=second"),
        );
        assert_eq!(
            forwarded(&headers, true),
            [
                "authorization: Basic YXBwOnNlY3JldA==",
                "x-app-header: kept",
                "cookie: theme=dark; app=codewire.session_token=x",
            ]
        );
        let mut lowercase = HeaderMap::new();
        lowercase.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("bEaReR cw_{}", "b".repeat(64))).unwrap(),
        );
        assert!(forwarded(&lowercase, false).is_empty());
        // An unparseable cookie is dropped rather than forwarded unfiltered.
        let mut opaque = HeaderMap::new();
        opaque.insert(
            header::COOKIE,
            HeaderValue::from_bytes(b"codewire.session_token=\xff").unwrap(),
        );
        assert!(forwarded(&opaque, false).is_empty());
    }

    #[test]
    fn no_platform_only_cookie_header_reaches_workload() {
        let input = HeaderMap::from_iter([(
            header::COOKIE,
            HeaderValue::from_static(
                "codewire.session_token=one; codewire.session_token=two; CODEWIRE_csrf=three",
            ),
        )]);
        assert!(!workload_request_headers(&input, false).contains_key(header::COOKIE));
    }

    #[test]
    fn response_rejects_reserved_and_sibling_domain_cookies() {
        for cookie in [
            "codewire.session_token=canary",
            "codewire_ssr_csrf=canary",
            "__Host-codewire-preview=canary; Secure; Path=/",
            "__Host-codewire-preview-challenge=canary; Secure; Path=/",
            "session=x; Domain=.preview.test",
            "session=x; Domain=other.preview.test",
            "session=x; Domain=web-abcde-org.preview.test; Domain=.preview.test",
            "session=x; Domain=\"web-abcde-org.preview.test\"",
            "malformed",
        ] {
            let input = HeaderMap::from_iter([(
                header::SET_COOKIE,
                HeaderValue::from_str(cookie).unwrap(),
            )]);
            assert!(
                !browser_response_headers(&input, HOST).contains_key(header::SET_COOKIE),
                "{cookie}"
            );
        }
    }

    #[test]
    fn response_preserves_multiple_application_cookies_and_clear_cookie() {
        let mut input = HeaderMap::new();
        for cookie in [
            "app=x; Secure; HttpOnly; Path=/",
            "theme=; Max-Age=0; Path=/",
            "session=x; Domain=.web-abcde-org.preview.test",
        ] {
            input.append(header::SET_COOKIE, HeaderValue::from_str(cookie).unwrap());
        }
        let output = browser_response_headers(&input, HOST);
        assert_eq!(output.get_all(header::SET_COOKIE).iter().count(), 3);
    }

    #[test]
    fn both_directions_strip_connection_nominated_fields() {
        let input = HeaderMap::from_iter([
            (
                header::CONNECTION,
                HeaderValue::from_static("x-private, Cookie"),
            ),
            (
                HeaderName::from_static("x-private"),
                HeaderValue::from_static("canary"),
            ),
            (header::COOKIE, HeaderValue::from_static("app=value")),
        ]);
        for output in [
            workload_request_headers(&input, false),
            browser_response_headers(&input, HOST),
        ] {
            assert!(!output.contains_key(header::CONNECTION));
            assert!(!output.contains_key("x-private"));
            assert!(!output.contains_key(header::COOKIE));
        }
    }
}
